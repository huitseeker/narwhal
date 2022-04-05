#![allow(dead_code)]
use crate::{
    primary::PrimaryMessage, BatchDigest, Certificate, CertificateDigest, PayloadToken,
    PrimaryWorkerMessage,
};
use blake2::digest::Update;
use bytes::Bytes;
use config::{Committee, WorkerId};
use crypto::{traits::VerifyingKey, Digest, Hash};
use futures::{
    future::{join_all, BoxFuture},
    stream::FuturesUnordered,
    FutureExt, StreamExt,
};
use network::SimpleSender;
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use store::Store;
use thiserror::Error;
use tokio::{
    sync::mpsc::{channel, Receiver, Sender},
    time::{sleep, timeout},
};
use tracing::log::{debug, error, warn};

#[cfg(test)]
#[path = "tests/block_synchronizer_tests.rs"]
mod block_synchronizer_tests;

const SYNCHRONIZE_EXPIRATION_THRESHOLD: Duration = Duration::from_secs(2);
const TIMEOUT_SYNCHRONIZING_BATCHES: Duration = Duration::from_secs(2);
const TIMEOUT_FETCH_CERTIFICATES: Duration = Duration::from_secs(2);

type ResultSender<T> = Sender<BlockSynchronizeResult<Certificate<T>>>;
type BlockSynchronizeResult<T> = Result<T, SyncError>;

// RequestID helps us identify an incoming request and
// all the consequent network requests associated with it.
#[derive(Clone, Debug, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct RequestID(pub [u8; crypto::DIGEST_LEN]);

impl RequestID {
    // Create a request key (deterministically) from arbitrary data.
    fn new(data: &[u8]) -> Self {
        RequestID(crypto::blake2b_256(|hasher| hasher.update(data)))
    }
}

impl From<&[CertificateDigest]> for RequestID {
    fn from(ids: &[CertificateDigest]) -> Self {
        let mut ids_sorted = ids.to_vec();
        ids_sorted.sort();

        let result: Vec<u8> = ids_sorted
            .into_iter()
            .flat_map(|d| Digest::from(d).to_vec())
            .collect();

        RequestID::new(&result)
    }
}

#[derive(Debug, Clone)]
pub struct CertificatesResponse<PublicKey: VerifyingKey> {
    certificates: Vec<(CertificateDigest, Option<Certificate<PublicKey>>)>,
    from: PublicKey,
}

impl<PublicKey: VerifyingKey> CertificatesResponse<PublicKey> {
    fn request_id(self) -> RequestID {
        let ids: Vec<CertificateDigest> =
            self.certificates.into_iter().map(|entry| entry.0).collect();

        RequestID::from(ids.as_slice())
    }

    /// This method does two things:
    /// 1) filters only the found certificates
    /// 2) validates the certificates
    /// Even if one found certificate is not valid, an error is returned. Otherwise
    /// and Ok result is returned with (any) found certificates.
    fn validate_certificates(
        self,
        committee: &Committee<PublicKey>,
    ) -> Result<Vec<Certificate<PublicKey>>, ()> {
        let peer_found_certs: Vec<Certificate<PublicKey>> =
            self.certificates.into_iter().filter_map(|e| e.1).collect();

        if peer_found_certs.as_slice().is_empty() {
            // no certificates found, skip
            warn!(
                "No certificates are able to be served from {:?}",
                &self.from
            );
            return Ok(vec![]);
        }

        if peer_found_certs
            .iter()
            .any(|c| c.verify(committee).is_err())
        {
            error!("Found at least one invalid certificate from peer {:?}. Will ignore all certificates", self.from);

            return Err(());
        }

        Ok(peer_found_certs)
    }
}

pub enum Command<PublicKey: VerifyingKey> {
    SynchroniseBlocks {
        block_ids: Vec<CertificateDigest>,
        /// The channel to send the results to
        respond_to: ResultSender<PublicKey>,
    },
}

// Those commands are used for internal purposes only for the component.
// We are implementing a very very naive state machine and go get from
// one state to the other those commands are being used.
enum StateCommand<PublicKey: VerifyingKey> {
    TimeoutWaitingCertificates {
        request_id: RequestID,
        block_ids: Vec<CertificateDigest>,
    },
    ErrorSynchronizingBatchesForBlock {
        request_id: RequestID,
        certificate: Certificate<PublicKey>,
    },
    SynchronizeBatches {
        request_id: RequestID,
        certificates_by_peer: HashMap<PublicKey, Vec<Certificate<PublicKey>>>,
        certificates_by_id: HashMap<CertificateDigest, Certificate<PublicKey>>,
    },
    BlockSynchronized {
        request_id: RequestID,
        certificate: Certificate<PublicKey>,
    },
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("Block with id {block_id} has not been found even though tried to fetch from peers")]
    NotFound { block_id: CertificateDigest },

    #[error("Block with id {block_id} could not be retrieved")]
    Error { block_id: CertificateDigest },

    #[error("Block with id {block_id} could not be retrieved, timeout while retrieving result")]
    Timeout { block_id: CertificateDigest },
}

impl SyncError {
    pub fn block_id(self) -> CertificateDigest {
        match self {
            SyncError::NotFound { block_id } => block_id,
            SyncError::Error { block_id } => block_id,
            SyncError::Timeout { block_id } => block_id,
        }
    }
}

pub struct BlockSynchronizer<PublicKey: VerifyingKey> {
    /// The public key of this primary.
    name: PublicKey,

    /// The committee information.
    committee: Committee<PublicKey>,

    /// Receive the commands for the synchronizer
    rx_commands: Receiver<Command<PublicKey>>,

    /// Receive the requested list of certificates through this channel
    rx_certificate_responses: Receiver<CertificatesResponse<PublicKey>>,

    /// Pending block requests
    pending_block_requests: HashMap<CertificateDigest, Vec<ResultSender<PublicKey>>>,

    /// Requests managers
    map_certificate_responses_senders: HashMap<RequestID, Sender<CertificatesResponse<PublicKey>>>,

    /// Send network requests
    network: SimpleSender,

    payload_store: Store<(BatchDigest, WorkerId), PayloadToken>,
}

impl<PublicKey: VerifyingKey> BlockSynchronizer<PublicKey> {
    pub fn spawn(
        name: PublicKey,
        committee: Committee<PublicKey>,
        rx_commands: Receiver<Command<PublicKey>>,
        rx_certificate_responses: Receiver<CertificatesResponse<PublicKey>>,
        network: SimpleSender,
        payload_store: Store<(BatchDigest, WorkerId), PayloadToken>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                rx_commands,
                rx_certificate_responses,
                pending_block_requests: HashMap::new(),
                map_certificate_responses_senders: HashMap::new(),
                network,
                payload_store,
            }
            .run()
            .await;
        });
    }

    pub async fn run(&mut self) {
        let mut waiting = FuturesUnordered::new();

        loop {
            tokio::select! {
                Some(command) = self.rx_commands.recv() => {
                    match command {
                        Command::SynchroniseBlocks { block_ids, respond_to } => {
                            let fut = self.handle_synchronize_blocks_command(block_ids, respond_to).await;
                            if fut.is_some() {
                                waiting.push(fut.unwrap());
                            }
                        }
                    }
                },
                Some(response) = self.rx_certificate_responses.recv() => {
                    self.handle_certificates_response(response).await;
                },
                Some(result) = waiting.next() => {
                    match result {
                        StateCommand::SynchronizeBatches { request_id, certificates_by_peer, certificates_by_id } => {
                            println!("Fetched certificates, now synchronizing batches for request id {:?}", request_id);

                            let futures = self.handle_synchronize_batches_for_blocks(request_id, certificates_by_peer, certificates_by_id).await;
                            for fut in futures {
                                waiting.push(fut);
                            }
                        },
                        StateCommand::TimeoutWaitingCertificates { request_id, block_ids } => {
                            println!("Timeout waiting for certificates for {:?} request id {:?}", block_ids, request_id);
                            self.handle_timeout_waiting_certificates(request_id, block_ids).await;
                        },
                        StateCommand::BlockSynchronized { request_id, certificate } => {
                            println!("Successfully synchronised the batches of the certificate! {} for request id {:?}", certificate.clone().digest(), request_id);

                            let get_result = || -> BlockSynchronizeResult<Certificate<PublicKey>> {
                                Ok(certificate.clone())
                            };

                            self.handle_synchronize_block_result(certificate.digest(), get_result).await;
                        },
                        StateCommand::ErrorSynchronizingBatchesForBlock { request_id, certificate } => {
                            println!("Error synchronising batches {:?} for request id {:?}", certificate.clone(), request_id);

                            let get_result = || -> BlockSynchronizeResult<Certificate<PublicKey>> {
                                Err(SyncError::Error { block_id: certificate.clone().digest() })
                            };

                            self.handle_synchronize_block_result(certificate.digest(), get_result).await;
                        }
                    }
                }
            }
        }
    }

    async fn handle_synchronize_block_result<F>(
        &mut self,
        block_id: CertificateDigest,
        get_result: F,
    ) where
        F: Fn() -> BlockSynchronizeResult<Certificate<PublicKey>>,
    {
        // remove the senders & broadcast result
        if let Some(respond_to) = self.pending_block_requests.remove(&block_id) {
            let futures: Vec<_> = respond_to.iter().map(|s| s.send(get_result())).collect();

            for r in join_all(futures).await {
                if r.is_err() {
                    error!("Couldn't send message to channel [{:?}]", r.err().unwrap());
                }
            }
        }
    }

    async fn handle_timeout_waiting_certificates(
        &mut self,
        request_id: RequestID,
        block_ids: Vec<CertificateDigest>,
    ) {
        // remove the request
        self.map_certificate_responses_senders.remove(&request_id);

        // remove the pending block retrieval and notify the respond_to channels
        for block_id in block_ids {
            let get_result = || -> BlockSynchronizeResult<Certificate<PublicKey>> {
                Err(SyncError::Timeout { block_id })
            };

            self.handle_synchronize_block_result(block_id, get_result)
                .await;
        }
    }

    async fn handle_synchronize_blocks_command<'a>(
        &mut self,
        block_ids: Vec<CertificateDigest>,
        respond_to: ResultSender<PublicKey>,
    ) -> Option<BoxFuture<'a, StateCommand<PublicKey>>> {
        let mut to_sync = Vec::new();
        // a new request to synchronise blocks
        // check if there are pending requests. If yes, then ignore
        for block_id in block_ids.clone() {
            if self.pending_block_requests.contains_key(&block_id) {
                debug!("Nothing to request here, it's already in pending state");
            } else {
                to_sync.push(block_id);
            }

            // add our self anyways to a pending request, as we don't expect to
            // fail down the line of this method (unless crash)
            self.pending_block_requests
                .entry(block_id)
                .or_insert_with(Vec::new)
                .push(respond_to.clone());
        }

        // nothing new to sync! just return
        if to_sync.is_empty() {
            return None;
        }

        // broadcast the message to fetch  the certificates
        let num_of_requests = self
            .broadcast_certificates_batch_request(block_ids.clone())
            .await;

        let (sender, receiver) = channel(num_of_requests);
        let key = RequestID::from(block_ids.as_slice());

        // record the request key to forward the results to the dedicated sender
        self.map_certificate_responses_senders.insert(key, sender);

        // now create the future that will wait to gather the responses
        Some(
            Self::await_for_certificate_responses(
                key,
                self.committee.clone(),
                block_ids,
                num_of_requests as u32,
                receiver,
            )
            .boxed(),
        )
    }

    // Broadcasts a CertificatesBatchRequest to all the other primary nodes for the provided
    // block ids. It returns back the number of primaries
    async fn broadcast_certificates_batch_request(
        &mut self,
        block_ids: Vec<CertificateDigest>,
    ) -> usize {
        // Naively now just broadcast the request to all the primaries
        let message = PrimaryMessage::<PublicKey>::CertificatesBatchRequest {
            certificate_ids: block_ids,
            requestor: self.name.clone(),
        };
        let bytes = bincode::serialize(&message).expect("Failed to serialize request");

        let primaries_addresses: Vec<SocketAddr> = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();

        self.network
            .broadcast(primaries_addresses.clone(), Bytes::from(bytes))
            .await;

        primaries_addresses.len()
    }

    async fn handle_synchronize_batches_for_blocks<'a>(
        &mut self,
        request_id: RequestID,
        certificates_by_peer: HashMap<PublicKey, Vec<Certificate<PublicKey>>>,
        certificates_by_id: HashMap<CertificateDigest, Certificate<PublicKey>>,
    ) -> Vec<BoxFuture<'a, StateCommand<PublicKey>>> {
        // Synchronise batches according to a provided list

        // Now wait to synchronise the batches for each block
        /*
        let mut peer_and_certificates = Vec::new();

        for entry in certificates_by_peer {
            peer_and_certificates.push(entry);
        }

        let mut certificates_balanced = HashMap::new();

        // Do some simple round robin
        let mut counter = 0;
        let total_peers = peer_and_certificates.len();

        // try to distribute the load in a very naive round robin fashion
        // more sophisticated algorithm can be chosen later
        for block_id in block_ids {

            match peer_and_certificates.get(counter) {
                None => {
                    // should exist!
                }
                Some(entry) => {
                    let e = entry.clone();
                    let peer = e.0;
                    let certificates = e.1;

                    // if certificate is found, insert on the bucket
                    if let Some(certificate) = certificates.iter().find(|item|item.digest().eq(&block_id)) {
                        certificates_balanced.insert(peer, certificate);
                    }
                }
            }

            // round robin
            counter = (counter + 1) % total_peers;
        }*/

        // remove the request
        self.map_certificate_responses_senders.remove(&request_id);

        // naively sync the batches for all the certificates for each peer
        for entry in certificates_by_peer {
            let peer = entry.0;
            let certificates = entry.1;

            // split batches by worker
            let batches_by_worker = Self::map_batches_by_worker(certificates.as_slice());

            // find the worker addresses
            for (worker_id, batch_ids) in batches_by_worker {
                // send the batches to each worker id
                let worker_address = self
                    .committee
                    .worker(&self.name, &worker_id)
                    .expect("Worker id not found")
                    .primary_to_worker;

                // send the network request to each of them
                let message = PrimaryWorkerMessage::Synchronize(batch_ids, peer.clone());
                let bytes =
                    bincode::serialize(&message).expect("Failed to serialize batch sync request");
                self.network.send(worker_address, Bytes::from(bytes)).await;
            }
        }

        // wait for the batches to sync
        let mut futures = Vec::new();
        for (_, certificate) in certificates_by_id {
            let fut =
                Self::wait_for_block_batches(request_id, self.payload_store.clone(), certificate);
            futures.push(fut.boxed());
        }

        futures
    }

    async fn wait_for_block_batches<'a>(
        request_id: RequestID,
        payload_store: Store<(BatchDigest, WorkerId), PayloadToken>,
        certificate: Certificate<PublicKey>,
    ) -> StateCommand<PublicKey> {
        let mut futures = Vec::new();

        for item in certificate.clone().header.payload {
            futures.push(payload_store.notify_read(item));
        }

        // Wait for all the items to sync - have a timeout
        let result = timeout(TIMEOUT_SYNCHRONIZING_BATCHES, join_all(futures)).await;
        if result.is_err()
            || result
                .unwrap()
                .into_iter()
                .any(|r| r.map_or_else(|_| true, |f| f.is_none()))
        {
            return StateCommand::ErrorSynchronizingBatchesForBlock {
                request_id,
                certificate,
            };
        }

        StateCommand::BlockSynchronized {
            request_id,
            certificate,
        }
    }

    async fn handle_certificates_response(&mut self, response: CertificatesResponse<PublicKey>) {
        let sender = self
            .map_certificate_responses_senders
            .get_mut(&response.clone().request_id());

        if sender.is_some() {
            let s = sender.unwrap();

            if let Err(e) = s.send(response).await {
                error!("Could not send the response to the sender {:?}", e);
            }
        } else {
            warn!("Couldn't find a sender to channel the response. Will drop the message.");
        }
    }

    async fn await_for_certificate_responses(
        request_id: RequestID,
        committee: Committee<PublicKey>,
        block_ids: Vec<CertificateDigest>,
        num_of_requests_sent: u32,
        mut receiver: Receiver<CertificatesResponse<PublicKey>>,
    ) -> StateCommand<PublicKey> {
        // map the peers (name) with their certificate responses
        let mut certificates_by_peer: HashMap<PublicKey, Vec<Certificate<PublicKey>>> =
            HashMap::new();

        // keep track of the found certificates
        // map the certificate digests and peers who have them available
        let mut found_certificates: HashMap<CertificateDigest, Certificate<PublicKey>> =
            HashMap::new();

        let total_expected_certificates = block_ids.len();
        let mut num_of_responses = 0;

        // we want at least the (floor) 50% of responses to be received so we have enough
        // nodes to load balance the follow up sync requests to. We can change this
        // and even make mandatory to wait until all responses have been received (with timeout).
        let requests_majority = (num_of_requests_sent as f32 / 2.0).ceil() as u32;

        let timer = sleep(TIMEOUT_FETCH_CERTIFICATES);
        tokio::pin!(timer);

        loop {
            tokio::select! {
                Some(response) = receiver.recv() => {
                    if certificates_by_peer.contains_key(&response.from) {
                        // skip , we already got an answer from this peer
                        continue;
                    }

                    num_of_responses += 1;

                    match response.clone().validate_certificates(&committee) {
                        Ok(certificates) => {
                            certificates.iter().for_each(|c| {
                                found_certificates.insert(c.digest(), c.clone());
                            });

                            certificates_by_peer.insert(response.from.clone(), certificates);

                            if found_certificates.len() == total_expected_certificates &&
                            num_of_responses >= requests_majority
                            {
                                // hey! have them all - break now and go to next state
                                return StateCommand::SynchronizeBatches {
                                request_id,
                                certificates_by_peer,
                                certificates_by_id: found_certificates,
                                };
                            }
                        },
                        Err(()) => {
                            warn!("Got invalid certificates from peer");
                        }
                    }
                },
                () = &mut timer => {
                    // We did time out, but we have managed to gather all the desired certificates
                    if found_certificates.len() == total_expected_certificates {
                        return StateCommand::SynchronizeBatches {
                            request_id,
                            certificates_by_peer,
                        certificates_by_id: found_certificates};
                    }
                    // or timeout - oh we haven't managed to fetch the certificates in time!
                    return StateCommand::TimeoutWaitingCertificates { request_id, block_ids };
                }
            }
        }
    }

    // a helper method that collects all the batches from each certificate and maps
    // them by the worker id.
    fn map_batches_by_worker(
        certificates: &[Certificate<PublicKey>],
    ) -> HashMap<WorkerId, Vec<BatchDigest>> {
        let mut batches_by_worker: HashMap<WorkerId, Vec<BatchDigest>> = HashMap::new();
        for certificate in certificates.iter() {
            for (batch_id, worker_id) in &certificate.header.payload {
                batches_by_worker
                    .entry(*worker_id)
                    .or_insert_with(Vec::new)
                    .push(*batch_id);
            }
        }

        batches_by_worker
    }
}
