#![allow(dead_code)]
use crate::{
    primary::PrimaryMessage, utils, BatchDigest, Certificate, CertificateDigest, PayloadToken,
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
use std::{cell::RefCell, cmp::Ordering, collections::HashMap, net::SocketAddr, time::Duration};
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

/// The minimum percentage of responses that should be received when requesting
/// the certificates from peers in order to procceed to next state.
const CERTIFICATE_RESPONSES_RATIO_THRESHOLD: f32 = 0.5;

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
        peers: Peers<PublicKey>,
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
                        StateCommand::SynchronizeBatches { request_id, peers } => {
                            println!("Fetched certificates, now synchronizing batches for request id {:?}", request_id);

                            let futures = self.handle_synchronize_batches_for_blocks(request_id, peers).await;
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

        let key = RequestID::from(block_ids.as_slice());

        // broadcast the message to fetch  the certificates
        let num_of_requests = self
            .broadcast_certificates_batch_request(block_ids.clone())
            .await;

        let (sender, receiver) = channel(num_of_requests);

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
        mut peers: Peers<PublicKey>,
    ) -> Vec<BoxFuture<'a, StateCommand<PublicKey>>> {
        // Important step to do that first, so we give the opportunity
        // to other future requests (with same set of ids) making a request.
        self.map_certificate_responses_senders.remove(&request_id);

        // Rebalance the certificates to ensure that
        // those are uniquely distributed across the peers.
        peers.rebalance_certificates();

        // naively sync the batches for all the certificates for each peer
        for (_, peer) in peers.peers.iter() {
            self.send_synchronize_batches_requests(peer.clone().name, peer.assigned_certificates())
                .await
        }

        peers
            .unique_certificates()
            .into_iter()
            .map(|certificate| {
                Self::wait_for_block_batches(request_id, self.payload_store.clone(), certificate)
                    .boxed()
            })
            .collect()
    }

    /// This method sends the necessary requests to the worker nodes to
    /// synchronize the missing batches. The batches will be synchronized
    /// from the dictated primary_peer_name.
    ///
    /// # Arguments
    ///
    /// * `primary_peer_name` - The primary from which we are looking to sync the batches.
    /// * `certificates` - The certificates for which we want to sync their batches.
    async fn send_synchronize_batches_requests(
        &mut self,
        primary_peer_name: PublicKey,
        certificates: Vec<Certificate<PublicKey>>,
    ) {
        let batches_by_worker = utils::map_certificate_batches_by_worker(certificates.as_slice());

        for (worker_id, batch_ids) in batches_by_worker {
            let worker_address = self
                .committee
                .worker(&self.name, &worker_id)
                .expect("Worker id not found")
                .primary_to_worker;

            let message = PrimaryWorkerMessage::Synchronize(batch_ids, primary_peer_name.clone());
            let bytes =
                bincode::serialize(&message).expect("Failed to serialize batch sync request");
            self.network.send(worker_address, Bytes::from(bytes)).await;
        }
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
        let total_expected_certificates = block_ids.len();
        let mut num_of_responses: f32 = 0.0;

        let timer = sleep(TIMEOUT_FETCH_CERTIFICATES);
        tokio::pin!(timer);

        let mut peers = Peers::<PublicKey>::new();

        loop {
            tokio::select! {
                Some(response) = receiver.recv() => {
                    if peers.contains_peer(&response.from) {
                        // skip , we already got an answer from this peer
                        continue;
                    }

                    num_of_responses += 1.0;

                    match response.clone().validate_certificates(&committee) {
                        Ok(certificates) => {
                            // add them as a new peer
                            peers.add_peer(response.from.clone(), certificates);

                            let requests_received_ratio = ((num_of_responses / num_of_requests_sent as f32) * 100.0).round();

                            if peers.unique_certificates().len() == total_expected_certificates &&
                            requests_received_ratio >= CERTIFICATE_RESPONSES_RATIO_THRESHOLD
                            {
                                return StateCommand::SynchronizeBatches {
                                request_id,
                                peers
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
                    if peers.unique_certificates().len() == total_expected_certificates {
                        return StateCommand::SynchronizeBatches {
                            request_id,
                            peers
                        };
                    }
                    // or timeout - oh we haven't managed to fetch the certificates in time!
                    return StateCommand::TimeoutWaitingCertificates { request_id, block_ids };
                }
            }
        }
    }
}

#[derive(Clone)]
struct Peer<PublicKey: VerifyingKey> {
    name: PublicKey,
    certificates_able_to_serve: HashMap<CertificateDigest, Certificate<PublicKey>>,
    assigned_certificates: HashMap<CertificateDigest, Certificate<PublicKey>>,
}

impl<PublicKey: VerifyingKey> Peer<PublicKey> {
    fn new(name: PublicKey, certificates_able_to_serve: Vec<Certificate<PublicKey>>) -> Self {
        let certs: HashMap<CertificateDigest, Certificate<PublicKey>> = certificates_able_to_serve
            .into_iter()
            .map(|c| (c.digest(), c))
            .collect();

        Peer {
            name,
            certificates_able_to_serve: certs,
            assigned_certificates: HashMap::new(),
        }
    }

    fn assign_certificate(&mut self, certificate: &Certificate<PublicKey>) {
        self.assigned_certificates
            .insert(certificate.digest(), certificate.clone());
    }

    fn assigned_certificates(&self) -> Vec<Certificate<PublicKey>> {
        self.assigned_certificates
            .clone()
            .into_iter()
            .map(|v| v.1)
            .collect()
    }
}

struct Peers<PublicKey: VerifyingKey> {
    peers: HashMap<PublicKey, Peer<PublicKey>>,
    rebalanced: RefCell<bool>,
}

impl<PublicKey: VerifyingKey> Peers<PublicKey> {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            rebalanced: RefCell::new(false),
        }
    }

    fn unique_certificates(&self) -> Vec<Certificate<PublicKey>> {
        let result: HashMap<CertificateDigest, Certificate<PublicKey>> = self
            .peers
            .values()
            .flat_map(|v| {
                if *self.rebalanced.borrow() {
                    v.assigned_certificates.clone()
                } else {
                    v.certificates_able_to_serve.clone()
                }
            })
            .collect();

        result.into_iter().map(|(_, c)| c).collect()
    }

    fn contains_peer(&mut self, name: &PublicKey) -> bool {
        self.peers.contains_key(name)
    }

    fn add_peer(&mut self, name: PublicKey, available_certificates: Vec<Certificate<PublicKey>>) {
        self.peers
            .insert(name.clone(), Peer::new(name, available_certificates));
    }

    /// Re-distributes the certificates to the peers in a load balanced manner.
    /// We expect to have duplicates across the peers. The goal is in the end
    /// for each peer to have a unique list of certificates and those lists to
    /// not differ significantly, so we balance the load.
    /// The method shouldn't be called more than once.
    fn rebalance_certificates(&mut self) {
        if *self.rebalanced.borrow() {
            panic!("rebalance_certificates has been called more than once, this is not allowed");
        }

        let certificates = self.unique_certificates();

        for certificate in certificates {
            self.reassign_certificate(certificate);
        }

        self.rebalanced.replace(true);
    }

    fn reassign_certificate(&mut self, certificate: Certificate<PublicKey>) {
        let mut peer = self.peer_to_assign_certificate(&certificate);

        // step 5 - assign the certificate to this peer
        peer.assign_certificate(&certificate);

        self.peers.insert(peer.clone().name, peer);

        // step 6 - delete the certificate from all the peers where is found
        self.delete_certificate_from_peers(&certificate);
    }

    fn peer_to_assign_certificate(
        &mut self,
        certificate: &Certificate<PublicKey>,
    ) -> Peer<PublicKey> {
        let p = self.ordered_peers_have_certificate(certificate.digest());

        p.get(0)
            .expect("Expected to have found at least one peer that can serve the certificate")
            .clone()
    }

    /// This method will perform two operations:
    /// 1) Will return only the peers that certificate dictated by the
    /// provided `certificate_id`
    /// 2) Will order the peers in ascending order based on their already
    /// assigned certificates and the ones able to serve.
    fn ordered_peers_have_certificate(
        &mut self,
        certificate_id: CertificateDigest,
    ) -> Vec<Peer<PublicKey>> {
        // step 1 - find the peers who have this id
        let mut peers_with_certificate: Vec<Peer<PublicKey>> = self
            .peers
            .iter()
            .filter(|p| p.1.certificates_able_to_serve.contains_key(&certificate_id))
            .map(|p| p.1.clone())
            .collect();

        peers_with_certificate.sort_by(|a, b| {
            // step 2 - order the peers in ascending order based on the number of
            // certificates they have been assigned + able to serve. We want to
            // prioritise those that have the smallest set of those.
            let a_size = a.assigned_certificates.len() + a.certificates_able_to_serve.len();
            let b_size = b.assigned_certificates.len() + b.certificates_able_to_serve.len();

            // if equal in size, compare on the assigned_certificates.
            // We want to prioritise then ones that have less already
            // assigned certificates so we give them the chance to start
            // getting some.
            if a_size == b_size {
                return if a.assigned_certificates.len() > b.assigned_certificates.len() {
                    Ordering::Greater
                } else if a.assigned_certificates.len() < b.assigned_certificates.len(){
                    Ordering::Less
                } else {
                    // In case they are absolutely equal, we prioritise the one whose
                    // name is "less than" the other. This isn't really necessary, but
                    // it gives us some determinism.
                    if a.name.lt(&b.name) {
                        return Ordering::Less;
                    }
                    Ordering::Greater
                };
            } else if a_size > b_size {
                return Ordering::Greater;
            }
            Ordering::Less
        });

        peers_with_certificate
    }

    // Deletes the provided certificate from the list of available
    // certificates from all the peers.
    fn delete_certificate_from_peers(&mut self, certificate: &Certificate<PublicKey>) {
        for (_, peer) in self.peers.iter_mut() {
            peer.certificates_able_to_serve
                .remove(&certificate.digest());
        }
    }
}
