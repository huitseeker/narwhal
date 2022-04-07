// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use crate::{
    block_synchronizer::peers::Peers, primary::PrimaryMessage, utils, BatchDigest, Certificate,
    CertificateDigest, PayloadToken, PrimaryWorkerMessage,
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
use std::{collections::HashMap, time::Duration};
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
mod peers;

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
        peers: Peers<PublicKey, Certificate<PublicKey>>,
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
        let primaries = self
            .broadcast_certificates_batch_request(block_ids.clone())
            .await;

        let (sender, receiver) = channel(primaries.as_slice().len());

        // record the request key to forward the results to the dedicated sender
        self.map_certificate_responses_senders.insert(key, sender);

        // now create the future that will wait to gather the responses
        Some(
            Self::await_for_certificate_responses(
                key,
                self.committee.clone(),
                block_ids,
                primaries,
                receiver,
            )
            .boxed(),
        )
    }

    // Broadcasts a CertificatesBatchRequest to all the other primary nodes for the provided
    // block ids. It returns back the primary names to which we have sent the requests.
    async fn broadcast_certificates_batch_request(
        &mut self,
        block_ids: Vec<CertificateDigest>,
    ) -> Vec<PublicKey> {
        // Naively now just broadcast the request to all the primaries
        let message = PrimaryMessage::<PublicKey>::CertificatesBatchRequest {
            certificate_ids: block_ids,
            requestor: self.name.clone(),
        };
        let bytes = bincode::serialize(&message).expect("Failed to serialize request");

        let primaries_addresses = self.committee.others_primaries(&self.name);

        self.network
            .broadcast(
                primaries_addresses
                    .clone()
                    .into_iter()
                    .map(|(_, address)| address.primary_to_primary)
                    .collect(),
                Bytes::from(bytes),
            )
            .await;

        primaries_addresses
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    async fn handle_synchronize_batches_for_blocks<'a>(
        &mut self,
        request_id: RequestID,
        mut peers: Peers<PublicKey, Certificate<PublicKey>>,
    ) -> Vec<BoxFuture<'a, StateCommand<PublicKey>>> {
        // Important step to do that first, so we give the opportunity
        // to other future requests (with same set of ids) making a request.
        self.map_certificate_responses_senders.remove(&request_id);

        // Rebalance the certificates to ensure that
        // those are uniquely distributed across the peers.
        peers.rebalance_values();

        for (_, peer) in peers.peers.iter() {
            self.send_synchronize_batches_requests(peer.clone().name, peer.assigned_values())
                .await
        }

        peers
            .unique_values()
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
        primaries_sent_requests_to: Vec<PublicKey>,
        mut receiver: Receiver<CertificatesResponse<PublicKey>>,
    ) -> StateCommand<PublicKey> {
        let total_expected_certificates = block_ids.len();
        let mut num_of_responses: f32 = 0.0;
        let num_of_requests_sent: f32 = primaries_sent_requests_to.len() as f32;

        let timer = sleep(TIMEOUT_FETCH_CERTIFICATES);
        tokio::pin!(timer);

        let mut peers = Peers::<PublicKey, Certificate<PublicKey>>::new();

        loop {
            tokio::select! {
                Some(response) = receiver.recv() => {
                    if peers.contains_peer(&response.from) {
                        // skip , we already got an answer from this peer
                        continue;
                    }

                    // check whether the peer is amongst the one we are expecting
                    // response from. That shouldn't really happen, since the
                    // responses we get are filtered by the request id, but still
                    // worth double checking
                    if !primaries_sent_requests_to.iter().any(|p|p.eq(&response.from)) {
                        continue;
                    }

                    num_of_responses += 1.0;

                    match response.clone().validate_certificates(&committee) {
                        Ok(certificates) => {
                            // Ensure we got responses for the certificates we asked for.
                            // Even if we have found one certificate that doesn't match
                            // we reject the payload - it shouldn't happen.
                            if certificates.iter().any(|c|!block_ids.contains(&c.digest())) {
                                continue;
                            }

                            // add them as a new peer
                            peers.add_peer(response.from.clone(), certificates);

                            if peers.unique_values().len() == total_expected_certificates &&
                            Self::reached_response_ratio(num_of_responses, num_of_requests_sent)
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
                    if peers.unique_values().len() == total_expected_certificates {
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

    fn reached_response_ratio(num_of_responses: f32, num_of_expected_responses: f32) -> bool {
        let ratio: f32 = ((num_of_responses / num_of_expected_responses) * 100.0).round();
        ratio >= CERTIFICATE_RESPONSES_RATIO_THRESHOLD * 100.0
    }
}
