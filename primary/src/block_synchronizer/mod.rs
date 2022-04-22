// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    block_synchronizer::{
        peers::Peers,
        responses::{CertificatesResponse, PayloadAvailabilityResponse, RequestID},
        PendingIdentifier::{Header, Payload},
    },
    primary::PrimaryMessage,
    utils, BatchDigest, Certificate, CertificateDigest, PayloadToken, PrimaryWorkerMessage,
};
use bytes::Bytes;
use config::{BlockSynchronizerParameters, Committee, WorkerId};
use crypto::{traits::VerifyingKey, Hash};
use futures::{
    future::{join_all, BoxFuture},
    stream::FuturesUnordered,
    FutureExt, StreamExt,
};
use network::SimpleSender;
use rand::{rngs::SmallRng, SeedableRng};
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
mod responses;

/// The minimum percentage
/// (number of responses received from primary nodes / number of requests sent to primary nodes)
/// that should be reached when requesting the certificates from peers in order to
/// proceed to next state.
const CERTIFICATE_RESPONSES_RATIO_THRESHOLD: f32 = 0.5;

type ResultSender<T> = Sender<BlockSynchronizeResult<Certificate<T>>>;
type BlockSynchronizeResult<T> = Result<T, SyncError>;

pub enum Command<PublicKey: VerifyingKey> {
    #[allow(dead_code)]
    /// A request to synchronize and output the block headers
    /// This will not perform any attempt to fetch the header's
    /// batches.
    SynchronizeBlockHeaders {
        block_ids: Vec<CertificateDigest>,
        respond_to: ResultSender<PublicKey>,
    },
    /// A request to synchronize the payload (batches) of the
    /// provided certificates. The certificates are needed in
    /// order to know which batches to ask from the peers
    /// to sync and from which workers.
    #[allow(dead_code)]
    SynchronizeBlockPayload {
        certificates: Vec<Certificate<PublicKey>>,
        respond_to: ResultSender<PublicKey>,
    },
}

// Those states are used for internal purposes only for the component.
// We are implementing a very very naive state machine and go get from
// one state to the other those commands are being used.
enum State<PublicKey: VerifyingKey> {
    HeadersSynchronized {
        request_id: RequestID,
        certificates: HashMap<CertificateDigest, Result<Certificate<PublicKey>, SyncError>>,
    },
    PayloadAvailabilityReceived {
        request_id: RequestID,
        certificates: HashMap<CertificateDigest, Result<Certificate<PublicKey>, SyncError>>,
        peers: Peers<PublicKey, Certificate<PublicKey>>,
    },
    PayloadSynchronized {
        request_id: RequestID,
        result: Result<Certificate<PublicKey>, SyncError>,
    },
}

#[derive(Debug, Error, Copy, Clone)]
pub enum SyncError {
    #[error("Block with id {block_id} could not be retrieved")]
    Error { block_id: CertificateDigest },

    #[error("Block with id {block_id} could not be retrieved, timeout while retrieving result")]
    Timeout { block_id: CertificateDigest },
}

impl SyncError {
    #[allow(dead_code)]
    pub fn block_id(self) -> CertificateDigest {
        match self {
            SyncError::Error { block_id } => block_id,
            SyncError::Timeout { block_id } => block_id,
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
enum PendingIdentifier {
    Header(CertificateDigest),
    Payload(CertificateDigest),
}

impl PendingIdentifier {
    #[allow(dead_code)]
    fn id(&self) -> CertificateDigest {
        match self {
            PendingIdentifier::Header(id) => *id,
            PendingIdentifier::Payload(id) => *id,
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

    /// Receive the availability for the requested certificates through this
    /// channel
    rx_payload_availability_responses: Receiver<PayloadAvailabilityResponse<PublicKey>>,

    /// Pending block requests either for header or payload type
    pending_requests: HashMap<PendingIdentifier, Vec<ResultSender<PublicKey>>>,

    /// Requests managers
    map_certificate_responses_senders: HashMap<RequestID, Sender<CertificatesResponse<PublicKey>>>,

    /// Holds the senders to match a batch_availability responses
    map_payload_availability_responses_senders:
        HashMap<RequestID, Sender<PayloadAvailabilityResponse<PublicKey>>>,

    /// Send network requests
    network: SimpleSender,

    /// The persistent storage for payload markers from workers
    payload_store: Store<(BatchDigest, WorkerId), PayloadToken>,

    /// Timeout when synchronizing the certificates
    certificates_synchronize_timeout: Duration,

    /// Timeout when synchronizing the payload
    payload_synchronize_timeout: Duration,

    /// Timeout when has requested the payload and waiting to receive
    payload_availability_timeout: Duration,
}

impl<PublicKey: VerifyingKey> BlockSynchronizer<PublicKey> {
    pub fn spawn(
        name: PublicKey,
        committee: Committee<PublicKey>,
        rx_commands: Receiver<Command<PublicKey>>,
        rx_certificate_responses: Receiver<CertificatesResponse<PublicKey>>,
        rx_payload_availability_responses: Receiver<PayloadAvailabilityResponse<PublicKey>>,
        network: SimpleSender,
        payload_store: Store<(BatchDigest, WorkerId), PayloadToken>,
        parameters: BlockSynchronizerParameters,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                rx_commands,
                rx_certificate_responses,
                rx_payload_availability_responses,
                pending_requests: HashMap::new(),
                map_certificate_responses_senders: HashMap::new(),
                map_payload_availability_responses_senders: HashMap::new(),
                network,
                payload_store,
                certificates_synchronize_timeout: Duration::from_millis(
                    parameters.certificates_synchronize_timeout_ms,
                ),
                payload_synchronize_timeout: Duration::from_millis(
                    parameters.payload_availability_timeout_ms,
                ),
                payload_availability_timeout: Duration::from_millis(
                    parameters.payload_availability_timeout_ms,
                ),
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
                        Command::SynchronizeBlockHeaders { block_ids, respond_to } => {
                            let fut = self.handle_synchronize_block_headers_command(block_ids, respond_to).await;
                            if fut.is_some() {
                                waiting.push(fut.unwrap());
                            }
                        },
                        Command::SynchronizeBlockPayload { certificates, respond_to } => {
                            let fut = self.handle_synchronize_block_payload_command(certificates, respond_to).await;
                            if fut.is_some() {
                                waiting.push(fut.unwrap());
                            }
                        }
                    }
                },
                Some(response) = self.rx_certificate_responses.recv() => {
                    self.handle_certificates_response(response).await;
                },
                Some(response) = self.rx_payload_availability_responses.recv() => {
                    self.handle_payload_availability_response(response).await;
                },
                Some(state) = waiting.next() => {
                    match state {
                        State::HeadersSynchronized { request_id, certificates } => {
                            debug!("Result for the block headers synchronize request id {}", request_id);

                            for (id, result) in certificates {
                                self.notify_requestors_for_result(Header(id), result).await;
                            }
                        },
                        State::PayloadAvailabilityReceived { request_id, certificates, peers } => {
                             debug!("Result for the block payload synchronize request id {}", request_id);

                            // now try to synchronise the payload only for the ones that have been found
                            let futures = self.handle_synchronize_block_payloads(request_id, peers).await;
                            for fut in futures {
                                waiting.push(fut);
                            }

                            // notify immediately for block_ids that have been errored or timedout
                            for (id, result) in certificates {
                                if result.is_err() {
                                    self.notify_requestors_for_result(Payload(id), result).await;
                                }
                            }
                        },
                        State::PayloadSynchronized { request_id, result } => {
                            let id = result.clone().map_or_else(|e| e.block_id(), |r| r.digest());

                            debug!("Block payload synchronize result received for certificate id {id} for request id {request_id}");

                            self.notify_requestors_for_result(Payload(id), result).await;
                        },
                    }
                }
            }
        }
    }

    async fn notify_requestors_for_result(
        &mut self,
        request: PendingIdentifier,
        result: BlockSynchronizeResult<Certificate<PublicKey>>,
    ) {
        // remove the senders & broadcast result
        if let Some(respond_to) = self.pending_requests.remove(&request) {
            let futures: Vec<_> = respond_to.iter().map(|s| s.send(result.clone())).collect();

            for r in join_all(futures).await {
                if r.is_err() {
                    error!("Couldn't send message to channel [{:?}]", r.err().unwrap());
                }
            }
        }
    }

    // Helper method to mark a request as pending. It returns true if it is the
    // first request for this identifier, otherwise false is returned instead.
    fn resolve_pending_request(
        &mut self,
        identifier: PendingIdentifier,
        respond_to: ResultSender<PublicKey>,
    ) -> bool {
        // add our self anyways to a pending request, as we don't expect to
        // fail down the line of this method (unless crash)
        self.pending_requests
            .entry(identifier)
            .or_default()
            .push(respond_to);

        return self.pending_requests.get(&identifier).unwrap().len() == 1;
    }

    async fn handle_synchronize_block_payload_command<'a>(
        &mut self,
        certificates: Vec<Certificate<PublicKey>>,
        respond_to: ResultSender<PublicKey>,
    ) -> Option<BoxFuture<'a, State<PublicKey>>> {
        let mut to_sync = Vec::new();

        for certificate in certificates.clone() {
            let block_id = certificate.digest();

            if self.resolve_pending_request(Payload(block_id), respond_to.clone()) {
                to_sync.push(certificate);
            } else {
                debug!("Nothing to request here, it's already in pending state");
            }
        }

        // nothing new to sync! just return
        if to_sync.is_empty() {
            return None;
        }

        let key = RequestID::from(to_sync.as_slice());

        let message = PrimaryMessage::<PublicKey>::PayloadAvailabilityRequest {
            certificate_ids: certificates.into_iter().map(|c| c.digest()).collect(),
            requestor: self.name.clone(),
        };

        // broadcast the message to fetch  the certificates
        let primaries = self.broadcast_batch_request(message).await;

        let (sender, receiver) = channel(primaries.as_slice().len());

        // record the request key to forward the results to the dedicated sender
        self.map_payload_availability_responses_senders
            .insert(key, sender);

        // now create the future that will wait to gather the responses
        Some(
            Self::wait_for_payload_availability_responses(
                self.payload_availability_timeout,
                key,
                to_sync,
                primaries,
                receiver,
            )
            .boxed(),
        )
    }

    async fn handle_synchronize_block_headers_command<'a>(
        &mut self,
        block_ids: Vec<CertificateDigest>,
        respond_to: ResultSender<PublicKey>,
    ) -> Option<BoxFuture<'a, State<PublicKey>>> {
        let mut to_sync = Vec::new();
        // a new request to synchronise blocks
        // check if there are pending requests. If yes, then ignore
        for block_id in block_ids.clone() {
            if self.resolve_pending_request(Header(block_id), respond_to.clone()) {
                to_sync.push(block_id);
            } else {
                debug!("Nothing to request here, it's already in pending state");
            }
        }

        // nothing new to sync! just return
        if to_sync.is_empty() {
            return None;
        }

        let key = RequestID::from(to_sync.as_slice());

        let message = PrimaryMessage::<PublicKey>::CertificatesBatchRequest {
            certificate_ids: block_ids,
            requestor: self.name.clone(),
        };

        // broadcast the message to fetch  the certificates
        let primaries = self.broadcast_batch_request(message).await;

        let (sender, receiver) = channel(primaries.as_slice().len());

        // record the request key to forward the results to the dedicated sender
        self.map_certificate_responses_senders.insert(key, sender);

        // now create the future that will wait to gather the responses
        Some(
            Self::wait_for_certificate_responses(
                self.certificates_synchronize_timeout,
                key,
                self.committee.clone(),
                to_sync,
                primaries,
                receiver,
            )
            .boxed(),
        )
    }

    // Broadcasts a message to all the other primary nodes.
    // It returns back the primary names to which we have sent the requests.
    async fn broadcast_batch_request(
        &mut self,
        message: PrimaryMessage<PublicKey>,
    ) -> Vec<PublicKey> {
        // Naively now just broadcast the request to all the primaries
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

    async fn handle_synchronize_block_payloads<'a>(
        &mut self,
        request_id: RequestID,
        mut peers: Peers<PublicKey, Certificate<PublicKey>>,
    ) -> Vec<BoxFuture<'a, State<PublicKey>>> {
        // Important step to do that first, so we give the opportunity
        // to other future requests (with same set of ids) making a request.
        self.map_payload_availability_responses_senders
            .remove(&request_id);

        // Rebalance the CertificateDigests to ensure that
        // those are uniquely distributed across the peers.
        peers.rebalance_values();

        for (_, peer) in peers.peers().iter() {
            self.send_synchronize_payload_requests(peer.clone().name, peer.assigned_values())
                .await
        }

        peers
            .unique_values()
            .into_iter()
            .map(|digest| {
                Self::wait_for_block_payload(
                    self.payload_synchronize_timeout,
                    request_id,
                    self.payload_store.clone(),
                    digest,
                )
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
    async fn send_synchronize_payload_requests(
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

    async fn wait_for_block_payload<'a>(
        payload_synchronize_timeout: Duration,
        request_id: RequestID,
        payload_store: Store<(BatchDigest, WorkerId), PayloadToken>,
        certificate: Certificate<PublicKey>,
    ) -> State<PublicKey> {
        let futures = certificate
            .header
            .payload
            .iter()
            .map(|(batch_digest, worker_id)| payload_store.notify_read((*batch_digest, *worker_id)))
            .collect::<Vec<_>>();

        // Wait for all the items to sync - have a timeout
        let result = timeout(payload_synchronize_timeout, join_all(futures)).await;
        if result.is_err()
            || result
                .unwrap()
                .into_iter()
                .any(|r| r.map_or_else(|_| true, |f| f.is_none()))
        {
            return State::PayloadSynchronized {
                request_id,
                result: Err(SyncError::Timeout {
                    block_id: certificate.digest(),
                }),
            };
        }

        State::PayloadSynchronized {
            request_id,
            result: Ok(certificate),
        }
    }

    async fn handle_payload_availability_response(
        &mut self,
        response: PayloadAvailabilityResponse<PublicKey>,
    ) {
        let sender = self
            .map_payload_availability_responses_senders
            .get(&response.clone().request_id());

        if let Some(s) = sender {
            if let Err(e) = s.send(response).await {
                error!("Could not send the response to the sender {:?}", e);
            }
        } else {
            warn!("Couldn't find a sender to channel the response. Will drop the message.");
        }
    }

    async fn handle_certificates_response(&mut self, response: CertificatesResponse<PublicKey>) {
        let sender = self
            .map_certificate_responses_senders
            .get(&response.clone().request_id());

        if let Some(s) = sender {
            if let Err(e) = s.send(response).await {
                error!("Could not send the response to the sender {:?}", e);
            }
        } else {
            warn!("Couldn't find a sender to channel the response. Will drop the message.");
        }
    }

    async fn wait_for_certificate_responses(
        fetch_certificates_timeout: Duration,
        request_id: RequestID,
        committee: Committee<PublicKey>,
        block_ids: Vec<CertificateDigest>,
        primaries_sent_requests_to: Vec<PublicKey>,
        mut receiver: Receiver<CertificatesResponse<PublicKey>>,
    ) -> State<PublicKey> {
        let total_expected_certificates = block_ids.len();
        let mut num_of_responses: u32 = 0;
        let num_of_requests_sent: u32 = primaries_sent_requests_to.len() as u32;

        let timer = sleep(fetch_certificates_timeout);
        tokio::pin!(timer);

        let mut peers = Peers::<PublicKey, Certificate<PublicKey>>::new(SmallRng::from_entropy());

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

                    num_of_responses += 1;

                    match response.validate_certificates(&committee) {
                        Ok(certificates) => {
                            // Ensure we got responses for the certificates we asked for.
                            // Even if we have found one certificate that doesn't match
                            // we reject the payload - it shouldn't happen.
                            if certificates.iter().any(|c|!block_ids.contains(&c.digest())) {
                                continue;
                            }

                            // add them as a new peer
                            peers.add_peer(response.from.clone(), certificates);

                            // We have received all possible responses
                            if (peers.unique_values().len() == total_expected_certificates &&
                            Self::reached_response_ratio(num_of_responses, num_of_requests_sent))
                            || num_of_responses == num_of_requests_sent
                            {
                                let result = Self::resolve_block_synchronize_result(&peers, block_ids, false);

                                return State::HeadersSynchronized {
                                    request_id,
                                    certificates: result,
                                };
                            }
                        },
                        Err(_) => {
                            warn!("Got invalid certificates from peer");
                        }
                    }
                },
                () = &mut timer => {
                    let result = Self::resolve_block_synchronize_result(&peers, block_ids, true);

                    return State::HeadersSynchronized {
                        request_id,
                        certificates: result,
                    };
                }
            }
        }
    }

    async fn wait_for_payload_availability_responses(
        fetch_certificates_timeout: Duration,
        request_id: RequestID,
        certificates: Vec<Certificate<PublicKey>>,
        primaries_sent_requests_to: Vec<PublicKey>,
        mut receiver: Receiver<PayloadAvailabilityResponse<PublicKey>>,
    ) -> State<PublicKey> {
        let total_expected_block_ids = certificates.len();
        let mut num_of_responses: u32 = 0;
        let num_of_requests_sent: u32 = primaries_sent_requests_to.len() as u32;
        let certificates_by_id: HashMap<CertificateDigest, Certificate<PublicKey>> = certificates
            .iter()
            .map(|c| (c.digest(), c.clone()))
            .collect();
        let block_ids: Vec<CertificateDigest> = certificates_by_id
            .iter()
            .map(|(id, _)| id.to_owned())
            .collect();

        let timer = sleep(fetch_certificates_timeout);
        tokio::pin!(timer);

        let mut peers = Peers::<PublicKey, Certificate<PublicKey>>::new(SmallRng::from_entropy());

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

                    num_of_responses += 1;

                    // Ensure we got responses for the certificates we asked for.
                    // Even if we have found one certificate that doesn't match
                    // we reject the payload - it shouldn't happen. Also, add the
                    // found ones in a vector.
                    let mut available_certs_for_peer = Vec::new();
                    for id in response.available_block_ids() {
                        if let Some(c) = certificates_by_id.get(&id) {
                            available_certs_for_peer.push(c.clone());
                        } else {
                            // We should expect to have found every
                            // responded id to our list of certificates.
                            continue;
                        }
                    }

                    // add them as a new peer
                    peers.add_peer(response.from.clone(), available_certs_for_peer);

                    // We have received all possible responses
                    if (peers.unique_values().len() == total_expected_block_ids &&
                    Self::reached_response_ratio(num_of_responses, num_of_requests_sent))
                    || num_of_responses == num_of_requests_sent
                    {
                        let result = Self::resolve_block_synchronize_result(&peers, block_ids, false);

                        return State::PayloadAvailabilityReceived {
                            request_id,
                            certificates: result,
                            peers,
                        };
                    }
                },
                () = &mut timer => {
                    let result = Self::resolve_block_synchronize_result(&peers, block_ids, true);

                    return State::PayloadAvailabilityReceived {
                        request_id,
                        certificates: result,
                        peers,
                    };
                }
            }
        }
    }

    fn resolve_block_synchronize_result(
        peers: &Peers<PublicKey, Certificate<PublicKey>>,
        block_ids: Vec<CertificateDigest>,
        timeout: bool,
    ) -> HashMap<CertificateDigest, Result<Certificate<PublicKey>, SyncError>> {
        let mut certificates_by_id: HashMap<CertificateDigest, Certificate<PublicKey>> = peers
            .unique_values()
            .into_iter()
            .map(|c| (c.digest(), c))
            .collect();

        let mut result: HashMap<CertificateDigest, Result<Certificate<PublicKey>, SyncError>> =
            HashMap::new();

        for block_id in block_ids {
            // if not found, then this is an Error - couldn't be retrieved
            // by any peer - suspicious!
            if let Some(certificate) = certificates_by_id.remove(&block_id) {
                result.insert(block_id, Ok(certificate));
            } else if timeout {
                result.insert(block_id, Err(SyncError::Timeout { block_id }));
            } else {
                result.insert(block_id, Err(SyncError::Error { block_id }));
            }
        }

        result
    }

    fn reached_response_ratio(num_of_responses: u32, num_of_expected_responses: u32) -> bool {
        let ratio: f32 =
            ((num_of_responses as f32 / num_of_expected_responses as f32) * 100.0).round();
        ratio >= CERTIFICATE_RESPONSES_RATIO_THRESHOLD * 100.0
    }
}
