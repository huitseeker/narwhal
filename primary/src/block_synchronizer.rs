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
use std::{cell::RefCell, cmp::Ordering, collections::HashMap, time::Duration};
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

        // naively sync the batches for all the certificates for each peer
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

                    num_of_responses += 1.0;

                    match response.clone().validate_certificates(&committee) {
                        Ok(certificates) => {
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

#[derive(Clone)]
struct Peer<PublicKey: VerifyingKey, Value: Hash + Clone> {
    name: PublicKey,
    values_able_to_serve: HashMap<<Value as Hash>::TypedDigest, Value>,
    assigned_values: HashMap<<Value as Hash>::TypedDigest, Value>,
}

impl<PublicKey: VerifyingKey, Value: Hash + Clone> Peer<PublicKey, Value> {
    fn new(name: PublicKey, values_able_to_serve: Vec<Value>) -> Self {
        let certs: HashMap<<Value as crypto::Hash>::TypedDigest, Value> = values_able_to_serve
            .into_iter()
            .map(|c| (c.digest(), c))
            .collect();

        Peer {
            name,
            values_able_to_serve: certs,
            assigned_values: HashMap::new(),
        }
    }

    fn assign_values(&mut self, certificate: &Value) {
        self.assigned_values
            .insert(certificate.digest(), certificate.clone());
    }

    fn assigned_values(&self) -> Vec<Value> {
        self.assigned_values
            .clone()
            .into_iter()
            .map(|v| v.1)
            .collect()
    }
}

struct Peers<PublicKey: VerifyingKey, Value: Hash + Clone> {
    peers: HashMap<PublicKey, Peer<PublicKey, Value>>,
    rebalanced: RefCell<bool>,
}

impl<PublicKey: VerifyingKey, Value: Hash + Clone> Peers<PublicKey, Value> {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            rebalanced: RefCell::new(false),
        }
    }

    fn unique_values(&self) -> Vec<Value> {
        let result: HashMap<<Value as Hash>::TypedDigest, Value> = self
            .peers
            .values()
            .flat_map(|v| {
                if *self.rebalanced.borrow() {
                    v.assigned_values.clone()
                } else {
                    v.values_able_to_serve.clone()
                }
            })
            .collect();

        result.into_iter().map(|(_, c)| c).collect()
    }

    fn contains_peer(&mut self, name: &PublicKey) -> bool {
        self.peers.contains_key(name)
    }

    fn add_peer(&mut self, name: PublicKey, available_values: Vec<Value>) {
        self.ensure_not_rebalanced();
        self.peers
            .insert(name.clone(), Peer::new(name, available_values));
    }

    /// Re-distributes the values to the peers in a load balanced manner.
    /// We expect to have duplicates across the peers. The goal is in the end
    /// for each peer to have a unique list of values and those lists to
    /// not differ significantly, so we balance the load.
    /// Once the peers are rebalanced, then no other operation that is allowed
    /// mutates the struct is allowed.
    fn rebalance_values(&mut self) {
        self.ensure_not_rebalanced();

        let values = self.unique_values();

        for v in values {
            self.reassign_value(v);
        }

        self.rebalanced.replace(true);
    }

    fn reassign_value(&mut self, value: Value) {
        self.ensure_not_rebalanced();

        let mut peer = self.peer_to_assign_value(&value);

        // step 5 - assign the value to this peer
        peer.assign_values(&value);

        self.peers.insert(peer.clone().name, peer);

        // step 6 - delete the values from all the peers where is found
        self.delete_values_from_peers(&value);
    }

    fn peer_to_assign_value(&mut self, value: &Value) -> Peer<PublicKey, Value> {
        self.ensure_not_rebalanced();

        let mut p = self.ordered_peers_have_value(value.digest());

        p.get_mut(0)
            .expect("Expected to have found at least one peer that can serve the value")
            .clone()
    }

    /// This method will perform two operations:
    /// 1) Will return only the peers that value dictated by the
    /// provided `value_id`
    /// 2) Will order the peers in ascending order based on their already
    /// assigned values and the ones able to serve.
    fn ordered_peers_have_value(
        &mut self,
        value_id: <Value as Hash>::TypedDigest,
    ) -> Vec<Peer<PublicKey, Value>> {
        self.ensure_not_rebalanced();

        // step 1 - find the peers who have this id
        let mut peers_with_value: Vec<Peer<PublicKey, Value>> = self
            .peers
            .iter()
            .filter(|p| p.1.values_able_to_serve.contains_key(&value_id))
            .map(|p| p.1.clone())
            .collect();

        peers_with_value.sort_by(|a, b| {
            // step 2 - order the peers in ascending order based on the number of
            // values they have been assigned + able to serve. We want to
            // prioritise those that have the smallest set of those.
            let a_size = a.assigned_values.len() + a.values_able_to_serve.len();
            let b_size = b.assigned_values.len() + b.values_able_to_serve.len();

            // if equal in size, compare on the assigned_values.
            // We want to prioritise then ones that have less already
            // assigned values so we give them the chance to start
            // getting some.
            match a_size.cmp(&b_size) {
                Ordering::Equal => {
                    match a.assigned_values.len().cmp(&b.assigned_values.len()) {
                        Ordering::Equal => {
                            // In case they are absolutely equal, we prioritise the one whose
                            // name is "less than" the other. This isn't really necessary, but
                            // it gives us some determinism.
                            a.name.cmp(&b.name)
                        }
                        other => other,
                    }
                }
                other => other,
            }
        });

        peers_with_value
    }

    // Deletes the provided certificate from the list of available
    // value from all the peers.
    fn delete_values_from_peers(&mut self, value: &Value) {
        self.ensure_not_rebalanced();

        for (_, peer) in self.peers.iter_mut() {
            peer.values_able_to_serve.remove(&value.digest());
        }
    }

    fn ensure_not_rebalanced(&mut self) {
        if *self.rebalanced.borrow() {
            panic!("rebalance has been called, this operation is not allowed");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::block_synchronizer::Peers;
    use blake2::{digest::Update, VarBlake2b};
    use crypto::{
        ed25519::{Ed25519KeyPair, Ed25519PublicKey},
        traits::KeyPair,
        Digest, Hash, DIGEST_LEN,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        borrow::Borrow,
        collections::{HashMap, HashSet},
        fmt,
    };

    #[test]
    fn test_assign_certificates_to_peers_when_all_respond() {
        struct TestCase {
            num_of_certificates: u8,
            num_of_peers: u8,
        }

        let test_cases: Vec<TestCase> = vec![
            TestCase {
                num_of_certificates: 5,
                num_of_peers: 4,
            },
            TestCase {
                num_of_certificates: 8,
                num_of_peers: 2,
            },
            TestCase {
                num_of_certificates: 3,
                num_of_peers: 2,
            },
            TestCase {
                num_of_certificates: 20,
                num_of_peers: 5,
            },
            TestCase {
                num_of_certificates: 10,
                num_of_peers: 1,
            },
        ];

        for test in test_cases {
            println!(
                "Testing case where num_of_certificates={} , num_of_peers={}",
                test.num_of_certificates, test.num_of_peers
            );
            let mut mock_certificates = Vec::new();

            for i in 0..test.num_of_certificates {
                mock_certificates.push(MockCertificate(i));
            }

            let mut rng = StdRng::from_seed([0; 32]);

            let mut peers = Peers::<Ed25519PublicKey, MockCertificate>::new();

            for _ in 0..test.num_of_peers {
                let key_pair = Ed25519KeyPair::generate(&mut rng);
                peers.add_peer(key_pair.public().clone(), mock_certificates.clone());
            }

            // WHEN
            peers.rebalance_values();

            // THEN
            assert_eq!(peers.peers.len() as u8, test.num_of_peers);

            // The certificates should be balanced to the peers.
            let mut seen_certificates = HashSet::new();

            for (_, peer) in peers.peers {
                // we want to ensure that a peer has got at least a certificate
                assert_ne!(
                    peer.assigned_values().len(),
                    0,
                    "Expected peer to have been assigned at least 1 certificate"
                );

                for c in peer.assigned_values() {
                    //println!("Cert for peer {}: {}", peer.name.encode_base64(), c.0);
                    assert!(
                        seen_certificates.insert(c.digest()),
                        "Certificate already assigned to another peer"
                    );
                }
            }

            // ensure that all the initial certificates have been assigned
            assert_eq!(
                seen_certificates.len(),
                mock_certificates.len(),
                "Returned certificates != Expected certificates"
            );

            for c in mock_certificates {
                assert!(
                    seen_certificates.contains(&c.digest()),
                    "Expected certificate not found in set of returned ones"
                );
            }
        }
    }

    #[test]
    fn test_assign_certificates_to_peers_when_all_respond_uniquely() {
        struct TestCase {
            num_of_certificates_each_peer: u8,
            num_of_peers: u8,
        }

        let test_cases: Vec<TestCase> = vec![
            TestCase {
                num_of_certificates_each_peer: 5,
                num_of_peers: 4,
            },
            TestCase {
                num_of_certificates_each_peer: 8,
                num_of_peers: 2,
            },
            TestCase {
                num_of_certificates_each_peer: 3,
                num_of_peers: 2,
            },
            TestCase {
                num_of_certificates_each_peer: 20,
                num_of_peers: 5,
            },
            TestCase {
                num_of_certificates_each_peer: 10,
                num_of_peers: 1,
            },
            TestCase {
                num_of_certificates_each_peer: 0,
                num_of_peers: 4,
            },
        ];

        for test in test_cases {
            println!(
                "Testing case where num_of_certificates_each_peer={} , num_of_peers={}",
                test.num_of_certificates_each_peer, test.num_of_peers
            );
            let mut mock_certificates_by_peer = HashMap::new();

            let mut rng = StdRng::from_seed([0; 32]);

            let mut peers = Peers::<Ed25519PublicKey, MockCertificate>::new();

            for peer_index in 0..test.num_of_peers {
                let key_pair = Ed25519KeyPair::generate(&mut rng);
                let peer_name = key_pair.public().clone();
                let mut mock_certificates = Vec::new();

                for i in 0..test.num_of_certificates_each_peer {
                    mock_certificates.push(MockCertificate(
                        i + (peer_index * test.num_of_certificates_each_peer),
                    ));
                }

                peers.add_peer(peer_name.clone(), mock_certificates.clone());

                mock_certificates_by_peer.insert(peer_name, mock_certificates.clone());
            }

            // WHEN
            peers.rebalance_values();

            // THEN
            assert_eq!(peers.peers.len() as u8, test.num_of_peers);

            // The certificates should be balanced to the peers.
            let mut seen_certificates = HashSet::new();

            for (_, peer) in peers.peers {
                // we want to ensure that a peer has got at least a certificate
                let peer_certs = mock_certificates_by_peer.get(&peer.name).unwrap();
                assert_eq!(
                    peer.assigned_values().len(),
                    peer_certs.len(),
                    "Expected peer to have been assigned the required certificates"
                );

                for c in peer.assigned_values() {
                    let found = peer_certs
                        .clone()
                        .into_iter()
                        .any(|c| c.digest().eq(&c.digest()));

                    assert!(found, "Assigned certificate not in set of expected");
                    assert!(
                        seen_certificates.insert(c.digest()),
                        "Certificate already assigned to another peer"
                    );
                }
            }
        }
    }

    // The mock certificate structure we'll use for our tests
    // It's easier to debug since the value is a u8 which can
    // be easily understood, print etc.
    #[derive(Clone)]
    struct MockCertificate(u8);

    #[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct MockDigest([u8; DIGEST_LEN]);

    impl From<MockDigest> for Digest {
        fn from(hd: MockDigest) -> Self {
            Digest::new(hd.0)
        }
    }

    impl fmt::Debug for MockDigest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            write!(f, "{}", base64::encode(&self.0))
        }
    }

    impl fmt::Display for MockDigest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            write!(f, "{}", base64::encode(&self.0).get(0..16).unwrap())
        }
    }

    impl Hash for MockCertificate {
        type TypedDigest = MockDigest;

        fn digest(&self) -> MockDigest {
            let v = self.0.borrow();

            let hasher_update = |hasher: &mut VarBlake2b| {
                hasher.update([*v].as_ref());
            };

            MockDigest(crypto::blake2b_256(hasher_update))
        }
    }
}
