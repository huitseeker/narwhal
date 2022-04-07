use crate::{
    block_synchronizer::{
        BlockSynchronizer, CertificatesResponse, Command, RequestID, StateCommand,
    },
    common::{
        certificate, create_db_stores, fixture_batch_with_transactions, fixture_header_builder,
        keys, resolve_name_and_committee,
    },
    primary::PrimaryMessage,
    BatchDigest, Certificate, CertificateDigest, PayloadToken,
};
use bincode::deserialize;
use config::WorkerId;
use crypto::{ed25519::Ed25519PublicKey, traits::VerifyingKey, Hash};
use ed25519_dalek::Signer;
use futures::{future::try_join_all, stream::FuturesUnordered, StreamExt};
use network::SimpleSender;
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use store::Store;
use tokio::{
    net::TcpListener,
    sync::mpsc::{channel, Sender},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::log::debug;

#[tokio::test]
async fn test_successful_block_synchronization() {
    // GIVEN
    let (_, _, payload_store) = create_db_stores();

    // AND the necessary keys
    let (name, committee) = resolve_name_and_committee(13001);

    let (tx_commands, rx_commands) = channel(10);
    let (tx_certificate_responses, rx_certificate_responses) = channel(10);

    // AND some blocks (certificates)
    let mut certificates: HashMap<CertificateDigest, Certificate<Ed25519PublicKey>> =
        HashMap::new();

    let key = keys().pop().unwrap();
    let worker_id_0 = 0;
    let worker_id_1 = 1;

    // AND generate headers with distributed batches between 2 workers (0 and 1)
    for _ in 0..8 {
        let batch_1 = fixture_batch_with_transactions(10);
        let batch_2 = fixture_batch_with_transactions(10);

        let header = fixture_header_builder()
            .with_payload_batch(batch_1.clone(), worker_id_0)
            .with_payload_batch(batch_2.clone(), worker_id_1)
            .build(|payload| key.sign(payload));

        let certificate = certificate(&header);

        certificates.insert(certificate.clone().digest(), certificate.clone());
    }

    // AND create the synchronizer
    BlockSynchronizer::spawn(
        name.clone(),
        committee.clone(),
        rx_commands,
        rx_certificate_responses,
        SimpleSender::new(),
        payload_store.clone(),
    );

    // AND the channel to respond to
    let (tx_synchronize, mut rx_synchronize) = channel(10);

    // AND let's assume that all the primaries are responding with the full set
    // of requested certificates.
    let handlers = FuturesUnordered::new();
    for primary in committee.others_primaries(&name) {
        println!("New primary added: {:?}", primary.1.primary_to_primary);

        let handler = primary_listener::<Ed25519PublicKey>(
            primary.0,
            primary.1.primary_to_primary,
            certificates.clone(),
            tx_certificate_responses.clone(),
            payload_store.clone(),
        );
        handlers.push(handler);
    }

    // WHEN
    tx_commands
        .send(Command::SynchroniseBlocks {
            block_ids: certificates.keys().copied().collect(),
            respond_to: tx_synchronize,
        })
        .await
        .ok()
        .unwrap();

    // wait for the primaries to receive all the requests
    if timeout(Duration::from_millis(4_000), try_join_all(handlers))
        .await
        .is_err()
    {
        panic!("primaries haven't received expected requests")
    }

    // THEN
    let timer = sleep(Duration::from_millis(5_000));
    tokio::pin!(timer);

    let total_expected_results = certificates.len();
    let mut total_results_received = 0;

    loop {
        tokio::select! {
            Some(result) = rx_synchronize.recv() => {
                assert!(result.is_ok(), "Error result received: {:?}", result.err().unwrap());

                if result.is_ok() {
                    let certificate = result.ok().unwrap();

                    println!("Received certificate result: {:?}", certificate.clone());

                    assert!(certificates.contains_key(&certificate.digest()));

                    total_results_received += 1;
                }

                if total_results_received == total_expected_results {
                    break;
                }
            },
            () = &mut timer => {
                panic!("Timeout, no result has been received in time")
            }
        }
    }
}

#[tokio::test]
async fn test_await_for_certificate_responses_from_majority() {
    // GIVEN
    // let (_, _, payload_store) = create_db_stores();

    // AND the necessary keys
    let (name, committee) = resolve_name_and_committee(13001);

    let (tx_certificate_responses, rx_certificate_responses) = channel(10);

    // AND some blocks (certificates)
    let mut certificates: HashMap<CertificateDigest, Certificate<Ed25519PublicKey>> =
        HashMap::new();

    let key = keys().pop().unwrap();

    // AND generate headers with distributed batches between 2 workers (0 and 1)
    for _ in 0..5 {
        let header = fixture_header_builder()
            .with_payload_batch(fixture_batch_with_transactions(10), 0)
            .build(|payload| key.sign(payload));

        let certificate = certificate(&header);

        certificates.insert(certificate.clone().digest(), certificate.clone());
    }

    let block_ids: Vec<CertificateDigest> = certificates.keys().copied().collect();

    let request_id = RequestID::from(block_ids.as_slice());

    let primaries = committee.others_primaries(&name);

    let certificates_to_be_sent: Vec<(CertificateDigest, Option<Certificate<Ed25519PublicKey>>)> =
        certificates
            .iter()
            .map(|e| (*e.0, Some(e.1.clone())))
            .collect();

    // AND send the responses from all the primaries
    for primary in primaries.clone() {
        let name = primary.0;

        tx_certificate_responses
            .send(CertificatesResponse {
                certificates: certificates_to_be_sent.clone(),
                from: name,
            })
            .await
            .unwrap();
    }

    let result = BlockSynchronizer::await_for_certificate_responses(
        request_id,
        committee.clone(),
        block_ids,
        primaries.into_iter().map(|(name, _)| name).collect(),
        rx_certificate_responses,
    )
    .await;

    match result {
        StateCommand::SynchronizeBatches { request_id, peers } => {
            assert_eq!(request_id, request_id);

            // we expect to have "exited" when 2 responses have been received
            // since this is the 50% of the total of peers.
            assert_eq!(peers.peers.len(), 2);

            // ensure that each peer has the requested certificates
            for (_, peer) in peers.peers {
                assert_eq!(
                    peer.values_able_to_serve.len(),
                    certificates.len(),
                    "Mismatch in certificates responded than expected"
                );

                for (digest, _) in peer.values_able_to_serve {
                    assert!(
                        certificates.contains_key(&digest),
                        "Certificate not expected"
                    );
                }
            }
        }
        _ => {
            panic!("Expected to receive a successful synchronize batches command");
        }
    }
}

pub fn primary_listener<PublicKey: VerifyingKey>(
    name: PublicKey,
    address: SocketAddr,
    expected_certificates: HashMap<CertificateDigest, Certificate<PublicKey>>,
    tx_certificate_responses: Sender<CertificatesResponse<PublicKey>>,
    payload_store: Store<(BatchDigest, WorkerId), PayloadToken>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        println!("[{}] Setting up server", &address);

        let listener = TcpListener::bind(&address).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let transport = Framed::new(socket, LengthDelimitedCodec::new());

        let (_, mut reader) = transport.split();
        match reader.next().await {
            Some(Ok(received)) => {
                let message = received.freeze();
                match deserialize(&message) {
                    Ok(PrimaryMessage::<PublicKey>::CertificatesBatchRequest {
                        certificate_ids,
                        requestor,
                    }) => {
                        debug!("{:?}", requestor);

                        let mut response_certificates: Vec<(
                            CertificateDigest,
                            Option<Certificate<PublicKey>>,
                        )> = Vec::new();

                        for c_id in certificate_ids {
                            let cert_option = expected_certificates.get(&c_id);

                            assert!(
                                cert_option.is_some(),
                                "Received certificate not amongst the expected"
                            );

                            let certificate = cert_option.unwrap().clone();

                            response_certificates.push((c_id, Some(certificate.clone())));

                            // write the payload to store and imitate a sync with the workers
                            for (digest, worker_id) in certificate.header.payload {
                                payload_store.write((digest, worker_id), 1).await;
                            }
                        }

                        tx_certificate_responses
                            .send(CertificatesResponse {
                                certificates: response_certificates,
                                from: name.clone(),
                            })
                            .await
                            .unwrap();
                    }
                    _ => panic!("Unexpected request received"),
                };
            }
            _ => panic!("Failed to receive network message"),
        }
    })
}
