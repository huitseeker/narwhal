// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crypto::{traits::VerifyingKey, Hash};
use rand::{prelude::SliceRandom as _, rngs::SmallRng};
use std::collections::HashMap;

#[derive(Clone)]
pub struct Peer<PublicKey: VerifyingKey, Value: Hash + Clone> {
    pub name: PublicKey,

    /// Those are the values that we got from the peer and that is able
    /// to serve.
    pub values_able_to_serve: HashMap<<Value as Hash>::TypedDigest, Value>,

    /// Those are the assigned values after a re-balancing event
    assigned_values: HashMap<<Value as Hash>::TypedDigest, Value>,
}

impl<PublicKey: VerifyingKey, Value: Hash + Clone> Peer<PublicKey, Value> {
    pub fn new(name: PublicKey, values_able_to_serve: Vec<Value>) -> Self {
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

    pub fn assign_values(&mut self, certificate: &Value) {
        self.assigned_values
            .insert(certificate.digest(), certificate.clone());
    }

    pub fn assigned_values(&self) -> Vec<Value> {
        self.assigned_values
            .clone()
            .into_iter()
            .map(|v| v.1)
            .collect()
    }
}

/// A helper structure to allow us store the peer result values
/// and redistribute the common ones between them evenly.
pub struct Peers<PublicKey: VerifyingKey, Value: Hash + Clone> {
    /// A map with all the peers assigned on this pool.
    peers: HashMap<PublicKey, Peer<PublicKey, Value>>,

    /// When true, it means that the values have been assigned to peers and no
    /// more mutating operations can be applied
    rebalanced: bool,

    /// An rng used to shuffle the list of peers
    rng: SmallRng,
}

impl<PublicKey: VerifyingKey, Value: Hash + Clone> Peers<PublicKey, Value> {
    pub fn new(rng: SmallRng) -> Self {
        Self {
            peers: HashMap::new(),
            rebalanced: false,
            rng,
        }
    }

    pub fn peers(&self) -> HashMap<PublicKey, Peer<PublicKey, Value>> {
        self.peers.to_owned()
    }

    /// Iterates over all the peer responses and retrieves the unique
    /// values (identified by their digest).
    pub fn unique_values(&self) -> Vec<Value> {
        let result: HashMap<<Value as Hash>::TypedDigest, Value> = self
            .peers
            .values()
            .flat_map(|v| {
                if self.rebalanced {
                    v.assigned_values.clone()
                } else {
                    v.values_able_to_serve.clone()
                }
            })
            .collect();

        result.into_iter().map(|(_, c)| c).collect()
    }

    pub fn contains_peer(&mut self, name: &PublicKey) -> bool {
        self.peers.contains_key(name)
    }

    pub fn add_peer(&mut self, name: PublicKey, available_values: Vec<Value>) {
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
    pub fn rebalance_values(&mut self) {
        self.ensure_not_rebalanced();

        let values = self.unique_values();

        for v in values {
            self.reassign_value(v);
        }

        self.rebalanced = true;
    }

    fn reassign_value(&mut self, value: Value) {
        let mut peer = self.peer_to_assign_value(&value);

        peer.assign_values(&value);

        self.peers.insert(peer.clone().name, peer);

        self.delete_values_from_peers(&value);
    }

    fn peer_to_assign_value(&mut self, value: &Value) -> Peer<PublicKey, Value> {
        let mut p = self.peers_have_value_shuffled(value.digest());

        p.get_mut(0)
            .expect("Expected to have found at least one peer that can serve the value")
            .clone()
    }

    /// This method will perform two operations:
    /// 1) Will return only the peers that value dictated by the
    /// provided `value_id`
    /// 2) Will shuffle the peers so the are ordered randomly
    fn peers_have_value_shuffled(
        &mut self,
        value_id: <Value as Hash>::TypedDigest,
    ) -> Vec<Peer<PublicKey, Value>> {
        // step 1 - find the peers who have this id
        let mut peers_with_value: Vec<Peer<PublicKey, Value>> = self
            .peers
            .iter()
            .filter(|p| p.1.values_able_to_serve.contains_key(&value_id))
            .map(|p| p.1.clone())
            .collect();

        // step 2 - shuffle the peers so we can later pick one in random.
        // For now we consider this good enough and we avoid doing any
        // explicit client-side load balancing as this should be tackled
        // on the server-side via demand control.
        peers_with_value.shuffle(&mut self.rng);

        peers_with_value
    }

    // Deletes the provided certificate from the list of available
    // value from all the peers.
    fn delete_values_from_peers(&mut self, value: &Value) {
        for (_, peer) in self.peers.iter_mut() {
            peer.values_able_to_serve.remove(&value.digest());
        }
    }

    fn ensure_not_rebalanced(&mut self) {
        if self.rebalanced {
            panic!("rebalance has been called, this operation is not allowed");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::block_synchronizer::peers::Peers;
    use blake2::{digest::Update, VarBlake2b};
    use crypto::{
        ed25519::{Ed25519KeyPair, Ed25519PublicKey},
        traits::KeyPair,
        Digest, Hash, DIGEST_LEN,
    };
    use rand::{
        rngs::{SmallRng, StdRng},
        SeedableRng,
    };
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

            let mut peers =
                Peers::<Ed25519PublicKey, MockCertificate>::new(SmallRng::from_entropy());

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

            for (_, peer) in peers.peers() {
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

            let mut peers =
                Peers::<Ed25519PublicKey, MockCertificate>::new(SmallRng::from_entropy());

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
            assert_eq!(peers.peers().len() as u8, test.num_of_peers);

            // The certificates should be balanced to the peers.
            let mut seen_certificates = HashSet::new();

            for (_, peer) in peers.peers() {
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
