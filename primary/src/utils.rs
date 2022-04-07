use crate::{BatchDigest, Certificate};
use config::WorkerId;
use crypto::traits::VerifyingKey;
use std::collections::HashMap;

// a helper method that collects all the batches from each certificate and maps
// them by the worker id.
pub fn map_certificate_batches_by_worker<PublicKey>(
    certificates: &[Certificate<PublicKey>],
) -> HashMap<WorkerId, Vec<BatchDigest>>
where
    PublicKey: VerifyingKey,
{
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
