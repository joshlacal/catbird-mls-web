//! Protected proof of an exact accepted outbound application. Public MLS
//! framing is never an own-echo authority without this durable record.
use super::*;
use catbird_mls::orchestrator::mls_provider::OwnEchoProof;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProof {
    accepted_request_sha256: [u8; 32],
    conversation_id: String,
    group_id: Vec<u8>,
    server_entry_id: String,
    mls_epoch: u64,
    aad_sha256: [u8; 32],
    ciphertext_sha256: [u8; 32],
}
impl WasmMLSContext {
    pub(super) fn protect_own_echo(&self, p: &OwnEchoProof) -> Result<(), MLSError> {
        catbird_mls::chat_v2::ids::CanonicalUuid::parse(&p.conversation_id)
            .map_err(|_| MLSError::StorageFailed)?;
        catbird_mls::chat_v2::ids::CanonicalUuid::parse(&p.server_entry_id)
            .map_err(|_| MLSError::StorageFailed)?;
        if p.group_id.len() != 32
            || p.mls_epoch > 9_007_199_254_740_991
            || p.canonical_entry_sha256
                != OwnEchoProof::compute_canonical_entry_sha256(
                    &p.conversation_id,
                    &p.group_id,
                    &p.server_entry_id,
                    p.mls_epoch,
                    &p.aad_sha256,
                    &p.ciphertext_sha256,
                )
        {
            return Err(MLSError::StorageFailed);
        }
        let record = StoredProof {
            accepted_request_sha256: p.accepted_request_sha256,
            conversation_id: p.conversation_id.clone(),
            group_id: p.group_id.clone(),
            server_entry_id: p.server_entry_id.clone(),
            mls_epoch: p.mls_epoch,
            aad_sha256: p.aad_sha256,
            ciphertext_sha256: p.ciphertext_sha256,
        };
        let raw = serde_json::to_vec(&record).map_err(|_| MLSError::StorageFailed)?;
        if let Some(old) = self.request_value("ownEcho", &p.server_entry_id)? {
            return if old == raw {
                Ok(())
            } else {
                Err(MLSError::StorageFailed)
            };
        }
        if !self.request_value_cas("ownEcho", &p.server_entry_id, None, &raw)? {
            return Err(MLSError::StorageFailed);
        }
        Ok(())
    }
    pub(super) fn protected_own_echo(
        &self,
        cid: &str,
        gid: &[u8],
        entry: &str,
        epoch: u64,
        aad: &[u8; 32],
        ciphertext: &[u8; 32],
    ) -> Result<bool, MLSError> {
        let Some(raw) = self.request_value("ownEcho", entry)? else {
            return Ok(false);
        };
        let record: StoredProof =
            serde_json::from_slice(&raw).map_err(|_| MLSError::StorageFailed)?;
        Ok(record.conversation_id == cid
            && record.group_id == gid
            && record.server_entry_id == entry
            && record.mls_epoch == epoch
            && record.aad_sha256 == *aad
            && record.ciphertext_sha256 == *ciphertext)
    }
}
