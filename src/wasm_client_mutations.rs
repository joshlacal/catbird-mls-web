//! Async `mls-ds` `/xrpc/blue.catbird.chat.*` mutations for `WasmMlsClient` (`Spec §6.3`, `I4`, `I6`, `I13`, `C33`).
//!
//! Every network call executes strictly outside `WasmAccountDb::write_tx` (`I6`).

use std::collections::BTreeSet;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use catbird_mls::canonical_transport::{
    canonical_application_aad_bytes, canonical_commit_aad_bytes, derive_key_id,
    is_transient_wire_failure, CanonicalOperation,
};
use catbird_mls::chat_v2::ids::BareDid;
use catbird_mls::chat_v2::transcript::direct_request as dr_transcript;
use catbird_mls::chat_v2::transcript::SignedMutationKind;
use catbird_mls::client::chat_wire;
use catbird_mls::client::{
    normalize_account_did, LeaveConversationOutcome, QueuedLabyrinthArchivePayload,
    UploadedConversationAttachment,
};
use catbird_mls::direct_request_keys::{
    DirectRequestKeyPublication, DirectRequestKeyPublicationInput,
};
use catbird_mls::direct_request_shared_crypto::build_request_key_publication;
use catbird_mls::groups::lifecycle::{enforce_admin_removal_policy, MemberRole};
use catbird_mls::groups::metadata_v1::validate_metadata_snapshot_size;
use catbird_mls::messaging::receive::{
    OriginalSenderArchiveAttestationEnvelope, PrivateMessageAadEnvelope,
    PrivateMessagePlaintextEnvelope,
};
use catbird_mls::metadata::{
    derive_metadata_key_from_group, encrypt_metadata_snapshot_with_nonce, GroupMetadataV1,
};
use catbird_mls::payload_types::{MLSAudioEmbed, MLSEmbedData, MLSImageEmbed, MLSMessagePayload};
use catbird_mls::storage::driver_wasm::WasmSqlBackend;
use catbird_mls::storage::{
    ConversationRow, GroupMetadataRow, KvWriteOverlay, MessageRow, OpenMlsKvProvider,
    OpenMlsKvStorage,
};
use catbird_mls::MLSError;

use crate::wasm_archive_policy;
use crate::wasm_client_sync::{apply_verified_roster_effects, store_roster};

use crate::wasm_client::{now_ms, now_secs, WasmMlsClient, CIPHERSUITE};

pub(crate) fn canonical_labyrinth_frame_for_text(input: &str) -> (String, String) {
    if let Ok(value) = serde_json::from_str::<Value>(input) {
        if value.get("text").and_then(Value::as_str).is_some() {
            let mut frame: Value =
                serde_json::from_str(&chat_wire::canonical_labyrinth_frame_json(input))
                    .unwrap_or_else(|_| value.clone());
            // A simple `{text, noBackup}` display object is upgraded to a typed MLS frame by
            // chat_wire. Carry its explicit sender veto across that normalization.
            if let (Some(no_backup), Some(object)) = (value.get("noBackup"), frame.as_object_mut())
            {
                object.insert("noBackup".into(), no_backup.clone());
            }
            return (input.to_string(), frame.to_string());
        }
    }
    let display = json!({ "text": input }).to_string();
    let frame_out = chat_wire::canonical_labyrinth_frame_json(&display);
    (display, frame_out)
}

/// Parses a client-generated ID that must be a UUIDv4 (`InvalidInput` otherwise).
fn uuid_v4(raw: &str, field: &str) -> Result<uuid::Uuid, MLSError> {
    uuid::Uuid::parse_str(raw.trim())
        .ok()
        .filter(|u| {
            u.get_version() == Some(uuid::Version::Random)
                && u.get_variant() == uuid::Variant::RFC4122
        })
        .ok_or_else(|| MLSError::invalid_input(format!("{field} must be a UUIDv4")))
}
/// Encrypted `account_meta` journal and global operation-id index for exact creation replay.
fn group_creation_key(operation_id: &str) -> String {
    format!("group_creation:{operation_id}")
}

const GROUP_CREATIONS_KEY: &str = "group_creations";

fn group_creation_operation_ids(tx: &impl WasmSqlBackend) -> Result<Vec<String>, MLSError> {
    tx.get_account_meta(GROUP_CREATIONS_KEY)?
        .map(|raw| serde_json::from_str(&raw))
        .transpose()
        .map(Option::unwrap_or_default)
        .map_err(|e| MLSError::Internal(format!("parse group creation journal index: {e}")))
}

fn group_creation_for_conversation(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
) -> Result<Option<(String, String)>, MLSError> {
    let mut found = None;
    for operation_id in group_creation_operation_ids(tx)? {
        let Some(raw) = tx.get_account_meta(&group_creation_key(&operation_id))? else {
            continue;
        };
        let pending: chat_wire::PendingGroupCreation = serde_json::from_str(&raw)
            .map_err(|e| MLSError::Internal(format!("parse group creation journal: {e}")))?;
        if pending.conversation_id == conversation_id {
            if found.is_some() {
                return Err(MLSError::InvalidState(
                    "multiple pending creations for one conversation".into(),
                ));
            }
            found = Some((operation_id, raw));
        }
    }
    Ok(found)
}

fn put_group_creation(
    tx: &impl WasmSqlBackend,
    pending: &chat_wire::PendingGroupCreation,
) -> Result<bool, MLSError> {
    if group_creation_for_conversation(tx, &pending.conversation_id)?.is_some() {
        return Ok(false);
    }
    let key = group_creation_key(&pending.journal_id);
    if tx.get_account_meta(&key)?.is_some() {
        return Err(MLSError::InvalidState(
            "group creation operation id already exists".into(),
        ));
    }
    tx.put_account_meta(
        &key,
        &serde_json::to_string(pending)?,
        pending.created_at_ms,
    )?;
    let mut operation_ids = group_creation_operation_ids(tx)?;
    operation_ids.push(pending.journal_id.clone());
    operation_ids.sort();
    tx.put_account_meta(
        GROUP_CREATIONS_KEY,
        &serde_json::to_string(&operation_ids)?,
        pending.created_at_ms,
    )?;
    Ok(true)
}

fn remove_group_creation_operation(
    tx: &impl WasmSqlBackend,
    operation_id: &str,
) -> Result<(), MLSError> {
    tx.delete_account_meta(&group_creation_key(operation_id))?;
    let mut operation_ids = group_creation_operation_ids(tx)?;
    operation_ids.retain(|id| id != operation_id);
    if operation_ids.is_empty() {
        tx.delete_account_meta(GROUP_CREATIONS_KEY)
    } else {
        tx.put_account_meta(
            GROUP_CREATIONS_KEY,
            &serde_json::to_string(&operation_ids)?,
            now_ms(),
        )
    }
}

pub(crate) fn remove_group_creation_journal(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
) -> Result<(), MLSError> {
    if let Some((operation_id, _)) = group_creation_for_conversation(tx, conversation_id)? {
        remove_group_creation_operation(tx, &operation_id)?;
    }
    Ok(())
}

/// Send journal: the exact signed body and archive copy of one candidate MLS generation, written
/// with the sender-ratchet advance before HTTP. The accepted-counter watermark advances only
/// after a verified response/echo or `StaleSend` proof.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingApplicationSend {
    pub(crate) body: Value,
    pub(crate) archive: QueuedLabyrinthArchivePayload,
}

/// `account_meta` key of the send journal for `message_id` in `conversation_id`.
pub(crate) fn pending_send_key(conversation_id: &str, message_id: &str) -> String {
    format!("application_send:{conversation_id}:{message_id}")
}

/// `account_meta` journal of this device's own Commit-bearing transition `transition_id` in
/// `conversation_id`: JSON of [`chat_wire::PendingCommitTransition`], written before HTTP. A
/// verified answer applies it ([`WasmMlsClient::submit_own_commit`]); otherwise the own echo in
/// sync, looked up by its signed `transitionId`, does. Keyed per transition so a later attempt
/// never replaces an earlier one that `mls-ds` may already have sequenced.
fn commit_transition_key(conversation_id: &str, transition_id: &str) -> String {
    format!("commit_transition:{conversation_id}:{transition_id}")
}

/// `account_meta` index of `conversation_id`'s outstanding own-Commit journals: a JSON array of
/// transition ids, written in the same transaction as each journal and absent when none.
fn commit_transitions_key(conversation_id: &str) -> String {
    format!("commit_transitions:{conversation_id}")
}

fn commit_transition_ids(tx: &impl WasmSqlBackend, cid: &str) -> Result<Vec<String>, MLSError> {
    tx.get_account_meta(&commit_transitions_key(cid))?
        .map(|raw| serde_json::from_str(&raw))
        .transpose()
        .map(Option::unwrap_or_default)
        .map_err(|e| MLSError::Internal(format!("parse own-Commit journal index: {e}")))
}

fn put_commit_transition_ids(
    tx: &impl WasmSqlBackend,
    cid: &str,
    ids: &[String],
) -> Result<(), MLSError> {
    let key = commit_transitions_key(cid);
    if ids.is_empty() {
        return tx.delete_account_meta(&key);
    }
    tx.put_account_meta(&key, &serde_json::to_string(ids)?, now_ms())
}

/// Journal `pending` and list it in its conversation's index, in the caller's transaction.
fn put_commit_transition(
    tx: &impl WasmSqlBackend,
    pending: &chat_wire::PendingCommitTransition,
) -> Result<(), MLSError> {
    let (cid, id) = (&pending.conversation_id, &pending.transition_id);
    let raw = serde_json::to_string(pending)
        .map_err(|e| MLSError::Internal(format!("serialize pending commit: {e}")))?;
    tx.put_account_meta(&commit_transition_key(cid, id), &raw, now_ms())?;
    let mut ids = commit_transition_ids(tx, cid)?;
    if !ids.contains(id) {
        ids.push(id.clone());
    }
    put_commit_transition_ids(tx, cid, &ids)
}

/// `cid`'s outstanding journal of own transition `transition_id`.
pub(crate) fn get_commit_transition(
    tx: &impl WasmSqlBackend,
    cid: &str,
    transition_id: &str,
) -> Result<Option<chat_wire::PendingCommitTransition>, MLSError> {
    tx.get_account_meta(&commit_transition_key(cid, transition_id))?
        .map(|raw| serde_json::from_str(&raw))
        .transpose()
        .map_err(|e| MLSError::Internal(format!("parse pending commit: {e}")))
}

/// Erase `cid`'s journal of `transition_id` and unlist it, in the caller's transaction.
fn remove_commit_transition(
    tx: &impl WasmSqlBackend,
    cid: &str,
    transition_id: &str,
) -> Result<(), MLSError> {
    tx.delete_account_meta(&commit_transition_key(cid, transition_id))?;
    let mut ids = commit_transition_ids(tx, cid)?;
    ids.retain(|id| id != transition_id);
    put_commit_transition_ids(tx, cid, &ids)
}

/// Erase, in the caller's transaction, every `cid` journal staged from a prior the local MLS
/// state `(generation, epoch)` has moved past (an older generation, or the same generation at
/// an older epoch), or all of them once this device is removed or the conversation closed:
/// their staged epoch keys can never land and must not linger.
pub(crate) fn prune_commit_transitions(
    tx: &impl WasmSqlBackend,
    cid: &str,
    generation: i64,
    epoch: i64,
    removed: bool,
) -> Result<(), MLSError> {
    for id in commit_transition_ids(tx, cid)? {
        let superseded = get_commit_transition(tx, cid, &id)?.is_none_or(|pending| {
            let prior = &pending.prior;
            removed
                || (
                    prior["generation"].as_i64().unwrap_or_default(),
                    prior["epoch"].as_i64().unwrap_or_default(),
                ) < (generation, epoch)
        });
        if superseded {
            remove_commit_transition(tx, cid, &id)?;
        }
    }
    Ok(())
}

/// `account_meta` journal of this device's signed close of `conversation_id`: the exact
/// `signedRequest` JSON, written before HTTP and only ever replayed byte for byte.
pub(crate) fn conversation_close_key(conversation_id: &str) -> String {
    format!("conversation_close:{conversation_id}")
}

/// Whether `mls-ds` refused a POST for good: a semantic 4xx (e.g. `StaleCoordinates`) in a
/// `ds_post_json` failure ("POST <nsid> returned HTTP <status>: <body>"). A lost answer, a 5xx,
/// a transient refusal (`408`, `425`, `429`, `CapacityUnavailable`) or an unverifiable 2xx is not.
pub(crate) fn is_terminal_refusal(error: &MLSError) -> bool {
    let MLSError::Internal(message) = error else {
        return false;
    };
    let Some((status, body)) = message
        .split_once(" returned HTTP ")
        .and_then(|(_, rest)| rest.split_once(": "))
    else {
        return false;
    };
    let Ok(status) = status.parse::<u16>() else {
        return false;
    };
    let failure = serde_json::from_str::<Value>(body).ok();
    let code = failure.as_ref().and_then(|f| f["error"].as_str());
    (400..500).contains(&status) && !is_transient_wire_failure(status, code)
}

/// The 2xx answer to this device's close `sent` (the exact `signedRequest` it POSTed): a
/// `conversationCloseEntry` of `conversation_id` carrying exactly that signed request. Returns
/// the entry seq.
fn verify_own_close_answer(
    answer: &Value,
    sent: &Value,
    conversation_id: &str,
) -> Result<i64, MLSError> {
    let refused =
        |what: String| MLSError::Cryptography(format!("unverified answer to own close: {what}"));
    let read = |value: &Value, name: &str| -> Result<Value, MLSError> {
        dr_transcript::normalize_read_presentation(&serde_json::to_vec(value)?, name, false)
            .map_err(|e| refused(format!("{name}: {e}")))
    };
    let answer = answer.get("result").unwrap_or(answer);
    let mut entry = answer["entry"].clone();
    let (tag, _) = entry
        .as_object_mut()
        .map(|fields| (fields.remove("$type"), fields.remove("sequencerReceipt")))
        .unwrap_or_default();
    let entry = read(&entry, "conversationCloseEntry")?;
    if tag != Some(json!("blue.catbird.chat.defs#conversationCloseEntry"))
        || entry["conversationId"] != conversation_id
        || entry["signedRequest"] != read(sent, "signedConversationClose")?
    {
        return Err(refused(
            "its entry is not this device's signed close".into(),
        ));
    }
    entry["seq"]
        .as_i64()
        .ok_or_else(|| refused("entry seq".into()))
}

impl WasmMlsClient {
    /// `mls-ds` bootstrap, mirroring catbird-mls `enroll_device_live`: completion is bound to
    /// `auth_generation`, the canonical device ID and signer key. A retry after a lost response
    /// resumes: `enrollDevice` is create-only and request-key revisions must advance by one, so it
    /// confirms what the DS already holds. The PDS device and declaration records are written only
    /// after `mls-ds` holds this device under this exact key, so a device ID registered under
    /// another key keeps its PDS record.
    pub(crate) async fn enroll_device_live(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<(), MLSError> {
        let db = self.require_db_mls()?;
        let pub_key = signer.public();
        let key_id = derive_key_id(pub_key);
        let enrollment_status = db.backend().get_account_meta("enrollment_status")?;
        let was_pending_approval = enrollment_status.as_deref() == Some("pending_approval");
        if let Some(auth_generation) = db.backend().get_account_meta("auth_generation")? {
            let bound_device = db.backend().get_account_meta("enrolled_device_id")?;
            let bound_key = db.backend().get_account_meta("enrolled_signer_key_id")?;
            if bound_device
                .as_deref()
                .is_some_and(|bound| bound != canonical_dev_id)
                || bound_key
                    .as_deref()
                    .is_some_and(|bound| bound != key_id.as_str())
            {
                return Err(MLSError::InvalidState(
                    "EnrollmentDeviceIdentityMismatch".into(),
                ));
            }
            if bound_device.as_deref() == Some(canonical_dev_id)
                && bound_key.as_deref() == Some(key_id.as_str())
                && !was_pending_approval
            {
                return Ok(());
            }
            if bound_key.is_none() {
                let devices = self
                    .ds_signed_get(
                        session_token,
                        canonical_dev_id,
                        "blue.catbird.chat.getOwnDevices",
                        &[("actorDeviceId", canonical_dev_id), ("limit", "100")],
                        signer,
                    )
                    .await?;
                let own = own_enrolled_device_entry(&devices, canonical_dev_id, pub_key)
                    .ok_or_else(|| {
                        MLSError::InvalidState("EnrollmentDeviceIdentityMismatch".into())
                    })?;
                if own
                    .pointer("/device/authGeneration")
                    .or_else(|| own.get("authGeneration"))
                    .and_then(Value::as_i64)
                    != auth_generation.parse::<i64>().ok()
                {
                    return Err(MLSError::InvalidState(
                        "EnrollmentDeviceIdentityMismatch".into(),
                    ));
                }
                let ts = now_ms();
                db.write_tx(|tx| {
                    tx.put_account_meta("enrolled_device_id", canonical_dev_id, ts)?;
                    tx.put_account_meta("enrolled_signer_key_id", &key_id, ts)
                })?;
                return Ok(());
            }
        }

        let now_s = now_secs();
        let key_packages_json = db.write_tx(|tx| {
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
            let scoped_id = format!("{}#{}", self.account_did, canonical_dev_id);
            let cred_with_key = CredentialWithKey {
                credential: BasicCredential::new(scoped_id.into_bytes()).into(),
                signature_key: pub_key.into(),
            };
            let caps = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[CIPHERSUITE]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            let mut items: Vec<(Vec<u8>, Value)> = Vec::with_capacity(2);
            for _ in 0..2 {
                let kp_bundle = KeyPackage::builder()
                    .key_package_lifetime(Lifetime::init(
                        now_s.saturating_sub(60),
                        now_s + 29 * 86_400,
                    ))
                    .leaf_node_capabilities(caps.clone())
                    .build(CIPHERSUITE, &provider, signer, cred_with_key.clone())
                    .map_err(|e| MLSError::Cryptography(format!("build enroll KP: {e:?}")))?;
                let kp_bytes = MlsMessageOut::from(kp_bundle.key_package().clone())
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize enroll KP: {e:?}")))?;
                let kp_ref = kp_bundle
                    .key_package()
                    .hash_ref(provider.crypto())
                    .map_err(|e| MLSError::Cryptography(format!("hash_ref: {e:?}")))?
                    .as_slice()
                    .to_vec();
                let entry = json!({
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": { "$bytes": STANDARD.encode(&kp_bytes) },
                    "sha256": STANDARD.encode(Sha256::digest(&kp_bytes)),
                    "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                });
                items.push((kp_ref, entry));
            }
            items.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(items.into_iter().map(|(_, v)| v).collect::<Vec<_>>())
        })?;

        let idem = uuid::Uuid::new_v4().to_string();
        let enroll_body = json!({
            "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\0",
            "actorDid": self.account_did,
            "deviceId": canonical_dev_id,
            "deviceName": "Catmos Web",
            "keyId": key_id,
            "signaturePublicKey": { "$bytes": STANDARD.encode(pub_key) },
            "expectedAuthGeneration": 0,
            "capability": {
                "protocolVersion": "1",
                "mlsVersion": "1.0",
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "credentialType": "basic",
                "addByValue": "supported",
                "updatePath": "supported",
                "removeByValue": "supported",
                "ratchetTreeGroupInfo": "supported",
                "externalPubGroupInfo": "presentButExternalCommitsForbidden",
                "applicationFrameProfile": "dagCborApplication1",
                "controlProfile": "publicGroup1",
                "attachmentProfile": "aes256GcmBlob1",
                "metadataProfile": "exporterAes256Gcm1",
                "typingProfile": "signedClearEphemeral1"
            },
            "keyPackages": key_packages_json,
            "idempotencyKey": idem,
            "signedAt": chat_wire::now_rfc3339_millis(),
        });

        let (enroll_resp, request_keys_published) = match self
            .submit_signed_chat_op(
                session_token,
                canonical_dev_id,
                None,
                CanonicalOperation::EnrollDevice,
                &enroll_body,
                signer,
            )
            .await
        {
            Ok(resp) => (resp, false),
            // An earlier attempt registered this device, but its response was lost.
            Err(e) if e.to_string().contains(r#""error":"DeviceAlreadyExists""#) => {
                // ponytail: first page only (100 items; accounts hold at most 20 active
                // devices); follow `nextPageCursor` if revoked devices ever push this one past it.
                let devices = self
                    .ds_signed_get(
                        session_token,
                        canonical_dev_id,
                        "blue.catbird.chat.getOwnDevices",
                        &[("actorDeviceId", canonical_dev_id), ("limit", "100")],
                        signer,
                    )
                    .await?;
                let own = own_enrolled_device_entry(&devices, canonical_dev_id, pub_key)
                    .cloned()
                    .ok_or_else(|| {
                        MLSError::InvalidState(format!(
                            "DeviceAlreadyExists: mls-ds holds device {canonical_dev_id} under another key"
                        ))
                    })?;
                let published = own.get("directRequestKeyPool").is_some();
                (own, published)
            }
            Err(e) => return Err(e),
        };
        let dev_view = enroll_resp.get("device").unwrap_or(&enroll_resp);
        let status_str = dev_view["status"].as_str().unwrap_or("");
        let auth_gen = dev_view
            .get("authGeneration")
            .and_then(Value::as_i64)
            .or_else(|| enroll_resp.get("authGeneration").and_then(Value::as_i64))
            .filter(|g| *g >= 1)
            .ok_or_else(|| {
                MLSError::Internal("enrollDevice response missing valid authGeneration >= 1".into())
            })?;
        // The key-mismatch check precedes every PDS write: a fresh answer or an adopted
        // enrollment naming another device or key leaves both PDS records untouched.
        if own_enrolled_device_entry(
            &json!({ "items": [&enroll_resp] }),
            canonical_dev_id,
            pub_key,
        )
        .is_none()
        {
            return Err(MLSError::InvalidState(
                "EnrollmentDeviceIdentityMismatch".into(),
            ));
        }
        let is_pending_approval = status_str == "pending_approval";

        let dev_rec = chat_wire::build_pds_device_put_record_body(
            &self.account_did,
            canonical_dev_id,
            pub_key,
        )?;
        let (st1, b1) = self
            .pds_post_json(
                session_token,
                "/xrpc/com.atproto.repo.createRecord",
                dev_rec,
            )
            .await?;
        if !(200..300).contains(&st1) {
            if matches!(st1, 400 | 409) {
                let get_url = format!(
                    "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=blue.catbird.chat.device&rkey={}",
                    self.pds_base(),
                    chat_wire::urlencode_form_component(&self.account_did),
                    chat_wire::urlencode_form_component(canonical_dev_id),
                );
                let resp = self
                    .http
                    .get(&get_url)
                    .bearer_auth(session_token)
                    .send()
                    .await
                    .map_err(|e| {
                        MLSError::Internal(format!(
                            "getRecord blue.catbird.chat.device failed: {e}"
                        ))
                    })?;
                if resp.status().is_success() {
                    let existing: Value = resp.json().await.map_err(|e| {
                        MLSError::Internal(format!("parse existing chat.device record: {e}"))
                    })?;
                    if !chat_wire::pds_device_record_matches(&existing["value"], pub_key) {
                        return Err(MLSError::InvalidState("EnrollmentPdsRecordConflict".into()));
                    }
                } else {
                    return Err(MLSError::Internal(format!(
                        "createRecord blue.catbird.chat.device HTTP {st1}: {}",
                        String::from_utf8_lossy(&b1)
                    )));
                }
            } else {
                return Err(MLSError::Internal(format!(
                    "createRecord blue.catbird.chat.device HTTP {st1}: {}",
                    String::from_utf8_lossy(&b1)
                )));
            }
        }

        let decl_rec = chat_wire::build_pds_chat_declaration_put_record_body(
            &self.account_did,
            &self.home_ds_did,
        )?;
        let (st2, b2) = self
            .pds_post_json(session_token, "/xrpc/com.atproto.repo.putRecord", decl_rec)
            .await?;
        if !(200..300).contains(&st2) {
            return Err(MLSError::Internal(format!(
                "putRecord blue.catbird.chat.declaration HTTP {st2}: {}",
                String::from_utf8_lossy(&b2)
            )));
        }

        let ts = now_ms();
        // Real `mls-ds` rejects `publishDirectRequestKeys` (400 PreparationConflict) and
        // `replenishKeyPackages` (403 NotAuthorized) while a 2nd+ device is `pending_approval`.
        // Re-running `enrollDevice` after approval hits `DeviceAlreadyExists` ->
        // `own_enrolled_device_entry`, sees `directRequestKeyPool.is_none()` and
        // `is_pending_approval == false`, publishes request keys, clears `enrollment_status`,
        // and replenishes KeyPackages.
        if !request_keys_published && !is_pending_approval {
            let dr_exact_request = db.write_tx(|tx| {
                let provider =
                    OpenMlsKvProvider::new(catbird_mls::storage::OpenMlsKvStorage::new(tx))?;
                let (raw_pub_rec, _) = build_request_key_publication(
                    &provider,
                    signer,
                    &DirectRequestKeyPublicationInput {
                        actor_did: self.account_did.clone(),
                        actor_device_id: canonical_dev_id.to_string(),
                        auth_generation: auth_gen,
                        revision: 1,
                        enabled: true,
                        count: 8,
                    },
                    now_s as i64,
                )?;
                let parsed_rec: DirectRequestKeyPublication = serde_json::from_slice(&raw_pub_rec)
                    .map_err(|e| {
                        MLSError::Internal(format!("parse DirectRequestKeyPublication: {e}"))
                    })?;
                Ok(parsed_rec.exact_request)
            })?;
            let _ = self
                .ds_post_json(
                    session_token,
                    "blue.catbird.chat.publishDirectRequestKeys",
                    dr_exact_request,
                )
                .await?;
        }
        // Persist the authoritative completion binding atomically.
        db.write_tx(|tx| {
            tx.put_account_meta("auth_generation", &auth_gen.to_string(), ts)?;
            tx.put_account_meta("enrolled_device_id", canonical_dev_id, ts)?;
            if is_pending_approval {
                tx.put_account_meta("enrollment_status", "pending_approval", ts)?;
            } else if was_pending_approval {
                tx.delete_account_meta("enrollment_status")?;
            }
            tx.put_account_meta("enrolled_signer_key_id", &key_id, ts)
        })?;
        if !is_pending_approval {
            let _ = self.replenish_key_packages_impl(4).await?;
        }
        Ok(())
    }

    pub(crate) fn is_device_pending_approval_impl(&self) -> Result<bool, MLSError> {
        Ok(self
            .require_db_mls()?
            .backend()
            .get_account_meta("enrollment_status")?
            .as_deref()
            == Some("pending_approval"))
    }

    pub(crate) async fn approve_device_impl(&self, target_device_id: &str) -> Result<(), MLSError> {
        let target_uuid = uuid_v4(target_device_id, "targetDeviceId")?;
        let canonical_target = target_uuid.hyphenated().to_string();
        let (session_token, actor_dev_id) = self.require_live_session()?;
        if canonical_target == actor_dev_id {
            return Err(MLSError::invalid_input(
                "cannot self-approve the current device",
            ));
        }
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        let own_devices = self
            .ds_signed_get(
                &session_token,
                &actor_dev_id,
                "blue.catbird.chat.getOwnDevices",
                &[("actorDeviceId", &actor_dev_id), ("limit", "100")],
                &signer,
            )
            .await?;
        let items = own_devices
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| MLSError::Internal("getOwnDevices missing items array".into()))?;
        let target_item = items
            .iter()
            .find(|item| {
                item.pointer("/device/deviceId")
                    .or_else(|| item.get("deviceId"))
                    .and_then(Value::as_str)
                    == Some(canonical_target.as_str())
            })
            .ok_or_else(|| {
                MLSError::InvalidState(format!(
                    "target device {canonical_target} not found in getOwnDevices"
                ))
            })?;
        let dev_view = target_item.get("device").unwrap_or(target_item);
        let ds_pub_key = chat_wire::json_bytes(&dev_view["signaturePublicKey"])?;
        let target_auth_gen = dev_view["authGeneration"]
            .as_i64()
            .filter(|g| *g >= 1)
            .ok_or_else(|| {
                MLSError::Cryptography("target device missing valid authGeneration".into())
            })?;
        let authorized_pds = self
            .verify_peer_device_keys_via_pds(&session_token, &self.account_did)
            .await?;
        let pds_match = authorized_pds
            .iter()
            .find(|(dev_id, _)| dev_id == &canonical_target)
            .ok_or_else(|| {
                MLSError::Cryptography(format!(
                    "target device {canonical_target} missing verified PDS blue.catbird.chat.device record"
                ))
            })?;
        if pds_match.1 != ds_pub_key {
            return Err(MLSError::Cryptography(format!(
                "target device {canonical_target} signaturePublicKey mismatch between mls-ds and PDS"
            )));
        }
        self.approve_device_with_key_impl(&canonical_target, &ds_pub_key, target_auth_gen)
            .await
    }

    pub(crate) async fn approve_device_with_key_impl(
        &self,
        target_device_id: &str,
        target_signature_public_key: &[u8],
        target_auth_generation: i64,
    ) -> Result<(), MLSError> {
        let target_uuid = uuid_v4(target_device_id, "targetDeviceId")?;
        let canonical_target = target_uuid.hyphenated().to_string();
        if target_signature_public_key.len() != 32 {
            return Err(MLSError::invalid_input(
                "targetSignaturePublicKey must be a 32-byte Ed25519 key",
            ));
        }
        if target_auth_generation < 1 {
            return Err(MLSError::invalid_input("targetAuthGeneration must be >= 1"));
        }
        let (session_token, actor_dev_id) = self.require_live_session()?;
        if canonical_target == actor_dev_id {
            return Err(MLSError::invalid_input(
                "cannot self-approve the current device",
            ));
        }
        let (signer, actor_auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        let body = json!({
            "$type": "blue.catbird.chat.defs#deviceApprovalBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-APPROVE\0",
            "actorDid": self.account_did,
            "actorDeviceId": actor_dev_id,
            "authGeneration": actor_auth_gen,
            "keyId": derive_key_id(signer.public()),
            "targetDeviceId": canonical_target,
            "targetKeyId": derive_key_id(target_signature_public_key),
            "targetAuthGeneration": target_auth_generation,
            "targetSignaturePublicKey": { "$bytes": STANDARD.encode(target_signature_public_key) },
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
            "signedAt": chat_wire::now_rfc3339_millis(),
        });
        let _ = self
            .submit_signed_chat_op(
                &session_token,
                &actor_dev_id,
                Some(actor_auth_gen),
                CanonicalOperation::ApproveDevice,
                &body,
                &signer,
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn replenish_key_packages_impl(&self, count: u32) -> Result<u32, MLSError> {
        if self.is_device_pending_approval_impl()? {
            return Err(MLSError::PendingDeviceAccess {
                reason: "DevicePendingApproval".into(),
            });
        }
        let clamped = count.clamp(1, 32);
        let now_s = now_secs();
        let device_str = self
            .canonical_uuid_v4_device_id()
            .unwrap_or_else(|| self.device_id.clone());
        let db = self.require_db_mls()?;
        let (signer, auth_gen, kps_json) = db.write_tx(|tx| {
            let signer_raw = tx
                .get_labyrinth_state("device_signer_json")?
                .ok_or_else(|| MLSError::InvalidState("WasmMlsClient not enrolled".into()))?;
            let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let auth_gen = tx
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            let provider = OpenMlsKvProvider::new(catbird_mls::storage::OpenMlsKvStorage::new(tx))?;
            let cred_with_key = CredentialWithKey {
                credential: BasicCredential::new(
                    format!("{}#{}", self.account_did, device_str).into_bytes(),
                )
                .into(),
                signature_key: signer.public().into(),
            };
            let caps = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[CIPHERSUITE]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            let mut items: Vec<(Vec<u8>, Value)> = Vec::with_capacity(clamped as usize);
            for _ in 0..clamped {
                let bundle = KeyPackage::builder()
                    .key_package_lifetime(Lifetime::init(
                        now_s.saturating_sub(60),
                        now_s + 29 * 86_400,
                    ))
                    .leaf_node_capabilities(caps.clone())
                    .build(CIPHERSUITE, &provider, &signer, cred_with_key.clone())
                    .map_err(|e| MLSError::Cryptography(format!("build replenish KP: {e:?}")))?;
                let kp_bytes = MlsMessageOut::from(bundle.key_package().clone())
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize replenish KP: {e:?}")))?;
                let kp_ref = bundle
                    .key_package()
                    .hash_ref(provider.crypto())
                    .map_err(|e| MLSError::Cryptography(format!("hash_ref: {e:?}")))?
                    .as_slice()
                    .to_vec();
                items.push((
                    kp_ref.clone(),
                    json!({
                        "framing": "mlsMessage",
                        "contentType": "keyPackage",
                        "bytes": { "$bytes": STANDARD.encode(&kp_bytes) },
                        "sha256": STANDARD.encode(Sha256::digest(&kp_bytes)),
                        "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                    }),
                ));
            }
            items.sort_by(|a, b| a.0.cmp(&b.0));
            Ok((
                signer,
                auth_gen,
                items.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
            ))
        })?;

        if let Some((session_token, canonical_dev_id)) = self.live_session() {
            let pub_key = signer.public();
            let idem = uuid::Uuid::new_v4().to_string();
            let body = json!({
                "$type": "blue.catbird.chat.defs#keyPackageReplenishmentBody",
                "signatureDomain": "CATBIRD-CHAT-DEVICE-REPLENISH\0",
                "actorDid": self.account_did,
                "actorDeviceId": canonical_dev_id,
                "authGeneration": auth_gen,
                "idempotencyKey": idem,
                "keyId": derive_key_id(pub_key),
                "keyPackages": kps_json,
                "signaturePublicKey": { "$bytes": STANDARD.encode(pub_key) },
                "signedAt": chat_wire::now_rfc3339_millis(),
            });
            let _ = self
                .submit_signed_chat_op(
                    &session_token,
                    &canonical_dev_id,
                    Some(auth_gen),
                    CanonicalOperation::ReplenishKeyPackages,
                    &body,
                    &signer,
                )
                .await?;
        }
        Ok(clamped)
    }

    pub(crate) async fn create_group_impl(
        &self,
        conversation_id: String,
        sequencer_did: String,
        member_dids: Vec<String>,
        title: Option<String>,
        description: Option<String>,
    ) -> Result<ConversationRow, MLSError> {
        let mut peer_set = BTreeSet::new();
        for raw_did in member_dids {
            let trimmed = raw_did.trim();
            if trimmed.is_empty() {
                continue;
            }
            let norm = normalize_account_did(trimmed)?;
            if norm != self.account_did {
                peer_set.insert(norm);
            }
        }
        let peers: Vec<String> = peer_set.into_iter().collect();

        let convo_uuid = uuid_v4(&conversation_id, "conversationId")?;
        let (session_token, canonical_dev_id) = self.require_live_session()?;
        for peer in &peers {
            BareDid::parse(peer)
                .map_err(|e| MLSError::invalid_input(format!("invalid peer DID `{peer}`: {e}")))?;
        }
        let canonical_convo_id = convo_uuid.hyphenated().to_string();
        if let Some(conversation) = self
            .require_db_mls()?
            .backend()
            .get_conversation(&canonical_convo_id)?
        {
            return Ok(conversation);
        }
        if group_creation_for_conversation(self.require_db_mls()?.backend(), &canonical_convo_id)?
            .is_some()
        {
            return self
                .resume_pending_group_creation(&session_token, &canonical_convo_id)
                .await?
                .ok_or_else(|| MLSError::Internal("group creation journal disappeared".into()));
        }

        let is_untitle_one_to_one =
            peers.len() == 1 && title.as_deref().unwrap_or("").trim().is_empty();
        if is_untitle_one_to_one {
            // Before any network effect: a journaled attempt may still be inside `Retry-After`.
            return self
                .create_c33_direct_request_live(
                    &session_token,
                    &canonical_convo_id,
                    &canonical_dev_id,
                    &peers[0],
                    description,
                )
                .await;
        }

        // Verify PDS `blue.catbird.chat.device` keys (`I4`) for all participants up front.
        for did in std::iter::once(&self.account_did).chain(&peers) {
            self.verify_peer_device_keys_via_pds(&session_token, did)
                .await?;
        }

        self.create_group_conversation_live(
            &session_token,
            &canonical_convo_id,
            &convo_uuid,
            &sequencer_did,
            &canonical_dev_id,
            &peers,
            title,
            description,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_group_conversation_live(
        &self,
        session_token: &str,
        canonical_convo_id: &str,
        convo_uuid: &uuid::Uuid,
        sequencer_did: &str,
        canonical_dev_id: &str,
        peers: &[String],
        title: Option<String>,
        description: Option<String>,
    ) -> Result<ConversationRow, MLSError> {
        let mut group_id_bytes = vec![0u8; 32];
        getrandom::getrandom(&mut group_id_bytes)
            .map_err(|e| MLSError::Internal(format!("getrandom: {e}")))?;
        let now_s = now_secs();
        let ts = now_ms();
        let transition_id = uuid::Uuid::new_v4().to_string();
        let title_str = title.clone().unwrap_or_default();
        let desc_str = description.clone().unwrap_or_default();
        let db = self.require_db_mls()?;

        let (signer, auth_gen, ggi_bytes, gch, ctag, meta_snap_json, kv_batch) = {
            let backend = db.backend();
            let signer_raw = backend
                .get_labyrinth_state("device_signer_json")?
                .ok_or_else(|| MLSError::InvalidState("WasmMlsClient not enrolled".into()))?;
            let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let auth_gen = backend
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            let overlay = KvWriteOverlay::new(backend);
            let (ggi, gch, ctag, snap) = {
                let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
                signer
                    .store(provider.storage())
                    .map_err(|e| MLSError::Internal(format!("store signer: {e:?}")))?;
                let caps = Capabilities::new(
                    Some(&[ProtocolVersion::Mls10]),
                    Some(&[CIPHERSUITE]),
                    Some(&[]),
                    Some(&[]),
                    Some(&[CredentialType::Basic]),
                );
                let create_cfg = MlsGroupCreateConfig::builder()
                    .ciphersuite(CIPHERSUITE)
                    .capabilities(caps)
                    .lifetime(Lifetime::init(
                        now_s.saturating_sub(60),
                        now_s + 29 * 86_400,
                    ))
                    .use_ratchet_tree_extension(true)
                    .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                    .max_past_epochs(5)
                    .sender_ratchet_configuration(
                        catbird_mls::GroupConfig::default().sender_ratchet_configuration(),
                    )
                    .build();
                let mut group = MlsGroup::new_with_group_id(
                    &provider,
                    &signer,
                    &create_cfg,
                    GroupId::from_slice(&group_id_bytes),
                    CredentialWithKey {
                        credential: BasicCredential::new(
                            format!("{}#{}", self.account_did, canonical_dev_id).into_bytes(),
                        )
                        .into(),
                        signature_key: signer.public().into(),
                    },
                )
                .map_err(|e| MLSError::Cryptography(format!("create X-Wing group: {e:?}")))?;

                let ggi = group
                    .export_group_info(provider.crypto(), &signer, true)
                    .map_err(|e| MLSError::Cryptography(format!("export_group_info: {e:?}")))?
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize ggi: {e:?}")))?;
                let (gch, ctag) = chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                let meta_key = derive_metadata_key_from_group(
                    &mut group,
                    provider.crypto(),
                    provider.storage(),
                    &group_id_bytes,
                    0,
                )
                .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
                let snap = chat_wire::build_encrypted_metadata_snapshot_json(
                    &meta_key,
                    &group_id_bytes,
                    convo_uuid,
                    0,
                    0,
                    &gch,
                    &ctag,
                    &transition_id,
                    1,
                    1,
                    &self.account_did,
                    canonical_dev_id,
                    auth_gen,
                    signer.public(),
                    &title_str,
                    &desc_str,
                    None,
                )?;
                (ggi, gch, ctag, snap)
            };
            (signer, auth_gen, ggi, gch, ctag, snap, overlay.into_batch())
        };

        let mut participants = vec![json!({
            "userDid": self.account_did,
            "status": "active",
            "role": "admin"
        })];
        for peer in peers {
            participants.push(json!({
                "userDid": peer,
                "status": "pending",
                "role": "member",
                "invitationProvenance": {
                    "invitationTransitionId": transition_id,
                    "invitedByDid": self.account_did,
                    "invitedByDeviceId": canonical_dev_id,
                }
            }));
        }
        participants.sort_by(|a, b| {
            a["userDid"]
                .as_str()
                .unwrap_or("")
                .cmp(b["userDid"].as_str().unwrap_or(""))
        });

        let next_coords = json!({
            "conversationId": canonical_convo_id,
            "generation": 0,
            "stateVersion": 0,
            "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) },
            "epoch": 0,
            "groupContextHash": { "$bytes": STANDARD.encode(gch) },
            "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
            "lifecycle": "active",
        });
        let create_body = json!({
            "$type": "blue.catbird.chat.defs#creationBody",
            "signatureDomain": "CATBIRD-CHAT-CREATE\0",
            "conversationId": canonical_convo_id,
            "conversationKind": "group",
            "transitionId": transition_id,
            "idempotencyKey": transition_id,
            "actorDid": self.account_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_gen,
            "absence": true,
            "next": next_coords,
            "manifest": {
                "participants": participants,
                "actorLeaf": {
                    "userDid": self.account_did,
                    "deviceId": canonical_dev_id,
                    "leafOrigin": "genesis",
                }
            },
            "genesisGroupInfo": {
                "framing": "mlsMessage",
                "contentType": "groupInfo",
                "bytes": { "$bytes": STANDARD.encode(&ggi_bytes) },
                "sha256": STANDARD.encode(Sha256::digest(&ggi_bytes)),
            },
            "metadataSnapshot": meta_snap_json,
            "signedAt": chat_wire::now_rfc3339_millis(),
        });
        let prepared = chat_wire::sign_clean_chat_mutation(
            &self.account_did,
            canonical_dev_id,
            Some(auth_gen),
            CanonicalOperation::CreateConversation,
            &create_body,
            &signer,
        )?;
        let request = prepared.body.unwrap_or_default();
        let request_value: Value = serde_json::from_slice(&request)?;
        let signed_at = request_value["signedRequest"]["body"]["signedAt"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let pending = chat_wire::PendingGroupCreation {
            version: chat_wire::GROUP_CREATION_JOURNAL_VERSION,
            conversation_id: canonical_convo_id.to_string(),
            journal_id: transition_id.clone(),
            sequencer_did: sequencer_did.to_string(),
            group_id: group_id_bytes,
            signer_public_key: signer.public().to_vec(),
            attempts: vec![chat_wire::PendingGroupCreationAttempt {
                operation_id: transition_id,
                signed_at,
                request,
                expired_confirmed: false,
            }],
            kv_batch,
            title,
            description,
            new_signer_json: None,
            created_at_ms: ts,
            retry_at_ms: 0,
            retry_count: 0,
            retry_code: None,
        };
        db.write_tx(|tx| put_group_creation(tx, &pending).map(|_| ()))?;
        self.resume_pending_group_creation(session_token, canonical_convo_id)
            .await?
            .ok_or_else(|| MLSError::Internal("group creation journal disappeared".into()))
    }

    /// Replay one exact creation and atomically adopt the journaled genesis state.
    async fn resume_pending_group_creation(
        &self,
        session_token: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationRow>, MLSError> {
        let db = self.require_db_mls()?;
        let Some((journal_id, raw)) =
            group_creation_for_conversation(db.backend(), conversation_id)?
        else {
            return Ok(None);
        };
        let key = group_creation_key(&journal_id);
        let pending: chat_wire::PendingGroupCreation = serde_json::from_str(&raw)
            .map_err(|e| MLSError::Internal(format!("parse group creation journal: {e}")))?;
        if pending.version != chat_wire::GROUP_CREATION_JOURNAL_VERSION
            || pending.conversation_id != conversation_id
            || pending.journal_id != journal_id
        {
            return Err(MLSError::InvalidState(
                "unsupported or mismatched group creation journal".into(),
            ));
        }
        let attempt = pending.attempts.last().ok_or_else(|| {
            MLSError::InvalidState("group creation journal has no attempts".into())
        })?;

        let submitted: Value = serde_json::from_slice(&attempt.request)
            .map_err(|e| MLSError::Internal(format!("parse group creation request: {e}")))?;
        let (verified_body, _) = chat_wire::verify_signed_mutation_body_and_digest(
            &submitted["signedRequest"],
            SignedMutationKind::Creation,
            &pending.signer_public_key,
        )?;
        let signed_next = chat_wire::canonicalize_wire_coordinate(&verified_body["next"], None)?;
        if verified_body["conversationId"] != pending.conversation_id
            || verified_body["transitionId"] != attempt.operation_id
            || verified_body["idempotencyKey"] != attempt.operation_id
            || verified_body["signedAt"] != attempt.signed_at
            || verified_body["actorDid"] != self.account_did
            || chat_wire::json_bytes(&signed_next["groupId"])? != pending.group_id
        {
            return Err(MLSError::Cryptography(
                "group creation journal does not match its signed request".into(),
            ));
        }

        let answer = match self
            .submit_prepared_signed_chat_op_for_authority(
                session_token,
                CanonicalOperation::CreateConversation,
                "blue.catbird.chat.createConversation",
                attempt.request.clone(),
                &pending.signer_public_key,
                Some(&pending.sequencer_did),
            )
            .await
        {
            Ok(answer) => answer,
            Err(error) => {
                if is_terminal_refusal(&error) {
                    db.write_tx(|tx| {
                        if tx.get_account_meta(&key)?.as_deref() == Some(raw.as_str()) {
                            remove_group_creation_operation(tx, &journal_id)?;
                        }
                        Ok(())
                    })?;
                }
                return Err(error);
            }
        };
        let server_seq = answer["result"]["entry"]["seq"]
            .as_i64()
            .ok_or_else(|| MLSError::Cryptography("creation answer missing entry seq".into()))?;
        if server_seq != 1 {
            return Err(MLSError::Cryptography(format!(
                "own creation answer: seq {server_seq} is not the first entry"
            )));
        }

        let roster =
            chat_wire::roster_from_participants(&verified_body["manifest"]["participants"])?;
        let generation = signed_next["generation"].as_i64().unwrap_or_default();
        let epoch = signed_next["epoch"].as_i64().unwrap_or_default();
        let coords = serde_json::to_string(&signed_next)?;
        let snapshot = serde_json::to_string(&verified_body["metadataSnapshot"])?;
        let title_str = pending.title.clone().unwrap_or_default();
        let description_str = pending.description.clone().unwrap_or_default();
        let ts = pending.created_at_ms;
        let conversation = db.write_tx(|tx| {
            if tx.get_account_meta(&key)?.as_deref() != Some(raw.as_str()) {
                if let Some(conversation) = tx.get_conversation(conversation_id)? {
                    return Ok(conversation);
                }
                return Err(MLSError::InvalidState(
                    "GroupCreationOwnershipChanged".into(),
                ));
            }
            pending.kv_batch.apply(tx)?;
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
            let group = MlsGroup::load(
                provider.storage(),
                &GroupId::from_slice(&pending.group_id),
            )
            .map_err(|e| MLSError::Internal(format!("load journaled genesis group: {e:?}")))?
            .ok_or_else(|| MLSError::group_not_found(conversation_id))?;
            chat_wire::require_coordinate_names_group(&signed_next, &group, &provider)?;
            if pending.title.is_some() || pending.description.is_some() {
                let metadata = GroupMetadataV1 {
                    version: 1,
                    title: title_str.clone(),
                    description: description_str.clone(),
                    avatar_blob_locator: None,
                    avatar_content_type: None,
                    space_avatar: None,
                    extra: Default::default(),
                };
                tx.upsert_group_metadata(&chat_wire::group_metadata_row_from_v1(
                    conversation_id,
                    1,
                    0,
                    &metadata,
                    ts,
                )?)?;
            }
            let row = ConversationRow {
                conversation_id: conversation_id.to_string(),
                group_id: pending.group_id.clone(),
                generation,
                epoch,
                last_seq: server_seq,
                sequencer_did: pending.sequencer_did.clone(),
                space_uri: Some(format!(
                    "at://{}/space/blue.catbird.labyrinth.conversation/{conversation_id}-{generation}",
                    pending.sequencer_did
                )),
                title: pending.title.clone(),
                unread_count: 0,
                updated_at_ms: ts,
            };
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{conversation_id}"),
                &coords,
                ts,
            )?;
            tx.put_account_meta(
                &format!("metadata_snapshot_json:{conversation_id}"),
                &snapshot,
                ts,
            )?;
            store_roster(tx, conversation_id, &roster, ts)?;
            remove_group_creation_operation(tx, &journal_id)?;
            Ok(row)
        })?;
        Ok(Some(conversation))
    }

    /// Complete every indexed creation before inventory can request leaf recovery for it.
    pub(crate) async fn complete_pending_group_creations(
        &self,
        session_token: &str,
    ) -> Result<u32, MLSError> {
        let db = self.require_db_mls()?;
        let operation_ids = group_creation_operation_ids(db.backend())?;
        let mut completed = 0u32;
        for operation_id in operation_ids {
            let key = group_creation_key(&operation_id);
            let Some(raw) = db.backend().get_account_meta(&key)? else {
                db.write_tx(|tx| remove_group_creation_operation(tx, &operation_id))?;
                continue;
            };
            let pending: chat_wire::PendingGroupCreation = serde_json::from_str(&raw)
                .map_err(|e| MLSError::Internal(format!("parse group creation journal: {e}")))?;
            if self
                .resume_pending_group_creation(session_token, &pending.conversation_id)
                .await?
                .is_some()
            {
                completed = completed.saturating_add(1);
            }
        }
        Ok(completed)
    }

    pub(crate) async fn add_group_members_impl(
        &self,
        conversation_id: &str,
        member_dids: Vec<String>,
    ) -> Result<ConversationRow, MLSError> {
        let mut peer_set = BTreeSet::new();
        for raw_did in member_dids {
            let trimmed = raw_did.trim();
            if !trimmed.is_empty() {
                let norm = normalize_account_did(trimmed)?;
                if norm != self.account_did {
                    peer_set.insert(norm);
                }
            }
        }
        let peers: Vec<String> = peer_set.into_iter().collect();
        uuid_v4(conversation_id, "conversationId")?;
        if peers.is_empty() {
            return Err(MLSError::invalid_input(
                "memberDids must name another account",
            ));
        }
        let (session_token, canonical_dev_id) = self.require_live_session()?;
        let db = self.require_db_mls()?;
        let existing = db
            .backend()
            .get_conversation(conversation_id)?
            .ok_or_else(|| MLSError::group_not_found(format!("missing {conversation_id}")))?;
        for peer in &peers {
            let _ = self
                .verify_peer_device_keys_via_pds(&session_token, peer)
                .await?;
        }
        let prior_coords = self.load_or_build_conversation_coords(conversation_id)?;
        let prior_sv = prior_coords["stateVersion"].as_i64().unwrap_or(0);
        let mut next_coords = prior_coords.clone();
        next_coords["stateVersion"] = json!(prior_sv + 1);
        let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        let transition_id = uuid::Uuid::new_v4().to_string();
        let changes: Vec<Value> = peers
            .iter()
            .map(|peer| {
                json!({
                    "$type": "blue.catbird.chat.defs#addParticipant",
                    "userDid": peer,
                    "role": "member",
                    "status": "pending",
                    "invitationProvenance": {
                        "invitationTransitionId": transition_id,
                        "invitedByDid": self.account_did,
                        "invitedByDeviceId": canonical_dev_id,
                    }
                })
            })
            .collect();
        let policy_body = json!({
            "$type": "blue.catbird.chat.defs#policyTransitionBody",
            "signatureDomain": "CATBIRD-CHAT-POLICY\0",
            "transitionId": transition_id,
            "idempotencyKey": transition_id,
            "actorDid": self.account_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_gen,
            "prior": prior_coords,
            "next": next_coords,
            "participantChanges": changes,
            "signedAt": chat_wire::now_rfc3339_millis(),
        });
        // Verified as the transition signed here: its signed `next` is the new state.
        self.submit_signed_chat_op(
            &session_token,
            &canonical_dev_id,
            Some(auth_gen),
            CanonicalOperation::SubmitTransition,
            &policy_body,
            &signer,
        )
        .await?;
        let coords_str =
            serde_json::to_string(&next_coords).map_err(|e| MLSError::Internal(e.to_string()))?;
        let ts = now_ms();
        let updated = db.write_tx(|tx| {
            let mut row = tx.get_conversation(conversation_id)?.unwrap_or(existing);
            row.updated_at_ms = ts;
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{conversation_id}"),
                &coords_str,
                ts,
            )?;
            // The verified answer applies the policy: its echo then moves only the cursor.
            apply_verified_roster_effects(
                tx,
                conversation_id,
                SignedMutationKind::PolicyTransition,
                &policy_body,
                ts,
            )?;
            Ok(row)
        })?;
        let _ = self
            .fulfill_leaf_recovery(
                &session_token,
                &canonical_dev_id,
                &signer,
                auth_gen,
                conversation_id,
            )
            .await;
        Ok(db
            .backend()
            .get_conversation(conversation_id)?
            .unwrap_or(updated))
    }

    pub(crate) async fn send_message_impl(
        &self,
        conversation_id: &str,
        message_id: &str,
        text: &str,
    ) -> Result<MessageRow, MLSError> {
        let (display_json, frame_json) = canonical_labyrinth_frame_for_text(text);
        self.send_canonical_frame_impl(conversation_id, message_id, display_json, frame_json)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_media_attachment_message_impl(
        &self,
        conversation_id: &str,
        message_id: &str,
        text: &str,
        uploaded: &UploadedConversationAttachment,
        width: Option<u32>,
        height: Option<u32>,
        alt_text: Option<String>,
        duration_ms: Option<u64>,
        waveform: Option<Vec<f32>>,
        transcript: Option<String>,
    ) -> Result<MessageRow, MLSError> {
        let _ = uuid_v4(conversation_id, "conversationId")?;
        let _ = uuid_v4(message_id, "messageId")?;
        let sha256_hex = hex::encode(&uploaded.ciphertext_sha256);
        let is_audio = duration_ms.is_some()
            || waveform.is_some()
            || transcript.is_some()
            || uploaded
                .mime_type
                .trim()
                .to_ascii_lowercase()
                .starts_with("audio/");
        let embed = if is_audio {
            MLSEmbedData::audio(MLSAudioEmbed {
                blob_id: uploaded.locator.clone(),
                key: uploaded.symmetric_key.clone(),
                iv: uploaded.iv.clone(),
                sha256: sha256_hex,
                content_type: uploaded.mime_type.clone(),
                size: uploaded.ciphertext_size,
                duration_ms: duration_ms.unwrap_or(1_000),
                waveform: waveform.unwrap_or_default(),
                transcript,
            })
            .map_err(|e| MLSError::Internal(format!("build MLSAudioEmbed: {e}")))?
        } else {
            MLSEmbedData::image(MLSImageEmbed {
                blob_id: uploaded.locator.clone(),
                key: uploaded.symmetric_key.clone(),
                iv: uploaded.iv.clone(),
                sha256: sha256_hex,
                content_type: uploaded.mime_type.clone(),
                size: uploaded.ciphertext_size as usize,
                width: width.unwrap_or(0),
                height: height.unwrap_or(0),
                alt_text,
                blurhash: None,
            })
            .map_err(|e| MLSError::Internal(format!("build MLSImageEmbed: {e}")))?
        };
        let payload = MLSMessagePayload::text_with_embed(text, embed);
        let display_json = serde_json::to_string(&payload)
            .map_err(|e| MLSError::Internal(format!("serialize media payload: {e}")))?;
        let frame_json = chat_wire::canonical_labyrinth_frame_json(&display_json);
        self.send_canonical_frame_impl(conversation_id, message_id, display_json, frame_json)
            .await
    }

    pub(crate) async fn send_canonical_frame_impl(
        &self,
        conversation_id: &str,
        message_id: &str,
        display_json: String,
        frame_json: String,
    ) -> Result<MessageRow, MLSError> {
        let convo_uuid = uuid_v4(conversation_id, "conversationId")?;
        let msg_uuid = uuid_v4(message_id, "messageId")?;
        let (session_token, canonical_dev_id) = self.require_live_session()?;
        let canonical_msg_id = msg_uuid.hyphenated().to_string();
        let reserve = || {
            self.reserve_application_send(
                convo_uuid,
                msg_uuid,
                &canonical_dev_id,
                &display_json,
                &frame_json,
            )
        };
        // A definitive refusal retires these exact bytes. `StaleSend` also proves that this
        // counter is covered by the sequencer's accepted watermark.
        let journal_key = pending_send_key(&convo_uuid.hyphenated().to_string(), &canonical_msg_id);
        let discard_refused = |pending: &PendingApplicationSend,
                               stale_send: bool|
         -> Result<(), MLSError> {
            self.require_db_mls()?.write_tx(|tx| {
                if stale_send {
                    let send_counter = pending.body["sendCounter"].as_u64().ok_or_else(|| {
                        MLSError::Internal("send journal missing valid sendCounter".into())
                    })?;
                    let counter_key = chat_wire::send_counter_key(&pending.archive.conversation_id);
                    let confirmed = chat_wire::confirmed_send_counter(
                        tx.get_account_meta(&counter_key)?.as_deref(),
                        send_counter,
                    )?;
                    tx.put_account_meta(&counter_key, &confirmed.to_string(), now_ms())?;
                }
                tx.delete_account_meta(&journal_key)
            })
        };

        let (mut signer, mut auth_gen, mut pending) = reserve()?;
        let resp_val = match self
            .submit_application_send(
                &session_token,
                &canonical_dev_id,
                &signer,
                auth_gen,
                &pending,
            )
            .await
        {
            Err(error) if chat_wire::is_stale_send(&error) => {
                discard_refused(&pending, true)?;
                (signer, auth_gen, pending) = reserve()?;
                match self
                    .submit_application_send(
                        &session_token,
                        &canonical_dev_id,
                        &signer,
                        auth_gen,
                        &pending,
                    )
                    .await
                {
                    Err(error) if chat_wire::is_stale_send(&error) => {
                        discard_refused(&pending, true)?;
                        return Err(error);
                    }
                    Err(error) => {
                        if is_terminal_refusal(&error) {
                            discard_refused(&pending, false)?;
                        }
                        return Err(error);
                    }
                    Ok(response) => response,
                }
            }
            Err(error) => {
                if is_terminal_refusal(&error) {
                    discard_refused(&pending, false)?;
                }
                return Err(error);
            }
            Ok(response) => response,
        };

        // Mandatory `I13` ES256 `sequencerReceipt`, verified under the method its `kid` names.
        let receipt_val = resp_val
            .get("sequencerReceipt")
            .or_else(|| {
                resp_val
                    .get("entry")
                    .and_then(|e| e.get("sequencerReceipt"))
            })
            .filter(|v| !v.is_null())
            .ok_or_else(|| {
                MLSError::Cryptography(
                    "sendMessage response missing mandatory sequencerReceipt (I13)".into(),
                )
            })?;
        let sec1_key = self
            .receipt_key_for(&session_token, &pending.archive.sequencer_did, receipt_val)
            .await?;
        let expected_entry_id = resp_val
            .pointer("/entry/entryId")
            .and_then(|v| v.as_str())
            .unwrap_or(&canonical_msg_id);
        let (final_row, gap_convo_opt) =
            self.finish_application_send(pending, receipt_val, expected_entry_id, &sec1_key, None)?;

        if let Some(gap_convo) = gap_convo_opt {
            let _ = self
                .sync_conversation_entries(&session_token, &canonical_dev_id, &signer, &gap_convo)
                .await;
        }

        let _ = self.flush_labyrinth_queue_impl().await;
        Ok(final_row)
    }

    /// POST one journaled send (`I6`: strictly outside `write_tx`). `mls-ds` refuses an
    /// out-of-order send with protocol error `StaleSend`, surfaced as
    /// `MLSError::InvalidState("StaleSend")` whatever the HTTP status.
    async fn submit_application_send(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_gen: i64,
        pending: &PendingApplicationSend,
    ) -> Result<Value, MLSError> {
        self.submit_signed_chat_op(
            session_token,
            canonical_dev_id,
            Some(auth_gen),
            CanonicalOperation::SendMessage,
            &pending.body,
            signer,
        )
        .await
        .map_err(|error| match &error {
            // `ds_post_json` failure: "POST <nsid> returned HTTP <status>: <protocol error JSON>".
            MLSError::Internal(message)
                if message
                    .split_once(": ")
                    .and_then(|(_, body)| serde_json::from_str::<Value>(body).ok())
                    .is_some_and(|body| body["error"] == chat_wire::STALE_SEND) =>
            {
                MLSError::InvalidState(chat_wire::STALE_SEND.into())
            }
            _ => error,
        })
    }

    /// Reserve the sender generation, candidate `sendCounter` and send journal in one write
    /// transaction before HTTP. A lost response can still publish the ciphertext, so rolling the
    /// ratchet back would reuse its key and nonce. An existing journal stays byte-identical; the
    /// accepted-counter watermark changes only after verified sequencing.
    fn reserve_application_send(
        &self,
        convo_uuid: uuid::Uuid,
        msg_uuid: uuid::Uuid,
        canonical_dev_id: &str,
        display_json: &str,
        frame_json: &str,
    ) -> Result<(SignatureKeyPair, i64, PendingApplicationSend), MLSError> {
        let canonical_convo_id = convo_uuid.hyphenated().to_string();
        let canonical_msg_id = msg_uuid.hyphenated().to_string();
        let mut frame_nonce = [0u8; 32];
        getrandom::getrandom(&mut frame_nonce)
            .map_err(|e| MLSError::Internal(format!("getrandom: {e}")))?;
        let ts = now_ms();

        let prior_coords = self.load_or_build_conversation_coords(&canonical_convo_id)?;
        let generation = prior_coords["generation"].as_i64().unwrap_or(0);
        let state_version = prior_coords["stateVersion"].as_i64().unwrap_or(0);
        let epoch_u64 = prior_coords["epoch"].as_u64().unwrap_or(0);
        let gch = chat_wire::json_bytes(&prior_coords["groupContextHash"])?;
        let ctag = chat_wire::json_bytes(&prior_coords["confirmationTag"])?;
        let journal_key = pending_send_key(&canonical_convo_id, &canonical_msg_id);

        self.require_db_mls()?.write_tx(|tx| {
            let convo = tx.get_conversation(&canonical_convo_id)?.ok_or_else(|| {
                MLSError::group_not_found(format!("missing {canonical_convo_id}"))
            })?;
            let signer_raw = tx
                .get_labyrinth_state("device_signer_json")?
                .ok_or_else(|| MLSError::InvalidState("WasmMlsClient not enrolled".into()))?;
            let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            if let Some(raw) = tx.get_account_meta(&journal_key)? {
                let pending: PendingApplicationSend = serde_json::from_str(&raw)
                    .map_err(|e| MLSError::Internal(format!("parse send journal: {e}")))?;
                if pending.archive.plaintext_json != display_json
                    || pending.archive.sender_device_id != canonical_dev_id
                {
                    return Err(MLSError::invalid_input(
                        "messageId already reserved for a different send",
                    ));
                }
                let auth_gen = pending.body["authGeneration"].as_i64().ok_or_else(|| {
                    MLSError::Internal("send journal missing authGeneration".into())
                })?;
                return Ok((signer, auth_gen, pending));
            }
            // Policy is sampled with the sender-generation reservation. The stamped frame is
            // journaled byte-for-byte, so a retry cannot silently loosen an earlier decision.
            let frame_json =
                wasm_archive_policy::stamp_outgoing(tx, &canonical_convo_id, frame_json)?;
            let archive_commitment =
                PrivateMessageAadEnvelope::for_payload(&frame_nonce, frame_json.as_bytes())
                    .archive_commitment;
            let auth_gen = tx
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            // The candidate after this device's last confirmed send. An uncertain attempt keeps
            // this exact journal; reservation itself must not burn the accepted-send watermark.
            let counter_key = chat_wire::send_counter_key(&canonical_convo_id);
            let send_counter =
                chat_wire::next_send_counter(tx.get_account_meta(&counter_key)?.as_deref())?;

            let attestation_transcript =
                labyrinth_protocol::transcripts::original_sender_archive_transcript(
                    &canonical_convo_id,
                    &canonical_msg_id,
                    &archive_commitment,
                );
            let original_sender_attestation = OriginalSenderArchiveAttestationEnvelope {
                sender_did: self.account_did.clone(),
                sender_device_id: canonical_dev_id.to_string(),
                sender_transport_public_key: signer.public().to_vec(),
                signature: signer.sign(&attestation_transcript).map_err(|error| {
                    MLSError::Cryptography(format!(
                        "sign original sender archive attestation: {error:?}"
                    ))
                })?,
            };
            original_sender_attestation.verify(
                &canonical_convo_id,
                &canonical_msg_id,
                &archive_commitment,
            )?;
            let inner_plaintext = serde_json::to_vec(&PrivateMessagePlaintextEnvelope {
                frame_nonce,
                canonical_payload_bytes: frame_json.as_bytes().to_vec(),
                original_sender_attestation: Some(original_sender_attestation.clone()),
            })
            .map_err(|error| {
                MLSError::Internal(format!(
                    "serialize PrivateMessagePlaintextEnvelope: {error}"
                ))
            })?;
            let aad_prior = chat_wire::build_aad_prior_coordinate(
                &convo_uuid,
                &convo.group_id,
                generation,
                state_version,
                epoch_u64 as i64,
                &gch,
                &ctag,
            );
            let aad_val = json!({
                "protocolVersion": "1",
                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                "generation": generation,
                "messageId": STANDARD.encode(msg_uuid.as_bytes()),
                "prior": aad_prior,
                "archiveCommitment": { "$bytes": STANDARD.encode(archive_commitment) },
                "originalSenderAttestation": original_sender_attestation.to_aad_json(),
            });
            let aad_bytes = canonical_application_aad_bytes(&aad_val).map_err(|e| {
                MLSError::Cryptography(format!("canonical_application_aad_bytes: {e}"))
            })?;

            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                    .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                    .ok_or_else(|| MLSError::group_not_found("missing MlsGroup"))?;
            group.set_aad(aad_bytes);
            let mls_out = group
                .create_message(&provider, &signer, &inner_plaintext)
                .map_err(|e| MLSError::Cryptography(format!("create_message: {e:?}")));
            group.set_aad(Vec::new());
            let ciphertext = mls_out?
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("serialize msg: {e:?}")))?;

            let body = json!({
                "$type": "blue.catbird.chat.defs#applicationSendBody",
                "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
                "messageId": canonical_msg_id,
                "actorDid": self.account_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "sendCounter": send_counter,
                "signedAt": chat_wire::now_rfc3339_millis(),
                "prior": prior_coords,
                "aad": aad_val,
                "applicationMessage": {
                    "framing": "mlsMessage",
                    "contentType": "privateMessageApplication",
                    "bytes": { "$bytes": STANDARD.encode(&ciphertext) },
                    "sha256": { "$bytes": STANDARD.encode(Sha256::digest(&ciphertext)) },
                },
                "blobBindings": [],
            });
            let pending = PendingApplicationSend {
                body,
                archive: QueuedLabyrinthArchivePayload {
                    version: 1,
                    message_id: canonical_msg_id.clone(),
                    conversation_id: canonical_convo_id.clone(),
                    group_id_hex: hex::encode(&convo.group_id),
                    epoch: group.epoch().as_u64() as i64,
                    expected_member_dids: member_root_dids(&group)?,
                    seq: 0,
                    sender_did: self.account_did.clone(),
                    sender_device_id: canonical_dev_id.to_string(),
                    sequencer_did: convo.sequencer_did,
                    space_uri: convo.space_uri,
                    plaintext_json: display_json.to_string(),
                    labyrinth_frame_json: frame_json,
                    mls_ciphertext_b64: STANDARD.encode(&ciphertext),
                    frame_nonce_b64: Some(STANDARD.encode(frame_nonce)),
                    sequencer_receipt_json: None,
                    original_sender_attestation_json: Some(
                        serde_json::to_string(&original_sender_attestation).map_err(|error| {
                            MLSError::Internal(format!(
                                "serialize original sender archive attestation: {error}"
                            ))
                        })?,
                    ),
                    created_at_ms: ts,
                },
            };
            let journal = serde_json::to_string(&pending)
                .map_err(|e| MLSError::Internal(format!("serialize send journal: {e}")))?;
            tx.put_account_meta(&journal_key, &journal, ts)?;
            Ok((signer, auth_gen, pending))
        })
    }

    /// Store a sequenced journaled send after verifying its `I13` receipt: the local row,
    /// archive evidence and Labyrinth outbox item land and the journal retires in one
    /// transaction. `ordered_seq` is the entry seq when sync recovers a send whose response was
    /// lost (own MLS ciphertext is not decryptable). Returns the conversation to gap-sync, if any.
    pub(crate) fn finish_application_send(
        &self,
        pending: PendingApplicationSend,
        receipt: &Value,
        entry_id: &str,
        receipt_key_sec1: &[u8],
        ordered_seq: Option<i64>,
    ) -> Result<(MessageRow, Option<ConversationRow>), MLSError> {
        let send_counter = pending.body["sendCounter"]
            .as_u64()
            .ok_or_else(|| MLSError::Internal("send journal missing valid sendCounter".into()))?;
        let mut queued = pending.archive;
        let group_id = hex::decode(&queued.group_id_hex)
            .map_err(|e| MLSError::Internal(format!("send journal group_id: {e}")))?;
        let frame_nonce: [u8; 32] = STANDARD
            .decode(queued.frame_nonce_b64.as_deref().unwrap_or_default())
            .ok()
            .and_then(|nonce| nonce.try_into().ok())
            .ok_or_else(|| {
                MLSError::Internal("send journal frame nonce must be 32 bytes".into())
            })?;
        let archive_commitment = PrivateMessageAadEnvelope::for_payload(
            &frame_nonce,
            queued.labyrinth_frame_json.as_bytes(),
        )
        .archive_commitment;
        let original_sender_attestation: OriginalSenderArchiveAttestationEnvelope =
            serde_json::from_str(
                queued
                    .original_sender_attestation_json
                    .as_deref()
                    .unwrap_or_default(),
            )
            .map_err(|error| {
                MLSError::Cryptography(format!(
                    "send journal original sender archive attestation: {error}"
                ))
            })?;
        let (rcpt_seq, _rcpt_gen, archived_json) =
            chat_wire::parse_and_verify_i13_sequencer_receipt(
                receipt,
                receipt_key_sec1,
                &queued.sequencer_did,
                &queued.conversation_id,
                &group_id,
                queued.epoch.max(0) as u64,
                entry_id,
                &queued.message_id,
                &archive_commitment,
                Some(&original_sender_attestation),
            )?;
        let authoritative_seq = rcpt_seq as i64;
        if ordered_seq.is_some_and(|expected| expected != authoritative_seq) {
            return Err(MLSError::Cryptography(format!(
                "I13: receipt seq {authoritative_seq} != entry seq {ordered_seq:?}"
            )));
        }
        queued.seq = authoritative_seq;
        queued.sequencer_receipt_json = Some(archived_json);
        let ts = now_ms();
        let journal_key = pending_send_key(&queued.conversation_id, &queued.message_id);

        self.require_db_mls()?.write_tx(|tx| {
            let mut gap_convo = None;
            if let Some(mut c) = tx.get_conversation(&queued.conversation_id)? {
                let prior_last_seq = c.last_seq;
                c.epoch = c.epoch.max(queued.epoch);
                if ordered_seq.is_some() || authoritative_seq == prior_last_seq.saturating_add(1) {
                    c.last_seq = prior_last_seq.max(authoritative_seq);
                } else if authoritative_seq > prior_last_seq.saturating_add(1) {
                    gap_convo = Some(c.clone());
                }
                c.updated_at_ms = ts;
                tx.upsert_conversation(&c)?;
            }
            let mut row = MessageRow {
                message_id: queued.message_id.clone(),
                conversation_id: queued.conversation_id.clone(),
                group_id,
                epoch: queued.epoch,
                seq: authoritative_seq,
                sender_did: queued.sender_did.clone(),
                sender_device_id: queued.sender_device_id.clone(),
                plaintext_json: queued.plaintext_json.clone(),
                created_at_ms: queued.created_at_ms,
                is_own: true,
            };
            let counter_key = chat_wire::send_counter_key(&queued.conversation_id);
            let confirmed = chat_wire::confirmed_send_counter(
                tx.get_account_meta(&counter_key)?.as_deref(),
                send_counter,
            )?;
            tx.put_account_meta(&counter_key, &confirmed.to_string(), ts)?;
            // Reconciliation of an old send can follow an archive-verified deletion.
            if tx.archive_frame_covered(&queued)? {
                wasm_archive_policy::observe_frame(tx, &queued)?;
                tx.dequeue_labyrinth_item(&queued.message_id)?;
                tx.delete_account_meta(&journal_key)?;
                row.plaintext_json = "{}".into();
                return Ok((row, gap_convo));
            }
            tx.insert_message(&row)?;
            let queued_bytes =
                serde_json::to_vec(&queued).map_err(|e| MLSError::Internal(e.to_string()))?;
            tx.put_labyrinth_state(
                &format!(
                    "native.message:{}:{}",
                    queued.conversation_id, queued.message_id
                ),
                &queued_bytes,
                ts,
            )?;
            tx.dequeue_labyrinth_item(&queued.message_id)?;
            wasm_archive_policy::enqueue(tx, &queued)?;
            tx.delete_account_meta(&journal_key)?;
            Ok((row, gap_convo))
        })
    }

    pub(crate) async fn remove_group_member_impl(
        &self,
        actor_role: MemberRole,
        conversation_id: &str,
        target_did: &str,
    ) -> Result<(), MLSError> {
        if target_did.trim().is_empty() {
            return Err(MLSError::invalid_input("target_did must not be empty"));
        }
        enforce_admin_removal_policy(&self.account_did, actor_role, &[target_did.to_string()])?;

        let convo_uuid = uuid_v4(conversation_id, "conversationId")?;
        let (session_token, canonical_dev_id) = self.require_live_session()?;
        let db = self.require_db_mls()?;
        let convo = db
            .backend()
            .get_conversation(conversation_id)?
            .ok_or_else(|| MLSError::group_not_found(format!("missing {conversation_id}")))?;
        let prior_coords = self.load_or_build_conversation_coords(conversation_id)?;
        let prior_sv = prior_coords["stateVersion"].as_i64().unwrap_or(0);
        let prior_epoch = prior_coords["epoch"].as_u64().unwrap_or(0);
        let prior_gen = prior_coords["generation"].as_i64().unwrap_or(0);
        let prior_gch = chat_wire::json_bytes(&prior_coords["groupContextHash"])?;
        let prior_ctag = chat_wire::json_bytes(&prior_coords["confirmationTag"])?;
        let transition_uuid = uuid::Uuid::new_v4();
        let transition_id = transition_uuid.to_string();

        let maybe_commit = {
            let backend = db.backend();
            if let Some(signer_raw) = backend.get_labyrinth_state("device_signer_json")? {
                let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let auth_gen = backend
                    .get_account_meta("auth_generation")?
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(1)
                    .max(1);
                let overlay = KvWriteOverlay::new(backend);
                let staged_opt = {
                    let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
                    if let Some(mut group) =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                    {
                        let prefix = format!("{target_did}#");
                        let mut target_leaves = Vec::new();
                        let mut removed_leaves = Vec::new();
                        for m in group.members() {
                            if let Ok(id_str) =
                                std::str::from_utf8(m.credential.serialized_content())
                            {
                                if let Some(dev_part) = id_str.strip_prefix(&prefix) {
                                    target_leaves.push(m.index);
                                    removed_leaves.push(json!({
                                        "$type": "blue.catbird.chat.defs#removeLeaf",
                                        "userDid": target_did,
                                        "deviceId": dev_part,
                                    }));
                                }
                            }
                        }
                        if target_leaves.is_empty() {
                            return Err(MLSError::MemberNotFound {
                                member_id: target_did.to_string(),
                            });
                        } else {
                            let prior_metadata =
                                wasm_archive_policy::metadata_snapshot_plaintext_for_carry_forward(
                                    backend,
                                    conversation_id,
                                    &mut group,
                                    &provider,
                                )?;
                            let aad_prior = chat_wire::build_aad_prior_coordinate(
                                &convo_uuid,
                                &convo.group_id,
                                prior_gen,
                                prior_sv,
                                prior_epoch as i64,
                                &prior_gch,
                                &prior_ctag,
                            );
                            let commit_aad_val = json!({
                                "protocolVersion": "1",
                                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                                "generation": prior_gen,
                                "transitionId": STANDARD.encode(transition_uuid.as_bytes()),
                                "prior": aad_prior,
                            });
                            let commit_aad_bytes = canonical_commit_aad_bytes(&commit_aad_val)
                                .map_err(|e| {
                                    MLSError::Cryptography(format!(
                                        "canonical_commit_aad_bytes: {e}"
                                    ))
                                })?;
                            group.set_aad(commit_aad_bytes);
                            let (commit_msg, _, _) = group
                                .remove_members(&provider, &signer, &target_leaves)
                                .map_err(|e| {
                                    MLSError::Cryptography(format!("remove_members: {e:?}"))
                                })?;
                            group.merge_pending_commit(&provider).map_err(|e| {
                                MLSError::Cryptography(format!("merge_pending_commit: {e:?}"))
                            })?;
                            group.set_aad(Vec::new());
                            let commit_bytes =
                                commit_msg.tls_serialize_detached().map_err(|e| {
                                    MLSError::Internal(format!("serialize commit: {e:?}"))
                                })?;
                            let next_epoch = group.epoch().as_u64();
                            let (next_gch, next_ctag) =
                                chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                            let carried_snap =
                                wasm_archive_policy::reencrypt_metadata_snapshot_for_epoch(
                                    prior_metadata,
                                    &mut group,
                                    &provider,
                                    &convo.group_id,
                                    &convo_uuid,
                                    prior_gen,
                                    next_epoch,
                                    &next_gch,
                                    &next_ctag,
                                )?;
                            Some((
                                commit_aad_val,
                                commit_bytes,
                                removed_leaves,
                                next_epoch,
                                next_gch,
                                next_ctag,
                                carried_snap,
                            ))
                        }
                    } else {
                        return Err(MLSError::group_not_found("missing MlsGroup"));
                    }
                };
                staged_opt.map(
                    |(
                        commit_aad_val,
                        commit_bytes,
                        removed_leaves,
                        next_epoch,
                        next_gch,
                        next_ctag,
                        carried_snap,
                    )| {
                        (
                            signer,
                            auth_gen,
                            commit_aad_val,
                            commit_bytes,
                            removed_leaves,
                            next_epoch,
                            next_gch,
                            next_ctag,
                            carried_snap,
                            overlay.into_batch(),
                        )
                    },
                )
            } else {
                return Err(MLSError::InvalidState("WasmMlsClient not enrolled".into()));
            }
        };

        if let Some((
            signer,
            auth_gen,
            commit_aad_val,
            commit_bytes,
            removed_leaves,
            next_epoch,
            next_gch,
            next_ctag,
            carried_snap,
            kv_batch,
        )) = maybe_commit
        {
            let next_coords = json!({
                "conversationId": conversation_id,
                "generation": prior_gen,
                "stateVersion": prior_sv + 1,
                "groupId": { "$bytes": STANDARD.encode(&convo.group_id) },
                "epoch": next_epoch,
                "groupContextHash": { "$bytes": STANDARD.encode(next_gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(&next_ctag) },
                "lifecycle": "active",
            });
            let commit_sha256: [u8; 32] = Sha256::digest(&commit_bytes).into();
            let body = json!({
                "$type": "blue.catbird.chat.defs#commitTransitionBody",
                "signatureDomain": "CATBIRD-CHAT-COMMIT\0",
                "transitionId": transition_id,
                "idempotencyKey": transition_id,
                "actorDid": self.account_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "signedAt": chat_wire::now_rfc3339_millis(),
                "prior": prior_coords,
                "next": next_coords,
                "aad": commit_aad_val,
                "manifest": {
                    "participantChanges": [{
                        "$type": "blue.catbird.chat.defs#removeParticipant",
                        "userDid": target_did,
                    }],
                    "leafChanges": removed_leaves,
                },
                "commit": {
                    "framing": "mlsMessage",
                    "contentType": "publicMessageCommit",
                    "bytes": { "$bytes": STANDARD.encode(&commit_bytes) },
                    "sha256": STANDARD.encode(commit_sha256),
                },
                "metadataSnapshot": carried_snap,
            });
            let pending = chat_wire::PendingCommitTransition {
                conversation_id: conversation_id.to_string(),
                transition_id,
                commit_sha256,
                prior: prior_coords,
                next: next_coords,
                kv_batch,
                removed_participant_did: Some(target_did.to_string()),
            };
            self.submit_own_commit(
                &session_token,
                &canonical_dev_id,
                auth_gen,
                &signer,
                &body,
                pending,
            )
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn update_group_metadata_impl(
        &self,
        conversation_id: &str,
        title: String,
        description: String,
    ) -> Result<GroupMetadataRow, MLSError> {
        let db = self.require_db_mls()?;
        let ts = now_ms();
        let backend = db.backend();
        let convo = backend
            .get_conversation(conversation_id)?
            .ok_or_else(|| MLSError::group_not_found(format!("missing {conversation_id}")))?;
        let existing_meta = backend.get_group_metadata(conversation_id)?;
        let next_ver = existing_meta
            .as_ref()
            .map(|m| m.metadata_version.saturating_add(1))
            .unwrap_or(1);
        let preserved_avatar = existing_meta
            .as_ref()
            .and_then(chat_wire::space_avatar_from_metadata_row);

        let mut meta_v1 = existing_meta
            .as_ref()
            .map(chat_wire::group_metadata_v1_from_row)
            .unwrap_or_else(|| GroupMetadataV1::new("", ""));
        meta_v1.version = 1;
        meta_v1.title = title.clone();
        meta_v1.description = description.clone();
        meta_v1.avatar_blob_locator = None;
        meta_v1.avatar_content_type = preserved_avatar
            .as_ref()
            .and_then(|avatar| avatar.mime_type.clone());
        meta_v1.space_avatar = preserved_avatar;
        meta_v1.extra.insert(
            "historyBackup".into(),
            json!(wasm_archive_policy::current_enabled(
                backend,
                conversation_id
            )?),
        );
        let serialized = serde_json::to_vec(&meta_v1)
            .map_err(|e| MLSError::Internal(format!("serialize GroupMetadataV1: {e}")))?;
        validate_metadata_snapshot_size(&serialized)?;

        let row = chat_wire::group_metadata_row_from_v1(
            conversation_id,
            next_ver,
            convo.epoch,
            &meta_v1,
            ts,
        )?;

        let maybe_live = if let (Some((session_token, dev_id)), Ok(convo_uuid), Some(signer_raw)) = (
            self.live_session(),
            uuid::Uuid::parse_str(conversation_id.trim()),
            backend.get_labyrinth_state("device_signer_json")?,
        ) {
            let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let auth_gen = backend
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            let overlay = KvWriteOverlay::new(backend);
            let snap_opt = {
                let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
                if let Some(mut group) =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                {
                    let epoch_u64 = group.epoch().as_u64();
                    let (gch, ctag) =
                        chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                    let meta_key = derive_metadata_key_from_group(
                        &mut group,
                        provider.crypto(),
                        provider.storage(),
                        &convo.group_id,
                        epoch_u64,
                    )
                    .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
                    let tid = uuid::Uuid::new_v4().to_string();
                    let mut nonce = [0u8; 12];
                    let _ = getrandom::getrandom(&mut nonce);
                    let ct = encrypt_metadata_snapshot_with_nonce(
                        &meta_key,
                        &convo.group_id,
                        epoch_u64,
                        next_ver as u64,
                        &nonce,
                        &meta_v1,
                    )?;
                    validate_metadata_snapshot_size(&ct)?;
                    let snap = json!({
                        "authorProof": {
                            "authGenerationAtOrigin": auth_gen,
                            "authorDeviceId": dev_id,
                            "authorDid": self.account_did,
                            "authorKeyId": derive_key_id(signer.public()),
                            "deviceStatusAtOrigin": "active",
                            "originSeq": convo.last_seq.saturating_add(1),
                            "originTransitionId": tid,
                            "roleAtOrigin": "admin",
                            "signaturePublicKey": STANDARD.encode(signer.public()),
                        },
                        "ciphertext": { "$bytes": STANDARD.encode(&ct) },
                        "ciphertextSha256": STANDARD.encode(Sha256::digest(&ct)),
                        "ciphertextSize": ct.len(),
                        "coordinate": {
                            "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
                            "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                            "epoch": epoch_u64,
                            "generation": convo.generation,
                            "groupContextHash": { "$bytes": STANDARD.encode(gch) },
                            "groupId": { "$bytes": STANDARD.encode(&convo.group_id) },
                        },
                        "metadataVersion": next_ver,
                        "nonce": { "$bytes": STANDARD.encode(nonce) },
                        "originTransitionId": tid,
                    });
                    Some((tid, snap))
                } else {
                    None
                }
            };
            snap_opt.map(|(tid, snap)| {
                (
                    session_token,
                    dev_id,
                    signer,
                    auth_gen,
                    tid,
                    snap,
                    overlay.into_batch(),
                )
            })
        } else {
            None
        };

        if let Some((session_token, dev_id, signer, auth_gen, tid, snap, kv_batch)) = maybe_live {
            let prior_coords = self.load_or_build_conversation_coords(conversation_id)?;
            let prior_sv = prior_coords["stateVersion"].as_i64().unwrap_or(0);
            let mut next_coords = prior_coords.clone();
            next_coords["stateVersion"] = json!(prior_sv + 1);
            let snap_str =
                serde_json::to_string(&snap).map_err(|e| MLSError::Internal(e.to_string()))?;
            let body = json!({
                "$type": "blue.catbird.chat.defs#metadataTransitionBody",
                "signatureDomain": "CATBIRD-CHAT-METADATA\0",
                "transitionId": tid,
                "idempotencyKey": tid,
                "actorDid": self.account_did,
                "actorDeviceId": dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "prior": prior_coords,
                "next": next_coords,
                "metadataSnapshot": snap,
                "signedAt": chat_wire::now_rfc3339_millis(),
            });
            // Verified as the transition signed here: its signed `next` is the new state.
            self.submit_signed_chat_op(
                &session_token,
                &dev_id,
                Some(auth_gen),
                CanonicalOperation::SubmitTransition,
                &body,
                &signer,
            )
            .await?;
            let coords_str = serde_json::to_string(&next_coords)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            db.write_tx(|tx| {
                kv_batch.apply(tx)?;
                tx.upsert_group_metadata(&row)?;
                if let Some(mut c) = tx.get_conversation(conversation_id)? {
                    c.title = row.title.clone();
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)?;
                }
                tx.put_account_meta(
                    &format!("metadata_snapshot_json:{conversation_id}"),
                    &snap_str,
                    ts,
                )?;
                tx.put_account_meta(
                    &format!("conversation_coords:{conversation_id}"),
                    &coords_str,
                    ts,
                )
            })?;
        } else {
            db.write_tx(|tx| {
                tx.upsert_group_metadata(&row)?;
                if let Some(mut c) = tx.get_conversation(conversation_id)? {
                    c.title = row.title.clone();
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)?;
                }
                Ok(())
            })?;
        }
        Ok(row)
    }

    /// Submit this device's own Commit-bearing transition `body` (`I6`: outside `write_tx`),
    /// journaled as `pending` under [`commit_transition_key`] before HTTP. A verified answer
    /// applies, in one transaction, the staged MLS batch, its epoch, the signed `next`, metadata
    /// snapshot and manifest participant effects on the verified roster, and the cursor (only
    /// onto the next entry), erases this journal and prunes every one it supersedes: `true`. A
    /// verified answer past a cursor gap changes nothing, since the entries before it still need
    /// this epoch's roster; the own echo in sync applies the journal: `false`. Either way the
    /// sequenced Commit moved the coordinate, so its verified answer drops any leaf-recovery
    /// authorization. A lost, transient or unverifiable answer is an error that keeps the
    /// journal for that echo; a terminal refusal erases this journal alone, since mls-ds will
    /// never sequence those bytes.
    pub(crate) async fn submit_own_commit(
        &self,
        session_token: &str,
        device_id: &str,
        auth_gen: i64,
        signer: &SignatureKeyPair,
        body: &Value,
        pending: chat_wire::PendingCommitTransition,
    ) -> Result<bool, MLSError> {
        let db = self.require_db_mls()?;
        let (cid, transition_id) = (
            pending.conversation_id.as_str(),
            pending.transition_id.as_str(),
        );
        db.write_tx(|tx| put_commit_transition(tx, &pending))?;
        let answer = match self
            .submit_signed_chat_op(
                session_token,
                device_id,
                Some(auth_gen),
                CanonicalOperation::SubmitTransition,
                body,
                signer,
            )
            .await
        {
            Ok(answer) => answer,
            Err(error) => {
                if is_terminal_refusal(&error) {
                    db.write_tx(|tx| remove_commit_transition(tx, cid, transition_id))?;
                }
                return Err(error);
            }
        };
        // `submit_signed_chat_op` verified this entry as the request signed here.
        let seq = answer["entry"]["seq"].as_i64().unwrap_or_default();
        let coords = serde_json::to_string(&pending.next)?;
        let snapshot = serde_json::to_string(&body["metadataSnapshot"])?;
        let generation = pending.next["generation"].as_i64().unwrap_or_default();
        let epoch = pending.next["epoch"].as_i64().unwrap_or_default();
        let ts = now_ms();
        db.write_tx(|tx| {
            tx.delete_account_meta(&chat_wire::leaf_recovery_authorization_key(cid))?;
            let convo = tx.get_conversation(cid)?;
            if convo
                .as_ref()
                .is_some_and(|c| seq > c.last_seq.saturating_add(1))
            {
                return Ok(false);
            }
            pending.kv_batch.apply(tx)?;
            if let Some(mut c) = convo {
                let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
                let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                    .map_err(|e| {
                        MLSError::Cryptography(format!("load group after own commit: {e:?}"))
                    })?
                    .ok_or_else(|| MLSError::group_not_found(cid))?;
                if let Some(prior) = pending.prior["epoch"].as_u64() {
                    crate::wasm_client_sync::advance_wasm_counter_epoch(
                        tx, cid, generation, prior, &group, ts,
                    )?;
                }
                c.epoch = epoch;
                if seq == c.last_seq.saturating_add(1) {
                    c.last_seq = seq;
                }
                c.updated_at_ms = ts;
                tx.upsert_conversation(&c)?;
            }
            tx.put_account_meta(&format!("metadata_snapshot_json:{cid}"), &snapshot, ts)?;
            tx.put_account_meta(&format!("conversation_coords:{cid}"), &coords, ts)?;
            // The verified answer applies its own transition, participant effects included; its
            // echo then moves only the cursor.
            if let Some(kind) = body["$type"]
                .as_str()
                .and_then(SignedMutationKind::from_type_id)
            {
                apply_verified_roster_effects(tx, cid, kind, body, ts)?;
            }
            remove_commit_transition(tx, cid, transition_id)?;
            prune_commit_transitions(tx, cid, generation, epoch, false)?;
            Ok(true)
        })
    }

    /// Close `conversation_id` on `mls-ds` (`O7`, `I14`): a `conversationCloseBody` retiring the
    /// current coordinate (`stateVersion + 1`, `superseded`), its exact `signedRequest` journaled
    /// under [`conversation_close_key`] before HTTP. A close already journaled is replayed byte
    /// for byte, never re-signed. Errors when the close is not applied yet; its journal then
    /// stays for [`Self::complete_pending_close`] unless mls-ds refused it for good.
    pub(crate) async fn close_conversation_live(
        &self,
        session_token: &str,
        device_id: &str,
        conversation_id: &str,
        conversation_kind: &str,
    ) -> Result<(), MLSError> {
        if self.is_conversation_closed(conversation_id)? {
            return Ok(());
        }
        let db = self.require_db_mls()?;
        let key = conversation_close_key(conversation_id);
        let raw = match db.backend().get_account_meta(&key)? {
            Some(raw) => raw,
            None => {
                let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
                let prior = self.load_or_build_conversation_coords(conversation_id)?;
                let mut retired = prior.clone();
                retired["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap_or(0) + 1);
                retired["lifecycle"] = json!("superseded");
                let transition = uuid::Uuid::new_v4().to_string();
                let body = json!({
                    "$type": "blue.catbird.chat.defs#conversationCloseBody",
                    "signatureDomain": "CATBIRD-CHAT-CLOSE\0",
                    "transitionId": transition,
                    "idempotencyKey": transition,
                    "actorDid": self.account_did,
                    "actorDeviceId": device_id,
                    "keyId": derive_key_id(signer.public()),
                    "authGeneration": auth_gen,
                    "conversationKind": conversation_kind,
                    "prior": prior,
                    "retired": retired,
                    "signedAt": chat_wire::now_rfc3339_millis(),
                });
                let prepared = chat_wire::sign_clean_chat_mutation(
                    &self.account_did,
                    device_id,
                    Some(auth_gen),
                    CanonicalOperation::CloseConversation,
                    &body,
                    &signer,
                )?;
                let mut wire: Value =
                    serde_json::from_slice(prepared.body.as_deref().unwrap_or_default())?;
                let raw = wire["signedRequest"].take().to_string();
                db.write_tx(|tx| tx.put_account_meta(&key, &raw, now_ms()))?;
                raw
            }
        };
        self.replay_journaled_close(session_token, conversation_id, &raw)
            .await
    }

    /// Sync replays this conversation's journaled close, if any, before its entries: a lost close
    /// answer never arrives as an echo once mls-ds wipes the conversation. `true` when the
    /// verified answer closed it; `false` when nothing is journaled or the replay failed (its
    /// journal stays for the next sync unless mls-ds refused it for good).
    pub(crate) async fn complete_pending_close(
        &self,
        session_token: &str,
        conversation_id: &str,
    ) -> Result<bool, MLSError> {
        let key = conversation_close_key(conversation_id);
        let Some(raw) = self.require_db_mls()?.backend().get_account_meta(&key)? else {
            return Ok(false);
        };
        Ok(self
            .replay_journaled_close(session_token, conversation_id, &raw)
            .await
            .is_ok())
    }

    /// POST the journaled close `raw` (the exact `signedRequest` JSON) of `cid`. A verified
    /// answer applies the terminal close at the coordinate this device signed, moving the cursor
    /// only onto the next entry; that write erases the journal. A lost, transient or
    /// unverifiable answer keeps the journal for the identical replay, which mls-ds answers with
    /// its recorded result even after the close wipe. A terminal refusal (e.g.
    /// `StaleCoordinates`) erases it: those bytes never land, and the next close signs afresh.
    async fn replay_journaled_close(
        &self,
        session_token: &str,
        cid: &str,
        raw: &str,
    ) -> Result<(), MLSError> {
        let request = format!("{{\"signedRequest\":{raw}}}").into_bytes();
        let answer = match self
            .ds_post_json(
                session_token,
                "blue.catbird.chat.closeConversation",
                request,
            )
            .await
        {
            Ok(answer) => answer,
            Err(error) => {
                if is_terminal_refusal(&error) {
                    self.require_db_mls()?
                        .write_tx(|tx| tx.delete_account_meta(&conversation_close_key(cid)))?;
                }
                return Err(error);
            }
        };
        let sent: Value = serde_json::from_str(raw)?;
        let answer: Value = serde_json::from_slice(&answer)
            .map_err(|error| MLSError::Cryptography(format!("parse close answer: {error}")))?;
        let seq = verify_own_close_answer(&answer, &sent, cid)?;
        let entry = answer
            .get("result")
            .unwrap_or(&answer)
            .get("entry")
            .ok_or_else(|| MLSError::Cryptography("own close answer missing entry".into()))?;
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        let (verified_body, request_digest) = chat_wire::verify_signed_mutation_body_and_digest(
            &entry["signedRequest"],
            SignedMutationKind::ConversationClose,
            signer.public(),
        )?;
        let sequencer_did = self
            .require_db_mls()?
            .backend()
            .get_conversation(cid)?
            .map(|conversation| conversation.sequencer_did)
            .unwrap_or_else(|| self.home_ds_did.clone());
        self.verify_control_entry_receipt(
            session_token,
            &sequencer_did,
            cid,
            entry,
            &verified_body,
            &request_digest,
        )
        .await?;
        let retired = chat_wire::canonicalize_wire_coordinate(&sent["body"]["retired"], None)?;
        let last_seq = self
            .require_db_mls()?
            .backend()
            .get_conversation(cid)?
            .map(|c| c.last_seq);
        let terminal_seq =
            Some(seq).filter(|seq| last_seq.map(|last| last.saturating_add(1)) == Some(*seq));
        self.apply_terminal_close(cid, Some(&retired), terminal_seq)
    }

    pub(crate) fn list_members_impl(&self, conversation_id: &str) -> Result<Vec<Value>, MLSError> {
        let db = self.require_db_mls()?;
        let Some(convo) = db.backend().get_conversation(conversation_id)? else {
            return Ok(Vec::new());
        };
        let provider = db.openmls_provider()?;
        let Some(group) = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
        else {
            return Ok(Vec::new());
        };
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for m in group.members() {
            if let Ok((did, _)) =
                chat_wire::parse_scoped_credential_did_device(m.credential.serialized_content())
            {
                if seen.insert(did.clone()) {
                    let role = if did == self.account_did {
                        "admin"
                    } else {
                        "member"
                    };
                    out.push(json!({
                        "did": did.clone(),
                        "handle": did,
                        "displayName": Value::Null,
                        "role": role,
                    }));
                }
            }
        }
        Ok(out)
    }

    /// Leave `conversation_id` cleanly (`FC-07`):
    /// - Re-archives local history into `OwnerMailbox` when Labyrinth is enrolled.
    /// - Closes `direct` or solo-admin 1-member `group` conversations via `close_conversation_live`.
    /// - Refuses `LastAdminCannotLeave` when this account is the sole active admin in a multi-member group.
    /// - Submits `#zeroLeafLeaveBody` (`CATBIRD-CHAT-LEAVE-ZERO-LEAF\0`) when `leaf_count == 0`.
    /// - Submits `#leaveRequestBody` (`CATBIRD-CHAT-LEAVE-REQUEST\0`) when `leaf_count > 0`.
    pub(crate) async fn leave_conversation_impl(
        &self,
        conversation_id: &str,
    ) -> Result<LeaveConversationOutcome, MLSError> {
        let convo_uuid = uuid_v4(conversation_id, "conversationId")?;
        let canonical_cid = convo_uuid.hyphenated().to_string();
        let (session_token, canonical_dev_id) = self.require_live_session()?;
        let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;

        let rearchived_messages = self
            .rearchive_conversation_before_leave_impl(&canonical_cid)
            .await
            .unwrap_or(0);

        let resp = self
            .ds_signed_get(
                &session_token,
                &canonical_dev_id,
                "blue.catbird.chat.getConversationState",
                &[
                    ("actorDeviceId", &canonical_dev_id),
                    ("conversationId", &canonical_cid),
                ],
                &signer,
            )
            .await?;
        let state = resp.get("state").unwrap_or(&resp);
        let prior =
            chat_wire::canonicalize_wire_coordinate(&state["coordinates"], Some(&canonical_cid))?;
        if prior["lifecycle"].as_str() != Some("active") {
            self.apply_terminal_close(&canonical_cid, Some(&prior), None)?;
            return Ok(LeaveConversationOutcome {
                left_immediately: true,
                leave_request_id: None,
                rearchived_messages,
            });
        }
        let kind = state
            .get("conversationKind")
            .or_else(|| state.get("kind"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                MLSError::Cryptography("getConversationState missing conversationKind".into())
            })?;
        if !matches!(kind, "direct" | "group") {
            return Err(MLSError::Cryptography(format!(
                "unsupported conversationKind `{kind}`"
            )));
        }
        let participants = state
            .get("participants")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                MLSError::Cryptography("getConversationState missing participants".into())
            })?;
        let Some(own) = participants
            .iter()
            .find(|p| p["userDid"].as_str() == Some(self.account_did.as_str()))
        else {
            self.apply_terminal_close(&canonical_cid, None, None)?;
            return Ok(LeaveConversationOutcome {
                left_immediately: true,
                leave_request_id: None,
                rearchived_messages,
            });
        };
        let active_admin =
            own["status"].as_str() == Some("active") && own["role"].as_str() == Some("admin");
        let active_participant_count = participants
            .iter()
            .filter(|p| matches!(p["status"].as_str(), Some("active" | "pending")))
            .count();
        let close = kind == "direct" || (active_participant_count <= 1 && active_admin);
        if kind == "group" && !close && active_admin {
            let another_active_admin = participants.iter().any(|p| {
                p["userDid"].as_str() != Some(self.account_did.as_str())
                    && p["status"].as_str() == Some("active")
                    && p["role"].as_str() == Some("admin")
            });
            if !another_active_admin {
                return Err(MLSError::InvalidState("LastAdminCannotLeave".into()));
            }
        }

        if close {
            // Ensure local coordinates exist when closing a conversation whose state was just fetched.
            let db = self.require_db_mls()?;
            if db
                .backend()
                .get_account_meta(&format!("conversation_coords:{canonical_cid}"))?
                .is_none()
            {
                let prior_str = serde_json::to_string(&prior)?;
                db.write_tx(|tx| {
                    tx.put_account_meta(
                        &format!("conversation_coords:{canonical_cid}"),
                        &prior_str,
                        now_ms(),
                    )
                })?;
            }
            self.close_conversation_live(&session_token, &canonical_dev_id, &canonical_cid, kind)
                .await?;
            return Ok(LeaveConversationOutcome {
                left_immediately: true,
                leave_request_id: None,
                rearchived_messages,
            });
        }

        let prior_sv = prior["stateVersion"].as_i64().unwrap_or(0);
        let request_id = uuid::Uuid::new_v4().to_string();
        let key_id = derive_key_id(signer.public());
        let leaf_count = own
            .get("leafCount")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| {
                state
                    .get("leaves")
                    .and_then(Value::as_array)
                    .map(|leaves| {
                        leaves
                            .iter()
                            .filter(|l| l["userDid"].as_str() == Some(self.account_did.as_str()))
                            .count() as u64
                    })
                    .unwrap_or(0)
            });

        if leaf_count == 0 {
            let mut next = prior.clone();
            next["stateVersion"] = json!(prior_sv + 1);
            let zero_body = json!({
                "$type": "blue.catbird.chat.defs#zeroLeafLeaveBody",
                "signatureDomain": "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0",
                "transitionId": request_id,
                "idempotencyKey": request_id,
                "actorDid": self.account_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": key_id,
                "authGeneration": auth_gen,
                "prior": prior,
                "next": next,
                "signedAt": chat_wire::now_rfc3339_millis(),
            });
            let answer = self
                .submit_signed_chat_op(
                    &session_token,
                    &canonical_dev_id,
                    Some(auth_gen),
                    CanonicalOperation::RequestLeave,
                    &zero_body,
                    &signer,
                )
                .await?;
            let seq = answer
                .get("result")
                .unwrap_or(&answer)
                .pointer("/entry/seq")
                .and_then(Value::as_i64);
            self.apply_terminal_close(&canonical_cid, None, seq)?;
            return Ok(LeaveConversationOutcome {
                left_immediately: true,
                leave_request_id: None,
                rearchived_messages,
            });
        }

        if let Some(existing_id) = resp
            .get("pendingLeaveRequests")
            .and_then(Value::as_array)
            .and_then(|reqs| {
                reqs.iter().find_map(|req| {
                    let is_mine = req["requesterDid"].as_str() == Some(self.account_did.as_str());
                    let is_pending = req["status"].as_str() == Some("pending");
                    let same_coord = chat_wire::canonicalize_wire_coordinate(
                        &req["prior"],
                        Some(&canonical_cid),
                    )
                    .ok()
                    .as_ref()
                        == Some(&prior);
                    (is_mine && is_pending && same_coord)
                        .then(|| req["leaveRequestId"].as_str().map(str::to_owned))
                        .flatten()
                })
            })
        {
            return Ok(LeaveConversationOutcome {
                left_immediately: false,
                leave_request_id: Some(existing_id),
                rearchived_messages,
            });
        }

        let leave_body = json!({
            "$type": "blue.catbird.chat.defs#leaveRequestBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-REQUEST\0",
            "leaveRequestId": request_id,
            "idempotencyKey": request_id,
            "actorDid": self.account_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": key_id,
            "authGeneration": auth_gen,
            "prior": prior,
            "signedAt": chat_wire::now_rfc3339_millis(),
        });
        let answer = self
            .submit_signed_chat_op(
                &session_token,
                &canonical_dev_id,
                Some(auth_gen),
                CanonicalOperation::RequestLeave,
                &leave_body,
                &signer,
            )
            .await?;
        let res = answer.get("result").unwrap_or(&answer);
        if res
            .get("$type")
            .and_then(Value::as_str)
            .is_some_and(|t| t != "blue.catbird.chat.defs#durableLeaveRequestResult")
        {
            return Err(MLSError::Cryptography(
                "unexpected RequestLeave response variant".into(),
            ));
        }
        Ok(LeaveConversationOutcome {
            left_immediately: false,
            leave_request_id: Some(request_id),
            rearchived_messages,
        })
    }

    pub(crate) async fn fulfill_pending_group_leaves_impl(&self) -> Result<u32, MLSError> {
        let (session_token, canonical_dev_id) = self.require_live_session()?;
        let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        let convos = self
            .require_db_mls()?
            .backend()
            .list_conversations(None, 200)?;
        let mut total = 0u32;
        for convo in convos {
            if self.is_conversation_closed(&convo.conversation_id)? {
                continue;
            }
            if let Ok(done) = self
                .fulfill_pending_group_leave_for_conversation(
                    &session_token,
                    &canonical_dev_id,
                    &signer,
                    auth_gen,
                    &convo.conversation_id,
                )
                .await
            {
                total = total.saturating_add(done);
            }
        }
        Ok(total)
    }

    pub(crate) async fn fulfill_pending_group_leave_for_conversation(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_gen: i64,
        conversation_id: &str,
    ) -> Result<u32, MLSError> {
        let Ok(convo_uuid) = uuid_v4(conversation_id, "conversationId") else {
            return Ok(0);
        };
        let canonical_cid = convo_uuid.hyphenated().to_string();
        if self.is_conversation_closed(&canonical_cid)? {
            return Ok(0);
        }
        let resp = match self
            .ds_signed_get(
                session_token,
                canonical_dev_id,
                "blue.catbird.chat.getConversationState",
                &[
                    ("actorDeviceId", canonical_dev_id),
                    ("conversationId", &canonical_cid),
                ],
                signer,
            )
            .await
        {
            Ok(resp) => resp,
            Err(_) => return Ok(0),
        };
        let Some(requests) = resp
            .get("pendingLeaveRequests")
            .and_then(Value::as_array)
            .filter(|r| !r.is_empty())
        else {
            return Ok(0);
        };
        let state = resp.get("state").unwrap_or(&resp);
        if state
            .get("conversationKind")
            .or_else(|| state.get("kind"))
            .and_then(Value::as_str)
            != Some("group")
        {
            return Ok(0);
        }
        let prior =
            chat_wire::canonicalize_wire_coordinate(&state["coordinates"], Some(&canonical_cid))?;
        if prior["lifecycle"].as_str() != Some("active") {
            return Ok(0);
        }
        let local_coords = self.load_or_build_conversation_coords(&canonical_cid)?;
        if chat_wire::canonicalize_wire_coordinate(&local_coords, Some(&canonical_cid))? != prior {
            return Ok(0);
        }
        let participants = state
            .get("participants")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let ts = now_ms();
        let mut sorted_reqs: Vec<&Value> = requests.iter().collect();
        sorted_reqs.sort_by_key(|r| r["requestedAt"].as_str());
        let chosen = sorted_reqs.into_iter().find_map(|req| {
            if req["status"].as_str() != Some("pending") {
                return None;
            }
            let requester_did = req["requesterDid"].as_str()?;
            if requester_did == self.account_did {
                return None;
            }
            if let Some(exp_str) = req["expiresAt"].as_str() {
                if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp_str) {
                    if exp_dt.timestamp_millis() <= ts {
                        return None;
                    }
                }
            }
            let req_prior =
                chat_wire::canonicalize_wire_coordinate(&req["prior"], Some(&canonical_cid))
                    .ok()?;
            if req_prior != prior {
                return None;
            }
            let req_p = participants
                .iter()
                .find(|p| p["userDid"].as_str() == Some(requester_did))?;
            if req_p["status"].as_str() != Some("active") {
                return None;
            }
            if req_p["role"].as_str() == Some("admin") {
                let other_admin = participants.iter().any(|p| {
                    p["userDid"].as_str() != Some(requester_did)
                        && p["status"].as_str() == Some("active")
                        && p["role"].as_str() == Some("admin")
                });
                if !other_admin {
                    return None;
                }
            }
            let leave_request_id = req["leaveRequestId"].as_str()?.to_owned();
            Some((leave_request_id, requester_did.to_owned()))
        });
        let Some((leave_request_id, requester_did)) = chosen else {
            return Ok(0);
        };

        let db = self.require_db_mls()?;
        let Some(convo) = db.backend().get_conversation(&canonical_cid)? else {
            return Ok(0);
        };
        let prior_sv = prior["stateVersion"].as_i64().unwrap_or(0);
        let prior_epoch = prior["epoch"].as_u64().unwrap_or(0);
        let prior_gen = prior["generation"].as_i64().unwrap_or(0);
        let prior_gch = chat_wire::json_bytes(&prior["groupContextHash"])?;
        let prior_ctag = chat_wire::json_bytes(&prior["confirmationTag"])?;
        let transition_uuid = uuid::Uuid::new_v4();
        let transition_id = transition_uuid.to_string();

        let staged = {
            let backend = db.backend();
            let overlay = KvWriteOverlay::new(backend);
            let inner = {
                let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
                let Some(mut group) =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                else {
                    return Ok(0);
                };
                let own_scoped = format!("{}#{canonical_dev_id}", self.account_did);
                if !group.members().any(|m| {
                    std::str::from_utf8(m.credential.serialized_content())
                        == Ok(own_scoped.as_str())
                }) {
                    return Ok(0);
                }
                let prefix = format!("{requester_did}#");
                let mut target_leaves = Vec::new();
                let mut removed_leaves = Vec::new();
                for m in group.members() {
                    if let Ok(id_str) = std::str::from_utf8(m.credential.serialized_content()) {
                        if let Some(dev_part) = id_str.strip_prefix(&prefix) {
                            target_leaves.push(m.index);
                            removed_leaves.push(json!({
                                "$type": "blue.catbird.chat.defs#removeLeaf",
                                "userDid": requester_did,
                                "deviceId": dev_part,
                            }));
                        }
                    }
                }
                if target_leaves.is_empty() {
                    return Ok(0);
                }
                let prior_metadata =
                    wasm_archive_policy::metadata_snapshot_plaintext_for_carry_forward(
                        backend,
                        &canonical_cid,
                        &mut group,
                        &provider,
                    )?;
                let aad_prior = chat_wire::build_aad_prior_coordinate(
                    &convo_uuid,
                    &convo.group_id,
                    prior_gen,
                    prior_sv,
                    prior_epoch as i64,
                    &prior_gch,
                    &prior_ctag,
                );
                let commit_aad_val = json!({
                    "protocolVersion": "1",
                    "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                    "generation": prior_gen,
                    "transitionId": STANDARD.encode(transition_uuid.as_bytes()),
                    "prior": aad_prior,
                });
                let commit_aad_bytes = canonical_commit_aad_bytes(&commit_aad_val)
                    .map_err(|e| MLSError::Cryptography(format!("commit AAD: {e}")))?;
                group.set_aad(commit_aad_bytes);
                let (commit_msg, _, _) = group
                    .remove_members(&provider, signer, &target_leaves)
                    .map_err(|e| MLSError::Cryptography(format!("remove_members: {e:?}")))?;
                group
                    .merge_pending_commit(&provider)
                    .map_err(|e| MLSError::Cryptography(format!("merge_pending_commit: {e:?}")))?;
                group.set_aad(Vec::new());
                let commit_bytes = commit_msg
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize commit: {e:?}")))?;
                let next_epoch = group.epoch().as_u64();
                let (next_gch, next_ctag) =
                    chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                let carried_snap =
                    wasm_archive_policy::reencrypt_metadata_snapshot_for_epoch(
                        prior_metadata,
                        &mut group,
                        &provider,
                        &convo.group_id,
                        &convo_uuid,
                        prior_gen,
                        next_epoch,
                        &next_gch,
                        &next_ctag,
                    )?;
                (
                    commit_aad_val,
                    commit_bytes,
                    removed_leaves,
                    next_epoch,
                    next_gch,
                    next_ctag,
                    carried_snap,
                )
            };
            (inner, overlay.into_batch())
        };
        let (
            (
                commit_aad_val,
                commit_bytes,
                removed_leaves,
                next_epoch,
                next_gch,
                next_ctag,
                carried_snap,
            ),
            kv_batch,
        ) = staged;
        let next_coords = json!({
            "conversationId": canonical_cid,
            "generation": prior_gen,
            "stateVersion": prior_sv + 1,
            "groupId": { "$bytes": STANDARD.encode(&convo.group_id) },
            "epoch": next_epoch,
            "groupContextHash": { "$bytes": STANDARD.encode(next_gch) },
            "confirmationTag": { "$bytes": STANDARD.encode(&next_ctag) },
            "lifecycle": "active",
        });
        let commit_sha256: [u8; 32] = Sha256::digest(&commit_bytes).into();
        let body = json!({
            "$type": "blue.catbird.chat.defs#leaveCommitFulfillmentBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0",
            "transitionId": transition_id,
            "idempotencyKey": transition_id,
            "leaveRequestId": leave_request_id,
            "actorDid": self.account_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_gen,
            "signedAt": chat_wire::now_rfc3339_millis(),
            "prior": prior,
            "next": next_coords,
            "aad": commit_aad_val,
            "manifest": {
                "participantChanges": [{
                    "$type": "blue.catbird.chat.defs#removeParticipant",
                    "userDid": requester_did,
                }],
                "leafChanges": removed_leaves,
            },
            "commit": {
                "framing": "mlsMessage",
                "contentType": "publicMessageCommit",
                "bytes": { "$bytes": STANDARD.encode(&commit_bytes) },
                "sha256": STANDARD.encode(commit_sha256),
            },
            "metadataSnapshot": carried_snap,
        });
        let pending = chat_wire::PendingCommitTransition {
            conversation_id: canonical_cid,
            transition_id,
            commit_sha256,
            prior,
            next: next_coords,
            kv_batch,
            removed_participant_did: Some(requester_did),
        };
        let applied = self
            .submit_own_commit(
                session_token,
                canonical_dev_id,
                auth_gen,
                signer,
                &body,
                pending,
            )
            .await?;
        Ok(u32::from(applied))
    }

    /// Remove a specific revoked own-account device leaf (`{account_did}#{target_device_id}`) from
    /// every active local MLS group without removing the account participant.
    pub(crate) async fn remove_specific_device_from_active_groups_impl(
        &self,
        target_device_id: &str,
    ) -> Result<u32, MLSError> {
        let (session_token, canonical_dev_id) = self.require_live_session()?;
        let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        let target_scoped = format!("{}#{target_device_id}", self.account_did);
        let convos = self
            .require_db_mls()?
            .backend()
            .list_conversations(None, 200)?;
        let mut updated = 0u32;
        for convo in convos {
            let cid = &convo.conversation_id;
            if self.is_conversation_closed(cid)? {
                continue;
            }
            let Ok(convo_uuid) = uuid_v4(cid, "conversationId") else {
                continue;
            };
            let Ok(prior) = self.load_or_build_conversation_coords(cid) else {
                continue;
            };
            let prior_sv = prior["stateVersion"].as_i64().unwrap_or(0);
            let prior_epoch = prior["epoch"].as_u64().unwrap_or(0);
            let prior_gen = prior["generation"].as_i64().unwrap_or(0);
            let (Ok(prior_gch), Ok(prior_ctag)) = (
                chat_wire::json_bytes(&prior["groupContextHash"]),
                chat_wire::json_bytes(&prior["confirmationTag"]),
            ) else {
                continue;
            };
            let transition_uuid = uuid::Uuid::new_v4();
            let transition_id = transition_uuid.to_string();
            let db = self.require_db_mls()?;
            let staged_opt = {
                let backend = db.backend();
                let overlay = KvWriteOverlay::new(backend);
                let inner_opt = {
                    let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
                    let Some(mut group) =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                    else {
                        continue;
                    };
                    let mut target_leaves = Vec::new();
                    let mut removed_leaves = Vec::new();
                    for m in group.members() {
                        if std::str::from_utf8(m.credential.serialized_content())
                            == Ok(target_scoped.as_str())
                        {
                            target_leaves.push(m.index);
                            removed_leaves.push(json!({
                                "$type": "blue.catbird.chat.defs#removeLeaf",
                                "userDid": self.account_did,
                                "deviceId": target_device_id,
                            }));
                        }
                    }
                    if target_leaves.is_empty() {
                        None
                    } else {
                        let prior_metadata =
                            wasm_archive_policy::metadata_snapshot_plaintext_for_carry_forward(
                                backend,
                                cid,
                                &mut group,
                                &provider,
                            )?;
                        let aad_prior = chat_wire::build_aad_prior_coordinate(
                            &convo_uuid,
                            &convo.group_id,
                            prior_gen,
                            prior_sv,
                            prior_epoch as i64,
                            &prior_gch,
                            &prior_ctag,
                        );
                        let commit_aad_val = json!({
                            "protocolVersion": "1",
                            "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                            "generation": prior_gen,
                            "transitionId": STANDARD.encode(transition_uuid.as_bytes()),
                            "prior": aad_prior,
                        });
                        let commit_aad_bytes = canonical_commit_aad_bytes(&commit_aad_val)
                            .map_err(|e| MLSError::Cryptography(format!("commit AAD: {e}")))?;
                        group.set_aad(commit_aad_bytes);
                        let (commit_msg, _, _) = group
                            .remove_members(&provider, &signer, &target_leaves)
                            .map_err(|e| {
                                MLSError::Cryptography(format!("remove_members: {e:?}"))
                            })?;
                        group
                            .merge_pending_commit(&provider)
                            .map_err(|e| MLSError::Cryptography(format!("merge_commit: {e:?}")))?;
                        group.set_aad(Vec::new());
                        let commit_bytes = commit_msg
                            .tls_serialize_detached()
                            .map_err(|e| MLSError::Internal(format!("serialize commit: {e:?}")))?;
                        let next_epoch = group.epoch().as_u64();
                        let (next_gch, next_ctag) =
                            chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                        let carried_snap =
                            wasm_archive_policy::reencrypt_metadata_snapshot_for_epoch(
                                prior_metadata,
                                &mut group,
                                &provider,
                                &convo.group_id,
                                &convo_uuid,
                                prior_gen,
                                next_epoch,
                                &next_gch,
                                &next_ctag,
                            )?;
                        Some((
                            commit_aad_val,
                            commit_bytes,
                            removed_leaves,
                            next_epoch,
                            next_gch,
                            next_ctag,
                            carried_snap,
                        ))
                    }
                };
                inner_opt.map(|inner| (inner, overlay.into_batch()))
            };
            let Some((
                (
                    commit_aad_val,
                    commit_bytes,
                    removed_leaves,
                    next_epoch,
                    next_gch,
                    next_ctag,
                    carried_snap,
                ),
                kv_batch,
            )) = staged_opt
            else {
                continue;
            };
            let next_coords = json!({
                "conversationId": cid,
                "generation": prior_gen,
                "stateVersion": prior_sv + 1,
                "groupId": { "$bytes": STANDARD.encode(&convo.group_id) },
                "epoch": next_epoch,
                "groupContextHash": { "$bytes": STANDARD.encode(next_gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(&next_ctag) },
                "lifecycle": "active",
            });
            let commit_sha256: [u8; 32] = Sha256::digest(&commit_bytes).into();
            let body = json!({
                "$type": "blue.catbird.chat.defs#commitTransitionBody",
                "signatureDomain": "CATBIRD-CHAT-COMMIT\0",
                "transitionId": transition_id,
                "idempotencyKey": transition_id,
                "actorDid": self.account_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "signedAt": chat_wire::now_rfc3339_millis(),
                "prior": prior,
                "next": next_coords,
                "aad": commit_aad_val,
                "manifest": {
                    "participantChanges": [],
                    "leafChanges": removed_leaves,
                },
                "commit": {
                    "framing": "mlsMessage",
                    "contentType": "publicMessageCommit",
                    "bytes": { "$bytes": STANDARD.encode(&commit_bytes) },
                    "sha256": STANDARD.encode(commit_sha256),
                },
                "metadataSnapshot": carried_snap,
            });
            let pending = chat_wire::PendingCommitTransition {
                conversation_id: cid.clone(),
                transition_id,
                commit_sha256,
                prior,
                next: next_coords,
                kv_batch,
                removed_participant_did: None,
            };
            if self
                .submit_own_commit(
                    &session_token,
                    &canonical_dev_id,
                    auth_gen,
                    &signer,
                    &body,
                    pending,
                )
                .await
                .is_ok()
            {
                updated = updated.saturating_add(1);
            }
        }
        Ok(updated)
    }
}

/// Match an own-device entry (`status == "active"` or `"pending_approval"`) under `(device_id, pub_key)`,
/// mirroring `chat_wire::own_active_device` widened for Wave-2 `pending_approval` devices.
fn own_enrolled_device_entry<'a>(
    devices: &'a Value,
    canonical_device_id: &str,
    pub_key: &[u8],
) -> Option<&'a Value> {
    devices["items"].as_array()?.iter().find(|item| {
        let dev = item.get("device").unwrap_or(item);
        let status = dev["status"].as_str().unwrap_or("");
        dev["deviceId"].as_str() == Some(canonical_device_id)
            && chat_wire::json_bytes(&dev["signaturePublicKey"])
                .ok()
                .as_deref()
                == Some(pub_key)
            && matches!(status, "active" | "pending_approval")
    })
}

/// Root DIDs of `group`'s members (credential `did#device`), sorted and unique: the send- or
/// receive-time MLS roster a queued archive item carries.
pub(crate) fn member_root_dids(group: &MlsGroup) -> Result<Vec<String>, MLSError> {
    let mut dids = std::collections::BTreeSet::new();
    for member in group.members() {
        let identity = std::str::from_utf8(member.credential.serialized_content())
            .map_err(|_| MLSError::Cryptography("non-UTF8 member credential".into()))?;
        let (did, _) = identity
            .split_once('#')
            .filter(|(did, device)| did.starts_with("did:") && !device.is_empty())
            .ok_or_else(|| MLSError::Cryptography("unscoped member credential".into()))?;
        dids.insert(did.to_owned());
    }
    Ok(dids.into_iter().collect())
}
