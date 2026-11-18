//! Browser storage adapter for the sequenced history-backup policy in the shared client.
//! All clean-slate Web archive queue writes pass through `enqueue`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use openmls::prelude::MlsGroup;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use catbird_mls::client::chat_wire;
use catbird_mls::client::QueuedLabyrinthArchivePayload;
use catbird_mls::direct_request_bootstrap;
use catbird_mls::groups::metadata_v1::validate_metadata_snapshot_size;
use catbird_mls::metadata::{
    decrypt_metadata_snapshot_plaintext, derive_metadata_key_from_group,
    encrypt_metadata_snapshot_plaintext_with_nonce, GroupMetadataV1,
};
use catbird_mls::storage::driver_wasm::WasmSqlBackend;
use catbird_mls::storage::{GroupMetadataRow, LabyrinthQueueRow};
use catbird_mls::MLSError;

const HISTORY_BACKUP: &str = "historyBackup";
const FLIPS_PREFIX: &str = "archive.policy.flips:";

fn metadata_nonce() -> Result<[u8; 12], MLSError> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| MLSError::Internal(format!("metadata nonce: {error}")))?;
    Ok(nonce)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Flip {
    seq: i64,
    enabled: bool,
}

fn flip_key(conversation_id: &str) -> String {
    format!("{FLIPS_PREFIX}{conversation_id}")
}

fn flips(tx: &impl WasmSqlBackend, conversation_id: &str) -> Result<Vec<Flip>, MLSError> {
    tx.get_account_meta(&flip_key(conversation_id))?
        .map(|raw| {
            serde_json::from_str(&raw).map_err(|e| {
                MLSError::Cryptography(format!("invalid archive policy flip log: {e}"))
            })
        })
        .transpose()
        .map(|flips| flips.unwrap_or_default())
}

fn metadata_enabled(metadata: &GroupMetadataV1) -> bool {
    match metadata.extra.get(HISTORY_BACKUP) {
        None => true,
        Some(value) => value.as_bool().unwrap_or(false),
    }
}

fn row_enabled(row: &GroupMetadataRow) -> bool {
    serde_json::from_str::<GroupMetadataV1>(&row.metadata_json)
        .map(|metadata| metadata_enabled(&metadata))
        .unwrap_or(false)
}

pub(crate) fn current_enabled(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
) -> Result<bool, MLSError> {
    if let Some(last) = flips(tx, conversation_id)?.last() {
        return Ok(last.enabled);
    }
    Ok(tx
        .get_group_metadata(conversation_id)?
        .as_ref()
        .is_none_or(row_enabled))
}

enum MetadataCarryScheme {
    Legacy,
    Canonical { origin_transition_id: String },
}

/// Authenticated prior metadata held only across one Commit build.
pub(crate) struct MetadataCarryForward {
    snapshot: Value,
    plaintext: Vec<u8>,
    nonce: [u8; 12],
    ciphertext_len: usize,
    scheme: MetadataCarryScheme,
}

impl MetadataCarryForward {
    pub(crate) fn snapshot(&self) -> &Value {
        &self.snapshot
    }

    pub(crate) fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

pub(crate) struct DecryptedMetadataSnapshot {
    pub(crate) epoch: u64,
    pub(crate) metadata_version: u64,
    pub(crate) metadata: GroupMetadataV1,
    pub(crate) plaintext: Vec<u8>,
    nonce: [u8; 12],
    ciphertext_len: usize,
    scheme: MetadataCarryScheme,
}

fn canonical_metadata_coordinates_from_wire(coordinate: &Value) -> Result<Value, MLSError> {
    let refused =
        |what: &str| MLSError::Cryptography(format!("metadata carry-forward: {what}"));
    let conversation_id = uuid::Uuid::from_slice(&chat_wire::json_bytes(
        coordinate
            .get("conversationId")
            .ok_or_else(|| refused("missing conversation id"))?,
    )?)
    .map_err(|_| refused("invalid conversation id"))?;
    let group_id = chat_wire::json_bytes(
        coordinate
            .get("groupId")
            .ok_or_else(|| refused("missing group id"))?,
    )?;
    let generation = coordinate
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| refused("missing generation"))?;
    let epoch = coordinate
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| refused("missing epoch"))?;
    let group_context_hash = chat_wire::json_bytes(
        coordinate
            .get("groupContextHash")
            .ok_or_else(|| refused("missing group context hash"))?,
    )?;
    let confirmation_tag = chat_wire::json_bytes(
        coordinate
            .get("confirmationTag")
            .ok_or_else(|| refused("missing confirmation tag"))?,
    )?;
    Ok(direct_request_bootstrap::canonical_metadata_coordinates(
        &conversation_id.to_string(),
        &group_id,
        generation,
        epoch,
        &group_context_hash,
        &confirmation_tag,
    ))
}

fn metadata_carry_scheme(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
    snapshot: &Value,
    metadata_version: u64,
) -> Result<MetadataCarryScheme, MLSError> {
    let refused = |what: &str| MLSError::Cryptography(format!("metadata snapshot: {what}"));
    let origin_transition_id = snapshot
        .get("originTransitionId")
        .and_then(Value::as_str)
        .ok_or_else(|| refused("missing authenticated origin"))?
        .to_owned();
    if !snapshot.get("authorProof").is_some_and(Value::is_object) {
        return Err(refused("missing authenticated origin"));
    }
    match tx.get_request(&origin_transition_id)? {
        Some(request) if request.conversation_id == conversation_id => {
            if metadata_version != 1 {
                return Err(refused("canonical metadata version is not 1"));
            }
            Ok(MetadataCarryScheme::Canonical {
                origin_transition_id,
            })
        }
        _ => Ok(MetadataCarryScheme::Legacy),
    }
}

/// Decrypt a snapshot against the group's current epoch without normalizing its plaintext.
/// Callers can therefore distinguish a byte-identical epoch carry from an authored metadata
/// transition.
pub(crate) fn decrypt_metadata_snapshot_for_current_group<P: OpenMlsProvider>(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
    snapshot: &Value,
    group: &mut MlsGroup,
    provider: &P,
) -> Result<DecryptedMetadataSnapshot, MLSError> {
    let refused = |what: &str| MLSError::Cryptography(format!("metadata snapshot: {what}"));
    let coordinate = snapshot
        .get("coordinate")
        .and_then(Value::as_object)
        .ok_or_else(|| refused("missing coordinate"))?;
    let epoch = coordinate
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| refused("missing epoch"))?;
    let group_id = group.group_id().as_slice().to_vec();
    if epoch != group.epoch().as_u64()
        || chat_wire::json_bytes(
            coordinate
                .get("groupId")
                .ok_or_else(|| refused("missing group id"))?,
        )? != group_id
    {
        return Err(MLSError::InvalidState("StaleMetadataSnapshot".into()));
    }
    let convo_uuid = uuid::Uuid::parse_str(conversation_id)
        .map_err(|_| refused("invalid conversation id"))?;
    if chat_wire::json_bytes(
        coordinate
            .get("conversationId")
            .ok_or_else(|| refused("missing conversation id"))?,
    )? != convo_uuid.as_bytes()
    {
        return Err(refused("snapshot names another conversation"));
    }
    let (group_context_hash, confirmation_tag) =
        chat_wire::compute_group_context_hash_and_tag(group, provider)?;
    let snapshot_group_context_hash = chat_wire::json_bytes(
        coordinate
            .get("groupContextHash")
            .ok_or_else(|| refused("missing group context hash"))?,
    )?;
    let snapshot_confirmation_tag = chat_wire::json_bytes(
        coordinate
            .get("confirmationTag")
            .ok_or_else(|| refused("missing confirmation tag"))?,
    )?;
    if snapshot_group_context_hash.as_slice() != group_context_hash.as_slice()
        || snapshot_confirmation_tag.as_slice() != confirmation_tag.as_slice()
    {
        return Err(MLSError::InvalidState("StaleMetadataSnapshot".into()));
    }
    let metadata_version = snapshot
        .get("metadataVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| refused("missing metadata version"))?;
    let scheme = metadata_carry_scheme(tx, conversation_id, snapshot, metadata_version)?;
    let nonce_vec = chat_wire::json_bytes(
        snapshot
            .get("nonce")
            .ok_or_else(|| refused("missing nonce"))?,
    )?;
    let nonce: [u8; 12] = nonce_vec
        .try_into()
        .map_err(|_| refused("invalid nonce"))?;
    let ciphertext = chat_wire::json_bytes(
        snapshot
            .get("ciphertext")
            .ok_or_else(|| refused("missing ciphertext"))?,
    )?;
    let declared_size = snapshot
        .get("ciphertextSize")
        .and_then(Value::as_u64)
        .and_then(|size| usize::try_from(size).ok())
        .ok_or_else(|| refused("missing ciphertext size"))?;
    let declared_hash = chat_wire::json_bytes(
        snapshot
            .get("ciphertextSha256")
            .ok_or_else(|| refused("missing ciphertext digest"))?,
    )?;
    if declared_size != ciphertext.len()
        || declared_hash.as_slice() != Sha256::digest(&ciphertext).as_slice()
    {
        return Err(refused("ciphertext binding mismatch"));
    }
    let plaintext = match &scheme {
        MetadataCarryScheme::Legacy => {
            let metadata_key = derive_metadata_key_from_group(
                group,
                provider.crypto(),
                provider.storage(),
                &group_id,
                epoch,
            )
            .map_err(|error| refused(&format!("derive metadata key: {error}")))?;
            decrypt_metadata_snapshot_plaintext(
                &metadata_key,
                &group_id,
                epoch,
                metadata_version,
                &nonce,
                &ciphertext,
            )
            .map_err(|error| refused(&format!("decrypt snapshot: {error}")))?
        }
        MetadataCarryScheme::Canonical {
            origin_transition_id,
        } => {
            let coordinates = canonical_metadata_coordinates_from_wire(&snapshot["coordinate"])?;
            let metadata_key =
                direct_request_bootstrap::request_metadata_key(group, provider, &coordinates)
                    .map_err(|error| {
                        refused(&format!("derive canonical metadata key: {error}"))
                    })?;
            direct_request_bootstrap::open_request_metadata(
                &metadata_key,
                &coordinates,
                origin_transition_id,
                &nonce,
                &ciphertext,
            )
            .map_err(|error| refused(&format!("decrypt canonical snapshot: {error}")))?
        }
    };
    validate_metadata_snapshot_size(&plaintext)?;
    let metadata = match &scheme {
        MetadataCarryScheme::Legacy => serde_json::from_slice(&plaintext)
            .map_err(|_| refused("invalid metadata plaintext"))?,
        MetadataCarryScheme::Canonical { .. } => {
            direct_request_bootstrap::decode_request_metadata(&plaintext)
                .map_err(|_| refused("invalid canonical metadata plaintext"))?
        }
    };
    Ok(DecryptedMetadataSnapshot {
        epoch,
        metadata_version,
        metadata,
        plaintext,
        nonce,
        ciphertext_len: ciphertext.len(),
        scheme,
    })
}

fn encoded_bytes_equal(prior: &Value, next: &Value) -> bool {
    prior == next
        || chat_wire::json_bytes(prior)
            .ok()
            .zip(chat_wire::json_bytes(next).ok())
            .is_some_and(|(prior, next)| prior == next)
}

fn object_equal_with_byte_fields(prior: &Value, next: &Value, byte_fields: &[&str]) -> bool {
    let (Some(prior), Some(next)) = (prior.as_object(), next.as_object()) else {
        return false;
    };
    prior.len() == next.len()
        && prior.iter().all(|(field, value)| {
            next.get(field).is_some_and(|next_value| {
                if byte_fields.contains(&field.as_str()) {
                    encoded_bytes_equal(value, next_value)
                } else {
                    value == next_value
                }
            })
        })
}

fn invariant_envelope_value_equal(field: &str, prior: &Value, next: &Value) -> bool {
    match field {
        // Older local snapshots may retain the permissive `{"$bytes": ...}` JSON view while
        // generated wire types use the canonical base64 string. The bytes themselves are the
        // immutable proof/binding.
        "authorProof" => {
            object_equal_with_byte_fields(prior, next, &["signaturePublicKey"])
        }
        "avatarBinding" => {
            object_equal_with_byte_fields(prior, next, &["ciphertextSha256"])
        }
        _ => prior == next,
    }
}

/// True only when `next` is the prior authenticated snapshot re-encrypted at another MLS
/// coordinate. Carries preserve every envelope field except the coordinate and AEAD bindings.
pub(crate) fn is_exact_metadata_epoch_carry(
    prior: &Value,
    prior_plaintext: &[u8],
    next: &Value,
    next_plaintext: &[u8],
) -> bool {
    const REENCRYPTED_FIELDS: [&str; 5] = [
        "coordinate",
        "nonce",
        "ciphertext",
        "ciphertextSha256",
        "ciphertextSize",
    ];
    let (Some(prior), Some(next)) = (prior.as_object(), next.as_object()) else {
        return false;
    };
    let invariant = |field: &&String| !REENCRYPTED_FIELDS.contains(&field.as_str());
    prior_plaintext == next_plaintext
        && prior.keys().filter(invariant).all(|field| {
            next.get(field).is_some_and(|next_value| {
                invariant_envelope_value_equal(field, &prior[field], next_value)
            })
        })
        && next.keys().filter(invariant).all(|field| {
            prior.get(field).is_some_and(|prior_value| {
                invariant_envelope_value_equal(field, prior_value, &next[field])
            })
        })
}

/// Decrypt the current authenticated snapshot before changing the MLS epoch. The plaintext is
/// held only while the Commit is built, so carrying it never normalizes or adds metadata fields.
pub(crate) fn metadata_snapshot_plaintext_for_carry_forward<P: OpenMlsProvider>(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
    group: &mut MlsGroup,
    provider: &P,
) -> Result<MetadataCarryForward, MLSError> {
    let encoded = tx
        .get_account_meta(&format!("metadata_snapshot_json:{conversation_id}"))?
        .ok_or_else(|| MLSError::InvalidState("MetadataSnapshotUnavailable".into()))?;
    let snapshot: Value = serde_json::from_str(&encoded).map_err(|_| {
        MLSError::Cryptography("metadata carry-forward: invalid cached snapshot".into())
    })?;
    let decrypted = decrypt_metadata_snapshot_for_current_group(
        tx,
        conversation_id,
        &snapshot,
        group,
        provider,
    )?;
    Ok(MetadataCarryForward {
        snapshot,
        plaintext: decrypted.plaintext,
        nonce: decrypted.nonce,
        ciphertext_len: decrypted.ciphertext_len,
        scheme: decrypted.scheme,
    })
}

/// Re-encrypt exact prior metadata plaintext for the next epoch under its original scheme. Only
/// its AEAD and coordinate bindings change; version, origin, author proof, avatar, unknown fields
/// and plaintext bytes do not.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reencrypt_metadata_snapshot_for_epoch<P: OpenMlsProvider>(
    carry: MetadataCarryForward,
    group: &mut MlsGroup,
    provider: &P,
    group_id: &[u8],
    convo_uuid: &uuid::Uuid,
    generation: i64,
    target_epoch: u64,
    next_gch: &[u8],
    next_ctag: &[u8],
) -> Result<Value, MLSError> {
    let refused =
        |what: &str| MLSError::Cryptography(format!("metadata carry-forward: {what}"));
    let MetadataCarryForward {
        mut snapshot,
        plaintext,
        nonce: previous_nonce,
        ciphertext_len: previous_len,
        scheme,
    } = carry;
    let metadata_version = snapshot
        .get("metadataVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| refused("missing metadata version"))?;
    let nonce = metadata_nonce()?;
    if previous_nonce == nonce {
        return Err(refused("nonce repeated across epochs"));
    }
    let ciphertext = match scheme {
        MetadataCarryScheme::Legacy => {
            let metadata_key = derive_metadata_key_from_group(
                group,
                provider.crypto(),
                provider.storage(),
                group_id,
                target_epoch,
            )
            .map_err(|error| refused(&format!("derive next metadata key: {error}")))?;
            encrypt_metadata_snapshot_plaintext_with_nonce(
                &metadata_key,
                group_id,
                target_epoch,
                metadata_version,
                &nonce,
                &plaintext,
            )
            .map_err(|error| refused(&format!("encrypt next snapshot: {error}")))?
        }
        MetadataCarryScheme::Canonical {
            origin_transition_id,
        } => {
            if metadata_version != 1 {
                return Err(refused("canonical metadata version is not 1"));
            }
            let generation = u64::try_from(generation)
                .map_err(|_| refused("negative canonical generation"))?;
            let coordinates = direct_request_bootstrap::canonical_metadata_coordinates(
                &convo_uuid.to_string(),
                group_id,
                generation,
                target_epoch,
                next_gch,
                next_ctag,
            );
            let metadata_key =
                direct_request_bootstrap::request_metadata_key(group, provider, &coordinates)
                    .map_err(|error| {
                        refused(&format!("derive next canonical metadata key: {error}"))
                    })?;
            direct_request_bootstrap::seal_request_metadata(
                &metadata_key,
                &coordinates,
                &origin_transition_id,
                &nonce,
                &plaintext,
            )
            .map_err(|error| refused(&format!("encrypt next canonical snapshot: {error}")))?
        }
    };
    if ciphertext.len() != previous_len {
        return Err(refused("plaintext length changed"));
    }
    snapshot["ciphertext"] = json!({ "$bytes": STANDARD.encode(&ciphertext) });
    snapshot["ciphertextSha256"] = json!(STANDARD.encode(Sha256::digest(&ciphertext)));
    snapshot["ciphertextSize"] = json!(ciphertext.len());
    snapshot["nonce"] = json!({ "$bytes": STANDARD.encode(nonce) });
    let coordinate = snapshot
        .get_mut("coordinate")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| refused("missing coordinate"))?;
    coordinate.insert(
        "confirmationTag".into(),
        json!({ "$bytes": STANDARD.encode(next_ctag) }),
    );
    coordinate.insert(
        "conversationId".into(),
        json!(STANDARD.encode(convo_uuid.as_bytes())),
    );
    coordinate.insert("epoch".into(), json!(target_epoch));
    coordinate.insert("generation".into(), json!(generation));
    coordinate.insert(
        "groupContextHash".into(),
        json!({ "$bytes": STANDARD.encode(next_gch) }),
    );
    coordinate.insert(
        "groupId".into(),
        json!({ "$bytes": STANDARD.encode(group_id) }),
    );
    Ok(snapshot)
}

fn enabled_at_seq(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
    seq: i64,
) -> Result<bool, MLSError> {
    let flips = flips(tx, conversation_id)?;
    if !flips.is_empty() && seq > 0 {
        return Ok(flips
            .iter()
            .rev()
            .find(|flip| flip.seq <= seq)
            .is_none_or(|flip| flip.enabled));
    }
    current_enabled(tx, conversation_id)
}

fn record_flip(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
    seq: i64,
    enabled: bool,
    now_ms: i64,
) -> Result<(), MLSError> {
    if seq < 0 {
        return Ok(());
    }
    let mut log = flips(tx, conversation_id)?;
    match log.binary_search_by_key(&seq, |flip| flip.seq) {
        Ok(index) if log[index].enabled != enabled => {
            return Err(MLSError::Cryptography(
                "conflicting archive policy at one sequence".into(),
            ));
        }
        Ok(_) => {}
        Err(index) => log.insert(index, Flip { seq, enabled }),
    }
    tx.put_account_meta(
        &flip_key(conversation_id),
        &serde_json::to_string(&log)?,
        now_ms,
    )
}

/// Establish the effective policy from an otherwise-authenticated recovery Welcome. The caller
/// has already verified its GroupInfo signer, signed fulfillment, next coordinate and receipt.
pub(crate) fn accept_recovery_attestation(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
    seq: i64,
    enabled: bool,
    now_ms: i64,
) -> Result<(), MLSError> {
    record_flip(tx, conversation_id, seq, enabled, now_ms)
}

/// A carried Commit or reset snapshot can tighten the setting, but only a separately signed
/// metadata transition may loosen it. Keep the authenticated snapshot itself unchanged.
pub(crate) fn accept_snapshot(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
    seq: i64,
    metadata: &GroupMetadataV1,
    signed_metadata_transition: bool,
    now_ms: i64,
) -> Result<(), MLSError> {
    let before = current_enabled(tx, conversation_id)?;
    let requested = metadata_enabled(metadata);
    let explicit_on = metadata.extra.get(HISTORY_BACKUP) == Some(&json!(true));
    if !before && requested && !(signed_metadata_transition && explicit_on) {
        record_flip(tx, conversation_id, seq, false, now_ms)?;
    } else if before != requested {
        record_flip(tx, conversation_id, seq, requested, now_ms)?;
    }
    Ok(())
}

fn frame_value(frame_json: &str) -> Option<Value> {
    serde_json::from_str::<Value>(frame_json).ok()
}

/// A malformed policy field vetoes backup. Only an absent field uses the old default.
fn frame_no_backup(frame_json: &str) -> bool {
    let Some(value) = frame_value(frame_json) else {
        return true;
    };
    match value.get("noBackup") {
        None => false,
        Some(value) => value.as_bool().unwrap_or(true),
    }
}

fn referenced_message_id(value: &Value) -> Option<&str> {
    [
        "/reaction/messageId",
        "/edit/messageId",
        "/edit/targetMessageId",
        "/unsend/messageId",
        "/editedMessageId",
    ]
    .into_iter()
    .find_map(|path| value.pointer(path).and_then(Value::as_str))
}

fn target_no_backup(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
    frame_json: &str,
) -> Result<bool, MLSError> {
    let Some(value) = frame_value(frame_json) else {
        return Ok(true);
    };
    let Some(target_id) = referenced_message_id(&value) else {
        return Ok(false);
    };
    if let Some(raw) =
        tx.get_labyrinth_state(&format!("native.message:{conversation_id}:{target_id}"))?
    {
        if let Ok(target) = serde_json::from_slice::<QueuedLabyrinthArchivePayload>(&raw) {
            if target.conversation_id == conversation_id
                && target.message_id == target_id
                && target.seq > 0
            {
                return Ok(frame_no_backup(&target.labyrinth_frame_json)
                    || !enabled_at_seq(tx, conversation_id, target.seq)?);
            }
        }
    }
    // A display row may omit the sender's stamped `noBackup`; only retained authenticated frame
    // evidence can prove that a reaction or edit's target is backup-eligible.
    Ok(true)
}

pub(crate) fn stamp_outgoing(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
    frame_json: &str,
) -> Result<String, MLSError> {
    let mut value = frame_value(frame_json)
        .ok_or_else(|| MLSError::Cryptography("outgoing archive frame is not JSON".into()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        MLSError::Cryptography("outgoing archive frame is not a JSON object".into())
    })?;
    let already_off = object
        .get("noBackup")
        .is_some_and(|flag| flag != &json!(false));
    let inherited_off = target_no_backup(tx, conversation_id, frame_json)?;
    let group_off = !current_enabled(tx, conversation_id)?;
    object.insert("backupPolicy".into(), json!(1));
    if already_off || inherited_off || group_off {
        object.insert("noBackup".into(), json!(true));
    }
    Ok(value.to_string())
}

/// Observe a verified, MLS-authenticated frame before deciding whether to enqueue it.
pub(crate) fn observe_frame(
    tx: &impl WasmSqlBackend,
    payload: &QueuedLabyrinthArchivePayload,
) -> Result<(), MLSError> {
    observe_verified_frame(
        tx,
        &payload.conversation_id,
        payload.seq,
        &payload.labyrinth_frame_json,
        payload.created_at_ms,
    )
}

pub(crate) fn observe_verified_frame(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
    seq: i64,
    frame_json: &str,
    created_at_ms: i64,
) -> Result<(), MLSError> {
    let frame = frame_value(frame_json);
    let change = frame.as_ref().and_then(|frame| {
        (frame["messageType"] == "system"
            && frame["backupPolicy"] == 1
            && frame["noBackup"] == true)
            .then(|| frame.get("historyBackupChange").and_then(Value::as_bool))
            .flatten()
    });
    let requested = match change {
        Some(enabled) => enabled,
        None if frame_no_backup(frame_json) => false,
        None => return Ok(()),
    };
    if requested != enabled_at_seq(tx, conversation_id, seq)? {
        record_flip(tx, conversation_id, seq, requested, created_at_ms)?;
    }
    Ok(())
}

/// Old queued rows may be inspected during flush. They can immediately tighten the setting,
/// while an opt-in waits for the canonical sequenced entry replay to authorize it.
pub(crate) fn observe_frame_tighten_only(
    tx: &impl WasmSqlBackend,
    payload: &QueuedLabyrinthArchivePayload,
) -> Result<(), MLSError> {
    if frame_value(&payload.labyrinth_frame_json)
        .as_ref()
        .is_some_and(|frame| frame["historyBackupChange"] == true)
    {
        return Ok(());
    }
    observe_frame(tx, payload)
}

pub(crate) fn should_enqueue(
    tx: &impl WasmSqlBackend,
    payload: &QueuedLabyrinthArchivePayload,
) -> Result<bool, MLSError> {
    Ok(!frame_no_backup(&payload.labyrinth_frame_json)
        && !target_no_backup(tx, &payload.conversation_id, &payload.labyrinth_frame_json)?
        && enabled_at_seq(tx, &payload.conversation_id, payload.seq)?)
}

pub(crate) fn enqueue(
    tx: &impl WasmSqlBackend,
    payload: &QueuedLabyrinthArchivePayload,
) -> Result<bool, MLSError> {
    observe_frame(tx, payload)?;
    if !should_enqueue(tx, payload)? {
        return Ok(false);
    }
    tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
        item_id: payload.message_id.clone(),
        conversation_id: payload.conversation_id.clone(),
        group_id_hex: payload.group_id_hex.clone(),
        seq: payload.seq,
        payload_bytes: serde_json::to_vec(payload)?,
        created_at_ms: payload.created_at_ms,
    })?;
    Ok(true)
}
