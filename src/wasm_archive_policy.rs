//! Browser storage adapter for the sequenced history-backup policy in the shared client.
//! All clean-slate Web archive queue writes pass through `enqueue`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use catbird_mls::client::chat_wire;
use catbird_mls::client::QueuedLabyrinthArchivePayload;
use catbird_mls::metadata::GroupMetadataV1;
use catbird_mls::storage::driver_wasm::WasmSqlBackend;
use catbird_mls::storage::{GroupMetadataRow, LabyrinthQueueRow};
use catbird_mls::MLSError;

const HISTORY_BACKUP: &str = "historyBackup";
const FLIPS_PREFIX: &str = "archive.policy.flips:";

pub(crate) fn metadata_nonce() -> Result<[u8; 12], MLSError> {
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

/// Carry every known and unknown metadata field through a Commit. The effective policy wins
/// over a stale carried snapshot so a reset or recovery cannot silently re-enable backup.
pub(crate) fn carried_metadata(
    tx: &impl WasmSqlBackend,
    conversation_id: &str,
    row: Option<&GroupMetadataRow>,
) -> Result<GroupMetadataV1, MLSError> {
    let mut metadata = row
        .map(chat_wire::group_metadata_v1_from_row)
        .unwrap_or_else(|| GroupMetadataV1::new("", ""));
    metadata.version = 1;
    metadata.avatar_blob_locator = None;
    metadata.space_avatar = row.and_then(chat_wire::space_avatar_from_metadata_row);
    metadata.avatar_content_type = metadata
        .space_avatar
        .as_ref()
        .and_then(|avatar| avatar.mime_type.clone());
    metadata.extra.insert(
        HISTORY_BACKUP.into(),
        json!(current_enabled(tx, conversation_id)?),
    );
    Ok(metadata)
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
    let frame = frame_value(&payload.labyrinth_frame_json);
    let change = frame.as_ref().and_then(|frame| {
        (frame["messageType"] == "system"
            && frame["backupPolicy"] == 1
            && frame["noBackup"] == true)
            .then(|| frame.get("historyBackupChange").and_then(Value::as_bool))
            .flatten()
    });
    let requested = match change {
        Some(enabled) => enabled,
        None if frame_no_backup(&payload.labyrinth_frame_json) => false,
        None => return Ok(()),
    };
    if requested != enabled_at_seq(tx, &payload.conversation_id, payload.seq)? {
        record_flip(
            tx,
            &payload.conversation_id,
            payload.seq,
            requested,
            payload.created_at_ms,
        )?;
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
