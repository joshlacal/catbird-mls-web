//! Browser WebSocket client for real-time MLS message delivery.
//!
//! This is the WASM equivalent of `catmos/src-tauri/src/websocket.rs`.
//! Instead of `tokio-tungstenite` + async loops, it wires browser-native
//! `web_sys::WebSocket` event callbacks.
//!
//! # Notes
//! - MLS decryption is available via the thread-local `STATE` (same WASM worker).
//!   Messages are decrypted inline using `MLSContext::decrypt_message`.
//!   Undecryptable messages (wrong epoch, before join) are silently skipped.
//! - WASM is single-threaded, so there is no `tokio::select!` and no
//!   `Arc<Mutex<>>` for shared async state. All handler closures run on the JS
//!   event loop.
//! - Membership, info, new-device, reaction, and read-receipt events do NOT
//!   require MLS crypto and are surfaced fully.

use std::io::Cursor;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciborium::Value as CborValue;
use js_sys::Function;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

// ---------------------------------------------------------------------------
// Public types (serde-compatible with Tauri output)
// ---------------------------------------------------------------------------

/// A single chat message ready for the UI layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_did: String,
    pub sender_handle: String,
    pub content: String,
    pub timestamp: String,
    /// `"pending"` | `"delivered"` | `"read"`
    pub status: String,
    /// `"text"` | `"system"` | `"encrypted"`
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<crate::ImageAttachment>,
}

impl From<crate::Message> for UiMessage {
    fn from(message: crate::Message) -> Self {
        Self {
            id: message.id,
            conversation_id: message.conversation_id,
            sender_did: message.sender_did,
            sender_handle: message.sender_handle,
            content: message.content,
            timestamp: message.timestamp,
            status: message.status,
            message_type: message.message_type,
            image: message.image,
        }
    }
}

/// Emitted for `#reactionEvent` frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionEvent {
    pub conversation_id: String,
    pub message_id: String,
    pub sender_did: String,
    pub emoji: String,
    /// `"add"` | `"remove"`
    pub action: String,
}

/// Emitted for `#typingEvent` frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingEvent {
    pub conversation_id: String,
    pub sender_did: String,
    pub is_typing: bool,
}

// ---------------------------------------------------------------------------
// Internal frame processing types
// ---------------------------------------------------------------------------

/// DAG-CBOR WebSocket frame header — same wire format as mls-ds `MessageHeader`.
#[derive(Debug, Deserialize)]
struct FrameHeader {
    op: i32,
    t: Option<String>,
}

/// Discriminated output from `handle_frame`.
#[allow(dead_code)]
enum FrameOutput {
    /// A displayable message (text, system, or encrypted placeholder).
    Message(UiMessage),
    /// A named non-message event with an arbitrary JS value payload.
    /// The first field is the `type` string passed to `on_event`.
    Event(String, JsValue),
}

// ---------------------------------------------------------------------------
// CBOR helper functions (ported verbatim from src-tauri/src/websocket.rs)
// ---------------------------------------------------------------------------

/// Extract a string from a CBOR map.
fn cbor_str(map: &[(CborValue, CborValue)], key: &str) -> Option<String> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Text(v)) if k == key => Some(v.clone()),
        _ => None,
    })
}

/// Extract an integer from a CBOR map.
fn cbor_int(map: &[(CborValue, CborValue)], key: &str) -> Option<i64> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Integer(v)) if k == key => {
            let n: i128 = (*v).into();
            Some(n as i64)
        }
        _ => None,
    })
}

/// Extract bytes from a CBOR map.
///
/// Handles three formats:
/// - CBOR byte string (major type 2) — raw bytes
/// - ATProto `{"$bytes": "base64..."}` map — base64-decoded
/// - CBOR array of integers — each int as u8
fn cbor_bytes(map: &[(CborValue, CborValue)], key: &str) -> Option<Vec<u8>> {
    map.iter().find_map(|(k, v)| {
        let CborValue::Text(k) = k else {
            return None;
        };
        if k != key {
            return None;
        }
        extract_bytes(v)
    })
}

/// Extract bytes from a CBOR value regardless of encoding format.
fn extract_bytes(v: &CborValue) -> Option<Vec<u8>> {
    match v {
        CborValue::Bytes(b) => Some(b.clone()),
        // ATProto {"$bytes": "base64..."} format
        CborValue::Map(entries) => {
            cbor_str(entries, "$bytes").and_then(|b64| B64.decode(&b64).ok())
        }
        CborValue::Array(arr) => arr
            .iter()
            .map(|item| match item {
                CborValue::Integer(i) => {
                    let n: i128 = (*i).into();
                    u8::try_from(n).ok()
                }
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// Extract a nested CBOR map from a parent map.
fn cbor_map<'a>(
    map: &'a [(CborValue, CborValue)],
    key: &str,
) -> Option<&'a [(CborValue, CborValue)]> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Map(m)) if k == key => Some(m.as_slice()),
        _ => None,
    })
}

/// Decode a DAG-CBOR WebSocket frame.
///
/// Returns the deserialized header and the remaining payload bytes. The frame
/// contains two concatenated CBOR items: header + payload.
fn split_frame(data: &[u8]) -> Option<(FrameHeader, &[u8])> {
    let mut cursor = Cursor::new(data);
    let header: FrameHeader = ciborium::from_reader(&mut cursor).ok()?;
    let consumed = cursor.position() as usize;
    Some((header, &data[consumed..]))
}

/// Shorten a DID for display (e.g. `"did:plc:abc123"` → `"abc123"`).
fn short_id(did: &str) -> &str {
    did.rsplit(':').next().unwrap_or(did)
}

/// Extract cursor string from a CBOR value (helper for non-map payloads).
#[allow(dead_code)]
fn cbor_str_from_cbor(val: &CborValue, key: &str) -> Option<String> {
    match val {
        CborValue::Map(ref entries) => cbor_str(entries, key),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Frame processing
// ---------------------------------------------------------------------------

/// Decode a binary DAG-CBOR frame and produce a [`FrameOutput`] if actionable.
///
/// Returns `Ok(None)` for frames that are intentionally ignored (typing
/// indicators, readdition requests, unknown types), `Ok(Some(_))` for
/// actionable frames, and `Err` for decode failures or server-error frames.
fn handle_frame(data: &[u8], convo_id: &str) -> Result<Option<FrameOutput>, String> {
    let (header, payload_bytes) =
        split_frame(data).ok_or_else(|| "Failed to decode DAG-CBOR frame header".to_string())?;

    if header.op == -1 {
        return Err("Server error frame received".to_string());
    }

    let event_type = header.t.as_deref().unwrap_or("");

    match event_type {
        // ------------------------------------------------------------------
        // Encrypted MLS message — surface as placeholder; no crypto in WASM.
        // ------------------------------------------------------------------
        "#messageEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode messageEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Err("messageEvent payload is not a CBOR map".into());
            };

            let msg_map =
                cbor_map(top, "message").ok_or("Missing 'message' field in messageEvent")?;

            let id = cbor_str(msg_map, "id").ok_or("Missing message.id")?;
            let msg_convo_id = cbor_str(msg_map, "convoId").ok_or("Missing message.convoId")?;
            let created_at = cbor_str(msg_map, "createdAt").ok_or("Missing message.createdAt")?;

            let ciphertext = cbor_bytes(msg_map, "ciphertext");
            let _epoch = cbor_int(msg_map, "epoch").unwrap_or(0);
            let sender_did_raw = cbor_str(msg_map, "senderDid").unwrap_or_default();

            // Debug: log message map keys and ciphertext presence
            let keys: Vec<String> = msg_map
                .iter()
                .filter_map(|(k, _)| {
                    if let CborValue::Text(t) = k {
                        Some(t.clone())
                    } else {
                        None
                    }
                })
                .collect();
            web_sys::console::log_1(&JsValue::from_str(&format!(
                "[catmos-ws] msg keys={:?}, ciphertext_present={}, sender={}",
                keys,
                ciphertext.is_some(),
                sender_did_raw
            )));

            // Skip self-echoes (own messages already displayed locally)
            let is_own = crate::STATE.with(|s| {
                let borrowed = s.borrow();
                borrowed
                    .as_ref()
                    .and_then(|st| st.user_did.as_ref())
                    .map(|did| did.to_lowercase() == sender_did_raw.to_lowercase())
                    .unwrap_or(false)
            });
            if is_own {
                return Ok(None);
            }

            // Try to decrypt using the MLS context (available in WASM worker)
            let mut decrypt_err: Option<String> = None;
            let decrypted = ciphertext.as_ref().and_then(|ct| {
                let gid = match crate::decode_group_id(&msg_convo_id) {
                    Some(g) => g,
                    None => {
                        decrypt_err = Some("failed to decode group_id".into());
                        return None;
                    }
                };
                crate::STATE.with(|s| {
                    let borrowed = s.borrow();
                    let state = match borrowed.as_ref() {
                        Some(st) => st,
                        None => {
                            decrypt_err = Some("STATE not initialized".into());
                            return None;
                        }
                    };
                    let ctx = match state.mls_context.as_ref() {
                        Some(c) => c,
                        None => {
                            decrypt_err = Some("MLS context not initialized".into());
                            return None;
                        }
                    };
                    match ctx.decrypt_message(gid.clone(), ct.clone()) {
                        Ok(res) if !res.plaintext.is_empty() => {
                            use catbird_mls::orchestrator::types::MLSMessagePayload;
                            let (text, payload_json) =
                                match MLSMessagePayload::decode(&res.plaintext) {
                                    Ok(payload) => {
                                        if !payload.is_displayable() {
                                            return None;
                                        }
                                        (
                                            payload.display_text(),
                                            String::from_utf8(res.plaintext.clone()).ok(),
                                        )
                                    }
                                    Err(_) => (
                                        String::from_utf8(res.plaintext)
                                            .unwrap_or_else(|_| "[Binary]".to_string()),
                                        None,
                                    ),
                                };
                            let sender = String::from_utf8(res.sender_credential.identity)
                                .unwrap_or(sender_did_raw.clone());
                            Some((
                                crate::ui_message_from_orchestrator(
                                    catbird_mls::orchestrator::types::Message {
                                        id: id.clone(),
                                        conversation_id: msg_convo_id.clone(),
                                        sender_did: sender.clone(),
                                        text,
                                        timestamp: chrono::DateTime::parse_from_rfc3339(
                                            &created_at,
                                        )
                                        .map(|dt| dt.with_timezone(&chrono::Utc))
                                        .unwrap_or_else(|_| chrono::Utc::now()),
                                        epoch: res.epoch,
                                        sequence_number: res.sequence_number,
                                        is_own: false,
                                        delivery_status: None,
                                        payload_json,
                                    },
                                )
                                .into(),
                                sender,
                            ))
                        }
                        Ok(_) => None, // empty plaintext (non-commit) — nothing to display
                        Err(catbird_mls::MLSError::InvalidInput { ref message })
                            if message.contains("commit message") =>
                        {
                            // Task #56: commit is staged in `pending_incoming_merges`;
                            // drive the explicit merge so the local epoch advances.
                            if let Err(e) = ctx.merge_incoming_commit(gid) {
                                web_sys::console::warn_1(&JsValue::from_str(&format!(
                                    "[catmos-ws] merge_incoming_commit failed: {:?}",
                                    e
                                )));
                            }
                            None
                        }
                        Err(catbird_mls::MLSError::InvalidInput { ref message })
                            if message.contains("proposal") =>
                        {
                            // Proposals never stage a commit; just skip.
                            None
                        }
                        Err(ref e) => {
                            let err_str = format!("{:?}", e);
                            if err_str.contains("CannotDecryptOwnMessage") {
                                // Self-echo — server doesn't include senderDid in
                                // WebSocket MessageView, so the DID-based filter
                                // above can't catch it. Mark for silent skip.
                                decrypt_err = Some("self-echo".into());
                            } else {
                                decrypt_err = Some(err_str);
                            }
                            None
                        }
                    }
                })
            });

            match decrypted {
                Some((ui_msg, _sender)) => {
                    // Record msg_id as seen for dedup against polling path
                    crate::SEEN_MSG_IDS.with(|s| {
                        let mut set = s.borrow_mut();
                        if set.len() > 1000 {
                            set.clear();
                        }
                        set.insert(id.clone());
                    });

                    Ok(Some(FrameOutput::Message(ui_msg)))
                }
                None => {
                    let reason = decrypt_err.unwrap_or_else(|| "no ciphertext or commit".into());

                    // Self-echo or commit: silently ignore (no fetch needed)
                    if reason == "self-echo" || reason == "no ciphertext or commit" {
                        return Ok(None);
                    }

                    // Can't decrypt inline — signal the frontend to fetch via
                    // HTTP (which handles auto-join, epoch sync, etc.).
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "[catmos-ws] decrypt failed for msg {} in {}: {}",
                        id, msg_convo_id, reason
                    )));
                    let obj = js_sys::Object::new();
                    js_sys::Reflect::set(
                        &obj,
                        &JsValue::from_str("type"),
                        &JsValue::from_str("fetchNeeded"),
                    )
                    .ok();
                    js_sys::Reflect::set(
                        &obj,
                        &JsValue::from_str("convoId"),
                        &JsValue::from_str(&msg_convo_id),
                    )
                    .ok();
                    js_sys::Reflect::set(
                        &obj,
                        &JsValue::from_str("reason"),
                        &JsValue::from_str(&reason),
                    )
                    .ok();
                    Ok(Some(FrameOutput::Event(
                        "fetchNeeded".to_string(),
                        obj.into(),
                    )))
                }
            }
        }

        // ------------------------------------------------------------------
        // Membership change — no crypto required, surface fully.
        // ------------------------------------------------------------------
        "#membershipChangeEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode membershipChangeEvent CBOR: {}", e))?;

            let (member_did, action) = match &payload {
                CborValue::Map(ref top) => (
                    cbor_str(top, "memberDid").unwrap_or_default(),
                    cbor_str(top, "action").unwrap_or_else(|| "changed".to_string()),
                ),
                _ => (String::new(), "changed".to_string()),
            };

            let content = match action.as_str() {
                "join" | "added" => format!("{} joined the group", short_id(&member_did)),
                "leave" | "left" => format!("{} left the group", short_id(&member_did)),
                "removed" => format!("{} was removed from the group", short_id(&member_did)),
                _ => format!("Membership updated: {}", short_id(&member_did)),
            };

            let msg = UiMessage {
                id: format!("sys-{}", uuid::Uuid::new_v4()),
                conversation_id: convo_id.to_string(),
                sender_did: String::new(),
                sender_handle: String::new(),
                content,
                timestamp: chrono::Utc::now().to_rfc3339(),
                status: "delivered".to_string(),
                message_type: "system".to_string(),
                image: None,
            };

            Ok(Some(FrameOutput::Message(msg)))
        }

        // ------------------------------------------------------------------
        // Info event — no crypto required.
        // ------------------------------------------------------------------
        "#infoEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode infoEvent CBOR: {}", e))?;

            let info_text = match &payload {
                CborValue::Map(ref top) => cbor_str(top, "message")
                    .or_else(|| cbor_str(top, "info"))
                    .unwrap_or_else(|| "Group info updated".to_string()),
                _ => "Group info updated".to_string(),
            };

            let msg = UiMessage {
                id: format!("sys-{}", uuid::Uuid::new_v4()),
                conversation_id: convo_id.to_string(),
                sender_did: String::new(),
                sender_handle: String::new(),
                content: info_text,
                timestamp: chrono::Utc::now().to_rfc3339(),
                status: "delivered".to_string(),
                message_type: "system".to_string(),
                image: None,
            };

            Ok(Some(FrameOutput::Message(msg)))
        }

        // ------------------------------------------------------------------
        // New device event — no crypto required.
        // ------------------------------------------------------------------
        "#newDeviceEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode newDeviceEvent CBOR: {}", e))?;

            let member_did = match &payload {
                CborValue::Map(ref top) => cbor_str(top, "memberDid").unwrap_or_default(),
                _ => String::new(),
            };

            let msg = UiMessage {
                id: format!("sys-{}", uuid::Uuid::new_v4()),
                conversation_id: convo_id.to_string(),
                sender_did: String::new(),
                sender_handle: String::new(),
                content: format!("{} added a new device", short_id(&member_did)),
                timestamp: chrono::Utc::now().to_rfc3339(),
                status: "delivered".to_string(),
                message_type: "system".to_string(),
                image: None,
            };

            Ok(Some(FrameOutput::Message(msg)))
        }

        // ------------------------------------------------------------------
        // Reaction event — no crypto required.
        // ------------------------------------------------------------------
        "#reactionEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode reactionEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Ok(None);
            };

            let reaction = ReactionEvent {
                conversation_id: cbor_str(top, "convoId").unwrap_or_else(|| convo_id.to_string()),
                message_id: cbor_str(top, "messageId").unwrap_or_default(),
                sender_did: cbor_str(top, "did").unwrap_or_default(),
                emoji: cbor_str(top, "reaction").unwrap_or_default(),
                action: cbor_str(top, "action").unwrap_or_else(|| "add".to_string()),
            };

            let event_js = make_event_js("reaction", &reaction)?;
            Ok(Some(FrameOutput::Event("reaction".to_string(), event_js)))
        }

        // ------------------------------------------------------------------
        // Group info refresh request — signal JS to re-fetch group state.
        // ------------------------------------------------------------------
        "#groupInfoRefreshRequestedEvent" => {
            let obj = js_sys::Object::new();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("type"),
                &JsValue::from_str("groupRefresh"),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("convoId"),
                &JsValue::from_str(convo_id),
            )
            .ok();
            Ok(Some(FrameOutput::Event(
                "groupRefresh".to_string(),
                obj.into(),
            )))
        }

        // ------------------------------------------------------------------
        // Group reset (spec §8.5 / §8.6) — server-driven RESET_PENDING.
        //
        // Persists the payload to the WASM storage backend (so deferred
        // recovery survives reload), adopts the new MLS group id, flips the
        // conversation state to ResetPending, and emits a `groupReset` event
        // to the JS layer. The frontend is expected to call
        // `catbird_mls_fetch_new_messages` (or the orchestrator's sync) so
        // the deferred External Commit picks up the new group.
        //
        // Note: catbird-mls-web does NOT wrap `MLSOrchestrator`, so there is
        // no in-process `RecoveryTracker` to clear here (that step in the
        // catmos Tauri reference implementation is intentionally skipped).
        // The JS layer drives sync.
        // ------------------------------------------------------------------
        "#groupResetEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode groupResetEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Ok(None);
            };

            let new_group_id = cbor_str(top, "newGroupId").unwrap_or_default();
            let reset_generation = cbor_int(top, "resetGeneration").unwrap_or(0) as i32;
            let reset_by = cbor_str(top, "resetBy").unwrap_or_default();
            let reason = cbor_str(top, "reason");
            let convo_id_owned = convo_id.to_string();
            let notified_at_ms = chrono::Utc::now().timestamp_millis();

            web_sys::console::log_1(&JsValue::from_str(&format!(
                "[catmos-ws] groupReset: convo={} newGroupId={} gen={} by={}",
                convo_id_owned,
                new_group_id,
                reset_generation,
                short_id(&reset_by)
            )));

            // Side-effects: persist + adopt new group_id. spawn_local because
            // MLSStorageBackend methods are async; the WASM event loop is
            // single-threaded so STATE access from inside the future is safe
            // as long as we don't hold a borrow across `await`.
            let new_gid_for_task = new_group_id.clone();
            let convo_id_for_task = convo_id_owned.clone();
            wasm_bindgen_futures::spawn_local(async move {
                use catbird_mls::orchestrator::storage::MLSStorageBackend;

                let storage = crate::STATE.with(|s| {
                    s.borrow()
                        .as_ref()
                        .map(|st| std::sync::Arc::clone(&st.storage))
                });
                let Some(storage) = storage else {
                    web_sys::console::warn_1(&JsValue::from_str(
                        "[catmos-ws] groupReset: STATE not initialized; skipping persistence",
                    ));
                    return;
                };

                // 1. Persist the RESET_PENDING payload.
                if let Err(e) = storage
                    .mark_reset_pending(
                        &convo_id_for_task,
                        &new_gid_for_task,
                        reset_generation,
                        notified_at_ms,
                    )
                    .await
                {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "[catmos-ws] mark_reset_pending failed for {}: {:?}",
                        convo_id_for_task, e
                    )));
                }

                // 2. Flip conversation state to ResetPending (carries payload).
                if let Err(e) = storage
                    .set_conversation_state(
                        &convo_id_for_task,
                        catbird_mls::orchestrator::types::ConversationState::ResetPending {
                            new_group_id: new_gid_for_task.clone(),
                            reset_generation,
                            notified_at_ms,
                        },
                    )
                    .await
                {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "[catmos-ws] set ResetPending failed for {}: {:?}",
                        convo_id_for_task, e
                    )));
                }

                // 3. Mark needs_rejoin so deferred recovery picks it up.
                if let Err(e) = storage.mark_needs_rejoin(&convo_id_for_task).await {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "[catmos-ws] mark_needs_rejoin failed for {}: {:?}",
                        convo_id_for_task, e
                    )));
                }

                // 4. Adopt the new group_id locally (so the next External
                //    Commit targets the post-reset group). Empty newGroupId
                //    means the server did not specify one — fall back to the
                //    pre-reset lookup-by-conversation-id heuristic.
                if !new_gid_for_task.is_empty() {
                    if let Err(e) =
                        storage.update_conversation_group_id(&convo_id_for_task, &new_gid_for_task)
                    {
                        web_sys::console::warn_1(&JsValue::from_str(&format!(
                            "[catmos-ws] update_conversation_group_id failed for {} -> {}: {}",
                            convo_id_for_task, new_gid_for_task, e
                        )));
                    }
                }
            });

            // Build the JS event payload.
            let obj = js_sys::Object::new();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("type"),
                &JsValue::from_str("groupReset"),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("convoId"),
                &JsValue::from_str(&convo_id_owned),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("newGroupId"),
                &JsValue::from_str(&new_group_id),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("resetGeneration"),
                &JsValue::from_f64(reset_generation as f64),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("resetBy"),
                &JsValue::from_str(&reset_by),
            )
            .ok();
            if let Some(ref r) = reason {
                js_sys::Reflect::set(&obj, &JsValue::from_str("reason"), &JsValue::from_str(r))
                    .ok();
            }
            Ok(Some(FrameOutput::Event(
                "groupReset".to_string(),
                obj.into(),
            )))
        }

        // ------------------------------------------------------------------
        // Reset requested (Phase 2.5, plan
        // `docs/plans/phase-2-5-indirect-funneling.md` §3, §5 Stage 1) —
        // server is funneling indirect-trigger resets (quorum vote, system
        // sweep, inline_409, inline_groupinfo_404) through SSE WITHOUT
        // minting an `mls_group_id` server-side. Subscribed clients elect a
        // first responder, race-bootstrap their own pre-generated group_id,
        // and the chokepoint's `crypto_sessions UNIQUE (conversation_id,
        // generation)` constraint serializes the winner.
        //
        // This is the WASM-side companion to
        // `MLSOrchestrator::record_reset_requested` (`catbird-mls/src/
        // orchestrator/recovery.rs:1387`). Because catbird-mls-web does NOT
        // wrap `MLSOrchestrator`, the orchestrator method's body is mirrored
        // inline here against the `MLSStorageBackend` trait — exactly the
        // same pattern as the legacy `#groupResetEvent` arm above.
        //
        // Behavior parity with the orchestrator method:
        // 1. Idempotency: if the persisted state is already
        //    `ResetPending { reset_generation: g, .. }` and the incoming
        //    `generation` matches `g`, no storage writes happen — only the
        //    JS event is emitted (for UI/debug visibility on reconnect
        //    replays).
        // 2. New group_id resolution: server-supplied
        //    `expectedNewMlsGroupId` (when present and non-empty) is used
        //    verbatim; otherwise a fresh UUIDv4-style 32-hex-char id is
        //    minted client-side as the race-bootstrap candidate.
        // 3. State writes mirror `persist_reset_pending_state` in the
        //    orchestrator: `mark_reset_pending` + `set_conversation_state(
        //    ResetPending)` + `mark_needs_rejoin` +
        //    `update_conversation_group_id`. The deferred-recovery loop
        //    drives the actual bootstrap.
        // ------------------------------------------------------------------
        "#resetRequestedEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode resetRequestedEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Ok(None);
            };

            let crypto_session_id = cbor_str(top, "cryptoSessionId").unwrap_or_default();
            let reset_generation = cbor_int(top, "generation").unwrap_or(0) as i32;
            let trigger = cbor_str(top, "trigger").unwrap_or_default();
            let request_event_id = cbor_str(top, "requestEventId").unwrap_or_default();
            let reason = cbor_str(top, "reason");
            // `expectedNewMlsGroupId` is `Option<String>` on the wire — the
            // common Phase 2.5 case is None (server has not minted). Treat
            // empty string the same as None for robustness.
            let expected_new_mls_group_id: Option<String> =
                cbor_str(top, "expectedNewMlsGroupId").filter(|s| !s.is_empty());
            let convo_id_owned = convo_id.to_string();
            let notified_at_ms = chrono::Utc::now().timestamp_millis();

            web_sys::console::log_1(&JsValue::from_str(&format!(
                "[catmos-ws] resetRequested: convo={} cryptoSession={} gen={} trigger={} reqId={} expected={}",
                convo_id_owned,
                short_id(&crypto_session_id),
                reset_generation,
                trigger,
                request_event_id,
                expected_new_mls_group_id
                    .as_deref()
                    .unwrap_or("<none>")
            )));

            let crypto_session_id_owned = crypto_session_id.clone();
            let trigger_owned = trigger.clone();
            let request_event_id_owned = request_event_id.clone();
            let expected_for_task = expected_new_mls_group_id.clone();
            let convo_id_for_task = convo_id_owned.clone();

            // Side-effects: idempotency check + persist. spawn_local because
            // MLSStorageBackend methods are async; the WASM event loop is
            // single-threaded so STATE access from inside the future is safe
            // as long as we don't hold a borrow across `await`.
            wasm_bindgen_futures::spawn_local(async move {
                use catbird_mls::orchestrator::storage::MLSStorageBackend;
                use catbird_mls::orchestrator::types::ConversationState;

                let storage = crate::STATE.with(|s| {
                    s.borrow()
                        .as_ref()
                        .map(|st| std::sync::Arc::clone(&st.storage))
                });
                let Some(storage) = storage else {
                    web_sys::console::warn_1(&JsValue::from_str(
                        "[catmos-ws] resetRequested: STATE not initialized; skipping persistence",
                    ));
                    return;
                };

                // 1. Idempotency: if we are already in ResetPending at the
                //    same generation, drop the duplicate (mirrors
                //    recovery.rs:1400-1412).
                match storage.get_conversation_state(&convo_id_for_task).await {
                    Ok(Some(ConversationState::ResetPending {
                        reset_generation: existing_gen,
                        new_group_id: existing_gid,
                        ..
                    })) if existing_gen == reset_generation => {
                        web_sys::console::log_1(&JsValue::from_str(&format!(
                            "[catmos-ws] resetRequested: already in ResetPending at gen={} (existing newGroupId={}); idempotent no-op",
                            reset_generation, existing_gid,
                        )));
                        return;
                    }
                    Ok(Some(ConversationState::ResetPending {
                        reset_generation: existing_gen,
                        ..
                    })) => {
                        web_sys::console::log_1(&JsValue::from_str(&format!(
                            "[catmos-ws] resetRequested: superseding ResetPending at old gen={} with new gen={}",
                            existing_gen, reset_generation,
                        )));
                    }
                    Ok(_) | Err(_) => {
                        // No persisted state, or state read failed — fall
                        // through and persist. A read error here is
                        // non-fatal; the writes below are authoritative.
                    }
                }

                // 2. Resolve new_group_id eagerly (mirrors
                //    recovery.rs:1430-1456). Server-supplied wins; else mint
                //    a UUIDv4-style 32-hex-char id locally for first-
                //    responder race bootstrap.
                let new_group_id_hex = match expected_for_task {
                    Some(hex_id) if !hex_id.is_empty() => {
                        web_sys::console::log_1(&JsValue::from_str(&format!(
                            "[catmos-ws] resetRequested: using server-supplied expectedNewMlsGroupId={}",
                            hex_id,
                        )));
                        hex_id
                    }
                    _ => {
                        let minted = format!("{:032x}", uuid::Uuid::new_v4().as_u128());
                        web_sys::console::log_1(&JsValue::from_str(&format!(
                            "[catmos-ws] resetRequested: server passed None; minting client-side candidate={}",
                            minted,
                        )));
                        minted
                    }
                };

                // 3. Persist the RESET_PENDING payload.
                if let Err(e) = storage
                    .mark_reset_pending(
                        &convo_id_for_task,
                        &new_group_id_hex,
                        reset_generation,
                        notified_at_ms,
                    )
                    .await
                {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "[catmos-ws] mark_reset_pending failed for {}: {:?}",
                        convo_id_for_task, e
                    )));
                }

                // 4. Flip conversation state to ResetPending (carries
                //    payload).
                if let Err(e) = storage
                    .set_conversation_state(
                        &convo_id_for_task,
                        ConversationState::ResetPending {
                            new_group_id: new_group_id_hex.clone(),
                            reset_generation,
                            notified_at_ms,
                        },
                    )
                    .await
                {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "[catmos-ws] set ResetPending failed for {}: {:?}",
                        convo_id_for_task, e
                    )));
                }

                // 5. Mark needs_rejoin so deferred recovery picks it up.
                if let Err(e) = storage.mark_needs_rejoin(&convo_id_for_task).await {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "[catmos-ws] mark_needs_rejoin failed for {}: {:?}",
                        convo_id_for_task, e
                    )));
                }

                // 6. Adopt the new group_id locally (so the next External
                //    Commit / first-responder bootstrap targets the post-
                //    reset group). Always non-empty here because step 2
                //    minted one when server passed None.
                if let Err(e) =
                    storage.update_conversation_group_id(&convo_id_for_task, &new_group_id_hex)
                {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "[catmos-ws] update_conversation_group_id failed for {} -> {}: {}",
                        convo_id_for_task, new_group_id_hex, e
                    )));
                }
            });

            // Build the JS event payload. Surfaced to the UI so a "Repairing
            // conversation…" banner can render while deferred recovery
            // bootstraps the new group.
            let obj = js_sys::Object::new();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("type"),
                &JsValue::from_str("resetRequested"),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("convoId"),
                &JsValue::from_str(&convo_id_owned),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("cryptoSessionId"),
                &JsValue::from_str(&crypto_session_id_owned),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("generation"),
                &JsValue::from_f64(reset_generation as f64),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("trigger"),
                &JsValue::from_str(&trigger_owned),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("requestEventId"),
                &JsValue::from_str(&request_event_id_owned),
            )
            .ok();
            if let Some(ref expected) = expected_new_mls_group_id {
                js_sys::Reflect::set(
                    &obj,
                    &JsValue::from_str("expectedNewMlsGroupId"),
                    &JsValue::from_str(expected),
                )
                .ok();
            }
            if let Some(ref r) = reason {
                js_sys::Reflect::set(&obj, &JsValue::from_str("reason"), &JsValue::from_str(r))
                    .ok();
            }
            Ok(Some(FrameOutput::Event(
                "resetRequested".to_string(),
                obj.into(),
            )))
        }

        // ------------------------------------------------------------------
        // Silent / no-op events.
        // ------------------------------------------------------------------
        "#readditionRequestedEvent" => Ok(None),

        // ------------------------------------------------------------------
        // Typing indicator — relay to JS as an event.
        // ------------------------------------------------------------------
        "#typingEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode typingEvent CBOR: {}", e))?;

            let CborValue::Map(ref top) = payload else {
                return Ok(None);
            };

            let action = cbor_str(top, "action").unwrap_or_default();
            let typing = TypingEvent {
                conversation_id: cbor_str(top, "convoId").unwrap_or_else(|| convo_id.to_string()),
                sender_did: cbor_str(top, "did").unwrap_or_default(),
                is_typing: action != "typingStop",
            };

            let event_js = make_event_js("typing", &typing)?;
            Ok(Some(FrameOutput::Event("typing".to_string(), event_js)))
        }

        // ------------------------------------------------------------------
        // Tree changed — surface to JS so the app can kick an HTTP catch-up
        // and pick up the commits that advance local epoch. Trying to apply
        // the commit from a co-delivered #messageEvent frame is unreliable
        // for heavily-inflated groups; fetch via the sync path instead.
        // ------------------------------------------------------------------
        "#treeChanged" => {
            let obj = js_sys::Object::new();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("type"),
                &JsValue::from_str("treeChanged"),
            )
            .ok();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("convoId"),
                &JsValue::from_str(convo_id),
            )
            .ok();
            Ok(Some(FrameOutput::Event(
                "treeChanged".to_string(),
                obj.into(),
            )))
        }

        // ------------------------------------------------------------------
        // Unknown event type — ignore without error.
        // ------------------------------------------------------------------
        _ => Ok(None),
    }
}

/// Build a `{type, data}` JS object suitable for the `on_event` callback.
fn make_event_js<T: Serialize>(event_type: &str, data: &T) -> Result<JsValue, String> {
    let data_js = serde_wasm_bindgen::to_value(data)
        .map_err(|e| format!("Failed to serialize event data: {}", e))?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("type"),
        &JsValue::from_str(event_type),
    )
    .map_err(|_| "Reflect::set 'type' failed".to_string())?;
    js_sys::Reflect::set(&obj, &JsValue::from_str("data"), &data_js)
        .map_err(|_| "Reflect::set 'data' failed".to_string())?;
    Ok(obj.into())
}

// ---------------------------------------------------------------------------
// WsSubscription — public WASM handle
// ---------------------------------------------------------------------------

/// A live browser WebSocket subscription.
///
/// The four `Closure` fields keep the handler allocations alive for the
/// lifetime of this struct. Without them the JS garbage collector would collect
/// the closures and the WebSocket handlers would silently stop firing.
///
/// Call [`WsSubscription::close`] to disconnect cleanly.
#[wasm_bindgen]
pub struct WsSubscription {
    ws: WebSocket,
    // These hold the Closure<...> allocations alive. Never read after init.
    _on_open: Closure<dyn FnMut(web_sys::Event)>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_error: Closure<dyn FnMut(ErrorEvent)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
}

#[wasm_bindgen]
impl WsSubscription {
    /// Close the underlying WebSocket connection.
    pub fn close(&self) {
        // Ignore the result — the socket may already be closing.
        let _ = self.ws.close();
    }

    /// Returns `true` if the WebSocket is in the `OPEN` (1) state.
    pub fn is_open(&self) -> bool {
        self.ws.ready_state() == WebSocket::OPEN
    }
}

// ---------------------------------------------------------------------------
// connect() — public async entry point
// ---------------------------------------------------------------------------

/// Connect to a conversation WebSocket and return a live [`WsSubscription`].
///
/// # Parameters
/// - `convo_id`    — The MLS conversation/group ID to subscribe to.
/// - `base_url`    — XRPC service base URL, e.g. `"https://mls.catbird.blue"`.
/// - `auth_token`  — Bearer token used to obtain the subscription ticket.
/// - `on_message`  — JS callback invoked with a JSON-serialized [`UiMessage`]
///                   on every text, system, or encrypted-placeholder frame.
/// - `on_event`    — JS callback invoked with `{type: string, data: any}` for
///                   reaction, read-receipt, and group-refresh events.
/// - `on_status`   — JS callback invoked with a plain string:
///                   `"connected"`, `"disconnected"`, or `"error"`.
///
/// # Errors
/// Returns `Err(JsValue)` when the ticket HTTP request fails, the ticket
/// response cannot be parsed, or `WebSocket` construction itself fails.
#[wasm_bindgen]
pub async fn connect(
    convo_id: String,
    base_url: String,
    auth_token: String,
    on_message: Function,
    on_event: Function,
    on_status: Function,
) -> Result<WsSubscription, JsValue> {
    // ------------------------------------------------------------------
    // 1. Request a subscription ticket from the MLS delivery service.
    // ------------------------------------------------------------------
    let client = reqwest::Client::new();
    let ticket_resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsChat.getSubscriptionTicket",
            base_url
        ))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({ "convoId": convo_id }))
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("Ticket request failed: {}", e)))?;

    if !ticket_resp.status().is_success() {
        let status = ticket_resp.status();
        let body = ticket_resp.text().await.unwrap_or_default();
        return Err(JsValue::from_str(&format!(
            "Ticket request returned {}: {}",
            status, body
        )));
    }

    let ticket_data: serde_json::Value = ticket_resp
        .json()
        .await
        .map_err(|e| JsValue::from_str(&format!("Ticket JSON parse failed: {}", e)))?;

    let ticket = ticket_data["ticket"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("No 'ticket' field in ticket response"))?;
    let ws_endpoint = ticket_data["endpoint"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("No 'endpoint' field in ticket response"))?;

    // ------------------------------------------------------------------
    // 2. Build the WebSocket URL.
    // ------------------------------------------------------------------
    let ws_url = format!("{}?convoId={}&ticket={}", ws_endpoint, convo_id, ticket);

    // ------------------------------------------------------------------
    // 3. Create the browser WebSocket.
    // ------------------------------------------------------------------
    let ws = WebSocket::new(&ws_url)
        .map_err(|e| JsValue::from_str(&format!("WebSocket construction failed: {:?}", e)))?;

    // Receive binary frames as ArrayBuffer so we can cheaply convert them to
    // a Rust Vec<u8> via js_sys::Uint8Array::new(&data).to_vec().
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

    // ------------------------------------------------------------------
    // 4. Wire event handlers.
    // ------------------------------------------------------------------

    // onopen — notify the caller that the connection is established.
    let on_status_open = on_status.clone();
    let on_open = Closure::<dyn FnMut(web_sys::Event)>::new(move |_: web_sys::Event| {
        let _ = on_status_open.call1(&JsValue::NULL, &JsValue::from_str("connected"));
    });
    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

    // onerror — surface as status "error".
    let on_status_err = on_status.clone();
    let on_error = Closure::<dyn FnMut(ErrorEvent)>::new(move |_: ErrorEvent| {
        let _ = on_status_err.call1(&JsValue::NULL, &JsValue::from_str("error"));
    });
    ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    // onclose — surface as status "disconnected".
    let on_status_close = on_status.clone();
    let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |_: CloseEvent| {
        let _ = on_status_close.call1(&JsValue::NULL, &JsValue::from_str("disconnected"));
    });
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

    // onmessage — decode the DAG-CBOR frame and dispatch to the right callback.
    let convo_id_for_handler = convo_id.clone();
    let on_message_cb = on_message.clone();
    let on_event_cb = on_event.clone();
    let on_message_handler = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        // event.data() is a JsValue wrapping an ArrayBuffer (because we set
        // binary_type = Arraybuffer above).
        let data = event.data();
        let bytes = js_sys::Uint8Array::new(&data).to_vec();

        match handle_frame(&bytes, &convo_id_for_handler) {
            Ok(Some(FrameOutput::Message(msg))) => match serde_wasm_bindgen::to_value(&msg) {
                Ok(js_msg) => {
                    let _ = on_message_cb.call1(&JsValue::NULL, &js_msg);
                }
                Err(e) => {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "[catmos-ws] Failed to serialize UiMessage: {}",
                        e
                    )));
                }
            },
            Ok(Some(FrameOutput::Event(_kind, js_val))) => {
                let _ = on_event_cb.call1(&JsValue::NULL, &js_val);
            }
            Ok(None) => {
                // Intentionally ignored frame type (typing, readdition, etc.)
            }
            Err(e) => {
                web_sys::console::warn_1(&JsValue::from_str(&format!(
                    "[catmos-ws] Frame decode error: {}",
                    e
                )));
            }
        }
    });
    ws.set_onmessage(Some(on_message_handler.as_ref().unchecked_ref()));

    // ------------------------------------------------------------------
    // 5. Return the subscription handle, keeping all closures alive.
    // ------------------------------------------------------------------
    Ok(WsSubscription {
        ws,
        _on_open: on_open,
        _on_message: on_message_handler,
        _on_error: on_error,
        _on_close: on_close,
    })
}
