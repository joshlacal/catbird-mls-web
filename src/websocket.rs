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
    #[serde(default)]
    pub sequence_number: u64,
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
            sequence_number: message.sequence_number,
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

/// Normalize a frame route before it reaches storage or crypto. Stable IDs
/// must be canonical UUIDv4 text; legacy group handles are accepted only when
/// their exact 16-byte coordinate is unambiguous to the storage mapping.
fn normalize_frame_identifier(identifier: &str) -> Result<String, String> {
    if uuid::Uuid::parse_str(identifier).is_ok() {
        return crate::canonical_uuid_string(identifier, "frame conversation identity")
            .map_err(|error| error.to_string());
    }
    crate::decode_group_id(identifier)
        .map(hex::encode)
        .ok_or_else(|| format!("frame conversation identifier is not a valid stable UUID or group id: {identifier}"))
}

/// Resolve a frame's stable-or-legacy coordinate to the subscription's one
/// stable identity and current MLS group bytes. Storage and ambiguity errors
/// are returned; an unknown identifier is never treated as the subscription's
/// fallback group.
fn resolve_message_identity(
    identifier: &str,
    subscribed_conversation_id: &str,
) -> Result<(String, Vec<u8>), String> {
    // Resolve through the same storage-backed identity function used by all
    // send/read paths. It checks an exact authorized alias before rejecting a
    // compact/uppercase UUID-shaped group coordinate.
    let (stable_id, group_id) = crate::resolve_conversation_identity(identifier)
        .map_err(|error| format!("conversation identity lookup failed: {:?}", error))?;
    require_subscription_match(&stable_id, subscribed_conversation_id)?;
    let group_bytes = crate::decode_group_coordinate(&group_id)
        .ok_or_else(|| format!("mapped group {} is not an exact 16-byte id", group_id))?;
    Ok((stable_id, group_bytes))
}

fn require_subscription_match(
    frame_conversation_id: &str,
    subscribed_conversation_id: &str,
) -> Result<(), String> {
    if frame_conversation_id != subscribed_conversation_id {
        return Err(format!(
            "frame stable conversation {} does not match subscription {}",
            frame_conversation_id, subscribed_conversation_id
        ));
    }
    Ok(())
}

/// Validate the stable scope carried by server-sent ephemeral/control
/// payloads. These events are never allowed to inherit the route's identity
/// when the payload omits or mismatches it.
fn validate_event_scope(
    top: &[(CborValue, CborValue)],
    subscribed_conversation_id: &str,
    event_name: &str,
) -> Result<String, String> {
    let raw = cbor_str(top, "convoId")
        .or_else(|| cbor_str(top, "conversationId"))
        .ok_or_else(|| format!("{} is missing conversation scope", event_name))?;
    let stable = crate::canonical_uuid_string(&raw, &format!("{} conversation scope", event_name))
        .map_err(|error| error.to_string())?;
    let subscribed = crate::canonical_uuid_string(
        subscribed_conversation_id,
        "subscription conversation scope",
    )
    .map_err(|error| error.to_string())?;
    if stable != subscribed {
        return Err(format!(
            "{} conversation {} does not match subscription {}",
            event_name, stable, subscribed
        ));
    }
    Ok(stable)
}

fn validate_event_generation(
    top: &[(CborValue, CborValue)],
    key: &str,
    event_name: &str,
) -> Result<i32, String> {
    let raw = cbor_int(top, key).ok_or_else(|| format!("{} is missing {}", event_name, key))?;
    i32::try_from(raw)
        .ok()
        .filter(|generation| *generation >= 0)
        .ok_or_else(|| format!("{} {} is out of range", event_name, key))
}

/// Validate a generation coordinate when an event carries one. Reaction and
/// typing lexicons historically omitted this field, so absence remains
/// compatible; a supplied value is never allowed to be negative or overflow
/// the local reset-coordinate type.
fn validate_optional_event_generation(
    top: &[(CborValue, CborValue)],
    key: &str,
    event_name: &str,
) -> Result<Option<i32>, String> {
    if cbor_int(top, key).is_none() {
        return Ok(None);
    }
    validate_event_generation(top, key, event_name).map(Some)
}

/// Validate an optional current-group coordinate carried by a scoped event.
/// If present it must resolve to the subscribed stable conversation's current
/// group; never let an event route inherit a different group implicitly.
fn validate_event_group_scope(
    top: &[(CborValue, CborValue)],
    subscribed_conversation_id: &str,
    event_name: &str,
) -> Result<(), String> {
    let Some(raw_group_id) = cbor_str(top, "groupId").or_else(|| cbor_str(top, "currentGroupId"))
    else {
        return Ok(());
    };
    let provided = crate::decode_group_coordinate(&raw_group_id)
        .ok_or_else(|| format!("{} groupId is not an exact 16-byte coordinate", event_name))?;
    let (_, current_group_id) = crate::resolve_conversation_identity(subscribed_conversation_id)
        .map_err(|error| format!("{} group scope lookup failed: {:?}", event_name, error))?;
    let current = crate::decode_group_coordinate(&current_group_id)
        .ok_or_else(|| format!("{} current group mapping is invalid", event_name))?;
    if provided != current {
        return Err(format!(
            "{} groupId does not match the current mapped group",
            event_name
        ));
    }
    Ok(())
}

#[cfg(all(test, target_arch = "wasm32"))]
mod identity_tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[cfg(not(feature = "inventory-worker-tests"))]
    wasm_bindgen_test_configure!(run_in_browser);

    fn message_frame(frame_conversation_id: &str) -> Vec<u8> {
        let header = CborValue::Map(vec![
            (CborValue::Text("op".into()), CborValue::Integer(0.into())),
            (
                CborValue::Text("t".into()),
                CborValue::Text("#messageEvent".into()),
            ),
        ]);
        let message = CborValue::Map(vec![
            (CborValue::Text("id".into()), CborValue::Text("m1".into())),
            (
                CborValue::Text("convoId".into()),
                CborValue::Text(frame_conversation_id.into()),
            ),
            (
                CborValue::Text("createdAt".into()),
                CborValue::Text("2026-01-01T00:00:00Z".into()),
            ),
            (
                CborValue::Text("senderDid".into()),
                CborValue::Text("did:plc:sender".into()),
            ),
        ]);
        let payload = CborValue::Map(vec![(CborValue::Text("message".into()), message)]);
        let mut frame = Vec::new();
        ciborium::into_writer(&header, &mut frame).expect("encode header");
        ciborium::into_writer(&payload, &mut frame).expect("encode payload");
        frame
    }

    fn event_frame(event_type: &str, entries: Vec<(&str, CborValue)>) -> Vec<u8> {
        let header = CborValue::Map(vec![
            (CborValue::Text("op".into()), CborValue::Integer(0.into())),
            (
                CborValue::Text("t".into()),
                CborValue::Text(event_type.into()),
            ),
        ]);
        let payload = CborValue::Map(
            entries
                .into_iter()
                .map(|(key, value)| (CborValue::Text(key.into()), value))
                .collect(),
        );
        let mut frame = Vec::new();
        ciborium::into_writer(&header, &mut frame).expect("encode header");
        ciborium::into_writer(&payload, &mut frame).expect("encode payload");
        frame
    }

    #[wasm_bindgen_test]
    fn cross_route_message_frame_is_rejected() {
        assert!(normalize_frame_identifier("018F3F6A-7B2C-4D91-8A5E-0F123456789A").is_err());
        assert!(normalize_frame_identifier("018f3f6a7b2c4d918a5e0f123456789a").is_err());
        assert_eq!(
            normalize_frame_identifier("ABEiM0RVZneImaq7zN3u_w").unwrap(),
            "00112233445566778899aabbccddeeff"
        );
        require_subscription_match(
            "018f3f6a-7b2c-4d91-8a5e-0f123456789b",
            "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
        )
        .expect_err("cross-route stable identities must be rejected");
        let frame = message_frame("018f3f6a-7b2c-4d91-8a5e-0f123456789b");
        let result = handle_frame(&frame, "018f3f6a-7b2c-4d91-8a5e-0f123456789a");
        assert!(
            result.is_err(),
            "a frame for another stable conversation must not be delivered on this subscription"
        );
    }

    #[wasm_bindgen_test]
    fn cleartext_reaction_frames_are_rejected() {
        let frame = event_frame(
            "#reactionEvent",
            vec![
                ("messageId", CborValue::Text("m1".into())),
                ("did", CborValue::Text("did:plc:sender".into())),
                ("reaction", CborValue::Text("👍".into())),
                ("action", CborValue::Text("add".into())),
            ],
        );
        assert!(
            handle_frame(&frame, "018f3f6a-7b2c-4d91-8a5e-0f123456789a").is_err(),
            "cleartext reaction events are not authenticated MLS payloads"
        );
    }

    #[wasm_bindgen_test]
    fn reset_and_typing_frames_must_be_scoped_to_the_subscribed_conversation() {
        let stable_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let other_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789b";
        let reset = event_frame(
            "#groupResetEvent",
            vec![
                ("convoId", CborValue::Text(other_id.into())),
                (
                    "newGroupId",
                    CborValue::Text("00112233445566778899aabbccddeeff".into()),
                ),
                ("resetGeneration", CborValue::Integer(2.into())),
            ],
        );
        assert!(
            handle_frame(&reset, stable_id).is_err(),
            "a reset for another stable conversation must not arm this route"
        );
        let typing = event_frame(
            "#typingEvent",
            vec![
                ("conversationId", CborValue::Text(other_id.into())),
                ("action", CborValue::Text("typingStart".into())),
            ],
        );
        assert!(
            handle_frame(&typing, stable_id).is_err(),
            "typing events must carry the subscribed stable conversation"
        );
    }

    #[wasm_bindgen_test]
    fn reset_frames_fail_closed_before_emitting_without_durable_storage_cas() {
        let frame = event_frame(
            "#groupResetEvent",
            vec![
                (
                    "convoId",
                    CborValue::Text("018f3f6a-7b2c-4d91-8a5e-0f123456789a".into()),
                ),
                (
                    "newGroupId",
                    CborValue::Text("00112233445566778899aabbccddeeff".into()),
                ),
                ("resetGeneration", CborValue::Integer(2.into())),
            ],
        );
        assert!(
            handle_frame(&frame, "018f3f6a-7b2c-4d91-8a5e-0f123456789a").is_err(),
            "the UI event must not race ahead of the durable reset CAS"
        );
    }
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

fn cbor_bool(map: &[(CborValue, CborValue)], key: &str) -> Option<bool> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Text(k), CborValue::Bool(v)) if k == key => Some(*v),
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
            let (_frame_stable_id, frame_group_id) =
                resolve_message_identity(&msg_convo_id, convo_id)?;
            if let Some(raw_group_id) =
                cbor_str(msg_map, "groupId").or_else(|| cbor_str(msg_map, "currentGroupId"))
            {
                let scoped_group = crate::decode_group_coordinate(&raw_group_id)
                    .ok_or("messageEvent groupId is not an exact 16-byte coordinate")?;
                if scoped_group != frame_group_id {
                    return Err(
                        "messageEvent groupId does not match the current mapped group".into(),
                    );
                }
            }

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
            let mut decrypted_reaction: Option<ReactionEvent> = None;
            let decrypted = ciphertext.as_ref().and_then(|ct| {
                let gid = frame_group_id.clone();
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
                            use catbird_mls::orchestrator::types::{
                                MLSMessagePayload, MLSMessageType, ReactionAction,
                            };
                            let sender = String::from_utf8(res.sender_credential.identity)
                                .unwrap_or(sender_did_raw.clone());
                            let (text, payload_json) =
                                match MLSMessagePayload::decode(&res.plaintext) {
                                    Ok(payload) => {
                                        // Reactions are authenticated MLS
                                        // control payloads, not displayable
                                        // messages. Dispatch them before the
                                        // display filter would discard them.
                                        if payload.message_type == MLSMessageType::Reaction {
                                            let reaction = payload
                                                .reaction
                                                .as_ref()
                                                .ok_or("reaction payload is missing its body");
                                            match reaction {
                                                Ok(reaction) => {
                                                    decrypted_reaction = Some(ReactionEvent {
                                                        conversation_id: convo_id.to_string(),
                                                        message_id: reaction.message_id.clone(),
                                                        sender_did: sender.clone(),
                                                        emoji: reaction.emoji.clone(),
                                                        action: match reaction.action {
                                                            ReactionAction::Add => {
                                                                "add".to_string()
                                                            }
                                                            ReactionAction::Remove => {
                                                                "remove".to_string()
                                                            }
                                                        },
                                                    });
                                                }
                                                Err(error) => {
                                                    decrypt_err = Some(error.to_string());
                                                }
                                            }
                                            return None;
                                        }
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
                            Some((
                                crate::ui_message_from_orchestrator(
                                    catbird_mls::orchestrator::types::Message {
                                        id: id.clone(),
                                        conversation_id: convo_id.to_string(),
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

            if let Some(reaction) = decrypted_reaction {
                let event_js = make_event_js("reaction", &reaction)?;
                return Ok(Some(FrameOutput::Event("reaction".to_string(), event_js)));
            }

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
                        &JsValue::from_str(convo_id),
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
                sequence_number: 0,
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
                sequence_number: 0,
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
                sequence_number: 0,
                status: "delivered".to_string(),
                message_type: "system".to_string(),
                image: None,
            };

            Ok(Some(FrameOutput::Message(msg)))
        }

        // ------------------------------------------------------------------
        // Reaction events must arrive as authenticated MLS payloads. The
        // historical cleartext relay is intentionally rejected; accepting it
        // would let a server/event-route forge reactions without MLS
        // authentication. Decrypted MLS reactions are dispatched in the
        // message path below before display filtering.
        // ------------------------------------------------------------------
        "#reactionEvent" => {
            let payload: CborValue = ciborium::from_reader(Cursor::new(payload_bytes))
                .map_err(|e| format!("Failed to decode reactionEvent CBOR: {}", e))?;
            let CborValue::Map(ref top) = payload else {
                return Err("reactionEvent payload is not a CBOR map".to_string());
            };
            validate_event_scope(top, convo_id, "reactionEvent")?;
            validate_event_group_scope(top, convo_id, "reactionEvent")?;
            validate_optional_event_generation(top, "generation", "reactionEvent")?;
            Err("cleartext reactionEvent is not an authenticated MLS payload".to_string())
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

            let convo_id_owned = validate_event_scope(top, convo_id, "groupResetEvent")?;
            validate_event_group_scope(top, convo_id, "groupResetEvent")?;
            let raw_new_group_id =
                cbor_str(top, "newGroupId").ok_or("groupResetEvent is missing newGroupId")?;
            let new_group_bytes = hex::decode(&raw_new_group_id)
                .map_err(|_| "groupResetEvent newGroupId is not valid hex".to_string())?;
            if new_group_bytes.len() != 16 || hex::encode(&new_group_bytes) != raw_new_group_id {
                return Err(
                    "groupResetEvent newGroupId must be exact lowercase 16-byte hex".to_string(),
                );
            }
            let new_group_id = hex::encode(new_group_bytes);
            let reset_generation =
                validate_event_generation(top, "resetGeneration", "groupResetEvent")?;
            let reset_by = cbor_str(top, "resetBy").unwrap_or_default();
            let reason = cbor_str(top, "reason");
            let notified_at_ms = chrono::Utc::now().timestamp_millis();

            web_sys::console::log_1(&JsValue::from_str(&format!(
                "[catmos-ws] groupReset: convo={} newGroupId={} gen={} by={}",
                convo_id_owned,
                new_group_id,
                reset_generation,
                short_id(&reset_by)
            )));

            // Persist and CAS before exposing the event. If this fails, the
            // frame is rejected and no UI code is allowed to act on a reset
            // that never became durable.
            let storage = crate::STATE
                .with(|s| {
                    s.borrow()
                        .as_ref()
                        .map(|state| std::sync::Arc::clone(&state.storage))
                })
                .ok_or_else(|| {
                    "groupResetEvent cannot persist without initialized STATE".to_string()
                })?;
            storage
                .mark_reset_pending_sync(
                    &convo_id_owned,
                    &new_group_id,
                    reset_generation,
                    notified_at_ms,
                )
                .map_err(|error| format!("groupResetEvent durable CAS failed: {}", error))?;

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

            let convo_id_owned = validate_event_scope(top, convo_id, "resetRequestedEvent")?;
            validate_event_group_scope(top, convo_id, "resetRequestedEvent")?;
            let crypto_session_id = cbor_str(top, "cryptoSessionId").unwrap_or_default();
            let reset_generation =
                validate_event_generation(top, "generation", "resetRequestedEvent")?;
            let trigger = cbor_str(top, "trigger").unwrap_or_default();
            let request_event_id = cbor_str(top, "requestEventId").unwrap_or_default();
            let reason = cbor_str(top, "reason");
            // `expectedNewMlsGroupId` is `Option<String>` on the wire — the
            // common Phase 2.5 case is None (server has not minted). Treat
            // empty string the same as None for robustness.
            let expected_new_mls_group_id: Option<String> = cbor_str(top, "expectedNewMlsGroupId")
                .filter(|s| !s.is_empty())
                .map(|raw| {
                    let bytes = hex::decode(&raw).map_err(|_| {
                        format!(
                            "resetRequestedEvent expectedNewMlsGroupId is not valid hex: {}",
                            raw
                        )
                    })?;
                    if bytes.len() != 16 || hex::encode(&bytes) != raw {
                        return Err(format!(
                            "resetRequestedEvent expectedNewMlsGroupId is not exact lowercase 16-byte hex: {}",
                            raw
                        ));
                    }
                    Ok(raw)
                })
                .transpose()?;
            let notified_at_ms = chrono::Utc::now().timestamp_millis();

            let storage = crate::STATE
                .with(|s| {
                    s.borrow()
                        .as_ref()
                        .map(|state| std::sync::Arc::clone(&state.storage))
                })
                .ok_or_else(|| {
                    "resetRequestedEvent cannot persist without initialized STATE".to_string()
                })?;
            // Reuse the durable target for a replay/reopen. Minting a fresh
            // candidate before consulting storage would turn an idempotent
            // replay into a conflicting target.
            let new_group_id_hex = match expected_new_mls_group_id.clone() {
                Some(hex_id) => hex_id,
                None => storage
                    .reset_target_for_generation(&convo_id_owned, reset_generation)
                    .map_err(|error| {
                        format!("resetRequestedEvent target lookup failed: {}", error)
                    })?
                    .unwrap_or_else(|| format!("{:032x}", uuid::Uuid::new_v4().as_u128())),
            };
            storage
                .mark_reset_pending_sync(
                    &convo_id_owned,
                    &new_group_id_hex,
                    reset_generation,
                    notified_at_ms,
                )
                .map_err(|error| format!("resetRequestedEvent durable CAS failed: {}", error))?;

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
            // Surface the effective durable target, including a replayed or
            // freshly minted candidate. Consumers must never act on a
            // different local target than the CAS just accepted.
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("expectedNewMlsGroupId"),
                &JsValue::from_str(&new_group_id_hex),
            )
            .ok();
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

            let scoped_conversation_id = validate_event_scope(top, convo_id, "typingEvent")?;
            validate_event_group_scope(top, convo_id, "typingEvent")?;
            validate_optional_event_generation(top, "generation", "typingEvent")?;
            let action = cbor_str(top, "action").unwrap_or_default();
            let typing = TypingEvent {
                conversation_id: scoped_conversation_id,
                sender_did: cbor_str(top, "did")
                    .or_else(|| cbor_str(top, "actorDid"))
                    .unwrap_or_default(),
                is_typing: cbor_bool(top, "isTyping")
                    .or_else(|| cbor_bool(top, "typing"))
                    .unwrap_or(action != "typingStop"),
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
/// - `convo_id` — The MLS conversation/group ID to subscribe to.
/// - `base_url` — XRPC service base URL, e.g. `"https://mls.catbird.blue"`.
/// - `auth_token` — Bearer token used to obtain the subscription ticket.
/// - `on_message` — JS callback invoked with a JSON-serialized [`UiMessage`]
///   on every text, system, or encrypted-placeholder frame.
/// - `on_event` — JS callback invoked with `{type: string, data: any}` for
///   reaction, read-receipt, and group-refresh events.
/// - `on_status` — JS callback invoked with a plain string:
///   `"connected"`, `"disconnected"`, or `"error"`.
///
/// # Errors
/// Returns `Err(JsValue)` when the ticket HTTP request fails, the ticket
/// response cannot be parsed, or `WebSocket` construction itself fails.
#[allow(dead_code)]
async fn connect(
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
            "{}/xrpc/blue.catbird.chat.getSubscriptionTicket",
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
