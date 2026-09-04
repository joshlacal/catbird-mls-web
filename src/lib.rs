//! catbird-mls-web — Universal browser WASM package for catbird-mls.
//!
//! Any web app (catmos, witchsky, etc.) can consume this package. Auth is
//! injected from the host app via `catbird_mls_set_auth()` / `catbird_mls_clear_auth()`.
//! Storage keys are configurable via `catbird_mls_init(config)`.
//!
//! # Architecture
//!
//! Three platform trait implementations + a WASM-native MLS crypto context:
//!
//! | Trait | Implementation | Backend |
//! |---|---|---|
//! | `MLSAPIClient` | `WasmApiClient` | `reqwest` → browser `fetch` |
//! | `MLSStorageBackend` | `WasmStorageBackend` | Encrypted SQLite (OPFS SAH VFS) |
//! | `CredentialStore` | `SqliteCredentialStore` | Encrypted SQLite (OPFS SAH VFS) |
//! | `MlsCryptoContext` | `WasmMLSContext` | OpenMLS + sqlite-wasm-rs + sqlite3mc |
//!
//! All persistent storage uses a single encrypted SQLite database over OPFS,
//! shared across OpenMLS state, conversation/message storage, and credentials.
//!
//! # Worker requirement
//!
//! `WasmMLSContext` and the shared `SqliteConn` use the OPFS Synchronous Access
//! Handle (SAH) pool VFS for synchronous SQLite I/O. This VFS is only available
//! inside Web Workers.

#![cfg(target_arch = "wasm32")]
// This crate has no native implementation. Keeping the entire adapter behind
// the target gate lets `cargo test --lib` provide a lightweight host smoke
// check without compiling browser-only OPFS SQLite or native Opus support.

mod api_client;
mod browser_transport;
mod credentials;
pub mod mls_storage;
pub mod sqlite_conn;
mod storage;
mod strict_projection;
mod wasm_mls_context;
mod websocket;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use js_sys::Array;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use api_client::WasmApiClient;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use catbird_mls::blob_crypto::{decrypt_blob, encrypt_blob};
use catbird_mls::orchestrator::api_client::MLSAPIClient;
use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::storage::MLSStorageBackend;
use catbird_mls::MLSError;
use credentials::SqliteCredentialStore;
use storage::WasmStorageBackend;
use wasm_mls_context::WasmMLSContext;

const MAX_CONVERSATION_PAGES: usize = 100;
const MAX_CONVERSATION_ITEMS: usize = 10_000;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use api_client::WasmApiClient as WasmApiClientExport;
pub use browser_transport::{
    catbird_mls_clear_signer_bridge, catbird_mls_has_signer_bridge,
    catbird_mls_prepare_signed_request, catbird_mls_prepare_unsigned_request,
    catbird_mls_set_signer_bridge,
};
pub use credentials::SqliteCredentialStore as SqliteCredentialStoreExport;
pub use mls_storage::WasmSqliteStorage;
pub use sqlite_conn::{SqliteConn, WasmSqliteError};
pub use storage::WasmStorageBackend as WasmStorageBackendExport;

// ---------------------------------------------------------------------------
// Panic hook
// ---------------------------------------------------------------------------

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ---------------------------------------------------------------------------
// Error helper macro
// ---------------------------------------------------------------------------

macro_rules! js_err {
    ($($arg:tt)*) => {
        JsValue::from_str(&format!($($arg)*))
    };
}

/// Decode a conversation/group ID string to raw bytes.
///
/// The server returns **hex-encoded** group IDs (e.g. `bf5fb90180e4d868…`).
/// `create_conversation` historically sent base64url to the server, but the
/// server normalises to hex in its responses.  Try hex first; fall back to
/// base64url for any IDs that were cached before normalisation.
fn decode_group_id(id: &str) -> Option<Vec<u8>> {
    // Any parseable UUID shape (canonical, uppercase, compact, or mixed
    // casing) is a stable conversation identity. Reject it before either
    // legacy decoder; otherwise compact UUIDs are valid-looking 16-byte hex
    // groups and hyphenated UUIDs can fall through base64url.
    if uuid::Uuid::parse_str(id).is_ok() {
        return None;
    }

    decode_group_coordinate(id)
}

/// Decode a group coordinate after its provenance is already known (server
/// response, persisted mapping, or reset payload). Group IDs are exactly
/// 16-byte hex/base64 coordinates; unlike a caller-supplied ambiguous handle,
/// a 32-hex coordinate may syntactically resemble a compact UUID and must be
/// accepted here so the crypto path can operate on the server's group bytes.
fn decode_group_coordinate(id: &str) -> Option<Vec<u8>> {
    // Group coordinates are exactly 16 bytes, represented by 32 hex digits.
    if id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes: Result<Vec<u8>, _> = (0..id.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&id[i..i + 2], 16))
            .collect();
        if let Ok(b) = bytes {
            return Some(b);
        }
    }
    // Fallback: base64url
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(id)
        .ok()
        .filter(|bytes| bytes.len() == 16)
}

// ---------------------------------------------------------------------------
// Public data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    pub id: String,
    /// Current MLS group identifier (hex). This is mutable across resets;
    /// callers must use `id` for UI/API identity.
    pub group_id: String,
    pub display_name: String,
    pub members: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_views: Option<Vec<catbird_mls::orchestrator::types::MemberView>>,
    /// Immutable projection kind (`direct` or `group`).
    pub conversation_kind: String,
    pub last_message: Option<String>,
    pub last_message_at: Option<String>,
    pub unread_count: u32,
    pub is_group: bool,
}

/// Keep roster persistence and UI projections on the shared MemberView shape.
/// Legacy local group-state rows only contain DIDs, so infer the local creator
/// role there while preserving server-provided roles everywhere else.
fn member_views_from_dids(
    dids: Vec<String>,
    local_user_did: &str,
) -> Vec<catbird_mls::orchestrator::types::MemberView> {
    use catbird_mls::orchestrator::types::{MemberRole, MemberView};
    let mut seen = std::collections::HashSet::new();
    dids.into_iter()
        .filter(|did| !did.is_empty() && seen.insert(did.clone()))
        .map(|did| MemberView {
            role: if did == local_user_did {
                MemberRole::Admin
            } else {
                MemberRole::Member
            },
            did,
        })
        .collect()
}

fn conversation_is_group(members: &[catbird_mls::orchestrator::types::MemberView]) -> bool {
    members.len() != 2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub id: String,
    pub conversation_id: String,
    pub sender_did: String,
    pub sender_handle: String,
    pub content: String,
    pub timestamp: String,
    pub status: String,
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageAttachment {
    pub blob_id: String,
    pub key_b64: String,
    pub iv_b64: String,
    pub sha256: String,
    pub content_type: String,
    pub size: usize,
    pub width: u32,
    pub height: u32,
    pub alt_text: Option<String>,
    pub blurhash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptInStatusResult {
    pub did: String,
    pub opted_in: bool,
}

/// Resolve a UI/API identifier to the stable conversation id and current MLS
/// group id. New callers pass the stable UUID. A legacy caller may still pass
/// a group id, but it must resolve through the durable per-user alias map;
/// unknown or ambiguous aliases fail closed before any crypto operation.
fn resolve_conversation_identity(identifier: &str) -> Result<(String, String), JsValue> {
    let (storage, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.storage), did))
    })?;

    // A canonical stable UUID is authoritative when it exists. Before
    // rejecting any other parseable UUID shape, consult the *exact* durable
    // alias key: legacy group coordinates can be compact/uppercase UUID-shaped
    // strings and are authorized by storage provenance, never by syntax.
    let parseable_uuid = uuid::Uuid::parse_str(identifier).is_ok();
    if parseable_uuid && canonical_uuid_string(identifier, "conversation identity").is_ok() {
        let canonical = canonical_uuid_string(identifier, "conversation identity")
            .map_err(|error| js_err!("{}", error))?;
        if let Some(mapping) = storage
            .resolve_conversation_mapping(&user_did, &canonical)
            .map_err(|e| js_err!("conversation identity lookup failed: {}", e))?
        {
            return Ok(mapping);
        }
    }
    // Check raw aliases before the UUID-shape rejection. This is deliberately
    // exact: do not lowercase or reformat an alias before resolving it.
    if let Some(mapping) = storage
        .resolve_conversation_mapping(&user_did, identifier)
        .map_err(|e| js_err!("conversation identity lookup failed: {}", e))?
    {
        return Ok(mapping);
    }
    if parseable_uuid {
        return Err(js_err!(
            "conversation identifier is not a canonical stable UUID and has no authorized exact group alias: {}",
            identifier
        ));
    }

    let group_id = decode_group_id(identifier)
        .map(|bytes| hex::encode(bytes))
        .ok_or_else(|| {
            js_err!(
                "conversation identifier is neither a canonical UUID nor a valid MLS group id: {}",
                identifier
            )
        })?;
    storage
        .resolve_conversation_mapping(&user_did, &group_id)
        .map_err(|e| js_err!("conversation identity lookup failed: {}", e))?
        .ok_or_else(|| {
            js_err!(
                "group '{}' has no unique persisted stable conversation mapping",
                group_id
            )
        })
}

/// Resolve a legacy group handle to the canonical stable conversation UUID.
/// Browser workers use this before subscription bookkeeping so aliases cannot
/// create duplicate WebSocket handles.
#[wasm_bindgen]
pub fn catbird_mls_resolve_conversation_id(identifier: String) -> Result<String, JsValue> {
    resolve_conversation_identity(&identifier).map(|(conversation_id, _)| conversation_id)
}

/// Parse the current group id from either the string or `$bytes` shape used
/// by create-conversation coordinate responses.
fn parse_response_group_id(value: Option<&serde_json::Value>) -> Option<String> {
    let value = value?;
    if let Some(group_id) = value.as_str() {
        return decode_group_coordinate(group_id).map(hex::encode);
    }
    let encoded = value.get("$bytes").and_then(|bytes| bytes.as_str())?;
    B64.decode(encoded)
        .ok()
        .filter(|bytes| bytes.len() == 16)
        .map(hex::encode)
}

async fn persist_conversation_projection(
    storage: &WasmStorageBackend,
    user_did: &str,
    conversation_id: &str,
    group_id: &str,
    epoch: u64,
    members: Vec<catbird_mls::orchestrator::types::MemberView>,
) -> Result<(), JsValue> {
    storage
        .upsert_conversation_projection(
            user_did,
            conversation_id,
            group_id,
            epoch,
            &members,
            None,
            None,
        )
        .map_err(|e| js_err!("persist conversation projection failed: {}", e))?;
    Ok(())
}

/// Persist a joined group without bypassing a pending reset winner. Normal
/// joins install/update the stable projection; a join that lands the exact
/// pending target completes the mapping, historical alias, roster, group
/// state, and reset authority in one transaction.
async fn persist_join_projection(
    storage: &WasmStorageBackend,
    user_did: &str,
    conversation_id: &str,
    group_id: &str,
    epoch: u64,
    members: Vec<catbird_mls::orchestrator::types::MemberView>,
) -> Result<(), JsValue> {
    use catbird_mls::orchestrator::storage::MLSStorageBackend;
    use catbird_mls::orchestrator::types::ConversationState;

    let state = storage
        .get_conversation_state(conversation_id)
        .await
        .map_err(|e| js_err!("joined conversation state lookup failed: {:?}", e))?;
    if let Some(ConversationState::ResetPending {
        new_group_id,
        reset_generation,
        ..
    }) = state
    {
        if new_group_id != group_id {
            return Err(js_err!(
                "joined group {} does not match pending reset target {}",
                group_id,
                new_group_id
            ));
        }
        let expected_state_version = storage
            .conversation_state_version(user_did, conversation_id)
            .map_err(|e| js_err!("joined conversation state version failed: {}", e))?;
        let committed = storage
            .complete_reset_pending_projection(
                user_did,
                conversation_id,
                reset_generation,
                expected_state_version,
                group_id,
                epoch,
                &members,
            )
            .map_err(|e| js_err!("joined reset projection failed: {}", e))?;
        if !committed {
            return Err(js_err!(
                "joined reset projection lost generation/target CAS for {}",
                conversation_id
            ));
        }
        return Ok(());
    }

    persist_conversation_projection(storage, user_did, conversation_id, group_id, epoch, members)
        .await
}

fn image_attachment_from_message(
    message: &catbird_mls::orchestrator::types::Message,
) -> Option<ImageAttachment> {
    let embed = message.image_embed()?;
    Some(ImageAttachment {
        blob_id: embed.blob_id,
        key_b64: base64::engine::general_purpose::STANDARD.encode(embed.key),
        iv_b64: base64::engine::general_purpose::STANDARD.encode(embed.iv),
        sha256: embed.sha256,
        content_type: embed.content_type,
        size: embed.size,
        width: embed.width,
        height: embed.height,
        alt_text: embed.alt_text,
        blurhash: embed.blurhash,
    })
}

fn ui_message_from_orchestrator(message: catbird_mls::orchestrator::types::Message) -> Message {
    let image = image_attachment_from_message(&message);
    let message_type = if image.is_some() {
        "image".to_string()
    } else {
        "text".to_string()
    };

    Message {
        id: message.id,
        conversation_id: message.conversation_id,
        sender_did: message.sender_did,
        sender_handle: String::new(),
        content: message.text,
        timestamp: message.timestamp.to_rfc3339(),
        status: if message.is_own {
            "sent".to_string()
        } else {
            "delivered".to_string()
        },
        message_type,
        image,
    }
}

// ---------------------------------------------------------------------------
// Init config (deserialized from JS)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InitConfig {
    base_url: String,
    #[serde(default = "default_storage_prefix")]
    storage_prefix: String,
    #[serde(default = "default_db_prefix")]
    db_prefix: String,
    #[serde(default = "default_proxy_did")]
    proxy_did: String,
    /// Pre-supplied MLS database encryption key (hex-encoded, 256-bit).
    /// When provided, skips localStorage lookup for the key.
    /// Required when running inside a Web Worker (no localStorage access).
    mls_db_key: Option<String>,
}

fn default_storage_prefix() -> String {
    "catbird_mls".to_string()
}

fn default_db_prefix() -> String {
    "catbird-mls".to_string()
}

fn default_proxy_did() -> String {
    api_client::DEFAULT_ATPROTO_PROXY_DID.to_string()
}

// ---------------------------------------------------------------------------
// Global app state (WASM is single-threaded — thread_local + RefCell is safe)
// ---------------------------------------------------------------------------

struct AppState {
    base_url: String,
    storage_prefix: String,
    #[allow(dead_code)]
    db_prefix: String,
    proxy_did: String,
    api_client: Arc<WasmApiClient>,
    storage: Arc<WasmStorageBackend>,
    #[allow(dead_code)]
    credentials: Arc<SqliteCredentialStore>,
    user_did: Option<String>,
    auth_token: Option<String>,
    mls_context: Option<WasmMLSContext>,
}

thread_local! {
    static STATE: RefCell<Option<AppState>> = RefCell::new(None);
    /// Cache of server-side epoch per conversation ID.
    /// The server's `current_epoch` is an incrementing counter that may diverge
    /// from the OpenMLS group epoch.  After external commit (or any commit the
    /// server acknowledges), we cache the server's epoch here so that
    /// `sendMessage` passes the value the server expects.
    static SERVER_EPOCHS: RefCell<std::collections::HashMap<String, u64>> =
        RefCell::new(std::collections::HashMap::new());
    /// Sync cursors per conversation — tracks the `lastSeq` returned by
    /// `get_messages` so subsequent polls only fetch new messages.
    static SYNC_CURSORS: RefCell<std::collections::HashMap<String, String>> =
        RefCell::new(std::collections::HashMap::new());
    /// Seen message IDs for deduplication between WebSocket and polling paths.
    /// Bounded to ~1000 entries to avoid unbounded memory growth.
    static SEEN_MSG_IDS: RefCell<std::collections::HashSet<String>> =
        RefCell::new(std::collections::HashSet::new());
    /// Groups we just created — skip auto-join in fetch_new_messages since we
    /// are already a member.  Prevents unnecessary External Commits that inflate
    /// the epoch right after group creation.
    static RECENTLY_CREATED: RefCell<std::collections::HashSet<String>> =
        RefCell::new(std::collections::HashSet::new());
    /// Count of key packages published by THIS web device in the current session.
    /// Server stats are per-DID (include iOS key packages) so we track locally
    /// to know when this device actually needs to publish more.
    static LOCAL_KP_COUNT: RefCell<u32> = RefCell::new(0);
}

// ---------------------------------------------------------------------------
// State access helpers
// ---------------------------------------------------------------------------

fn with_state<F, R>(f: F) -> Result<R, JsValue>
where
    F: FnOnce(&AppState) -> Result<R, JsValue>,
{
    STATE.with(|s| {
        let borrowed = s.borrow();
        let state = borrowed.as_ref().ok_or_else(|| {
            js_err!("catbird-mls-web: not initialized — call catbird_mls_init() first")
        })?;
        f(state)
    })
}

fn with_state_mut<F, R>(f: F) -> Result<R, JsValue>
where
    F: FnOnce(&mut AppState) -> Result<R, JsValue>,
{
    STATE.with(|s| {
        let mut borrowed = s.borrow_mut();
        let state = borrowed.as_mut().ok_or_else(|| {
            js_err!("catbird-mls-web: not initialized — call catbird_mls_init() first")
        })?;
        f(state)
    })
}

// ---------------------------------------------------------------------------
// Session persistence — localStorage
// ---------------------------------------------------------------------------

fn save_session(storage_prefix: &str, did: &str, token: &str) -> Result<(), JsValue> {
    // localStorage is unavailable inside Web Workers — silently skip.
    let Some(window) = web_sys::window() else {
        return Ok(());
    };
    let storage = window
        .local_storage()
        .map_err(|e| js_err!("localStorage error: {:?}", e))?
        .ok_or_else(|| js_err!("No localStorage available"))?;
    storage.set_item(&format!("{}_session_id", storage_prefix), token)?;
    storage.set_item(&format!("{}_user_did", storage_prefix), did)?;
    Ok(())
}

fn load_session(storage_prefix: &str) -> Option<(String, String)> {
    let storage = web_sys::window()?.local_storage().ok()??;
    let did = storage
        .get_item(&format!("{}_user_did", storage_prefix))
        .ok()??;
    let token = storage
        .get_item(&format!("{}_session_id", storage_prefix))
        .ok()??;
    Some((did, token))
}

fn clear_session(storage_prefix: &str) {
    if let Some(Ok(Some(storage))) = web_sys::window().map(|w| w.local_storage()) {
        let _ = storage.remove_item(&format!("{}_session_id", storage_prefix));
        let _ = storage.remove_item(&format!("{}_user_did", storage_prefix));
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|e| js_err!("Serialization failed: {}", e))
}

fn array_to_strings(arr: &Array) -> Vec<String> {
    arr.iter().filter_map(|v| v.as_string()).collect()
}

/// Build a reqwest Client with the atproto-proxy header set.
fn proxy_client(proxy_did: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Ok(value) = reqwest::header::HeaderValue::from_str(proxy_did) {
        headers.insert("atproto-proxy", value);
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

// ---------------------------------------------------------------------------
// MLS storage key management
// ---------------------------------------------------------------------------

fn get_or_create_mls_key(storage_prefix: &str) -> Result<String, JsValue> {
    let ls = web_sys::window()
        .ok_or_else(|| js_err!("No global window"))?
        .local_storage()
        .map_err(|e| js_err!("localStorage unavailable: {:?}", e))?
        .ok_or_else(|| js_err!("No localStorage available"))?;

    let key_name = format!("{}_mls_db_key", storage_prefix);

    if let Some(key) = ls.get_item(&key_name).ok().flatten() {
        return Ok(key);
    }

    let mut key_bytes = [0u8; 32];
    getrandom::getrandom(&mut key_bytes)
        .map_err(|e| js_err!("Failed to generate MLS key: {}", e))?;
    let key_hex: String = key_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    ls.set_item(&key_name, &key_hex)
        .map_err(|e| js_err!("Failed to persist MLS key: {:?}", e))?;
    Ok(key_hex)
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/// Initialize the MLS WASM module.
///
/// `config` — JS object: `{ baseUrl: string, storagePrefix?: string, dbPrefix?: string }`
///
/// Defaults:
/// - `storagePrefix`: `"catbird_mls"` (localStorage keys)
/// - `dbPrefix`: `"catbird-mls"` (IndexedDB / SQLite names)
#[wasm_bindgen]
pub async fn catbird_mls_init(config: JsValue) -> Result<(), JsValue> {
    let cfg: InitConfig =
        serde_wasm_bindgen::from_value(config).map_err(|e| js_err!("Invalid config: {}", e))?;

    let api_client = Arc::new(WasmApiClient::with_proxy(
        cfg.base_url.clone(),
        cfg.proxy_did.clone(),
    ));

    // Resolve the MLS database encryption key. Pre-supplied key takes priority
    // (Worker mode — localStorage is unavailable there); fall back to localStorage.
    let db_key = match cfg.mls_db_key.clone() {
        Some(key) if !key.is_empty() => key,
        _ => get_or_create_mls_key(&cfg.storage_prefix)
            .map_err(|e| js_err!("Could not obtain MLS database key: {:?}", e))?,
    };

    // Open ONE shared encrypted SQLite database for OpenMLS state,
    // conversations/messages, and credentials. Previously each used a separate
    // IndexedDB — credentials leaked signing keys and MLS DID in plaintext, and
    // conversation storage had no encryption at the IDB layer.
    let sqlite_db_name = format!("{}-app.db", cfg.db_prefix);
    let shared_conn = match sqlite_conn::SqliteConn::open(&sqlite_db_name, &db_key) {
        Ok(conn) => Rc::new(conn),
        Err(e) => {
            web_sys::console::warn_1(&js_err!(
                "catbird-mls-web: SQLite unavailable ({}). \
                 All persistent storage commands will return errors. \
                 Ensure catbird_mls_init() runs inside a Worker.",
                e
            ));
            return Err(js_err!("Failed to open SQLite database: {}", e));
        }
    };

    // Create all schemas on the shared connection. Each component owns its own
    // tables; ensure_schema is idempotent (CREATE TABLE IF NOT EXISTS).
    mls_storage::WasmSqliteStorage::ensure_schema(&shared_conn)
        .map_err(|e| js_err!("Failed to create OpenMLS schema: {}", e))?;
    WasmStorageBackend::ensure_schema(&shared_conn)
        .map_err(|e| js_err!("Failed to create storage schema: {}", e))?;
    SqliteCredentialStore::ensure_schema(&shared_conn)
        .map_err(|e| js_err!("Failed to create credential schema: {}", e))?;

    let storage = WasmStorageBackend::new(Rc::clone(&shared_conn));
    let credentials = SqliteCredentialStore::new(Rc::clone(&shared_conn));

    let mls_context = match WasmMLSContext::open_with_conn(Rc::clone(&shared_conn)) {
        Ok(ctx) => Some(ctx),
        Err(e) => {
            web_sys::console::warn_1(&js_err!(
                "catbird-mls-web: MLS context unavailable ({}). \
                 Crypto commands will return errors.",
                e
            ));
            None
        }
    };

    // Reload persisted MLS groups into the in-memory cache so they survive
    // page refreshes. Group IDs in the `group_states` SQLite table are the
    // server-canonical hex strings; we also accept URL-safe base64 no-pad
    // for backward compat.
    if let Some(ref ctx) = mls_context {
        match storage.list_group_ids() {
            Ok(ids) => {
                let mut loaded = 0u32;
                for id_str in &ids {
                    let Some(gid_bytes) = decode_group_coordinate(id_str) else {
                        web_sys::console::warn_1(
                            &format!("catbird-mls-web: invalid group_id in storage: {}", id_str)
                                .into(),
                        );
                        continue;
                    };
                    match ctx.ensure_group_loaded(&gid_bytes) {
                        Ok(true) => loaded += 1,
                        Ok(false) => {
                            web_sys::console::warn_1(
                                &format!(
                                "catbird-mls-web: group {} in SQLite but not in OpenMLS storage",
                                id_str
                            )
                                .into(),
                            );
                        }
                        Err(e) => {
                            web_sys::console::warn_1(
                                &format!("catbird-mls-web: failed to load group {}: {}", id_str, e)
                                    .into(),
                            );
                        }
                    }
                }
                web_sys::console::log_1(
                    &format!(
                        "catbird-mls-web: reloaded {}/{} MLS groups from storage",
                        loaded,
                        ids.len()
                    )
                    .into(),
                );
            }
            Err(e) => {
                web_sys::console::warn_1(
                    &format!(
                        "catbird-mls-web: failed to enumerate persisted groups: {}",
                        e
                    )
                    .into(),
                );
            }
        }
    }

    let state = AppState {
        base_url: cfg.base_url,
        storage_prefix: cfg.storage_prefix,
        db_prefix: cfg.db_prefix,
        proxy_did: cfg.proxy_did,
        api_client,
        storage: Arc::new(storage),
        credentials: Arc::new(credentials),
        user_did: None,
        auth_token: None,
        mls_context,
    };

    STATE.with(|s| {
        *s.borrow_mut() = Some(state);
    });

    Ok(())
}

// ---------------------------------------------------------------------------
// Smoke test
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn catbird_mls_ping() -> String {
    "catbird-mls-web ready".to_string()
}

// ---------------------------------------------------------------------------
// Auth injection — host app provides credentials
// ---------------------------------------------------------------------------

/// Set auth credentials. The host app calls this after its own login flow.
///
/// Persists the session to localStorage for future restores.
#[wasm_bindgen]
pub fn catbird_mls_set_auth(did: String, token: String) -> Result<(), JsValue> {
    with_state_mut(|state| {
        state.api_client.set_auth(did.clone(), token.clone());
        save_session(&state.storage_prefix, &did, &token)?;
        state.storage.set_active_user_did(Some(did.clone()));
        state.user_did = Some(did);
        state.auth_token = Some(token);
        Ok(())
    })
}

/// Clear auth credentials and session storage.
#[wasm_bindgen]
pub fn catbird_mls_clear_auth() -> Result<(), JsValue> {
    with_state_mut(|state| {
        state.api_client.clear_auth();
        clear_session(&state.storage_prefix);
        state.storage.set_active_user_did(None);
        state.user_did = None;
        state.auth_token = None;
        Ok(())
    })
}

/// Try to restore a previously saved session from localStorage.
///
/// Returns `true` if a session was restored, `false` otherwise.
#[wasm_bindgen]
pub fn catbird_mls_try_restore_session() -> Result<bool, JsValue> {
    let storage_prefix = with_state(|s| Ok(s.storage_prefix.clone()))?;

    match load_session(&storage_prefix) {
        Some((did, token)) => with_state_mut(|state| {
            state.api_client.set_auth(did.clone(), token.clone());
            state.storage.set_active_user_did(Some(did.clone()));
            state.user_did = Some(did);
            state.auth_token = Some(token);
            Ok(true)
        }),
        None => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// MLS bootstrap — device registration + key packages
// ---------------------------------------------------------------------------

/// Bootstrap MLS device: register with the delivery service, generate
/// credentials, and upload key packages.
///
/// Must be called after `catbird_mls_init()` and `catbird_mls_set_auth()`. Idempotent —
/// skips registration if credentials already exist and key packages are
/// available on the server.
///
/// Returns a JSON object with `status`, `deviceId`, `mlsDid`, `keyPackagesPublished`.
#[wasm_bindgen]
pub async fn catbird_mls_setup() -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::orchestrator::credentials::CredentialStore;

    let (api_client, credentials, storage, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated — call catbird_mls_set_auth() first"))?;
        Ok((
            Arc::clone(&s.api_client),
            Arc::clone(&s.credentials),
            Arc::clone(&s.storage),
            did,
        ))
    })?;

    // Replay owner-bound speculative cleanup intents before any new setup
    // work. A crash/cancellation between MLS group creation and server
    // projection therefore cannot strand a group indefinitely; a target that
    // has since been adopted by the stable mapping is retained idempotently.
    for (intent_conversation, intent_group, reason) in storage
        .list_cleanup_intents(&user_did)
        .map_err(|e| js_err!("cleanup intent replay failed: {}", e))?
    {
        match storage
            .resolve_conversation_mapping(&user_did, &intent_group)
            .map_err(|e| js_err!("cleanup intent ownership lookup failed: {}", e))?
        {
            Some((stable_id, _))
                if stable_id == intent_conversation
                    // A create intent is armed before the server chooses the
                    // stable UUID, so its recorded conversation field is the
                    // speculative group itself. Any authenticated stable
                    // projection adopting that exact target is the intended
                    // outcome and may clear the replay intent idempotently.
                    || (reason == "create-speculative" && intent_conversation == intent_group) =>
            {
                storage
                    .clear_cleanup_intent(&user_did, &intent_group)
                    .map_err(|e| js_err!("clear adopted cleanup intent failed: {}", e))?;
            }
            Some((stable_id, _)) => {
                return Err(js_err!(
                    "cleanup intent {} conflicts with stable conversation {}",
                    intent_group,
                    stable_id
                ));
            }
            None => {
                let Some(group_bytes) = decode_group_coordinate(&intent_group) else {
                    return Err(js_err!(
                        "cleanup intent {} has an invalid exact group coordinate",
                        intent_group
                    ));
                };
                with_state(|s| {
                    if let Some(ctx) = s.mls_context.as_ref() {
                        ctx.delete_group(group_bytes.clone()).map_err(|e| {
                            js_err!("cleanup intent {} MLS delete failed: {:?}", intent_group, e)
                        })?;
                    }
                    Ok(())
                })?;
                storage
                    .delete_group_state(&intent_group)
                    .await
                    .map_err(|e| {
                        js_err!(
                            "cleanup intent {} group-state delete failed: {:?}",
                            intent_group,
                            e
                        )
                    })?;
                storage
                    .delete_conversation_by_group(&user_did, &intent_group)
                    .map_err(|e| {
                        js_err!(
                            "cleanup intent {} projection delete failed: {}",
                            intent_group,
                            e
                        )
                    })?;
                storage
                    .clear_cleanup_intent(&user_did, &intent_group)
                    .map_err(|e| js_err!("cleanup intent {} clear failed: {}", intent_group, e))?;
                web_sys::console::log_1(&JsValue::from_str(&format!(
                    "catbird-mls-web: replayed {} cleanup intent for {}",
                    reason, intent_group
                )));
            }
        }
    }

    web_sys::console::log_1(&js_err!(
        "catbird-mls-web: catbird_mls_setup() starting for {}",
        user_did
    ));

    // 1. Check if already registered
    let has_creds = credentials
        .has_credentials(&user_did)
        .await
        .map_err(|e| js_err!("Credential check failed: {:?}", e))?;
    web_sys::console::log_1(&js_err!("catbird-mls-web: has_credentials={}", has_creds));

    if has_creds {
        let stats = api_client
            .get_key_package_stats()
            .await
            .map_err(|e| js_err!("Key package stats failed: {:?}", e))?;
        if stats.available > 0 {
            let result = serde_json::json!({
                "status": "already_registered",
                "keyPackagesAvailable": stats.available,
            });
            return to_js(&result);
        }
        // No key packages on server — clear stale credentials and re-register
        credentials
            .clear_all(&user_did)
            .await
            .map_err(|e| js_err!("Failed to clear stale credentials: {:?}", e))?;
    }

    // 2. Generate device UUID
    let device_uuid = uuid::Uuid::new_v4().to_string();
    let identity_bytes = user_did.as_bytes().to_vec();

    // 3. Create initial key package (also creates signing key pair)
    let kp_result = with_state(|s| {
        let ctx = s.mls_context.as_ref().ok_or_else(|| {
            js_err!("MLS context not initialized — run catbird_mls_init() inside a Worker")
        })?;
        ctx.create_key_package(identity_bytes.clone())
            .map_err(|e| js_err!("create_key_package failed: {:?}", e))
    })?;

    web_sys::console::log_1(&js_err!(
        "catbird-mls-web: key package created, registering device {}...",
        device_uuid
    ));

    // 4. Register device with server via prepared request
    let expires_str = (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339();
    let input = serde_json::json!({
        "deviceUuid": device_uuid,
        "deviceName": "Catbird Web",
        "signaturePublicKey": { "$bytes": B64.encode(&kp_result.hash_ref) },
        "keyPackages": [{
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "expiresAt": expires_str,
            "data": { "$bytes": B64.encode(&kp_result.key_package_data) },
        }],
    });
    let req = catbird_mls::orchestrator::canonical_transport::PreparedRequest {
        operation: catbird_mls::orchestrator::canonical_transport::CanonicalOperation::EnrollDevice,
        method: "POST".to_string(),
        path: "/xrpc/blue.catbird.chat.enrollDevice".to_string(),
        body: Some(serde_json::to_vec(&input).map_err(|e| js_err!("JSON error: {:?}", e))?),
    };
    let response = api_client
        .submit_prepared_request(req)
        .await
        .map_err(|e| js_err!("Device registration failed: {:?}", e))?;
    if response.status != 200 {
        return Err(js_err!(
            "Device registration failed with status {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        ));
    }
    let output: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|e| js_err!("JSON decode: {:?}", e))?;
    let server_device_id = output
        .get("deviceId")
        .and_then(|v| v.as_str())
        .unwrap_or(&device_uuid)
        .to_string();
    let mls_did = output
        .get("mlsDid")
        .or_else(|| output.get("credentialDid"))
        .and_then(|v| v.as_str())
        .unwrap_or(&user_did)
        .to_string();

    // 5. Store credentials
    credentials
        .store_mls_did(&user_did, &mls_did)
        .await
        .map_err(|e| js_err!("store_mls_did failed: {:?}", e))?;
    credentials
        .store_device_uuid(&user_did, &server_device_id)
        .await
        .map_err(|e| js_err!("store_device_uuid failed: {:?}", e))?;
    credentials
        .store_signing_key(&user_did, &kp_result.hash_ref)
        .await
        .map_err(|e| js_err!("store_signing_key failed: {:?}", e))?;

    // 6. Publish additional key packages (target: 10)
    let target_count = 10u32;
    let mut published = 1u32; // 1 already sent during registration
    LOCAL_KP_COUNT.with(|c| *c.borrow_mut() = 1); // Track the registration KP
    for _ in 0..(target_count - 1) {
        let kp = with_state(|s| {
            let ctx = s
                .mls_context
                .as_ref()
                .ok_or_else(|| js_err!("MLS context not initialized"))?;
            ctx.create_key_package(identity_bytes.clone())
                .map_err(|e| js_err!("create_key_package failed: {:?}", e))
        })?;

        let expires_at = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();
        let replenish_input = serde_json::json!({
            "keyPackages": [{
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "expiresAt": expires_at,
                "data": { "$bytes": B64.encode(&kp.key_package_data) },
            }],
            "deviceId": server_device_id,
        });
        let replenish_req = catbird_mls::orchestrator::canonical_transport::PreparedRequest {
            operation:
                catbird_mls::orchestrator::canonical_transport::CanonicalOperation::ReplenishKeyPackages,
            method: "POST".to_string(),
            path: "/xrpc/blue.catbird.chat.replenishKeyPackages".to_string(),
            body: Some(
                serde_json::to_vec(&replenish_input).map_err(|e| js_err!("JSON error: {:?}", e))?,
            ),
        };
        match api_client.submit_prepared_request(replenish_req).await {
            Ok(resp) if resp.status == 200 => {
                published += 1;
                LOCAL_KP_COUNT.with(|c| *c.borrow_mut() += 1);
            }
            Ok(resp) => {
                web_sys::console::warn_1(&js_err!(
                    "Key package publish failed with status {}",
                    resp.status
                ));
                break;
            }
            Err(e) => {
                web_sys::console::warn_1(&js_err!("Key package publish failed: {:?}", e));
                break;
            }
        }
    }

    web_sys::console::log_1(&js_err!(
        "catbird-mls-web: device registered! id={}, mls_did={}, key_packages={}",
        server_device_id,
        mls_did,
        published
    ));

    let result = serde_json::json!({
        "status": "registered",
        "deviceId": server_device_id,
        "mlsDid": mls_did,
        "keyPackagesPublished": published,
    });
    to_js(&result)
}

// ---------------------------------------------------------------------------
// Key package replenishment
// ---------------------------------------------------------------------------

/// Check and replenish key packages on the server.
///
/// If fewer than 5 key packages are available, creates and publishes
/// new ones up to a target of 10.
///
/// Returns a JSON object with `available` (before) and `published` counts.
#[wasm_bindgen]
pub async fn catbird_mls_replenish_key_packages() -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let (api_client, credentials, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), Arc::clone(&s.credentials), did))
    })?;
    let device_uuid = credentials
        .get_device_uuid(&user_did)
        .await
        .map_err(|e| js_err!("Device UUID lookup failed: {:?}", e))?;

    // Track how many key packages THIS web device has published in this session.
    // Server stats are per-DID (includes iOS key packages) so we can't rely on them
    // to know if this device has enough of its own key packages on the server.
    let local_published = LOCAL_KP_COUNT.with(|c| *c.borrow());

    // If we've already published enough this session, skip.
    // Key packages from other devices (iOS) are useless to us since private keys are local.
    if local_published >= 5 {
        let result = serde_json::json!({
            "localPublished": local_published,
            "published": 0,
            "status": "sufficient_this_session",
        });
        return to_js(&result);
    }

    let identity_bytes = user_did.as_bytes().to_vec();
    let target = 10u32;
    let to_create = target.saturating_sub(local_published) as usize;
    let mut published = 0u32;

    let cipher_suite = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
    let expires_at = (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339();

    web_sys::console::log_1(&js_err!(
        "catbird-mls-web: replenishing key packages: local_published={}, creating {}",
        local_published,
        to_create
    ));

    for _ in 0..to_create {
        let kp_result = with_state(|s| {
            let ctx = s
                .mls_context
                .as_ref()
                .ok_or_else(|| js_err!("MLS context not initialized"))?;
            ctx.create_key_package(identity_bytes.clone())
                .map_err(|e| js_err!("create_key_package failed: {:?}", e))
        });
        match kp_result {
            Ok(kp) => {
                let replenish_input = serde_json::json!({
                    "keyPackages": [{
                        "cipherSuite": cipher_suite,
                        "expiresAt": expires_at,
                        "data": { "$bytes": B64.encode(&kp.key_package_data) },
                    }],
                    "deviceId": device_uuid.as_deref(),
                });
                let replenish_req = catbird_mls::orchestrator::canonical_transport::PreparedRequest {
                    operation: catbird_mls::orchestrator::canonical_transport::CanonicalOperation::ReplenishKeyPackages,
                    method: "POST".to_string(),
                    path: "/xrpc/blue.catbird.chat.replenishKeyPackages".to_string(),
                    body: Some(serde_json::to_vec(&replenish_input).map_err(|e| js_err!("JSON error: {:?}", e))?),
                };
                match api_client.submit_prepared_request(replenish_req).await {
                    Ok(resp) if resp.status == 200 => {
                        published += 1;
                        LOCAL_KP_COUNT.with(|c| *c.borrow_mut() += 1);
                    }
                    Ok(resp) => {
                        web_sys::console::warn_1(&js_err!(
                            "Key package publish failed with status {}",
                            resp.status
                        ));
                        break;
                    }
                    Err(e) => {
                        web_sys::console::warn_1(&js_err!(
                            "catbird-mls-web: publish_key_package failed: {:?}",
                            e
                        ));
                        break;
                    }
                }
            }
            Err(e) => {
                web_sys::console::warn_1(&js_err!(
                    "catbird-mls-web: create_key_package failed: {:?}",
                    e
                ));
                break;
            }
        }
    }

    web_sys::console::log_1(&js_err!(
        "catbird-mls-web: replenished {} key packages (total this session: {})",
        published,
        LOCAL_KP_COUNT.with(|c| *c.borrow())
    ));

    let result = serde_json::json!({
        "localPublished": LOCAL_KP_COUNT.with(|c| *c.borrow()),
        "published": published,
        "status": if published > 0 { "replenished" } else { "failed" },
    });
    to_js(&result)
}

// ---------------------------------------------------------------------------
// Group joining — external commit to join existing groups
// ---------------------------------------------------------------------------

/// Join an existing MLS group via Welcome message or external commit.
///
/// This is needed when this web client is a new device joining conversations
/// that already exist. Tries Welcome first (faster), falls back to external
/// commit.
///
/// Returns a JSON object with `status` and `epoch`.
#[wasm_bindgen]
pub async fn catbird_mls_join_group(convo_id: String) -> Result<JsValue, JsValue> {
    let result = try_join_group_internal(&convo_id).await?;
    to_js(&result)
}

/// Internal join helper — returns a JSON value, reusable from auto-join paths.
async fn try_join_group_internal(convo_id: &str) -> Result<serde_json::Value, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::orchestrator::storage::MLSStorageBackend;

    let (resolved_convo_id, _) = resolve_conversation_identity(convo_id)?;

    let (api_client, storage, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), Arc::clone(&s.storage), did))
    })?;

    let identity_bytes = user_did.as_bytes().to_vec();

    // 1. Try Welcome first
    match api_client.get_welcome(&resolved_convo_id).await {
        Ok(welcome_bytes) => {
            let join_result = with_state(|s| {
                let ctx = s
                    .mls_context
                    .as_ref()
                    .ok_or_else(|| js_err!("MLS context not initialized"))?;
                ctx.process_welcome(welcome_bytes, identity_bytes.clone(), None)
                    .map_err(|e| js_err!("process_welcome failed: {:?}", e))
            });

            match join_result {
                Ok(jr) => {
                    // Cache the local MLS epoch so send_message uses it
                    let welcome_epoch = with_state(|s| {
                        Ok(s.mls_context
                            .as_ref()
                            .and_then(|ctx| ctx.get_epoch(jr.group_id.clone()).ok())
                            .unwrap_or(0))
                    })
                    .unwrap_or(0);
                    SERVER_EPOCHS.with(|m| {
                        m.borrow_mut()
                            .insert(resolved_convo_id.clone(), welcome_epoch)
                    });

                    // MLS metadata cutover: bootstrap encrypted metadata so
                    // the conversation list / header render the title +
                    // description + avatar without waiting for a UI nudge.
                    // Best-effort — never block the join path on this.
                    let group_id_hex_for_bootstrap = jr
                        .group_id
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>();
                    let members =
                        match fetch_roster_for_convo(&api_client, &resolved_convo_id).await {
                            Ok(roster) if !roster.is_empty() => roster,
                            Ok(_) | Err(_) => storage
                                .get_group_state(&group_id_hex_for_bootstrap)
                                .await
                                .ok()
                                .flatten()
                                .map(|state| member_views_from_dids(state.members, &user_did))
                                .unwrap_or_else(|| {
                                    member_views_from_dids(vec![user_did.clone()], &user_did)
                                }),
                        };
                    persist_join_projection(
                        &storage,
                        &user_did,
                        &resolved_convo_id,
                        &group_id_hex_for_bootstrap,
                        welcome_epoch,
                        members,
                    )
                    .await?;
                    if let Err(e) = wasm_bootstrap_group_metadata(group_id_hex_for_bootstrap).await
                    {
                        web_sys::console::warn_1(&JsValue::from_str(&format!(
                            "[bootstrap] post-Welcome bootstrap failed (non-fatal): {:?}",
                            e
                        )));
                    }

                    return Ok(serde_json::json!({
                        "status": "joined_via_welcome",
                        "groupId": jr.group_id.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
                        "epoch": welcome_epoch,
                    }));
                }
                Err(e) => {
                    // Welcome was for a different device's key package — fall through
                    web_sys::console::warn_1(&js_err!(
                        "catbird-mls-web: process_welcome failed ({:?}), trying external commit",
                        e
                    ));
                }
            }
        }
        Err(_) => {
            // Welcome not available — fall through to external commit
        }
    }

    // 2. External commit fallback
    let group_info_bytes = api_client
        .get_group_info(&resolved_convo_id)
        .await
        .map_err(|e| js_err!("get_group_info failed: {:?}", e))?;

    let identity_for_gi = identity_bytes.clone();
    let ext_commit = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.create_external_commit(group_info_bytes, identity_bytes)
            .map_err(|e| js_err!("create_external_commit failed: {:?}", e))
    })?;

    // 3. Send external commit to server
    let input = serde_json::json!({
        "action": "externalCommit",
        "convoId": resolved_convo_id.clone(),
        "commit": { "$bytes": B64.encode(&ext_commit.commit_data) },
        "idempotencyKey": uuid::Uuid::new_v4().to_string(),
    });
    let req = catbird_mls::orchestrator::canonical_transport::PreparedRequest {
        operation:
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::SubmitTransition,
        method: "POST".to_string(),
        path: "/xrpc/blue.catbird.chat.submitTransition".to_string(),
        body: Some(serde_json::to_vec(&input).map_err(|e| js_err!("JSON error: {:?}", e))?),
    };
    let response = api_client
        .submit_prepared_request(req)
        .await
        .map_err(|e| js_err!("process_external_commit failed: {:?}", e))?;
    if response.status != 200 {
        return Err(js_err!(
            "process_external_commit failed with status {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        ));
    }
    let output: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|e| js_err!("JSON decode: {:?}", e))?;
    let server_epoch = output.get("newEpoch").and_then(|v| v.as_u64()).unwrap_or(0);

    // 4. Merge pending commit to finalize local state
    let local_epoch = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.merge_pending_commit(ext_commit.group_id.clone())
            .map_err(|e| js_err!("merge_pending_commit failed: {:?}", e))
    })?;

    // Cache server epoch so send_message uses it instead of local MLS epoch
    SERVER_EPOCHS.with(|m| {
        m.borrow_mut()
            .insert(resolved_convo_id.clone(), server_epoch)
    });

    let group_id_hex = ext_commit
        .group_id
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    let members = match fetch_roster_for_convo(&api_client, &resolved_convo_id).await {
        Ok(roster) if !roster.is_empty() => roster,
        Ok(_) | Err(_) => storage
            .get_group_state(&group_id_hex)
            .await
            .ok()
            .flatten()
            .map(|state| member_views_from_dids(state.members, &user_did))
            .unwrap_or_else(|| member_views_from_dids(vec![user_did.clone()], &user_did)),
    };
    persist_join_projection(
        &storage,
        &user_did,
        &resolved_convo_id,
        &group_id_hex,
        server_epoch.max(local_epoch),
        members,
    )
    .await?;

    // Publish updated GroupInfo so other clients can also external-commit join
    let publish_result = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.export_group_info(ext_commit.group_id.clone(), identity_for_gi)
            .map_err(|e| js_err!("export_group_info failed: {:?}", e))
    });
    match publish_result {
        Ok(gi_bytes) => {
            if let Err(e) = api_client
                .publish_group_info(&resolved_convo_id, &gi_bytes)
                .await
            {
                web_sys::console::warn_1(&js_err!(
                    "catbird-mls-web: publish_group_info failed after join: {:?}",
                    e
                ));
            }
        }
        Err(e) => {
            web_sys::console::warn_1(&js_err!(
                "catbird-mls-web: export_group_info failed after join: {:?}",
                e
            ));
        }
    }

    web_sys::console::log_1(&js_err!(
        "catbird-mls-web: try_join_group — server_epoch={}, local_epoch={}",
        server_epoch,
        local_epoch
    ));
    // MLS metadata cutover: bootstrap encrypted metadata after external
    // commit so the just-joined conversation displays title/description
    // /avatar immediately. Best-effort — never block the join path.
    let group_id_hex_for_bootstrap = ext_commit
        .group_id
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    if let Err(e) = wasm_bootstrap_group_metadata(group_id_hex_for_bootstrap).await {
        web_sys::console::warn_1(&JsValue::from_str(&format!(
            "[bootstrap] post-ExternalCommit bootstrap failed (non-fatal): {:?}",
            e
        )));
    }

    Ok(serde_json::json!({
        "status": "joined_via_external_commit",
        "epoch": server_epoch,
    }))
}

// ---------------------------------------------------------------------------
// Conversation commands
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedCreateResponse {
    Created {
        conversation_id: String,
        group_id: String,
        epoch: u64,
    },
    ExistingDirect {
        conversation_id: String,
        group_id: String,
        epoch: u64,
    },
}

fn canonical_uuid_text(value: &serde_json::Value, field: &str) -> Result<String, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{} must be a string", field))?;
    canonical_uuid_string(text, field)
}

fn canonical_uuid_string(text: &str, field: &str) -> Result<String, String> {
    let parsed = uuid::Uuid::parse_str(text).map_err(|_| format!("{} must be a UUID", field))?;
    let canonical = parsed.hyphenated().to_string();
    if canonical != text {
        return Err(format!("{} must use canonical lowercase UUID text", field));
    }
    if parsed.get_version() != Some(uuid::Version::Random)
        || parsed.get_variant() != uuid::Variant::RFC4122
    {
        return Err(format!("{} must be a canonical UUIDv4", field));
    }
    Ok(text.to_owned())
}

/// Strictly decode the closed conversation-creation union. The server's
/// created group must equal the exact group proposed by the client; missing or
/// unknown tags never fall back to a speculative local group.
fn parse_create_response(
    output: &serde_json::Value,
    proposed_group_id: &str,
) -> Result<ParsedCreateResponse, String> {
    let result = output
        .get("result")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "create response is missing result object".to_string())?;
    let result_type = result
        .get("$type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "create response is missing exact result $type".to_string())?;
    let coordinates = result
        .get("coordinates")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "create result is missing coordinates".to_string())?;
    let conversation_id = canonical_uuid_text(
        coordinates
            .get("conversationId")
            .ok_or_else(|| "create coordinates missing conversationId".to_string())?,
        "coordinates.conversationId",
    )?;
    let group_value = coordinates
        .get("groupId")
        .ok_or_else(|| "create coordinates missing groupId".to_string())?;
    let response_group_id = parse_response_group_id(Some(group_value))
        .ok_or_else(|| "create coordinates groupId is not an exact 16-byte group id".to_string())?;
    let proposed_group_id = decode_group_coordinate(proposed_group_id)
        .map(|bytes| hex::encode(bytes))
        .ok_or_else(|| "proposed group id is not an exact 16-byte group id".to_string())?;
    let epoch = coordinates
        .get("epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "create coordinates missing nonnegative epoch".to_string())?;

    match result_type {
        "blue.catbird.chat.defs#conversationCreatedResult" => {
            if result
                .get("entry")
                .and_then(serde_json::Value::as_object)
                .is_none()
            {
                return Err("conversationCreatedResult is missing entry".to_string());
            }
            if response_group_id != proposed_group_id {
                return Err(format!(
                    "created result group {} differs from proposed group {}",
                    response_group_id, proposed_group_id
                ));
            }
            Ok(ParsedCreateResponse::Created {
                conversation_id,
                group_id: response_group_id,
                epoch,
            })
        }
        "blue.catbird.chat.defs#existingDirectConversationResult" => {
            if result
                .get("conversationKind")
                .and_then(serde_json::Value::as_str)
                != Some("direct")
            {
                return Err(
                    "existingDirectConversationResult must declare conversationKind=direct"
                        .to_string(),
                );
            }
            let top_level_id = result
                .get("conversationId")
                .ok_or_else(|| {
                    "existingDirectConversationResult is missing conversationId".to_string()
                })
                .and_then(|value| canonical_uuid_text(value, "conversationId"))?;
            if top_level_id != conversation_id {
                return Err("existing direct result has mismatched conversation ids".to_string());
            }
            Ok(ParsedCreateResponse::ExistingDirect {
                conversation_id,
                group_id: response_group_id,
                epoch,
            })
        }
        other => Err(format!(
            "unknown conversation creation result tag: {}",
            other
        )),
    }
}

fn validate_existing_direct_view(
    view: &catbird_mls::orchestrator::types::ConversationView,
    expected_conversation_id: &str,
    expected_group_id: &str,
) -> Result<(), String> {
    if view.conversation_id != expected_conversation_id {
        return Err("existing direct view has a mismatched stable conversation id".to_string());
    }
    let actual_group = decode_group_coordinate(&view.group_id)
        .map(hex::encode)
        .ok_or_else(|| "existing direct view has an invalid group coordinate".to_string())?;
    let expected_group = decode_group_coordinate(expected_group_id)
        .map(hex::encode)
        .ok_or_else(|| "existing direct result has an invalid group coordinate".to_string())?;
    if actual_group != expected_group {
        return Err("existing direct view has a mismatched group coordinate".to_string());
    }
    if view.members.len() != 2 {
        return Err("existing direct view must contain exactly two members".to_string());
    }
    let mut dids = std::collections::HashSet::new();
    let admins = view
        .members
        .iter()
        .filter(|member| {
            dids.insert(member.did.clone())
                && matches!(
                    member.role,
                    catbird_mls::orchestrator::types::MemberRole::Admin
                )
        })
        .count();
    if dids.len() != 2 || admins != 1 {
        return Err(
            "existing direct view must preserve unique creator/admin and invitee/member roles"
                .to_string(),
        );
    }
    Ok(())
}

#[wasm_bindgen]
pub async fn catbird_mls_list_conversations() -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let (api_client, storage, user_did) = with_state(|s| {
        let user_did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), Arc::clone(&s.storage), user_did))
    })?;

    let mut seen = std::collections::HashSet::new();
    let mut seen_cursors = std::collections::HashSet::new();
    let mut convos = Vec::new();
    let mut cursor = None;
    let mut page_count = 0usize;
    loop {
        page_count = page_count.saturating_add(1);
        if page_count > MAX_CONVERSATION_PAGES {
            return Err(js_err!("get_conversations exceeded the page ceiling"));
        }
        let page = api_client
            .get_conversations(50, cursor.as_deref())
            .await
            .map_err(|e| js_err!("get_conversations failed: {:?}", e))?;
        if page.conversations.len() > 50
            || convos.len().saturating_add(page.conversations.len()) > MAX_CONVERSATION_ITEMS
        {
            return Err(js_err!("get_conversations exceeded the item ceiling"));
        }
        for c in page.conversations {
            // The stable conversation id is the sole UI/API identity. A
            // duplicate across pages must not create a second Svelte row or
            // regress the already-authoritative group coordinate.
            let conversation_id = c.conversation_id.clone();
            canonical_uuid_string(&conversation_id, "conversationId")
                .map_err(|e| js_err!("invalid conversation list identity: {}", e))?;
            let listed_group_id = decode_group_coordinate(&c.group_id)
                .map(|bytes| hex::encode(bytes))
                .ok_or_else(|| js_err!("conversation {} has invalid groupId", conversation_id))?;
            if !seen.insert(conversation_id.clone()) {
                continue;
            }
            // A server page can race a completed reset and still contain the
            // predecessor group alias. Preserve the locally fenced current
            // coordinate instead of letting that stale snapshot regress the
            // stable projection (or fail the entire list operation).
            let mut group_id = listed_group_id.clone();
            let mut members = c.members.clone();
            let mut epoch = c.epoch;
            let stale_alias = if let Some((_, current_group)) = storage
                .resolve_conversation_mapping(&user_did, &conversation_id)
                .map_err(|e| js_err!("conversation mapping lookup failed: {}", e))?
            {
                if current_group != listed_group_id
                    && storage
                        .conversation_group_aliases(&user_did, &conversation_id)
                        .map_err(|e| js_err!("conversation alias lookup failed: {}", e))?
                        .iter()
                        .any(|alias| alias == &listed_group_id)
                {
                    if let Some(local) = storage
                        .get_conversation(&user_did, &conversation_id)
                        .await
                        .map_err(|e| js_err!("stale conversation lookup failed: {:?}", e))?
                    {
                        group_id = local.group_id;
                        members = local.members;
                        epoch = local.epoch;
                    } else {
                        group_id = current_group;
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if !stale_alias {
                persist_conversation_projection(
                    &storage,
                    &user_did,
                    &conversation_id,
                    &group_id,
                    epoch,
                    members.clone(),
                )
                .await?;
            }

            // MLS metadata cutover: read display name from the local
            // decrypted-blob cache only; storage errors are not absence.
            let cached_title = storage
                .get_metadata_text(&group_id)
                .map_err(|e| js_err!("conversation metadata lookup failed: {}", e))?
                .and_then(|(title, _desc)| title);
            let member_dids: Vec<String> = members.iter().map(|m| m.did.clone()).collect();
            let display_name = cached_title
                .filter(|t: &String| !t.is_empty())
                .unwrap_or_else(|| member_dids.join(", "));
            let conversation_kind = storage
                .conversation_kind(&user_did, &conversation_id)
                .map_err(|e| js_err!("conversation kind lookup failed: {}", e))?
                .unwrap_or_else(|| {
                    if conversation_is_group(&members) {
                        "group".to_string()
                    } else {
                        "direct".to_string()
                    }
                });
            convos.push(Conversation {
                id: conversation_id,
                group_id,
                display_name,
                members: member_dids.clone(),
                member_views: Some(members.clone()),
                conversation_kind: conversation_kind.clone(),
                last_message: None,
                last_message_at: None,
                unread_count: 0,
                is_group: conversation_kind == "group",
            });
        }
        let Some(next) = page.cursor else { break };
        if !seen_cursors.insert(next.clone()) {
            return Err(js_err!("get_conversations pagination repeated cursor"));
        }
        cursor = Some(next);
    }

    to_js(&convos)
}

#[wasm_bindgen]
pub async fn catbird_mls_create_conversation(
    name: String,
    member_dids: Array,
) -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::orchestrator::storage::MLSStorageBackend;
    use catbird_mls::KeyPackageData;

    let (api_client, storage, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), Arc::clone(&s.storage), did))
    })?;

    let member_dids_vec = array_to_strings(&member_dids);
    if member_dids_vec.len() > MAX_CONVERSATION_ITEMS
        || member_dids_vec
            .iter()
            .any(|did| did.is_empty() || did == &user_did)
    {
        return Err(js_err!(
            "conversation invitee list contains an invalid or self DID"
        ));
    }
    let mut unique_member_dids = std::collections::HashSet::new();
    if member_dids_vec
        .iter()
        .any(|did| !unique_member_dids.insert(did.clone()))
    {
        return Err(js_err!("conversation invitee list contains duplicate DIDs"));
    }
    let identity_bytes = user_did.as_bytes().to_vec();

    let group_id_bytes = with_state(|s| {
        let ctx = s.mls_context.as_ref().ok_or_else(|| {
            js_err!("MLS context not initialized — run catbird_mls_init() inside a Worker")
        })?;
        let result = ctx
            .create_group(identity_bytes.clone(), None)
            .map_err(|e| js_err!("create_group failed: {:?}", e))?;
        Ok(result.group_id)
    })?;

    // Arm cancellation recovery immediately after the speculative MLS group
    // is created.  Key-package lookup, commit construction, and the network
    // request can all fail after this point; leaving the intent until after
    // those steps would strand a group with no replay/cleanup owner.
    let group_id_str = group_id_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    if let Err(error) = storage.mark_cleanup_intent(
        &user_did,
        &group_id_str,
        &group_id_str,
        "create-speculative",
    ) {
        let cleanup_error = with_state(|s| {
            if let Some(ctx) = s.mls_context.as_ref() {
                ctx.delete_group(group_id_bytes.clone())
                    .map_err(|e| js_err!("speculative MLS cleanup failed: {:?}", e))?;
            }
            Ok(())
        })
        .err();
        return Err(match cleanup_error {
            Some(cleanup_error) => js_err!(
                "cannot arm speculative create cleanup: {}; speculative cleanup failed: {:?}",
                error,
                cleanup_error
            ),
            None => js_err!("cannot arm speculative create cleanup: {}", error),
        });
    }

    let (_commit_bytes, welcome_bytes) = if member_dids_vec.is_empty() {
        (None, None)
    } else {
        let (credentials, user_did) = with_state(|s| {
            let did = s
                .user_did
                .clone()
                .ok_or_else(|| js_err!("Not authenticated"))?;
            Ok((Arc::clone(&s.credentials), did))
        })?;
        let actor_device_id = credentials
            .get_device_uuid(&user_did)
            .await
            .unwrap_or_default()
            .unwrap_or_default();
        let kp_refs = api_client
            .get_key_packages(&actor_device_id, &member_dids_vec)
            .await
            .map_err(|e| js_err!("get_key_packages failed: {:?}", e))?;

        let key_packages: Vec<KeyPackageData> = kp_refs
            .into_iter()
            .map(|r| KeyPackageData {
                data: r.key_package_data,
            })
            .collect();

        let add_result = with_state(|s| {
            let ctx = s
                .mls_context
                .as_ref()
                .ok_or_else(|| js_err!("MLS context not initialized"))?;
            ctx.add_members(group_id_bytes.clone(), key_packages)
                .map_err(|e| js_err!("add_members failed: {:?}", e))
        })?;

        with_state(|s| {
            let ctx = s
                .mls_context
                .as_ref()
                .ok_or_else(|| js_err!("MLS context not initialized"))?;
            ctx.merge_pending_commit(group_id_bytes.clone())
                .map_err(|e| js_err!("merge_pending_commit failed: {:?}", e))
        })?;

        (Some(add_result.commit_data), Some(add_result.welcome_data))
    };

    let mut req_body = serde_json::json!({
        "groupId": group_id_str,
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "members": member_dids_vec,
    });
    if let Some(welcome) = &welcome_bytes {
        req_body["welcomeMessage"] = serde_json::json!({ "$bytes": B64.encode(welcome) });
    }
    let create_req = catbird_mls::orchestrator::canonical_transport::PreparedRequest {
        operation:
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::CreateConversation,
        method: "POST".to_string(),
        path: "/xrpc/blue.catbird.chat.createConversation".to_string(),
        body: Some(serde_json::to_vec(&req_body).map_err(|e| js_err!("JSON error: {:?}", e))?),
    };
    let resp = api_client
        .submit_prepared_request(create_req)
        .await
        .map_err(|e| js_err!("create_conversation failed: {:?}", e))?;
    if resp.status != 200 {
        return Err(js_err!(
            "create_conversation failed with status {}: {}",
            resp.status,
            String::from_utf8_lossy(&resp.body)
        ));
    }
    let output: serde_json::Value =
        serde_json::from_slice(&resp.body).map_err(|e| js_err!("JSON decode: {:?}", e))?;
    let parsed = parse_create_response(&output, &group_id_str)
        .map_err(|error| js_err!("invalid create conversation result: {}", error))?;

    // The server can report that a direct conversation already exists. The
    // locally-created MLS group is speculative and must be discarded; return
    // one projection for the existing stable conversation instead of adding a
    // second row keyed by the fresh group id.
    if let ParsedCreateResponse::ExistingDirect {
        conversation_id: convo_id,
        group_id: existing_group_id,
        epoch: server_epoch,
    } = parsed.clone()
    {
        with_state(|s| {
            if let Some(ctx) = s.mls_context.as_ref() {
                ctx.delete_group(group_id_bytes.clone())
                    .map_err(|e| js_err!("existing direct MLS group cleanup failed: {:?}", e))?;
            }
            Ok(())
        })?;
        storage
            .delete_group_state(&group_id_str)
            .await
            .map_err(|e| js_err!("existing direct group cleanup failed: {:?}", e))?;
        storage
            .delete_conversation_by_group(&user_did, &group_id_str)
            .map_err(|e| js_err!("existing direct conversation cleanup failed: {}", e))?;
        storage
            .clear_cleanup_intent(&user_did, &group_id_str)
            .map_err(|e| js_err!("existing direct cleanup intent clear failed: {}", e))?;

        let mut existing_view = storage
            .get_conversation(&user_did, &convo_id)
            .await
            .map_err(|e| js_err!("existing conversation lookup failed: {:?}", e))?;
        // A legacy local projection may have a group and member DIDs but no
        // persisted roles/creator, so treat any failed final-view validation
        // as incomplete and fetch the authoritative server projection.
        let local_view_incomplete = existing_view.as_ref().is_some_and(|view| {
            validate_existing_direct_view(view, &convo_id, &existing_group_id).is_err()
        });
        if existing_view.is_none() || local_view_incomplete {
            // A race loser may have no local projection (fresh browser,
            // cleared storage, or a reset during create). Fetch the
            // authoritative server view instead of fabricating one from the
            // speculative request.
            let mut cursor = None;
            let mut seen_cursors = std::collections::HashSet::new();
            let mut page_count = 0usize;
            loop {
                page_count = page_count.saturating_add(1);
                if page_count > MAX_CONVERSATION_PAGES {
                    return Err(js_err!(
                        "existing direct authoritative lookup exceeded the page ceiling"
                    ));
                }
                let page = api_client
                    .get_conversations(50, cursor.as_deref())
                    .await
                    .map_err(|e| js_err!("existing direct authoritative lookup failed: {:?}", e))?;
                if page.conversations.len() > 50 {
                    return Err(js_err!(
                        "existing direct authoritative lookup exceeded the item ceiling"
                    ));
                }
                if let Some(found) = page
                    .conversations
                    .into_iter()
                    .find(|view| view.conversation_id == convo_id)
                {
                    existing_view = Some(found);
                    break;
                }
                let Some(next) = page.cursor else { break };
                if !seen_cursors.insert(next.clone()) {
                    return Err(js_err!(
                        "existing direct conversation pagination repeated cursor"
                    ));
                }
                cursor = Some(next);
            }
        }
        if local_view_incomplete
            && existing_view
                .as_ref()
                .is_some_and(|view| view.group_id.is_empty() || view.members.is_empty())
        {
            return Err(js_err!(
                "existingDirectConversationResult authoritative conversation {} is incomplete",
                convo_id
            ));
        }
        let existing_view = existing_view.ok_or_else(|| {
            js_err!(
                "existingDirectConversationResult authoritative conversation {} was not found",
                convo_id
            )
        })?;
        validate_existing_direct_view(&existing_view, &convo_id, &existing_group_id)
            .map_err(|error| js_err!("invalid existing direct authoritative view: {}", error))?;
        let members = existing_view
            .members
            .iter()
            .map(|member| member.did.clone())
            .collect::<Vec<_>>();
        let epoch = if server_epoch > 0 {
            server_epoch
        } else {
            existing_view.epoch
        };
        storage
            .upsert_conversation_projection(
                &user_did,
                &convo_id,
                &existing_group_id,
                epoch,
                &existing_view.members,
                None,
                None,
            )
            .map_err(|e| js_err!("persist existing direct projection failed: {}", e))?;

        let display_name = storage
            .get_metadata_text(&existing_group_id)
            .map_err(|e| js_err!("existing direct metadata lookup failed: {}", e))?
            .and_then(|(title, _)| title)
            .filter(|title| !title.is_empty())
            .unwrap_or_else(|| {
                if members.is_empty() {
                    name.clone()
                } else {
                    members.join(", ")
                }
            });
        SERVER_EPOCHS.with(|cache| cache.borrow_mut().insert(convo_id.clone(), epoch));
        return to_js(&Conversation {
            id: convo_id,
            group_id: existing_group_id,
            display_name,
            members: members.clone(),
            member_views: Some(existing_view.members.clone()),
            conversation_kind: "direct".to_string(),
            last_message: None,
            last_message_at: None,
            unread_count: 0,
            is_group: members.len() != 2,
        });
    }

    let ParsedCreateResponse::Created {
        conversation_id: convo_id,
        group_id: current_group_id,
        epoch: server_epoch,
    } = parsed
    else {
        unreachable!("existing direct result returned above")
    };

    let create_member_views: Vec<catbird_mls::orchestrator::types::MemberView> =
        std::iter::once(catbird_mls::orchestrator::types::MemberView {
            did: user_did.clone(),
            role: catbird_mls::orchestrator::types::MemberRole::Admin,
        })
        .chain(member_dids_vec.iter().cloned().map(|did| {
            catbird_mls::orchestrator::types::MemberView {
                did,
                role: catbird_mls::orchestrator::types::MemberRole::Member,
            }
        }))
        .collect();
    let create_member_dids: Vec<String> = create_member_views
        .iter()
        .map(|member| member.did.clone())
        .collect();
    let create_is_group = create_member_dids.len() != 2;
    let create_epoch = if server_epoch > 0 {
        server_epoch
    } else {
        with_state(|s| {
            Ok(s.mls_context
                .as_ref()
                .and_then(|ctx| ctx.get_epoch(group_id_bytes.clone()).ok())
                .unwrap_or(0))
        })
        .unwrap_or(0)
    };
    storage
        .upsert_conversation_projection(
            &user_did,
            &convo_id,
            &current_group_id,
            create_epoch,
            &create_member_views,
            None,
            None,
        )
        .map_err(|e| js_err!("persist created conversation projection failed: {}", e))?;
    storage
        .clear_cleanup_intent(&user_did, &group_id_str)
        .map_err(|e| js_err!("create cleanup intent clear failed: {}", e))?;
    SERVER_EPOCHS.with(|m| m.borrow_mut().insert(convo_id.clone(), create_epoch));

    // Mark as recently created so fetch_new_messages won't try to auto-join
    // (we're already a member — auto-join would cause unnecessary External Commits)
    RECENTLY_CREATED.with(|s| s.borrow_mut().insert(convo_id.clone()));

    // Publish GroupInfo so other clients can join via external commit
    let gi_result = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS not init"))?;
        ctx.export_group_info(group_id_bytes.clone(), identity_bytes.clone())
            .map_err(|e| js_err!("export_group_info: {:?}", e))
    });
    if let Ok(gi) = gi_result {
        if let Err(e) = api_client.publish_group_info(&convo_id, &gi).await {
            web_sys::console::warn_1(&js_err!(
                "catbird-mls-web: publish_group_info failed after create: {:?}",
                e
            ));
        }
    }

    let convo = Conversation {
        id: convo_id.clone(),
        group_id: current_group_id,
        display_name: name,
        members: create_member_dids,
        member_views: Some(create_member_views),
        conversation_kind: if create_is_group {
            "group".to_string()
        } else {
            "direct".to_string()
        },
        last_message: None,
        last_message_at: None,
        unread_count: 0,
        is_group: create_is_group,
    };

    to_js(&convo)
}

#[wasm_bindgen]
pub async fn catbird_mls_subscribe(
    convo_id: String,
    on_message: js_sys::Function,
    on_event: js_sys::Function,
    on_status: js_sys::Function,
) -> Result<websocket::WsSubscription, JsValue> {
    let (resolved_convo_id, _) = resolve_conversation_identity(&convo_id)?;
    let (base_url, auth_token) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token))
    })?;

    websocket::connect(
        resolved_convo_id,
        base_url,
        auth_token,
        on_message,
        on_event,
        on_status,
    )
    .await
}

#[wasm_bindgen]
pub async fn catbird_mls_unsubscribe(_convo_id: String) -> Result<(), JsValue> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Message commands
// ---------------------------------------------------------------------------

/// Re-join a group via external commit to sync the local epoch with the server.
///
/// Deletes the existing group state first so that `create_external_commit` can
/// create a fresh one, then merges and sends the external commit.
///
/// NOTE: External Commit MUST NOT be triggered automatically from the send /
/// 409 hot path — that causes epoch inflation (spec §5.3). Callers should
/// instead call `storage.mark_needs_rejoin(&convo_id)` and surface the error.
/// This function is retained for explicit user-driven rejoin flows and for the
/// deferred-recovery worker.
#[allow(dead_code)]
async fn rejoin_group(convo_id: &str) -> Result<(), JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let (resolved_convo_id, resolved_group_id) = resolve_conversation_identity(convo_id)?;

    let (api_client, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), did))
    })?;

    let identity_bytes = user_did.as_bytes().to_vec();

    // Delete existing group so OpenMLS doesn't complain about duplicate group IDs
    let group_id_bytes = decode_group_coordinate(&resolved_group_id);
    if let Some(ref gid) = group_id_bytes {
        STATE.with(|s| {
            let borrowed = s.borrow();
            if let Some(state) = borrowed.as_ref() {
                if let Some(ctx) = &state.mls_context {
                    let _ = ctx.delete_group(gid.clone());
                }
            }
        });
    }

    let group_info_bytes = api_client
        .get_group_info(&resolved_convo_id)
        .await
        .map_err(|e| js_err!("rejoin get_group_info failed: {:?}", e))?;

    let identity_for_gi = identity_bytes.clone();
    let ext_commit = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.create_external_commit(group_info_bytes, identity_bytes)
            .map_err(|e| js_err!("rejoin create_external_commit failed: {:?}", e))
    })?;

    let input = serde_json::json!({
        "action": "externalCommit",
        "convoId": resolved_convo_id,
        "commit": { "$bytes": B64.encode(&ext_commit.commit_data) },
        "idempotencyKey": uuid::Uuid::new_v4().to_string(),
    });
    let req = catbird_mls::orchestrator::canonical_transport::PreparedRequest {
        operation:
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::SubmitTransition,
        method: "POST".to_string(),
        path: "/xrpc/blue.catbird.chat.submitTransition".to_string(),
        body: Some(serde_json::to_vec(&input).map_err(|e| js_err!("JSON error: {:?}", e))?),
    };
    let response = api_client
        .submit_prepared_request(req)
        .await
        .map_err(|e| js_err!("rejoin process_external_commit failed: {:?}", e))?;
    if response.status != 200 {
        return Err(js_err!(
            "rejoin process_external_commit failed with status {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        ));
    }
    let output: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|e| js_err!("JSON decode: {:?}", e))?;
    let server_epoch = output.get("newEpoch").and_then(|v| v.as_u64()).unwrap_or(0);

    let local_epoch = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.merge_pending_commit(ext_commit.group_id.clone())
            .map_err(|e| js_err!("rejoin merge_pending_commit failed: {:?}", e))
    })?;

    SERVER_EPOCHS.with(|m| {
        m.borrow_mut()
            .insert(resolved_convo_id.clone(), server_epoch)
    });

    // Publish updated GroupInfo so other clients can also external-commit join
    let publish_result = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.export_group_info(ext_commit.group_id.clone(), identity_for_gi)
            .map_err(|e| js_err!("export_group_info failed: {:?}", e))
    });
    match publish_result {
        Ok(gi_bytes) => {
            if let Err(e) = api_client
                .publish_group_info(&resolved_convo_id, &gi_bytes)
                .await
            {
                web_sys::console::warn_1(&js_err!(
                    "catbird-mls-web: publish_group_info failed after rejoin: {:?}",
                    e
                ));
            }
        }
        Err(e) => {
            web_sys::console::warn_1(&js_err!(
                "catbird-mls-web: export_group_info failed after rejoin: {:?}",
                e
            ));
        }
    }

    web_sys::console::log_1(&js_err!(
        "catbird-mls-web: rejoin_group({}) — server_epoch={}, local_epoch={}",
        resolved_convo_id,
        server_epoch,
        local_epoch
    ));

    Ok(())
}

async fn send_payload_message_internal(
    convo_id: String,
    payload: catbird_mls::orchestrator::types::MLSMessagePayload,
) -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let (resolved_convo_id, group_id_hex) = resolve_conversation_identity(&convo_id)?;
    let (api_client, storage, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), Arc::clone(&s.storage), did))
    })?;

    let group_id_bytes = decode_group_coordinate(&group_id_hex).ok_or_else(|| {
        js_err!(
            "Invalid MLS group id '{}': not hex or base64url",
            group_id_hex
        )
    })?;

    // Encode as MLSMessagePayload JSON envelope (interoperable with iOS Catbird)
    let payload_bytes = payload
        .encode()
        .map_err(|e| js_err!("Failed to encode MLSMessagePayload: {:?}", e))?;
    let payload_json = String::from_utf8(payload_bytes.clone())
        .map_err(|e| js_err!("Failed to stringify MLSMessagePayload: {:?}", e))?;
    let display_text = payload.display_text();

    // Generate a stable msg_id before the retry loop for idempotent sends
    let msg_id = uuid::Uuid::new_v4().to_string();

    // Try sending up to 3 times, syncing epoch on 409 conflict
    for _attempt in 0..3 {
        // Try encrypt; if group not found locally, auto-join first
        let encrypt_result = {
            let first_try = with_state(|s| {
                let ctx = s.mls_context.as_ref().ok_or_else(|| {
                    js_err!("MLS context not initialized — run catbird_mls_init() inside a Worker")
                })?;
                match ctx.encrypt_message(group_id_bytes.clone(), payload_bytes.clone()) {
                    Ok(r) => Ok(Ok(r)),
                    Err(MLSError::GroupNotFound { .. }) => Ok(Err(())),
                    Err(e) => Err(js_err!("encrypt_message failed: {:?}", e)),
                }
            })?;

            match first_try {
                Ok(result) => result,
                Err(()) => {
                    // Spec §5.3 (MLS_CLIENT_PROTOCOL): Do NOT perform External Commit
                    // in the send hot path. External commits inflate epochs and race
                    // with other clients doing the same. Flag the conversation for
                    // deferred recovery and return an error; the sync loop / explicit
                    // rejoin entrypoint will handle the actual rejoin.
                    use catbird_mls::orchestrator::storage::MLSStorageBackend;
                    web_sys::console::warn_1(&js_err!(
                        "catbird-mls-web: group {} not found locally for send — flagging for deferred rejoin",
                        resolved_convo_id
                    ));
                    let _ = storage.mark_needs_rejoin(&resolved_convo_id).await;
                    return Err(js_err!(
                        "Group not found locally — sync in progress, please retry"
                    ));
                }
            }
        };

        // Query epoch AFTER encryption succeeds — the encrypt call ensures the
        // group is loaded in the MLS context, so get_epoch will find it.
        // Prefer SERVER_EPOCHS cache (set by join/rejoin/409 recovery), then
        // fall back to querying the MLS context directly.
        let epoch = {
            let mls_epoch = STATE.with(|s| {
                let borrowed = s.borrow();
                borrowed
                    .as_ref()
                    .and_then(|st| st.mls_context.as_ref())
                    .and_then(|ctx| ctx.get_epoch(group_id_bytes.clone()).ok())
            });
            // If MLS context returned an epoch, use it and update cache
            if let Some(e) = mls_epoch {
                if e > 0 {
                    SERVER_EPOCHS.with(|m| m.borrow_mut().insert(resolved_convo_id.clone(), e));
                }
                // Still prefer server cache if it's higher (server may be ahead after commits)
                let cached = SERVER_EPOCHS.with(|m| m.borrow().get(&resolved_convo_id).copied());
                cached.unwrap_or(e)
            } else {
                SERVER_EPOCHS
                    .with(|m| m.borrow().get(&resolved_convo_id).copied())
                    .unwrap_or(0)
            }
        };

        let send_input = serde_json::json!({
            "convoId": resolved_convo_id.clone(),
            "ciphertext": { "$bytes": B64.encode(&encrypt_result.ciphertext) },
            "epoch": epoch,
            "msgId": msg_id.clone(),
            "paddedSize": encrypt_result.ciphertext.len() as u32,
        });
        let send_req = catbird_mls::orchestrator::canonical_transport::PreparedRequest {
            operation:
                catbird_mls::orchestrator::canonical_transport::CanonicalOperation::SendMessage,
            method: "POST".to_string(),
            path: "/xrpc/blue.catbird.chat.sendMessage".to_string(),
            body: Some(
                serde_json::to_vec(&send_input).map_err(|e| js_err!("JSON error: {:?}", e))?,
            ),
        };
        match api_client.submit_prepared_request(send_req).await {
            Ok(resp) if resp.status == 200 => {
                // Persist to IndexedDB so messages survive navigation/reload
                let now = chrono::Utc::now();
                {
                    use catbird_mls::orchestrator::storage::MLSStorageBackend;
                    let stored_msg = catbird_mls::orchestrator::types::Message {
                        id: msg_id.clone(),
                        conversation_id: resolved_convo_id.clone(),
                        sender_did: user_did.clone(),
                        text: display_text.clone(),
                        timestamp: now,
                        epoch,
                        sequence_number: 0,
                        is_own: true,
                        delivery_status: None,
                        payload_json: Some(payload_json.clone()),
                    };
                    if let Err(e) = storage.store_message(&stored_msg).await {
                        web_sys::console::warn_1(&js_err!(
                            "catbird-mls-web: failed to persist sent message: {:?}",
                            e
                        ));
                    }
                }
                let message =
                    ui_message_from_orchestrator(catbird_mls::orchestrator::types::Message {
                        id: msg_id.clone(),
                        conversation_id: resolved_convo_id.clone(),
                        sender_did: user_did,
                        text: display_text.clone(),
                        timestamp: now,
                        epoch,
                        sequence_number: 0,
                        is_own: true,
                        delivery_status: None,
                        payload_json: Some(payload_json.clone()),
                    });
                return to_js(&message);
            }
            Ok(resp) => {
                let is_409 = resp.status == 409;
                let server_epoch_hint = if is_409 {
                    serde_json::from_slice::<serde_json::Value>(&resp.body)
                        .ok()
                        .and_then(|v| v.get("serverEpoch").and_then(|e| e.as_u64()))
                } else {
                    None
                };
                if is_409 {
                    web_sys::console::warn_1(&js_err!(
                        "catbird-mls-web: send_message 409 conflict for {}: server_epoch_hint={:?}, client_epoch={}",
                        resolved_convo_id,
                        server_epoch_hint,
                        epoch
                    ));
                    if let Some(target_epoch) = server_epoch_hint {
                        SERVER_EPOCHS.with(|m| {
                            m.borrow_mut()
                                .insert(resolved_convo_id.clone(), target_epoch)
                        });
                    }
                }
                return Err(js_err!(
                    "send_message failed with status {}: {}",
                    resp.status,
                    String::from_utf8_lossy(&resp.body)
                ));
            }
            Err(e) => {
                return Err(js_err!("send_message failed: {:?}", e));
            }
        }
    }

    Err(js_err!("send_message failed after retries"))
}

#[wasm_bindgen]
pub async fn catbird_mls_send_message(
    convo_id: String,
    content: String,
) -> Result<JsValue, JsValue> {
    send_payload_message_internal(
        convo_id,
        catbird_mls::orchestrator::types::MLSMessagePayload::text(&content),
    )
    .await
}

#[wasm_bindgen]
pub async fn catbird_mls_send_image(
    convo_id: String,
    content: String,
    data: Vec<u8>,
    content_type: String,
    width: u32,
    height: u32,
    alt_text: Option<String>,
) -> Result<JsValue, JsValue> {
    if !content_type.starts_with("image/") {
        return Err(js_err!("Unsupported image content type: {}", content_type));
    }
    if data.len() > 10 * 1024 * 1024 {
        return Err(js_err!("Image too large (max 10MB)"));
    }

    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;
    let encrypted = encrypt_blob(&data).map_err(|e| js_err!("encrypt_blob failed: {}", e))?;
    let (blob_id, _uploaded_size) = api_client
        .upload_blob(&encrypted.ciphertext)
        .await
        .map_err(|e| js_err!("upload_blob failed: {:?}", e))?;

    let embed = catbird_mls::orchestrator::types::MLSEmbedData::image(
        catbird_mls::orchestrator::types::MLSImageEmbed {
            blob_id,
            key: encrypted.key,
            iv: encrypted.iv,
            sha256: encrypted.sha256,
            content_type,
            size: data.len(),
            width,
            height,
            alt_text,
            blurhash: None,
        },
    )
    .map_err(|e| js_err!("Failed to encode image embed: {:?}", e))?;

    send_payload_message_internal(
        convo_id,
        catbird_mls::orchestrator::types::MLSMessagePayload::text_with_embed(&content, embed),
    )
    .await
}

#[wasm_bindgen]
pub async fn catbird_mls_get_image_attachment(
    blob_id: String,
    key_b64: String,
    iv_b64: String,
    sha256: String,
    content_type: String,
) -> Result<String, JsValue> {
    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;
    let key = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|e| js_err!("Invalid image key: {:?}", e))?;
    let iv = base64::engine::general_purpose::STANDARD
        .decode(iv_b64)
        .map_err(|e| js_err!("Invalid image IV: {:?}", e))?;
    let ciphertext = api_client
        .get_blob(&blob_id)
        .await
        .map_err(|e| js_err!("get_blob failed: {:?}", e))?;
    let plaintext = decrypt_blob(&ciphertext, &key, &iv, &sha256)
        .map_err(|e| js_err!("decrypt_blob failed: {}", e))?;

    Ok(format!(
        "data:{};base64,{}",
        content_type,
        base64::engine::general_purpose::STANDARD.encode(plaintext)
    ))
}

#[wasm_bindgen]
pub async fn catbird_mls_messages(
    convo_id: String,
    before: Option<String>,
) -> Result<JsValue, JsValue> {
    let (resolved_convo_id, _group_id) = resolve_conversation_identity(&convo_id)?;
    let storage = with_state(|s| Ok(Arc::clone(&s.storage)))?;

    let stored = storage
        .get_messages_before_cursor(&resolved_convo_id, 50, before.as_deref())
        .await
        .map_err(|e| js_err!("get_messages failed: {:?}", e))?;

    let messages: Vec<Message> = stored
        .into_iter()
        .filter(|m| m.has_displayable_body())
        .map(|mut message| {
            // Legacy rows may still carry the group id. Normalize the UI/API
            // projection to the stable conversation identity.
            message.conversation_id = resolved_convo_id.clone();
            ui_message_from_orchestrator(message)
        })
        .collect();

    to_js(&messages)
}

#[wasm_bindgen]
pub async fn catbird_mls_fetch_new_messages(convo_id: String) -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::orchestrator::storage::MLSStorageBackend;
    use catbird_mls::orchestrator::types::MLSMessagePayload;

    let (resolved_convo_id, group_id_hex) = resolve_conversation_identity(&convo_id)?;
    let (api_client, user_did, storage) = with_state(|s| {
        let did = s.user_did.clone().unwrap_or_default();
        Ok((Arc::clone(&s.api_client), did, Arc::clone(&s.storage)))
    })?;

    let stored_cursor = SYNC_CURSORS.with(|m| m.borrow().get(&resolved_convo_id).cloned());
    let (envelopes, new_cursor) = api_client
        .get_messages(
            &resolved_convo_id,
            stored_cursor.as_deref(),
            50,
            None,
            None,
            None,
        )
        .await
        .map_err(|e| js_err!("fetch_new_messages failed: {:?}", e))?;

    // Update sync cursor for next poll
    if let Some(ref cursor) = new_cursor {
        SYNC_CURSORS.with(|m| {
            m.borrow_mut()
                .insert(resolved_convo_id.clone(), cursor.clone())
        });
    }

    let group_id_bytes = decode_group_coordinate(&group_id_hex);

    web_sys::console::log_1(&js_err!(
        "catbird-mls-web: fetch_new_messages({}) — {} envelopes, group_id_decoded={}",
        resolved_convo_id,
        envelopes.len(),
        group_id_bytes.is_some()
    ));

    // Before decrypting, check if the group exists locally. If not, try to join.
    // Skip auto-join for groups we just created (we're already a member).
    let recently_created = RECENTLY_CREATED.with(|s| s.borrow().contains(&resolved_convo_id));
    if let Some(ref gid) = group_id_bytes {
        if recently_created {
            web_sys::console::log_1(&js_err!(
                "catbird-mls-web: skipping auto-join for recently created group {}",
                resolved_convo_id
            ));
        } else {
            let group_exists = STATE.with(|s| {
                let borrowed = s.borrow();
                if let Some(state) = borrowed.as_ref() {
                    if let Some(ctx) = &state.mls_context {
                        return ctx.get_epoch(gid.clone()).is_ok();
                    }
                }
                false
            });

            if !group_exists {
                match try_join_group_internal(&resolved_convo_id).await {
                    Ok(result) => {
                        let status = result["status"].as_str().unwrap_or("unknown");
                        web_sys::console::log_1(&js_err!(
                            "catbird-mls-web: auto-joined group {} ({})",
                            resolved_convo_id,
                            status
                        ));
                    }
                    Err(e) => {
                        web_sys::console::warn_1(&js_err!(
                            "catbird-mls-web: auto-join failed for {}: {:?}",
                            resolved_convo_id,
                            e
                        ));
                    }
                }
            }
        }
    }

    let mut messages = Vec::with_capacity(envelopes.len());
    for env in envelopes {
        // Self-echo filter: skip our own messages (already shown locally from send)
        if env.sender_did.to_lowercase() == user_did.to_lowercase() {
            continue;
        }

        let msg_id = env
            .server_message_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Dedup: skip messages already seen via WebSocket
        let already_seen = SEEN_MSG_IDS.with(|s| s.borrow().contains(&msg_id));
        if already_seen {
            continue;
        }

        // Returns Some((message, sender_did)) for displayable messages,
        // None for commit/proposal control messages that should be hidden.
        let decoded = match &group_id_bytes {
            Some(gid) => STATE.with(|s| {
                let borrowed = s.borrow();
                if let Some(state) = borrowed.as_ref() {
                    if let Some(ctx) = &state.mls_context {
                        match ctx.decrypt_message(gid.clone(), env.ciphertext.clone()) {
                            Ok(res) => {
                                // Empty plaintext = commit/control message, skip
                                if res.plaintext.is_empty() {
                                    return None;
                                }
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
                                        Err(_) => {
                                            let text = String::from_utf8(res.plaintext)
                                                .unwrap_or_else(|_| "[Binary]".to_string());
                                            if text.trim().is_empty() {
                                                return None;
                                            }
                                            (text, None)
                                        }
                                    };
                                let sender = String::from_utf8(res.sender_credential.identity)
                                    .unwrap_or_else(|_| env.sender_did.clone());
                                return Some((
                                    catbird_mls::orchestrator::types::Message {
                                        id: msg_id.clone(),
                                        conversation_id: resolved_convo_id.clone(),
                                        sender_did: sender.clone(),
                                        text,
                                        timestamp: env.timestamp,
                                        epoch: res.epoch,
                                        sequence_number: res.sequence_number,
                                        is_own: false,
                                        delivery_status: None,
                                        payload_json,
                                    },
                                    sender,
                                ));
                            }
                            Err(MLSError::InvalidInput { ref message })
                                if message.contains("commit message")
                                    || message.contains("proposal") =>
                            {
                                // Task #56: commit/proposal messages no longer auto-merge inside
                                // `decrypt_message`. For commits, the staged commit is sitting in
                                // `pending_incoming_merges`; drive the explicit merge here so the
                                // local epoch advances. Proposals don't stage anything, so skip.
                                if message.contains("commit message") {
                                    if let Err(e) = ctx.merge_incoming_commit(gid.clone()) {
                                        web_sys::console::warn_1(&js_err!(
                                            "catbird-mls-web: merge_incoming_commit failed for msg {}: {:?}",
                                            msg_id,
                                            e
                                        ));
                                    }
                                }
                                return None;
                            }
                            Err(ref e) => {
                                let err_str = format!("{:?}", e);
                                // WrongEpoch / TooDistantInThePast / AeadError = message from
                                // before we joined (after external commit, earlier epochs are
                                // undecryptable — this is expected MLS forward secrecy behavior)
                                let is_historical = err_str.contains("WrongEpoch")
                                    || err_str.contains("TooDistantInThePast")
                                    || err_str.contains("AeadError")
                                    || err_str.contains("UnableToDecrypt");
                                if !is_historical {
                                    web_sys::console::warn_1(&js_err!(
                                        "catbird-mls-web: decrypt error for msg {}: {:?}",
                                        msg_id,
                                        e
                                    ));
                                }
                            }
                        }
                    }
                }
                // Undecryptable — skip rather than show "[Encrypted]"
                None
            }),
            None => None,
        };

        let Some((mut storage_msg, _sender_did)) = decoded else {
            continue;
        };
        storage_msg.conversation_id = resolved_convo_id.clone();

        // Record as seen for dedup against WebSocket path
        SEEN_MSG_IDS.with(|s| {
            let mut set = s.borrow_mut();
            // Bound the set to prevent unbounded memory growth
            if set.len() > 1000 {
                set.clear();
            }
            set.insert(msg_id.clone());
        });

        // Persist to storage so catbird_mls_messages() returns these
        let _ = storage.store_message(&storage_msg).await;

        messages.push(ui_message_from_orchestrator(storage_msg));
    }

    // After processing all messages (including commits that advance the epoch),
    // refresh the SERVER_EPOCHS cache with the latest epoch from the MLS context.
    if let Some(ref gid) = group_id_bytes {
        let updated_epoch = STATE.with(|s| {
            let borrowed = s.borrow();
            borrowed
                .as_ref()
                .and_then(|st| st.mls_context.as_ref())
                .and_then(|ctx| ctx.get_epoch(gid.clone()).ok())
        });
        if let Some(epoch) = updated_epoch {
            if epoch > 0 {
                SERVER_EPOCHS.with(|m| m.borrow_mut().insert(resolved_convo_id.clone(), epoch));
            }
        }
    }

    to_js(&messages)
}

/// Build the shared MLS reaction envelope. Reactions are application
/// messages, not a cleartext delivery-service action; the stable conversation
/// route and current group coordinate are selected by
/// `send_payload_message_internal` after identity resolution.
fn reaction_payload_for_wire(
    message_id: &str,
    emoji: &str,
    action: &str,
) -> Result<catbird_mls::orchestrator::types::MLSMessagePayload, String> {
    let action = match action {
        "add" => catbird_mls::orchestrator::types::ReactionAction::Add,
        "remove" => catbird_mls::orchestrator::types::ReactionAction::Remove,
        other => return Err(format!("unsupported reaction action: {}", other)),
    };
    Ok(catbird_mls::orchestrator::types::MLSMessagePayload::reaction(message_id, emoji, action))
}

#[wasm_bindgen]
pub async fn catbird_mls_send_reaction(
    conversation_id: String,
    message_id: String,
    emoji: String,
    action: String,
) -> Result<(), JsValue> {
    let (resolved_convo_id, _) = resolve_conversation_identity(&conversation_id)?;
    let payload = reaction_payload_for_wire(&message_id, &emoji, &action)
        .map_err(|error| js_err!("send reaction failed: {}", error))?;
    // The shared send path encrypts the complete reaction envelope with the
    // current MLS group, submits the stable conversation route, and persists
    // the resulting message. Historical-alias message IDs remain untouched
    // inside the encrypted payload for cross-reset targeting.
    send_payload_message_internal(resolved_convo_id, payload).await?;

    Ok(())
}

#[wasm_bindgen]
pub async fn catbird_mls_update_cursor(
    _conversation_id: String,
    _cursor: String,
) -> Result<(), JsValue> {
    Err(js_err!("legacy mlsChat updateCursor is disabled; subscription cursors are managed via subscribeEvents"))
}

// ---------------------------------------------------------------------------
// Member commands
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub async fn catbird_mls_get_members(conversation_id: String) -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::storage::MLSStorageBackend;

    let (resolved_convo_id, _group_id) = resolve_conversation_identity(&conversation_id)?;
    let (storage, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.storage), did))
    })?;

    let convo = storage
        .get_conversation(&user_did, &resolved_convo_id)
        .await
        .map_err(|e| js_err!("get_group_members storage error: {:?}", e))?;

    let members: Vec<GroupMember> = match convo {
        Some(c) => c
            .members
            .into_iter()
            .map(|m| GroupMember {
                did: m.did.clone(),
                handle: String::new(),
                display_name: None,
                role: match m.role {
                    catbird_mls::orchestrator::types::MemberRole::Admin => "admin".to_string(),
                    catbird_mls::orchestrator::types::MemberRole::Member => "member".to_string(),
                },
            })
            .collect(),
        None => vec![],
    };

    to_js(&members)
}

/// Add one or more members to an existing group in a single MLS commit.
///
/// Flow:
/// 1. Fetch key packages for all `member_dids` in one batch request.
/// 2. Produce a single `add_members` commit + Welcome covering all new members.
/// 3. Merge the pending commit locally (one epoch advance regardless of member count).
/// 4. Send the commit + welcome to the server via `commitGroupChange`.
/// 5. Update the cached server epoch.
#[wasm_bindgen]
pub async fn catbird_mls_add_group_members(
    conversation_id: String,
    member_dids: Array,
) -> Result<(), JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::KeyPackageData;

    let member_dids_vec = array_to_strings(&member_dids);
    if member_dids_vec.is_empty() {
        return Ok(());
    }

    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;

    // Resolve stable conversation ID → current group ID bytes. Legacy group
    // callers remain accepted when no durable mapping exists.
    let (resolved_convo_id, group_id_hex) = resolve_conversation_identity(&conversation_id)?;
    let group_id_bytes = decode_group_coordinate(&group_id_hex)
        .ok_or_else(|| js_err!("Invalid conversation/group ID: {}", group_id_hex))?;

    // 1. Fetch key packages for all new members in one batch request.
    let (credentials, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.credentials), did))
    })?;
    let actor_device_id = credentials
        .get_device_uuid(&user_did)
        .await
        .unwrap_or_default()
        .unwrap_or_default();
    let kp_refs = api_client
        .get_key_packages(&actor_device_id, &member_dids_vec)
        .await
        .map_err(|e| js_err!("get_key_packages failed: {:?}", e))?;

    let key_packages: Vec<KeyPackageData> = kp_refs
        .into_iter()
        .map(|r| KeyPackageData {
            data: r.key_package_data,
        })
        .collect();

    if key_packages.is_empty() {
        return Err(js_err!(
            "No key packages available for any of the requested members"
        ));
    }

    // 2. Single MLS add_members commit covering all new members (one epoch advance).
    let add_result = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.add_members(group_id_bytes.clone(), key_packages)
            .map_err(|e| js_err!("add_members failed: {:?}", e))
    })?;

    // 3. Send commit + welcome to server.
    let mut input = serde_json::json!({
        "action": "addMembers",
        "convoId": resolved_convo_id,
        "memberDids": member_dids_vec,
        "commit": { "$bytes": B64.encode(&add_result.commit_data) },
        "idempotencyKey": uuid::Uuid::new_v4().to_string(),
    });
    input["welcome"] = serde_json::json!({ "$bytes": B64.encode(&add_result.welcome_data) });
    let add_req = catbird_mls::orchestrator::canonical_transport::PreparedRequest {
        operation:
            catbird_mls::orchestrator::canonical_transport::CanonicalOperation::SubmitTransition,
        method: "POST".to_string(),
        path: "/xrpc/blue.catbird.chat.submitTransition".to_string(),
        body: Some(serde_json::to_vec(&input).map_err(|e| js_err!("JSON error: {:?}", e))?),
    };
    let response = api_client
        .submit_prepared_request(add_req)
        .await
        .map_err(|e| {
            let _ = with_state(|s| {
                if let Some(ctx) = s.mls_context.as_ref() {
                    let _ = ctx.clear_pending_commit(group_id_bytes.clone());
                }
                Ok(())
            });
            js_err!("add_members server call failed: {:?}", e)
        })?;
    if response.status != 200 {
        let _ = with_state(|s| {
            if let Some(ctx) = s.mls_context.as_ref() {
                let _ = ctx.clear_pending_commit(group_id_bytes.clone());
            }
            Ok(())
        });
        return Err(js_err!(
            "add_members server call failed with status {}",
            response.status
        ));
    }

    Ok(())
}

/// Add a single member to a group (convenience wrapper around batch add).
#[wasm_bindgen]
pub async fn catbird_mls_add_participants(
    conversation_id: String,
    target_did: String,
) -> Result<(), JsValue> {
    let arr = Array::new();
    arr.push(&JsValue::from_str(&target_did));
    catbird_mls_add_group_members(conversation_id, arr).await
}

#[wasm_bindgen]
pub async fn catbird_mls_demote_member(
    _conversation_id: String,
    _target_did: String,
) -> Result<(), JsValue> {
    Err(js_err!("demoteAdmin is a signed policy transition and is not wired in WASM"))
}

#[wasm_bindgen]
pub async fn catbird_mls_remove_participants(
    conversation_id: String,
    target_did: String,
) -> Result<(), JsValue> {
    let (resolved_convo_id, _group_id) = resolve_conversation_identity(&conversation_id)?;
    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;

    let input = serde_json::json!({
        "convoId": resolved_convo_id,
        "targetDid": target_did,
    });
    let req = catbird_mls::orchestrator::canonical_transport::PreparedRequest {
        operation: catbird_mls::orchestrator::canonical_transport::CanonicalOperation::RequestLeave,
        method: "POST".to_string(),
        path: "/xrpc/blue.catbird.chat.requestLeave".to_string(),
        body: Some(serde_json::to_vec(&input).map_err(|e| js_err!("JSON error: {:?}", e))?),
    };
    let resp = api_client
        .submit_prepared_request(req)
        .await
        .map_err(|e| js_err!("remove_group_member failed: {:?}", e))?;
    if resp.status != 200 {
        return Err(js_err!(
            "remove_group_member failed with status {}: {}",
            resp.status,
            String::from_utf8_lossy(&resp.body)
        ));
    }

    Ok(())
}

/// Leave a conversation.
#[wasm_bindgen]
pub async fn catbird_mls_leave_conversation(conversation_id: String) -> Result<(), JsValue> {
    let (resolved_convo_id, _group_id) = resolve_conversation_identity(&conversation_id)?;
    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;

    let input = serde_json::json!({
        "convoId": resolved_convo_id,
    });
    let req = catbird_mls::orchestrator::canonical_transport::PreparedRequest {
        operation: catbird_mls::orchestrator::canonical_transport::CanonicalOperation::RequestLeave,
        method: "POST".to_string(),
        path: "/xrpc/blue.catbird.chat.requestLeave".to_string(),
        body: Some(serde_json::to_vec(&input).map_err(|e| js_err!("JSON error: {:?}", e))?),
    };
    let resp = api_client
        .submit_prepared_request(req)
        .await
        .map_err(|e| js_err!("leave_conversation failed: {:?}", e))?;
    if resp.status != 200 {
        return Err(js_err!(
            "leave_conversation failed with status {}: {}",
            resp.status,
            String::from_utf8_lossy(&resp.body)
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Typing indicator
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub async fn catbird_mls_send_typing(
    _conversation_id: String,
    _is_typing: bool,
) -> Result<(), JsValue> {
    Err(js_err!("Typing is temporarily unavailable: canonical signed typing transport is not wired in WASM"))
}

// ---------------------------------------------------------------------------
// Promote / Group metadata
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub async fn catbird_mls_promote_member(
    _conversation_id: String,
    _target_did: String,
) -> Result<(), JsValue> {
    Err(js_err!("promoteAdmin is a signed policy transition and is not wired in WASM"))
}

/// Read MLS group metadata (title/description/avatar) from local decrypted
/// state.
///
/// Post-cutover this reads from the locally persisted decrypted blob
/// (populated by `wasm_bootstrap_group_metadata` after every Welcome /
/// commit-merge). Returns `null` if no bootstrap has run for this group.
#[wasm_bindgen]
pub fn catbird_mls_get_group_metadata(conversation_id: String) -> Result<JsValue, JsValue> {
    let (_resolved_convo_id, group_id_hex) = resolve_conversation_identity(&conversation_id)?;
    let storage = with_state(|s| Ok(Arc::clone(&s.storage)))?;
    let text = storage
        .get_metadata_text(&group_id_hex)
        .map_err(|e| js_err!("get group metadata failed: {}", e))?;
    let avatar = storage
        .get_metadata_avatar(&group_id_hex)
        .map_err(|e| js_err!("get group avatar failed: {}", e))?;

    // A successfully resolved projection with no bootstrapped metadata is the
    // only absence case. Unknown mappings and storage failures have already
    // returned errors above and must not be collapsed into `null`.
    if text
        .as_ref()
        .is_some_and(|(title, description)| title.is_none() && description.is_none())
        && avatar.is_none()
    {
        return Ok(JsValue::NULL);
    }

    match text {
        Some((title, description)) => {
            let avatar_b64 = avatar
                .as_ref()
                .map(|(b, _ct)| base64::engine::general_purpose::STANDARD.encode(b));
            let avatar_ct = avatar.as_ref().and_then(|(_, ct)| ct.clone());
            to_js(&serde_json::json!({
                "title": title,
                "description": description,
                "avatarBytesBase64": avatar_b64,
                "avatarContentType": avatar_ct,
            }))
        }
        None => Ok(JsValue::NULL),
    }
}

/// Update MLS group metadata via the encrypted-blob path (post-cutover).
///
/// Mirrors the iOS / Android contract: stages a `GroupContextExtensions`
/// commit that bumps the `MetadataReference` in AppDataDictionary 0x8001,
/// sends it to the server with `action = "updateMetadata"`, merges locally
/// on success, then derives the post-merge metadata key from the new
/// epoch's exporter, encrypts `GroupMetadataV1` (and optionally an avatar
/// blob), and uploads via `putGroupMetadataBlob`.
///
/// Returns a JS object with `commitBytes` (base64), `ciphertext` (base64),
/// `reference` (the `MetadataReference` JSON), and `metadataVersion`.
/// The ciphertext echo is informational — uploading happens internally.
#[wasm_bindgen]
pub async fn catbird_mls_update_group_metadata(
    conversation_id: String,
    title: Option<String>,
    description: Option<String>,
    avatar_blob_locator: Option<String>,
    avatar_content_type: Option<String>,
    avatar_bytes: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    use catbird_mls::metadata;

    let (resolved_convo_id, group_id_hex) = resolve_conversation_identity(&conversation_id)?;
    let (api_client, storage, user_did) = with_state(|s| {
        let user_did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), Arc::clone(&s.storage), user_did))
    })?;

    let group_id_bytes = decode_group_coordinate(&group_id_hex)
        .ok_or_else(|| js_err!("Invalid conversation/group ID: {}", group_id_hex))?;

    // 1. Stage the GroupContextExtensions commit locally.
    let commit_bytes = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.update_group_metadata(group_id_bytes.clone())
            .map_err(|e| js_err!("update_group_metadata stage failed: {:?}", e))
    })?;

    // 2. Send commit to server (action = "updateMetadata").
    let (success, new_epoch) = match api_client
        .commit_update_metadata(&resolved_convo_id, &commit_bytes)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            // Server rejected — clear pending so the group isn't stuck.
            let _ = with_state(|s| {
                if let Some(ctx) = s.mls_context.as_ref() {
                    let _ = ctx.clear_pending_commit(group_id_bytes.clone());
                }
                Ok(())
            });
            return Err(js_err!(
                "commit_update_metadata server call failed: {:?}",
                e
            ));
        }
    };
    if !success {
        let _ = with_state(|s| {
            if let Some(ctx) = s.mls_context.as_ref() {
                let _ = ctx.clear_pending_commit(group_id_bytes.clone());
            }
            Ok(())
        });
        return Err(js_err!("Server rejected updateMetadata commit"));
    }

    // 3. Merge pending commit locally (epoch advances).
    let local_epoch = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.merge_pending_commit(group_id_bytes.clone())
            .map_err(|e| js_err!("merge_pending_commit failed: {:?}", e))
    })?;

    // 4. Cache server epoch.
    if new_epoch > 0 {
        SERVER_EPOCHS.with(|m| m.borrow_mut().insert(resolved_convo_id.clone(), new_epoch));
    }

    // 5. Read post-merge MetadataReference + derive metadata key from new
    //    epoch's exporter secret.
    let (metadata_key_vec, epoch_used, reference) = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.current_metadata_info(group_id_bytes.clone())
            .map_err(|e| js_err!("current_metadata_info failed: {:?}", e))?
            .ok_or_else(|| js_err!("MetadataReference missing after metadata commit merge"))
    })?;
    let reference = reference
        .ok_or_else(|| js_err!("MetadataReference missing in AppDataDictionary post-merge"))?;
    let metadata_version = reference.metadata_version;
    let blob_locator = reference.blob_locator.clone();

    let mut metadata_key = [0u8; 32];
    if metadata_key_vec.len() != 32 {
        return Err(js_err!(
            "Derived metadata key has wrong length: {} (expected 32)",
            metadata_key_vec.len()
        ));
    }
    metadata_key.copy_from_slice(&metadata_key_vec);

    // 6. Build GroupMetadataV1 payload + encrypt.
    let payload = metadata::GroupMetadataV1 {
        version: 1,
        title: title.clone().unwrap_or_default(),
        description: description.clone().unwrap_or_default(),
        avatar_blob_locator: avatar_blob_locator.clone(),
        avatar_content_type: avatar_content_type.clone(),
    };

    let ciphertext = metadata::encrypt_metadata_blob(
        &metadata_key,
        &group_id_bytes,
        epoch_used,
        metadata_version,
        &payload,
    )
    .map_err(|e| js_err!("encrypt_metadata_blob failed: {:?}", e))?;

    // 7. Upload metadata blob.
    let (_confirmed_locator, _size) = api_client
        .put_group_metadata_blob(
            &blob_locator,
            &group_id_hex,
            &ciphertext,
            Some(metadata_version),
            None,
        )
        .await
        .map_err(|e| {
            // Non-fatal: commit already merged. Surface as error so JS knows
            // the title/description are temporarily unavailable to peers,
            // but the group is otherwise healthy. Mirrors iOS warning path.
            js_err!("put_group_metadata_blob failed: {:?}", e)
        })?;

    // 8. Optional avatar encrypt + upload.
    if let (Some(av_locator), Some(av_bytes)) =
        (avatar_blob_locator.as_deref(), avatar_bytes.as_deref())
    {
        let av_ct = metadata::encrypt_avatar_blob(
            &metadata_key,
            &group_id_bytes,
            epoch_used,
            metadata_version,
            av_bytes,
        )
        .map_err(|e| js_err!("encrypt_avatar_blob failed: {:?}", e))?;
        let _ = api_client
            .put_group_metadata_blob(
                av_locator,
                &group_id_hex,
                &av_ct,
                Some(metadata_version),
                Some("avatar"),
            )
            .await
            .map_err(|e| js_err!("put_group_metadata_blob (avatar) failed: {:?}", e))?;
    }

    // 9. Persist the decrypted state locally so the conversation list /
    //    header render the new title/description without a re-fetch.
    storage
        .upsert_metadata(
            &group_id_hex,
            Some(&payload.title),
            Some(&payload.description),
            metadata_version as i64,
            avatar_blob_locator.as_deref(),
            avatar_content_type.as_deref(),
            avatar_bytes.as_deref(),
        )
        .map_err(|e| js_err!("persist group metadata failed: {}", e))?;

    // 10. Echo result back to JS.
    let reference_json = serde_json::to_value(&reference)
        .map_err(|e| js_err!("serialize MetadataReference: {}", e))?;
    let _ = local_epoch; // currently unused beyond the merge guarantee
    to_js(&serde_json::json!({
        "commitBytes": base64::engine::general_purpose::STANDARD.encode(&commit_bytes),
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        "reference": reference_json,
        "metadataVersion": metadata_version,
        "epoch": epoch_used,
    }))
}

/// Bootstrap (decrypt and persist locally) the current group metadata after
/// a Welcome / external join / commit-merge that touched metadata.
///
/// Reads the `MetadataReference` from AppDataDictionary, derives the
/// metadata key from the current epoch's exporter, fetches the encrypted
/// blob via `getGroupMetadataBlob`, decrypts it, persists title /
/// description / avatar locator to local storage, and returns
/// `{title, description, avatarBlobLocator, metadataVersion}` to JS for
/// immediate UI updates. Also fetches+decrypts the avatar blob if a
/// locator is present and persists the raw bytes.
///
/// Returns `null` if the group has no `MetadataReference` yet (e.g. just
/// after a fresh group creation that hasn't run an `updateMetadata` commit).
#[wasm_bindgen]
pub async fn wasm_bootstrap_group_metadata(group_id_hex: String) -> Result<JsValue, JsValue> {
    use catbird_mls::metadata;

    let (api_client, storage, user_did) = with_state(|s| {
        let user_did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), Arc::clone(&s.storage), user_did))
    })?;

    let group_id_bytes = decode_group_coordinate(&group_id_hex)
        .ok_or_else(|| js_err!("Invalid group_id_hex: {}", group_id_hex))?;
    let group_id_hex_norm = hex::encode(&group_id_bytes);

    let info = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.current_metadata_info(group_id_bytes.clone())
            .map_err(|e| js_err!("current_metadata_info failed: {:?}", e))
    })?;

    let (metadata_key_vec, epoch, reference) = match info {
        Some(t) => t,
        None => return Ok(JsValue::NULL),
    };
    let reference = match reference {
        Some(r) => r,
        None => return Ok(JsValue::NULL),
    };
    let metadata_version = reference.metadata_version;

    let mut metadata_key = [0u8; 32];
    if metadata_key_vec.len() != 32 {
        return Err(js_err!(
            "Derived metadata key has wrong length: {} (expected 32)",
            metadata_key_vec.len()
        ));
    }
    metadata_key.copy_from_slice(&metadata_key_vec);

    // Fetch encrypted blob from server.
    let ciphertext = api_client
        .get_group_metadata_blob(
            &reference.blob_locator,
            &group_id_hex_norm,
            Some(metadata_version),
            None,
        )
        .await
        .map_err(|e| js_err!("get_group_metadata_blob failed: {:?}", e))?;

    // Decrypt.
    let payload = metadata::decrypt_metadata_blob(
        &metadata_key,
        &group_id_bytes,
        epoch,
        metadata_version,
        &ciphertext,
    )
    .map_err(|e| js_err!("decrypt_metadata_blob failed: {:?}", e))?;

    // Optionally fetch + decrypt avatar.
    let mut avatar_bytes: Option<Vec<u8>> = None;
    if let Some(ref av_locator) = payload.avatar_blob_locator {
        if !av_locator.is_empty() {
            match api_client
                .get_group_metadata_blob(
                    av_locator,
                    &group_id_hex_norm,
                    Some(metadata_version),
                    Some("avatar"),
                )
                .await
            {
                Ok(av_ct) => match metadata::decrypt_avatar_blob(
                    &metadata_key,
                    &group_id_bytes,
                    epoch,
                    metadata_version,
                    &av_ct,
                ) {
                    Ok(av_bytes) => avatar_bytes = Some(av_bytes),
                    Err(e) => {
                        web_sys::console::warn_1(&JsValue::from_str(&format!(
                            "[bootstrap] avatar decrypt failed: {:?}",
                            e
                        )));
                    }
                },
                Err(e) => {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "[bootstrap] avatar fetch failed: {:?}",
                        e
                    )));
                }
            }
        }
    }

    // Persist locally.
    storage
        .upsert_metadata(
            &group_id_hex_norm,
            Some(&payload.title),
            Some(&payload.description),
            metadata_version as i64,
            payload.avatar_blob_locator.as_deref(),
            payload.avatar_content_type.as_deref(),
            avatar_bytes.as_deref(),
        )
        .map_err(|e| js_err!("persist group metadata failed: {}", e))?;

    // Build JS object.
    let avatar_b64 = avatar_bytes
        .as_ref()
        .map(|b| base64::engine::general_purpose::STANDARD.encode(b));
    to_js(&serde_json::json!({
        "title": payload.title,
        "description": payload.description,
        "avatarBlobLocator": payload.avatar_blob_locator,
        "avatarContentType": payload.avatar_content_type,
        "avatarBytesBase64": avatar_b64,
        "metadataVersion": metadata_version,
        "epoch": epoch,
    }))
}

/// Re-publish encrypted metadata after a group reset (`bootstrap_reset_group`
/// or first-responder reset). The new MLS group has a fresh epoch, so we
/// must derive a new metadata key, re-encrypt the existing title /
/// description / avatar payload (read from local storage) under that key,
/// and upload the blobs to the server's reset_generation slot.
///
/// Caller must already have:
/// - Joined / created the post-reset group.
/// - Persisted the desired title / description / avatar to local storage
///   via a prior bootstrap or update.
///
/// `reset_generation` is currently informational — the server's
/// `putGroupMetadataBlob` accepts it as an optional query param.
#[wasm_bindgen]
pub async fn wasm_republish_metadata_after_reset(
    new_group_id_hex: String,
    reset_generation: Option<u64>,
) -> Result<JsValue, JsValue> {
    use catbird_mls::metadata;

    let (api_client, storage, user_did) = with_state(|s| {
        let user_did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), Arc::clone(&s.storage), user_did))
    })?;

    let group_id_bytes = decode_group_coordinate(&new_group_id_hex)
        .ok_or_else(|| js_err!("Invalid new_group_id_hex: {}", new_group_id_hex))?;
    let group_id_hex_norm = hex::encode(&group_id_bytes);

    // 1. Resolve the target through the durable stable/alias map, then read
    // metadata from the stable projection. Reset keeps historical group rows
    // for crypto/AAD but metadata belongs to the stable application row.
    let stable_conversation_id = storage
        .resolve_conversation_mapping(&user_did, &group_id_hex_norm)
        .map_err(|e| js_err!("metadata identity lookup failed: {}", e))?
        .map(|(conversation_id, _)| conversation_id)
        .ok_or_else(|| js_err!("metadata group {} has no stable mapping", group_id_hex_norm))?;
    let (title_opt, desc_opt, avatar, _stored_metadata_version) = storage
        .get_metadata_for_conversation(&user_did, &stable_conversation_id)
        .map_err(|e| js_err!("get stable metadata: {}", e))?;

    let title = title_opt.unwrap_or_default();
    let description = desc_opt.unwrap_or_default();

    if title.is_empty() && description.is_empty() && avatar.is_none() {
        // Nothing to republish — no-op for first-time creators.
        return Ok(JsValue::NULL);
    }

    // 2. Stage an updateMetadata commit on the new group so we have a fresh
    //    MetadataReference (locator + version=1) to upload against.
    let commit_bytes = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.update_group_metadata(group_id_bytes.clone())
            .map_err(|e| js_err!("update_group_metadata stage failed: {:?}", e))
    })?;

    let (success, new_epoch) = api_client
        .commit_update_metadata(&stable_conversation_id, &commit_bytes)
        .await
        .map_err(|e| {
            let _ = with_state(|s| {
                if let Some(ctx) = s.mls_context.as_ref() {
                    let _ = ctx.clear_pending_commit(group_id_bytes.clone());
                }
                Ok(())
            });
            js_err!("commit_update_metadata (reset republish) failed: {:?}", e)
        })?;
    if !success {
        let _ = with_state(|s| {
            if let Some(ctx) = s.mls_context.as_ref() {
                let _ = ctx.clear_pending_commit(group_id_bytes.clone());
            }
            Ok(())
        });
        return Err(js_err!("Server rejected reset-republish updateMetadata"));
    }

    let _ = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.merge_pending_commit(group_id_bytes.clone())
            .map_err(|e| js_err!("merge_pending_commit failed: {:?}", e))
    })?;
    let _ = new_epoch;

    // 3. Read post-merge MetadataReference + derive new metadata key.
    let (metadata_key_vec, epoch_used, reference) = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.current_metadata_info(group_id_bytes.clone())
            .map_err(|e| js_err!("current_metadata_info failed: {:?}", e))?
            .ok_or_else(|| js_err!("MetadataReference missing after reset-republish merge"))
    })?;
    let reference = reference
        .ok_or_else(|| js_err!("MetadataReference missing in AppDataDictionary post-merge"))?;
    let metadata_version = reference.metadata_version;
    let mut metadata_key = [0u8; 32];
    if metadata_key_vec.len() != 32 {
        return Err(js_err!("metadata key wrong length"));
    }
    metadata_key.copy_from_slice(&metadata_key_vec);

    let avatar_bytes = avatar.as_ref().map(|(b, _ct)| b.clone());
    let avatar_content_type = avatar.as_ref().and_then(|(_, ct)| ct.clone());
    let avatar_blob_locator = if avatar_bytes.is_some() {
        Some(uuid::Uuid::new_v4().to_string().to_lowercase())
    } else {
        None
    };

    let payload = metadata::GroupMetadataV1 {
        version: 1,
        title: title.clone(),
        description: description.clone(),
        avatar_blob_locator: avatar_blob_locator.clone(),
        avatar_content_type: avatar_content_type.clone(),
    };

    // 4. Encrypt + upload metadata blob (under fresh epoch's key).
    let metadata_ct = metadata::encrypt_metadata_blob(
        &metadata_key,
        &group_id_bytes,
        epoch_used,
        metadata_version,
        &payload,
    )
    .map_err(|e| js_err!("encrypt_metadata_blob (reset): {:?}", e))?;
    let _ = api_client
        .put_group_metadata_blob(
            &reference.blob_locator,
            &group_id_hex_norm,
            &metadata_ct,
            Some(metadata_version),
            None,
        )
        .await
        .map_err(|e| js_err!("put_group_metadata_blob (reset metadata): {:?}", e))?;

    // 5. Re-encrypt + upload avatar blob if we have one.
    if let (Some(av_bytes), Some(av_locator)) =
        (avatar_bytes.as_deref(), avatar_blob_locator.as_deref())
    {
        let av_ct = metadata::encrypt_avatar_blob(
            &metadata_key,
            &group_id_bytes,
            epoch_used,
            metadata_version,
            av_bytes,
        )
        .map_err(|e| js_err!("encrypt_avatar_blob (reset): {:?}", e))?;
        let _ = api_client
            .put_group_metadata_blob(
                av_locator,
                &group_id_hex_norm,
                &av_ct,
                Some(metadata_version),
                Some("avatar"),
            )
            .await
            .map_err(|e| js_err!("put_group_metadata_blob (reset avatar): {:?}", e))?;
    }

    // 6. Persist the (possibly-new-locator) avatar metadata so subsequent
    //    bootstraps round-trip cleanly.
    storage
        .upsert_metadata(
            &group_id_hex_norm,
            Some(&title),
            Some(&description),
            metadata_version as i64,
            avatar_blob_locator.as_deref(),
            avatar_content_type.as_deref(),
            avatar_bytes.as_deref(),
        )
        .map_err(|e| js_err!("persist reset metadata failed: {}", e))?;

    let _ = reset_generation;
    to_js(&serde_json::json!({
        "title": title,
        "description": description,
        "avatarBlobLocator": avatar_blob_locator,
        "metadataVersion": metadata_version,
        "epoch": epoch_used,
    }))
}

// ---------------------------------------------------------------------------
// Profile commands
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub async fn catbird_mls_get_profiles(dids: Array) -> Result<JsValue, JsValue> {
    let dids = array_to_strings(&dids);
    if dids.is_empty() {
        return to_js(&Vec::<ProfileView>::new());
    }
    if dids.len() > MAX_CONVERSATION_ITEMS {
        return Err(js_err!("profile request exceeded the item ceiling"));
    }

    let auth_token = with_state(|s| {
        s.auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))
    })?;

    let client = reqwest::Client::new();
    let mut profiles = Vec::with_capacity(dids.len());
    // app.bsky.actor.getProfiles has a hard 25-actor request limit. Chunking
    // here also gives callers a deterministic item ceiling per HTTP request.
    for chunk in dids.chunks(25) {
        let mut url =
            reqwest::Url::parse("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfiles")
                .map_err(|e| js_err!("URL parse error: {}", e))?;
        for did in chunk {
            url.query_pairs_mut().append_pair("actors", did);
        }

        let resp = client
            .get(url)
            .bearer_auth(&auth_token)
            .send()
            .await
            .map_err(|e| js_err!("Profile fetch failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(js_err!("Profile fetch failed: {}", resp.status()));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| js_err!("Profile parse failed: {}", e))?;

        if let Some(arr) = data["profiles"].as_array() {
            if arr.len() > 25 {
                return Err(js_err!(
                    "Profile response exceeded the 25-item page ceiling"
                ));
            }
            if profiles.len().saturating_add(arr.len()) > MAX_CONVERSATION_ITEMS {
                return Err(js_err!("profile results exceeded the item ceiling"));
            }
            profiles.extend(arr.iter().map(|p| ProfileView {
                did: p["did"].as_str().unwrap_or("").to_string(),
                handle: p["handle"].as_str().unwrap_or("").to_string(),
                display_name: p["displayName"].as_str().map(str::to_string),
                avatar: p["avatar"].as_str().map(str::to_string),
            }));
        }
    }

    to_js(&profiles)
}

#[wasm_bindgen]
pub async fn catbird_mls_search_users(query: String) -> Result<JsValue, JsValue> {
    if query.trim().is_empty() {
        return to_js(&Vec::<SearchResult>::new());
    }

    let auth_token = with_state(|s| {
        s.auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))
    })?;

    let client = reqwest::Client::new();
    let url = reqwest::Url::parse_with_params(
        "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActorsTypeahead",
        &[("q", query.as_str()), ("limit", "10")],
    )
    .map_err(|e| js_err!("URL parse error: {}", e))?;

    let resp = client
        .get(url)
        .bearer_auth(&auth_token)
        .send()
        .await
        .map_err(|e| js_err!("Search failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(js_err!("Search failed: {}", resp.status()));
    }

    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| js_err!("Search parse failed: {}", e))?;

    let results: Vec<SearchResult> = data["actors"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|a| SearchResult {
                    did: a["did"].as_str().unwrap_or("").to_string(),
                    handle: a["handle"].as_str().unwrap_or("").to_string(),
                    display_name: a["displayName"].as_str().map(str::to_string),
                    avatar: a["avatar"].as_str().map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default();

    to_js(&results)
}

#[wasm_bindgen]
pub async fn catbird_mls_check_opt_in_status(dids: Array) -> Result<JsValue, JsValue> {
    let dids = array_to_strings(&dids);
    if dids.is_empty() {
        return to_js(&Vec::<OptInStatusResult>::new());
    }

    let (base_url, auth_token, proxy_did) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token, s.proxy_did.clone()))
    })?;

    let dids_param = dids.join(",");
    let url = format!(
        "{}/xrpc/blue.catbird.chat.getDevices?dids={}",
        base_url, dids_param
    );

    let client = proxy_client(&proxy_did);
    let resp = client
        .get(&url)
        .bearer_auth(&auth_token)
        .send()
        .await
        .map_err(|e| js_err!("check_opt_in_status failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("check_opt_in_status failed ({}): {}", status, body));
    }

    let output: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| js_err!("check_opt_in_status parse failed: {}", e))?;

    let statuses: Vec<OptInStatusResult> = output["statuses"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|s| OptInStatusResult {
                    did: s["did"].as_str().unwrap_or("").to_string(),
                    opted_in: s["optedIn"].as_bool().unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default();

    to_js(&statuses)
}

// ---------------------------------------------------------------------------
// Deferred recovery — first-responder bootstrap for ResetPending convos
// ---------------------------------------------------------------------------

/// Drive the deferred-recovery state machine for any conversation in
/// `ResetPending` (spec §8.5 Phase 1, plan task #24).
///
/// Browser apps should call this on a periodic timer (e.g. every 30s) and on
/// `visibilitychange="visible"`. It:
///
/// 1. Iterates conversations with `state == ResetPending`.
/// 2. For each, attempts the Welcome → External Commit ladder
///    (`try_join_group_internal`) — if either succeeds, clears `reset_pending`.
/// 3. If both fail, runs the first-responder bootstrap: fetches the roster via
///    `getConvos`, builds a local MLS group at the predetermined `newGroupId`
///    via `WasmMLSContext::create_group_with_id`, and submits via
///    `createConvo` with an `Idempotency-Key` header
///    (`<convoId>:<resetGeneration>:<callerDid>:bootstrap`, per Phase 0 Q4).
/// 4. On 409 `ConvoAlreadyExists` (race-loss): deletes the local
///    pre-bootstrap group and leaves `reset_pending` set so the next loop
///    picks up the winner's Welcome. Other server errors: same.
///
/// Returns the count of conversations the loop touched.
///
/// Shares the re-entrancy guard with the background-tasks timer: if a
/// deferred-recovery pass is already in flight (a timer tick or another
/// manual call), this returns `{ touched: 0, alreadyRunning: true }` instead
/// of running a second pass concurrently — concurrent passes can clobber
/// each other's bootstrap state. Each pass also runs under a deadline
/// (`MANUAL_PASS_DEADLINE_MS` here; 2× `interval_ms` for timer ticks) — on
/// timeout the pass is cancelled and `{ touched: 0, timedOut: true }` is
/// returned.
//
// TODO(architecture): WASM bootstrap is currently inline-mirrored from
// `catbird-mls/src/orchestrator/recovery.rs::try_first_responder_bootstrap`.
// Long-term, WASM should migrate to driving `MLSOrchestrator` directly so
// the ladder lives in one place across all platforms (Phase 4+ backlog).
//
// TODO(test-gap): bootstrap ladder itself has no unit coverage —
// `catbird-mls-web` is `cdylib`-only and uses sqlite-wasm-rs OPFS VFS that
// doesn't run on host. Verified by inspection against
// `try_first_responder_bootstrap` (recovery.rs:1593) and the catmos /
// catmos-cli inheritor implementations. (Guard/deadline plumbing IS covered
// by `background_tasks_tests`.)
#[wasm_bindgen]
pub async fn catbird_mls_run_deferred_recovery() -> Result<JsValue, JsValue> {
    run_deferred_recovery_guarded(MANUAL_PASS_DEADLINE_MS).await
}

/// Un-guarded single deferred-recovery pass — the body of
/// `catbird_mls_run_deferred_recovery`. Callers MUST go through
/// `run_deferred_recovery_guarded`; calling this directly bypasses the
/// re-entrancy guard and can run concurrently with a timer tick.
async fn run_deferred_recovery_inner() -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::storage::MLSStorageBackend;
    use catbird_mls::orchestrator::types::ConversationState;

    let (api_client, storage, user_did, base_url, auth_token, proxy_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((
            Arc::clone(&s.api_client),
            Arc::clone(&s.storage),
            did,
            s.base_url.clone(),
            token,
            s.proxy_did.clone(),
        ))
    })?;

    // 1. Find ResetPending convos.
    let convos = storage
        .list_conversations(&user_did)
        .await
        .map_err(|e| js_err!("list_conversations failed: {:?}", e))?;

    let mut pending: Vec<(String, String, i32)> = Vec::new();
    for c in &convos {
        if let Ok(Some(ConversationState::ResetPending {
            new_group_id,
            reset_generation,
            ..
        })) = storage.get_conversation_state(&c.conversation_id).await
        {
            pending.push((c.conversation_id.clone(), new_group_id, reset_generation));
        }
    }

    if pending.is_empty() {
        return to_js(&serde_json::json!({ "touched": 0 }));
    }

    let mut touched: usize = 0;
    for (convo_id, new_group_id_hex, reset_generation) in pending {
        touched += 1;

        // 2. Try Welcome → External Commit ladder.
        if try_join_group_internal(&convo_id).await.is_ok() {
            web_sys::console::log_1(&js_err!(
                "[deferred-recovery] {}: atomically completed via Welcome/ExternalCommit",
                convo_id
            ));
            continue;
        }

        // 3. First-responder bootstrap fallback.
        let new_group_id_bytes = match decode_group_coordinate(&new_group_id_hex) {
            Some(bytes) => bytes,
            None => {
                web_sys::console::warn_1(&js_err!(
                    "[deferred-recovery] {}: ResetPending.new_group_id is not an exact 16-byte coordinate ({})",
                    convo_id,
                    new_group_id_hex
                ));
                continue;
            }
        };

        // 3a. Fetch fresh roster (server clears membership atomically with
        // reset; cached `group_states.members` is the pre-reset roster).
        let roster = match fetch_roster_for_convo(&api_client, &convo_id).await {
            Ok(r) => r,
            Err(e) => {
                web_sys::console::warn_1(&js_err!(
                    "[deferred-recovery] {}: fetch_roster failed: {}",
                    convo_id,
                    e
                ));
                continue;
            }
        };
        if roster.is_empty() {
            web_sys::console::warn_1(&js_err!(
                "[deferred-recovery] {}: roster empty — cannot bootstrap",
                convo_id
            ));
            continue;
        }

        // 3b. Build the local group at the predetermined id.
        storage
            .mark_cleanup_intent(
                &user_did,
                &convo_id,
                &new_group_id_hex,
                "reset-bootstrap-speculative",
            )
            .map_err(|e| js_err!("{} reset cleanup intent failed: {}", convo_id, e))?;
        let identity_bytes = user_did.as_bytes().to_vec();
        let creation = with_state(|s| {
            let ctx = s
                .mls_context
                .as_ref()
                .ok_or_else(|| js_err!("MLS context not initialized"))?;
            ctx.create_group_with_id(identity_bytes.clone(), new_group_id_bytes.clone(), None)
                .map_err(|e| js_err!("create_group_with_id failed: {:?}", e))
        });
        if let Err(e) = creation {
            web_sys::console::warn_1(&e);
            continue;
        }

        // 3c. Export GroupInfo from the freshly-created group — required
        // by `bootstrapResetGroup` (lexicon `groupInfo` field).
        let group_info_bytes = with_state(|s| {
            let ctx = s
                .mls_context
                .as_ref()
                .ok_or_else(|| js_err!("MLS context not initialized"))?;
            ctx.export_group_info(new_group_id_bytes.clone(), identity_bytes.clone())
                .map_err(|e| js_err!("export_group_info failed: {:?}", e))
        });
        let group_info_bytes = match group_info_bytes {
            Ok(b) => b,
            Err(e) => {
                web_sys::console::warn_1(&e);
                let _ = with_state(|s| {
                    if let Some(ctx) = s.mls_context.as_ref() {
                        let _ = ctx.delete_group(new_group_id_bytes.clone());
                    }
                    Ok(())
                });
                continue;
            }
        };

        // 3d. Submit via `bootstrapResetGroup` (server task #17 / spec §8.5).
        // Server UPDATEs the post-reset row in place
        // (id=originalConvoId, group_id=newGroupId) rather than INSERTing a
        // new conversation — earlier fix-forward target was `createConvo`,
        // but that orphaned the post-reset row (id mismatch). Members
        // roster is preserved server-side; the lexicon `members` field is
        // diagnostic-only but required. Idempotency-Key kept for
        // client-side dedup of network retries.
        let idem_key = format!("{}:{}:{}:bootstrap", convo_id, reset_generation, user_did);
        let body = serde_json::json!({
            "originalConvoId": &convo_id,
            "newGroupId": &new_group_id_hex,
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "groupInfo": &group_info_bytes,
            "members": roster.iter().map(|member| member.did.clone()).collect::<Vec<_>>(),
            "currentEpoch": 1,
        });
        let url = format!(
            "{}/xrpc/blue.catbird.chat.requestReset",
            base_url.trim_end_matches('/')
        );
        let client = proxy_client(&proxy_did);
        let resp = match client
            .post(&url)
            .bearer_auth(&auth_token)
            .header("Idempotency-Key", &idem_key)
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                web_sys::console::warn_1(&js_err!(
                    "[deferred-recovery] {}: bootstrapResetGroup network err: {} — dropping local pre-bootstrap group, keeping reset_pending",
                    convo_id,
                    e
                ));
                let _ = with_state(|s| {
                    if let Some(ctx) = s.mls_context.as_ref() {
                        let _ = ctx.delete_group(new_group_id_bytes.clone());
                    }
                    Ok(())
                });
                continue;
            }
        };

        let status = resp.status().as_u16();
        if resp.status().is_success() {
            // 3e. Race winner — commit the stable mapping, historical alias,
            // group state, roster, and reset-authority clear as one exact
            // generation-fenced transaction. Recovery remains pending when
            // any part of that commit fails.
            let local_epoch = with_state(|s| {
                Ok(s.mls_context
                    .as_ref()
                    .and_then(|ctx| ctx.get_epoch(new_group_id_bytes.clone()).ok())
                    .unwrap_or(0))
            })
            .unwrap_or(0);
            let expected_state_version = match storage
                .conversation_state_version(&user_did, &convo_id)
            {
                Ok(version) => version,
                Err(e) => {
                    web_sys::console::warn_1(&js_err!(
                        "[deferred-recovery] {}: reset state-version lookup failed: {} — keeping reset_pending",
                        convo_id,
                        e
                    ));
                    continue;
                }
            };
            let committed = storage.complete_reset_pending_projection(
                &user_did,
                &convo_id,
                reset_generation,
                expected_state_version,
                &new_group_id_hex,
                local_epoch,
                &roster,
            );
            match committed {
                Ok(true) => {
                    storage
                        .clear_cleanup_intent(&user_did, &new_group_id_hex)
                        .map_err(|e| {
                            js_err!(
                                "{} reset cleanup intent clear failed after commit: {}",
                                convo_id,
                                e
                            )
                        })?;
                }
                Ok(false) => {
                    web_sys::console::warn_1(&js_err!(
                        "[deferred-recovery] {}: reset winner lost generation/target CAS; keeping reset_pending",
                        convo_id
                    ));
                    continue;
                }
                Err(e) => {
                    web_sys::console::warn_1(&js_err!(
                        "[deferred-recovery] {}: atomic reset projection failed: {} — keeping reset_pending",
                        convo_id, e
                    ));
                    continue;
                }
            }
            SERVER_EPOCHS.with(|m| m.borrow_mut().insert(convo_id.clone(), local_epoch));
            web_sys::console::log_1(&js_err!(
                "[deferred-recovery] {}: bootstrap WON at epoch {} (gen {})",
                convo_id,
                local_epoch,
                reset_generation
            ));
            continue;
        }

        let body_text = resp.text().await.unwrap_or_default();
        let race_loss = status == 409 && body_text.contains("AlreadyBootstrapped");

        // 3f. On 409 race-loss OR other server error: drop the local
        // pre-bootstrap group; leave reset_pending set so the next loop
        // retries Welcome.
        let _ = with_state(|s| {
            if let Some(ctx) = s.mls_context.as_ref() {
                let _ = ctx.delete_group(new_group_id_bytes.clone());
            }
            Ok(())
        });

        if race_loss {
            web_sys::console::log_1(&js_err!(
                "[deferred-recovery] {}: bootstrap LOST race (409 AlreadyBootstrapped, gen {}) — will retry Welcome",
                convo_id,
                reset_generation
            ));
        } else {
            web_sys::console::warn_1(&js_err!(
                "[deferred-recovery] {}: bootstrapResetGroup {} -> {} — keeping reset_pending, will retry",
                convo_id,
                status,
                body_text
            ));
        }
    }

    to_js(&serde_json::json!({ "touched": touched }))
}

/// Page through `getConvos` to find the membership roster for one
/// conversation. Mirrors `MLSOrchestrator::fetch_roster_for_convo`
/// (`catbird-mls/src/orchestrator/recovery.rs:1726`). Phase 0 Q3 confirms the
/// `groupResetEvent` does NOT carry a roster, and the local
/// `group_states.members` cache is the pre-reset roster (server clears
/// membership atomically with reset).
async fn fetch_roster_for_convo(
    api_client: &Arc<WasmApiClient>,
    convo_id: &str,
) -> std::result::Result<Vec<catbird_mls::orchestrator::types::MemberView>, String> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = std::collections::HashSet::new();
    let mut page_count = 0usize;
    let mut item_count = 0usize;
    loop {
        page_count = page_count.saturating_add(1);
        if page_count > MAX_CONVERSATION_PAGES {
            return Err(format!(
                "server conversation pagination exceeded page ceiling for {convo_id}"
            ));
        }
        let page = api_client
            .get_conversations(50, cursor.as_deref())
            .await
            .map_err(|e| format!("get_conversations failed: {:?}", e))?;
        if page.conversations.len() > 50 {
            return Err(format!(
                "server conversation page exceeded item ceiling for {convo_id}"
            ));
        }
        item_count = item_count.saturating_add(page.conversations.len());
        if item_count > MAX_CONVERSATION_ITEMS {
            return Err(format!(
                "server conversation pagination exceeded item ceiling for {convo_id}"
            ));
        }
        for cv in &page.conversations {
            if cv.conversation_id == convo_id {
                return Ok(cv.members.clone());
            }
        }
        let Some(next) = page.cursor else {
            return Err(format!(
                "server did not return convo {convo_id} in pagination"
            ));
        };
        if !seen_cursors.insert(next.clone()) {
            return Err(format!(
                "server conversation pagination repeated cursor for {convo_id}"
            ));
        }
        cursor = Some(next);
    }
}

// ---------------------------------------------------------------------------
// Background tasks — crate-owned deferred-recovery timer (WS-5.5)
//
// Before this existed, hosts had to wire their own `setInterval` around
// `catbird_mls_run_deferred_recovery()` (a documented MUST that the primary
// consumer never implemented). `catbird_mls_start_background_tasks()` moves
// the timer into the crate so the host calls one function after setup.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// Bound to the *global* scope (`globalThis.setInterval`), not
    /// `web_sys::Window` — this crate must run inside a Web Worker (see module
    /// docs), where `web_sys::window()` is `None`. Plain extern bindings work
    /// in both Window and Worker contexts.
    #[wasm_bindgen(js_name = setInterval)]
    fn js_set_interval(handler: &Closure<dyn FnMut()>, timeout_ms: f64) -> f64;

    #[wasm_bindgen(js_name = clearInterval)]
    fn js_clear_interval(handle: f64);

    /// Global `setTimeout`, same Window + Worker rationale as `setInterval`
    /// above. Takes a plain `js_sys::Function` so a `Promise` constructor's
    /// `resolve` can be passed directly (see `sleep_ms`).
    #[wasm_bindgen(js_name = setTimeout)]
    fn js_set_timeout(handler: &js_sys::Function, timeout_ms: f64) -> f64;
}

/// Promise-based sleep via the global `setTimeout` (Window + Worker safe).
/// If the returned future is dropped before the deadline, the underlying JS
/// timer still fires once and resolves an orphaned promise — harmless.
async fn sleep_ms(ms: f64) {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let _ = js_set_timeout(&resolve, ms);
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// Race `fut` against a `setTimeout`-backed deadline. Returns `None` if the
/// deadline fires first; the losing `fut` is **dropped** (cancelled), so its
/// destructors — including `TickInFlightReset` — run. Needed because
/// reqwest-on-wasm has no default request timeout: a stalled fetch would
/// otherwise hold a deferred-recovery pass open forever.
async fn race_with_timeout<F: std::future::Future>(fut: F, deadline_ms: f64) -> Option<F::Output> {
    use std::future::Future as _;
    use std::task::Poll;
    let mut fut = Box::pin(fut);
    let mut deadline = Box::pin(sleep_ms(deadline_ms));
    std::future::poll_fn(move |cx| {
        if let Poll::Ready(out) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(out));
        }
        if deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

/// Live background-task state. Dropping this without calling
/// `clearInterval` would leak the JS interval (it would keep firing into a
/// freed closure), so teardown always goes through
/// `catbird_mls_stop_background_tasks()`.
struct BackgroundTasks {
    interval_handle: f64,
    /// Keeps the JS callback allocation alive for the lifetime of the
    /// interval (same pattern as `WsSubscription`'s handler closures).
    _tick_closure: Closure<dyn FnMut()>,
}

thread_local! {
    static BACKGROUND_TASKS: RefCell<Option<BackgroundTasks>> = const { RefCell::new(None) };
    /// Re-entrancy guard shared by EVERY deferred-recovery entry point —
    /// timer ticks AND the manual `catbird_mls_run_deferred_recovery()`
    /// export. While a pass is in flight, any other entry skips (slow
    /// network); the next interval fire picks the work back up. Set/reset
    /// only via `run_deferred_recovery_guarded` + `TickInFlightReset`.
    static BACKGROUND_TICK_IN_FLIGHT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// RAII reset for `BACKGROUND_TICK_IN_FLIGHT`. Constructed by
/// `run_deferred_recovery_guarded` immediately after it sets the flag, so the
/// flag is cleared on every exit path — normal completion, `?`/early return,
/// and (the load-bearing case) the pass future being dropped when
/// `race_with_timeout` cancels it at the deadline. Without this, one wedged
/// pass would permanently skip every subsequent tick while
/// `catbird_mls_background_tasks_running()` still reported `true`.
struct TickInFlightReset;

impl Drop for TickInFlightReset {
    fn drop(&mut self) {
        BACKGROUND_TICK_IN_FLIGHT.with(|f| f.set(false));
    }
}

/// Per-pass deadline for the manual `catbird_mls_run_deferred_recovery()`
/// export: 2× the recommended 30s timer interval, matching the 2×
/// `interval_ms` deadline timer ticks get.
const MANUAL_PASS_DEADLINE_MS: f64 = 60_000.0;

/// The single guarded entry for a deferred-recovery pass. Both the timer
/// tick and the manual export route through here, so they share one
/// re-entrancy guard — a manual call (e.g. on `visibilitychange`) can never
/// run a pass concurrently with a timer tick.
///
/// - If a pass is already in flight: returns a benign
///   `{ touched: 0, alreadyRunning: true }` without touching the flag (the
///   in-flight pass owns it).
/// - Otherwise: sets the flag, arms the RAII reset, and races the pass
///   against `deadline_ms`. On timeout the pass is dropped (cancelled), a
///   warning is logged, and `{ touched: 0, timedOut: true }` is returned;
///   the RAII reset clears the flag so the loop never wedges.
async fn run_deferred_recovery_guarded(deadline_ms: f64) -> Result<JsValue, JsValue> {
    if BACKGROUND_TICK_IN_FLIGHT.with(|f| f.replace(true)) {
        web_sys::console::log_1(&js_err!(
            "[background-tasks] deferred-recovery pass already in flight — skipping"
        ));
        return to_js(&serde_json::json!({ "touched": 0, "alreadyRunning": true }));
    }
    let _reset = TickInFlightReset;

    match race_with_timeout(run_deferred_recovery_inner(), deadline_ms).await {
        Some(result) => result,
        None => {
            web_sys::console::warn_1(&js_err!(
                "[background-tasks] deferred-recovery pass exceeded {}ms deadline — cancelled, in-flight flag cleared",
                deadline_ms
            ));
            to_js(&serde_json::json!({ "touched": 0, "timedOut": true }))
        }
    }
}

/// One timer tick: run a guarded deferred-recovery pass, swallowing-and-
/// logging errors so one failed tick never kills the loop.
async fn background_tasks_tick(deadline_ms: f64) {
    if let Err(e) = run_deferred_recovery_guarded(deadline_ms).await {
        web_sys::console::warn_2(
            &js_err!("[background-tasks] deferred-recovery tick failed (loop continues):"),
            &e,
        );
    }
}

/// Start the crate-owned background task loop (currently: deferred recovery,
/// spec §8.5 Phase 1). Call once after `catbird_mls_setup()`; `interval_ms`
/// of `30_000` (30s) is the recommended cadence.
///
/// - Runs one tick immediately, then every `interval_ms`.
/// - Per-tick errors (including "not initialized" / "not authenticated") are
///   logged to the console and swallowed — the loop keeps running.
/// - Each tick runs under a 2×`interval_ms` deadline: reqwest-on-wasm has no
///   default request timeout, so a stalled fetch would otherwise wedge the
///   in-flight guard and skip every subsequent tick. On timeout the pass is
///   cancelled, a warning is logged, and the next fire runs normally.
/// - Calling again while running **replaces** the existing timer (restart
///   semantics); timers never stack.
/// - `catbird_mls_run_deferred_recovery()` stays exported for on-demand
///   ticks (e.g. on `visibilitychange === "visible"`, where background-tab
///   timer throttling delays the next interval fire). It shares this loop's
///   re-entrancy guard, so an on-demand tick never runs concurrently with a
///   timer tick.
#[wasm_bindgen]
pub fn catbird_mls_start_background_tasks(interval_ms: u32) -> Result<(), JsValue> {
    if interval_ms == 0 {
        return Err(js_err!(
            "start_background_tasks: interval_ms must be > 0 (recommended: 30000)"
        ));
    }

    // Restart semantics: replace any existing timer instead of stacking.
    catbird_mls_stop_background_tasks();

    let tick_deadline_ms = f64::from(interval_ms) * 2.0;
    let tick_closure = Closure::<dyn FnMut()>::new(move || {
        wasm_bindgen_futures::spawn_local(background_tasks_tick(tick_deadline_ms));
    });
    let interval_handle = js_set_interval(&tick_closure, f64::from(interval_ms));
    BACKGROUND_TASKS.with(|t| {
        *t.borrow_mut() = Some(BackgroundTasks {
            interval_handle,
            _tick_closure: tick_closure,
        });
    });

    // First tick now — a convo already in ResetPending shouldn't wait a full
    // interval to start healing.
    wasm_bindgen_futures::spawn_local(background_tasks_tick(tick_deadline_ms));

    web_sys::console::log_1(&js_err!(
        "[background-tasks] started (deferred-recovery every {}ms)",
        interval_ms
    ));
    Ok(())
}

/// Stop the background task loop started by
/// `catbird_mls_start_background_tasks()`. Idempotent — safe to call when
/// nothing is running. Call on logout/teardown if the Worker outlives the
/// session (terminating the Worker also kills the timer).
#[wasm_bindgen]
pub fn catbird_mls_stop_background_tasks() {
    if let Some(tasks) = BACKGROUND_TASKS.with(|t| t.borrow_mut().take()) {
        js_clear_interval(tasks.interval_handle);
        web_sys::console::log_1(&js_err!("[background-tasks] stopped"));
    }
}

/// Whether the background task loop is currently running. Exposed for hosts
/// and the wasm-bindgen test suite.
#[wasm_bindgen]
pub fn catbird_mls_background_tasks_running() -> bool {
    BACKGROUND_TASKS.with(|t| t.borrow().is_some())
}

#[cfg(all(test, target_arch = "wasm32"))]
mod background_tasks_tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn in_flight() -> bool {
        BACKGROUND_TICK_IN_FLIGHT.with(|f| f.get())
    }

    fn set_in_flight(v: bool) {
        BACKGROUND_TICK_IN_FLIGHT.with(|f| f.set(v));
    }

    /// Read one field of a pass result. `to_js` serializes
    /// `serde_json::Value` objects via serde-wasm-bindgen, which emits JS
    /// `Map`s for maps — handle both `Map` and plain-object shapes so the
    /// test doesn't encode the serializer's choice.
    fn result_field(v: &JsValue, key: &str) -> JsValue {
        use wasm_bindgen::JsCast;
        let key = JsValue::from_str(key);
        if let Some(map) = v.dyn_ref::<js_sys::Map>() {
            map.get(&key)
        } else {
            js_sys::Reflect::get(v, &key).unwrap_or(JsValue::UNDEFINED)
        }
    }

    #[wasm_bindgen_test]
    fn start_stop_and_restart_guard() {
        assert!(!catbird_mls_background_tasks_running());

        catbird_mls_start_background_tasks(60_000).expect("start should succeed");
        assert!(catbird_mls_background_tasks_running());

        // Double-start replaces the existing timer rather than stacking.
        catbird_mls_start_background_tasks(120_000).expect("restart should succeed");
        assert!(catbird_mls_background_tasks_running());

        catbird_mls_stop_background_tasks();
        assert!(!catbird_mls_background_tasks_running());

        // Stop is idempotent.
        catbird_mls_stop_background_tasks();
        assert!(!catbird_mls_background_tasks_running());

        // Zero interval is rejected and does not start anything.
        catbird_mls_start_background_tasks(0).expect_err("zero interval must be rejected");
        assert!(!catbird_mls_background_tasks_running());
    }

    #[wasm_bindgen_test]
    async fn failed_ticks_do_not_kill_the_loop() {
        // Not initialized / not authenticated → every tick errors. The loop
        // must swallow those errors and stay alive.
        catbird_mls_start_background_tasks(25).expect("start should succeed");
        sleep_ms(150.0).await; // several error ticks elapse
        assert!(
            catbird_mls_background_tasks_running(),
            "timer must survive failing ticks"
        );
        catbird_mls_stop_background_tasks();
        assert!(!catbird_mls_background_tasks_running());
    }

    #[wasm_bindgen_test]
    async fn manual_export_shares_in_flight_guard() {
        // Simulate a pass in flight (exactly what a slow timer tick holds).
        assert!(!in_flight(), "flag must start clear");
        set_in_flight(true);

        // The manual export must NOT start a concurrent pass — it returns a
        // benign already-running result instead.
        let result = catbird_mls_run_deferred_recovery()
            .await
            .expect("manual call during an in-flight pass must be benign, not an error");
        assert_eq!(
            result_field(&result, "alreadyRunning").as_bool(),
            Some(true),
            "expected alreadyRunning: true"
        );
        assert_eq!(
            result_field(&result, "touched").as_f64(),
            Some(0.0),
            "an already-running skip must touch nothing"
        );

        // The skip path must not clear a flag it does not own.
        assert!(in_flight(), "skip path must leave the owner's flag set");
        set_in_flight(false);
    }

    #[wasm_bindgen_test]
    async fn manual_pass_resets_in_flight_flag_on_error() {
        // Not initialized / not authenticated → the pass errors immediately.
        // The RAII reset must still clear the flag on the error path, so a
        // failed manual pass never wedges the timer loop.
        assert!(!in_flight(), "flag must start clear");
        let _ = catbird_mls_run_deferred_recovery().await;
        assert!(!in_flight(), "error path must reset the in-flight flag");
    }

    #[wasm_bindgen_test]
    fn in_flight_reset_guard_is_drop_safe() {
        set_in_flight(true);
        {
            let _reset = TickInFlightReset;
            assert!(in_flight(), "guard construction must not clear the flag");
        }
        assert!(!in_flight(), "Drop must reset the in-flight flag");
    }

    #[wasm_bindgen_test]
    async fn deadline_cancellation_resets_in_flight_flag() {
        // A wedged pass (reqwest-on-wasm has no default timeout) must be
        // cancelled at the deadline, and dropping it must reset the flag via
        // the RAII guard — otherwise every later tick would skip forever.
        assert!(!in_flight(), "flag must start clear");
        set_in_flight(true);
        let wedged_pass = async {
            let _reset = TickInFlightReset;
            sleep_ms(10_000.0).await; // far past the deadline below
        };
        let raced = race_with_timeout(wedged_pass, 50.0).await;
        assert!(
            raced.is_none(),
            "the deadline must win against a wedged pass"
        );
        assert!(
            !in_flight(),
            "dropping the cancelled pass must reset the flag via RAII"
        );
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod conversation_identity_tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn create_response(
        result_type: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "result": {
                "$type": result_type,
                "conversationKind": "direct",
                "conversationId": conversation_id,
                "coordinates": {
                    "conversationId": conversation_id,
                    "groupId": group_id,
                    "epoch": 3
                },
                "entry": {}
            }
        })
    }

    #[wasm_bindgen_test]
    fn stable_conversation_ids_are_not_decoded_as_mls_group_ids() {
        let stable_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        assert!(
            decode_group_id(stable_id).is_none(),
            "stable conversation UUIDs must resolve through storage, never base64-decode as group IDs"
        );
    }

    #[wasm_bindgen_test]
    fn every_parseable_uuid_shape_is_reserved_for_conversation_identity() {
        // UUID parsing is intentionally broader than the canonical wire form:
        // uppercase and compact forms are still UUIDs and must not fall
        // through the legacy group-id decoder.
        for stable_id in [
            "018F3F6A-7B2C-4D91-8A5E-0F123456789A",
            "018f3f6a7b2c4d918a5e0f123456789a",
        ] {
            assert!(
                decode_group_id(stable_id).is_none(),
                "parseable UUID shape must never be interpreted as an MLS group: {stable_id}"
            );
        }

        // Group coordinates are exactly one MLS group id (16 bytes), not any
        // arbitrary even-length hex string or base64 payload.
        assert!(decode_group_coordinate("00112233445566778899aabbccddeeff").is_some());
        assert!(decode_group_id("00112233445566778899aabbccddeeff").is_none());
        assert!(decode_group_id("00112233").is_none());
        assert!(decode_group_id("not-a-group").is_none());
    }

    #[wasm_bindgen_test]
    fn create_response_requires_the_closed_exact_union_and_matching_coordinates() {
        let conversation_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let proposed_group_id = "00112233445566778899aabbccddeeff";
        let created_tag = "blue.catbird.chat.defs#conversationCreatedResult";
        let existing_tag = "blue.catbird.chat.defs#existingDirectConversationResult";

        assert!(matches!(
            parse_create_response(
                &create_response(created_tag, conversation_id, proposed_group_id),
                proposed_group_id,
            ),
            Ok(ParsedCreateResponse::Created { .. })
        ));
        assert!(parse_create_response(
            &create_response(
                created_tag,
                conversation_id,
                "ffeeddccbbaa99887766554433221100"
            ),
            proposed_group_id,
        )
        .is_err());
        assert!(parse_create_response(
            &create_response(
                "blue.catbird.chat.defs#unknownResult",
                conversation_id,
                proposed_group_id
            ),
            proposed_group_id,
        )
        .is_err());
        assert!(parse_create_response(
            &serde_json::json!({
                "result": {
                    "coordinates": {
                        "conversationId": conversation_id,
                        "groupId": proposed_group_id,
                        "epoch": 3
                    }
                }
            }),
            proposed_group_id,
        )
        .is_err());
        assert!(parse_create_response(
            &create_response(
                existing_tag,
                "018F3F6A-7B2C-4D91-8A5E-0F123456789A",
                proposed_group_id
            ),
            proposed_group_id,
        )
        .is_err());
    }

    #[wasm_bindgen_test]
    fn create_response_rejects_noncanonical_or_wrong_length_coordinates() {
        let created_tag = "blue.catbird.chat.defs#conversationCreatedResult";
        let conversation_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let proposed_group_id = "00112233445566778899aabbccddeeff";
        assert!(parse_create_response(
            &create_response(
                created_tag,
                "018f3f6a7b2c4d918a5e0f123456789a",
                proposed_group_id
            ),
            proposed_group_id,
        )
        .is_err());
        assert!(parse_create_response(
            &create_response(created_tag, conversation_id, "00112233"),
            proposed_group_id,
        )
        .is_err());
    }

    #[wasm_bindgen_test]
    fn roster_projection_keeps_member_roles_and_derives_direct_shape() {
        use catbird_mls::orchestrator::types::{MemberRole, MemberView};

        let server_roster = vec![
            MemberView {
                did: "did:plc:creator".to_string(),
                role: MemberRole::Admin,
            },
            MemberView {
                did: "did:plc:invitee".to_string(),
                role: MemberRole::Member,
            },
        ];
        assert_eq!(server_roster.len(), 2);
        assert!(!conversation_is_group(&server_roster));
        assert_eq!(server_roster[0].role, MemberRole::Admin);

        let fallback = member_views_from_dids(
            vec!["did:plc:creator".to_string(), "did:plc:invitee".to_string()],
            "did:plc:creator",
        );
        assert_eq!(fallback, server_roster);

        let group = vec![
            server_roster[0].clone(),
            server_roster[1].clone(),
            MemberView {
                did: "did:plc:third".to_string(),
                role: MemberRole::Member,
            },
        ];
        assert!(conversation_is_group(&group));
    }

    #[wasm_bindgen_test]
    fn reaction_payload_is_cross_client_compatible_for_current_and_historical_messages() {
        use catbird_mls::orchestrator::types::{MLSMessagePayload, MLSMessageType, ReactionAction};

        for (message_id, action) in [
            ("post-reset-current-message", "add"),
            ("pre-reset-historical-alias-message", "remove"),
        ] {
            let payload = reaction_payload_for_wire(message_id, "👍", action)
                .expect("supported reaction action");
            assert_eq!(payload.message_type, MLSMessageType::Reaction);
            let reaction = payload.reaction.as_ref().expect("reaction body");
            assert_eq!(reaction.message_id, message_id);
            assert_eq!(reaction.emoji, "👍");
            assert_eq!(
                reaction.action,
                if action == "add" {
                    ReactionAction::Add
                } else {
                    ReactionAction::Remove
                }
            );
            let encoded = payload.encode().expect("encode reaction payload");
            let decoded = MLSMessagePayload::decode(&encoded).expect("decode reaction payload");
            assert_eq!(decoded.message_type, MLSMessageType::Reaction);
            assert_eq!(decoded.reaction.unwrap().message_id, message_id);
        }
        assert!(reaction_payload_for_wire("message", "👍", "toggle").is_err());
    }
}

// ---------------------------------------------------------------------------
// Field-level encryption — JS exports
//
// In-memory only at this layer (Task 5 of the MLS field-level encryption
// plan). The platform layer is responsible for unlocking the content root
// key from secure storage and pushing it in via `setContentRootKey`.
// Persistence of the root key is Task 23 (storage.rs).
// ---------------------------------------------------------------------------

/// Set the 32-byte content root key used for per-conversation field
/// encryption / HMAC. Must be exactly `KEY_LEN` bytes.
#[wasm_bindgen(js_name = setContentRootKey)]
pub fn catbird_mls_set_content_root_key(key: Vec<u8>) -> Result<(), JsValue> {
    with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized — run catbird_mls_init()"))?;
        // Push into the MLS context first so validation (length check)
        // runs before storage adopts the key. Storage holds an independent
        // copy of the 32 bytes so the message write/read paths don't have
        // to reach back into the `RefCell<Option<WasmMLSContext>>` (which
        // would risk re-entrant borrows on the thread-local STATE).
        ctx.set_content_root_key(key.clone())
            .map_err(|e| js_err!("setContentRootKey failed: {:?}", e))?;
        s.storage.set_content_root_key(key);
        Ok(())
    })
}

/// Clear the cached content root key. Use on logout.
#[wasm_bindgen(js_name = clearContentRootKey)]
pub fn catbird_mls_clear_content_root_key() -> Result<(), JsValue> {
    with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized — run catbird_mls_init()"))?;
        ctx.clear_content_root_key();
        s.storage.clear_content_root_key();
        Ok(())
    })
}

/// Encrypt a message payload under the conversation-scoped content key
/// derived from the cached content root key. Returns the on-the-wire
/// bytes (version byte + nonce + ciphertext + tag).
#[wasm_bindgen(js_name = encryptMessagePayload)]
pub fn catbird_mls_encrypt_message_payload(
    conversation_id: String,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized — run catbird_mls_init()"))?;
        ctx.encrypt_message_payload(&conversation_id, &plaintext)
            .map_err(|e| js_err!("encryptMessagePayload failed: {:?}", e))
    })
}

/// Decrypt an on-the-wire message payload previously produced by
/// `encryptMessagePayload` for the same conversation.
#[wasm_bindgen(js_name = decryptMessagePayload)]
pub fn catbird_mls_decrypt_message_payload(
    conversation_id: String,
    wire: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized — run catbird_mls_init()"))?;
        ctx.decrypt_message_payload(&conversation_id, &wire)
            .map_err(|e| js_err!("decryptMessagePayload failed: {:?}", e))
    })
}

/// Compute the HMAC chain entry for a message. `prev_hmac` is the previous
/// entry's HMAC (or `None` for the first entry in the chain — the spec
/// seed will be used internally).
#[wasm_bindgen(js_name = computeMessageHmac)]
pub fn catbird_mls_compute_message_hmac(
    conversation_id: String,
    prev_hmac: Option<Vec<u8>>,
    message_id: String,
    payload_wire: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized — run catbird_mls_init()"))?;
        ctx.compute_message_hmac(
            &conversation_id,
            prev_hmac.as_deref(),
            &message_id,
            &payload_wire,
        )
        .map_err(|e| js_err!("computeMessageHmac failed: {:?}", e))
    })
}

/// Verify an HMAC chain entry. Returns `true` if `expected` matches the
/// computed HMAC under the cached content root key.
#[wasm_bindgen(js_name = verifyMessageHmac)]
pub fn catbird_mls_verify_message_hmac(
    conversation_id: String,
    prev_hmac: Option<Vec<u8>>,
    message_id: String,
    payload_wire: Vec<u8>,
    expected: Vec<u8>,
) -> Result<bool, JsValue> {
    with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized — run catbird_mls_init()"))?;
        ctx.verify_message_hmac(
            &conversation_id,
            prev_hmac.as_deref(),
            &message_id,
            &payload_wire,
            &expected,
        )
        .map_err(|e| js_err!("verifyMessageHmac failed: {:?}", e))
    })
}
