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
mod browser_enrollment;
mod browser_exports;
mod browser_session;
mod browser_subscription;
mod browser_transport;
mod credentials;
pub mod mls_storage;
mod request_runtime;
pub mod sqlite_conn;
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
use credentials::SqliteCredentialStore;
use mls_storage::WasmStorageBackend;
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
pub use mls_storage::{WasmSqliteStorage, WasmStorageBackend as WasmStorageBackendExport};
pub use sqlite_conn::{SqliteConn, WasmSqliteError};
pub use wasm_mls_context::WasmMLSContext as WasmMLSContextExport;

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
/// 32-byte canonical or retained 16-byte legacy hex/base64 coordinates; unlike a caller-supplied ambiguous handle,
/// a 32-hex coordinate may syntactically resemble a compact UUID and must be
/// accepted here so the crypto path can operate on the server's group bytes.
fn decode_group_coordinate(id: &str) -> Option<Vec<u8>> {
    // Legacy coordinates remain readable after upgrading to canonical 32-byte groups.
    if matches!(id.len(), 32 | 64) && id.chars().all(|c| c.is_ascii_hexdigit()) {
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
        .filter(|bytes| matches!(bytes.len(), 16 | 32))
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
    #[serde(default)]
    pub sequence_number: u64,
    pub status: String,
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_invitation: Option<catbird_mls::orchestrator::GroupInvitationReference>,
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
        .filter(|bytes| matches!(bytes.len(), 16 | 32))
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
    let group_invitation = message
        .payload()
        .and_then(|p| p.checked_group_invitation().ok().flatten())
        .filter(|r| {
            r.invited_by_did
                == catbird_mls::orchestrator::credential_binding::credential_root_did(
                    &message.sender_did,
                )
        });
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
        sequence_number: message.sequence_number,
        status: if message.is_own {
            "sent".to_string()
        } else {
            "delivered".to_string()
        },
        message_type,
        image,
        group_invitation,
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
    /// Required: released by the host persistent protected key vault.
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
    mls_context: Option<Arc<WasmMLSContext>>,
    request_engine: Option<Arc<request_runtime::BrowserOrchestrator>>,
    request_ready: bool,
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
pub fn catbird_mls_init(config: JsValue) -> impl std::future::Future<Output = Result<(), JsValue>> {
    catbird_mls_stop_background_tasks();
    crate::browser_session::advance();
    crate::browser_session::run(async move {
        let cfg: InitConfig =
            serde_wasm_bindgen::from_value(config).map_err(|e| js_err!("Invalid config: {}", e))?;

        let api_client = Arc::new(WasmApiClient::with_proxy(
            cfg.base_url.clone(),
            cfg.proxy_did.clone(),
        ));

        // The host releases the key from its protected persistent vault. Missing
        // custody fails before opening a database or creating any MLS identity.
        let db_key = cfg
            .mls_db_key
            .clone()
            .filter(|key| key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| js_err!("Protected database key is required"))?;

        // Open ONE shared encrypted SQLite database for OpenMLS state,
        // conversations/messages, and credentials. Previously each used a separate
        // IndexedDB — credentials leaked signing keys and MLS DID in plaintext, and
        // conversation storage had no encryption at the IDB layer.
        sqlite_conn::SqliteConn::initialize_opfs()
            .await
            .map_err(|error| js_err!("Persistent encrypted storage unavailable: {}", error))?;
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

        let mls_context = Some(Arc::new(
            WasmMLSContext::open_with_conn(Rc::clone(&shared_conn))
                .map_err(|e| js_err!("Protected MLS custody validation failed: {e}"))?,
        ));

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
                                &format!(
                                    "catbird-mls-web: invalid group_id in storage: {}",
                                    id_str
                                )
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
                                    &format!(
                                        "catbird-mls-web: failed to load group {}: {}",
                                        id_str, e
                                    )
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

        let storage = Arc::new(storage);
        let credentials = Arc::new(credentials);
        let request_engine = if let Some(ctx) = mls_context.as_ref() {
            credentials
                .attach_runtime(Arc::clone(ctx), Arc::clone(&api_client))
                .map_err(|e| js_err!("{e}"))?;
            Some(Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
                Arc::clone(ctx),
                Arc::clone(&storage),
                Arc::clone(&api_client),
                Arc::clone(&credentials),
                Default::default(),
            )))
        } else {
            None
        };
        let state = AppState {
            base_url: cfg.base_url,
            storage_prefix: cfg.storage_prefix,
            db_prefix: cfg.db_prefix,
            proxy_did: cfg.proxy_did,
            api_client,
            storage,
            credentials,
            user_did: None,
            auth_token: None,
            mls_context,
            request_engine,
            request_ready: false,
        };

        STATE.with(|s| {
            *s.borrow_mut() = Some(state);
        });

        Ok(())
    })
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
    catbird_mls_stop_background_tasks();
    crate::browser_session::advance();
    with_state_mut(|state| {
        state
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("Protected crypto unavailable"))?
            .bind_request_owner(&did)
            .map_err(|e| js_err!("{e}"))?;
        state.request_ready = false;
        state.request_engine = state.mls_context.as_ref().map(|ctx| {
            Arc::new(catbird_mls::orchestrator::MLSOrchestrator::new(
                Arc::clone(ctx),
                Arc::clone(&state.storage),
                Arc::clone(&state.api_client),
                Arc::clone(&state.credentials),
                Default::default(),
            ))
        });
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
    catbird_mls_stop_background_tasks();
    crate::browser_session::advance();
    with_state_mut(|state| {
        state.request_ready = false;
        state.request_engine = None;
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
        Some((did, token)) => {
            catbird_mls_set_auth(did, token)?;
            Ok(true)
        }
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
pub fn catbird_mls_setup() -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move { request_runtime::setup().await })
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
pub fn catbird_mls_replenish_key_packages(
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move { request_runtime::replenish().await })
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
pub fn catbird_mls_join_group(
    convo_id: String,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
        canonical_uuid_string(&convo_id, "conversation ID").map_err(|e| js_err!("{e}"))?;
        let (owner, runtime) = request_runtime::current_engine()?;
        let epoch = runtime
            .join_or_rejoin(&convo_id)
            .await
            .map_err(|e| js_err!("{e}"))?;
        request_runtime::current(&owner, &runtime)?;
        to_js(&serde_json::json!({"status":"joined", "epoch":epoch}))
    })
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

pub fn catbird_mls_list_conversations(
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
        let (owner, runtime) = request_runtime::current_engine()?;
        request_runtime::synchronize(&owner, &runtime, true).await?;
        let views = runtime
            .conversation_display_snapshot(&owner)
            .await
            .map_err(|e| js_err!("{}", e))?;
        let storage = with_state(|s| Ok(s.storage.clone()))?;
        let requests = runtime
            .list_direct_request_views()
            .await
            .map_err(|e| js_err!("{}", e))?;
        request_runtime::current(&owner, &runtime)?;
        let mut conversations = Vec::new();
        for view in views {
            if matches!(
                storage
                    .get_conversation_state(&view.conversation_id)
                    .await
                    .map_err(|e| js_err!("{}", e))?,
                Some(
                    catbird_mls::orchestrator::types::ConversationState::Closed
                        | catbird_mls::orchestrator::types::ConversationState::DeviceRemoved
                )
            ) {
                continue;
            }
            // Request rows live in the request workspace until consent is verified.
            // A missing local request projection never authorizes normal chat UI.
            if view
                .canonical_state
                .as_ref()
                .is_some_and(|s| s.direct_request.is_some())
                && !requests.iter().any(|r| {
                    r.conversation_id == view.conversation_id
                        && r.consent == catbird_mls::orchestrator::RequestConsent::Accepted
                })
            {
                continue;
            }
            let group_id = decode_group_coordinate(&view.group_id)
                .map(hex::encode)
                .ok_or_else(|| js_err!("Invalid protected group coordinate"))?;
            let members = view
                .members
                .iter()
                .map(|m| m.did.clone())
                .collect::<Vec<_>>();
            let title = storage
                .get_metadata_text(&group_id)
                .map_err(|e| js_err!("{}", e))?
                .and_then(|(title, _)| title)
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| members.join(", "));
            let kind = storage
                .conversation_kind(&owner, &view.conversation_id)
                .map_err(|e| js_err!("{}", e))?
                .unwrap_or_else(|| {
                    if conversation_is_group(&view.members) {
                        "group"
                    } else {
                        "direct"
                    }
                    .into()
                });
            conversations.push(Conversation {
                id: view.conversation_id,
                group_id,
                display_name: title,
                members,
                member_views: Some(view.members),
                is_group: kind == "group",
                conversation_kind: kind,
                last_message: None,
                last_message_at: None,
                unread_count: 0,
            });
        }
        request_runtime::current(&owner, &runtime)?;
        to_js(&conversations)
    })
}

pub fn catbird_mls_create_conversation(
    name: String,
    member_dids: Array,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
        let members = array_to_strings(&member_dids);
        if members.len() == 1 {
            return Err(js_err!(
                "Direct conversations require a local draft and an encrypted first message"
            ));
        }
        let (owner, runtime) = request_runtime::current_engine()?;
        let view = runtime
            .create_group(&name, Some(&members), None)
            .await
            .map_err(|e| js_err!("{e}"))?;
        request_runtime::current(&owner, &runtime)?;
        to_js(&Conversation {
            id: view.conversation_id,
            group_id: view.group_id,
            display_name: name,
            members: view.members.iter().map(|m| m.did.clone()).collect(),
            member_views: Some(view.members),
            conversation_kind: "group".into(),
            last_message: None,
            last_message_at: None,
            unread_count: 0,
            is_group: true,
        })
    })
}

pub fn catbird_mls_subscribe(
    convo_id: String,
    on_message: js_sys::Function,
    on_event: js_sys::Function,
    on_status: js_sys::Function,
) -> impl std::future::Future<Output = Result<browser_subscription::CanonicalSubscription, JsValue>>
{
    crate::browser_session::run(async move {
        browser_subscription::connect(convo_id, on_message, on_event, on_status).await
    })
}

pub fn catbird_mls_unsubscribe(
    _convo_id: String,
) -> impl std::future::Future<Output = Result<(), JsValue>> {
    crate::browser_session::run(async move { Ok(()) })
}

// ---------------------------------------------------------------------------
// Message commands
// ---------------------------------------------------------------------------

async fn send_payload_message_internal(
    convo_id: String,
    payload: catbird_mls::orchestrator::types::MLSMessagePayload,
) -> Result<JsValue, JsValue> {
    let (resolved, _) = resolve_conversation_identity(&convo_id)?;
    let (owner, runtime) = request_runtime::current_engine()?;
    let encoded = String::from_utf8(payload.encode().map_err(|e| js_err!("{e}"))?)
        .map_err(|e| js_err!("{e}"))?;
    let message = runtime
        .send_payload_json(&resolved, &encoded)
        .await
        .map_err(|e| js_err!("{e}"))?;
    request_runtime::current(&owner, &runtime)?;
    to_js(&ui_message_from_orchestrator(message))
}

pub fn catbird_mls_send_message(
    convo_id: String,
    content: String,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
        send_payload_message_internal(
            convo_id,
            catbird_mls::orchestrator::types::MLSMessagePayload::text(&content),
        )
        .await
    })
}

pub fn catbird_mls_send_image(
    convo_id: String,
    content: String,
    data: Vec<u8>,
    content_type: String,
    width: u32,
    height: u32,
    alt_text: Option<String>,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
        request_runtime::require_ordinary_access(&convo_id).await?;
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
    })
}

pub fn catbird_mls_get_image_attachment(
    convo_id: String,
    blob_id: String,
    key_b64: String,
    iv_b64: String,
    sha256: String,
    content_type: String,
) -> impl std::future::Future<Output = Result<String, JsValue>> {
    crate::browser_session::run(async move {
        request_runtime::require_ordinary_access(&convo_id).await?;
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
    })
}

pub fn catbird_mls_messages(
    convo_id: String,
    before: Option<String>,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
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
    })
}

pub fn catbird_mls_fetch_new_messages(
    convo_id: String,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
        let (resolved, _) = resolve_conversation_identity(&convo_id)?;
        let (owner, runtime) = request_runtime::current_engine()?;
        let previous = SYNC_CURSORS.with(|m| m.borrow().get(&resolved).cloned());
        let (messages, cursor) = runtime
            .fetch_messages(&resolved, previous.as_deref(), 50, None, None, None)
            .await
            .map_err(|e| js_err!("{e}"))?;
        request_runtime::current(&owner, &runtime)?;
        // The shared engine rejects a failed control/application before this cursor advances.
        if let Some(cursor) = cursor {
            SYNC_CURSORS.with(|m| m.borrow_mut().insert(resolved, cursor));
        }
        to_js(
            &messages
                .into_iter()
                .filter(|m| m.has_displayable_body())
                .map(ui_message_from_orchestrator)
                .collect::<Vec<_>>(),
        )
    })
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

pub fn catbird_mls_send_reaction(
    conversation_id: String,
    message_id: String,
    emoji: String,
    action: String,
) -> impl std::future::Future<Output = Result<(), JsValue>> {
    crate::browser_session::run(async move {
        let (resolved_convo_id, _) = resolve_conversation_identity(&conversation_id)?;
        let payload = reaction_payload_for_wire(&message_id, &emoji, &action)
            .map_err(|error| js_err!("send reaction failed: {}", error))?;
        // The shared send path encrypts the complete reaction envelope with the
        // current MLS group, submits the stable conversation route, and persists
        // the resulting message. Historical-alias message IDs remain untouched
        // inside the encrypted payload for cross-reset targeting.
        send_payload_message_internal(resolved_convo_id, payload).await?;

        Ok(())
    })
}

pub fn catbird_mls_update_cursor(
    _conversation_id: String,
    _cursor: String,
) -> impl std::future::Future<Output = Result<(), JsValue>> {
    crate::browser_session::run(async move {
        Err(js_err!("legacy mlsChat updateCursor is disabled; subscription cursors are managed via subscribeEvents"))
    })
}

// ---------------------------------------------------------------------------
// Member commands
// ---------------------------------------------------------------------------

pub fn catbird_mls_get_members(
    conversation_id: String,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
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
                        catbird_mls::orchestrator::types::MemberRole::Member => {
                            "member".to_string()
                        }
                    },
                })
                .collect(),
            None => vec![],
        };

        to_js(&members)
    })
}

/// Add one or more members to an existing group in a single MLS commit.
///
/// Flow:
/// 1. Fetch key packages for all `member_dids` in one batch request.
/// 2. Produce a single `add_members` commit + Welcome covering all new members.
/// 3. Merge the pending commit locally (one epoch advance regardless of member count).
/// 4. Send the commit + welcome to the server via `commitGroupChange`.
/// 5. Update the cached server epoch.
pub fn catbird_mls_add_group_members(
    conversation_id: String,
    member_dids: Array,
) -> impl std::future::Future<Output = Result<(), JsValue>> {
    crate::browser_session::run(async move {
        let (cid, _) = resolve_conversation_identity(&conversation_id)?;
        request_runtime::require_ordinary_access(&cid).await?;
        let (owner, runtime) = request_runtime::current_engine()?;
        runtime
            .add_members(&cid, &array_to_strings(&member_dids))
            .await
            .map_err(|e| js_err!("{e}"))?;
        request_runtime::current(&owner, &runtime)
    })
}

pub fn catbird_mls_add_participants(
    conversation_id: String,
    target_did: String,
) -> impl std::future::Future<Output = Result<(), JsValue>> {
    crate::browser_session::run(async move {
        let arr = Array::new();
        arr.push(&JsValue::from_str(&target_did));
        catbird_mls_add_group_members(conversation_id, arr).await
    })
}

pub fn catbird_mls_demote_member(
    _conversation_id: String,
    _target_did: String,
) -> impl std::future::Future<Output = Result<(), JsValue>> {
    crate::browser_session::run(async move {
        Err(js_err!(
            "demoteAdmin is a signed policy transition and is not wired in WASM"
        ))
    })
}

pub fn catbird_mls_remove_participants(
    conversation_id: String,
    target_did: String,
) -> impl std::future::Future<Output = Result<(), JsValue>> {
    crate::browser_session::run(async move {
        let (cid, _) = resolve_conversation_identity(&conversation_id)?;
        request_runtime::require_ordinary_access(&cid).await?;
        let (owner, runtime) = request_runtime::current_engine()?;
        runtime
            .remove_members(&cid, &[target_did])
            .await
            .map_err(|e| js_err!("{e}"))?;
        request_runtime::current(&owner, &runtime)
    })
}

pub fn catbird_mls_leave_conversation(
    conversation_id: String,
) -> impl std::future::Future<Output = Result<(), JsValue>> {
    crate::browser_session::run(async move {
        let (cid, _) = resolve_conversation_identity(&conversation_id)?;
        request_runtime::require_ordinary_access(&cid).await?;
        let (owner, runtime) = request_runtime::current_engine()?;
        runtime
            .leave_group(&cid)
            .await
            .map_err(|e| js_err!("{e}"))?;
        request_runtime::current(&owner, &runtime)
    })
}

// ---------------------------------------------------------------------------
// Typing indicator
// ---------------------------------------------------------------------------

pub fn catbird_mls_send_typing(
    _conversation_id: String,
    _is_typing: bool,
) -> impl std::future::Future<Output = Result<(), JsValue>> {
    crate::browser_session::run(async move {
        Err(js_err!(
        "Typing is temporarily unavailable: canonical signed typing transport is not wired in WASM"
    ))
    })
}

// ---------------------------------------------------------------------------
// Promote / Group metadata
// ---------------------------------------------------------------------------

pub fn catbird_mls_promote_member(
    _conversation_id: String,
    _target_did: String,
) -> impl std::future::Future<Output = Result<(), JsValue>> {
    crate::browser_session::run(async move {
        Err(js_err!(
            "promoteAdmin is a signed policy transition and is not wired in WASM"
        ))
    })
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
pub fn catbird_mls_update_group_metadata(
    conversation_id: String,
    title: Option<String>,
    description: Option<String>,
    avatar_blob_locator: Option<String>,
    avatar_content_type: Option<String>,
    avatar_bytes: Option<Vec<u8>>,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
        use catbird_mls::metadata;

        let (resolved_convo_id, group_id_hex) = resolve_conversation_identity(&conversation_id)?;
        request_runtime::require_ordinary_access(&resolved_convo_id).await?;
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
    })
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
pub fn wasm_bootstrap_group_metadata(
    group_id_hex: String,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
        use catbird_mls::metadata;
        let (stable_id, _) = resolve_conversation_identity(&group_id_hex)?;
        request_runtime::require_ordinary_access(&stable_id).await?;

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
    })
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
pub fn wasm_republish_metadata_after_reset(
    new_group_id_hex: String,
    reset_generation: Option<u64>,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
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
    })
}

// ---------------------------------------------------------------------------
// Profile commands
// ---------------------------------------------------------------------------

pub fn catbird_mls_get_profiles(
    dids: Array,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
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
    })
}

pub fn catbird_mls_search_users(
    query: String,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
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
    })
}

pub fn catbird_mls_check_opt_in_status(
    dids: Array,
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
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
    })
}

// ---------------------------------------------------------------------------
// Deferred recovery — first-responder bootstrap for ResetPending convos
// ---------------------------------------------------------------------------

/// Reconcile the exact authenticated account inventories through shared Rust.
/// A failed pass retains prior durable progress and pending policy.
pub fn catbird_mls_run_deferred_recovery(
) -> impl std::future::Future<Output = Result<JsValue, JsValue>> {
    crate::browser_session::run(async move {
        run_deferred_recovery_guarded(MANUAL_PASS_DEADLINE_MS).await
    })
}

/// Un-guarded single deferred-recovery pass — the body of
/// `catbird_mls_run_deferred_recovery`. Callers MUST go through
/// `run_deferred_recovery_guarded`; calling this directly bypasses the
/// re-entrancy guard and can run concurrently with a timer tick.
async fn run_deferred_recovery_inner() -> Result<JsValue, JsValue> {
    let (owner, runtime) = request_runtime::current_engine()?;
    request_runtime::synchronize(&owner, &runtime, true).await?;
    request_runtime::current(&owner, &runtime)?;
    to_js(&serde_json::json!({"touched":0,"reconciled":true}))
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
        crate::browser_session::spawn(background_tasks_tick(tick_deadline_ms));
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
    crate::browser_session::spawn(background_tasks_tick(tick_deadline_ms));

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

    #[cfg(not(feature = "inventory-worker-tests"))]
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

    #[cfg(not(feature = "inventory-worker-tests"))]
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
        assert_eq!(
            serde_json::to_value(fallback).unwrap(),
            serde_json::to_value(&server_roster).unwrap()
        );

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
