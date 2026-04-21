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

mod api_client;
mod credentials;
pub mod mls_storage;
pub mod sqlite_conn;
mod storage;
mod wasm_mls_context;
mod websocket;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use js_sys::Array;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use api_client::WasmApiClient;
use base64::Engine as _;
use catbird_mls::blob_crypto::{decrypt_blob, encrypt_blob};
use catbird_mls::MLSError;
use credentials::SqliteCredentialStore;
use storage::WasmStorageBackend;
use wasm_mls_context::WasmMLSContext;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use api_client::WasmApiClient as WasmApiClientExport;
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
    // Hex: only [0-9a-fA-F] and even length
    if id.len() % 2 == 0 && id.chars().all(|c| c.is_ascii_hexdigit()) {
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
}

// ---------------------------------------------------------------------------
// Public data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    pub id: String,
    pub display_name: String,
    pub members: Vec<String>,
    pub last_message: Option<String>,
    pub last_message_at: Option<String>,
    pub unread_count: u32,
    pub is_group: bool,
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
                    let Some(gid_bytes) = decode_group_id(id_str) else {
                        web_sys::console::warn_1(&format!(
                            "catbird-mls-web: invalid group_id in storage: {}",
                            id_str
                        ).into());
                        continue;
                    };
                    match ctx.ensure_group_loaded(&gid_bytes) {
                        Ok(true) => loaded += 1,
                        Ok(false) => {
                            web_sys::console::warn_1(&format!(
                                "catbird-mls-web: group {} in SQLite but not in OpenMLS storage",
                                id_str
                            ).into());
                        }
                        Err(e) => {
                            web_sys::console::warn_1(&format!(
                                "catbird-mls-web: failed to load group {}: {}",
                                id_str, e
                            ).into());
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
                web_sys::console::warn_1(&format!(
                    "catbird-mls-web: failed to enumerate persisted groups: {}",
                    e
                ).into());
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

    let (api_client, credentials, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated — call catbird_mls_set_auth() first"))?;
        Ok((Arc::clone(&s.api_client), Arc::clone(&s.credentials), did))
    })?;

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

    // 4. Register device with server
    let device_info = api_client
        .register_device(
            &device_uuid,
            "Catbird Web",
            &user_did,
            &kp_result.hash_ref,
            std::slice::from_ref(&kp_result.key_package_data),
        )
        .await
        .map_err(|e| js_err!("Device registration failed: {:?}", e))?;

    // 5. Store credentials
    credentials
        .store_mls_did(&user_did, &device_info.mls_did)
        .await
        .map_err(|e| js_err!("store_mls_did failed: {:?}", e))?;
    credentials
        .store_device_uuid(&user_did, &device_uuid)
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
        match api_client
            .publish_key_package(
                &kp.key_package_data,
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                &expires_at,
            )
            .await
        {
            Ok(()) => {
                published += 1;
                LOCAL_KP_COUNT.with(|c| *c.borrow_mut() += 1);
            }
            Err(e) => {
                web_sys::console::warn_1(&js_err!("Key package publish failed: {:?}", e));
                break;
            }
        }
    }

    web_sys::console::log_1(&js_err!(
        "catbird-mls-web: device registered! id={}, mls_did={}, key_packages={}",
        device_info.device_id,
        device_info.mls_did,
        published
    ));

    let result = serde_json::json!({
        "status": "registered",
        "deviceId": device_info.device_id,
        "mlsDid": device_info.mls_did,
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

    let (api_client, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), did))
    })?;

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
                match api_client
                    .publish_key_package(&kp.key_package_data, cipher_suite, &expires_at)
                    .await
                {
                    Ok(()) => {
                        published += 1;
                        LOCAL_KP_COUNT.with(|c| *c.borrow_mut() += 1);
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

    let (api_client, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), did))
    })?;

    let identity_bytes = user_did.as_bytes().to_vec();

    // 1. Try Welcome first
    match api_client.get_welcome(convo_id).await {
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
                        Ok(s.mls_context.as_ref()
                            .and_then(|ctx| ctx.get_epoch(jr.group_id.clone()).ok())
                            .unwrap_or(0))
                    }).unwrap_or(0);
                    SERVER_EPOCHS.with(|m| m.borrow_mut().insert(convo_id.to_string(), welcome_epoch));

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
        .get_group_info(convo_id)
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
    // TODO(A7): confirmation_tag stubbed as None until pyramid wiring (#15/#18).
    let server_result = api_client
        .process_external_commit(
            convo_id,
            &ext_commit.commit_data,
            ext_commit.group_info.as_deref(),
            None,
        )
        .await
        .map_err(|e| js_err!("process_external_commit failed: {:?}", e))?;

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
    SERVER_EPOCHS.with(|m| m.borrow_mut().insert(convo_id.to_string(), server_result.epoch));

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
            if let Err(e) = api_client.publish_group_info(convo_id, &gi_bytes).await {
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
        server_result.epoch,
        local_epoch
    ));

    Ok(serde_json::json!({
        "status": "joined_via_external_commit",
        "epoch": server_result.epoch,
    }))
}

// ---------------------------------------------------------------------------
// Conversation commands
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub async fn catbird_mls_list_conversations() -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;

    let page = api_client
        .get_conversations(50, None)
        .await
        .map_err(|e| js_err!("get_conversations failed: {:?}", e))?;

    let convos: Vec<Conversation> = page
        .conversations
        .into_iter()
        .map(|c| {
            let member_dids: Vec<String> = c.members.iter().map(|m| m.did.clone()).collect();
            // Decrypt MLS group metadata (name/description stored in encrypted extensions)
            let mls_metadata = with_state(|s| {
                if let Some(ctx) = &s.mls_context {
                    if let Some(gid) = decode_group_id(&c.group_id) {
                        return Ok(ctx.get_group_metadata(gid));
                    }
                }
                Ok(None)
            })
            .ok()
            .flatten();
            let display_name = mls_metadata
                .as_ref()
                .and_then(|m| m.name.clone())
                .or_else(|| c.metadata.as_ref().and_then(|m| m.name.clone()))
                .unwrap_or_else(|| member_dids.join(", "));
            Conversation {
                id: c.group_id,
                display_name,
                members: member_dids.clone(),
                last_message: None,
                last_message_at: None,
                unread_count: 0,
                is_group: member_dids.len() > 2,
            }
        })
        .collect();

    to_js(&convos)
}

#[wasm_bindgen]
pub async fn catbird_mls_create_conversation(
    name: String,
    member_dids: Array,
) -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::orchestrator::types::ConversationMetadata;
    use catbird_mls::KeyPackageData;

    let (api_client, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), did))
    })?;

    let member_dids_vec = array_to_strings(&member_dids);
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

    let (commit_bytes, welcome_bytes) = if member_dids_vec.is_empty() {
        (None, None)
    } else {
        let kp_refs = api_client
            .get_key_packages(&member_dids_vec)
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

    // Encode as hex to match server convention (GroupId = hex-encoded string)
    let group_id_str: String = group_id_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let metadata = ConversationMetadata {
        name: Some(name.clone()),
        description: None,
        avatar_url: None,
    };

    let server_result = api_client
        .create_conversation(
            &group_id_str,
            if member_dids_vec.is_empty() {
                None
            } else {
                Some(&member_dids_vec)
            },
            Some(&metadata),
            commit_bytes.as_deref(),
            welcome_bytes.as_deref(),
        )
        .await
        .map_err(|e| js_err!("create_conversation failed: {:?}", e))?;

    let convo_id = &server_result.conversation.group_id;

    // Cache epoch after group creation. Prefer server-reported epoch; fall back
    // to querying the local MLS context (which is already at 1+ after add_members).
    let create_epoch = {
        let server_epoch = server_result.conversation.epoch;
        if server_epoch > 0 {
            server_epoch
        } else {
            with_state(|s| {
                Ok(s.mls_context.as_ref()
                    .and_then(|ctx| ctx.get_epoch(group_id_bytes.clone()).ok())
                    .unwrap_or(0))
            }).unwrap_or(0)
        }
    };
    SERVER_EPOCHS.with(|m| m.borrow_mut().insert(convo_id.clone(), create_epoch));

    // Mark as recently created so fetch_new_messages won't try to auto-join
    // (we're already a member — auto-join would cause unnecessary External Commits)
    RECENTLY_CREATED.with(|s| s.borrow_mut().insert(convo_id.clone()));

    // Publish GroupInfo so other clients can join via external commit
    let gi_result = with_state(|s| {
        let ctx = s.mls_context.as_ref().ok_or_else(|| js_err!("MLS not init"))?;
        ctx.export_group_info(group_id_bytes.clone(), identity_bytes.clone())
            .map_err(|e| js_err!("export_group_info: {:?}", e))
    });
    if let Ok(gi) = gi_result {
        if let Err(e) = api_client.publish_group_info(convo_id, &gi).await {
            web_sys::console::warn_1(&js_err!(
                "catbird-mls-web: publish_group_info failed after create: {:?}",
                e
            ));
        }
    }

    let convo = Conversation {
        id: convo_id.clone(),
        display_name: name,
        members: member_dids_vec,
        last_message: None,
        last_message_at: None,
        unread_count: 0,
        is_group: true,
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
    let (base_url, auth_token) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token))
    })?;

    websocket::connect(
        convo_id, base_url, auth_token, on_message, on_event, on_status,
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

    let (api_client, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), did))
    })?;

    let identity_bytes = user_did.as_bytes().to_vec();

    // Delete existing group so OpenMLS doesn't complain about duplicate group IDs
    let group_id_bytes = decode_group_id(convo_id);
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
        .get_group_info(convo_id)
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

    // TODO(A7): confirmation_tag stubbed as None until pyramid wiring (#15/#18).
    let server_result = api_client
        .process_external_commit(
            convo_id,
            &ext_commit.commit_data,
            ext_commit.group_info.as_deref(),
            None,
        )
        .await
        .map_err(|e| js_err!("rejoin process_external_commit failed: {:?}", e))?;

    let local_epoch = with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.merge_pending_commit(ext_commit.group_id.clone())
            .map_err(|e| js_err!("rejoin merge_pending_commit failed: {:?}", e))
    })?;

    // Cache the server's epoch for this conversation so sendMessage uses it
    // instead of the local MLS epoch (which may differ from the server's counter).
    SERVER_EPOCHS.with(|m| m.borrow_mut().insert(convo_id.to_string(), server_result.epoch));

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
            if let Err(e) = api_client.publish_group_info(convo_id, &gi_bytes).await {
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
        convo_id,
        server_result.epoch,
        local_epoch
    ));

    Ok(())
}

async fn send_payload_message_internal(
    convo_id: String,
    payload: catbird_mls::orchestrator::types::MLSMessagePayload,
) -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let (api_client, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.api_client), did))
    })?;

    let group_id_bytes = decode_group_id(&convo_id)
        .ok_or_else(|| js_err!("Invalid convo_id '{}': not hex or base64url", convo_id))?;

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
    let mut last_err = String::new();
    for attempt in 0..3 {
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
                        convo_id
                    ));
                    let storage = with_state(|s| Ok(Arc::clone(&s.storage)))?;
                    let _ = storage.mark_needs_rejoin(&convo_id).await;
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
                borrowed.as_ref()
                    .and_then(|st| st.mls_context.as_ref())
                    .and_then(|ctx| ctx.get_epoch(group_id_bytes.clone()).ok())
            });
            // If MLS context returned an epoch, use it and update cache
            if let Some(e) = mls_epoch {
                if e > 0 {
                    SERVER_EPOCHS.with(|m| m.borrow_mut().insert(convo_id.clone(), e));
                }
                // Still prefer server cache if it's higher (server may be ahead after commits)
                let cached = SERVER_EPOCHS.with(|m| m.borrow().get(&convo_id).copied());
                cached.unwrap_or(e)
            } else {
                SERVER_EPOCHS.with(|m| m.borrow().get(&convo_id).copied()).unwrap_or(0)
            }
        };

        match api_client
            .send_message_with_id(&convo_id, &encrypt_result.ciphertext, epoch, &msg_id)
            .await
        {
            Ok(_send_resp) => {
                // Persist to IndexedDB so messages survive navigation/reload
                let now = chrono::Utc::now();
                {
                    use catbird_mls::orchestrator::storage::MLSStorageBackend;
                    let storage = with_state(|s| Ok(Arc::clone(&s.storage)))?;
                    let stored_msg = catbird_mls::orchestrator::types::Message {
                        id: msg_id.clone(),
                        conversation_id: convo_id.clone(),
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
                            "catbird-mls-web: failed to persist sent message: {:?}", e
                        ));
                    }
                }
                let message = ui_message_from_orchestrator(catbird_mls::orchestrator::types::Message {
                    id: msg_id.clone(),
                    conversation_id: convo_id,
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
            Err(e) => {
                let (is_409, server_epoch_hint) = match &e {
                    catbird_mls::orchestrator::error::OrchestratorError::ServerError { status, body } => {
                        let is_conflict = *status == 409;
                        let hint = if is_conflict {
                            serde_json::from_str::<serde_json::Value>(body)
                                .ok()
                                .and_then(|v| v.get("serverEpoch").and_then(|e| e.as_u64()))
                        } else {
                            None
                        };
                        (is_conflict, hint)
                    }
                    _ => (false, None),
                };
                last_err = format!("{:?}", e);

                if is_409 && attempt < 2 {
                    if let Some(correct_epoch) = server_epoch_hint {
                        // Server told us the correct epoch — cache and retry (no rejoin needed)
                        web_sys::console::warn_1(&js_err!(
                            "catbird-mls-web: send_message 409 (sent epoch={}, server={}), retrying with correct epoch (attempt {})",
                            epoch,
                            correct_epoch,
                            attempt + 1
                        ));
                        SERVER_EPOCHS.with(|m| m.borrow_mut().insert(convo_id.clone(), correct_epoch));
                        continue;
                    } else {
                        // 409 without serverEpoch hint — we'd need to rejoin to make
                        // progress, but External Commit in the send hot path causes
                        // epoch inflation (spec §5.3). Flag for deferred recovery and
                        // surface the error; the sync loop / explicit rejoin
                        // entrypoint will handle the actual rejoin.
                        use catbird_mls::orchestrator::storage::MLSStorageBackend;
                        web_sys::console::warn_1(&js_err!(
                            "catbird-mls-web: send_message 409 (epoch={}), no server hint — flagging {} for deferred rejoin",
                            epoch,
                            convo_id
                        ));
                        let storage = with_state(|s| Ok(Arc::clone(&s.storage)))?;
                        let _ = storage.mark_needs_rejoin(&convo_id).await;
                        return Err(js_err!(
                            "Epoch conflict with no server hint — sync in progress, please retry"
                        ));
                    }
                }
            }
        }
    }

    Err(js_err!("send_message failed after retries: {}", last_err))
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
    use catbird_mls::orchestrator::storage::MLSStorageBackend;

    let storage = with_state(|s| Ok(Arc::clone(&s.storage)))?;

    let before_seq = before.as_deref().and_then(|b| b.parse::<u64>().ok());

    let stored = storage
        .get_messages(&convo_id, 50, before_seq)
        .await
        .map_err(|e| js_err!("get_messages failed: {:?}", e))?;

    let messages: Vec<Message> = stored
        .into_iter()
        .filter(|m| m.has_displayable_body())
        .map(ui_message_from_orchestrator)
        .collect();

    to_js(&messages)
}

#[wasm_bindgen]
pub async fn catbird_mls_fetch_new_messages(convo_id: String) -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;
    use catbird_mls::orchestrator::storage::MLSStorageBackend;
    use catbird_mls::orchestrator::types::MLSMessagePayload;

    let (api_client, user_did, storage) = with_state(|s| {
        let did = s.user_did.clone().unwrap_or_default();
        Ok((Arc::clone(&s.api_client), did, Arc::clone(&s.storage)))
    })?;

    let stored_cursor = SYNC_CURSORS.with(|m| m.borrow().get(&convo_id).cloned());
    let (envelopes, new_cursor) = api_client
        .get_messages(&convo_id, stored_cursor.as_deref(), 50, None, None, None)
        .await
        .map_err(|e| js_err!("fetch_new_messages failed: {:?}", e))?;

    // Update sync cursor for next poll
    if let Some(ref cursor) = new_cursor {
        SYNC_CURSORS.with(|m| m.borrow_mut().insert(convo_id.clone(), cursor.clone()));
    }

    let group_id_bytes = decode_group_id(&convo_id);

    web_sys::console::log_1(&js_err!(
        "catbird-mls-web: fetch_new_messages({}) — {} envelopes, group_id_decoded={}",
        convo_id,
        envelopes.len(),
        group_id_bytes.is_some()
    ));

    // Before decrypting, check if the group exists locally. If not, try to join.
    // Skip auto-join for groups we just created (we're already a member).
    let recently_created = RECENTLY_CREATED.with(|s| s.borrow().contains(&convo_id));
    if let Some(ref gid) = group_id_bytes {
        if recently_created {
            web_sys::console::log_1(&js_err!(
                "catbird-mls-web: skipping auto-join for recently created group {}",
                convo_id
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
                match try_join_group_internal(&convo_id).await {
                    Ok(result) => {
                        let status = result["status"].as_str().unwrap_or("unknown");
                        web_sys::console::log_1(&js_err!(
                            "catbird-mls-web: auto-joined group {} ({})",
                            convo_id,
                            status
                        ));
                    }
                    Err(e) => {
                        web_sys::console::warn_1(&js_err!(
                            "catbird-mls-web: auto-join failed for {}: {:?}",
                            convo_id,
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
                                        conversation_id: env.conversation_id.clone(),
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

        let Some((storage_msg, _sender_did)) = decoded else {
            continue;
        };

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
            borrowed.as_ref()
                .and_then(|st| st.mls_context.as_ref())
                .and_then(|ctx| ctx.get_epoch(gid.clone()).ok())
        });
        if let Some(epoch) = updated_epoch {
            if epoch > 0 {
                SERVER_EPOCHS.with(|m| m.borrow_mut().insert(convo_id.clone(), epoch));
            }
        }
    }

    to_js(&messages)
}

#[wasm_bindgen]
pub async fn catbird_mls_send_reaction(
    conversation_id: String,
    message_id: String,
    emoji: String,
    action: String,
) -> Result<(), JsValue> {
    let (base_url, auth_token, proxy_did) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token, s.proxy_did.clone()))
    })?;

    let client = proxy_client(&proxy_did);
    let action_name = if action == "remove" {
        "removeReaction"
    } else {
        "addReaction"
    };

    let no_op_ciphertext = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 512]);

    let input = serde_json::json!({
        "convoId": conversation_id,
        "delivery": "ephemeral",
        "action": action_name,
        "targetMessageId": message_id,
        "reactionEmoji": emoji,
        "msgId": uuid::Uuid::new_v4().to_string(),
        "epoch": 0,
        "paddedSize": 512,
        "ciphertext": { "$bytes": no_op_ciphertext },
    });

    let resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsChat.sendMessage",
            base_url
        ))
        .bearer_auth(&auth_token)
        .json(&input)
        .send()
        .await
        .map_err(|e| js_err!("Reaction update failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("Reaction update failed ({}): {}", status, body));
    }

    Ok(())
}

#[wasm_bindgen]
pub async fn catbird_mls_update_cursor(
    conversation_id: String,
    cursor: String,
) -> Result<(), JsValue> {
    let (base_url, auth_token, proxy_did) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token, s.proxy_did.clone()))
    })?;

    let input = serde_json::json!({
        "convoId": conversation_id,
        "cursor": cursor,
    });

    let client = proxy_client(&proxy_did);
    let resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsChat.updateCursor",
            base_url
        ))
        .bearer_auth(&auth_token)
        .json(&input)
        .send()
        .await
        .map_err(|e| js_err!("Update cursor failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("Update cursor failed ({}): {}", status, body));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Member commands
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub async fn catbird_mls_get_members(conversation_id: String) -> Result<JsValue, JsValue> {
    use catbird_mls::orchestrator::storage::MLSStorageBackend;

    let (storage, user_did) = with_state(|s| {
        let did = s
            .user_did
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((Arc::clone(&s.storage), did))
    })?;

    let convo = storage
        .get_conversation(&user_did, &conversation_id)
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
                role: format!("{:?}", m.role),
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

    // Resolve conversation ID → group ID bytes (hex-encoded on server).
    let group_id_bytes = decode_group_id(&conversation_id)
        .ok_or_else(|| js_err!("Invalid conversation/group ID: {}", conversation_id))?;

    // 1. Fetch key packages for all new members in one batch request.
    let kp_refs = api_client
        .get_key_packages(&member_dids_vec)
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
    let server_result = api_client
        .add_members(
            &conversation_id,
            &member_dids_vec,
            &add_result.commit_data,
            Some(&add_result.welcome_data),
        )
        .await
        .map_err(|e| {
            // Clear pending commit so group isn't stuck on failure.
            let _ = with_state(|s| {
                if let Some(ctx) = s.mls_context.as_ref() {
                    let _ = ctx.clear_pending_commit(group_id_bytes.clone());
                }
                Ok(())
            });
            js_err!("add_members server call failed: {:?}", e)
        })?;

    if !server_result.success {
        let _ = with_state(|s| {
            if let Some(ctx) = s.mls_context.as_ref() {
                let _ = ctx.clear_pending_commit(group_id_bytes.clone());
            }
            Ok(())
        });
        return Err(js_err!("Server rejected add_members commit"));
    }

    // 4. Merge pending commit locally so epoch advances.
    with_state(|s| {
        let ctx = s
            .mls_context
            .as_ref()
            .ok_or_else(|| js_err!("MLS context not initialized"))?;
        ctx.merge_pending_commit(group_id_bytes.clone())
            .map_err(|e| js_err!("merge_pending_commit failed: {:?}", e))
    })?;

    // 5. Cache the new server epoch.
    if server_result.new_epoch > 0 {
        SERVER_EPOCHS.with(|m| {
            m.borrow_mut()
                .insert(conversation_id.clone(), server_result.new_epoch)
        });
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
    conversation_id: String,
    target_did: String,
) -> Result<(), JsValue> {
    let (base_url, auth_token, proxy_did) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token, s.proxy_did.clone()))
    })?;

    let input = serde_json::json!({
        "convoId": conversation_id,
        "targetDid": target_did,
    });

    let client = proxy_client(&proxy_did);
    let resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsChat.demoteAdmin",
            base_url
        ))
        .bearer_auth(&auth_token)
        .json(&input)
        .send()
        .await
        .map_err(|e| js_err!("demote_member failed: {}", e))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("demote_member failed: {}", body));
    }

    Ok(())
}

#[wasm_bindgen]
pub async fn catbird_mls_remove_participants(
    conversation_id: String,
    target_did: String,
) -> Result<(), JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;

    api_client
        .remove_members(&conversation_id, &[target_did], &[])
        .await
        .map_err(|e| js_err!("remove_group_member failed: {:?}", e))?;

    Ok(())
}

/// Leave a conversation.
#[wasm_bindgen]
pub async fn catbird_mls_leave_conversation(conversation_id: String) -> Result<(), JsValue> {
    use catbird_mls::orchestrator::api_client::MLSAPIClient;

    let api_client = with_state(|s| Ok(Arc::clone(&s.api_client)))?;

    api_client
        .leave_conversation(&conversation_id)
        .await
        .map_err(|e| js_err!("leave_conversation failed: {:?}", e))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Typing indicator
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub async fn catbird_mls_send_typing(
    conversation_id: String,
    is_typing: bool,
) -> Result<(), JsValue> {
    let (base_url, auth_token, proxy_did) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token, s.proxy_did.clone()))
    })?;

    let action_name = if is_typing { "typing" } else { "typingStop" };
    let no_op_ciphertext = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 512]);
    let input = serde_json::json!({
        "convoId": conversation_id,
        "delivery": "ephemeral",
        "action": action_name,
        "msgId": uuid::Uuid::new_v4().to_string(),
        "epoch": 0,
        "paddedSize": 512,
        "ciphertext": { "$bytes": no_op_ciphertext },
    });

    let client = proxy_client(&proxy_did);
    let resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsChat.sendMessage",
            base_url
        ))
        .bearer_auth(&auth_token)
        .json(&input)
        .send()
        .await
        .map_err(|e| js_err!("Typing update failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("Typing update failed ({}): {}", status, body));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Promote / Group metadata
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub async fn catbird_mls_promote_member(
    conversation_id: String,
    target_did: String,
) -> Result<(), JsValue> {
    let (base_url, auth_token, proxy_did) = with_state(|s| {
        let token = s
            .auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))?;
        Ok((s.base_url.clone(), token, s.proxy_did.clone()))
    })?;

    let input = serde_json::json!({
        "convoId": conversation_id,
        "targetDid": target_did,
    });

    let client = proxy_client(&proxy_did);
    let resp = client
        .post(format!(
            "{}/xrpc/blue.catbird.mlsChat.promoteAdmin",
            base_url
        ))
        .bearer_auth(&auth_token)
        .json(&input)
        .send()
        .await
        .map_err(|e| js_err!("promote_member failed: {}", e))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(js_err!("promote_member failed: {}", body));
    }

    Ok(())
}

/// Read MLS group metadata (name/description/avatar) from local state.
#[wasm_bindgen]
pub fn catbird_mls_get_group_metadata(conversation_id: String) -> Result<JsValue, JsValue> {
    let metadata = with_state(|s| {
        if let Some(ctx) = &s.mls_context {
            if let Some(gid) = decode_group_id(&conversation_id) {
                return Ok(ctx.get_group_metadata(gid));
            }
        }
        Ok(None)
    })?;

    match metadata {
        Some(m) => to_js(&serde_json::json!({
            "name": m.name,
            "description": m.description,
            "avatarBlobHash": m.avatar_hash,
        })),
        None => Ok(JsValue::NULL),
    }
}

/// Update MLS group metadata via encrypted extension.
///
/// NOTE: Full implementation requires porting group-extension commit logic to
/// `WasmMLSContext`. For now this is a stub.
#[wasm_bindgen]
pub async fn catbird_mls_update_group_metadata(
    _conversation_id: String,
    _name: Option<String>,
    _description: Option<String>,
    _avatar_hash: Option<String>,
) -> Result<(), JsValue> {
    Err(js_err!(
        "update_group_metadata is not yet supported in the browser runtime"
    ))
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

    let auth_token = with_state(|s| {
        s.auth_token
            .clone()
            .ok_or_else(|| js_err!("Not authenticated"))
    })?;

    let client = reqwest::Client::new();
    let mut url =
        reqwest::Url::parse("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfiles")
            .map_err(|e| js_err!("URL parse error: {}", e))?;

    for did in &dids {
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

    let profiles: Vec<ProfileView> = data["profiles"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|p| ProfileView {
                    did: p["did"].as_str().unwrap_or("").to_string(),
                    handle: p["handle"].as_str().unwrap_or("").to_string(),
                    display_name: p["displayName"].as_str().map(str::to_string),
                    avatar: p["avatar"].as_str().map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default();

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
        "{}/xrpc/blue.catbird.mlsChat.getOptInStatus?dids={}",
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
