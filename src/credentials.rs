//! SqliteCredentialStore — implements CredentialStore using encrypted SQLite.
//!
//! Replaces the previous IndexedDB implementation. Credentials are stored in
//! the same encrypted SQLite database as all other app data, via the shared
//! `SqliteConn` from `sqlite_conn.rs`.
//!
//! # Migration Note
//!
//! No migration from the old IndexedDB database is performed. Users with
//! existing credentials in the old `*-credentials` IndexedDB will need to
//! re-login. The old IndexedDB is intentionally left in place (the browser
//! will garbage-collect it or the user can clear site data).
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS credentials (
//!     user_did        TEXT NOT NULL,
//!     credential_type TEXT NOT NULL,
//!     value           BLOB NOT NULL,
//!     PRIMARY KEY (user_did, credential_type)
//! );
//! ```
//!
//! # Security
//!
//! All credential data (signing keys, MLS DID, device UUID) is stored as
//! BLOBs in an encrypted SQLite database using sqlite3mc ChaCha20. This
//! fixes the plaintext-IndexedDB vulnerability where signing-key bytes
//! (base64-encoded), MLS DID, and device UUID were readable by any
//! same-origin script with IndexedDB access.

use crate::{
    api_client::WasmApiClient,
    browser_enrollment::{invalid, EnrollmentJournal},
    wasm_mls_context::WasmMLSContext,
};
use async_trait::async_trait;
use catbird_mls::orchestrator::credentials::CleanChatSigningAuthority;
use catbird_mls::orchestrator::credentials::CredentialStore;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::mls_provider::MlsCryptoContext;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use crate::sqlite_conn::SqliteConn;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Credential type keys stored in the `credential_type` column.
const TYPE_SIGNING_KEY: &str = "signing_key";
const TYPE_MLS_DID: &str = "mls_did";
const TYPE_DEVICE_UUID: &str = "device_uuid";

// ---------------------------------------------------------------------------
// SqliteCredentialStore
// ---------------------------------------------------------------------------

/// An implementation of [`CredentialStore`] that persists credentials in the
/// shared encrypted SQLite database, suitable for WASM environments.
pub struct SqliteCredentialStore {
    conn: Rc<SqliteConn>,
    runtime: RefCell<Option<(Arc<WasmMLSContext>, Arc<WasmApiClient>)>>,
    enrolling: Cell<bool>,
}

impl SqliteCredentialStore {
    /// Create a new credential store wrapping the shared SQLite connection.
    ///
    /// The caller must have already called [`Self::ensure_schema`] on this
    /// connection.
    pub fn new(conn: Rc<SqliteConn>) -> Self {
        Self {
            conn,
            runtime: RefCell::new(None),
            enrolling: Cell::new(false),
        }
    }

    pub fn attach_runtime(
        &self,
        context: Arc<WasmMLSContext>,
        api: Arc<WasmApiClient>,
    ) -> Result<()> {
        let mut runtime = self.runtime.borrow_mut();
        if runtime.is_some() {
            return Err(OrchestratorError::Credential(
                "credential runtime already attached".into(),
            ));
        }
        *runtime = Some((context, api));
        Ok(())
    }

    pub(crate) fn begin_enrollment(&self) -> Result<EnrollmentGuard<'_>> {
        if self.enrolling.replace(true) {
            return Err(OrchestratorError::Credential(
                "device enrollment is already in progress".into(),
            ));
        }
        Ok(EnrollmentGuard(&self.enrolling))
    }

    pub(crate) fn enrollment(&self, did: &str) -> Result<Option<EnrollmentJournal>> {
        self.get_blob(did, "verified_browser_enrollment_v1")?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(Self::cred_err))
            .transpose()
    }

    pub fn has_complete_binding(&self, did: &str) -> Result<bool> {
        Ok(self
            .enrollment(did)?
            .is_some_and(|entry| entry.auth_generation.is_some()))
    }

    pub(crate) fn has_legacy_state(&self, did: &str) -> Result<bool> {
        for kind in [TYPE_SIGNING_KEY, TYPE_MLS_DID, TYPE_DEVICE_UUID] {
            if self.get_blob(did, kind)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn save_enrollment(&self, journal: &EnrollmentJournal) -> Result<()> {
        self.put_blob(
            &journal.did,
            "verified_browser_enrollment_v1",
            &serde_json::to_vec(journal).map_err(Self::cred_err)?,
        )?;
        self.conn.ensure_durable().map_err(Self::cred_err)
    }

    /// Create the credentials table on the shared connection.
    pub fn ensure_schema(conn: &SqliteConn) -> std::result::Result<(), String> {
        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS credentials (
                user_did        TEXT NOT NULL,
                credential_type TEXT NOT NULL,
                value           BLOB NOT NULL,
                PRIMARY KEY (user_did, credential_type)
            );",
        )
        .map_err(|e| format!("credentials table: {}", e))
    }

    fn cred_err(e: impl std::fmt::Debug) -> OrchestratorError {
        OrchestratorError::Credential(format!("{:?}", e))
    }

    /// Store a credential value as a BLOB.
    fn put_blob(&self, user_did: &str, credential_type: &str, value: &[u8]) -> Result<()> {
        self.conn
            .exec_with_text_and_blob_params(
                "INSERT OR REPLACE INTO credentials (user_did, credential_type, value)
                 VALUES (?1, ?2, ?3)",
                &[(1, user_did), (2, credential_type)],
                &[(3, value)],
            )
            .map_err(Self::cred_err)
    }

    /// Retrieve a credential value as bytes.
    fn get_blob(&self, user_did: &str, credential_type: &str) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_blob(
                "SELECT value FROM credentials WHERE user_did = ?1 AND credential_type = ?2",
                &[(1, user_did), (2, credential_type)],
            )
            .map_err(Self::cred_err)
    }

    /// Delete a credential.
    fn delete_credential(&self, user_did: &str, credential_type: &str) -> Result<()> {
        self.conn
            .exec_with_text_params(
                "DELETE FROM credentials WHERE user_did = ?1 AND credential_type = ?2",
                &[(1, user_did), (2, credential_type)],
            )
            .map_err(Self::cred_err)
    }
}

// ---------------------------------------------------------------------------
// CredentialStore trait implementation
// ---------------------------------------------------------------------------

#[async_trait(?Send)]
impl CredentialStore for SqliteCredentialStore {
    async fn get_auth_generation(&self, user_did: &str) -> Result<Option<i64>> {
        Ok(self
            .enrollment(user_did)?
            .and_then(|binding| binding.auth_generation))
    }

    async fn sign_clean_chat_transcript(
        &self,
        user_did: &str,
        transcript: &[u8],
        key_id: &str,
    ) -> Result<Option<CleanChatSigningAuthority>> {
        use catbird_mls::orchestrator::api_client::MLSAPIClient;
        let (context, api) = self.runtime.borrow().clone().ok_or_else(invalid)?;
        if !api.is_authenticated_as(user_did).await {
            return Err(OrchestratorError::NotAuthenticated);
        }
        // No suspension between reading the authority tuple and using its signer.
        let binding = self.enrollment(user_did)?.ok_or_else(invalid)?;
        binding.validate_local(user_did, &context)?;
        let generation = binding.auth_generation.ok_or_else(invalid)?;
        if key_id != binding.key_id {
            return Err(invalid());
        }
        let signature = context
            .sign_with_identity_key(binding.mls_did.into_bytes(), transcript.to_vec())
            .map_err(|_| invalid())?;
        Ok(Some(CleanChatSigningAuthority {
            public_key: binding.public_key,
            signature,
            device_id: binding.device_id,
            auth_generation: Some(generation),
        }))
    }

    async fn direct_request_receipt_authority_document(
        &self,
        expected_authority_did: &str,
    ) -> Result<Option<Vec<u8>>> {
        fetch_receipt_authority_document(expected_authority_did)
            .await
            .map(Some)
    }

    async fn get_chat_declaration_authority(&self, user_did: &str) -> Result<Option<String>> {
        fetch_chat_declaration_authority(user_did).await
    }

    async fn get_authorized_device_keys(&self, root_did: &str) -> Result<Option<Vec<Vec<u8>>>> {
        use catbird_mls::orchestrator::api_client::MLSAPIClient;
        let (_, api) = self.runtime.borrow().clone().ok_or_else(invalid)?;
        if !api.is_authenticated_as(root_did).await {
            return Ok(None);
        }
        let binding = self.enrollment(root_did)?.ok_or_else(invalid)?;
        if binding.auth_generation.is_none() {
            return Err(invalid());
        }
        let devices = api.list_devices(&binding.device_id).await?;
        Ok(Some(
            devices
                .into_iter()
                .filter(|device| device.status.as_deref() == Some("active"))
                .filter_map(|device| device.signature_public_key)
                .collect(),
        ))
    }

    // -- Signing key ---------------------------------------------------------

    async fn store_signing_key(&self, user_did: &str, key_data: &[u8]) -> Result<()> {
        self.put_blob(user_did, TYPE_SIGNING_KEY, key_data)
    }

    async fn get_signing_key(&self, user_did: &str) -> Result<Option<Vec<u8>>> {
        self.get_blob(user_did, TYPE_SIGNING_KEY)
    }

    async fn delete_signing_key(&self, user_did: &str) -> Result<()> {
        self.delete_credential(user_did, TYPE_SIGNING_KEY)
    }

    // -- MLS DID -------------------------------------------------------------

    async fn store_mls_did(&self, user_did: &str, mls_did: &str) -> Result<()> {
        self.put_blob(user_did, TYPE_MLS_DID, mls_did.as_bytes())
    }

    async fn get_mls_did(&self, user_did: &str) -> Result<Option<String>> {
        if let Some(binding) = self.enrollment(user_did)? {
            return Ok(binding.auth_generation.map(|_| binding.mls_did));
        }
        let blob = self.get_blob(user_did, TYPE_MLS_DID)?;
        match blob {
            None => Ok(None),
            Some(bytes) => {
                let s = String::from_utf8(bytes)
                    .map_err(|e| OrchestratorError::Credential(format!("UTF-8 decode: {}", e)))?;
                Ok(Some(s))
            }
        }
    }

    // -- Device UUID ---------------------------------------------------------

    async fn store_device_uuid(&self, user_did: &str, uuid: &str) -> Result<()> {
        self.put_blob(user_did, TYPE_DEVICE_UUID, uuid.as_bytes())
    }

    async fn get_device_uuid(&self, user_did: &str) -> Result<Option<String>> {
        if let Some(binding) = self.enrollment(user_did)? {
            return Ok(binding.auth_generation.map(|_| binding.device_id));
        }
        let blob = self.get_blob(user_did, TYPE_DEVICE_UUID)?;
        match blob {
            None => Ok(None),
            Some(bytes) => {
                let s = String::from_utf8(bytes)
                    .map_err(|e| OrchestratorError::Credential(format!("UTF-8 decode: {}", e)))?;
                Ok(Some(s))
            }
        }
    }

    // -- Aggregate queries ---------------------------------------------------

    async fn has_credentials(&self, user_did: &str) -> Result<bool> {
        if self.enrollment(user_did)?.is_some() {
            return self.has_complete_binding(user_did);
        }
        let signing_key = self.get_blob(user_did, TYPE_SIGNING_KEY)?;
        if signing_key.is_none() {
            return Ok(false);
        }
        let mls_did = self.get_blob(user_did, TYPE_MLS_DID)?;
        if mls_did.is_none() {
            return Ok(false);
        }
        let device_uuid = self.get_blob(user_did, TYPE_DEVICE_UUID)?;
        Ok(device_uuid.is_some())
    }

    async fn clear_all(&self, user_did: &str) -> Result<()> {
        if self.enrollment(user_did)?.is_some() {
            return Err(OrchestratorError::Credential(
                "explicit device removal is required before clearing browser custody".into(),
            ));
        }
        self.conn
            .exec_with_text_params(
                "DELETE FROM credentials WHERE user_did = ?1",
                &[(1, user_did)],
            )
            .map_err(Self::cred_err)
    }
}

pub(crate) struct EnrollmentGuard<'a>(&'a Cell<bool>);
impl Drop for EnrollmentGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

/// Maximum wire bytes accepted for public authority and declaration reads (1 MiB).
const MAX_WIRE_BYTES: usize = 1_048_576;

fn failure(e: impl std::fmt::Debug) -> OrchestratorError {
    OrchestratorError::Credential(format!("browser authority resolution failed: {e:?}"))
}

fn js_field(value: &wasm_bindgen::JsValue, name: &str) -> Result<wasm_bindgen::JsValue> {
    js_sys::Reflect::get(value, &wasm_bindgen::JsValue::from_str(name)).map_err(failure)
}

fn js_method(value: &wasm_bindgen::JsValue, name: &str) -> Result<js_sys::Function> {
    use wasm_bindgen::JsCast;
    js_field(value, name)?.dyn_into().map_err(failure)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_str(s: &str) -> std::result::Result<String, ()> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(());
            }
            let hi = hex_val(bytes[i + 1]).ok_or(())?;
            let lo = hex_val(bytes[i + 2]).ok_or(())?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

fn is_safe_public_host(raw_host: &str) -> bool {
    let host = raw_host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_lowercase();
    if host.is_empty() {
        return false;
    }
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".onion")
    {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let octets = v4.octets();
                if octets[0] == 127
                    || octets == [0, 0, 0, 0]
                    || octets == [255, 255, 255, 255]
                    || (octets[0] == 169 && octets[1] == 254)
                    || (octets[0] >= 224 && octets[0] <= 239)
                    || octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
                    || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                    || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                    || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                    || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                    || octets[0] >= 240
                {
                    return false;
                }
            }
            std::net::IpAddr::V6(v6) => {
                let octets = v6.octets();
                if octets == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                    || octets == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    || octets[0] == 0xff
                    || (octets[0] & 0xfe) == 0xfc
                    || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
                {
                    return false;
                }
                if octets[0..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
                    let v4_octets = [octets[12], octets[13], octets[14], octets[15]];
                    if v4_octets[0] == 127
                        || v4_octets == [0, 0, 0, 0]
                        || v4_octets == [255, 255, 255, 255]
                        || (v4_octets[0] == 169 && v4_octets[1] == 254)
                        || (v4_octets[0] >= 224 && v4_octets[0] <= 239)
                        || v4_octets[0] == 10
                        || (v4_octets[0] == 172 && (16..=31).contains(&v4_octets[1]))
                        || (v4_octets[0] == 192 && v4_octets[1] == 168)
                        || (v4_octets[0] == 192 && v4_octets[1] == 0 && v4_octets[2] == 2)
                        || (v4_octets[0] == 198 && (v4_octets[1] == 18 || v4_octets[1] == 19))
                        || (v4_octets[0] == 198 && v4_octets[1] == 51 && v4_octets[2] == 100)
                        || (v4_octets[0] == 203 && v4_octets[1] == 0 && v4_octets[2] == 113)
                        || v4_octets[0] >= 240
                    {
                        return false;
                    }
                }
            }
        }
    }
    true
}

fn did_web_to_document_url(did: &str) -> Result<String> {
    if did.contains('#') || did.contains('?') || did.contains('@') {
        return Err(OrchestratorError::Credential("invalid did:web syntax".into()));
    }
    let method_specific = did
        .strip_prefix("did:web:")
        .ok_or_else(|| OrchestratorError::Credential("expected did:web identifier".into()))?;
    let parts: Vec<&str> = method_specific.split(':').collect();
    if parts.is_empty() || parts[0].is_empty() {
        return Err(OrchestratorError::Credential("empty authority in did:web".into()));
    }
    let raw_authority = parts[0];
    let (raw_host, port) = if let Some(idx) = raw_authority.to_lowercase().find("%3a") {
        let h = &raw_authority[..idx];
        let p_str = &raw_authority[idx + 3..];
        let p: u16 = p_str
            .parse()
            .map_err(|_| OrchestratorError::Credential("invalid port in did:web".into()))?;
        if p == 0 {
            return Err(OrchestratorError::Credential("invalid port 0 in did:web".into()));
        }
        (h, Some(p))
    } else {
        (raw_authority, None)
    };

    if raw_host.is_empty()
        || raw_host.contains('%')
        || raw_host.contains('/')
        || raw_host.contains('?')
        || raw_host.contains('#')
        || raw_host.contains('\\')
        || raw_host.contains('@')
    {
        return Err(OrchestratorError::Credential("invalid host in did:web".into()));
    }
    if !is_safe_public_host(raw_host) {
        return Err(OrchestratorError::Credential(
            "unsafe host in did:web identifier".into(),
        ));
    }

    let mut path_segments = Vec::new();
    for seg in &parts[1..] {
        if seg.is_empty()
            || *seg == "."
            || *seg == ".."
            || seg.contains('/')
            || seg.contains('\\')
            || seg.contains('?')
            || seg.contains('#')
        {
            return Err(OrchestratorError::Credential("invalid path segment in did:web".into()));
        }
        let decoded = percent_decode_str(seg)
            .map_err(|_| OrchestratorError::Credential("invalid percent encoding in did:web".into()))?;
        if decoded.is_empty()
            || decoded == "."
            || decoded == ".."
            || decoded.contains('/')
            || decoded.contains('\\')
        {
            return Err(OrchestratorError::Credential("illegal path segment in did:web".into()));
        }
        path_segments.push(*seg);
    }

    let path = if path_segments.is_empty() {
        "/.well-known/did.json".to_string()
     } else {
        format!("/{}/did.json", path_segments.join("/"))
    };

    if let Some(p) = port {
        Ok(format!("https://{raw_host}:{p}{path}"))
    } else {
        Ok(format!("https://{raw_host}{path}"))
    }
}

fn is_valid_bare_did(did: &str) -> bool {
    if !did.starts_with("did:") || did.len() < 7 || did.len() > 512 {
        return false;
    }
    if did.contains('#')
        || did.contains('?')
        || did.contains('/')
        || did.contains('@')
        || did.contains(' ')
        || did.contains('\\')
    {
        return false;
    }
    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() < 3 {
        return false;
    }
    let method = parts[1];
    if method.is_empty()
        || !method.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return false;
    }
    for part in &parts[2..] {
        if part.is_empty() {
            return false;
        }
    }
    true
}

fn did_to_document_url(did: &str) -> Result<String> {
    if did.starts_with("did:web:") {
        did_web_to_document_url(did)
    } else if did.starts_with("did:plc:") {
        if did.contains('#') || did.contains('?') || did.contains('/') || did.contains('@') {
            return Err(OrchestratorError::Credential("invalid did:plc syntax".into()));
        }
        let specific = &did["did:plc:".len()..];
        if specific.is_empty() || !specific.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(OrchestratorError::Credential(
                "invalid did:plc identifier characters".into(),
            ));
        }
        Ok(format!("https://plc.directory/{did}"))
    } else {
        Err(OrchestratorError::Credential(format!(
            "unsupported DID method for resolution: {did}"
        )))
    }
}

fn normalize_endpoint(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        if let Some(slash_idx) = rest.find('/') {
            let host_port = &rest[..slash_idx];
            let path = &rest[slash_idx..];
            if let Some(host) = host_port.strip_suffix(":443") {
                return format!("https://{host}{path}");
            }
        } else if let Some(host) = rest.strip_suffix(":443") {
            return format!("https://{host}");
        }
    }
    url.to_string()
}

fn endpoints_match(actual: &str, expected: &str) -> bool {
    normalize_endpoint(actual) == normalize_endpoint(expected)
}

fn validate_pds_endpoint(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let rest = trimmed.strip_prefix("https://").ok_or_else(|| {
        OrchestratorError::Credential("PDS serviceEndpoint must use https scheme".into())
    })?;
    if rest.contains('?') || rest.contains('#') || rest.contains('@') {
        return Err(OrchestratorError::Credential(
            "PDS serviceEndpoint must not contain query, fragment, or credentials".into(),
        ));
    }
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].trim_end_matches('/')),
        None => (rest, ""),
    };
    let (host, port) = if let Some(colon_idx) = authority.find(':') {
        let h = &authority[..colon_idx];
        let p_str = &authority[colon_idx + 1..];
        let p: u16 = p_str
            .parse()
            .map_err(|_| OrchestratorError::Credential("invalid port in PDS endpoint".into()))?;
        if p == 0 {
            return Err(OrchestratorError::Credential("invalid port 0 in PDS endpoint".into()));
        }
        (h, Some(p))
    } else {
        (authority, None)
    };
    if host.is_empty() || !is_safe_public_host(host) {
        return Err(OrchestratorError::Credential(
            "PDS serviceEndpoint host is unsafe or invalid".into(),
        ));
    }
    if let Some(p) = port {
        Ok(format!("https://{host}:{p}{path}"))
    } else {
        Ok(format!("https://{host}{path}"))
    }
}

async fn safe_browser_fetch(url: &str) -> Result<(u16, Vec<u8>)> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let options = js_sys::Object::new();
    for (name, value) in [
        ("redirect", "error"),
        ("credentials", "omit"),
        ("cache", "no-store"),
        ("method", "GET"),
    ] {
        js_sys::Reflect::set(
            &options,
            &wasm_bindgen::JsValue::from_str(name),
            &wasm_bindgen::JsValue::from_str(value),
        )
        .map_err(failure)?;
    }
    let headers = js_sys::Object::new();
    js_sys::Reflect::set(
        &headers,
        &wasm_bindgen::JsValue::from_str("Accept"),
        &wasm_bindgen::JsValue::from_str("application/json"),
    )
    .map_err(failure)?;
    js_sys::Reflect::set(
        &options,
        &wasm_bindgen::JsValue::from_str("headers"),
        &headers,
    )
    .map_err(failure)?;

    let global = js_sys::global();
    let promise = js_method(&global, "fetch")?
        .call2(&global, &wasm_bindgen::JsValue::from_str(url), &options)
        .map_err(failure)?;
    let response = JsFuture::from(promise.dyn_into::<js_sys::Promise>().map_err(failure)?)
        .await
        .map_err(failure)?;

    let redirected = js_field(&response, "redirected")?
        .as_bool()
        .unwrap_or(false);
    if redirected {
        return Err(OrchestratorError::Credential("redirects are prohibited".into()));
    }

    if let Some(resp_url) = js_field(&response, "url")?.as_string() {
        if !resp_url.is_empty() && !endpoints_match(&resp_url, url) {
            return Err(OrchestratorError::Credential(format!(
                "response url mismatch: requested {url}, got {resp_url}"
            )));
        }
    }

    let status = js_field(&response, "status")?
        .as_f64()
        .unwrap_or(0.0) as u16;

    let stream = js_field(&response, "body")?;
    if stream.is_undefined() || stream.is_null() {
        return Ok((status, Vec::new()));
    }

    let reader = js_method(&stream, "getReader")?
        .call0(&stream)
        .map_err(failure)?;
    let read = js_method(&reader, "read")?;
    let mut bytes = Vec::new();
    loop {
        let promise = read
            .call0(&reader)
            .map_err(failure)?
            .dyn_into::<js_sys::Promise>()
            .map_err(failure)?;
        let chunk = JsFuture::from(promise).await.map_err(failure)?;
        if js_field(&chunk, "done")?.as_bool() == Some(true) {
            break;
        }
        let data = js_sys::Uint8Array::new(&js_field(&chunk, "value")?);
        if bytes.len().saturating_add(data.length() as usize) > MAX_WIRE_BYTES {
            let _ = js_method(&reader, "cancel")?.call0(&reader);
            return Err(OrchestratorError::Credential(
                "response exceeds 1 MiB limit".into(),
            ));
        }
        bytes.extend(data.to_vec());
    }

    Ok((status, bytes))
}

/// Resolve only the expected coordinator DID document. Never a receipt-supplied URL.
async fn fetch_receipt_authority_document(expected_authority_did: &str) -> Result<Vec<u8>> {
    if !expected_authority_did.starts_with("did:web:")
        || expected_authority_did.contains('#')
        || expected_authority_did.contains('?')
    {
        return Err(OrchestratorError::Credential(
            "receipt authority must be a bare did:web identifier".into(),
        ));
    }
    let url = did_web_to_document_url(expected_authority_did)?;
    let (status, bytes) = safe_browser_fetch(&url).await?;
    if status != 200 || bytes.is_empty() {
        return Err(OrchestratorError::Credential(format!(
            "receipt authority resolution failed with status {status}"
        )));
    }
    let doc: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        OrchestratorError::Credential(format!("receipt authority document JSON invalid: {e}"))
    })?;
    let id = doc.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
        OrchestratorError::Credential("receipt authority document missing id".into())
    })?;
    if id != expected_authority_did {
        return Err(OrchestratorError::Credential(format!(
            "receipt authority document id mismatch: expected {expected_authority_did}, got {id}"
        )));
    }
    Ok(bytes)
}

/// Resolve verified account-home chat declaration for a user DID from authenticated PDS.
async fn fetch_chat_declaration_authority(user_did: &str) -> Result<Option<String>> {
    if !is_valid_bare_did(user_did) {
        return Err(OrchestratorError::Credential("invalid bare user DID".into()));
    }
    let did_doc_url = did_to_document_url(user_did)?;
    let (status, bytes) = safe_browser_fetch(&did_doc_url).await?;
    if status != 200 || bytes.is_empty() {
        return Err(OrchestratorError::Credential(format!(
            "user DID document resolution failed with status {status}"
        )));
    }
    let doc: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        OrchestratorError::Credential(format!("user DID document JSON invalid: {e}"))
    })?;
    let id = doc.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
        OrchestratorError::Credential("user DID document missing id".into())
    })?;
    if id != user_did {
        return Err(OrchestratorError::Credential(format!(
            "user DID document id mismatch: expected {user_did}, got {id}"
        )));
    }

    let services = doc
        .get("service")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            OrchestratorError::Credential("user DID document missing service array".into())
        })?;

    let pds_services: Vec<&serde_json::Value> = services
        .iter()
        .filter(|s| {
            let s_id = s.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let s_type = s.get("type").and_then(|v| v.as_str()).unwrap_or("");
            (s_id == "#atproto_pds" || s_id == format!("{user_did}#atproto_pds"))
                && s_type == "AtprotoPersonalDataServer"
        })
        .collect();

    if pds_services.len() != 1 {
        return Err(OrchestratorError::Credential(format!(
            "user DID document must contain exactly one #atproto_pds service, found {}",
            pds_services.len()
        )));
    }

    let raw_endpoint = pds_services[0]
        .get("serviceEndpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            OrchestratorError::Credential("missing serviceEndpoint in #atproto_pds".into())
        })?;

    let pds_endpoint = validate_pds_endpoint(raw_endpoint)?;

    let record_url = format!(
        "{pds_endpoint}/xrpc/com.atproto.repo.getRecord?repo={user_did}&collection=blue.catbird.chat.declaration&rkey=self"
    );
    let (rec_status, rec_bytes) = safe_browser_fetch(&record_url).await?;

    if rec_status == 400 || rec_status == 404 {
        let err_body: serde_json::Value = serde_json::from_slice(&rec_bytes).map_err(|_| {
            OrchestratorError::Credential(format!(
                "PDS getRecord returned status {rec_status} with non-JSON body"
            ))
        })?;
        if err_body.get("error").and_then(|v| v.as_str()) == Some("RecordNotFound") {
            return Ok(None);
        }
        return Err(OrchestratorError::Credential(format!(
            "PDS getRecord returned error: {err_body}"
        )));
    }

    if rec_status != 200 {
        return Err(OrchestratorError::Credential(format!(
            "PDS getRecord returned status {rec_status}"
        )));
    }

    let record_envelope: serde_json::Value = serde_json::from_slice(&rec_bytes).map_err(|e| {
        OrchestratorError::Credential(format!("declaration record JSON invalid: {e}"))
    })?;

    let expected_uri = format!("at://{user_did}/blue.catbird.chat.declaration/self");
    if record_envelope.get("uri").and_then(|v| v.as_str()) != Some(&expected_uri) {
        return Err(OrchestratorError::Credential(
            "declaration record uri does not match expected canonical at-uri".into(),
        ));
    }

    let val = record_envelope
        .get("value")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            OrchestratorError::Credential("declaration record missing value object".into())
        })?;

    if val.get("$type").and_then(|v| v.as_str()) != Some("blue.catbird.chat.declaration") {
        return Err(OrchestratorError::Credential(
            "declaration record $type mismatch".into(),
        ));
    }

    if val.get("protocolVersion").and_then(|v| v.as_str()) != Some("1") {
        return Err(OrchestratorError::Credential(
            "declaration record protocolVersion must be 1".into(),
        ));
    }

    let delivery_service = val
        .get("deliveryService")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            OrchestratorError::Credential("declaration record missing deliveryService".into())
        })?;

    if !is_valid_bare_did(delivery_service) {
        return Err(OrchestratorError::Credential(format!(
            "declaration record deliveryService is not a valid bare DID: {delivery_service}"
        )));
    }

    Ok(Some(delivery_service.to_string()))
}
