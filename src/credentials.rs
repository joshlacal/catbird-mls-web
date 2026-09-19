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

    async fn direct_request_receipt_authority_document(&self) -> Result<Option<Vec<u8>>> {
        fetch_receipt_authority_document().await.map(Some)
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

/// Fetch only the configured authority. Receipt fields never choose this URL.
/// Browser redirect errors and a bounded streaming read prevent resolver pivots.
async fn fetch_receipt_authority_document() -> Result<Vec<u8>> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    fn failure(_: impl std::fmt::Debug) -> OrchestratorError {
        OrchestratorError::Credential("receipt authority document resolution failed".into())
    }
    fn field(value: &JsValue, name: &str) -> Result<JsValue> {
        js_sys::Reflect::get(value, &JsValue::from_str(name)).map_err(failure)
    }
    fn method(value: &JsValue, name: &str) -> Result<js_sys::Function> {
        field(value, name)?.dyn_into().map_err(failure)
    }
    let options = js_sys::Object::new();
    for (name, value) in [
        ("redirect", "error"),
        ("credentials", "omit"),
        ("cache", "no-store"),
        ("method", "GET"),
    ] {
        js_sys::Reflect::set(
            &options,
            &JsValue::from_str(name),
            &JsValue::from_str(value),
        )
        .map_err(failure)?;
    }
    let global = js_sys::global();
    let promise = method(&global, "fetch")?
        .call2(
            &global,
            &JsValue::from_str("https://chat.catbird.blue/.well-known/did.json"),
            &options,
        )
        .map_err(failure)?;
    let response = JsFuture::from(promise.dyn_into::<js_sys::Promise>().map_err(failure)?)
        .await
        .map_err(failure)?;
    if field(&response, "status")?.as_f64() != Some(200.0)
        || field(&response, "redirected")?.as_bool() != Some(false)
        || field(&response, "url")?.as_string().as_deref()
            != Some("https://chat.catbird.blue/.well-known/did.json")
    {
        return Err(invalid());
    }
    let stream = field(&response, "body")?;
    let reader = method(&stream, "getReader")?
        .call0(&stream)
        .map_err(failure)?;
    let read = method(&reader, "read")?;
    let mut bytes = Vec::new();
    loop {
        let promise = read
            .call0(&reader)
            .map_err(failure)?
            .dyn_into::<js_sys::Promise>()
            .map_err(failure)?;
        let chunk = JsFuture::from(promise).await.map_err(failure)?;
        if field(&chunk, "done")?.as_bool() == Some(true) {
            break;
        }
        let data = js_sys::Uint8Array::new(&field(&chunk, "value")?);
        if bytes.len().saturating_add(data.length() as usize) > 65_536 {
            let _ = method(&reader, "cancel")?.call0(&reader);
            return Err(OrchestratorError::Credential(
                "receipt authority document exceeds 64 KiB".into(),
            ));
        }
        bytes.extend(data.to_vec());
    }
    if bytes.is_empty() {
        return Err(invalid());
    }
    Ok(bytes)
}
