//! WasmMLSContext — implements `MlsCryptoContext` for WASM targets.
//!
//! Combines `openmls_libcrux_crypto` (post-quantum crypto) with
//! `WasmSqliteStorage` (OPFS SAH VFS, sqlite3mc encrypted) to give a
//! fully in-browser OpenMLS stack.
//!
//! # Threading model
//!
//! WASM is single-threaded. All mutable state lives in `RefCell` rather
//! than `Mutex`. The `MlsCryptoContextBounds` supertrait removes the
//! `Send + Sync` requirement on WASM, so this compiles cleanly.
//!
//! # Persistence
//!
//! Groups and signing keys are persisted to `WasmSqliteStorage` by
//! OpenMLS itself (via the `StorageProvider` trait). The `RefCell` caches
//! only keep recently used objects in memory for performance.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use base64::Engine as _;
use openmls::component::ComponentData;
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCrypto;
use openmls_traits::OpenMlsProvider;

use catbird_mls::orchestrator::mls_provider::{
    IncomingCommitMergeOutcome, MlsCryptoContext, MlsDecryptOutcome,
};
use catbird_mls::{
    AddMembersResult, CredentialData, DecryptResult, EncryptResult, ExternalCommitResult,
    GroupConfig, GroupCreationResult, KeyPackageData, KeyPackageResult, MLSError, WelcomeResult,
};

use crate::mls_storage::WasmSqliteStorage;
use crate::sqlite_conn::SqliteConn;
use catbird_mls::orchestrator::direct_request_bootstrap::DirectRequestBootstrapInput;
use catbird_mls::orchestrator::direct_request_journal::{
    DirectRequestJournal, DirectRequestJournalPhase,
};

impl From<crate::sqlite_conn::WasmSqliteError> for MLSError {
    fn from(_: crate::sqlite_conn::WasmSqliteError) -> Self {
        MLSError::StorageError
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const BUCKET_SIZES: [usize; 5] = [512, 1024, 2048, 4096, 8192];

/// The delivery service validates every KeyPackage leaf against a closed
/// "clean leaf" profile: MLS 1.0 only, the XWING suite only, no extensions, no
/// proposals, Basic credentials only (`mls-ds/server/src/chat_protocol/wire.rs`
/// `validate_clean_leaf_shape`). OpenMLS' default `Capabilities` advertises
/// every version/suite, so the profile must be set explicitly — the native
/// key-package paths do the same (`catbird-mls/src/api.rs`,
/// `orchestrator/direct_request_shared_crypto.rs`).
fn clean_leaf_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

/// Fresh 29-day key-package lifetime starting one minute in the past, matching
/// the native request package builder and the service's remaining-lifetime and
/// maximum-lifetime bounds.
fn key_package_lifetime() -> Result<Lifetime, MLSError> {
    let now = chrono::Utc::now().timestamp();
    if now < 0 {
        return Err(MLSError::OpenMLS("system clock before epoch".into()));
    }
    let now = now as u64;
    Ok(Lifetime::init(now.saturating_sub(60), now + 29 * 86400))
}

// ---------------------------------------------------------------------------
// OpenMLS provider: LibcruxCrypto + WasmSqliteStorage
// ---------------------------------------------------------------------------

pub struct WasmOpenMlsProvider {
    crypto: LibcruxCrypto,
    storage: WasmSqliteStorage,
}

impl OpenMlsProvider for WasmOpenMlsProvider {
    type CryptoProvider = LibcruxCrypto;
    type RandProvider = LibcruxCrypto;
    type StorageProvider = WasmSqliteStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

// ---------------------------------------------------------------------------
// WasmMLSContext
// ---------------------------------------------------------------------------

/// MLS crypto context backed by WASM-compatible storage and crypto.
///
/// Owns the OpenMLS provider and caches in-memory group + signer state.
pub struct WasmMLSContext {
    provider: WasmOpenMlsProvider,
    /// Cached in-memory groups: group_id bytes → MlsGroup.
    groups: RefCell<HashMap<Vec<u8>, MlsGroup>>,
    /// Cached signing keys: identity bytes → SignatureKeyPair.
    signers: RefCell<HashMap<Vec<u8>, Rc<SignatureKeyPair>>>,
    /// Task #56: receiver-side staged commits awaiting explicit merge.
    ///
    /// Keyed by `(group_id, target_epoch)`. Populated by `decrypt_message`
    /// when a `StagedCommitMessage` is received; drained by
    /// `merge_incoming_commit` (applies the commit and advances the local
    /// epoch) or `discard_incoming_commit` (drops the entry, epoch is left
    /// unchanged).
    ///
    /// Mirrors the `MLSContext::pending_incoming_merges` map in
    /// `catbird-mls/src/api.rs` (task #33) so that the WASM client matches
    /// the explicit stage/merge contract rather than auto-merging inside
    /// `decrypt_message`.
    pending_incoming_merges: RefCell<HashMap<(Vec<u8>, u64), StagedCommit>>,
    /// Field-level encryption: cached content root key for the current
    /// user (32 bytes). Populated by `set_content_root_key`, cleared on
    /// logout. Used by `encrypt_message_payload` / `decrypt_message_payload`
    /// / `compute_message_hmac` / `verify_message_hmac` which delegate to
    /// `catbird_mls::field_encryption`. In-memory only — persistence is
    /// owned by the platform layer (Task 23, storage.rs).
    content_root_key: RefCell<Option<Vec<u8>>>,
}

mod direct_requests;
mod own_echo;

impl WasmMLSContext {
    /// Open (or create) the MLS SQLite database as a standalone database.
    ///
    /// Prefer [`Self::open_with_conn`] when sharing the database with other
    /// stores (conversation storage, credentials).
    ///
    /// * `db_path` — path for the SQLite file (OPFS path in a Worker).
    /// * `encryption_key` — hex-encoded 256-bit key for sqlite3mc.
    pub fn open(db_path: &str, encryption_key: &str) -> Result<Self, MLSError> {
        let storage = WasmSqliteStorage::open(db_path, encryption_key)
            .map_err(|e| MLSError::invalid_input(format!("WasmSqliteStorage::open: {e}")))?;

        Self::ensure_request_schema(storage.conn())?;
        let crypto = LibcruxCrypto::new()
            .map_err(|e| MLSError::OpenMLS(format!("LibcruxCrypto::new: {e:?}")))?;
        let context = Self {
            provider: WasmOpenMlsProvider { crypto, storage },
            groups: RefCell::new(HashMap::new()),
            signers: RefCell::new(HashMap::new()),
            pending_incoming_merges: RefCell::new(HashMap::new()),
            content_root_key: RefCell::new(None),
        };
        context.validate_request_custody()?;
        Ok(context)
    }

    /// Open using a shared [`SqliteConn`].
    ///
    /// The caller must have already called [`WasmSqliteStorage::ensure_schema`]
    /// on the connection. Used by `catbird_mls_init` to share a single encrypted
    /// database across OpenMLS state, conversation storage, and credentials.
    pub fn open_with_conn(conn: Rc<SqliteConn>) -> Result<Self, MLSError> {
        let storage = WasmSqliteStorage::new(conn);

        Self::ensure_request_schema(storage.conn())?;
        let crypto = LibcruxCrypto::new()
            .map_err(|e| MLSError::OpenMLS(format!("LibcruxCrypto::new: {e:?}")))?;
        let context = Self {
            provider: WasmOpenMlsProvider { crypto, storage },
            groups: RefCell::new(HashMap::new()),
            signers: RefCell::new(HashMap::new()),
            pending_incoming_merges: RefCell::new(HashMap::new()),
            content_root_key: RefCell::new(None),
        };
        context.validate_request_custody()?;
        Ok(context)
    }

    fn ensure_request_schema(conn: &SqliteConn) -> Result<(), MLSError> {
        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS direct_request_journal_v2 (
            request_id TEXT PRIMARY KEY, group_id TEXT NOT NULL UNIQUE,
            record_json TEXT NOT NULL
        )",
        )?;
        Self::ensure_request_custody_schema(conn)?;
        Ok(())
    }

    pub(crate) fn list_direct_request_journal(
        &self,
    ) -> Result<Vec<DirectRequestJournal>, MLSError> {
        self.provider
            .storage()
            .conn()
            .query_text(
                "SELECT record_json FROM direct_request_journal_v2 ORDER BY request_id",
                &[],
                1,
            )?
            .into_iter()
            .map(|row| {
                let record: DirectRequestJournal =
                    serde_json::from_str(row[0].as_deref().ok_or(MLSError::StorageError)?)
                        .map_err(|_| MLSError::StorageError)?;
                record.validate()?;
                Ok(record)
            })
            .collect()
    }

    /// Shared bootstrap crypto and its unpublished ownership journal commit in
    /// one encrypted transaction. Never inserts into live cache/projection.
    pub(crate) fn prepare_direct_request_bootstrap(
        &self,
        input: &DirectRequestBootstrapInput,
    ) -> Result<DirectRequestJournal, MLSError> {
        let (context, _) =
            catbird_mls::orchestrator::direct_request_bootstrap::context(&input.context_json)?;
        let request_id = context["requestId"]
            .as_str()
            .ok_or_else(|| MLSError::invalid_input("request ID missing"))?;
        let identity = format!(
            "{}#{}",
            context["actorDid"]
                .as_str()
                .ok_or(MLSError::SerializationError)?,
            context["actorDeviceId"]
                .as_str()
                .ok_or(MLSError::SerializationError)?
        );
        let signer = self.existing_signer(identity.as_bytes())?;
        let conn = self.provider.storage().conn();
        let record=conn.transaction(|| -> Result<DirectRequestJournal, MLSError> {
            for record in self.list_direct_request_journal()? {
                if record.request_id == request_id {
                    if record.input_sha256 != DirectRequestJournal::input_digest(input)? {
                        return Err(MLSError::invalid_input("request identity already binds different input"));
                    }
                    return Ok(record);
                }
            }
            if MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&input.group_id))
                .map_err(|_| MLSError::StorageError)?.is_some() {
                return Err(MLSError::invalid_input("bootstrap group already exists"));
            }
            let now = u64::try_from(chrono::Utc::now().timestamp()).map_err(|_| MLSError::SerializationError)?;
            let (_unpublished_group, bootstrap) = catbird_mls::orchestrator::direct_request_bootstrap::prepare_with_provider(
                &self.provider, signer.as_ref(), input, now,
            )?;
            let record = DirectRequestJournal::from_prepared(input, bootstrap.clone())?;
            record.validate()?;
            let json = serde_json::to_string(&record).map_err(|_| MLSError::SerializationError)?;
            conn.exec_with_text_params(
                "INSERT INTO direct_request_journal_v2(request_id, group_id, record_json) VALUES(?1, ?2, ?3)",
                &[(1, request_id), (2, &hex::encode(&input.group_id)), (3, &json)],
            )?;
            Ok(record)
        })?;
        conn.ensure_durable()?;
        Ok(record)
    }

    fn require_published_group(&self, group_id: &[u8]) -> Result<(), MLSError> {
        let rows = self.provider.storage().conn().query_text(
            "SELECT record_json FROM direct_request_journal_v2 WHERE group_id = ?1",
            &[(1, &hex::encode(group_id))],
            1,
        )?;
        if let Some(row) = rows.first() {
            let record: DirectRequestJournal =
                serde_json::from_str(row[0].as_deref().ok_or(MLSError::StorageError)?)
                    .map_err(|_| MLSError::StorageError)?;
            record.validate()?;
            if !matches!(
                record.phase,
                DirectRequestJournalPhase::PublishedAwaitingProjection
                    | DirectRequestJournalPhase::RequestSent
            ) {
                return Err(MLSError::OperationNotSupported {
                    reason: "request group is unpublished".into(),
                });
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: signer helpers
    // -----------------------------------------------------------------------

    /// Get or create an Ed25519 `SignatureKeyPair` for `identity_bytes`.
    ///
    /// Creates a new pair on first call, persists it via `StorageProvider`,
    /// and caches it in `self.signers`.
    fn get_or_create_signer(
        &self,
        identity_bytes: &[u8],
    ) -> Result<Rc<SignatureKeyPair>, MLSError> {
        if let Some(s) = self.signers.borrow().get(identity_bytes) {
            return Ok(s.clone());
        }

        let conn = self.provider.storage().conn();
        let mapping_key = [b"catbird.browser.identity.v1\0".as_slice(), identity_bytes].concat();
        if let Some(public_key) = conn.get(&mapping_key).map_err(|_| MLSError::StorageError)? {
            let signer = SignatureKeyPair::read(
                self.provider.storage(),
                &public_key,
                SignatureScheme::ED25519,
            )
            .ok_or(MLSError::StorageError)?;
            let signer = Rc::new(signer);
            self.signers
                .borrow_mut()
                .insert(identity_bytes.to_vec(), Rc::clone(&signer));
            return Ok(signer);
        }

        let signer = SignatureKeyPair::new(SignatureScheme::ED25519)
            .map_err(|e| MLSError::OpenMLS(format!("SignatureKeyPair::new: {e:?}")))?;

        conn.transaction(|| -> Result<(), crate::sqlite_conn::WasmSqliteError> {
            signer.store(self.provider.storage())?;
            conn.put(&mapping_key, signer.public())
        })
        .map_err(|_| MLSError::StorageError)?;

        let signer = Rc::new(signer);
        let result = Rc::clone(&signer);
        self.signers
            .borrow_mut()
            .insert(identity_bytes.to_vec(), signer);
        Ok(result)
    }

    /// Load the signing key for a group's own leaf from storage (or cache).
    ///
    /// Called inside methods that hold `&mut MlsGroup` — `group` is passed
    /// by reference so we can extract the identity/pubkey before the borrow
    /// overlaps with the `signers` RefCell.
    fn signer_from_identity(
        &self,
        identity: Vec<u8>,
        pub_key: Vec<u8>,
    ) -> Result<Rc<SignatureKeyPair>, MLSError> {
        if let Some(s) = self.signers.borrow().get(&identity) {
            if s.public() == pub_key.as_slice() {
                return Ok(Rc::clone(s));
            }
        }

        let s = SignatureKeyPair::read(self.provider.storage(), &pub_key, SignatureScheme::ED25519)
            .ok_or_else(|| {
                MLSError::invalid_input(
                    "signing key not found in storage — re-initialise the context",
                )
            })?;

        let s = Rc::new(s);
        self.signers.borrow_mut().insert(identity, Rc::clone(&s));
        Ok(s)
    }

    fn existing_signer(&self, identity: &[u8]) -> Result<Rc<SignatureKeyPair>, MLSError> {
        if let Some(signer) = self.signers.borrow().get(identity) {
            return Ok(Rc::clone(signer));
        }
        let key = [b"catbird.browser.identity.v1\0".as_slice(), identity].concat();
        let public_key = self
            .provider
            .storage()
            .conn()
            .get(&key)
            .map_err(|_| MLSError::StorageError)?
            .ok_or_else(|| MLSError::invalid_input("identity is not enrolled"))?;
        self.signer_from_identity(identity.to_vec(), public_key)
    }

    // -----------------------------------------------------------------------
    // Internal: group config builders
    // -----------------------------------------------------------------------

    fn make_create_config(config: &GroupConfig) -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .max_past_epochs(config.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                config.out_of_order_tolerance,
                config.maximum_forward_distance,
            ))
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build()
    }

    fn make_join_config(config: &GroupConfig) -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(config.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                config.out_of_order_tolerance,
                config.maximum_forward_distance,
            ))
            .use_ratchet_tree_extension(true)
            .build()
    }

    fn default_config() -> GroupConfig {
        GroupConfig::default()
    }

    // -----------------------------------------------------------------------
    // Internal: load group from storage into cache
    // -----------------------------------------------------------------------

    /// Try to load a persisted group into the in-memory cache.
    ///
    /// Returns `Ok(true)` if the group was found and loaded (or was already
    /// cached), `Ok(false)` if the group does not exist in OpenMLS storage.
    ///
    /// Unlike [`Self::ensure_loaded`], this does NOT return an error when the
    /// group is missing — callers (such as startup group reload) can distinguish
    /// "missing" from "load error" and log appropriately.
    pub fn ensure_group_loaded(&self, group_id: &[u8]) -> Result<bool, MLSError> {
        self.require_published_group(group_id)?;
        if self.groups.borrow().contains_key(group_id) {
            return Ok(true);
        }

        let gid = GroupId::from_slice(group_id);
        match MlsGroup::load(self.provider.storage(), &gid) {
            Ok(Some(group)) => {
                self.groups.borrow_mut().insert(group_id.to_vec(), group);
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(e) => Err(MLSError::OpenMLS(format!("MlsGroup::load: {e:?}"))),
        }
    }

    /// Ensure the group is in the in-memory cache, loading from OpenMLS
    /// storage if necessary.
    fn ensure_loaded(&self, group_id: &[u8]) -> Result<(), MLSError> {
        self.require_published_group(group_id)?;
        if self.groups.borrow().contains_key(group_id) {
            return Ok(());
        }

        let gid = GroupId::from_slice(group_id);
        let group = MlsGroup::load(self.provider.storage(), &gid)
            .map_err(|e| MLSError::OpenMLS(format!("MlsGroup::load: {e:?}")))?
            .ok_or_else(|| {
                MLSError::group_not_found(format!(
                    "group {} not found in storage",
                    base64::engine::general_purpose::STANDARD.encode(group_id),
                ))
            })?;

        self.groups.borrow_mut().insert(group_id.to_vec(), group);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Padding — must match catbird-mls/src/api.rs exactly.
//
// Format: [4-byte big-endian length][MLS ciphertext][zero padding → bucket]
// ---------------------------------------------------------------------------

fn pad_ciphertext(ciphertext: &[u8]) -> (Vec<u8>, u32) {
    let actual_len = ciphertext.len();
    let total_needed = 4 + actual_len;
    let bucket = BUCKET_SIZES
        .iter()
        .copied()
        .find(|&b| b >= total_needed)
        .unwrap_or_else(|| total_needed.div_ceil(8192) * 8192);

    let mut padded = Vec::with_capacity(bucket);
    padded.extend_from_slice(&(actual_len as u32).to_be_bytes());
    padded.extend_from_slice(ciphertext);
    padded.resize(bucket, 0);
    (padded, bucket as u32)
}

fn strip_padding(data: &[u8]) -> &[u8] {
    if data.len() < 5 {
        return data;
    }
    let claimed_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if claimed_len > 0 && claimed_len <= data.len() - 4 && matches!(data[4], 0x00..=0x04) {
        &data[4..4 + claimed_len]
    } else {
        data
    }
}

// ---------------------------------------------------------------------------
// MlsCryptoContext implementation
// ---------------------------------------------------------------------------

impl WasmMLSContext {
    // ------------------------------------------------------------------
    // Group lifecycle
    // ------------------------------------------------------------------

    pub(crate) fn create_group(
        &self,
        identity_bytes: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        let config = config.unwrap_or_else(Self::default_config);
        let signer = self.get_or_create_signer(&identity_bytes)?;

        let credential = BasicCredential::new(identity_bytes.clone());
        let cred_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let group_config = Self::make_create_config(&config);
        let group = MlsGroup::new(
            &self.provider,
            signer.as_ref(),
            &group_config,
            cred_with_key,
        )
        .map_err(|e| MLSError::OpenMLS(format!("MlsGroup::new: {e:?}")))?;

        let group_id = group.group_id().as_slice().to_vec();
        self.groups.borrow_mut().insert(group_id.clone(), group);

        Ok(GroupCreationResult {
            group_id,
            encrypted_metadata_blob: None,
            metadata_reference_json: None,
            metadata_blob_locator: None,
        })
    }

    /// Create an MLS group at a **predetermined** `group_id` (RFC 9420 §11
    /// `MlsGroup::new_with_group_id`). Used by the first-responder bootstrap
    /// path (spec §8.5 / Phase 1) where every member must land on the same
    /// `groupId` published by the server's `groupResetEvent`.
    ///
    /// `group_id` is the raw bytes of the target MLS group identifier (NOT
    /// hex-encoded). Mirrors the native `MLSContext::create_group_with_id`
    /// (`catbird-mls/src/mls_context.rs:1922`).
    pub(crate) fn create_group_with_id(
        &self,
        identity_bytes: Vec<u8>,
        group_id: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        self.require_published_group(&group_id)?;
        if MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&group_id))
            .map_err(|_| MLSError::StorageError)?
            .is_some()
        {
            return Err(MLSError::invalid_input("group already exists"));
        }
        let config = config.unwrap_or_else(Self::default_config);
        let signer = self.get_or_create_signer(&identity_bytes)?;

        let credential = BasicCredential::new(identity_bytes.clone());
        let cred_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let group_config = Self::make_create_config(&config);
        let openmls_group_id = openmls::prelude::GroupId::from_slice(&group_id);
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            signer.as_ref(),
            &group_config,
            openmls_group_id,
            cred_with_key,
        )
        .map_err(|e| MLSError::OpenMLS(format!("MlsGroup::new_with_group_id: {e:?}")))?;

        let stored_group_id = group.group_id().as_slice().to_vec();
        self.groups
            .borrow_mut()
            .insert(stored_group_id.clone(), group);

        Ok(GroupCreationResult {
            group_id: stored_group_id,
            encrypted_metadata_blob: None,
            metadata_reference_json: None,
            metadata_blob_locator: None,
        })
    }

    pub(crate) fn delete_group(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        if self.retire_request_group(&group_id)? {
            return Ok(());
        }
        if !self.ensure_group_loaded(&group_id)? {
            return Ok(());
        }
        let mut groups = self.groups.borrow_mut();
        groups
            .get_mut(&group_id)
            .expect("group loaded")
            .delete(self.provider.storage())
            .map_err(|_| MLSError::StorageError)?;
        groups.remove(&group_id);
        self.pending_incoming_merges
            .borrow_mut()
            .retain(|(id, _), _| id != &group_id);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Member management
    // ------------------------------------------------------------------

    pub(crate) fn add_members(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, MLSError> {
        // Deserialize + validate incoming key packages.
        let kps: Vec<KeyPackage> = key_packages
            .iter()
            .map(|kpd| {
                let (kp_in, _) = KeyPackageIn::tls_deserialize_bytes(&kpd.data)
                    .map_err(|e| MLSError::OpenMLS(format!("KP deserialize: {e:?}")))?;
                kp_in
                    .validate(self.provider.crypto(), ProtocolVersion::default())
                    .map_err(|e| MLSError::OpenMLS(format!("KP validate: {e:?}")))
            })
            .collect::<Result<_, _>>()?;

        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        // Extract own leaf data before taking a mutable reference.
        let (identity, pub_key) = {
            let leaf = group
                .own_leaf()
                .ok_or_else(|| MLSError::invalid_input("group has no own leaf"))?;
            (
                leaf.credential().serialized_content().to_vec(),
                leaf.signature_key().as_slice().to_vec(),
            )
        };
        let signer = self.signer_from_identity(identity, pub_key)?;

        let (commit_msg, welcome, _group_info) = group
            .add_members(&self.provider, signer.as_ref(), &kps)
            .map_err(|e| MLSError::OpenMLS(format!("add_members: {e:?}")))?;

        let commit_data = commit_msg
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("commit serialize: {e:?}")))?;

        let welcome_data = welcome
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("welcome serialize: {e:?}")))?;

        Ok(AddMembersResult {
            commit_data,
            welcome_data,
            metadata_blob_locator: None,
            metadata_blob_ciphertext: None,
            metadata_version: None,
            next_confirmation_tag: None,
            next_group_context_hash: None,
        })
    }

    pub(crate) fn remove_members(
        &self,
        group_id: Vec<u8>,
        member_identities: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, MLSError> {
        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        let leaf_indices: Vec<LeafNodeIndex> = group
            .members()
            .filter(|m| {
                member_identities
                    .iter()
                    .any(|i| i.as_slice() == m.credential.serialized_content())
            })
            .map(|m| m.index)
            .collect();

        if leaf_indices.is_empty() {
            return Err(MLSError::invalid_input(
                "remove_members: no matching members found",
            ));
        }

        let (identity, pub_key) = {
            let leaf = group
                .own_leaf()
                .ok_or_else(|| MLSError::invalid_input("group has no own leaf"))?;
            (
                leaf.credential().serialized_content().to_vec(),
                leaf.signature_key().as_slice().to_vec(),
            )
        };
        let signer = self.signer_from_identity(identity, pub_key)?;

        let (commit_msg, _welcome, _group_info) = group
            .remove_members(&self.provider, signer.as_ref(), &leaf_indices)
            .map_err(|e| MLSError::OpenMLS(format!("remove_members: {e:?}")))?;

        commit_msg
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("commit serialize: {e:?}")))
    }

    // ------------------------------------------------------------------
    // Group metadata (encrypted-only path; MLS metadata cutover)
    // ------------------------------------------------------------------

    /// Stage a `GroupContextExtensions` commit that updates only the
    /// AppDataDictionary `MetadataReference` (component 0x8001) — used for
    /// the encrypted-blob metadata path.
    ///
    /// Mirrors `MLSContext::update_group_metadata` in catbird-mls/src/mls_context.rs:
    /// - Rebuilds RequiredCapabilities WITHOUT the retired plaintext 0xff00
    ///   extension (defensively prunes legacy entries).
    /// - Replaces any leftover plaintext 0xff00 extension with an empty
    ///   payload during the same commit.
    /// - Plans the next `MetadataReference` (fresh UUID locator,
    ///   incremented version, empty hash) and writes it into the
    ///   AppDataDictionary as an `AppDataUpdate` proposal AND directly via
    ///   the commit-stage's `app_data_dictionary_updater`.
    ///
    /// Returns the serialized commit message bytes. Caller must:
    ///   1. Send commit to server (action = "updateMetadata").
    ///   2. On success, call `merge_pending_commit` to advance epoch.
    ///   3. After merge, derive metadata key via
    ///      `derive_metadata_key_from_group` against the post-merge epoch
    ///      and upload the encrypted blob via `putGroupMetadataBlob`.
    ///   4. On server failure, call `clear_pending_commit`.
    pub(crate) fn update_group_metadata(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        use catbird_mls::metadata;
        use catbird_mls::metadata::RETIRED_PLAINTEXT_METADATA_EXTENSION_TYPE as CATBIRD_METADATA_EXTENSION_TYPE;

        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        let (identity, pub_key) = {
            let leaf = group
                .own_leaf()
                .ok_or_else(|| MLSError::invalid_input("group has no own leaf"))?;
            (
                leaf.credential().serialized_content().to_vec(),
                leaf.signature_key().as_slice().to_vec(),
            )
        };
        let signer = self.signer_from_identity(identity, pub_key)?;

        // Clone existing extensions; we must preserve any not-our-business
        // extensions (e.g. RequiredCapabilities for AppData/RatchetTree).
        let mut extensions = group.extensions().clone();

        // Rebuild RequiredCapabilities WITHOUT the retired 0xff00.
        let existing_rc = extensions.required_capabilities().cloned();
        let mut ext_types: Vec<ExtensionType> = existing_rc
            .as_ref()
            .map(|rc| {
                rc.extension_types()
                    .iter()
                    .copied()
                    .filter(|t| {
                        !matches!(t, ExtensionType::Unknown(CATBIRD_METADATA_EXTENSION_TYPE))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if !ext_types.contains(&ExtensionType::AppDataDictionary) {
            ext_types.push(ExtensionType::AppDataDictionary);
        }
        if !ext_types.contains(&ExtensionType::RatchetTree) {
            ext_types.push(ExtensionType::RatchetTree);
        }

        let mut proposal_types = existing_rc
            .as_ref()
            .map(|rc| rc.proposal_types().to_vec())
            .unwrap_or_default();
        if !proposal_types.contains(&ProposalType::AppDataUpdate) {
            proposal_types.push(ProposalType::AppDataUpdate);
        }
        let credential_types = existing_rc
            .as_ref()
            .map(|rc| rc.credential_types().to_vec())
            .unwrap_or_default();

        extensions
            .add_or_replace(Extension::RequiredCapabilities(
                RequiredCapabilitiesExtension::new(&ext_types, &proposal_types, &credential_types),
            ))
            .map_err(|e| {
                MLSError::OpenMLS(format!(
                    "Failed to add required capabilities extension: {e:?}"
                ))
            })?;

        // Replace any pre-existing plaintext 0xff00 extension with empty.
        if extensions
            .unknown(CATBIRD_METADATA_EXTENSION_TYPE)
            .is_some()
        {
            let _ = extensions.add_or_replace(Extension::Unknown(
                CATBIRD_METADATA_EXTENSION_TYPE,
                UnknownExtension(Vec::new()),
            ));
        }

        // Always advance the encrypted MetadataReference for this commit.
        // `metadata_changed = true` because each call should bump version.
        // Phase F: legacy 0xff00 reader removed; post-cutover + DB wipe,
        // no group ever has the retired plaintext extension, so
        // `had_metadata_before` is always false here.
        let planned_reference_json = metadata::planned_metadata_reference_json(
            metadata::current_metadata_reference(group).as_ref(),
            false,
            true,
        )
        .map_err(|e| MLSError::OpenMLS(format!("plan metadata reference: {e:?}")))?;

        let mut commit_builder = group
            .commit_builder()
            .propose_group_context_extensions(extensions)
            .map_err(|e| MLSError::OpenMLS(format!("propose_group_context_extensions: {e:?}")))?;

        if let Some(ref ref_json) = planned_reference_json {
            commit_builder = commit_builder.add_proposal(Proposal::AppDataUpdate(Box::new(
                AppDataUpdateProposal::update(
                    metadata::METADATA_REFERENCE_COMPONENT_ID,
                    ref_json.clone(),
                ),
            )));
        }

        let mut commit_stage = commit_builder
            .load_psks(self.provider.storage())
            .map_err(|e| MLSError::OpenMLS(format!("load_psks: {e:?}")))?;

        if let Some(ref_json) = planned_reference_json {
            let mut updater = commit_stage.app_data_dictionary_updater();
            updater.set(ComponentData::from_parts(
                metadata::METADATA_REFERENCE_COMPONENT_ID,
                ref_json.into(),
            ));
            commit_stage.with_app_data_dictionary_updates(updater.changes());
        }

        let commit_bundle = commit_stage
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                signer.as_ref(),
                |_| true,
            )
            .map_err(|e| MLSError::OpenMLS(format!("build metadata commit: {e:?}")))?
            .stage_commit(&self.provider)
            .map_err(|e| MLSError::OpenMLS(format!("stage metadata commit: {e:?}")))?;

        let (commit_msg, _welcome, _group_info) = commit_bundle.into_contents();

        commit_msg
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("commit serialize: {e:?}")))
    }

    /// Read the current `MetadataReference` (encrypted-blob path) from the
    /// group's AppDataDictionary together with the metadata encryption key
    /// derived from the current epoch's exporter secret.
    ///
    /// Returns `None` if the group is not loaded or has no
    /// `MetadataReference` set yet (typical for groups that haven't had a
    /// metadata commit yet — e.g. just after Welcome).
    ///
    /// The returned tuple is `(metadata_key_32_bytes, epoch, reference)`.
    pub(crate) fn current_metadata_info(
        &self,
        group_id: Vec<u8>,
    ) -> Result<
        Option<(
            Vec<u8>,
            u64,
            Option<catbird_mls::metadata::MetadataReference>,
        )>,
        MLSError,
    > {
        use catbird_mls::metadata;

        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = match groups.get_mut(&group_id) {
            Some(g) => g,
            None => return Ok(None),
        };
        let epoch = group.epoch().as_u64();
        let reference = metadata::current_metadata_reference(group);

        let key = match metadata::derive_metadata_key_from_group(
            group,
            self.provider.crypto(),
            self.provider.storage(),
            &group_id,
            epoch,
        ) {
            Ok(k) => k,
            Err(e) => {
                return Err(MLSError::OpenMLS(format!(
                    "derive_metadata_key_from_group: {e:?}"
                )));
            }
        };

        Ok(Some((key.to_vec(), epoch, reference)))
    }

    // ------------------------------------------------------------------
    // Commit management
    // ------------------------------------------------------------------

    pub(crate) fn merge_pending_commit(&self, group_id: Vec<u8>) -> Result<u64, MLSError> {
        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MLSError::OpenMLS(format!("merge_pending_commit: {e:?}")))?;

        Ok(group.epoch().as_u64())
    }

    pub(crate) fn clear_pending_commit(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        group
            .clear_pending_commit(self.provider.storage())
            .map_err(|e| MLSError::OpenMLS(format!("clear_pending_commit: {e:?}")))?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Receiver-side staged commits (task #56)
    //
    // `decrypt_message` stages incoming commits in `pending_incoming_merges`
    // rather than auto-merging. Callers (see lib.rs and websocket.rs receive
    // paths) must explicitly call one of the two methods below to advance
    // the local epoch (`merge_incoming_commit`) or abandon the staged
    // commit (`discard_incoming_commit`).
    // ------------------------------------------------------------------

    /// Merge any incoming staged commit currently pending for `group_id`.
    ///
    /// Returns the new (post-merge) local epoch. If multiple staged commits
    /// are pending for the same group (e.g. rapid back-to-back commits from
    /// different senders), they are merged in ascending target-epoch order.
    ///
    /// Returns `InvalidInput("no pending staged commit …")` if no staged
    /// commit exists for the group — callers that saw a "commit message"
    /// signal from `decrypt_message` should always have a match here unless
    /// another caller already merged it.
    pub(crate) fn merge_incoming_commit(&self, group_id: Vec<u8>) -> Result<u64, MLSError> {
        // Pop the lowest-epoch entry for this group.
        let (key, staged) = {
            let mut pending = self.pending_incoming_merges.borrow_mut();
            let key_opt = pending
                .keys()
                .filter(|(gid, _)| gid == &group_id)
                .min_by_key(|(_, epoch)| *epoch)
                .cloned();
            match key_opt {
                Some(k) => {
                    let staged = pending.remove(&k).expect("just located");
                    (k, staged)
                }
                None => {
                    return Err(MLSError::invalid_input(format!(
                        "no pending staged commit for group {} (not staged, or already merged/discarded)",
                        base64::engine::general_purpose::STANDARD.encode(&group_id),
                    )));
                }
            }
        };

        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        let epoch_before = group.epoch().as_u64();
        group
            .merge_staged_commit(&self.provider, staged)
            .map_err(|e| MLSError::OpenMLS(format!("merge_staged_commit: {e:?}")))?;
        let epoch_after = group.epoch().as_u64();

        if epoch_after <= epoch_before {
            web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(&format!(
                "[catbird-mls-web] ⚠️ merge_incoming_commit did not advance epoch for group {} (key epoch {}): {} -> {}",
                base64::engine::general_purpose::STANDARD.encode(&group_id),
                key.1,
                epoch_before,
                epoch_after,
            )));
        }

        Ok(epoch_after)
    }

    /// Discard any pending staged commits for `group_id` without advancing
    /// the local epoch. Idempotent — no-op if nothing is staged.
    ///
    /// Use this when recovery policy decides the staged commit should not
    /// be applied (e.g. a fork/reset is being initiated and the client is
    /// about to rejoin).
    pub(crate) fn discard_incoming_commit(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        let mut pending = self.pending_incoming_merges.borrow_mut();
        let before = pending.len();
        pending.retain(|(gid, _), _| gid != &group_id);
        let dropped = before - pending.len();
        if dropped > 0 {
            web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(&format!(
                "[catbird-mls-web] 🗑️ discard_incoming_commit: dropped {} staged commit(s) for group {}",
                dropped,
                base64::engine::general_purpose::STANDARD.encode(&group_id),
            )));
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Group state queries
    // ------------------------------------------------------------------

    pub(crate) fn get_epoch(&self, group_id: Vec<u8>) -> Result<u64, MLSError> {
        self.ensure_loaded(&group_id)?;
        let groups = self.groups.borrow();
        let group = groups
            .get(&group_id)
            .expect("ensure_loaded guarantees presence");
        Ok(group.epoch().as_u64())
    }

    // `get_group_metadata` (legacy 0xff00 reader on the WASM context)
    // removed in Phase F. The `catbird_mls_get_group_metadata` JS export
    // (lib.rs) now reads from local OPFS-SQLite storage that's populated
    // by `wasm_bootstrap_group_metadata` after every Welcome / commit-merge.

    pub(crate) fn export_group_info(
        &self,
        group_id: Vec<u8>,
        signer_identity_bytes: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        let signer = self.get_or_create_signer(&signer_identity_bytes)?;

        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        let group_info = group
            .export_group_info(self.provider.crypto(), signer.as_ref(), true)
            .map_err(|e| MLSError::OpenMLS(format!("export_group_info: {e:?}")))?;

        group_info
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("group_info serialize: {e:?}")))
    }

    // ------------------------------------------------------------------
    // Joining
    // ------------------------------------------------------------------

    pub(crate) fn process_welcome(
        &self,
        welcome_bytes: Vec<u8>,
        identity_bytes: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<WelcomeResult, MLSError> {
        let config = config.unwrap_or_else(Self::default_config);
        let signer = self.get_or_create_signer(&identity_bytes)?;

        let (msg_in, _) = MlsMessageIn::tls_deserialize_bytes(&welcome_bytes)
            .map_err(|e| MLSError::OpenMLS(format!("Welcome msg deserialize: {e:?}")))?;

        let welcome = match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            other => {
                return Err(MLSError::invalid_input(format!(
                    "expected Welcome, got {:?}",
                    std::mem::discriminant(&other)
                )))
            }
        };

        let join_config = Self::make_join_config(&config);
        let staged = StagedWelcome::new_from_welcome(&self.provider, &join_config, welcome, None)
            .map_err(|e| {
            MLSError::OpenMLS(format!("StagedWelcome::new_from_welcome: {e:?}"))
        })?;

        let group = staged
            .into_group(&self.provider)
            .map_err(|e| MLSError::OpenMLS(format!("staged.into_group: {e:?}")))?;

        let group_id = group.group_id().as_slice().to_vec();
        self.groups.borrow_mut().insert(group_id.clone(), group);
        self.signers.borrow_mut().insert(identity_bytes, signer);

        Ok(WelcomeResult { group_id })
    }

    pub(crate) fn create_external_commit(
        &self,
        group_info_bytes: Vec<u8>,
        identity_bytes: Vec<u8>,
    ) -> Result<ExternalCommitResult, MLSError> {
        let (msg_in, _) = MlsMessageIn::tls_deserialize_bytes(&group_info_bytes)
            .map_err(|e| MLSError::OpenMLS(format!("GroupInfo deserialize: {e:?}")))?;

        let verifiable_group_info = match msg_in.extract() {
            MlsMessageBodyIn::GroupInfo(gi) => gi,
            _ => {
                return Err(MLSError::invalid_input(
                    "expected GroupInfo for external commit",
                ))
            }
        };

        // Any request journal entry owns its exact crypto, including terminal
        // records. External joining must not overwrite that group underneath
        // a retained request/artifact binding, or publish it into the live cache.
        let group_id = hex::encode(verifiable_group_info.group_id().as_slice());
        if self.provider.storage().conn().exists(
            "SELECT 1 FROM direct_request_journal_v2 WHERE group_id = ?1 UNION ALL SELECT 1 FROM direct_request_live_v2 WHERE group_id = ?1 UNION ALL SELECT 1 FROM direct_request_import_ownership_v2 WHERE group_id = ?1",
            &[(1, &group_id)],
        )? {
            return Err(MLSError::OperationNotSupported {
                reason: "external joining cannot replace a request-owned group".into(),
            });
        }

        let config = Self::default_config();
        let signer = self.get_or_create_signer(&identity_bytes)?;

        let credential = BasicCredential::new(identity_bytes.clone());
        let cred_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let join_config = Self::make_join_config(&config);

        let (group, commit_msg, group_info_out) = MlsGroup::join_by_external_commit(
            &self.provider,
            signer.as_ref(),
            None,
            verifiable_group_info,
            &join_config,
            None,
            None,
            b"",
            cred_with_key,
        )
        .map_err(|e| MLSError::OpenMLS(format!("join_by_external_commit: {e:?}")))?;

        let commit_data = commit_msg
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("commit serialize: {e:?}")))?;

        let group_info = group_info_out
            .as_ref()
            .map(|gi| {
                gi.tls_serialize_detached()
                    .map_err(|e| MLSError::OpenMLS(format!("GroupInfo serialize: {e:?}")))
            })
            .transpose()?;

        let group_id = group.group_id().as_slice().to_vec();
        self.groups.borrow_mut().insert(group_id.clone(), group);
        self.signers.borrow_mut().insert(identity_bytes, signer);

        Ok(ExternalCommitResult {
            commit_data,
            group_id,
            group_info,
        })
    }

    pub(crate) fn discard_pending_external_join(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        if let Some(mut group) = self.groups.borrow_mut().remove(&group_id) {
            let _ = group.delete(self.provider.storage());
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Messaging
    // ------------------------------------------------------------------

    pub(crate) fn encrypt_message(
        &self,
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<EncryptResult, MLSError> {
        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        let (identity, pub_key) = {
            let leaf = group
                .own_leaf()
                .ok_or_else(|| MLSError::invalid_input("group has no own leaf"))?;
            (
                leaf.credential().serialized_content().to_vec(),
                leaf.signature_key().as_slice().to_vec(),
            )
        };
        let signer = self.signer_from_identity(identity, pub_key)?;

        let msg_out = group
            .create_message(&self.provider, signer.as_ref(), &plaintext)
            .map_err(|e| MLSError::OpenMLS(format!("create_message: {e:?}")))?;

        let raw = msg_out
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("msg serialize: {e:?}")))?;

        let (padded, padded_size) = pad_ciphertext(&raw);
        Ok(EncryptResult {
            ciphertext: padded,
            padded_size,
        })
    }

    pub(crate) fn encrypt_canonical_message(
        &self,
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
        expected_epoch: u64,
    ) -> Result<EncryptResult, MLSError> {
        if aad.is_empty() || aad.len() > 64 * 1024 {
            return Err(MLSError::invalid_input(
                "Canonical application AAD is missing or exceeds its bound",
            ));
        }
        self.require_published_group(&group_id)?;
        // The transaction owns ratchet advancement. Publish a fresh cache entry
        // only after its ciphertext and ratchet are durably committed.
        self.groups.borrow_mut().remove(&group_id);
        let conn = self.provider.storage().conn();
        let (group, ciphertext) = conn.transaction(|| -> Result<_, MLSError> {
            let mut group =
                MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&group_id))
                    .map_err(|_| MLSError::StorageFailed)?
                    .ok_or_else(|| MLSError::group_not_found("Canonical message group missing"))?;
            if group.epoch().as_u64() != expected_epoch {
                return Err(MLSError::invalid_input(
                    "MLS epoch changed before application encryption",
                ));
            }
            let leaf = group
                .own_leaf()
                .ok_or_else(|| MLSError::invalid_input("Group has no own leaf"))?;
            let signer = self.signer_from_identity(
                leaf.credential().serialized_content().to_vec(),
                leaf.signature_key().as_slice().to_vec(),
            )?;
            group.set_aad(aad);
            let result = group
                .create_message(&self.provider, signer.as_ref(), &plaintext)
                .map_err(|_| MLSError::EncryptionFailed)
                .and_then(|message| {
                    message
                        .tls_serialize_detached()
                        .map_err(|_| MLSError::SerializationError)
                });
            group.set_aad(Vec::new());
            Ok((group, result?))
        })?;
        conn.ensure_durable()?;
        self.groups.borrow_mut().insert(group_id, group);
        Ok(EncryptResult {
            padded_size: u32::try_from(ciphertext.len())
                .map_err(|_| MLSError::SerializationError)?,
            ciphertext,
        })
    }

    pub(crate) fn decrypt_message(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<DecryptResult, MLSError> {
        match self.decrypt_classified(group_id, ciphertext)? {
            MlsDecryptOutcome::Message(message)
                if message.content_type == catbird_mls::DecryptContentType::Commit =>
            {
                Err(MLSError::invalid_input(
                    "received a commit message (not application data)",
                ))
            }
            MlsDecryptOutcome::Message(message) => Ok(message),
            MlsDecryptOutcome::OwnPrivateMessage { .. } | MlsDecryptOutcome::OwnPendingCommit => {
                Err(MLSError::DecryptionFailed)
            }
        }
    }
    fn decrypt_classified(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<MlsDecryptOutcome, MLSError> {
        use sha2::{Digest, Sha256};
        let raw = strip_padding(&ciphertext);

        let (msg_in, _) = MlsMessageIn::tls_deserialize_bytes(raw)
            .map_err(|e| MLSError::OpenMLS(format!("MlsMessageIn deserialize: {e:?}")))?;

        let protocol_msg: ProtocolMessage = msg_in
            .try_into()
            .map_err(|e| MLSError::OpenMLS(format!("MlsMessageIn to ProtocolMessage: {e:?}")))?;

        self.ensure_loaded(&group_id)?;
        let mut groups = self.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("ensure_loaded guarantees presence");

        let processed = group
            .process_message(&self.provider, protocol_msg)
            .map_err(|e| MLSError::OpenMLS(format!("process_message: {e:?}")))?;

        // Interpret the same AppData update operations as the shared native
        // adapter, then keep the resulting commit staged for explicit merge.
        let processed = if let ProcessedMessageContent::UnresolvedAppDataCommit(unresolved) =
            processed.content()
        {
            use openmls::messages::proposals::AppDataUpdateOperation;
            let mut updater = group.app_data_dictionary_updater();
            for proposal in unresolved.app_data_update_proposals() {
                match proposal.operation() {
                    AppDataUpdateOperation::Update(data) => updater.set(ComponentData::from_parts(
                        proposal.component_id(),
                        data.clone(),
                    )),
                    AppDataUpdateOperation::Remove => updater.remove(&proposal.component_id()),
                }
            }
            group
                .resolve_app_data_commit(&self.provider, processed, updater.changes())
                .map_err(|_| MLSError::InvalidCommit)?
        } else {
            processed
        };
        let epoch = processed.epoch().as_u64();
        match processed.content() {
            ProcessedMessageContent::OwnPrivateMessage => {
                return Ok(MlsDecryptOutcome::OwnPrivateMessage {
                    epoch,
                    aad_sha256: Sha256::digest(processed.aad()).into(),
                    ciphertext_sha256: Sha256::digest(&ciphertext).into(),
                })
            }
            ProcessedMessageContent::OwnPendingCommit => {
                return Ok(MlsDecryptOutcome::OwnPendingCommit)
            }
            _ => {}
        }

        // Extract credential data before consuming `processed`.
        let sender_credential = {
            let cred = processed.credential();
            CredentialData {
                credential_type: "basic".to_string(),
                identity: cred.serialized_content().to_vec(),
            }
        };

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(MlsDecryptOutcome::Message(DecryptResult {
                    plaintext: app_msg.into_bytes(),
                    epoch,
                    sequence_number: 0,
                    sender_credential,
                    content_type: catbird_mls::DecryptContentType::Application,
                    proposal_ref: None,
                }))
            }

            ProcessedMessageContent::StagedCommitMessage(commit) => {
                // Task #56: stage the incoming commit instead of auto-merging.
                // Callers (`catbird_mls_fetch_new_messages`, the WebSocket loop)
                // must explicitly invoke `merge_incoming_commit(group_id, target_epoch)`
                // to advance the local epoch, or `discard_incoming_commit(...)` to
                // abandon it. Mirrors the `MLSContext::decrypt_message` behavior in
                // `catbird-mls/src/api.rs` under task #33.
                //
                // The error variant below is preserved verbatim — existing lib.rs
                // and websocket.rs callers pattern-match on the "commit message"
                // substring to distinguish control traffic from decrypt failures.
                let target_epoch = commit.group_context().epoch().as_u64();
                self.pending_incoming_merges
                    .borrow_mut()
                    .insert((group_id.clone(), target_epoch), *commit);

                Ok(MlsDecryptOutcome::Message(DecryptResult {
                    plaintext: Vec::new(),
                    epoch: target_epoch,
                    sequence_number: 0,
                    sender_credential,
                    content_type: catbird_mls::DecryptContentType::Commit,
                    proposal_ref: None,
                }))
            }

            // These outcomes do not carry authenticated plaintext. The
            // legacy browser Result adapter has no durable own-echo proof
            // authority, so it must not merge a pending commit or invent a
            // successfully decrypted message. Matches native's legacy wrapper.
            ProcessedMessageContent::OwnPendingCommit
            | ProcessedMessageContent::OwnPrivateMessage => Err(MLSError::DecryptionFailed),
            ProcessedMessageContent::UnresolvedAppDataCommit(_) => Err(MLSError::Internal(
                "AppData commit remained unresolved after resolution".into(),
            )),

            ProcessedMessageContent::ProposalMessage(_) => Err(MLSError::invalid_input(
                "received a proposal (not application data)",
            )),

            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Err(MLSError::invalid_input(
                    "received an external join proposal (not application data)",
                ))
            }
        }
    }

    // ------------------------------------------------------------------
    // Key packages
    // ------------------------------------------------------------------

    pub(crate) fn create_key_package(
        &self,
        identity_bytes: Vec<u8>,
    ) -> Result<KeyPackageResult, MLSError> {
        let signer = self.get_or_create_signer(&identity_bytes)?;

        let credential = BasicCredential::new(identity_bytes.clone());
        let cred_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let bundle = KeyPackage::builder()
            .key_package_lifetime(key_package_lifetime()?)
            .leaf_node_capabilities(clean_leaf_capabilities())
            .build(CIPHERSUITE, &self.provider, signer.as_ref(), cred_with_key)
            .map_err(|e| MLSError::OpenMLS(format!("KeyPackage::builder: {e:?}")))?;
        let key_package = bundle.key_package().clone();

        let hash_ref = key_package
            .hash_ref(self.provider.crypto())
            .map(|h| h.as_slice().to_vec())
            .map_err(|e| MLSError::OpenMLS(format!("key_package.hash_ref: {e:?}")))?;

        let key_package_data = MlsMessageOut::from(key_package)
            .tls_serialize_detached()
            .map_err(|e| MLSError::OpenMLS(format!("key_package serialize: {e:?}")))?;

        let signature_public_key = signer.public().into();

        Ok(KeyPackageResult {
            key_package_data,
            hash_ref,
            signature_public_key,
        })
    }

    // ------------------------------------------------------------------
    // Field-level encryption (per-conversation content key path).
    //
    // Delegates to `catbird_mls::field_encryption` for the actual crypto.
    // The `content_root_key` is a 32-byte secret derived/fetched by the
    // platform layer (e.g. unlocked from secure storage) and pushed into
    // the WASM context via `set_content_root_key`. The context never
    // persists it — that is the platform's responsibility (Task 23).
    // ------------------------------------------------------------------

    pub(crate) fn set_content_root_key(&self, key: Vec<u8>) -> Result<(), MLSError> {
        if key.len() != catbird_mls::field_encryption::KEY_LEN {
            return Err(MLSError::invalid_input(format!(
                "content root key must be {} bytes, got {}",
                catbird_mls::field_encryption::KEY_LEN,
                key.len(),
            )));
        }
        *self.content_root_key.borrow_mut() = Some(key);
        Ok(())
    }

    pub(crate) fn clear_content_root_key(&self) {
        *self.content_root_key.borrow_mut() = None;
    }

    pub(crate) fn encrypt_message_payload(
        &self,
        conversation_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, MLSError> {
        let guard = self.content_root_key.borrow();
        let root = guard
            .as_ref()
            .ok_or_else(|| MLSError::invalid_input("content root key not set"))?;
        catbird_mls::field_encryption::encrypt_payload(root, conversation_id, plaintext)
            .map_err(|e| MLSError::invalid_input(e.to_string()))
    }

    pub(crate) fn decrypt_message_payload(
        &self,
        conversation_id: &str,
        wire: &[u8],
    ) -> Result<Vec<u8>, MLSError> {
        let guard = self.content_root_key.borrow();
        let root = guard
            .as_ref()
            .ok_or_else(|| MLSError::invalid_input("content root key not set"))?;
        catbird_mls::field_encryption::decrypt_payload(root, conversation_id, wire)
            .map_err(|e| MLSError::invalid_input(e.to_string()))
    }

    pub(crate) fn compute_message_hmac(
        &self,
        conversation_id: &str,
        prev_hmac: Option<&[u8]>,
        message_id: &str,
        payload_wire: &[u8],
    ) -> Result<Vec<u8>, MLSError> {
        let guard = self.content_root_key.borrow();
        let root = guard
            .as_ref()
            .ok_or_else(|| MLSError::invalid_input("content root key not set"))?;
        let h = catbird_mls::field_encryption::compute_entry_hmac(
            root,
            conversation_id,
            prev_hmac,
            message_id,
            payload_wire,
        )
        .map_err(|e| MLSError::invalid_input(e.to_string()))?;
        Ok(h.to_vec())
    }

    pub(crate) fn verify_message_hmac(
        &self,
        conversation_id: &str,
        prev_hmac: Option<&[u8]>,
        message_id: &str,
        payload_wire: &[u8],
        expected: &[u8],
    ) -> Result<bool, MLSError> {
        let guard = self.content_root_key.borrow();
        let root = guard
            .as_ref()
            .ok_or_else(|| MLSError::invalid_input("content root key not set"))?;
        catbird_mls::field_encryption::verify_entry_hmac(
            root,
            conversation_id,
            prev_hmac,
            message_id,
            payload_wire,
            expected,
        )
        .map_err(|e| MLSError::invalid_input(e.to_string()))
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod compatibility_tests;

// The adapter implements the shared interface; request lifecycle remains in Rust.
impl MlsCryptoContext for WasmMLSContext {
    // Protected provider capability; product activation remains a separate host gate.
    fn get_conversation_policy(
        &self,
        owner: &str,
        cid: &str,
    ) -> Result<Option<catbird_atproto::blue_catbird::chat::ConversationState>, MLSError> {
        self.protected_policy(owner, cid)
    }
    fn put_conversation_policy(
        &self,
        owner: &str,
        state: &catbird_atproto::blue_catbird::chat::ConversationState,
    ) -> Result<bool, MLSError> {
        self.protect_policy(owner, state)
    }
    fn get_conversation_departure(
        &self,
        owner: &str,
        cid: &str,
    ) -> Result<Option<catbird_atproto::blue_catbird::chat::ConversationCoordinates>, MLSError>
    {
        self.protected_departure(owner, cid)
    }
    fn put_conversation_departure(
        &self,
        owner: &str,
        state: &catbird_atproto::blue_catbird::chat::ConversationCoordinates,
    ) -> Result<bool, MLSError> {
        self.protect_departure(owner, state)
    }
    fn list_account_exits(
        &self,
    ) -> Result<Vec<catbird_mls::orchestrator::account_exit::AccountExitRecord>, MLSError> {
        self.protected_account_exits()
    }
    fn put_account_exit(
        &self,
        record: &catbird_mls::orchestrator::account_exit::AccountExitRecord,
    ) -> Result<(), MLSError> {
        self.protect_account_exit(record)
    }
    fn decrypt_message_outcome(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<MlsDecryptOutcome, MLSError> {
        self.decrypt_classified(group_id, ciphertext)
    }
    fn store_own_echo_proof(
        &self,
        proof: &catbird_mls::orchestrator::mls_provider::OwnEchoProof,
    ) -> Result<(), MLSError> {
        self.protect_own_echo(proof)
    }
    fn has_own_echo_proof(
        &self,
        cid: &str,
        gid: &[u8],
        entry: &str,
        epoch: u64,
        aad: &[u8; 32],
        ciphertext: &[u8; 32],
    ) -> Result<bool, MLSError> {
        self.protected_own_echo(cid, gid, entry, epoch, aad, ciphertext)
    }
    fn supports_direct_request_bootstrap(&self) -> bool {
        true
    }
    fn prepare_direct_request_bootstrap(
        &self,
        input: &DirectRequestBootstrapInput,
    ) -> Result<DirectRequestJournal, MLSError> {
        WasmMLSContext::prepare_direct_request_bootstrap(self, input)
    }
    fn list_direct_request_journal(&self) -> Result<Vec<DirectRequestJournal>, MLSError> {
        WasmMLSContext::list_direct_request_journal(self)
    }

    fn process_direct_request_welcome(
        &self,
        input: &catbird_mls::orchestrator::direct_request_bootstrap::DirectRequestWelcomeInput,
    ) -> Result<WelcomeResult, MLSError> {
        self.import_request_welcome(input)
    }
    fn decrypt_direct_request_introduction(
        &self,
        input: &catbird_mls::orchestrator::direct_request_bootstrap::DirectRequestWelcomeInput,
    ) -> Result<
        catbird_mls::orchestrator::direct_request_bootstrap::DirectRequestIntroductionResult,
        MLSError,
    > {
        self.decrypt_request_intro(input)
    }
    fn read_direct_request_key_publication(
        &self,
        device: &str,
    ) -> Result<Option<Vec<u8>>, MLSError> {
        self.request_value("keys", device)
    }
    fn prepare_direct_request_key_publication(
        &self,
        input: &catbird_mls::orchestrator::direct_request_keys::DirectRequestKeyPublicationInput,
        expected: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, MLSError> {
        self.prepare_request_keys(input, expected)
    }
    fn acknowledge_direct_request_key_publication(
        &self,
        device: &str,
        expected: &[u8],
        next: &[u8],
    ) -> Result<bool, MLSError> {
        self.acknowledge_request_keys(device, expected, next)
    }
    fn commit_closed_direct_request_projection(
        &self,
        cid: &str,
        expected: &[u8],
        next: &[u8],
    ) -> Result<bool, MLSError> {
        self.close_request_projection(cid, expected, next)
    }
    fn persist_direct_request_publish(&self, id: &str, bytes: &[u8]) -> Result<(), MLSError> {
        self.persist_request_publish(id, bytes)
    }
    fn confirm_published_bootstrap(
        &self,
        id: &str,
        receipt: &[u8],
        key: &[u8],
    ) -> Result<DirectRequestJournal, MLSError> {
        self.resolve_request_journal(id, receipt, key, true)
    }
    fn abandon_rejected_bootstrap(
        &self,
        id: &str,
        receipt: &[u8],
        key: &[u8],
    ) -> Result<DirectRequestJournal, MLSError> {
        self.resolve_request_journal(id, receipt, key, false)
    }
    fn mark_direct_request_projected(&self, id: &str) -> Result<(), MLSError> {
        self.mark_request_projected(id)
    }
    fn read_direct_request_intent(&self, id: &str) -> Result<Option<Vec<u8>>, MLSError> {
        self.request_value("intent", id)
    }
    fn compare_exchange_direct_request_intent(
        &self,
        id: &str,
        old: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, MLSError> {
        self.request_value_cas("intent", id, old, next)
    }
    fn list_direct_request_intents(&self) -> Result<Vec<Vec<u8>>, MLSError> {
        self.request_values("intent")
    }
    fn read_direct_request_projection(&self, id: &str) -> Result<Option<Vec<u8>>, MLSError> {
        self.request_value("projection", id)
    }
    fn compare_exchange_direct_request_projection(
        &self,
        id: &str,
        old: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, MLSError> {
        self.request_value_cas("projection", id, old, next)
    }
    fn list_direct_request_projections(&self) -> Result<Vec<Vec<u8>>, MLSError> {
        self.request_values("projection")
    }
    fn read_request_value(&self, namespace: &str, id: &str) -> Result<Option<Vec<u8>>, MLSError> {
        self.request_value(namespace, id)
    }
    fn compare_exchange_request_value(
        &self,
        namespace: &str,
        id: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, MLSError> {
        self.request_value_cas(namespace, id, expected, next)
    }
    fn list_request_values(&self, namespace: &str) -> Result<Vec<Vec<u8>>, MLSError> {
        self.request_values(namespace)
    }
    fn request_values_total_bytes(&self, namespace: &str) -> Result<u64, MLSError> {
        self.request_values_total_bytes(namespace)
    }

    fn create_key_package(&self, identity: Vec<u8>) -> Result<KeyPackageResult, MLSError> {
        WasmMLSContext::create_key_package(self, identity)
    }
    fn create_group(
        &self,
        identity: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        WasmMLSContext::create_group(self, identity, config)
    }
    fn create_group_with_id(
        &self,
        identity: Vec<u8>,
        group_id: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<GroupCreationResult, MLSError> {
        WasmMLSContext::create_group_with_id(self, identity, group_id, config)
    }
    fn add_members(
        &self,
        group_id: Vec<u8>,
        key_packages: Vec<KeyPackageData>,
    ) -> Result<AddMembersResult, MLSError> {
        WasmMLSContext::add_members(self, group_id, key_packages)
    }
    fn remove_members(
        &self,
        group_id: Vec<u8>,
        member_identities: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, MLSError> {
        WasmMLSContext::remove_members(self, group_id, member_identities)
    }
    fn merge_pending_commit(&self, group_id: Vec<u8>) -> Result<u64, MLSError> {
        WasmMLSContext::merge_pending_commit(self, group_id)
    }
    fn clear_pending_commit(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        WasmMLSContext::clear_pending_commit(self, group_id)
    }
    fn get_epoch(&self, group_id: Vec<u8>) -> Result<u64, MLSError> {
        WasmMLSContext::get_epoch(self, group_id)
    }
    fn export_group_info(
        &self,
        group_id: Vec<u8>,
        signer_identity: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        WasmMLSContext::export_group_info(self, group_id, signer_identity)
    }
    fn encrypt_message_with_aad(
        &self,
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
        expected_epoch: u64,
    ) -> Result<EncryptResult, MLSError> {
        self.encrypt_canonical_message(group_id, plaintext, aad, expected_epoch)
    }
    fn encrypt_message(
        &self,
        group_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<EncryptResult, MLSError> {
        WasmMLSContext::encrypt_message(self, group_id, plaintext)
    }
    fn decrypt_message(
        &self,
        group_id: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<DecryptResult, MLSError> {
        WasmMLSContext::decrypt_message(self, group_id, ciphertext)
    }
    fn create_external_commit(
        &self,
        group_info: Vec<u8>,
        identity: Vec<u8>,
    ) -> Result<ExternalCommitResult, MLSError> {
        WasmMLSContext::create_external_commit(self, group_info, identity)
    }
    fn discard_pending_external_join(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        WasmMLSContext::discard_pending_external_join(self, group_id)
    }
    fn delete_group(&self, group_id: Vec<u8>) -> Result<(), MLSError> {
        WasmMLSContext::delete_group(self, group_id)
    }
    fn process_welcome(
        &self,
        welcome_data: Vec<u8>,
        identity: Vec<u8>,
        config: Option<GroupConfig>,
    ) -> Result<WelcomeResult, MLSError> {
        WasmMLSContext::process_welcome(self, welcome_data, identity, config)
    }

    fn identity_public_key(&self, identity: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        Ok(self.existing_signer(&identity)?.public().to_vec())
    }
    fn sign_with_identity_key(
        &self,
        identity: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        use openmls_traits::signatures::Signer;
        self.existing_signer(&identity)?
            .sign(&payload)
            .map_err(|_| MLSError::OpenMLSError)
    }
    fn export_identity_key(&self, identity: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        serde_json::to_vec(self.existing_signer(&identity)?.as_ref())
            .map_err(|_| MLSError::SerializationError)
    }
    fn import_identity_key(&self, identity: Vec<u8>, key_data: Vec<u8>) -> Result<(), MLSError> {
        let signer: SignatureKeyPair =
            serde_json::from_slice(&key_data).map_err(|_| MLSError::SerializationError)?;
        // The upstream serde implementation does not validate key relations.
        // The Ed25519 signing implementation rejects a private seed of the
        // wrong length; strict verification binds that seed to the public key.
        use openmls_traits::signatures::Signer;
        if signer.signature_scheme() != SignatureScheme::ED25519 {
            return Err(MLSError::invalid_input("identity signer must use Ed25519"));
        }
        let public_bytes: &[u8; 32] = signer
            .public()
            .try_into()
            .map_err(|_| MLSError::invalid_input("identity public key must be 32 bytes"))?;
        let public = ed25519_dalek::VerifyingKey::from_bytes(public_bytes)
            .map_err(|_| MLSError::invalid_input("invalid identity public key"))?;
        const IMPORT_PROOF: &[u8] = b"CATBIRD-BROWSER-IDENTITY-IMPORT-V1\0";
        let signature = signer
            .sign(IMPORT_PROOF)
            .map_err(|_| MLSError::invalid_input("invalid identity private key"))?;
        let signature = ed25519_dalek::Signature::from_slice(&signature)
            .map_err(|_| MLSError::invalid_input("invalid identity import signature"))?;
        public
            .verify_strict(IMPORT_PROOF, &signature)
            .map_err(|_| {
                MLSError::invalid_input("identity private and public keys do not match")
            })?;
        let mapping_key = [
            b"catbird.browser.identity.v1\0".as_slice(),
            identity.as_slice(),
        ]
        .concat();
        let conn = self.provider.storage().conn();
        conn.transaction(|| -> Result<(), crate::sqlite_conn::WasmSqliteError> {
            if let Some(existing) = conn.get(&mapping_key)? {
                if existing != signer.public() {
                    return Err(crate::sqlite_conn::WasmSqliteError::Serialization(
                        "identity signer replacement requires explicit rotation".into(),
                    ));
                }
            }
            signer.store(self.provider.storage())?;
            conn.put(&mapping_key, signer.public())
        })
        .map_err(|_| MLSError::StorageError)?;
        self.signers.borrow_mut().insert(identity, Rc::new(signer));
        Ok(())
    }
    fn update_group_metadata(
        &self,
        _group_id: Vec<u8>,
        _metadata_json: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "shared encrypted metadata update is not wired for browser".into(),
        })
    }
    fn propose_self_remove(&self, _group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "browser self-remove proposal unavailable".into(),
        })
    }
    fn commit_pending_proposals(&self, _group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "browser proposal commit unavailable".into(),
        })
    }
    fn add_members_with_aad(
        &self,
        _group_id: Vec<u8>,
        _key_packages: Vec<KeyPackageData>,
        _aad: Option<Vec<u8>>,
    ) -> Result<AddMembersResult, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "browser authenticated Add unavailable".into(),
        })
    }
    fn remove_members_with_aad(
        &self,
        _group_id: Vec<u8>,
        _member_identities: Vec<Vec<u8>>,
        _aad: Option<Vec<u8>>,
    ) -> Result<catbird_mls::RemoveMembersResult, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "browser authenticated Remove unavailable".into(),
        })
    }
    fn add_members_with_metadata(
        &self,
        _group_id: Vec<u8>,
        _key_packages: Vec<KeyPackageData>,
        _title: Option<String>,
        _description: Option<String>,
    ) -> Result<AddMembersResult, MLSError> {
        Err(MLSError::OperationNotSupported {
            reason: "browser Add with metadata unavailable".into(),
        })
    }
    fn ensure_storage_durable(&self) -> Result<(), MLSError> {
        self.provider
            .storage()
            .conn()
            .ensure_durable()
            .map_err(|_| MLSError::StorageError)
    }
    fn get_confirmation_tag(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        use openmls_traits::storage::StorageProvider;
        self.ensure_loaded(&group_id)?;
        let tag: ConfirmationTag = self
            .provider
            .storage()
            .confirmation_tag(&GroupId::from_slice(&group_id))
            .map_err(|_| MLSError::StorageError)?
            .ok_or(MLSError::StorageError)?;
        let bytes = tag
            .tls_serialize_detached()
            .map_err(|_| MLSError::SerializationError)?;
        Ok(if bytes.len() == 33 && bytes[0] == 32 {
            bytes[1..].to_vec()
        } else {
            bytes
        })
    }
    fn get_group_context_hash(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        use openmls_traits::storage::StorageProvider;
        use sha2::Digest;
        self.ensure_loaded(&group_id)?;
        let context: GroupContext = self
            .provider
            .storage()
            .group_context(&GroupId::from_slice(&group_id))
            .map_err(|_| MLSError::StorageError)?
            .ok_or(MLSError::StorageError)?;
        let bytes = context
            .tls_serialize_detached()
            .map_err(|_| MLSError::SerializationError)?;
        Ok(sha2::Sha256::digest(bytes).to_vec())
    }
    fn epoch_authenticator(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MLSError> {
        self.ensure_loaded(&group_id)?;
        Ok(self.groups.borrow()[&group_id]
            .epoch_authenticator()
            .as_slice()
            .to_vec())
    }
    fn group_member_identities(&self, group_id: Vec<u8>) -> Result<Vec<Vec<u8>>, MLSError> {
        self.ensure_loaded(&group_id)?;
        Ok(self.groups.borrow()[&group_id]
            .members()
            .map(|member| member.credential.serialized_content().to_vec())
            .collect())
    }
    fn group_is_active(&self, group_id: Vec<u8>) -> Result<bool, MLSError> {
        self.ensure_loaded(&group_id)?;
        Ok(self.groups.borrow()[&group_id].is_active())
    }
    fn merge_incoming_commit(&self, group_id: Vec<u8>, target_epoch: u64) -> Result<u64, MLSError> {
        self.merge_incoming_commit_with_outcome(group_id, target_epoch)
            .map(|outcome| outcome.epoch())
    }
    fn merge_incoming_commit_with_outcome(
        &self,
        group_id: Vec<u8>,
        target_epoch: u64,
    ) -> Result<IncomingCommitMergeOutcome, MLSError> {
        self.ensure_loaded(&group_id)?;
        if self.get_epoch(group_id.clone())?.checked_add(1) != Some(target_epoch) {
            return Err(MLSError::invalid_input(
                "incoming commit target does not follow local epoch",
            ));
        }
        let key = (group_id.clone(), target_epoch);
        let staged = self
            .pending_incoming_merges
            .borrow_mut()
            .remove(&key)
            .ok_or_else(|| MLSError::invalid_input("exact incoming commit is not staged"))?;
        let removed = staged.self_removed();
        self.groups
            .borrow_mut()
            .get_mut(&group_id)
            .expect("group loaded")
            .merge_staged_commit(&self.provider, staged)
            .map_err(|e| MLSError::OpenMLS(format!("merge_staged_commit: {e:?}")))?;
        Ok(if removed {
            IncomingCommitMergeOutcome::Removed {
                epoch: target_epoch,
            }
        } else {
            IncomingCommitMergeOutcome::Active {
                epoch: target_epoch,
            }
        })
    }
    fn discard_incoming_commit(
        &self,
        group_id: Vec<u8>,
        target_epoch: u64,
    ) -> Result<(), MLSError> {
        self.pending_incoming_merges
            .borrow_mut()
            .remove(&(group_id, target_epoch));
        Ok(())
    }
}
