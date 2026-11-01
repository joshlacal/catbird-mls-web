//! Unified WASM SQLite storage (`Spec §6.1`).
//!
//! Shares the 15-table `catbird_mls::storage::UNIFIED_SCHEMA_DDL` and single-table
//! `openmls_kv` `StorageProvider<CURRENT_VERSION>` (`OpenMlsKvStorage`) with native
//! SQLCipher over `sqlite-wasm-rs` (`opfs-sahpool` + `sqlite3mc` ChaCha20).

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use catbird_mls::orchestrator::error::{OrchestratorError, Result as OrchResult};
use catbird_mls::orchestrator::storage::{MLSStorageBackend, OPTIONAL_STORAGE_METHODS};
use catbird_mls::orchestrator::types::*;
use catbird_mls::orchestrator::welcome_recovery::{ReissueAttempt, ReissueAttemptLog};
use catbird_mls::storage::driver_wasm::WasmSqlBackend as _;
use catbird_mls::storage::openmls_kv::{OpenMlsKvError, OpenMlsKvStorage};
use catbird_mls::storage::{GroupMetadataRow, UNIFIED_SCHEMA_DDL};
use chrono::{DateTime, TimeZone, Utc};
use openmls_traits::storage::{traits, StorageProvider, CURRENT_VERSION};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::rc::Rc;

use crate::sqlite_conn::{SqliteConn, WasmSqliteError};

fn map_kv_err(err: OpenMlsKvError) -> WasmSqliteError {
    match err {
        OpenMlsKvError::Sql(message) => WasmSqliteError::Sqlite { code: 1, message },
        OpenMlsKvError::Serialization(msg) => WasmSqliteError::Serialization(msg),
        OpenMlsKvError::Keychain(err) => WasmSqliteError::Serialization(err.to_string()),
    }
}

// ---------------------------------------------------------------------------
// WasmSqliteStorage — delegates StorageProvider<CURRENT_VERSION> to OpenMlsKvStorage
// ---------------------------------------------------------------------------

pub struct WasmSqliteStorage {
    conn: Rc<SqliteConn>,
    inner: OpenMlsKvStorage<Rc<SqliteConn>>,
}

impl WasmSqliteStorage {
    pub fn new(conn: Rc<SqliteConn>) -> Self {
        let inner = OpenMlsKvStorage::new(Rc::clone(&conn));
        Self { conn, inner }
    }

    pub fn conn(&self) -> &Rc<SqliteConn> {
        &self.conn
    }

    pub fn ensure_schema(conn: &SqliteConn) -> Result<(), WasmSqliteError> {
        conn.exec_raw(UNIFIED_SCHEMA_DDL)
    }

    pub fn open(db_name: &str, key: &str) -> Result<Self, WasmSqliteError> {
        let conn = SqliteConn::open(db_name, key)?;
        Self::ensure_schema(&conn)?;
        Ok(Self::new(Rc::new(conn)))
    }
}

impl StorageProvider<CURRENT_VERSION> for WasmSqliteStorage {
    type Error = WasmSqliteError;

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        self.inner
            .queue_proposal(group_id, proposal_ref, proposal)
            .map_err(map_kv_err)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.inner
            .queued_proposal_refs(group_id)
            .map_err(map_kv_err)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        self.inner.queued_proposals(group_id).map_err(map_kv_err)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        self.inner
            .remove_proposal(group_id, proposal_ref)
            .map_err(map_kv_err)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner
            .clear_proposal_queue::<GroupId, ProposalRef>(group_id)
            .map_err(map_kv_err)
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.inner.write_tree(group_id, tree).map_err(map_kv_err)
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.inner.tree(group_id).map_err(map_kv_err)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner.delete_tree(group_id).map_err(map_kv_err)
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_context(group_id, group_context)
            .map_err(map_kv_err)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.inner.group_context(group_id).map_err(map_kv_err)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner.delete_context(group_id).map_err(map_kv_err)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_interim_transcript_hash(group_id, interim_transcript_hash)
            .map_err(map_kv_err)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.inner
            .interim_transcript_hash(group_id)
            .map_err(map_kv_err)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner
            .delete_interim_transcript_hash(group_id)
            .map_err(map_kv_err)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_confirmation_tag(group_id, confirmation_tag)
            .map_err(map_kv_err)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.inner.confirmation_tag(group_id).map_err(map_kv_err)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner
            .delete_confirmation_tag(group_id)
            .map_err(map_kv_err)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_group_state(group_id, group_state)
            .map_err(map_kv_err)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.inner.group_state(group_id).map_err(map_kv_err)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner.delete_group_state(group_id).map_err(map_kv_err)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_message_secrets(group_id, message_secrets)
            .map_err(map_kv_err)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.inner.message_secrets(group_id).map_err(map_kv_err)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner
            .delete_message_secrets(group_id)
            .map_err(map_kv_err)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_resumption_psk_store(group_id, resumption_psk)
            .map_err(map_kv_err)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.inner
            .resumption_psk_store(group_id)
            .map_err(map_kv_err)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner
            .delete_all_resumption_psk_secrets(group_id)
            .map_err(map_kv_err)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_own_leaf_index(group_id, own_leaf_index)
            .map_err(map_kv_err)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.inner.own_leaf_index(group_id).map_err(map_kv_err)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner
            .delete_own_leaf_index(group_id)
            .map_err(map_kv_err)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_group_epoch_secrets(group_id, group_epoch_secrets)
            .map_err(map_kv_err)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.inner.group_epoch_secrets(group_id).map_err(map_kv_err)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner
            .delete_group_epoch_secrets(group_id)
            .map_err(map_kv_err)
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_signature_key_pair(public_key, signature_key_pair)
            .map_err(map_kv_err)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.inner
            .signature_key_pair(public_key)
            .map_err(map_kv_err)
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.inner
            .delete_signature_key_pair(public_key)
            .map_err(map_kv_err)
    }

    fn write_encryption_key_pair<
        HpkePublicKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &HpkePublicKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_encryption_key_pair(public_key, key_pair)
            .map_err(map_kv_err)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.inner
            .encryption_key_pair(public_key)
            .map_err(map_kv_err)
    }

    fn delete_encryption_key_pair<HpkePublicKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &HpkePublicKey,
    ) -> Result<(), Self::Error> {
        self.inner
            .delete_encryption_key_pair(public_key)
            .map_err(map_kv_err)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        self.inner
            .write_encryption_epoch_key_pairs(group_id, epoch, leaf_index, key_pairs)
            .map_err(map_kv_err)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        self.inner
            .encryption_epoch_key_pairs(group_id, epoch, leaf_index)
            .map_err(map_kv_err)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        self.inner
            .delete_encryption_epoch_key_pairs(group_id, epoch, leaf_index)
            .map_err(map_kv_err)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_key_package(hash_ref, key_package)
            .map_err(map_kv_err)
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.inner.key_package(hash_ref).map_err(map_kv_err)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.inner.delete_key_package(hash_ref).map_err(map_kv_err)
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.inner.write_psk(psk_id, psk).map_err(map_kv_err)
    }

    fn psk<
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
        PskId: traits::PskId<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.inner.psk(psk_id).map_err(map_kv_err)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.inner.delete_psk(psk_id).map_err(map_kv_err)
    }

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_mls_join_config(group_id, config)
            .map_err(map_kv_err)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.inner
            .mls_group_join_config(group_id)
            .map_err(map_kv_err)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner.delete_group_config(group_id).map_err(map_kv_err)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        self.inner
            .append_own_leaf_node(group_id, leaf_node)
            .map_err(map_kv_err)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.inner.own_leaf_nodes(group_id).map_err(map_kv_err)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner
            .delete_own_leaf_nodes(group_id)
            .map_err(map_kv_err)
    }

    fn write_application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        application_export_tree: &ApplicationExportTree,
    ) -> Result<(), Self::Error> {
        self.inner
            .write_application_export_tree(group_id, application_export_tree)
            .map_err(map_kv_err)
    }

    fn application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ApplicationExportTree>, Self::Error> {
        self.inner
            .application_export_tree(group_id)
            .map_err(map_kv_err)
    }

    fn delete_application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.inner
            .delete_application_export_tree::<GroupId, ApplicationExportTree>(group_id)
            .map_err(map_kv_err)
    }
}

// ---------------------------------------------------------------------------
// WasmUnifiedStorage (`WasmStorageBackend`) — MLSStorageBackend on UNIFIED_SCHEMA_DDL
// ---------------------------------------------------------------------------

const OP_RESET_PENDING: &str = "reset_pending";
const OP_RESET_HIGH_WATER: &str = "reset_high_water";
const OP_QUARANTINE: &str = "quarantine";
const OP_WELCOME_REISSUE: &str = "welcome_reissue";
const OP_PENDING_MESSAGE: &str = "pending_message";
const OP_PENDING_LOCAL_DELETE: &str = "pending_local_delete";
const OP_CLEANUP_INTENT: &str = "cleanup_intent";
const GLOBAL_RECOVERY_SCOPE_KEY: &str = "__global__";
const CONVO_RECOVERY_PREFIX: &str = "convo:";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedResetPendingPayload {
    new_group_id_hex: String,
    reset_generation: i32,
    notified_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedQuarantinePayload {
    reason_tag: String,
    since_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredConversationEnvelope {
    user_did: String,
    group_id_str: String,
    #[serde(default)]
    historical_group_ids: Vec<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    state_version: Option<i64>,
    is_active: bool,
    state: ConversationState,
    needs_rejoin: bool,
    join_method: Option<JoinMethod>,
    join_epoch: Option<u64>,
    view: ConversationView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMessageEnvelope {
    text: String,
    payload_json: Option<String>,
    delivery_status: Option<DeliveryStatus>,
    timestamp_rfc3339: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMetadataJson {
    #[serde(default)]
    avatar_locator: Option<String>,
    #[serde(default)]
    avatar_bytes_b64: Option<String>,
    #[serde(default)]
    avatar_content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CleanupIntentPayload {
    user_did: String,
    conversation_id: String,
    group_id: String,
    reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MessageHistoryCursor {
    version: u8,
    sequence_number: u64,
    epoch: u64,
    conversation_id: String,
    id: String,
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn encode_group_id_blob(group_id_str: &str) -> Vec<u8> {
    if !group_id_str.is_empty()
        && group_id_str.len().is_multiple_of(2)
        && group_id_str.bytes().all(|b| b.is_ascii_hexdigit())
    {
        if let Ok(decoded) = hex::decode(group_id_str) {
            return decoded;
        }
    }
    group_id_str.as_bytes().to_vec()
}

fn join_method_str(method: Option<JoinMethod>) -> &'static str {
    match method {
        Some(JoinMethod::Creator) | None => "created",
        Some(JoinMethod::Welcome) => "welcome",
        Some(JoinMethod::ExternalCommit) => "external_commit",
    }
}

fn sql_to_orch_err(err: impl std::fmt::Display) -> OrchestratorError {
    OrchestratorError::Storage(err.to_string())
}

pub struct WasmUnifiedStorage {
    conn: Rc<SqliteConn>,
    active_user_did: RefCell<Option<String>>,
    content_root_key: RefCell<Option<Vec<u8>>>,
}

// WASM dedicated Workers are strictly single-threaded (`#![cfg(target_arch = "wasm32")]`).
unsafe impl Send for WasmUnifiedStorage {}
unsafe impl Sync for WasmUnifiedStorage {}

pub type WasmStorageBackend = WasmUnifiedStorage;

impl WasmUnifiedStorage {
    pub fn new(conn: Rc<SqliteConn>) -> Self {
        Self {
            conn,
            active_user_did: RefCell::new(None),
            content_root_key: RefCell::new(None),
        }
    }

    pub fn ensure_schema(conn: &SqliteConn) -> std::result::Result<(), String> {
        conn.exec_raw(UNIFIED_SCHEMA_DDL)
            .map_err(|e| format!("unified schema: {e}"))
    }

    pub fn set_active_user_did(&self, user_did: Option<String>) {
        *self.active_user_did.borrow_mut() = user_did;
    }

    pub fn set_content_root_key(&self, key: Vec<u8>) {
        *self.content_root_key.borrow_mut() = Some(key);
    }

    pub fn clear_content_root_key(&self) {
        *self.content_root_key.borrow_mut() = None;
    }

    fn load_envelope(
        &self,
        conversation_id: &str,
    ) -> std::result::Result<Option<StoredConversationEnvelope>, String> {
        let rows = self
            .conn
            .query_text(
                "SELECT state_json, needs_rejoin FROM conversations WHERE conversation_id = ?1",
                &[(1, conversation_id)],
                2,
            )
            .map_err(|e| format!("load_envelope({conversation_id}): {e}"))?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let needs_rejoin = row
            .get(1)
            .and_then(|v| v.as_deref())
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0)
            != 0;
        if let Some(Some(json)) = row.into_iter().next() {
            if !json.is_empty() {
                let mut env: StoredConversationEnvelope = serde_json::from_str(&json)
                    .map_err(|e| format!("corrupt state_json for {conversation_id}: {e}"))?;
                env.needs_rejoin = needs_rejoin;
                return Ok(Some(env));
            }
        }
        let Some(raw) = self
            .conn
            .get_conversation(conversation_id)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let group_id_str = hex::encode(&raw.group_id);
        let updated_dt = Utc
            .timestamp_millis_opt(raw.updated_at_ms)
            .single()
            .unwrap_or_else(Utc::now);
        let cached_meta = self
            .conn
            .get_group_metadata(conversation_id)
            .ok()
            .flatten();
        let meta_title = raw
            .title
            .or_else(|| cached_meta.as_ref().and_then(|m| m.title.clone()));
        let meta_desc = cached_meta.and_then(|m| m.description);
        Ok(Some(StoredConversationEnvelope {
            user_did: self.active_user_did.borrow().clone().unwrap_or_default(),
            group_id_str: group_id_str.clone(),
            historical_group_ids: Vec::new(),
            kind: None,
            state_version: None,
            is_active: true,
            state: ConversationState::Active,
            needs_rejoin: false,
            join_method: Some(JoinMethod::Creator),
            join_epoch: Some(raw.epoch.max(0) as u64),
            view: ConversationView {
                group_id: group_id_str,
                conversation_id: raw.conversation_id,
                epoch: raw.epoch.max(0) as u64,
                members: Vec::new(),
                metadata: if meta_title.is_some() || meta_desc.is_some() {
                    Some(ConversationMetadata {
                        name: meta_title,
                        description: meta_desc,
                        avatar_url: None,
                    })
                } else {
                    None
                },
                created_at: Some(updated_dt),
                updated_at: Some(updated_dt),
                sequencer_did: (!raw.sequencer_did.is_empty()).then_some(raw.sequencer_did),
                canonical_state: None,
            },
        }))
    }

    fn load_all_envelopes(
        &self,
    ) -> std::result::Result<Vec<(String, StoredConversationEnvelope)>, String> {
        let rows = self
            .conn
            .query_text(
                "SELECT conversation_id FROM conversations ORDER BY updated_at_ms DESC",
                &[],
                1,
            )
            .map_err(|e| format!("load_all_envelopes: {e}"))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            if let Some(Some(cid)) = row.into_iter().next() {
                if let Some(env) = self.load_envelope(&cid)? {
                    out.push((cid, env));
                }
            }
        }
        Ok(out)
    }

    fn save_envelope(
        &self,
        conversation_id: &str,
        env: &StoredConversationEnvelope,
    ) -> std::result::Result<(), String> {
        let state_json =
            serde_json::to_string(env).map_err(|e| format!("serialize state_json: {e}"))?;
        let group_id_blob = encode_group_id_blob(&env.group_id_str);
        let generation = env
            .view
            .canonical_state
            .as_ref()
            .map(|s| s.coordinates.generation as i64)
            .unwrap_or(0);
        let epoch = env.view.epoch as i64;
        let join_method = join_method_str(env.join_method);
        let join_epoch = env.join_epoch.unwrap_or(0) as i64;
        let state_tag = env.state.tag();
        let needs_rejoin = i64::from(env.needs_rejoin);
        let sequencer_did = env.view.sequencer_did.as_deref().unwrap_or("");
        let title = env
            .view
            .metadata
            .as_ref()
            .and_then(|m| m.name.as_deref())
            .unwrap_or("");
        let description = env
            .view
            .metadata
            .as_ref()
            .and_then(|m| m.description.as_deref())
            .unwrap_or("");
        let updated_at_ms = env
            .view
            .updated_at
            .map(|dt| dt.timestamp_millis())
            .unwrap_or_else(now_ms);

        self.conn
            .exec_with_text_int_blob_params(
                "INSERT INTO conversations (\
                    conversation_id, group_id, generation, epoch, join_method, join_epoch, \
                    state_tag, state_json, needs_rejoin, sequencer_did, \
                    title, description, updated_at_ms\
                 ) VALUES (\
                    ?1, ?2, ?3, ?4, ?5, ?6, \
                    ?7, ?8, ?9, ?10, \
                    NULLIF(?11, ''), NULLIF(?12, ''), ?13\
                 ) ON CONFLICT(conversation_id) DO UPDATE SET \
                    group_id = excluded.group_id, \
                    generation = excluded.generation, \
                    epoch = excluded.epoch, \
                    join_method = excluded.join_method, \
                    join_epoch = excluded.join_epoch, \
                    state_tag = excluded.state_tag, \
                    state_json = excluded.state_json, \
                    needs_rejoin = excluded.needs_rejoin, \
                    sequencer_did = CASE WHEN excluded.sequencer_did != '' THEN excluded.sequencer_did ELSE conversations.sequencer_did END, \
                    title = COALESCE(excluded.title, conversations.title), \
                    description = COALESCE(excluded.description, conversations.description), \
                    updated_at_ms = excluded.updated_at_ms",
                &[
                    (1, conversation_id),
                    (5, join_method),
                    (7, state_tag),
                    (8, &state_json),
                    (10, sequencer_did),
                    (11, title),
                    (12, description),
                ],
                &[
                    (3, generation),
                    (4, epoch),
                    (6, join_epoch),
                    (9, needs_rejoin),
                    (13, updated_at_ms),
                ],
                &[(2, &group_id_blob)],
            )
            .map_err(|e| format!("save_envelope({conversation_id}): {e}"))?;
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    fn load_pending_op(
        &self,
        op_kind: &str,
        op_key: &str,
    ) -> std::result::Result<Option<String>, String> {
        let rows = self
            .conn
            .query_text(
                "SELECT payload_json FROM pending_ops WHERE op_kind = ?1 AND op_key = ?2",
                &[(1, op_kind), (2, op_key)],
                1,
            )
            .map_err(|e| format!("load_pending_op({op_kind}, {op_key}): {e}"))?;
        Ok(rows.into_iter().next().and_then(|mut r| r.pop().flatten()))
    }

    fn put_pending_op(
        &self,
        op_kind: &str,
        op_key: &str,
        payload_json: &str,
        created_at_ms: i64,
    ) -> std::result::Result<(), String> {
        self.conn
            .exec_with_text_int_blob_params(
                "INSERT OR REPLACE INTO pending_ops (op_kind, op_key, payload_json, created_at_ms) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[(1, op_kind), (2, op_key), (3, payload_json)],
                &[(4, created_at_ms)],
                &[],
            )
            .map_err(|e| format!("put_pending_op({op_kind}, {op_key}): {e}"))?;
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    fn delete_pending_op(&self, op_kind: &str, op_key: &str) -> std::result::Result<bool, String> {
        let existed = self.load_pending_op(op_kind, op_key)?.is_some();
        self.conn
            .exec_with_text_int_blob_params(
                "DELETE FROM pending_ops WHERE op_kind = ?1 AND op_key = ?2",
                &[(1, op_kind), (2, op_key)],
                &[],
                &[],
            )
            .map_err(|e| format!("delete_pending_op({op_kind}, {op_key}): {e}"))?;
        let _ = self.conn.ensure_durable();
        Ok(existed)
    }

    fn load_reset_pending(
        &self,
        conversation_id: &str,
    ) -> std::result::Result<Option<PersistedResetPendingPayload>, String> {
        let Some(raw) = self.load_pending_op(OP_RESET_PENDING, conversation_id)? else {
            return Ok(None);
        };
        serde_json::from_str(&raw)
            .map(Some)
            .map_err(|e| format!("malformed persisted reset_pending for {conversation_id}: {e}"))
    }

    fn load_reset_high_water(
        &self,
        conversation_id: &str,
    ) -> std::result::Result<Option<i32>, String> {
        let Some(raw) = self.load_pending_op(OP_RESET_HIGH_WATER, conversation_id)? else {
            return Ok(None);
        };
        serde_json::from_str(&raw)
            .map(Some)
            .map_err(|e| format!("malformed reset_high_water for {conversation_id}: {e}"))
    }

    // -- Synchronous helpers called directly by `lib.rs` and `websocket.rs` --

    pub fn list_group_ids(&self) -> std::result::Result<Vec<String>, String> {
        let mut out = Vec::new();
        for (_, env) in self.load_all_envelopes()? {
            if env.is_active && !env.group_id_str.is_empty() && !out.contains(&env.group_id_str) {
                out.push(env.group_id_str);
            }
        }
        Ok(out)
    }

    pub fn conversation_group_aliases(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> std::result::Result<Vec<String>, String> {
        let Some(env) = self.load_envelope(conversation_id)? else {
            return Ok(Vec::new());
        };
        if !env.user_did.is_empty() && env.user_did != user_did {
            return Ok(Vec::new());
        }
        let mut aliases = env.historical_group_ids;
        if !env.group_id_str.is_empty() && !aliases.contains(&env.group_id_str) {
            aliases.push(env.group_id_str);
        }
        Ok(aliases)
    }

    pub fn conversation_state_version(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> std::result::Result<Option<i64>, String> {
        let Some(env) = self.load_envelope(conversation_id)? else {
            return Ok(None);
        };
        if !env.user_did.is_empty() && env.user_did != user_did {
            return Ok(None);
        }
        Ok(env.state_version.or_else(|| {
            env.view
                .canonical_state
                .as_ref()
                .map(|s| s.coordinates.state_version as i64)
        }))
    }

    pub fn conversation_kind(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> std::result::Result<Option<String>, String> {
        let Some(env) = self.load_envelope(conversation_id)? else {
            return Ok(None);
        };
        if !env.user_did.is_empty() && env.user_did != user_did {
            return Ok(None);
        }
        Ok(env.kind)
    }

    pub fn update_conversation_group_id(
        &self,
        user_did: &str,
        conversation_id: &str,
        new_group_id: &str,
    ) -> std::result::Result<(), String> {
        if let Some(mut env) = self.load_envelope(conversation_id)? {
            if !env.user_did.is_empty() && env.user_did != user_did {
                return Err("conversation owner mismatch".into());
            }
            if !env.group_id_str.is_empty()
                && env.group_id_str != new_group_id
                && !env.historical_group_ids.contains(&env.group_id_str)
            {
                env.historical_group_ids.push(env.group_id_str.clone());
            }
            env.group_id_str = new_group_id.to_string();
            env.view.group_id = new_group_id.to_string();
            self.save_envelope(conversation_id, &env)?;
        }
        Ok(())
    }

    fn resolve_metadata_convo_key(&self, group_or_convo_id: &str) -> String {
        if let Ok(envelopes) = self.load_all_envelopes() {
            for (cid, env) in envelopes {
                if cid == group_or_convo_id
                    || env.group_id_str == group_or_convo_id
                    || env.historical_group_ids.iter().any(|g| g == group_or_convo_id)
                {
                    return cid;
                }
            }
        }
        group_or_convo_id.to_string()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_metadata(
        &self,
        group_id_hex: &str,
        title: Option<&str>,
        description: Option<&str>,
        metadata_version: i64,
        avatar_blob_locator: Option<&str>,
        avatar_content_type: Option<&str>,
        avatar_bytes: Option<&[u8]>,
    ) -> std::result::Result<(), String> {
        let key = self.resolve_metadata_convo_key(group_id_hex);
        let existing = self
            .conn
            .get_group_metadata(&key)
            .map_err(|e| e.to_string())?;
        if let Some(prev) = &existing {
            if prev.metadata_version > metadata_version {
                return Ok(());
            }
        }
        let prev_json: StoredMetadataJson = existing
            .as_ref()
            .and_then(|r| serde_json::from_str(&r.metadata_json).ok())
            .unwrap_or(StoredMetadataJson {
                avatar_locator: None,
                avatar_bytes_b64: None,
                avatar_content_type: None,
            });
        let meta_json = StoredMetadataJson {
            avatar_locator: avatar_blob_locator
                .map(ToString::to_string)
                .or(prev_json.avatar_locator),
            avatar_bytes_b64: avatar_bytes
                .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
                .or(prev_json.avatar_bytes_b64),
            avatar_content_type: avatar_content_type
                .map(ToString::to_string)
                .or(prev_json.avatar_content_type),
        };
        let row = GroupMetadataRow {
            conversation_id: key,
            metadata_version,
            epoch: existing.as_ref().map(|r| r.epoch).unwrap_or(0),
            title: title
                .map(ToString::to_string)
                .or_else(|| existing.as_ref().and_then(|r| r.title.clone())),
            description: description
                .map(ToString::to_string)
                .or_else(|| existing.as_ref().and_then(|r| r.description.clone())),
            avatar_setter_did: existing.as_ref().and_then(|r| r.avatar_setter_did.clone()),
            avatar_blob_cid: avatar_blob_locator
                .map(ToString::to_string)
                .or_else(|| existing.as_ref().and_then(|r| r.avatar_blob_cid.clone())),
            avatar_sym_key: existing.as_ref().and_then(|r| r.avatar_sym_key.clone()),
            avatar_sha256: existing.as_ref().and_then(|r| r.avatar_sha256.clone()),
            avatar_mime_type: avatar_content_type
                .map(ToString::to_string)
                .or_else(|| existing.as_ref().and_then(|r| r.avatar_mime_type.clone())),
            metadata_json: serde_json::to_string(&meta_json)
                .map_err(|e| format!("serialize metadata_json: {e}"))?,
            updated_at_ms: now_ms(),
        };
        self.conn
            .upsert_group_metadata(&row)
            .map_err(|e| e.to_string())?;
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_metadata_fenced(
        &self,
        group_id_hex: &str,
        expected_state_version: Option<i64>,
        title: Option<&str>,
        description: Option<&str>,
        metadata_version: i64,
        avatar_blob_locator: Option<&str>,
        avatar_content_type: Option<&str>,
        avatar_bytes: Option<&[u8]>,
    ) -> std::result::Result<(), String> {
        let key = self.resolve_metadata_convo_key(group_id_hex);
        if let Some(expected) = expected_state_version {
            if let Some(env) = self.load_envelope(&key)? {
                if let Some(actual) = env.state_version {
                    if actual > expected {
                        return Ok(());
                    }
                }
            }
        }
        self.upsert_metadata(
            group_id_hex,
            title,
            description,
            metadata_version,
            avatar_blob_locator,
            avatar_content_type,
            avatar_bytes,
        )
    }

    pub fn get_metadata_text(
        &self,
        group_id_hex: &str,
    ) -> std::result::Result<Option<(Option<String>, Option<String>)>, String> {
        let key = self.resolve_metadata_convo_key(group_id_hex);
        let row = self
            .conn
            .get_group_metadata(&key)
            .map_err(|e| e.to_string())?;
        Ok(row.map(|r| (r.title, r.description)))
    }

    pub fn get_metadata_avatar(
        &self,
        group_id_hex: &str,
    ) -> std::result::Result<Option<(Vec<u8>, Option<String>)>, String> {
        let key = self.resolve_metadata_convo_key(group_id_hex);
        let Some(row) = self
            .conn
            .get_group_metadata(&key)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let meta: StoredMetadataJson = serde_json::from_str(&row.metadata_json).map_err(|e| {
            format!("corrupt metadata_json for {key}: {e}")
        })?;
        let Some(b64) = meta.avatar_bytes_b64 else {
            return Ok(None);
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| format!("decode avatar bytes: {e}"))?;
        Ok(Some((bytes, meta.avatar_content_type.or(row.avatar_mime_type))))
    }

    #[allow(clippy::type_complexity)]
    pub fn get_metadata_for_conversation(
        &self,
        _user_did: &str,
        conversation_id: &str,
    ) -> std::result::Result<
        (
            Option<String>,
            Option<String>,
            Option<(Vec<u8>, Option<String>)>,
            Option<i64>,
        ),
        String,
    > {
        let Some(row) = self
            .conn
            .get_group_metadata(conversation_id)
            .map_err(|e| e.to_string())?
        else {
            return Ok((None, None, None, None));
        };
        let avatar = self.get_metadata_avatar(conversation_id)?;
        Ok((row.title, row.description, avatar, Some(row.metadata_version)))
    }

    pub fn upsert_conversation_mapping(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> std::result::Result<(), String> {
        let env = if let Some(mut existing) = self.load_envelope(conversation_id)? {
            if !existing.group_id_str.is_empty()
                && existing.group_id_str != group_id
                && !existing.historical_group_ids.contains(&existing.group_id_str)
            {
                existing
                    .historical_group_ids
                    .push(existing.group_id_str.clone());
            }
            existing.user_did = user_did.to_string();
            existing.group_id_str = group_id.to_string();
            existing.is_active = true;
            existing.view.group_id = group_id.to_string();
            existing
        } else {
            let now = Utc::now();
            StoredConversationEnvelope {
                user_did: user_did.to_string(),
                group_id_str: group_id.to_string(),
                historical_group_ids: Vec::new(),
                kind: None,
                state_version: None,
                is_active: true,
                state: ConversationState::Active,
                needs_rejoin: false,
                join_method: None,
                join_epoch: None,
                view: ConversationView {
                    group_id: group_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    epoch: 0,
                    members: Vec::new(),
                    metadata: None,
                    created_at: Some(now),
                    updated_at: Some(now),
                    sequencer_did: None,
                    canonical_state: None,
                },
            }
        };
        self.save_envelope(conversation_id, &env)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_conversation_projection(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
        epoch: u64,
        members: &[MemberView],
        _expected_generation: Option<i32>,
        expected_state_version: Option<i64>,
    ) -> std::result::Result<(), String> {
        let now = Utc::now();
        let env = if let Some(mut existing) = self.load_envelope(conversation_id)? {
            if let (Some(actual), Some(expected)) = (existing.state_version, expected_state_version)
            {
                if actual > expected {
                    return Err("stale state_version in upsert_conversation_projection".into());
                }
            }
            if !existing.group_id_str.is_empty()
                && existing.group_id_str != group_id
                && !existing.historical_group_ids.contains(&existing.group_id_str)
            {
                existing
                    .historical_group_ids
                    .push(existing.group_id_str.clone());
            }
            existing.user_did = user_did.to_string();
            existing.group_id_str = group_id.to_string();
            existing.state_version = expected_state_version.or(existing.state_version);
            existing.is_active = true;
            existing.view.group_id = group_id.to_string();
            existing.view.epoch = epoch;
            existing.view.members = members.to_vec();
            existing.view.updated_at = Some(now);
            existing
        } else {
            StoredConversationEnvelope {
                user_did: user_did.to_string(),
                group_id_str: group_id.to_string(),
                historical_group_ids: Vec::new(),
                kind: None,
                state_version: expected_state_version,
                is_active: true,
                state: ConversationState::Active,
                needs_rejoin: false,
                join_method: None,
                join_epoch: Some(epoch),
                view: ConversationView {
                    group_id: group_id.to_string(),
                    conversation_id: conversation_id.to_string(),
                    epoch,
                    members: members.to_vec(),
                    metadata: None,
                    created_at: Some(now),
                    updated_at: Some(now),
                    sequencer_did: None,
                    canonical_state: None,
                },
            }
        };
        self.save_envelope(conversation_id, &env)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_reset_pending_projection(
        &self,
        user_did: &str,
        conversation_id: &str,
        expected_generation: i32,
        expected_state_version: Option<i64>,
        new_group_id: &str,
        epoch: u64,
        members: &[MemberView],
    ) -> std::result::Result<bool, String> {
        let Some(mut env) = self.load_envelope(conversation_id)? else {
            return Ok(false);
        };
        if !env.user_did.is_empty() && env.user_did != user_did {
            return Ok(false);
        }
        if let (Some(actual), Some(expected)) = (env.state_version, expected_state_version) {
            if actual != expected {
                return Ok(false);
            }
        }
        let Some(pending) = self.load_reset_pending(conversation_id)? else {
            return Ok(false);
        };
        if pending.reset_generation != expected_generation || pending.new_group_id_hex != new_group_id
        {
            return Ok(false);
        }
        if !env.group_id_str.is_empty()
            && env.group_id_str != new_group_id
            && !env.historical_group_ids.contains(&env.group_id_str)
        {
            env.historical_group_ids.push(env.group_id_str.clone());
        }
        self.delete_pending_op(OP_RESET_PENDING, conversation_id)?;
        env.group_id_str = new_group_id.to_string();
        env.view.group_id = new_group_id.to_string();
        env.view.epoch = epoch;
        env.view.members = members.to_vec();
        env.view.updated_at = Some(Utc::now());
        env.join_epoch = Some(epoch);
        env.state = ConversationState::Active;
        env.is_active = true;
        env.needs_rejoin = false;
        self.save_envelope(conversation_id, &env)?;
        Ok(true)
    }

    pub fn resolve_conversation_mapping(
        &self,
        user_did: &str,
        identifier: &str,
    ) -> std::result::Result<Option<(String, String)>, String> {
        if let Some(env) = self.load_envelope(identifier)? {
            if env.is_active && (env.user_did.is_empty() || env.user_did == user_did) {
                return Ok(Some((identifier.to_string(), env.group_id_str)));
            }
        }
        let mut matches = Vec::new();
        for (cid, env) in self.load_all_envelopes()? {
            if !env.is_active || (!env.user_did.is_empty() && env.user_did != user_did) {
                continue;
            }
            if env.group_id_str == identifier
                || env.historical_group_ids.iter().any(|g| g == identifier)
            {
                matches.push((cid, env.group_id_str));
            }
        }
        match matches.as_slice() {
            [pair] => Ok(Some(pair.clone())),
            [] => Ok(None),
            _ => Err(format!("ambiguous group mapping for {identifier}")),
        }
    }

    pub fn delete_conversation_by_group(
        &self,
        user_did: &str,
        group_id: &str,
    ) -> std::result::Result<(), String> {
        for (cid, mut env) in self.load_all_envelopes()? {
            if (env.user_did.is_empty() || env.user_did == user_did)
                && (env.group_id_str == group_id || cid == group_id)
            {
                env.is_active = false;
                env.state = ConversationState::Failed;
                self.save_envelope(&cid, &env)?;
            }
        }
        Ok(())
    }

    pub fn mark_cleanup_intent(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
        reason: &str,
    ) -> std::result::Result<(), String> {
        let payload = CleanupIntentPayload {
            user_did: user_did.to_string(),
            conversation_id: conversation_id.to_string(),
            group_id: group_id.to_string(),
            reason: reason.to_string(),
        };
        let json = serde_json::to_string(&payload)
            .map_err(|e| format!("serialize cleanup_intent: {e}"))?;
        let key = format!("{user_did}:{group_id}");
        self.put_pending_op(OP_CLEANUP_INTENT, &key, &json, now_ms())
    }

    pub fn clear_cleanup_intent(
        &self,
        user_did: &str,
        group_id: &str,
    ) -> std::result::Result<(), String> {
        let key = format!("{user_did}:{group_id}");
        self.delete_pending_op(OP_CLEANUP_INTENT, &key)?;
        Ok(())
    }

    pub fn list_cleanup_intents(
        &self,
        user_did: &str,
    ) -> std::result::Result<Vec<(String, String, String)>, String> {
        let rows = self
            .conn
            .query_text(
                "SELECT payload_json FROM pending_ops WHERE op_kind = ?1 ORDER BY created_at_ms ASC",
                &[(1, OP_CLEANUP_INTENT)],
                1,
            )
            .map_err(|e| format!("list_cleanup_intents: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            if let Some(Some(json)) = row.into_iter().next() {
                if let Ok(item) = serde_json::from_str::<CleanupIntentPayload>(&json) {
                    if item.user_did == user_did {
                        out.push((item.conversation_id, item.group_id, item.reason));
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn mark_reset_pending_sync(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> std::result::Result<(), String> {
        if let Some(existing) = self.load_reset_pending(conversation_id)? {
            if existing.reset_generation > reset_generation {
                return Err(format!("stale reset generation {reset_generation}"));
            }
            if existing.reset_generation == reset_generation
                && existing.new_group_id_hex == new_group_id_hex
            {
                return Ok(());
            }
            if existing.reset_generation == reset_generation {
                return Err(format!(
                    "conflicting reset target for generation {reset_generation}"
                ));
            }
        }
        let payload = PersistedResetPendingPayload {
            new_group_id_hex: new_group_id_hex.to_string(),
            reset_generation,
            notified_at_ms,
        };
        let json = serde_json::to_string(&payload)
            .map_err(|e| format!("serialize reset_pending: {e}"))?;
        self.put_pending_op(OP_RESET_PENDING, conversation_id, &json, notified_at_ms)?;

        let prev_high = self.load_reset_high_water(conversation_id)?.unwrap_or(0);
        let next_high = prev_high.max(reset_generation);
        self.put_pending_op(
            OP_RESET_HIGH_WATER,
            conversation_id,
            &next_high.to_string(),
            notified_at_ms,
        )?;
        let _ = self.delete_pending_op(OP_QUARANTINE, conversation_id)?;

        if let Some(mut env) = self.load_envelope(conversation_id)? {
            env.state = ConversationState::ResetPending {
                new_group_id: new_group_id_hex.to_string(),
                reset_generation,
                notified_at_ms,
            };
            env.needs_rejoin = true;
            self.save_envelope(conversation_id, &env)?;
        }
        Ok(())
    }

    pub fn reset_target_for_generation(
        &self,
        conversation_id: &str,
        generation: i32,
    ) -> std::result::Result<Option<String>, String> {
        let Some(pending) = self.load_reset_pending(conversation_id)? else {
            return Ok(None);
        };
        if pending.reset_generation == generation {
            Ok(Some(pending.new_group_id_hex))
        } else {
            Ok(None)
        }
    }

    pub fn encode_history_cursor(message: &Message) -> std::result::Result<String, String> {
        let cursor = MessageHistoryCursor {
            version: 1,
            sequence_number: message.sequence_number,
            epoch: message.epoch,
            conversation_id: message.conversation_id.clone(),
            id: message.id.clone(),
        };
        let bytes = serde_json::to_vec(&cursor).map_err(|e| e.to_string())?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub async fn get_messages_before_cursor(
        &self,
        conversation_id: &str,
        limit: u32,
        before: Option<&str>,
    ) -> OrchResult<Vec<Message>> {
        let before_seq = match before {
            None => None,
            Some(raw) => {
                if let Ok(seq) = raw.parse::<u64>() {
                    Some(seq)
                } else {
                    let bytes = URL_SAFE_NO_PAD
                        .decode(raw)
                        .map_err(|e| OrchestratorError::Storage(format!("invalid cursor: {e}")))?;
                    let parsed: MessageHistoryCursor = serde_json::from_slice(&bytes)
                        .map_err(|e| OrchestratorError::Storage(format!("corrupt cursor: {e}")))?;
                    Some(parsed.sequence_number)
                }
            }
        };
        self.get_messages(conversation_id, limit, before_seq).await
    }
}

#[async_trait(?Send)]
impl MLSStorageBackend for WasmUnifiedStorage {
    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        OPTIONAL_STORAGE_METHODS
    }

    async fn commit_conversation_projection(
        &self,
        request: &ConversationProjectionCommitRequest,
    ) -> OrchResult<ConversationProjectionCommitOutcome> {
        use ConversationProjectionCommitOutcome as Outcome;

        let view = request.canonical.as_ref().ok_or_else(|| {
            OrchestratorError::Storage(
                "conversation projection commit requires canonical ConversationView".into(),
            )
        })?;
        if request.mode != ConversationProjectionCommitMode::Live
            || request.owner_user_did.is_empty()
        {
            return Err(OrchestratorError::Storage(
                "invalid conversation projection mode or empty owner DID".into(),
            ));
        }

        let existing = self
            .load_envelope(&view.conversation_id)
            .map_err(sql_to_orch_err)?;
        let reset_pending = self
            .load_reset_pending(&view.conversation_id)
            .map_err(sql_to_orch_err)?;

        if let Some(old) = &existing {
            let effective_state = if let Some(p) = &reset_pending {
                ConversationState::ResetPending {
                    new_group_id: p.new_group_id_hex.clone(),
                    reset_generation: p.reset_generation,
                    notified_at_ms: p.notified_at_ms,
                }
            } else {
                old.state.clone()
            };

            let reset_authorized = match &effective_state {
                ConversationState::ResetPending {
                    new_group_id,
                    reset_generation,
                    ..
                } => {
                    request.canonical_lifecycle.reset_generation == Some(*reset_generation)
                        && request
                            .canonical_lifecycle
                            .reset_pending_target_group_id
                            .as_deref()
                            == Some(new_group_id.as_str())
                        && &view.group_id == new_group_id
                }
                _ => false,
            };

            if (!old.user_did.is_empty() && old.user_did != request.owner_user_did)
                || matches!(
                    effective_state,
                    ConversationState::Closed | ConversationState::DeviceRemoved
                )
                || (matches!(effective_state, ConversationState::ResetPending { .. })
                    && !reset_authorized)
            {
                return Ok(Outcome::FenceMismatch { affected_rows: 0 });
            }

            if let (Some(a), Some(b)) = (&old.view.canonical_state, &view.canonical_state) {
                if (a.coordinates.generation, a.coordinates.state_version)
                    > (b.coordinates.generation, b.coordinates.state_version)
                {
                    return Ok(Outcome::FenceMismatch { affected_rows: 0 });
                }
            }
        }

        let mut loaded_aliases = Vec::with_capacity(request.aliases.len());
        for claim in &request.aliases {
            let Some(alias) = self
                .load_envelope(&claim.alias_conversation_id)
                .map_err(sql_to_orch_err)?
            else {
                return Ok(Outcome::FenceMismatch { affected_rows: 0 });
            };
            let alias_reset = self
                .load_reset_pending(&claim.alias_conversation_id)
                .map_err(sql_to_orch_err)?;
            if alias_reset.is_some()
                || matches!(
                    alias.state,
                    ConversationState::Closed
                        | ConversationState::DeviceRemoved
                        | ConversationState::ResetPending { .. }
                )
                || claim.alias_incarnation > claim.canonical_incarnation
                || (!alias.user_did.is_empty() && alias.user_did != request.owner_user_did)
                || claim.owner_user_did != request.owner_user_did
                || alias.group_id_str != view.group_id
                || claim.alias_group_id != view.group_id
                || claim.alias_conversation_id != view.group_id
                || claim.canonical_conversation_id != view.conversation_id
                || claim.canonical_incarnation != view.epoch
                || claim.alias_incarnation != alias.view.epoch
            {
                return Ok(Outcome::FenceMismatch { affected_rows: 0 });
            }
            loaded_aliases.push((claim.alias_conversation_id.clone(), alias));
        }

        let all_rows = self.load_all_envelopes().map_err(sql_to_orch_err)?;
        let ambiguous_ids: Vec<String> = all_rows
            .into_iter()
            .filter(|(cid, env)| {
                env.is_active
                    && (env.user_did.is_empty() || env.user_did == request.owner_user_did)
                    && env.group_id_str == view.group_id
                    && cid != &view.conversation_id
                    && cid != &view.group_id
            })
            .map(|(cid, _)| cid)
            .collect();
        if !ambiguous_ids.is_empty() {
            return Ok(Outcome::Ambiguous {
                canonical_ids: ambiguous_ids,
                affected_rows: 0,
            });
        }

        let updated_env = if let Some(mut old) = existing {
            if !old.group_id_str.is_empty()
                && old.group_id_str != view.group_id
                && !old.historical_group_ids.contains(&old.group_id_str)
            {
                old.historical_group_ids.push(old.group_id_str.clone());
            }
            old.user_did = request.owner_user_did.clone();
            old.group_id_str = view.group_id.clone();
            old.view = view.clone();
            old.is_active = true;
            old
        } else {
            StoredConversationEnvelope {
                user_did: request.owner_user_did.clone(),
                group_id_str: view.group_id.clone(),
                historical_group_ids: Vec::new(),
                kind: None,
                state_version: None,
                is_active: true,
                state: ConversationState::Initializing,
                needs_rejoin: false,
                join_method: None,
                join_epoch: None,
                view: view.clone(),
            }
        };
        self.save_envelope(&view.conversation_id, &updated_env)
            .map_err(sql_to_orch_err)?;

        for (alias_id, mut alias_env) in loaded_aliases {
            alias_env.is_active = false;
            self.save_envelope(&alias_id, &alias_env)
                .map_err(sql_to_orch_err)?;
        }

        Ok(if request.aliases.is_empty() {
            Outcome::AlreadyAbsent { affected_rows: 1 }
        } else {
            Outcome::Retired {
                affected_rows: request.aliases.len() as u32 + 1,
            }
        })
    }

    async fn ensure_conversation_exists(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> OrchResult<()> {
        self.upsert_conversation_mapping(user_did, conversation_id, group_id)
            .map_err(sql_to_orch_err)
    }

    async fn update_join_info(
        &self,
        conversation_id: &str,
        _user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> OrchResult<()> {
        let Some(mut env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        else {
            return Err(OrchestratorError::ConversationNotFound(
                conversation_id.to_string(),
            ));
        };
        env.join_method = Some(join_method);
        env.join_epoch = Some(join_epoch);
        env.view.epoch = join_epoch;
        env.view.updated_at = Some(Utc::now());
        self.save_envelope(conversation_id, &env)
            .map_err(sql_to_orch_err)
    }

    async fn get_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> OrchResult<Option<ConversationView>> {
        let Some(env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        else {
            return Ok(None);
        };
        if !env.is_active || (!env.user_did.is_empty() && env.user_did != user_did) {
            return Ok(None);
        }
        Ok(Some(env.view))
    }

    async fn list_conversations(&self, user_did: &str) -> OrchResult<Vec<ConversationView>> {
        let rows = self.load_all_envelopes().map_err(sql_to_orch_err)?;
        Ok(rows
            .into_iter()
            .filter(|(_, env)| {
                env.is_active && (env.user_did.is_empty() || env.user_did == user_did)
            })
            .map(|(_, env)| env.view)
            .collect())
    }

    async fn delete_conversations(&self, user_did: &str, ids: &[&str]) -> OrchResult<()> {
        for id in ids {
            if let Some(mut env) = self.load_envelope(id).map_err(sql_to_orch_err)? {
                if env.user_did.is_empty() || env.user_did == user_did {
                    env.is_active = false;
                    env.state = ConversationState::Failed;
                    self.save_envelope(id, &env).map_err(sql_to_orch_err)?;
                }
            }
        }
        Ok(())
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> OrchResult<()> {
        if let Some(mut env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        {
            if matches!(state, ConversationState::Active) {
                env.is_active = true;
                env.needs_rejoin = false;
            }
            env.state = state;
            env.view.updated_at = Some(Utc::now());
            self.save_envelope(conversation_id, &env)
                .map_err(sql_to_orch_err)?;
        }
        Ok(())
    }

    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> OrchResult<Option<ConversationState>> {
        if let Some(pending) = self
            .load_reset_pending(conversation_id)
            .map_err(sql_to_orch_err)?
        {
            return Ok(Some(ConversationState::ResetPending {
                new_group_id: pending.new_group_id_hex,
                reset_generation: pending.reset_generation,
                notified_at_ms: pending.notified_at_ms,
            }));
        }
        let Some(env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        else {
            return Ok(None);
        };
        if matches!(env.state, ConversationState::ResetPending { .. }) {
            return Err(OrchestratorError::Storage(format!(
                "incomplete reset_pending state for {conversation_id}: payload not committed"
            )));
        }
        Ok(Some(env.state))
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> OrchResult<()> {
        if let Some(mut env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        {
            env.needs_rejoin = true;
            self.save_envelope(conversation_id, &env)
                .map_err(sql_to_orch_err)?;
        }
        Ok(())
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> OrchResult<bool> {
        Ok(self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
            .map(|e| e.needs_rejoin)
            .unwrap_or(false))
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> OrchResult<()> {
        if let Some(mut env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        {
            env.needs_rejoin = false;
            self.save_envelope(conversation_id, &env)
                .map_err(sql_to_orch_err)?;
        }
        Ok(())
    }

    async fn get_welcome_reissue_attempt_log(
        &self,
        conversation_id: &str,
    ) -> OrchResult<ReissueAttemptLog> {
        let Some(raw) = self
            .load_pending_op(OP_WELCOME_REISSUE, conversation_id)
            .map_err(sql_to_orch_err)?
        else {
            return Ok(ReissueAttemptLog::default());
        };
        let ts_list: Vec<i64> = serde_json::from_str(&raw)
            .map_err(|e| OrchestratorError::Storage(format!("corrupt welcome_reissue log: {e}")))?;
        Ok(ReissueAttemptLog {
            attempts: ts_list
                .into_iter()
                .map(|attempted_at_ms| ReissueAttempt { attempted_at_ms })
                .collect(),
        })
    }

    async fn record_welcome_reissue_attempt(
        &self,
        conversation_id: &str,
        attempted_at_ms: i64,
    ) -> OrchResult<()> {
        let mut ts_list: Vec<i64> = if let Some(raw) = self
            .load_pending_op(OP_WELCOME_REISSUE, conversation_id)
            .map_err(sql_to_orch_err)?
        {
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            Vec::new()
        };
        ts_list.push(attempted_at_ms);
        let json = serde_json::to_string(&ts_list)
            .map_err(|e| OrchestratorError::Storage(format!("serialize welcome_reissue: {e}")))?;
        self.put_pending_op(OP_WELCOME_REISSUE, conversation_id, &json, attempted_at_ms)
            .map_err(sql_to_orch_err)
    }

    async fn mark_reset_pending(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> OrchResult<()> {
        if let Some(existing) = self
            .load_reset_pending(conversation_id)
            .map_err(sql_to_orch_err)?
        {
            if existing.reset_generation >= reset_generation {
                return Err(OrchestratorError::Storage(format!(
                    "stale reset generation {reset_generation}"
                )));
            }
        }
        self.mark_reset_pending_sync(
            conversation_id,
            new_group_id_hex,
            reset_generation,
            notified_at_ms,
        )
        .map_err(sql_to_orch_err)
    }

    async fn adopt_reset_pending_target(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_old_target: &str,
        authoritative_new_target: &str,
    ) -> OrchResult<bool> {
        let canonical_hex = |value: &str| {
            !value.is_empty()
                && value.len().is_multiple_of(2)
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if !canonical_hex(expected_old_target) || !canonical_hex(authoritative_new_target) {
            return Err(OrchestratorError::Storage(
                "reset target must be non-empty canonical hex".to_string(),
            ));
        }

        let Some(pending) = self
            .load_reset_pending(conversation_id)
            .map_err(sql_to_orch_err)?
        else {
            return Ok(false);
        };
        if pending.reset_generation != expected_generation
            || pending.new_group_id_hex != expected_old_target
        {
            return Ok(false);
        }
        let updated = PersistedResetPendingPayload {
            new_group_id_hex: authoritative_new_target.to_string(),
            reset_generation: expected_generation,
            notified_at_ms: pending.notified_at_ms,
        };
        let json = serde_json::to_string(&updated)
            .map_err(|e| OrchestratorError::Storage(format!("serialize reset_pending: {e}")))?;
        self.put_pending_op(
            OP_RESET_PENDING,
            conversation_id,
            &json,
            pending.notified_at_ms,
        )
        .map_err(sql_to_orch_err)?;
        if let Some(mut env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        {
            env.state = ConversationState::ResetPending {
                new_group_id: authoritative_new_target.to_string(),
                reset_generation: expected_generation,
                notified_at_ms: pending.notified_at_ms,
            };
            env.needs_rejoin = true;
            self.save_envelope(conversation_id, &env)
                .map_err(sql_to_orch_err)?;
        }
        Ok(true)
    }

    async fn complete_reset_pending(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_new_group_id_hex: &str,
        landed_epoch: u64,
    ) -> OrchResult<bool> {
        let Some(mut env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        else {
            return Ok(false);
        };
        let Some(pending) = self
            .load_reset_pending(conversation_id)
            .map_err(sql_to_orch_err)?
        else {
            return Ok(false);
        };
        if pending.reset_generation != expected_generation
            || pending.new_group_id_hex != expected_new_group_id_hex
        {
            return Ok(false);
        }
        if !env.group_id_str.is_empty()
            && env.group_id_str != expected_new_group_id_hex
            && !env.historical_group_ids.contains(&env.group_id_str)
        {
            env.historical_group_ids.push(env.group_id_str.clone());
        }
        self.delete_pending_op(OP_RESET_PENDING, conversation_id)
            .map_err(sql_to_orch_err)?;
        env.group_id_str = expected_new_group_id_hex.to_string();
        env.view.group_id = expected_new_group_id_hex.to_string();
        env.view.epoch = landed_epoch;
        env.join_epoch = Some(landed_epoch);
        env.state = ConversationState::Active;
        env.is_active = true;
        env.needs_rejoin = false;
        env.view.updated_at = Some(Utc::now());
        self.save_envelope(conversation_id, &env)
            .map_err(sql_to_orch_err)?;
        Ok(true)
    }

    async fn complete_account_exit(
        &self,
        conversation_id: &str,
        expected_group_id_hex: &str,
        expected_reset_generation: Option<i32>,
        terminal_epoch: u64,
        terminal_state: ConversationState,
    ) -> OrchResult<bool> {
        if !matches!(
            terminal_state,
            ConversationState::Closed | ConversationState::DeviceRemoved
        ) || expected_group_id_hex.len() != 64
            || !expected_group_id_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || terminal_epoch > 9_007_199_254_740_991
            || expected_reset_generation.is_some_and(|g| g <= 0)
        {
            return Err(OrchestratorError::Storage(
                "invalid account exit tuple".into(),
            ));
        }

        let Some(mut env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        else {
            return Ok(false);
        };
        let pending = self
            .load_reset_pending(conversation_id)
            .map_err(sql_to_orch_err)?;
        let high_water = self
            .load_reset_high_water(conversation_id)
            .map_err(sql_to_orch_err)?;

        let same_terminal = env.state == terminal_state
            && env.group_id_str == expected_group_id_hex
            && env.view.epoch == terminal_epoch;
        if env.state == ConversationState::Closed && (!same_terminal || pending.is_some()) {
            return Ok(false);
        }

        let allowed = match (expected_reset_generation, pending.as_ref()) {
            (Some(expected), Some(p)) => {
                expected == p.reset_generation && p.new_group_id_hex == expected_group_id_hex
            }
            (Some(expected), None) => same_terminal && high_water == Some(expected),
            (None, None) => {
                !matches!(env.state, ConversationState::ResetPending { .. })
                    && env.group_id_str == expected_group_id_hex
            }
            (None, Some(_)) => false,
        };

        if !allowed
            || (env.group_id_str == expected_group_id_hex && env.view.epoch > terminal_epoch)
        {
            return Ok(false);
        }

        if let Some(gen) = expected_reset_generation {
            self.put_pending_op(
                OP_RESET_HIGH_WATER,
                conversation_id,
                &gen.to_string(),
                now_ms(),
            )
            .map_err(sql_to_orch_err)?;
        }
        self.delete_pending_op(OP_RESET_PENDING, conversation_id)
            .map_err(sql_to_orch_err)?;
        env.group_id_str = expected_group_id_hex.to_string();
        env.view.group_id = expected_group_id_hex.to_string();
        env.view.epoch = terminal_epoch;
        env.state = terminal_state;
        env.needs_rejoin = false;
        env.view.updated_at = Some(Utc::now());
        self.save_envelope(conversation_id, &env)
            .map_err(sql_to_orch_err)?;
        Ok(true)
    }

    async fn clear_reset_pending_for_delete(
        &self,
        conversation_id: &str,
        expected_generation: i32,
    ) -> OrchResult<bool> {
        let Some(pending) = self
            .load_reset_pending(conversation_id)
            .map_err(sql_to_orch_err)?
        else {
            return Ok(false);
        };
        if pending.reset_generation != expected_generation {
            return Ok(false);
        }
        self.delete_pending_op(OP_RESET_PENDING, conversation_id)
            .map_err(sql_to_orch_err)
    }

    async fn set_conversation_sequencer(
        &self,
        conversation_id: &str,
        sequencer_did: &str,
    ) -> OrchResult<()> {
        if let Some(mut env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        {
            env.view.sequencer_did = Some(sequencer_did.to_string());
            self.save_envelope(conversation_id, &env)
                .map_err(sql_to_orch_err)?;
        } else {
            self.conn
                .exec_with_text_int_blob_params(
                    "UPDATE conversations SET sequencer_did = ?2 WHERE conversation_id = ?1",
                    &[(1, conversation_id), (2, sequencer_did)],
                    &[],
                    &[],
                )
                .map_err(sql_to_orch_err)?;
        }
        Ok(())
    }

    async fn mark_quarantined(
        &self,
        conversation_id: &str,
        reason_tag: &str,
        since_ms: i64,
    ) -> OrchResult<()> {
        let payload = PersistedQuarantinePayload {
            reason_tag: reason_tag.to_string(),
            since_ms,
        };
        let json = serde_json::to_string(&payload)
            .map_err(|e| OrchestratorError::Storage(format!("serialize quarantine: {e}")))?;
        self.put_pending_op(OP_QUARANTINE, conversation_id, &json, since_ms)
            .map_err(sql_to_orch_err)
    }

    async fn clear_quarantine(&self, conversation_id: &str) -> OrchResult<()> {
        self.delete_pending_op(OP_QUARANTINE, conversation_id)
            .map_err(sql_to_orch_err)?;
        Ok(())
    }

    async fn store_message(&self, message: &Message) -> OrchResult<()> {
        let group_id_blob = self
            .load_envelope(&message.conversation_id)
            .map_err(sql_to_orch_err)?
            .map(|env| encode_group_id_blob(&env.group_id_str))
            .unwrap_or_default();
        let envelope = StoredMessageEnvelope {
            text: message.text.clone(),
            payload_json: message.payload_json.clone(),
            delivery_status: message.delivery_status.clone(),
            timestamp_rfc3339: message.timestamp.to_rfc3339(),
        };
        let plaintext_json = serde_json::to_string(&envelope)
            .map_err(|e| OrchestratorError::Storage(format!("serialize message: {e}")))?;
        let created_at_ms = message.timestamp.timestamp_millis();

        self.conn
            .exec_with_text_int_blob_params(
                "INSERT OR REPLACE INTO messages (\
                    message_id, conversation_id, group_id, epoch, seq, \
                    sender_did, sender_device_id, plaintext_json, created_at_ms, is_own\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                &[
                    (1, &message.id),
                    (2, &message.conversation_id),
                    (6, &message.sender_did),
                    (7, ""),
                    (8, &plaintext_json),
                ],
                &[
                    (4, message.epoch as i64),
                    (5, message.sequence_number as i64),
                    (9, created_at_ms),
                    (10, i64::from(message.is_own)),
                ],
                &[(3, &group_id_blob)],
            )
            .map_err(sql_to_orch_err)?;

        self.conn
            .exec_with_text_int_blob_params(
                "UPDATE conversations SET last_seq = MAX(last_seq, ?2), updated_at_ms = MAX(updated_at_ms, ?3) \
                 WHERE conversation_id = ?1",
                &[(1, &message.conversation_id)],
                &[(2, message.sequence_number as i64), (3, created_at_ms)],
                &[],
            )
            .map_err(sql_to_orch_err)?;
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> OrchResult<Vec<Message>> {
        let rows = self
            .conn
            .list_messages(
                conversation_id,
                before_sequence.map(|s| s as i64),
                limit as usize,
            )
            .map_err(sql_to_orch_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows.into_iter().rev() {
            let (text, payload_json, delivery_status, timestamp) =
                if let Ok(env) = serde_json::from_str::<StoredMessageEnvelope>(&row.plaintext_json)
                {
                    let ts = DateTime::parse_from_rfc3339(&env.timestamp_rfc3339)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| {
                            Utc.timestamp_millis_opt(row.created_at_ms)
                                .single()
                                .unwrap_or_else(Utc::now)
                        });
                    (env.text, env.payload_json, env.delivery_status, ts)
                } else {
                    let ts = Utc
                        .timestamp_millis_opt(row.created_at_ms)
                        .single()
                        .unwrap_or_else(Utc::now);
                    (row.plaintext_json, None, None, ts)
                };
            out.push(Message {
                id: row.message_id,
                conversation_id: row.conversation_id,
                sender_did: row.sender_did,
                text,
                timestamp,
                epoch: row.epoch.max(0) as u64,
                sequence_number: row.seq.max(0) as u64,
                is_own: row.is_own,
                delivery_status,
                payload_json,
            });
        }
        Ok(out)
    }

    async fn message_exists(&self, message_id: &str) -> OrchResult<bool> {
        self.conn
            .exists(
                "SELECT 1 FROM messages WHERE message_id = ?1 LIMIT 1",
                &[(1, message_id)],
            )
            .map_err(sql_to_orch_err)
    }

    async fn get_sync_cursor(&self, user_did: &str) -> OrchResult<SyncCursor> {
        let key = format!("sync_cursor:{user_did}");
        let Some(json) = self.conn.get_account_meta(&key).map_err(sql_to_orch_err)? else {
            return Ok(SyncCursor::default());
        };
        serde_json::from_str(&json)
            .map_err(|e| OrchestratorError::Storage(format!("corrupt sync_cursor: {e}")))
    }

    async fn set_sync_cursor(&self, user_did: &str, cursor: &SyncCursor) -> OrchResult<()> {
        let key = format!("sync_cursor:{user_did}");
        let json = serde_json::to_string(cursor)
            .map_err(|e| OrchestratorError::Storage(format!("serialize sync_cursor: {e}")))?;
        self.conn
            .put_account_meta(&key, &json, now_ms())
            .map_err(sql_to_orch_err)?;
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    async fn set_group_state(&self, state: &GroupState) -> OrchResult<()> {
        let key = format!("group_state:{}", state.group_id);
        let json = serde_json::to_string(state)
            .map_err(|e| OrchestratorError::Storage(format!("serialize group_state: {e}")))?;
        self.conn
            .put_account_meta(&key, &json, now_ms())
            .map_err(sql_to_orch_err)?;
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    async fn get_group_state(&self, group_id: &str) -> OrchResult<Option<GroupState>> {
        let exact_key = format!("group_state:{group_id}");
        if let Some(json) = self
            .conn
            .get_account_meta(&exact_key)
            .map_err(sql_to_orch_err)?
        {
            let parsed: GroupState = serde_json::from_str(&json)
                .map_err(|e| OrchestratorError::Storage(format!("corrupt group_state: {e}")))?;
            return Ok(Some(parsed));
        }
        let rows = self
            .conn
            .query_text(
                "SELECT value_json FROM account_meta WHERE key LIKE 'group_state:%'",
                &[],
                1,
            )
            .map_err(sql_to_orch_err)?;
        for row in rows {
            if let Some(Some(json)) = row.into_iter().next() {
                if let Ok(state) = serde_json::from_str::<GroupState>(&json) {
                    if state.conversation_id == group_id || state.group_id == group_id {
                        return Ok(Some(state));
                    }
                }
            }
        }
        Ok(None)
    }

    async fn delete_group_state(&self, group_id: &str) -> OrchResult<()> {
        let key = format!("group_state:{group_id}");
        self.conn
            .delete_account_meta(&key)
            .map_err(sql_to_orch_err)?;
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    async fn store_pending_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> OrchResult<()> {
        self.put_pending_op(OP_PENDING_MESSAGE, message_id, conversation_id, now_ms())
            .map_err(sql_to_orch_err)
    }

    async fn remove_pending_message(&self, message_id: &str) -> OrchResult<bool> {
        self.delete_pending_op(OP_PENDING_MESSAGE, message_id)
            .map_err(sql_to_orch_err)
    }

    async fn store_sequencer_receipt(&self, receipt: &SequencerReceipt) -> OrchResult<()> {
        let entry_id = hex::encode(&receipt.commit_hash);
        let json = serde_json::to_string(receipt)
            .map_err(|e| OrchestratorError::Storage(format!("serialize receipt: {e}")))?;
        self.conn
            .exec_with_text_int_blob_params(
                "INSERT OR REPLACE INTO sequencer_receipts \
                 (conversation_id, epoch, seq, entry_id, receipt_json) \
                 VALUES (?1, ?2, 0, ?3, ?4)",
                &[
                    (1, &receipt.convo_id),
                    (3, &entry_id),
                    (4, &json),
                ],
                &[(2, i64::from(receipt.epoch))],
                &[],
            )
            .map_err(sql_to_orch_err)?;
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    async fn get_sequencer_receipts(
        &self,
        convo_id: &str,
        since_epoch: Option<i32>,
    ) -> OrchResult<Vec<SequencerReceipt>> {
        let mut candidate_ids = vec![convo_id.to_string()];
        if let Some(env) = self.load_envelope(convo_id).map_err(sql_to_orch_err)? {
            if !env.group_id_str.is_empty() && env.group_id_str != convo_id {
                candidate_ids.push(env.group_id_str);
            }
        } else {
            for (cid, env) in self.load_all_envelopes().map_err(sql_to_orch_err)? {
                if env.group_id_str == convo_id && cid != convo_id {
                    candidate_ids.push(cid);
                }
            }
        }

        let min_epoch = i64::from(since_epoch.unwrap_or(i32::MIN));
        let mut out = Vec::new();
        for cid in candidate_ids {
            let rows = self
                .conn
                .query_text_mixed(
                    "SELECT receipt_json FROM sequencer_receipts \
                     WHERE conversation_id = ?1 AND epoch >= ?2 \
                     ORDER BY epoch ASC, entry_id ASC",
                    &[(1, &cid)],
                    &[(2, min_epoch)],
                    1,
                )
                .map_err(sql_to_orch_err)?;
            for row in rows {
                if let Some(Some(json)) = row.into_iter().next() {
                    let parsed: SequencerReceipt = serde_json::from_str(&json).map_err(|e| {
                        OrchestratorError::Storage(format!("corrupt sequencer_receipt: {e}"))
                    })?;
                    out.push(parsed);
                }
            }
        }
        Ok(out)
    }

    async fn clear_sequencer_receipts(&self, conversation_id: &str) -> OrchResult<()> {
        let mut candidate_ids = vec![conversation_id.to_string()];
        if let Some(env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        {
            if !env.group_id_str.is_empty() && env.group_id_str != conversation_id {
                candidate_ids.push(env.group_id_str);
            }
        }
        for cid in candidate_ids {
            self.conn
                .exec_with_text_int_blob_params(
                    "DELETE FROM sequencer_receipts WHERE conversation_id = ?1",
                    &[(1, &cid)],
                    &[],
                    &[],
                )
                .map_err(sql_to_orch_err)?;
        }
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    async fn cleanup_old_epoch_data(
        &self,
        conversation_id: &str,
        retain_from_epoch: u64,
    ) -> OrchResult<()> {
        self.conn
            .exec_with_text_int_blob_params(
                "DELETE FROM epoch_secrets WHERE group_id_hex = ?1 AND epoch < ?2",
                &[(1, conversation_id)],
                &[(2, retain_from_epoch as i64)],
                &[],
            )
            .map_err(sql_to_orch_err)?;
        if let Some(env) = self
            .load_envelope(conversation_id)
            .map_err(sql_to_orch_err)?
        {
            if env.group_id_str != conversation_id {
                self.conn
                    .exec_with_text_int_blob_params(
                        "DELETE FROM epoch_secrets WHERE group_id_hex = ?1 AND epoch < ?2",
                        &[(1, &env.group_id_str)],
                        &[(2, retain_from_epoch as i64)],
                        &[],
                    )
                    .map_err(sql_to_orch_err)?;
            }
        }
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    async fn get_recovery_state(&self) -> OrchResult<PersistedRecoveryState> {
        let global_rows = self
            .conn
            .query_text(
                "SELECT last_attempt_at_ms FROM recovery_state WHERE scope_key = ?1",
                &[(1, GLOBAL_RECOVERY_SCOPE_KEY)],
                1,
            )
            .map_err(sql_to_orch_err)?;
        let last_global_rejoin_attempt_at_ms = global_rows
            .into_iter()
            .next()
            .and_then(|mut r| r.pop().flatten())
            .and_then(|v| v.parse::<i64>().ok());

        let rows = self
            .conn
            .query_text(
                "SELECT scope_key, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms, extra_json \
                 FROM recovery_state WHERE scope_key LIKE 'convo:%'",
                &[],
                5,
            )
            .map_err(sql_to_orch_err)?;
        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            let scope_key = row
                .first()
                .and_then(|v| v.clone())
                .unwrap_or_default();
            let failed_rejoin_count = row
                .get(1)
                .and_then(|v| v.as_deref())
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0)
                .max(0) as u32;
            let last_attempt_at_ms = row
                .get(2)
                .and_then(|v| v.as_deref())
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            let quarantined_until_ms = row
                .get(3)
                .and_then(|v| v.as_deref())
                .and_then(|v| v.parse::<i64>().ok());
            let extra_json = row.get(4).and_then(|v| v.clone());
            let conversation_id = extra_json.unwrap_or_else(|| {
                scope_key
                    .strip_prefix(CONVO_RECOVERY_PREFIX)
                    .unwrap_or(&scope_key)
                    .to_string()
            });
            entries.push(PersistedRecoveryBackoff {
                conversation_id,
                failed_rejoin_count,
                last_attempt_at_ms,
                quarantined_until_ms,
            });
        }
        Ok(PersistedRecoveryState {
            entries,
            last_global_rejoin_attempt_at_ms,
        })
    }

    async fn set_recovery_backoff(&self, entry: &PersistedRecoveryBackoff) -> OrchResult<()> {
        let scope_key = format!("{CONVO_RECOVERY_PREFIX}{}", entry.conversation_id);
        match entry.quarantined_until_ms {
            Some(q_ms) => self
                .conn
                .exec_with_text_int_blob_params(
                    "INSERT OR REPLACE INTO recovery_state \
                     (scope_key, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms, extra_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[(1, &scope_key), (5, &entry.conversation_id)],
                    &[
                        (2, i64::from(entry.failed_rejoin_count)),
                        (3, entry.last_attempt_at_ms),
                        (4, q_ms),
                    ],
                    &[],
                )
                .map_err(sql_to_orch_err)?,
            None => self
                .conn
                .exec_with_text_int_blob_params(
                    "INSERT OR REPLACE INTO recovery_state \
                     (scope_key, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms, extra_json) \
                     VALUES (?1, ?2, ?3, NULL, ?4)",
                    &[(1, &scope_key), (4, &entry.conversation_id)],
                    &[
                        (2, i64::from(entry.failed_rejoin_count)),
                        (3, entry.last_attempt_at_ms),
                    ],
                    &[],
                )
                .map_err(sql_to_orch_err)?,
        }
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    async fn clear_recovery_backoff(&self, conversation_id: &str) -> OrchResult<()> {
        let scope_key = format!("{CONVO_RECOVERY_PREFIX}{conversation_id}");
        self.conn
            .exec_with_text_int_blob_params(
                "DELETE FROM recovery_state WHERE scope_key = ?1",
                &[(1, &scope_key)],
                &[],
                &[],
            )
            .map_err(sql_to_orch_err)?;
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    async fn set_last_global_rejoin_attempt_at(&self, at_ms: i64) -> OrchResult<()> {
        self.conn
            .exec_with_text_int_blob_params(
                "INSERT OR REPLACE INTO recovery_state \
                 (scope_key, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms, extra_json) \
                 VALUES (?1, 0, ?2, NULL, NULL)",
                &[(1, GLOBAL_RECOVERY_SCOPE_KEY)],
                &[(2, at_ms)],
                &[],
            )
            .map_err(sql_to_orch_err)?;
        let _ = self.conn.ensure_durable();
        Ok(())
    }

    async fn mark_pending_local_delete(
        &self,
        conversation_id: &str,
        group_id_hex: Option<&str>,
    ) -> OrchResult<()> {
        let intent = PendingLocalDelete {
            conversation_id: conversation_id.to_string(),
            group_id_hex: group_id_hex.map(ToString::to_string),
        };
        let json = serde_json::to_string(&intent).map_err(|e| {
            OrchestratorError::Storage(format!("serialize pending_local_delete: {e}"))
        })?;
        self.put_pending_op(OP_PENDING_LOCAL_DELETE, conversation_id, &json, now_ms())
            .map_err(sql_to_orch_err)
    }

    async fn clear_pending_local_delete(&self, conversation_id: &str) -> OrchResult<()> {
        self.delete_pending_op(OP_PENDING_LOCAL_DELETE, conversation_id)
            .map_err(sql_to_orch_err)?;
        Ok(())
    }

    async fn list_pending_local_deletes(&self) -> OrchResult<Vec<PendingLocalDelete>> {
        let rows = self
            .conn
            .query_text(
                "SELECT payload_json FROM pending_ops WHERE op_kind = ?1 ORDER BY created_at_ms ASC",
                &[(1, OP_PENDING_LOCAL_DELETE)],
                1,
            )
            .map_err(sql_to_orch_err)?;
        let mut out = Vec::new();
        for row in rows {
            if let Some(Some(json)) = row.into_iter().next() {
                let parsed: PendingLocalDelete = serde_json::from_str(&json).map_err(|e| {
                    OrchestratorError::Storage(format!("corrupt pending_local_delete: {e}"))
                })?;
                out.push(parsed);
            }
        }
        Ok(out)
    }
}
