//! Browser WASM `#[wasm_bindgen]` wrapper around unified `catbird_mls::client` + `WasmAccountDb` (`Spec §6.3`, `G2`, `D3`, `D4`, `I6`, `I8`, `I15`, `I16`).

use std::cell::RefCell;
use std::rc::Rc;

use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use catbird_mls::canonical_transport::derive_key_id;
use catbird_mls::client::{
    account_did_hash_hex, evaluate_spaces_eligibility, execute_pq_otc_handshake,
    generate_otc_offer, generate_recovery_code_vdevice, normalize_account_did,
    personal_mailbox_space_uri, verify_recovery_code_vdevice, CircleOwnerStateDto,
    EnrollmentReceipt, LabyrinthBackupStatus, SpacesEligibilityInput,
    UploadedConversationAttachment,
};
use catbird_mls::groups::lifecycle::MemberRole;
use catbird_mls::requests::c33::{
    validate_direct_request_key_package_lifetime, DIRECT_REQUEST_KP_MIN_LIFETIME_SECS,
    RECOVERY_KP_MAX_LIFETIME_SECS,
};
use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend};
use catbird_mls::storage::{MutationJournalRow, OpenMlsKvProvider};
use catbird_mls::MLSError;

use crate::sqlite_conn::SqliteConn;

pub(crate) const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

pub(crate) fn mls_to_js_err(err: MLSError) -> JsValue {
    JsValue::from_str(&err.to_string())
}

fn to_js_val<T: serde::Serialize>(val: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(val).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Conversation Space URI (`at:space/{sequencerDid}/blue.catbird.labyrinth.conversation/{skey}`).
pub(crate) fn conversation_space_uri(sequencer_did: &str, skey: &str) -> String {
    atproto_spaces::SpaceUri::conversation(sequencer_did, skey)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| {
            format!("at:space/{sequencer_did}/blue.catbird.labyrinth.conversation/{skey}")
        })
}

pub(crate) fn now_ms() -> i64 {
    js_sys::Date::now() as i64
}

pub(crate) fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0).max(0.0) as u64
}

pub(crate) fn uuid_v4(value: &str) -> Option<uuid::Uuid> {
    let uuid = uuid::Uuid::parse_str(value.trim()).ok()?;
    (uuid.get_version_num() == 4 && uuid.get_variant() == uuid::Variant::RFC4122).then_some(uuid)
}

pub(crate) type PendingOtcInitiator = (String, labyrinth::otc::Initiator, u32, [u8; 32]);

/// Unified browser WASM MLS client backed by per-account `catbird-mls/<did_hash>.db` on OPFS (`sqlite3mc` ChaCha20).
#[wasm_bindgen]
pub struct WasmMlsClient {
    pub(crate) account_did: String,
    pub(crate) account_did_hash: String,
    pub(crate) device_id: String,
    pub(crate) home_ds_did: String,
    pub(crate) home_ds_endpoint: String,
    pub(crate) pds_endpoint: String,
    pub(crate) auth_token: RefCell<Option<String>>,
    pub(crate) http: reqwest::Client,
    pub(crate) db: Option<WasmAccountDb<Rc<SqliteConn>>>,
    pub(crate) pending_otc_initiator: RefCell<Option<PendingOtcInitiator>>,
    pub(crate) pending_otc_offer_digits: RefCell<Option<Zeroizing<String>>>,
}

#[wasm_bindgen]
impl WasmMlsClient {
    /// Open or create `catbird-mls/<did_hash>.db` inside the Dedicated Worker's OPFS SAH pool (`I8`).
    #[wasm_bindgen(constructor)]
    pub fn open(
        account_did: String,
        device_id: String,
        home_ds_did: String,
        home_ds_endpoint: String,
        pds_endpoint: String,
        db_key_hex: String,
    ) -> Result<WasmMlsClient, JsValue> {
        let normalized_did = normalize_account_did(&account_did).map_err(mls_to_js_err)?;
        let did_hash = account_did_hash_hex(&normalized_did).map_err(mls_to_js_err)?;
        let db_path = format!("catbird-mls/{did_hash}.db");
        Self::open_with_db_path(
            account_did,
            device_id,
            home_ds_did,
            home_ds_endpoint,
            pds_endpoint,
            db_key_hex,
            &db_path,
        )
    }

    /// Initialize persistent OPFS storage (`multipleciphers-opfs-sahpool`) in this Dedicated Worker
    /// before opening `catbird-mls/<did_hash>.db` (`I8`).
    #[wasm_bindgen(js_name = openAsync)]
    pub async fn open_async(
        account_did: String,
        device_id: String,
        home_ds_did: String,
        home_ds_endpoint: String,
        pds_endpoint: String,
        db_key_hex: String,
    ) -> Result<WasmMlsClient, JsValue> {
        SqliteConn::initialize_opfs().await.map_err(|e| {
            JsValue::from_str(&format!("Persistent encrypted storage unavailable: {e}"))
        })?;
        Self::open(
            account_did,
            device_id,
            home_ds_did,
            home_ds_endpoint,
            pds_endpoint,
            db_key_hex,
        )
    }

    fn require_db(&self) -> Result<&WasmAccountDb<Rc<SqliteConn>>, JsValue> {
        self.db
            .as_ref()
            .ok_or_else(|| JsValue::from_str("WasmMlsClient handle is closed"))
    }

    fn wipe_and_close_local_storage(&mut self) -> Result<(), MLSError> {
        *self.auth_token.borrow_mut() = None;
        crate::sync_public_api_state(&self.home_ds_endpoint, &self.home_ds_did, None);
        *self.pending_otc_initiator.borrow_mut() = None;
        *self.pending_otc_offer_digits.borrow_mut() = None;
        if let Some(db) = self.db.take() {
            let db_path = db.backend().db_path().to_owned();
            let _ = db.write_tx(|tx| tx.wipe_all_tables());
            drop(db);
            let _ = SqliteConn::delete_opfs_database(&db_path);
        }
        Ok(())
    }

    /// Inject or refresh the `nest` BFF / OAuth bearer session token for live XRPC dispatches.
    #[wasm_bindgen(js_name = setAuthToken)]
    pub fn set_auth_token(&self, token: Option<String>) {
        let cleaned = token.filter(|s| !s.trim().is_empty());
        crate::sync_public_api_state(
            &self.home_ds_endpoint,
            &self.home_ds_did,
            cleaned.as_deref(),
        );
        *self.auth_token.borrow_mut() = cleaned;
    }

    #[wasm_bindgen(js_name = accountDid)]
    pub fn account_did(&self) -> String {
        self.account_did.clone()
    }

    #[wasm_bindgen(js_name = accountDidHash)]
    pub fn account_did_hash(&self) -> String {
        self.account_did_hash.clone()
    }

    #[wasm_bindgen(js_name = deviceId)]
    pub fn device_id(&self) -> String {
        self.device_id.clone()
    }

    #[wasm_bindgen(js_name = homeDsDid)]
    pub fn home_ds_did(&self) -> String {
        self.home_ds_did.clone()
    }

    #[wasm_bindgen(js_name = homeDsEndpoint)]
    pub fn home_ds_endpoint(&self) -> String {
        self.home_ds_endpoint.clone()
    }

    #[wasm_bindgen(js_name = pdsEndpoint)]
    pub fn pds_endpoint(&self) -> String {
        self.pds_endpoint.clone()
    }

    /// Evaluate `I15` Spaces capability and Labyrinth OAuth scopes.
    #[wasm_bindgen(js_name = evaluateSpacesEligibility)]
    pub fn evaluate_spaces_eligibility_js(
        &self,
        pds_supports_spaces: bool,
        granted_scopes_js: JsValue,
    ) -> Result<JsValue, JsValue> {
        let granted_oauth_scopes: Vec<String> =
            serde_wasm_bindgen::from_value(granted_scopes_js)
                .map_err(|e| JsValue::from_str(&format!("invalid granted_scopes array: {e}")))?;
        let status = evaluate_spaces_eligibility(&SpacesEligibilityInput {
            account_did: self.account_did.clone(),
            pds_endpoint: self.pds_endpoint.clone(),
            pds_supports_spaces,
            granted_oauth_scopes,
        });
        to_js_val(&status)
    }

    /// Enroll this Web Worker device after enforcing `I15` Spaces gate, minting `X-Wing`
    /// KeyPackages (`C33` >= 35d direct-request + <= 30d recovery), publishing `ADR-009`
    /// `blue.catbird.chat.device` + `blue.catbird.chat.declaration` + `mls-ds` `enrollDevice`
    /// outside `WasmAccountDb::write_tx` (`I6`), and initializing Labyrinth (`D4`).
    #[wasm_bindgen(js_name = enrollDevice)]
    pub async fn enroll_device(
        &self,
        pds_supports_spaces: bool,
        granted_scopes_js: JsValue,
    ) -> Result<JsValue, JsValue> {
        let granted_oauth_scopes: Vec<String> =
            serde_wasm_bindgen::from_value(granted_scopes_js)
                .map_err(|e| JsValue::from_str(&format!("invalid granted_scopes array: {e}")))?;
        let eligibility = evaluate_spaces_eligibility(&SpacesEligibilityInput {
            account_did: self.account_did.clone(),
            pds_endpoint: self.pds_endpoint.clone(),
            pds_supports_spaces,
            granted_oauth_scopes,
        });
        if !eligibility.eligible {
            return Err(JsValue::from_str(&format!(
                "Spaces-required gate blocked enrollment: {}",
                eligibility.user_message
            )));
        }

        let db = self.require_db()?;
        let canonical_device_uuid = uuid_v4(&self.device_id)
            .ok_or_else(|| JsValue::from_str("device_id must be a UUIDv4"))?;
        let canonical_device_id = canonical_device_uuid.hyphenated().to_string();
        let cred_identity = format!("{}#{canonical_device_id}", self.account_did);
        if db
            .backend()
            .get_account_meta("auth_generation")
            .map_err(mls_to_js_err)?
            .is_some()
        {
            let bound_device = db
                .backend()
                .get_account_meta("enrolled_device_id")
                .map_err(mls_to_js_err)?;
            let matches_device =
                |candidate: &str| uuid_v4(candidate).as_ref() == Some(&canonical_device_uuid);
            let device_matches = if let Some(bound) = bound_device {
                matches_device(&bound)
            } else {
                db.backend()
                    .get_labyrinth_state("status_json")
                    .map_err(mls_to_js_err)?
                    .and_then(|raw| serde_json::from_slice::<LabyrinthBackupStatus>(&raw).ok())
                    .is_some_and(|status| {
                        status
                            .active_device_ids
                            .iter()
                            .any(|device| matches_device(device))
                    })
            };
            let signer_raw = db
                .backend()
                .get_labyrinth_state("device_signer_json")
                .map_err(mls_to_js_err)?
                .ok_or_else(|| JsValue::from_str("Enrollment signer binding is missing"))?;
            let bound_signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                .map_err(|e| JsValue::from_str(&format!("deserialize device signer: {e}")))?;
            let key_matches = db
                .backend()
                .get_account_meta("enrolled_signer_key_id")
                .map_err(mls_to_js_err)?
                .is_none_or(|key| key == derive_key_id(bound_signer.public()));
            if !device_matches || !key_matches {
                return Err(JsValue::from_str(
                    "Enrollment device identity does not match the retained signer",
                ));
            }
        }

        let now_s = now_secs();
        let dr_lifetime_secs = DIRECT_REQUEST_KP_MIN_LIFETIME_SECS + 86_400 * 5;
        validate_direct_request_key_package_lifetime(now_s, now_s + dr_lifetime_secs)
            .map_err(mls_to_js_err)?;
        let dr_lifetime = Lifetime::new(dr_lifetime_secs);
        let rec_lifetime = Lifetime::new(RECOVERY_KP_MAX_LIFETIME_SECS - 3_600);

        let mailbox_uri = personal_mailbox_space_uri(&self.account_did);
        let ts = now_ms();

        let (signer, dr_kp_bytes, rec_kp_bytes) = db
            .write_tx(|tx| {
                let signer = match tx.get_labyrinth_state("device_signer_json")? {
                    Some(raw) => serde_json::from_slice::<SignatureKeyPair>(&raw).map_err(|e| {
                        MLSError::Internal(format!("deserialize device_signer_json: {e}"))
                    })?,
                    None => SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
                        .map_err(|e| MLSError::Internal(format!("SignatureKeyPair::new: {e:?}")))?,
                };
                let provider =
                    OpenMlsKvProvider::new(catbird_mls::storage::OpenMlsKvStorage::new(tx))?;
                signer
                    .store(provider.storage())
                    .map_err(|e| MLSError::Internal(format!("store signer: {e:?}")))?;
                let cred_with_key = CredentialWithKey {
                    credential: BasicCredential::new(cred_identity.as_bytes().to_vec()).into(),
                    signature_key: signer.public().into(),
                };
                let caps = Capabilities::builder()
                    .ciphersuites(vec![CIPHERSUITE])
                    .build();
                let dr_bundle = KeyPackage::builder()
                    .leaf_node_capabilities(caps.clone())
                    .key_package_lifetime(dr_lifetime)
                    .build(CIPHERSUITE, &provider, &signer, cred_with_key.clone())
                    .map_err(|e| MLSError::Internal(format!("build dr kp: {e:?}")))?;
                let rec_bundle = KeyPackage::builder()
                    .leaf_node_capabilities(caps)
                    .key_package_lifetime(rec_lifetime)
                    .build(CIPHERSUITE, &provider, &signer, cred_with_key)
                    .map_err(|e| MLSError::Internal(format!("build rec kp: {e:?}")))?;

                let dr_bytes = dr_bundle
                    .key_package()
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("ser dr kp: {e:?}")))?;
                let rec_bytes = rec_bundle
                    .key_package()
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("ser rec kp: {e:?}")))?;

                let signer_json = serde_json::to_vec(&signer)
                    .map_err(|e| MLSError::Internal(format!("ser signer: {e}")))?;
                tx.put_labyrinth_state("device_signer_json", &signer_json, ts)?;

                if tx.get_labyrinth_state("status_json")?.is_none() {
                    let status = LabyrinthBackupStatus {
                        backup_enabled: true,
                        mailbox_space_uri: mailbox_uri.clone(),
                        has_recovery_code: false,
                        has_passkey_prf: false,
                        recovery_needs_attention: false,
                        recovery_generation: 0,
                        epoch_seq: 1,
                        active_device_ids: vec![canonical_device_id.clone()],
                        recovery_method_stale: false,
                        rotation_exclusions: Vec::new(),
                        pending_directory_epoch: None,
                        directory_publication_stalled: false,
                        directory_publication_retry_count: 0,
                        directory_publication_error: None,
                    };
                    tx.put_labyrinth_state(
                        "status_json",
                        &serde_json::to_vec(&status)
                            .map_err(|e| MLSError::Internal(e.to_string()))?,
                        ts,
                    )?;
                }
                Ok((signer, dr_bytes, rec_bytes))
            })
            .map_err(mls_to_js_err)?;
        let pub_key = signer.public().to_vec();

        if let Some((session_token, canonical_dev_id)) = self.live_session() {
            self.enroll_device_live(&session_token, &canonical_dev_id, &signer)
                .await
                .map_err(mls_to_js_err)?;
        }

        let receipt = EnrollmentReceipt {
            account_did: self.account_did.clone(),
            account_did_hash: self.account_did_hash.clone(),
            device_id: canonical_device_id,
            signature_public_key: pub_key,
            direct_request_kp_bytes: dr_kp_bytes,
            recovery_kp_bytes: rec_kp_bytes,
            mailbox_space_uri: mailbox_uri,
            labyrinth_backup_enabled: true,
        };
        to_js_val(&receipt)
    }

    #[wasm_bindgen(js_name = isDevicePendingApproval)]
    pub fn is_device_pending_approval(&self) -> Result<bool, JsValue> {
        self.is_device_pending_approval_impl()
            .map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = approveDevice)]
    pub async fn approve_device(&self, target_device_id: String) -> Result<(), JsValue> {
        self.approve_device_impl(&target_device_id)
            .await
            .map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = approveDeviceWithKey)]
    pub async fn approve_device_with_key(
        &self,
        target_device_id: String,
        target_signature_public_key: &[u8],
        target_auth_generation: i64,
    ) -> Result<(), JsValue> {
        self.approve_device_with_key_impl(
            &target_device_id,
            target_signature_public_key,
            target_auth_generation,
        )
        .await
        .map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = listDevices)]
    pub async fn list_devices(&self) -> Result<JsValue, JsValue> {
        let devices = self.list_devices_impl().await.map_err(mls_to_js_err)?;
        to_js_val(&devices)
    }

    #[wasm_bindgen(js_name = revokeDevice)]
    pub async fn revoke_device(&self, target_device_id: String) -> Result<JsValue, JsValue> {
        let report = self
            .revoke_device_impl(&target_device_id)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&report)
    }

    #[wasm_bindgen(js_name = retireCurrentDevice)]
    pub async fn retire_current_device(&mut self) -> Result<(), JsValue> {
        self.retire_current_device_pre_wipe()
            .await
            .map_err(mls_to_js_err)?;
        self.wipe_and_close_local_storage().map_err(mls_to_js_err)
    }

    /// Fail-closed `D-3` account deletion: purges `OwnerMailbox`, `mailboxKeys` PDS records,
    /// `mls-ds` `deleteAccountData`, and owned conversation Space records BEFORE wiping local OPFS.
    #[wasm_bindgen(js_name = deleteAccountData)]
    pub async fn delete_account_data(&mut self) -> Result<(), JsValue> {
        self.delete_account_data_remote_impl()
            .await
            .map_err(mls_to_js_err)?;
        self.wipe_and_close_local_storage().map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = replenishKeyPackages)]
    pub async fn replenish_key_packages(&self, count: u32) -> Result<u32, JsValue> {
        self.replenish_key_packages_impl(count)
            .await
            .map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = listConversations)]
    pub fn list_conversations(
        &self,
        before_updated_ms: Option<i64>,
        limit: u32,
    ) -> Result<JsValue, JsValue> {
        let rows = self
            .require_db()?
            .backend()
            .list_conversations(before_updated_ms, limit as usize)
            .map_err(mls_to_js_err)?;
        to_js_val(&rows)
    }

    #[wasm_bindgen(js_name = listMessages)]
    pub fn list_messages(
        &self,
        conversation_id: String,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<JsValue, JsValue> {
        let rows = self
            .require_db()?
            .backend()
            .list_messages(&conversation_id, before_seq, limit as usize)
            .map_err(mls_to_js_err)?;
        to_js_val(&rows)
    }

    #[wasm_bindgen(js_name = listRequests)]
    pub fn list_requests(&self, consent_filter: Option<String>) -> Result<JsValue, JsValue> {
        let rows = self
            .require_db()?
            .backend()
            .list_requests(consent_filter.as_deref())
            .map_err(mls_to_js_err)?;
        to_js_val(&rows)
    }

    #[wasm_bindgen(js_name = listMembers)]
    pub fn list_members(&self, conversation_id: String) -> Result<JsValue, JsValue> {
        let members = self
            .list_members_impl(&conversation_id)
            .map_err(mls_to_js_err)?;
        to_js_val(&members)
    }

    #[wasm_bindgen(js_name = getGroupMetadata)]
    pub fn get_group_metadata(&self, conversation_id: String) -> Result<JsValue, JsValue> {
        let row = self
            .require_db()?
            .backend()
            .get_group_metadata(&conversation_id)
            .map_err(mls_to_js_err)?;
        to_js_val(&row)
    }

    #[wasm_bindgen(js_name = createGroup)]
    pub async fn create_group(
        &self,
        conversation_id: String,
        sequencer_did: String,
        member_dids_js: JsValue,
        title: Option<String>,
        description: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let member_dids: Vec<String> = if member_dids_js.is_null() || member_dids_js.is_undefined()
        {
            Vec::new()
        } else {
            serde_wasm_bindgen::from_value(member_dids_js)
                .map_err(|e| JsValue::from_str(&format!("invalid member_dids array: {e}")))?
        };
        let convo = self
            .create_group_impl(
                conversation_id,
                sequencer_did,
                member_dids,
                title,
                description,
            )
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&convo)
    }

    #[wasm_bindgen(js_name = addGroupMembers)]
    pub async fn add_group_members(
        &self,
        conversation_id: String,
        member_dids_js: JsValue,
    ) -> Result<JsValue, JsValue> {
        let member_dids: Vec<String> = serde_wasm_bindgen::from_value(member_dids_js)
            .map_err(|e| JsValue::from_str(&format!("invalid member_dids array: {e}")))?;
        let convo = self
            .add_group_members_impl(&conversation_id, member_dids)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&convo)
    }

    #[wasm_bindgen(js_name = sendMessage)]
    pub async fn send_message(
        &self,
        conversation_id: String,
        message_id: String,
        text: String,
    ) -> Result<JsValue, JsValue> {
        let row = self
            .send_message_impl(&conversation_id, &message_id, &text)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&row)
    }

    /// Publish an MLS-authenticated policy change. The control message itself never enters
    /// history backup, while its sequenced setting applies to later messages.
    #[wasm_bindgen(js_name = setHistoryBackupEnabled)]
    pub async fn set_history_backup_enabled(
        &self,
        conversation_id: String,
        enabled: bool,
    ) -> Result<JsValue, JsValue> {
        let frame = serde_json::json!({
            "version": 1,
            "messageType": "system",
            "text": if enabled { "History backup turned on" } else { "History backup turned off" },
            "historyBackupChange": enabled,
            "backupPolicy": 1,
            "noBackup": true,
        });
        let row = self
            .send_message_impl(
                &conversation_id,
                &uuid::Uuid::new_v4().to_string(),
                &frame.to_string(),
            )
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&row)
    }

    #[wasm_bindgen(js_name = uploadConversationAttachment)]
    pub async fn upload_conversation_attachment(
        &self,
        conversation_id: String,
        plaintext: &[u8],
        mime_type: String,
    ) -> Result<JsValue, JsValue> {
        let uploaded = self
            .upload_conversation_attachment_impl(&conversation_id, plaintext, mime_type)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&uploaded)
    }

    #[wasm_bindgen(js_name = downloadConversationAttachment)]
    pub async fn download_conversation_attachment(
        &self,
        locator: String,
        symmetric_key: &[u8],
        iv: &[u8],
        expected_sha256: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, JsValue> {
        self.download_conversation_attachment_impl(
            &locator,
            symmetric_key,
            iv,
            expected_sha256.as_deref(),
        )
        .await
        .map_err(mls_to_js_err)
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = sendMediaAttachmentMessage)]
    pub async fn send_media_attachment_message(
        &self,
        conversation_id: String,
        message_id: String,
        text: String,
        uploaded_js: JsValue,
        width: Option<u32>,
        height: Option<u32>,
        alt_text: Option<String>,
        duration_ms: Option<u64>,
        waveform_js: JsValue,
        transcript: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let uploaded: UploadedConversationAttachment = serde_wasm_bindgen::from_value(uploaded_js)
            .map_err(|e| JsValue::from_str(&format!("invalid uploaded attachment: {e}")))?;
        let waveform: Option<Vec<f32>> = if waveform_js.is_null() || waveform_js.is_undefined() {
            None
        } else {
            Some(
                serde_wasm_bindgen::from_value(waveform_js)
                    .map_err(|e| JsValue::from_str(&format!("invalid waveform array: {e}")))?,
            )
        };
        let row = self
            .send_media_attachment_message_impl(
                &conversation_id,
                &message_id,
                &text,
                &uploaded,
                width,
                height,
                alt_text,
                duration_ms,
                waveform,
                transcript,
            )
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&row)
    }

    #[wasm_bindgen(js_name = leaveConversation)]
    pub async fn leave_conversation(&self, conversation_id: String) -> Result<JsValue, JsValue> {
        let out = self
            .leave_conversation_impl(&conversation_id)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&out)
    }

    #[wasm_bindgen(js_name = fulfillPendingGroupLeaves)]
    pub async fn fulfill_pending_group_leaves(&self) -> Result<u32, JsValue> {
        self.fulfill_pending_group_leaves_impl()
            .await
            .map_err(mls_to_js_err)
    }

    /// Enforce `D3` (`M-F01`) admin-only member removal and dispatch `#commitTransitionBody` on live sessions.
    #[wasm_bindgen(js_name = removeGroupMember)]
    pub async fn remove_group_member(
        &self,
        is_admin: bool,
        conversation_id: String,
        target_did: String,
    ) -> Result<(), JsValue> {
        let role = if is_admin {
            MemberRole::Admin
        } else {
            MemberRole::Member
        };
        self.remove_group_member_impl(role, &conversation_id, &target_did)
            .await
            .map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = updateGroupMetadata)]
    pub async fn update_group_metadata(
        &self,
        conversation_id: String,
        title: String,
        description: String,
    ) -> Result<JsValue, JsValue> {
        let row = self
            .update_group_metadata_impl(&conversation_id, title, description)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&row)
    }

    #[wasm_bindgen(js_name = acceptDirectRequest)]
    pub async fn accept_direct_request(&self, request_id: String) -> Result<(), JsValue> {
        self.accept_direct_request_impl(&request_id)
            .await
            .map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = declineDirectRequest)]
    pub async fn decline_direct_request(&self, request_id: String) -> Result<(), JsValue> {
        self.decline_direct_request_impl(&request_id)
            .await
            .map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = flushLabyrinthQueue)]
    pub async fn flush_labyrinth_queue(&self) -> Result<u32, JsValue> {
        self.flush_labyrinth_queue_impl()
            .await
            .map_err(mls_to_js_err)
    }

    #[wasm_bindgen]
    pub async fn sync(&self) -> Result<u32, JsValue> {
        self.sync_impl().await.map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = acknowledgeEntriesUpTo)]
    pub async fn acknowledge_entries_up_to(
        &self,
        conversation_id: String,
        up_to_seq: i64,
    ) -> Result<(), JsValue> {
        self.acknowledge_entries_up_to_impl(&conversation_id, up_to_seq)
            .await
            .map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = labyrinthStatus)]
    pub fn labyrinth_status(&self) -> Result<JsValue, JsValue> {
        let raw_opt = self
            .require_db()?
            .backend()
            .get_labyrinth_state("status_json")
            .map_err(mls_to_js_err)?;
        let status = match raw_opt {
            Some(bytes) => serde_json::from_slice::<LabyrinthBackupStatus>(&bytes)
                .map_err(|e| JsValue::from_str(&e.to_string()))?,
            None => LabyrinthBackupStatus {
                backup_enabled: true,
                mailbox_space_uri: personal_mailbox_space_uri(&self.account_did),
                has_recovery_code: false,
                has_passkey_prf: false,
                recovery_needs_attention: false,
                recovery_generation: 0,
                epoch_seq: 0,
                active_device_ids: vec![self.device_id.clone()],
                recovery_method_stale: false,
                rotation_exclusions: Vec::new(),
                pending_directory_epoch: None,
                directory_publication_stalled: false,
                directory_publication_retry_count: 0,
                directory_publication_error: None,
            },
        };
        to_js_val(&status)
    }

    #[wasm_bindgen(js_name = enableLabyrinthLive)]
    pub async fn enable_labyrinth_live(&self) -> Result<JsValue, JsValue> {
        let status = self
            .enable_labyrinth_live_impl()
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&status)
    }

    #[wasm_bindgen(js_name = createRecoveryCodeLive)]
    pub async fn create_recovery_code_live(&self) -> Result<String, JsValue> {
        self.create_recovery_code_live_impl()
            .await
            .map_err(mls_to_js_err)
    }
    #[wasm_bindgen(js_name = acknowledgeRecoveryAttention)]
    pub fn acknowledge_recovery_attention(&self) -> Result<JsValue, JsValue> {
        let status = self
            .acknowledge_recovery_attention_impl()
            .map_err(mls_to_js_err)?;
        to_js_val(&status)
    }


    #[wasm_bindgen(js_name = restoreWithRecoveryCodeLive)]
    pub async fn restore_with_recovery_code_live(&self, code: String) -> Result<JsValue, JsValue> {
        let status = self
            .restore_with_recovery_code_live_impl(&code)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&status)
    }

    #[wasm_bindgen(js_name = registerPasskeyPrfLive)]
    pub async fn register_passkey_prf_live(
        &self,
        credential_id: &[u8],
        prf_output_32: &[u8],
    ) -> Result<JsValue, JsValue> {
        let status = self
            .register_passkey_prf_live_impl(credential_id, prf_output_32)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&status)
    }

    #[wasm_bindgen(js_name = restoreWithPasskeyPrf)]
    pub async fn restore_with_passkey_prf(
        &self,
        credential_id: &[u8],
        prf_output_32: &[u8],
    ) -> Result<JsValue, JsValue> {
        let status = self
            .restore_with_passkey_prf_impl(credential_id, prf_output_32)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&status)
    }

    #[wasm_bindgen(js_name = verifyAndReindexHistory)]
    pub async fn verify_and_reindex_history(
        &self,
        conversation_id: String,
    ) -> Result<u32, JsValue> {
        self.verify_and_reindex_history_impl(&conversation_id)
            .await
            .map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = getReadState)]
    pub async fn get_read_state(&self, conversation_id: String) -> Result<JsValue, JsValue> {
        let out = self
            .get_read_state_impl(&conversation_id)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&out)
    }

    #[wasm_bindgen(js_name = advanceReadState)]
    pub async fn advance_read_state(
        &self,
        conversation_id: String,
        candidate_seq: u64,
    ) -> Result<JsValue, JsValue> {
        let out = self
            .advance_read_state_impl(&conversation_id, candidate_seq)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&out)
    }

    #[wasm_bindgen(js_name = listReadStates)]
    pub async fn list_read_states(&self) -> Result<JsValue, JsValue> {
        let out = self.list_read_states_impl().await.map_err(mls_to_js_err)?;
        to_js_val(&out)
    }

    #[wasm_bindgen(js_name = getCircleOwnerState)]
    pub async fn get_circle_owner_state(&self, circle_id: String) -> Result<JsValue, JsValue> {
        let out = self
            .get_circle_owner_state_impl(&circle_id)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&out)
    }

    #[wasm_bindgen(js_name = putCircleOwnerState)]
    pub async fn put_circle_owner_state(
        &self,
        state_js: JsValue,
        swap_record_cid: Option<String>,
    ) -> Result<String, JsValue> {
        let state: CircleOwnerStateDto = serde_wasm_bindgen::from_value(state_js)
            .map_err(|e| JsValue::from_str(&format!("invalid CircleOwnerStateDto: {e}")))?;
        self.put_circle_owner_state_impl(state, swap_record_cid)
            .await
            .map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = mergeCircleOwnerState)]
    pub async fn merge_circle_owner_state(&self, update_js: JsValue) -> Result<JsValue, JsValue> {
        let update: CircleOwnerStateDto = serde_wasm_bindgen::from_value(update_js)
            .map_err(|e| JsValue::from_str(&format!("invalid CircleOwnerStateDto: {e}")))?;
        let out = self
            .merge_circle_owner_state_impl(update)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&out)
    }

    #[wasm_bindgen(js_name = clearCircleAclTombstone)]
    pub async fn clear_circle_acl_tombstone(
        &self,
        circle_id: String,
        member_did: String,
    ) -> Result<JsValue, JsValue> {
        let out = self
            .clear_circle_acl_tombstone_impl(&circle_id, &member_did)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&out)
    }

    #[wasm_bindgen(js_name = listCircleOwnerStates)]
    pub async fn list_circle_owner_states(&self) -> Result<JsValue, JsValue> {
        let out = self
            .list_circle_owner_states_impl()
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&out)
    }

    #[wasm_bindgen(js_name = setupRecoveryCode)]
    pub fn setup_recovery_code(&self) -> Result<String, JsValue> {
        let (grouped, vdev_id) =
            generate_recovery_code_vdevice(&self.account_did).map_err(mls_to_js_err)?;
        let ts = now_ms();
        self.require_db()?
            .write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.has_recovery_code = true;
                tx.put_labyrinth_state("recovery_vdevice_id", &vdev_id, ts)?;
                tx.put_labyrinth_state(
                    "status_json",
                    &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                    ts,
                )?;
                Ok(())
            })
            .map_err(mls_to_js_err)?;
        Ok(grouped)
    }

    #[wasm_bindgen(js_name = restoreWithRecoveryCode)]
    pub fn restore_with_recovery_code(
        &self,
        recovery_code_input: String,
    ) -> Result<JsValue, JsValue> {
        let ts = now_ms();
        let status = self
            .require_db()?
            .write_tx(|tx| {
                let expected = tx.get_labyrinth_state("recovery_vdevice_id")?;
                let vdev_id = verify_recovery_code_vdevice(
                    &self.account_did,
                    &recovery_code_input,
                    expected.as_deref(),
                )?;
                tx.put_labyrinth_state("recovery_vdevice_id", &vdev_id, ts)?;

                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.epoch_seq = st.epoch_seq.saturating_add(1);
                st.has_recovery_code = true;
                if !st.active_device_ids.contains(&self.device_id) {
                    st.active_device_ids.push(self.device_id.clone());
                }
                tx.upsert_mutation_journal(&MutationJournalRow {
                    journal_id: format!("restore-epoch-{}", st.epoch_seq),
                    op_type: "epoch_rotation".to_string(),
                    epoch_seq: st.epoch_seq,
                    state_json: serde_json::json!({ "trigger": "recovery_code_restore" })
                        .to_string(),
                    status: "done".to_string(),
                    created_at_ms: ts,
                    updated_at_ms: ts,
                })?;
                tx.put_labyrinth_state(
                    "status_json",
                    &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                    ts,
                )?;
                Ok(st)
            })
            .map_err(mls_to_js_err)?;
        to_js_val(&status)
    }

    #[wasm_bindgen(js_name = registerPasskeyPrf)]
    pub fn register_passkey_prf(
        &self,
        credential_id: &[u8],
        prf_output_32: &[u8],
    ) -> Result<JsValue, JsValue> {
        if credential_id.is_empty() || prf_output_32.len() != 32 {
            return Err(JsValue::from_str(
                "passkey PRF requires non-empty credential_id and 32-byte PRF output",
            ));
        }
        let mut digest_hasher = Sha256::new();
        digest_hasher.update(b"catbird.wasm.passkey_prf.v1\0");
        digest_hasher.update(self.account_did.as_bytes());
        digest_hasher.update([0u8]);
        digest_hasher.update(credential_id);
        digest_hasher.update([0u8]);
        digest_hasher.update(prf_output_32);
        let prf_digest: [u8; 32] = digest_hasher.finalize().into();
        let ts = now_ms();
        let status = self
            .require_db()?
            .write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.has_passkey_prf = true;
                tx.put_labyrinth_state("passkey_credential_id", credential_id, ts)?;
                tx.put_labyrinth_state("passkey_prf_digest", &prf_digest, ts)?;
                tx.put_labyrinth_state(
                    "status_json",
                    &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                    ts,
                )?;
                Ok(st)
            })
            .map_err(mls_to_js_err)?;
        to_js_val(&status)
    }

    #[wasm_bindgen(js_name = initiateOtcPairing)]
    pub async fn initiate_otc_pairing(&self) -> Result<JsValue, JsValue> {
        self.ensure_wasm_archive_ready_for_otc_offer()
            .await
            .map_err(mls_to_js_err)?;
        let offer = generate_otc_offer().map_err(mls_to_js_err)?;
        let ts = now_ms();
        let mut salt = [0u8; 16];
        let _ = getrandom::getrandom(&mut salt);
        let mut hasher = Sha256::new();
        hasher.update(b"catbird.otc.offer.v1\0");
        hasher.update(salt);
        hasher.update(offer.six_digit_code.as_bytes());
        let code_digest_hex = hex::encode(hasher.finalize());
        let offer_state = serde_json::json!({
            "salt_hex": hex::encode(salt),
            "code_digest_hex": code_digest_hex,
            "expires_at_ms": ts.saturating_add(10 * 60 * 1000),
            "attempts": 0u64,
        });
        self.require_db()?
            .write_tx(|tx| {
                tx.put_labyrinth_state("pending_otc_digits", offer.six_digit_code.as_bytes(), ts)?;
                tx.put_labyrinth_state(
                    "pending_otc_offer",
                    &serde_json::to_vec(&offer_state)
                        .map_err(|e| MLSError::Internal(e.to_string()))?,
                    ts,
                )
            })
            .map_err(mls_to_js_err)?;
        *self.pending_otc_offer_digits.borrow_mut() =
            Some(Zeroizing::new(offer.six_digit_code.clone()));
        to_js_val(&offer)
    }

    #[wasm_bindgen(js_name = startOtcPairing)]
    pub async fn start_otc_pairing(&self, six_digit_code: String) -> Result<JsValue, JsValue> {
        let initiated = self
            .start_otc_pairing_impl(&six_digit_code)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&initiated)
    }

    #[wasm_bindgen(js_name = respondOtcPairing)]
    pub async fn respond_otc_pairing(
        &self,
        session_id_hex: String,
        six_digit_code: Option<String>,
    ) -> Result<(), JsValue> {
        self.respond_otc_pairing_impl(&session_id_hex, six_digit_code.as_deref())
            .await
            .map_err(mls_to_js_err)
    }

    #[wasm_bindgen(js_name = completeLiveOtcPairing)]
    pub async fn complete_live_otc_pairing(
        &self,
        six_digit_code: String,
    ) -> Result<JsValue, JsValue> {
        let completion = self
            .complete_live_otc_pairing_impl(&six_digit_code)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&completion)
    }

    #[wasm_bindgen(js_name = completeOtcPairing)]
    pub fn complete_otc_pairing(&self, six_digit_code: String) -> Result<JsValue, JsValue> {
        let db = self.require_db()?;
        let expected = db
            .backend()
            .get_labyrinth_state("pending_otc_digits")
            .map_err(mls_to_js_err)?
            .and_then(|b| String::from_utf8(b).ok());

        let ts = now_ms();
        let completion = db
            .write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                let next_epoch = st.epoch_seq.saturating_add(1);
                let done = execute_pq_otc_handshake(
                    &self.account_did,
                    &six_digit_code,
                    expected.as_deref(),
                    next_epoch,
                )?;
                st.epoch_seq = next_epoch;
                if !st.active_device_ids.contains(&self.device_id) {
                    st.active_device_ids.push(self.device_id.clone());
                }
                tx.upsert_mutation_journal(&MutationJournalRow {
                    journal_id: format!("otc-epoch-{next_epoch}"),
                    op_type: "epoch_rotation".to_string(),
                    epoch_seq: next_epoch,
                    state_json: serde_json::json!({ "trigger": "otc_pq_pairing" }).to_string(),
                    status: "done".to_string(),
                    created_at_ms: ts,
                    updated_at_ms: ts,
                })?;
                tx.put_labyrinth_state(
                    "status_json",
                    &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                    ts,
                )?;
                Ok(done)
            })
            .map_err(mls_to_js_err)?;
        to_js_val(&completion)
    }

    #[wasm_bindgen(js_name = revokeLabyrinthDevice)]
    pub async fn revoke_labyrinth_device(
        &self,
        target_device_id: String,
    ) -> Result<JsValue, JsValue> {
        let outcome = self
            .revoke_labyrinth_device_impl(&target_device_id)
            .await
            .map_err(mls_to_js_err)?;
        to_js_val(&outcome)
    }

    #[wasm_bindgen]
    pub fn close(&mut self) {
        self.db = None;
    }
}

impl WasmMlsClient {
    #[doc(hidden)]
    pub fn open_with_db_path(
        account_did: String,
        device_id: String,
        home_ds_did: String,
        home_ds_endpoint: String,
        pds_endpoint: String,
        db_key_hex: String,
        db_path: &str,
    ) -> Result<WasmMlsClient, JsValue> {
        let normalized_did = normalize_account_did(&account_did).map_err(mls_to_js_err)?;
        let did_hash = account_did_hash_hex(&normalized_did).map_err(mls_to_js_err)?;
        if device_id.trim().is_empty() {
            return Err(JsValue::from_str("device_id must not be empty"));
        }
        let conn = Rc::new(
            SqliteConn::open(db_path, &db_key_hex)
                .map_err(|e| JsValue::from_str(&e.to_string()))?,
        );
        let db = WasmAccountDb::new(conn);
        let ts = now_ms();
        db.write_tx(|tx| {
            tx.repair_legacy_erasure_evidence(ts)?;
            tx.put_account_meta("owner_did", &normalized_did, ts)?;
            tx.put_account_meta("device_id", &device_id, ts)?;
            tx.put_account_meta("home_ds_did", &home_ds_did, ts)?;
            tx.put_account_meta("home_ds_endpoint", &home_ds_endpoint, ts)?;
            tx.put_account_meta("pds_endpoint", &pds_endpoint, ts)?;
            Ok(())
        })
        .map_err(mls_to_js_err)?;

        Ok(Self {
            account_did: normalized_did,
            account_did_hash: did_hash,
            device_id,
            home_ds_did,
            home_ds_endpoint,
            pds_endpoint,
            auth_token: RefCell::new(None),
            http: reqwest::Client::new(),
            db: Some(db),
            pending_otc_initiator: RefCell::new(None),
            pending_otc_offer_digits: RefCell::new(None),
        })
    }

    #[doc(hidden)]
    pub async fn open_with_db_path_async(
        account_did: String,
        device_id: String,
        home_ds_did: String,
        home_ds_endpoint: String,
        pds_endpoint: String,
        db_key_hex: String,
        db_path: &str,
    ) -> Result<WasmMlsClient, JsValue> {
        SqliteConn::initialize_opfs().await.map_err(|e| {
            JsValue::from_str(&format!("Persistent encrypted storage unavailable: {e}"))
        })?;
        Self::open_with_db_path(
            account_did,
            device_id,
            home_ds_did,
            home_ds_endpoint,
            pds_endpoint,
            db_key_hex,
            db_path,
        )
    }
}

fn minify_validated_json_raw(raw: &str) -> Vec<u8> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut in_string = false;
    let mut escape = false;
    for &b in bytes {
        if in_string {
            out.push(b);
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else if matches!(b, b' ' | b'\n' | b'\r' | b'\t') {
            continue;
        } else {
            if b == b'"' {
                in_string = true;
            }
            out.push(b);
        }
    }
    out
}

fn is_hex_len(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn verify_optional_tls_artifacts(node: &serde_json::Value) -> Result<usize, String> {
    use openmls::prelude::tls_codec::Deserialize as _;
    let mut decoded = 0usize;
    match node {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if let Some(hex_str) = v.as_str() {
                    if k == "key_package_tls_hex" || k == "keyPackageTlsHex" {
                        let raw =
                            hex::decode(hex_str).map_err(|e| format!("invalid {k} hex: {e}"))?;
                        let kp_in = KeyPackageIn::tls_deserialize_exact(&raw)
                            .map_err(|e| format!("invalid KeyPackage TLS in {k}: {e:?}"))?;
                        let crypto = openmls_libcrux_crypto::Provider::default();
                        let kp_verified = kp_in
                            .validate(crypto.crypto(), ProtocolVersion::Mls10)
                            .map_err(|e| {
                            format!("KeyPackage validation failed in {k}: {e:?}")
                        })?;
                        if kp_verified.ciphersuite() != CIPHERSUITE {
                            return Err(format!(
                                "KeyPackage ciphersuite {:?} != expected {:?}",
                                kp_verified.ciphersuite(),
                                CIPHERSUITE
                            ));
                        }
                        decoded += 1;
                    } else if matches!(
                        k.as_str(),
                        "welcome_tls_hex"
                            | "commit_tls_hex"
                            | "private_message_tls_hex"
                            | "mls_message_tls_hex"
                            | "welcomeTlsHex"
                            | "commitTlsHex"
                            | "privateMessageTlsHex"
                            | "mlsMessageTlsHex"
                    ) {
                        let raw =
                            hex::decode(hex_str).map_err(|e| format!("invalid {k} hex: {e}"))?;
                        let _msg = MlsMessageIn::tls_deserialize_exact(&raw)
                            .map_err(|e| format!("invalid MlsMessage TLS in {k}: {e:?}"))?;
                        decoded += 1;
                    }
                } else {
                    decoded += verify_optional_tls_artifacts(v)?;
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                decoded += verify_optional_tls_artifacts(item)?;
            }
        }
        _ => {}
    }
    Ok(decoded)
}

#[derive(serde::Deserialize)]
struct GoldenTranscriptRawEnvelope {
    schema_version: String,
    index: u8,
    slug: String,
    category: String,
    seed: u64,
    wire_frames: Box<serde_json::value::RawValue>,
    wire_digest_blake3: String,
    conversations: serde_json::Value,
    devices: serde_json::Value,
    assertions: serde_json::Value,
    post_state_blake3: String,
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct GoldenWireFrameView {
    seq: u64,
    device_id: String,
    method: String,
    url: String,
    status: u16,
    request_body_blake3: String,
    response_body_blake3: String,
    #[serde(default)]
    space: Option<String>,
}

#[derive(serde::Deserialize)]
struct GoldenMessageView {
    message_id: String,
    seq: i64,
    epoch: i64,
    sender_did: String,
    plaintext: String,
}

#[derive(serde::Deserialize)]
struct GoldenConversationView {
    conversation_id: String,
    is_direct: bool,
    epoch: u64,
    tree_hash_hex: String,
    roster: Vec<String>,
    active_leaf_count: usize,
    messages: Vec<GoldenMessageView>,
    read_through_seq: u64,
}

#[derive(serde::Deserialize)]
struct GoldenDeviceView {
    label: String,
    did: String,
    device_id: String,
    home_ds_did: String,
    handle_open: bool,
    pending_approval: bool,
    conversation_epochs: std::collections::BTreeMap<String, u64>,
    read_watermarks: std::collections::BTreeMap<String, u64>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct GoldenWasmVerificationReport {
    index: u8,
    slug: String,
    category: String,
    seed: u64,
    wire_frame_count: usize,
    conversation_count: usize,
    message_count: usize,
    open_device_count: usize,
    tls_artifacts_decoded: usize,
    wire_digest_blake3: String,
    post_state_blake3: String,
}

#[derive(serde::Deserialize)]
struct GoldenManifestFileEntry {
    filename: String,
    bytes: Vec<u8>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct GoldenManifestVerificationReport {
    verified_count: usize,
    manifest_sha256: String,
}

/// Verify `MANIFEST.sha256` and raw SHA-256 digests of all 50 `T7-GOLDEN-50` transcripts inside WASM (`C5`).
#[wasm_bindgen(js_name = verifyGoldenManifest)]
pub fn verify_golden_manifest(manifest_raw: &str, entries_js: JsValue) -> Result<JsValue, JsValue> {
    let files: Vec<GoldenManifestFileEntry> = serde_wasm_bindgen::from_value(entries_js)
        .map_err(|e| JsValue::from_str(&format!("invalid file entries: {e}")))?;
    let mut expected = std::collections::BTreeMap::new();
    for line in manifest_raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((sha, fname)) = trimmed.split_once("  ") else {
            return Err(JsValue::from_str(&format!(
                "malformed MANIFEST.sha256 line: {line}"
            )));
        };
        if !is_hex_len(sha, 64) {
            return Err(JsValue::from_str(&format!(
                "invalid SHA-256 hex in MANIFEST.sha256 for {fname}"
            )));
        }
        if fname.is_empty() || expected.insert(fname, sha.to_ascii_lowercase()).is_some() {
            return Err(JsValue::from_str(
                "empty or duplicate transcript name in MANIFEST.sha256",
            ));
        }
    }
    if expected.len() != 50 {
        return Err(JsValue::from_str(&format!(
            "MANIFEST.sha256 must list 50 transcripts, found {}",
            expected.len()
        )));
    }
    if files.len() != 50 {
        return Err(JsValue::from_str(&format!(
            "expected 50 transcript payloads, received {}",
            files.len()
        )));
    }
    let by_name: std::collections::BTreeMap<&str, &[u8]> = files
        .iter()
        .map(|f| (f.filename.as_str(), f.bytes.as_slice()))
        .collect();
    for (fname, expected_sha) in &expected {
        let Some(raw_bytes) = by_name.get(fname) else {
            return Err(JsValue::from_str(&format!(
                "missing transcript file listed in MANIFEST.sha256: {fname}"
            )));
        };
        let actual_sha = hex::encode(Sha256::digest(raw_bytes));
        if &actual_sha != expected_sha {
            return Err(JsValue::from_str(&format!(
                "SHA-256 mismatch for {fname}: expected {expected_sha}, got {actual_sha}"
            )));
        }
    }
    let manifest_sha256 = hex::encode(Sha256::digest(manifest_raw.as_bytes()));
    to_js_val(&GoldenManifestVerificationReport {
        verified_count: expected.len(),
        manifest_sha256,
    })
}

/// Cryptographically verify a `T7-GOLDEN-50` transcript JSON inside compiled WASM (`C5`),
/// including `blake3` wire/post-state digests, `SpaceUri` & DID validation, optional TLS `0x004D`
/// artifact decoding, and unified `WasmAccountDb<SqliteConn>` SQLite round-trip projection.
#[wasm_bindgen(js_name = verifyGoldenTranscriptJson)]
pub fn verify_golden_transcript_json(raw_json: &str) -> Result<JsValue, JsValue> {
    const VALID_CATEGORIES: &[&str] = &[
        "direct1_to1",
        "group_chat",
        "multidevice1_to4_leaves",
        "epoch_ratchets",
        "federated_ds_relay_reset",
        "y7_pruning_space_backfill",
        "d2_device_approval",
        "d3_deletion",
        "d4_pq_otc_reindex",
        "y8_read_state",
    ];

    let env: GoldenTranscriptRawEnvelope = serde_json::from_str(raw_json)
        .map_err(|e| JsValue::from_str(&format!("invalid GoldenTranscript JSON: {e}")))?;
    if env.schema_version != "catbird.golden-transcript.v1" {
        return Err(JsValue::from_str(&format!(
            "unsupported schema_version: {}",
            env.schema_version
        )));
    }
    if !(1..=50).contains(&env.index) || env.slug.trim().is_empty() {
        return Err(JsValue::from_str("invalid transcript index or empty slug"));
    }
    if !VALID_CATEGORIES.contains(&env.category.as_str()) {
        return Err(JsValue::from_str(&format!(
            "unknown golden category: {}",
            env.category
        )));
    }

    let wire_bytes = minify_validated_json_raw(env.wire_frames.get());
    let computed_wire_blake3 = blake3::hash(&wire_bytes).to_hex().to_string();
    if computed_wire_blake3 != env.wire_digest_blake3 {
        return Err(JsValue::from_str(&format!(
            "wire_digest_blake3 mismatch on #{:02} ({}): expected {}, computed {}",
            env.index, env.slug, env.wire_digest_blake3, computed_wire_blake3
        )));
    }

    let post_state_bytes = serde_json::to_vec(&serde_json::json!({
        "conversations": &env.conversations,
        "devices": &env.devices,
        "assertions": &env.assertions,
    }))
    .map_err(|e| JsValue::from_str(&format!("serialize post_state: {e}")))?;
    let computed_post_blake3 = blake3::hash(&post_state_bytes).to_hex().to_string();
    if computed_post_blake3 != env.post_state_blake3 {
        return Err(JsValue::from_str(&format!(
            "post_state_blake3 mismatch on #{:02} ({}): expected {}, computed {}",
            env.index, env.slug, env.post_state_blake3, computed_post_blake3
        )));
    }

    let wire_frames_val: serde_json::Value = serde_json::from_str(env.wire_frames.get())
        .map_err(|e| JsValue::from_str(&format!("parse wire_frames value: {e}")))?;
    let wire_frames: Vec<GoldenWireFrameView> = serde_json::from_str(env.wire_frames.get())
        .map_err(|e| JsValue::from_str(&format!("parse typed wire_frames: {e}")))?;
    let conversations: Vec<GoldenConversationView> = serde_json::from_value(env.conversations)
        .map_err(|e| JsValue::from_str(&format!("parse typed conversations: {e}")))?;
    let devices: Vec<GoldenDeviceView> = serde_json::from_value(env.devices)
        .map_err(|e| JsValue::from_str(&format!("parse typed devices: {e}")))?;

    let mut prev_wire_seq = 0u64;
    for wf in &wire_frames {
        if wf.seq <= prev_wire_seq {
            return Err(JsValue::from_str("non-monotonic wire_frames.seq"));
        }
        prev_wire_seq = wf.seq;
        if wf.device_id.trim().is_empty() || wf.method.trim().is_empty() || wf.url.trim().is_empty()
        {
            return Err(JsValue::from_str(
                "empty device_id/method/url in wire_frame",
            ));
        }
        if wf.status < 100 || wf.status >= 600 {
            return Err(JsValue::from_str("invalid HTTP status in wire_frame"));
        }
        if !is_hex_len(&wf.request_body_blake3, 64) || !is_hex_len(&wf.response_body_blake3, 64) {
            return Err(JsValue::from_str(
                "invalid 64-hex request/response blake3 digest in wire_frame",
            ));
        }
        if let Some(space) = &wf.space {
            atproto_spaces::SpaceUri::parse_hedged(space).map_err(|e| {
                JsValue::from_str(&format!("invalid wire_frame SpaceUri '{space}': {e}"))
            })?;
        }
    }

    let mut tls_artifacts_decoded =
        verify_optional_tls_artifacts(&wire_frames_val).map_err(|e| JsValue::from_str(&e))?;
    for v in env.extra.values() {
        tls_artifacts_decoded +=
            verify_optional_tls_artifacts(v).map_err(|e| JsValue::from_str(&e))?;
    }

    let mut total_messages = 0usize;
    for conv in &conversations {
        if conv.conversation_id.trim().is_empty() {
            return Err(JsValue::from_str("empty conversation_id"));
        }
        if !conv.tree_hash_hex.is_empty() && !is_hex_len(&conv.tree_hash_hex, 64) {
            return Err(JsValue::from_str("invalid tree_hash_hex length"));
        }
        for member_did in &conv.roster {
            normalize_account_did(member_did).map_err(mls_to_js_err)?;
        }
        let mut prev_msg_seq = 0i64;
        for msg in &conv.messages {
            normalize_account_did(&msg.sender_did).map_err(mls_to_js_err)?;
            if msg.seq <= 0 || msg.seq < prev_msg_seq {
                return Err(JsValue::from_str(&format!(
                    "I2 monotonic seq violated in {}: {} after {}",
                    conv.conversation_id, msg.seq, prev_msg_seq
                )));
            }
            prev_msg_seq = msg.seq;
            total_messages += 1;
        }
        if conv.is_direct && conv.roster.len() > 2 {
            return Err(JsValue::from_str(
                "direct conversation exceeded 2 root DIDs",
            ));
        }
        let _ = conv.active_leaf_count;
    }

    let mut open_device_count = 0usize;
    for (dev_idx, dev) in devices.iter().enumerate() {
        let norm_did = normalize_account_did(&dev.did).map_err(mls_to_js_err)?;
        if !atproto_spaces::is_valid_did(&dev.home_ds_did) {
            return Err(JsValue::from_str(&format!(
                "invalid home_ds_did: {}",
                dev.home_ds_did
            )));
        }
        let mailbox_uri = personal_mailbox_space_uri(&norm_did);
        atproto_spaces::SpaceUri::parse(&mailbox_uri)
            .map_err(|e| JsValue::from_str(&format!("invalid mailbox SpaceUri: {e}")))?;

        if dev.pending_approval && !dev.read_watermarks.is_empty() {
            return Err(JsValue::from_str(&format!(
                "D-2 violation: pending-approval device {} recorded read_watermarks",
                dev.label
            )));
        }
        if !dev.handle_open {
            continue;
        }
        open_device_count += 1;

        // Exercise real WASM SQLite (`WasmAccountDb<Rc<SqliteConn>>`) persistence & readback.
        let key_hex = hex::encode(Sha256::digest(
            format!("golden-50:{}:{}:{dev_idx}", env.index, dev.device_id).as_bytes(),
        ));
        let conn = Rc::new(
            SqliteConn::open_in_memory(&key_hex)
                .map_err(|e| JsValue::from_str(&format!("WASM SQLite open_in_memory: {e}")))?,
        );
        let db = WasmAccountDb::new(conn);
        db.write_tx(|tx| {
            tx.put_account_meta("owner_did", &norm_did, 1)?;
            tx.put_account_meta("device_id", &dev.device_id, 1)?;
            tx.put_account_meta("home_ds_did", &dev.home_ds_did, 1)?;
            tx.put_account_meta(
                "device_pending_approval",
                if dev.pending_approval {
                    "true"
                } else {
                    "false"
                },
                1,
            )?;
            for (cid, &epoch) in &dev.conversation_epochs {
                let Some(conv) = conversations.iter().find(|c| &c.conversation_id == cid) else {
                    continue;
                };
                let max_seq = conv.messages.iter().map(|m| m.seq).max().unwrap_or(0);
                let watermark = dev.read_watermarks.get(cid).copied().unwrap_or(0) as i64;
                let unread_count =
                    conv.messages.iter().filter(|m| m.seq > watermark).count() as i64;
                let group_id = Sha256::digest(cid.as_bytes()).to_vec();
                tx.upsert_conversation(&catbird_mls::storage::ConversationRow {
                    conversation_id: cid.clone(),
                    group_id: group_id.clone(),
                    generation: 0,
                    epoch: epoch as i64,
                    last_seq: max_seq.max(conv.read_through_seq as i64),
                    sequencer_did: dev.home_ds_did.clone(),
                    space_uri: Some(mailbox_uri.clone()),
                    title: (!conv.is_direct).then(|| format!("group-{cid}")),
                    unread_count,
                    updated_at_ms: 1_763_000_000_000 + (env.index as i64),
                })?;
                if watermark > 0 {
                    tx.put_account_meta(
                        &format!("read_watermark:{cid}"),
                        &watermark.to_string(),
                        1,
                    )?;
                }
                for msg in &conv.messages {
                    tx.insert_message(&catbird_mls::storage::MessageRow {
                        message_id: msg.message_id.clone(),
                        conversation_id: cid.clone(),
                        group_id: group_id.clone(),
                        epoch: msg.epoch,
                        seq: msg.seq,
                        sender_did: msg.sender_did.clone(),
                        sender_device_id: dev.device_id.clone(),
                        plaintext_json: serde_json::json!({
                            "type": "text",
                            "text": msg.plaintext,
                        })
                        .to_string(),
                        created_at_ms: 1_763_000_000_000 + msg.seq,
                        is_own: msg.sender_did == norm_did,
                    })?;
                }
            }
            Ok(())
        })
        .map_err(mls_to_js_err)?;

        let stored_owner = db
            .backend()
            .get_account_meta("owner_did")
            .map_err(mls_to_js_err)?;
        if stored_owner.as_deref() != Some(norm_did.as_str()) {
            return Err(JsValue::from_str("owner_did round-trip mismatch"));
        }
        let stored_convos = db
            .backend()
            .list_conversations(None, 100)
            .map_err(mls_to_js_err)?;
        for (cid, &expected_epoch) in &dev.conversation_epochs {
            let Some(conv) = conversations.iter().find(|c| &c.conversation_id == cid) else {
                continue;
            };
            let Some(row) = stored_convos.iter().find(|r| &r.conversation_id == cid) else {
                return Err(JsValue::from_str(&format!(
                    "missing persisted conversation {cid}"
                )));
            };
            if row.epoch != expected_epoch as i64 {
                return Err(JsValue::from_str(&format!(
                    "conversation epoch mismatch for {cid}"
                )));
            }
            let stored_msgs = db
                .backend()
                .list_messages(cid, None, 250)
                .map_err(mls_to_js_err)?;
            if stored_msgs.len() != conv.messages.len() {
                return Err(JsValue::from_str(&format!(
                    "persisted message count mismatch for {cid}: {} != {}",
                    stored_msgs.len(),
                    conv.messages.len()
                )));
            }
        }
    }

    to_js_val(&GoldenWasmVerificationReport {
        index: env.index,
        slug: env.slug,
        category: env.category,
        seed: env.seed,
        wire_frame_count: wire_frames.len(),
        conversation_count: conversations.len(),
        message_count: total_messages,
        open_device_count,
        tls_artifacts_decoded,
        wire_digest_blake3: computed_wire_blake3,
        post_state_blake3: computed_post_blake3,
    })
}

#[cfg(test)]
mod tests {
    use super::uuid_v4;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn uuid_v4_matching_is_spelling_independent() {
        assert_eq!(
            uuid_v4("00000000-0000-4000-8000-00000000E001"),
            uuid_v4("00000000-0000-4000-8000-00000000e001")
        );
        assert!(uuid_v4("00000000-0000-1000-8000-00000000e001").is_none());
    }
}
