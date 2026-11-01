//! Browser WASM `#[wasm_bindgen]` wrapper around unified `catbird_mls::client` + `WasmAccountDb` (`Spec §6.3`, `G2`, `D3`, `D4`, `I8`, `I15`, `I16`).

use std::rc::Rc;

use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use wasm_bindgen::prelude::*;

use catbird_mls::client::{
    account_did_hash_hex, evaluate_spaces_eligibility, execute_pq_otc_handshake,
    generate_otc_offer, generate_recovery_code_vdevice, normalize_account_did,
    personal_mailbox_space_uri, verify_recovery_code_vdevice, EnrollmentReceipt,
    LabyrinthBackupStatus, SpacesEligibilityInput,
};
use catbird_mls::groups::lifecycle::{enforce_admin_removal_policy, MemberRole};
use catbird_mls::messaging::receive::PrivateMessagePlaintextEnvelope;
use catbird_mls::metadata::{
    derive_metadata_key_from_group, encrypt_metadata_snapshot_with_nonce, GroupMetadataV1,
};
use catbird_mls::requests::c33::{
    validate_direct_request_key_package_lifetime, DIRECT_REQUEST_KP_MIN_LIFETIME_SECS,
    RECOVERY_KP_MAX_LIFETIME_SECS,
};
use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend};
use catbird_mls::storage::{
    ConversationRow, GroupMetadataRow, LabyrinthQueueRow, MessageRow, MutationJournalRow,
    OpenMlsKvProvider,
};
use catbird_mls::MLSError;

use crate::sqlite_conn::SqliteConn;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

fn mls_to_js_err(err: MLSError) -> JsValue {
    JsValue::from_str(&err.to_string())
}

fn to_js_val<T: serde::Serialize>(val: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(val).map_err(|e| JsValue::from_str(&e.to_string()))
}

fn now_ms() -> i64 {
    js_sys::Date::now() as i64
}

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0).max(0.0) as u64
}

/// Unified browser WASM MLS client backed by per-account `catbird-mls/<did_hash>.db` on OPFS (`sqlite3mc` ChaCha20).
#[wasm_bindgen]
pub struct WasmMlsClient {
    account_did: String,
    account_did_hash: String,
    device_id: String,
    home_ds_did: String,
    home_ds_endpoint: String,
    pds_endpoint: String,
    db: Option<WasmAccountDb<Rc<SqliteConn>>>,
}

#[wasm_bindgen]
impl WasmMlsClient {
    /// Open or create `catbird-mls/<did_hash>.db` inside the Dedicated Worker's OPFS SAH pool (`I8`).
    ///
    /// Note: caller must hold the awaited `navigator.locks` Worker mutex (`tab-lock.ts`) and pass
    /// the 64-hex key unwrapped from IndexedDB's non-extractable `CryptoKey` (`webcrypto-keystore.ts`).
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
        if device_id.trim().is_empty() {
            return Err(JsValue::from_str("device_id must not be empty"));
        }
        let db_path = format!("catbird-mls/{did_hash}.db");
        let conn = Rc::new(
            SqliteConn::open(&db_path, &db_key_hex)
                .map_err(|e| JsValue::from_str(&e.to_string()))?,
        );
        let db = WasmAccountDb::new(conn);
        let ts = now_ms();
        db.write_tx(|tx| {
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
            db: Some(db),
        })
    }

    fn require_db(&self) -> Result<&WasmAccountDb<Rc<SqliteConn>>, JsValue> {
        self.db
            .as_ref()
            .ok_or_else(|| JsValue::from_str("WasmMlsClient handle is closed"))
    }

    #[wasm_bindgen(js_name = accountDid)]
    pub fn account_did(&self) -> String {
        self.account_did.clone()
    }

    #[wasm_bindgen(js_name = accountDidHash)]
    pub fn account_did_hash(&self) -> String {
        self.account_did_hash.clone()
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
    /// KeyPackages (`C33` >= 35d direct-request + <= 30d recovery), and initializing Labyrinth (`D4`).
    #[wasm_bindgen(js_name = enrollDevice)]
    pub fn enroll_device(
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
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| JsValue::from_str(&format!("SignatureKeyPair::new: {e:?}")))?;
        let pub_key = signer.public().to_vec();
        let cred_identity = format!("{}#{}", self.account_did, self.device_id);

        let now_s = now_secs();
        let dr_lifetime_secs = DIRECT_REQUEST_KP_MIN_LIFETIME_SECS + 86_400 * 5;
        validate_direct_request_key_package_lifetime(now_s, now_s + dr_lifetime_secs)
            .map_err(mls_to_js_err)?;
        let dr_lifetime = Lifetime::new(dr_lifetime_secs);
        let rec_lifetime = Lifetime::new(RECOVERY_KP_MAX_LIFETIME_SECS - 3_600);

        let mailbox_uri = personal_mailbox_space_uri(&self.account_did);
        let ts = now_ms();

        let (dr_kp_bytes, rec_kp_bytes) = db
            .write_tx(|tx| {
                let provider =
                    OpenMlsKvProvider::new(catbird_mls::storage::OpenMlsKvStorage::new(tx))?;
                signer
                    .store(provider.storage())
                    .map_err(|e| MLSError::Internal(format!("store signer: {e:?}")))?;
                let cred_with_key = CredentialWithKey {
                    credential: BasicCredential::new(cred_identity.as_bytes().to_vec()).into(),
                    signature_key: pub_key.clone().into(),
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

                let status = LabyrinthBackupStatus {
                    backup_enabled: true,
                    mailbox_space_uri: mailbox_uri.clone(),
                    has_recovery_code: false,
                    has_passkey_prf: false,
                    epoch_seq: 1,
                    active_device_ids: vec![self.device_id.clone()],
                };
                tx.put_labyrinth_state(
                    "status_json",
                    &serde_json::to_vec(&status).map_err(|e| MLSError::Internal(e.to_string()))?,
                    ts,
                )?;
                Ok((dr_bytes, rec_bytes))
            })
            .map_err(mls_to_js_err)?;

        let receipt = EnrollmentReceipt {
            account_did: self.account_did.clone(),
            account_did_hash: self.account_did_hash.clone(),
            device_id: self.device_id.clone(),
            signature_public_key: pub_key,
            direct_request_kp_bytes: dr_kp_bytes,
            recovery_kp_bytes: rec_kp_bytes,
            mailbox_space_uri: mailbox_uri,
            labyrinth_backup_enabled: true,
        };
        to_js_val(&receipt)
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
    pub fn create_group(
        &self,
        conversation_id: String,
        sequencer_did: String,
        title: Option<String>,
        description: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let db = self.require_db()?;
        let ts = now_ms();
        let mut group_id_bytes = [0u8; 32];
        getrandom::getrandom(&mut group_id_bytes)
            .map_err(|e| JsValue::from_str(&format!("getrandom: {e}")))?;

        let convo = db
            .write_tx(|tx| {
                let signer_raw = tx
                    .get_labyrinth_state("device_signer_json")?
                    .ok_or_else(|| MLSError::InvalidState("device not enrolled".to_string()))?;
                let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                    .map_err(|e| MLSError::Internal(format!("deser signer: {e}")))?;

                let provider =
                    OpenMlsKvProvider::new(catbird_mls::storage::OpenMlsKvStorage::new(tx))?;
                let cred_with_key = CredentialWithKey {
                    credential: BasicCredential::new(
                        format!("{}#{}", self.account_did, self.device_id).into_bytes(),
                    )
                    .into(),
                    signature_key: signer.public().into(),
                };
                let create_cfg = MlsGroupCreateConfig::builder()
                    .ciphersuite(CIPHERSUITE)
                    .use_ratchet_tree_extension(true)
                    .max_past_epochs(5)
                    .build();
                let mut group = MlsGroup::new_with_group_id(
                    &provider,
                    &signer,
                    &create_cfg,
                    GroupId::from_slice(&group_id_bytes),
                    cred_with_key,
                )
                .map_err(|e| MLSError::Cryptography(format!("create group: {e:?}")))?;

                let epoch = group.epoch().as_u64();
                let space_uri = format!(
                    "at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{conversation_id}-0"
                );
                let row = ConversationRow {
                    conversation_id: conversation_id.clone(),
                    group_id: group_id_bytes.to_vec(),
                    generation: 0,
                    epoch: epoch as i64,
                    last_seq: 0,
                    sequencer_did: sequencer_did.clone(),
                    space_uri: Some(space_uri),
                    title: title.clone(),
                    unread_count: 0,
                    updated_at_ms: ts,
                };
                tx.upsert_conversation(&row)?;

                if title.is_some() || description.is_some() {
                    let meta_v1 = GroupMetadataV1 {
                        version: 1,
                        title: title.clone().unwrap_or_default(),
                        description: description.clone().unwrap_or_default(),
                        avatar_blob_locator: None,
                        avatar_content_type: None,
                        space_avatar: None,
                    };
                    let meta_key = derive_metadata_key_from_group(
                        &mut group,
                        provider.crypto(),
                        provider.storage(),
                        &group_id_bytes,
                        epoch,
                    )
                    .map_err(|e| MLSError::Cryptography(format!("derive meta key: {e}")))?;
                    let mut nonce = [0u8; 12];
                    let _ = getrandom::getrandom(&mut nonce);
                    let _ct = encrypt_metadata_snapshot_with_nonce(
                        &meta_key,
                        &group_id_bytes,
                        epoch,
                        1,
                        &nonce,
                        &meta_v1,
                    )
                    .map_err(|e| MLSError::Cryptography(format!("encrypt meta: {e}")))?;
                    tx.upsert_group_metadata(&GroupMetadataRow {
                        conversation_id: conversation_id.clone(),
                        metadata_version: 1,
                        epoch: epoch as i64,
                        title,
                        description,
                        avatar_setter_did: None,
                        avatar_blob_cid: None,
                        avatar_sym_key: None,
                        avatar_sha256: None,
                        avatar_mime_type: None,
                        metadata_json: serde_json::to_string(&meta_v1)
                            .map_err(|e| MLSError::Internal(e.to_string()))?,
                        updated_at_ms: ts,
                    })?;
                }
                Ok(row)
            })
            .map_err(mls_to_js_err)?;
        to_js_val(&convo)
    }

    #[wasm_bindgen(js_name = sendMessage)]
    pub fn send_message(
        &self,
        conversation_id: String,
        message_id: String,
        text: String,
    ) -> Result<JsValue, JsValue> {
        let db = self.require_db()?;
        let ts = now_ms();
        let mut frame_nonce = [0u8; 32];
        getrandom::getrandom(&mut frame_nonce)
            .map_err(|e| JsValue::from_str(&format!("getrandom: {e}")))?;
        let payload_json = serde_json::json!({ "text": text }).to_string();
        let (inner_pt, aad) = PrivateMessagePlaintextEnvelope::seal_with_aad(
            frame_nonce,
            payload_json.clone().into_bytes(),
        )
        .map_err(mls_to_js_err)?;

        let msg_row = db
            .write_tx(|tx| {
                let mut convo = tx.get_conversation(&conversation_id)?.ok_or_else(|| {
                    MLSError::group_not_found(format!("missing {conversation_id}"))
                })?;
                let signer_raw = tx
                    .get_labyrinth_state("device_signer_json")?
                    .ok_or_else(|| MLSError::InvalidState("device not enrolled".to_string()))?;
                let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                    .map_err(|e| MLSError::Internal(format!("deser signer: {e}")))?;
                let provider =
                    OpenMlsKvProvider::new(catbird_mls::storage::OpenMlsKvStorage::new(tx))?;
                let mut group =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                        .ok_or_else(|| MLSError::group_not_found("missing MlsGroup"))?;
                group.set_aad(aad);
                let msg_out = group
                    .create_message(&provider, &signer, &inner_pt)
                    .map_err(|e| MLSError::Cryptography(format!("create_message: {e:?}")))?;
                let ct_bytes = msg_out
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("ser msg: {e:?}")))?;

                let next_seq = convo.last_seq + 1;
                let row = MessageRow {
                    message_id: message_id.clone(),
                    conversation_id: conversation_id.clone(),
                    group_id: convo.group_id.clone(),
                    epoch: group.epoch().as_u64() as i64,
                    seq: next_seq,
                    sender_did: self.account_did.clone(),
                    sender_device_id: self.device_id.clone(),
                    plaintext_json: payload_json,
                    created_at_ms: ts,
                    is_own: true,
                };
                tx.insert_message(&row)?;
                tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                    item_id: message_id,
                    conversation_id: conversation_id.clone(),
                    group_id_hex: hex::encode(&convo.group_id),
                    seq: next_seq,
                    payload_bytes: ct_bytes,
                    created_at_ms: ts,
                })?;
                convo.last_seq = next_seq;
                convo.updated_at_ms = ts;
                tx.upsert_conversation(&convo)?;
                Ok(row)
            })
            .map_err(mls_to_js_err)?;
        to_js_val(&msg_row)
    }

    /// Enforce `D3` (`M-F01`) admin-only member removal.
    #[wasm_bindgen(js_name = removeGroupMember)]
    pub fn remove_group_member(
        &self,
        is_admin: bool,
        _conversation_id: String,
        target_did: String,
    ) -> Result<(), JsValue> {
        let role = if is_admin {
            MemberRole::Admin
        } else {
            MemberRole::Member
        };
        enforce_admin_removal_policy(&self.account_did, role, std::slice::from_ref(&target_did))
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
                epoch_seq: 0,
                active_device_ids: vec![self.device_id.clone()],
            },
        };
        to_js_val(&status)
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
    pub fn initiate_otc_pairing(&self) -> Result<JsValue, JsValue> {
        let offer = generate_otc_offer().map_err(mls_to_js_err)?;
        let ts = now_ms();
        self.require_db()?
            .write_tx(|tx| {
                tx.put_labyrinth_state("pending_otc_digits", offer.six_digit_code.as_bytes(), ts)
            })
            .map_err(mls_to_js_err)?;
        to_js_val(&offer)
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
    pub fn revoke_labyrinth_device(&self, target_device_id: String) -> Result<JsValue, JsValue> {
        if target_device_id.trim().is_empty() {
            return Err(JsValue::from_str("target_device_id must not be empty"));
        }
        let ts = now_ms();
        let status = self
            .require_db()?
            .write_tx(|tx| {
                let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                    MLSError::InvalidState("Labyrinth status not initialized".to_string())
                })?;
                let mut st: LabyrinthBackupStatus =
                    serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
                st.active_device_ids.retain(|d| d != &target_device_id);
                st.epoch_seq = st.epoch_seq.saturating_add(1);
                tx.upsert_mutation_journal(&MutationJournalRow {
                    journal_id: format!("revoke-{target_device_id}-{}", st.epoch_seq),
                    op_type: "device_revocation".to_string(),
                    epoch_seq: st.epoch_seq,
                    state_json: serde_json::json!({ "revokedDeviceId": target_device_id })
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

    #[wasm_bindgen]
    pub fn close(&mut self) {
        self.db = None;
    }
}
