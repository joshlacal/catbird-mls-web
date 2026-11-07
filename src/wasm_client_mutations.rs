//! Async `mls-ds` `/xrpc/blue.catbird.chat.*` mutations for `WasmMlsClient` (`Spec §6.3`, `I4`, `I6`, `I13`, `C33`).
//!
//! Every network call executes strictly outside `WasmAccountDb::write_tx` (`I6`).

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use catbird_mls::chat_v2::ids::BareDid;
use catbird_mls::chat_v2::transcript::direct_request::{self as dr_transcript, DirectRequestKind};
use catbird_mls::client::chat_wire;
use catbird_mls::client::{normalize_account_did, QueuedLabyrinthArchivePayload};
use catbird_mls::groups::lifecycle::{enforce_admin_removal_policy, MemberRole};
use catbird_mls::groups::metadata_v1::validate_metadata_snapshot_size;
use catbird_mls::messaging::receive::{
    OriginalSenderArchiveAttestationEnvelope, PrivateMessageAadEnvelope,
    PrivateMessagePlaintextEnvelope,
};
use catbird_mls::metadata::{
    derive_metadata_key_from_group, encrypt_metadata_snapshot_with_nonce, GroupMetadataV1,
};
use catbird_mls::orchestrator::canonical_transport::{
    canonical_application_aad_bytes, canonical_commit_aad_bytes, derive_key_id, CanonicalOperation,
};
use catbird_mls::orchestrator::direct_request_bootstrap::{self, DirectRequestBootstrapInput};
use catbird_mls::orchestrator::direct_request_keys::{
    DirectRequestKeyPublication, DirectRequestKeyPublicationInput,
};
use catbird_mls::orchestrator::direct_request_shared_crypto::build_request_key_publication;
use catbird_mls::storage::driver_wasm::WasmSqlBackend;
use catbird_mls::storage::{
    ConversationRow, GroupMetadataRow, KvWriteOverlay, LabyrinthQueueRow, MessageRow,
    OpenMlsKvProvider, OpenMlsKvStorage, RequestRow,
};
use catbird_mls::MLSError;

use crate::wasm_client::{now_ms, now_secs, WasmMlsClient, CIPHERSUITE};

fn canonical_labyrinth_frame_for_text(input: &str) -> (String, String) {
    let frame = chat_wire::canonical_labyrinth_frame_json(input);
    if serde_json::from_str::<Value>(input)
        .ok()
        .and_then(|v| v.get("text").and_then(|t| t.as_str()).map(str::to_string))
        .is_some()
    {
        return (input.to_string(), frame);
    }
    let display = json!({ "text": input }).to_string();
    let frame_out = chat_wire::canonical_labyrinth_frame_json(&display);
    (display, frame_out)
}

/// Parses a client-generated ID that must be a UUIDv4 (`InvalidInput` otherwise).
fn uuid_v4(raw: &str, field: &str) -> Result<uuid::Uuid, MLSError> {
    uuid::Uuid::parse_str(raw.trim())
        .ok()
        .filter(|u| {
            u.get_version() == Some(uuid::Version::Random)
                && u.get_variant() == uuid::Variant::RFC4122
        })
        .ok_or_else(|| MLSError::invalid_input(format!("{field} must be a UUIDv4")))
}

/// Send journal: the exact signed body and archive copy of one reserved MLS generation, written in
/// the write transaction that advances the sender ratchet and `sendCounter`, before any HTTP.
/// Retries resubmit these bytes; only `StaleSend` replaces them with a fresh frame.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingApplicationSend {
    pub(crate) body: Value,
    pub(crate) archive: QueuedLabyrinthArchivePayload,
}

/// `account_meta` key of the send journal for `message_id` in `conversation_id`.
pub(crate) fn pending_send_key(conversation_id: &str, message_id: &str) -> String {
    format!("application_send:{conversation_id}:{message_id}")
}

impl WasmMlsClient {
    /// `mls-ds` bootstrap, mirroring catbird-mls `enroll_device_live`: completion is bound to
    /// `auth_generation`, the canonical device ID and signer key. A retry after a lost response
    /// resumes: `enrollDevice` is create-only and request-key revisions must advance by one, so it
    /// confirms what the DS already holds.
    pub(crate) async fn enroll_device_live(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<(), MLSError> {
        let db = self.require_db_mls()?;
        let pub_key = signer.public();
        let key_id = derive_key_id(pub_key);
        if let Some(auth_generation) = db.backend().get_account_meta("auth_generation")? {
            let bound_device = db.backend().get_account_meta("enrolled_device_id")?;
            let bound_key = db.backend().get_account_meta("enrolled_signer_key_id")?;
            if bound_device
                .as_deref()
                .is_some_and(|bound| bound != canonical_dev_id)
                || bound_key
                    .as_deref()
                    .is_some_and(|bound| bound != key_id.as_str())
            {
                return Err(MLSError::InvalidState(
                    "EnrollmentDeviceIdentityMismatch".into(),
                ));
            }
            if bound_device.as_deref() == Some(canonical_dev_id)
                && bound_key.as_deref() == Some(key_id.as_str())
            {
                return Ok(());
            }
            let devices = self
                .ds_signed_get(
                    session_token,
                    canonical_dev_id,
                    "blue.catbird.chat.getOwnDevices",
                    &[("actorDeviceId", canonical_dev_id), ("limit", "100")],
                    signer,
                )
                .await?;
            let own = chat_wire::own_active_device(&devices, canonical_dev_id, pub_key)
                .ok_or_else(|| MLSError::InvalidState("EnrollmentDeviceIdentityMismatch".into()))?;
            if own
                .pointer("/device/authGeneration")
                .or_else(|| own.get("authGeneration"))
                .and_then(Value::as_i64)
                != auth_generation.parse::<i64>().ok()
            {
                return Err(MLSError::InvalidState(
                    "EnrollmentDeviceIdentityMismatch".into(),
                ));
            }
            let ts = now_ms();
            db.write_tx(|tx| {
                tx.put_account_meta("enrolled_device_id", canonical_dev_id, ts)?;
                tx.put_account_meta("enrolled_signer_key_id", &key_id, ts)
            })?;
            return Ok(());
        }
        let dev_rec = chat_wire::build_pds_device_put_record_body(
            &self.account_did,
            canonical_dev_id,
            pub_key,
        )?;
        let (st1, b1) = self
            .pds_post_json(session_token, "/xrpc/com.atproto.repo.putRecord", dev_rec)
            .await?;
        if !(200..300).contains(&st1) {
            return Err(MLSError::Internal(format!(
                "putRecord blue.catbird.chat.device HTTP {st1}: {}",
                String::from_utf8_lossy(&b1)
            )));
        }

        let decl_rec = chat_wire::build_pds_chat_declaration_put_record_body(
            &self.account_did,
            &self.home_ds_did,
        )?;
        let (st2, b2) = self
            .pds_post_json(session_token, "/xrpc/com.atproto.repo.putRecord", decl_rec)
            .await?;
        if !(200..300).contains(&st2) {
            return Err(MLSError::Internal(format!(
                "putRecord blue.catbird.chat.declaration HTTP {st2}: {}",
                String::from_utf8_lossy(&b2)
            )));
        }

        let now_s = now_secs();
        let key_packages_json = db.write_tx(|tx| {
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
            let scoped_id = format!("{}#{}", self.account_did, canonical_dev_id);
            let cred_with_key = CredentialWithKey {
                credential: BasicCredential::new(scoped_id.into_bytes()).into(),
                signature_key: pub_key.into(),
            };
            let caps = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[CIPHERSUITE]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            let mut items: Vec<(Vec<u8>, Value)> = Vec::with_capacity(2);
            for _ in 0..2 {
                let kp_bundle = KeyPackage::builder()
                    .key_package_lifetime(Lifetime::init(
                        now_s.saturating_sub(60),
                        now_s + 29 * 86_400,
                    ))
                    .leaf_node_capabilities(caps.clone())
                    .build(CIPHERSUITE, &provider, signer, cred_with_key.clone())
                    .map_err(|e| MLSError::Cryptography(format!("build enroll KP: {e:?}")))?;
                let kp_bytes = MlsMessageOut::from(kp_bundle.key_package().clone())
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize enroll KP: {e:?}")))?;
                let kp_ref = kp_bundle
                    .key_package()
                    .hash_ref(provider.crypto())
                    .map_err(|e| MLSError::Cryptography(format!("hash_ref: {e:?}")))?
                    .as_slice()
                    .to_vec();
                let entry = json!({
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": { "$bytes": STANDARD.encode(&kp_bytes) },
                    "sha256": STANDARD.encode(Sha256::digest(&kp_bytes)),
                    "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                });
                items.push((kp_ref, entry));
            }
            items.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(items.into_iter().map(|(_, v)| v).collect::<Vec<_>>())
        })?;

        let idem = uuid::Uuid::new_v4().to_string();
        let enroll_body = json!({
            "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\0",
            "actorDid": self.account_did,
            "deviceId": canonical_dev_id,
            "deviceName": "Catmos Web",
            "keyId": key_id,
            "signaturePublicKey": { "$bytes": STANDARD.encode(pub_key) },
            "expectedAuthGeneration": 0,
            "capability": {
                "protocolVersion": "1",
                "mlsVersion": "1.0",
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "credentialType": "basic",
                "addByValue": "supported",
                "updatePath": "supported",
                "removeByValue": "supported",
                "ratchetTreeGroupInfo": "supported",
                "externalPubGroupInfo": "presentButExternalCommitsForbidden",
                "applicationFrameProfile": "dagCborApplication1",
                "controlProfile": "publicGroup1",
                "attachmentProfile": "aes256GcmBlob1",
                "metadataProfile": "exporterAes256Gcm1",
                "typingProfile": "signedClearEphemeral1"
            },
            "keyPackages": key_packages_json,
            "idempotencyKey": idem,
            "signedAt": chat_wire::now_rfc3339_millis(),
        });

        let (enroll_resp, request_keys_published) = match self
            .submit_signed_chat_op(
                session_token,
                canonical_dev_id,
                None,
                CanonicalOperation::EnrollDevice,
                &enroll_body,
                signer,
            )
            .await
        {
            Ok(resp) => (resp, false),
            // An earlier attempt registered this device, but its response was lost.
            Err(e) if e.to_string().contains(r#""error":"DeviceAlreadyExists""#) => {
                // ponytail: first page only (100 items; accounts hold at most 20 active
                // devices); follow `nextPageCursor` if revoked devices ever push this one past it.
                let devices = self
                    .ds_signed_get(
                        session_token,
                        canonical_dev_id,
                        "blue.catbird.chat.getOwnDevices",
                        &[("actorDeviceId", canonical_dev_id), ("limit", "100")],
                        signer,
                    )
                    .await?;
                let own = chat_wire::own_active_device(&devices, canonical_dev_id, pub_key)
                    .cloned()
                    .ok_or_else(|| {
                        MLSError::InvalidState(format!(
                            "DeviceAlreadyExists: mls-ds holds device {canonical_dev_id} under another key"
                        ))
                    })?;
                let published = own.get("directRequestKeyPool").is_some();
                (own, published)
            }
            Err(e) => return Err(e),
        };
        let auth_gen = enroll_resp
            .get("device")
            .and_then(|d| d.get("authGeneration"))
            .and_then(|g| g.as_i64())
            .or_else(|| enroll_resp.get("authGeneration").and_then(|g| g.as_i64()))
            .filter(|g| *g >= 1)
            .ok_or_else(|| {
                MLSError::Internal("enrollDevice response missing valid authGeneration >= 1".into())
            })?;

        let ts = now_ms();
        if !request_keys_published {
            let dr_exact_request = db.write_tx(|tx| {
                let provider =
                    OpenMlsKvProvider::new(catbird_mls::storage::OpenMlsKvStorage::new(tx))?;
                let (raw_pub_rec, _) = build_request_key_publication(
                    &provider,
                    signer,
                    &DirectRequestKeyPublicationInput {
                        actor_did: self.account_did.clone(),
                        actor_device_id: canonical_dev_id.to_string(),
                        auth_generation: auth_gen,
                        revision: 1,
                        enabled: true,
                        count: 8,
                    },
                    now_s as i64,
                )?;
                let parsed_rec: DirectRequestKeyPublication = serde_json::from_slice(&raw_pub_rec)
                    .map_err(|e| {
                        MLSError::Internal(format!("parse DirectRequestKeyPublication: {e}"))
                    })?;
                Ok(parsed_rec.exact_request)
            })?;
            let _ = self
                .ds_post_json(
                    session_token,
                    "blue.catbird.chat.publishDirectRequestKeys",
                    dr_exact_request,
                )
                .await?;
        }
        // Persist the authoritative completion binding atomically.
        db.write_tx(|tx| {
            tx.put_account_meta("auth_generation", &auth_gen.to_string(), ts)?;
            tx.put_account_meta("enrolled_device_id", canonical_dev_id, ts)?;
            tx.put_account_meta("enrolled_signer_key_id", &key_id, ts)
        })?;
        let _ = self.replenish_key_packages_impl(4).await?;
        Ok(())
    }

    pub(crate) async fn replenish_key_packages_impl(&self, count: u32) -> Result<u32, MLSError> {
        let clamped = count.clamp(1, 32);
        let now_s = now_secs();
        let device_str = self
            .canonical_uuid_v4_device_id()
            .unwrap_or_else(|| self.device_id.clone());
        let db = self.require_db_mls()?;
        let (signer, auth_gen, kps_json) = db.write_tx(|tx| {
            let signer_raw = tx
                .get_labyrinth_state("device_signer_json")?
                .ok_or_else(|| MLSError::InvalidState("WasmMlsClient not enrolled".into()))?;
            let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let auth_gen = tx
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            let provider = OpenMlsKvProvider::new(catbird_mls::storage::OpenMlsKvStorage::new(tx))?;
            let cred_with_key = CredentialWithKey {
                credential: BasicCredential::new(
                    format!("{}#{}", self.account_did, device_str).into_bytes(),
                )
                .into(),
                signature_key: signer.public().into(),
            };
            let caps = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[CIPHERSUITE]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            let mut items: Vec<(Vec<u8>, Value)> = Vec::with_capacity(clamped as usize);
            for _ in 0..clamped {
                let bundle = KeyPackage::builder()
                    .key_package_lifetime(Lifetime::init(
                        now_s.saturating_sub(60),
                        now_s + 29 * 86_400,
                    ))
                    .leaf_node_capabilities(caps.clone())
                    .build(CIPHERSUITE, &provider, &signer, cred_with_key.clone())
                    .map_err(|e| MLSError::Cryptography(format!("build replenish KP: {e:?}")))?;
                let kp_bytes = MlsMessageOut::from(bundle.key_package().clone())
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize replenish KP: {e:?}")))?;
                let kp_ref = bundle
                    .key_package()
                    .hash_ref(provider.crypto())
                    .map_err(|e| MLSError::Cryptography(format!("hash_ref: {e:?}")))?
                    .as_slice()
                    .to_vec();
                items.push((
                    kp_ref.clone(),
                    json!({
                        "framing": "mlsMessage",
                        "contentType": "keyPackage",
                        "bytes": { "$bytes": STANDARD.encode(&kp_bytes) },
                        "sha256": STANDARD.encode(Sha256::digest(&kp_bytes)),
                        "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                    }),
                ));
            }
            items.sort_by(|a, b| a.0.cmp(&b.0));
            Ok((
                signer,
                auth_gen,
                items.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
            ))
        })?;

        if let Some((session_token, canonical_dev_id)) = self.live_session() {
            let pub_key = signer.public();
            let idem = uuid::Uuid::new_v4().to_string();
            let body = json!({
                "$type": "blue.catbird.chat.defs#keyPackageReplenishmentBody",
                "signatureDomain": "CATBIRD-CHAT-DEVICE-REPLENISH\0",
                "actorDid": self.account_did,
                "actorDeviceId": canonical_dev_id,
                "authGeneration": auth_gen,
                "idempotencyKey": idem,
                "keyId": derive_key_id(pub_key),
                "keyPackages": kps_json,
                "signaturePublicKey": { "$bytes": STANDARD.encode(pub_key) },
                "signedAt": chat_wire::now_rfc3339_millis(),
            });
            let _ = self
                .submit_signed_chat_op(
                    &session_token,
                    &canonical_dev_id,
                    Some(auth_gen),
                    CanonicalOperation::ReplenishKeyPackages,
                    &body,
                    &signer,
                )
                .await?;
        }
        Ok(clamped)
    }

    pub(crate) async fn create_group_impl(
        &self,
        conversation_id: String,
        sequencer_did: String,
        member_dids: Vec<String>,
        title: Option<String>,
        description: Option<String>,
    ) -> Result<ConversationRow, MLSError> {
        let mut peer_set = BTreeSet::new();
        for raw_did in member_dids {
            let trimmed = raw_did.trim();
            if trimmed.is_empty() {
                continue;
            }
            let norm = normalize_account_did(trimmed)?;
            if norm != self.account_did {
                peer_set.insert(norm);
            }
        }
        let peers: Vec<String> = peer_set.into_iter().collect();

        let convo_uuid = uuid_v4(&conversation_id, "conversationId")?;
        let (session_token, canonical_dev_id) = self.require_live_session()?;
        for peer in &peers {
            BareDid::parse(peer)
                .map_err(|e| MLSError::invalid_input(format!("invalid peer DID `{peer}`: {e}")))?;
        }
        let canonical_convo_id = convo_uuid.hyphenated().to_string();

        let mut peer_map: BTreeMap<String, Vec<(String, Vec<u8>)>> = BTreeMap::new();
        peer_map.insert(
            self.account_did.clone(),
            self.verify_peer_device_keys_via_pds(&session_token, &self.account_did)
                .await?,
        );
        for peer in &peers {
            peer_map.insert(
                peer.clone(),
                self.verify_peer_device_keys_via_pds(&session_token, peer)
                    .await?,
            );
        }

        let is_untitle_one_to_one =
            peers.len() == 1 && title.as_deref().unwrap_or("").trim().is_empty();
        if is_untitle_one_to_one {
            return self
                .create_c33_direct_request_live(
                    &session_token,
                    &canonical_convo_id,
                    &sequencer_did,
                    &canonical_dev_id,
                    &peers[0],
                    description,
                    &peer_map,
                )
                .await;
        }

        self.create_group_conversation_live(
            &session_token,
            &canonical_convo_id,
            &convo_uuid,
            &sequencer_did,
            &canonical_dev_id,
            &peers,
            title,
            description,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_c33_direct_request_live(
        &self,
        session_token: &str,
        canonical_convo_id: &str,
        sequencer_did: &str,
        canonical_dev_id: &str,
        peer_did: &str,
        description: Option<String>,
        peer_map: &BTreeMap<String, Vec<(String, Vec<u8>)>>,
    ) -> Result<ConversationRow, MLSError> {
        let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public()));
        let request_id = uuid::Uuid::new_v4().to_string();
        let first_message_id = uuid::Uuid::new_v4().to_string();

        let prepare_body = json!({
            "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
            "protocolVersion": "2",
            "actorDid": self.account_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": key_id,
            "authGeneration": auth_gen,
            "requestId": request_id,
            "firstMessageId": first_message_id,
            "conversationId": canonical_convo_id,
            "recipientDid": peer_did,
            "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
            "profile": "encryptedIntroduction1",
            "idempotencyKey": request_id,
            "signedAt": chat_wire::now_rfc3339_millis(),
        });
        let prepare_wrapper_bytes = chat_wire::sign_direct_request_wrapper(
            DirectRequestKind::Prepare,
            prepare_body.clone(),
            &signer,
        )?;
        let prepare_verified = dr_transcript::verify_signed_request(
            DirectRequestKind::Prepare,
            &prepare_wrapper_bytes,
            signer.public(),
        )
        .map_err(|e| MLSError::Cryptography(format!("verify self C33 prepare: {e}")))?;
        let prepare_wrapper_val: Value = serde_json::from_slice(&prepare_wrapper_bytes)
            .map_err(|e| MLSError::Internal(e.to_string()))?;

        let prepare_resp = self
            .ds_post_json(
                session_token,
                "blue.catbird.chat.prepareDirectRequest",
                serde_json::to_vec(&json!({ "signedRequest": prepare_wrapper_val }))
                    .map_err(|e| MLSError::Internal(e.to_string()))?,
            )
            .await?;
        let prep_outer: Value = serde_json::from_slice(&prepare_resp)
            .map_err(|e| MLSError::Internal(format!("parse prepareDirectRequest: {e}")))?;
        let preparation = prep_outer
            .pointer("/outcome/preparation")
            .or_else(|| prep_outer.get("preparation"))
            .or_else(|| prep_outer.get("outcome"))
            .unwrap_or(&prep_outer);
        let selected = preparation
            .get("selectedDevices")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                MLSError::Internal("prepareDirectRequest missing selectedDevices".into())
            })?;

        let mut packages: Vec<Vec<u8>> = Vec::with_capacity(selected.len());
        let mut refs: Vec<Vec<u8>> = Vec::with_capacity(selected.len());
        let mut min_deadline = u64::MAX;

        for dev in selected {
            let kp_bytes = chat_wire::json_bytes(&dev["keyPackage"]["bytes"])?;
            let kp_ref = chat_wire::json_bytes(&dev["keyPackage"]["keyPackageRef"])?;
            let MlsMessageBodyIn::KeyPackage(kp_in) =
                MlsMessageIn::tls_deserialize_exact(&kp_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("deserialize selected KP: {e:?}")))?
                    .extract()
            else {
                return Err(MLSError::Cryptography(
                    "selectedDevice not KeyPackage".into(),
                ));
            };
            let unverified_cred = kp_in.unverified_credential();
            chat_wire::verify_leaf_pds_map_i4(
                unverified_cred.credential.serialized_content(),
                unverified_cred.signature_key.as_slice(),
                peer_map,
            )?;
            let exp_str = dev["grant"]["body"]["expiresAt"]
                .as_str()
                .ok_or_else(|| MLSError::invalid_input("grant missing expiresAt"))?;
            let exp_secs = chrono::DateTime::parse_from_rfc3339(exp_str)
                .map_err(|e| MLSError::invalid_input(format!("invalid grant expiresAt: {e}")))?
                .timestamp()
                .max(0) as u64;
            min_deadline = min_deadline.min(exp_secs);
            packages.push(kp_bytes);
            refs.push(kp_ref);
        }

        let authority_did = preparation
            .get("authorityDid")
            .and_then(|v| v.as_str())
            .unwrap_or(sequencer_did);
        let receipt_kid = preparation
            .get("receiptKeyId")
            .and_then(|v| v.as_str())
            .unwrap_or("#mls-receipt-1");
        let authority_key = self
            .fetch_sequencer_receipt_key_sec1(session_token, authority_did, receipt_kid)
            .await?;
        let sequencer_receipt_key = self
            .fetch_sequencer_receipt_key_sec1(session_token, authority_did, "#mls-receipt-1")
            .await?;

        let effective_convo_id = preparation
            .get("conversationId")
            .and_then(|v| v.as_str())
            .unwrap_or(canonical_convo_id)
            .to_string();
        let prep_digest_b64 =
            STANDARD.encode(chat_wire::json_bytes(&preparation["preparationDigest"])?);
        let context_json = serde_json::to_vec(&json!({
            "protocolVersion": "2",
            "requestId": request_id,
            "firstMessageId": first_message_id,
            "conversationId": effective_convo_id,
            "origin": prepare_body["origin"],
            "actorDid": self.account_did,
            "actorDeviceId": canonical_dev_id,
            "actorKeyId": key_id,
            "recipientDid": peer_did,
            "preparationDigest": prep_digest_b64,
        }))
        .map_err(|e| MLSError::Internal(e.to_string()))?;

        let intro_text = description
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "👋".to_string());
        let mut group_id_bytes = vec![0u8; 32];
        getrandom::getrandom(&mut group_id_bytes)
            .map_err(|e| MLSError::Internal(format!("getrandom: {e}")))?;
        let now_s = now_secs();
        let db = self.require_db_mls()?;

        let (bootstrap, kv_batch, opening_members) = {
            let overlay = KvWriteOverlay::new(db.backend());
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
            let (group, boot) = direct_request_bootstrap::prepare_with_provider(
                &provider,
                &signer,
                &DirectRequestBootstrapInput {
                    draft_id: request_id.clone(),
                    context_json,
                    group_id: group_id_bytes.clone(),
                    generation: 0,
                    state_version: 1,
                    key_packages: packages,
                    expected_package_refs: refs,
                    authority_import_until: min_deadline,
                    preparation_request_digest: *prepare_verified.request_digest(),
                    receipt_authority_key: authority_key,
                    sequencer_did: authority_did.to_owned(),
                    sequencer_receipt_authority_key: sequencer_receipt_key,
                    text: intro_text.clone(),
                    invitation: None,
                    metadata: GroupMetadataV1 {
                        version: 1,
                        title: String::new(),
                        description: String::new(),
                        avatar_blob_locator: None,
                        avatar_content_type: None,
                        space_avatar: None,
                    },
                },
                now_s,
            )?;
            let members = member_root_dids(&group)?;
            drop(provider);
            (boot, overlay.into_batch(), members)
        };

        let import_until_str = chat_wire::unix_secs_rfc3339_millis(bootstrap.import_until)?;
        let artifact = |data: &[u8], content_type: &str| {
            json!({
                "framing": "mlsMessage",
                "contentType": content_type,
                "bytes": STANDARD.encode(data),
                "sha256": STANDARD.encode(Sha256::digest(data)),
            })
        };
        let mut deliveries: Vec<Value> = Vec::with_capacity(selected.len());
        for d in selected {
            let kp_ref_b64 =
                STANDARD.encode(chat_wire::json_bytes(&d["keyPackage"]["keyPackageRef"])?);
            deliveries.push(json!({
                "recipientDid": d["actorDid"],
                "recipientDeviceId": d["actorDeviceId"],
                "provenance": {
                    "requestId": request_id,
                    "preparationDigest": prep_digest_b64,
                    "contextHash": STANDARD.encode(bootstrap.context_hash),
                    "grantId": d["grant"]["body"]["grantId"],
                    "grantRevision": d["grant"]["body"]["grantRevision"],
                    "keyPackageRef": kp_ref_b64,
                    "importUntil": import_until_str,
                }
            }));
        }
        let mut publish_body = prepare_verified.body().clone();
        publish_body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
        publish_body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
        publish_body["signedAt"] = json!(chat_wire::now_rfc3339_millis());
        publish_body["preparationDigest"] = json!(prep_digest_b64);
        publish_body["preparationRequestDigest"] =
            json!(STANDARD.encode(prepare_verified.request_digest()));
        publish_body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
        publish_body["next"] = bootstrap.coordinates.clone();
        publish_body["importUntil"] = json!(import_until_str);
        publish_body["archiveCommitment"] = json!(STANDARD.encode(bootstrap.archive_commitment));
        publish_body["originalSenderAttestation"] = json!({
            "senderDid": bootstrap.original_sender_attestation.sender_did,
            "senderDeviceId": bootstrap.original_sender_attestation.sender_device_id,
            "senderTransportPubkey": STANDARD.encode(
                &bootstrap
                    .original_sender_attestation
                    .sender_transport_public_key
            ),
            "signature": STANDARD.encode(&bootstrap.original_sender_attestation.signature),
        });
        publish_body["artifacts"] = json!({
            "genesisGroupInfo": artifact(&bootstrap.genesis_group_info, "groupInfo"),
            "addCommit": artifact(&bootstrap.add_commit, "publicMessageCommit"),
            "finalGroupInfo": artifact(&bootstrap.final_group_info, "groupInfo"),
            "welcome": {
                "opaqueWelcome": STANDARD.encode(&bootstrap.welcome),
                "sha256": STANDARD.encode(Sha256::digest(&bootstrap.welcome)),
                "deliveries": deliveries,
            },
            "initialCiphertext": STANDARD.encode(&bootstrap.initial_ciphertext),
            "metadataSnapshot": {
                "coordinate": direct_request_bootstrap::metadata_coordinate(&bootstrap.coordinates)?,
                "originTransitionId": request_id,
                "metadataVersion": 1,
                "nonce": STANDARD.encode(&bootstrap.metadata_nonce),
                "ciphertext": STANDARD.encode(&bootstrap.metadata_ciphertext),
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&bootstrap.metadata_ciphertext)),
                "ciphertextSize": bootstrap.metadata_ciphertext.len(),
                "authorProof": {
                    "authorDid": self.account_did,
                    "authorDeviceId": canonical_dev_id,
                    "authorKeyId": key_id,
                    "signaturePublicKey": STANDARD.encode(signer.public()),
                    "authGenerationAtOrigin": auth_gen,
                    "originTransitionId": request_id,
                    "originSeq": 1,
                    "roleAtOrigin": "admin",
                    "deviceStatusAtOrigin": "active",
                },
            }
        });

        require_direct_request_archive_commitment(&publish_body, &bootstrap.archive_commitment)?;

        let publish_wrapper_bytes = chat_wire::sign_direct_request_wrapper(
            DirectRequestKind::Publish,
            publish_body,
            &signer,
        )?;
        let publish_wrapper_val: Value = serde_json::from_slice(&publish_wrapper_bytes)
            .map_err(|e| MLSError::Internal(e.to_string()))?;
        let _ = self
            .ds_post_json(
                session_token,
                "blue.catbird.chat.publishDirectRequest",
                serde_json::to_vec(&json!({ "signedRequest": publish_wrapper_val }))
                    .map_err(|e| MLSError::Internal(e.to_string()))?,
            )
            .await?;

        let own_ds = self.home_ds_did.trim();
        let effective_sequencer = if !own_ds.is_empty() && own_ds <= authority_did {
            own_ds.to_string()
        } else {
            authority_did.to_string()
        };
        let space_uri = Some(format!(
            "at://{effective_sequencer}/space/blue.catbird.labyrinth.conversation/{effective_convo_id}-0"
        ));
        let ts = now_ms();
        let (display_json, frame_json) = canonical_labyrinth_frame_for_text(&intro_text);
        let coords_str = serde_json::to_string(&bootstrap.coordinates)
            .map_err(|e| MLSError::Internal(e.to_string()))?;

        db.write_tx(|tx| {
            kv_batch.apply(tx)?;
            let row = ConversationRow {
                conversation_id: effective_convo_id.clone(),
                group_id: group_id_bytes.clone(),
                generation: 0,
                epoch: 1,
                last_seq: 1,
                sequencer_did: effective_sequencer.clone(),
                space_uri: space_uri.clone(),
                title: None,
                unread_count: 0,
                updated_at_ms: ts,
            };
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{effective_convo_id}"),
                &coords_str,
                ts,
            )?;
            tx.upsert_request(&RequestRow {
                request_id: request_id.clone(),
                conversation_id: effective_convo_id.clone(),
                sender_did: self.account_did.clone(),
                recipient_did: peer_did.to_string(),
                consent: "outgoingPending".to_string(),
                first_message_id: Some(first_message_id.clone()),
                first_message_archived: false,
                payload_json: display_json.clone(),
                expires_at_ms: (bootstrap.import_until as i64).saturating_mul(1000),
                updated_at_ms: ts,
            })?;
            tx.insert_message(&MessageRow {
                message_id: first_message_id.clone(),
                conversation_id: effective_convo_id.clone(),
                group_id: group_id_bytes.clone(),
                epoch: 1,
                seq: 1,
                sender_did: self.account_did.clone(),
                sender_device_id: canonical_dev_id.to_string(),
                plaintext_json: display_json.clone(),
                created_at_ms: ts,
                is_own: true,
            })?;
            let staged_opening = QueuedLabyrinthArchivePayload {
                version: 1,
                message_id: first_message_id,
                conversation_id: effective_convo_id.clone(),
                group_id_hex: hex::encode(&group_id_bytes),
                epoch: 1,
                seq: 1,
                expected_member_dids: opening_members.clone(),
                sender_did: self.account_did.clone(),
                sender_device_id: canonical_dev_id.to_string(),
                sequencer_did: effective_sequencer,
                space_uri,
                plaintext_json: display_json,
                labyrinth_frame_json: frame_json,
                mls_ciphertext_b64: STANDARD.encode(&bootstrap.initial_ciphertext),
                frame_nonce_b64: None,
                sequencer_receipt_json: None,
                original_sender_attestation_json: Some(
                    serde_json::to_string(&bootstrap.original_sender_attestation).map_err(
                        |error| {
                            MLSError::Internal(format!(
                                "serialize C33 original sender attestation: {error}"
                            ))
                        },
                    )?,
                ),
                created_at_ms: ts,
            };
            tx.put_account_meta(
                &format!("c33_pending_opening:{effective_convo_id}"),
                &serde_json::to_string(&staged_opening)
                    .map_err(|e| MLSError::Internal(e.to_string()))?,
                ts,
            )?;
            Ok(row)
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_group_conversation_live(
        &self,
        session_token: &str,
        canonical_convo_id: &str,
        convo_uuid: &uuid::Uuid,
        sequencer_did: &str,
        canonical_dev_id: &str,
        peers: &[String],
        title: Option<String>,
        description: Option<String>,
    ) -> Result<ConversationRow, MLSError> {
        let mut group_id_bytes = vec![0u8; 32];
        getrandom::getrandom(&mut group_id_bytes)
            .map_err(|e| MLSError::Internal(format!("getrandom: {e}")))?;
        let now_s = now_secs();
        let ts = now_ms();
        let transition_id = uuid::Uuid::new_v4().to_string();
        let title_str = title.clone().unwrap_or_default();
        let desc_str = description.clone().unwrap_or_default();
        let db = self.require_db_mls()?;

        let (signer, auth_gen, ggi_bytes, gch, ctag, meta_snap_json, kv_batch) = {
            let backend = db.backend();
            let signer_raw = backend
                .get_labyrinth_state("device_signer_json")?
                .ok_or_else(|| MLSError::InvalidState("WasmMlsClient not enrolled".into()))?;
            let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let auth_gen = backend
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            let overlay = KvWriteOverlay::new(backend);
            let (ggi, gch, ctag, snap) = {
                let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
                signer
                    .store(provider.storage())
                    .map_err(|e| MLSError::Internal(format!("store signer: {e:?}")))?;
                let caps = Capabilities::new(
                    Some(&[ProtocolVersion::Mls10]),
                    Some(&[CIPHERSUITE]),
                    Some(&[]),
                    Some(&[]),
                    Some(&[CredentialType::Basic]),
                );
                let create_cfg = MlsGroupCreateConfig::builder()
                    .ciphersuite(CIPHERSUITE)
                    .capabilities(caps)
                    .lifetime(Lifetime::init(
                        now_s.saturating_sub(60),
                        now_s + 29 * 86_400,
                    ))
                    .use_ratchet_tree_extension(true)
                    .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                    .max_past_epochs(5)
                    .build();
                let mut group = MlsGroup::new_with_group_id(
                    &provider,
                    &signer,
                    &create_cfg,
                    GroupId::from_slice(&group_id_bytes),
                    CredentialWithKey {
                        credential: BasicCredential::new(
                            format!("{}#{}", self.account_did, canonical_dev_id).into_bytes(),
                        )
                        .into(),
                        signature_key: signer.public().into(),
                    },
                )
                .map_err(|e| MLSError::Cryptography(format!("create X-Wing group: {e:?}")))?;

                let ggi = group
                    .export_group_info(provider.crypto(), &signer, true)
                    .map_err(|e| MLSError::Cryptography(format!("export_group_info: {e:?}")))?
                    .tls_serialize_detached()
                    .map_err(|e| MLSError::Internal(format!("serialize ggi: {e:?}")))?;
                let (gch, ctag) = chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                let meta_key = derive_metadata_key_from_group(
                    &mut group,
                    provider.crypto(),
                    provider.storage(),
                    &group_id_bytes,
                    0,
                )
                .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
                let snap = chat_wire::build_encrypted_metadata_snapshot_json(
                    &meta_key,
                    &group_id_bytes,
                    convo_uuid,
                    0,
                    0,
                    &gch,
                    &ctag,
                    &transition_id,
                    1,
                    1,
                    &self.account_did,
                    canonical_dev_id,
                    auth_gen,
                    signer.public(),
                    &title_str,
                    &desc_str,
                    None,
                )?;
                (ggi, gch, ctag, snap)
            };
            (signer, auth_gen, ggi, gch, ctag, snap, overlay.into_batch())
        };

        let mut participants = vec![json!({
            "userDid": self.account_did,
            "status": "active",
            "role": "admin"
        })];
        for peer in peers {
            participants.push(json!({
                "userDid": peer,
                "status": "pending",
                "role": "member",
                "invitationProvenance": {
                    "invitationTransitionId": transition_id,
                    "invitedByDid": self.account_did,
                    "invitedByDeviceId": canonical_dev_id,
                }
            }));
        }
        participants.sort_by(|a, b| {
            a["userDid"]
                .as_str()
                .unwrap_or("")
                .cmp(b["userDid"].as_str().unwrap_or(""))
        });

        let next_coords = json!({
            "conversationId": canonical_convo_id,
            "generation": 0,
            "stateVersion": 0,
            "groupId": { "$bytes": STANDARD.encode(&group_id_bytes) },
            "epoch": 0,
            "groupContextHash": { "$bytes": STANDARD.encode(gch) },
            "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
            "lifecycle": "active",
        });
        let create_body = json!({
            "$type": "blue.catbird.chat.defs#creationBody",
            "signatureDomain": "CATBIRD-CHAT-CREATE\0",
            "conversationId": canonical_convo_id,
            "conversationKind": "group",
            "transitionId": transition_id,
            "idempotencyKey": transition_id,
            "actorDid": self.account_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_gen,
            "absence": true,
            "next": next_coords,
            "manifest": {
                "participants": participants,
                "actorLeaf": {
                    "userDid": self.account_did,
                    "deviceId": canonical_dev_id,
                    "leafOrigin": "genesis",
                }
            },
            "genesisGroupInfo": {
                "framing": "mlsMessage",
                "contentType": "groupInfo",
                "bytes": { "$bytes": STANDARD.encode(&ggi_bytes) },
                "sha256": STANDARD.encode(Sha256::digest(&ggi_bytes)),
            },
            "metadataSnapshot": meta_snap_json,
            "signedAt": chat_wire::now_rfc3339_millis(),
        });

        let resp = self
            .submit_signed_chat_op(
                session_token,
                canonical_dev_id,
                Some(auth_gen),
                CanonicalOperation::CreateConversation,
                &create_body,
                &signer,
            )
            .await?;

        let server_coords = resp
            .get("state")
            .and_then(|s| s.get("coordinates"))
            .or_else(|| resp.get("coordinates"))
            .cloned()
            .ok_or_else(|| {
                MLSError::Internal("createConversation response missing coordinates".into())
            })?;
        let server_seq = resp
            .get("seq")
            .and_then(|s| s.as_i64())
            .or_else(|| {
                resp.get("entry")
                    .and_then(|e| e.get("seq"))
                    .and_then(|s| s.as_i64())
            })
            .filter(|&seq| seq >= 1)
            .ok_or_else(|| {
                MLSError::Internal("createConversation response missing seq >= 1".into())
            })?;
        let generation = server_coords["generation"].as_i64().unwrap_or(0);
        let coords_str =
            serde_json::to_string(&server_coords).map_err(|e| MLSError::Internal(e.to_string()))?;
        let snap_str = serde_json::to_string(&meta_snap_json)
            .map_err(|e| MLSError::Internal(e.to_string()))?;

        db.write_tx(|tx| {
            kv_batch.apply(tx)?;
            if title.is_some() || description.is_some() {
                let meta_v1 = GroupMetadataV1 {
                    version: 1,
                    title: title_str.clone(),
                    description: desc_str.clone(),
                    avatar_blob_locator: None,
                    avatar_content_type: None,
                    space_avatar: None,
                };
                let meta_row =
                    chat_wire::group_metadata_row_from_v1(canonical_convo_id, 1, 0, &meta_v1, ts)?;
                tx.upsert_group_metadata(&meta_row)?;
            }
            let row = ConversationRow {
                conversation_id: canonical_convo_id.to_string(),
                group_id: group_id_bytes,
                generation,
                epoch: 0,
                last_seq: server_seq,
                sequencer_did: sequencer_did.to_string(),
                space_uri: Some(format!(
                    "at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{canonical_convo_id}-{generation}"
                )),
                title,
                unread_count: 0,
                updated_at_ms: ts,
            };
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{canonical_convo_id}"),
                &coords_str,
                ts,
            )?;
            tx.put_account_meta(
                &format!("metadata_snapshot_json:{canonical_convo_id}"),
                &snap_str,
                ts,
            )?;
            Ok(row)
        })
    }

    pub(crate) async fn add_group_members_impl(
        &self,
        conversation_id: &str,
        member_dids: Vec<String>,
    ) -> Result<ConversationRow, MLSError> {
        let mut peer_set = BTreeSet::new();
        for raw_did in member_dids {
            let trimmed = raw_did.trim();
            if !trimmed.is_empty() {
                let norm = normalize_account_did(trimmed)?;
                if norm != self.account_did {
                    peer_set.insert(norm);
                }
            }
        }
        let peers: Vec<String> = peer_set.into_iter().collect();
        uuid_v4(conversation_id, "conversationId")?;
        if peers.is_empty() {
            return Err(MLSError::invalid_input(
                "memberDids must name another account",
            ));
        }
        let (session_token, canonical_dev_id) = self.require_live_session()?;
        let db = self.require_db_mls()?;
        let existing = db
            .backend()
            .get_conversation(conversation_id)?
            .ok_or_else(|| MLSError::group_not_found(format!("missing {conversation_id}")))?;
        for peer in &peers {
            let _ = self
                .verify_peer_device_keys_via_pds(&session_token, peer)
                .await?;
        }
        let prior_coords = self.load_or_build_conversation_coords(conversation_id)?;
        let prior_sv = prior_coords["stateVersion"].as_i64().unwrap_or(0);
        let mut next_coords = prior_coords.clone();
        next_coords["stateVersion"] = json!(prior_sv + 1);
        let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        let transition_id = uuid::Uuid::new_v4().to_string();
        let changes: Vec<Value> = peers
            .iter()
            .map(|peer| {
                json!({
                    "$type": "blue.catbird.chat.defs#addParticipant",
                    "userDid": peer,
                    "role": "member",
                    "status": "pending",
                    "invitationProvenance": {
                        "$type": "blue.catbird.chat.defs#invitationProvenance",
                        "invitationTransitionId": transition_id,
                        "invitedByDid": self.account_did,
                        "invitedByDeviceId": canonical_dev_id,
                    }
                })
            })
            .collect();
        let policy_body = json!({
            "$type": "blue.catbird.chat.defs#policyTransitionBody",
            "signatureDomain": "CATBIRD-CHAT-POLICY\0",
            "transitionId": transition_id,
            "idempotencyKey": transition_id,
            "actorDid": self.account_did,
            "actorDeviceId": canonical_dev_id,
            "keyId": derive_key_id(signer.public()),
            "authGeneration": auth_gen,
            "prior": prior_coords,
            "next": next_coords,
            "participantChanges": changes,
            "signedAt": chat_wire::now_rfc3339_millis(),
        });
        let resp = self
            .submit_signed_chat_op(
                &session_token,
                &canonical_dev_id,
                Some(auth_gen),
                CanonicalOperation::SubmitTransition,
                &policy_body,
                &signer,
            )
            .await?;
        let updated_coords = resp
            .get("state")
            .and_then(|s| s.get("coordinates"))
            .or_else(|| resp.get("coordinates"))
            .cloned()
            .unwrap_or(next_coords);
        let coords_str = serde_json::to_string(&updated_coords)
            .map_err(|e| MLSError::Internal(e.to_string()))?;
        let ts = now_ms();
        let updated = db.write_tx(|tx| {
            let mut row = tx.get_conversation(conversation_id)?.unwrap_or(existing);
            row.updated_at_ms = ts;
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{conversation_id}"),
                &coords_str,
                ts,
            )?;
            Ok(row)
        })?;
        let _ = self
            .fulfill_leaf_recovery_inbox(&session_token, &canonical_dev_id, &signer, auth_gen, None)
            .await;
        Ok(db
            .backend()
            .get_conversation(conversation_id)?
            .unwrap_or(updated))
    }

    pub(crate) async fn send_message_impl(
        &self,
        conversation_id: &str,
        message_id: &str,
        text: &str,
    ) -> Result<MessageRow, MLSError> {
        let convo_uuid = uuid_v4(conversation_id, "conversationId")?;
        let msg_uuid = uuid_v4(message_id, "messageId")?;
        let (session_token, canonical_dev_id) = self.require_live_session()?;
        let (display_json, frame_json) = canonical_labyrinth_frame_for_text(text);
        let canonical_msg_id = msg_uuid.hyphenated().to_string();
        let reserve = |discard_refused| {
            self.reserve_application_send(
                convo_uuid,
                msg_uuid,
                &canonical_dev_id,
                &display_json,
                &frame_json,
                discard_refused,
            )
        };

        let (mut signer, mut auth_gen, mut pending) = reserve(false)?;
        let resp_val = match self
            .submit_application_send(
                &session_token,
                &canonical_dev_id,
                &signer,
                auth_gen,
                &pending,
            )
            .await
        {
            // `mls-ds` already sequenced a newer send from this device and refuses these bytes
            // for good. Send the same message id once more as a fresh frame and counter.
            Err(error) if chat_wire::is_stale_send(&error) => {
                (signer, auth_gen, pending) = reserve(true)?;
                self.submit_application_send(
                    &session_token,
                    &canonical_dev_id,
                    &signer,
                    auth_gen,
                    &pending,
                )
                .await?
            }
            result => result?,
        };

        let receipt_val = resp_val
            .get("sequencerReceipt")
            .or_else(|| {
                resp_val
                    .get("entry")
                    .and_then(|e| e.get("sequencerReceipt"))
            })
            .filter(|v| !v.is_null())
            .ok_or_else(|| {
                MLSError::Cryptography(
                    "sendMessage response missing mandatory sequencerReceipt (I13)".into(),
                )
            })?;
        let kid = receipt_val
            .get("kid")
            .and_then(|v| v.as_str())
            .unwrap_or("#mls-receipt-1");
        let sec1_key = self
            .fetch_sequencer_receipt_key_sec1(&session_token, &pending.archive.sequencer_did, kid)
            .await?;
        let expected_entry_id = resp_val
            .pointer("/entry/entryId")
            .and_then(|v| v.as_str())
            .or_else(|| receipt_val.get("entryId").and_then(|v| v.as_str()))
            .unwrap_or(&canonical_msg_id);
        let (final_row, gap_convo_opt) =
            self.finish_application_send(pending, receipt_val, expected_entry_id, &sec1_key, None)?;

        if let Some(gap_convo) = gap_convo_opt {
            let _ = self
                .sync_conversation_entries(
                    &session_token,
                    &canonical_dev_id,
                    &signer,
                    auth_gen,
                    &gap_convo,
                )
                .await;
        }

        let _ = self.flush_labyrinth_queue_impl().await;
        Ok(final_row)
    }

    /// POST one journaled send (`I6`: strictly outside `write_tx`). `mls-ds` refuses an
    /// out-of-order send with protocol error `StaleSend`, surfaced as
    /// `MLSError::InvalidState("StaleSend")` whatever the HTTP status.
    async fn submit_application_send(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_gen: i64,
        pending: &PendingApplicationSend,
    ) -> Result<Value, MLSError> {
        self.submit_signed_chat_op(
            session_token,
            canonical_dev_id,
            Some(auth_gen),
            CanonicalOperation::SendMessage,
            &pending.body,
            signer,
        )
        .await
        .map_err(|error| match &error {
            // `ds_post_json` failure: "POST <nsid> returned HTTP <status>: <protocol error JSON>".
            MLSError::Internal(message)
                if message
                    .split_once(": ")
                    .and_then(|(_, body)| serde_json::from_str::<Value>(body).ok())
                    .is_some_and(|body| body["error"] == chat_wire::STALE_SEND) =>
            {
                MLSError::InvalidState(chat_wire::STALE_SEND.into())
            }
            _ => error,
        })
    }

    /// Reserve the sender generation, `sendCounter` and send journal in one write transaction
    /// before any HTTP. A lost response can still publish the ciphertext, so rolling the ratchet
    /// back would reuse its key and nonce. An existing journal for the message is returned
    /// unchanged unless `discard_refused` drops it (`StaleSend` refused those bytes for good).
    fn reserve_application_send(
        &self,
        convo_uuid: uuid::Uuid,
        msg_uuid: uuid::Uuid,
        canonical_dev_id: &str,
        display_json: &str,
        frame_json: &str,
        discard_refused: bool,
    ) -> Result<(SignatureKeyPair, i64, PendingApplicationSend), MLSError> {
        let canonical_convo_id = convo_uuid.hyphenated().to_string();
        let canonical_msg_id = msg_uuid.hyphenated().to_string();
        let mut frame_nonce = [0u8; 32];
        getrandom::getrandom(&mut frame_nonce)
            .map_err(|e| MLSError::Internal(format!("getrandom: {e}")))?;
        let archive_commitment =
            PrivateMessageAadEnvelope::for_payload(&frame_nonce, frame_json.as_bytes())
                .archive_commitment;
        let ts = now_ms();

        let prior_coords = self.load_or_build_conversation_coords(&canonical_convo_id)?;
        let generation = prior_coords["generation"].as_i64().unwrap_or(0);
        let state_version = prior_coords["stateVersion"].as_i64().unwrap_or(0);
        let epoch_u64 = prior_coords["epoch"].as_u64().unwrap_or(0);
        let gch = chat_wire::json_bytes(&prior_coords["groupContextHash"])?;
        let ctag = chat_wire::json_bytes(&prior_coords["confirmationTag"])?;
        let journal_key = pending_send_key(&canonical_convo_id, &canonical_msg_id);

        self.require_db_mls()?.write_tx(|tx| {
            let convo = tx.get_conversation(&canonical_convo_id)?.ok_or_else(|| {
                MLSError::group_not_found(format!("missing {canonical_convo_id}"))
            })?;
            let signer_raw = tx
                .get_labyrinth_state("device_signer_json")?
                .ok_or_else(|| MLSError::InvalidState("WasmMlsClient not enrolled".into()))?;
            let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            if discard_refused {
                tx.delete_account_meta(&journal_key)?;
            }
            if let Some(raw) = tx.get_account_meta(&journal_key)? {
                let pending: PendingApplicationSend = serde_json::from_str(&raw)
                    .map_err(|e| MLSError::Internal(format!("parse send journal: {e}")))?;
                if pending.archive.plaintext_json != display_json
                    || pending.archive.sender_device_id != canonical_dev_id
                {
                    return Err(MLSError::invalid_input(
                        "messageId already reserved for a different send",
                    ));
                }
                let auth_gen = pending.body["authGeneration"].as_i64().ok_or_else(|| {
                    MLSError::Internal("send journal missing authGeneration".into())
                })?;
                return Ok((signer, auth_gen, pending));
            }
            let auth_gen = tx
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            // Strictly above every counter this device signed here, so `mls-ds` sequences its
            // sends in MLS generation order; persisted with this frame's ratchet advance below.
            let counter_key = chat_wire::send_counter_key(&canonical_convo_id);
            let send_counter =
                chat_wire::next_send_counter(tx.get_account_meta(&counter_key)?.as_deref())?;

            let attestation_transcript =
                labyrinth_protocol::transcripts::original_sender_archive_transcript(
                    &canonical_convo_id,
                    &canonical_msg_id,
                    &archive_commitment,
                );
            let original_sender_attestation = OriginalSenderArchiveAttestationEnvelope {
                sender_did: self.account_did.clone(),
                sender_device_id: canonical_dev_id.to_string(),
                sender_transport_public_key: signer.public().to_vec(),
                signature: signer.sign(&attestation_transcript).map_err(|error| {
                    MLSError::Cryptography(format!(
                        "sign original sender archive attestation: {error:?}"
                    ))
                })?,
            };
            original_sender_attestation.verify(
                &canonical_convo_id,
                &canonical_msg_id,
                &archive_commitment,
            )?;
            let inner_plaintext = serde_json::to_vec(&PrivateMessagePlaintextEnvelope {
                frame_nonce,
                canonical_payload_bytes: frame_json.as_bytes().to_vec(),
                original_sender_attestation: Some(original_sender_attestation.clone()),
            })
            .map_err(|error| {
                MLSError::Internal(format!(
                    "serialize PrivateMessagePlaintextEnvelope: {error}"
                ))
            })?;
            let aad_prior = chat_wire::build_aad_prior_coordinate(
                &convo_uuid,
                &convo.group_id,
                generation,
                state_version,
                epoch_u64 as i64,
                &gch,
                &ctag,
            );
            let aad_val = json!({
                "protocolVersion": "1",
                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                "generation": generation,
                "messageId": STANDARD.encode(msg_uuid.as_bytes()),
                "prior": aad_prior,
                "archiveCommitment": { "$bytes": STANDARD.encode(archive_commitment) },
                "originalSenderAttestation": original_sender_attestation.to_aad_json(),
            });
            let aad_bytes = canonical_application_aad_bytes(&aad_val).map_err(|e| {
                MLSError::Cryptography(format!("canonical_application_aad_bytes: {e}"))
            })?;

            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                    .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                    .ok_or_else(|| MLSError::group_not_found("missing MlsGroup"))?;
            group.set_aad(aad_bytes);
            let mls_out = group
                .create_message(&provider, &signer, &inner_plaintext)
                .map_err(|e| MLSError::Cryptography(format!("create_message: {e:?}")));
            group.set_aad(Vec::new());
            let ciphertext = mls_out?
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("serialize msg: {e:?}")))?;

            let body = json!({
                "$type": "blue.catbird.chat.defs#applicationSendBody",
                "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
                "messageId": canonical_msg_id,
                "actorDid": self.account_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "sendCounter": send_counter,
                "signedAt": chat_wire::now_rfc3339_millis(),
                "prior": prior_coords,
                "aad": aad_val,
                "applicationMessage": {
                    "framing": "mlsMessage",
                    "contentType": "privateMessageApplication",
                    "bytes": { "$bytes": STANDARD.encode(&ciphertext) },
                    "sha256": { "$bytes": STANDARD.encode(Sha256::digest(&ciphertext)) },
                },
                "blobBindings": [],
            });
            let pending = PendingApplicationSend {
                body,
                archive: QueuedLabyrinthArchivePayload {
                    version: 1,
                    message_id: canonical_msg_id.clone(),
                    conversation_id: canonical_convo_id.clone(),
                    group_id_hex: hex::encode(&convo.group_id),
                    epoch: group.epoch().as_u64() as i64,
                    expected_member_dids: member_root_dids(&group)?,
                    seq: 0,
                    sender_did: self.account_did.clone(),
                    sender_device_id: canonical_dev_id.to_string(),
                    sequencer_did: convo.sequencer_did,
                    space_uri: convo.space_uri,
                    plaintext_json: display_json.to_string(),
                    labyrinth_frame_json: frame_json.to_string(),
                    mls_ciphertext_b64: STANDARD.encode(&ciphertext),
                    frame_nonce_b64: Some(STANDARD.encode(frame_nonce)),
                    sequencer_receipt_json: None,
                    original_sender_attestation_json: Some(
                        serde_json::to_string(&original_sender_attestation).map_err(|error| {
                            MLSError::Internal(format!(
                                "serialize original sender archive attestation: {error}"
                            ))
                        })?,
                    ),
                    created_at_ms: ts,
                },
            };
            let journal = serde_json::to_string(&pending)
                .map_err(|e| MLSError::Internal(format!("serialize send journal: {e}")))?;
            tx.put_account_meta(&counter_key, &send_counter.to_string(), ts)?;
            tx.put_account_meta(&journal_key, &journal, ts)?;
            Ok((signer, auth_gen, pending))
        })
    }

    /// Store a sequenced journaled send after verifying its `I13` receipt: the local row,
    /// archive evidence and Labyrinth outbox item land and the journal retires in one
    /// transaction. `ordered_seq` is the entry seq when sync recovers a send whose response was
    /// lost (own MLS ciphertext is not decryptable). Returns the conversation to gap-sync, if any.
    pub(crate) fn finish_application_send(
        &self,
        pending: PendingApplicationSend,
        receipt: &Value,
        entry_id: &str,
        receipt_key_sec1: &[u8],
        ordered_seq: Option<i64>,
    ) -> Result<(MessageRow, Option<ConversationRow>), MLSError> {
        let mut queued = pending.archive;
        let group_id = hex::decode(&queued.group_id_hex)
            .map_err(|e| MLSError::Internal(format!("send journal group_id: {e}")))?;
        let frame_nonce: [u8; 32] = STANDARD
            .decode(queued.frame_nonce_b64.as_deref().unwrap_or_default())
            .ok()
            .and_then(|nonce| nonce.try_into().ok())
            .ok_or_else(|| {
                MLSError::Internal("send journal frame nonce must be 32 bytes".into())
            })?;
        let archive_commitment = PrivateMessageAadEnvelope::for_payload(
            &frame_nonce,
            queued.labyrinth_frame_json.as_bytes(),
        )
        .archive_commitment;
        let original_sender_attestation: OriginalSenderArchiveAttestationEnvelope =
            serde_json::from_str(
                queued
                    .original_sender_attestation_json
                    .as_deref()
                    .unwrap_or_default(),
            )
            .map_err(|error| {
                MLSError::Cryptography(format!(
                    "send journal original sender archive attestation: {error}"
                ))
            })?;
        let (rcpt_seq, _rcpt_gen, archived_json) =
            chat_wire::parse_and_verify_i13_sequencer_receipt(
                receipt,
                receipt_key_sec1,
                &queued.sequencer_did,
                &queued.conversation_id,
                &group_id,
                queued.epoch.max(0) as u64,
                entry_id,
                &queued.message_id,
                &archive_commitment,
                Some(&original_sender_attestation),
            )?;
        let authoritative_seq = rcpt_seq as i64;
        if ordered_seq.is_some_and(|expected| expected != authoritative_seq) {
            return Err(MLSError::Cryptography(format!(
                "I13: receipt seq {authoritative_seq} != entry seq {ordered_seq:?}"
            )));
        }
        queued.seq = authoritative_seq;
        queued.sequencer_receipt_json = Some(archived_json);
        let ts = now_ms();
        let journal_key = pending_send_key(&queued.conversation_id, &queued.message_id);

        self.require_db_mls()?.write_tx(|tx| {
            let mut gap_convo = None;
            if let Some(mut c) = tx.get_conversation(&queued.conversation_id)? {
                let prior_last_seq = c.last_seq;
                c.epoch = c.epoch.max(queued.epoch);
                if ordered_seq.is_some() || authoritative_seq == prior_last_seq.saturating_add(1) {
                    c.last_seq = prior_last_seq.max(authoritative_seq);
                } else if authoritative_seq > prior_last_seq.saturating_add(1) {
                    gap_convo = Some(c.clone());
                }
                c.updated_at_ms = ts;
                tx.upsert_conversation(&c)?;
            }
            let row = MessageRow {
                message_id: queued.message_id.clone(),
                conversation_id: queued.conversation_id.clone(),
                group_id,
                epoch: queued.epoch,
                seq: authoritative_seq,
                sender_did: queued.sender_did.clone(),
                sender_device_id: queued.sender_device_id.clone(),
                plaintext_json: queued.plaintext_json.clone(),
                created_at_ms: queued.created_at_ms,
                is_own: true,
            };
            tx.insert_message(&row)?;
            let queued_bytes =
                serde_json::to_vec(&queued).map_err(|e| MLSError::Internal(e.to_string()))?;
            tx.put_labyrinth_state(
                &format!(
                    "native.message:{}:{}",
                    queued.conversation_id, queued.message_id
                ),
                &queued_bytes,
                ts,
            )?;
            tx.dequeue_labyrinth_item(&queued.message_id)?;
            tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                item_id: queued.message_id.clone(),
                conversation_id: queued.conversation_id.clone(),
                group_id_hex: queued.group_id_hex.clone(),
                seq: authoritative_seq,
                payload_bytes: queued_bytes,
                created_at_ms: ts,
            })?;
            tx.delete_account_meta(&journal_key)?;
            Ok((row, gap_convo))
        })
    }

    pub(crate) async fn remove_group_member_impl(
        &self,
        actor_role: MemberRole,
        conversation_id: &str,
        target_did: &str,
    ) -> Result<(), MLSError> {
        if target_did.trim().is_empty() {
            return Err(MLSError::invalid_input("target_did must not be empty"));
        }
        enforce_admin_removal_policy(&self.account_did, actor_role, &[target_did.to_string()])?;

        let convo_uuid = uuid_v4(conversation_id, "conversationId")?;
        let (session_token, canonical_dev_id) = self.require_live_session()?;
        let db = self.require_db_mls()?;
        let convo = db
            .backend()
            .get_conversation(conversation_id)?
            .ok_or_else(|| MLSError::group_not_found(format!("missing {conversation_id}")))?;
        let prior_coords = self.load_or_build_conversation_coords(conversation_id)?;
        let prior_sv = prior_coords["stateVersion"].as_i64().unwrap_or(0);
        let prior_epoch = prior_coords["epoch"].as_u64().unwrap_or(0);
        let prior_gen = prior_coords["generation"].as_i64().unwrap_or(0);
        let prior_gch = chat_wire::json_bytes(&prior_coords["groupContextHash"])?;
        let prior_ctag = chat_wire::json_bytes(&prior_coords["confirmationTag"])?;
        let transition_uuid = uuid::Uuid::new_v4();
        let transition_id = transition_uuid.to_string();
        let ts = now_ms();

        let maybe_commit = {
            let backend = db.backend();
            if let Some(signer_raw) = backend.get_labyrinth_state("device_signer_json")? {
                let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let auth_gen = backend
                    .get_account_meta("auth_generation")?
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(1)
                    .max(1);
                let meta_row = backend.get_group_metadata(conversation_id)?;
                let overlay = KvWriteOverlay::new(backend);
                let staged_opt = {
                    let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
                    if let Some(mut group) =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                    {
                        let prefix = format!("{target_did}#");
                        let mut target_leaves = Vec::new();
                        let mut removed_leaves = Vec::new();
                        for m in group.members() {
                            if let Ok(id_str) =
                                std::str::from_utf8(m.credential.serialized_content())
                            {
                                if let Some(dev_part) = id_str.strip_prefix(&prefix) {
                                    target_leaves.push(m.index);
                                    removed_leaves.push(json!({
                                        "$type": "blue.catbird.chat.defs#removeLeaf",
                                        "userDid": target_did,
                                        "deviceId": dev_part,
                                    }));
                                }
                            }
                        }
                        if target_leaves.is_empty() {
                            return Err(MLSError::MemberNotFound {
                                member_id: target_did.to_string(),
                            });
                        } else {
                            let aad_prior = chat_wire::build_aad_prior_coordinate(
                                &convo_uuid,
                                &convo.group_id,
                                prior_gen,
                                prior_sv,
                                prior_epoch as i64,
                                &prior_gch,
                                &prior_ctag,
                            );
                            let commit_aad_val = json!({
                                "protocolVersion": "1",
                                "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                                "generation": prior_gen,
                                "transitionId": STANDARD.encode(transition_uuid.as_bytes()),
                                "prior": aad_prior,
                            });
                            let commit_aad_bytes = canonical_commit_aad_bytes(&commit_aad_val)
                                .map_err(|e| {
                                    MLSError::Cryptography(format!(
                                        "canonical_commit_aad_bytes: {e}"
                                    ))
                                })?;
                            group.set_aad(commit_aad_bytes);
                            let (commit_msg, _, _) = group
                                .remove_members(&provider, &signer, &target_leaves)
                                .map_err(|e| {
                                    MLSError::Cryptography(format!("remove_members: {e:?}"))
                                })?;
                            group.merge_pending_commit(&provider).map_err(|e| {
                                MLSError::Cryptography(format!("merge_pending_commit: {e:?}"))
                            })?;
                            group.set_aad(Vec::new());
                            let commit_bytes =
                                commit_msg.tls_serialize_detached().map_err(|e| {
                                    MLSError::Internal(format!("serialize commit: {e:?}"))
                                })?;
                            let next_epoch = group.epoch().as_u64();
                            let (next_gch, next_ctag) =
                                chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                            let meta_ver = meta_row
                                .as_ref()
                                .map(|m| m.metadata_version.max(1) as u64)
                                .unwrap_or(1);
                            let title_s = meta_row
                                .as_ref()
                                .and_then(|m| m.title.clone())
                                .unwrap_or_default();
                            let desc_s = meta_row
                                .as_ref()
                                .and_then(|m| m.description.clone())
                                .unwrap_or_default();
                            let avatar_opt = meta_row
                                .as_ref()
                                .and_then(chat_wire::space_avatar_from_metadata_row);
                            let meta_key = derive_metadata_key_from_group(
                                &mut group,
                                provider.crypto(),
                                provider.storage(),
                                &convo.group_id,
                                next_epoch,
                            )
                            .map_err(|e| {
                                MLSError::Cryptography(format!("derive metadata key: {e}"))
                            })?;
                            let carried_snap = chat_wire::build_encrypted_metadata_snapshot_json(
                                &meta_key,
                                &convo.group_id,
                                &convo_uuid,
                                prior_gen,
                                next_epoch,
                                &next_gch,
                                &next_ctag,
                                &transition_id,
                                meta_ver,
                                1,
                                &self.account_did,
                                &canonical_dev_id,
                                auth_gen,
                                signer.public(),
                                &title_s,
                                &desc_s,
                                avatar_opt,
                            )?;
                            Some((
                                commit_aad_val,
                                commit_bytes,
                                removed_leaves,
                                next_epoch,
                                next_gch,
                                next_ctag,
                                carried_snap,
                            ))
                        }
                    } else {
                        return Err(MLSError::group_not_found("missing MlsGroup"));
                    }
                };
                staged_opt.map(
                    |(
                        commit_aad_val,
                        commit_bytes,
                        removed_leaves,
                        next_epoch,
                        next_gch,
                        next_ctag,
                        carried_snap,
                    )| {
                        (
                            signer,
                            auth_gen,
                            commit_aad_val,
                            commit_bytes,
                            removed_leaves,
                            next_epoch,
                            next_gch,
                            next_ctag,
                            carried_snap,
                            overlay.into_batch(),
                        )
                    },
                )
            } else {
                return Err(MLSError::InvalidState("WasmMlsClient not enrolled".into()));
            }
        };

        if let Some((
            signer,
            auth_gen,
            commit_aad_val,
            commit_bytes,
            removed_leaves,
            next_epoch,
            next_gch,
            next_ctag,
            carried_snap,
            kv_batch,
        )) = maybe_commit
        {
            let next_coords = json!({
                "conversationId": conversation_id,
                "generation": prior_gen,
                "stateVersion": prior_sv + 1,
                "groupId": { "$bytes": STANDARD.encode(&convo.group_id) },
                "epoch": next_epoch,
                "groupContextHash": { "$bytes": STANDARD.encode(next_gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(&next_ctag) },
                "lifecycle": "active",
            });
            let carried_snap_str = serde_json::to_string(&carried_snap)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let body = json!({
                "$type": "blue.catbird.chat.defs#commitTransitionBody",
                "signatureDomain": "CATBIRD-CHAT-COMMIT\0",
                "transitionId": transition_id,
                "idempotencyKey": transition_id,
                "actorDid": self.account_did,
                "actorDeviceId": canonical_dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "signedAt": chat_wire::now_rfc3339_millis(),
                "prior": prior_coords,
                "next": next_coords,
                "aad": commit_aad_val,
                "manifest": {
                    "participantChanges": [{
                        "$type": "blue.catbird.chat.defs#removeParticipant",
                        "userDid": target_did,
                    }],
                    "leafChanges": removed_leaves,
                },
                "commit": {
                    "framing": "mlsMessage",
                    "contentType": "publicMessageCommit",
                    "bytes": { "$bytes": STANDARD.encode(&commit_bytes) },
                    "sha256": STANDARD.encode(Sha256::digest(&commit_bytes)),
                },
                "metadataSnapshot": carried_snap,
            });
            let resp = self
                .submit_signed_chat_op(
                    &session_token,
                    &canonical_dev_id,
                    Some(auth_gen),
                    CanonicalOperation::SubmitTransition,
                    &body,
                    &signer,
                )
                .await?;
            let updated_coords = resp
                .get("state")
                .and_then(|s| s.get("coordinates"))
                .or_else(|| resp.get("coordinates"))
                .cloned()
                .unwrap_or(next_coords);
            let coords_str = serde_json::to_string(&updated_coords)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            db.write_tx(|tx| {
                kv_batch.apply(tx)?;
                if let Some(mut c) = tx.get_conversation(conversation_id)? {
                    c.epoch = next_epoch as i64;
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)?;
                }
                tx.put_account_meta(
                    &format!("metadata_snapshot_json:{conversation_id}"),
                    &carried_snap_str,
                    ts,
                )?;
                tx.put_account_meta(
                    &format!("conversation_coords:{conversation_id}"),
                    &coords_str,
                    ts,
                )
            })?;
        }
        Ok(())
    }

    pub(crate) async fn update_group_metadata_impl(
        &self,
        conversation_id: &str,
        title: String,
        description: String,
    ) -> Result<GroupMetadataRow, MLSError> {
        let db = self.require_db_mls()?;
        let ts = now_ms();
        let backend = db.backend();
        let convo = backend
            .get_conversation(conversation_id)?
            .ok_or_else(|| MLSError::group_not_found(format!("missing {conversation_id}")))?;
        let existing_meta = backend.get_group_metadata(conversation_id)?;
        let next_ver = existing_meta
            .as_ref()
            .map(|m| m.metadata_version.saturating_add(1))
            .unwrap_or(1);
        let preserved_avatar = existing_meta
            .as_ref()
            .and_then(chat_wire::space_avatar_from_metadata_row);

        let meta_v1 = GroupMetadataV1 {
            version: 1,
            title: title.clone(),
            description: description.clone(),
            avatar_blob_locator: None,
            avatar_content_type: None,
            space_avatar: preserved_avatar,
        };
        let serialized = serde_json::to_vec(&meta_v1)
            .map_err(|e| MLSError::Internal(format!("serialize GroupMetadataV1: {e}")))?;
        validate_metadata_snapshot_size(&serialized)?;

        let row = chat_wire::group_metadata_row_from_v1(
            conversation_id,
            next_ver,
            convo.epoch,
            &meta_v1,
            ts,
        )?;

        let maybe_live = if let (Some((session_token, dev_id)), Ok(convo_uuid), Some(signer_raw)) = (
            self.live_session(),
            uuid::Uuid::parse_str(conversation_id.trim()),
            backend.get_labyrinth_state("device_signer_json")?,
        ) {
            let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let auth_gen = backend
                .get_account_meta("auth_generation")?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(1)
                .max(1);
            let overlay = KvWriteOverlay::new(backend);
            let snap_opt = {
                let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
                if let Some(mut group) =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                {
                    let epoch_u64 = group.epoch().as_u64();
                    let (gch, ctag) =
                        chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
                    let meta_key = derive_metadata_key_from_group(
                        &mut group,
                        provider.crypto(),
                        provider.storage(),
                        &convo.group_id,
                        epoch_u64,
                    )
                    .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
                    let tid = uuid::Uuid::new_v4().to_string();
                    let mut nonce = [0u8; 12];
                    let _ = getrandom::getrandom(&mut nonce);
                    let ct = encrypt_metadata_snapshot_with_nonce(
                        &meta_key,
                        &convo.group_id,
                        epoch_u64,
                        next_ver as u64,
                        &nonce,
                        &meta_v1,
                    )?;
                    validate_metadata_snapshot_size(&ct)?;
                    let snap = json!({
                        "authorProof": {
                            "authGenerationAtOrigin": auth_gen,
                            "authorDeviceId": dev_id,
                            "authorDid": self.account_did,
                            "authorKeyId": derive_key_id(signer.public()),
                            "deviceStatusAtOrigin": "active",
                            "originSeq": convo.last_seq.saturating_add(1),
                            "originTransitionId": tid,
                            "roleAtOrigin": "admin",
                            "signaturePublicKey": { "$bytes": STANDARD.encode(signer.public()) },
                        },
                        "ciphertext": { "$bytes": STANDARD.encode(&ct) },
                        "ciphertextSha256": STANDARD.encode(Sha256::digest(&ct)),
                        "ciphertextSize": ct.len(),
                        "coordinate": {
                            "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
                            "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
                            "epoch": epoch_u64,
                            "generation": convo.generation,
                            "groupContextHash": { "$bytes": STANDARD.encode(gch) },
                            "groupId": { "$bytes": STANDARD.encode(&convo.group_id) },
                        },
                        "metadataVersion": next_ver,
                        "nonce": { "$bytes": STANDARD.encode(nonce) },
                        "originTransitionId": tid,
                    });
                    Some((tid, snap))
                } else {
                    None
                }
            };
            snap_opt.map(|(tid, snap)| {
                (
                    session_token,
                    dev_id,
                    signer,
                    auth_gen,
                    tid,
                    snap,
                    overlay.into_batch(),
                )
            })
        } else {
            None
        };

        if let Some((session_token, dev_id, signer, auth_gen, tid, snap, kv_batch)) = maybe_live {
            let prior_coords = self.load_or_build_conversation_coords(conversation_id)?;
            let prior_sv = prior_coords["stateVersion"].as_i64().unwrap_or(0);
            let mut next_coords = prior_coords.clone();
            next_coords["stateVersion"] = json!(prior_sv + 1);
            let snap_str =
                serde_json::to_string(&snap).map_err(|e| MLSError::Internal(e.to_string()))?;
            let body = json!({
                "$type": "blue.catbird.chat.defs#metadataTransitionBody",
                "signatureDomain": "CATBIRD-CHAT-METADATA\0",
                "transitionId": tid,
                "idempotencyKey": tid,
                "actorDid": self.account_did,
                "actorDeviceId": dev_id,
                "keyId": derive_key_id(signer.public()),
                "authGeneration": auth_gen,
                "prior": prior_coords,
                "next": next_coords,
                "metadataSnapshot": snap,
                "signedAt": chat_wire::now_rfc3339_millis(),
            });
            let resp = self
                .submit_signed_chat_op(
                    &session_token,
                    &dev_id,
                    Some(auth_gen),
                    CanonicalOperation::SubmitTransition,
                    &body,
                    &signer,
                )
                .await?;
            let updated_coords = resp
                .get("state")
                .and_then(|s| s.get("coordinates"))
                .or_else(|| resp.get("coordinates"))
                .cloned()
                .unwrap_or(next_coords);
            let coords_str = serde_json::to_string(&updated_coords)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            db.write_tx(|tx| {
                kv_batch.apply(tx)?;
                tx.upsert_group_metadata(&row)?;
                if let Some(mut c) = tx.get_conversation(conversation_id)? {
                    c.title = row.title.clone();
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)?;
                }
                tx.put_account_meta(
                    &format!("metadata_snapshot_json:{conversation_id}"),
                    &snap_str,
                    ts,
                )?;
                tx.put_account_meta(
                    &format!("conversation_coords:{conversation_id}"),
                    &coords_str,
                    ts,
                )
            })?;
        } else {
            db.write_tx(|tx| {
                tx.upsert_group_metadata(&row)?;
                if let Some(mut c) = tx.get_conversation(conversation_id)? {
                    c.title = row.title.clone();
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)?;
                }
                Ok(())
            })?;
        }
        Ok(row)
    }

    pub(crate) fn list_members_impl(&self, conversation_id: &str) -> Result<Vec<Value>, MLSError> {
        let db = self.require_db_mls()?;
        let Some(convo) = db.backend().get_conversation(conversation_id)? else {
            return Ok(Vec::new());
        };
        let provider = db.openmls_provider()?;
        let Some(group) = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
        else {
            return Ok(Vec::new());
        };
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for m in group.members() {
            if let Ok((did, _)) =
                chat_wire::parse_scoped_credential_did_device(m.credential.serialized_content())
            {
                if seen.insert(did.clone()) {
                    let role = if did == self.account_did {
                        "admin"
                    } else {
                        "member"
                    };
                    out.push(json!({
                        "did": did.clone(),
                        "handle": did,
                        "displayName": Value::Null,
                        "role": role,
                    }));
                }
            }
        }
        Ok(out)
    }
}

/// Root DIDs of `group`'s members (credential `did#device`), sorted and unique: the send- or
/// receive-time MLS roster a queued archive item carries.
pub(crate) fn member_root_dids(group: &MlsGroup) -> Result<Vec<String>, MLSError> {
    let mut dids = std::collections::BTreeSet::new();
    for member in group.members() {
        let identity = std::str::from_utf8(member.credential.serialized_content())
            .map_err(|_| MLSError::Cryptography("non-UTF8 member credential".into()))?;
        let (did, _) = identity
            .split_once('#')
            .filter(|(did, device)| did.starts_with("did:") && !device.is_empty())
            .ok_or_else(|| MLSError::Cryptography("unscoped member credential".into()))?;
        dids.insert(did.to_owned());
    }
    Ok(dids.into_iter().collect())
}

fn require_direct_request_archive_commitment(
    body: &Value,
    expected: &[u8; 32],
) -> Result<(), MLSError> {
    let actual = body
        .get("archiveCommitment")
        .ok_or_else(|| MLSError::Cryptography("C33 publication missing archiveCommitment".into()))
        .and_then(chat_wire::json_bytes)?;
    if actual.as_slice() != expected {
        return Err(MLSError::Cryptography(
            "C33 publication archiveCommitment mismatch".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_direct_request_archive_commitment;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde_json::json;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn c33_publication_requires_the_prepared_archive_commitment() {
        let expected = [42u8; 32];
        let mut body = json!({});
        assert!(require_direct_request_archive_commitment(&body, &expected).is_err());
        body["archiveCommitment"] = json!(STANDARD.encode(expected));
        require_direct_request_archive_commitment(&body, &expected).unwrap();
        body["archiveCommitment"] = json!(STANDARD.encode([41u8; 32]));
        assert!(require_direct_request_archive_commitment(&body, &expected).is_err());
    }
}
