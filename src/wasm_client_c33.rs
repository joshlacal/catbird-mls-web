//! `C33` direct-request creation for `WasmMlsClient` (`Spec §6.3`, `I4`, `I6`, `I13`, `C33`).
//!
//! The one outgoing creation per normalized peer DID is journaled in `account_meta`
//! (`direct_request_creation:{peer_did}`) and advanced only by compare-and-swap inside one
//! `write_tx`; every network call runs outside it (`I6`). The DS fences one live preparation per
//! pair while the app names a new conversation on every tap, so the peer keys it. Retries replay
//! the exact signed prepare and, once prepared, the exact publication over the unapplied MLS
//! bootstrap: a lost or transient response never rebuilds MLS or reserves another recipient key
//! package, and nothing is committed before a verified published receipt.

use std::collections::BTreeMap;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use catbird_mls::chat_v2::transcript::direct_request::{self as dr_transcript, DirectRequestKind};
use catbird_mls::client::chat_wire;
use catbird_mls::client::QueuedLabyrinthArchivePayload;
use catbird_mls::metadata::GroupMetadataV1;
use catbird_mls::orchestrator::canonical_transport::{
    is_transient_wire_failure, retry_after_secs, MAX_RETRY_AFTER_SECS,
};
use catbird_mls::orchestrator::direct_request_bootstrap::{
    self, DirectRequestBootstrap, DirectRequestBootstrapInput,
};
use catbird_mls::storage::driver_wasm::WasmSqlBackend;
use catbird_mls::storage::{
    ConversationRow, KvWriteBatch, KvWriteOverlay, MessageRow, OpenMlsKvProvider, OpenMlsKvStorage,
    RequestRow,
};
use catbird_mls::MLSError;

use crate::wasm_client::{now_ms, now_secs, WasmMlsClient};
use crate::wasm_client_mutations::member_root_dids;

const PREPARE_NSID: &str = "blue.catbird.chat.prepareDirectRequest";
const PUBLISH_NSID: &str = "blue.catbird.chat.publishDirectRequest";
const DIRECT_REQUEST_CREATION_VERSION: u32 = 1;

/// `account_meta` key of the outgoing creation journal for `peer_did`.
fn creation_key(peer_did: &str) -> String {
    format!("direct_request_creation:{peer_did}")
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingDirectRequestCreation {
    version: u32,
    request_id: String,
    first_message_id: String,
    conversation_id: String,
    intro_text: String,
    prepare_wrapper: Vec<u8>,
    /// `now_ms()` before which a retry answers `retry_code` without any request.
    retry_at_ms: i64,
    retry_code: Option<String>,
    /// Present once the verified preparation is built into a signed publication, journaled
    /// before the publication is first sent.
    publish: Option<PendingDirectRequestPublication>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingDirectRequestPublication {
    group_id: Vec<u8>,
    sequencer_did: String,
    bootstrap: DirectRequestBootstrap,
    kv_batch: KvWriteBatch,
    publish_wrapper: Vec<u8>,
}

fn same_direct_request_attempt(
    left: &PendingDirectRequestCreation,
    right: &PendingDirectRequestCreation,
) -> Result<bool, MLSError> {
    Ok(left.version == right.version
        && left.request_id == right.request_id
        && left.first_message_id == right.first_message_id
        && left.conversation_id == right.conversation_id
        && left.intro_text == right.intro_text
        && left.prepare_wrapper == right.prepare_wrapper
        && serde_json::to_vec(&left.publish)? == serde_json::to_vec(&right.publish)?)
}

/// `{"signedRequest":<wrapper>}`, byte-identical on every replay of a journaled wrapper.
fn signed_request_body(wrapper: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(wrapper.len() + 18);
    body.extend_from_slice(b"{\"signedRequest\":");
    body.extend_from_slice(wrapper);
    body.push(b'}');
    body
}

/// A `mls-ds` answer of any status, for `c33_refused` to decide on.
struct DsResponse {
    status: u16,
    retry_after: Option<String>,
    body: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct ChatProtocolFailure {
    error: String,
}

/// Whether the DS will refuse these exact bytes again: a semantic 4xx. A transient failure
/// (`is_transient_wire_failure`, e.g. `503 CapacityUnavailable`, `429`) and every 5xx keep the
/// journaled bytes for the identical retry.
fn is_terminal_rejection(status: u16, code: Option<&str>) -> bool {
    (400..500).contains(&status) && !is_transient_wire_failure(status, code)
}

impl WasmMlsClient {
    /// Untitled 1:1 creation (`C33`). The peer-keyed journal is created and advanced with CAS,
    /// so concurrent callers can only publish the one immutable bootstrap that won ownership,
    /// and a journaled attempt's conversation and text win over the caller's.
    pub(crate) async fn create_c33_direct_request_live(
        &self,
        session_token: &str,
        canonical_convo_id: &str,
        canonical_dev_id: &str,
        peer_did: &str,
        description: Option<String>,
    ) -> Result<ConversationRow, MLSError> {
        let (signer, auth_generation) = self.load_enrolled_signer_and_auth_gen()?;
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public()));
        loop {
            let journaled = self
                .require_db_mls()?
                .backend()
                .get_account_meta(&creation_key(peer_did))?;
            let mut raw = match journaled {
                Some(raw) => raw,
                None => {
                    let request_id = uuid::Uuid::new_v4().to_string();
                    let first_message_id = uuid::Uuid::new_v4().to_string();
                    let prepare_body = json!({
                        "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
                        "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
                        "protocolVersion": "2",
                        "actorDid": self.account_did,
                        "actorDeviceId": canonical_dev_id,
                        "keyId": key_id,
                        "authGeneration": auth_generation,
                        "requestId": request_id,
                        "firstMessageId": first_message_id,
                        "conversationId": canonical_convo_id,
                        "recipientDid": peer_did,
                        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
                        "profile": "encryptedIntroduction1",
                        "idempotencyKey": request_id,
                        "signedAt": chat_wire::now_rfc3339_millis(),
                    });
                    let candidate = serde_json::to_string(&PendingDirectRequestCreation {
                        version: DIRECT_REQUEST_CREATION_VERSION,
                        prepare_wrapper: chat_wire::sign_direct_request_wrapper(
                            DirectRequestKind::Prepare,
                            prepare_body,
                            &signer,
                        )?,
                        request_id,
                        first_message_id,
                        conversation_id: canonical_convo_id.to_string(),
                        intro_text: description
                            .as_deref()
                            .filter(|text| !text.trim().is_empty())
                            .unwrap_or("👋")
                            .to_string(),
                        retry_at_ms: 0,
                        retry_code: None,
                        publish: None,
                    })?;
                    // A concurrent creation that won ownership is reloaded instead.
                    if !self.swap_direct_request_creation(
                        peer_did,
                        None,
                        Some(candidate.as_str()),
                    )? {
                        continue;
                    }
                    candidate
                }
            };
            let mut pending: PendingDirectRequestCreation = serde_json::from_str(&raw)
                .map_err(|e| MLSError::Internal(format!("parse pending direct request: {e}")))?;
            if pending.version != DIRECT_REQUEST_CREATION_VERSION {
                return Err(MLSError::Internal(format!(
                    "unsupported pending direct request version {}",
                    pending.version
                )));
            }
            // Before any network effect: a journaled attempt may still be inside `Retry-After`.
            let wait_ms = pending.retry_at_ms.saturating_sub(now_ms());
            if wait_ms > 0 && wait_ms <= MAX_RETRY_AFTER_SECS as i64 * 1_000 {
                return Err(match pending.retry_code {
                    Some(code) => MLSError::InvalidState(code),
                    None => MLSError::Internal("C33 direct request deferred by Retry-After".into()),
                });
            }
            let prepare = dr_transcript::verify_signed_request(
                DirectRequestKind::Prepare,
                &pending.prepare_wrapper,
                signer.public(),
            )
            .map_err(|e| MLSError::Cryptography(format!("verify self C33 prepare: {e}")))?;
            if pending.publish.is_none()
                && !self
                    .prepare_c33_publication(
                        session_token,
                        &mut pending,
                        &mut raw,
                        &prepare,
                        peer_did,
                        canonical_dev_id,
                        &signer,
                        &key_id,
                        auth_generation,
                    )
                    .await?
            {
                continue;
            }
            return self
                .publish_c33_direct_request(
                    session_token,
                    pending,
                    raw,
                    &prepare,
                    peer_did,
                    canonical_dev_id,
                    &signer,
                    &key_id,
                    auth_generation,
                )
                .await;
        }
    }

    /// Prepare stage of `create_c33_direct_request_live`: replay the journaled prepare, verify
    /// the preparation, build the MLS bootstrap as an unapplied overlay, sign its publication
    /// and journal all of it before anything is published. `false`: ownership was lost.
    #[allow(clippy::too_many_arguments)]
    async fn prepare_c33_publication(
        &self,
        session_token: &str,
        pending: &mut PendingDirectRequestCreation,
        raw: &mut String,
        prepare: &dr_transcript::VerifiedDirectRequest,
        peer_did: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        key_id: &str,
        auth_generation: i64,
    ) -> Result<bool, MLSError> {
        // PDS `blue.catbird.chat.device` keys (`I4`) for both accounts, up front.
        let mut peer_map: BTreeMap<String, Vec<(String, Vec<u8>)>> = BTreeMap::new();
        for did in [self.account_did.as_str(), peer_did] {
            let keys = self
                .verify_peer_device_keys_via_pds(session_token, did)
                .await?;
            peer_map.insert(did.to_owned(), keys);
        }

        let prepare_http = self
            .ds_post_raw(
                session_token,
                PREPARE_NSID,
                signed_request_body(&pending.prepare_wrapper),
            )
            .await?;
        if prepare_http.status >= 400 {
            return Err(self.c33_refused(peer_did, pending, raw, PREPARE_NSID, &prepare_http));
        }
        let prep_outer: Value = serde_json::from_slice(&prepare_http.body)
            .map_err(|e| MLSError::Internal(format!("parse prepareDirectRequest: {e}")))?;
        // The coordinator signs both a preparation and a terminal receipt. Its DID derives from
        // both homes; the peer's comes from its public declaration (no bearer to its PDS).
        let peer_ds = self
            .resolve_peer_home_ds_did(session_token, peer_did)
            .await
            .ok_or_else(|| {
                MLSError::Cryptography("C33 peer home DS authority unavailable".into())
            })?;
        let authority_did =
            dr_transcript::derive_deterministic_coordinator(self.home_ds_did.trim(), &peer_ds)
                .map_err(|e| MLSError::Cryptography(format!("C33 coordinator: {e}")))?;
        let authority_doc = self
            .resolve_did_document(session_token, &authority_did)
            .await?
            .ok_or_else(|| {
                MLSError::Cryptography(format!(
                    "C33: missing receipt authority DID document {authority_did}"
                ))
            })?;
        let receipt_key = |kid: &str| {
            dr_transcript::resolve_direct_request_receipt_key_for_authority(
                &authority_did,
                &authority_doc,
                kid,
            )
            .map_err(|e| MLSError::Cryptography(format!("C33 receipt authority: {e}")))
        };
        let outcome = &prep_outer["outcome"];
        if outcome["$type"] == "blue.catbird.chat.defs#signedDirectRequestReceipt" {
            // A signed durable decision (e.g. the replayed lease expired) drops the attempt only
            // once it verifies like a publication outcome; anything else fails closed.
            let key = receipt_key(outcome["body"]["keyId"].as_str().unwrap_or_default())?;
            let receipt = chat_wire::verify_c33_outcome(outcome, &authority_did, &key)?;
            let code = chat_wire::c33_terminal_receipt_code(&receipt, prepare, None)?
                .ok_or_else(|| MLSError::Cryptography("C33 outcome binding mismatch".into()))?;
            return Err(self.forget_c33_creation(peer_did, raw, MLSError::InvalidState(code)));
        }
        let preparation = prep_outer
            .pointer("/outcome/preparation")
            .or_else(|| prep_outer.get("preparation"))
            .or_else(|| prep_outer.get("outcome"))
            .unwrap_or(&prep_outer);
        let selected = preparation
            .get("selectedDevices")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                MLSError::Internal(format!(
                    "prepareDirectRequest did not return selectedDevices: {prep_outer}"
                ))
            })?;

        let mut packages: Vec<Vec<u8>> = Vec::with_capacity(selected.len());
        let mut refs: Vec<Vec<u8>> = Vec::with_capacity(selected.len());
        let mut min_deadline = u64::MAX;
        for dev in selected {
            let kp_bytes = chat_wire::json_bytes(&dev["keyPackage"]["bytes"])?;
            let MlsMessageBodyIn::KeyPackage(kp_in) =
                MlsMessageIn::tls_deserialize_exact(&kp_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("deserialize selected KP: {e:?}")))?
                    .extract()
            else {
                return Err(MLSError::Cryptography(
                    "selectedDevice not KeyPackage".into(),
                ));
            };
            // `I4` (`ADR-009`) against PDS `blue.catbird.chat.device` before group creation.
            let unverified_cred = kp_in.unverified_credential();
            chat_wire::verify_leaf_pds_map_i4(
                unverified_cred.credential.serialized_content(),
                unverified_cred.signature_key.as_slice(),
                &peer_map,
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
            refs.push(chat_wire::json_bytes(&dev["keyPackage"]["keyPackageRef"])?);
        }

        if preparation["authorityDid"].as_str() != Some(authority_did.as_str()) {
            return Err(MLSError::Cryptography(
                "C33 preparation authority mismatch".into(),
            ));
        }
        let receipt_kid = preparation["receiptKeyId"]
            .as_str()
            .ok_or_else(|| MLSError::Cryptography("C33 preparation missing receiptKeyId".into()))?;
        let authority_key = receipt_key(receipt_kid)?;
        // The bootstrap input pins the sequencer's current receipt method; the published
        // opening receipt itself is verified under the method its own `kid` names.
        let sequencer_receipt_key =
            chat_wire::current_sequencer_receipt_key(&authority_doc, &authority_did)?;
        if preparation["conversationId"].as_str() != Some(pending.conversation_id.as_str()) {
            return Err(MLSError::Cryptography(
                "C33 preparation conversation mismatch".into(),
            ));
        }
        let prep_digest_b64 =
            STANDARD.encode(chat_wire::json_bytes(&preparation["preparationDigest"])?);
        let context_json = serde_json::to_vec(&json!({
            "protocolVersion": "2",
            "requestId": pending.request_id,
            "firstMessageId": pending.first_message_id,
            "conversationId": pending.conversation_id,
            "origin": prepare.body()["origin"],
            "actorDid": self.account_did,
            "actorDeviceId": canonical_dev_id,
            "actorKeyId": key_id,
            "recipientDid": peer_did,
            "preparationDigest": prep_digest_b64,
        }))?;

        let mut group_id = vec![0u8; 32];
        getrandom::getrandom(&mut group_id)
            .map_err(|e| MLSError::Internal(format!("getrandom: {e}")))?;
        let overlay = KvWriteOverlay::new(self.require_db_mls()?.backend());
        let (_, bootstrap) = direct_request_bootstrap::prepare_with_provider(
            &OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?,
            signer,
            &DirectRequestBootstrapInput {
                draft_id: pending.request_id.clone(),
                context_json,
                group_id: group_id.clone(),
                generation: 0,
                state_version: 1,
                key_packages: packages,
                expected_package_refs: refs,
                authority_import_until: min_deadline,
                preparation_request_digest: *prepare.request_digest(),
                receipt_authority_key: authority_key,
                sequencer_did: authority_did.clone(),
                sequencer_receipt_authority_key: sequencer_receipt_key,
                text: pending.intro_text.clone(),
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
            now_secs(),
        )?;
        let kv_batch = overlay.into_batch();

        let import_until = chat_wire::unix_secs_rfc3339_millis(bootstrap.import_until)?;
        let artifact = |data: &[u8], content_type: &str| {
            json!({
                "framing": "mlsMessage",
                "contentType": content_type,
                "bytes": STANDARD.encode(data),
                "sha256": STANDARD.encode(Sha256::digest(data)),
            })
        };
        let deliveries: Vec<Value> = selected
            .iter()
            .zip(&bootstrap.expected_package_refs)
            .map(|(device, package_ref)| {
                json!({
                    "recipientDid": device["actorDid"],
                    "recipientDeviceId": device["actorDeviceId"],
                    "provenance": {
                        "requestId": pending.request_id,
                        "preparationDigest": prep_digest_b64,
                        "contextHash": STANDARD.encode(bootstrap.context_hash),
                        "grantId": device["grant"]["body"]["grantId"],
                        "grantRevision": device["grant"]["body"]["grantRevision"],
                        "keyPackageRef": STANDARD.encode(package_ref),
                        "importUntil": import_until,
                    }
                })
            })
            .collect();
        let mut publish_body = prepare.body().clone();
        publish_body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
        publish_body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
        publish_body["signedAt"] = json!(chat_wire::now_rfc3339_millis());
        publish_body["preparationDigest"] = json!(prep_digest_b64);
        publish_body["preparationRequestDigest"] = json!(STANDARD.encode(prepare.request_digest()));
        publish_body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
        publish_body["next"] = bootstrap.coordinates.clone();
        publish_body["importUntil"] = json!(import_until);
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
                "originTransitionId": pending.request_id,
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
                    "authGenerationAtOrigin": auth_generation,
                    "originTransitionId": pending.request_id,
                    "originSeq": 1,
                    "roleAtOrigin": "admin",
                    "deviceStatusAtOrigin": "active",
                },
            }
        });
        require_direct_request_archive_commitment(&publish_body, &bootstrap.archive_commitment)?;

        let publish_wrapper = chat_wire::sign_direct_request_wrapper(
            DirectRequestKind::Publish,
            publish_body,
            signer,
        )?;
        pending.publish = Some(PendingDirectRequestPublication {
            group_id,
            sequencer_did: authority_did,
            bootstrap,
            kv_batch,
            publish_wrapper,
        });
        // CAS before send: a concurrent builder that lost ownership reloads this exact winner
        // instead of publishing a second MLS bootstrap.
        self.save_direct_request_creation(peer_did, pending, raw)
    }

    /// Publish stage of `create_c33_direct_request_live`: replay the journaled publication and
    /// commit its bootstrap only on the verified published receipt, in the same write that
    /// drops the journal. An unsigned, malformed or unbound answer commits nothing and keeps
    /// the journal.
    #[allow(clippy::too_many_arguments)]
    async fn publish_c33_direct_request(
        &self,
        session_token: &str,
        mut pending: PendingDirectRequestCreation,
        mut raw: String,
        prepare: &dr_transcript::VerifiedDirectRequest,
        peer_did: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        key_id: &str,
        auth_generation: i64,
    ) -> Result<ConversationRow, MLSError> {
        let publication = pending
            .publish
            .as_ref()
            .ok_or_else(|| MLSError::Internal("C33 creation journal has no publication".into()))?;
        let verified_publication = dr_transcript::verify_signed_request(
            DirectRequestKind::Publish,
            &publication.publish_wrapper,
            signer.public(),
        )
        .map_err(|e| MLSError::Cryptography(format!("C33 signed publication: {e}")))?;
        let published_http = self
            .ds_post_raw(
                session_token,
                PUBLISH_NSID,
                signed_request_body(&publication.publish_wrapper),
            )
            .await?;
        if published_http.status >= 400 {
            return Err(self.c33_refused(
                peer_did,
                &mut pending,
                &mut raw,
                PUBLISH_NSID,
                &published_http,
            ));
        }
        let PendingDirectRequestCreation {
            request_id,
            first_message_id,
            conversation_id,
            intro_text,
            ..
        } = &pending;
        let PendingDirectRequestPublication {
            group_id,
            sequencer_did,
            bootstrap,
            kv_batch,
            ..
        } = publication;

        let published: Value = serde_json::from_slice(&published_http.body)?;
        let outcome = published.get("outcome").ok_or_else(|| {
            MLSError::Cryptography("C33 publication response missing signed outcome".into())
        })?;
        let receipt_method = outcome
            .pointer("/body/keyId")
            .and_then(Value::as_str)
            .ok_or_else(|| MLSError::Cryptography("C33 outcome missing receipt keyId".into()))?;
        let authority_doc = self
            .resolve_did_document(session_token, sequencer_did)
            .await?
            .ok_or_else(|| {
                MLSError::Cryptography("C33 publication authority document unavailable".into())
            })?;
        let authority_key = dr_transcript::resolve_direct_request_receipt_key_for_authority(
            sequencer_did,
            &authority_doc,
            receipt_method,
        )
        .map_err(|e| MLSError::Cryptography(format!("C33 publication receipt key: {e}")))?;
        let receipt = chat_wire::verify_c33_outcome(outcome, sequencer_did, &authority_key)?;
        // A signed decision not to publish (e.g. the lease expired before this replay).
        if let Some(code) =
            chat_wire::c33_terminal_receipt_code(&receipt, prepare, Some(&verified_publication))?
        {
            return Err(self.forget_c33_creation(peer_did, &raw, MLSError::InvalidState(code)));
        }
        if receipt["$type"] != "blue.catbird.chat.defs#directRequestPublishedReceipt"
            || receipt["requestId"] != *request_id
            || receipt["conversationId"] != *conversation_id
            || receipt["firstMessageId"] != *first_message_id
            || receipt["requestKind"] != "publish"
            || receipt["actorDid"].as_str() != Some(self.account_did.as_str())
            || receipt["actorDeviceId"].as_str() != Some(canonical_dev_id)
            || receipt["actorKeyId"] != key_id
            || receipt["authGeneration"].as_i64() != Some(auth_generation)
            || receipt["requestDigest"].as_str()
                != Some(
                    STANDARD
                        .encode(verified_publication.request_digest())
                        .as_str(),
                )
            || receipt["preparationRequestDigest"].as_str()
                != Some(STANDARD.encode(prepare.request_digest()).as_str())
            || receipt["coordinates"] != bootstrap.coordinates
        {
            return Err(MLSError::Cryptography(
                "C33 publication outcome binding mismatch".into(),
            ));
        }
        let opening_receipt = &receipt["sequencerReceipt"];
        let sequencer_receipt_key = self
            .fetch_sequencer_receipt_key_sec1(
                session_token,
                sequencer_did,
                chat_wire::sequencer_receipt_kid(sequencer_did, opening_receipt)?,
            )
            .await?;
        let (opening_seq, _, opening_receipt_json) =
            direct_request_bootstrap::verify_opening_receipt(
                bootstrap,
                opening_receipt,
                sequencer_did,
                &sequencer_receipt_key,
            )?;
        let opening_seq = i64::try_from(opening_seq)
            .map_err(|_| MLSError::Cryptography("C33 sequence overflow".into()))?;
        let opening = bootstrap.opening.as_ref().ok_or_else(|| {
            MLSError::Cryptography("C33 sender missing authenticated opening frame".into())
        })?;
        let frame_json = String::from_utf8(opening.canonical_payload_bytes.clone())
            .map_err(|e| MLSError::Cryptography(format!("C33 opening frame: {e}")))?;
        let display_json = json!({ "text": intro_text }).to_string();
        let coords_json = serde_json::to_string(&bootstrap.coordinates)?;
        let attestation_json = serde_json::to_string(&bootstrap.original_sender_attestation)?;
        let space_uri = Some(format!(
            "at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{conversation_id}-0"
        ));
        let key = creation_key(peer_did);
        let ts = now_ms();

        self.require_db_mls()?.write_tx(|tx| {
            let Some(current_raw) = tx.get_account_meta(&key)? else {
                return tx.get_conversation(conversation_id)?.ok_or_else(|| {
                    MLSError::Internal("C33 journal disappeared before publication commit".into())
                });
            };
            let current: PendingDirectRequestCreation = serde_json::from_str(&current_raw)
                .map_err(|e| MLSError::Internal(format!("parse current C33 journal: {e}")))?;
            if !same_direct_request_attempt(&pending, &current)? {
                return Err(MLSError::InvalidState(
                    "DirectRequestOwnershipChanged".into(),
                ));
            }
            kv_batch.apply(tx)?;
            let group = MlsGroup::load(&OpenMlsKvStorage::new(tx), &GroupId::from_slice(group_id))
                .map_err(|e| MLSError::Internal(format!("load C33 roster: {e:?}")))?
                .ok_or_else(|| MLSError::group_not_found(conversation_id.as_str()))?;
            let row = ConversationRow {
                conversation_id: conversation_id.clone(),
                group_id: group_id.clone(),
                generation: 0,
                epoch: 1,
                last_seq: opening_seq,
                sequencer_did: sequencer_did.clone(),
                space_uri: space_uri.clone(),
                title: None,
                unread_count: 0,
                updated_at_ms: ts,
            };
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{conversation_id}"),
                &coords_json,
                ts,
            )?;
            tx.upsert_request(&RequestRow {
                request_id: request_id.clone(),
                conversation_id: conversation_id.clone(),
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
                conversation_id: conversation_id.clone(),
                group_id: group_id.clone(),
                epoch: 1,
                seq: opening_seq,
                sender_did: self.account_did.clone(),
                sender_device_id: canonical_dev_id.to_string(),
                plaintext_json: display_json.clone(),
                created_at_ms: ts,
                is_own: true,
            })?;
            // Staged for the conversation Space; archived only after the recipient accepts.
            let staged_opening = serde_json::to_string(&QueuedLabyrinthArchivePayload {
                version: 1,
                message_id: first_message_id.clone(),
                conversation_id: conversation_id.clone(),
                group_id_hex: hex::encode(group_id),
                epoch: 1,
                expected_member_dids: member_root_dids(&group)?,
                seq: opening_seq,
                sender_did: self.account_did.clone(),
                sender_device_id: canonical_dev_id.to_string(),
                sequencer_did: sequencer_did.clone(),
                space_uri,
                plaintext_json: display_json,
                labyrinth_frame_json: frame_json,
                mls_ciphertext_b64: STANDARD.encode(&bootstrap.initial_ciphertext),
                frame_nonce_b64: Some(STANDARD.encode(opening.frame_nonce)),
                sequencer_receipt_json: Some(opening_receipt_json),
                original_sender_attestation_json: Some(attestation_json),
                created_at_ms: ts,
            })?;
            tx.put_labyrinth_state(
                &format!("native.message:{conversation_id}:{first_message_id}"),
                staged_opening.as_bytes(),
                ts,
            )?;
            tx.put_account_meta(
                &format!("c33_pending_opening:{conversation_id}"),
                &staged_opening,
                ts,
            )?;
            // The attempt is resolved in the same write that applies its bootstrap.
            tx.delete_account_meta(&key)?;
            Ok(row)
        })
    }

    /// A refused prepare may resolve its pre-publication journal. Once publication bytes exist,
    /// no unsigned response proves nonpublication: every 4xx/5xx/auth failure retains them.
    fn c33_refused(
        &self,
        peer_did: &str,
        pending: &mut PendingDirectRequestCreation,
        expected_raw: &mut String,
        nsid: &str,
        resp: &DsResponse,
    ) -> MLSError {
        let code = serde_json::from_slice::<ChatProtocolFailure>(&resp.body)
            .ok()
            .map(|failure| failure.error);
        let terminal = is_terminal_rejection(resp.status, code.as_deref());
        let error = match code {
            Some(code) => MLSError::InvalidState(code),
            None => MLSError::Internal(format!(
                "POST {nsid} returned HTTP {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            )),
        };
        if terminal && pending.publish.is_none() {
            return self.forget_c33_creation(peer_did, expected_raw, error);
        }
        let delay_ms = if terminal {
            0
        } else {
            retry_after_secs(resp.retry_after.as_deref()).unwrap_or(0) * 1_000
        };
        pending.retry_at_ms = now_ms().saturating_add(delay_ms as i64);
        pending.retry_code = match &error {
            MLSError::InvalidState(code) => Some(code.clone()),
            _ => None,
        };
        match self.save_direct_request_creation(peer_did, pending, expected_raw) {
            Ok(true) => error,
            Ok(false) => MLSError::InvalidState("DirectRequestOwnershipChanged".into()),
            Err(db) => db,
        }
    }

    /// Compare-and-swap of `peer_did`'s creation journal in its own `write_tx`, never around
    /// HTTP (`I6`): it becomes `next` (`None`: deleted) only while it holds exactly `expected`.
    fn swap_direct_request_creation(
        &self,
        peer_did: &str,
        expected: Option<&str>,
        next: Option<&str>,
    ) -> Result<bool, MLSError> {
        let key = creation_key(peer_did);
        self.require_db_mls()?.write_tx(|tx| {
            if tx.get_account_meta(&key)?.as_deref() != expected {
                return Ok(false);
            }
            match next {
                Some(raw) => tx.put_account_meta(&key, raw, now_ms())?,
                None => tx.delete_account_meta(&key)?,
            }
            Ok(true)
        })
    }

    /// CAS `pending` over `expected_raw`. Losing ownership leaves the winner untouched so the
    /// caller can reload its immutable publication.
    fn save_direct_request_creation(
        &self,
        peer_did: &str,
        pending: &PendingDirectRequestCreation,
        expected_raw: &mut String,
    ) -> Result<bool, MLSError> {
        let payload = serde_json::to_string(pending)?;
        let saved = self.swap_direct_request_creation(
            peer_did,
            Some(expected_raw.as_str()),
            Some(payload.as_str()),
        )?;
        if saved {
            *expected_raw = payload;
        }
        Ok(saved)
    }

    /// Drop the creation journal only if this caller still owns the exact bytes.
    fn forget_c33_creation(&self, peer_did: &str, expected_raw: &str, error: MLSError) -> MLSError {
        match self.swap_direct_request_creation(peer_did, Some(expected_raw), None) {
            Ok(true) => error,
            Ok(false) => MLSError::InvalidState("DirectRequestOwnershipChanged".into()),
            Err(db) => db,
        }
    }

    /// `ds_post_json` that returns every answer with its status and `Retry-After`, so
    /// `c33_refused` can decide. A transport failure stays an `Err`: its outcome is unknown.
    async fn ds_post_raw(
        &self,
        session_token: &str,
        nsid: &str,
        body: Vec<u8>,
    ) -> Result<DsResponse, MLSError> {
        let jwt = self.mint_ds_auth_token(session_token, nsid).await?;
        let resp = self
            .http
            .post(format!("{}/xrpc/{nsid}", self.ds_base()))
            .bearer_auth(&jwt)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| MLSError::Internal(format!("POST {nsid} failed: {e}")))?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = resp
            .bytes()
            .await
            .map_err(|e| MLSError::Internal(format!("read {nsid} body: {e}")))?
            .to_vec();
        Ok(DsResponse {
            status,
            retry_after,
            body,
        })
    }
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
