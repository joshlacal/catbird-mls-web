//! Async network, `I4`/`I13`/`I14` verification, `C33` consent, Labyrinth Space archival,
//! and `sync()` catch-up methods for `WasmMlsClient` (`Spec §6.3`, `I6`).

use std::collections::BTreeMap;
use std::rc::Rc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use catbird_mls::chat_v2::ids::BareDid;
use catbird_mls::chat_v2::transcript::direct_request::{self as dr_transcript, DirectRequestKind};
use catbird_mls::chat_v2::transcript::SignedMutationKind;
use catbird_mls::chat_v2::wire::ACCOUNT_DELETED_ENTRY_KIND;
use catbird_mls::client::chat_wire;
use catbird_mls::client::QueuedLabyrinthArchivePayload;
use catbird_mls::messaging::receive::{
    extract_plaintext_body_and_verify_aad, verify_application_aad_archive_evidence,
    OriginalSenderArchiveAttestationEnvelope, PrivateMessagePlaintextEnvelope,
};
use catbird_mls::metadata::derive_metadata_key_from_group;
use catbird_mls::orchestrator::canonical_transport::{
    canonical_application_aad_bytes, canonical_commit_aad_bytes, derive_key_id, CanonicalOperation,
};
use catbird_mls::orchestrator::direct_request_bootstrap::{
    DirectRequestBootstrap, DirectRequestIntroductionResult, DirectRequestWelcomeInput,
    C33_OPENING_UNAVAILABLE,
};
use catbird_mls::orchestrator::direct_request_shared_crypto::decrypt_introduction_with_provider;
use catbird_mls::orchestrator::MLSMessagePayload;
use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend};
use catbird_mls::storage::{
    ConversationRow, KvWriteOverlay, LabyrinthQueueRow, MessageRow, OpenMlsKvProvider,
    OpenMlsKvStorage, RequestRow,
};
use catbird_mls::MLSError;

use crate::sqlite_conn::SqliteConn;
use crate::wasm_client::{now_ms, uuid_v4, WasmMlsClient};
use crate::wasm_client_mutations::{
    conversation_close_key, get_commit_transition, is_terminal_refusal, pending_send_key,
    prune_commit_transitions,
};

fn build_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(5)
        .sender_ratchet_configuration(
            catbird_mls::GroupConfig::default().sender_ratchet_configuration(),
        )
        .build()
}

/// Stage the MLS Welcome message `welcome` against `provider`.
fn stage_welcome<P: OpenMlsProvider>(
    provider: &P,
    welcome: &[u8],
) -> Result<StagedWelcome, MLSError> {
    let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(welcome)
        .map_err(|e| MLSError::Cryptography(format!("deserialize Welcome: {e:?}")))?
        .extract()
    else {
        return Err(MLSError::Cryptography("not a Welcome".into()));
    };
    StagedWelcome::new_from_welcome(provider, &build_join_config(), welcome, None)
        .map_err(|e| MLSError::Cryptography(format!("stage Welcome: {e:?}")))
}

fn require_browser_welcome_receipt_inputs(
    preparation_request_digest: &[u8; 32],
    published_receipt: &[u8],
    receipt_authority_did: &str,
    receipt_authority_key: &[u8],
) -> Result<(), MLSError> {
    if preparation_request_digest == &[0; 32]
        || published_receipt.is_empty()
        || receipt_authority_did.is_empty()
        || receipt_authority_key.is_empty()
    {
        return Err(MLSError::Cryptography(
            "C33 Welcome is missing verified publication receipt inputs".into(),
        ));
    }
    Ok(())
}

/// The outer signed send of an application entry, verified under its actor device's PDS key
/// (`I4`) and bound to this conversation and message id, before any effect.
fn verify_application_body(
    signed_request: &Value,
    entry: &Value,
    peer_map: &BTreeMap<String, Vec<(String, Vec<u8>)>>,
    conversation_id: &str,
    message_id: &str,
) -> Result<Value, MLSError> {
    let body = &signed_request["body"];
    let did = body["actorDid"]
        .as_str()
        .ok_or_else(|| MLSError::Cryptography("applicationSendBody missing actorDid".into()))?;
    let device = body["actorDeviceId"].as_str().ok_or_else(|| {
        MLSError::Cryptography("applicationSendBody missing actorDeviceId".into())
    })?;
    let (_, key) = peer_map
        .get(did)
        .and_then(|devices| devices.iter().find(|(id, _)| id == device))
        .ok_or_else(|| {
            MLSError::Cryptography("application outer sender key is not authorized".into())
        })?;
    let verified = chat_wire::verify_signed_mutation_body(
        signed_request,
        SignedMutationKind::ApplicationSend,
        key,
    )?;
    if verified["actorDid"] != did
        || verified["actorDeviceId"] != device
        || verified["messageId"] != message_id
        || verified["prior"]["conversationId"] != conversation_id
        || entry
            .get("conversationId")
            .and_then(Value::as_str)
            .is_some_and(|conversation| conversation != conversation_id)
    {
        return Err(MLSError::Cryptography(
            "signed application coordinates or sender mismatch".into(),
        ));
    }
    Ok(verified)
}

fn acceptance_refused(what: impl std::fmt::Display) -> MLSError {
    MLSError::Cryptography(format!("C33 acceptance: {what}"))
}

/// Contract B: a 2xx answer that sequences this device's own signed request (`submitted`, its
/// `{"signedRequest": ...}` request body) is evidence only of that request. Its `entry` must be
/// exactly it (the entry kind for its body, its conversation, the very wrapper this device
/// signed, so it verifies under this device's key) and its `coordinates` that request's signed
/// `next`. Returns the verified entry seq.
fn verify_own_entry_answer(answer: &Value, submitted: &Value) -> Result<i64, MLSError> {
    let refused =
        |what: String| MLSError::Cryptography(format!("unverified answer to own request: {what}"));
    let read = |value: &Value, name: &str| -> Result<Value, MLSError> {
        dr_transcript::normalize_read_presentation(&serde_json::to_vec(value)?, name, false)
            .map_err(|e| refused(format!("{name}: {e}")))
    };
    let (entry_kind, wrapper) = match submitted
        .pointer("/signedRequest/body/$type")
        .and_then(Value::as_str)
        .and_then(SignedMutationKind::from_type_id)
    {
        Some(SignedMutationKind::Creation) => ("creationEntry", "signedCreation"),
        Some(SignedMutationKind::CommitTransition) => ("commitEntry", "signedCommitTransition"),
        Some(SignedMutationKind::PolicyTransition) => ("policyEntry", "signedPolicyTransition"),
        Some(SignedMutationKind::MetadataTransition) => {
            ("metadataEntry", "signedMetadataTransition")
        }
        Some(SignedMutationKind::LeafRecoveryFulfillment) => (
            "leafRecoveryFulfillmentEntry",
            "signedLeafRecoveryFulfillment",
        ),
        _ => return Err(refused("no sequenced own request".into())),
    };
    let own = read(&submitted["signedRequest"], wrapper)?;
    let mut entry = answer["entry"].clone();
    let tag = entry
        .as_object_mut()
        .and_then(|fields| fields.remove("$type"));
    let entry = read(&entry, entry_kind)?;
    if tag
        != Some(Value::String(format!(
            "blue.catbird.chat.defs#{entry_kind}"
        )))
        || entry["signedRequest"] != own
        || entry["conversationId"] != own["body"]["next"]["conversationId"]
        || read(&answer["coordinates"], "conversationCoordinates")? != own["body"]["next"]
    {
        return Err(refused(
            "its entry or coordinates are not this device's signed request".into(),
        ));
    }
    entry["seq"]
        .as_i64()
        .ok_or_else(|| refused("entry seq".into()))
}

/// One conversation's sync pass, as its control-entry checks read it.
struct SyncPass<'a> {
    session_token: &'a str,
    canonical_dev_id: &'a str,
    signer: &'a SignatureKeyPair,
    cid: &'a str,
    /// The pass's entries, in seq order.
    batch: &'a [Value],
}

/// A verified control body names only `cid`: its `prior` (without one, its own
/// `conversationId`) and each `next`, `retired` and `successor` coordinate it carries.
fn binds_only(body: &Value, cid: &str) -> bool {
    body.get("prior").unwrap_or(body)["conversationId"].as_str() == Some(cid)
        && ["next", "retired", "successor"].iter().all(|field| {
            body.get(field)
                .is_none_or(|coordinate| coordinate["conversationId"].as_str() == Some(cid))
        })
}

impl WasmMlsClient {
    pub(crate) fn effective_auth_token(&self) -> Option<String> {
        if let Some(tok) = self
            .auth_token
            .borrow()
            .as_ref()
            .filter(|s| !s.trim().is_empty())
        {
            return Some(tok.clone());
        }
        crate::with_state(|s| Ok(s.auth_token.clone()))
            .ok()
            .flatten()
            .filter(|s| !s.trim().is_empty())
    }

    pub(crate) fn canonical_uuid_v4_device_id(&self) -> Option<String> {
        if BareDid::parse(&self.account_did).is_err() {
            return None;
        }
        let uuid = uuid_v4(&self.device_id)?;
        Some(uuid.hyphenated().to_string())
    }

    pub(crate) fn live_session(&self) -> Option<(String, String)> {
        Some((
            self.effective_auth_token()?,
            self.canonical_uuid_v4_device_id()?,
        ))
    }

    /// Live session for sends and group creation; there is no local-only fallback.
    pub(crate) fn require_live_session(&self) -> Result<(String, String), MLSError> {
        let device = self
            .canonical_uuid_v4_device_id()
            .ok_or_else(|| MLSError::invalid_input("device_id must be a UUIDv4"))?;
        let token = self
            .effective_auth_token()
            .ok_or_else(|| MLSError::InvalidState("not authenticated: call setAuthToken".into()))?;
        Ok((token, device))
    }

    pub(crate) fn ds_base(&self) -> String {
        self.home_ds_endpoint.trim_end_matches('/').to_string()
    }

    pub(crate) fn pds_base(&self) -> String {
        self.pds_endpoint.trim_end_matches('/').to_string()
    }

    pub(crate) fn require_db_mls(&self) -> Result<&WasmAccountDb<Rc<SqliteConn>>, MLSError> {
        self.db.as_ref().ok_or(MLSError::ContextClosed)
    }

    pub(crate) fn load_enrolled_signer_and_auth_gen(
        &self,
    ) -> Result<(SignatureKeyPair, i64), MLSError> {
        let db = self.require_db_mls()?;
        let signer_raw = db
            .backend()
            .get_labyrinth_state("device_signer_json")?
            .ok_or_else(|| MLSError::InvalidState("WasmMlsClient is not enrolled".to_string()))?;
        let signer: SignatureKeyPair = serde_json::from_slice(&signer_raw)
            .map_err(|e| MLSError::Internal(format!("deserialize device_signer_json: {e}")))?;
        let auth_gen = db
            .backend()
            .get_account_meta("auth_generation")?
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(1)
            .max(1);
        Ok((signer, auth_gen))
    }

    pub(crate) async fn mint_ds_auth_token(
        &self,
        session_token: &str,
        nsid: &str,
    ) -> Result<String, MLSError> {
        let aud_clean = self
            .home_ds_did
            .split('#')
            .next()
            .unwrap_or(&self.home_ds_did);
        let url = format!(
            "{}/xrpc/com.atproto.server.getServiceAuth?aud={}&lxm={}",
            self.pds_base(),
            chat_wire::urlencode_form_component(aud_clean),
            chat_wire::urlencode_form_component(nsid),
        );
        if let Ok(resp) = self
            .http
            .get(&url)
            .bearer_auth(session_token)
            .header("Accept", "application/json")
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(bytes) = resp.bytes().await {
                    if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                        if let Some(tok) = val.get("token").and_then(|v| v.as_str()) {
                            if !tok.trim().is_empty() {
                                return Ok(tok.to_string());
                            }
                        }
                    }
                }
            }
        }
        Ok(session_token.to_string())
    }

    pub(crate) async fn ds_post_json(
        &self,
        session_token: &str,
        nsid: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, MLSError> {
        let jwt = self.mint_ds_auth_token(session_token, nsid).await?;
        let url = format!("{}/xrpc/{nsid}", self.ds_base());
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&jwt)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| MLSError::Internal(format!("POST {nsid} failed: {e}")))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| MLSError::Internal(format!("read {nsid} body: {e}")))?
            .to_vec();
        if !(200..300).contains(&status) {
            return Err(MLSError::Internal(format!(
                "POST {nsid} returned HTTP {status}: {}",
                String::from_utf8_lossy(&bytes)
            )));
        }
        Ok(bytes)
    }

    /// POST one signed clean-chat mutation and return its 2xx answer. An answer that sequences
    /// this device's own transition or creation must verify first ([`verify_own_entry_answer`]):
    /// any other answer is an error, so no caller moves its cursor, writes coordinates or merges
    /// a staged commit from it (contract B).
    pub(crate) async fn submit_signed_chat_op(
        &self,
        session_token: &str,
        device_id: &str,
        auth_generation: Option<i64>,
        operation: CanonicalOperation,
        body_value: &Value,
        signer: &SignatureKeyPair,
    ) -> Result<Value, MLSError> {
        let prepared = chat_wire::sign_clean_chat_mutation(
            &self.account_did,
            device_id,
            auth_generation,
            operation,
            body_value,
            signer,
        )?;
        let nsid = prepared
            .path
            .strip_prefix("/xrpc/")
            .unwrap_or(&prepared.path);
        let request = prepared.body.unwrap_or_default();
        let own_request = matches!(
            operation,
            CanonicalOperation::SubmitTransition | CanonicalOperation::CreateConversation
        )
        .then(|| serde_json::from_slice::<Value>(&request))
        .transpose()?;
        let bytes = self.ds_post_json(session_token, nsid, request).await?;
        if bytes.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(MLSError::Internal(format!(
                "POST {nsid} returned empty response body"
            )));
        }
        let val: Value = serde_json::from_slice(&bytes)
            .map_err(|e| MLSError::Internal(format!("parse {operation:?} JSON: {e}")))?;
        if let Some(submitted) = &own_request {
            let answer = match operation {
                CanonicalOperation::CreateConversation => &val["result"],
                _ => &val,
            };
            verify_own_entry_answer(answer, submitted)?;
        }
        Ok(val)
    }

    pub(crate) async fn ds_signed_get(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        nsid: &str,
        query_pairs: &[(&str, &str)],
        signer: &SignatureKeyPair,
    ) -> Result<Value, MLSError> {
        let jwt = self.mint_ds_auth_token(session_token, nsid).await?;
        let canonical_query = chat_wire::canonical_query_string(query_pairs);
        let url = if canonical_query.is_empty() {
            format!("{}/xrpc/{nsid}", self.ds_base())
        } else {
            format!("{}/xrpc/{nsid}?{canonical_query}", self.ds_base())
        };
        let headers = chat_wire::build_chat_read_headers(
            nsid,
            &canonical_query,
            &self.account_did,
            canonical_dev_id,
            signer,
            now_ms(),
        )?;
        let mut req = self.http.get(&url).bearer_auth(&jwt);
        for h in &headers {
            req = req.header(&h.name, &h.value);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| MLSError::Internal(format!("GET {nsid} failed: {e}")))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| MLSError::Internal(format!("read {nsid} body: {e}")))?
            .to_vec();
        if !(200..300).contains(&status) {
            return Err(MLSError::Internal(format!(
                "GET {nsid} returned HTTP {status}: {}",
                String::from_utf8_lossy(&bytes)
            )));
        }
        if bytes.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(MLSError::Internal(format!(
                "GET {nsid} returned empty response body"
            )));
        }
        let val: Value = serde_json::from_slice(&bytes)
            .map_err(|e| MLSError::Internal(format!("parse {nsid} JSON: {e}")))?;
        Ok(val)
    }

    pub(crate) async fn pds_post_json(
        &self,
        session_token: &str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), MLSError> {
        let url = format!("{}{path}", self.pds_base());
        let resp = self
            .http
            .post(&url)
            .bearer_auth(session_token)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| MLSError::Internal(format!("POST {path} failed: {e}")))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| MLSError::Internal(format!("read {path} body: {e}")))?
            .to_vec();
        Ok((status, bytes))
    }

    pub(crate) async fn resolve_did_document(
        &self,
        session_token: &str,
        did: &str,
    ) -> Result<Option<Vec<u8>>, MLSError> {
        let clean_did = did.split('#').next().unwrap_or(did);
        let pds_url = format!(
            "{}/xrpc/com.atproto.identity.resolveDid?did={}",
            self.pds_base(),
            chat_wire::urlencode_form_component(clean_did)
        );
        if let Ok(resp) = self
            .http
            .get(&pds_url)
            .bearer_auth(session_token)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(bytes) = resp.bytes().await {
                    if !bytes.is_empty() {
                        if let Ok(doc) = chat_wire::extract_did_doc_from_resolve_response(&bytes) {
                            return Ok(Some(doc));
                        }
                    }
                }
            }
        }
        if let Some(rest) = clean_did.strip_prefix("did:web:") {
            let decoded = rest.replace("%3A", ":").replace("%3a", ":");
            let wk_url = if clean_did == self.home_ds_did.split('#').next().unwrap_or("") {
                format!("{}/.well-known/did.json", self.ds_base())
            } else {
                let scheme = if decoded.starts_with("127.0.0.1") || decoded.starts_with("localhost")
                {
                    "http"
                } else {
                    "https"
                };
                format!("{scheme}://{decoded}/.well-known/did.json")
            };
            if let Ok(resp) = self.http.get(&wk_url).send().await {
                if resp.status().is_success() {
                    if let Ok(bytes) = resp.bytes().await {
                        if !bytes.is_empty() {
                            if let Ok(doc) =
                                chat_wire::extract_did_doc_from_resolve_response(&bytes)
                            {
                                return Ok(Some(doc));
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    pub(crate) async fn verify_peer_device_keys_via_pds(
        &self,
        session_token: &str,
        did: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, MLSError> {
        let pds_endpoint = self
            .resolve_did_document(session_token, did)
            .await?
            .and_then(|doc| chat_wire::extract_pds_endpoint_from_did_doc(&doc))
            .unwrap_or_else(|| self.pds_base());
        let list_url = format!(
            "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection=blue.catbird.chat.device&limit=100",
            pds_endpoint.trim_end_matches('/'),
            chat_wire::urlencode_form_component(did)
        );
        // Public record read on the DID's own PDS: a peer-controlled origin never receives this
        // session's bearer token.
        let resp =
            self.http.get(&list_url).send().await.map_err(|e| {
                MLSError::Internal(format!("I4 PDS listRecords({did}) failed: {e}"))
            })?;
        if !resp.status().is_success() {
            return Err(MLSError::insufficient_permissions(format!(
                "I4: PDS listRecords({did}) returned HTTP {}",
                resp.status().as_u16()
            )));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| MLSError::Internal(e.to_string()))?;
        let pairs = chat_wire::parse_pds_device_list_records(did, &body)?;
        if pairs.is_empty() {
            return Err(MLSError::insufficient_permissions(format!(
                "I4: zero valid blue.catbird.chat.device records on PDS for `{did}`"
            )));
        }
        let db = self.require_db_mls()?;
        let ts = now_ms();
        let cached_json = serde_json::to_string(
            &pairs
                .iter()
                .map(|(dev_id, pk)| {
                    json!({
                        "did": did,
                        "deviceId": dev_id,
                        "signaturePublicKey": STANDARD.encode(pk),
                    })
                })
                .collect::<Vec<_>>(),
        )
        .map_err(|e| MLSError::Internal(e.to_string()))?;
        db.write_tx(|tx| {
            tx.put_account_meta(&format!("authorized_device_keys:{did}"), &cached_json, ts)
        })?;
        Ok(pairs)
    }

    pub(crate) async fn resolve_peer_home_ds_did(
        &self,
        session_token: &str,
        did: &str,
    ) -> Option<String> {
        let pds_endpoint = self
            .resolve_did_document(session_token, did)
            .await
            .ok()
            .flatten()
            .and_then(|doc| chat_wire::extract_pds_endpoint_from_did_doc(&doc))
            .unwrap_or_else(|| self.pds_base());
        let get_url = format!(
            "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=blue.catbird.chat.declaration&rkey=self",
            pds_endpoint.trim_end_matches('/'),
            chat_wire::urlencode_form_component(did),
        );
        // Public record read on a peer-controlled PDS: never with this session's bearer token.
        let resp = self.http.get(&get_url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body = resp.bytes().await.ok()?;
        let val: Value = serde_json::from_slice(&body).ok()?;
        val.pointer("/value/deliveryService")
            .or_else(|| val.pointer("/value/homeDsDid"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    }

    async fn resolve_direct_request_coordinator(
        &self,
        session_token: &str,
        actor_did: &str,
        recipient_did: &str,
    ) -> Result<String, MLSError> {
        if actor_did == recipient_did {
            return Err(MLSError::Cryptography(
                "C33 participants must be distinct".into(),
            ));
        }
        let actor_home = self
            .resolve_peer_home_ds_did(session_token, actor_did)
            .await
            .ok_or_else(|| MLSError::Cryptography("C33 actor home DS unavailable".into()))?;
        let recipient_home = self
            .resolve_peer_home_ds_did(session_token, recipient_did)
            .await
            .ok_or_else(|| MLSError::Cryptography("C33 recipient home DS unavailable".into()))?;
        dr_transcript::derive_deterministic_coordinator(&actor_home, &recipient_home)
            .map_err(|e| MLSError::Cryptography(format!("C33 coordinator: {e}")))
    }

    pub(crate) async fn fetch_sequencer_receipt_key_sec1(
        &self,
        session_token: &str,
        sequencer_did: &str,
        kid_hint: &str,
    ) -> Result<Vec<u8>, MLSError> {
        let clean_did = sequencer_did.split('#').next().unwrap_or(sequencer_did);
        let cache_key = format!("receipt_pub_sec1_b64:{clean_did}:{kid_hint}");
        let db = self.require_db_mls()?;
        if let Some(cached_b64) = db.backend().get_account_meta(&cache_key)? {
            if let Ok(sec1) = STANDARD.decode(cached_b64.trim()) {
                if !sec1.is_empty() {
                    return Ok(sec1);
                }
            }
        }
        let doc_bytes = self
            .resolve_did_document(session_token, clean_did)
            .await?
            .ok_or_else(|| {
                MLSError::Cryptography(format!(
                    "I13: unable to resolve DID document for `{clean_did}`"
                ))
            })?;
        let sec1 = chat_wire::decode_p256_sec1_from_did_doc(&doc_bytes, clean_did, kid_hint)?;
        let ts = now_ms();
        db.write_tx(|tx| tx.put_account_meta(&cache_key, &STANDARD.encode(&sec1), ts))?;
        Ok(sec1)
    }

    pub(crate) fn load_or_build_conversation_coords(
        &self,
        conversation_id: &str,
    ) -> Result<Value, MLSError> {
        let db = self.require_db_mls()?;
        if let Some(raw) = db
            .backend()
            .get_account_meta(&format!("conversation_coords:{conversation_id}"))?
        {
            let parsed: Value =
                serde_json::from_str(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            return chat_wire::canonicalize_wire_coordinate(&parsed, Some(conversation_id));
        }
        let convo = db
            .backend()
            .get_conversation(conversation_id)?
            .ok_or_else(|| MLSError::group_not_found(format!("missing {conversation_id}")))?;
        let provider = db.openmls_provider()?;
        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
            .ok_or_else(|| MLSError::group_not_found("missing MlsGroup"))?;
        let (gch, ctag) = chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
        Ok(json!({
            "conversationId": conversation_id,
            "generation": convo.generation,
            "stateVersion": 0,
            "groupId": { "$bytes": STANDARD.encode(&convo.group_id) },
            "epoch": group.epoch().as_u64(),
            "groupContextHash": { "$bytes": STANDARD.encode(gch) },
            "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
            "lifecycle": "active",
        }))
    }

    pub(crate) async fn accept_direct_request_impl(
        &self,
        request_id: &str,
    ) -> Result<(), MLSError> {
        let db = self.require_db_mls()?;
        let ts = now_ms();
        let req_opt = db
            .backend()
            .list_requests(None)?
            .into_iter()
            .find(|r| r.request_id == request_id || r.conversation_id == request_id);
        if req_opt
            .as_ref()
            .is_some_and(|r| r.consent == C33_OPENING_UNAVAILABLE)
        {
            // No signed opening survives to accept against: terminal, never re-requested.
            return Err(MLSError::InvalidState("OpeningUnavailable".into()));
        }

        if let (Some((session_token, canonical_dev_id)), Some(req)) =
            (self.live_session(), req_opt.as_ref())
        {
            if let Some(pub_str) = db
                .backend()
                .get_account_meta(&format!("c33_publication_json:{}", req.conversation_id))?
            {
                let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
                let pub_val: Value = serde_json::from_str(&pub_str)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let p_body = pub_val.get("body").unwrap_or(&pub_val);
                let prior = p_body["next"].clone();
                let prior_sv = prior["stateVersion"].as_u64().unwrap_or(1);
                let mut next = prior.clone();
                next["stateVersion"] = json!(prior_sv + 1);
                let transition = uuid::Uuid::new_v4().to_string();
                let accept_body = json!({
                    "$type": "blue.catbird.chat.defs#directRequestAcceptanceBody",
                    "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPT\0",
                    "protocolVersion": "2",
                    "actorDid": self.account_did,
                    "actorDeviceId": canonical_dev_id,
                    "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public())),
                    "authGeneration": auth_gen,
                    "requestId": p_body["requestId"],
                    "transitionId": transition,
                    "prior": prior,
                    "next": next,
                    "invitationProvenance": {
                        "invitationTransitionId": p_body["requestId"],
                        "invitedByDid": p_body["actorDid"],
                        "invitedByDeviceId": p_body["actorDeviceId"],
                    },
                    "idempotencyKey": transition,
                    "signedAt": chat_wire::now_rfc3339_millis(),
                });
                let wrapper_bytes = chat_wire::sign_direct_request_wrapper(
                    DirectRequestKind::Accept,
                    accept_body,
                    &signer,
                )?;
                let mut wire = b"{\"directRequest\":".to_vec();
                wire.extend_from_slice(&wrapper_bytes);
                wire.push(b'}');
                let resp_bytes = self
                    .ds_post_json(&session_token, "blue.catbird.chat.acceptConversation", wire)
                    .await?;
                // The cursor moves only over a verified entry, and only when it is the next one.
                let (accepted_seq, next_coords) = self
                    .verify_direct_request_acceptance(
                        &session_token,
                        &req.conversation_id,
                        &resp_bytes,
                        signer.public(),
                        p_body,
                    )
                    .await?;
                let coords_str = serde_json::to_string(&next_coords)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                db.write_tx(|tx| {
                    if let Some(mut c) = tx.get_conversation(&req.conversation_id)? {
                        if accepted_seq == c.last_seq.saturating_add(1) {
                            c.last_seq = accepted_seq;
                        }
                        c.updated_at_ms = ts;
                        tx.upsert_conversation(&c)?;
                    }
                    tx.put_account_meta(
                        &format!("conversation_coords:{}", req.conversation_id),
                        &coords_str,
                        ts,
                    )
                })?;
                self.archive_accepted_opening_messages(&req.conversation_id)
                    .await?;
            }
        }

        db.write_tx(|tx| {
            let mut rows = tx.list_requests(None)?;
            if let Some(req) = rows
                .iter_mut()
                .find(|r| r.request_id == request_id || r.conversation_id == request_id)
            {
                req.consent = "accepted".to_string();
                req.updated_at_ms = ts;
                tx.upsert_request(req)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// The `acceptConversation` answer's `acceptanceProof`, verified
    /// ([`Self::verify_acceptance_proof`]) over this device's signed acceptance of
    /// `publication`'s request. Returns that entry's seq and the receipt's next coordinates.
    async fn verify_direct_request_acceptance(
        &self,
        session_token: &str,
        conversation_id: &str,
        response: &[u8],
        own_signature_key: &[u8],
        publication: &Value,
    ) -> Result<(i64, Value), MLSError> {
        let response: Value = serde_json::from_slice(response)?;
        let proof = response
            .get("acceptanceProof")
            .ok_or_else(|| acceptance_refused("missing acceptanceProof"))?;
        let verified = self
            .verify_acceptance_proof(session_token, conversation_id, proof, own_signature_key)
            .await?;
        let accepted = &verified["entry"]["signedRequest"]["body"];
        if accepted["requestId"] != publication["requestId"]
            || accepted["prior"] != publication["next"]
        {
            return Err(acceptance_refused("proof is for another request"));
        }
        let seq = verified["entry"]["seq"]
            .as_i64()
            .ok_or_else(|| acceptance_refused("entry seq"))?;
        let next = chat_wire::canonicalize_wire_coordinate(
            &verified["receipt"]["body"]["next"],
            Some(conversation_id),
        )?;
        Ok((seq, next))
    }

    /// `proof` (`{entry, receipt}`) verified: the conversation coordinator's acceptance-commit
    /// receipt, under the method its `keyId` names, over the exact sequenced entry carrying an
    /// acceptance signed under `accepter_key`. Returns the verified proof.
    async fn verify_acceptance_proof(
        &self,
        session_token: &str,
        conversation_id: &str,
        proof: &Value,
        accepter_key: &[u8],
    ) -> Result<Value, MLSError> {
        let authority = self
            .require_db_mls()?
            .backend()
            .get_conversation(conversation_id)?
            .ok_or_else(|| MLSError::group_not_found(conversation_id))?
            .sequencer_did;
        let document = self
            .resolve_did_document(session_token, &authority)
            .await?
            .ok_or_else(|| acceptance_refused("coordinator document unavailable"))?;
        let method = proof
            .pointer("/receipt/body/keyId")
            .and_then(Value::as_str)
            .ok_or_else(|| acceptance_refused("receipt keyId"))?;
        let key = dr_transcript::resolve_direct_request_receipt_key_for_authority(
            &authority, &document, method,
        )
        .map_err(acceptance_refused)?;
        dr_transcript::verify_received_direct_request_acceptance_proof_for_authority(
            &authority,
            &serde_json::to_vec(proof)?,
            &key,
            accepter_key,
        )
        .map_err(acceptance_refused)
    }

    /// Contract A: a `directRequestAcceptanceEntry` met in sync, verified before any effect. It
    /// must be exactly that entry for `cid` at `entry_seq`; its signer a current leaf of the
    /// local group ([`Self::control_signer_key`]); its acceptance signed under that leaf's key
    /// for this conversation, changing only `stateVersion`, by the local request's recipient for
    /// that request; and a `sequencerReceipt` it carries the coordinator's acceptance proof over
    /// it. Returns the coordinates it moves the conversation to.
    #[allow(clippy::too_many_arguments)]
    async fn verify_synced_direct_request_acceptance(
        &self,
        session_token: &str,
        cid: &str,
        entry: &Value,
        entry_seq: i64,
        peer_map: &BTreeMap<String, Vec<(String, Vec<u8>)>>,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<Value, MLSError> {
        let mut presented = entry.clone();
        let fields = presented
            .as_object_mut()
            .ok_or_else(|| acceptance_refused("entry is not an object"))?;
        let receipt = fields.remove("sequencerReceipt");
        if fields.remove("$type")
            != Some(json!("blue.catbird.chat.defs#directRequestAcceptanceEntry"))
        {
            return Err(acceptance_refused("not a directRequestAcceptanceEntry"));
        }
        let entry = dr_transcript::normalize_read_presentation(
            &serde_json::to_vec(&presented)?,
            "directRequestAcceptanceEntry",
            false,
        )
        .map_err(acceptance_refused)?;
        if entry["conversationId"] != cid || entry["seq"] != entry_seq {
            return Err(acceptance_refused(
                "entry is for another conversation or seq",
            ));
        }
        let signed = &entry["signedRequest"];
        let key = self.control_signer_key(
            cid,
            signed["body"]["actorDid"].as_str(),
            signed["body"]["actorDeviceId"].as_str(),
            peer_map,
            canonical_dev_id,
            signer,
        )?;
        let acceptance = dr_transcript::verify_signed_request(
            DirectRequestKind::Accept,
            &serde_json::to_vec(signed)?,
            &key,
        )
        .map_err(acceptance_refused)?;
        let body = acceptance.body();
        let mut next = body["prior"].clone();
        next["stateVersion"] = body["prior"]["stateVersion"]
            .as_u64()
            .and_then(|version| version.checked_add(1))
            .into();
        if body["prior"]["conversationId"] != cid || body["next"] != next {
            return Err(acceptance_refused(
                "not this conversation's next policy version",
            ));
        }
        let request = self
            .require_db_mls()?
            .backend()
            .list_requests(None)?
            .into_iter()
            .find(|r| r.conversation_id == cid);
        if request.is_some_and(|r| {
            body["actorDid"] != r.recipient_did.as_str()
                || body["requestId"] != r.request_id.as_str()
        }) {
            return Err(acceptance_refused(
                "not the recipient's acceptance of this request",
            ));
        }
        if let Some(receipt) = receipt {
            let proof = json!({ "entry": entry, "receipt": receipt });
            let verified = self
                .verify_acceptance_proof(session_token, cid, &proof, &key)
                .await?;
            next = verified["receipt"]["body"]["next"].clone();
        }
        chat_wire::canonicalize_wire_coordinate(&next, Some(cid))
    }

    /// `cid`'s local MLS group, the authority control entries verify against. A missing
    /// conversation or group is an error.
    fn control_group(&self, cid: &str) -> Result<MlsGroup, MLSError> {
        let db = self.require_db_mls()?;
        let convo = db.backend().get_conversation(cid)?.ok_or_else(|| {
            MLSError::Cryptography("control entry has no local conversation".into())
        })?;
        let provider = db.openmls_provider()?;
        MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
            .map_err(|e| MLSError::Internal(format!("load control authority: {e:?}")))?
            .ok_or_else(|| MLSError::Cryptography("control entry has no active MLS group".into()))
    }

    /// Whether `did` holds a current leaf of `cid`'s local MLS group.
    fn is_member_did(&self, cid: &str, did: &str) -> Result<bool, MLSError> {
        Ok(self.control_group(cid)?.members().any(|member| {
            chat_wire::parse_scoped_credential_did_device(member.credential.serialized_content())
                .is_ok_and(|(leaf_did, _)| leaf_did == did)
        }))
    }

    /// The key of the current leaf of `cid`'s local MLS group that `actor_did`/`actor_dev` name,
    /// when it is that device's PDS-authorized key or this device's own: the membership rule of
    /// native `verify_participant_control_body`. A missing conversation or group is an error.
    fn control_signer_key(
        &self,
        cid: &str,
        actor_did: Option<&str>,
        actor_dev: Option<&str>,
        peer_map: &BTreeMap<String, Vec<(String, Vec<u8>)>>,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<Vec<u8>, MLSError> {
        for member in self.control_group(cid)?.members() {
            let (did, device) = chat_wire::parse_scoped_credential_did_device(
                member.credential.serialized_content(),
            )?;
            if actor_did != Some(did.as_str()) || actor_dev != Some(device.as_str()) {
                continue;
            }
            let key = member.signature_key.as_slice();
            let own =
                did == self.account_did && device == canonical_dev_id && key == signer.public();
            if own
                || peer_map.get(&did).is_some_and(|keys| {
                    keys.iter()
                        .any(|(id, authorized)| *id == device && authorized.as_slice() == key)
                })
            {
                return Ok(key.to_vec());
            }
        }
        Err(MLSError::Cryptography(
            "I4: control entry signer is not an authorized active participant device".into(),
        ))
    }

    pub(crate) async fn archive_accepted_opening_messages(
        &self,
        conversation_id: &str,
    ) -> Result<(), MLSError> {
        let db = self.require_db_mls()?;
        let ts = now_ms();
        let enqueued = db.write_tx(|tx| {
            let key = format!("c33_pending_opening:{conversation_id}");
            let Some(staged_str) = tx.get_account_meta(&key)? else {
                return Ok(false);
            };
            if staged_str.is_empty() || staged_str == "archived" {
                return Ok(false);
            }
            let staged: QueuedLabyrinthArchivePayload = serde_json::from_str(&staged_str)
                .map_err(|e| MLSError::Internal(format!("parse c33_pending_opening: {e}")))?;
            let payload_bytes = serde_json::to_vec(&staged)
                .map_err(|e| MLSError::Internal(format!("serialize c33_pending_opening: {e}")))?;
            tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                item_id: staged.message_id.clone(),
                conversation_id: conversation_id.to_string(),
                group_id_hex: staged.group_id_hex.clone(),
                seq: staged.seq,
                payload_bytes,
                created_at_ms: ts,
            })?;
            tx.put_account_meta(&key, "archived", ts)?;
            let mut reqs = tx.list_requests(None)?;
            for r in &mut reqs {
                if r.conversation_id == conversation_id {
                    r.first_message_archived = true;
                    r.updated_at_ms = ts;
                    tx.upsert_request(r)?;
                }
            }
            Ok(true)
        })?;
        let _ = enqueued;
        Ok(())
    }

    pub(crate) async fn decline_direct_request_impl(
        &self,
        request_id: &str,
    ) -> Result<(), MLSError> {
        let db = self.require_db_mls()?;
        let ts = now_ms();
        let req_opt = db
            .backend()
            .list_requests(None)?
            .into_iter()
            .find(|r| r.request_id == request_id || r.conversation_id == request_id);

        if let (Some((session_token, canonical_dev_id)), Some(req)) =
            (self.live_session(), req_opt.as_ref())
        {
            // Journaled before HTTP: a lost answer is replayed byte for byte by the next sync.
            let _ = self
                .close_conversation_live(
                    &session_token,
                    &canonical_dev_id,
                    &req.conversation_id,
                    "direct",
                )
                .await;
        }

        db.write_tx(|tx| {
            let mut rows = tx.list_requests(None)?;
            if let Some(req) = rows
                .iter_mut()
                .find(|r| r.request_id == request_id || r.conversation_id == request_id)
            {
                req.consent = "declined".to_string();
                req.updated_at_ms = ts;
                tx.upsert_request(req)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    pub(crate) async fn acknowledge_entries_up_to_impl(
        &self,
        conversation_id: &str,
        up_to_seq: i64,
    ) -> Result<(), MLSError> {
        let cid = conversation_id.trim();
        if cid.is_empty() || up_to_seq < 1 {
            return Ok(());
        }
        let db = self.require_db_mls()?;
        let ts = now_ms();
        let generation = db.write_tx(|tx| {
            let meta_key = format!("acked_seq:{cid}");
            let prev = tx
                .get_account_meta(&meta_key)?
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            let next_wm = prev.max(up_to_seq);
            tx.put_account_meta(&meta_key, &next_wm.to_string(), ts)?;
            Ok(tx
                .get_conversation(cid)?
                .map(|c| c.generation.max(0))
                .unwrap_or(0))
        })?;
        if let Some((session_token, canonical_dev_id)) = self.live_session() {
            if uuid::Uuid::parse_str(cid)
                .ok()
                .filter(|u| u.get_version_num() == 4)
                .is_some()
            {
                let (signer, auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
                let ack_bytes = chat_wire::build_acknowledge_entries_request(
                    cid,
                    generation,
                    &canonical_dev_id,
                    auth_gen,
                    up_to_seq,
                    &signer,
                )?;
                self.ds_post_json(
                    &session_token,
                    "blue.catbird.chat.acknowledgeEntries",
                    ack_bytes,
                )
                .await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn sync_impl(&self) -> Result<u32, MLSError> {
        let Some((session_token, canonical_dev_id)) = self.live_session() else {
            return Ok(0);
        };
        let Ok((signer, auth_gen)) = self.load_enrolled_signer_and_auth_gen() else {
            return Ok(0);
        };
        let mut applied = 0u32;

        let (conv_applied, inventory_session_id) = self
            .sync_conversations_list(&session_token, &canonical_dev_id, &signer, auth_gen)
            .await?;
        applied = applied.saturating_add(conv_applied);
        applied = applied.saturating_add(
            self.sync_pending_welcomes(
                &session_token,
                &canonical_dev_id,
                &signer,
                auth_gen,
                inventory_session_id.as_deref(),
            )
            .await?,
        );
        applied = applied.saturating_add(
            self.fulfill_leaf_recovery_inbox(
                &session_token,
                &canonical_dev_id,
                &signer,
                auth_gen,
                inventory_session_id.as_deref(),
            )
            .await?,
        );

        let convos = self
            .require_db_mls()?
            .backend()
            .list_conversations(None, 200)?;
        for convo in convos {
            // A journaled close is replayed before the conversation's entries: once mls-ds wipes
            // the conversation, its lost answer never arrives as an echo.
            if self
                .complete_pending_close(&session_token, &convo.conversation_id)
                .await?
            {
                applied = applied.saturating_add(1);
                continue;
            }
            applied = applied.saturating_add(
                self.sync_conversation_entries(
                    &session_token,
                    &canonical_dev_id,
                    &signer,
                    auth_gen,
                    &convo,
                )
                .await?,
            );
        }

        let _ = self.flush_labyrinth_queue_impl().await;
        Ok(applied)
    }

    async fn sync_conversations_list(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_gen: i64,
    ) -> Result<(u32, Option<String>), MLSError> {
        let resp = self
            .ds_signed_get(
                session_token,
                canonical_dev_id,
                "blue.catbird.chat.getConversations",
                &[
                    ("actorDeviceId", canonical_dev_id),
                    ("limit", "100"),
                    ("supportedProtocolVersions", "1"),
                    ("supportedProtocolVersions", "2"),
                ],
                signer,
            )
            .await?;
        let inventory_session_id = resp
            .get("inventorySessionId")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let Some(items) = resp
            .get("items")
            .or_else(|| resp.get("conversations"))
            .or_else(|| resp.get("states"))
            .and_then(|v| v.as_array())
        else {
            return Ok((0, inventory_session_id));
        };
        let db = self.require_db_mls()?;
        let mut count = 0u32;
        for item in items {
            let state = item.get("state").unwrap_or(item);
            let coords = state.get("coordinates").unwrap_or(&Value::Null);
            let Some(cid) = coords
                .get("conversationId")
                .or_else(|| state.get("conversationId"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let kind = state
                .get("conversationKind")
                .or_else(|| state.get("kind"))
                .and_then(|v| v.as_str())
                .unwrap_or("group");

            let has_local = db.backend().get_conversation(cid)?.is_some();

            if kind == "direct" && !has_local {
                // A pruned opening's terminal state is recorded once; it is never re-fetched.
                if db
                    .backend()
                    .list_requests(Some(C33_OPENING_UNAVAILABLE))?
                    .iter()
                    .any(|r| r.conversation_id == cid)
                {
                    continue;
                }
                if self
                    .import_incoming_c33_direct_request(
                        session_token,
                        canonical_dev_id,
                        signer,
                        cid,
                    )
                    .await?
                {
                    count = count.saturating_add(1);
                }
                continue;
            }
            if kind == "group" {
                if let Some(participants) = state.get("participants").and_then(|v| v.as_array()) {
                    if let Some(me) = participants.iter().find(|p| {
                        p.get("userDid").and_then(|u| u.as_str()) == Some(&self.account_did)
                            && p.get("status").and_then(|s| s.as_str()) == Some("pending")
                    }) {
                        if let Some(prov) = me.get("invitationProvenance") {
                            if let Ok(prior) =
                                chat_wire::canonicalize_wire_coordinate(coords, Some(cid))
                            {
                                let prior_sv = prior
                                    .get("stateVersion")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(0);
                                let mut next = prior.clone();
                                next["stateVersion"] = json!(prior_sv + 1);
                                let tid = uuid::Uuid::new_v4().to_string();
                                let body = json!({
                                    "$type": "blue.catbird.chat.defs#participantAcceptanceBody",
                                    "signatureDomain": "CATBIRD-CHAT-ACCEPT\0",
                                    "transitionId": tid,
                                    "recoveryRequestId": uuid::Uuid::new_v4().to_string(),
                                    "idempotencyKey": tid,
                                    "actorDid": self.account_did,
                                    "actorDeviceId": canonical_dev_id,
                                    "keyId": derive_key_id(signer.public()),
                                    "authGeneration": auth_gen,
                                    "signedAt": chat_wire::now_rfc3339_millis(),
                                    "prior": prior,
                                    "next": next,
                                    "invitationProvenance": prov,
                                });
                                let _ = self
                                    .submit_signed_chat_op(
                                        session_token,
                                        canonical_dev_id,
                                        Some(auth_gen),
                                        CanonicalOperation::AcceptConversation,
                                        &body,
                                        signer,
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }
        }
        Ok((count, inventory_session_id))
    }

    async fn import_incoming_c33_direct_request(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        cid: &str,
    ) -> Result<bool, MLSError> {
        let entries_val = self
            .ds_signed_get(
                session_token,
                canonical_dev_id,
                "blue.catbird.chat.getEntries",
                &[
                    ("actorDeviceId", canonical_dev_id),
                    ("afterSeq", "0"),
                    ("conversationId", cid),
                    ("limit", "100"),
                ],
                signer,
            )
            .await?;
        let Some(entries) = entries_val.get("entries").and_then(|v| v.as_array()) else {
            return Ok(false);
        };
        let Some(raw_dr_entry) = entries.iter().find(|e| {
            e.get("$type").and_then(|t| t.as_str())
                == Some("blue.catbird.chat.defs#directRequestEntry")
                || e.get("entryKind").and_then(|t| t.as_str()) == Some("directRequest")
                || e.get("directRequest").is_some()
        }) else {
            return Ok(false);
        };
        if raw_dr_entry["payloadPruned"] == true
            || (raw_dr_entry.get("directRequest").is_none()
                && raw_dr_entry["$type"] == "blue.catbird.chat.defs#directRequestEntry"
                && catbird_mls::orchestrator::direct_request_bootstrap::is_pruned_opening_entry(
                    raw_dr_entry,
                ))
        {
            return self
                .record_pruned_c33_opening(session_token, cid, raw_dr_entry)
                .await;
        }

        let pub_wrapper = raw_dr_entry
            .get("signedRequest")
            .or_else(|| raw_dr_entry.get("directRequest"))
            .unwrap_or(raw_dr_entry);
        let p_body = pub_wrapper.get("body").unwrap_or(pub_wrapper);
        let sender_did = p_body
            .get("actorDid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MLSError::Cryptography("C33 entry missing actorDid".into()))?;
        let sender_device_id = p_body
            .get("actorDeviceId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MLSError::Cryptography("C33 entry missing actorDeviceId".into()))?;
        let request_id = p_body
            .get("requestId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MLSError::Cryptography("C33 entry missing requestId".into()))?;
        let first_message_id = p_body
            .get("firstMessageId")
            .and_then(|v| v.as_str())
            .unwrap_or(request_id);

        let mut peer_map: BTreeMap<String, Vec<(String, Vec<u8>)>> = BTreeMap::new();
        peer_map.insert(
            sender_did.to_string(),
            self.verify_peer_device_keys_via_pds(session_token, sender_did)
                .await?,
        );
        if let Ok(own_pairs) = self
            .verify_peer_device_keys_via_pds(session_token, &self.account_did)
            .await
        {
            peer_map.insert(self.account_did.clone(), own_pairs);
        }
        let candidate_key = chat_wire::json_bytes(
            &p_body["artifacts"]["metadataSnapshot"]["authorProof"]["signaturePublicKey"],
        )?;
        chat_wire::verify_leaf_pds_map_i4(
            format!("{sender_did}#{sender_device_id}").as_bytes(),
            &candidate_key,
            &peer_map,
        )?;

        let pub_norm = dr_transcript::normalize_read_presentation(
            &serde_json::to_vec(pub_wrapper).map_err(|e| MLSError::Internal(e.to_string()))?,
            "signedDirectRequestPublication",
            false,
        )
        .map_err(|e| MLSError::Cryptography(format!("normalize C33 publication: {e}")))?;
        let pub_norm_bytes =
            serde_json::to_vec(&pub_norm).map_err(|e| MLSError::Internal(e.to_string()))?;
        let verified_pub = dr_transcript::verify_received_signed_request(
            DirectRequestKind::Publish,
            &pub_norm_bytes,
            &candidate_key,
        )
        .map_err(|e| MLSError::Cryptography(format!("verify C33 publication: {e}")))?;

        let vp = verified_pub.body();
        if vp["conversationId"].as_str() != Some(cid)
            || vp["next"]["conversationId"].as_str() != Some(cid)
            || vp["actorDid"].as_str() != Some(sender_did)
            || vp["actorDeviceId"].as_str() != Some(sender_device_id)
            || (vp["actorDid"].as_str() != Some(self.account_did.as_str())
                && vp["recipientDid"].as_str() != Some(self.account_did.as_str()))
        {
            return Err(MLSError::Cryptography(
                "C33 publication conversation/participant mismatch".into(),
            ));
        }
        let recipient_did = vp["recipientDid"]
            .as_str()
            .ok_or_else(|| MLSError::Cryptography("C33 missing recipientDid".into()))?;
        // A sibling's own opening (another of this account's devices published it, and mls-ds
        // made this device a Welcome recipient) holds the recipient's leaves too.
        let is_incoming = sender_did != self.account_did;
        if !peer_map.contains_key(recipient_did) {
            let pairs = self
                .verify_peer_device_keys_via_pds(session_token, recipient_did)
                .await?;
            peer_map.insert(recipient_did.to_owned(), pairs);
        }
        let effective_seq_did = self
            .resolve_direct_request_coordinator(session_token, sender_did, recipient_did)
            .await?;
        let ctx_val = json!({
            "protocolVersion": "2",
            "requestId": vp["requestId"],
            "firstMessageId": vp["firstMessageId"],
            "conversationId": vp["conversationId"],
            "origin": vp["origin"],
            "actorDid": vp["actorDid"],
            "actorDeviceId": vp["actorDeviceId"],
            "actorKeyId": vp["keyId"],
            "recipientDid": vp["recipientDid"],
            "preparationDigest": vp["preparationDigest"],
        });
        let context_json =
            serde_json::to_vec(&ctx_val).map_err(|e| MLSError::Internal(e.to_string()))?;
        let context_hash = dr_transcript::direct_request_context_hash(&context_json)
            .map_err(|e| MLSError::Cryptography(format!("C33 context_hash: {e}")))?;
        let expected_ctx_hash = chat_wire::json_bytes(&vp["contextHash"])?;
        if expected_ctx_hash.as_slice() != context_hash {
            return Err(MLSError::Cryptography("C33 contextHash mismatch".into()));
        }

        let artifact = &vp["artifacts"];
        let deliveries_arr = artifact["welcome"]["deliveries"]
            .as_array()
            .ok_or_else(|| MLSError::invalid_input("C33 welcome missing deliveries"))?;
        let mut local_pkg_ref: Option<Vec<u8>> = None;
        let mut refs: Vec<Vec<u8>> = Vec::with_capacity(deliveries_arr.len());
        for d in deliveries_arr {
            let r = chat_wire::json_bytes(&d["provenance"]["keyPackageRef"])?;
            if d.get("recipientDid").and_then(|v| v.as_str()) == Some(self.account_did.as_str())
                && d.get("recipientDeviceId").and_then(|v| v.as_str()) == Some(canonical_dev_id)
            {
                local_pkg_ref = Some(r.clone());
            }
            refs.push(r);
        }
        let import_until = chrono::DateTime::parse_from_rfc3339(
            vp["importUntil"]
                .as_str()
                .ok_or_else(|| MLSError::invalid_input("C33 missing importUntil"))?,
        )
        .map_err(|e| MLSError::invalid_input(format!("C33 importUntil: {e}")))?
        .timestamp()
        .max(0) as u64;
        let opening_commitment: [u8; 32] = chat_wire::json_bytes(&vp["archiveCommitment"])?
            .try_into()
            .map_err(|_| MLSError::Cryptography("C33 archiveCommitment must be 32 bytes".into()))?;
        let original_sender_attestation = OriginalSenderArchiveAttestationEnvelope::from_aad_json(
            vp.get("originalSenderAttestation").ok_or_else(|| {
                MLSError::Cryptography("C33 publication missing original sender attestation".into())
            })?,
        )?;
        if original_sender_attestation.sender_did != sender_did
            || original_sender_attestation.sender_device_id != sender_device_id
        {
            return Err(MLSError::Cryptography(
                "C33 original sender attestation attribution mismatch".into(),
            ));
        }
        original_sender_attestation.verify(cid, first_message_id, &opening_commitment)?;

        let bootstrap = DirectRequestBootstrap {
            context_json,
            context_hash,
            coordinates: vp["next"].clone(),
            import_until,
            expected_package_refs: refs.clone(),
            genesis_group_info: chat_wire::json_bytes(&artifact["genesisGroupInfo"]["bytes"])?,
            add_commit: chat_wire::json_bytes(&artifact["addCommit"]["bytes"])?,
            final_group_info: chat_wire::json_bytes(&artifact["finalGroupInfo"]["bytes"])?,
            welcome: chat_wire::json_bytes(&artifact["welcome"]["opaqueWelcome"])?,
            metadata_nonce: chat_wire::json_bytes(&artifact["metadataSnapshot"]["nonce"])?,
            metadata_ciphertext: chat_wire::json_bytes(
                &artifact["metadataSnapshot"]["ciphertext"],
            )?,
            initial_ciphertext: chat_wire::json_bytes(&artifact["initialCiphertext"])?,
            archive_commitment: opening_commitment,
            original_sender_attestation,
            opening: None,
        };
        let publication_receipt = raw_dr_entry.get("publicationReceipt").ok_or_else(|| {
            MLSError::Cryptography("C33 entry missing signed publicationReceipt".into())
        })?;
        let publication_receipt = dr_transcript::normalize_read_presentation(
            &serde_json::to_vec(publication_receipt)
                .map_err(|e| MLSError::Internal(e.to_string()))?,
            "signedDirectRequestReceipt",
            true,
        )
        .map_err(|e| MLSError::Cryptography(format!("C33 publication receipt: {e}")))?;
        let authority_doc = self
            .resolve_did_document(session_token, &effective_seq_did)
            .await?
            .ok_or_else(|| {
                MLSError::Cryptography("C33 receipt authority document unavailable".into())
            })?;
        let receipt_method = publication_receipt
            .pointer("/body/keyId")
            .and_then(Value::as_str)
            .ok_or_else(|| MLSError::Cryptography("C33 outcome missing receipt keyId".into()))?;
        let receipt_key = dr_transcript::resolve_direct_request_receipt_key_for_authority(
            &effective_seq_did,
            &authority_doc,
            receipt_method,
        )
        .map_err(|e| MLSError::Cryptography(format!("C33 receipt key: {e}")))?;
        let entry_receipt = raw_dr_entry.get("sequencerReceipt").ok_or_else(|| {
            MLSError::Cryptography("C33 entry missing I13 sequencerReceipt".into())
        })?;
        // The exact retained method that signed this opening, never a fixed generation (G3).
        let sequencer_receipt_key = chat_wire::decode_p256_sec1_from_did_doc(
            &authority_doc,
            &effective_seq_did,
            chat_wire::sequencer_receipt_kid(&effective_seq_did, entry_receipt)?,
        )?;
        let (entry_seq, _, dr_rcpt_json) =
            catbird_mls::orchestrator::direct_request_bootstrap::verify_opening_receipt(
                &bootstrap,
                entry_receipt,
                &effective_seq_did,
                &sequencer_receipt_key,
            )?;
        let (_, _, outcome_rcpt_json) =
            catbird_mls::orchestrator::direct_request_bootstrap::verify_opening_receipt(
                &bootstrap,
                &publication_receipt["body"]["receipt"]["sequencerReceipt"],
                &effective_seq_did,
                &sequencer_receipt_key,
            )?;
        let entry_seq = i64::try_from(entry_seq)
            .map_err(|_| MLSError::Cryptography("C33 entry sequence overflow".into()))?;
        if raw_dr_entry["seq"].as_i64() != Some(entry_seq)
            || dr_rcpt_json != outcome_rcpt_json
            || raw_dr_entry["entryId"].as_str() != Some(first_message_id)
        {
            return Err(MLSError::Cryptography(
                "C33 entry and outcome receipt mismatch".into(),
            ));
        }
        let welcome_input = DirectRequestWelcomeInput {
            bootstrap: bootstrap.clone(),
            publication_request: pub_norm_bytes.clone(),
            actor_signature_public_key: candidate_key,
            preparation_request_digest: chat_wire::json_bytes(&vp["preparationRequestDigest"])?
                .try_into()
                .map_err(|_| {
                    MLSError::Cryptography("C33 preparation digest must be 32 bytes".into())
                })?,
            local_identity: format!("{}#{}", self.account_did, canonical_dev_id).into_bytes(),
            local_package_ref: local_pkg_ref.ok_or_else(|| {
                MLSError::Cryptography("C33 Welcome was not addressed to this device".into())
            })?,
            published_receipt: serde_json::to_vec(&publication_receipt)
                .map_err(|e| MLSError::Internal(e.to_string()))?,
            receipt_authority_did: effective_seq_did.clone(),
            receipt_authority_key: receipt_key,
            sequencer_receipt_authority_key: sequencer_receipt_key,
        };
        require_browser_welcome_receipt_inputs(
            &welcome_input.preparation_request_digest,
            &welcome_input.published_receipt,
            &welcome_input.receipt_authority_did,
            &welcome_input.receipt_authority_key,
        )?;
        catbird_mls::orchestrator::direct_request_shared_crypto::validate_request_welcome_receipt(
            &welcome_input,
        )?;
        let ts = now_ms();
        let pub_norm_str = String::from_utf8(pub_norm_bytes)
            .map_err(|e| MLSError::Internal(format!("C33 pub UTF-8: {e}")))?;
        let coords_canon = chat_wire::canonicalize_wire_coordinate(&vp["next"], Some(cid))?;
        let coords_str =
            serde_json::to_string(&coords_canon).map_err(|e| MLSError::Internal(e.to_string()))?;

        let db = self.require_db_mls()?;
        db.write_tx(|tx| {
            let provider = OpenMlsKvProvider::new(catbird_mls::storage::OpenMlsKvStorage::new(tx))?;
            let mls_welcome = MlsMessageIn::tls_deserialize_exact(&bootstrap.welcome)
                .map_err(|e| MLSError::Cryptography(format!("deserialize C33 Welcome: {e:?}")))?;
            let MlsMessageBodyIn::Welcome(welcome) = mls_welcome.extract() else {
                return Err(MLSError::Cryptography(
                    "C33 opaqueWelcome is not an MLS Welcome".into(),
                ));
            };
            let staged =
                StagedWelcome::new_from_welcome(&provider, &build_join_config(), welcome, None)
                    .map_err(|e| MLSError::Cryptography(format!("stage C33 Welcome: {e:?}")))?;
            let sender_member = staged
                .welcome_sender()
                .map_err(|e| MLSError::Cryptography(format!("welcome_sender: {e:?}")))?;
            chat_wire::verify_leaf_pds_map_i4(
                sender_member.credential().serialized_content(),
                sender_member.signature_key().as_slice(),
                &peer_map,
            )?;
            let mut group = staged
                .into_group(&provider)
                .map_err(|e| MLSError::Cryptography(format!("into_group C33: {e:?}")))?;
            for m in group.members() {
                chat_wire::verify_leaf_pds_map_i4(
                    m.credential.serialized_content(),
                    m.signature_key.as_slice(),
                    &peer_map,
                )?;
            }
            let group_id = group.group_id().as_slice().to_vec();
            let epoch = group.epoch().as_u64() as i64;
            let (intro_json, opening) =
                match decrypt_introduction_with_provider(&provider, &mut group, &welcome_input)? {
                    DirectRequestIntroductionResult::Ready { plaintext, opening } => {
                        let intro_val =
                            dr_transcript::decode_direct_request_introduction(&plaintext)
                                .map_err(|e| MLSError::Cryptography(format!("decode C33: {e}")))?;
                        let txt = intro_val.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        (json!({ "text": txt }).to_string(), Some(opening))
                    }
                    DirectRequestIntroductionResult::Unavailable { code } => (
                        json!({ "text": format!("[unavailable:{code}]") }).to_string(),
                        None,
                    ),
                };
            let space_uri = Some(format!(
                "at://{effective_seq_did}/space/blue.catbird.labyrinth.conversation/{cid}-0"
            ));
            tx.upsert_conversation(&ConversationRow {
                conversation_id: cid.to_string(),
                group_id: group_id.clone(),
                generation: 0,
                epoch,
                last_seq: entry_seq,
                sequencer_did: effective_seq_did.clone(),
                space_uri: space_uri.clone(),
                title: None,
                unread_count: i64::from(is_incoming),
                updated_at_ms: ts,
            })?;
            tx.put_account_meta(&format!("conversation_coords:{cid}"), &coords_str, ts)?;
            tx.put_account_meta(&format!("c33_publication_json:{cid}"), &pub_norm_str, ts)?;
            tx.upsert_request(&RequestRow {
                request_id: request_id.to_string(),
                conversation_id: cid.to_string(),
                sender_did: sender_did.to_string(),
                recipient_did: recipient_did.to_string(),
                consent: if is_incoming {
                    "incomingPending".to_string()
                } else {
                    "outgoingPending".to_string()
                },
                first_message_id: Some(first_message_id.to_string()),
                first_message_archived: false,
                payload_json: intro_json.clone(),
                expires_at_ms: (import_until as i64).saturating_mul(1000),
                updated_at_ms: ts,
            })?;
            tx.insert_message(&MessageRow {
                message_id: first_message_id.to_string(),
                conversation_id: cid.to_string(),
                group_id: group_id.clone(),
                epoch,
                seq: entry_seq,
                sender_did: sender_did.to_string(),
                sender_device_id: sender_device_id.to_string(),
                plaintext_json: intro_json.clone(),
                created_at_ms: ts,
                is_own: !is_incoming,
            })?;
            // A sibling's own opening is its sending device's archive duty: never staged here.
            if let Some(opening) = opening.filter(|_| is_incoming) {
                let staged_opening = QueuedLabyrinthArchivePayload {
                    version: 1,
                    message_id: first_message_id.to_string(),
                    conversation_id: cid.to_string(),
                    group_id_hex: hex::encode(&group_id),
                    epoch,
                    seq: entry_seq,
                    expected_member_dids: crate::wasm_client_mutations::member_root_dids(&group)?,
                    sender_did: sender_did.to_string(),
                    sender_device_id: sender_device_id.to_string(),
                    sequencer_did: effective_seq_did,
                    space_uri,
                    plaintext_json: intro_json.clone(),
                    labyrinth_frame_json: String::from_utf8(opening.canonical_payload_bytes)
                        .map_err(|e| {
                            MLSError::Cryptography(format!("C33 canonical opening frame: {e}"))
                        })?,
                    mls_ciphertext_b64: STANDARD.encode(&bootstrap.initial_ciphertext),
                    frame_nonce_b64: Some(STANDARD.encode(opening.frame_nonce)),
                    sequencer_receipt_json: Some(dr_rcpt_json),
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
                tx.put_labyrinth_state(
                    &format!("native.message:{cid}:{first_message_id}"),
                    &serde_json::to_vec(&staged_opening)
                        .map_err(|e| MLSError::Internal(e.to_string()))?,
                    ts,
                )?;
                tx.put_account_meta(
                    &format!("c33_pending_opening:{cid}"),
                    &serde_json::to_string(&staged_opening)
                        .map_err(|e| MLSError::Internal(e.to_string()))?,
                    ts,
                )?;
            }
            Ok(())
        })?;
        Ok(true)
    }

    /// An opening pruned before this device imported it keeps only its receipts: no Welcome,
    /// preview or acceptance can follow. Its participants come from signed evidence alone: the
    /// coordinator's outcome names the sender, and this account, which never imported the
    /// opening, is the recipient. Their homes select the coordinator; no inventory field does.
    async fn record_pruned_c33_opening(
        &self,
        session_token: &str,
        cid: &str,
        entry: &Value,
    ) -> Result<bool, MLSError> {
        let missing = |what: &str| MLSError::Cryptography(format!("C33 pruned opening: {what}"));
        // Read unverified only to select the coordinator, whose verified outcome must then name
        // the same sender.
        let sender_did = entry
            .pointer("/publicationReceipt/body/receipt/actorDid")
            .and_then(Value::as_str)
            .ok_or_else(|| missing("outcome actorDid"))?;
        if sender_did == self.account_did {
            // ponytail: re-read every sync. Nothing signed names the recipient of an own opening
            // another device published, so it is never recorded; keep a local skip marker if
            // such openings become common.
            return Ok(false);
        }
        let recipient_did = self.account_did.as_str();
        let authority = self
            .resolve_direct_request_coordinator(session_token, sender_did, recipient_did)
            .await?;
        let document = self
            .resolve_did_document(session_token, &authority)
            .await?
            .ok_or_else(|| missing("receipt authority document"))?;
        let receipt =
            catbird_mls::orchestrator::direct_request_bootstrap::verify_pruned_opening_entry(
                entry, cid, &authority, &document,
            )?;
        if receipt["actorDid"].as_str() != Some(sender_did) {
            return Err(missing("receipt sender binding"));
        }
        let row = RequestRow {
            request_id: receipt["requestId"]
                .as_str()
                .ok_or_else(|| missing("requestId"))?
                .to_string(),
            conversation_id: cid.to_string(),
            sender_did: sender_did.to_string(),
            recipient_did: recipient_did.to_string(),
            consent: C33_OPENING_UNAVAILABLE.to_string(),
            first_message_id: receipt["firstMessageId"].as_str().map(str::to_owned),
            first_message_archived: false,
            payload_json: json!({ "unavailable": "OpeningPruned" }).to_string(),
            expires_at_ms: 0,
            updated_at_ms: now_ms(),
        };
        self.require_db_mls()?
            .write_tx(|tx| tx.upsert_request(&row))?;
        Ok(false)
    }

    async fn acquire_inventory_session_id_wasm(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<Option<String>, MLSError> {
        let resp = self
            .ds_signed_get(
                session_token,
                canonical_dev_id,
                "blue.catbird.chat.getConversations",
                &[
                    ("actorDeviceId", canonical_dev_id),
                    ("limit", "1"),
                    ("supportedProtocolVersions", "1"),
                    ("supportedProtocolVersions", "2"),
                ],
                signer,
            )
            .await?;
        Ok(resp
            .get("inventorySessionId")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned))
    }

    async fn sync_pending_welcomes(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_gen: i64,
        inventory_session_id: Option<&str>,
    ) -> Result<u32, MLSError> {
        let owned_sid = if inventory_session_id.is_none() {
            self.acquire_inventory_session_id_wasm(session_token, canonical_dev_id, signer)
                .await?
        } else {
            None
        };
        let mut query_pairs: Vec<(&str, &str)> = vec![("actorDeviceId", canonical_dev_id)];
        if let Some(sid) = inventory_session_id.or(owned_sid.as_deref()) {
            query_pairs.push(("inventorySessionId", sid));
        }
        query_pairs.extend_from_slice(&[
            ("limit", "100"),
            ("supportedProtocolVersions", "1"),
            ("supportedProtocolVersions", "2"),
        ]);
        let resp = self
            .ds_signed_get(
                session_token,
                canonical_dev_id,
                "blue.catbird.chat.getPendingWelcomes",
                &query_pairs,
                signer,
            )
            .await?;
        let Some(welcomes) = resp
            .get("items")
            .or_else(|| resp.get("welcomes"))
            .or_else(|| resp.get("deliveries"))
            .and_then(|v| v.as_array())
        else {
            return Ok(0);
        };
        let db = self.require_db_mls()?;
        let mut joined = 0u32;

        for raw_item in welcomes {
            let w_env = raw_item
                .get("welcome")
                .filter(|v| v.is_object())
                .unwrap_or(raw_item);
            let welcome_id = w_env
                .get("welcomeId")
                .or_else(|| raw_item.get("welcomeId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let coords = w_env
                .get("coordinates")
                .or_else(|| raw_item.get("coordinates"))
                .unwrap_or(&Value::Null);
            let Some(cid) = coords
                .get("conversationId")
                .or_else(|| w_env.get("conversationId"))
                .or_else(|| raw_item.get("conversationId"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let transition_seq = w_env
                .get("transitionSeq")
                .or_else(|| raw_item.get("transitionSeq"))
                .or_else(|| w_env.get("seq"))
                .and_then(|v| v.as_i64())
                .unwrap_or(1);

            let is_dr_welcome = w_env.get("$type").and_then(|t| t.as_str())
                == Some("blue.catbird.chat.defs#directRequestWelcomeView");
            if db.backend().get_conversation(cid)?.is_some() {
                let has_pending_request = db
                    .backend()
                    .list_requests(None)?
                    .iter()
                    .any(|r| r.conversation_id == cid && r.consent != "accepted");
                let status_str = w_env.get("status").and_then(|v| v.as_str()).unwrap_or("");
                if !welcome_id.is_empty()
                    && status_str != "acknowledged"
                    && !is_dr_welcome
                    && !has_pending_request
                {
                    let coords_canon = chat_wire::canonicalize_wire_coordinate(coords, Some(cid))
                        .or_else(|_| self.load_or_build_conversation_coords(cid))?;
                    let ack_body = json!({
                        "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
                        "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
                        "welcomeId": welcome_id,
                        "transitionSeq": transition_seq,
                        "coordinates": coords_canon,
                        "actorDid": self.account_did,
                        "actorDeviceId": canonical_dev_id,
                        "keyId": derive_key_id(signer.public()),
                        "authGeneration": auth_gen,
                        "idempotencyKey": uuid::Uuid::new_v4().to_string(),
                        "signedAt": chat_wire::now_rfc3339_millis(),
                    });
                    let _ = self
                        .submit_signed_chat_op(
                            session_token,
                            canonical_dev_id,
                            Some(auth_gen),
                            CanonicalOperation::AcknowledgeWelcome,
                            &ack_body,
                            signer,
                        )
                        .await;
                }
                continue;
            }

            let sequencer_did = w_env
                .get("sequencerDid")
                .or_else(|| raw_item.get("sequencerDid"))
                .and_then(|v| v.as_str())
                .unwrap_or(&self.home_ds_did);
            let Ok(welcome_bytes) = w_env
                .get("opaqueWelcome")
                .or_else(|| raw_item.get("opaqueWelcome"))
                .or_else(|| w_env.get("welcome").and_then(|w| w.get("opaqueWelcome")))
                .or_else(|| w_env.get("bytes"))
                .ok_or_else(|| MLSError::invalid_input("missing opaqueWelcome"))
                .and_then(chat_wire::json_bytes)
            else {
                continue;
            };
            // A direct-request Welcome joins only through the checked `C33` import (signed
            // publication, coordinator outcome and `I13` receipt), never here: the DS's direct
            // view is refused and not acknowledged.
            if is_dr_welcome {
                continue;
            }
            let next = match self
                .join_recovery_welcome(
                    session_token,
                    canonical_dev_id,
                    signer,
                    raw_item,
                    cid,
                    transition_seq,
                    &welcome_bytes,
                    sequencer_did,
                )
                .await
            {
                Ok(next) => next,
                Err(error) => {
                    // Neither joined nor acknowledged: a later sync retries it.
                    tracing::warn!(conversation_id = cid, %error, "Welcome not joined");
                    continue;
                }
            };

            if !welcome_id.is_empty() {
                let ack_body = json!({
                    "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
                    "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\0",
                    "welcomeId": welcome_id,
                    "transitionSeq": transition_seq,
                    "coordinates": next,
                    "actorDid": self.account_did,
                    "actorDeviceId": canonical_dev_id,
                    "keyId": derive_key_id(signer.public()),
                    "authGeneration": auth_gen,
                    "idempotencyKey": uuid::Uuid::new_v4().to_string(),
                    "signedAt": chat_wire::now_rfc3339_millis(),
                });
                let _ = self
                    .submit_signed_chat_op(
                        session_token,
                        canonical_dev_id,
                        Some(auth_gen),
                        CanonicalOperation::AcknowledgeWelcome,
                        &ack_body,
                        signer,
                    )
                    .await;
            }
            joined = joined.saturating_add(1);
        }
        Ok(joined)
    }

    /// Join `cid` from a generic Welcome only as the verified Welcome of the signed
    /// `leafRecoveryFulfillmentEntry` sequenced at its `transition_seq` (mls-ds makes the added
    /// device a recipient of that entry), so a direct request's Welcome, which has none, never
    /// joins here. Staged without consuming it, the Welcome's group must hold the fulfiller
    /// `actorDid#actorDeviceId` under its PDS-authorized key; the body verifies under that key
    /// and must deliver exactly these Welcome bytes to this device under the request whose
    /// `addLeafByRecovery` adds it. Joined, every leaf is PDS-authorized (`I4`) and the body's
    /// signed `next` must name the group: it becomes the conversation's coordinates, with the
    /// cursor at `transition_seq`. Returns that `next`, for the acknowledgement.
    #[allow(clippy::too_many_arguments)]
    async fn join_recovery_welcome(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        view: &Value,
        cid: &str,
        transition_seq: i64,
        welcome_bytes: &[u8],
        sequencer_did: &str,
    ) -> Result<Value, MLSError> {
        let refused = |what: &str| MLSError::Cryptography(format!("recovery Welcome: {what}"));
        let after = transition_seq.saturating_sub(1).to_string();
        let page = self
            .ds_signed_get(
                session_token,
                canonical_dev_id,
                "blue.catbird.chat.getEntries",
                &[
                    ("actorDeviceId", canonical_dev_id),
                    ("afterSeq", &after),
                    ("conversationId", cid),
                    ("limit", "1"),
                ],
                signer,
            )
            .await?;
        let entry = page["entries"]
            .get(0)
            .filter(|entry| {
                entry["seq"] == transition_seq
                    && chat_wire::signed_entry_kind(entry)
                        .is_ok_and(|kind| kind == SignedMutationKind::LeafRecoveryFulfillment)
            })
            .ok_or_else(|| refused("no leafRecoveryFulfillmentEntry at its transitionSeq"))?;
        let signed = &entry["signedRequest"];
        let fulfiller_did = signed["body"]["actorDid"].as_str().unwrap_or_default();
        let fulfiller_device = signed["body"]["actorDeviceId"].as_str().unwrap_or_default();
        let fulfiller_leaf = format!("{fulfiller_did}#{fulfiller_device}").into_bytes();

        let mut candidate_dids: BTreeMap<String, ()> = BTreeMap::new();
        chat_wire::collect_dids_from_json(view, &mut candidate_dids);
        chat_wire::collect_dids_from_json(entry, &mut candidate_dids);
        candidate_dids.insert(self.account_did.clone(), ());
        let db = self.require_db_mls()?;
        // Staged over `KvWriteOverlay`: OpenMLS's one-time KeyPackageBundle deletion never
        // reaches `openmls_kv` before the fulfillment verifies.
        let fulfiller_key = {
            let overlay = KvWriteOverlay::new(db.backend());
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
            let staged = stage_welcome(&provider, welcome_bytes)?;
            let mut fulfiller_key = None;
            for member in staged.members() {
                let identity = member.credential.serialized_content();
                if let Ok((did, _)) = chat_wire::parse_scoped_credential_did_device(identity) {
                    candidate_dids.insert(did, ());
                }
                if identity == fulfiller_leaf.as_slice() {
                    fulfiller_key = Some(member.signature_key);
                }
            }
            fulfiller_key.ok_or_else(|| refused("the fulfiller is no member of its group"))?
        };
        let mut peer_map: BTreeMap<String, Vec<(String, Vec<u8>)>> = BTreeMap::new();
        for did in candidate_dids.keys() {
            let pairs = self
                .verify_peer_device_keys_via_pds(session_token, did)
                .await?;
            peer_map.insert(did.clone(), pairs);
        }
        if chat_wire::authorized_device_key(fulfiller_did, fulfiller_device, &peer_map)
            != Some(fulfiller_key.as_slice())
        {
            return Err(refused(
                "the fulfiller's leaf key is not its authorized key",
            ));
        }
        let body = chat_wire::verify_signed_mutation_body(
            signed,
            SignedMutationKind::LeafRecoveryFulfillment,
            &fulfiller_key,
        )?;
        let next = chat_wire::fulfillment_welcome_next(
            &body,
            cid,
            welcome_bytes,
            &self.account_did,
            canonical_dev_id,
        )?;
        let generation = next["generation"].as_i64().unwrap_or_default();
        let ts = now_ms();
        db.write_tx(|tx| {
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
            let staged = stage_welcome(&provider, welcome_bytes)?;
            let sender = staged
                .welcome_sender()
                .map_err(|e| MLSError::Cryptography(format!("welcome_sender: {e:?}")))?;
            chat_wire::verify_leaf_pds_map_i4(
                sender.credential().serialized_content(),
                sender.signature_key().as_slice(),
                &peer_map,
            )?;
            let mut group = staged
                .into_group(&provider)
                .map_err(|e| MLSError::Cryptography(format!("into_group: {e:?}")))?;
            for m in group.members() {
                chat_wire::verify_leaf_pds_map_i4(
                    m.credential.serialized_content(),
                    m.signature_key.as_slice(),
                    &peer_map,
                )?;
            }
            chat_wire::require_coordinate_names_group(&next, &group, &provider)?;
            let snapshot = &body["metadataSnapshot"];
            let mut title = None;
            if let Some((m_epoch, m_ver, meta)) =
                chat_wire::try_decrypt_group_metadata_snapshot(&mut group, &provider, snapshot)
            {
                let row = chat_wire::group_metadata_row_from_v1(cid, m_ver, m_epoch, &meta, ts)?;
                title = row.title.clone();
                tx.upsert_group_metadata(&row)?;
            }
            tx.put_account_meta(
                &format!("metadata_snapshot_json:{cid}"),
                &snapshot.to_string(),
                ts,
            )?;
            tx.upsert_conversation(&ConversationRow {
                conversation_id: cid.to_string(),
                group_id: group.group_id().as_slice().to_vec(),
                generation,
                epoch: group.epoch().as_u64() as i64,
                last_seq: transition_seq,
                sequencer_did: sequencer_did.to_string(),
                space_uri: Some(format!(
                    "at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{cid}-{generation}"
                )),
                title,
                unread_count: 0,
                updated_at_ms: ts,
            })?;
            tx.put_account_meta(&format!("conversation_coords:{cid}"), &next.to_string(), ts)
        })?;
        Ok(next)
    }

    pub(crate) async fn fulfill_leaf_recovery_inbox(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_gen: i64,
        inventory_session_id: Option<&str>,
    ) -> Result<u32, MLSError> {
        let owned_sid = if inventory_session_id.is_none() {
            self.acquire_inventory_session_id_wasm(session_token, canonical_dev_id, signer)
                .await?
        } else {
            None
        };
        let mut query_pairs: Vec<(&str, &str)> = vec![("actorDeviceId", canonical_dev_id)];
        if let Some(sid) = inventory_session_id.or(owned_sid.as_deref()) {
            query_pairs.push(("inventorySessionId", sid));
        }
        query_pairs.extend_from_slice(&[
            ("limit", "100"),
            ("supportedProtocolVersions", "1"),
            ("supportedProtocolVersions", "2"),
        ]);
        let resp = self
            .ds_signed_get(
                session_token,
                canonical_dev_id,
                "blue.catbird.chat.getLeafRecoveryInbox",
                &query_pairs,
                signer,
            )
            .await?;
        let Some(requests) = resp
            .get("items")
            .or_else(|| resp.get("requests"))
            .or_else(|| resp.get("inbox"))
            .and_then(|v| v.as_array())
        else {
            return Ok(0);
        };
        let db = self.require_db_mls()?;
        let mut fulfilled = 0u32;

        for req in requests {
            let Some(cid) = req
                .get("conversationId")
                .or_else(|| {
                    req.get("boundCoordinate")
                        .and_then(|c| c.get("conversationId"))
                })
                .or_else(|| req.get("coordinates").and_then(|c| c.get("conversationId")))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let Ok(convo_uuid) = uuid::Uuid::parse_str(cid) else {
                continue;
            };
            let Some(recovery_request_id) = req
                .get("recoveryRequestId")
                .or_else(|| req.get("requestId"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let Some(target_did) = req
                .get("requesterDid")
                .or_else(|| req.get("userDid"))
                .or_else(|| req.get("targetDid"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let Some(target_device_id) = req
                .get("requesterDeviceId")
                .or_else(|| req.get("deviceId"))
                .or_else(|| req.get("targetDeviceId"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let kp_obj = req
                .get("reservation")
                .and_then(|r| r.get("keyPackage"))
                .or_else(|| req.get("keyPackage"))
                .unwrap_or(req);
            let (Ok(kp_bytes), Ok(kp_ref)) = (
                chat_wire::json_bytes(&kp_obj["bytes"]),
                chat_wire::json_bytes(&kp_obj["keyPackageRef"]),
            ) else {
                continue;
            };

            let target_pairs = self
                .verify_peer_device_keys_via_pds(session_token, target_did)
                .await?;
            let mut peer_map = BTreeMap::new();
            peer_map.insert(target_did.to_string(), target_pairs);

            let MlsMessageBodyIn::KeyPackage(kp_in) =
                MlsMessageIn::tls_deserialize_exact(&kp_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("deserialize recovery KP: {e:?}")))?
                    .extract()
            else {
                continue;
            };
            let unverified_cred = kp_in.unverified_credential();
            chat_wire::verify_leaf_pds_map_i4(
                unverified_cred.credential.serialized_content(),
                unverified_cred.signature_key.as_slice(),
                &peer_map,
            )?;

            let prior_coords = if let Some(c) = req
                .get("boundCoordinate")
                .or_else(|| req.get("coordinates"))
                .or_else(|| req.get("prior"))
            {
                chat_wire::canonicalize_wire_coordinate(c, Some(cid))?
            } else {
                self.load_or_build_conversation_coords(cid)?
            };
            let prior_sv = prior_coords["stateVersion"].as_i64().unwrap_or(0);
            let prior_epoch = prior_coords["epoch"].as_u64().unwrap_or(0);
            let prior_gen = prior_coords["generation"].as_i64().unwrap_or(0);
            let prior_gch = chat_wire::json_bytes(&prior_coords["groupContextHash"])?;
            let prior_ctag = chat_wire::json_bytes(&prior_coords["confirmationTag"])?;
            let transition_uuid = uuid::Uuid::new_v4();
            let transition_id = transition_uuid.to_string();
            let welcome_id = uuid::Uuid::new_v4().to_string();

            // Stage `add_members` + `merge_pending_commit` over `KvWriteOverlay` before HTTP (`I6`)
            // so an HTTP 409 / network failure never forks local OpenMLS epoch state!
            let Some(convo) = db.backend().get_conversation(cid)? else {
                continue;
            };
            let meta_row = db.backend().get_group_metadata(cid)?;
            let overlay = KvWriteOverlay::new(db.backend());
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay))?;
            let validated_kp = kp_in
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| MLSError::Cryptography(format!("validate recovery KP: {e:?}")))?;
            let Some(mut group) =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                    .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
            else {
                continue;
            };
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
                .map_err(|e| MLSError::Cryptography(format!("canonical_commit_aad_bytes: {e}")))?;
            group.set_aad(commit_aad_bytes);
            let (commit_out, welcome_out, _) = group
                .add_members(&provider, signer, &[validated_kp])
                .map_err(|e| MLSError::Cryptography(format!("recovery add_members: {e:?}")))?;
            group
                .merge_pending_commit(&provider)
                .map_err(|e| MLSError::Cryptography(format!("merge recovery commit: {e:?}")))?;
            group.set_aad(Vec::new());
            let commit_bytes = commit_out
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("serialize commit: {e:?}")))?;
            let welcome_bytes = welcome_out
                .tls_serialize_detached()
                .map_err(|e| MLSError::Internal(format!("serialize welcome: {e:?}")))?;
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
            .map_err(|e| MLSError::Cryptography(format!("derive metadata key: {e}")))?;
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
                canonical_dev_id,
                auth_gen,
                signer.public(),
                &title_s,
                &desc_s,
                avatar_opt,
            )?;
            drop(provider);
            let kv_batch = overlay.into_batch();
            let group_id = convo.group_id;

            let next_coords = json!({
                "conversationId": cid,
                "generation": prior_gen,
                "stateVersion": prior_sv + 1,
                "groupId": { "$bytes": STANDARD.encode(&group_id) },
                "epoch": next_epoch,
                "groupContextHash": { "$bytes": STANDARD.encode(next_gch) },
                "confirmationTag": { "$bytes": STANDARD.encode(&next_ctag) },
                "lifecycle": "active",
            });
            let fulfill_body = json!({
                "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
                "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0",
                "transitionId": transition_id,
                "recoveryRequestId": recovery_request_id,
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
                    "participantChanges": [],
                    "leafChanges": [{
                        "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                        "userDid": target_did,
                        "deviceId": target_device_id,
                        "recoveryRequestId": recovery_request_id,
                        "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                    }],
                    "leafRecoveryRequestId": recovery_request_id,
                    "welcomeBundle": {
                        "welcomeId": welcome_id,
                        "framing": "mlsMessage",
                        "contentType": "welcome",
                        "opaqueWelcome": { "$bytes": STANDARD.encode(&welcome_bytes) },
                        "sha256": STANDARD.encode(Sha256::digest(&welcome_bytes)),
                        "deliveries": [{
                            "recipientDid": target_did,
                            "recipientDeviceId": target_device_id,
                            "provenance": {
                                "recoveryRequestId": recovery_request_id,
                                "keyPackageRef": { "$bytes": STANDARD.encode(&kp_ref) },
                            }
                        }]
                    }
                },
                "commit": {
                    "framing": "mlsMessage",
                    "contentType": "publicMessageCommit",
                    "bytes": { "$bytes": STANDARD.encode(&commit_bytes) },
                    "sha256": STANDARD.encode(Sha256::digest(&commit_bytes)),
                },
                "metadataSnapshot": carried_snap,
            });
            // Journaled before HTTP; a lost answer leaves the staged epoch to this Commit's own
            // echo in sync.
            let pending = chat_wire::PendingCommitTransition {
                conversation_id: cid.to_string(),
                transition_id,
                commit_sha256: Sha256::digest(&commit_bytes).into(),
                prior: prior_coords,
                next: chat_wire::canonicalize_wire_coordinate(&next_coords, None)?,
                kv_batch,
                removed_participant_did: None,
            };
            match self
                .submit_own_commit(
                    session_token,
                    canonical_dev_id,
                    auth_gen,
                    signer,
                    &fulfill_body,
                    pending,
                )
                .await
            {
                Ok(_) => fulfilled = fulfilled.saturating_add(1),
                // A competing device fulfilled first or the epoch moved: this attempt is void.
                Err(e) if is_terminal_refusal(&e) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(fulfilled)
    }

    /// The sequencer's key for the exact retained method that signed `receipt` (`I13`, G3):
    /// the method its `kid` names, never a fixed generation. Resolved outside `write_tx` (`I6`).
    pub(crate) async fn receipt_key_for(
        &self,
        session_token: &str,
        sequencer_did: &str,
        receipt: &Value,
    ) -> Result<Vec<u8>, MLSError> {
        let kid = chat_wire::sequencer_receipt_kid(sequencer_did, receipt)?;
        self.fetch_sequencer_receipt_key_sec1(session_token, sequencer_did, kid)
            .await
    }

    /// Whether `cid` is closed: its terminal marker, or retired coordinates.
    pub(crate) fn is_conversation_closed(&self, cid: &str) -> Result<bool, MLSError> {
        let backend = self.require_db_mls()?.backend();
        if backend
            .get_account_meta(&format!("conversation_closed:{cid}"))?
            .is_some_and(|marker| marker == "true")
        {
            return Ok(true);
        }
        Ok(backend
            .get_account_meta(&format!("conversation_coords:{cid}"))?
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .is_some_and(|coords| coords["lifecycle"] == "superseded"))
    }

    /// Terminal close, in one transaction: erase `cid`'s MLS group and every journal holding
    /// its staged epoch keys or plaintext (own Commit, close, application sends, staged opening,
    /// queued archive copies), write the terminal marker and, when given, the verified `retired`
    /// coordinate and the cursor onto `terminal_seq`. Messages and receipt-bound archive
    /// evidence stay.
    pub(crate) fn apply_terminal_close(
        &self,
        cid: &str,
        retired: Option<&Value>,
        terminal_seq: Option<i64>,
    ) -> Result<(), MLSError> {
        let ts = now_ms();
        self.require_db_mls()?.write_tx(|tx| {
            if let Some(mut convo) = tx.get_conversation(cid)? {
                let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
                if let Some(mut group) =
                    MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                        .map_err(|e| MLSError::Internal(format!("load closing group: {e:?}")))?
                {
                    group
                        .delete(provider.storage())
                        .map_err(|e| MLSError::Internal(format!("delete closing group: {e:?}")))?;
                }
                if let Some(seq) = terminal_seq {
                    convo.last_seq = convo.last_seq.max(seq);
                }
                convo.updated_at_ms = ts;
                tx.upsert_conversation(&convo)?;
            }
            prune_commit_transitions(tx, cid, 0, 0, true)?;
            for key in [
                conversation_close_key(cid),
                format!("c33_pending_opening:{cid}"),
            ] {
                tx.delete_account_meta(&key)?;
            }
            let erase = |sql: &str, param: &str| {
                tx.exec_with_text_params(sql, &[(1, param)])
                    .map_err(|e| MLSError::Internal(format!("erase closed conversation: {e}")))
            };
            erase(
                "DELETE FROM account_meta WHERE substr(key, 1, length(?1)) = ?1",
                &pending_send_key(cid, ""),
            )?;
            erase(
                "DELETE FROM labyrinth_queue WHERE conversation_id = ?1",
                cid,
            )?;
            if let Some(retired) = retired {
                tx.put_account_meta(
                    &format!("conversation_coords:{cid}"),
                    &serde_json::to_string(retired)?,
                    ts,
                )?;
            }
            tx.put_account_meta(&format!("conversation_closed:{cid}"), "true", ts)
        })
    }

    /// Effects of a verified account deletion: its local messages and queued archive duty go,
    /// and the recorded deletion keeps its purged mailbox out of archive rosters.
    fn apply_verified_account_deletion(
        &self,
        cid: &str,
        deleted_did: &str,
        seq: i64,
        ts: i64,
    ) -> Result<(), MLSError> {
        self.require_db_mls()?.write_tx(|tx| {
            tx.put_labyrinth_state(
                &chat_wire::account_deletion_key(cid, deleted_did),
                seq.to_string().as_bytes(),
                ts,
            )?;
            tx.purge_messages_from_sender(None, deleted_did)?;
            tx.purge_labyrinth_queue_from_sender(deleted_did)
        })
    }

    /// A stored message re-presented by a sequenced entry. Its `I13` receipt must verify against
    /// the retained frame, nonce and original-sender attestation exactly as at first delivery,
    /// and the display row must still be the plaintext that evidence authenticated, before the
    /// cursor moves.
    fn finish_received_archive_evidence(
        &self,
        cid: &str,
        message_id: &str,
        entry_seq: i64,
        entry_id: &str,
        receipt: &Value,
        receipt_key: &[u8],
    ) -> Result<(), MLSError> {
        let ts = now_ms();
        self.require_db_mls()?.write_tx(|tx| {
            let mut convo = tx
                .get_conversation(cid)?
                .ok_or_else(|| MLSError::group_not_found(cid))?;
            let message = tx.get_message(message_id)?.ok_or_else(|| {
                MLSError::Cryptography(
                    "cached message disappeared before receipt validation".into(),
                )
            })?;
            let raw = tx
                .get_labyrinth_state(&format!("native.message:{cid}:{message_id}"))?
                .ok_or_else(|| {
                    MLSError::Cryptography(
                        "cached message has no retained authenticated archive frame".into(),
                    )
                })?;
            let evidence: QueuedLabyrinthArchivePayload = serde_json::from_slice(&raw)
                .map_err(|e| MLSError::Cryptography(format!("cached archive evidence: {e}")))?;
            let prior_receipt = evidence.sequencer_receipt_json.as_deref().ok_or_else(|| {
                MLSError::Cryptography("cached message has no verified I13 receipt".into())
            })?;
            let prior: chat_wire::StoredArchivedReceipt = serde_json::from_str(prior_receipt)
                .map_err(|e| MLSError::Cryptography(format!("cached archive receipt: {e}")))?;
            serde_json::from_str::<MLSMessagePayload>(&evidence.labyrinth_frame_json)
                .map_err(|e| MLSError::Cryptography(format!("cached archive payload: {e}")))?;
            let nonce: [u8; 32] = evidence
                .frame_nonce_b64
                .as_deref()
                .and_then(|nonce| STANDARD.decode(nonce).ok())
                .and_then(|nonce| nonce.try_into().ok())
                .ok_or_else(|| {
                    MLSError::Cryptography("cached archive nonce must be 32 bytes".into())
                })?;
            let commitment = labyrinth_protocol::receipt::compute_archive_commitment(
                &nonce,
                evidence.labyrinth_frame_json.as_bytes(),
            );
            let attestation: OriginalSenderArchiveAttestationEnvelope = serde_json::from_str(
                evidence
                    .original_sender_attestation_json
                    .as_deref()
                    .ok_or_else(|| {
                        MLSError::Cryptography(
                            "cached message missing original sender attestation".into(),
                        )
                    })?,
            )
            .map_err(|e| {
                MLSError::Cryptography(format!("cached original sender attestation: {e}"))
            })?;
            let (seq, generation, stored_receipt) =
                chat_wire::parse_and_verify_i13_sequencer_receipt(
                    receipt,
                    receipt_key,
                    &convo.sequencer_did,
                    cid,
                    &message.group_id,
                    prior.epoch,
                    entry_id,
                    message_id,
                    &commitment,
                    Some(&attestation),
                )?;
            if evidence.message_id != message_id
                || evidence.conversation_id != cid
                // An imported or replaced row never inherits another frame's receipt.
                || evidence.plaintext_json != message.plaintext_json
                || message.conversation_id != cid
                || message.group_id != convo.group_id
                || attestation.sender_did != message.sender_did
                || attestation.sender_device_id != message.sender_device_id
                || generation != convo.generation.max(0) as u64
                || i64::try_from(seq).ok() != Some(entry_seq)
                || stored_receipt != prior_receipt
            {
                return Err(MLSError::Cryptography(
                    "I13: cached archive proof binding mismatch".into(),
                ));
            }
            convo.last_seq = convo.last_seq.max(entry_seq);
            convo.updated_at_ms = ts;
            tx.upsert_conversation(&convo)
        })
    }

    /// Record a sequenced application entry this device can never decrypt: evidence and a system
    /// gap row at its seq, so the timeline shows the gap and sync moves on to later Commits.
    /// First, in the same transaction, the entry authenticates without its plaintext: its signed
    /// sender is an active, PDS-authorized leaf of the group (`I4`); the signed AAD carries that
    /// leaf's archive commitment and original-sender attestation; and the `I13` receipt of the
    /// method its `kid` names sequenced exactly this entry at `seq`. A stored message keeps its
    /// row. No archive or witness copy exists (no plaintext).
    fn record_undecryptable_entry(
        &self,
        evidence: &chat_wire::UndecryptableEntryEvidence,
        signed_aad: &Value,
        receipt: &Value,
        receipt_key: &[u8],
        peer_map: &BTreeMap<String, Vec<(String, Vec<u8>)>>,
    ) -> Result<(), MLSError> {
        let cid = evidence.conversation_id.as_str();
        let aad = canonical_application_aad_bytes(signed_aad).map_err(|error| {
            MLSError::Cryptography(format!("invalid signed application AAD: {error}"))
        })?;
        let (commitment, attestation) =
            verify_application_aad_archive_evidence(&aad, cid, &evidence.message_id)?;
        if attestation.sender_did != evidence.sender_did
            || attestation.sender_device_id != evidence.sender_device_id
        {
            return Err(MLSError::Cryptography(
                "undecryptable entry attestation differs from its signed sender".into(),
            ));
        }
        let epoch = u64::try_from(evidence.epoch)
            .map_err(|_| MLSError::Cryptography("undecryptable entry epoch is negative".into()))?;
        self.require_db_mls()?.write_tx(|tx| {
            let mut convo = tx
                .get_conversation(cid)?
                .ok_or_else(|| MLSError::group_not_found(cid))?;
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
                .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                .ok_or_else(|| MLSError::group_not_found(cid))?;
            let member = group
                .members()
                .find(|member| {
                    chat_wire::parse_scoped_credential_did_device(
                        member.credential.serialized_content(),
                    )
                    .is_ok_and(|(did, device)| {
                        did == evidence.sender_did && device == evidence.sender_device_id
                    })
                })
                .ok_or_else(|| {
                    MLSError::Cryptography(
                        "I4: undecryptable entry sender is not an active group leaf".into(),
                    )
                })?;
            chat_wire::verify_leaf_pds_map_i4(
                member.credential.serialized_content(),
                member.signature_key.as_slice(),
                peer_map,
            )?;
            if attestation.sender_transport_public_key.as_slice() != member.signature_key.as_slice()
            {
                return Err(MLSError::Cryptography(
                    "original sender attestation differs from the sender's MLS leaf".into(),
                ));
            }
            let (seq, generation, _) = chat_wire::parse_and_verify_i13_sequencer_receipt(
                receipt,
                receipt_key,
                &convo.sequencer_did,
                cid,
                &convo.group_id,
                epoch,
                &evidence.entry_id,
                &evidence.message_id,
                &commitment,
                Some(&attestation),
            )?;
            if i64::try_from(seq).ok() != Some(evidence.seq) {
                return Err(MLSError::Cryptography(format!(
                    "I13: receipt seq {seq} != entry seq {}",
                    evidence.seq
                )));
            }
            if generation != convo.generation.max(0) as u64 {
                return Err(MLSError::Cryptography(
                    "I13: receipt generation mismatch".into(),
                ));
            }
            if tx.get_message(&evidence.message_id)?.is_none() {
                let is_own = evidence.sender_did == self.account_did;
                tx.insert_message(&evidence.gap_row(&convo.group_id, is_own)?)?;
                tx.put_labyrinth_state(
                    &chat_wire::undecryptable_evidence_key(cid, &evidence.message_id),
                    &serde_json::to_vec(evidence)?,
                    evidence.recorded_at_ms,
                )?;
                if !is_own {
                    convo.unread_count = convo.unread_count.saturating_add(1);
                }
            }
            convo.last_seq = convo.last_seq.max(evidence.seq);
            convo.updated_at_ms = evidence.recorded_at_ms;
            tx.upsert_conversation(&convo)
        })
    }

    /// The PDS-authorized key of exactly `(did, device)`, reading `did`'s device records once.
    async fn pds_device_key(
        &self,
        session_token: &str,
        peer_map: &mut BTreeMap<String, Vec<(String, Vec<u8>)>>,
        did: &str,
        device: &str,
    ) -> Result<Vec<u8>, MLSError> {
        if !peer_map.contains_key(did) {
            let pairs = self
                .verify_peer_device_keys_via_pds(session_token, did)
                .await?;
            peer_map.insert(did.to_owned(), pairs);
        }
        chat_wire::authorized_device_key(did, device, peer_map)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                MLSError::Cryptography(format!("I4: {did}#{device} is not a PDS-authorized device"))
            })
    }

    /// The invitation chain: `invitee` holds a pending invitation to `pass.cid` that verifies.
    /// The `creationEntry` or `policyEntry` inviting it (the one whose signed `transitionId` an
    /// acceptance's `provenance` names, else any naming `invitee` as pending) is sought among
    /// this pass's entries before `before_seq`, then by paging `getEntries` from seq 0. Found,
    /// it must verify under the PDS-authorized key of exactly its signing device and name
    /// `invitee`'s pending row, with exactly `provenance` when given: anything else is an error.
    /// Not found is an error when this device reads seq 1. Otherwise the invitation predates
    /// this device's readable history (mls-ds never makes a later joiner a recipient of earlier
    /// control entries), and the actor's device signature and coordinate step stand alone.
    async fn verify_invitation_chain(
        &self,
        pass: &SyncPass<'_>,
        invitee: &str,
        provenance: Option<&Value>,
        before_seq: i64,
        peer_map: &mut BTreeMap<String, Vec<(String, Vec<u8>)>>,
    ) -> Result<(), MLSError> {
        let refused = |what: &str| MLSError::Cryptography(format!("invitation chain: {what}"));
        // An unverified selection: the invitation found must then verify.
        let invitation = |entries: &[Value]| {
            entries.iter().find_map(|entry| {
                if !entry["seq"].as_i64().is_some_and(|seq| seq < before_seq) {
                    return None;
                }
                let kind = chat_wire::signed_entry_kind(entry).ok().filter(|kind| {
                    matches!(
                        kind,
                        SignedMutationKind::Creation | SignedMutationKind::PolicyTransition
                    )
                })?;
                let body = &entry["signedRequest"]["body"];
                let names = match provenance {
                    Some(provenance) => {
                        body["transitionId"] == provenance["invitationTransitionId"]
                    }
                    None => {
                        chat_wire::invitation_provenance(kind, body, pass.cid, invitee).is_some()
                    }
                };
                names.then(|| (kind, entry.clone()))
            })
        };
        let mut found = invitation(pass.batch);
        let mut reads_seq_1 = false;
        let mut after_seq = 0i64;
        for _page in 0..50 {
            if found.is_some() {
                break;
            }
            let after = after_seq.to_string();
            let page = self
                .ds_signed_get(
                    pass.session_token,
                    pass.canonical_dev_id,
                    "blue.catbird.chat.getEntries",
                    &[
                        ("actorDeviceId", pass.canonical_dev_id),
                        ("afterSeq", &after),
                        ("conversationId", pass.cid),
                        ("limit", "100"),
                    ],
                    pass.signer,
                )
                .await?;
            let entries = page["entries"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default();
            reads_seq_1 |= entries.iter().any(|entry| entry["seq"] == 1);
            found = invitation(entries);
            let last = entries
                .iter()
                .filter_map(|entry| entry["seq"].as_i64())
                .max()
                .unwrap_or(after_seq);
            if !page["hasMore"].as_bool().unwrap_or(entries.len() >= 100)
                || last <= after_seq
                || last + 1 >= before_seq
            {
                break;
            }
            after_seq = last;
        }
        let Some((kind, invitation)) = found else {
            return if reads_seq_1 {
                Err(refused("no invitation in history that starts at seq 1"))
            } else {
                Ok(())
            };
        };
        let body = &invitation["signedRequest"]["body"];
        let (did, device) = match provenance {
            Some(provenance) => (
                &provenance["invitedByDid"],
                &provenance["invitedByDeviceId"],
            ),
            None => (&body["actorDid"], &body["actorDeviceId"]),
        };
        let (Some(did), Some(device)) = (did.as_str(), device.as_str()) else {
            return Err(refused("no signing device"));
        };
        let key = self
            .pds_device_key(pass.session_token, peer_map, did, device)
            .await?;
        let verified =
            chat_wire::verify_signed_mutation_body(&invitation["signedRequest"], kind, &key)?;
        match chat_wire::invitation_provenance(kind, &verified, pass.cid, invitee) {
            Some(named) if provenance.is_none_or(|provenance| *provenance == named) => Ok(()),
            _ => Err(refused(
                "the invitation does not invite the actor as signed",
            )),
        }
    }

    /// A sequenced control entry of `kind` that carries no Commit, verified under its kind's
    /// authority and bound to `pass.cid` before any effect. Returns its verified body and the
    /// coordinate it moves the conversation to, if any:
    /// - `policyEntry`, `metadataEntry`: a current leaf; `next` is `prior` one `stateVersion` on.
    /// - `participantAcceptanceEntry`: the actor's device, with the invitation chain its signed
    ///   `invitationProvenance` names; `next` likewise. It never accepts a direct request.
    /// - `conversationCloseEntry`: a current leaf, or in a direct conversation any participant
    ///   device (a pending invitee may close it); `retired` is `prior` one `stateVersion` on,
    ///   superseded.
    /// - `zeroLeafLeaveEntry`: a participant device; `next` likewise.
    /// - `leaveRequestEntry`: a current leaf; `resetRequestEntry`, `resetActivationEntry`,
    ///   `leaveCancellationEntry`, `creationEntry`: a participant device. These only bind the
    ///   conversation and change nothing beyond the cursor (this client does not apply a reset
    ///   activation).
    ///
    /// A current leaf is [`Self::control_signer_key`]'s. A participant device is the
    /// PDS-authorized device of a DID holding a current leaf, or of an invitee the invitation
    /// chain verifies ([`Self::verify_invitation_chain`]).
    async fn verify_control_entry(
        &self,
        pass: &SyncPass<'_>,
        kind: SignedMutationKind,
        entry: &Value,
        peer_map: &mut BTreeMap<String, Vec<(String, Vec<u8>)>>,
    ) -> Result<(Value, Option<Value>), MLSError> {
        use SignedMutationKind as K;
        let cid = pass.cid;
        let signed = &entry["signedRequest"];
        let seq = entry["seq"].as_i64().unwrap_or_default();
        let actor = signed
            .pointer("/body/actorDid")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let device = signed
            .pointer("/body/actorDeviceId")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let leaf_key = self.control_signer_key(
            cid,
            Some(actor),
            Some(device),
            peer_map,
            pass.canonical_dev_id,
            pass.signer,
        );
        let body = match kind {
            K::PolicyTransition | K::MetadataTransition | K::LeaveRequest => {
                chat_wire::verify_signed_mutation_body(signed, kind, &leaf_key?)?
            }
            K::ConversationClose if leaf_key.is_ok() => {
                chat_wire::verify_signed_mutation_body(signed, kind, &leaf_key?)?
            }
            K::ParticipantAcceptance => {
                let key = self
                    .pds_device_key(pass.session_token, peer_map, actor, device)
                    .await?;
                let body = chat_wire::verify_signed_mutation_body(signed, kind, &key)?;
                self.verify_invitation_chain(
                    pass,
                    actor,
                    Some(&body["invitationProvenance"]),
                    seq,
                    peer_map,
                )
                .await?;
                body
            }
            K::ConversationClose
            | K::ZeroLeafLeave
            | K::ResetRequest
            | K::ResetActivation
            | K::LeaveCancellation
            | K::Creation => {
                let key = self
                    .pds_device_key(pass.session_token, peer_map, actor, device)
                    .await?;
                let body = chat_wire::verify_signed_mutation_body(signed, kind, &key)?;
                if kind == K::ConversationClose && body["conversationKind"] != "direct" {
                    return Err(MLSError::Cryptography(
                        "I4: only a current leaf closes a group conversation".into(),
                    ));
                }
                if !self.is_member_did(cid, actor)? {
                    self.verify_invitation_chain(pass, actor, None, seq, peer_map)
                        .await?;
                }
                body
            }
            _ => {
                return Err(MLSError::Cryptography(
                    "entry is not a control entry".into(),
                ))
            }
        };
        let next = match kind {
            K::ConversationClose => Some(chat_wire::verify_coordinate_step(
                &body["prior"],
                &body["retired"],
                cid,
                "superseded",
            )?),
            K::PolicyTransition
            | K::MetadataTransition
            | K::ParticipantAcceptance
            | K::ZeroLeafLeave => Some(chat_wire::verify_state_version_step(&body, cid)?),
            _ if binds_only(&body, cid) => None,
            _ => {
                return Err(MLSError::Cryptography(
                    "control entry is signed for a different conversation".into(),
                ))
            }
        };
        Ok((body, next))
    }

    /// A sequenced Commit-bearing entry (`commitEntry`, `leafRecoveryFulfillmentEntry`,
    /// `leaveCommitFulfillmentEntry`) of `kind`, applied only once verified, in one transaction
    /// with its verified `next` and the cursor. Returns whether it removed this device. A
    /// missing local group is an error.
    ///
    /// This device's own echo verifies under its own signer. Its Commit is merged already, or
    /// its `commit_transition` journal (the same transition, Commit digest and `next`, staged
    /// from exactly the local prior MLS state) merges it now; an own Commit neither merged nor
    /// journaled is an error, so `next` is never written over an unmerged epoch. An older echo
    /// closing a sequence gap behind a later durable Commit only moves the cursor.
    ///
    /// A peer's verifies under its actor's current leaf key, and only the verified body's
    /// Commit is processed: at the local epoch, sent by exactly that leaf. Merged, its signed
    /// `next` must name the local MLS state at the local generation, one `stateVersion` past
    /// its `prior`. Its metadata snapshot comes from the verified body alone.
    fn apply_synced_commit(
        &self,
        cid: &str,
        entry: &Value,
        kind: SignedMutationKind,
        peer_map: &BTreeMap<String, Vec<(String, Vec<u8>)>>,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
    ) -> Result<bool, MLSError> {
        let refused = |what: &str| MLSError::Cryptography(format!("Commit entry: {what}"));
        let signed = &entry["signedRequest"];
        let entry_seq = entry["seq"].as_i64().ok_or_else(|| refused("no seq"))?;
        let actor_did = signed.pointer("/body/actorDid").and_then(Value::as_str);
        let actor_dev = signed
            .pointer("/body/actorDeviceId")
            .and_then(Value::as_str);
        let own =
            actor_did == Some(self.account_did.as_str()) && actor_dev == Some(canonical_dev_id);
        // Actor labels only route: the complete body verifies before any effect.
        let body = if own {
            chat_wire::verify_own_commit_body(signed, signer.public())?
        } else {
            let key = self.control_signer_key(
                cid,
                actor_did,
                actor_dev,
                peer_map,
                canonical_dev_id,
                signer,
            )?;
            chat_wire::verify_signed_mutation_body(signed, kind, &key)?
        };
        if body["prior"]["conversationId"].as_str() != Some(cid)
            || body["next"]["conversationId"].as_str() != Some(cid)
        {
            return Err(refused("signed for a different conversation"));
        }
        let next = chat_wire::canonicalize_wire_coordinate(&body["next"], None)?;
        let commit = chat_wire::json_bytes(&body["commit"]["bytes"])?;
        let own_leaf = format!("{}#{canonical_dev_id}", self.account_did).into_bytes();
        let ts = now_ms();
        self.require_db_mls()?.write_tx(|tx| {
            let mut c = tx
                .get_conversation(cid)?
                .ok_or_else(|| MLSError::group_not_found(cid))?;
            let group_id = GroupId::from_slice(&c.group_id);
            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
            let load = || {
                MlsGroup::load(provider.storage(), &group_id)
                    .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                    .ok_or_else(|| refused("no local MLS group"))
            };
            let mut group = load()?;
            let mut kicked = false;
            if own {
                let (Some(generation), Some(epoch)) =
                    (next["generation"].as_i64(), next["epoch"].as_u64())
                else {
                    return Err(refused("own next coordinate"));
                };
                let local_epoch = group.epoch().as_u64();
                if generation < c.generation || (generation == c.generation && epoch < local_epoch)
                {
                    // An older echo closing a sequence gap behind a later durable Commit.
                    c.last_seq = c.last_seq.max(entry_seq);
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)?;
                    return Ok(false);
                }
                if generation != c.generation {
                    return Err(refused("own Commit is not for the local generation"));
                }
                let transition_id = body["transitionId"].as_str().unwrap_or_default();
                let journal = get_commit_transition(tx, cid, transition_id)?;
                match journal {
                    Some(pending) => {
                        let digest: [u8; 32] = Sha256::digest(&commit).into();
                        if pending.conversation_id != cid
                            || pending.commit_sha256 != digest
                            || chat_wire::canonicalize_wire_coordinate(&pending.next, None)? != next
                        {
                            return Err(refused("journal does not match the sequenced own Commit"));
                        }
                        if local_epoch < epoch {
                            // The staged state applies only over the prior it was staged from.
                            let prior =
                                chat_wire::canonicalize_wire_coordinate(&pending.prior, None)?;
                            if prior["generation"].as_i64() != Some(c.generation)
                                || chat_wire::require_coordinate_names_group(
                                    &prior, &group, &provider,
                                )
                                .is_err()
                            {
                                return Err(refused(
                                    "journal is not staged from the local prior MLS state",
                                ));
                            }
                            pending.kv_batch.apply(tx)?;
                            group = load()?;
                        }
                    }
                    None if local_epoch < epoch => {
                        return Err(MLSError::InvalidState(format!(
                            "unapplied own Commit {transition_id} has no recovery journal"
                        )));
                    }
                    None => {}
                }
                chat_wire::require_coordinate_names_group(&next, &group, &provider)?;
                tx.put_account_meta(
                    &format!("metadata_snapshot_json:{cid}"),
                    &body["metadataSnapshot"].to_string(),
                    ts,
                )?;
            } else {
                let message = MlsMessageIn::tls_deserialize_exact(&commit)
                    .map_err(|e| refused(&format!("deserialize: {e:?}")))?
                    .try_into_protocol_message()
                    .map_err(|e| refused(&format!("protocol message: {e:?}")))?;
                if message.epoch() != group.epoch() {
                    return Err(refused("not for the local epoch"));
                }
                let processed = group
                    .process_message(&provider, message)
                    .map_err(|e| refused(&format!("process: {e:?}")))?;
                let actor = format!(
                    "{}#{}",
                    body["actorDid"].as_str().unwrap_or_default(),
                    body["actorDeviceId"].as_str().unwrap_or_default()
                );
                if processed.credential().serialized_content() != actor.as_bytes() {
                    return Err(refused("its MLS sender is not the signed actor"));
                }
                let sender = processed.sender().clone();
                let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
                else {
                    return Err(refused("carries no MLS Commit"));
                };
                chat_wire::verify_staged_commit_pds_map_i4(&group, &sender, &staged, peer_map)?;
                kicked = staged.self_removed()
                    || staged.remove_proposals().any(|proposal| {
                        let removed = proposal.remove_proposal().removed();
                        group.members().any(|member| {
                            member.index == removed
                                && member.credential.serialized_content() == own_leaf.as_slice()
                        })
                    });
                group
                    .merge_staged_commit(&provider, *staged)
                    .map_err(|e| refused(&format!("merge: {e:?}")))?;
                chat_wire::require_coordinate_names_group(&next, &group, &provider)?;
                if next["generation"].as_i64() != Some(c.generation)
                    || next["stateVersion"].as_i64()
                        != body["prior"]["stateVersion"]
                            .as_i64()
                            .and_then(|version| version.checked_add(1))
                {
                    return Err(refused(
                        "next is not the local generation one stateVersion on",
                    ));
                }
                if !kicked {
                    let snapshot = &body["metadataSnapshot"];
                    if let Some((m_epoch, m_ver, meta)) =
                        chat_wire::try_decrypt_group_metadata_snapshot(
                            &mut group, &provider, snapshot,
                        )
                    {
                        let row =
                            chat_wire::group_metadata_row_from_v1(cid, m_ver, m_epoch, &meta, ts)?;
                        c.title = row.title.clone();
                        tx.upsert_group_metadata(&row)?;
                    }
                    tx.put_account_meta(
                        &format!("metadata_snapshot_json:{cid}"),
                        &snapshot.to_string(),
                        ts,
                    )?;
                }
            }
            c.epoch = group.epoch().as_u64() as i64;
            tx.put_account_meta(&format!("conversation_coords:{cid}"), &next.to_string(), ts)?;
            prune_commit_transitions(tx, cid, c.generation, c.epoch, kicked)?;
            c.last_seq = c.last_seq.max(entry_seq);
            c.updated_at_ms = ts;
            tx.upsert_conversation(&c)?;
            Ok(kicked)
        })
    }

    pub(crate) async fn sync_conversation_entries(
        &self,
        session_token: &str,
        canonical_dev_id: &str,
        signer: &SignatureKeyPair,
        auth_gen: i64,
        convo: &ConversationRow,
    ) -> Result<u32, MLSError> {
        let _ = auth_gen;
        let cid = convo.conversation_id.as_str();
        if self.is_conversation_closed(cid)?
            || uuid::Uuid::parse_str(cid)
                .ok()
                .filter(|u| u.get_version_num() == 4)
                .is_none()
        {
            return Ok(0);
        }

        // Paginate `blue.catbird.chat.getEntries` up to 50 pages of 100 entries (`I2`)
        let mut cursor_after_seq = convo.last_seq.max(0);
        let mut all_raw_entries: Vec<Value> = Vec::new();
        for _page in 0..50 {
            let after_seq_str = cursor_after_seq.to_string();
            let resp = self
                .ds_signed_get(
                    session_token,
                    canonical_dev_id,
                    "blue.catbird.chat.getEntries",
                    &[
                        ("actorDeviceId", canonical_dev_id),
                        ("afterSeq", &after_seq_str),
                        ("conversationId", cid),
                        ("limit", "100"),
                    ],
                    signer,
                )
                .await?;
            let Some(page_entries) = resp.get("entries").and_then(|v| v.as_array()) else {
                break;
            };
            if page_entries.is_empty() {
                break;
            }
            let page_max_seq = page_entries
                .iter()
                .filter_map(|e| e.get("seq").and_then(|s| s.as_i64()))
                .max()
                .unwrap_or(cursor_after_seq);
            all_raw_entries.extend(page_entries.iter().cloned());
            let has_more = resp
                .get("hasMore")
                .and_then(|v| v.as_bool())
                .unwrap_or(page_entries.len() >= 100);
            let next_after = resp
                .get("nextAfterSeq")
                .and_then(|v| v.as_i64())
                .unwrap_or(page_max_seq);
            if !has_more || next_after <= cursor_after_seq {
                break;
            }
            cursor_after_seq = next_after;
        }
        if all_raw_entries.is_empty() {
            return Ok(0);
        }

        let mut sorted_entries = all_raw_entries;
        sorted_entries.sort_by_key(|e| e.get("seq").and_then(|s| s.as_i64()).unwrap_or(0));
        sorted_entries.dedup_by_key(|e| e.get("seq").and_then(|s| s.as_i64()).unwrap_or(0));

        let db = self.require_db_mls()?;
        let mut candidate_dids = BTreeMap::new();
        for entry in &sorted_entries {
            chat_wire::collect_dids_from_json(entry, &mut candidate_dids);
        }
        if let Ok(provider) = db.openmls_provider() {
            if let Ok(Some(group)) =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
            {
                for m in group.members() {
                    if let Ok((d, _)) = chat_wire::parse_scoped_credential_did_device(
                        m.credential.serialized_content(),
                    ) {
                        candidate_dids.insert(d, ());
                    }
                }
            }
        }
        let mut peer_map: BTreeMap<String, Vec<(String, Vec<u8>)>> = BTreeMap::new();
        for did in candidate_dids.keys() {
            let pairs = self
                .verify_peer_device_keys_via_pds(session_token, did)
                .await?;
            peer_map.insert(did.clone(), pairs);
        }

        let mut max_seq = convo.last_seq;
        let mut applied_count = 0u32;
        let mut saw_c33_accept = false;
        let mut was_kicked = false;
        let mut was_closed = false;
        let pass = SyncPass {
            session_token,
            canonical_dev_id,
            signer,
            cid,
            batch: &sorted_entries,
        };

        for entry in &sorted_entries {
            let entry_seq = entry.get("seq").and_then(|v| v.as_i64()).unwrap_or(max_seq);
            let entry_type = entry
                .get("$type")
                .or_else(|| entry.get("entryKind"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let signed_req = entry.get("signedRequest").unwrap_or(entry);
            let body = signed_req.get("body").unwrap_or(signed_req);
            let body_type = body.get("$type").and_then(|v| v.as_str()).unwrap_or("");
            let ts = now_ms();
            let is_application = entry_type.ends_with("applicationMessageEntry")
                || entry_type.ends_with("applicationEntry")
                || body_type.ends_with("applicationSendBody")
                || body.get("applicationMessage").is_some()
                || entry.get("applicationMessage").is_some();
            if entry_seq <= convo.last_seq && !is_application {
                // A replayed control entry must not reapply its effects.
                continue;
            }

            if entry_type == ACCOUNT_DELETED_ENTRY_KIND {
                // An entry whose sequencer authority does not verify stops this pass here: it is
                // never skipped and passed by later entries.
                let key_id =
                    chat_wire::account_deleted_entry_key_id(cid, &convo.sequencer_did, entry)
                        .ok_or_else(|| {
                            MLSError::Cryptography(
                                "account deletion is not bound to this conversation's sequencer"
                                    .into(),
                            )
                        })?;
                let key = self
                    .fetch_sequencer_receipt_key_sec1(session_token, &convo.sequencer_did, key_id)
                    .await?;
                let (deleted_did, seq) = chat_wire::verify_account_deleted_entry_signature(
                    cid,
                    &convo.sequencer_did,
                    entry,
                    &key,
                )
                .ok_or_else(|| {
                    MLSError::Cryptography(
                        "account deletion sequencer authority does not verify".into(),
                    )
                })?;
                self.apply_verified_account_deletion(cid, &deleted_did, seq, ts)?;
                applied_count = applied_count.saturating_add(1);
                max_seq = max_seq.max(entry_seq);
                continue;
            }

            if entry_type.ends_with("directRequestAcceptanceEntry")
                || body_type.ends_with("directRequestAcceptanceBody")
            {
                // Contract A: verified before any effect; a failure changes nothing.
                let next = self
                    .verify_synced_direct_request_acceptance(
                        session_token,
                        cid,
                        entry,
                        entry_seq,
                        &peer_map,
                        canonical_dev_id,
                        signer,
                    )
                    .await?;
                let next = serde_json::to_string(&next)?;
                db.write_tx(|tx| {
                    let mut reqs = tx.list_requests(None)?;
                    for r in &mut reqs {
                        if r.conversation_id == cid {
                            r.consent = "accepted".to_string();
                            r.updated_at_ms = ts;
                            tx.upsert_request(r)?;
                        }
                    }
                    tx.put_account_meta(&format!("conversation_coords:{cid}"), &next, ts)?;
                    if let Some(mut c) = tx.get_conversation(cid)? {
                        c.last_seq = c.last_seq.max(entry_seq);
                        c.updated_at_ms = ts;
                        tx.upsert_conversation(&c)?;
                    }
                    Ok(())
                })?;
                saw_c33_accept = true;
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            if is_application {
                let is_pruned = entry.get("payloadPruned").and_then(Value::as_bool) == Some(true);
                let msg_id = body
                    .get("messageId")
                    .or_else(|| entry.get("messageId"))
                    .or_else(|| entry.get("entryId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if msg_id.is_empty() {
                    return Err(MLSError::Cryptography(format!(
                        "application entry at seq {entry_seq} has no message id"
                    )));
                }
                // `I4` before any effect: the outer signed send binds its sender device key,
                // conversation and message id. A pruned entry keeps only its signed receipt.
                let verified_body = if is_pruned {
                    None
                } else {
                    Some(verify_application_body(
                        signed_req, entry, &peer_map, cid, msg_id,
                    )?)
                };
                let body = verified_body.as_ref().unwrap_or(body);
                // `I13` on every path: the entry's own receipt under the exact method its `kid`
                // names, resolved outside `write_tx` (`I6`).
                let rcpt_val = entry
                    .get("sequencerReceipt")
                    .filter(|v| v.is_object())
                    .ok_or_else(|| {
                        MLSError::Cryptography(format!(
                            "I13: applicationEntry {msg_id} at seq {entry_seq} missing sequencerReceipt"
                        ))
                    })?;
                let expected_rcpt_entry_id = entry
                    .get("entryId")
                    .and_then(|v| v.as_str())
                    .unwrap_or(msg_id);
                let rcpt_key = self
                    .receipt_key_for(session_token, &convo.sequencer_did, rcpt_val)
                    .await?;
                let rcpt_sec1 = rcpt_key.as_slice();
                let evidence_key = format!("native.message:{cid}:{msg_id}");
                if db.backend().get_message(msg_id)?.is_some()
                    && db.backend().get_labyrinth_state(&evidence_key)?.is_some()
                {
                    self.finish_received_archive_evidence(
                        cid,
                        msg_id,
                        entry_seq,
                        expected_rcpt_entry_id,
                        rcpt_val,
                        rcpt_sec1,
                    )?;
                    max_seq = max_seq.max(entry_seq);
                    applied_count = applied_count.saturating_add(1);
                    continue;
                }
                if is_pruned {
                    // Only the signed receipt remains: it must sequence exactly this entry.
                    db.write_tx(|tx| {
                        let mut c = tx
                            .get_conversation(cid)?
                            .ok_or_else(|| MLSError::group_not_found(cid))?;
                        chat_wire::verify_pruned_application_receipt(
                            rcpt_val,
                            rcpt_sec1,
                            &c.sequencer_did,
                            cid,
                            &c.group_id,
                            expected_rcpt_entry_id,
                            entry_seq,
                        )?;
                        c.last_seq = c.last_seq.max(entry_seq);
                        c.updated_at_ms = ts;
                        tx.upsert_conversation(&c)
                    })?;
                    max_seq = max_seq.max(entry_seq);
                    applied_count = applied_count.saturating_add(1);
                    continue;
                }
                let app_obj = body
                    .get("applicationMessage")
                    .or_else(|| entry.get("applicationMessage"))
                    .unwrap_or(entry);
                let ct_bytes = chat_wire::json_bytes(
                    app_obj
                        .get("bytes")
                        .or_else(|| entry.get("ciphertext"))
                        .ok_or_else(|| {
                            MLSError::invalid_input("applicationMessageEntry missing bytes")
                        })?,
                )?;
                let journal_key = crate::wasm_client_mutations::pending_send_key(cid, msg_id);
                if let Some(raw) = db.backend().get_account_meta(&journal_key)? {
                    let pending: crate::wasm_client_mutations::PendingApplicationSend =
                        serde_json::from_str(&raw)
                            .map_err(|e| MLSError::Internal(format!("parse send journal: {e}")))?;
                    if pending.archive.sender_did != self.account_did
                        || pending.archive.sender_device_id != canonical_dev_id
                        || STANDARD
                            .decode(&pending.archive.mls_ciphertext_b64)
                            .ok()
                            .as_deref()
                            != Some(ct_bytes.as_slice())
                    {
                        return Err(MLSError::Cryptography(
                            "send journal does not match sequenced application ciphertext".into(),
                        ));
                    }
                    // Own MLS ciphertext is not decryptable. A send whose response was lost is
                    // recovered only from its exact journal, with the same I13 receipt checks.
                    self.finish_application_send(
                        pending,
                        rcpt_val,
                        expected_rcpt_entry_id,
                        rcpt_sec1,
                        Some(entry_seq),
                    )?;
                    max_seq = max_seq.max(entry_seq);
                    applied_count = applied_count.saturating_add(1);
                    continue;
                }

                // Set only when OpenMLS can never open this current-epoch entry for this device.
                let mut undecryptable = None;
                let decrypt_result = db.write_tx(|tx| {
                    let mut c = tx
                        .get_conversation(cid)?
                        .ok_or_else(|| MLSError::group_not_found(cid))?;
                    let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
                    // No group, no roster to authenticate against: never store, advance or ACK.
                    let mut group =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                            .ok_or_else(|| MLSError::group_not_found(cid))?;
                    let msg_in = MlsMessageIn::tls_deserialize_exact(&ct_bytes).map_err(|e| {
                        MLSError::Cryptography(format!("deserialize app msg: {e:?}"))
                    })?;
                    let proto = msg_in
                        .try_into_protocol_message()
                        .map_err(|e| MLSError::Cryptography(format!("app protocol msg: {e:?}")))?;
                    let msg_epoch = proto.epoch().as_u64() as i64;
                    let current_epoch = proto.epoch() == group.epoch();
                    let processed = group.process_message(&provider, proto).map_err(|e| {
                        if current_epoch {
                            undecryptable = chat_wire::permanent_decrypt_failure(&e)
                                .map(|reason| (reason, msg_epoch));
                        }
                        MLSError::Cryptography(format!("decrypt app msg: {e:?}"))
                    })?;
                    let sender_cred = processed.credential().clone();
                    let aad_bytes = processed.aad().to_vec();
                    let signed_aad =
                        canonical_application_aad_bytes(body.get("aad").ok_or_else(|| {
                            MLSError::Cryptography("signed application body missing MLS AAD".into())
                        })?)
                        .map_err(|error| {
                            MLSError::Cryptography(format!(
                                "invalid signed application AAD: {error}"
                            ))
                        })?;
                    if signed_aad != aad_bytes {
                        return Err(MLSError::Cryptography(
                            "decrypted MLS AAD differs from signed outer application AAD".into(),
                        ));
                    }
                    let member = group
                        .members()
                        .find(|m| {
                            m.credential.serialized_content() == sender_cred.serialized_content()
                        })
                        .ok_or_else(|| {
                            MLSError::Cryptography(
                                "I4: applicationMessage sender leaf not in group roster".into(),
                            )
                        })?;
                    let (sender_did, sender_dev_id) = chat_wire::verify_leaf_pds_map_i4(
                        member.credential.serialized_content(),
                        member.signature_key.as_slice(),
                        &peer_map,
                    )?;
                    if body["actorDid"].as_str() != Some(sender_did.as_str())
                        || body["actorDeviceId"].as_str() != Some(sender_dev_id.as_str())
                    {
                        return Err(MLSError::Cryptography(
                            "verified outer sender differs from decrypted MLS sender".into(),
                        ));
                    }
                    let ProcessedMessageContent::ApplicationMessage(app_msg) =
                        processed.into_content()
                    else {
                        return Err(MLSError::Cryptography("expected ApplicationMessage".into()));
                    };
                    let app_bytes = app_msg.into_bytes();
                    let inner: PrivateMessagePlaintextEnvelope = serde_json::from_slice(&app_bytes)
                        .map_err(|e| {
                            MLSError::Cryptography(format!("application archive envelope: {e}"))
                        })?;
                    let (
                        _display_body,
                        json_str,
                        verified_commitment_opt,
                        original_sender_attestation,
                    ) = extract_plaintext_body_and_verify_aad(&app_bytes, &aad_bytes)?;
                    let verified_commitment = verified_commitment_opt.ok_or_else(|| {
                        MLSError::Cryptography(
                            "I13: applicationEntry missing verified AAD archiveCommitment".into(),
                        )
                    })?;
                    let original_sender_attestation =
                        original_sender_attestation.ok_or_else(|| {
                            MLSError::Cryptography(
                                "application message missing original sender archive attestation"
                                    .into(),
                            )
                        })?;
                    if original_sender_attestation.sender_did != sender_did
                        || original_sender_attestation.sender_device_id != sender_dev_id
                        || original_sender_attestation
                            .sender_transport_public_key
                            .as_slice()
                            != member.signature_key.as_slice()
                    {
                        return Err(MLSError::Cryptography(
                            "original sender attestation differs from decrypted MLS sender leaf"
                                .into(),
                        ));
                    }
                    let (rcpt_seq, rcpt_generation, stored_receipt) =
                        chat_wire::parse_and_verify_i13_sequencer_receipt(
                            rcpt_val,
                            rcpt_sec1,
                            &c.sequencer_did,
                            cid,
                            &c.group_id,
                            msg_epoch.max(0) as u64,
                            expected_rcpt_entry_id,
                            msg_id,
                            &verified_commitment,
                            Some(&original_sender_attestation),
                        )?;
                    if rcpt_seq as i64 != entry_seq {
                        return Err(MLSError::Cryptography(format!(
                            "I13: receipt seq {rcpt_seq} != entry seq {entry_seq}"
                        )));
                    }
                    // The receipt's generation is not signed: bind it to the local conversation
                    // so retained evidence only ever carries an authenticated generation.
                    if rcpt_generation != c.generation.max(0) as u64 {
                        return Err(MLSError::Cryptography(
                            "I13: receipt generation mismatch".into(),
                        ));
                    }
                    let archive = QueuedLabyrinthArchivePayload {
                        version: 1,
                        message_id: msg_id.to_string(),
                        conversation_id: cid.to_string(),
                        group_id_hex: hex::encode(&c.group_id),
                        epoch: msg_epoch,
                        expected_member_dids: crate::wasm_client_mutations::member_root_dids(
                            &group,
                        )?,
                        seq: entry_seq,
                        sender_did: sender_did.clone(),
                        sender_device_id: sender_dev_id.clone(),
                        sequencer_did: c.sequencer_did.clone(),
                        space_uri: c.space_uri.clone(),
                        plaintext_json: json_str.clone(),
                        labyrinth_frame_json: String::from_utf8(inner.canonical_payload_bytes)
                            .map_err(|e| {
                                MLSError::Cryptography(format!("application archive frame: {e}"))
                            })?,
                        mls_ciphertext_b64: STANDARD.encode(&ct_bytes),
                        frame_nonce_b64: Some(STANDARD.encode(inner.frame_nonce)),
                        sequencer_receipt_json: Some(stored_receipt),
                        original_sender_attestation_json: Some(
                            serde_json::to_string(&original_sender_attestation).map_err(
                                |error| {
                                    MLSError::Internal(format!(
                                        "serialize original sender archive attestation: {error}"
                                    ))
                                },
                            )?,
                        ),
                        created_at_ms: ts,
                    };

                    tx.insert_message(&MessageRow {
                        message_id: msg_id.to_string(),
                        conversation_id: cid.to_string(),
                        group_id: c.group_id.clone(),
                        epoch: msg_epoch,
                        seq: entry_seq,
                        sender_did: sender_did.clone(),
                        sender_device_id: sender_dev_id,
                        plaintext_json: json_str,
                        created_at_ms: ts,
                        is_own: sender_did == self.account_did,
                    })?;
                    let archive_bytes = serde_json::to_vec(&archive)
                        .map_err(|e| MLSError::Internal(e.to_string()))?;
                    tx.put_labyrinth_state(&evidence_key, &archive_bytes, ts)?;
                    // Witness copy: pre-removal history must not depend on its sender flushing.
                    // An own-account message stays the sending device's archive duty.
                    if sender_did != self.account_did {
                        tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                            item_id: msg_id.to_string(),
                            conversation_id: cid.to_string(),
                            group_id_hex: archive.group_id_hex.clone(),
                            seq: entry_seq,
                            payload_bytes: archive_bytes,
                            created_at_ms: ts,
                        })?;
                    }
                    c.last_seq = c.last_seq.max(entry_seq);
                    if sender_did != self.account_did {
                        c.unread_count = c.unread_count.saturating_add(1);
                    }
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)
                });
                if let (Err(error), Some((reason, epoch))) = (&decrypt_result, undecryptable) {
                    // Never fail-stop or force a rejoin here: later entries, Commits above all,
                    // must still apply. The failed attempt rolled back; record the gap instead,
                    // once the entry proves itself without its plaintext.
                    tracing::warn!(
                        conversation_id = cid,
                        seq = entry_seq,
                        reason,
                        %error,
                        "recording permanently undecryptable application entry"
                    );
                    self.record_undecryptable_entry(
                        &chat_wire::UndecryptableEntryEvidence {
                            version: 1,
                            conversation_id: cid.to_owned(),
                            message_id: msg_id.to_owned(),
                            entry_id: expected_rcpt_entry_id.to_owned(),
                            seq: entry_seq,
                            epoch,
                            sender_did: body["actorDid"].as_str().unwrap_or_default().to_owned(),
                            sender_device_id: body["actorDeviceId"]
                                .as_str()
                                .unwrap_or_default()
                                .to_owned(),
                            reason: reason.to_owned(),
                            recorded_at_ms: ts,
                        },
                        &body["aad"],
                        rcpt_val,
                        rcpt_sec1,
                        &peer_map,
                    )?;
                    max_seq = max_seq.max(entry_seq);
                    applied_count = applied_count.saturating_add(1);
                    continue;
                }
                decrypt_result?;
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            // Every other entry is a signed control entry: its kind comes from its signed body
            // (a relabelled entry is refused), and it verifies under that kind's authority
            // before any effect. An opening (`directRequestEntry`) past the cursor, consumed only
            // by the checked `C33` import, and anything else unrecognised stop the pass here.
            let kind = chat_wire::signed_entry_kind(entry)?;
            if matches!(
                kind,
                SignedMutationKind::CommitTransition
                    | SignedMutationKind::LeafRecoveryFulfillment
                    | SignedMutationKind::LeaveCommitFulfillment
            ) {
                was_kicked |= self.apply_synced_commit(
                    cid,
                    entry,
                    kind,
                    &peer_map,
                    canonical_dev_id,
                    signer,
                )?;
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }
            let (verified, next) = self
                .verify_control_entry(&pass, kind, entry, &mut peer_map)
                .await?;
            max_seq = max_seq.max(entry_seq);
            applied_count = applied_count.saturating_add(1);
            if kind == SignedMutationKind::ConversationClose {
                self.apply_terminal_close(cid, next.as_ref(), Some(entry_seq))?;
                was_closed = true;
                break;
            }
            db.write_tx(|tx| {
                let mut c = tx
                    .get_conversation(cid)?
                    .ok_or_else(|| MLSError::group_not_found(cid))?;
                if kind == SignedMutationKind::MetadataTransition {
                    let snapshot = &verified["metadataSnapshot"];
                    let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
                    if let Some(mut group) =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                    {
                        if let Some((m_epoch, m_ver, meta)) =
                            chat_wire::try_decrypt_group_metadata_snapshot(
                                &mut group, &provider, snapshot,
                            )
                        {
                            let row = chat_wire::group_metadata_row_from_v1(
                                cid, m_ver, m_epoch, &meta, ts,
                            )?;
                            c.title = row.title.clone();
                            tx.upsert_group_metadata(&row)?;
                        }
                    }
                    tx.put_account_meta(
                        &format!("metadata_snapshot_json:{cid}"),
                        &snapshot.to_string(),
                        ts,
                    )?;
                }
                if let Some(next) = &next {
                    tx.put_account_meta(
                        &format!("conversation_coords:{cid}"),
                        &next.to_string(),
                        ts,
                    )?;
                }
                c.last_seq = c.last_seq.max(entry_seq);
                c.updated_at_ms = ts;
                tx.upsert_conversation(&c)
            })?;
        }

        if saw_c33_accept && !was_closed {
            let _ = self.archive_accepted_opening_messages(cid).await;
        }
        if max_seq >= 1 && applied_count > 0 && !was_kicked && !was_closed {
            self.acknowledge_entries_up_to_impl(cid, max_seq).await?;
        }
        Ok(applied_count)
    }
}

#[cfg(test)]
mod tests {
    use super::require_browser_welcome_receipt_inputs;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn browser_welcome_requires_verified_receipt_inputs() {
        assert!(
            require_browser_welcome_receipt_inputs(&[0; 32], b"receipt", "did:web:ds", b"key")
                .is_err()
        );
        assert!(
            require_browser_welcome_receipt_inputs(&[1; 32], b"", "did:web:ds", b"key").is_err()
        );
        require_browser_welcome_receipt_inputs(&[1; 32], b"receipt", "did:web:ds", b"key").unwrap();
    }
}
