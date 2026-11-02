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
use catbird_mls::client::chat_wire;
use catbird_mls::client::{LabyrinthBackupStatus, QueuedLabyrinthArchivePayload};
use catbird_mls::messaging::receive::extract_plaintext_body_and_verify_aad;
use catbird_mls::metadata::derive_metadata_key_from_group;
use catbird_mls::orchestrator::canonical_transport::{
    canonical_commit_aad_bytes, derive_key_id, CanonicalOperation,
};
use catbird_mls::orchestrator::direct_request_bootstrap::{
    DirectRequestBootstrap, DirectRequestIntroductionResult, DirectRequestWelcomeInput,
};
use catbird_mls::orchestrator::direct_request_shared_crypto::decrypt_introduction_with_provider;
use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend};
use catbird_mls::storage::{
    ConversationRow, KvWriteOverlay, LabyrinthQueueRow, MessageRow, OpenMlsKvProvider,
    OpenMlsKvStorage, RequestRow,
};
use catbird_mls::MLSError;

use crate::sqlite_conn::SqliteConn;
use crate::wasm_client::{now_ms, WasmMlsClient};

fn build_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(5)
        .build()
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
        let u = uuid::Uuid::parse_str(self.device_id.trim()).ok()?;
        if u.get_version_num() != 4 {
            return None;
        }
        Some(u.hyphenated().to_string())
    }

    pub(crate) fn live_session(&self) -> Option<(String, String)> {
        Some((
            self.effective_auth_token()?,
            self.canonical_uuid_v4_device_id()?,
        ))
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
        let bytes = self
            .ds_post_json(session_token, nsid, prepared.body.unwrap_or_default())
            .await?;
        if bytes.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(MLSError::Internal(format!(
                "POST {nsid} returned empty response body"
            )));
        }
        let val: Value = serde_json::from_slice(&bytes)
            .map_err(|e| MLSError::Internal(format!("parse {operation:?} JSON: {e}")))?;
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
        let resp = self
            .http
            .get(&list_url)
            .bearer_auth(session_token)
            .send()
            .await
            .map_err(|e| MLSError::Internal(format!("I4 PDS listRecords({did}) failed: {e}")))?;
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
        let resp = self
            .http
            .get(&get_url)
            .bearer_auth(session_token)
            .send()
            .await
            .ok()?;
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
                let next_coords = serde_json::from_slice::<Value>(&resp_bytes)
                    .ok()
                    .and_then(|v| {
                        v.get("coordinates").cloned().or_else(|| {
                            v.get("acceptanceProof")
                                .and_then(|p| p.get("receipt"))
                                .and_then(|r| r.get("body"))
                                .and_then(|b| b.get("next"))
                                .cloned()
                        })
                    })
                    .unwrap_or(next);
                let next_coords = chat_wire::canonicalize_wire_coordinate(
                    &next_coords,
                    Some(&req.conversation_id),
                )?;
                let coords_str = serde_json::to_string(&next_coords)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                db.write_tx(|tx| {
                    if let Some(mut c) = tx.get_conversation(&req.conversation_id)? {
                        c.last_seq = c.last_seq.max(2);
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
            if let Ok((signer, auth_gen)) = self.load_enrolled_signer_and_auth_gen() {
                if let Ok(prior_coords) =
                    self.load_or_build_conversation_coords(&req.conversation_id)
                {
                    let prior_sv = prior_coords
                        .get("stateVersion")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    let mut retired_coords = prior_coords.clone();
                    retired_coords["stateVersion"] = json!(prior_sv + 1);
                    retired_coords["lifecycle"] = json!("superseded");
                    let transition = uuid::Uuid::new_v4().to_string();
                    let close_body = json!({
                        "$type": "blue.catbird.chat.defs#conversationCloseBody",
                        "signatureDomain": "CATBIRD-CHAT-CLOSE\0",
                        "transitionId": transition,
                        "idempotencyKey": transition,
                        "actorDid": self.account_did,
                        "actorDeviceId": canonical_dev_id,
                        "keyId": derive_key_id(signer.public()),
                        "authGeneration": auth_gen,
                        "prior": prior_coords,
                        "retired": retired_coords,
                        "reason": "declined_direct_request",
                        "signedAt": chat_wire::now_rfc3339_millis(),
                    });
                    let _ = self
                        .submit_signed_chat_op(
                            &session_token,
                            &canonical_dev_id,
                            Some(auth_gen),
                            CanonicalOperation::CloseConversation,
                            &close_body,
                            &signer,
                        )
                        .await;
                }
            }
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

    pub(crate) async fn flush_labyrinth_queue_impl(&self) -> Result<u32, MLSError> {
        let Some((session_token, _)) = self.live_session() else {
            return Ok(0);
        };
        let db = self.require_db_mls()?;
        if let Some(raw) = db.backend().get_labyrinth_state("status_json")? {
            if let Ok(st) = serde_json::from_slice::<LabyrinthBackupStatus>(&raw) {
                if !st.backup_enabled {
                    return Ok(0);
                }
            }
        }
        let rows = db.backend().list_labyrinth_queue(None, 100)?;
        if rows.is_empty() {
            return Ok(0);
        }
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        let ts = now_ms();
        let mut flushed = 0u32;

        for row in rows {
            let Ok(payload) =
                serde_json::from_slice::<QueuedLabyrinthArchivePayload>(&row.payload_bytes)
            else {
                continue;
            };
            let mek_key = format!("convo_sender_mek:{}", payload.conversation_id);
            let mek_secret: [u8; 32] = db.write_tx(|tx| {
                if let Some(existing) = tx.get_labyrinth_state(&mek_key)? {
                    if let Ok(arr) = <[u8; 32]>::try_from(existing.as_slice()) {
                        return Ok(arr);
                    }
                }
                let mut fresh = [0u8; 32];
                getrandom::getrandom(&mut fresh)
                    .map_err(|e| MLSError::Internal(format!("getrandom mek: {e}")))?;
                tx.put_labyrinth_state(&mek_key, &fresh, ts)?;
                Ok(fresh)
            })?;

            let (_, apply_body) = chat_wire::build_space_apply_writes_for_queue_payload(
                &payload, mek_secret, &signer,
            )?;
            let (status, body) = self
                .pds_post_json(
                    &session_token,
                    "/xrpc/com.atproto.space.applyWrites",
                    apply_body,
                )
                .await?;
            let committed = (200..300).contains(&status)
                || status == 409
                || (status == 400
                    && serde_json::from_slice::<Value>(&body)
                        .ok()
                        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
                        .as_deref()
                        == Some("RecordAlreadyExists"));
            if committed {
                db.write_tx(|tx| tx.dequeue_labyrinth_item(&row.item_id))?;
                flushed = flushed.saturating_add(1);
            }
        }
        Ok(flushed)
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
            let sequencer_did = state
                .get("sequencerDid")
                .or_else(|| state.get("authorityDid"))
                .and_then(|v| v.as_str())
                .unwrap_or(&self.home_ds_did);
            let has_local = db.backend().get_conversation(cid)?.is_some();

            if kind == "direct" && !has_local {
                if self
                    .import_incoming_c33_direct_request(
                        session_token,
                        canonical_dev_id,
                        signer,
                        cid,
                        sequencer_did,
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
        sequencer_did_fallback: &str,
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
        };
        let welcome_input = DirectRequestWelcomeInput {
            bootstrap: bootstrap.clone(),
            publication_request: pub_norm_bytes.clone(),
            actor_signature_public_key: candidate_key,
            preparation_request_digest: [0u8; 32],
            local_identity: format!("{}#{}", self.account_did, canonical_dev_id).into_bytes(),
            local_package_ref: local_pkg_ref
                .or_else(|| refs.into_iter().next())
                .unwrap_or_default(),
            published_receipt: Vec::new(),
            receipt_authority_did: sequencer_did_fallback.to_string(),
            receipt_authority_key: Vec::new(),
        };

        let entry_seq = raw_dr_entry
            .get("seq")
            .and_then(|v| v.as_i64())
            .unwrap_or(1)
            .max(1);
        let sender_ds_opt = self
            .resolve_peer_home_ds_did(session_token, sender_did)
            .await;
        let effective_seq_did = raw_dr_entry
            .get("sequencerDid")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| {
                let sender_ds = sender_ds_opt?;
                let own_ds = self.home_ds_did.trim();
                if !own_ds.is_empty() && own_ds <= sender_ds.as_str() {
                    Some(own_ds.to_string())
                } else {
                    Some(sender_ds)
                }
            })
            .unwrap_or_else(|| sequencer_did_fallback.to_string());
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
            let intro_json =
                match decrypt_introduction_with_provider(&provider, &mut group, &welcome_input)? {
                    DirectRequestIntroductionResult::Ready { plaintext } => {
                        let intro_val =
                            dr_transcript::decode_direct_request_introduction(&plaintext)
                                .map_err(|e| MLSError::Cryptography(format!("decode C33: {e}")))?;
                        let txt = intro_val.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        json!({ "text": txt }).to_string()
                    }
                    DirectRequestIntroductionResult::Unavailable { code } => {
                        json!({ "text": format!("[unavailable:{code}]") }).to_string()
                    }
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
                unread_count: 1,
                updated_at_ms: ts,
            })?;
            tx.put_account_meta(&format!("conversation_coords:{cid}"), &coords_str, ts)?;
            tx.put_account_meta(&format!("c33_publication_json:{cid}"), &pub_norm_str, ts)?;
            let is_incoming = sender_did != self.account_did;
            tx.upsert_request(&RequestRow {
                request_id: request_id.to_string(),
                conversation_id: cid.to_string(),
                sender_did: sender_did.to_string(),
                recipient_did: self.account_did.clone(),
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
            let staged_opening = QueuedLabyrinthArchivePayload {
                version: 1,
                message_id: first_message_id.to_string(),
                conversation_id: cid.to_string(),
                group_id_hex: hex::encode(&group_id),
                epoch,
                seq: entry_seq,
                sender_did: sender_did.to_string(),
                sender_device_id: sender_device_id.to_string(),
                sequencer_did: effective_seq_did,
                space_uri,
                plaintext_json: intro_json.clone(),
                labyrinth_frame_json: chat_wire::canonical_labyrinth_frame_json(&intro_json),
                mls_ciphertext_b64: STANDARD.encode(&bootstrap.initial_ciphertext),
                frame_nonce_b64: None,
                sequencer_receipt_json: None,
                created_at_ms: ts,
            };
            tx.put_account_meta(
                &format!("c33_pending_opening:{cid}"),
                &serde_json::to_string(&staged_opening)
                    .map_err(|e| MLSError::Internal(e.to_string()))?,
                ts,
            )
        })?;
        Ok(true)
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

            if db.backend().get_conversation(cid)?.is_some() {
                let is_dr_welcome = w_env.get("$type").and_then(|t| t.as_str())
                    == Some("blue.catbird.chat.defs#directRequestWelcomeView");
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

            let mut candidate_dids: BTreeMap<String, ()> = BTreeMap::new();
            chat_wire::collect_dids_from_json(raw_item, &mut candidate_dids);
            candidate_dids.insert(self.account_did.clone(), ());

            // Peek member DIDs over KvWriteOverlay so OpenMLS's one-time KeyPackageBundle deletion
            // during `StagedWelcome::new_from_welcome` never mutates `openmls_kv` before `I4` PDS key fetch!
            {
                let overlay = KvWriteOverlay::new(db.backend());
                if let Ok(provider) = OpenMlsKvProvider::new(OpenMlsKvStorage::new(&overlay)) {
                    if let Ok(msg_in) = MlsMessageIn::tls_deserialize_exact(&welcome_bytes) {
                        if let MlsMessageBodyIn::Welcome(w_peek) = msg_in.extract() {
                            if let Ok(staged_peek) = StagedWelcome::new_from_welcome(
                                &provider,
                                &build_join_config(),
                                w_peek,
                                None,
                            ) {
                                if let Ok(s) = staged_peek.welcome_sender() {
                                    if let Ok((d, _)) =
                                        chat_wire::parse_scoped_credential_did_device(
                                            s.credential().serialized_content(),
                                        )
                                    {
                                        candidate_dids.insert(d, ());
                                    }
                                }
                                for m in staged_peek.members() {
                                    if let Ok((d, _)) =
                                        chat_wire::parse_scoped_credential_did_device(
                                            m.credential.serialized_content(),
                                        )
                                    {
                                        candidate_dids.insert(d, ());
                                    }
                                }
                            }
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

            let coords_canon = chat_wire::canonicalize_wire_coordinate(coords, Some(cid))?;
            let coords_str = serde_json::to_string(&coords_canon)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let meta_snap_opt = w_env.get("metadataSnapshot");
            let ts = now_ms();

            db.write_tx(|tx| {
                let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
                let msg_in = MlsMessageIn::tls_deserialize_exact(&welcome_bytes)
                    .map_err(|e| MLSError::Cryptography(format!("deserialize Welcome: {e:?}")))?;
                let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
                    return Err(MLSError::Cryptography("not Welcome".into()));
                };
                let staged =
                    StagedWelcome::new_from_welcome(&provider, &build_join_config(), welcome, None)
                        .map_err(|e| MLSError::Cryptography(format!("stage Welcome: {e:?}")))?;
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

                let mut decrypted_title: Option<String> = None;
                if let Some(snap) = meta_snap_opt {
                    if let Some((m_epoch, m_ver, meta)) =
                        chat_wire::try_decrypt_group_metadata_snapshot(&mut group, &provider, snap)
                    {
                        let row =
                            chat_wire::group_metadata_row_from_v1(cid, m_ver, m_epoch, &meta, ts)?;
                        decrypted_title = row.title.clone();
                        tx.upsert_group_metadata(&row)?;
                    }
                    if let Ok(snap_s) = serde_json::to_string(snap) {
                        tx.put_account_meta(&format!("metadata_snapshot_json:{cid}"), &snap_s, ts)?;
                    }
                }
                let gen_i64 = coords_canon
                    .get("generation")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                tx.upsert_conversation(&ConversationRow {
                    conversation_id: cid.to_string(),
                    group_id: group.group_id().as_slice().to_vec(),
                    generation: gen_i64,
                    epoch: group.epoch().as_u64() as i64,
                    last_seq: transition_seq,
                    sequencer_did: sequencer_did.to_string(),
                    space_uri: Some(format!(
                        "at://{sequencer_did}/space/blue.catbird.labyrinth.conversation/{cid}-{gen_i64}"
                    )),
                    title: decrypted_title,
                    unread_count: 0,
                    updated_at_ms: ts,
                })?;
                tx.put_account_meta(&format!("conversation_coords:{cid}"), &coords_str, ts)
            })?;

            if !welcome_id.is_empty() {
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
            joined = joined.saturating_add(1);
        }
        Ok(joined)
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
            let ts = now_ms();

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
            let submit_res = self
                .submit_signed_chat_op(
                    session_token,
                    canonical_dev_id,
                    Some(auth_gen),
                    CanonicalOperation::SubmitTransition,
                    &fulfill_body,
                    signer,
                )
                .await;
            let resp_val = match submit_res {
                Ok(v) => v,
                Err(e) if e.to_string().contains("HTTP 409") => {
                    // Competing device already fulfilled or rotated epoch; leave local `openmls_kv` untouched.
                    continue;
                }
                Err(e) => return Err(e),
            };
            let authoritative_seq = resp_val
                .get("seq")
                .or_else(|| resp_val.get("transitionSeq"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let coords_str = serde_json::to_string(&next_coords)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            let carried_snap_str = serde_json::to_string(&carried_snap)
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            db.write_tx(|tx| {
                kv_batch.apply(tx)?;
                if let Some(mut c) = tx.get_conversation(cid)? {
                    c.epoch = next_epoch as i64;
                    if authoritative_seq == c.last_seq + 1 {
                        c.last_seq = authoritative_seq;
                    }
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)?;
                }
                tx.put_account_meta(
                    &format!("metadata_snapshot_json:{cid}"),
                    &carried_snap_str,
                    ts,
                )?;
                tx.put_account_meta(&format!("conversation_coords:{cid}"), &coords_str, ts)
            })?;
            fulfilled = fulfilled.saturating_add(1);
        }
        Ok(fulfilled)
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
        if uuid::Uuid::parse_str(cid)
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

        // Pre-resolve the conversation sequencer's ES256 receipt key (`I13`) outside `write_tx` (`I6`)
        // whenever any non-pruned `applicationEntry` is present in the batch.
        let mut receipt_sec1_opt: Option<Vec<u8>> = None;
        for entry in &sorted_entries {
            let et = entry
                .get("$type")
                .or_else(|| entry.get("entryKind"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let sr = entry.get("signedRequest").unwrap_or(entry);
            let b = sr.get("body").unwrap_or(sr);
            let bt = b.get("$type").and_then(|v| v.as_str()).unwrap_or("");
            let is_app = et.ends_with("applicationMessageEntry")
                || et.ends_with("applicationEntry")
                || bt.ends_with("applicationSendBody")
                || b.get("applicationMessage").is_some()
                || entry.get("applicationMessage").is_some();
            let is_pruned = entry
                .get("payloadPruned")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if is_app && !is_pruned {
                let rcpt_kid = entry
                    .get("sequencerReceipt")
                    .and_then(|r| r.get("kid").or_else(|| r.get("keyId")))
                    .and_then(|v| v.as_str())
                    .unwrap_or("#mls-receipt-1");
                let sec1 = self
                    .fetch_sequencer_receipt_key_sec1(session_token, &convo.sequencer_did, rcpt_kid)
                    .await?;
                receipt_sec1_opt = Some(sec1);
                break;
            }
        }

        let mut max_seq = convo.last_seq;
        let mut applied_count = 0u32;
        let mut saw_c33_accept = false;
        let mut was_kicked = false;

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

            if entry_type.ends_with("accountDeletedEntry") || entry_type == "accountDeleted" {
                if let Some(deleted_did) = entry
                    .get("deletedDid")
                    .or_else(|| body.get("actorDid"))
                    .and_then(|v| v.as_str())
                {
                    let _ = db.write_tx(|tx| tx.purge_messages_from_sender(None, deleted_did));
                }
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            if entry_type.ends_with("directRequestAcceptanceEntry")
                || body_type.ends_with("directRequestAcceptanceBody")
                || entry_type.ends_with("participantAcceptanceEntry")
                || body_type.ends_with("participantAcceptanceBody")
            {
                let next_opt = body
                    .get("next")
                    .or_else(|| entry.get("coordinates"))
                    .and_then(|c| chat_wire::canonicalize_wire_coordinate(c, Some(cid)).ok());
                db.write_tx(|tx| {
                    let mut reqs = tx.list_requests(None)?;
                    for r in &mut reqs {
                        if r.conversation_id == cid {
                            r.consent = "accepted".to_string();
                            r.updated_at_ms = ts;
                            tx.upsert_request(r)?;
                        }
                    }
                    if let Some(ref nc) = next_opt {
                        let s = serde_json::to_string(nc)
                            .map_err(|e| MLSError::Internal(e.to_string()))?;
                        tx.put_account_meta(&format!("conversation_coords:{cid}"), &s, ts)?;
                    }
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

            if entry_type.ends_with("commitEntry")
                || entry_type.ends_with("leafRecoveryFulfillmentEntry")
                || body_type.ends_with("commitTransitionBody")
                || body_type.ends_with("leafRecoveryFulfillmentBody")
            {
                let actor_did = body
                    .get("actorDid")
                    .or_else(|| entry.get("actorDid"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let actor_dev = body
                    .get("actorDeviceId")
                    .or_else(|| entry.get("actorDeviceId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let is_own_echo = actor_did == self.account_did && actor_dev == canonical_dev_id;
                let commit_bytes_opt = body
                    .get("commit")
                    .or_else(|| entry.get("commit"))
                    .and_then(|c| c.get("bytes"))
                    .and_then(|b| chat_wire::json_bytes(b).ok());
                let snap_opt = body
                    .get("metadataSnapshot")
                    .or_else(|| entry.get("metadataSnapshot"));
                let next_opt = body
                    .get("next")
                    .or_else(|| entry.get("coordinates"))
                    .and_then(|c| chat_wire::canonicalize_wire_coordinate(c, Some(cid)).ok());
                let own_leaf_identity =
                    format!("{}#{canonical_dev_id}", self.account_did).into_bytes();

                let kicked_in_tx = db.write_tx(|tx| {
                    let Some(mut c) = tx.get_conversation(cid)? else {
                        return Ok(false);
                    };
                    let mut local_kicked = false;
                    if !is_own_echo {
                        if let Some(ref commit_bytes) = commit_bytes_opt {
                            let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
                            if let Some(mut group) = MlsGroup::load(
                                provider.storage(),
                                &GroupId::from_slice(&c.group_id),
                            )
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                            {
                                let msg_in = MlsMessageIn::tls_deserialize_exact(commit_bytes)
                                    .map_err(|e| {
                                        MLSError::Cryptography(format!("deserialize Commit: {e:?}"))
                                    })?;
                                let proto = msg_in.try_into_protocol_message().map_err(|e| {
                                    MLSError::Cryptography(format!("commit protocol msg: {e:?}"))
                                })?;
                                if proto.epoch().as_u64() == group.epoch().as_u64() {
                                    let processed =
                                        group.process_message(&provider, proto).map_err(|e| {
                                            MLSError::Cryptography(format!("process Commit: {e:?}"))
                                        })?;
                                    let commit_sender = processed.sender().clone();
                                    if let ProcessedMessageContent::StagedCommitMessage(staged) =
                                        processed.into_content()
                                    {
                                        chat_wire::verify_staged_commit_pds_map_i4(
                                            &group,
                                            &commit_sender,
                                            &staged,
                                            &peer_map,
                                        )?;
                                        let self_removed = staged.self_removed()
                                            || staged.remove_proposals().any(|rp| {
                                                let removed_idx = rp.remove_proposal().removed();
                                                group
                                                    .members()
                                                    .find(|m| m.index == removed_idx)
                                                    .map(|m| {
                                                        m.credential.serialized_content()
                                                            == own_leaf_identity.as_slice()
                                                    })
                                                    .unwrap_or(false)
                                            });
                                        group.merge_staged_commit(&provider, *staged).map_err(
                                            |e| {
                                                MLSError::Cryptography(format!(
                                                    "merge_staged_commit: {e:?}"
                                                ))
                                            },
                                        )?;
                                        c.epoch = group.epoch().as_u64() as i64;
                                        if self_removed {
                                            local_kicked = true;
                                        }
                                    }
                                }
                                if !local_kicked {
                                    if let Some(snap) = snap_opt {
                                        if let Some((m_epoch, m_ver, meta)) =
                                            chat_wire::try_decrypt_group_metadata_snapshot(
                                                &mut group, &provider, snap,
                                            )
                                        {
                                            let row = chat_wire::group_metadata_row_from_v1(
                                                cid, m_ver, m_epoch, &meta, ts,
                                            )?;
                                            c.title = row.title.clone();
                                            tx.upsert_group_metadata(&row)?;
                                        }
                                        if let Ok(snap_s) = serde_json::to_string(snap) {
                                            tx.put_account_meta(
                                                &format!("metadata_snapshot_json:{cid}"),
                                                &snap_s,
                                                ts,
                                            )?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if let Some(ref nc) = next_opt {
                        let s = serde_json::to_string(nc)
                            .map_err(|e| MLSError::Internal(e.to_string()))?;
                        tx.put_account_meta(&format!("conversation_coords:{cid}"), &s, ts)?;
                    }
                    c.last_seq = c.last_seq.max(entry_seq);
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)?;
                    Ok(local_kicked)
                })?;
                if kicked_in_tx {
                    was_kicked = true;
                }
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            if entry_type.ends_with("metadataEntry")
                || body_type.ends_with("metadataTransitionBody")
            {
                let snap_opt = body
                    .get("metadataSnapshot")
                    .or_else(|| entry.get("metadataSnapshot"));
                let next_opt = body
                    .get("next")
                    .or_else(|| entry.get("coordinates"))
                    .and_then(|c| chat_wire::canonicalize_wire_coordinate(c, Some(cid)).ok());
                db.write_tx(|tx| {
                    let Some(mut c) = tx.get_conversation(cid)? else {
                        return Ok(());
                    };
                    if let Some(snap) = snap_opt {
                        let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
                        if let Some(mut group) =
                            MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                                .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                        {
                            if let Some((m_epoch, m_ver, meta)) =
                                chat_wire::try_decrypt_group_metadata_snapshot(
                                    &mut group, &provider, snap,
                                )
                            {
                                let row = chat_wire::group_metadata_row_from_v1(
                                    cid, m_ver, m_epoch, &meta, ts,
                                )?;
                                c.title = row.title.clone();
                                tx.upsert_group_metadata(&row)?;
                            }
                        }
                        if let Ok(snap_s) = serde_json::to_string(snap) {
                            tx.put_account_meta(
                                &format!("metadata_snapshot_json:{cid}"),
                                &snap_s,
                                ts,
                            )?;
                        }
                    }
                    if let Some(ref nc) = next_opt {
                        let s = serde_json::to_string(nc)
                            .map_err(|e| MLSError::Internal(e.to_string()))?;
                        tx.put_account_meta(&format!("conversation_coords:{cid}"), &s, ts)?;
                    }
                    c.last_seq = c.last_seq.max(entry_seq);
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)
                })?;
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            if entry_type.ends_with("applicationMessageEntry")
                || entry_type.ends_with("applicationEntry")
                || body_type.ends_with("applicationSendBody")
                || body.get("applicationMessage").is_some()
                || entry.get("applicationMessage").is_some()
            {
                let is_pruned = entry
                    .get("payloadPruned")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if is_pruned {
                    db.write_tx(|tx| {
                        if let Some(mut c) = tx.get_conversation(cid)? {
                            c.last_seq = c.last_seq.max(entry_seq);
                            c.updated_at_ms = ts;
                            tx.upsert_conversation(&c)?;
                        }
                        Ok(())
                    })?;
                    max_seq = max_seq.max(entry_seq);
                    continue;
                }

                let msg_id = body
                    .get("messageId")
                    .or_else(|| entry.get("messageId"))
                    .or_else(|| entry.get("entryId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if msg_id.is_empty() {
                    max_seq = max_seq.max(entry_seq);
                    continue;
                }
                let existing_msgs = db.backend().list_messages(cid, None, 200)?;
                if existing_msgs.iter().any(|m| m.message_id == msg_id) {
                    db.write_tx(|tx| {
                        if let Some(mut c) = tx.get_conversation(cid)? {
                            c.last_seq = c.last_seq.max(entry_seq);
                            c.updated_at_ms = ts;
                            tx.upsert_conversation(&c)?;
                        }
                        Ok(())
                    })?;
                    max_seq = max_seq.max(entry_seq);
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
                let rcpt_val = entry.get("sequencerReceipt").ok_or_else(|| {
                    MLSError::Cryptography(format!(
                        "I13: applicationEntry seq={entry_seq} missing sequencerReceipt"
                    ))
                })?;
                let expected_rcpt_entry_id = rcpt_val
                    .get("entryId")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or(msg_id);
                let rcpt_sec1 = receipt_sec1_opt.as_deref().ok_or_else(|| {
                    MLSError::Cryptography(
                        "I13: sequencer receipt public key was not pre-resolved".into(),
                    )
                })?;

                db.write_tx(|tx| {
                    let Some(mut c) = tx.get_conversation(cid)? else {
                        return Ok(());
                    };
                    let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(tx))?;
                    let Some(mut group) =
                        MlsGroup::load(provider.storage(), &GroupId::from_slice(&c.group_id))
                            .map_err(|e| MLSError::Internal(format!("load group: {e:?}")))?
                    else {
                        return Ok(());
                    };
                    let msg_in = MlsMessageIn::tls_deserialize_exact(&ct_bytes).map_err(|e| {
                        MLSError::Cryptography(format!("deserialize app msg: {e:?}"))
                    })?;
                    let proto = msg_in
                        .try_into_protocol_message()
                        .map_err(|e| MLSError::Cryptography(format!("app protocol msg: {e:?}")))?;
                    let msg_epoch = proto.epoch().as_u64() as i64;
                    let processed = group
                        .process_message(&provider, proto)
                        .map_err(|e| MLSError::Cryptography(format!("decrypt app msg: {e:?}")))?;
                    let sender_cred = processed.credential().clone();
                    let aad_bytes = processed.aad().to_vec();
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
                    let ProcessedMessageContent::ApplicationMessage(app_msg) =
                        processed.into_content()
                    else {
                        return Err(MLSError::Cryptography("expected ApplicationMessage".into()));
                    };
                    let (_display_body, json_str, verified_commitment_opt) =
                        extract_plaintext_body_and_verify_aad(&app_msg.into_bytes(), &aad_bytes)?;
                    let verified_commitment = verified_commitment_opt.ok_or_else(|| {
                        MLSError::Cryptography(
                            "I13: applicationEntry missing verified AAD archiveCommitment".into(),
                        )
                    })?;
                    let (rcpt_seq, _, _) = chat_wire::parse_and_verify_i13_sequencer_receipt(
                        rcpt_val,
                        rcpt_sec1,
                        &c.sequencer_did,
                        cid,
                        &c.group_id,
                        msg_epoch.max(0) as u64,
                        expected_rcpt_entry_id,
                        &verified_commitment,
                    )?;
                    if rcpt_seq as i64 != entry_seq {
                        return Err(MLSError::Cryptography(format!(
                            "I13: receipt seq {rcpt_seq} != entry seq {entry_seq}"
                        )));
                    }

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
                    c.last_seq = c.last_seq.max(entry_seq);
                    if sender_did != self.account_did {
                        c.unread_count = c.unread_count.saturating_add(1);
                    }
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)
                })?;
                max_seq = max_seq.max(entry_seq);
                applied_count = applied_count.saturating_add(1);
                continue;
            }

            db.write_tx(|tx| {
                if let Some(mut c) = tx.get_conversation(cid)? {
                    c.last_seq = c.last_seq.max(entry_seq);
                    c.updated_at_ms = ts;
                    tx.upsert_conversation(&c)?;
                }
                Ok(())
            })?;
            max_seq = max_seq.max(entry_seq);
        }

        if saw_c33_accept {
            let _ = self.archive_accepted_opening_messages(cid).await;
        }
        if max_seq >= 1 && applied_count > 0 && !was_kicked {
            self.acknowledge_entries_up_to_impl(cid, max_seq).await?;
        }
        Ok(applied_count)
    }
}
