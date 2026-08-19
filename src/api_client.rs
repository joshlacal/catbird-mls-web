//! WasmApiClient -- implements MLSAPIClient for browser using reqwest (fetch-backed)
//!
//! Port of catmos/src-tauri/src/api_client.rs (ReqwestApiClient) for WASM.
//! reqwest with WASM features uses the browser fetch API under the hood.
//! Uses shared catbird-atproto types for request/response serialization.
//! Non-lexicon delivery status lookups intentionally degrade to a local fallback.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use catbird_atproto::blue_catbird;
use reqwest::Client;
use std::sync::RwLock;

use catbird_mls::orchestrator::api_client::MLSAPIClient;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;

// -- WasmApiClient ------------------------------------------------------------

pub const DEFAULT_ATPROTO_PROXY_DID: &str = "did:web:mlschat.catbird.blue#atproto_mls";

pub struct WasmApiClient {
    client: Client,
    base_url: String,
    auth_token: RwLock<Option<String>>,
    current_did: RwLock<Option<String>>,
}

impl WasmApiClient {
    pub fn new(base_url: String) -> Self {
        Self::with_proxy(base_url, DEFAULT_ATPROTO_PROXY_DID.to_string())
    }

    pub fn with_proxy(base_url: String, proxy_did: String) -> Self {
        let mut default_headers = reqwest::header::HeaderMap::new();
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&proxy_did) {
            default_headers.insert("atproto-proxy", value);
        }
        let client = Client::builder()
            .default_headers(default_headers)
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token: RwLock::new(None),
            current_did: RwLock::new(None),
        }
    }

    pub fn set_auth(&self, did: String, token: String) {
        *self.auth_token.write().unwrap() = Some(token);
        *self.current_did.write().unwrap() = Some(did);
    }

    pub fn clear_auth(&self) {
        *self.auth_token.write().unwrap() = None;
        *self.current_did.write().unwrap() = None;
    }

    pub fn get_auth_token(&self) -> Option<String> {
        self.auth_token.read().unwrap().clone()
    }

    fn xrpc_url(&self, nsid: &str) -> String {
        format!("{}/xrpc/{}", self.base_url, nsid)
    }

    fn auth_header(&self) -> Result<String> {
        self.auth_token
            .read()
            .unwrap()
            .clone()
            .ok_or(OrchestratorError::NotAuthenticated)
    }

    async fn handle_error(&self, resp: reqwest::Response) -> OrchestratorError {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        OrchestratorError::ServerError { status, body }
    }

    async fn send_message_request(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
        msg_id: &str,
    ) -> Result<SendMessageResponse> {
        let token = self.auth_header()?;
        let padded_size = ciphertext.len() as u32;
        let input = serde_json::json!({
            "convoId": convo_id,
            "ciphertext": { "$bytes": B64.encode(ciphertext) },
            "epoch": epoch,
            "msgId": msg_id,
            "paddedSize": padded_size,
        });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.sendMessage"))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            if status == 409 {
                tracing::error!(
                    convo_id,
                    client_epoch = epoch,
                    "409 Conflict: epoch mismatch — server has different epoch"
                );
            }
            return Err(self.handle_error(resp).await);
        }
        Ok(SendMessageResponse {
            message_id: msg_id.to_string(),
            seq: 0,
            epoch,
        })
    }

    /// Check opt-in status for a DID.
    pub async fn get_opt_in_status(&self, did: &str) -> Result<bool> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getDevices"))
            .bearer_auth(&token)
            .query(&[("dids", did)])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let devices = output.get("devices").and_then(|v| v.as_array());
        Ok(devices.map(|d| !d.is_empty()).unwrap_or(false))
    }

    /// Opt the current user into MLS chat.
    pub async fn opt_in(&self, device_id: Option<String>) -> Result<()> {
        let token = self.auth_header()?;
        let input = serde_json::json!({
            "action": "optIn",
            "deviceId": device_id.filter(|id| !id.trim().is_empty()),
        });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.enrollDevice"))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }

    /// Upload an encrypted group metadata blob keyed by a client-generated locator.
    pub async fn put_group_metadata_blob(
        &self,
        blob_locator: &str,
        group_id: &str,
        encrypted_blob: &[u8],
        metadata_version: Option<u64>,
        kind: Option<&str>,
    ) -> Result<(String, usize)> {
        let token = self.auth_header()?;
        let version_str = metadata_version.map(|v| v.to_string());
        let mut query: Vec<(&str, &str)> =
            vec![("blobLocator", blob_locator), ("groupId", group_id)];
        if let Some(ref v) = version_str {
            query.push(("metadataVersion", v.as_str()));
        }
        if let Some(k) = kind {
            query.push(("kind", k));
        }
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.uploadBlob"))
            .bearer_auth(&token)
            .query(&query)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(encrypted_blob.to_vec())
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let locator = output
            .get("blobLocator")
            .or_else(|| output.get("blobId"))
            .and_then(|v| v.as_str())
            .unwrap_or(blob_locator)
            .to_string();
        let size = output
            .get("size")
            .and_then(|v| v.as_u64())
            .map(|s| s as usize)
            .unwrap_or(encrypted_blob.len());

        Ok((locator, size))
    }

    /// Fetch an encrypted group metadata blob by locator.
    pub async fn get_group_metadata_blob(
        &self,
        blob_locator: &str,
        group_id: &str,
        metadata_version: Option<u64>,
        kind: Option<&str>,
    ) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let version_str = metadata_version.map(|v| v.to_string());
        let mut query: Vec<(&str, &str)> =
            vec![("blobLocator", blob_locator), ("groupId", group_id)];
        if let Some(ref v) = version_str {
            query.push(("metadataVersion", v.as_str()));
        }
        if let Some(k) = kind {
            query.push(("kind", k));
        }
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getBlob"))
            .bearer_auth(&token)
            .query(&query)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        Ok(body.to_vec())
    }

    /// Fetch the latest encrypted group metadata blob for a group.
    pub async fn get_latest_group_metadata_blob(&self, group_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getBlob"))
            .bearer_auth(&token)
            .query(&[("groupId", group_id)])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        Ok(body.to_vec())
    }

    /// Upload a generic opaque blob (file attachment, avatar, etc.).
    pub async fn upload_blob(&self, data: &[u8]) -> Result<(String, usize)> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.uploadBlob"))
            .bearer_auth(&token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let blob_id = output
            .get("blobId")
            .or_else(|| output.get("blobLocator"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let size = output
            .get("size")
            .and_then(|v| v.as_u64())
            .map(|s| s as usize)
            .unwrap_or(data.len());

        Ok((blob_id, size))
    }

    /// Fetch a generic opaque blob by blob ID.
    pub async fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getBlob"))
            .bearer_auth(&token)
            .query(&[("blobId", blob_id)])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        Ok(body.to_vec())
    }

    /// Send an `updateMetadata` commit to the server (MLS metadata cutover).
    pub async fn commit_update_metadata(
        &self,
        convo_id: &str,
        commit_data: &[u8],
    ) -> Result<(bool, u64)> {
        let token = self.auth_header()?;
        let input = serde_json::json!({
            "action": "updateMetadata",
            "convoId": convo_id,
            "commit": { "$bytes": B64.encode(commit_data) },
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
        });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.submitTransition"))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let new_epoch = output.get("newEpoch").and_then(|v| v.as_u64()).unwrap_or(0);
        let success = output.get("success").and_then(|v| v.as_bool()).unwrap_or(true);
        Ok((success, new_epoch))
    }
}

// -- MLSAPIClient impl --------------------------------------------------------

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MLSAPIClient for WasmApiClient {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        self.current_did.read().unwrap().as_deref() == Some(did)
    }

    async fn current_did(&self) -> Option<String> {
        self.current_did.read().unwrap().clone()
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        let token = self.auth_header()?;
        let mut query = vec![("limit", limit.to_string())];
        if let Some(c) = cursor {
            query.push(("pageCursor", c.to_string()));
        }

        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getConversations"))
            .bearer_auth(&token)
            .query(&query)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        let output: blue_catbird::chat::get_conversations::GetConversationsOutput<String> =
            serde_json::from_slice(&body)
                .map_err(|e| OrchestratorError::Api(format!("getConversations parse: {e}")))?;

        let mut conversations = Vec::new();
        for item in output.items {
            if let blue_catbird::chat::ConversationInventoryItem::ConversationInventoryState(state_item) = item {
                let s = state_item.state;
                let coords = s.coordinates;
                let members = s
                    .participants
                    .into_iter()
                    .map(|p| MemberView {
                        did: p.user_did.to_string(),
                        role: if p.role.eq_ignore_ascii_case("admin") {
                            MemberRole::Admin
                        } else {
                            MemberRole::Member
                        },
                    })
                    .collect();
                conversations.push(ConversationView {
                    group_id: hex::encode(coords.group_id.as_ref()),
                    conversation_id: coords.conversation_id.to_string(),
                    epoch: coords.epoch.max(0) as u64,
                    members,
                    metadata: None,
                    created_at: None,
                    updated_at: None,
                    sequencer_did: None,
                });
            }
        }

        Ok(ConversationListPage {
            conversations,
            cursor: output.next_page_cursor,
        })
    }

    async fn create_conversation(
        &self,
        group_id: &str,
        initial_members: Option<&[String]>,
        _metadata: Option<&ConversationMetadata>,
        _commit_data: Option<&[u8]>,
        welcome_data: Option<&[u8]>,
    ) -> Result<CreateConversationResult> {
        let token = self.auth_header()?;
        let mut req = serde_json::json!({
            "groupId": group_id,
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "members": initial_members.unwrap_or(&[]),
        });
        if let Some(welcome) = welcome_data {
            req["welcomeMessage"] = serde_json::json!({ "$bytes": B64.encode(welcome) });
        }

        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.createConversation"))
            .bearer_auth(&token)
            .json(&req)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: blue_catbird::chat::create_conversation::CreateConversationOutput<String> =
            serde_json::from_slice(&body)
                .map_err(|e| OrchestratorError::Api(format!("createConversation parse: {e}")))?;

        let (group_id, conversation_id, epoch) = match output.result {
            blue_catbird::chat::ConversationCreationResult::ConversationCreatedResult(res) => {
                let coords = res.coordinates;
                (
                    hex::encode(coords.group_id.as_ref()),
                    coords.conversation_id.to_string(),
                    coords.epoch.max(0) as u64,
                )
            }
            blue_catbird::chat::ConversationCreationResult::ExistingDirectConversationResult(res) => {
                let coords = res.coordinates;
                (
                    hex::encode(coords.group_id.as_ref()),
                    coords.conversation_id.to_string(),
                    coords.epoch.max(0) as u64,
                )
            }
        };

        Ok(CreateConversationResult {
            conversation: ConversationView {
                group_id,
                conversation_id,
                epoch,
                members: vec![],
                metadata: None,
                created_at: None,
                updated_at: None,
                sequencer_did: None,
            },
            commit_data: None,
            welcome_data: None,
        })
    }

    async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
        let token = self.auth_header()?;
        let input = serde_json::json!({
            "convoId": convo_id,
        });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.requestLeave"))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }

    async fn add_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
        welcome_data: Option<&[u8]>,
    ) -> Result<AddMembersServerResult> {
        let token = self.auth_header()?;
        let mut input = serde_json::json!({
            "action": "addMembers",
            "convoId": convo_id,
            "memberDids": member_dids,
            "commit": { "$bytes": B64.encode(commit_data) },
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
        });
        if let Some(welcome) = welcome_data {
            input["welcome"] = serde_json::json!({ "$bytes": B64.encode(welcome) });
        }
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.submitTransition"))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let success = output.get("success").and_then(|v| v.as_bool()).unwrap_or(true);
        let new_epoch = output.get("newEpoch").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(AddMembersServerResult {
            success,
            new_epoch,
            receipt: None,
        })
    }

    async fn remove_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
    ) -> Result<()> {
        let token = self.auth_header()?;
        for did in member_dids {
            let input = serde_json::json!({
                "convoId": convo_id,
                "commit": { "$bytes": B64.encode(commit_data) },
                "targetDid": did,
            });
            let resp = self
                .client
                .post(self.xrpc_url("blue.catbird.chat.requestLeave"))
                .bearer_auth(&token)
                .json(&input)
                .send()
                .await
                .map_err(|e| OrchestratorError::Api(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(self.handle_error(resp).await);
            }
        }
        Ok(())
    }

    async fn send_message(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
    ) -> Result<SendMessageResponse> {
        let msg_id = uuid::Uuid::new_v4().to_string();
        self.send_message_request(convo_id, ciphertext, epoch, &msg_id)
            .await
    }

    async fn send_message_with_id(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: u64,
        msg_id: &str,
    ) -> Result<SendMessageResponse> {
        self.send_message_request(convo_id, ciphertext, epoch, msg_id)
            .await
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        _message_type: Option<&str>,
        _from_epoch: Option<u32>,
        _to_epoch: Option<u32>,
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)> {
        let token = self.auth_header()?;
        let after_seq = cursor.and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
        let query = vec![
            ("conversationId", convo_id.to_string()),
            ("afterSeq", after_seq.to_string()),
            ("limit", limit.to_string()),
        ];
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getEntries"))
            .bearer_auth(&token)
            .query(&query)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let mut envelopes = Vec::new();
        if let Some(entries) = output.get("entries").and_then(|v| v.as_array()) {
            for entry in entries {
                let entry_id = entry.get("entryId").and_then(|v| v.as_str()).unwrap_or("");
                let epoch = entry.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);
                let ct_bytes = entry.get("ciphertext").and_then(|v| {
                    if let Some(s) = v.as_str() {
                        B64.decode(s).ok()
                    } else if let Some(b) = v.get("$bytes").and_then(|b| b.as_str()) {
                        B64.decode(b).ok()
                    } else {
                        None
                    }
                }).unwrap_or_default();
                envelopes.push(IncomingEnvelope {
                    conversation_id: convo_id.to_string(),
                    sender_did: String::new(),
                    ciphertext: ct_bytes,
                    timestamp: chrono::Utc::now(),
                    server_message_id: Some(entry_id.to_string()),
                    server_epoch: Some(epoch),
                });
            }
        }
        let next_cursor = output.get("nextAfterSeq").map(|v| v.to_string());
        Ok((envelopes, next_cursor))
    }

    async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
        device_id: Option<&str>,
    ) -> Result<()> {
        let token = self.auth_header()?;
        let body = serde_json::json!({
            "keyPackages": [{
                "cipherSuite": cipher_suite,
                "expiresAt": expires_at,
                "data": { "$bytes": B64.encode(key_package) },
            }],
            "deviceId": device_id,
        });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.replenishKeyPackages"))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }

    async fn get_key_packages(&self, dids: &[String]) -> Result<Vec<KeyPackageRef>> {
        let token = self.auth_header()?;
        let dids_str = dids.join(",");
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getKeyPackages"))
            .bearer_auth(&token)
            .query(&[("dids", dids_str.as_str())])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let kps = output.get("keyPackages").and_then(|v| v.as_array()).ok_or_else(|| {
            OrchestratorError::Api("missing keyPackages".into())
        })?;
        Ok(kps.iter().filter_map(|kp| {
            let did = kp.get("did").and_then(|v| v.as_str())?.to_string();
            let kp_data = kp.get("keyPackage").and_then(|v| {
                if let Some(s) = v.as_str() {
                    B64.decode(s).ok()
                } else if let Some(b) = v.get("$bytes").and_then(|b| b.as_str()) {
                    B64.decode(b).ok()
                } else {
                    None
                }
            })?;
            let hash = kp.get("keyPackageHash").and_then(|v| v.as_str()).map(str::to_string);
            let cipher_suite = kp.get("cipherSuite").and_then(|v| v.as_str()).unwrap_or("").to_string();
            Some(KeyPackageRef {
                did,
                key_package_data: kp_data,
                hash,
                cipher_suite,
            })
        }).collect())
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getDevices"))
            .bearer_auth(&token)
            .query(&[("include", "stats")])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let stats = output.get("stats").and_then(|v| v.as_object()).ok_or_else(|| {
            OrchestratorError::Api("missing stats in key package response".into())
        })?;
        let parse_u32 = |key: &str| -> u32 {
            stats.get(key).and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).unwrap_or(0) as u32
        };
        let available = parse_u32("available");
        let total = if parse_u32("total") > 0 { parse_u32("total") } else { parse_u32("published").max(available) };
        Ok(KeyPackageStats { available, total })
    }

    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        _device_id: &str,
    ) -> Result<KeyPackageSyncResult> {
        Ok(KeyPackageSyncResult {
            orphaned_count: 0,
            deleted_count: 0,
        })
    }

    async fn register_device(
        &self,
        device_uuid: &str,
        device_name: &str,
        _mls_did: &str,
        signature_key: &[u8],
        key_packages: &[Vec<u8>],
    ) -> Result<DeviceInfo> {
        let token = self.auth_header()?;
        let kp_items: Vec<serde_json::Value> = key_packages
            .iter()
            .map(|kp| {
                let expires_str = (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339();
                serde_json::json!({
                    "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                    "expiresAt": expires_str,
                    "data": { "$bytes": B64.encode(kp) },
                })
            })
            .collect();
        let input = serde_json::json!({
            "deviceUuid": device_uuid,
            "deviceName": device_name,
            "signaturePublicKey": { "$bytes": B64.encode(signature_key) },
            "keyPackages": kp_items,
        });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.enrollDevice"))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let device_id = output.get("deviceId").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let mls_did = output.get("mlsDid").or_else(|| output.get("credentialDid")).and_then(|v| v.as_str()).unwrap_or("").to_string();
        Ok(DeviceInfo {
            device_id,
            mls_did,
            device_uuid: device_uuid.to_string(),
            created_at: None,
        })
    }

    async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getDevices"))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let devices = output.get("devices").and_then(|v| v.as_array()).ok_or_else(|| {
            OrchestratorError::Api("missing devices in response".into())
        })?;
        Ok(devices.iter().map(|d| DeviceInfo {
            device_id: d.get("deviceId").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            mls_did: d.get("credentialDid").or_else(|| d.get("mlsDid")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
            device_uuid: d.get("deviceUuid").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            created_at: None,
        }).collect())
    }

    async fn remove_device(&self, device_id: &str) -> Result<()> {
        let token = self.auth_header()?;
        let body = serde_json::json!({
            "deviceId": device_id,
        });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.revokeDevice"))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }

    async fn publish_group_info(&self, convo_id: &str, group_info: &[u8]) -> Result<()> {
        let token = self.auth_header()?;
        let input = serde_json::json!({
            "action": "updateGroupInfo",
            "convoId": convo_id,
            "groupInfo": { "$bytes": B64.encode(group_info) },
        });
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.submitTransition"))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        Ok(())
    }

    async fn get_group_info(&self, convo_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getConversationState"))
            .bearer_auth(&token)
            .query(&[("conversationId", convo_id), ("include", "groupInfo,epoch")])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let bytes = output.get("groupInfo").and_then(|v| {
            if let Some(s) = v.as_str() {
                B64.decode(s).ok()
            } else if let Some(b) = v.get("$bytes").and_then(|b| b.as_str()) {
                B64.decode(b).ok()
            } else {
                None
            }
        }).ok_or_else(|| OrchestratorError::Api("missing groupInfo in group state".into()))?;
        Ok(bytes)
    }

    async fn get_welcome(&self, convo_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getConversationState"))
            .bearer_auth(&token)
            .query(&[("conversationId", convo_id), ("include", "welcome")])
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let bytes = output.get("welcome").and_then(|v| {
            if let Some(s) = v.as_str() {
                B64.decode(s).ok()
            } else if let Some(b) = v.get("$bytes").and_then(|b| b.as_str()) {
                B64.decode(b).ok()
            } else {
                None
            }
        }).ok_or_else(|| OrchestratorError::ServerError {
            status: 404,
            body: r#"{"error":"NotFound","message":"No welcome available"}"#.to_string(),
        })?;
        Ok(bytes)
    }

    async fn get_delivery_status(
        &self,
        convo_id: &str,
        message_ids: &[String],
    ) -> Result<Vec<(String, DeliveryStatus)>> {
        let _ = (convo_id, message_ids);
        Ok(vec![])
    }

    async fn report_recovery_failure(
        &self,
        convo_id: &str,
        failure_type: &str,
        epoch_authenticator: Option<&str>,
        failure_mode: Option<&str>,
    ) -> Result<()> {
        let token = self.auth_header()?;

        let mut body = serde_json::json!({
            "convoId": convo_id,
            "failureType": failure_type,
        });
        if let Some(auth) = epoch_authenticator {
            body["epochAuthenticator"] = serde_json::Value::String(auth.to_string());
        }
        if let Some(mode) = failure_mode {
            body["failureMode"] = serde_json::Value::String(mode.to_string());
        }

        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.requestLeafRecovery"))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }

        let status_code = status.as_u16();
        let body_text = resp.text().await.unwrap_or_default();

        if status_code == 403 {
            tracing::info!(
                convo_id,
                failure_type,
                body = %body_text,
                "report_recovery_failure: 403 (stale membership) — ignoring"
            );
            return Ok(());
        }

        tracing::warn!(
            convo_id,
            failure_type,
            status = status_code,
            body = %body_text,
            "report_recovery_failure: server rejected report"
        );
        Err(OrchestratorError::ServerError {
            status: status_code,
            body: body_text,
        })
    }

    async fn process_external_commit(
        &self,
        convo_id: &str,
        commit_data: &[u8],
        group_info: Option<&[u8]>,
        confirmation_tag: Option<&str>,
    ) -> Result<ProcessExternalCommitResult> {
        let token = self.auth_header()?;
        let mut input = serde_json::json!({
            "action": "externalCommit",
            "convoId": convo_id,
            "commit": { "$bytes": B64.encode(commit_data) },
            "idempotencyKey": uuid::Uuid::new_v4().to_string(),
        });
        if let Some(gi) = group_info {
            input["groupInfo"] = serde_json::json!({ "$bytes": B64.encode(gi) });
        }
        if let Some(tag) = confirmation_tag {
            input["confirmationTag"] = serde_json::json!(tag);
        }
        let resp = self
            .client
            .post(self.xrpc_url("blue.catbird.chat.submitTransition"))
            .bearer_auth(&token)
            .json(&input)
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(self.handle_error(resp).await);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let output: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let new_epoch = output.get("newEpoch").and_then(|v| v.as_u64()).unwrap_or(0);
        let rejoined_at = output.get("rejoinedAt").and_then(|v| v.as_str()).unwrap_or("").to_string();
        Ok(ProcessExternalCommitResult {
            epoch: new_epoch,
            rejoined_at: if rejoined_at.is_empty() {
                chrono::Utc::now().to_rfc3339()
            } else {
                rejoined_at
            },
            receipt: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_api_client_can_construct() {
        let client = WasmApiClient::new("http://localhost:8080".to_string());
        assert_eq!(client.base_url, "http://localhost:8080");
    }
}
