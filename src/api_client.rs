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

pub const DEFAULT_ATPROTO_PROXY_DID: &str = "did:web:chat.catbird.blue#atproto_mls";

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

    async fn submit_prepared_request(
        &self,
        request: catbird_mls::orchestrator::canonical_transport::PreparedRequest,
    ) -> Result<catbird_mls::orchestrator::canonical_transport::GatewayResponse> {
        let token = self.auth_header()?;
        let url = format!("{}{}", self.base_url, request.path);
        let mut builder = match request.method.as_str() {
            "POST" => self.client.post(&url),
            "GET" => self.client.get(&url),
            "PUT" => self.client.put(&url),
            "DELETE" => self.client.delete(&url),
            _ => self.client.post(&url),
        };
        builder = builder.bearer_auth(&token);
        if let Some(body) = request.body {
            builder = builder
                .body(body)
                .header(reqwest::header::CONTENT_TYPE, "application/json");
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);

        let body = resp
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?
            .to_vec();

        Ok(catbird_mls::orchestrator::canonical_transport::GatewayResponse {
            status,
            content_type,
            body,
        })
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

    async fn get_key_packages(
        &self,
        actor_device_id: &str,
        dids: &[String],
    ) -> Result<Vec<KeyPackageRef>> {
        let token = self.auth_header()?;
        let mut query: Vec<(&str, &str)> = vec![("actorDeviceId", actor_device_id)];
        for did in dids {
            query.push(("userDids", did.as_str()));
        }
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getDevices"))
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
        let output: blue_catbird::chat::get_devices::GetDevicesOutput<String> =
            serde_json::from_slice(&body)
                .map_err(|e| OrchestratorError::Api(format!("getDevices parse: {e}")))?;
        Ok(output
            .devices
            .iter()
            .map(|kp| KeyPackageRef {
                did: kp.user_did.to_string(),
                key_package_data: vec![],
                hash: Some(kp.key_id.to_string()),
                cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
            })
            .collect())
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getOwnDevices"))
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
        let output: blue_catbird::chat::get_own_devices::GetOwnDevicesOutput<String> =
            serde_json::from_slice(&body)
                .map_err(|e| OrchestratorError::Api(format!("getOwnDevices parse: {e}")))?;
        let available: u32 = output
            .items
            .iter()
            .map(|item| item.device.available_package_count.max(0) as u32)
            .sum();
        Ok(KeyPackageStats {
            available,
            total: available,
        })
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

    async fn list_devices(&self, _actor_device_id: &str) -> Result<Vec<DeviceInfo>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getOwnDevices"))
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
        let output: blue_catbird::chat::get_own_devices::GetOwnDevicesOutput<String> =
            serde_json::from_slice(&body)
                .map_err(|e| OrchestratorError::Api(format!("getOwnDevices parse: {e}")))?;
        let current_did = self.current_did().await.unwrap_or_default();
        Ok(output
            .items
            .iter()
            .map(|d| DeviceInfo {
                device_id: d.device.device_id.to_string(),
                mls_did: current_did.clone(),
                device_uuid: d.device.key_id.to_string(),
                created_at: None,
            })
            .collect())
    }

    async fn get_group_info(&self, convo_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getConversationState"))
            .bearer_auth(&token)
            .query(&[("conversationId", convo_id)])
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
        let output: blue_catbird::chat::get_conversation_state::GetConversationStateOutput<String> =
            serde_json::from_slice(&body)
                .map_err(|e| OrchestratorError::Api(format!("getConversationState parse: {e}")))?;
        Ok(output.state.coordinates.group_id.as_ref().to_vec())
    }

    async fn get_welcome(&self, _convo_id: &str) -> Result<Vec<u8>> {
        Err(OrchestratorError::ServerError {
            status: 404,
            body: r#"{"error":"NotFound","message":"No welcome available"}"#.to_string(),
        })
    }

    async fn get_delivery_status(
        &self,
        _convo_id: &str,
        _message_ids: &[String],
    ) -> Result<Vec<(String, DeliveryStatus)>> {
        Ok(vec![])
    }

    async fn get_group_metadata_blob(
        &self,
        _convo_id: &str,
        _group_id_hex: &str,
        blob_locator: &str,
    ) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let url = format!("{}/xrpc/blue.catbird.chat.getBlob?blobId={}", self.base_url, urlencoding::encode(blob_locator));
        let resp = self
            .client
            .get(&url)
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
        Ok(body.to_vec())
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
