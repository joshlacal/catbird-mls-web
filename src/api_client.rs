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
    actor_device: RwLock<Option<String>>,
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
            actor_device: RwLock::new(None),
        }
    }

    pub fn set_auth(&self, did: String, token: String) {
        if self.current_did.read().unwrap().as_deref()!=Some(&did){*self.actor_device.write().unwrap()=None;}
        *self.auth_token.write().unwrap() = Some(token);
        *self.current_did.write().unwrap() = Some(did);
    }

    pub fn clear_auth(&self) {
        *self.actor_device.write().unwrap()=None;
        *self.auth_token.write().unwrap() = None;
        *self.current_did.write().unwrap() = None;
    }

    pub(crate) fn bind_actor(&self,owner:&str,device:&str)->Result<()> {
        if self.current_did.read().unwrap().as_deref()!=Some(owner){return Err(OrchestratorError::NotAuthenticated);}
        catbird_mls::chat_v2::ids::CanonicalUuid::parse(device).map_err(|e|OrchestratorError::Api(e.to_string()))?;
        *self.actor_device.write().unwrap()=Some(device.to_owned());Ok(())
    }
    pub(crate) fn actor_device(&self)->Result<String>{self.actor_device.read().unwrap().clone().ok_or_else(||OrchestratorError::Api("Enrolled actor device is unavailable".into()))}
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
        let output: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| OrchestratorError::Api(e.to_string()))?;
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
        let output: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| OrchestratorError::Api(e.to_string()))?;
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
        let output: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| OrchestratorError::Api(e.to_string()))?;
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
        let output: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let new_epoch = output.get("newEpoch").and_then(|v| v.as_u64()).unwrap_or(0);
        let success = output
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
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

        Ok(
            catbird_mls::orchestrator::canonical_transport::GatewayResponse {
                status,
                content_type,
                body,
            },
        )
    }

    async fn get_conversations(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        let token = self.auth_header()?;
        let mut query = vec![("actorDeviceId",self.actor_device()?),("limit", limit.to_string()),("supportedProtocolVersions","1".into()),("supportedProtocolVersions","2".into())];
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

        let output = catbird_mls::orchestrator::canonical_transport::decode_conversations_inventory(&body)
            .map_err(|error| OrchestratorError::Api(format!("Canonical getConversations decode: {error}")))?;

        if output.has_more != output.next_page_cursor.is_some() {return Err(OrchestratorError::Api("Conversation pagination is incomplete".into()));}
        let wire:serde_json::Value=serde_json::from_slice(&body).map_err(|e|OrchestratorError::Api(e.to_string()))?;
        if wire["inventoryScope"]["supportedProtocolVersions"]!=serde_json::json!(["1","2"]){return Err(OrchestratorError::Api("Conversation protocol scope mismatch".into()));}
        let mut conversations = Vec::new();
        for item in output.items {
            if let blue_catbird::chat::ConversationInventoryItem::ConversationInventoryState(
                state_item,
            ) = item
            {
                conversations.push(canonical_conversation_view(&state_item.state));
            }
        }

        Ok(ConversationListPage {
            conversations,
            cursor: output.next_page_cursor.map(|value| value.to_string()),
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
        let after_seq = cursor.map(|v| v.parse::<u64>().map_err(|_|OrchestratorError::Api("Invalid entry cursor".into()))).transpose()?.unwrap_or(0);
        let query = vec![
            ("actorDeviceId", self.actor_device()?),
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
        if body.len()>16*1024*1024 { return Err(OrchestratorError::Api("Entry page exceeds bound".into())); }
        catbird_mls::chat_v2::transcript::decode_strict_json(&body).map_err(|e|OrchestratorError::Api(e.to_string()))?;
        let output:serde_json::Value=serde_json::from_slice(&body).map_err(|e|OrchestratorError::Api(e.to_string()))?;
        let entries=output["entries"].as_array().filter(|e|e.len()<=limit as usize).ok_or_else(||OrchestratorError::Api("Invalid entries page".into()))?;
        let mut envelopes=Vec::new();let mut greatest=after_seq;
        for entry in entries {
            let seq=entry["seq"].as_u64().filter(|n|*n>greatest && *n<=9_007_199_254_740_991).ok_or_else(||OrchestratorError::Api("Nonmonotonic entry sequence".into()))?;
            if entry["conversationId"]!=convo_id{return Err(OrchestratorError::Api("Foreign conversation entry".into()));}
            crate::strict_projection::validate_read_shape("conversationEntry",&serde_json::to_vec(entry).map_err(|e|OrchestratorError::Api(e.to_string()))?).map_err(|e|OrchestratorError::Api(e.to_string()))?;
            if let Some(envelope)=IncomingEnvelope::from_canonical_entry(entry,convo_id)?{envelopes.push(envelope);}
            greatest=seq;
        }
        if output["nextAfterSeq"].as_u64()!=Some(greatest){return Err(OrchestratorError::Api("Entry continuation mismatch".into()));}
        let next_cursor=(greatest>after_seq).then(||greatest.to_string());
        Ok((envelopes,next_cursor))
    }

    async fn get_key_packages(
        &self,
        _actor_device_id: &str,
        _dids: &[String],
    ) -> Result<Vec<KeyPackageRef>> {
        // getDevices is an inventory of device identities, not an authorized
        // package reservation. Never manufacture empty packages or treat a
        // device key ID as an MLS KeyPackage reference.
        Err(OrchestratorError::Api(
            "browser key-package acquisition requires an authorized preparation; legacy getDevices cannot supply packages".into(),
        ))
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let actor=self.actor_device()?;
        let device=self.list_devices(&actor).await?.into_iter().find(|d|d.device_id==actor && d.status.as_deref()==Some("enabled"))
            .ok_or_else(||OrchestratorError::Api("Current enrolled device is unavailable".into()))?;
        let available=device.available_package_count.ok_or_else(||OrchestratorError::Api("Missing device package inventory".into()))?;
        Ok(KeyPackageStats{available,total:available.saturating_add(device.reserved_package_count.unwrap_or(0))})
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

    async fn list_devices(&self, actor_device_id: &str) -> Result<Vec<DeviceInfo>> {
        let token=self.auth_header()?;
        let current_did=self.current_did().await.ok_or(OrchestratorError::NotAuthenticated)?;
        let mut items=Vec::new();let mut cursor=None;let mut seen=std::collections::HashSet::new();let mut seen_cursors=std::collections::HashSet::new();
        for _ in 0..100 {
            let mut query=vec![("actorDeviceId",actor_device_id.to_owned()),("limit","100".into())];
            if let Some(c)=cursor.take(){query.push(("pageCursor",c));}
            let resp=self.client.get(self.xrpc_url("blue.catbird.chat.getOwnDevices")).bearer_auth(&token).query(&query).send().await.map_err(|e|OrchestratorError::Api(e.to_string()))?;
            if !resp.status().is_success(){return Err(self.handle_error(resp).await);}
            let body=resp.bytes().await.map_err(|e|OrchestratorError::Api(e.to_string()))?;
            let output:blue_catbird::chat::get_own_devices::GetOwnDevicesOutput<String>=serde_json::from_slice(&body).map_err(|e|OrchestratorError::Api(format!("getOwnDevices parse: {e}")))?;
            for d in output.items {
                let device_id=d.device.device_id.to_string();
                if !seen.insert(device_id.clone()){return Err(OrchestratorError::Api("Repeated own-device entry".into()));}
                items.push(DeviceInfo {mls_did:format!("{current_did}#{device_id}"),device_uuid:device_id.clone(),device_id,created_at:None,key_id:Some(d.device.key_id.to_string()),signature_public_key:Some(d.device.signature_public_key.to_vec()),auth_generation:Some(d.device.auth_generation),status:Some(d.device.status.to_string()),available_package_count:Some(d.device.available_package_count.max(0) as u32),reserved_package_count:Some(d.device.reserved_package_count.max(0) as u32)});
            }
            if !self.is_authenticated_as(&current_did).await{return Err(OrchestratorError::NotAuthenticated);}
            match (output.has_more,output.next_page_cursor) {
                (false,None)=>return Ok(items),
                (true,Some(c)) if seen_cursors.insert(c.to_string())=>cursor=Some(c.to_string()),
                _=>return Err(OrchestratorError::Api("Own-device inventory cursor is inconsistent".into()))
            }
        }
        Err(OrchestratorError::Api("Own-device inventory page bound exceeded".into()))
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
        let resp = self
            .client
            .get(self.xrpc_url("blue.catbird.chat.getBlob"))
            .query(&[("blobId", blob_locator)])
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

fn canonical_conversation_view(
    state: &catbird_atproto::blue_catbird::chat::ConversationState,
) -> ConversationView {
    ConversationView {
        canonical_state: Some(state.clone()),
        group_id: hex::encode(state.coordinates.group_id.as_ref()),
        conversation_id: state.coordinates.conversation_id.to_string(),
        epoch: state.coordinates.epoch as u64,
        members: state.participants.iter().map(|participant| MemberView {
            did: participant.user_did.to_string(),
            role: if participant.role == "admin" { MemberRole::Admin } else { MemberRole::Member },
        }).collect(),
        metadata: None,
        created_at: None,
        updated_at: None,
        sequencer_did: None,
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

#[cfg(test)]
mod canonical_admission_projection_tests {
    use super::*;
    use catbird_mls::orchestrator::canonical_transport::{decode_conversation_state, encode_conversation_state, decode_conversations_inventory};

    fn inventory(wire: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "items": [{"$type": "blue.catbird.chat.defs#conversationInventoryState", "state": wire}],
            "hasMore": true, "nextPageCursor": "page-2", "inventorySessionId": "inventory-session",
            "snapshotEventCursor": "event-fence", "snapshotExpiresAt": "2026-09-05T12:00:00.000Z"
        })).unwrap()
    }


    #[test]
    fn canonical_pending_and_accepted_leafless_views_keep_exact_snapshot() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/canonical-conversation-state.json")).unwrap();
        for (status, version) in [("pending", 41), ("active", 42)] {
            let mut wire = fixture.clone();
            wire["participants"][1]["status"] = serde_json::json!(status);
            wire["coordinates"]["stateVersion"] = serde_json::json!(version);
            wire["snapshotSeq"] = serde_json::json!(version + 4);
            let expected = decode_conversation_state(wire.to_string().as_bytes()).unwrap();
            let mut page = decode_conversations_inventory(&inventory(wire)).unwrap();
            assert_eq!(page.next_page_cursor.as_deref(), Some("page-2"));
            assert_eq!(page.inventory_session_id, "inventory-session");
            assert_eq!(page.snapshot_event_cursor, "event-fence");
            let catbird_atproto::blue_catbird::chat::ConversationInventoryItem::ConversationInventoryState(item) = page.items.remove(0) else { panic!("missing canonical state") };
            let state = item.state;
            assert_eq!(state, expected);
            let view = canonical_conversation_view(&state);
            assert_eq!(view.canonical_state.as_ref(), Some(&state));
            assert_eq!(view.epoch, state.coordinates.epoch as u64);
            assert_eq!(view.group_id, hex::encode(state.coordinates.group_id.as_ref()));
            let persisted: ConversationView = serde_json::from_slice(&serde_json::to_vec(&view).unwrap()).unwrap();
            let retained = persisted.canonical_state.unwrap();
            assert_eq!(decode_conversation_state(&encode_conversation_state(&retained).unwrap()).unwrap(), state);
            assert_eq!(retained.participants[1].status, status);
            assert_eq!(retained.participants[1].leaf_count, 0);
            assert_eq!(retained.participants[1].invitation_provenance, state.participants[1].invitation_provenance);
            assert!(view.created_at.is_none());
            assert!(view.metadata.is_none());
        }
    }

    #[test]
    fn legacy_view_is_unknown_and_malformed_canonical_state_is_rejected() {
        let mut wire: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/canonical-conversation-state.json")).unwrap();
        let state = decode_conversation_state(wire.to_string().as_bytes()).unwrap();
        let view = canonical_conversation_view(&state);
        let mut old_view = serde_json::to_value(view).unwrap();
        assert!(old_view.as_object_mut().unwrap().remove("canonicalState").is_some());
        let legacy: ConversationView = serde_json::from_value(old_view).unwrap();
        assert!(legacy.canonical_state.is_none());
        wire["participants"][1]["status"] = serde_json::json!("unknown");
        assert!(decode_conversations_inventory(&inventory(wire)).is_err());
    }
}
