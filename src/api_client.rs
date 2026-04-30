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
use catbird_atproto::jacquard_common::IntoStatic;
use reqwest::Client;
use std::sync::RwLock;

use catbird_atproto::blue_catbird::mlsChat::commit_group_change::CommitGroupChange;
use catbird_atproto::catbird::mls_chat as lexicon;
use catbird_atproto::types::string::{Datetime, Did};
use catbird_mls::orchestrator::api_client::MLSAPIClient;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;

fn parse_did(s: &str) -> Did<'static> {
    Did::new_owned(s.to_string()).unwrap_or_else(|_| panic!("invalid DID: {}", s))
}

fn parse_lexicon_json<'de, T>(body: &'de [u8]) -> Result<T::Output>
where
    T: serde::Deserialize<'de> + IntoStatic,
{
    let parsed: T =
        serde_json::from_slice(body).map_err(|e| OrchestratorError::Api(e.to_string()))?;
    Ok(parsed.into_static())
}

// -- Helper parsers (ported from ReqwestApiClient) ----------------------------

fn decode_hex_bytes(input: &str) -> std::result::Result<Vec<u8>, String> {
    let trimmed = input.trim_start_matches("0x").trim_start_matches("0X");
    if trimmed.len() % 2 != 0 {
        return Err("hex string length must be even".to_string());
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let chars: Vec<char> = trimmed.chars().collect();
    for idx in (0..chars.len()).step_by(2) {
        let pair: String = [chars[idx], chars[idx + 1]].iter().collect();
        let byte = u8::from_str_radix(&pair, 16)
            .map_err(|_| format!("invalid hex byte at position {}", idx))?;
        out.push(byte);
    }
    Ok(out)
}

fn parse_receipt_bytes_data(
    field: &str,
    value: &catbird_atproto::jacquard_common::types::value::Data<'_>,
) -> std::result::Result<Vec<u8>, String> {
    use catbird_atproto::jacquard_common::types::value::Data;

    match value {
        Data::Bytes(bytes) => Ok(bytes.to_vec()),
        Data::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (idx, item) in items.iter().enumerate() {
                let n = item
                    .as_integer()
                    .ok_or_else(|| format!("{field}[{idx}] is not an integer"))?;
                let byte =
                    u8::try_from(n).map_err(|_| format!("{field}[{idx}] is out of byte range"))?;
                out.push(byte);
            }
            Ok(out)
        }
        _ => {
            if let Some(encoded) = value.as_str() {
                if let Ok(decoded) = B64.decode(encoded) {
                    return Ok(decoded);
                }
                if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE.decode(encoded) {
                    return Ok(decoded);
                }
                if let Ok(decoded) =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)
                {
                    return Ok(decoded);
                }
                if let Ok(decoded) = decode_hex_bytes(encoded) {
                    return Ok(decoded);
                }
                return Err(format!(
                    "{field} was a string but not valid base64/base64url/hex"
                ));
            }
            Err(format!(
                "{field} must be bytes, an array of integers, or an encoded string"
            ))
        }
    }
}

fn parse_sequencer_receipt_data(
    value: &catbird_atproto::jacquard_common::types::value::Data<'_>,
) -> std::result::Result<SequencerReceipt, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "receipt is not an ATProto object".to_string())?;

    let convo_id = object
        .get("convo_id")
        .or_else(|| object.get("convoId"))
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| "missing convo_id/convoId".to_string())?;
    let epoch = object
        .get("epoch")
        .and_then(|value| value.as_integer())
        .ok_or_else(|| "missing epoch".to_string())
        .and_then(|value| i32::try_from(value).map_err(|_| "epoch out of i32 range".to_string()))?;
    let commit_hash = parse_receipt_bytes_data(
        "commit_hash",
        object
            .get("commit_hash")
            .or_else(|| object.get("commitHash"))
            .ok_or_else(|| "missing commit_hash/commitHash".to_string())?,
    )?;
    let sequencer_did = object
        .get("sequencer_did")
        .or_else(|| object.get("sequencerDid"))
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| "missing sequencer_did/sequencerDid".to_string())?;
    let issued_at = object
        .get("issued_at")
        .or_else(|| object.get("issuedAt"))
        .and_then(|value| value.as_integer())
        .ok_or_else(|| "missing issued_at/issuedAt".to_string())?;
    let signature = parse_receipt_bytes_data(
        "signature",
        object
            .get("signature")
            .ok_or_else(|| "missing signature".to_string())?,
    )?;

    Ok(SequencerReceipt {
        convo_id,
        epoch,
        commit_hash,
        sequencer_did,
        issued_at,
        signature,
    })
}

fn parse_commit_group_change_receipt(
    output: &lexicon::commit_group_change::Output,
    op: &str,
) -> Option<SequencerReceipt> {
    let receipt = output.extra_data.as_ref().and_then(|extra| {
        extra.get("receipt").or_else(|| {
            extra
                .values()
                .find_map(|value| value.as_object().and_then(|object| object.get("receipt")))
        })
    });

    let receipt = match receipt {
        Some(value) => value,
        None => return None,
    };

    match parse_sequencer_receipt_data(receipt) {
        Ok(receipt) => Some(receipt),
        Err(error) => {
            tracing::warn!(
                operation = op,
                error = %error,
                "Failed to parse sequencer receipt; continuing without receipt"
            );
            None
        }
    }
}

/// Convert a lexicon ConvoView to an orchestrator ConversationView.
fn parse_conversation(c: &lexicon::defs::ConvoView) -> ConversationView {
    ConversationView {
        group_id: c.group_id.to_string(),
        conversation_id: c.conversation_id.to_string(),
        epoch: c.epoch as u64,
        members: c
            .members
            .iter()
            .map(|m| MemberView {
                did: m.user_did.as_str().to_string(),
                role: if m.is_admin {
                    MemberRole::Admin
                } else {
                    MemberRole::Member
                },
            })
            .collect(),
        metadata: c.metadata.as_ref().map(|m| ConversationMetadata {
            name: m.name.as_ref().map(|name| name.to_string()),
            description: m
                .description
                .as_ref()
                .map(|description| description.to_string()),
            avatar_url: None,
        }),
        created_at: Some(c.created_at.as_ref().with_timezone(&chrono::Utc)),
        updated_at: None,
    }
}

/// Build a `CommitGroupChange<'static>` for the wire **without** going through
/// the buggy `InputData → Input` adapter in `catbird-atproto`.
///
/// Why not use `catbird_atproto::catbird::mls_chat::commit_group_change::InputData`?
/// That adapter types `commit` / `welcome` / `group_info` / `confirmation_tag`
/// as `Option<String>`, and its `From<InputData> for Input` impl maps them via
/// `String → bytes::Bytes`. `bytes::Bytes::from(String)` takes the UTF-8 bytes
/// of the string verbatim — so when callers pass a pre-base64 string, the
/// bytes field ends up containing the ASCII of the base64 text and the
/// jacquard serializer then wraps it as `{"$bytes": base64(ASCII-base64)}`,
/// producing double-encoded commits the server rejects or silently mis-decodes.
/// Building the lexicon struct directly lets us pass raw
/// `bytes::Bytes::from(Vec<u8>)` so the single serializer layer does the one
/// correct base64 encode.
///
/// Mirrors the fix shipped in catmos-cli (commit `1ecf9e4`) for the same
/// class of bug.
#[allow(clippy::too_many_arguments)]
fn build_commit_group_change(
    convo_id: &str,
    action: &str,
    commit: Option<Vec<u8>>,
    welcome: Option<Vec<u8>>,
    group_info: Option<Vec<u8>>,
    confirmation_tag: Option<Vec<u8>>,
    member_dids: Option<Vec<String>>,
    idempotency_key: Option<String>,
) -> CommitGroupChange<'static> {
    CommitGroupChange {
        convo_id: convo_id.to_string().into(),
        action: action.to_string().into(),
        commit: commit.map(bytes::Bytes::from),
        welcome: welcome.map(bytes::Bytes::from),
        group_info: group_info.map(bytes::Bytes::from),
        confirmation_tag: confirmation_tag.map(bytes::Bytes::from),
        member_dids: member_dids.map(|dids| dids.iter().map(|d| parse_did(d)).collect()),
        idempotency_key: idempotency_key.map(Into::into),
        ..Default::default()
    }
}

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
        // TODO(A7/§5.5): populate confirmation_tag with real MLS state when the
        // pyramid wiring task (#15 / #18) lands. Currently stubbed to None so the
        // WASM wrapper compiles against the post-A7 lexicon surface.
        let input: lexicon::send_message::Input = lexicon::send_message::InputData {
            convo_id: convo_id.to_string(),
            ciphertext: ciphertext.to_vec(),
            confirmation_tag: None,
            epoch: epoch as usize,
            msg_id: msg_id.to_string(),
            padded_size: i64::from(padded_size),
            delivery: None,
        }
        .into();
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::send_message::NSID))
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
        let did = parse_did(did);
        let input: lexicon::get_opt_in_status::Input = lexicon::get_opt_in_status::InputData {
            dids: vec![did.clone()],
        }
        .into();
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::get_opt_in_status::NSID))
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
        let output =
            parse_lexicon_json::<blue_catbird::mlsChat::opt_in::OptInOutput<'_>>(body.as_ref())?;
        let statuses = output.statuses.unwrap_or_default();
        Ok(statuses
            .iter()
            .any(|s| s.did.as_str() == did.as_str() && s.opted_in))
    }

    /// Opt the current user into MLS chat.
    pub async fn opt_in(&self, device_id: Option<String>) -> Result<()> {
        let token = self.auth_header()?;
        let input: lexicon::opt_in::Input = lexicon::opt_in::InputData {
            action: "optIn".into(),
            allow_followers_bypass: None,
            allow_following_bypass: None,
            auto_expire_days: None,
            device_id: device_id.filter(|id| !id.trim().is_empty()).map(Into::into),
            dids: None,
        }
        .into();
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::opt_in::NSID))
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
    ///
    /// Optional `metadata_version` and `kind` query params let the server bind
    /// the upload to a specific epoch/version (so concurrent committers don't
    /// clobber each other) and distinguish metadata blobs from avatar blobs
    /// (`kind = "avatar"` mirrors the iOS contract).
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
        let mut query: Vec<(&str, &str)> = vec![
            ("blobLocator", blob_locator),
            ("groupId", group_id),
        ];
        if let Some(ref v) = version_str {
            query.push(("metadataVersion", v.as_str()));
        }
        if let Some(k) = kind {
            query.push(("kind", k));
        }
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::put_group_metadata_blob::NSID))
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::put_group_metadata_blob::PutGroupMetadataBlobOutput<'_>,
        >(body.as_ref())?;
        let size = usize::try_from(output.size)
            .map_err(|_| OrchestratorError::Api("metadata blob size out of range".into()))?;

        Ok((output.blob_locator.to_string(), size))
    }

    /// Fetch an encrypted group metadata blob by locator.
    ///
    /// Optional `metadata_version` and `kind` mirror the iOS contract.
    pub async fn get_group_metadata_blob(
        &self,
        blob_locator: &str,
        group_id: &str,
        metadata_version: Option<u64>,
        kind: Option<&str>,
    ) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let version_str = metadata_version.map(|v| v.to_string());
        let mut query: Vec<(&str, &str)> = vec![
            ("blobLocator", blob_locator),
            ("groupId", group_id),
        ];
        if let Some(ref v) = version_str {
            query.push(("metadataVersion", v.as_str()));
        }
        if let Some(k) = kind {
            query.push(("kind", k));
        }
        let resp = self
            .client
            .get(self.xrpc_url(lexicon::get_group_metadata_blob::NSID))
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
            .get(self.xrpc_url(lexicon::get_group_metadata_blob::NSID))
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

    /// Upload a generic opaque blob. The server assigns the final blob ID.
    pub async fn upload_blob(&self, data: &[u8]) -> Result<(String, usize)> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::upload_blob::NSID))
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
        let output = parse_lexicon_json::<blue_catbird::mlsChat::upload_blob::UploadBlobOutput<'_>>(
            body.as_ref(),
        )?;
        let size = usize::try_from(output.size)
            .map_err(|_| OrchestratorError::Api("blob size out of range".into()))?;

        Ok((output.blob_id.to_string(), size))
    }

    /// Fetch a generic opaque blob by blob ID.
    pub async fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url(lexicon::get_blob::NSID))
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
    ///
    /// Mirrors `add_members` in the trait impl below: uses
    /// `build_commit_group_change` directly with `action = "updateMetadata"`
    /// to avoid the `String → bytes::Bytes` UTF-8 double-encoding bug from
    /// the catbird-atproto adapter.
    ///
    /// Returns `(success, new_epoch)` so callers can decide whether to merge
    /// the local pending commit, clear it, or surface an error.
    pub async fn commit_update_metadata(
        &self,
        convo_id: &str,
        commit_data: &[u8],
    ) -> Result<(bool, u64)> {
        let token = self.auth_header()?;
        let input = build_commit_group_change(
            convo_id,
            "updateMetadata",
            Some(commit_data.to_vec()),
            None, // no welcome
            None, // no group_info
            None, // confirmation_tag stubbed (TODO A7)
            None, // no member_dids change
            Some(uuid::Uuid::new_v4().to_string()),
        );
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::commit_group_change::NSID))
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::commit_group_change::CommitGroupChangeOutput<'_>,
        >(body.as_ref())?;
        let new_epoch = output
            .new_epoch
            .and_then(|epoch| u64::try_from(epoch).ok())
            .unwrap_or(0);
        Ok((output.success, new_epoch))
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
        let mut url = format!(
            "{}?limit={}",
            self.xrpc_url(lexicon::get_convos::NSID),
            limit
        );
        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={}", c));
        }

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
        let output = parse_lexicon_json::<blue_catbird::mlsChat::get_convos::GetConvosOutput<'_>>(
            body.as_ref(),
        )?;
        let conversations = output
            .conversations
            .iter()
            .map(parse_conversation)
            .collect();

        Ok(ConversationListPage {
            conversations,
            cursor: output.cursor.as_ref().map(|cursor| cursor.to_string()),
        })
    }

    async fn create_conversation(
        &self,
        group_id: &str,
        initial_members: Option<&[String]>,
        metadata: Option<&ConversationMetadata>,
        _commit_data: Option<&[u8]>,
        welcome_data: Option<&[u8]>,
    ) -> Result<CreateConversationResult> {
        let token = self.auth_header()?;
        let input: lexicon::create_convo::Input = lexicon::create_convo::InputData {
            group_id: group_id.to_string(),
            cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
            initial_members: initial_members
                .map(|members| members.iter().map(|d| parse_did(d)).collect()),
            metadata: metadata.map(|m| {
                lexicon::create_convo::MetadataInputData {
                    name: m.name.clone(),
                    description: m.description.clone(),
                }
                .into()
            }),
            welcome_message: welcome_data.map(|w| B64.encode(w)),
            current_epoch: None,
            key_package_hashes: None,
        }
        .into();

        let resp = self
            .client
            .post(self.xrpc_url(lexicon::create_convo::NSID))
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::create_convo::CreateConvoOutput<'_>,
        >(body.as_ref())?;
        let conversation = parse_conversation(&output.convo);
        Ok(CreateConversationResult {
            conversation,
            commit_data: None,
            welcome_data: None,
        })
    }

    async fn leave_conversation(&self, convo_id: &str) -> Result<()> {
        let token = self.auth_header()?;
        let input: lexicon::leave_convo::Input = lexicon::leave_convo::InputData {
            convo_id: convo_id.to_string(),
            commit: None,
            target_did: None,
        }
        .into();
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::leave_convo::NSID))
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
        // TODO(A7): confirmation_tag + epoch_authenticator stubbed as None;
        // real values require MLS state computation (deferred with #15/#18).
        //
        // NOTE: uses `build_commit_group_change` directly instead of the
        // `InputData → Input` adapter in `catbird-atproto` to avoid the
        // `String → bytes::Bytes` UTF-8-copy double-base64-encoding bug
        // (see helper doc comment).
        let input = build_commit_group_change(
            convo_id,
            "addMembers",
            Some(commit_data.to_vec()),
            welcome_data.map(|w| w.to_vec()),
            None,
            None,
            Some(member_dids.to_vec()),
            Some(uuid::Uuid::new_v4().to_string()),
        );
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::commit_group_change::NSID))
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::commit_group_change::CommitGroupChangeOutput<'_>,
        >(body.as_ref())?;
        Ok(AddMembersServerResult {
            success: output.success,
            new_epoch: output
                .new_epoch
                .and_then(|epoch| u64::try_from(epoch).ok())
                .unwrap_or(0),
            receipt: parse_commit_group_change_receipt(&output, "add_members"),
        })
    }

    async fn remove_members(
        &self,
        convo_id: &str,
        member_dids: &[String],
        commit_data: &[u8],
    ) -> Result<()> {
        let token = self.auth_header()?;
        // v2 removal flows through leaveConvo with targetDid set per member.
        for did in member_dids {
            let input: lexicon::leave_convo::Input = lexicon::leave_convo::InputData {
                convo_id: convo_id.to_string(),
                commit: Some(B64.encode(commit_data)),
                target_did: Some(parse_did(did)),
            }
            .into();
            let resp = self
                .client
                .post(self.xrpc_url(lexicon::leave_convo::NSID))
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
        message_type: Option<&str>,
        from_epoch: Option<u32>,
        to_epoch: Option<u32>,
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)> {
        let token = self.auth_header()?;
        let mut url = format!(
            "{}?convoId={}&limit={}",
            self.xrpc_url(lexicon::get_messages::NSID),
            convo_id,
            limit
        );
        if let Some(c) = cursor {
            url.push_str(&format!("&sinceSeq={}", c));
        }
        if let Some(t) = message_type {
            url.push_str(&format!("&type={}", t));
        }
        if let Some(from) = from_epoch {
            url.push_str(&format!("&fromEpoch={}", from));
        }
        if let Some(to) = to_epoch {
            url.push_str(&format!("&toEpoch={}", to));
        }

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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::get_messages::GetMessagesOutput<'_>,
        >(body.as_ref())?;
        let envelopes = output
            .messages
            .iter()
            .map(|m| {
                let timestamp = m.created_at.as_ref().with_timezone(&chrono::Utc);
                IncomingEnvelope {
                    conversation_id: m.convo_id.to_string(),
                    sender_did: String::new(), // Dumb DS — sender unknown
                    ciphertext: m.ciphertext.to_vec(),
                    timestamp,
                    server_message_id: Some(m.id.to_string()),
                }
            })
            .collect();
        let next_cursor = output.last_seq.map(|seq| seq.to_string());
        Ok((envelopes, next_cursor))
    }

    async fn publish_key_package(
        &self,
        key_package: &[u8],
        cipher_suite: &str,
        expires_at: &str,
    ) -> Result<()> {
        let token = self.auth_header()?;
        let expires = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map(Datetime::new)
            .map_err(|e| OrchestratorError::Api(format!("Invalid expires timestamp: {e}")))?;
        let input: lexicon::publish_key_packages::Input =
            lexicon::publish_key_packages::InputData {
                action: "publish".to_string(),
                convo_id: None,
                device_id: None,
                key_packages: Some(vec![lexicon::publish_key_packages::KeyPackageItemData {
                    cipher_suite: cipher_suite.to_string(),
                    expires,
                    key_package: key_package.to_vec(),
                }
                .into()]),
                local_hashes: None,
                reason: None,
                target_dids: None,
            }
            .into();
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::publish_key_packages::NSID))
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

    async fn get_key_packages(&self, dids: &[String]) -> Result<Vec<KeyPackageRef>> {
        let token = self.auth_header()?;
        let url = format!(
            "{}?dids={}",
            self.xrpc_url(lexicon::get_key_packages::NSID),
            dids.join(",")
        );
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::get_key_packages::GetKeyPackagesOutput<'_>,
        >(body.as_ref())?;
        Ok(output
            .key_packages
            .iter()
            .filter_map(|kp| {
                // post-regen: key_package is raw bytes::Bytes, no base64 decode needed.
                let kp_data = kp.key_package.to_vec();
                Some(KeyPackageRef {
                    did: kp.did.as_str().to_string(),
                    key_package_data: kp_data,
                    hash: kp.key_package_hash.as_ref().map(|hash| hash.to_string()),
                    cipher_suite: kp.cipher_suite.to_string(),
                })
            })
            .collect())
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url(lexicon::get_key_package_status::NSID))
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::get_key_package_status::GetKeyPackageStatusOutput<'_>,
        >(body.as_ref())?;
        let stats = output.stats.ok_or_else(|| {
            OrchestratorError::Api("missing stats in key package response".into())
        })?;
        let available = u32::try_from(stats.total_available.max(0)).unwrap_or(u32::MAX);
        let total_consumed = u32::try_from(stats.total_consumed.max(0)).unwrap_or(u32::MAX);
        let total = available.saturating_add(total_consumed);
        Ok(KeyPackageStats { available, total })
    }

    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        _device_id: &str,
    ) -> Result<KeyPackageSyncResult> {
        // Not implemented on server yet
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
        let kp_items: Vec<lexicon::register_device::KeyPackageItem> = key_packages
            .iter()
            .map(|kp| {
                lexicon::register_device::KeyPackageItemData {
                    cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
                    expires: Datetime::new(
                        (chrono::Utc::now() + chrono::Duration::days(90)).fixed_offset(),
                    ),
                    key_package: kp.clone(),
                }
                .into()
            })
            .collect();
        let input: lexicon::register_device::Input = lexicon::register_device::InputData {
            device_uuid: Some(device_uuid.to_string()),
            device_name: device_name.to_string(),
            signature_public_key: signature_key.to_vec(),
            key_packages: kp_items,
        }
        .into();
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::register_device::NSID))
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::register_device::RegisterDeviceOutput<'_>,
        >(body.as_ref())?;
        Ok(DeviceInfo {
            device_id: output.device_id.to_string(),
            mls_did: output.mls_did.to_string(),
            device_uuid: device_uuid.to_string(),
            created_at: None,
        })
    }

    async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url(lexicon::list_devices::NSID))
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::list_devices::ListDevicesOutput<'_>,
        >(body.as_ref())?;
        Ok(output
            .devices
            .iter()
            .map(|d| DeviceInfo {
                device_id: d.device_id.to_string(),
                mls_did: d.credential_did.to_string(),
                device_uuid: d
                    .device_uuid
                    .as_ref()
                    .map(|uuid| uuid.to_string())
                    .unwrap_or_default(),
                created_at: Some(d.registered_at.as_ref().with_timezone(&chrono::Utc)),
            })
            .collect())
    }

    async fn remove_device(&self, device_id: &str) -> Result<()> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .request(
                reqwest::Method::DELETE,
                self.xrpc_url(lexicon::list_devices::NSID),
            )
            .bearer_auth(&token)
            .query(&[("deviceId", device_id)])
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
        // See `build_commit_group_change` doc: direct construction avoids the
        // double-base64 bug in the InputData adapter's String → Bytes mapping.
        let input = build_commit_group_change(
            convo_id,
            "updateGroupInfo",
            None,
            None,
            Some(group_info.to_vec()),
            None,
            None,
            None,
        );
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::commit_group_change::NSID))
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
            .get(self.xrpc_url(lexicon::get_group_state::NSID))
            .bearer_auth(&token)
            .query(&[("convoId", convo_id), ("include", "groupInfo,epoch")])
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::get_group_state::GetGroupStateOutput<'_>,
        >(body.as_ref())?;
        // post-regen: group_info is raw bytes::Bytes; no base64 decode.
        output
            .group_info
            .as_ref()
            .map(|value| value.to_vec())
            .ok_or_else(|| OrchestratorError::Api("missing groupInfo in group state".into()))
    }

    async fn get_welcome(&self, convo_id: &str) -> Result<Vec<u8>> {
        let token = self.auth_header()?;
        let resp = self
            .client
            .get(self.xrpc_url(lexicon::get_group_state::NSID))
            .bearer_auth(&token)
            .query(&[("convoId", convo_id), ("include", "welcome")])
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::get_group_state::GetGroupStateOutput<'_>,
        >(body.as_ref())?;
        // post-regen: welcome is raw bytes::Bytes; no base64 decode.
        match output.welcome.as_ref().map(|value| value.to_vec()) {
            Some(bytes) => Ok(bytes),
            None => Err(OrchestratorError::ServerError {
                status: 404,
                body: r#"{"error":"NotFound","message":"No welcome available"}"#.to_string(),
            }),
        }
    }

    async fn get_delivery_status(
        &self,
        convo_id: &str,
        message_ids: &[String],
    ) -> Result<Vec<(String, DeliveryStatus)>> {
        let _ = (convo_id, message_ids);
        Ok(vec![])
    }

    // TODO(test-gap): no unit coverage — `catbird-mls-web` has cdylib-only
    // crate-type and uses sqlite-wasm-rs OPFS VFS that doesn't run on host.
    // Verified by inspection against catmos/src-tauri/src/api_client.rs:567
    // and catbird-mls/src/orchestrator/recovery.rs:898 (`report_unrecoverable_local`).
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
            .post(self.xrpc_url("blue.catbird.mlsChat.reportRecoveryFailure"))
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

        // 403 = caller is no longer a member; treat as soft-ack so the
        // orchestrator's best-effort reporter doesn't keep retrying.
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
        // See `build_commit_group_change` doc: direct construction avoids the
        // double-base64 bug in the InputData adapter's String → Bytes mapping.
        //
        // `confirmation_tag` is passed as `Option<&str>` from the orchestrator.
        // Byte-preserving mapping: `s.as_bytes().to_vec()` produces the same
        // wire bytes the buggy adapter was emitting (UTF-8 of the string).
        // Whether the caller intends those bytes to be interpreted as ASCII
        // or pre-base64 is a separate concern tracked outside this fix — the
        // InputData adapter's behaviour was the same on that field, so this
        // fix is strictly additive for that field. Commit/welcome/group_info
        // are the wire-level correctness targets here.
        let input = build_commit_group_change(
            convo_id,
            "externalCommit",
            Some(commit_data.to_vec()),
            None,
            group_info.map(|value| value.to_vec()),
            confirmation_tag.map(|s| s.as_bytes().to_vec()),
            None,
            Some(uuid::Uuid::new_v4().to_string()),
        );
        let resp = self
            .client
            .post(self.xrpc_url(lexicon::commit_group_change::NSID))
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
        let output = parse_lexicon_json::<
            blue_catbird::mlsChat::commit_group_change::CommitGroupChangeOutput<'_>,
        >(body.as_ref())?;
        Ok(ProcessExternalCommitResult {
            epoch: output
                .new_epoch
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(0),
            rejoined_at: output
                .rejoined_at
                .as_ref()
                .map(|value| value.as_ref().to_string())
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
            receipt: parse_commit_group_change_receipt(&output, "process_external_commit"),
        })
    }
}
