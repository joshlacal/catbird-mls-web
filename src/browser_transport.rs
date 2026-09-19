//! Browser clean-chat preparation.
//!
//! The browser keeps the private Ed25519 key in a host-owned WebCrypto
//! `CryptoKey`. WASM stores only the custody-validated key metadata, a signer
//! callback, and the public binding needed to reject confused-deputy requests.
//! Prepared values deliberately contain no auth headers or signer metadata.
//!
//! Signed preparation routes through the byte-faithful port of the approved
//! Rust strict projector (`strict_projection`): duplicate/unknown/null/tag/
//! bounds checks and canonical dag-cbor bytes are the SAME code as native
//! (catbird-mls d69da1e1), and validation structurally precedes signing — the
//! signer callback is invoked only after the strict projection and binding
//! validation succeed.

use std::cell::RefCell;
use std::fmt;

use base64::Engine as _;
use js_sys::{Function, Promise, Reflect, Uint8Array};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use catbird_mls::orchestrator::canonical_transport::{
    canonical_route, CanonicalOperation, CleanChatSigningContext, PreparedRequest,
};

use crate::strict_projection::{
    derive_key_id, finish_signed_request, parse_generated_request, prepare_signed_body,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserPreparedRequest {
    pub operation: String,
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

impl From<PreparedRequest> for BrowserPreparedRequest {
    fn from(request: PreparedRequest) -> Self {
        Self {
            operation: operation_name(request.operation).to_owned(),
            method: request.method,
            path: request.path,
            body: request
                .body
                .map(|body| String::from_utf8_lossy(&body).into_owned()),
        }
    }
}

#[derive(Clone)]
struct SignerBridge {
    callback: Function,
    actor_did: String,
    device_id: String,
    dpop_jkt: String,
    public_key: Vec<u8>,
    auth_generation: Option<i64>,
}

thread_local! {
    static SIGNER: RefCell<Option<SignerBridge>> = const { RefCell::new(None) };
}

fn js_error(message: impl fmt::Display) -> JsValue {
    JsValue::from_str(&message.to_string())
}

/// Validate that the host-supplied signer key satisfies the clean-chat custody
/// contract: a private, non-extractable, sign-only Ed25519 `CryptoKey`.
///
/// Only metadata properties are inspected — the WASM bridge never receives,
/// derives, or exports private key bytes. Extractable or raw-imported keys are
/// rejected.
fn validate_signer_key(key: &JsValue) -> Result<(), JsValue> {
    let type_value =
        Reflect::get(key, &"type".into()).map_err(|_| js_error("signer key is invalid"))?;
    if type_value.as_string().as_deref() != Some("private") {
        return Err(js_error("browser signer key must be a private CryptoKey"));
    }
    let extractable =
        Reflect::get(key, &"extractable".into()).map_err(|_| js_error("signer key is invalid"))?;
    if extractable.as_bool() != Some(false) {
        return Err(js_error(
            "browser signer key must be non-extractable (extractable or raw-imported keys are rejected)",
        ));
    }
    let algorithm =
        Reflect::get(key, &"algorithm".into()).map_err(|_| js_error("signer key is invalid"))?;
    let algorithm_name =
        Reflect::get(&algorithm, &"name".into()).map_err(|_| js_error("signer key is invalid"))?;
    if algorithm_name.as_string().as_deref() != Some("Ed25519") {
        return Err(js_error(
            "browser signer key must use the Ed25519 algorithm",
        ));
    }
    let usages =
        Reflect::get(key, &"usages".into()).map_err(|_| js_error("signer key is invalid"))?;
    let usages = usages
        .dyn_into::<js_sys::Array>()
        .map_err(|_| js_error("signer key is invalid"))?;
    let mut names = Vec::new();
    for usage in usages.iter() {
        names.push(
            usage
                .as_string()
                .ok_or_else(|| js_error("signer key is invalid"))?,
        );
    }
    if names != ["sign"] {
        return Err(js_error(
            "browser signer key must be sign-only (usages exactly [\"sign\"])",
        ));
    }
    Ok(())
}

#[wasm_bindgen]
pub fn catbird_mls_set_signer_bridge(
    callback: Function,
    key: JsValue,
    actor_did: String,
    device_id: String,
    dpop_jkt: String,
    public_key: Uint8Array,
    auth_generation: Option<i64>,
) -> Result<(), JsValue> {
    if !callback.is_function() {
        return Err(js_error("signer callback is not callable"));
    }
    validate_signer_key(&key)?;
    if !actor_did.starts_with("did:") || actor_did.chars().any(char::is_whitespace) {
        return Err(js_error("actor DID is not canonical"));
    }
    uuid::Uuid::parse_str(&device_id).map_err(|_| js_error("device ID is not a UUID"))?;
    let jkt_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&dpop_jkt)
        .map_err(|_| js_error("DPoP JKT is not base64url"))?;
    if jkt_bytes.len() != 32
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&jkt_bytes) != dpop_jkt
    {
        return Err(js_error("DPoP JKT must be canonical 32-byte base64url"));
    }
    let public_key = public_key.to_vec();
    if public_key.len() != 32 {
        return Err(js_error("signer public key must be 32 bytes"));
    }
    if auth_generation.is_some_and(|value| value < 1) {
        return Err(js_error("auth generation must be positive"));
    }
    SIGNER.with(|slot| {
        *slot.borrow_mut() = Some(SignerBridge {
            callback,
            actor_did,
            device_id,
            dpop_jkt,
            public_key,
            auth_generation,
        });
    });
    Ok(())
}

#[wasm_bindgen]
pub fn catbird_mls_clear_signer_bridge() {
    SIGNER.with(|slot| *slot.borrow_mut() = None);
}

#[wasm_bindgen]
pub fn catbird_mls_has_signer_bridge() -> bool {
    SIGNER.with(|slot| slot.borrow().is_some())
}

/// Whitelist of generated query keys per unsigned GET operation. Unknown raw
/// keys are rejected, never forwarded.
fn read_query_whitelist(operation: CanonicalOperation) -> &'static [&'static str] {
    match operation {
        CanonicalOperation::GetConversations => &[
            "actorDeviceId",
            "limit",
            "pageCursor",
            "supportedProtocolVersions",
        ],
        CanonicalOperation::GetBlob => &["actorDeviceId", "blobId"],
        CanonicalOperation::GetBlobUsage => &["actorDeviceId"],
        CanonicalOperation::GetConversationState => &["actorDeviceId", "conversationId"],
        CanonicalOperation::GetDevices => &["actorDeviceId", "userDids"],
        CanonicalOperation::GetDeviceKey => &["actorDeviceId", "ownerDid", "deviceId", "keyId"],
        CanonicalOperation::GetEntries => &["actorDeviceId", "afterSeq", "conversationId", "limit"],
        CanonicalOperation::GetLeafRecoveryInbox => &[
            "actorDeviceId",
            "inventorySessionId",
            "limit",
            "pageCursor",
            "supportedProtocolVersions",
        ],
        CanonicalOperation::GetOwnDevices => &["actorDeviceId", "limit", "pageCursor"],
        CanonicalOperation::GetPendingWelcomes => &[
            "actorDeviceId",
            "inventorySessionId",
            "limit",
            "pageCursor",
            "supportedProtocolVersions",
        ],
        _ => &[],
    }
}

fn is_read(operation: CanonicalOperation) -> bool {
    matches!(
        operation,
        CanonicalOperation::GetConversations
            | CanonicalOperation::GetBlob
            | CanonicalOperation::GetBlobUsage
            | CanonicalOperation::GetConversationState
            | CanonicalOperation::GetDevices
            | CanonicalOperation::GetDeviceKey
            | CanonicalOperation::GetEntries
            | CanonicalOperation::GetLeafRecoveryInbox
            | CanonicalOperation::GetOwnDevices
            | CanonicalOperation::GetPendingWelcomes
    )
}

fn query_value(value: &serde_json::Value) -> Result<String, String> {
    match value {
        serde_json::Value::String(value) => Ok(value.clone()),
        serde_json::Value::Bool(value) => Ok(value.to_string()),
        serde_json::Value::Number(value) => Ok(value.to_string()),
        _ => Err("query parameters must be scalar".into()),
    }
}

fn encode_query(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

#[wasm_bindgen]
pub fn catbird_mls_prepare_unsigned_request(
    operation: String,
    request_json: String,
) -> Result<JsValue, JsValue> {
    let operation = parse_operation(&operation).map_err(js_error)?;
    // The generated DTO parse validates the request shape (types/required).
    parse_generated_request(operation, request_json.as_bytes()).map_err(js_error)?;
    let route = canonical_route(operation);
    let (method, path, body) = if is_read(operation) {
        let value: serde_json::Value =
            serde_json::from_str(&request_json).map_err(|error| js_error(error))?;
        let object = value
            .as_object()
            .ok_or_else(|| js_error("generated read request must be an object"))?;
        let whitelist = read_query_whitelist(operation);
        let mut fields = Vec::new();
        for (key, value) in object {
            if key == "$type" {
                continue;
            }
            if !whitelist.contains(&key.as_str()) {
                return Err(js_error(format!(
                    "unknown query parameter {key} for {}",
                    operation_name(operation)
                )));
            }
            if value.is_null() {
                continue;
            }
            if let Some(values) = value.as_array() {
                for value in values {
                    fields.push(format!(
                        "{}={}",
                        encode_query(key),
                        encode_query(&query_value(value).map_err(js_error)?)
                    ));
                }
            } else {
                fields.push(format!(
                    "{}={}",
                    encode_query(key),
                    encode_query(&query_value(value).map_err(js_error)?)
                ));
            }
        }
        let path = if fields.is_empty() {
            route.path.to_owned()
        } else {
            format!("{}?{}", route.path, fields.join("&"))
        };
        ("GET".to_owned(), path, None)
    } else {
        (
            "POST".to_owned(),
            route.path.to_owned(),
            Some(request_json.into_bytes()),
        )
    };
    let prepared = PreparedRequest {
        operation,
        method,
        path,
        body,
    };
    serde_wasm_bindgen::to_value(&BrowserPreparedRequest::from(prepared))
        .map_err(|error| js_error(error))
}

#[wasm_bindgen]
pub async fn catbird_mls_prepare_signed_request(
    operation: String,
    request_json: String,
) -> Result<JsValue, JsValue> {
    let signer = SIGNER
        .with(|slot| slot.borrow().clone())
        .ok_or_else(|| js_error("signed preparation requires signer authority"))?;
    let operation = parse_operation(&operation).map_err(js_error)?;
    let binding = CleanChatSigningContext {
        actor_did: signer.actor_did.clone(),
        device_id: signer.device_id.clone(),
        auth_generation: signer.auth_generation,
    };
    // STRICT projection + binding validation FIRST — no signature is produced
    // until the approved Rust projection fully validates the payload.
    let projection =
        prepare_signed_body(&binding, operation, request_json.as_bytes()).map_err(js_error)?;
    // The retained signer's public key must match the body keyId (native
    // `verify_authority` parity).
    if derive_key_id(&signer.public_key) != projection.key_id {
        return Err(js_error(
            "signer public key does not match the signed body keyId",
        ));
    }
    let input = Uint8Array::from(projection.transcript.as_slice());
    let returned = signer
        .callback
        .call1(&JsValue::UNDEFINED, &input)
        .map_err(|_| js_error("browser signer callback failed"))?;
    let returned = JsFuture::from(Promise::resolve(&returned))
        .await
        .map_err(|_| js_error("browser signer promise rejected"))?;
    let signature = Uint8Array::new(&returned).to_vec();
    if signature.len() != 64 {
        return Err(js_error("browser signer must return exactly 64 bytes"));
    }
    // Verify the returned signature against the retained public key (native
    // `verify_authority` parity — fail closed on a bad signer callback).
    verify_signature(&signer.public_key, &projection.transcript, &signature)?;
    let prepared = finish_signed_request(projection, signature).map_err(js_error)?;
    serde_wasm_bindgen::to_value(&BrowserPreparedRequest::from(prepared))
        .map_err(|error| js_error(error))
}

fn verify_signature(public_key: &[u8], transcript: &[u8], signature: &[u8]) -> Result<(), JsValue> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let public_key = VerifyingKey::from_bytes(
        public_key
            .try_into()
            .map_err(|_| js_error("signer public key is not 32 bytes"))?,
    )
    .map_err(|_| js_error("signer public key is not a valid Ed25519 key"))?;
    let signature = Signature::from_slice(signature)
        .map_err(|_| js_error("browser signer signature is invalid"))?;
    public_key
        .verify_strict(transcript, &signature)
        .map_err(|_| js_error("browser signer signature verification failed"))
}

fn parse_operation(value: &str) -> Result<CanonicalOperation, String> {
    let operation = match value {
        "prepareDirectRequest"
        | "publishDirectRequest"
        | "cancelDirectRequestPreparation"
        | "getDirectRequestOutcome"
        | "publishDirectRequestKeys" => {
            return Err("browser direct-request lifecycle is unavailable".into());
        }
        "acceptConversation" => CanonicalOperation::AcceptConversation,
        "acknowledgeWelcome" => CanonicalOperation::AcknowledgeWelcome,
        "activateReset" => CanonicalOperation::ActivateReset,
        "cancelLeafRecovery" => CanonicalOperation::CancelLeafRecovery,
        "cancelLeave" => CanonicalOperation::CancelLeave,
        "closeConversation" => CanonicalOperation::CloseConversation,
        "getConversations" => CanonicalOperation::GetConversations,
        "createConversation" => CanonicalOperation::CreateConversation,
        "deleteBlob" => CanonicalOperation::DeleteBlob,
        "sendMessage" => CanonicalOperation::SendMessage,
        "getBlob" => CanonicalOperation::GetBlob,
        "getBlobUsage" => CanonicalOperation::GetBlobUsage,
        "getConversationState" => CanonicalOperation::GetConversationState,
        "getDevices" => CanonicalOperation::GetDevices,
        "getDeviceKey" => CanonicalOperation::GetDeviceKey,
        "getEntries" => CanonicalOperation::GetEntries,
        "getLeafRecoveryInbox" => CanonicalOperation::GetLeafRecoveryInbox,
        "getOwnDevices" => CanonicalOperation::GetOwnDevices,
        "getPendingWelcomes" => CanonicalOperation::GetPendingWelcomes,
        "getSubscriptionTicket" => CanonicalOperation::GetSubscriptionTicket,
        "prepareBlobUpload" => CanonicalOperation::PrepareBlobUpload,
        "publishTyping" => CanonicalOperation::PublishTyping,
        "rejectWelcome" => CanonicalOperation::RejectWelcome,
        "replenishKeyPackages" => CanonicalOperation::ReplenishKeyPackages,
        "requestLeafRecovery" => CanonicalOperation::RequestLeafRecovery,
        "enrollDevice" => CanonicalOperation::EnrollDevice,
        "requestLeave" => CanonicalOperation::RequestLeave,
        "requestReset" => CanonicalOperation::RequestReset,
        "revokeDevice" => CanonicalOperation::RevokeDevice,
        "submitTransition" => CanonicalOperation::SubmitTransition,
        "subscribeEvents" => CanonicalOperation::SubscribeEvents,
        "uploadBlob" => CanonicalOperation::UploadBlob,
        _ => return Err(format!("unsupported clean-chat operation: {value}")),
    };
    Ok(operation)
}

fn operation_name(operation: CanonicalOperation) -> &'static str {
    match operation {
        CanonicalOperation::PrepareDirectRequest => "prepareDirectRequest",
        CanonicalOperation::PublishDirectRequest => "publishDirectRequest",
        CanonicalOperation::CancelDirectRequestPreparation => "cancelDirectRequestPreparation",
        CanonicalOperation::GetDirectRequestOutcome => "getDirectRequestOutcome",
        CanonicalOperation::PublishDirectRequestKeys => "publishDirectRequestKeys",
        CanonicalOperation::AcceptConversation => "acceptConversation",
        CanonicalOperation::AcknowledgeWelcome => "acknowledgeWelcome",
        CanonicalOperation::ActivateReset => "activateReset",
        CanonicalOperation::CancelLeafRecovery => "cancelLeafRecovery",
        CanonicalOperation::CancelLeave => "cancelLeave",
        CanonicalOperation::CloseConversation => "closeConversation",
        CanonicalOperation::GetConversations => "getConversations",
        CanonicalOperation::CreateConversation => "createConversation",
        CanonicalOperation::DeleteBlob => "deleteBlob",
        CanonicalOperation::SendMessage => "sendMessage",
        CanonicalOperation::GetBlob => "getBlob",
        CanonicalOperation::GetBlobUsage => "getBlobUsage",
        CanonicalOperation::GetConversationState => "getConversationState",
        CanonicalOperation::GetDevices => "getDevices",
        CanonicalOperation::GetDeviceKey => "getDeviceKey",
        CanonicalOperation::GetEntries => "getEntries",
        CanonicalOperation::GetLeafRecoveryInbox => "getLeafRecoveryInbox",
        CanonicalOperation::GetOwnDevices => "getOwnDevices",
        CanonicalOperation::GetPendingWelcomes => "getPendingWelcomes",
        CanonicalOperation::GetSubscriptionTicket => "getSubscriptionTicket",
        CanonicalOperation::PrepareBlobUpload => "prepareBlobUpload",
        CanonicalOperation::PublishTyping => "publishTyping",
        CanonicalOperation::RejectWelcome => "rejectWelcome",
        CanonicalOperation::ReplenishKeyPackages => "replenishKeyPackages",
        CanonicalOperation::RequestLeafRecovery => "requestLeafRecovery",
        CanonicalOperation::EnrollDevice => "enrollDevice",
        CanonicalOperation::RequestLeave => "requestLeave",
        CanonicalOperation::RequestReset => "requestReset",
        CanonicalOperation::RevokeDevice => "revokeDevice",
        CanonicalOperation::SubmitTransition => "submitTransition",
        CanonicalOperation::SubscribeEvents => "subscribeEvents",
        CanonicalOperation::UploadBlob => "uploadBlob",
    }
}
