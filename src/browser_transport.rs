//! Browser clean-chat preparation.
//!
//! The browser keeps the private Ed25519 key in a host-owned CryptoKey.  WASM
//! stores only a callback and the public binding needed to reject confused
//! deputy requests.  Prepared values deliberately contain no auth headers or
//! signer metadata.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use js_sys::{Function, Promise, Uint8Array};
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::Serialize;
use serde_ipld_dagcbor::to_vec as to_dag_cbor;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use catbird_mls::orchestrator::canonical_transport::{
    canonical_route, CanonicalOperation, CleanChatRequest, PreparedRequest,
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
            body: request.body.map(|body| String::from_utf8_lossy(&body).into_owned()),
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

#[wasm_bindgen]
pub fn catbird_mls_set_signer_bridge(
    callback: Function,
    actor_did: String,
    device_id: String,
    dpop_jkt: String,
    public_key: Uint8Array,
    auth_generation: Option<i64>,
) -> Result<(), JsValue> {
    if !callback.is_function() {
        return Err(js_error("signer callback is not callable"));
    }
    if !actor_did.starts_with("did:") || actor_did.chars().any(char::is_whitespace) {
        return Err(js_error("actor DID is not canonical"));
    }
    Uuid::parse_str(&device_id).map_err(|_| js_error("device ID is not a UUID"))?;
    let jkt_bytes = URL_SAFE_NO_PAD
        .decode(&dpop_jkt)
        .map_err(|_| js_error("DPoP JKT is not base64url"))?;
    if jkt_bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&jkt_bytes) != dpop_jkt {
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

#[wasm_bindgen]
pub fn catbird_mls_prepare_unsigned_request(
    operation: String,
    request_json: String,
) -> Result<JsValue, JsValue> {
    let operation = parse_operation(&operation).map_err(js_error)?;
    let _request = parse_generated_request(operation, request_json.as_bytes()).map_err(js_error)?;
    let route = canonical_route(operation);
    let (method, path, body) = if is_read(operation) {
        let value: serde_json::Value =
            serde_json::from_str(&request_json).map_err(|error| js_error(error))?;
        let object = value
            .as_object()
            .ok_or_else(|| js_error("generated read request must be an object"))?;
        let mut fields = Vec::new();
        for (key, value) in object {
            if key == "$type" || value.is_null() {
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
        ("POST".to_owned(), route.path.to_owned(), Some(request_json.into_bytes()))
    };
    let prepared = PreparedRequest {
        operation,
        method,
        path,
        authorization: String::new(),
        dpop: String::new(),
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
    let projection = project_signed(&signer, operation, request_json.as_bytes()).map_err(js_error)?;
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
    let mut signed_request = serde_json::Map::new();
    signed_request.insert("body".into(), projection.body);
    signed_request.insert("signature".into(), serde_json::Value::String(STANDARD.encode(signature)));
    let endpoint = serde_json::json!({ "signedRequest": signed_request });
    let bytes = serde_json::to_vec(&endpoint).map_err(|error| js_error(error))?;
    let _ = parse_generated_request(operation, &bytes).map_err(js_error)?;
    let prepared = BrowserPreparedRequest {
        operation: operation_name(operation).to_owned(),
        method: "POST".into(),
        path: canonical_route(operation).path.to_owned(),
        body: Some(String::from_utf8(bytes).map_err(|error| js_error(error))?),
    };
    serde_wasm_bindgen::to_value(&prepared).map_err(|error| js_error(error))
}

struct Projection {
    body: serde_json::Value,
    transcript: Vec<u8>,
}

fn project_signed(
    signer: &SignerBridge,
    operation: CanonicalOperation,
    input: &[u8],
) -> Result<Projection, String> {
    let root: serde_json::Value = serde_json::from_slice(input).map_err(|error| error.to_string())?;
    let root_object = root
        .as_object()
        .ok_or_else(|| "signed request must be an object".to_owned())?;
    if root_object.keys().any(|key| key != "signedRequest") {
        return Err("signed request wrapper has unknown fields".into());
    }
    let signed_request = root_object
        .get("signedRequest")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "signedRequest must be an object".to_owned())?;
    if signed_request
        .keys()
        .any(|key| !matches!(key.as_str(), "body" | "signature" | "$type"))
    {
        return Err("signedRequest has unknown fields".into());
    }
    let body = root
        .get("signedRequest")
        .and_then(|value| value.get("body"))
        .cloned()
        .ok_or_else(|| "signedRequest.body is required".to_owned())?;
    let body_object = body
        .as_object()
        .ok_or_else(|| "signedRequest.body must be an object".to_owned())?;
    let body_type = body_object
        .get("$type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "signed body $type is required".to_owned())?;
    let domain = signed_domain(operation, body_type)?;
    validate_binding(signer, operation, body_object, domain)?;
    let canonical = canonical_value(&body, None)?;
    let cbor = to_dag_cbor(&canonical).map_err(|error| error.to_string())?;
    let mut transcript = domain.as_bytes().to_vec();
    transcript.extend_from_slice(&cbor);
    Ok(Projection { body, transcript })
}

fn signed_domain(operation: CanonicalOperation, body_type: &str) -> Result<&'static str, String> {
    let (expected, domain) = match operation {
        CanonicalOperation::AcceptConversation => ("participantAcceptanceBody", "CATBIRD-CHAT-ACCEPT\0"),
        CanonicalOperation::AcknowledgeWelcome => ("welcomeAcknowledgementBody", "CATBIRD-CHAT-WELCOME-ACK\0"),
        CanonicalOperation::ActivateReset => ("resetActivationBody", "CATBIRD-CHAT-RESET-ACTIVATE\0"),
        CanonicalOperation::CancelLeafRecovery => ("leafRecoveryCancellationBody", "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL\0"),
        CanonicalOperation::CancelLeave => ("leaveCancellationBody", "CATBIRD-CHAT-LEAVE-CANCEL\0"),
        CanonicalOperation::CloseConversation => ("conversationCloseBody", "CATBIRD-CHAT-CLOSE\0"),
        CanonicalOperation::CreateConversation => ("creationBody", "CATBIRD-CHAT-CREATE\0"),
        CanonicalOperation::DeleteBlob => ("blobDeletionBody", "CATBIRD-CHAT-BLOB-DELETE\0"),
        CanonicalOperation::SendMessage => ("applicationSendBody", "CATBIRD-CHAT-MESSAGE\0"),
        CanonicalOperation::PrepareBlobUpload => ("blobUploadPreparationBody", "CATBIRD-CHAT-BLOB-PREPARE\0"),
        CanonicalOperation::PublishTyping => ("typingBody", "CATBIRD-CHAT-TYPING\0"),
        CanonicalOperation::RebindDeviceAuthentication => ("deviceAuthenticationRebindBody", "CATBIRD-CHAT-DEVICE-REBIND\0"),
        CanonicalOperation::RejectWelcome => ("welcomeRejectionBody", "CATBIRD-CHAT-WELCOME-REJECT\0"),
        CanonicalOperation::ReplenishKeyPackages => ("keyPackageReplenishmentBody", "CATBIRD-CHAT-DEVICE-REPLENISH\0"),
        CanonicalOperation::RequestLeafRecovery => ("leafRecoveryRequestBody", "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\0"),
        CanonicalOperation::EnrollDevice => ("deviceEnrollmentBody", "CATBIRD-CHAT-DEVICE-ENROLL\0"),
        CanonicalOperation::RequestReset => ("resetRequestBody", "CATBIRD-CHAT-RESET-REQUEST\0"),
        CanonicalOperation::RevokeDevice => ("deviceRevocationBody", "CATBIRD-CHAT-DEVICE-REVOKE\0"),
        CanonicalOperation::RequestLeave | CanonicalOperation::SubmitTransition => {
            return Err("union signed mutations require a generated variant adapter".into())
        }
        _ => return Err(format!("{} is not a signed mutation", operation_name(operation))),
    };
    if body_type != format!("blue.catbird.chat.defs#{expected}") {
        return Err("signed body type does not match operation".into());
    }
    Ok(domain)
}

fn validate_binding(
    signer: &SignerBridge,
    operation: CanonicalOperation,
    body: &serde_json::Map<String, serde_json::Value>,
    domain: &str,
) -> Result<(), String> {
    if body.get("actorDid").and_then(serde_json::Value::as_str) != Some(&signer.actor_did) {
        return Err("signed body actorDid does not match signer authority".into());
    }
    let device_key = if operation == CanonicalOperation::EnrollDevice { "deviceId" } else { "actorDeviceId" };
    if body.get(device_key).and_then(serde_json::Value::as_str) != Some(&signer.device_id) {
        return Err("signed body device binding does not match signer authority".into());
    }
    if operation == CanonicalOperation::EnrollDevice {
        if body.get("dpopJkt").and_then(serde_json::Value::as_str) != Some(&signer.dpop_jkt) {
            return Err("signed body DPoP JKT does not match signer authority".into());
        }
        if body.get("expectedAuthGeneration").and_then(serde_json::Value::as_i64) != Some(0) {
            return Err("enrollment generation must be zero".into());
        }
    } else {
        if let Some(jkt) = body.get("dpopJkt").and_then(serde_json::Value::as_str) {
            if jkt != signer.dpop_jkt {
                return Err("signed body DPoP JKT does not match signer authority".into());
            }
        }
        let generation = body
            .get("authGeneration")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| "signed body authGeneration is required".to_owned())?;
        if Some(generation) != signer.auth_generation {
            return Err("signed body authGeneration does not match signer authority".into());
        }
    }
    if body.get("signatureDomain").and_then(serde_json::Value::as_str) != Some(domain) {
        return Err("signed body signatureDomain is not canonical".into());
    }
    let key_id = body
        .get("keyId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "signed body keyId is required".to_owned())?;
    if key_id != derive_key_id(&signer.public_key) {
        return Err("signed body keyId does not match signer public key".into());
    }
    if let Some(public_key) = body.get("signaturePublicKey") {
        let public_key = decode_bytes(public_key)?;
        if public_key != signer.public_key {
            return Err("signed body signaturePublicKey does not match signer public key".into());
        }
    }
    Ok(())
}

fn derive_key_id(key: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key))
}

#[derive(Debug)]
enum Canonical {
    Text(String),
    Bytes(Vec<u8>),
    Integer(u64),
    Bool(bool),
    Array(Vec<Canonical>),
    Map(BTreeMap<String, Canonical>),
}

impl Serialize for Canonical {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Text(value) => serializer.serialize_str(value),
            Self::Bytes(value) => serializer.serialize_bytes(value),
            Self::Integer(value) => serializer.serialize_u64(*value),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(value)?;
                }
                seq.end()
            }
            Self::Map(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

fn canonical_value(
    value: &serde_json::Value,
    field: Option<&str>,
) -> Result<Canonical, String> {
    match value {
        serde_json::Value::Null => Err("null is not canonical clean-chat data".into()),
        serde_json::Value::Bool(value) => Ok(Canonical::Bool(*value)),
        serde_json::Value::Number(value) => Ok(Canonical::Integer(
            value.as_u64().ok_or_else(|| "non-integer number in signed body".to_owned())?,
        )),
        serde_json::Value::String(value) => {
            if matches!(field, Some("deviceId" | "actorDeviceId" | "messageId" | "operationId" | "idempotencyKey")) {
                return Ok(Canonical::Bytes(
                    Uuid::parse_str(value).map_err(|_| format!("{field:?} is not a UUID"))?.into_bytes().to_vec(),
                ));
            }
            Ok(Canonical::Text(value.clone()))
        }
        serde_json::Value::Array(values) => Ok(Canonical::Array(
            values
                .iter()
                .map(|value| canonical_value(value, field))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        serde_json::Value::Object(values) => {
            if values.len() == 1 && values.contains_key("$bytes") {
                return Ok(Canonical::Bytes(decode_bytes(value)?));
            }
            let mut output = BTreeMap::new();
            for (key, value) in values {
                output.insert(key.clone(), canonical_value(value, Some(key))?);
            }
            Ok(Canonical::Map(output))
        }
    }
}

fn decode_bytes(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    match value {
        serde_json::Value::Object(values) => values
            .get("$bytes")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "invalid byte object".to_owned())
            .and_then(|value| STANDARD.decode(value).map_err(|_| "invalid base64 bytes".into())),
        serde_json::Value::String(value) => STANDARD.decode(value).map_err(|_| "invalid base64 bytes".into()),
        serde_json::Value::Array(values) => values
            .iter()
            .map(|value| value.as_u64().filter(|value| *value <= 255).map(|value| value as u8).ok_or_else(|| "invalid byte array".to_owned()))
            .collect(),
        _ => Err("invalid byte value".into()),
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

fn parse_operation(value: &str) -> Result<CanonicalOperation, String> {
    let operation = match value {
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
        "getEntries" => CanonicalOperation::GetEntries,
        "getLeafRecoveryInbox" => CanonicalOperation::GetLeafRecoveryInbox,
        "getOwnDevices" => CanonicalOperation::GetOwnDevices,
        "getPendingWelcomes" => CanonicalOperation::GetPendingWelcomes,
        "getSubscriptionTicket" => CanonicalOperation::GetSubscriptionTicket,
        "prepareBlobUpload" => CanonicalOperation::PrepareBlobUpload,
        "publishTyping" => CanonicalOperation::PublishTyping,
        "rebindDeviceAuthentication" => CanonicalOperation::RebindDeviceAuthentication,
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
        CanonicalOperation::GetEntries => "getEntries",
        CanonicalOperation::GetLeafRecoveryInbox => "getLeafRecoveryInbox",
        CanonicalOperation::GetOwnDevices => "getOwnDevices",
        CanonicalOperation::GetPendingWelcomes => "getPendingWelcomes",
        CanonicalOperation::GetSubscriptionTicket => "getSubscriptionTicket",
        CanonicalOperation::PrepareBlobUpload => "prepareBlobUpload",
        CanonicalOperation::PublishTyping => "publishTyping",
        CanonicalOperation::RebindDeviceAuthentication => "rebindDeviceAuthentication",
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

fn parse_generated_request(operation: CanonicalOperation, body: &[u8]) -> Result<CleanChatRequest, String> {
    macro_rules! parse {
        ($ty:path, $variant:ident) => {
            serde_json::from_slice::<$ty>(body)
                .map(CleanChatRequest::$variant)
                .map_err(|error| format!("generated request is invalid: {error}"))
        };
    }
    use catbird_mls::orchestrator::canonical_transport::*;
    use catbird_mls::atproto::blue_catbird::chat::{
        get_conversations::GetConversations,
        get_entries::GetEntries,
    };
    match operation {
        CanonicalOperation::AcceptConversation => parse!(AcceptConversationRequestBody, AcceptConversation),
        CanonicalOperation::AcknowledgeWelcome => parse!(AcknowledgeWelcomeRequestBody, AcknowledgeWelcome),
        CanonicalOperation::ActivateReset => parse!(ActivateResetRequestBody, ActivateReset),
        CanonicalOperation::CancelLeafRecovery => parse!(CancelLeafRecoveryRequestBody, CancelLeafRecovery),
        CanonicalOperation::CancelLeave => parse!(CancelLeaveRequestBody, CancelLeave),
        CanonicalOperation::CloseConversation => parse!(CloseConversationRequestBody, CloseConversation),
        CanonicalOperation::GetConversations => parse!(GetConversations<String>, GetConversations),
        CanonicalOperation::CreateConversation => parse!(CreateConversationRequestBody, CreateConversation),
        CanonicalOperation::DeleteBlob => parse!(DeleteBlobRequestBody, DeleteBlob),
        CanonicalOperation::SendMessage => parse!(SendMessageRequestBody, SendMessage),
        CanonicalOperation::GetBlob => parse!(GetBlobRequestBody, GetBlob),
        CanonicalOperation::GetBlobUsage => parse!(GetBlobUsageRequestBody, GetBlobUsage),
        CanonicalOperation::GetConversationState => parse!(GetConversationStateRequestBody, GetConversationState),
        CanonicalOperation::GetDevices => parse!(GetDevicesRequestBody, GetDevices),
        CanonicalOperation::GetEntries => parse!(GetEntries<String>, GetEntries),
        CanonicalOperation::GetLeafRecoveryInbox => parse!(GetLeafRecoveryInboxRequestBody, GetLeafRecoveryInbox),
        CanonicalOperation::GetOwnDevices => parse!(GetOwnDevicesRequestBody, GetOwnDevices),
        CanonicalOperation::GetPendingWelcomes => parse!(GetPendingWelcomesRequestBody, GetPendingWelcomes),
        CanonicalOperation::GetSubscriptionTicket => parse!(GetSubscriptionTicketRequestBody, GetSubscriptionTicket),
        CanonicalOperation::PrepareBlobUpload => parse!(PrepareBlobUploadRequestBody, PrepareBlobUpload),
        CanonicalOperation::PublishTyping => parse!(PublishTypingRequestBody, PublishTyping),
        CanonicalOperation::RebindDeviceAuthentication => parse!(RebindDeviceAuthenticationRequestBody, RebindDeviceAuthentication),
        CanonicalOperation::RejectWelcome => parse!(RejectWelcomeRequestBody, RejectWelcome),
        CanonicalOperation::ReplenishKeyPackages => parse!(ReplenishKeyPackagesRequestBody, ReplenishKeyPackages),
        CanonicalOperation::RequestLeafRecovery => parse!(RequestLeafRecoveryRequestBody, RequestLeafRecovery),
        CanonicalOperation::EnrollDevice => parse!(EnrollDeviceRequestBody, EnrollDevice),
        CanonicalOperation::RequestLeave => parse!(RequestLeaveRequestBody, RequestLeave),
        CanonicalOperation::RequestReset => parse!(RequestResetRequestBody, RequestReset),
        CanonicalOperation::RevokeDevice => parse!(RevokeDeviceRequestBody, RevokeDevice),
        CanonicalOperation::SubmitTransition => parse!(SubmitTransitionRequestBody, SubmitTransition),
        CanonicalOperation::SubscribeEvents => parse!(SubscribeEventsRequestBody, SubscribeEvents),
        CanonicalOperation::UploadBlob => parse!(UploadBlobRequestBody, UploadBlob),
    }
}
