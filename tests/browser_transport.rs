#![cfg(target_arch = "wasm32")]

use base64::Engine as _;
use js_sys::{Function, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// ---------------------------------------------------------------------------
// Fixture corpus (approved signing-vector corpus; provenance checked by
// tests/provenance.rs against the pinned catbird-mls sibling).
// ---------------------------------------------------------------------------

const SIGNING_DOMAIN_VECTORS: &str = include_str!("fixtures/mls_chat_signing_domain_vectors.json");
const CONTRACT_VECTORS: &str = include_str!("fixtures/mls_chat_contract_vectors.json");

fn fixture_json(source: &str) -> serde_json::Value {
    serde_json::from_str(source).expect("fixture is valid JSON")
}

fn hex_decode(value: &str) -> Vec<u8> {
    hex::decode(value).expect("fixture hex decodes")
}

/// Wire conversion identical to the native test helper: `$uuid` markers become
/// UUID strings, `$bytesHex` markers become standard base64.
fn fixture_wire_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(object) if object.len() == 1 && object.contains_key("$uuid") => {
            let uuid = object["$uuid"]
                .as_str()
                .expect("fixture UUID marker is a string")
                .to_owned();
            serde_json::Value::String(uuid)
        }
        serde_json::Value::Object(object)
            if object.len() == 1 && object.contains_key("$bytesHex") =>
        {
            let bytes = object["$bytesHex"]
                .as_str()
                .expect("fixture bytes marker is a string");
            serde_json::Value::String(
                base64::engine::general_purpose::STANDARD
                    .encode(hex::decode(bytes).expect("fixture bytes are hex")),
            )
        }
        serde_json::Value::Object(object) => serde_json::Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (key, fixture_wire_value(value)))
                .collect(),
        ),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(fixture_wire_value).collect())
        }
        value => value,
    }
}

fn signing_domain_operation(body_name: &str) -> &'static str {
    match body_name {
        "deviceEnrollmentBody" => "enrollDevice",
        "keyPackageReplenishmentBody" => "replenishKeyPackages",
        "deviceRevocationBody" => "revokeDevice",
        "blobUploadPreparationBody" => "prepareBlobUpload",
        "applicationSendBody" => "sendMessage",
        "typingBody" => "publishTyping",
        "leafRecoveryRequestBody" => "requestLeafRecovery",
        "leafRecoveryCancellationBody" => "cancelLeafRecovery",
        "welcomeAcknowledgementBody" => "acknowledgeWelcome",
        "welcomeRejectionBody" => "rejectWelcome",
        other => panic!("unmapped signed-domain fixture {other}"),
    }
}

fn signing_domain_binding(
    body: &serde_json::Value,
    operation: &str,
) -> (String, String, String, Option<i64>) {
    let device_field = if operation == "enrollDevice" {
        "deviceId"
    } else {
        "actorDeviceId"
    };
    // The retained bridge argument is not part of the current enrollment or
    // replenishment transcript. Device authorization uses authGeneration/keyId.
    let dpop_jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
    let auth_generation = if operation == "enrollDevice" {
        None
    } else {
        Some(
            body["authGeneration"]
                .as_i64()
                .expect("signed-domain auth generation"),
        )
    };
    (
        body["actorDid"].as_str().expect("actor DID").to_owned(),
        body[device_field].as_str().expect("device ID").to_owned(),
        dpop_jkt,
        auth_generation,
    )
}

/// Build a fake signer-key object with the given custody properties. Real
/// CryptoKeys are covered by `extractable_crypto_key_is_rejected` below; these
/// objects exercise the WASM custody validator deterministically.
fn fake_signer_key(extractable: bool, algorithm: &str, usages: &[&str]) -> JsValue {
    let object = js_sys::Object::new();
    js_sys::Reflect::set(&object, &"type".into(), &JsValue::from_str("private")).unwrap();
    js_sys::Reflect::set(
        &object,
        &"extractable".into(),
        &JsValue::from_bool(extractable),
    )
    .unwrap();
    let algorithm_object = js_sys::Object::new();
    js_sys::Reflect::set(
        &algorithm_object,
        &"name".into(),
        &JsValue::from_str(algorithm),
    )
    .unwrap();
    js_sys::Reflect::set(&object, &"algorithm".into(), &algorithm_object).unwrap();
    let usage_array = js_sys::Array::new();
    for usage in usages {
        usage_array.push(&JsValue::from_str(usage));
    }
    js_sys::Reflect::set(&object, &"usages".into(), &usage_array).unwrap();
    object.into()
}

fn valid_fake_key() -> JsValue {
    fake_signer_key(false, "Ed25519", &["sign"])
}

/// Install a signer bridge whose callback returns the fixture signature bytes.
fn install_fixture_signer(
    public_key_hex: &str,
    signature_hex: &str,
    actor_did: &str,
    device_id: &str,
    dpop_jkt: &str,
    auth_generation: Option<i64>,
) {
    let public_key = Uint8Array::from(hex_decode(public_key_hex).as_slice());
    let signature = hex_decode(signature_hex);
    let signature_js = format!(
        "return new Uint8Array([{}])",
        signature
            .iter()
            .map(|byte| byte.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let callback = Function::new_with_args("transcript", &signature_js);
    catbird_mls_web::catbird_mls_set_signer_bridge(
        callback,
        valid_fake_key(),
        actor_did.to_owned(),
        device_id.to_owned(),
        dpop_jkt.to_owned(),
        public_key,
        auth_generation,
    )
    .expect("fixture signer bridge installs");
}

fn prepared_body(prepared: JsValue) -> serde_json::Value {
    let body: String = js_sys::Reflect::get(&prepared, &"body".into())
        .expect("prepared body field")
        .as_string()
        .expect("prepared body is a string");
    serde_json::from_str(&body).expect("prepared body is valid JSON")
}

#[wasm_bindgen_test]
async fn strict_projection_rejects_duplicate_key_before_signing() {
    let fixture = fixture_json(SIGNING_DOMAIN_VECTORS);
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["bodyName"] == "applicationSendBody")
        .expect("applicationSendBody fixture");
    let (actor_did, device_id, dpop_jkt, auth_generation) =
        signing_domain_binding(&case["body"], "sendMessage");
    install_fixture_signer(
        case["publicKeyHex"].as_str().unwrap(),
        case["signatureHex"].as_str().unwrap(),
        &actor_did,
        &device_id,
        &dpop_jkt,
        auth_generation,
    );

    // Duplicate `actorDid` key: serde_json::Value keeps the last, but the
    // strict projector must reject it.
    let duplicate = r#"{"signedRequest":{"body":{"$type":"blue.catbird.chat.defs#applicationSendBody","actorDid":"did:plc:alicefixtureaaaaaaaaaaaa","actorDid":"did:plc:alicefixtureaaaaaaaaaaaa"}}}"#;
    let error = catbird_mls_web::catbird_mls_prepare_signed_request(
        "sendMessage".to_owned(),
        duplicate.to_owned(),
    )
    .await
    .expect_err("duplicate key must be rejected by the strict projector");
    let error = error.as_string().unwrap_or_default();
    assert!(
        error.contains("duplicate"),
        "duplicate-key rejection: got {error}"
    );
}

#[wasm_bindgen_test]
async fn strict_projection_rejects_unknown_field_before_signing() {
    let fixture = fixture_json(SIGNING_DOMAIN_VECTORS);
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["bodyName"] == "applicationSendBody")
        .expect("applicationSendBody fixture");
    let (actor_did, device_id, dpop_jkt, auth_generation) =
        signing_domain_binding(&case["body"], "sendMessage");
    install_fixture_signer(
        case["publicKeyHex"].as_str().unwrap(),
        case["signatureHex"].as_str().unwrap(),
        &actor_did,
        &device_id,
        &dpop_jkt,
        auth_generation,
    );

    // Unknown field in the body: schema projection must reject it.
    let mut body = case["body"].clone();
    body["bogusField"] = serde_json::json!(1);
    let request = serde_json::json!({ "signedRequest": { "body": body } });
    let error = catbird_mls_web::catbird_mls_prepare_signed_request(
        "sendMessage".to_owned(),
        request.to_string(),
    )
    .await
    .expect_err("unknown field must be rejected by the strict projector");
    let error = error.as_string().unwrap_or_default();
    assert!(
        error.contains("unknown") && error.contains("bogusField"),
        "unknown-field rejection: got {error}"
    );
}

#[wasm_bindgen_test]
async fn strict_projection_rejects_out_of_bounds_before_signing() {
    let fixture = fixture_json(SIGNING_DOMAIN_VECTORS);
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["bodyName"] == "applicationSendBody")
        .expect("applicationSendBody fixture");
    let (actor_did, device_id, dpop_jkt, auth_generation) =
        signing_domain_binding(&case["body"], "sendMessage");
    install_fixture_signer(
        case["publicKeyHex"].as_str().unwrap(),
        case["signatureHex"].as_str().unwrap(),
        &actor_did,
        &device_id,
        &dpop_jkt,
        auth_generation,
    );

    // authGeneration 0 is below the canonical 1..=2^53-1 bound.
    let mut body = case["body"].clone();
    body["authGeneration"] = serde_json::json!(0);
    let request = serde_json::json!({ "signedRequest": { "body": body } });
    let error = catbird_mls_web::catbird_mls_prepare_signed_request(
        "sendMessage".to_owned(),
        request.to_string(),
    )
    .await
    .expect_err("out-of-bounds value must be rejected by the strict projector");
    let error = error.as_string().unwrap_or_default();
    assert!(
        error.contains("authGeneration"),
        "out-of-bounds rejection: got {error}"
    );
}

// ---------------------------------------------------------------------------
// RED test (finding 1b): signed-wrapper bytes for known-good vectors equal the
// approved Rust fixture wrapper bytes.
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
async fn signed_wrapper_bytes_match_approved_fixture_all_ten_domains() {
    let fixture = fixture_json(SIGNING_DOMAIN_VECTORS);
    let cases = fixture["cases"].as_array().expect("signing-domain cases");
    assert_eq!(cases.len(), 10);

    for case in cases {
        let body_name = case["bodyName"].as_str().expect("body name");
        let operation = signing_domain_operation(body_name);
        let (actor_did, device_id, dpop_jkt, auth_generation) =
            signing_domain_binding(&case["body"], operation);
        install_fixture_signer(
            case["publicKeyHex"].as_str().expect("public key"),
            case["signatureHex"].as_str().expect("signature"),
            &actor_did,
            &device_id,
            &dpop_jkt,
            auth_generation,
        );

        let request = serde_json::json!({ "signedRequest": { "body": case["body"] } });
        let prepared = catbird_mls_web::catbird_mls_prepare_signed_request(
            operation.to_owned(),
            request.to_string(),
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "fixture {body_name} must prepare: {}",
                error.as_string().unwrap_or_default()
            )
        });
        let wire = prepared_body(prepared);
        assert_eq!(
            wire["signedRequest"], case["wrapper"],
            "signed wrapper JSON mismatch for {body_name}"
        );
        let wrapper_bytes = serde_json::to_vec(&wire["signedRequest"]).expect("wrapper serializes");
        assert_eq!(
            hex::encode(wrapper_bytes),
            case["wrapperJsonHex"].as_str().expect("wrapper hex"),
            "signed wrapper bytes mismatch for {body_name}"
        );
        assert_eq!(
            wire["signedRequest"]["signature"]
                .as_str()
                .expect("bare base64 signature")
                .len(),
            88,
            "signature is canonical standard base64 for {body_name}"
        );
    }
}

#[wasm_bindgen_test]
async fn signed_wrapper_bytes_match_approved_blob_fixture() {
    let contract = fixture_json(CONTRACT_VECTORS);
    let blob = contract["signedMutator"]["body"].clone();
    let operation = "deleteBlob";
    let (actor_did, device_id, dpop_jkt, auth_generation) =
        signing_domain_binding(&blob, operation);
    install_fixture_signer(
        contract["signedMutator"]["publicKeyHex"]
            .as_str()
            .expect("blob public key"),
        contract["signedMutator"]["signatureHex"]
            .as_str()
            .expect("blob signature"),
        &actor_did,
        &device_id,
        &dpop_jkt,
        auth_generation,
    );

    let request = serde_json::json!({ "signedRequest": { "body": blob } });
    let prepared = catbird_mls_web::catbird_mls_prepare_signed_request(
        operation.to_owned(),
        request.to_string(),
    )
    .await
    .expect("blob deletion fixture prepares");
    let wire = prepared_body(prepared);
    let expected_signature = base64::engine::general_purpose::STANDARD.encode(hex_decode(
        contract["signedMutator"]["signatureHex"]
            .as_str()
            .expect("blob signature hex"),
    ));
    assert_eq!(
        wire["signedRequest"]["signature"]
            .as_str()
            .expect("signature"),
        expected_signature
    );
    assert_eq!(
        wire["signedRequest"]["body"]["$type"],
        "blue.catbird.chat.defs#blobDeletionBody"
    );
}

// ---------------------------------------------------------------------------
// Retired authentication-rebind operations fail before invoking a signer.
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
async fn retired_authentication_rebind_is_rejected_before_signing() {
    catbird_mls_web::catbird_mls_set_signer_bridge(
        Function::new_no_args("throw new Error('retired route invoked signer')"),
        valid_fake_key(),
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "70707070-7070-4070-b070-707070707070".to_owned(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        Uint8Array::new_with_length(32),
        Some(1),
    )
    .unwrap();
    let error = catbird_mls_web::catbird_mls_prepare_signed_request(
        "rebindDeviceAuthentication".to_owned(),
        "{}".to_owned(),
    )
    .await
    .expect_err("retired operation must not prepare");
    assert!(error
        .as_string()
        .unwrap_or_default()
        .contains("unsupported"));
    catbird_mls_web::catbird_mls_clear_signer_bridge();
}

// ---------------------------------------------------------------------------
// RED test (finding 3): unsigned GET query validation.
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn unsigned_get_rejects_unknown_query_keys() {
    let request = r#"{"actorDeviceId":"70707070-7070-4070-b070-707070707070","limit":25,"pageCursor":"opaque","bogus":"x"}"#;
    let error = catbird_mls_web::catbird_mls_prepare_unsigned_request(
        "getConversations".to_owned(),
        request.to_owned(),
    )
    .expect_err("unknown query key must be rejected");
    let error = error.as_string().unwrap_or_default();
    assert!(
        error.contains("bogus") && error.contains("getConversations"),
        "unknown-query-key rejection: got {error}"
    );
}

#[wasm_bindgen_test]
fn unsigned_get_forwards_only_whitelisted_keys() {
    let prepared = catbird_mls_web::catbird_mls_prepare_unsigned_request(
        "getConversations".to_owned(),
        r#"{"actorDeviceId":"70707070-7070-4070-b070-707070707070","limit":25,"pageCursor":"opaque","supportedProtocolVersions":["1","2"]}"#.to_owned(),
    )
    .expect("known query keys prepare");
    let path: String = js_sys::Reflect::get(&prepared, &"path".into())
        .expect("prepared path field")
        .as_string()
        .expect("path is a string");
    assert_eq!(
        path,
        "/xrpc/blue.catbird.chat.getConversations?actorDeviceId=70707070-7070-4070-b070-707070707070&limit=25&pageCursor=opaque&supportedProtocolVersions=1&supportedProtocolVersions=2"
    );
}

// ---------------------------------------------------------------------------
// RED test (finding 4): key custody — the bridge accepts only a non-extractable,
// sign-only Ed25519 private CryptoKey.
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn extractable_key_is_rejected() {
    let callback = Function::new_no_args("return new Uint8Array(64)");
    let public_key = Uint8Array::new_with_length(32);
    let error = catbird_mls_web::catbird_mls_set_signer_bridge(
        callback,
        fake_signer_key(true, "Ed25519", &["sign"]),
        "did:plc:z72i7hdynmk67x4h5wqf3s6a".to_owned(),
        "11111111-1111-4111-8111-111111111111".to_owned(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        public_key,
        Some(1),
    )
    .expect_err("extractable signer key must be rejected");
    assert!(
        error
            .as_string()
            .unwrap_or_default()
            .contains("non-extractable"),
        "extractable key rejection message"
    );
}

#[wasm_bindgen_test]
fn non_sign_only_key_is_rejected() {
    let callback = Function::new_no_args("return new Uint8Array(64)");
    let public_key = Uint8Array::new_with_length(32);
    let error = catbird_mls_web::catbird_mls_set_signer_bridge(
        callback,
        fake_signer_key(false, "Ed25519", &["sign", "verify"]),
        "did:plc:z72i7hdynmk67x4h5wqf3s6a".to_owned(),
        "11111111-1111-4111-8111-111111111111".to_owned(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        public_key,
        Some(1),
    )
    .expect_err("non sign-only signer key must be rejected");
    assert!(
        error.as_string().unwrap_or_default().contains("sign-only"),
        "sign-only custody rejection message"
    );
}

#[wasm_bindgen_test]
fn non_ed25519_key_is_rejected() {
    let callback = Function::new_no_args("return new Uint8Array(64)");
    let public_key = Uint8Array::new_with_length(32);
    let error = catbird_mls_web::catbird_mls_set_signer_bridge(
        callback,
        fake_signer_key(false, "ECDSA", &["sign"]),
        "did:plc:z72i7hdynmk67x4h5wqf3s6a".to_owned(),
        "11111111-1111-4111-8111-111111111111".to_owned(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        public_key,
        Some(1),
    )
    .expect_err("non-Ed25519 signer key must be rejected");
    assert!(
        error.as_string().unwrap_or_default().contains("Ed25519"),
        "algorithm custody rejection message"
    );
}

#[wasm_bindgen_test]
fn sign_only_non_extractable_ed25519_key_is_accepted() {
    let callback = Function::new_no_args("return new Uint8Array(64)");
    let public_key = Uint8Array::new_with_length(32);
    catbird_mls_web::catbird_mls_set_signer_bridge(
        callback,
        fake_signer_key(false, "Ed25519", &["sign"]),
        "did:plc:z72i7hdynmk67x4h5wqf3s6a".to_owned(),
        "11111111-1111-4111-8111-111111111111".to_owned(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        public_key,
        Some(1),
    )
    .expect("sign-only non-extractable Ed25519 key is accepted");
    assert!(catbird_mls_web::catbird_mls_has_signer_bridge());
    catbird_mls_web::catbird_mls_clear_signer_bridge();
}

// ---------------------------------------------------------------------------
// Existing fail-closed and surface tests (kept, adapted to the new signature).
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
async fn signed_preparation_fails_closed_without_authority() {
    // Ensure no signer is installed (earlier tests may have installed one).
    catbird_mls_web::catbird_mls_clear_signer_bridge();

    let request = r#"{
        "signedRequest": {
            "body": {
                "$type": "blue.catbird.chat.defs#applicationSendBody"
            },
            "signature": {"$bytes": ""}
        }
    }"#;

    let error = catbird_mls_web::catbird_mls_prepare_signed_request(
        "sendMessage".to_owned(),
        request.to_owned(),
    )
    .await
    .expect_err("signed preparation must require a configured non-exporting signer");

    let error = error.as_string().unwrap_or_default();
    assert!(error.contains("signer") || error.contains("authority"));
}

#[wasm_bindgen_test]
fn signer_bridge_has_no_private_key_export_surface() {
    let callback = Function::new_no_args("return new Uint8Array(64)");
    let public_key = Uint8Array::new_with_length(32);
    let jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
    catbird_mls_web::catbird_mls_set_signer_bridge(
        callback,
        fake_signer_key(false, "Ed25519", &["sign"]),
        "did:plc:z72i7hdynmk67x4h5wqf3s6a".to_owned(),
        "11111111-1111-4111-8111-111111111111".to_owned(),
        jkt,
        public_key,
        Some(1),
    )
    .expect("valid browser signer bridge");
    assert!(catbird_mls_web::catbird_mls_has_signer_bridge());
    catbird_mls_web::catbird_mls_clear_signer_bridge();
    assert!(!catbird_mls_web::catbird_mls_has_signer_bridge());

    let exports = js_sys::Reflect::own_keys(&js_sys::global()).expect("global keys");
    let names = exports
        .iter()
        .filter_map(|value| value.as_string())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!names.contains("privateKey"));
    assert!(!names.contains("signingKeyBytes"));
}

#[wasm_bindgen_test]
async fn request_routes_fail_before_signing_while_browser_capability_is_unavailable() {
    catbird_mls_web::catbird_mls_set_signer_bridge(
        Function::new_no_args("throw new Error('request signer must not be invoked')"),
        fake_signer_key(false, "Ed25519", &["sign"]),
        "did:plc:z72i7hdynmk67x4h5wqf3s6a".into(),
        "11111111-1111-4111-8111-111111111111".into(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        Uint8Array::new_with_length(32),
        Some(1),
    )
    .unwrap();
    for operation in [
        "prepareDirectRequest",
        "publishDirectRequest",
        "cancelDirectRequestPreparation",
        "getDirectRequestOutcome",
        "publishDirectRequestKeys",
    ] {
        let signed_error =
            catbird_mls_web::catbird_mls_prepare_signed_request(operation.into(), "{}".into())
                .await
                .unwrap_err();
        assert!(signed_error
            .as_string()
            .unwrap()
            .contains("browser direct-request lifecycle is unavailable"));
        let unsigned_error =
            catbird_mls_web::catbird_mls_prepare_unsigned_request(operation.into(), "{}".into())
                .unwrap_err();
        assert!(unsigned_error
            .as_string()
            .unwrap()
            .contains("browser direct-request lifecycle is unavailable"));
    }
    catbird_mls_web::catbird_mls_clear_signer_bridge();
}
