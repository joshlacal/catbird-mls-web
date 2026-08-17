#![cfg(target_arch = "wasm32")]

use js_sys::{Function, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn signed_preparation_fails_closed_without_authority() {
    let request = r#"{
        \"signedRequest\": {
            \"body\": {
                \"$type\": \"blue.catbird.chat.defs#applicationSendBody\"
            },
            \"signature\": {\"$bytes\": \"\"}
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
