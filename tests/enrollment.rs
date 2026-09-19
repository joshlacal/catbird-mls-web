//! Real encrypted OPFS custody with a deterministic HTTP response-loss fixture.
//! The fixture validates transport retry identity, not delivery-service authorization.
#![cfg(target_arch = "wasm32")]
use catbird_mls::orchestrator::{credentials::CredentialStore, mls_provider::MlsCryptoContext};
use std::{rc::Rc, sync::Arc};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_dedicated_worker);
mod api_client {
    pub use catbird_mls_web::WasmApiClientExport as WasmApiClient;
}
mod wasm_mls_context {
    pub use catbird_mls_web::WasmMLSContextExport as WasmMLSContext;
}
mod sqlite_conn {
    pub use catbird_mls_web::SqliteConn;
}
#[path = "../src/browser_enrollment.rs"]
mod browser_enrollment;
#[path = "../src/credentials.rs"]
mod credentials;
use api_client::WasmApiClient;
use credentials::SqliteCredentialStore;
use sqlite_conn::SqliteConn;
use wasm_mls_context::WasmMLSContext;

#[wasm_bindgen(inline_js = r#"
let originalFetch;
let captured = [];
let substitute = false;
export function installEnrollmentFixture() {
  originalFetch = globalThis.fetch; captured = []; substitute = false;
  globalThis.fetch = async (request) => {
    const text = await request.clone().text(); captured.push(text);
    if (captured.length === 1) throw new Error('injected response loss');
    const b = JSON.parse(text).signedRequest.body;
    const response = new Response(JSON.stringify({device:{deviceId:substitute ? "00000000-0000-4000-8000-000000000999" : b.deviceId,keyId:b.keyId,
      signaturePublicKey:{$bytes:b.signaturePublicKey},authGeneration:7,status:'active',
      availablePackageCount:1,reservedPackageCount:0,
      createdAt:'2026-09-19T12:00:00.000Z',updatedAt:'2026-09-19T12:00:00.000Z'}}),
      {status:200,headers:{'content-type':'application/json'}});
    Object.defineProperty(response,'url',{value:request.url});
    return response;
  };
}
export function substituteDevice(value) { substitute = value; }
export function installAuthorityFixture(mode) {
  originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (url !== 'https://chat.catbird.blue/.well-known/did.json' || options.redirect !== 'error' || options.credentials !== 'omit')
      throw new Error('untrusted resolver configuration');
    const response = new Response(mode === 'oversized' ? new Uint8Array(65537) : '{"id":"did:web:chat.catbird.blue"}', {status:200});
    Object.defineProperty(response,'url',{value:url});
    Object.defineProperty(response,'redirected',{value:mode === 'redirected'});
    return response;
  };
}
export function captureCount() { return captured.length; }
export function exactRetry() { return captured.length >= 2 && captured.every(value => value === captured[0]); }
export function restoreEnrollmentFixture() { globalThis.fetch = originalFetch; }
"#)]
extern "C" {
    fn installEnrollmentFixture();
    fn installAuthorityFixture(mode: &str);
    fn captureCount() -> u32;
    fn substituteDevice(value: bool);
    fn exactRetry() -> bool;
    fn restoreEnrollmentFixture();
}
struct RestoreFetch;
impl Drop for RestoreFetch {
    fn drop(&mut self) {
        restoreEnrollmentFixture();
    }
}

#[wasm_bindgen_test]
async fn lost_response_reopens_exact_attempt_and_nonexporting_signer() {
    SqliteConn::initialize_opfs().await.unwrap();
    let path = format!("enrollment-{}.db", uuid::Uuid::new_v4());
    let key = "bd".repeat(32);
    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    let api = Arc::new(WasmApiClient::new("https://enrollment.invalid".into()));
    api.set_auth(did.into(), "fixture-only".into());
    installEnrollmentFixture();
    let _restore = RestoreFetch;
    let (exact_bytes, device_id, public) = {
        let conn = Rc::new(SqliteConn::open(&path, &key).unwrap());
        SqliteCredentialStore::ensure_schema(&conn).unwrap();
        catbird_mls_web::WasmSqliteStorage::ensure_schema(&conn).unwrap();
        let ctx = Arc::new(WasmMLSContext::open_with_conn(conn.clone()).unwrap());
        let creds = Arc::new(SqliteCredentialStore::new(conn));
        creds.attach_runtime(ctx.clone(), api.clone()).unwrap();
        let failure =
            browser_enrollment::initialize_enrollment(ctx, creds.clone(), api.clone(), did)
                .await
                .unwrap_err();
        assert_eq!(captureCount(), 1, "unexpected pre-HTTP failure: {failure}");
        let journal = creds.enrollment(did).unwrap().unwrap();
        assert!(journal.auth_generation.is_none());
        assert!(!creds.has_complete_binding(did).unwrap());
        (journal.request_body, journal.device_id, journal.public_key)
    };
    let conn = Rc::new(SqliteConn::open(&path, &key).unwrap());
    let ctx = Arc::new(WasmMLSContext::open_with_conn(conn.clone()).unwrap());
    let creds = Arc::new(SqliteCredentialStore::new(conn));
    creds.attach_runtime(ctx.clone(), api.clone()).unwrap();
    substituteDevice(true);
    assert!(browser_enrollment::initialize_enrollment(
        ctx.clone(),
        creds.clone(),
        api.clone(),
        did
    )
    .await
    .is_err());
    assert_eq!(creds.get_auth_generation(did).await.unwrap(), None);
    assert_eq!(
        creds.enrollment(did).unwrap().unwrap().request_body,
        exact_bytes
    );
    substituteDevice(false);
    let mls_did = browser_enrollment::initialize_enrollment(ctx.clone(), creds.clone(), api, did)
        .await
        .unwrap();
    assert!(exactRetry());
    assert_eq!(mls_did, format!("{did}#{device_id}"));
    assert_eq!(creds.get_auth_generation(did).await.unwrap(), Some(7));
    assert!(creds.get_signing_key(did).await.unwrap().is_none());
    let binding = creds.enrollment(did).unwrap().unwrap();
    assert_eq!(binding.request_body, exact_bytes);
    let proof = creds
        .sign_clean_chat_transcript(did, b"exact signing bytes", &binding.key_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(proof.public_key, public);
    assert_eq!(proof.auth_generation, Some(7));
    ed25519_dalek::VerifyingKey::from_bytes(proof.public_key.as_slice().try_into().unwrap())
        .unwrap()
        .verify_strict(
            b"exact signing bytes",
            &ed25519_dalek::Signature::from_slice(&proof.signature).unwrap(),
        )
        .unwrap();
    assert!(creds
        .sign_clean_chat_transcript(did, b"bytes", "substituted-key")
        .await
        .is_err());
    assert!(creds.clear_all(did).await.is_err());
    assert_eq!(
        ctx.identity_public_key(mls_did.into_bytes()).unwrap(),
        public
    );
}

#[wasm_bindgen_test]
async fn legacy_hash_identity_is_retained_and_never_silently_reenrolled() {
    SqliteConn::initialize_opfs().await.unwrap();
    let path = format!("legacy-enrollment-{}.db", uuid::Uuid::new_v4());
    let conn = Rc::new(SqliteConn::open(&path, &"bc".repeat(32)).unwrap());
    SqliteCredentialStore::ensure_schema(&conn).unwrap();
    catbird_mls_web::WasmSqliteStorage::ensure_schema(&conn).unwrap();
    let ctx = Arc::new(WasmMLSContext::open_with_conn(conn.clone()).unwrap());
    let creds = Arc::new(SqliteCredentialStore::new(conn));
    let did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
    creds.store_signing_key(did, &[5; 32]).await.unwrap();
    creds
        .store_device_uuid(did, "00000000-0000-4000-8000-000000000001")
        .await
        .unwrap();
    creds.store_mls_did(did, did).await.unwrap();
    let api = Arc::new(WasmApiClient::new("https://enrollment.invalid".into()));
    api.set_auth(did.into(), "fixture-only".into());
    assert!(
        browser_enrollment::initialize_enrollment(ctx, creds.clone(), api, did)
            .await
            .unwrap_err()
            .to_string()
            .contains("explicit new-device")
    );
    assert_eq!(creds.get_signing_key(did).await.unwrap(), Some(vec![5; 32]));
    assert!(creds.enrollment(did).unwrap().is_none());
    assert_eq!(creds.get_auth_generation(did).await.unwrap(), None);
}

#[wasm_bindgen_test]
async fn receipt_resolver_is_pinned_redirect_free_and_byte_bounded() {
    SqliteConn::initialize_opfs().await.unwrap();
    let conn = Rc::new(
        SqliteConn::open(
            &format!("resolver-{}.db", uuid::Uuid::new_v4()),
            &"ba".repeat(32),
        )
        .unwrap(),
    );
    SqliteCredentialStore::ensure_schema(&conn).unwrap();
    catbird_mls_web::WasmSqliteStorage::ensure_schema(&conn).unwrap();
    let creds = SqliteCredentialStore::new(conn);
    for mode in ["valid", "oversized", "redirected"] {
        installAuthorityFixture(mode);
        let _restore = RestoreFetch;
        let result = creds.direct_request_receipt_authority_document().await;
        if mode == "valid" {
            assert_eq!(
                result.unwrap().unwrap(),
                br#"{"id":"did:web:chat.catbird.blue"}"#
            );
        } else {
            assert!(result.is_err());
        }
    }
}
