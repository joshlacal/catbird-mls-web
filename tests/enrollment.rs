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
let chatScenario = 'valid';
export function setChatScenario(s) { chatScenario = s; }
export function installAuthorityFixture(mode) {
  originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (url !== 'https://chat.catbird.blue/.well-known/did.json' || options.redirect !== 'error' || options.credentials !== 'omit')
      throw new Error('untrusted resolver configuration');
    const response = new Response(mode === 'oversized' ? new Uint8Array(1048577) : '{"id":"did:web:chat.catbird.blue"}', {status:200});
    Object.defineProperty(response,'url',{value:url});
    Object.defineProperty(response,'redirected',{value:mode === 'redirected'});
    return response;
  };
}
export function installDeclarationFixture() {
  originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, options) => {
    const url = typeof input === 'string' ? input : input.url;
    if (options.redirect !== 'error' || options.credentials !== 'omit')
      throw new Error('untrusted resolver configuration');
    if (url === 'https://plc.directory/did:plc:aliceuser111111111111111') {
      if (chatScenario === 'missing_pds') {
        const r = new Response(JSON.stringify({id: 'did:plc:aliceuser111111111111111', service: []}), {status: 200});
        Object.defineProperty(r, 'url', {value: url});
        Object.defineProperty(r, 'redirected', {value: false});
        return r;
      }
      if (chatScenario === 'unsafe_pds') {
        const r = new Response(JSON.stringify({
          id: 'did:plc:aliceuser111111111111111',
          service: [{id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: 'http://127.0.0.1:8080'}]
        }), {status: 200});
        Object.defineProperty(r, 'url', {value: url});
        Object.defineProperty(r, 'redirected', {value: false});
        return r;
      }
      if (chatScenario === 'doc_id_mismatch') {
        const r = new Response(JSON.stringify({
          id: 'did:plc:bobuser2222222222222222',
          service: [{id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: 'https://pds.example.com'}]
        }), {status: 200});
        Object.defineProperty(r, 'url', {value: url});
        Object.defineProperty(r, 'redirected', {value: false});
        return r;
      }
      const r = new Response(JSON.stringify({
        id: 'did:plc:aliceuser111111111111111',
        service: [{id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: 'https://pds.example.com'}]
      }), {status: 200});
        Object.defineProperty(r, 'url', {value: url});
        Object.defineProperty(r, 'redirected', {value: false});
        return r;
    }
    if (url === 'https://alice.example.com/.well-known/did.json') {
      const r = new Response(JSON.stringify({
        id: 'did:web:alice.example.com',
        service: [{id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: 'https://pds.example.com'}]
      }), {status: 200});
      Object.defineProperty(r, 'url', {value: url});
      Object.defineProperty(r, 'redirected', {value: false});
      return r;
    }
    if (url.startsWith('https://pds.example.com/xrpc/com.atproto.repo.getRecord')) {
      if (chatScenario === 'record_not_found') {
        const r = new Response(JSON.stringify({error: 'RecordNotFound', message: 'Record not found'}), {status: 404});
        Object.defineProperty(r, 'url', {value: url});
        Object.defineProperty(r, 'redirected', {value: false});
        return r;
      }
      if (chatScenario === 'server_error') {
        const r = new Response('server error', {status: 500});
        Object.defineProperty(r, 'url', {value: url});
        Object.defineProperty(r, 'redirected', {value: false});
        return r;
      }
      if (chatScenario === 'invalid_request') {
        const r = new Response(JSON.stringify({error: 'InvalidRequest', message: 'Invalid query'}), {status: 400});
        Object.defineProperty(r, 'url', {value: url});
        Object.defineProperty(r, 'redirected', {value: false});
        return r;
      }
      if (chatScenario === 'malformed_uri') {
        const r = new Response(JSON.stringify({
          uri: 'at://did:plc:other/blue.catbird.chat.declaration/self',
          value: {
            $type: 'blue.catbird.chat.declaration',
            allowIncoming: 'all',
            deliveryService: 'did:web:chat.catbird.blue',
            protocolVersion: '1'
          }
        }), {status: 200});
        Object.defineProperty(r, 'url', {value: url});
        Object.defineProperty(r, 'redirected', {value: false});
        return r;
      }
      if (chatScenario === 'malformed_delivery_service') {
        const r = new Response(JSON.stringify({
          uri: 'at://did:plc:aliceuser111111111111111/blue.catbird.chat.declaration/self',
          value: {
            $type: 'blue.catbird.chat.declaration',
            allowIncoming: 'all',
            deliveryService: 'not-a-did',
            protocolVersion: '1'
          }
        }), {status: 200});
        Object.defineProperty(r, 'url', {value: url});
        Object.defineProperty(r, 'redirected', {value: false});
        return r;
      }
      if (chatScenario === 'oversized') {
        const r = new Response(new Uint8Array(1048577), {status: 200});
        Object.defineProperty(r, 'url', {value: url});
        Object.defineProperty(r, 'redirected', {value: false});
        return r;
      }
      if (chatScenario === 'redirected') {
        const r = new Response('{}', {status: 200});
        Object.defineProperty(r, 'url', {value: url});
        Object.defineProperty(r, 'redirected', {value: true});
        return r;
      }
      const target = url.includes('did%3Aweb%3Aalice.example.com') || url.includes('did:web:alice.example.com')
        ? 'did:web:alice.example.com'
        : 'did:plc:aliceuser111111111111111';
      const r = new Response(JSON.stringify({
        uri: `at://${target}/blue.catbird.chat.declaration/self`,
        value: {
          $type: 'blue.catbird.chat.declaration',
          allowIncoming: 'all',
          deliveryService: 'did:web:chat.catbird.blue',
          protocolVersion: '1',
          createdAt: '2026-09-19T12:00:00.000Z'
        }
      }), {status: 200});
      Object.defineProperty(r, 'url', {value: url});
      Object.defineProperty(r, 'redirected', {value: false});
      return r;
    }
    throw new Error('unexpected url: ' + url);
  };
}
export function captureCount() { return captured.length; }
export function exactRetry() { return captured.length >= 2 && captured.every(value => value === captured[0]); }
export function restoreEnrollmentFixture() { globalThis.fetch = originalFetch; }
"#)]
extern "C" {
    fn installEnrollmentFixture();
    fn installAuthorityFixture(mode: &str);
    fn setChatScenario(s: &str);
    fn installDeclarationFixture();
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
        let result = creds
            .direct_request_receipt_authority_document("did:web:chat.catbird.blue")
            .await;
        if mode == "valid" {
            assert_eq!(
                result.unwrap().unwrap(),
                br#"{"id":"did:web:chat.catbird.blue"}"#
            );
        } else {
            assert!(result.is_err());
        }
    }

    // Strict doc.id check: expecting a different authority DID must fail
    installAuthorityFixture("valid");
    let _restore = RestoreFetch;
    assert!(creds
        .direct_request_receipt_authority_document("did:web:wrong.authority.example")
        .await
        .is_err());

    // Safe public host check: local and loopback addresses fail closed
    assert!(creds
        .direct_request_receipt_authority_document("did:web:127.0.0.1")
        .await
        .is_err());
    assert!(creds
        .direct_request_receipt_authority_document("did:web:localhost")
        .await
        .is_err());

    // Non-did:web syntax fails closed
    assert!(creds
        .direct_request_receipt_authority_document("did:plc:someone")
        .await
        .is_err());
}

#[wasm_bindgen_test]
async fn chat_declaration_resolver_binds_pds_record_and_fails_closed() {
    SqliteConn::initialize_opfs().await.unwrap();
    let conn = Rc::new(
        SqliteConn::open(
            &format!("decl-{}.db", uuid::Uuid::new_v4()),
            &"ba".repeat(32),
        )
        .unwrap(),
    );
    SqliteCredentialStore::ensure_schema(&conn).unwrap();
    catbird_mls_web::WasmSqliteStorage::ensure_schema(&conn).unwrap();
    let creds = SqliteCredentialStore::new(conn);
    let did = "did:plc:aliceuser111111111111111";

    // 1. Valid resolution for did:plc
    installDeclarationFixture();
    let _restore = RestoreFetch;
    setChatScenario("valid");
    assert_eq!(
        creds.get_chat_declaration_authority(did).await.unwrap(),
        Some("did:web:chat.catbird.blue".to_string())
    );

    // Valid resolution for did:web user
    assert_eq!(
        creds
            .get_chat_declaration_authority("did:web:alice.example.com")
            .await
            .unwrap(),
        Some("did:web:chat.catbird.blue".to_string())
    );

    // 2. Explicit RecordNotFound -> None
    setChatScenario("record_not_found");
    assert_eq!(
        creds.get_chat_declaration_authority(did).await.unwrap(),
        None
    );

    // 3. Server errors, invalid requests, and malformed responses fail closed
    for scenario in [
        "server_error",
        "invalid_request",
        "malformed_uri",
        "malformed_delivery_service",
        "missing_pds",
        "unsafe_pds",
        "doc_id_mismatch",
        "oversized",
        "redirected",
    ] {
        setChatScenario(scenario);
        assert!(
            creds.get_chat_declaration_authority(did).await.is_err(),
            "scenario {scenario} must fail closed"
        );
    }

    // 4. Invalid bare DID syntax fails closed before network request
    assert!(creds
        .get_chat_declaration_authority("not-a-did")
        .await
        .is_err());
    assert!(creds
        .get_chat_declaration_authority("did:plc:alice#fragment")
        .await
        .is_err());
}
