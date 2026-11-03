//! Shared provider exercised against the assembled browser crate in a real Worker.
#![cfg(target_arch = "wasm32")]

use base64::Engine as _;
use catbird_mls::orchestrator::direct_request_bootstrap::DirectRequestBootstrapInput;
use catbird_mls::orchestrator::mls_provider::MlsCryptoContext;
use catbird_mls::MLSError;
use catbird_mls_web::{SqliteConn, WasmMLSContextExport as WasmMLSContext, WasmSqliteStorage};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use std::rc::Rc;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn provider_reopens_identity_and_group_from_opfs() {
    SqliteConn::initialize_opfs().await.unwrap();
    let path = format!("provider-{}.db", uuid::Uuid::new_v4());
    let key = "ab".repeat(32);
    let identity = b"did:example:alice#device".to_vec();
    let (public_key, group_id) = {
        let context = WasmMLSContext::open(&path, &key).unwrap();
        let provider: &dyn MlsCryptoContext = &context;
        let kp = provider.create_key_package(identity.clone()).unwrap();
        let group = provider.create_group(identity.clone(), None).unwrap();
        provider.ensure_storage_durable().unwrap();
        (kp.signature_public_key, group.group_id)
    };
    let context = WasmMLSContext::open(&path, &key).unwrap();
    let provider: &dyn MlsCryptoContext = &context;
    let kp = provider.create_key_package(identity).unwrap();
    assert_eq!(public_key, kp.signature_public_key);
    assert_eq!(provider.get_epoch(group_id.clone()).unwrap(), 0);
    assert!(provider
        .add_members_with_aad(group_id.clone(), vec![], Some(vec![1]))
        .is_err());
    assert_eq!(provider.get_epoch(group_id).unwrap(), 0);
}
fn assert_valid_signature(context: &WasmMLSContext, identity: &[u8], public: &[u8]) {
    let payload = b"retained signer test".to_vec();
    let signature =
        MlsCryptoContext::sign_with_identity_key(context, identity.to_vec(), payload.clone())
            .unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(public.try_into().unwrap())
        .unwrap()
        .verify_strict(
            &payload,
            &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();
}

#[wasm_bindgen_test]
async fn invalid_identity_import_preserves_enrolled_signer_after_reopen() {
    SqliteConn::initialize_opfs().await.unwrap();
    let path = format!("signer-{}.db", uuid::Uuid::new_v4());
    let key = "ab".repeat(32);
    let identity = b"did:example:alice#device".to_vec();
    let (public, exported) = {
        let context = WasmMLSContext::open(&path, &key).unwrap();
        let public = context
            .create_key_package(identity.clone())
            .unwrap()
            .signature_public_key;
        let exported = MlsCryptoContext::export_identity_key(&context, identity.clone()).unwrap();
        let original: serde_json::Value = serde_json::from_slice(&exported).unwrap();
        let mut invalids = Vec::new();
        let mut mismatch = original.clone();
        mismatch["private"][0] = serde_json::json!(mismatch["private"][0].as_u64().unwrap() ^ 1);
        invalids.push(mismatch);
        let mut short = original.clone();
        short["private"].as_array_mut().unwrap().pop();
        invalids.push(short);
        let wrong_scheme = SignatureKeyPair::from_raw(
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            vec![1; 32],
            public.clone(),
        );
        invalids.push(serde_json::to_value(wrong_scheme).unwrap());
        let mut short_public = original.clone();
        short_public["public"].as_array_mut().unwrap().pop();
        invalids.push(short_public);
        let replacement = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        invalids.push(serde_json::to_value(replacement).unwrap());
        for invalid in invalids {
            assert!(MlsCryptoContext::import_identity_key(
                &context,
                identity.clone(),
                serde_json::to_vec(&invalid).unwrap()
            )
            .is_err());
            assert_eq!(
                MlsCryptoContext::export_identity_key(&context, identity.clone()).unwrap(),
                exported
            );
            assert_valid_signature(&context, &identity, &public);
        }
        MlsCryptoContext::import_identity_key(&context, identity.clone(), exported.clone())
            .unwrap();
        assert_valid_signature(&context, &identity, &public);
        MlsCryptoContext::ensure_storage_durable(&context).unwrap();
        (public, exported)
    };
    let reopened = WasmMLSContext::open(&path, &key).unwrap();
    assert_eq!(
        MlsCryptoContext::export_identity_key(&reopened, identity.clone()).unwrap(),
        exported
    );
    assert_valid_signature(&reopened, &identity, &public);
}

#[wasm_bindgen_test]
async fn external_join_cannot_overwrite_request_candidate_after_reopen() {
    use sha2::Digest;
    SqliteConn::initialize_opfs().await.unwrap();
    let path = format!("candidate-{}.db", uuid::Uuid::new_v4());
    let key = "ab".repeat(32);
    let actor = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#00000000-0000-4000-8000-000000000000";
    let recipient = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb#00000000-0000-4000-8000-000000000001";
    let conn = Rc::new(SqliteConn::open(&path, &key).unwrap());
    WasmSqliteStorage::ensure_schema(&conn).unwrap();
    let context = WasmMLSContext::open_with_conn(Rc::clone(&conn)).unwrap();
    let actor_package = context
        .create_key_package(actor.as_bytes().to_vec())
        .unwrap();
    let recipient_package = context
        .create_key_package(recipient.as_bytes().to_vec())
        .unwrap();
    let now = chrono::Utc::now().timestamp() as u64;
    let context_json = serde_json::to_vec(&serde_json::json!({
            "protocolVersion":"2", "requestId":uuid::Uuid::new_v4().to_string(),
            "firstMessageId":uuid::Uuid::new_v4().to_string(), "conversationId":uuid::Uuid::new_v4().to_string(),
            "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
            "actorDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "actorDeviceId":"00000000-0000-4000-8000-000000000000",
            "actorKeyId":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&actor_package.signature_public_key)),
            "recipientDid":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", "preparationDigest":base64::engine::general_purpose::STANDARD.encode([42;32])
        })).unwrap();
    let input = DirectRequestBootstrapInput {
        draft_id: uuid::Uuid::new_v4().to_string(),
        context_json,
        group_id: vec![37; 32],
        generation: 0,
        state_version: 1,
        key_packages: vec![recipient_package.key_package_data],
        expected_package_refs: vec![recipient_package.hash_ref],
        authority_import_until: now + 20 * 86400,
        preparation_request_digest: [21; 32],
        receipt_authority_key: vec![2; 33],
        sequencer_did: "did:web:chat.catbird.blue".into(),
        // The sequencer's real `#mls-receipt-1` P-256 SEC1 key.
        sequencer_receipt_authority_key: p256::ecdsa::SigningKey::from_slice(&[19; 32])
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        text: "retained encrypted introduction".into(),
        invitation: None,
        metadata: catbird_mls::metadata::GroupMetadataV1 {
            version: 1,
            title: "Request".into(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
            space_avatar: None,
        },
    };
    let record = MlsCryptoContext::prepare_direct_request_bootstrap(&context, &input).unwrap();
    assert!(MlsCryptoContext::supports_direct_request_bootstrap(
        &context
    ));
    let before = conn
        .query_text(
            "SELECT hex(storage_key), hex(value) FROM openmls_kv ORDER BY storage_key",
            &[],
            2,
        )
        .unwrap();
    let err = MlsCryptoContext::create_external_commit(
        &context,
        record.bootstrap.final_group_info.clone(),
        b"did:example:attacker#device".to_vec(),
    )
    .err()
    .expect("request-owned external join must fail");
    assert!(matches!(err, MLSError::OperationNotSupported { .. }));
    assert_eq!(
        MlsCryptoContext::list_direct_request_journal(&context).unwrap(),
        vec![record.clone()]
    );
    assert!(MlsCryptoContext::get_epoch(&context, input.group_id.clone()).is_err());
    assert!(context.ensure_group_loaded(&input.group_id).is_err());
    assert_eq!(
        conn.query_text(
            "SELECT hex(storage_key), hex(value) FROM openmls_kv ORDER BY storage_key",
            &[],
            2,
        )
        .unwrap(),
        before
    );
    drop(context);
    drop(conn);
    let conn = Rc::new(SqliteConn::open(&path, &key).unwrap());
    let reopened = WasmMLSContext::open_with_conn(Rc::clone(&conn)).unwrap();
    assert_eq!(
        MlsCryptoContext::list_direct_request_journal(&reopened).unwrap(),
        vec![record.clone()]
    );
    assert_eq!(
        conn.query_text(
            "SELECT hex(storage_key), hex(value) FROM openmls_kv ORDER BY storage_key",
            &[],
            2,
        )
        .unwrap(),
        before
    );
    assert_eq!(
        MlsCryptoContext::prepare_direct_request_bootstrap(&reopened, &input).unwrap(),
        record
    );
    assert!(reopened.ensure_group_loaded(&input.group_id).is_err());
}
