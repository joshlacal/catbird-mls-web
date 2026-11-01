//! The delivery service rejects any KeyPackage whose leaf does not match its
//! closed clean-leaf profile (`mls-ds/server/src/chat_protocol/wire.rs`
//! `validate_clean_leaf_shape`): MLS 1.0 only, the XWING suite only, no leaf
//! extensions, no proposals, Basic credentials only. A live browser enrollment
//! against the shipping router returned HTTP 400 `InvalidKeyPackage` while the
//! browser advertised OpenMLS' default (everything) capabilities. These tests
//! assert the browser's own KeyPackage bytes carry exactly the accepted profile,
//! so a drift fails here instead of only at the router.
#![cfg(target_arch = "wasm32")]
use catbird_mls::orchestrator::mls_provider::MlsCryptoContext;
use catbird_mls_web::{SqliteConn, WasmMLSContextExport as Context};
use openmls::prelude::tls_codec::Deserialize as _;
use openmls_traits::OpenMlsProvider;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_dedicated_worker);

fn open(path: &str) -> Context {
    Context::open(path, &"bc".repeat(32)).unwrap()
}

#[wasm_bindgen_test]
async fn browser_key_package_leaf_matches_closed_service_profile() {
    SqliteConn::initialize_opfs().await.unwrap();
    let path = format!("kp-profile-{}.db", uuid::Uuid::new_v4());
    let ctx = open(&path);
    let identity = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#00000000-0000-4000-8000-000000000000";

    let kp = ctx
        .create_key_package(identity.as_bytes().to_vec())
        .unwrap();

    // Parse the produced wire bytes exactly as the native request paths do: a
    // framed MlsMessageOut carrying a KeyPackage, then validated.
    let message = openmls::prelude::MlsMessageIn::tls_deserialize_exact(&kp.key_package_data)
        .expect("key package is a framed MlsMessage");
    let openmls::prelude::MlsMessageBodyIn::KeyPackage(kp_in) = message.extract() else {
        panic!("expected KeyPackage body");
    };
    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let crypto = OpenMlsProvider::crypto(&provider);
    let key_package = kp_in
        .validate(crypto, openmls::prelude::ProtocolVersion::Mls10)
        .expect("key package validates");
    let leaf = key_package.leaf_node();

    let capabilities = leaf.capabilities();
    assert_eq!(
        capabilities.versions(),
        [openmls::prelude::ProtocolVersion::Mls10],
        "service requires MLS 1.0 only"
    );
    assert_eq!(
        capabilities.ciphersuites().len(),
        1,
        "service requires exactly one ciphersuite"
    );
    assert_eq!(
        capabilities.ciphersuites()[0],
        openmls::prelude::Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519.into(),
        "service requires the XWING ciphersuite"
    );
    assert!(
        capabilities.extensions().is_empty(),
        "service rejects leaf capability extensions"
    );
    assert!(
        capabilities.proposals().is_empty(),
        "service rejects leaf capability proposals"
    );
    assert_eq!(
        capabilities.credentials(),
        [openmls::prelude::CredentialType::Basic],
        "service requires Basic credentials only"
    );
    assert!(
        leaf.extensions().iter().next().is_none(),
        "service rejects leaf extensions"
    );

    // The wire-level values the service compares before its shape check.
    assert_eq!(
        leaf.credential().serialized_content(),
        identity.as_bytes(),
        "BasicCredential content must be the exact did#device identity"
    );
    assert_eq!(
        leaf.signature_key().as_slice(),
        kp.signature_public_key.as_slice(),
        "leaf signature key must be the signer's public key"
    );

    // Lifetime bounds: not_before < now < not_after, at least ten minutes of
    // remaining life, and at most 30 days + 1 hour long.
    let openmls::treesync::LeafNodeSource::KeyPackage(lifetime) = leaf.leaf_node_source() else {
        panic!("leaf must be sourced from a KeyPackage");
    };
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
    assert!(lifetime.not_before() < now, "lifetime must have started");
    assert!(now < lifetime.not_after(), "lifetime must not be expired");
    assert!(
        lifetime.not_after() - now >= 10 * 60,
        "service requires at least ten minutes remaining"
    );
    assert!(
        lifetime.not_after().saturating_sub(lifetime.not_before()) <= 30 * 24 * 60 * 60 + 60 * 60,
        "service rejects lifetimes over 30 days + 1 hour"
    );
}
