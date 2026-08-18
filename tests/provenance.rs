//! Provenance guards for vendored clean-chat artifacts.
//!
//! `src/generated/blue.catbird.chat.defs.json` (the strict projection schema)
//! and `tests/fixtures/*.json` (the approved signing-vector corpus) are copied
//! verbatim from the pinned approved catbird-mls sibling (d69da1e1). These
//! tests fail closed if any vendored artifact drifts from the sibling, and they
//! assert the schema's embedded provenance matches the approved Petrel
//! revision recorded by the Task 1 generator.

#![cfg(not(target_arch = "wasm32"))]

use std::path::PathBuf;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sibling(path: &str) -> PathBuf {
    crate_root().join("../catbird-mls").join(path)
}

fn vendored(path: &str) -> PathBuf {
    crate_root().join(path)
}

fn read_bytes(path: &PathBuf) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

const VENDORED_ARTIFACTS: &[(&str, &str)] = &[
    (
        "src/generated/blue.catbird.chat.defs.json",
        "src/orchestrator/generated/blue.catbird.chat.defs.json",
    ),
    (
        "tests/fixtures/mls_chat_signing_domain_vectors.json",
        "src/orchestrator/generated/mls_chat_signing_domain_vectors.json",
    ),
    (
        "tests/fixtures/mls_chat_contract_vectors.json",
        "src/orchestrator/generated/mls_chat_contract_vectors.json",
    ),
    (
        "tests/fixtures/mls_chat_control_fingerprint_source.json",
        "src/orchestrator/generated/mls_chat_control_fingerprint_source.json",
    ),
];

#[test]
fn vendored_artifacts_match_pinned_sibling_byte_for_byte() {
    for (vendored_path, sibling_path) in VENDORED_ARTIFACTS {
        let vendored_bytes = read_bytes(&vendored(vendored_path));
        let sibling_bytes = read_bytes(&sibling(sibling_path));
        assert_eq!(
            sha256(&vendored_bytes),
            sha256(&sibling_bytes),
            "{vendored_path} must be byte-identical to the pinned sibling {sibling_path}"
        );
    }
}

#[test]
fn vendored_schema_embeds_approved_petrel_provenance() {
    let schema: serde_json::Value = serde_json::from_slice(&read_bytes(&vendored(
        "src/generated/blue.catbird.chat.defs.json",
    )))
    .expect("vendored schema is valid JSON");
    let provenance = &schema["_catbird_mls_provenance"];
    assert_eq!(
        provenance["sourceRevision"]
            .as_str()
            .expect("source revision"),
        "954d7ab20f362b731ee13f87eea89ae83558c624",
        "schema source revision must match the approved Petrel head"
    );
    assert_eq!(
        provenance["sourceSha256"].as_str().expect("source sha256"),
        "88fb17ca9ca2bcc605c22123ba3ae801b2baf1f725afe85934680b5cd2f66c7a",
        "schema source sha256 must match the approved Petrel lexicon"
    );
    assert_eq!(
        provenance["generatorVersion"]
            .as_u64()
            .expect("generator version"),
        7
    );
}

#[test]
fn vendored_fixture_corpus_matches_approved_counts() {
    let signing: serde_json::Value = serde_json::from_slice(&read_bytes(&vendored(
        "tests/fixtures/mls_chat_signing_domain_vectors.json",
    )))
    .expect("signing-domain vectors are valid JSON");
    assert_eq!(
        signing["cases"].as_array().expect("cases").len(),
        11,
        "signing-domain corpus must stay at the approved 11 cases"
    );
    assert_eq!(
        signing["_catbird_mls_provenance"]["vectorSetCount"].as_u64(),
        Some(25),
        "signing-domain corpus must belong to the approved all-25 vector set"
    );

    let contract: serde_json::Value = serde_json::from_slice(&read_bytes(&vendored(
        "tests/fixtures/mls_chat_contract_vectors.json",
    )))
    .expect("contract vectors are valid JSON");
    assert_eq!(
        contract["controlEntryFingerprints"]["cases"]
            .as_array()
            .expect("control cases")
            .len(),
        13,
        "control corpus must stay at the approved 13 cases"
    );

    let control: serde_json::Value = serde_json::from_slice(&read_bytes(&vendored(
        "tests/fixtures/mls_chat_control_fingerprint_source.json",
    )))
    .expect("control fingerprint source is valid JSON");
    assert_eq!(
        control["cases"].as_array().expect("cases").len(),
        13,
        "control fingerprint source must stay at the approved 13 cases"
    );
}
