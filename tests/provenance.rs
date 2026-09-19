//! Provenance guards for vendored clean-chat artifacts.
//!
//! `src/generated/blue.catbird.chat.defs.json` (the strict projection schema)
//! and `tests/fixtures/*.json` (the approved signing-vector corpus) are copied
//! verbatim from the sealed catbird-mls input recorded by scripts/sync-chat-artifacts.py. These
//! tests fail closed if any vendored artifact drifts from the sibling, and they
//! validate every copied byte against the retained source revision and hash manifest.

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
fn vendored_artifacts_match_sealed_input_manifest() {
    let manifest: serde_json::Value = serde_json::from_slice(&read_bytes(&vendored(
        "tests/fixtures/chat-artifact-provenance.json",
    )))
    .unwrap();
    let revision = manifest["coreRevision"].as_str().unwrap();
    assert_eq!(revision.len(), 40);
    for entry in manifest["artifacts"].as_array().unwrap() {
        let output = read_bytes(&vendored(entry["target"].as_str().unwrap()));
        assert_eq!(sha256(&output), entry["sha256"].as_str().unwrap());
        let pinned = std::process::Command::new("jj")
            .current_dir(crate_root().join("../catbird-mls"))
            .args([
                "file",
                "show",
                "-r",
                revision,
                entry["source"].as_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(pinned.status.success());
        assert_eq!(pinned.stdout, output);
    }
    let schema: serde_json::Value = serde_json::from_slice(&read_bytes(&vendored(
        "src/generated/blue.catbird.chat.defs.json",
    )))
    .unwrap();
    for key in [
        "directRequestEntry",
        "directRequestAcceptanceEntry",
        "directRequestInventoryScope",
        "subscriptionMessage",
    ] {
        assert!(
            schema["defs"].get(key).is_some(),
            "Missing request contract {key}"
        );
    }
}

#[test]
fn vendored_fixture_corpus_matches_approved_counts() {
    let signing: serde_json::Value = serde_json::from_slice(&read_bytes(&vendored(
        "tests/fixtures/mls_chat_signing_domain_vectors.json",
    )))
    .expect("signing-domain vectors are valid JSON");
    assert_eq!(
        signing["cases"].as_array().expect("cases").len(),
        10,
        "signing-domain corpus must match the sealed 10-case input"
    );
    assert_eq!(
        signing["_catbird_mls_provenance"]["vectorSetCount"].as_u64(),
        Some(24),
        "signing-domain corpus must belong to the sealed 24-case vector set"
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
