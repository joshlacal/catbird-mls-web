use super::*;
use wasm_bindgen_test::*;

fn context() -> WasmMLSContext {
    let conn = Rc::new(
        SqliteConn::open(
            &format!("crypto-{}.db", uuid::Uuid::new_v4()),
            &"12".repeat(32),
        )
        .unwrap(),
    );
    WasmSqliteStorage::ensure_schema(&conn).unwrap();
    WasmMLSContext::open_with_conn(conn).unwrap()
}

#[wasm_bindgen_test]
fn signer_cache_matches_exact_public_key_without_copying_private_material() {
    let context = context();
    let first = context.get_or_create_signer(b"device").unwrap();
    let again = context.get_or_create_signer(b"device").unwrap();
    assert!(Rc::ptr_eq(&first, &again));
    let second = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    second.store(context.provider.storage()).unwrap();
    let loaded = context
        .signer_from_identity(b"device".to_vec(), second.public().to_vec())
        .unwrap();
    assert_eq!(loaded.public(), second.public());
    assert_ne!(loaded.public(), first.public());
    assert!(context
        .signer_from_identity(b"device".to_vec(), vec![0; 32])
        .is_err());
}

#[wasm_bindgen_test]
fn canonical_group_and_legacy_coordinates_decode_without_truncation() {
    for length in [16, 32] {
        let bytes = vec![0xab; length];
        assert_eq!(
            crate::decode_group_coordinate(&hex::encode(&bytes)),
            Some(bytes.clone())
        );
        use base64::Engine as _;
        assert_eq!(
            crate::decode_group_coordinate(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
            ),
            Some(bytes)
        );
    }
    assert!(crate::decode_group_coordinate(&"ab".repeat(31)).is_none());
    assert!(crate::decode_group_coordinate(&"ab".repeat(33)).is_none());
}

#[wasm_bindgen_test]
fn own_private_echo_fails_without_merging_or_deleting_group() {
    let context = context();
    let group_id = vec![5; 32];
    context
        .create_group_with_id(b"device".to_vec(), group_id.clone(), None)
        .unwrap();
    let ciphertext = context
        .encrypt_message(group_id.clone(), b"hello".to_vec())
        .unwrap()
        .ciphertext;
    assert!(matches!(
        context.decrypt_message(group_id.clone(), ciphertext),
        Err(MLSError::DecryptionFailed)
    ));
    assert!(context.groups.borrow().contains_key(&group_id));
    assert!(context.pending_incoming_merges.borrow().is_empty());
    assert_eq!(
        context
            .groups
            .borrow()
            .get(&group_id)
            .unwrap()
            .epoch()
            .as_u64(),
        0
    );
}

#[wasm_bindgen_test]
fn app_data_commit_resolves_and_stays_staged_until_explicit_merge() {
    let alice = context();
    let bob = context();
    let group_id = vec![9; 32];
    // This receiver-compatibility fixture explicitly negotiates the draft
    // capability. Canonical production clients do not advertise AppData.
    let capabilities = Capabilities::new(
        None,
        Some(&[CIPHERSUITE]),
        Some(&[ExtensionType::RatchetTree, ExtensionType::AppDataDictionary]),
        Some(&[ProposalType::AppDataUpdate]),
        Some(&[CredentialType::Basic]),
    );
    let alice_signer = alice.get_or_create_signer(b"alice").unwrap();
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities.clone())
        .build();
    let group = MlsGroup::new_with_group_id(
        &alice.provider,
        alice_signer.as_ref(),
        &config,
        GroupId::from_slice(&group_id),
        CredentialWithKey {
            credential: BasicCredential::new(b"alice".to_vec()).into(),
            signature_key: alice_signer.public().into(),
        },
    )
    .unwrap();
    alice.groups.borrow_mut().insert(group_id.clone(), group);
    let bob_signer = bob.get_or_create_signer(b"bob").unwrap();
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(
            CIPHERSUITE,
            &bob.provider,
            bob_signer.as_ref(),
            CredentialWithKey {
                credential: BasicCredential::new(b"bob".to_vec()).into(),
                signature_key: bob_signer.public().into(),
            },
        )
        .unwrap();
    let key_package_data = bundle.key_package().tls_serialize_detached().unwrap();
    let add = alice
        .add_members(
            group_id.clone(),
            vec![KeyPackageData {
                data: key_package_data,
            }],
        )
        .unwrap();
    bob.process_welcome(add.welcome_data, b"bob".to_vec(), None)
        .unwrap();
    alice.merge_pending_commit(group_id.clone()).unwrap();
    let prior_epoch = bob.groups.borrow().get(&group_id).unwrap().epoch().as_u64();
    let commit = alice.update_group_metadata(group_id.clone()).unwrap();
    assert!(
        matches!(bob.decrypt_message(group_id.clone(), commit), Err(MLSError::InvalidInput { message }) if message.contains("commit message"))
    );
    assert_eq!(
        bob.groups.borrow().get(&group_id).unwrap().epoch().as_u64(),
        prior_epoch
    );
    assert_eq!(bob.pending_incoming_merges.borrow().len(), 1);
    bob.merge_incoming_commit(group_id.clone()).unwrap();
    alice.merge_pending_commit(group_id.clone()).unwrap();
    assert_eq!(
        bob.groups.borrow().get(&group_id).unwrap().epoch().as_u64(),
        prior_epoch + 1
    );
    let ciphertext = alice
        .encrypt_message(group_id.clone(), b"after metadata".to_vec())
        .unwrap()
        .ciphertext;
    let decrypted = bob.decrypt_message(group_id, ciphertext).unwrap();
    assert_eq!(decrypted.plaintext, b"after metadata");
    assert_eq!(decrypted.epoch, prior_epoch + 1);
}
