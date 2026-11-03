//! Real XWING request custody across close/reopen of encrypted browser OPFS.
//! Signed service authority is a fixture, not authenticated server DB evidence.
#![cfg(target_arch = "wasm32")]
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::orchestrator::{
    direct_request_bootstrap::*, direct_request_journal::DirectRequestJournalPhase,
    mls_provider::MlsCryptoContext,
};
use catbird_mls_web::{SqliteConn, WasmMLSContextExport as Context};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_dedicated_worker);
const ALICE: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
const ADEV: &str = "00000000-0000-4000-8000-000000000000";
const BDEV: &str = "00000000-0000-4000-8000-000000000001";
fn open(path: &str) -> Context {
    Context::open(path, &"bc".repeat(32)).unwrap()
}
fn sign_publication(
    ctx: &Context,
    input: &DirectRequestBootstrapInput,
    b: &DirectRequestBootstrap,
    public: &[u8],
) -> Vec<u8> {
    use catbird_mls::chat_v2::transcript::direct_request::{
        direct_request_signing_bytes, DirectRequestKind,
    };
    let (c, _) = context(&input.context_json).unwrap();
    let date = |v: u64| {
        chrono::DateTime::from_timestamp(v as i64, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    };
    let artifact = |v: &Vec<u8>, kind: &str| json!({"framing":"mlsMessage","contentType":kind,"bytes":STANDARD.encode(v),"sha256":STANDARD.encode(Sha256::digest(v))});
    let deliveries=b.expected_package_refs.iter().enumerate().map(|(i,r)|json!({"recipientDid":BOB,"recipientDeviceId":format!("00000000-0000-4000-8000-{:012}",i+1),"provenance":{"requestId":c["requestId"],"preparationDigest":c["preparationDigest"],"contextHash":STANDARD.encode(b.context_hash),"grantId":uuid::Uuid::new_v4().to_string(),"grantRevision":1,"keyPackageRef":STANDARD.encode(r),"importUntil":date(b.import_until)}})).collect::<Vec<_>>();
    let metadata = json!({"coordinate":metadata_coordinate(&b.coordinates).unwrap(),"originTransitionId":c["requestId"],"metadataVersion":1,"nonce":STANDARD.encode(&b.metadata_nonce),"ciphertext":STANDARD.encode(&b.metadata_ciphertext),"ciphertextSha256":STANDARD.encode(Sha256::digest(&b.metadata_ciphertext)),"ciphertextSize":b.metadata_ciphertext.len(),"authorProof":{"authorDid":ALICE,"authorDeviceId":ADEV,"authorKeyId":c["actorKeyId"],"signaturePublicKey":STANDARD.encode(public),"authGenerationAtOrigin":1,"originTransitionId":c["requestId"],"originSeq":1,"roleAtOrigin":"admin","deviceStatusAtOrigin":"active"}});
    let body = json!({"$type":"blue.catbird.chat.defs#directRequestPublicationBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-PUBLISH\u{0}","protocolVersion":"2","actorDid":ALICE,"actorDeviceId":ADEV,"keyId":c["actorKeyId"],"authGeneration":1,"requestId":c["requestId"],"firstMessageId":c["firstMessageId"],"conversationId":c["conversationId"],"recipientDid":BOB,"origin":c["origin"],"profile":"encryptedIntroduction1","preparationDigest":c["preparationDigest"],"preparationRequestDigest":STANDARD.encode(input.preparation_request_digest),"contextHash":STANDARD.encode(b.context_hash),"next":b.coordinates,"importUntil":date(b.import_until),"archiveCommitment":STANDARD.encode(b.archive_commitment),"artifacts":{"genesisGroupInfo":artifact(&b.genesis_group_info,"groupInfo"),"addCommit":artifact(&b.add_commit,"publicMessageCommit"),"finalGroupInfo":artifact(&b.final_group_info,"groupInfo"),"welcome":{"opaqueWelcome":STANDARD.encode(&b.welcome),"sha256":STANDARD.encode(Sha256::digest(&b.welcome)),"deliveries":deliveries},"metadataSnapshot":metadata,"initialCiphertext":STANDARD.encode(&b.initial_ciphertext)},"idempotencyKey":uuid::Uuid::new_v4().to_string(),"signedAt":date(chrono::Utc::now().timestamp() as u64)});
    let transcript = direct_request_signing_bytes(
        DirectRequestKind::Publish,
        &serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let signature = ctx
        .sign_with_identity_key(format!("{ALICE}#{ADEV}").into_bytes(), transcript)
        .unwrap();
    serde_json::to_vec(
        &json!({"signedRequest":{"body":body,"signature":STANDARD.encode(signature)}}),
    )
    .unwrap()
}
fn receipt(
    input: &DirectRequestBootstrapInput,
    b: &DirectRequestBootstrap,
    publication: &[u8],
    key: &p256::ecdsa::SigningKey,
) -> Vec<u8> {
    use catbird_mls::chat_v2::transcript::direct_request::{
        direct_request_receipt_key_id, direct_request_signing_bytes, DirectRequestKind,
    };
    use p256::ecdsa::signature::Signer;
    let (c, _) = context(&input.context_json).unwrap();
    let publication: Value = serde_json::from_slice(publication).unwrap();
    let transcript = direct_request_signing_bytes(
        DirectRequestKind::Publish,
        &serde_json::to_vec(&publication["signedRequest"]["body"]).unwrap(),
    )
    .unwrap();
    let body = json!({"$type":"blue.catbird.chat.defs#directRequestReceiptBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-OUTCOME\u{0}","protocolVersion":"2","authorityDid":"did:web:chat.catbird.blue","keyId":direct_request_receipt_key_id(key.verifying_key().to_encoded_point(true).as_bytes()).unwrap(),"receipt":{"$type":"blue.catbird.chat.defs#directRequestPublishedReceipt","requestId":c["requestId"],"requestKind":"publish","actorDid":ALICE,"actorDeviceId":ADEV,"actorKeyId":c["actorKeyId"],"authGeneration":1,"preparationRequestDigest":STANDARD.encode(input.preparation_request_digest),"requestDigest":STANDARD.encode(Sha256::digest(transcript)),"recordedAt":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true),"conversationId":c["conversationId"],"firstMessageId":c["firstMessageId"],"coordinates":b.coordinates,"sequencerReceipt":sequencer_receipt(&publication["signedRequest"]["body"])}});
    let input = direct_request_signing_bytes(
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let sig: p256::ecdsa::Signature = key.sign(&input);
    serde_json::to_vec(&json!({"body":body,"signature":STANDARD.encode(sig.normalize_s().unwrap_or(sig).to_bytes())})).unwrap()
}
/// I13 receipt over the signed opening, by the sequencer's `[19;32]` `#mls-receipt-1`
/// key (mirrors catbird-mls `tests/fixtures/direct_request_i13.rs::receipt`, seq 1).
fn sequencer_receipt(publication: &Value) -> Value {
    use labyrinth_protocol::receipt::{
        expected_receipt_key_id, sign_sequencer_receipt, SequencerReceiptPayload,
    };
    let key = p256::ecdsa::SigningKey::from_slice(&[19; 32]).unwrap();
    let bytes = |v: &Value| STANDARD.decode(v.as_str().unwrap()).unwrap();
    let payload = SequencerReceiptPayload {
        sequencer_did: "did:web:chat.catbird.blue".into(),
        conversation_id: publication["conversationId"].as_str().unwrap().into(),
        group_id: bytes(&publication["next"]["groupId"]),
        epoch: publication["next"]["epoch"].as_u64().unwrap(),
        sender_device_did_url: format!("{ALICE}#{ADEV}"),
        entry_id: publication["firstMessageId"].as_str().unwrap().into(),
        archive_commitment: bytes(&publication["archiveCommitment"]).try_into().unwrap(),
        seq: 1,
        issued_at_ms: chrono::DateTime::parse_from_rfc3339(
            publication["signedAt"].as_str().unwrap(),
        )
        .unwrap()
        .timestamp_millis(),
    };
    let signed = sign_sequencer_receipt(
        &key,
        &expected_receipt_key_id(&payload.sequencer_did),
        &payload,
    )
    .unwrap();
    json!({
        "sequencerDid":payload.sequencer_did,"conversationId":payload.conversation_id,
        "generation":publication["next"]["generation"],"groupId":STANDARD.encode(&payload.group_id),
        "epoch":payload.epoch,"senderDid":ALICE,"senderDeviceId":ADEV,
        "entryId":payload.entry_id,"archiveCommitment":STANDARD.encode(payload.archive_commitment),
        "seq":payload.seq,"issuedAtMs":payload.issued_at_ms,"kid":signed.key_id,
        "signature":STANDARD.encode(signed.signature),
    })
}
#[wasm_bindgen_test]
async fn unknown_publication_multisecret_import_ratchet_and_retirement_reopen() {
    SqliteConn::initialize_opfs().await.unwrap();
    let alicepath = format!("req-alice-{}.db", uuid::Uuid::new_v4());
    let bobpath = format!("req-bob-{}.db", uuid::Uuid::new_v4());
    let secondpath = format!("req-bob2-{}.db", uuid::Uuid::new_v4());
    let alice = open(&alicepath);
    let bob = open(&bobpath);
    let second = open(&secondpath);
    let actor = format!("{ALICE}#{ADEV}");
    let recipient = format!("{BOB}#{BDEV}");
    let ap = alice.create_key_package(actor.as_bytes().to_vec()).unwrap();
    let bp = bob
        .create_key_package(recipient.as_bytes().to_vec())
        .unwrap();
    let sp = second
        .create_key_package(format!("{BOB}#00000000-0000-4000-8000-000000000002").into_bytes())
        .unwrap();
    let authority = p256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
    let authority_key = authority
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    // The sequencer's separate `#mls-receipt-1` I13 key, pinned beside the request authority key.
    let sequencer_key = p256::ecdsa::SigningKey::from_slice(&[19; 32])
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let input=DirectRequestBootstrapInput{draft_id:uuid::Uuid::new_v4().to_string(),context_json:serde_json::to_vec(&json!({"protocolVersion":"2","requestId":uuid::Uuid::new_v4().to_string(),"firstMessageId":uuid::Uuid::new_v4().to_string(),"conversationId":uuid::Uuid::new_v4().to_string(),"origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},"actorDid":ALICE,"actorDeviceId":ADEV,"actorKeyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&ap.signature_public_key)),"recipientDid":BOB,"preparationDigest":STANDARD.encode([42;32])})).unwrap(),group_id:vec![37;32],generation:0,state_version:1,key_packages:vec![bp.key_package_data,sp.key_package_data],expected_package_refs:vec![bp.hash_ref.clone(),sp.hash_ref],authority_import_until:chrono::Utc::now().timestamp() as u64+20*86400,preparation_request_digest:[21;32],receipt_authority_key:authority_key.clone(),sequencer_did:"did:web:chat.catbird.blue".into(),sequencer_receipt_authority_key:sequencer_key.clone(),text:"Preview before consent".into(),invitation:None,metadata:catbird_mls::metadata::GroupMetadataV1{version:1,title:"Request".into(),description:String::new(),avatar_blob_locator:None,avatar_content_type:None,space_avatar:None}};
    let journal = alice.prepare_direct_request_bootstrap(&input).unwrap();
    let publication =
        sign_publication(&alice, &input, &journal.bootstrap, &ap.signature_public_key);
    alice
        .persist_direct_request_publish(&journal.request_id, &publication)
        .unwrap();
    assert!(alice.delete_group(input.group_id.clone()).is_err());
    assert!(alice.get_epoch(input.group_id.clone()).is_err());
    drop(alice);
    let alice = open(&alicepath);
    let retained = alice.list_direct_request_journal().unwrap().remove(0);
    assert_eq!(retained.phase, DirectRequestJournalPhase::OutcomeUnknown);
    assert_eq!(
        retained.publish_request.as_deref(),
        Some(publication.as_slice())
    );
    alice
        .persist_direct_request_publish(&journal.request_id, &publication)
        .unwrap();
    let proof = receipt(&input, &journal.bootstrap, &publication, &authority);
    alice
        .confirm_published_bootstrap(&journal.request_id, &proof, &authority_key)
        .unwrap();
    drop(alice);
    let alice = open(&alicepath);
    assert_eq!(alice.get_epoch(input.group_id.clone()).unwrap(), 1);
    alice
        .mark_direct_request_projected(&journal.request_id)
        .unwrap();
    let welcome = DirectRequestWelcomeInput {
        bootstrap: journal.bootstrap.clone(),
        local_identity: recipient.as_bytes().to_vec(),
        local_package_ref: bp.hash_ref,
        publication_request: publication.clone(),
        actor_signature_public_key: ap.signature_public_key,
        published_receipt: proof.clone(),
        receipt_authority_did: "did:web:chat.catbird.blue".into(),
        receipt_authority_key: authority_key.clone(),
        sequencer_receipt_authority_key: sequencer_key.clone(),
        preparation_request_digest: input.preparation_request_digest,
    };
    bob.process_direct_request_welcome(&welcome).unwrap();
    assert!(bob
        .create_external_commit(
            journal.bootstrap.final_group_info.clone(),
            recipient.as_bytes().to_vec()
        )
        .is_err());
    assert!(bob.delete_group(input.group_id.clone()).is_err());
    drop(bob);
    let bob = open(&bobpath);
    bob.process_direct_request_welcome(&welcome).unwrap();
    let outcome = bob.decrypt_direct_request_introduction(&welcome).unwrap();
    let DirectRequestIntroductionResult::Ready { plaintext, .. } = &outcome else {
        panic!("preview unavailable")
    };
    let decoded =
        catbird_mls::chat_v2::transcript::direct_request::decode_direct_request_introduction(
            plaintext,
        )
        .unwrap();
    assert_eq!(decoded["text"], "Preview before consent");
    drop(bob);
    let bob = open(&bobpath);
    assert_eq!(
        bob.decrypt_direct_request_introduction(&welcome).unwrap(),
        outcome
    );
    // A separately addressed device can import the full Welcome even if the
    // authenticated first application is poisoned. That never grants consent.
    let mut poisoned = journal.bootstrap.clone();
    *poisoned.initial_ciphertext.last_mut().unwrap() ^= 0x80;
    let poisoned_publication = sign_publication(
        &alice,
        &input,
        &poisoned,
        &alice
            .identity_public_key(actor.as_bytes().to_vec())
            .unwrap(),
    );
    let poisoned_receipt = receipt(&input, &poisoned, &poisoned_publication, &authority);
    let poisoned_welcome = DirectRequestWelcomeInput {
        bootstrap: poisoned,
        local_identity: format!("{BOB}#00000000-0000-4000-8000-000000000002").into_bytes(),
        local_package_ref: input.expected_package_refs[1].clone(),
        publication_request: poisoned_publication,
        actor_signature_public_key: alice
            .identity_public_key(actor.as_bytes().to_vec())
            .unwrap(),
        published_receipt: poisoned_receipt,
        receipt_authority_did: "did:web:chat.catbird.blue".into(),
        receipt_authority_key: authority_key.clone(),
        sequencer_receipt_authority_key: sequencer_key.clone(),
        preparation_request_digest: input.preparation_request_digest,
    };
    second
        .process_direct_request_welcome(&poisoned_welcome)
        .unwrap();
    let unavailable = second
        .decrypt_direct_request_introduction(&poisoned_welcome)
        .unwrap();
    assert!(matches!(
        unavailable,
        DirectRequestIntroductionResult::Unavailable { .. }
    ));
    assert_eq!(second.get_epoch(input.group_id.clone()).unwrap(), 1);
    drop(second);
    let second = open(&secondpath);
    assert_eq!(
        second
            .decrypt_direct_request_introduction(&poisoned_welcome)
            .unwrap(),
        unavailable
    );
    alice.delete_group(input.group_id.clone()).unwrap();
    drop(alice);
    let alice = open(&alicepath);
    let retired = alice
        .confirm_published_bootstrap(&journal.request_id, &proof, &authority_key)
        .unwrap();
    assert_eq!(retired.phase, DirectRequestJournalPhase::RetiredPublished);
    assert!(alice.get_epoch(input.group_id).is_err());
}

#[wasm_bindgen_test]
async fn request_key_batch_is_atomic_exact_and_persistent() {
    use catbird_mls::orchestrator::direct_request_keys::{
        DirectRequestKeyPublication, DirectRequestKeyPublicationInput,
    };
    SqliteConn::initialize_opfs().await.unwrap();
    let path = format!("req-keys-{}.db", uuid::Uuid::new_v4());
    let context = open(&path);
    context
        .create_key_package(format!("{ALICE}#{ADEV}").into_bytes())
        .unwrap();
    let input = DirectRequestKeyPublicationInput {
        actor_did: ALICE.into(),
        actor_device_id: ADEV.into(),
        auth_generation: 7,
        revision: 1,
        count: 2,
        enabled: true,
    };
    let raw = context
        .prepare_direct_request_key_publication(&input, None)
        .unwrap()
        .unwrap();
    let record = DirectRequestKeyPublication::decode(&raw, ALICE, ADEV).unwrap();
    assert_eq!(record.body().unwrap()["keys"].as_array().unwrap().len(), 2);
    assert!(!record.acknowledged);
    drop(context);
    let context = open(&path);
    assert_eq!(
        context
            .read_direct_request_key_publication(ADEV)
            .unwrap()
            .unwrap(),
        raw
    );
    assert!(context
        .prepare_direct_request_key_publication(&input, None)
        .unwrap()
        .is_none());
    assert!(context
        .prepare_direct_request_key_publication(&input, Some(&raw))
        .is_err());
    let mut ack = record;
    ack.acknowledged = true;
    let acknowledged = serde_json::to_vec(&ack).unwrap();
    assert!(context
        .acknowledge_direct_request_key_publication(ADEV, &raw, &acknowledged)
        .unwrap());
    drop(context);
    let context = open(&path);
    assert_eq!(
        context
            .read_direct_request_key_publication(ADEV)
            .unwrap()
            .unwrap(),
        acknowledged
    );
}

#[wasm_bindgen_test]
async fn protected_policy_is_monotonic_owner_bound_and_reopens() {
    use catbird_mls::orchestrator::canonical_transport::decode_conversation_state;
    SqliteConn::initialize_opfs().await.unwrap();
    let mut state = decode_conversation_state(include_bytes!(
        "../../catbird-mls/tests/fixtures/swift_pending_conversation_state.json"
    ))
    .unwrap();
    let owner = state.participants[0].user_did.to_string();
    let cid = state.coordinates.conversation_id.to_string();
    let path = format!("req-policy-{}.db", uuid::Uuid::new_v4());
    let ctx = open(&path);
    assert!(ctx.put_conversation_policy(&owner, &state).unwrap());
    let previous = state.clone();
    state.snapshot_seq += 1;
    assert!(ctx.put_conversation_policy(&owner, &state).unwrap());
    assert!(!ctx.put_conversation_policy(&owner, &previous).unwrap());
    assert!(ctx
        .get_conversation_policy("did:plc:cccccccccccccccccccccccc", &cid)
        .is_err());
    drop(ctx);
    let ctx = open(&path);
    assert_eq!(
        ctx.get_conversation_policy(&owner, &cid).unwrap(),
        Some(state)
    );
}
