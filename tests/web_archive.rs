//! Browser Labyrinth archive as a transport sender (SPEC p.40-41) over real encrypted OPFS.
//! Alice's web device is enrolled for chat, not for Labyrinth. Alice and Bob each hold a
//! Labyrinth epoch generated here and attested by their account's enrolled MLS device key. A
//! stateful fetch fixture serves the PDS device records, Alice's `mailboxKeys/self` from her own
//! PDS, Bob's only through the home DS relay, `mls-ds` `getEpochHead`, and captures Space
//! `applyWrites`. The queued row is Alice's own send with a real frame nonce, `I13` receipt and
//! original sender attestation, stored as `finish_application_send` stores it.
#![cfg(target_arch = "wasm32")]
use std::rc::Rc;
use atproto_spaces::{
    kem::{encode_p256_did_key, P256SecretKey},
    lthash::compute_dagcbor_cid,
    tokens::SpaceSigningKey,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::client::{
    chat_wire, QueuedLabyrinthArchivePayload, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls::labyrinth::repo_proof::build_repo_proof_car_v1;
use catbird_mls::messaging::receive::{
    OriginalSenderArchiveAttestationEnvelope, PrivateMessageAadEnvelope,
};
use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend as _};
use catbird_mls::storage::LabyrinthQueueRow;
use catbird_mls_web::{SqliteConn, WasmMlsClient};
use labyrinth::mailbox::{EpochPublic, MailboxKeys};
use labyrinth::records::{Batch, EpochPublicDef, MailboxKeysRecord, MekDistribution};
use labyrinth_protocol::receipt::{
    expected_receipt_key_id, sign_sequencer_receipt, SequencerReceiptPayload,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen(inline_js = r#"
let originalFetch;
let fx;
export function installArchiveFixture() {
  originalFetch = globalThis.fetch;
  fx = {records: {}, cids: {}, docs: {}, proofs: {}, ownPds: {}, relay: {}, heads: {}, writes: [], calls: {}};
  globalThis.fetch = async (request) => {
    const reply = (body, status = 200) => {
      const r = new Response(JSON.stringify(body), {status, headers: {'content-type': 'application/json'}});
      Object.defineProperty(r, 'url', {value: request.url});
      return r;
    };
    const replyBytes = (base64, status = 200) => {
      const raw = atob(base64);
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      const r = new Response(bytes, {status, headers: {'content-type': 'application/vnd.ipld.car'}});
      Object.defineProperty(r, 'url', {value: request.url});
      return r;
    };
    const url = new URL(request.url);
    if (url.hostname === 'plc.directory') {
      const did = decodeURIComponent(url.pathname.slice(1));
      return did in fx.docs ? reply(fx.docs[did]) : reply({error: 'NotFound'}, 404);
    }
    if (url.pathname === '/.well-known/did.json') {
      const did = `did:web:${url.hostname}`;
      return did in fx.docs ? reply(fx.docs[did]) : reply({error: 'NotFound'}, 404);
    }
    const q = (name) => url.searchParams.get(name);
    const nsid = url.pathname.replace('/xrpc/', '');
    fx.calls[nsid] = (fx.calls[nsid] || 0) + 1;
    const text = request.method === 'POST' ? await request.clone().text() : '';
    const b = text ? JSON.parse(text).signedRequest?.body : undefined;
    const auth = request.headers.get('authorization');
    const denied = () => reply({error: 'AuthRequired', message: nsid}, 401);
    const ownPds = auth === 'Bearer session';
    const ds = auth === 'Bearer service-auth' && request.headers.has('catbird-labyrinth-read');
    const mailboxKeys = (store, did, rkey) => {
      const stored = rkey === 'self' ? store[did] : undefined;
      return stored
        ? reply({uri: `at://${did}/blue.catbird.labyrinth.mailboxKeys/self`, cid: stored.cid, value: stored.value})
        : reply({error: 'RecordNotFound', message: `${did} ${rkey}`}, 400);
    };
    switch (nsid) {
      case 'com.atproto.server.getServiceAuth': return reply({token: 'service-auth'});
      case 'com.atproto.repo.createRecord':
      case 'com.atproto.repo.putRecord': {
        const r = JSON.parse(text);
        const uri = `at://${r.repo}/${r.collection}/${r.rkey}`;
        fx.records[uri] = r.record;
        return reply({uri, cid: fx.cids[uri] || 'bafyfixture'});
      }
      case 'com.atproto.repo.listRecords': {
        const prefix = `at://${q('repo')}/${q('collection')}/`;
        return reply({records: Object.entries(fx.records).filter(([uri]) => uri.startsWith(prefix))
          .map(([uri, value]) => ({uri, cid: fx.cids[uri] || 'bafyfixture', value}))});
      }
      case 'com.atproto.sync.getRecord': {
        const uri = `at://${q('did')}/${q('collection')}/${q('rkey')}`;
        return uri in fx.proofs ? replyBytes(fx.proofs[uri]) : reply({error: 'RecordNotFound'}, 404);
      }
      case 'blue.catbird.chat.enrollDevice':
        return reply({device: {deviceId: b.deviceId, keyId: b.keyId, signaturePublicKey: b.signaturePublicKey,
          authGeneration: 1, status: 'active', availablePackageCount: 2, reservedPackageCount: 0,
          createdAt: '2026-11-07T00:00:00.000Z', updatedAt: '2026-11-07T00:00:00.000Z'}});
      case 'blue.catbird.chat.publishDirectRequestKeys': return reply({revision: b.revision, enabled: true});
      case 'blue.catbird.chat.replenishKeyPackages': return reply({acceptedCount: b.keyPackages.length});
      case 'com.atproto.repo.getRecord':
        return ownPds ? mailboxKeys(fx.ownPds, q('repo'), q('rkey')) : denied();
      case 'blue.catbird.labyrinth.getMailboxKeysRecord':
        return ds ? mailboxKeys(fx.relay, q('did'), q('rkey')) : denied();
      case 'blue.catbird.labyrinth.getEpochHead': {
        if (!ds) return denied();
        const epoch = fx.heads[q('did')];
        return epoch ? reply({epoch}) : reply({error: 'EpochNotFound', message: q('did')}, 404);
      }
      case 'com.atproto.space.applyWrites': {
        if (!ownPds) return denied();
        const input = JSON.parse(text);
        fx.writes.push(input);
        return reply({results: input.writes.map((w) => ({$type: 'com.atproto.space.applyWrites#createResult',
          uri: `${input.space}/${input.repo}/${w.collection}/${w.rkey}`, cid: 'bafywrite'}))});
      }
      default: return reply({error: 'NotFound', message: nsid}, 404);
    }
  };
}
export function publishDidDoc(did, doc) { fx.docs[did] = JSON.parse(doc); }
export function faultDidDoc(did, fault) {
  const doc = fx.docs[did];
  if (fault === 'malformed') doc.id = `${did}-wrong`;
  if (fault === 'missing_atproto') {
    doc.verificationMethod = doc.verificationMethod.filter((method) => !method.id.endsWith('#atproto'));
  }
}
export function publishRepoProof(uri, cid, proof) { fx.cids[uri] = cid; fx.proofs[uri] = proof; }
export function recordJson(uri) { return JSON.stringify(fx.records[uri]); }
export function publishMailboxKeys(did, record, cid, ownPds) {
  (ownPds ? fx.ownPds : fx.relay)[did] = {value: JSON.parse(record), cid};
}
export function publishEpochHead(did, epoch) { fx.heads[did] = JSON.parse(epoch); }
export function spaceWrites() { return JSON.stringify(fx.writes); }
export function callCount(nsid) { return fx.calls[nsid] || 0; }
export function restoreFetch() { globalThis.fetch = originalFetch; }
"#)]
extern "C" {
    fn installArchiveFixture();
    fn publishDidDoc(did: &str, doc: &str);
    fn faultDidDoc(did: &str, fault: &str);
    fn publishRepoProof(uri: &str, cid: &str, proof: &str);
    fn recordJson(uri: &str) -> String;
    fn publishMailboxKeys(did: &str, record: &str, cid: &str, own_pds: bool);
    fn publishEpochHead(did: &str, epoch: &str);
    fn spaceWrites() -> String;
    fn callCount(nsid: &str) -> u32;
    fn restoreFetch();
}
struct RestoreFetch;
impl Drop for RestoreFetch {
    fn drop(&mut self) {
        restoreFetch();
    }
}

const SEQUENCER: &str = "did:web:ds.catbird.test";
const ALICE_DEVICE: &str = "00000000-0000-4000-8000-00000000a001";
const BOB_DEVICE: &str = "00000000-0000-4000-8000-00000000b001";
const TEXT: &str = r#"{"text":"archived from the web"}"#;

fn did(name: &str) -> String {
    format!("did:plc:{name:a<24}")
}
fn p256_key(did: &str, purpose: &[u8]) -> P256SecretKey {
    for attempt in 0u32..128 {
        let mut hash = Sha256::new();
        hash.update(b"catbird-web-archive-fixture\0");
        hash.update(purpose);
        hash.update(did.as_bytes());
        hash.update(attempt.to_be_bytes());
        if let Ok(secret) = P256SecretKey::from_slice(&hash.finalize()) {
            return secret;
        }
    }
    panic!("fixture P-256 key derivation exhausted");
}

fn publish_did_document(did: &str) {
    let sign_multibase = encode_p256_did_key(&p256_key(did, b"sign").public_key());
    let kem_multibase = encode_p256_did_key(&p256_key(did, b"kem").public_key());
    let mut methods = vec![
        json!({
            "id": format!("{did}#atproto"),
            "controller": did,
            "type": "Multikey",
            "publicKeyMultibase": sign_multibase.strip_prefix("did:key:").unwrap(),
        }),
        json!({
            "id": format!("{did}#atproto_kem"),
            "controller": did,
            "type": "Multikey",
            "publicKeyMultibase": kem_multibase.strip_prefix("did:key:").unwrap(),
        }),
    ];
    if did == SEQUENCER {
        let receipt =
            encode_p256_did_key(&P256SecretKey::from_slice(&[19; 32]).unwrap().public_key());
        methods.push(json!({
            "id": format!("{did}#mls-receipt-1"),
            "controller": did,
            "type": "Multikey",
            "publicKeyMultibase": receipt.strip_prefix("did:key:").unwrap(),
        }));
    }
    let service_endpoint = if did == SEQUENCER {
        "https://ds.catbird.test"
    } else {
        "https://pds.catbird.test"
    };
    let doc = json!({
        "id": did,
        "verificationMethod": methods,
        "service": [{
            "id": format!("{did}#atproto_pds"),
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": service_endpoint,
        }],
    });
    publishDidDoc(did, &serde_json::to_string(&doc).unwrap());
}

fn publish_record_proof(did: &str, collection: &str, rkey: &str, value: &Value) -> String {
    let typed: catbird_atproto::types::value::Data =
        serde_json::from_value(value.clone()).unwrap();
    let dagcbor = serde_ipld_dagcbor::to_vec(&typed).unwrap();
    let cid = compute_dagcbor_cid(&dagcbor).to_string();
    let signing_key =
        SpaceSigningKey::from_p256_secret(&p256_key(did, b"sign"), "#atproto");
    let (_, car) = build_repo_proof_car_v1(
        did,
        "3lb2zzzzzzzzz",
        &[(format!("{collection}/{rkey}"), dagcbor)],
        &signing_key,
    )
    .unwrap();
    let uri = format!("at://{did}/{collection}/{rkey}");
    publishRepoProof(&uri, &cid, &STANDARD.encode(car));
    cid
}


fn install() -> RestoreFetch {
    installArchiveFixture();
    RestoreFetch
}

async fn open(did: &str, device_id: &str) -> WasmMlsClient {
    let client = WasmMlsClient::open_async(
        did.into(),
        device_id.into(),
        SEQUENCER.into(),
        "https://ds.catbird.test".into(),
        "https://pds.catbird.test".into(),
        "ab".repeat(32),
    )
    .await
    .unwrap();
    client.set_auth_token(Some("session".into()));
    client
}

/// The account database a closed client left behind.
fn account_db(did: &str) -> WasmAccountDb<Rc<SqliteConn>> {
    let path = format!(
        "catbird-mls/{}.db",
        hex::encode(Sha256::digest(did.as_bytes()))
    );
    WasmAccountDb::new(Rc::new(SqliteConn::open(&path, &"ab".repeat(32)).unwrap()))
}

/// Enroll both chat devices (their PDS device records land in the fixture) and return their
/// MLS signing keys.
async fn enroll(alice: &str, bob: &str) -> (SignatureKeyPair, SignatureKeyPair) {
    publish_did_document(SEQUENCER);
    for (did, device_id) in [(alice, ALICE_DEVICE), (bob, BOB_DEVICE)] {
        publish_did_document(did);
        let client = open(did, device_id).await;
        let scopes = serde_wasm_bindgen::to_value(&REQUIRED_LABYRINTH_OAUTH_SCOPES).unwrap();
        client.enroll_device(true, scopes).await.unwrap();
        for (collection, rkey) in [
            ("blue.catbird.chat.device", device_id),
            ("blue.catbird.chat.declaration", "self"),
        ] {
            let uri = format!("at://{did}/{collection}/{rkey}");
            let value: Value = serde_json::from_str(&recordJson(&uri)).unwrap();
            publish_record_proof(did, collection, rkey, &value);
        }
    }
    let signer = |did: &str| {
        let raw = account_db(did)
            .backend()
            .get_labyrinth_state("device_signer_json")
            .unwrap();
        serde_json::from_slice::<SignatureKeyPair>(&raw.expect("enrolled signer")).unwrap()
    };
    (signer(alice), signer(bob))
}

/// The account's MLS device key as its Labyrinth transport key ([CB-3]).
struct Device<'a>(&'a SignatureKeyPair);
impl labyrinth::sign::TransportSigner for Device<'_> {
    fn transport_public_key(&self) -> [u8; 32] {
        self.0.public().try_into().unwrap()
    }
    fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).unwrap().try_into().unwrap()
    }
}

/// Epoch 0 of `did`, attested by its device, as `mailboxKeys/self` (on the own PDS or behind
/// the relay) and, with `ds_head`, as its `mls-ds` head.
fn publish_epoch(
    did: &str,
    device: &SignatureKeyPair,
    seed: u8,
    own_pds: bool,
    ds_head: bool,
) -> (EpochPublic, MailboxKeys) {
    let keys = MailboxKeys::derive(&[seed; 32], 0);
    let epoch = EpochPublic::sign(did, 0, &keys, [seed; 32], None, None, &Device(device)).unwrap();
    let record = MailboxKeysRecord::from_public(&epoch, None, "2026-11-07T00:00:00.000Z".into());
    let value = serde_json::to_value(&record).unwrap();
    let cid = publish_record_proof(
        did,
        labyrinth::records::nsid::MAILBOX_KEYS,
        "self",
        &value,
    );
    publishMailboxKeys(
        did,
        &serde_json::to_string(&record).unwrap(),
        &cid,
        own_pds,
    );
    if ds_head {
        let head = EpochPublicDef::from_public(&epoch);
        publishEpochHead(did, &serde_json::to_string(&head).unwrap());
    }
    (epoch, keys)
}

fn sequencer_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[19; 32]).unwrap()
}

/// Queue Alice's own sequenced send at seq 2 in her account database.
fn queue_own_send(
    alice: &str,
    bob: &str,
    signer: &SignatureKeyPair,
    cid: &str,
    mid: &str,
) -> QueuedLabyrinthArchivePayload {
    queue_own_send_with_frame(
        alice,
        bob,
        signer,
        cid,
        mid,
        2,
        TEXT,
        chat_wire::canonical_labyrinth_frame_json(TEXT),
    )
}

fn queue_own_send_with_frame(
    alice: &str,
    bob: &str,
    signer: &SignatureKeyPair,
    cid: &str,
    mid: &str,
    seq: u64,
    display: &str,
    frame: String,
) -> QueuedLabyrinthArchivePayload {
    let nonce = [7u8; 32];
    let commitment =
        PrivateMessageAadEnvelope::for_payload(&nonce, frame.as_bytes()).archive_commitment;
    let transcript =
        labyrinth_protocol::transcripts::original_sender_archive_transcript(cid, mid, &commitment);
    let attestation = OriginalSenderArchiveAttestationEnvelope {
        sender_did: alice.into(),
        sender_device_id: ALICE_DEVICE.into(),
        sender_transport_public_key: signer.public().to_vec(),
        signature: signer.sign(&transcript).unwrap(),
    };
    let group_id = vec![9u8; 32];
    let issued_at_ms = js_sys::Date::now() as i64;
    let signed = sign_sequencer_receipt(
        &sequencer_key(),
        &expected_receipt_key_id(SEQUENCER),
        &SequencerReceiptPayload {
            sequencer_did: SEQUENCER.into(),
            conversation_id: cid.into(),
            group_id: group_id.clone(),
            epoch: 1,
            sender_device_did_url: format!("{alice}#{ALICE_DEVICE}"),
            entry_id: mid.into(),
            archive_commitment: commitment,
            seq: seq.try_into().unwrap(),
            issued_at_ms,
        },
    )
    .unwrap();
    let receipt = json!({
        "sequencerDid": SEQUENCER, "conversationId": cid, "generation": 0,
        "groupId": STANDARD.encode(&group_id), "epoch": 1, "senderDid": alice,
        "senderDeviceId": ALICE_DEVICE, "entryId": mid,
        "archiveCommitment": STANDARD.encode(commitment), "seq": seq, "issuedAtMs": issued_at_ms,
        "kid": signed.key_id, "signature": STANDARD.encode(signed.signature),
    });
    let sec1 = sequencer_key().verifying_key().to_encoded_point(false);
    let (_, _, archived_receipt) = chat_wire::parse_and_verify_i13_sequencer_receipt(
        &receipt,
        sec1.as_bytes(),
        SEQUENCER,
        cid,
        &group_id,
        1,
        mid,
        mid,
        &commitment,
        Some(&attestation),
    )
    .unwrap();
    let queued = QueuedLabyrinthArchivePayload {
        version: 1,
        message_id: mid.into(),
        conversation_id: cid.into(),
        group_id_hex: hex::encode(&group_id),
        epoch: 1,
        expected_member_dids: vec![alice.into(), bob.into()],
        seq: seq as i64,
        sender_did: alice.into(),
        sender_device_id: ALICE_DEVICE.into(),
        sequencer_did: SEQUENCER.into(),
        space_uri: None,
        plaintext_json: display.into(),
        labyrinth_frame_json: frame,
        mls_ciphertext_b64: String::new(),
        frame_nonce_b64: Some(STANDARD.encode(nonce)),
        sequencer_receipt_json: Some(archived_receipt),
        original_sender_attestation_json: Some(serde_json::to_string(&attestation).unwrap()),
        created_at_ms: issued_at_ms,
    };
    account_db(alice)
        .write_tx(|tx| {
            tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                item_id: mid.into(),
                conversation_id: cid.into(),
                group_id_hex: queued.group_id_hex.clone(),
                seq: seq as i64,
                payload_bytes: serde_json::to_vec(&queued).unwrap(),
                created_at_ms: issued_at_ms,
            })
        })
        .unwrap();
    queued
}

fn space_writes() -> Vec<Value> {
    serde_json::from_str(&spaceWrites()).unwrap()
}

fn queued_rows(did: &str) -> usize {
    account_db(did)
        .backend()
        .list_labyrinth_queue(None, 10)
        .unwrap()
        .len()
}

/// An older queue row can reach flush without the new enqueue gate. Its authenticated sender
/// veto must still prevent MEK distribution and the Space write.
#[wasm_bindgen_test]
async fn flush_drops_sender_veto_before_archive_write() {
    let _fetch = install();
    let (alice, bob) = (did("archivevetoalice"), did("archivevetobob"));
    let cid = "00000000-0000-4000-8000-0000000c0011";
    let mid = "00000000-0000-4000-8000-0000000d0011";
    let (alice_signer, _) = enroll(&alice, &bob).await;
    let frame = json!({
        "version": 1,
        "messageType": "system",
        "text": "History backup turned off",
        "historyBackupChange": false,
        "backupPolicy": 1,
        "noBackup": true,
    })
    .to_string();
    queue_own_send_with_frame(
        &alice,
        &bob,
        &alice_signer,
        cid,
        mid,
        2,
        &frame,
        frame.clone(),
    );

    let client = open(&alice, ALICE_DEVICE).await;
    assert_eq!(client.flush_labyrinth_queue().await.unwrap(), 0);
    drop(client);
    assert_eq!(queued_rows(&alice), 0);
    assert!(space_writes().is_empty());
}

/// A locally retained, sequenced off decision also vetoes an unflagged old queue row.
#[wasm_bindgen_test]
async fn flush_drops_queue_row_after_sequenced_policy_off() {
    let _fetch = install();
    let (alice, bob) = (did("archiveflipalice"), did("archiveflipbob"));
    let cid = "00000000-0000-4000-8000-0000000c0012";
    let mid = "00000000-0000-4000-8000-0000000d0012";
    let (alice_signer, _) = enroll(&alice, &bob).await;
    queue_own_send(&alice, &bob, &alice_signer, cid, mid);
    account_db(&alice)
        .write_tx(|tx| {
            tx.put_account_meta(
                &format!("archive.policy.flips:{cid}"),
                r#"[{"seq":1,"enabled":false}]"#,
                js_sys::Date::now() as i64,
            )
        })
        .unwrap();

    let client = open(&alice, ALICE_DEVICE).await;
    assert_eq!(client.flush_labyrinth_queue().await.unwrap(), 0);
    drop(client);
    assert_eq!(queued_rows(&alice), 0);
    assert!(space_writes().is_empty());
}

/// Creation-time queue order may put a later message before an older off control. Flush must
/// process the policy before it decides to archive either message.
#[wasm_bindgen_test]
async fn flush_observes_all_queued_opt_outs_before_selecting_rows() {
    let _fetch = install();
    let (alice, bob) = (did("archiveorderalice"), did("archiveorderbob"));
    let cid = "00000000-0000-4000-8000-0000000c0013";
    let message_id = "00000000-0000-4000-8000-0000000d0013";
    let control_id = "00000000-0000-4000-8000-0000000d0014";
    let (alice_signer, _) = enroll(&alice, &bob).await;
    let normal = queue_own_send(&alice, &bob, &alice_signer, cid, message_id);
    let frame = json!({
        "version": 1, "messageType": "system", "text": "History backup turned off",
        "historyBackupChange": false, "backupPolicy": 1, "noBackup": true,
    })
    .to_string();
    let control = queue_own_send_with_frame(
        &alice,
        &bob,
        &alice_signer,
        cid,
        control_id,
        1,
        &frame,
        frame.clone(),
    );
    account_db(&alice)
        .write_tx(|tx| {
            tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                item_id: control_id.into(),
                conversation_id: cid.into(),
                group_id_hex: control.group_id_hex.clone(),
                seq: 1,
                payload_bytes: serde_json::to_vec(&control).unwrap(),
                created_at_ms: normal.created_at_ms + 1,
            })
        })
        .unwrap();

    let client = open(&alice, ALICE_DEVICE).await;
    assert_eq!(client.flush_labyrinth_queue().await.unwrap(), 0);
    drop(client);
    assert_eq!(queued_rows(&alice), 0);
    assert!(space_writes().is_empty());
}

#[wasm_bindgen_test]
async fn flush_stops_before_writing_when_policy_queue_row_is_malformed() {
    let _fetch = install();
    let (alice, bob) = (did("archivemalformedalice"), did("archivemalformedbob"));
    let cid = "00000000-0000-4000-8000-0000000c0014";
    let mid = "00000000-0000-4000-8000-0000000d0015";
    let (alice_signer, _) = enroll(&alice, &bob).await;
    let normal = queue_own_send(&alice, &bob, &alice_signer, cid, mid);
    account_db(&alice)
        .write_tx(|tx| {
            tx.enqueue_labyrinth_item(&LabyrinthQueueRow {
                item_id: "00000000-0000-4000-8000-0000000d0016".into(),
                conversation_id: cid.into(),
                group_id_hex: normal.group_id_hex,
                seq: 1,
                payload_bytes: b"{}".to_vec(),
                created_at_ms: normal.created_at_ms + 1,
            })
        })
        .unwrap();

    let client = open(&alice, ALICE_DEVICE).await;
    assert!(client.flush_labyrinth_queue().await.is_err());
    drop(client);
    assert_eq!(queued_rows(&alice), 2);
    assert!(space_writes().is_empty());
}

/// Fails before the fix: the flush sealed the batch under a local random `convo_sender_mek:`
/// secret and wrote no `blue.catbird.labyrinth.mek` record, so no member could ever open it.
#[wasm_bindgen_test]
async fn flush_distributes_a_transport_mek_every_member_epoch_opens() {
    let _fetch = install();
    let (alice, bob) = (did("archivemekalice"), did("archivemekbob"));
    let cid = "00000000-0000-4000-8000-0000000c0001";
    let mid = "00000000-0000-4000-8000-0000000d0001";
    let (alice_signer, bob_signer) = enroll(&alice, &bob).await;
    let (alice_epoch, _) = publish_epoch(&alice, &alice_signer, 1, true, true);
    let (bob_epoch, bob_keys) = publish_epoch(&bob, &bob_signer, 2, false, true);
    let queued = queue_own_send(&alice, &bob, &alice_signer, cid, mid);
    let resolve_calls_before = callCount("com.atproto.identity.resolveDid");

    let mut client = open(&alice, ALICE_DEVICE).await;
    for (fault_did, fault) in [
        (&bob, "malformed"),
        (&alice, "missing_atproto"),
    ] {
        publish_did_document(fault_did);
        faultDidDoc(fault_did, fault);
        assert!(
            client.flush_labyrinth_queue().await.is_err(),
            "a {fault} DID document must fail closed"
        );
        drop(client);
        assert_eq!(queued_rows(&alice), 1);
        assert!(space_writes().is_empty());
        client = open(&alice, ALICE_DEVICE).await;
    }
    publish_did_document(&alice);
    publish_did_document(&bob);
    assert_eq!(client.flush_labyrinth_queue().await.unwrap(), 1);
    assert_eq!(
        callCount("com.atproto.identity.resolveDid"),
        resolve_calls_before
    );
    drop(client);

    let writes = space_writes();
    let space = format!("at:space/{SEQUENCER}/blue.catbird.labyrinth.conversation/{cid}-0");
    let created: Vec<_> = writes
        .iter()
        .map(|w| {
            (
                w["space"].as_str().unwrap(),
                w["repo"].as_str().unwrap(),
                w["writes"][0]["collection"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        created,
        [
            (space.as_str(), alice.as_str(), "blue.catbird.labyrinth.mek"),
            (
                space.as_str(),
                alice.as_str(),
                "blue.catbird.labyrinth.batch"
            ),
        ]
    );

    let wire: MekDistribution =
        serde_json::from_value(writes[0]["writes"][0]["value"].clone()).unwrap();
    let (record, _) = wire.to_record().unwrap();
    let recipients: Vec<_> = record
        .recipients
        .iter()
        .map(|r| (r.did.as_str(), r.recipient_epoch_head))
        .collect();
    assert_eq!(
        recipients,
        [
            (alice.as_str(), alice_epoch.head),
            (bob.as_str(), bob_epoch.head)
        ]
    );
    let mek = labyrinth::mek::open(&record, &bob, &bob_epoch, &bob_keys, None).unwrap();

    let batch: Batch = serde_json::from_value(writes[1]["writes"][0]["value"].clone()).unwrap();
    let sealed = batch.to_messages().unwrap();
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0].mek_id, record.mek_id);
    let (nonce, frame) = labyrinth::message::open_sender_committed(&sealed[0], cid, &mek).unwrap();
    assert_eq!(STANDARD.encode(nonce), queued.frame_nonce_b64.unwrap());
    assert_eq!(frame, queued.labyrinth_frame_json.into_bytes());
    assert_eq!(queued_rows(&alice), 0);
}

/// Fails before the fix: the flush never consulted a directory, so it wrote the batch and
/// dequeued the row. Bob's epoch is on his PDS but `mls-ds` has no head for it; one source is
/// not evidence ([CB-28], [CB-29]), so nothing is written and the row stays queued.
#[wasm_bindgen_test]
async fn flush_refuses_a_single_source_epoch_and_keeps_the_row() {
    let _fetch = install();
    let (alice, bob) = (did("archivesinglealice"), did("archivesinglebob"));
    let cid = "00000000-0000-4000-8000-0000000c0002";
    let mid = "00000000-0000-4000-8000-0000000d0002";
    let (alice_signer, bob_signer) = enroll(&alice, &bob).await;
    publish_epoch(&alice, &alice_signer, 3, true, true);
    publish_epoch(&bob, &bob_signer, 4, false, false);
    queue_own_send(&alice, &bob, &alice_signer, cid, mid);

    let client = open(&alice, ALICE_DEVICE).await;
    assert!(client.flush_labyrinth_queue().await.is_err());
    drop(client);

    assert!(space_writes().is_empty());
    assert_eq!(queued_rows(&alice), 1);
}
