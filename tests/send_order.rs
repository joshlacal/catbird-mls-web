//! Seed 2323 regressions for `WasmMlsClient` over real encrypted OPFS. A stateful fetch fixture
//! applies the `mls-ds` send-order rule (an unresolved send is accepted only if
//! `(prior.generation, prior.epoch, sendCounter)` exceeds the device's last accepted send in the
//! conversation, otherwise `StaleSend`) and returns real `I13` ES256 receipts. Alice and Bob are
//! enrolled clients sharing one MLS group, built in their account databases the way
//! `createGroup` plus Bob's Welcome import leave it.
#![cfg(target_arch = "wasm32")]
use std::rc::Rc;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::client::{chat_wire, REQUIRED_LABYRINTH_OAUTH_SCOPES};
use catbird_mls::orchestrator::MLSMessagePayload;
use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend as _};
use catbird_mls::storage::{ConversationRow, MessageRow};
use catbird_mls_web::{SqliteConn, WasmMlsClient};
use labyrinth_protocol::receipt::{
    expected_receipt_key_id, sign_sequencer_receipt, SequencerReceiptPayload,
};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen(inline_js = r#"
let originalFetch;
let receiptFor;
let ds;
const bytes = (v) => (typeof v === 'string' ? v : v.$bytes);
const compare = (a, b) => {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
};
function attempt(text, outcome) {
  const b = JSON.parse(text).signedRequest.body;
  ds.sends.push({messageId: b.messageId, sendCounter: b.sendCounter,
    ciphertext: bytes(b.applicationMessage.bytes), outcome});
}
// mls-ds `resolve_application_send`: the idempotency lookup, then the per-device order rule.
function sequence(text) {
  const signedRequest = JSON.parse(text).signedRequest;
  const b = signedRequest.body;
  const cid = b.prior.conversationId;
  const done = ds.accepted[`${cid} ${b.messageId}`];
  if (done) {
    attempt(text, done.text === text ? 'replayed' : 'conflict');
    return done.text === text ? [200, done.response] : [409, {error: 'InvalidRequest', message: 'messageId conflict'}];
  }
  const device = `${cid} ${b.actorDid} ${b.actorDeviceId}`;
  const position = [b.prior.generation, b.prior.epoch, b.sendCounter];
  const last = ds.order[device];
  if (ds.refuse || (ds.enforce && last && compare(position, last) <= 0)) {
    attempt(text, 'stale');
    return [400, {error: 'StaleSend', message: 'StaleSend'}];
  }
  if (!last || compare(position, last) > 0) ds.order[device] = position;
  attempt(text, 'accepted');
  const seq = ++ds.seq[cid];
  const entry = {$type: 'blue.catbird.chat.defs#applicationEntry', entryId: b.messageId,
    conversationId: cid, seq, signedRequest,
    sequencerReceipt: JSON.parse(receiptFor(JSON.stringify({body: b, seq}))),
    receivedAt: new Date().toISOString()};
  ds.entries[cid].push(entry);
  ds.accepted[`${cid} ${b.messageId}`] = {text, response: {entry}};
  return [200, {entry}];
}
export function installDs(receipt, didDoc) {
  originalFetch = globalThis.fetch;
  receiptFor = receipt;
  ds = {records: {}, sends: [], accepted: {}, order: {}, seq: {}, entries: {}, held: [],
    hold: 0, lose: 0, refuse: false, enforce: true};
  globalThis.fetch = async (request) => {
    const reply = (body, status = 200) => {
      const r = new Response(JSON.stringify(body), {status, headers: {'content-type': 'application/json'}});
      Object.defineProperty(r, 'url', {value: request.url});
      return r;
    };
    const url = new URL(request.url);
    if (url.pathname === '/.well-known/did.json') return reply(JSON.parse(didDoc));
    const nsid = url.pathname.replace('/xrpc/', '');
    const text = request.method === 'POST' ? await request.clone().text() : '';
    const b = text ? JSON.parse(text).signedRequest?.body : undefined;
    switch (nsid) {
      case 'com.atproto.server.getServiceAuth': return reply({token: 'service-auth'});
      case 'com.atproto.repo.putRecord': {
        const r = JSON.parse(text);
        ds.records[`at://${r.repo}/${r.collection}/${r.rkey}`] = r.record;
        return reply({uri: 'at://fixture', cid: 'bafyfixture'});
      }
      case 'com.atproto.repo.listRecords': {
        const prefix = `at://${url.searchParams.get('repo')}/${url.searchParams.get('collection')}/`;
        return reply({records: Object.entries(ds.records).filter(([uri]) => uri.startsWith(prefix))
          .map(([uri, value]) => ({uri, cid: 'bafyfixture', value}))});
      }
      case 'blue.catbird.chat.enrollDevice':
        return reply({device: {deviceId: b.deviceId, keyId: b.keyId, signaturePublicKey: b.signaturePublicKey,
          authGeneration: 1, status: 'active', availablePackageCount: 2, reservedPackageCount: 0,
          createdAt: '2026-11-07T00:00:00.000Z', updatedAt: '2026-11-07T00:00:00.000Z'}});
      case 'blue.catbird.chat.publishDirectRequestKeys': return reply({revision: b.revision, enabled: true});
      case 'blue.catbird.chat.replenishKeyPackages': return reply({acceptedCount: b.keyPackages.length});
      case 'blue.catbird.chat.sendMessage': {
        if (ds.hold > 0) {
          ds.hold--;
          ds.held.push(text);
          attempt(text, 'held');
          throw new TypeError('network held sendMessage');
        }
        const [status, body] = sequence(text);
        if (status === 200 && ds.lose > 0) {
          ds.lose--;
          throw new TypeError('sendMessage response lost');
        }
        return reply(body, status);
      }
      case 'blue.catbird.chat.getEntries': {
        const after = Number(url.searchParams.get('afterSeq'));
        return reply({entries: (ds.entries[url.searchParams.get('conversationId')] || [])
          .filter((e) => e.seq > after), hasMore: false});
      }
      case 'blue.catbird.chat.acknowledgeEntries': return reply({});
      case 'blue.catbird.chat.getConversations':
      case 'blue.catbird.chat.getPendingWelcomes':
      case 'blue.catbird.chat.getLeafRecoveryInbox': return reply({items: [], hasMore: false});
      default: return reply({error: 'NotFound', message: nsid}, 404);
    }
  };
}
export function openConversation(cid) { ds.seq[cid] = 1; ds.entries[cid] = []; }
export function holdNextSend() { ds.hold += 1; }
export function loseNextSendResponse() { ds.lose += 1; }
export function deliverHeld() { for (const text of ds.held.splice(0)) sequence(text); }
export function refuseEverySend(refuse) { ds.refuse = refuse; }
export function enforceSendOrder(enforce) { ds.enforce = enforce; }
export function appendEntry(cid, entry) {
  const e = JSON.parse(entry);
  e.seq = ++ds.seq[cid];
  ds.entries[cid].push(e);
  return e.seq;
}
export function dsSends() { return JSON.stringify(ds.sends); }
export function restoreFetch() { globalThis.fetch = originalFetch; }
"#)]
extern "C" {
    fn installDs(receipt: &js_sys::Function, did_doc: &str);
    fn openConversation(cid: &str);
    fn holdNextSend();
    fn loseNextSendResponse();
    fn deliverHeld();
    fn refuseEverySend(refuse: bool);
    fn enforceSendOrder(enforce: bool);
    fn appendEntry(cid: &str, entry: &str) -> u32;
    fn dsSends() -> String;
    fn restoreFetch();
}
struct RestoreFetch;
impl Drop for RestoreFetch {
    fn drop(&mut self) {
        restoreFetch();
    }
}

const SEQUENCER: &str = "did:web:ds.catbird.test";
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const ALICE_DEVICE: &str = "00000000-0000-4000-8000-00000000a001";
const BOB_DEVICE: &str = "00000000-0000-4000-8000-00000000b001";

fn did(name: &str) -> String {
    format!("did:plc:{name:a<24}")
}

fn message_id(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

fn sequencer_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[19; 32]).unwrap()
}

/// `I13` receipt for a send the fixture sequenced: `{"body": <wire send body>, "seq": n}`.
fn receipt_for(request: String) -> String {
    let request: Value = serde_json::from_str(&request).unwrap();
    let body = &request["body"];
    let text = |v: &Value| v.as_str().unwrap().to_owned();
    let payload = SequencerReceiptPayload {
        sequencer_did: SEQUENCER.into(),
        conversation_id: text(&body["prior"]["conversationId"]),
        group_id: chat_wire::json_bytes(&body["prior"]["groupId"]).unwrap(),
        epoch: body["prior"]["epoch"].as_u64().unwrap(),
        sender_device_did_url: format!(
            "{}#{}",
            text(&body["actorDid"]),
            text(&body["actorDeviceId"])
        ),
        entry_id: text(&body["messageId"]),
        archive_commitment: chat_wire::json_bytes(&body["aad"]["archiveCommitment"])
            .unwrap()
            .try_into()
            .unwrap(),
        seq: request["seq"].as_u64().unwrap(),
        issued_at_ms: js_sys::Date::now() as i64,
    };
    let signed = sign_sequencer_receipt(
        &sequencer_key(),
        &expected_receipt_key_id(SEQUENCER),
        &payload,
    )
    .unwrap();
    json!({
        "sequencerDid": SEQUENCER, "conversationId": payload.conversation_id,
        "generation": body["prior"]["generation"], "groupId": STANDARD.encode(&payload.group_id),
        "epoch": payload.epoch, "senderDid": body["actorDid"], "senderDeviceId": body["actorDeviceId"],
        "entryId": payload.entry_id, "archiveCommitment": STANDARD.encode(payload.archive_commitment),
        "seq": payload.seq, "issuedAtMs": payload.issued_at_ms, "kid": signed.key_id,
        "signature": STANDARD.encode(signed.signature),
    })
    .to_string()
}

fn install_ds() -> RestoreFetch {
    let point = sequencer_key().verifying_key().to_encoded_point(false);
    let did_doc = json!({"id": SEQUENCER, "verificationMethod": [{
        "id": format!("{SEQUENCER}#mls-receipt-1"), "type": "JsonWebKey2020", "controller": SEQUENCER,
        "publicKeyJwk": {"kty": "EC", "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())},
    }]});
    let receipt = Closure::<dyn Fn(String) -> String>::new(receipt_for);
    installDs(receipt.as_ref().unchecked_ref(), &did_doc.to_string());
    receipt.forget();
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

fn device_signer(db: &WasmAccountDb<Rc<SqliteConn>>) -> SignatureKeyPair {
    let raw = db
        .backend()
        .get_labyrinth_state("device_signer_json")
        .unwrap();
    serde_json::from_slice(&raw.expect("enrolled signer")).unwrap()
}

fn credential(did: &str, device_id: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(format!("{did}#{device_id}").into_bytes()).into(),
        signature_key: signer.public().into(),
    }
}

fn capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

/// Enroll both devices, then leave both account databases the way `createGroup` and Bob's
/// Welcome import do: one MLS group at epoch 1 holding both leaves, conversation at seq 1.
async fn conversation(alice: &str, bob: &str, cid: &str) -> (WasmMlsClient, WasmMlsClient) {
    for (did, device_id) in [(alice, ALICE_DEVICE), (bob, BOB_DEVICE)] {
        let client = open(did, device_id).await;
        let scopes = serde_wasm_bindgen::to_value(&REQUIRED_LABYRINTH_OAUTH_SCOPES).unwrap();
        client.enroll_device(true, scopes).await.unwrap();
    }
    let (alice_db, bob_db) = (account_db(alice), account_db(bob));
    {
        let (alice_signer, bob_signer) = (device_signer(&alice_db), device_signer(&bob_db));
        let (alice_mls, bob_mls) = (
            alice_db.openmls_provider().unwrap(),
            bob_db.openmls_provider().unwrap(),
        );
        let package = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(
                CIPHERSUITE,
                &bob_mls,
                &bob_signer,
                credential(bob, BOB_DEVICE, &bob_signer),
            )
            .unwrap();
        let create = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(capabilities())
            .use_ratchet_tree_extension(true)
            .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(5)
            .build();
        let group_id = [
            uuid::Uuid::new_v4().into_bytes(),
            uuid::Uuid::new_v4().into_bytes(),
        ]
        .concat();
        let mut group = MlsGroup::new_with_group_id(
            &alice_mls,
            &alice_signer,
            &create,
            GroupId::from_slice(&group_id),
            credential(alice, ALICE_DEVICE, &alice_signer),
        )
        .unwrap();
        let (_, welcome, _) = group
            .add_members(&alice_mls, &alice_signer, &[package.key_package().clone()])
            .unwrap();
        group.merge_pending_commit(&alice_mls).unwrap();
        let welcome =
            MlsMessageIn::tls_deserialize_exact(welcome.tls_serialize_detached().unwrap()).unwrap();
        let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
            panic!("expected a Welcome");
        };
        let join = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(5)
            .build();
        StagedWelcome::new_from_welcome(&bob_mls, &join, welcome, None)
            .unwrap()
            .into_group(&bob_mls)
            .unwrap();
        for db in [&alice_db, &bob_db] {
            db.write_tx(|tx| {
                tx.upsert_conversation(&ConversationRow {
                    conversation_id: cid.into(),
                    group_id: group_id.clone(),
                    generation: 0,
                    epoch: 1,
                    last_seq: 1,
                    sequencer_did: SEQUENCER.into(),
                    space_uri: None,
                    title: None,
                    unread_count: 0,
                    updated_at_ms: 0,
                })
            })
            .unwrap();
        }
    }
    drop((alice_db, bob_db));
    openConversation(cid);
    (open(alice, ALICE_DEVICE).await, open(bob, BOB_DEVICE).await)
}

async fn send(client: &WasmMlsClient, cid: &str, n: u32, text: &str) -> Result<MessageRow, String> {
    let row = client
        .send_message(cid.into(), message_id(n), text.into())
        .await
        .map_err(|error| error.as_string().unwrap_or_default())?;
    Ok(serde_wasm_bindgen::from_value(row).unwrap())
}

/// `(sendCounter, outcome, ciphertext)` of every `sendMessage` the fixture saw for `n`.
fn attempts(n: u32) -> Vec<(u64, String, String)> {
    let sends: Vec<Value> = serde_json::from_str(&dsSends()).unwrap();
    sends
        .into_iter()
        .filter(|send| send["messageId"] == message_id(n))
        .map(|send| {
            let field = |name: &str| send[name].as_str().unwrap().to_owned();
            (
                send["sendCounter"].as_u64().unwrap(),
                field("outcome"),
                field("ciphertext"),
            )
        })
        .collect()
}

/// `(seq, displayed text)` of the timeline, oldest first; a gap row shows its notice key.
fn timeline(client: &WasmMlsClient, cid: &str) -> Vec<(i64, String)> {
    let mut rows: Vec<MessageRow> =
        serde_wasm_bindgen::from_value(client.list_messages(cid.into(), None, 50).unwrap())
            .unwrap();
    rows.sort_by_key(|row| row.seq);
    rows.iter()
        .map(|row| {
            let payload: Value = serde_json::from_str(&row.plaintext_json).unwrap();
            (row.seq, payload["text"].as_str().unwrap().to_owned())
        })
        .collect()
}

fn conversation_row(client: &WasmMlsClient, cid: &str) -> ConversationRow {
    let rows: Vec<ConversationRow> =
        serde_wasm_bindgen::from_value(client.list_conversations(None, 10).unwrap()).unwrap();
    rows.into_iter()
        .find(|row| row.conversation_id == cid)
        .unwrap()
}

fn timeline_of(rows: &[(i64, &str)]) -> Vec<(i64, String)> {
    rows.iter()
        .map(|(seq, text)| (*seq, text.to_string()))
        .collect()
}

/// The counter is reserved with the ratchet advance in one transaction and persists in
/// `account_meta`, so every signed send carries a strictly larger value, across a reopen too.
#[wasm_bindgen_test]
async fn send_counter_strictly_increases_across_sends_and_reopen() {
    let _restore = install_ds();
    let (alice, bob) = (did("counteralice"), did("counterbob"));
    let cid = "00000000-0000-4000-8000-0000000c0001";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    send(&bob_client, cid, 1, "one").await.unwrap();
    send(&bob_client, cid, 2, "two").await.unwrap();
    drop(bob_client);
    let bob_client = open(&bob, BOB_DEVICE).await;
    send(&bob_client, cid, 3, "three").await.unwrap();
    let counters: Vec<_> = (1..=3)
        .flat_map(attempts)
        .map(|(counter, outcome, _)| (counter, outcome))
        .collect();
    assert_eq!(
        counters,
        [(1, "accepted"), (2, "accepted"), (3, "accepted")].map(|(c, o)| (c, o.to_owned()))
    );
    alice_client.sync().await.unwrap();
    assert_eq!(
        timeline(&alice_client, cid),
        timeline_of(&[(2, "one"), (3, "two"), (4, "three")])
    );
}

/// A send held in the network keeps its journal; after a newer send is sequenced, the caller's
/// retry resubmits those exact bytes, `mls-ds` refuses them (`StaleSend`), and the same message
/// id goes out once more as a fresh frame with a new counter. The refused bytes are never
/// sequenced, and a second `StaleSend` is returned rather than retried.
#[wasm_bindgen_test]
async fn stale_send_reencrypts_once_and_never_resubmits_refused_bytes() {
    let _restore = install_ds();
    let (alice, bob) = (did("stalealice"), did("stalebob"));
    let cid = "00000000-0000-4000-8000-0000000c0002";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    holdNextSend();
    send(&bob_client, cid, 1, "held").await.unwrap_err();
    send(&bob_client, cid, 2, "newer").await.unwrap();
    let row = send(&bob_client, cid, 1, "held")
        .await
        .expect("StaleSend re-encrypts the same message id");
    let held = attempts(1);
    assert_eq!(
        held.iter()
            .map(|(counter, outcome, _)| (*counter, outcome.as_str()))
            .collect::<Vec<_>>(),
        [(1, "held"), (1, "stale"), (3, "accepted")]
    );
    assert_eq!(
        held[0].2, held[1].2,
        "the retry resubmits the journaled bytes"
    );
    assert_ne!(
        held[2].2, held[0].2,
        "the refused bytes are never sequenced"
    );
    assert_eq!((row.message_id, row.seq), (message_id(1), 3));
    alice_client.sync().await.unwrap();
    assert_eq!(
        timeline(&alice_client, cid),
        timeline_of(&[(2, "newer"), (3, "held")])
    );

    refuseEverySend(true);
    let error = send(&bob_client, cid, 4, "refused").await.unwrap_err();
    assert!(error.contains("StaleSend"), "{error}");
    assert_eq!(
        attempts(4)
            .into_iter()
            .map(|(counter, outcome, _)| (counter, outcome))
            .collect::<Vec<_>>(),
        [(4, "stale"), (5, "stale")].map(|(c, o)| (c, o.to_owned())),
        "exactly one fresh re-encryption"
    );
}

/// `mls-ds` sequenced a send whose response was lost. The generation was reserved before
/// HTTP, so the next send uses the next one (a reused generation would reach Alice as
/// `SecretReuse`), and Bob recovers his own entry from the send journal.
#[wasm_bindgen_test]
async fn lost_send_response_never_reuses_the_reserved_generation() {
    let _restore = install_ds();
    let (alice, bob) = (did("lostalice"), did("lostbob"));
    let cid = "00000000-0000-4000-8000-0000000c0003";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    loseNextSendResponse();
    send(&bob_client, cid, 1, "response lost")
        .await
        .unwrap_err();
    send(&bob_client, cid, 2, "after the loss").await.unwrap();
    assert_eq!(attempts(1)[0].0, 1);
    assert_eq!(attempts(2)[0].0, 2);
    alice_client.sync().await.unwrap();
    let expected = timeline_of(&[(2, "response lost"), (3, "after the loss")]);
    assert_eq!(timeline(&alice_client, cid), expected);
    bob_client.sync().await.unwrap();
    assert_eq!(timeline(&bob_client, cid), expected);
    assert_eq!(conversation_row(&bob_client, cid).last_seq, 3);
}

/// Seed 2323: a send held by the network was sequenced after six newer sends from the same
/// device, beyond the receiver's sender-ratchet window. The receiver records a gap row and
/// evidence, advances its cursor and still applies the later Commit.
#[wasm_bindgen_test]
async fn undecryptable_current_epoch_entry_is_tombstoned_and_a_later_commit_applies() {
    let _restore = install_ds();
    let (alice, bob) = (did("tombalice"), did("tombbob"));
    let cid = "00000000-0000-4000-8000-0000000c0004";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    // A `mls-ds` without the send-order rule sequences the late send.
    enforceSendOrder(false);
    holdNextSend();
    send(&bob_client, cid, 1, "late").await.unwrap_err();
    for n in 2..=7 {
        send(&bob_client, cid, n, &format!("newer {n}"))
            .await
            .unwrap();
    }
    deliverHeld();
    drop(bob_client);
    let commit = {
        let db = account_db(&bob);
        let signer = device_signer(&db);
        let mls = db.openmls_provider().unwrap();
        let group_id = db
            .backend()
            .get_conversation(cid)
            .unwrap()
            .unwrap()
            .group_id;
        let mut group = MlsGroup::load(mls.storage(), &GroupId::from_slice(&group_id))
            .unwrap()
            .unwrap();
        let bundle = group
            .self_update(&mls, &signer, LeafNodeParameters::default())
            .unwrap();
        group.merge_pending_commit(&mls).unwrap();
        bundle.into_commit().tls_serialize_detached().unwrap()
    };
    let commit_entry = json!({
        "$type": "blue.catbird.chat.defs#commitEntry",
        "entryId": uuid::Uuid::new_v4().to_string(),
        "conversationId": cid,
        "signedRequest": {"body": {
            "$type": "blue.catbird.chat.defs#commitTransitionBody",
            "actorDid": bob, "actorDeviceId": BOB_DEVICE,
            "commit": {"bytes": STANDARD.encode(&commit)},
        }},
    });
    assert_eq!(appendEntry(cid, &commit_entry.to_string()), 9);

    alice_client
        .sync()
        .await
        .expect("an undecryptable entry no longer stops sync");
    let mut expected: Vec<(i64, String)> = (2..=7).map(|n| (n, format!("newer {n}"))).collect();
    expected.push((8, chat_wire::UNDECRYPTABLE_MESSAGE_NOTICE.into()));
    assert_eq!(timeline(&alice_client, cid), expected);
    let rows: Vec<MessageRow> =
        serde_wasm_bindgen::from_value(alice_client.list_messages(cid.into(), None, 50).unwrap())
            .unwrap();
    let gap = rows.iter().find(|row| row.seq == 8).unwrap();
    assert_eq!(
        (gap.message_id.as_str(), gap.sender_did.as_str(), gap.is_own),
        (message_id(1).as_str(), bob.as_str(), false)
    );
    assert_eq!(
        gap.plaintext_json,
        serde_json::to_string(&MLSMessagePayload::system(
            chat_wire::UNDECRYPTABLE_MESSAGE_NOTICE
        ))
        .unwrap()
    );
    let convo = conversation_row(&alice_client, cid);
    assert_eq!(
        (convo.last_seq, convo.epoch, convo.unread_count),
        (9, 2, 7),
        "cursor past the gap, Bob's Commit applied"
    );
    drop(alice_client);
    let evidence = account_db(&alice)
        .backend()
        .get_labyrinth_state(&chat_wire::undecryptable_evidence_key(cid, &message_id(1)))
        .unwrap()
        .expect("undecryptable evidence");
    let evidence: chat_wire::UndecryptableEntryEvidence =
        serde_json::from_slice(&evidence).unwrap();
    assert_eq!(
        (
            evidence.seq,
            evidence.epoch,
            evidence.reason.as_str(),
            evidence.sender_did.as_str(),
            evidence.sender_device_id.as_str(),
        ),
        (8, 1, "TooDistantInThePast", bob.as_str(), BOB_DEVICE)
    );
}
