//! `C33` direct requests for `WasmMlsClient` over real encrypted OPFS. A stateful fetch fixture
//! plays the PDSes and `mls-ds`: enrollment records each account's PDS device key, declaration
//! and request keys, `prepareDirectRequest` reserves one of Bob's published request keys, and
//! `publishDirectRequest` answers the coordinator's ES256 outcome over the seq-1 `I13` receipt
//! of the signed opening. The coordinator (both accounts' home DS) publishes its request-receipt
//! method, `#mls-receipt-1` and the rotated `#mls-receipt-2` in its DID document. A recipient's
//! sync reads the inventory, pending Welcomes and entries a test serves, `acceptConversation`
//! answers a coordinator-signed acceptance proof, and `submitTransition` echoes the signed
//! transition it sequences.
#![cfg(target_arch = "wasm32")]
use std::rc::Rc;

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_v2::transcript::direct_request::{
    direct_request_acceptance_entry_hash, direct_request_receipt_key_id_for_authority,
    direct_request_signing_bytes, DirectRequestKind,
};
use catbird_mls::client::chat_wire::{self, StoredArchivedReceipt};
use catbird_mls::client::{QueuedLabyrinthArchivePayload, REQUIRED_LABYRINTH_OAUTH_SCOPES};
use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend as _};
use catbird_mls::storage::{ConversationRow, MessageRow, RequestRow};
use catbird_mls_web::{SqliteConn, WasmMlsClient};
use labyrinth_protocol::receipt::{
    expected_receipt_key_id, sign_sequencer_receipt, SequencerReceiptPayload,
};
use openmls::prelude::{GroupId, MlsGroup, OpenMlsProvider as _, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen(inline_js = r#"
let originalFetch;
let publishResponse;
let acceptResponse;
let ds;
export function installDs(respond, accept, didDocs, preparation) {
  originalFetch = globalThis.fetch;
  publishResponse = respond;
  acceptResponse = accept;
  const docs = JSON.parse(didDocs);
  ds = {records: {}, keys: {}, prepares: [], publishes: [], lose: 0, reply: 'signed', accept: 'signed',
    inventory: {}, welcomes: {}, entries: {}, calls: {}, accepts: [], transitions: [], transition: 'echo',
    closes: [], close: 'echo', also: []};
  globalThis.fetch = async (request) => {
    const reply = (body, status = 200) => {
      const r = new Response(JSON.stringify(body), {status, headers: {'content-type': 'application/json'}});
      Object.defineProperty(r, 'url', {value: request.url});
      return r;
    };
    const url = new URL(request.url);
    // Every did:web host serves its own document.
    if (url.pathname === '/.well-known/did.json')
      return url.host in docs ? reply(docs[url.host]) : reply({error: 'NotFound'}, 404);
    const param = (name) => url.searchParams.get(name);
    const nsid = url.pathname.replace('/xrpc/', '');
    ds.calls[nsid] = (ds.calls[nsid] || 0) + 1;
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
        const prefix = `at://${param('repo')}/${param('collection')}/`;
        return reply({records: Object.entries(ds.records).filter(([uri]) => uri.startsWith(prefix))
          .map(([uri, value]) => ({uri, cid: 'bafyfixture', value}))});
      }
      case 'com.atproto.repo.getRecord': {
        const uri = `at://${param('repo')}/${param('collection')}/${param('rkey')}`;
        return uri in ds.records ? reply({uri, cid: 'bafyfixture', value: ds.records[uri]})
          : reply({error: 'RecordNotFound', message: uri}, 400);
      }
      case 'blue.catbird.chat.enrollDevice':
        return reply({device: {deviceId: b.deviceId, keyId: b.keyId, signaturePublicKey: b.signaturePublicKey,
          authGeneration: 1, status: 'active', availablePackageCount: 2, reservedPackageCount: 0,
          createdAt: '2026-11-07T00:00:00.000Z', updatedAt: '2026-11-07T00:00:00.000Z'}});
      case 'blue.catbird.chat.publishDirectRequestKeys':
        ds.keys[b.actorDid] = b.keys.map((k) => ({actorDid: b.actorDid, actorDeviceId: b.actorDeviceId,
          keyPackage: k.keyPackage, grant: k.grant}));
        return reply({revision: b.revision, enabled: true});
      case 'blue.catbird.chat.replenishKeyPackages': return reply({acceptedCount: b.keyPackages.length});
      // Every preparation reserves one more of the recipient's published request keys, plus one
      // of each sibling account device `alsoSelect` named for it.
      case 'blue.catbird.chat.prepareDirectRequest':
        ds.prepares.push(text);
        return reply({outcome: {...JSON.parse(preparation), conversationId: b.conversationId,
          selectedDevices: [ds.keys[b.recipientDid].pop(), ...ds.also.splice(0).map((did) => ds.keys[did].pop())]}});
      case 'blue.catbird.chat.publishDirectRequest': {
        ds.publishes.push(text);
        const outcome = JSON.parse(publishResponse(text, ds.reply));
        if (ds.lose > 0) {
          ds.lose--;
          throw new TypeError('publishDirectRequest response lost');
        }
        return reply(outcome);
      }
      // A device's sync reads exactly what the test serves it.
      case 'blue.catbird.chat.getConversations':
        return reply({items: ds.inventory[param('actorDeviceId')] || [], hasMore: false});
      case 'blue.catbird.chat.getPendingWelcomes':
        return reply({items: ds.welcomes[param('actorDeviceId')] || [], hasMore: false});
      case 'blue.catbird.chat.getLeafRecoveryInbox': return reply({items: [], hasMore: false});
      case 'blue.catbird.chat.getEntries': {
        const after = Number(param('afterSeq'));
        return reply({entries: (ds.entries[param('conversationId')] || []).filter((e) => e.seq > after),
          hasMore: false});
      }
      case 'blue.catbird.chat.acceptConversation':
        ds.accepts.push(text);
        return reply(JSON.parse(acceptResponse(text, ds.accept)));
      case 'blue.catbird.chat.acknowledgeEntries': return reply({});
      // An own transition's answer: its entry echoes the signed request at seq 2 and its
      // coordinates are that request's signed `next` (`echo`), or the echo is altered
      // (`foreignEntry`) or names other coordinates (`foreignCoordinates`), or the transition is
      // sequenced but its answer lost (`lose`), or it is refused for good (`stale`).
      case 'blue.catbird.chat.submitTransition': {
        ds.transitions.push(text);
        const signedRequest = JSON.parse(text).signedRequest;
        const entry = {$type: `blue.catbird.chat.defs#${b.$type.split('#')[1].replace(/(Transition)?Body$/, 'Entry')}`,
          entryId: b.transitionId, conversationId: b.next.conversationId, seq: 2,
          signedRequest: structuredClone(signedRequest), receivedAt: b.signedAt};
        ds.sequenced = structuredClone(entry);
        const coordinates = structuredClone(b.next);
        if (ds.transition === 'lose') throw new TypeError('submitTransition response lost');
        if (ds.transition === 'stale') return reply({error: 'StaleCoordinates', message: 'stale'}, 409);
        if (ds.transition === 'foreignEntry') entry.signedRequest.body.signedAt = '2026-11-07T00:00:00.000Z';
        if (ds.transition === 'foreignCoordinates') coordinates.epoch += 1;
        return reply({coordinates, entry, welcomes: []});
      }
      // An own close's recorded result at seq 2 (`echo`, also for an exact replay), its entry
      // altered (`forged`), or the close sequenced but its answer lost (`lose`).
      case 'blue.catbird.chat.closeConversation': {
        ds.closes.push(text);
        const tombstone = {conversationId: b.prior.conversationId, conversationKind: b.conversationKind,
          retired: b.retired, closedByDid: b.actorDid, closedByDeviceId: b.actorDeviceId, terminalSeq: 2,
          closedAt: b.signedAt};
        const entry = {$type: 'blue.catbird.chat.defs#conversationCloseEntry', entryId: b.transitionId,
          conversationId: b.prior.conversationId, seq: 2, signedRequest: JSON.parse(text).signedRequest,
          tombstone, receivedAt: b.signedAt};
        if (ds.close === 'lose') throw new TypeError('closeConversation response lost');
        if (ds.close === 'forged') entry.signedRequest.body.signedAt = '2026-11-07T00:00:00.000Z';
        return reply({result: {entry, tombstone}});
      }
      default: return reply({error: 'NotFound', message: nsid}, 404);
    }
  };
}
export function losePublishResponse() { ds.lose += 1; }
export function replyToPublish(kind) { ds.reply = kind; }
export function answerAccept(kind) { ds.accept = kind; }
export function answerTransition(kind) { ds.transition = kind; }
export function answerClose(kind) { ds.close = kind; }
export function sequencedTransition() { return JSON.stringify(ds.sequenced); }
export function alsoSelect(did) { ds.also.push(did); }
export function serveInventory(deviceId, items) { ds.inventory[deviceId] = JSON.parse(items); }
export function serveWelcomes(deviceId, items) { ds.welcomes[deviceId] = JSON.parse(items); }
export function serveEntries(cid, entries) { ds.entries[cid] = JSON.parse(entries); }
export function putPdsRecord(uri, record) { ds.records[uri] = JSON.parse(record); }
export function dsCalls(nsid) { return ds.calls[nsid] || 0; }
export function dsPrepares() { return JSON.stringify(ds.prepares); }
export function dsPublishes() { return JSON.stringify(ds.publishes); }
export function dsAccepts() { return JSON.stringify(ds.accepts); }
export function dsTransitions() { return JSON.stringify(ds.transitions); }
export function dsCloses() { return JSON.stringify(ds.closes); }
export function restoreFetch() { globalThis.fetch = originalFetch; }
"#)]
extern "C" {
    fn installDs(
        respond: &js_sys::Function,
        accept: &js_sys::Function,
        did_docs: &str,
        preparation: &str,
    );
    fn losePublishResponse();
    fn replyToPublish(kind: &str);
    fn answerAccept(kind: &str);
    fn answerTransition(kind: &str);
    fn answerClose(kind: &str);
    fn sequencedTransition() -> String;
    fn alsoSelect(did: &str);
    fn serveInventory(device_id: &str, items: &str);
    fn serveWelcomes(device_id: &str, items: &str);
    fn serveEntries(cid: &str, entries: &str);
    fn putPdsRecord(uri: &str, record: &str);
    fn dsCalls(nsid: &str) -> u32;
    fn dsPrepares() -> String;
    fn dsPublishes() -> String;
    fn dsAccepts() -> String;
    fn dsTransitions() -> String;
    fn dsCloses() -> String;
    fn restoreFetch();
}
struct RestoreFetch;
impl Drop for RestoreFetch {
    fn drop(&mut self) {
        restoreFetch();
    }
}

/// Both accounts' home DS, hence the `C33` coordinator and the conversation sequencer. A
/// production-valid authority: direct-request transcripts refuse reserved TLDs like `.test`.
const SEQUENCER: &str = "did:web:chat.catbird.blue";
/// Mallory's home DS. It sorts before `SEQUENCER`, so it coordinates any pair with Mallory.
const ATTACKER: &str = "did:web:attacker.catbird.blue";
const ALICE_DEVICE: &str = "00000000-0000-4000-8000-00000000a001";
const BOB_DEVICE: &str = "00000000-0000-4000-8000-00000000b001";

fn did(name: &str) -> String {
    format!("did:plc:{name:a<24}")
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

/// The coordinator's ES256 key, behind both its request-receipt and `#mls-receipt-1` methods.
fn coordinator_key() -> SigningKey {
    key(19)
}

/// The coordinator's rotated `#mls-receipt-2` key.
fn rotated_key() -> SigningKey {
    key(23)
}

/// The attacker DS's key, behind each of its methods.
fn attacker_key() -> SigningKey {
    key(29)
}

fn public_key(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

/// `authority`'s request-receipt method for `key`.
fn request_receipt_method(authority: &str, key: &SigningKey) -> String {
    direct_request_receipt_key_id_for_authority(authority, &public_key(key)).unwrap()
}

/// The method that signs the coordinator's preparations and outcomes.
fn receipt_method() -> String {
    request_receipt_method(SEQUENCER, &coordinator_key())
}

/// `authority`'s `I13` receipt method of `generation`.
fn receipt_kid(authority: &str, generation: u32) -> String {
    format!("{authority}#mls-receipt-{generation}")
}

fn did_document(authority: &str, methods: &[(String, SigningKey)]) -> Value {
    let methods: Vec<Value> = methods
        .iter()
        .map(|(id, key)| {
            let mut multikey = vec![0x80, 0x24];
            multikey.extend(public_key(key));
            json!({"id": id, "controller": authority, "type": "Multikey",
                "publicKeyMultibase": format!("m{}", STANDARD_NO_PAD.encode(&multikey))})
        })
        .collect();
    json!({"id": authority, "verificationMethod": methods})
}

/// Each `did:web` host's document. The coordinator still publishes `#mls-receipt-1` beside
/// its rotated `#mls-receipt-2`.
fn did_documents() -> String {
    json!({
        "chat.catbird.blue": did_document(SEQUENCER, &[
            (receipt_method(), coordinator_key()),
            (receipt_kid(SEQUENCER, 1), coordinator_key()),
            (receipt_kid(SEQUENCER, 2), rotated_key()),
        ]),
        "attacker.catbird.blue": did_document(ATTACKER, &[
            (request_receipt_method(ATTACKER, &attacker_key()), attacker_key()),
            (receipt_kid(ATTACKER, 1), attacker_key()),
        ]),
    })
    .to_string()
}

/// What `prepareDirectRequest` answers besides the conversation and the selected device.
fn preparation() -> String {
    json!({
        "authorityDid": SEQUENCER,
        "receiptKeyId": receipt_method(),
        "preparationDigest": STANDARD.encode([7u8; 32]),
    })
    .to_string()
}

/// `key`'s base64 ES256 signature over `body`'s `kind` transcript.
fn es256(key: &SigningKey, kind: DirectRequestKind, body: &Value) -> String {
    let transcript =
        direct_request_signing_bytes(kind, &serde_json::to_vec(body).unwrap()).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(&transcript);
    STANDARD.encode(signature.normalize_s().unwrap_or(signature).to_bytes())
}

/// `authority`'s `#directRequestPublishedReceipt` outcome for publication body `b`, naming
/// `actor`, over the seq-1 `I13` receipt of its opening that `receipt_signer` (a key and the
/// method it claims) signs. `signed` adds the outcome signature under `authority_key`.
fn outcome(
    b: &Value,
    actor: &Value,
    authority: &str,
    authority_key: &SigningKey,
    receipt_signer: (&SigningKey, &str),
    signed: bool,
) -> Value {
    let text = |v: &Value| v.as_str().unwrap().to_owned();
    let bytes = |v: &Value| STANDARD.decode(v.as_str().unwrap()).unwrap();
    let payload = SequencerReceiptPayload {
        sequencer_did: authority.into(),
        conversation_id: text(&b["conversationId"]),
        group_id: bytes(&b["next"]["groupId"]),
        epoch: b["next"]["epoch"].as_u64().unwrap(),
        sender_device_did_url: format!("{}#{}", text(&b["actorDid"]), text(&b["actorDeviceId"])),
        entry_id: text(&b["firstMessageId"]),
        archive_commitment: bytes(&b["archiveCommitment"]).try_into().unwrap(),
        seq: 1,
        issued_at_ms: chrono::DateTime::parse_from_rfc3339(b["signedAt"].as_str().unwrap())
            .unwrap()
            .timestamp_millis(),
    };
    let (receipt_key, receipt_kid) = receipt_signer;
    let receipt = sign_sequencer_receipt(receipt_key, receipt_kid, &payload).unwrap();
    let opening_receipt = json!({
        "sequencerDid": authority, "conversationId": payload.conversation_id,
        "generation": b["next"]["generation"], "groupId": STANDARD.encode(&payload.group_id),
        "epoch": payload.epoch, "senderDid": b["actorDid"], "senderDeviceId": b["actorDeviceId"],
        "entryId": payload.entry_id, "archiveCommitment": STANDARD.encode(payload.archive_commitment),
        "seq": payload.seq, "issuedAtMs": payload.issued_at_ms, "kid": receipt.key_id,
        "signature": STANDARD.encode(receipt.signature),
    });
    let publication =
        direct_request_signing_bytes(DirectRequestKind::Publish, &serde_json::to_vec(b).unwrap())
            .unwrap();
    let mut outcome = json!({
        "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
        "body": {
            "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
            "protocolVersion": "2", "authorityDid": authority,
            "keyId": request_receipt_method(authority, authority_key),
            "receipt": {
                "$type": "blue.catbird.chat.defs#directRequestPublishedReceipt",
                "requestId": b["requestId"], "requestKind": "publish",
                "requestDigest": STANDARD.encode(Sha256::digest(&publication)),
                "recordedAt": b["signedAt"], "conversationId": b["conversationId"],
                "firstMessageId": b["firstMessageId"], "coordinates": b["next"],
                "preparationRequestDigest": b["preparationRequestDigest"],
                "actorDid": actor, "actorDeviceId": b["actorDeviceId"],
                "actorKeyId": b["keyId"], "authGeneration": b["authGeneration"],
                "sequencerReceipt": opening_receipt,
            },
        },
    });
    if signed {
        outcome["signature"] = json!(es256(
            authority_key,
            DirectRequestKind::Outcome,
            &outcome["body"]
        ));
    }
    outcome
}

/// The coordinator's answer to `publishDirectRequest` `request` (`{"signedRequest": ...}`):
/// `signed`, the outcome over a `#mls-receipt-1` opening receipt; `rotated`, over a
/// `#mls-receipt-2` one; `unsigned`, that outcome without its signature; `wrongActor`, signed
/// but naming the recipient as the actor.
fn publish_response(request: String, reply: String) -> String {
    let request: Value = serde_json::from_str(&request).unwrap();
    let b = &request["signedRequest"]["body"];
    let actor = if reply == "wrongActor" {
        &b["recipientDid"]
    } else {
        &b["actorDid"]
    };
    let (receipt_key, generation) = if reply == "rotated" {
        (rotated_key(), 2)
    } else {
        (coordinator_key(), 1)
    };
    let outcome = outcome(
        b,
        actor,
        SEQUENCER,
        &coordinator_key(),
        (&receipt_key, &receipt_kid(SEQUENCER, generation)),
        reply != "unsigned",
    );
    json!({ "outcome": outcome }).to_string()
}

/// The coordinator's answer to `acceptConversation` `request` (`{"directRequest": ...}`): a
/// `directRequestAcceptanceProof` sequencing that signed acceptance at seq 2 (`signed`) or seq 3
/// (`gap`), its acceptance-commit receipt signed by the coordinator, or by a key behind none of
/// its request-receipt methods (`forged`).
fn accept_response(request: String, kind: String) -> String {
    let request: Value = serde_json::from_str(&request).unwrap();
    let wrapper = &request["directRequest"];
    let body = &wrapper["body"];
    let seq = if kind == "gap" { 3 } else { 2 };
    let entry = json!({
        "entryId": body["transitionId"], "conversationId": body["prior"]["conversationId"],
        "seq": seq, "signedRequest": wrapper,
        "receivedAt": body["signedAt"],
    });
    let acceptance = direct_request_signing_bytes(
        DirectRequestKind::Accept,
        &serde_json::to_vec(body).unwrap(),
    )
    .unwrap();
    let entry_hash =
        direct_request_acceptance_entry_hash(&serde_json::to_vec(&entry).unwrap()).unwrap();
    let receipt = json!({
        "$type": "blue.catbird.chat.defs#directRequestAcceptanceCommitReceiptBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPTANCE-COMMIT\0",
        "protocolVersion": "2", "authorityDid": SEQUENCER, "keyId": receipt_method(),
        "requestId": body["requestId"],
        "acceptanceDigest": STANDARD.encode(Sha256::digest(&acceptance)),
        "entryHash": STANDARD.encode(entry_hash),
        "prior": body["prior"], "next": body["next"], "recordedAt": body["signedAt"],
    });
    let signer = if kind == "forged" {
        rotated_key()
    } else {
        coordinator_key()
    };
    let signature = es256(&signer, DirectRequestKind::AcceptanceCommit, &receipt);
    json!({"coordinates": body["next"], "acceptanceProof": {"entry": entry,
        "receipt": {"body": receipt, "signature": signature}}})
    .to_string()
}

fn install_ds() -> RestoreFetch {
    let respond = Closure::<dyn Fn(String, String) -> String>::new(publish_response);
    let accept = Closure::<dyn Fn(String, String) -> String>::new(accept_response);
    installDs(
        respond.as_ref().unchecked_ref(),
        accept.as_ref().unchecked_ref(),
        &did_documents(),
        &preparation(),
    );
    respond.forget();
    accept.forget();
    RestoreFetch
}

async fn open(did: &str, device_id: &str) -> WasmMlsClient {
    let client = WasmMlsClient::open_async(
        did.into(),
        device_id.into(),
        SEQUENCER.into(),
        "https://chat.catbird.blue".into(),
        "https://pds.catbird.blue".into(),
        "ab".repeat(32),
    )
    .await
    .unwrap();
    client.set_auth_token(Some("session".into()));
    client
}

/// An enrolled client: PDS device record and declaration, `mls-ds` device and request keys.
async fn enrolled(did: &str, device_id: &str) -> WasmMlsClient {
    let client = open(did, device_id).await;
    let scopes = serde_wasm_bindgen::to_value(&REQUIRED_LABYRINTH_OAUTH_SCOPES).unwrap();
    client.enroll_device(true, scopes).await.unwrap();
    client
}

/// The app's untitled 1:1 `createGroup` with `peer`, which names a new conversation per tap.
async fn create(client: &WasmMlsClient, cid: &str, peer: &str) -> Result<ConversationRow, String> {
    let members = serde_wasm_bindgen::to_value(&[peer]).unwrap();
    let row = client
        .create_group(cid.into(), SEQUENCER.into(), members, None, None)
        .await
        .map_err(|error| error.as_string().unwrap_or_default())?;
    Ok(serde_wasm_bindgen::from_value(row).unwrap())
}

async fn sync(client: &WasmMlsClient) -> Result<u32, String> {
    client
        .sync()
        .await
        .map_err(|error| error.as_string().unwrap_or_default())
}

async fn accept(client: &WasmMlsClient, request: &str) -> Result<(), String> {
    client
        .accept_direct_request(request.into())
        .await
        .map_err(|error| error.as_string().unwrap_or_default())
}

/// Exact bodies the fixture received, oldest first.
fn sent(log: String) -> Vec<String> {
    serde_json::from_str(&log).unwrap()
}

fn signed_body(raw: &str) -> Value {
    let mut request: Value = serde_json::from_str(raw).unwrap();
    request["signedRequest"]["body"].take()
}

fn conversations(client: &WasmMlsClient) -> Vec<ConversationRow> {
    serde_wasm_bindgen::from_value(client.list_conversations(None, 10).unwrap()).unwrap()
}

fn conversation(client: &WasmMlsClient, cid: &str) -> ConversationRow {
    conversations(client)
        .into_iter()
        .find(|row| row.conversation_id == cid)
        .unwrap()
}

fn requests(client: &WasmMlsClient) -> Vec<RequestRow> {
    serde_wasm_bindgen::from_value(client.list_requests(None).unwrap()).unwrap()
}

fn request(client: &WasmMlsClient, cid: &str) -> RequestRow {
    requests(client)
        .into_iter()
        .find(|row| row.conversation_id == cid)
        .unwrap()
}

fn messages(client: &WasmMlsClient, cid: &str) -> Vec<MessageRow> {
    serde_wasm_bindgen::from_value(client.list_messages(cid.into(), None, 10).unwrap()).unwrap()
}

/// The account database a closed client left behind.
fn account_db(did: &str) -> WasmAccountDb<Rc<SqliteConn>> {
    let path = format!(
        "catbird-mls/{}.db",
        hex::encode(Sha256::digest(did.as_bytes()))
    );
    WasmAccountDb::new(Rc::new(SqliteConn::open(&path, &"ab".repeat(32)).unwrap()))
}

/// `account`'s outgoing creation journal for `peer`, from its closed database.
fn creation_journal(account: &str, peer: &str) -> Option<Value> {
    account_db(account)
        .backend()
        .get_account_meta(&format!("direct_request_creation:{peer}"))
        .unwrap()
        .map(|raw| serde_json::from_str(&raw).unwrap())
}

/// Alice's published requests to Bob, one per conversation id: Bob's open client and Alice's
/// exact `publishDirectRequest` bodies, in order.
async fn published(alice: &str, bob: &str, cids: &[&str]) -> (WasmMlsClient, Vec<String>) {
    let bob_client = enrolled(bob, BOB_DEVICE).await;
    let alice_client = enrolled(alice, ALICE_DEVICE).await;
    for cid in cids {
        create(&alice_client, cid, bob).await.unwrap();
    }
    (bob_client, sent(dsPublishes()))
}

/// The coordinator's signed outcome for publication `raw`, its opening receipt signed by
/// `receipt_signer`.
fn published_outcome(raw: &str, receipt_signer: (&SigningKey, &str)) -> Value {
    let b = signed_body(raw);
    outcome(
        &b,
        &b["actorDid"],
        SEQUENCER,
        &coordinator_key(),
        receipt_signer,
        true,
    )
}

/// `getEntries`' seq-1 `directRequestEntry` with `outcome`: carrying the opening's
/// `signed_request`, or `payloadPruned` without it.
fn opening_entry(outcome: &Value, signed_request: Option<Value>) -> Value {
    let receipt = &outcome["body"]["receipt"];
    let mut entry = json!({
        "$type": "blue.catbird.chat.defs#directRequestEntry",
        "entryId": receipt["firstMessageId"], "conversationId": receipt["conversationId"],
        "seq": 1, "receivedAt": receipt["recordedAt"], "publicationReceipt": outcome,
        "sequencerReceipt": receipt["sequencerReceipt"],
    });
    match signed_request {
        Some(signed_request) => entry["signedRequest"] = signed_request,
        None => entry["payloadPruned"] = json!(true),
    }
    entry
}

/// A `getConversations` direct state for `cid` whose unsigned fields name `sender` and
/// `recipient`.
fn direct_state(cid: &str, sender: &str, recipient: &str) -> Value {
    json!({
        "conversationKind": "direct", "coordinates": {"conversationId": cid},
        "participants": [{"userDid": sender}, {"userDid": recipient}],
        "directRequest": {"senderDid": sender, "recipientDid": recipient},
    })
}

/// Serve Bob the inventory and intact seq-1 openings of Alice's publications `raws`, each
/// under the coordinator's `#mls-receipt-1` opening receipt.
fn serve_openings(raws: &[String], alice: &str, bob: &str) {
    let mut states = Vec::new();
    for raw in raws {
        let mut request: Value = serde_json::from_str(raw).unwrap();
        let outcome = published_outcome(raw, (&coordinator_key(), &receipt_kid(SEQUENCER, 1)));
        let cid = outcome["body"]["receipt"]["conversationId"]
            .as_str()
            .unwrap();
        let entry = opening_entry(&outcome, Some(request["signedRequest"].take()));
        serveEntries(cid, &json!([entry]).to_string());
        states.push(direct_state(cid, alice, bob));
    }
    serveInventory(BOB_DEVICE, &Value::from(states).to_string());
}

/// `getPendingWelcomes`' item for the Welcome of publication `raw` to Bob: the DS's
/// `directRequestWelcomeView` when `direct`, otherwise posing as a generic `welcomeView`.
fn welcome_view(raw: &str, bob: &str, direct: bool) -> Value {
    let b = signed_body(raw);
    let mut view = json!({
        "welcomeId": b["requestId"], "conversationId": b["conversationId"], "transitionSeq": 1,
        "coordinates": b["next"], "status": "pending",
        "opaqueWelcome": b["artifacts"]["welcome"]["opaqueWelcome"],
        "recipientDid": bob, "recipientDeviceId": BOB_DEVICE,
    });
    if direct {
        view["$type"] = json!("blue.catbird.chat.defs#directRequestWelcomeView");
    }
    view
}

/// `account`'s stored coordinates of `cid`, canonical, from its closed database.
fn stored_coords(account: &str, cid: &str) -> Value {
    let raw = account_db(account)
        .backend()
        .get_account_meta(&format!("conversation_coords:{cid}"))
        .unwrap()
        .expect("stored coordinates");
    chat_wire::canonicalize_wire_coordinate(&serde_json::from_str(&raw).unwrap(), Some(cid))
        .unwrap()
}

/// `account`'s enrolled device signer, from its closed database.
fn device_signer(account: &str) -> SignatureKeyPair {
    let raw = account_db(account)
        .backend()
        .get_labyrinth_state("device_signer_json")
        .unwrap()
        .expect("enrolled signer");
    serde_json::from_slice(&raw).unwrap()
}

/// The signed acceptance in `acceptConversation` request `raw` (`{"directRequest": ...}`).
fn sent_acceptance(raw: &str) -> Value {
    let mut request: Value = serde_json::from_str(raw).unwrap();
    request["directRequest"].take()
}

/// `signer`'s acceptance wrapper over `body`, its `keyId` naming `signer`'s key.
fn signed_acceptance(mut body: Value, signer: &SignatureKeyPair) -> Value {
    body["keyId"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(signer.public())));
    let wrapper =
        chat_wire::sign_direct_request_wrapper(DirectRequestKind::Accept, body, signer).unwrap();
    serde_json::from_slice(&wrapper).unwrap()
}

/// The coordinator's acceptance-commit receipt over acceptance request `raw` at seq 2,
/// `signed` by the coordinator or `forged` under a key behind none of its methods.
fn acceptance_receipt(raw: &str, kind: &str) -> Value {
    let mut answer: Value =
        serde_json::from_str(&accept_response(raw.into(), kind.into())).unwrap();
    answer["acceptanceProof"]["receipt"].take()
}

/// `getEntries`' seq-2 `directRequestAcceptanceEntry` carrying acceptance `wrapper`, with
/// `receipt` as its `sequencerReceipt` when given.
fn acceptance_entry(wrapper: &Value, receipt: Option<&Value>) -> Value {
    let body = &wrapper["body"];
    let mut entry = json!({
        "$type": "blue.catbird.chat.defs#directRequestAcceptanceEntry",
        "entryId": body["transitionId"], "conversationId": body["prior"]["conversationId"],
        "seq": 2, "signedRequest": wrapper, "receivedAt": body["signedAt"],
    });
    if let Some(receipt) = receipt {
        entry["sequencerReceipt"] = receipt.clone();
    }
    entry
}

async fn remove(client: &WasmMlsClient, cid: &str, member: &str) -> Result<(), String> {
    client
        .remove_group_member(true, cid.into(), member.into())
        .await
        .map_err(|error| error.as_string().unwrap_or_default())
}

/// `mls-ds` published the request but its answer was lost. The next tap (a new conversation id)
/// replays the journaled request id and byte-identical publication with no second prepare, and
/// commits the journaled conversation: one conversation results.
///
/// Fail-before: the retry signed a fresh prepare with new request and group ids (a second
/// `prepareDirectRequest` and a different publication) and committed a second conversation.
#[wasm_bindgen_test]
async fn lost_publish_response_replays_the_journaled_publication() {
    let _restore = install_ds();
    let (alice, bob) = (did("replaypubalice"), did("replaypubbob"));
    drop(enrolled(&bob, BOB_DEVICE).await);
    let alice_client = enrolled(&alice, ALICE_DEVICE).await;
    let first_cid = "00000000-0000-4000-8000-0000000c3301";
    losePublishResponse();
    let lost = create(&alice_client, first_cid, &bob).await.unwrap_err();
    assert!(lost.contains("publishDirectRequest"), "{lost}");
    let row = create(&alice_client, "00000000-0000-4000-8000-0000000c3302", &bob)
        .await
        .expect("the journaled publication lands");

    let prepares = sent(dsPrepares());
    let publishes = sent(dsPublishes());
    assert_eq!(prepares.len(), 1, "no second prepare");
    assert_eq!(publishes.len(), 2);
    assert_eq!(publishes[0], publishes[1], "byte-identical publication");
    let request_id = signed_body(&prepares[0])["requestId"].clone();
    assert_eq!(signed_body(&publishes[1])["requestId"], request_id);
    assert_eq!(
        row.conversation_id, first_cid,
        "the journaled conversation wins"
    );
    assert_eq!(conversations(&alice_client).len(), 1);
    let requests = requests(&alice_client);
    assert_eq!(
        requests
            .iter()
            .map(|r| r.request_id.as_str())
            .collect::<Vec<_>>(),
        [request_id.as_str().unwrap()]
    );
    drop(alice_client);
    assert!(
        creation_journal(&alice, &bob).is_none(),
        "resolved by the commit"
    );
}

/// A 2xx answer proves nothing without the coordinator's signed outcome bound to this request:
/// an unsigned outcome, then on the identical replay a signed one naming another actor, both
/// fail with no conversation, request or message, and the journal keeps the publication.
///
/// Fail-before: the publish answer was never read, so the first call committed every row.
#[wasm_bindgen_test]
async fn unsigned_or_unbound_publish_outcome_commits_nothing() {
    let _restore = install_ds();
    let (alice, bob) = (did("unboundalice"), did("unboundbob"));
    drop(enrolled(&bob, BOB_DEVICE).await);
    let alice_client = enrolled(&alice, ALICE_DEVICE).await;
    let cid = "00000000-0000-4000-8000-0000000c3303";
    for reply in ["unsigned", "wrongActor"] {
        replyToPublish(reply);
        let error = create(&alice_client, cid, &bob).await.expect_err(reply);
        assert!(
            error.starts_with("Cryptography error: C33"),
            "{reply}: {error}"
        );
    }

    let publishes = sent(dsPublishes());
    assert_eq!(publishes.len(), 2);
    assert_eq!(
        publishes[0], publishes[1],
        "the retry replays the journaled bytes"
    );
    assert_eq!(sent(dsPrepares()).len(), 1);
    assert!(conversations(&alice_client).is_empty());
    assert!(requests(&alice_client).is_empty());
    assert!(messages(&alice_client, cid).is_empty());
    drop(alice_client);
    let journal = creation_journal(&alice, &bob).expect("the attempt is kept");
    assert!(journal["publish"].is_object(), "with its publication");
}

/// A verified signed publication commits the conversation at the receipt's sequence and stages
/// the opening for the conversation Space with its frame nonce, the verified `I13` receipt and
/// the applied group's roster, resolving the journal in the same write.
///
/// Fail-before: the staged opening carried neither a frame nonce nor a sequencer receipt.
#[wasm_bindgen_test]
async fn verified_publication_stages_the_opening_with_its_nonce_and_receipt() {
    let _restore = install_ds();
    let (alice, bob) = (did("stagedalice"), did("stagedbob"));
    drop(enrolled(&bob, BOB_DEVICE).await);
    let alice_client = enrolled(&alice, ALICE_DEVICE).await;
    let cid = "00000000-0000-4000-8000-0000000c3304";
    let row = create(&alice_client, cid, &bob).await.unwrap();
    assert_eq!(
        (
            row.conversation_id.as_str(),
            row.last_seq,
            row.epoch,
            row.sequencer_did.as_str()
        ),
        (cid, 1, 1, SEQUENCER)
    );
    let opening = messages(&alice_client, cid);
    assert_eq!(opening.len(), 1);
    assert_eq!((opening[0].seq, opening[0].is_own), (1, true));
    assert_eq!(requests(&alice_client)[0].consent, "outgoingPending");
    drop(alice_client);

    let staged: QueuedLabyrinthArchivePayload = serde_json::from_str(
        &account_db(&alice)
            .backend()
            .get_account_meta(&format!("c33_pending_opening:{cid}"))
            .unwrap()
            .expect("staged opening"),
    )
    .unwrap();
    let nonce = STANDARD
        .decode(staged.frame_nonce_b64.as_deref().expect("frame nonce"))
        .unwrap();
    assert_eq!(nonce.len(), 32);
    let receipt: StoredArchivedReceipt = serde_json::from_str(
        staged
            .sequencer_receipt_json
            .as_deref()
            .expect("verified I13 opening receipt"),
    )
    .unwrap();
    assert_eq!(
        (
            receipt.seq,
            receipt.entry_id.as_str(),
            receipt.key_id.as_str()
        ),
        (
            1,
            opening[0].message_id.as_str(),
            expected_receipt_key_id(SEQUENCER).as_str()
        )
    );
    assert!(receipt.original_sender_attestation.is_some());
    let mut roster = vec![alice.clone(), bob.clone()];
    roster.sort();
    assert_eq!((staged.seq, staged.expected_member_dids), (1, roster));
    assert!(creation_journal(&alice, &bob).is_none());
}

/// A direct request's Welcome joins only through the checked `C33` import. Bob's inventory
/// omits the conversation while `getPendingWelcomes` offers its Welcome, first posing as a
/// generic `welcomeView`, then as the DS's `directRequestWelcomeView`: Bob joins nothing and
/// acknowledges nothing. Once the inventory names the request, the checked import still finds
/// its request KeyPackage and imports the opening as a pending request.
///
/// Fail-before: with no local conversation, the generic importer joined the request's group
/// with no publication, outcome or `I13` receipt check and no request to consent to.
#[wasm_bindgen_test]
async fn a_direct_request_welcome_joins_only_through_the_checked_import() {
    let _restore = install_ds();
    let (alice, bob) = (did("welcomealice"), did("welcomebob"));
    let cid = "00000000-0000-4000-8000-0000000c3305";
    let (bob_client, raws) = published(&alice, &bob, &[cid]).await;
    for direct in [false, true] {
        serveWelcomes(
            BOB_DEVICE,
            &json!([welcome_view(&raws[0], &bob, direct)]).to_string(),
        );
        sync(&bob_client).await.unwrap();
        assert!(
            conversations(&bob_client).is_empty(),
            "joined through the generic import (directRequestWelcomeView: {direct})"
        );
        assert!(requests(&bob_client).is_empty());
    }
    assert_eq!(dsCalls("blue.catbird.chat.acknowledgeWelcome"), 0);

    serveWelcomes(BOB_DEVICE, "[]");
    serve_openings(&raws, &alice, &bob);
    sync(&bob_client).await.unwrap();
    assert_eq!(conversation(&bob_client, cid).last_seq, 1);
    assert_eq!(request(&bob_client, cid).consent, "incomingPending");
    assert_eq!(messages(&bob_client, cid).len(), 1);
}

/// A pruned opening's participants come from its signed evidence alone: the coordinator's
/// outcome names the sender, and the account that never imported the opening is the
/// recipient. First a forged pruned opening claims to be Bob's own, to Mallory, whose home DS
/// (the attacker) would then coordinate and signs it: nothing signed names an own opening's
/// recipient, so Bob records nothing. Then Bob's inventory names Mallory as the sender of
/// Alice's pruned opening: Bob records it as Alice's, under Alice's real coordinator.
///
/// Fail-before: the inventory's participant pair chose the coordinator, so Bob recorded the
/// forged opening as his terminal request to Mallory, closing that conversation for good.
#[wasm_bindgen_test]
async fn a_pruned_openings_participants_come_from_its_signed_outcome() {
    let _restore = install_ds();
    let (alice, bob, mallory) = (did("prunedalice"), did("prunedbob"), did("prunedmallory"));
    putPdsRecord(
        &format!("at://{mallory}/blue.catbird.chat.declaration/self"),
        &json!({ "deliveryService": ATTACKER }).to_string(),
    );
    let cid = "00000000-0000-4000-8000-0000000c3306";
    let (bob_client, raws) = published(&alice, &bob, &[cid]).await;

    let forged_cid = "00000000-0000-4000-8000-0000000c3307";
    let mut b = signed_body(&raws[0]);
    b["conversationId"] = json!(forged_cid);
    b["next"]["conversationId"] = json!(forged_cid);
    b["actorDid"] = json!(bob);
    b["actorDeviceId"] = json!(BOB_DEVICE);
    let forged = outcome(
        &b,
        &b["actorDid"],
        ATTACKER,
        &attacker_key(),
        (&attacker_key(), &receipt_kid(ATTACKER, 1)),
        true,
    );
    serveEntries(
        forged_cid,
        &json!([opening_entry(&forged, None)]).to_string(),
    );
    let forged_state = direct_state(forged_cid, &bob, &mallory);
    serveInventory(BOB_DEVICE, &json!([forged_state]).to_string());
    sync(&bob_client).await.unwrap();
    assert!(
        requests(&bob_client).is_empty(),
        "nothing signed names an own opening's recipient"
    );

    let honest = published_outcome(&raws[0], (&coordinator_key(), &receipt_kid(SEQUENCER, 1)));
    serveEntries(cid, &json!([opening_entry(&honest, None)]).to_string());
    serveInventory(
        BOB_DEVICE,
        &json!([forged_state, direct_state(cid, &mallory, &bob)]).to_string(),
    );
    sync(&bob_client).await.unwrap();
    let recorded: Vec<_> = requests(&bob_client)
        .into_iter()
        .map(|r| (r.conversation_id, r.sender_did, r.recipient_did, r.consent))
        .collect();
    assert_eq!(
        recorded,
        [(cid.into(), alice, bob, "openingUnavailable".into())]
    );
    assert!(conversations(&bob_client).is_empty());
}

/// Accepting moves the cursor only over its own verified entry: the coordinator's
/// acceptance-commit receipt over the sequenced entry carrying Bob's signed acceptance, and
/// only when that entry is the next one. An answer the coordinator did not sign is refused
/// with nothing changed; a verified acceptance at seq 2 moves the cursor from 1 to 2; one at
/// seq 3 is accepted but leaves the unverified seq 2 to sync.
///
/// Fail-before: accepting set `last_seq` to 2 from any 2xx answer, signed or not.
#[wasm_bindgen_test]
async fn accepting_moves_the_cursor_only_over_its_verified_entry() {
    let _restore = install_ds();
    let (alice, bob) = (did("acceptalice"), did("acceptbob"));
    let (next, gap) = (
        "00000000-0000-4000-8000-0000000c3308",
        "00000000-0000-4000-8000-0000000c3309",
    );
    let (bob_client, raws) = published(&alice, &bob, &[next, gap]).await;
    serve_openings(&raws, &alice, &bob);
    sync(&bob_client).await.unwrap();
    assert_eq!(conversation(&bob_client, next).last_seq, 1);
    assert_eq!(conversation(&bob_client, gap).last_seq, 1);

    answerAccept("forged");
    let error = accept(&bob_client, next).await.unwrap_err();
    assert!(error.contains("C33 acceptance"), "{error}");
    assert_eq!(conversation(&bob_client, next).last_seq, 1);
    assert_eq!(request(&bob_client, next).consent, "incomingPending");

    answerAccept("signed");
    accept(&bob_client, next).await.unwrap();
    assert_eq!(conversation(&bob_client, next).last_seq, 2);
    assert_eq!(request(&bob_client, next).consent, "accepted");

    answerAccept("gap");
    accept(&bob_client, gap).await.unwrap();
    assert_eq!(
        conversation(&bob_client, gap).last_seq,
        1,
        "seq 2 is not verified yet"
    );
    assert_eq!(request(&bob_client, gap).consent, "accepted");
}

/// `C33` import verifies the opening's `I13` receipt under the method its own `kid` names. The
/// coordinator rotated to `#mls-receipt-2` and still publishes `#mls-receipt-1`. A receipt that
/// names `#mls-receipt-2` but was signed with the `#mls-receipt-1` key is refused and imports
/// nothing; the genuine `#mls-receipt-2` receipt then imports the opening.
///
/// Fail-before: the importer verified every opening receipt under `#mls-receipt-1`, so it
/// imported the mislabeled receipt (and refused the genuine rotated one).
#[wasm_bindgen_test]
async fn c33_import_verifies_the_receipt_under_its_own_kid() {
    let _restore = install_ds();
    replyToPublish("rotated");
    let (alice, bob) = (did("rotatedalice"), did("rotatedbob"));
    let cid = "00000000-0000-4000-8000-0000000c3310";
    let (bob_client, raws) = published(&alice, &bob, &[cid]).await;
    let mut publication: Value = serde_json::from_str(&raws[0]).unwrap();
    let signed_request = publication["signedRequest"].take();
    serveInventory(
        BOB_DEVICE,
        &json!([direct_state(cid, &alice, &bob)]).to_string(),
    );

    let mislabeled = published_outcome(&raws[0], (&coordinator_key(), &receipt_kid(SEQUENCER, 2)));
    let entry = opening_entry(&mislabeled, Some(signed_request.clone()));
    serveEntries(cid, &json!([entry]).to_string());
    let error = sync(&bob_client)
        .await
        .expect_err("a receipt verifies only under the method its kid names");
    assert!(conversations(&bob_client).is_empty(), "{error}");
    assert!(requests(&bob_client).is_empty());
    assert!(messages(&bob_client, cid).is_empty());

    let genuine = published_outcome(&raws[0], (&rotated_key(), &receipt_kid(SEQUENCER, 2)));
    serveEntries(
        cid,
        &json!([opening_entry(&genuine, Some(signed_request))]).to_string(),
    );
    sync(&bob_client).await.unwrap();
    assert_eq!(conversation(&bob_client, cid).last_seq, 1);
    assert_eq!(request(&bob_client, cid).consent, "incomingPending");
    assert_eq!(messages(&bob_client, cid).len(), 1);
}

/// Contract A: an acceptance met in sync changes nothing until it verifies. Bob accepts Alice's
/// two requests; Alice, the sender, then syncs a seq-2 `directRequestAcceptanceEntry` that is
/// Bob's acceptance altered after signing, stripped of its signature, signed by a device of
/// Bob's that is no leaf of the group, signed by Bob for his other request, or carrying an
/// acceptance-commit receipt its coordinator did not sign. Each fails her sync and leaves her
/// request pending, her cursor at 1 and her coordinates as they were. Bob's genuine acceptances,
/// one bare and one with the coordinator's receipt, then move her exactly to seq 2 at their
/// signed coordinates.
///
/// Fail-before: sync applied any entry labelled an acceptance unverified, so the altered one
/// accepted the request, moved the cursor and wrote its coordinates.
#[wasm_bindgen_test]
async fn a_synced_acceptance_changes_nothing_until_it_verifies() {
    let _restore = install_ds();
    let (alice, bob) = (did("syncacceptalice"), did("syncacceptbob"));
    let (cid, other) = (
        "00000000-0000-4000-8000-0000000c3311",
        "00000000-0000-4000-8000-0000000c3312",
    );
    let (bob_client, raws) = published(&alice, &bob, &[cid, other]).await;
    serve_openings(&raws, &alice, &bob);
    sync(&bob_client).await.unwrap();
    accept(&bob_client, cid).await.unwrap();
    accept(&bob_client, other).await.unwrap();
    drop(bob_client);
    let accepts = sent(dsAccepts());
    let (genuine, genuine_other) = (sent_acceptance(&accepts[0]), sent_acceptance(&accepts[1]));
    let coordinates = stored_coords(&alice, cid);

    let mut altered = genuine.clone();
    altered["body"]["signedAt"] = json!("2026-11-07T00:00:00.000Z");
    let mut unsigned = genuine.clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    let mut stranger = genuine["body"].clone();
    stranger["actorDeviceId"] = json!("00000000-0000-4000-8000-00000000b002");
    let stranger = signed_acceptance(
        stranger,
        &SignatureKeyPair::new(SignatureScheme::ED25519).unwrap(),
    );
    let mut other_request = genuine["body"].clone();
    other_request["requestId"] = genuine_other["body"]["requestId"].clone();
    let other_request = signed_acceptance(other_request, &device_signer(&bob));
    let forged_receipt = acceptance_receipt(&accepts[0], "forged");
    let alice_client = open(&alice, ALICE_DEVICE).await;
    for (case, entry) in [
        ("altered", acceptance_entry(&altered, None)),
        ("unsigned", acceptance_entry(&unsigned, None)),
        ("not a leaf", acceptance_entry(&stranger, None)),
        ("other request", acceptance_entry(&other_request, None)),
        (
            "forged receipt",
            acceptance_entry(&genuine, Some(&forged_receipt)),
        ),
    ] {
        serveEntries(cid, &json!([entry]).to_string());
        let error = sync(&alice_client).await.expect_err(case);
        assert!(error.starts_with("Cryptography error:"), "{case}: {error}");
        assert_eq!(
            request(&alice_client, cid).consent,
            "outgoingPending",
            "{case}"
        );
        assert_eq!(conversation(&alice_client, cid).last_seq, 1, "{case}");
    }
    drop(alice_client);
    assert_eq!(stored_coords(&alice, cid), coordinates);

    serveEntries(cid, &json!([acceptance_entry(&genuine, None)]).to_string());
    let receipt = acceptance_receipt(&accepts[1], "signed");
    serveEntries(
        other,
        &json!([acceptance_entry(&genuine_other, Some(&receipt))]).to_string(),
    );
    let alice_client = open(&alice, ALICE_DEVICE).await;
    sync(&alice_client).await.unwrap();
    for id in [cid, other] {
        assert_eq!(request(&alice_client, id).consent, "accepted");
        assert_eq!(conversation(&alice_client, id).last_seq, 2);
    }
    drop(alice_client);
    for (id, acceptance) in [(cid, &genuine), (other, &genuine_other)] {
        let next = chat_wire::canonicalize_wire_coordinate(&acceptance["body"]["next"], Some(id));
        assert_eq!(stored_coords(&alice, id), next.unwrap());
    }
}

/// Contract A: only a verified `directRequestAcceptanceEntry` accepts a request. Bob's
/// acceptance, altered after signing, reaches Alice relabeled: as a `participantAcceptanceEntry`
/// around its direct-request body, as a direct-request entry around a
/// `participantAcceptanceBody`, and as a pending invitee's acceptance throughout. Each must
/// verify as the kind it claims: each fails her sync and neither accepts her request, moves her
/// cursor nor archives its staged opening.
///
/// Fail-before: a participant acceptance shared the direct-request effects, so the relabeled
/// forgery accepted the request and archived the opening; later, a participant acceptance
/// still moved the cursor unverified.
#[wasm_bindgen_test]
async fn a_relabeled_acceptance_never_accepts_the_request() {
    let _restore = install_ds();
    let (alice, bob) = (did("relabelalice"), did("relabelbob"));
    let cid = "00000000-0000-4000-8000-0000000c3314";
    let (bob_client, raws) = published(&alice, &bob, &[cid]).await;
    serve_openings(&raws, &alice, &bob);
    sync(&bob_client).await.unwrap();
    accept(&bob_client, cid).await.unwrap();
    drop(bob_client);
    let mut forged = sent_acceptance(&sent(dsAccepts())[0]);
    forged["body"]["signedAt"] = json!("2026-11-07T00:00:00.000Z");
    let relabeled = |entry_kind: &str, body_kind: &str| {
        let mut entry = acceptance_entry(&forged, None);
        entry["$type"] = json!(format!("blue.catbird.chat.defs#{entry_kind}"));
        entry["signedRequest"]["body"]["$type"] =
            json!(format!("blue.catbird.chat.defs#{body_kind}"));
        json!([entry]).to_string()
    };
    let alice_client = open(&alice, ALICE_DEVICE).await;
    for (entry_kind, body_kind) in [
        ("participantAcceptanceEntry", "directRequestAcceptanceBody"),
        ("directRequestAcceptanceEntry", "participantAcceptanceBody"),
        ("participantAcceptanceEntry", "participantAcceptanceBody"),
    ] {
        serveEntries(cid, &relabeled(entry_kind, body_kind));
        let error = sync(&alice_client)
            .await
            .expect_err(&format!("{entry_kind} around {body_kind}"));
        assert!(
            error.starts_with("Cryptography error:"),
            "{entry_kind} around {body_kind}: {error}"
        );
        assert_eq!(conversation(&alice_client, cid).last_seq, 1, "{entry_kind}");
        let request = request(&alice_client, cid);
        assert_eq!(
            (request.consent.as_str(), request.first_message_archived),
            ("outgoingPending", false)
        );
    }
    drop(alice_client);
    let opening = account_db(&alice)
        .backend()
        .get_account_meta(&format!("c33_pending_opening:{cid}"))
        .unwrap();
    assert!(
        opening.is_some_and(|staged| staged != "archived"),
        "the opening stays staged"
    );
}

/// The enrolled device rows of `account`'s database: its signer and enrollment binding.
const DEVICE_ROWS: [&str; 3] = [
    "auth_generation",
    "enrolled_device_id",
    "enrolled_signer_key_id",
];

/// Swap the device `account`'s closed database is enrolled as for `device` (`None`: a fresh,
/// unenrolled one with a new signer), returning the device it held. A browser profile holds one
/// database per account, so two devices of one account take turns in it.
fn swap_device(
    account: &str,
    device: Option<(Vec<u8>, Vec<Option<String>>)>,
) -> (Vec<u8>, Vec<Option<String>>) {
    let db = account_db(account);
    let backend = db.backend();
    let held = (
        backend
            .get_labyrinth_state("device_signer_json")
            .unwrap()
            .unwrap(),
        DEVICE_ROWS
            .iter()
            .map(|key| backend.get_account_meta(key).unwrap())
            .collect(),
    );
    let (signer, rows) = device.unwrap_or_else(|| {
        let fresh = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        (serde_json::to_vec(&fresh).unwrap(), vec![None; 3])
    });
    db.write_tx(|tx| {
        tx.put_labyrinth_state("device_signer_json", &signer, 0)?;
        for (key, value) in DEVICE_ROWS.iter().zip(&rows) {
            match value {
                Some(value) => tx.put_account_meta(key, value, 0)?,
                None => tx.delete_account_meta(key)?,
            }
        }
        Ok(())
    })
    .unwrap();
    held
}

/// An opening another of this account's devices published imports on this device as the
/// account's outgoing request. Alice's first device publishes to Bob, and mls-ds makes her
/// second device a Welcome recipient: there the signed publication's actor (Alice) is the
/// sender and its recipient (Bob) the recipient, whose PDS keys authorize his leaves; the
/// request is `outgoingPending` with no unread count, the opening is Alice's own message and
/// nothing is staged for archive (the publishing device's duty). Bob's acceptance then verifies
/// against that recipient, and accepting archives nothing on the second device.
///
/// Fail-before: only the sender's and this account's keys were fetched, so Bob's leaf failed
/// `I4` and every sync of the second device errored.
#[wasm_bindgen_test]
async fn a_siblings_own_opening_imports_as_an_outgoing_request() {
    const SIBLING_DEVICE: &str = "00000000-0000-4000-8000-00000000a002";
    let _restore = install_ds();
    let (alice, bob) = (did("siblingalice"), did("siblingbob"));
    let cid = "00000000-0000-4000-8000-0000000c3320";
    let bob_client = enrolled(&bob, BOB_DEVICE).await;
    drop(enrolled(&alice, ALICE_DEVICE).await);
    let first = swap_device(&alice, None);
    // The sibling enrolls last, so the preparation selects one of its request keys.
    drop(enrolled(&alice, SIBLING_DEVICE).await);
    let sibling = swap_device(&alice, Some(first));
    alsoSelect(&alice);
    let alice_client = open(&alice, ALICE_DEVICE).await;
    create(&alice_client, cid, &bob).await.unwrap();
    drop(alice_client);
    // The publishing device's own copy goes: the sibling imports into the same database.
    {
        let db = account_db(&alice);
        let group_id = db
            .backend()
            .get_conversation(cid)
            .unwrap()
            .unwrap()
            .group_id;
        let mls = db.openmls_provider().unwrap();
        let mut group = MlsGroup::load(mls.storage(), &GroupId::from_slice(&group_id))
            .unwrap()
            .unwrap();
        group.delete(mls.storage()).unwrap();
        db.write_tx(|tx| {
            tx.delete_conversation(cid)?;
            tx.delete_account_meta(&format!("c33_pending_opening:{cid}"))
        })
        .unwrap();
    }
    swap_device(&alice, Some(sibling));
    let raw = sent(dsPublishes()).pop().unwrap();
    let mut publication: Value = serde_json::from_str(&raw).unwrap();
    let outcome = published_outcome(&raw, (&coordinator_key(), &receipt_kid(SEQUENCER, 1)));
    let opening = opening_entry(&outcome, Some(publication["signedRequest"].take()));
    serveEntries(cid, &json!([opening]).to_string());
    let state = json!([direct_state(cid, &alice, &bob)]).to_string();
    serveInventory(SIBLING_DEVICE, &state);
    let sibling_client = open(&alice, SIBLING_DEVICE).await;
    sync(&sibling_client).await.unwrap();
    let row = conversation(&sibling_client, cid);
    assert_eq!((row.last_seq, row.unread_count), (1, 0));
    let recorded = request(&sibling_client, cid);
    assert_eq!(
        (
            recorded.sender_did.as_str(),
            recorded.recipient_did.as_str(),
            recorded.consent.as_str()
        ),
        (alice.as_str(), bob.as_str(), "outgoingPending")
    );
    let opening_rows: Vec<bool> = messages(&sibling_client, cid)
        .iter()
        .map(|m| m.is_own)
        .collect();
    assert_eq!(
        opening_rows,
        [true],
        "the opening is this account's own message"
    );

    serveInventory(BOB_DEVICE, &state);
    sync(&bob_client).await.unwrap();
    accept(&bob_client, cid).await.unwrap();
    let acceptance = sent_acceptance(&sent(dsAccepts())[0]);
    serveEntries(
        cid,
        &json!([opening, acceptance_entry(&acceptance, None)]).to_string(),
    );
    sync(&sibling_client).await.unwrap();
    assert_eq!(request(&sibling_client, cid).consent, "accepted");
    assert_eq!(conversation(&sibling_client, cid).last_seq, 2);
    drop(sibling_client);
    let db = account_db(&alice);
    assert_eq!(
        db.backend()
            .get_account_meta(&format!("c33_pending_opening:{cid}"))
            .unwrap(),
        None
    );
    assert!(db
        .backend()
        .list_labyrinth_queue(Some(cid), 10)
        .unwrap()
        .is_empty());
}

/// Contract B: a 2xx answer to this device's own `submitTransition` is evidence only of the
/// signed request it echoes. Alice removes Bob: an answer whose entry is not her signed Commit,
/// then one whose coordinates are not its signed `next`, each fail and change nothing (no staged
/// merge, coordinates or cursor); the genuine echo merges the Commit and writes its signed
/// `next`.
///
/// Fail-before: any 2xx answer merged the Commit and wrote the answer's coordinates.
#[wasm_bindgen_test]
async fn an_own_commit_answer_counts_only_as_its_signed_request() {
    let _restore = install_ds();
    let (alice, bob) = (did("ownansweralice"), did("ownanswerbob"));
    let cid = "00000000-0000-4000-8000-0000000c3313";
    drop(published(&alice, &bob, &[cid]).await);
    let coordinates = stored_coords(&alice, cid);
    let alice_client = open(&alice, ALICE_DEVICE).await;
    for answer in ["foreignEntry", "foreignCoordinates"] {
        answerTransition(answer);
        let error = remove(&alice_client, cid, &bob).await.unwrap_err();
        assert!(
            error.starts_with("Cryptography error: unverified answer to own request"),
            "{answer}: {error}"
        );
        let row = conversation(&alice_client, cid);
        assert_eq!((row.epoch, row.last_seq), (1, 1), "{answer}");
    }
    drop(alice_client);
    assert_eq!(stored_coords(&alice, cid), coordinates);

    answerTransition("echo");
    let alice_client = open(&alice, ALICE_DEVICE).await;
    remove(&alice_client, cid, &bob).await.unwrap();
    assert_eq!(conversation(&alice_client, cid).epoch, 2);
    drop(alice_client);
    let signed = signed_body(sent(dsTransitions()).last().unwrap());
    let next = chat_wire::canonicalize_wire_coordinate(&signed["next"], Some(cid)).unwrap();
    assert_eq!(stored_coords(&alice, cid), next);
}

/// `account`'s `account_meta` value at `key`, from its closed database.
fn account_meta(account: &str, key: &str) -> Option<String> {
    account_db(account).backend().get_account_meta(key).unwrap()
}

/// `account`'s own-Commit journal of the `transitions`-th (from 1) `submitTransition` this
/// test sent for `cid`, from its closed database.
fn commit_journal(account: &str, cid: &str, transitions: usize) -> Option<String> {
    let body = signed_body(&sent(dsTransitions())[transitions - 1]);
    let transition = body["transitionId"].as_str().unwrap();
    account_meta(account, &format!("commit_transition:{cid}:{transition}"))
}

/// Alice removes Bob and `mls-ds` sequences the Commit, but its answer is lost: nothing merges,
/// and the staged Commit stays journaled. Her next sync reads her own echo and merges exactly
/// that journal: the Commit's epoch, its signed `next` and the cursor, the journal gone.
///
/// Fail-before: nothing was journaled before HTTP, so the lost answer dropped the staged Commit
/// and the echo could never merge it.
#[wasm_bindgen_test]
async fn a_lost_own_commit_answer_is_merged_by_its_own_echo() {
    let _restore = install_ds();
    let (alice, bob) = (did("lostcommitalice"), did("lostcommitbob"));
    let cid = "00000000-0000-4000-8000-0000000c3315";
    drop(published(&alice, &bob, &[cid]).await);
    let alice_client = open(&alice, ALICE_DEVICE).await;
    answerTransition("lose");
    remove(&alice_client, cid, &bob).await.unwrap_err();
    let row = conversation(&alice_client, cid);
    assert_eq!((row.epoch, row.last_seq), (1, 1));
    drop(alice_client);
    assert!(
        commit_journal(&alice, cid, 1).is_some(),
        "the lost Commit stays journaled"
    );

    serveEntries(cid, &format!("[{}]", sequencedTransition()));
    let alice_client = open(&alice, ALICE_DEVICE).await;
    sync(&alice_client).await.unwrap();
    let row = conversation(&alice_client, cid);
    assert_eq!((row.epoch, row.last_seq), (2, 2));
    drop(alice_client);
    assert_eq!(commit_journal(&alice, cid, 1), None);
    let signed = signed_body(sent(dsTransitions()).last().unwrap());
    let next = chat_wire::canonicalize_wire_coordinate(&signed["next"], Some(cid)).unwrap();
    assert_eq!(stored_coords(&alice, cid), next);
}

/// An answer that does not verify as Alice's own Commit is refused like a lost one: nothing
/// merges and the journal stays for the own echo. A retry refused for good (`409
/// StaleCoordinates`) proves its own bytes are never sequenced: its journal goes, the first stays.
///
/// Fail-before: no attempt was journaled, so a refused answer left nothing for the echo.
#[wasm_bindgen_test]
async fn a_refused_own_commit_keeps_its_journal_until_refused_for_good() {
    let _restore = install_ds();
    let (alice, bob) = (did("refusedcommitalice"), did("refusedcommitbob"));
    let cid = "00000000-0000-4000-8000-0000000c3316";
    drop(published(&alice, &bob, &[cid]).await);
    let alice_client = open(&alice, ALICE_DEVICE).await;
    answerTransition("foreignEntry");
    remove(&alice_client, cid, &bob).await.unwrap_err();
    drop(alice_client);
    let kept = commit_journal(&alice, cid, 1).expect("a refused answer keeps the journal");
    let pending: Value = serde_json::from_str(&kept).unwrap();
    let signed = signed_body(sent(dsTransitions()).last().unwrap());
    assert_eq!(pending["transition_id"], signed["transitionId"]);
    assert_eq!(pending["removed_participant_did"], json!(bob));

    answerTransition("stale");
    let alice_client = open(&alice, ALICE_DEVICE).await;
    let error = remove(&alice_client, cid, &bob).await.unwrap_err();
    assert!(error.contains("HTTP 409"), "{error}");
    assert_eq!(conversation(&alice_client, cid).epoch, 1);
    drop(alice_client);
    assert_eq!(
        commit_journal(&alice, cid, 2),
        None,
        "a terminal refusal drops its journal"
    );
    assert!(
        commit_journal(&alice, cid, 1).is_some(),
        "and only its own: the refused answer's Commit may still be sequenced"
    );
}

/// Bob declines Alice's request, closing the conversation. The close's answer is lost, then
/// forged: each leaves it open with the exact signed close journaled. His next sync replays
/// those bytes, and the verified answer closes it at the coordinate he signed.
///
/// Fail-before: web never journaled nor verified a close (its body even lacked the required
/// `conversationKind`), so the conversation never closed.
#[wasm_bindgen_test]
async fn a_lost_or_forged_close_answer_resolves_by_exact_replay() {
    let _restore = install_ds();
    let (alice, bob) = (did("closealice"), did("closebob"));
    let cid = "00000000-0000-4000-8000-0000000c3317";
    let (journal, closed) = (
        format!("conversation_close:{cid}"),
        format!("conversation_closed:{cid}"),
    );
    let (bob_client, raws) = published(&alice, &bob, &[cid]).await;
    serve_openings(&raws, &alice, &bob);
    sync(&bob_client).await.unwrap();
    answerClose("lose");
    bob_client.decline_direct_request(cid.into()).await.unwrap();
    drop(bob_client);
    let signed = account_meta(&bob, &journal).expect("the close is journaled");
    assert_eq!(account_meta(&bob, &closed), None);

    answerClose("forged");
    let bob_client = open(&bob, BOB_DEVICE).await;
    sync(&bob_client).await.unwrap();
    drop(bob_client);
    assert_eq!(account_meta(&bob, &journal).as_ref(), Some(&signed));
    assert_eq!(account_meta(&bob, &closed), None);

    answerClose("echo");
    let bob_client = open(&bob, BOB_DEVICE).await;
    sync(&bob_client).await.unwrap();
    drop(bob_client);
    let closes = sent(dsCloses());
    assert_eq!(closes.len(), 3);
    let exact = format!("{{\"signedRequest\":{signed}}}");
    assert!(closes.iter().all(|close| *close == exact), "{closes:?}");
    assert_eq!(account_meta(&bob, &closed).as_deref(), Some("true"));
    assert_eq!(account_meta(&bob, &journal), None);
    let retired: Value = serde_json::from_str(&signed).unwrap();
    assert_eq!(
        stored_coords(&bob, cid),
        chat_wire::canonicalize_wire_coordinate(&retired["body"]["retired"], Some(cid)).unwrap()
    );
}

/// Alice's Commit C1 is sequenced but its answer lost. Before any sync she tries another
/// removal from the same unmerged prior, which `mls-ds` refuses as stale. That refusal drops
/// only the second attempt's journal: her next sync reads C1's echo and merges C1's journal.
///
/// Fail-before: one journal per conversation, so the second attempt overwrote C1's journal and
/// its refusal deleted it; C1's echo then found no journal and sync failed for good.
#[wasm_bindgen_test]
async fn a_refused_retry_never_drops_a_lost_commits_journal() {
    let _restore = install_ds();
    let (alice, bob) = (did("stallcommitalice"), did("stallcommitbob"));
    let cid = "00000000-0000-4000-8000-0000000c3318";
    drop(published(&alice, &bob, &[cid]).await);
    let alice_client = open(&alice, ALICE_DEVICE).await;
    answerTransition("lose");
    remove(&alice_client, cid, &bob).await.unwrap_err();
    let first = sequencedTransition();
    answerTransition("stale");
    let error = remove(&alice_client, cid, &bob).await.unwrap_err();
    assert!(error.contains("HTTP 409"), "{error}");
    assert_eq!(conversation(&alice_client, cid).epoch, 1);

    serveEntries(cid, &format!("[{first}]"));
    sync(&alice_client).await.unwrap();
    let row = conversation(&alice_client, cid);
    assert_eq!((row.epoch, row.last_seq), (2, 2));
    drop(alice_client);
    let signed: Value = serde_json::from_str(&first).unwrap();
    let next = chat_wire::canonicalize_wire_coordinate(
        &signed["signedRequest"]["body"]["next"],
        Some(cid),
    )
    .unwrap();
    assert_eq!(stored_coords(&alice, cid), next);
    assert_eq!(
        account_meta(&alice, &format!("commit_transitions:{cid}")),
        None
    );
}
