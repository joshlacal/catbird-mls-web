//! Leaf recovery from signed requests, verified rosters and the reset-retired rejoin for
//! `WasmMlsClient` over real encrypted OPFS. A stateful fetch fixture plays `mls-ds` and the
//! accounts' PDS: it sequences each signed creation, transition, acceptance and reset activation
//! as the entry its body names and keeps the conversation state those entries leave
//! (`coordinates`, `participants`, `leaves`); it opens each acceptance's and
//! `requestLeafRecovery`'s recovery on one of the device's enrolled KeyPackages, lists the open ones
//! in `getConversationState` and delivers a fulfillment's Welcome to its recipient device. It
//! verifies nothing: every check is the client's. Devices outside any client (an account's second
//! device, the fulfiller of a test-built group, a reset activator) sign with their own keys,
//! registered on the fixture PDS.
#![cfg(target_arch = "wasm32")]
use std::rc::Rc;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_v2::transcript::{
    decode_strict_json, project_signed_body, SignedMutationKind, SigningTranscript,
};
use catbird_mls::client::{chat_wire, REQUIRED_LABYRINTH_OAUTH_SCOPES};
use catbird_mls::messaging::receive::PrivateMessagePlaintextEnvelope;
use catbird_mls::metadata::derive_metadata_key_from_group;
use catbird_mls::orchestrator::canonical_transport::{
    canonical_commit_aad_bytes, derive_key_id, CanonicalOperation,
};
use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend as _};
use catbird_mls::storage::{ConversationRow, MessageRow};
use catbird_mls_web::{SqliteConn, WasmMlsClient};
use labyrinth_protocol::receipt::{sign_sequencer_receipt, SequencerReceiptPayload};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider;
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
const SEQUENCER = 'did:web:ds.catbird.test';
const bytes = (v) => (typeof v === 'string' ? v : v.$bytes);
// A coordinate as mls-ds compares it.
const key = (c) => [c.conversationId, c.generation, c.stateVersion, bytes(c.groupId), c.epoch,
  bytes(c.groupContextHash), bytes(c.confirmationTag), c.lifecycle].join(' ');
const refused = (error) => [409, {error, message: error}];
const stateView = (cid) => ({conversationId: cid, conversationKind: 'group', sequencerDid: SEQUENCER,
  ...structuredClone(ds.convos[cid])});
// The recovery mls-ds opens for `b` (an acceptance or a `requestLeafRecovery` body), bound to
// `bound` and reserving the oldest of the device's enrolled KeyPackages.
function openRecovery(cid, b, bound, kind, signedRequest) {
  const kp = (ds.kps[b.actorDeviceId] || []).shift();
  if (!kp) return undefined;
  const ids = {conversationId: cid, recoveryRequestId: b.recoveryRequestId, boundCoordinate: bound,
    requesterDid: b.actorDid, requesterDeviceId: b.actorDeviceId};
  const view = {$type: 'blue.catbird.chat.defs#leafRecoveryView', ...ids, recoveryKind: kind,
    status: 'open', requestedAt: b.signedAt, expiresAt: '2099-01-01T00:00:00.000Z',
    reservation: {...ids, requesterKeyId: b.keyId, requesterAuthGeneration: b.authGeneration,
      keyPackageRef: kp.keyPackageRef, cipherSuite: 'MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519',
      purpose: 'leafRecovery', status: 'active', expiresAt: '2099-01-01T00:00:00.000Z', keyPackage: kp},
    ...(signedRequest ? {signedRequest} : {})};
  (ds.recoveries[cid] ||= []).push(view);
  return view;
}
// `signedRequest` sequenced as `cid`'s next entry, and the state it leaves: its participant and
// leaf changes, an acceptance's active row, a reset's manifest, its coordinate; every request open
// at another coordinate is superseded, and a fulfillment's Welcome is delivered.
function sequence(cid, signedRequest) {
  const b = signedRequest.body;
  const kind = b.$type.split('#')[1].replace(/(Transition)?Body$/, 'Entry');
  const seq = ++ds.seq[cid];
  const entry = {$type: `blue.catbird.chat.defs#${kind}`, entryId: b.transitionId, conversationId: cid,
    seq, signedRequest, receivedAt: b.signedAt,
    sequencerReceipt: JSON.parse(receiptFor(JSON.stringify({
      body: b, seq, entryId: b.transitionId, control: true})))};
  ds.entries[cid].push(entry);
  const c = ds.convos[cid];
  if (kind === 'resetActivationEntry') {
    c.participants = structuredClone(b.manifest.participants);
    c.leaves = [b.manifest.actorLeaf];
    c.coordinates = b.successor;
  } else {
    for (const change of b.participantChanges || b.manifest?.participantChanges || []) {
      const type = change.$type.split('#')[1];
      if (type === 'addParticipant') c.participants.push({userDid: change.userDid, role: change.role,
        status: 'pending', invitationProvenance: change.invitationProvenance});
      if (type === 'removeParticipant') c.participants = c.participants.filter((p) => p.userDid !== change.userDid);
      if (type === 'changeParticipantRole') c.participants.find((p) => p.userDid === change.userDid).role = change.role;
    }
    for (const change of b.manifest?.leafChanges || []) {
      if (change.$type.endsWith('#removeLeaf'))
        c.leaves = c.leaves.filter((l) => l.userDid !== change.userDid || l.deviceId !== change.deviceId);
      if (change.$type.endsWith('#addLeafByRecovery'))
        c.leaves.push({userDid: change.userDid, deviceId: change.deviceId, leafOrigin: 'recovery'});
    }
    if (kind === 'participantAcceptanceEntry') {
      const row = c.participants.find((p) => p.userDid === b.actorDid);
      row.status = 'active';
      delete row.invitationProvenance;
    }
    c.coordinates = b.next;
  }
  for (const r of ds.recoveries[cid] || [])
    if (r.status === 'open' && key(r.boundCoordinate) !== key(c.coordinates)) r.status = 'superseded';
  const bundle = b.manifest?.welcomeBundle;
  for (const d of bundle?.deliveries || [])
    (ds.welcomes[d.recipientDeviceId] ||= []).push({welcomeId: bundle.welcomeId, conversationId: cid,
      transitionSeq: entry.seq, coordinates: b.next, status: 'pending', opaqueWelcome: bundle.opaqueWelcome,
      sha256: bundle.sha256, recipientDid: d.recipientDid, recipientDeviceId: d.recipientDeviceId,
      provenance: d.provenance, expiresAt: '2099-01-01T00:00:00.000Z'});
  return entry;
}
function handlePost(nsid, text) {
  const request = JSON.parse(text);
  const signedRequest = request.signedRequest;
  const b = signedRequest?.body;
  const cid = b?.prior?.conversationId;
  const stale = () => key(b.prior) !== key(ds.convos[cid].coordinates);
  switch (nsid) {
    case 'com.atproto.repo.putRecord':
      ds.records[`at://${request.repo}/${request.collection}/${request.rkey}`] = request.record;
      return [200, {uri: 'at://fixture', cid: 'bafyfixture'}];
    case 'blue.catbird.chat.enrollDevice':
      ds.devices[b.deviceId] = b.actorDid;
      ds.kps[b.deviceId] = b.keyPackages.slice();
      return [200, {device: {deviceId: b.deviceId, keyId: b.keyId, signaturePublicKey: b.signaturePublicKey,
        authGeneration: 1, status: 'active', availablePackageCount: 2, reservedPackageCount: 0,
        createdAt: '2026-11-07T00:00:00.000Z', updatedAt: '2026-11-07T00:00:00.000Z'}}];
    case 'blue.catbird.chat.publishDirectRequestKeys': return [200, {revision: b.revision, enabled: true}];
    case 'blue.catbird.chat.replenishKeyPackages':
      (ds.kps[b.actorDeviceId] ||= []).push(...b.keyPackages);
      return [200, {acceptedCount: b.keyPackages.length}];
    case 'blue.catbird.chat.createConversation': {
      const id = b.conversationId;
      ds.createCalls.push(text);
      const completed = ds.creates[id];
      if (completed)
        return completed.text === text ? [200, structuredClone(completed.response)]
          : [400, {error: 'IdempotencyConflict', message: 'creation bytes changed'}];
      ds.convos[id] = {coordinates: b.next, participants: structuredClone(b.manifest.participants),
        leaves: [b.manifest.actorLeaf]};
      ds.seq[id] = 0;
      ds.entries[id] = [];
      const response = {result: {entry: sequence(id, signedRequest), coordinates: b.next}};
      ds.creates[id] = {text, response: structuredClone(response)};
      return [200, response];
    }
    case 'blue.catbird.chat.submitTransition':
      if (stale()) return refused('StaleCoordinates');
      ds.transitions.push(b);
      return [200, {coordinates: b.next, entry: sequence(cid, signedRequest), welcomes: []}];
    case 'blue.catbird.chat.acceptConversation': {
      if (stale()) return refused('StaleCoordinates');
      const entry = sequence(cid, signedRequest);
      entry.recovery = openRecovery(cid, b, b.next, 'add');
      return [200, {coordinates: b.next, entry, recovery: entry.recovery}];
    }
    // One open request per exact device, bound to the coordinate it was signed at.
    case 'blue.catbird.chat.requestLeafRecovery': {
      ds.requests.push(b);
      if (stale()) return refused('StaleCoordinates');
      if ((ds.recoveries[cid] || []).some((r) => r.status === 'open' && r.requesterDid === b.actorDid
        && r.requesterDeviceId === b.actorDeviceId)) return refused('LeafRecoveryAlreadyOpen');
      const recovery = openRecovery(cid, b, b.prior, b.recoveryKind, signedRequest);
      return recovery ? [200, {recovery}] : refused('KeyPackageUnavailable');
    }
    case 'blue.catbird.chat.acknowledgeWelcome':
      ds.welcomeAcks.push(b);
      ds.welcomes[b.actorDeviceId] = (ds.welcomes[b.actorDeviceId] || []).filter((w) => w.welcomeId !== b.welcomeId);
      return [200, {}];
    case 'blue.catbird.chat.acknowledgeEntries':
      ds.acked[`${request.conversationId} ${request.actorDeviceId}`] = request.upToSeq;
      return [200, {}];
    case 'blue.catbird.chat.sendMessage': {
      const seq = ++ds.seq[cid];
      const entry = {$type: 'blue.catbird.chat.defs#applicationEntry', entryId: b.messageId,
        conversationId: cid, seq, signedRequest, receivedAt: new Date().toISOString(),
        sequencerReceipt: JSON.parse(receiptFor(JSON.stringify({body: b, seq})))};
      ds.entries[cid].push(entry);
      return [200, {entry}];
    }
    default: return [404, {error: 'NotFound', message: nsid}];
  }
}
function handleGet(nsid, params) {
  const device = params.get('actorDeviceId');
  const cid = params.get('conversationId');
  switch (nsid) {
    case 'com.atproto.repo.listRecords': {
      const prefix = `at://${params.get('repo')}/${params.get('collection')}/`;
      return [200, {records: Object.entries(ds.records).filter(([uri]) => uri.startsWith(prefix))
        .map(([uri, value]) => ({uri, cid: 'bafyfixture', value}))}];
    }
    case 'blue.catbird.chat.getConversations':
      return [200, {items: Object.keys(ds.convos).filter((id) => ds.convos[id].participants
        .some((p) => p.userDid === ds.devices[device])).map((id) => ({state: stateView(id)})), hasMore: false}];
    case 'blue.catbird.chat.getPendingWelcomes': return [200, {items: ds.welcomes[device] || [], hasMore: false}];
    // A device's own recovery inbox: a fulfiller never takes work from it, whatever it lists.
    case 'blue.catbird.chat.getLeafRecoveryInbox': return [200, {items: ds.inbox[device] || [], hasMore: false}];
    case 'blue.catbird.chat.getConversationState':
      return [200, {state: stateView(cid),
        pendingLeafRecoveryRequests: (ds.recoveries[cid] || []).filter((r) => r.status === 'open')}];
    // A device reads the entries up to the end of its membership interval (`readableUntil`).
    case 'blue.catbird.chat.getEntries': {
      const after = Number(params.get('afterSeq'));
      (ds.reads[`${cid} ${device}`] ||= []).push(after);
      const until = ds.until[device] ?? Infinity;
      return [200, {entries: (ds.entries[cid] || []).filter((e) => e.seq > after && e.seq <= until)
        .slice(0, Number(params.get('limit') || 100)), hasMore: false}];
    }
    default: return [404, {error: 'NotFound', message: nsid}];
  }
}
export function installDs(receipt, didDoc) {
  originalFetch = globalThis.fetch;
  receiptFor = receipt;
  ds = {records: {}, devices: {}, kps: {}, seq: {}, entries: {}, convos: {}, recoveries: {}, welcomes: {},
    inbox: {}, until: {}, reads: {}, acked: {}, welcomeAcks: [], transitions: [], requests: [],
    creates: {}, createCalls: [], loseCreate: 0};
  globalThis.fetch = async (request) => {
    const url = new URL(request.url);
    const nsid = url.pathname.replace('/xrpc/', '');
    const [status, body] = url.pathname === '/.well-known/did.json' ? [200, JSON.parse(didDoc)]
      : nsid === 'com.atproto.server.getServiceAuth' ? [200, {token: 'service-auth'}]
      : request.method === 'POST' ? handlePost(nsid, await request.clone().text())
      : handleGet(nsid, url.searchParams);
    if (nsid === 'blue.catbird.chat.createConversation' && status === 200 && ds.loseCreate > 0) {
      ds.loseCreate--;
      throw new TypeError('createConversation response lost');
    }
    const r = new Response(JSON.stringify(body), {status, headers: {'content-type': 'application/json'}});
    Object.defineProperty(r, 'url', {value: request.url});
    return r;
  };
}
export function restoreFetch() { globalThis.fetch = originalFetch; }
export function loseNextCreateResponse() { ds.loseCreate++; }
export function createCallsJson() { return JSON.stringify(ds.createCalls); }
export function conversationCount() { return Object.keys(ds.convos).length; }
// The fixture's `[status, body]` answer to a POST of `text` to `nsid`.
export function post(nsid, text) { return JSON.stringify(handlePost(nsid, text)); }
// A conversation built outside any client: mls-ds holds `state` and no entry yet.
export function openConversation(cid, state) {
  ds.convos[cid] = JSON.parse(state);
  ds.seq[cid] = 0;
  ds.entries[cid] = [];
}
// `signedRequest` sequenced as `cid`'s next entry and applied to its state: returns its seq.
export function sequenceEntry(cid, signedRequest) { return sequence(cid, JSON.parse(signedRequest)).seq; }
// `entry` served at `cid`'s next seq, the conversation state left as it was.
export function appendEntry(cid, entry) {
  const e = JSON.parse(entry);
  e.seq = ++ds.seq[cid];
  e.sequencerReceipt = JSON.parse(receiptFor(JSON.stringify({
    body: e.signedRequest.body, seq: e.seq, entryId: e.entryId, control: true})));
  ds.entries[cid].push(e);
  return e.seq;
}
export function dropLastEntry(cid) { ds.entries[cid].pop(); ds.seq[cid]--; }
export function entriesJson(cid) { return JSON.stringify(ds.entries[cid] || []); }
export function stateJson(cid) { return JSON.stringify(stateView(cid)); }
// mls-ds lists exactly `items` as `cid`'s recoveries, in its state and in `device`'s inbox alike.
export function serveRecoveries(cid, device, items) {
  ds.recoveries[cid] = JSON.parse(items);
  ds.inbox[device] = JSON.parse(items);
}
export function recoveriesJson(cid) { return JSON.stringify(ds.recoveries[cid] || []); }
// The oldest of `device`'s enrolled KeyPackages, no longer reservable by mls-ds.
export function takeKeyPackage(device) { return JSON.stringify(ds.kps[device].shift()); }
export function addKeyPackages(device, items) { (ds.kps[device] ||= []).push(...JSON.parse(items)); }
export function readableUntil(device, seq) { ds.until[device] = seq; }
export function readableAgain(device) { delete ds.until[device]; }
// How many `getEntries` reads of `cid` `device` made.
export function entryReads(cid, device) { return (ds.reads[`${cid} ${device}`] || []).length; }
export function requestsJson(device) { return JSON.stringify(ds.requests.filter((b) => b.actorDeviceId === device)); }
export function transitionsJson() { return JSON.stringify(ds.transitions); }
export function welcomesJson(device) { return JSON.stringify(ds.welcomes[device] || []); }
// `device`'s pending Welcomes expire undelivered.
export function loseWelcomes(device) { ds.welcomes[device] = []; }
export function welcomeAcks() { return JSON.stringify(ds.welcomeAcks); }
export function ackedUpTo(cid, device) { return ds.acked[`${cid} ${device}`] || 0; }
"#)]
extern "C" {
    fn installDs(receipt: &js_sys::Function, did_doc: &str);
    fn restoreFetch();
    fn post(nsid: &str, text: &str) -> String;
    fn loseNextCreateResponse();
    fn createCallsJson() -> String;
    fn conversationCount() -> u32;
    fn openConversation(cid: &str, state: &str);
    fn sequenceEntry(cid: &str, signed_request: &str) -> u32;
    fn appendEntry(cid: &str, entry: &str) -> u32;
    fn dropLastEntry(cid: &str);
    fn entriesJson(cid: &str) -> String;
    fn stateJson(cid: &str) -> String;
    fn serveRecoveries(cid: &str, device: &str, items: &str);
    fn recoveriesJson(cid: &str) -> String;
    fn takeKeyPackage(device: &str) -> String;
    fn addKeyPackages(device: &str, items: &str);
    fn readableUntil(device: &str, seq: u32);
    fn readableAgain(device: &str);
    fn entryReads(cid: &str, device: &str) -> u32;
    fn requestsJson(device: &str) -> String;
    fn transitionsJson() -> String;
    fn welcomesJson(device: &str) -> String;
    fn loseWelcomes(device: &str);
    fn welcomeAcks() -> String;
    fn ackedUpTo(cid: &str, device: &str) -> u32;
}

struct RestoreFetch;
impl Drop for RestoreFetch {
    fn drop(&mut self) {
        restoreFetch();
    }
}

type Db = WasmAccountDb<Rc<SqliteConn>>;

const SEQUENCER: &str = "did:web:ds.catbird.test";
const RECEIPT_KID: &str = "did:web:ds.catbird.test#mls-receipt-1";
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const ALICE_DEVICE: &str = "00000000-0000-4000-8000-00000000a001";
const ALICE2_DEVICE: &str = "00000000-0000-4000-8000-00000000a002";
const BOB_DEVICE: &str = "00000000-0000-4000-8000-00000000b001";
const BOB2_DEVICE: &str = "00000000-0000-4000-8000-00000000b002";
const CAROL_DEVICE: &str = "00000000-0000-4000-8000-00000000c001";
const EVE_DEVICE: &str = "00000000-0000-4000-8000-00000000e001";

fn did(name: &str) -> String {
    format!("did:plc:{name:a<24}")
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn sequencer_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[19; 32]).unwrap()
}

/// `I13` receipt for an application or control entry the fixture sequenced.
fn receipt_for(request: String) -> String {
    let request: Value = serde_json::from_str(&request).unwrap();
    let body = &request["body"];
    let control = request["control"].as_bool().unwrap_or(false);
    let coordinate = if control {
        body.get("next")
            .or_else(|| body.get("successor"))
            .or_else(|| body.get("prior"))
            .unwrap()
    } else {
        &body["prior"]
    };
    let text = |v: &Value| v.as_str().unwrap().to_owned();
    let (entry_id, archive_commitment) = if control {
        let kind = body["$type"]
            .as_str()
            .and_then(SignedMutationKind::from_type_id)
            .unwrap();
        let strict = decode_strict_json(&serde_json::to_vec(body).unwrap()).unwrap();
        let projected = project_signed_body(kind, &strict).unwrap();
        (
            text(&request["entryId"]),
            *SigningTranscript::build_for(kind, &projected)
                .unwrap()
                .request_digest(),
        )
    } else {
        (
            text(&body["messageId"]),
            chat_wire::json_bytes(&body["aad"]["archiveCommitment"])
                .unwrap()
                .try_into()
                .unwrap(),
        )
    };
    let payload = SequencerReceiptPayload {
        sequencer_did: SEQUENCER.into(),
        conversation_id: text(&coordinate["conversationId"]),
        group_id: chat_wire::json_bytes(&coordinate["groupId"]).unwrap(),
        epoch: coordinate["epoch"].as_u64().unwrap(),
        sender_device_did_url: format!(
            "{}#{}",
            text(&body["actorDid"]),
            text(&body["actorDeviceId"])
        ),
        entry_id,
        archive_commitment,
        seq: request["seq"].as_u64().unwrap(),
        issued_at_ms: js_sys::Date::now() as i64,
    };
    let signed = sign_sequencer_receipt(&sequencer_key(), RECEIPT_KID, &payload).unwrap();
    json!({
        "sequencerDid": SEQUENCER, "conversationId": payload.conversation_id,
        "generation": coordinate["generation"], "groupId": STANDARD.encode(&payload.group_id),
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
        "id": RECEIPT_KID, "type": "JsonWebKey2020", "controller": SEQUENCER,
        "publicKeyJwk": {"kty": "EC", "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())},
    }]});
    let receipt = Closure::<dyn Fn(String) -> String>::new(receipt_for);
    installDs(receipt.as_ref().unchecked_ref(), &did_doc.to_string());
    receipt.forget();
    RestoreFetch
}

/// The fixture's answer to the request `body` POSTed to `nsid`: `(status, body)`.
fn post_json(nsid: &str, body: &str) -> (u16, Value) {
    serde_json::from_str(&post(nsid, body)).unwrap()
}

/// `body` signed as `operation` by `signer`, the device `body` names: the request mls-ds receives,
/// and the path it is POSTed to.
fn signed_request(
    operation: CanonicalOperation,
    mut body: Value,
    signer: &SignatureKeyPair,
) -> (String, Value) {
    body["keyId"] = json!(derive_key_id(signer.public()));
    let did = body["actorDid"].as_str().unwrap().to_owned();
    let device = body["actorDeviceId"].as_str().unwrap().to_owned();
    let prepared =
        chat_wire::sign_clean_chat_mutation(&did, &device, Some(1), operation, &body, signer)
            .unwrap();
    let request = serde_json::from_slice(prepared.body.as_deref().unwrap()).unwrap();
    (
        prepared.path.trim_start_matches("/xrpc/").to_owned(),
        request,
    )
}

/// The signed wrapper of `body` as `operation`, signed by `signer`.
fn signed(operation: CanonicalOperation, body: Value, signer: &SignatureKeyPair) -> Value {
    signed_request(operation, body, signer).1["signedRequest"].take()
}

/// `body` signed as `operation` by `signer` and POSTed to the fixture: its answer, which must be
/// a success.
fn submit(operation: CanonicalOperation, body: Value, signer: &SignatureKeyPair) -> Value {
    let (nsid, request) = signed_request(operation, body, signer);
    let (status, answer) = post_json(&nsid, &request.to_string());
    assert_eq!(status, 200, "{nsid}: {answer}");
    answer
}

/// `cid`'s state as mls-ds presents it.
fn state(cid: &str) -> Value {
    serde_json::from_str(&stateJson(cid)).unwrap()
}

/// `entry` of `kind` in `cid`, as `getEntries` serves it.
fn entry(kind: &str, cid: &str, signed_request: Value) -> Value {
    json!({
        "$type": format!("blue.catbird.chat.defs#{kind}"), "entryId": new_id(),
        "conversationId": cid, "receivedAt": "2026-11-07T00:00:00.000Z",
        "signedRequest": signed_request,
    })
}

/// Every signed `leafRecoveryFulfillmentBody` mls-ds received from `device`, oldest first.
fn fulfillments(device: &str) -> Vec<Value> {
    serde_json::from_str::<Vec<Value>>(&transitionsJson())
        .unwrap()
        .into_iter()
        .filter(|body| {
            body["$type"] == "blue.catbird.chat.defs#leafRecoveryFulfillmentBody"
                && body["actorDeviceId"] == device
        })
        .collect()
}

/// The Welcome bytes mls-ds holds last for `device`.
fn last_welcome(device: &str) -> Vec<u8> {
    let welcomes: Vec<Value> = serde_json::from_str(&welcomesJson(device)).unwrap();
    chat_wire::json_bytes(&welcomes.last().expect("a Welcome")["opaqueWelcome"]).unwrap()
}

/// mls-ds's participant rows of `cid`, as a reset manifest echoes them.
fn manifest_participants(cid: &str) -> Value {
    state(cid)["participants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| json!({ "userDid": row["userDid"], "role": row["role"], "status": row["status"] }))
        .collect()
}

/// The verified roster of `(did, role, status)` rows.
fn roster_of(rows: &[(&str, &str, &str)]) -> Value {
    rows.iter()
        .map(|(did, role, status)| ((*did).to_owned(), json!({ "role": role, "status": status })))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

fn canonical(coordinate: &Value, cid: &str) -> Value {
    chat_wire::canonicalize_wire_coordinate(coordinate, Some(cid)).unwrap()
}

fn account_db(did: &str) -> Db {
    let path = format!(
        "catbird-mls/{}.db",
        hex::encode(Sha256::digest(did.as_bytes()))
    );
    WasmAccountDb::new(Rc::new(SqliteConn::open(&path, &"ab".repeat(32)).unwrap()))
}

/// `cid`'s verified roster as `db` holds it.
fn roster(db: &Db, cid: &str) -> Option<Value> {
    db.backend()
        .get_account_meta(&chat_wire::conversation_roster_key(cid))
        .unwrap()
        .map(|raw| serde_json::from_str(&raw).unwrap())
}

/// `cid`'s coordinates as `db` recorded them, canonical.
fn coordinates(db: &Db, cid: &str) -> Option<Value> {
    db.backend()
        .get_account_meta(&format!("conversation_coords:{cid}"))
        .unwrap()
        .map(|raw| canonical(&serde_json::from_str(&raw).unwrap(), cid))
}

/// `(did#device, leaf encryption key)` of every leaf of `cid`'s MLS group in `db`, sorted; none
/// without a group.
fn leaves(db: &Db, cid: &str) -> Vec<(String, Vec<u8>)> {
    let Some(row) = db.backend().get_conversation(cid).unwrap() else {
        return Vec::new();
    };
    let mls = db.openmls_provider().unwrap();
    let Some(group) = MlsGroup::load(mls.storage(), &GroupId::from_slice(&row.group_id)).unwrap()
    else {
        return Vec::new();
    };
    let mut leaves: Vec<_> = group
        .members()
        .map(|member| {
            let identity = member.credential.serialized_content().to_vec();
            (String::from_utf8(identity).unwrap(), member.encryption_key)
        })
        .collect();
    leaves.sort();
    leaves
}

fn identities(leaves: &[(String, Vec<u8>)]) -> Vec<String> {
    leaves
        .iter()
        .map(|(identity, _)| identity.clone())
        .collect()
}

/// `bytes` (a `{"$bytes": ...}` view) as a signed body carries them: base64.
fn signed_bytes(bytes: &Value) -> Value {
    json!(STANDARD.encode(chat_wire::json_bytes(bytes).unwrap()))
}

/// The verified rosters `member` holds of `cids`.
async fn rosters(member: &mut Member, cids: &[String]) -> Vec<Option<Value>> {
    member
        .read(|db| cids.iter().map(|cid| roster(db, cid)).collect())
        .await
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

fn credential(did: &str, device: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(format!("{did}#{device}").into_bytes()).into(),
        signature_key: signer.public().into(),
    }
}

/// The group configuration `createGroup` uses.
fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(capabilities())
        .use_ratchet_tree_extension(true)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(5)
        .sender_ratchet_configuration(
            catbird_mls::GroupConfig::default().sender_ratchet_configuration(),
        )
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(5)
        .sender_ratchet_configuration(
            catbird_mls::GroupConfig::default().sender_ratchet_configuration(),
        )
        .build()
}

/// The coordinate naming `group`'s MLS state as `cid` at `generation` and `state_version`.
fn coordinate_of(
    group: &MlsGroup,
    provider: &Provider,
    cid: &str,
    generation: i64,
    state_version: i64,
) -> Value {
    let (hash, tag) = chat_wire::compute_group_context_hash_and_tag(group, provider).unwrap();
    json!({
        "conversationId": cid, "generation": generation, "stateVersion": state_version,
        "groupId": { "$bytes": STANDARD.encode(group.group_id().as_slice()) },
        "epoch": group.epoch().as_u64(),
        "groupContextHash": { "$bytes": STANDARD.encode(hash) },
        "confirmationTag": { "$bytes": STANDARD.encode(tag) },
        "lifecycle": "active",
    })
}

async fn open(did: &str, device: &str) -> WasmMlsClient {
    let client = WasmMlsClient::open_async(
        did.into(),
        device.into(),
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

/// An enrolled web device of `did`, with the signer its enrollment stored.
struct Member {
    did: String,
    device: &'static str,
    client: WasmMlsClient,
    signer: SignatureKeyPair,
}

impl Member {
    async fn enrolled(did: &str, device: &'static str) -> Self {
        let client = open(did, device).await;
        let scopes = serde_wasm_bindgen::to_value(&REQUIRED_LABYRINTH_OAUTH_SCOPES).unwrap();
        client.enroll_device(true, scopes).await.unwrap();
        drop(client);
        let raw = account_db(did)
            .backend()
            .get_labyrinth_state("device_signer_json")
            .unwrap()
            .expect("enrolled signer");
        Self {
            did: did.into(),
            device,
            client: open(did, device).await,
            signer: serde_json::from_slice(&raw).unwrap(),
        }
    }

    async fn sync(&self) -> Result<u32, String> {
        self.client
            .sync()
            .await
            .map_err(|error| error.as_string().unwrap_or_default())
    }

    /// `read` of this account's database, its client closed meanwhile.
    async fn read<T>(&mut self, read: impl FnOnce(&Db) -> T) -> T {
        self.client.close();
        let out = read(&account_db(&self.did));
        self.client = open(&self.did, self.device).await;
        out
    }

    fn row(&self, cid: &str) -> Option<ConversationRow> {
        serde_wasm_bindgen::from_value::<Vec<ConversationRow>>(
            self.client.list_conversations(None, 50).unwrap(),
        )
        .unwrap()
        .into_iter()
        .find(|row| row.conversation_id == cid)
    }

    /// What a refused entry leaves as it was: the conversation row, its coordinates, verified
    /// roster and MLS leaves, and this device's acknowledgement.
    async fn snapshot(&mut self, cid: &str) -> Snapshot {
        let (row, coordinates, roster, leaves) = self
            .read(|db| {
                (
                    db.backend().get_conversation(cid).unwrap(),
                    coordinates(db, cid),
                    roster(db, cid),
                    leaves(db, cid),
                )
            })
            .await;
        (
            row,
            coordinates,
            roster,
            leaves,
            ackedUpTo(cid, self.device),
        )
    }
}

type Snapshot = (
    Option<ConversationRow>,
    Option<Value>,
    Option<Value>,
    Vec<(String, Vec<u8>)>,
    u32,
);

/// A device outside any client: its key registered on its account's PDS, the private keys of its
/// KeyPackages and groups in its own `provider`.
struct Device {
    did: String,
    id: &'static str,
    signer: SignatureKeyPair,
    provider: Provider,
}

impl Device {
    fn new(did: &str, id: &'static str) -> Self {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let record = chat_wire::build_pds_device_put_record_body(did, id, signer.public()).unwrap();
        let (status, _) = post_json(
            "com.atproto.repo.putRecord",
            std::str::from_utf8(&record).unwrap(),
        );
        assert_eq!(status, 200);
        Self {
            did: did.into(),
            id,
            signer,
            provider: Provider::new().unwrap(),
        }
    }

    fn leaf(&self) -> String {
        format!("{}#{}", self.did, self.id)
    }

    fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                credential(&self.did, self.id, &self.signer),
            )
            .unwrap()
            .key_package()
            .clone()
    }

    /// A fresh KeyPackage of this device enrolled with mls-ds, as mls-ds stores it.
    fn enroll_key_package(&self) -> Value {
        let package = self.key_package();
        let bytes = MlsMessageOut::from(package.clone())
            .tls_serialize_detached()
            .unwrap();
        let reference = package.hash_ref(self.provider.crypto()).unwrap();
        let view = json!({
            "framing": "mlsMessage", "contentType": "keyPackage",
            "bytes": { "$bytes": STANDARD.encode(&bytes) },
            "sha256": STANDARD.encode(Sha256::digest(&bytes)),
            "keyPackageRef": { "$bytes": STANDARD.encode(reference.as_slice()) },
        });
        addKeyPackages(self.id, &json!([view]).to_string());
        view
    }

    /// This device's signed `requestLeafRecovery` body of `kind` in `cid`, bound to `prior`.
    fn request_body(&self, cid: &str, prior: &Value, kind: &str, request_id: &str) -> Value {
        chat_wire::leaf_recovery_request_body(
            request_id,
            &self.did,
            self.id,
            &derive_key_id(self.signer.public()),
            1,
            &canonical(prior, cid),
            kind,
            &chat_wire::now_rfc3339_millis(),
        )
        .unwrap()
    }

    /// This device's `requestLeafRecovery` of `kind`, signed at `cid`'s current coordinate as
    /// mls-ds presents it, on a freshly enrolled KeyPackage: mls-ds's view of the request.
    fn request_recovery(&self, cid: &str, kind: &str) -> Value {
        self.enroll_key_package();
        let body = self.request_body(cid, &state(cid)["coordinates"], kind, &new_id());
        submit(CanonicalOperation::RequestLeafRecovery, body, &self.signer)["recovery"].take()
    }

    /// `welcome` staged with this device's KeyPackages: the joined group, the roster attestation
    /// its GroupInfo carries and the identity of the leaf that signed that GroupInfo.
    fn join(&self, welcome: &[u8]) -> (MlsGroup, Option<Vec<u8>>, Vec<u8>) {
        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(welcome)
            .unwrap()
            .extract()
        else {
            panic!("expected a Welcome");
        };
        let builder =
            StagedWelcome::build_from_welcome(&self.provider, &join_config(), welcome).unwrap();
        let attestation = builder
            .processed_welcome()
            .unverified_group_info()
            .extensions()
            .unknown(chat_wire::ROSTER_ATTESTATION_EXTENSION_TYPE)
            .map(|extension| extension.0.clone());
        let staged = builder.build().unwrap();
        let sender = staged
            .welcome_sender()
            .unwrap()
            .credential()
            .serialized_content()
            .to_vec();
        (
            staged.into_group(&self.provider).unwrap(),
            attestation,
            sender,
        )
    }

    /// A fresh group of this device alone.
    fn create_group(&self) -> MlsGroup {
        let group_id = [
            uuid::Uuid::new_v4().into_bytes(),
            uuid::Uuid::new_v4().into_bytes(),
        ]
        .concat();
        MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &create_config(),
            GroupId::from_slice(&group_id),
            credential(&self.did, self.id, &self.signer),
        )
        .unwrap()
    }

    /// This device's Commit adding `adds` to its `group` (`cid` at `generation`, `prior_version`),
    /// its GroupInfo carrying `attestation`, merged; and `fulfiller`'s signed
    /// `leafRecoveryFulfillmentBody` of it, recovering `target` (`(did, device)`) on the reserved
    /// KeyPackage `reserved` under request `request_id`, with a metadata snapshot of the new
    /// epoch. mls-ds sequences it and delivers its Welcome to `target`. Returns its `next`.
    #[allow(clippy::too_many_arguments)]
    fn fulfill(
        &self,
        group: &mut MlsGroup,
        fulfiller: &Device,
        cid: &str,
        generation: i64,
        prior_version: i64,
        adds: Vec<KeyPackage>,
        attestation: Option<Extension>,
        request_id: &str,
        target: (&str, &str),
        reserved: &Value,
    ) -> Value {
        let provider = &self.provider;
        let prior = coordinate_of(group, provider, cid, generation, prior_version);
        let convo_uuid = uuid::Uuid::parse_str(cid).unwrap();
        let transition = uuid::Uuid::new_v4();
        let aad = json!({
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(convo_uuid.as_bytes()),
            "generation": generation,
            "transitionId": STANDARD.encode(transition.as_bytes()),
            "prior": chat_wire::build_aad_prior_coordinate(
                &convo_uuid,
                group.group_id().as_slice(),
                generation,
                prior_version,
                group.epoch().as_u64() as i64,
                &chat_wire::json_bytes(&prior["groupContextHash"]).unwrap(),
                &chat_wire::json_bytes(&prior["confirmationTag"]).unwrap(),
            ),
        });
        group.set_aad(canonical_commit_aad_bytes(&aad).unwrap());
        let mut builder = group
            .commit_builder()
            .propose_adds(adds)
            .force_self_update(true)
            .load_psks(provider.storage())
            .unwrap();
        if let Some(attestation) = attestation {
            builder = builder
                .create_group_info_with_extensions([attestation])
                .unwrap();
        }
        let bundle = builder
            .build(provider.rand(), provider.crypto(), &self.signer, |_| true)
            .unwrap()
            .stage_commit(provider)
            .unwrap();
        let welcome = bundle
            .to_welcome_msg()
            .unwrap()
            .tls_serialize_detached()
            .unwrap();
        let commit = bundle.into_commit().tls_serialize_detached().unwrap();
        group.merge_pending_commit(provider).unwrap();
        group.set_aad(Vec::new());
        let next = coordinate_of(group, provider, cid, generation, prior_version + 1);
        let group_id = group.group_id().as_slice().to_vec();
        let epoch = group.epoch().as_u64();
        let metadata_key = derive_metadata_key_from_group(
            group,
            provider.crypto(),
            provider.storage(),
            &group_id,
            epoch,
        )
        .unwrap();
        let snapshot = chat_wire::build_encrypted_metadata_snapshot_json(
            &metadata_key,
            &group_id,
            &convo_uuid,
            generation,
            epoch,
            &chat_wire::json_bytes(&next["groupContextHash"]).unwrap(),
            &chat_wire::json_bytes(&next["confirmationTag"]).unwrap(),
            &transition.to_string(),
            1,
            1,
            &fulfiller.did,
            fulfiller.id,
            1,
            fulfiller.signer.public(),
            "Recovered",
            "",
            None,
        )
        .unwrap();
        let (target_did, target_device) = target;
        let reference = &reserved["keyPackageRef"];
        let body = json!({
            "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
            "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0",
            "transitionId": transition.to_string(), "idempotencyKey": transition.to_string(),
            "recoveryRequestId": request_id, "actorDid": fulfiller.did,
            "actorDeviceId": fulfiller.id, "authGeneration": 1,
            "signedAt": chat_wire::now_rfc3339_millis(),
            "prior": prior, "next": next, "aad": aad,
            "manifest": {
                "participantChanges": [],
                "leafChanges": [{
                    "$type": "blue.catbird.chat.defs#addLeafByRecovery", "userDid": target_did,
                    "deviceId": target_device, "recoveryRequestId": request_id,
                    "keyPackageRef": reference,
                }],
                "leafRecoveryRequestId": request_id,
                "welcomeBundle": {
                    "welcomeId": new_id(), "framing": "mlsMessage", "contentType": "welcome",
                    "opaqueWelcome": { "$bytes": STANDARD.encode(&welcome) },
                    "sha256": STANDARD.encode(Sha256::digest(&welcome)),
                    "deliveries": [{
                        "recipientDid": target_did, "recipientDeviceId": target_device,
                        "provenance": { "recoveryRequestId": request_id, "keyPackageRef": reference },
                    }],
                },
            },
            "commit": {
                "framing": "mlsMessage", "contentType": "publicMessageCommit",
                "bytes": { "$bytes": STANDARD.encode(&commit) },
                "sha256": STANDARD.encode(Sha256::digest(&commit)),
            },
            "metadataSnapshot": snapshot,
        });
        submit(
            CanonicalOperation::SubmitTransition,
            body,
            &fulfiller.signer,
        );
        next
    }
}

/// The reserved KeyPackage mls-ds stores as `reserved`, validated.
fn validated(reserved: &Value, provider: &Provider) -> KeyPackage {
    let MlsMessageBodyIn::KeyPackage(package) =
        MlsMessageIn::tls_deserialize_exact(chat_wire::json_bytes(&reserved["bytes"]).unwrap())
            .unwrap()
            .extract()
    else {
        panic!("expected a KeyPackage");
    };
    package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap()
}

/// A reset activation of `prior`'s conversation by the device `(did, device)`, retiring `prior`
/// and opening `successor` with mls-ds's `participants` and its actor's leaf: the signed request.
fn activation(
    signer: &SignatureKeyPair,
    (did, device): (&str, &str),
    prior: &Value,
    successor: &Value,
    participants: &Value,
) -> Value {
    let cid = prior["conversationId"].as_str().unwrap();
    let mut retired = prior.clone();
    retired["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap() + 1);
    retired["lifecycle"] = json!("superseded");
    let (transition, ciphertext, group_info) = (new_id(), [0x63_u8; 48], [0x64_u8; 64]);
    let key = signer.public();
    let body = json!({
        "$type": "blue.catbird.chat.defs#resetActivationBody",
        "signatureDomain": "CATBIRD-CHAT-RESET-ACTIVATE\0",
        "resetRequestId": new_id(), "transitionId": transition, "idempotencyKey": transition,
        "actorDid": did, "actorDeviceId": device, "conversationKind": "group", "authGeneration": 1,
        "prior": prior, "retired": retired, "successor": successor,
        "manifest": {
            "participants": participants,
            "actorLeaf": { "userDid": did, "deviceId": device, "leafOrigin": "genesis" },
        },
        "genesisGroupInfo": {
            "framing": "mlsMessage", "contentType": "groupInfo",
            "bytes": { "$bytes": STANDARD.encode(group_info) },
            "sha256": STANDARD.encode(Sha256::digest(group_info)),
        },
        "metadataSnapshot": {
            "authorProof": {
                "authGenerationAtOrigin": 1, "authorDeviceId": device, "authorDid": did,
                "authorKeyId": derive_key_id(key), "deviceStatusAtOrigin": "active",
                "originSeq": 1, "originTransitionId": transition, "roleAtOrigin": "admin",
                "signaturePublicKey": { "$bytes": STANDARD.encode(key) },
            },
            "ciphertext": { "$bytes": STANDARD.encode(ciphertext) },
            "ciphertextSha256": STANDARD.encode(Sha256::digest(ciphertext)),
            "ciphertextSize": ciphertext.len(),
            "coordinate": {
                "conversationId": STANDARD.encode(uuid::Uuid::parse_str(cid).unwrap().as_bytes()),
                "generation": successor["generation"], "epoch": 0,
                "groupId": successor["groupId"],
                "groupContextHash": successor["groupContextHash"],
                "confirmationTag": successor["confirmationTag"],
            },
            "metadataVersion": 2, "nonce": { "$bytes": STANDARD.encode([0x65_u8; 12]) },
            "originTransitionId": transition,
        },
        "signedAt": "2026-11-07T00:00:00.000Z",
    });
    signed(CanonicalOperation::ActivateReset, body, signer)
}

/// A successor of `prior` on a fresh group no device holds.
fn unheld_successor(prior: &Value) -> Value {
    let bytes = |byte: u8| json!({ "$bytes": STANDARD.encode([byte; 32]) });
    json!({
        "conversationId": prior["conversationId"],
        "generation": prior["generation"].as_i64().unwrap() + 1, "stateVersion": 0,
        "groupId": bytes(0x5a), "epoch": 0, "groupContextHash": bytes(0x61),
        "confirmationTag": bytes(0x62), "lifecycle": "active",
    })
}

/// Alice creates `cid` inviting Bob; Bob accepts from his inventory; Alice's sync fulfills the add
/// his acceptance requested, attesting her verified roster; Bob joins from that Welcome holding it.
async fn group_with(alice: &str, bob: &str, cid: &str) -> (Member, Member) {
    let mut alice = Member::enrolled(alice, ALICE_DEVICE).await;
    let mut bob = Member::enrolled(bob, BOB_DEVICE).await;
    create(&alice, cid, &bob.did).await;
    bob.sync().await.expect("bob accepts");
    alice.sync().await.expect("alice adds bob");
    bob.sync().await.expect("bob joins");
    assert!(bob.row(cid).is_some(), "bob joined from alice's Welcome");
    assert_eq!(
        requestsJson(BOB_DEVICE),
        "[]",
        "his acceptance opened his request, and a pending Welcome requests nothing"
    );
    let expected = roster_of(&[
        (&alice.did, "admin", "active"),
        (&bob.did, "member", "active"),
    ]);
    assert_eq!(
        alice.read(|db| roster(db, cid)).await,
        Some(expected.clone())
    );
    assert_eq!(
        bob.read(|db| roster(db, cid)).await,
        Some(expected),
        "the Welcome attests alice's roster"
    );
    (alice, bob)
}

/// `alice` creates the group `cid`, inviting `bob`.
async fn create(alice: &Member, cid: &str, bob: &str) {
    alice
        .client
        .create_group(
            cid.into(),
            SEQUENCER.into(),
            serde_wasm_bindgen::to_value(&[bob]).unwrap(),
            Some("Recovery".into()),
            Some(String::new()),
        )
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn group_creation_lost_response_replays_after_reopen() {
    let _restore = install_ds();
    let (alice_did, bob_did) = (did("resumecreatealice"), did("resumecreatebob"));
    let mut alice = Member::enrolled(&alice_did, ALICE_DEVICE).await;
    let bob = Member::enrolled(&bob_did, BOB_DEVICE).await;
    let cid = "00000000-0000-4000-8000-00000000c297";
    loseNextCreateResponse();
    alice
        .client
        .create_group(
            cid.into(),
            SEQUENCER.into(),
            serde_wasm_bindgen::to_value(&[&bob_did]).unwrap(),
            Some("Resumable genesis".into()),
            None,
        )
        .await
        .expect_err("the committed response is lost");
    assert!(alice.row(cid).is_none());

    alice.client.close();
    alice.client = open(&alice.did, alice.device).await;
    alice
        .sync()
        .await
        .expect("sync replays the creation journal");
    let calls: Vec<String> = serde_json::from_str(&createCallsJson()).unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1], "creation replay changed bytes");
    assert_eq!(conversationCount(), 1);
    let snapshot = alice.snapshot(cid).await;
    let row = snapshot.0.expect("creator conversation");
    let server = state(cid)["coordinates"].clone();
    assert_eq!(
        row.group_id,
        chat_wire::json_bytes(&server["groupId"]).unwrap()
    );
    assert_eq!(row.epoch, 0);
    assert_eq!(snapshot.1, Some(canonical(&server, cid)));
    assert_eq!(
        identities(&snapshot.3),
        [format!("{alice_did}#{ALICE_DEVICE}")]
    );
    alice
        .client
        .create_group(
            cid.into(),
            SEQUENCER.into(),
            serde_wasm_bindgen::to_value(&[&bob_did]).unwrap(),
            Some("Resumable genesis".into()),
            None,
        )
        .await
        .expect("a completed logical retry returns the existing group");
    let completed_calls: Vec<String> = serde_json::from_str(&createCallsJson()).unwrap();
    assert_eq!(
        completed_calls.len(),
        2,
        "completed retry sent a new create"
    );

    bob.sync().await.expect("invitee accepts");
    alice.sync().await.expect("creator fulfills recovery");
    bob.sync().await.expect("invitee joins");
    let message_id = new_id();
    alice
        .client
        .send_message(cid.into(), message_id.clone(), "resumed genesis".into())
        .await
        .expect("creator sends");
    bob.sync().await.expect("invitee decrypts");
    let messages: Vec<MessageRow> =
        serde_wasm_bindgen::from_value(bob.client.list_messages(cid.into(), None, 20).unwrap())
            .unwrap();
    assert!(messages.iter().any(|message| {
        message.message_id == message_id && message.plaintext_json.contains("resumed genesis")
    }));
}

/// A delivery service cannot make a member add a device. Alice creates a group whose only leaf
/// is hers (Bob, invited, never accepts). mls-ds lists, one at a time, in her conversation state
/// and her own recovery inbox alike: her second device's add request without its signature; a
/// stranger's validly signed add; that device's request signed at another coordinate. None is
/// work. Then the genuine signed request with a signature that no longer verifies, or presented
/// under another request ID, kind, device, key ID, auth generation or coordinate, or reserving
/// another device's KeyPackage: each fails Alice's sync of that conversation. After every one
/// Alice has submitted nothing and her leaves, epoch, coordinates, roster, cursor and
/// acknowledgement are unchanged. The genuine request then adds her second device, once.
///
/// Fail-before (web `7be78145`): `fulfill_leaf_recovery_inbox` (`wasm_client_sync.rs`) Committed
/// every request `getLeafRecoveryInbox` listed whose KeyPackage was its account's own, so the
/// unsigned request added the device on Alice's first sync.
#[wasm_bindgen_test]
async fn malicious_ds_signed_recovery_views_never_add_a_device() {
    let _restore = install_ds();
    let (alice, bob, carol) = (
        did("rogueviewalice"),
        did("rogueviewbob"),
        did("rogueviewcarol"),
    );
    let cid = "00000000-0000-4000-8000-00000000f001";
    let mut alice = Member::enrolled(&alice, ALICE_DEVICE).await;
    let _bob = Member::enrolled(&bob, BOB_DEVICE).await;
    create(&alice, cid, &bob).await;
    let alice2 = Device::new(&alice.did, ALICE2_DEVICE);
    let stranger = Device::new(&carol, CAROL_DEVICE);
    let genuine = alice2.request_recovery(cid, "add");
    assert_eq!(genuine["status"], "open", "{genuine}");
    let strangers = stranger.request_recovery(cid, "add");
    let carol_package = stranger.enroll_key_package();
    let current = state(cid)["coordinates"].clone();
    let mut other_coordinate = current.clone();
    other_coordinate["stateVersion"] = json!(current["stateVersion"].as_i64().unwrap() + 1);

    let (before, before_count) = (alice.snapshot(cid).await, fulfillments(ALICE_DEVICE).len());
    assert_eq!(
        identities(&before.3),
        [format!("{}#{ALICE_DEVICE}", alice.did)]
    );
    let edited = |edit: &dyn Fn(&mut Value)| {
        let mut view = genuine.clone();
        edit(&mut view);
        view
    };
    let serve = |view: &Value| serveRecoveries(cid, ALICE_DEVICE, &json!([view]).to_string());

    let request_id = genuine["recoveryRequestId"].as_str().unwrap();
    let elsewhere = signed(
        CanonicalOperation::RequestLeafRecovery,
        alice2.request_body(cid, &other_coordinate, "add", request_id),
        &alice2.signer,
    );
    for (case, view) in [
        (
            "an unsigned request",
            edited(&|view| {
                view.as_object_mut().unwrap().remove("signedRequest");
            }),
        ),
        ("a stranger's signed add", strangers),
        (
            "a request signed at another coordinate",
            edited(&|view| view["signedRequest"] = elsewhere.clone()),
        ),
    ] {
        serve(&view);
        alice
            .sync()
            .await
            .unwrap_or_else(|error| panic!("{case} is no work: {error}"));
        assert_eq!(
            (alice.snapshot(cid).await, fulfillments(ALICE_DEVICE).len()),
            (before.clone(), before_count),
            "{case}"
        );
    }

    let carol_key_id = derive_key_id(stranger.signer.public());
    let refused = [
        (
            "a signature that does not verify",
            edited(&|view| {
                view["signedRequest"]["body"]["signedAt"] = json!("2026-11-07T00:00:00.000Z")
            }),
            "verify signed transition",
        ),
        (
            "another request ID",
            edited(&|view| view["recoveryRequestId"] = json!(new_id())),
            "not the authorized request",
        ),
        (
            "another kind",
            edited(&|view| view["recoveryKind"] = json!("replace")),
            "not the authorized request",
        ),
        (
            "another device",
            edited(&|view| {
                view["requesterDid"] = json!(carol);
                view["requesterDeviceId"] = json!(CAROL_DEVICE);
                view["reservation"]["requesterDid"] = json!(carol);
                view["reservation"]["requesterDeviceId"] = json!(CAROL_DEVICE);
            }),
            "verify signed transition",
        ),
        (
            "another key ID",
            edited(&|view| view["reservation"]["requesterKeyId"] = json!(carol_key_id)),
            "not the authorized request",
        ),
        (
            "another auth generation",
            edited(&|view| view["reservation"]["requesterAuthGeneration"] = json!(2)),
            "not the authorized request",
        ),
        (
            "another coordinate",
            edited(&|view| view["boundCoordinate"] = other_coordinate.clone()),
            "not bound to the current coordinate",
        ),
        (
            "another device's KeyPackage",
            edited(&|view| {
                view["reservation"]["keyPackage"] = carol_package.clone();
                view["reservation"]["keyPackageRef"] = carol_package["keyPackageRef"].clone();
            }),
            "not the authorized device's own",
        ),
    ];
    for (case, view, reason) in refused {
        serve(&view);
        let error = alice.sync().await.expect_err(case);
        assert!(
            error.contains(&format!("conversation {cid}: ")) && error.contains(reason),
            "{case}: {error}"
        );
        assert_eq!(
            (alice.snapshot(cid).await, fulfillments(ALICE_DEVICE).len()),
            (before.clone(), before_count),
            "{case}"
        );
    }

    serve(&genuine);
    alice.sync().await.expect("the genuine signed request");
    let added = fulfillments(ALICE_DEVICE);
    assert_eq!(added.len(), before_count + 1, "one fulfillment");
    assert_eq!(added[0]["recoveryRequestId"], genuine["recoveryRequestId"]);
    let (row, _, _, leaves, _) = alice.snapshot(cid).await;
    assert_eq!(row.unwrap().epoch, before.0.as_ref().unwrap().epoch + 1);
    assert!(identities(&leaves).contains(&alice2.leaf()));
}

/// An existing member's new device joins from its own signed request, once. Bob, a joined member,
/// has a second device (outside any client: this browser holds one database per account), which
/// signs an add request. Alice's sync fulfills it with exactly one Add whose Welcome's GroupInfo,
/// signed by her leaf, attests her verified roster; the new device joins from it, holding Alice's
/// leaves, and Bob's client applies the Add. mls-ds then lists the consumed request again, as first
/// listed and rebound to the current coordinate: Alice adds nothing.
///
/// Fail-before (web `7be78145`): setup fails, Bob never joins: `fulfill_leaf_recovery_inbox`
/// (`wasm_client_sync.rs`) fulfilled only what `getLeafRecoveryInbox` listed (nothing here), never
/// an accepted invitation nor a signed request, and attached no roster to any Welcome.
#[wasm_bindgen_test]
async fn existing_members_new_device_is_added_from_its_signed_request() {
    let _restore = install_ds();
    let cid = "00000000-0000-4000-8000-00000000f002";
    let (mut alice, mut bob) = group_with(&did("newdevicealice"), &did("newdevicebob"), cid).await;
    let alice_roster = alice.read(|db| roster(db, cid)).await.unwrap();
    let bob2 = Device::new(&bob.did, BOB2_DEVICE);
    let request = bob2.request_recovery(cid, "add");
    assert_eq!(request["status"], "open", "{request}");
    let earlier = fulfillments(ALICE_DEVICE).len();

    alice.sync().await.expect("alice adds bob's new device");
    let added = fulfillments(ALICE_DEVICE);
    assert_eq!(added.len(), earlier + 1, "exactly one fulfillment");
    let added = added.last().unwrap();
    assert_eq!(added["recoveryRequestId"], request["recoveryRequestId"]);
    assert_eq!(
        added["manifest"]["leafChanges"],
        json!([{
            "$type": "blue.catbird.chat.defs#addLeafByRecovery",
            "userDid": bob.did, "deviceId": BOB2_DEVICE,
            "recoveryRequestId": request["recoveryRequestId"],
            "keyPackageRef": signed_bytes(&request["reservation"]["keyPackageRef"]),
        }])
    );
    let alice_leaves = alice.read(|db| leaves(db, cid)).await;
    assert!(identities(&alice_leaves).contains(&bob2.leaf()));

    let (group, attestation, sender) = bob2.join(&last_welcome(BOB2_DEVICE));
    assert_eq!(sender, format!("{}#{ALICE_DEVICE}", alice.did).into_bytes());
    let leaf_dids = [alice.did.clone(), bob.did.clone()];
    assert_eq!(
        chat_wire::attested_roster(&attestation.unwrap(), cid, 0, &bob.did, &leaf_dids).unwrap(),
        alice_roster,
        "the Welcome attests alice's roster"
    );
    let mut joined: Vec<String> = group
        .members()
        .map(|member| String::from_utf8(member.credential.serialized_content().to_vec()).unwrap())
        .collect();
    joined.sort();
    assert_eq!(joined, identities(&alice_leaves));
    bob.sync().await.expect("bob applies the add");
    assert_eq!(bob.read(|db| leaves(db, cid)).await, alice_leaves);

    let epoch = alice.row(cid).unwrap().epoch;
    let mut rebound = request.clone();
    rebound["boundCoordinate"] = state(cid)["coordinates"].clone();
    rebound["reservation"]["boundCoordinate"] = rebound["boundCoordinate"].clone();
    for (case, view) in [("as first listed", request), ("rebound", rebound)] {
        serveRecoveries(cid, ALICE_DEVICE, &json!([view]).to_string());
        alice
            .sync()
            .await
            .unwrap_or_else(|error| panic!("{case}: a consumed request is no work: {error}"));
        assert_eq!(
            (
                fulfillments(ALICE_DEVICE).len(),
                alice.row(cid).unwrap().epoch
            ),
            (earlier + 1, epoch),
            "{case}"
        );
    }
}

/// A `replace` re-adds exactly the requester device's current leaf from another leaf-holding
/// device (either another account or an active sibling device `device != own_device`), while a
/// device never fulfills its own `replace`. Bob's second device (outside any client) joins from
/// its signed add; then it signs a replace. Alice fulfills it with one Commit that removes
/// exactly that leaf and adds its new KeyPackage (`removeLeaf`, then `addLeafByRecovery`): every
/// identity stays and, besides the committer's own, only that leaf is new. Bob's client processes
/// the Commit to Alice's leaves, and `bob2` rejoins from its Welcome. A subsequent `bob2` replace
/// is likewise fulfilled by Bob's sibling client (`BOB_DEVICE != BOB2_DEVICE`), whereas a
/// self-replace signed by `BOB_DEVICE` itself is left unfulfilled by `bob.sync()`.
///
/// Fail-before (web `7be78145`): setup fails, Bob never joins: `fulfill_leaf_recovery_inbox`
/// (`wasm_client_sync.rs`) fulfilled only what `getLeafRecoveryInbox` listed and only as an Add,
/// never an accepted invitation nor a signed `replace`.
#[wasm_bindgen_test]
async fn signed_replace_readds_the_exact_leaf() {
    let _restore = install_ds();
    let cid = "00000000-0000-4000-8000-00000000f003";
    let (mut alice, mut bob) = group_with(&did("replacealice"), &did("replacebob"), cid).await;
    let mut bob2 = Device::new(&bob.did, BOB2_DEVICE);
    bob2.request_recovery(cid, "add");
    alice.sync().await.expect("alice adds bob's second device");
    bob.sync().await.expect("bob applies the add");

    let request = bob2.request_recovery(cid, "replace");
    assert_eq!(
        (&request["status"], &request["recoveryKind"]),
        (&json!("open"), &json!("replace")),
        "{request}"
    );

    let before = alice.read(|db| leaves(db, cid)).await;
    alice.sync().await.expect("alice replaces the leaf");
    let replace = fulfillments(ALICE_DEVICE).pop().unwrap();
    assert_eq!(replace["recoveryRequestId"], request["recoveryRequestId"]);
    assert_eq!(
        replace["manifest"]["leafChanges"],
        json!([
            {
                "$type": "blue.catbird.chat.defs#removeLeaf",
                "userDid": bob.did, "deviceId": BOB2_DEVICE,
            },
            {
                "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                "userDid": bob.did, "deviceId": BOB2_DEVICE,
                "recoveryRequestId": request["recoveryRequestId"],
                "keyPackageRef": signed_bytes(&request["reservation"]["keyPackageRef"]),
            },
        ])
    );
    let after = alice.read(|db| leaves(db, cid)).await;
    assert_eq!(identities(&after), identities(&before), "every leaf stays");
    let committer = format!("{}#{ALICE_DEVICE}", alice.did);
    for ((identity, old), (_, new)) in before.iter().zip(&after) {
        if *identity != committer {
            assert_eq!(old != new, *identity == bob2.leaf(), "{identity}");
        }
    }

    bob.sync().await.expect("bob processes the replace");
    assert_eq!(bob.read(|db| leaves(db, cid)).await, after);
    let (group, _, _) = bob2.join(&last_welcome(BOB2_DEVICE));
    let mut rejoined: Vec<String> = group
        .members()
        .map(|member| String::from_utf8(member.credential.serialized_content().to_vec()).unwrap())
        .collect();
    rejoined.sort();
    assert_eq!(rejoined, identities(&after));

    // Active sibling device (`BOB_DEVICE != BOB2_DEVICE`) holding a leaf also fulfills replace.
    bob2.provider = Provider::new().unwrap();
    let sibling_req = bob2.request_recovery(cid, "replace");
    bob.sync()
        .await
        .expect("sibling device holding a leaf fulfills same-account replace");
    let sibling_replace = fulfillments(BOB_DEVICE)
        .pop()
        .expect("bob's sibling fulfillment");
    assert_eq!(
        sibling_replace["recoveryRequestId"],
        sibling_req["recoveryRequestId"]
    );
    let after_sibling = bob.read(|db| leaves(db, cid)).await;
    alice.sync().await.expect("alice processes sibling replace");
    assert_eq!(alice.read(|db| leaves(db, cid)).await, after_sibling);
    let (sibling_group, _, _) = bob2.join(&last_welcome(BOB2_DEVICE));
    let mut sibling_rejoined: Vec<String> = sibling_group
        .members()
        .map(|member| String::from_utf8(member.credential.serialized_content().to_vec()).unwrap())
        .collect();
    sibling_rejoined.sort();
    assert_eq!(sibling_rejoined, identities(&after_sibling));

    // A device never fulfills its own `replace` (`device == own_device`).
    let self_body = chat_wire::leaf_recovery_request_body(
        &new_id(),
        &bob.did,
        BOB_DEVICE,
        &derive_key_id(bob.signer.public()),
        1,
        &canonical(&state(cid)["coordinates"], cid),
        "replace",
        &chat_wire::now_rfc3339_millis(),
    )
    .unwrap();
    let self_req = submit(
        CanonicalOperation::RequestLeafRecovery,
        self_body,
        &bob.signer,
    )["recovery"]
        .take();
    assert_eq!(
        (&self_req["status"], &self_req["recoveryKind"]),
        (&json!("open"), &json!("replace")),
        "{self_req}"
    );
    let entries_before_self = serde_json::from_str::<Vec<Value>>(&entriesJson(cid))
        .unwrap()
        .len();
    let bob_fulfillments_before = fulfillments(BOB_DEVICE).len();
    bob.sync()
        .await
        .expect("a device never fulfills its own replace");
    assert_eq!(fulfillments(BOB_DEVICE).len(), bob_fulfillments_before);
    assert_eq!(
        serde_json::from_str::<Vec<Value>>(&entriesJson(cid))
            .unwrap()
            .len(),
        entries_before_self
    );
}

/// A recovery joiner's verified roster comes only from the roster attestation in its Welcome's
/// GroupInfo, signed by exactly its verified fulfiller's leaf. Fulfillments of fresh
/// conversations built outside any client, each a Welcome Bob's client joins: with a valid
/// attestation by its fulfiller Carol it grants Carol's roster (and the snapshot's title); one
/// carrying none, one attesting a roster without the fulfiller's leaf, one attesting another
/// generation, and one whose GroupInfo Eve signed although Carol signed the fulfillment, grant
/// none, while the join still proceeds. No later sync, whatever participants mls-ds names in their
/// states, creates one.
///
/// Fail-before (web `7be78145`): `join_recovery_welcome` (`wasm_client_sync.rs`) joined every
/// one of them and recorded no roster from any Welcome, so Carol's attestation granted none.
#[wasm_bindgen_test]
async fn recovery_welcome_attests_the_roster() {
    let _restore = install_ds();
    let (bob, carol, eve) = (did("attestbob"), did("attestcarol"), did("attesteve"));
    let mut bob = Member::enrolled(&bob, BOB_DEVICE).await;
    let carol = Device::new(&carol, CAROL_DEVICE);
    let eve = Device::new(&eve, EVE_DEVICE);
    let carols = roster_of(&[
        (&bob.did, "member", "active"),
        (&carol.did, "admin", "active"),
    ]);
    let with_eve = roster_of(&[
        (&bob.did, "member", "active"),
        (&carol.did, "admin", "active"),
        (&eve.did, "member", "active"),
    ]);
    // Fulfillment of a fresh conversation, committed by `committer` and signed by Carol.
    let serve = |committer: &Device, attestation: &dyn Fn(&str) -> Option<Extension>| {
        let cid = new_id();
        let mut group = committer.create_group();
        let reserved: Value = serde_json::from_str(&takeKeyPackage(BOB_DEVICE)).unwrap();
        let mut adds = vec![validated(&reserved, &committer.provider)];
        if committer.id != carol.id {
            adds.push(carol.key_package());
        }
        let prior = coordinate_of(&group, &committer.provider, &cid, 0, 1);
        let mut participants = vec![
            json!({ "userDid": carol.did, "role": "admin", "status": "active" }),
            json!({ "userDid": bob.did, "role": "member", "status": "active" }),
        ];
        if committer.id != carol.id {
            participants
                .push(json!({ "userDid": committer.did, "role": "member", "status": "active" }));
        }
        openConversation(
            &cid,
            &json!({
                "coordinates": prior, "participants": participants,
                "leaves": [{ "userDid": committer.did, "deviceId": committer.id, "leafOrigin": "genesis" }],
            })
            .to_string(),
        );
        committer.fulfill(
            &mut group,
            &carol,
            &cid,
            0,
            1,
            adds,
            attestation(&cid),
            &new_id(),
            (&bob.did, BOB_DEVICE),
            &reserved,
        );
        cid
    };
    let valid = serve(&carol, &|cid| {
        Some(chat_wire::roster_attestation_extension(cid, 0, &carols).unwrap())
    });
    let refused = [
        ("no attestation", serve(&carol, &|_| None)),
        (
            "a roster without the fulfiller's leaf",
            serve(&carol, &|cid| {
                let bobs = roster_of(&[(&bob.did, "member", "active")]);
                Some(chat_wire::roster_attestation_extension(cid, 0, &bobs).unwrap())
            }),
        ),
        (
            "another generation",
            serve(&carol, &|cid| {
                Some(chat_wire::roster_attestation_extension(cid, 1, &carols).unwrap())
            }),
        ),
        (
            "a GroupInfo another member signed",
            serve(&eve, &|cid| {
                Some(chat_wire::roster_attestation_extension(cid, 0, &with_eve).unwrap())
            }),
        ),
    ];

    bob.sync().await.expect("bob joins every verified Welcome");
    let cids: Vec<String> = std::iter::once(valid.clone())
        .chain(refused.iter().map(|(_, cid)| cid.clone()))
        .collect();
    assert_eq!(bob.row(&valid).unwrap().title.as_deref(), Some("Recovered"));
    for (case, cid) in &refused {
        assert!(bob.row(cid).is_some(), "{case}: the join still proceeds");
    }
    let expected: Vec<Option<Value>> = std::iter::once(Some(carols.clone()))
        .chain(refused.iter().map(|_| None))
        .collect();
    assert_eq!(
        rosters(&mut bob, &cids).await,
        expected,
        "only carol's attestation"
    );

    bob.sync().await.expect("bob syncs his conversations");
    assert_eq!(
        rosters(&mut bob, &cids).await,
        expected,
        "no state view creates one"
    );
}

/// Policy and reset take effect only from an active admin by this device's verified roster,
/// checked before any effect. In a conversation Alice created and Bob joined (both holding Alice's
/// roster), member Bob's policy making himself admin, and his reset activation, each fail Alice's
/// sync `InsufficientPermissions`; with no verified roster, Bob's sync refuses even admin Alice's
/// reset `RosterUnverified`. None moves the row, coordinates, roster, MLS leaves, cursor or
/// acknowledgement.
///
/// Fail-before (web `7be78145`): setup fails, Bob never joins (`fulfill_leaf_recovery_inbox`
/// fulfilled only `getLeafRecoveryInbox` items); past it, `apply_conversation_entries` applied
/// any current leaf's policy, and `verify_control_entry` took a reset activation as cursor-only.
#[wasm_bindgen_test]
async fn non_admin_reset_and_policy_are_refused_before_any_effect() {
    let _restore = install_ds();
    let cid = "00000000-0000-4000-8000-00000000f005";
    let (mut alice, mut bob) = group_with(&did("adminalice"), &did("adminbob"), cid).await;
    let prior = state(cid)["coordinates"].clone();
    let participants = manifest_participants(cid);
    let mut next = prior.clone();
    next["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap() + 1);
    let transition = new_id();
    let escalation = json!({
        "$type": "blue.catbird.chat.defs#policyTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-POLICY\0",
        "transitionId": transition, "idempotencyKey": transition,
        "actorDid": bob.did, "actorDeviceId": BOB_DEVICE, "authGeneration": 1,
        "prior": prior, "next": next,
        "participantChanges": [{
            "$type": "blue.catbird.chat.defs#changeParticipantRole",
            "userDid": bob.did, "role": "admin",
        }],
        "signedAt": chat_wire::now_rfc3339_millis(),
    });
    let refused = [
        (
            "a member's role escalation",
            entry(
                "policyEntry",
                cid,
                signed(
                    CanonicalOperation::SubmitTransition,
                    escalation,
                    &bob.signer,
                ),
            ),
        ),
        (
            "a member's reset",
            entry(
                "resetActivationEntry",
                cid,
                activation(
                    &bob.signer,
                    (&bob.did, BOB_DEVICE),
                    &prior,
                    &unheld_successor(&prior),
                    &participants,
                ),
            ),
        ),
    ];
    for (case, entry) in refused {
        let before = alice.snapshot(cid).await;
        appendEntry(cid, &entry.to_string());
        let error = alice.sync().await.expect_err(case);
        assert!(
            error.contains(&format!("conversation {cid}: "))
                && error.contains(&format!("{} is not an active admin of {cid}", bob.did)),
            "{case}: {error}"
        );
        assert_eq!(alice.snapshot(cid).await, before, "{case}");
        dropLastEntry(cid);
    }

    bob.read(|db| {
        db.write_tx(|tx| tx.delete_account_meta(&chat_wire::conversation_roster_key(cid)))
            .unwrap()
    })
    .await;
    let before = bob.snapshot(cid).await;
    let admins = activation(
        &alice.signer,
        (&alice.did, ALICE_DEVICE),
        &prior,
        &unheld_successor(&prior),
        &participants,
    );
    appendEntry(cid, &entry("resetActivationEntry", cid, admins).to_string());
    let error = bob.sync().await.expect_err("no verified roster");
    assert!(
        error.contains(&format!("no verified roster for conversation {cid}")),
        "{error}"
    );
    assert_eq!(bob.snapshot(cid).await, before);
}

/// A device retired by a reset rejoins through its own signed request and a verified Welcome. In
/// Alice's conversation, which Bob joined holding her roster, Alice's second device (outside any
/// client: this client never activates a reset) resets to a successor group of its own. Bob's sync
/// verifies the activation against his roster, retires his leaf, takes the manifest's roster and,
/// reading nothing past the reset, signs one `add` bound to the successor; syncing again reads
/// and signs nothing. The activator fulfills that verified request, attesting the manifest's
/// roster; Bob's sync joins his existing conversation row from the Welcome, keeping his history,
/// at the fulfillment's signed coordinate with the attested roster. The activation replayed at a
/// later seq names a state Bob already left and fails his sync with nothing changed; his next
/// message decrypts in the activator's group.
///
/// Fail-before (web `7be78145`): setup fails, Bob never joins (`fulfill_leaf_recovery_inbox`
/// fulfilled only `getLeafRecoveryInbox` items); past it, `verify_control_entry` took the reset
/// activation as cursor-only, so Bob never retired, requested or rejoined.
#[wasm_bindgen_test]
async fn reset_retired_device_requests_and_rejoins_from_its_verified_welcome() {
    let _restore = install_ds();
    let cid = "00000000-0000-4000-8000-00000000f006";
    let (alice, mut bob) = group_with(&did("rejoinalice"), &did("rejoinbob"), cid).await;
    alice
        .client
        .send_message(cid.into(), new_id(), "before".into())
        .await
        .unwrap();
    bob.sync().await.expect("bob reads alice");
    let joined = bob.row(cid).unwrap();

    let activator = Device::new(&alice.did, ALICE2_DEVICE);
    let mut successor_group = activator.create_group();
    let generation = joined.generation + 1;
    let successor = coordinate_of(&successor_group, &activator.provider, cid, generation, 0);
    let manifest = manifest_participants(cid);
    let manifest_roster = chat_wire::roster_from_participants(&manifest).unwrap();
    let reset = activation(
        &activator.signer,
        (&alice.did, ALICE2_DEVICE),
        &state(cid)["coordinates"],
        &successor,
        &manifest,
    );
    let reset_seq = sequenceEntry(cid, &reset.to_string());
    // mls-ds serves Bob's reset-closed device nothing past the reset.
    readableUntil(BOB_DEVICE, reset_seq);
    let acked = ackedUpTo(cid, BOB_DEVICE);

    bob.sync().await.expect("bob retires and requests his add");
    let retired = bob.row(cid).unwrap();
    assert_eq!(
        (
            retired.generation,
            retired.group_id.as_slice(),
            retired.last_seq
        ),
        (
            generation,
            successor_group.group_id().as_slice(),
            i64::from(reset_seq)
        )
    );
    let (coords, held_roster, held) = bob
        .read(|db| (coordinates(db, cid), roster(db, cid), leaves(db, cid)))
        .await;
    assert_eq!(coords, Some(canonical(&successor, cid)));
    assert_eq!(
        held_roster,
        Some(manifest_roster.clone()),
        "the manifest's roster"
    );
    assert!(held.is_empty(), "bob holds no leaf");
    assert_eq!(
        ackedUpTo(cid, BOB_DEVICE),
        acked,
        "nothing acknowledged past the reset"
    );
    let requests =
        |device: &str| serde_json::from_str::<Vec<Value>>(&requestsJson(device)).unwrap();
    let requested = requests(BOB_DEVICE);
    assert_eq!(requested.len(), 1, "one request");
    assert_eq!(
        (
            &requested[0]["recoveryKind"],
            canonical(&requested[0]["prior"], cid)
        ),
        (&json!("add"), canonical(&successor, cid))
    );
    let reads = entryReads(cid, BOB_DEVICE);
    bob.sync()
        .await
        .expect("a retired row reads nothing past its reset");
    assert_eq!(bob.row(cid).unwrap(), retired);
    assert_eq!(requests(BOB_DEVICE).len(), 1, "no second request");
    assert_eq!(entryReads(cid, BOB_DEVICE), reads, "no entry read");

    let view = serde_json::from_str::<Vec<Value>>(&recoveriesJson(cid))
        .unwrap()
        .into_iter()
        .find(|view| view["requesterDeviceId"] == BOB_DEVICE && view["status"] == "open")
        .expect("bob's open request");
    let reserved = &view["reservation"]["keyPackage"];
    let next = activator.fulfill(
        &mut successor_group,
        &activator,
        cid,
        generation,
        0,
        vec![validated(reserved, &activator.provider)],
        Some(chat_wire::roster_attestation_extension(cid, generation, &manifest_roster).unwrap()),
        view["recoveryRequestId"].as_str().unwrap(),
        (&bob.did, BOB_DEVICE),
        reserved,
    );
    // The fulfillment opens Bob's next membership interval.
    readableAgain(BOB_DEVICE);
    bob.sync()
        .await
        .expect("bob rejoins from the verified Welcome");
    let rejoined = bob.row(cid).unwrap();
    assert_eq!(
        (
            rejoined.generation,
            rejoined.group_id.as_slice(),
            rejoined.epoch
        ),
        (generation, successor_group.group_id().as_slice(), 1)
    );
    let (coords, held_roster, held, own_request) = bob
        .read(|db| {
            (
                coordinates(db, cid),
                roster(db, cid),
                leaves(db, cid),
                db.backend()
                    .get_account_meta(&chat_wire::own_leaf_recovery_key(cid))
                    .unwrap(),
            )
        })
        .await;
    assert_eq!(coords, Some(canonical(&next, cid)));
    assert_eq!(held_roster, Some(manifest_roster), "the attested roster");
    let mut expected = vec![activator.leaf(), format!("{}#{BOB_DEVICE}", bob.did)];
    expected.sort();
    assert_eq!(identities(&held), expected);
    assert_eq!(own_request, None, "the fulfillment answered his request");
    let acks: Vec<Value> = serde_json::from_str(&welcomeAcks()).unwrap();
    assert_eq!(
        canonical(&acks.last().unwrap()["coordinates"], cid),
        canonical(&next, cid)
    );
    let history: Vec<MessageRow> =
        serde_wasm_bindgen::from_value(bob.client.list_messages(cid.into(), None, 50).unwrap())
            .unwrap();
    assert!(
        history
            .iter()
            .any(|row| row.plaintext_json.contains("before")),
        "bob keeps his history"
    );

    let before = bob.snapshot(cid).await;
    appendEntry(cid, &entry("resetActivationEntry", cid, reset).to_string());
    let error = bob.sync().await.expect_err("the replayed activation");
    assert!(
        error.contains("prior is not this device's current coordinate"),
        "{error}"
    );
    assert_eq!(bob.snapshot(cid).await, before);
    dropLastEntry(cid);

    bob.client
        .send_message(cid.into(), new_id(), "after the reset".into())
        .await
        .expect("bob sends in the successor generation");
    let sent = serde_json::from_str::<Vec<Value>>(&entriesJson(cid))
        .unwrap()
        .pop()
        .unwrap();
    let ciphertext =
        chat_wire::json_bytes(&sent["signedRequest"]["body"]["applicationMessage"]["bytes"])
            .unwrap();
    let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let ProcessedMessageContent::ApplicationMessage(plaintext) = successor_group
        .process_message(&activator.provider, message)
        .unwrap()
        .into_content()
    else {
        panic!("expected an application message");
    };
    let envelope: PrivateMessagePlaintextEnvelope =
        serde_json::from_slice(&plaintext.into_bytes()).unwrap();
    assert!(
        String::from_utf8(envelope.canonical_payload_bytes)
            .unwrap()
            .contains("after the reset"),
        "the activator decrypts bob's message"
    );
}

/// A device whose account is an active participant of a conversation it holds nothing of requests
/// its own leaf recovery, once per coordinate, once that pass's Welcomes are in. Bob accepts
/// Alice's invitation: the answer's recovery is his open request, so syncing again requests
/// nothing. Alice adds him, but his Welcome expires undelivered. Bob's sync, no Welcome pending,
/// signs one `replace` of the leaf mls-ds lists for his device, bound to the current coordinate;
/// syncing again requests nothing. Alice fulfills it from his verified signed request (removing
/// that leaf, adding his new KeyPackage, attesting her roster), and Bob's sync joins from its
/// Welcome, holding Alice's leaves and roster, and requests nothing more.
///
/// Fail-before (web `7be78145`): `sync_inventory_item` (`wasm_client_sync.rs`) never requested a
/// device's own recovery, so Bob never asked (and `fulfill_leaf_recovery_inbox` fulfilled only
/// what `getLeafRecoveryInbox` listed, so Alice never added him).
#[wasm_bindgen_test]
async fn a_device_without_its_conversation_requests_its_own_leaf_once() {
    let _restore = install_ds();
    let cid = "00000000-0000-4000-8000-00000000f007";
    let mut alice = Member::enrolled(&did("lostwelcomealice"), ALICE_DEVICE).await;
    let mut bob = Member::enrolled(&did("lostwelcomebob"), BOB_DEVICE).await;
    create(&alice, cid, &bob.did).await;
    let requests = || serde_json::from_str::<Vec<Value>>(&requestsJson(BOB_DEVICE)).unwrap();
    bob.sync().await.expect("bob accepts");
    bob.sync().await.expect("his acceptance opened his request");
    assert!(requests().is_empty(), "the acceptance's request is his own");
    alice.sync().await.expect("alice adds bob");
    loseWelcomes(BOB_DEVICE);

    bob.sync().await.expect("bob requests his own leaf");
    let requested = requests();
    assert_eq!(requested.len(), 1, "one request");
    assert_eq!(
        (
            &requested[0]["recoveryKind"],
            canonical(&requested[0]["prior"], cid)
        ),
        (
            &json!("replace"),
            canonical(&state(cid)["coordinates"], cid)
        )
    );
    bob.sync().await.expect("his request stays open");
    assert_eq!(requests().len(), 1, "no second request");
    assert!(bob.row(cid).is_none());

    alice.sync().await.expect("alice replaces bob's leaf");
    let replace = fulfillments(ALICE_DEVICE).pop().unwrap();
    assert_eq!(
        replace["recoveryRequestId"],
        requested[0]["recoveryRequestId"]
    );
    assert_eq!(
        replace["manifest"]["leafChanges"][0]["$type"],
        "blue.catbird.chat.defs#removeLeaf"
    );
    bob.sync()
        .await
        .expect("bob joins from the replace's Welcome");
    assert_eq!(requests().len(), 1, "a pending Welcome requests nothing");
    let alice_state = alice.read(|db| (leaves(db, cid), roster(db, cid))).await;
    assert_eq!(
        bob.read(|db| (leaves(db, cid), roster(db, cid))).await,
        alice_state
    );
}
