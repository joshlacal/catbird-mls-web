//! Seed 2323 and sync-verification regressions for `WasmMlsClient` over real encrypted OPFS. A
//! stateful fetch fixture applies the `mls-ds` send-order rule (an unresolved send is accepted
//! only if `(prior.generation, prior.epoch, sendCounter)` exceeds the device's last accepted send
//! in the conversation, otherwise `StaleSend`) and returns real `I13` ES256 receipts under a
//! rotatable `#mls-receipt-<n>` method. Alice and Bob are enrolled clients sharing one MLS group,
//! built in their account databases the way `createGroup` plus Bob's Welcome import leave it.
#![cfg(target_arch = "wasm32")]
use std::rc::Rc;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::canonical_transport::{derive_key_id, CanonicalOperation};
use catbird_mls::chat_v2::transcript::{
    decode_strict_json, project_signed_body, SignedMutationKind, SigningTranscript,
};
use catbird_mls::client::deletion_authority::{
    self as deletion_authority, UnverifiedAccountDeletion, UnverifiedDeletionReason,
};
use catbird_mls::client::{
    chat_wire, QueuedLabyrinthArchivePayload, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend as _};
use catbird_mls::storage::{ConversationRow, MessageRow};
use catbird_mls::MLSMessagePayload;
use catbird_mls_web::{SqliteConn, WasmMlsClient};
use labyrinth_protocol::receipt::{sign_sequencer_receipt, SequencerReceiptPayload};
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
let pdsRepo;
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
    sequencerReceipt: JSON.parse(receiptFor(JSON.stringify({body: b, seq, keyGeneration: ds.keyGeneration}))),
    receivedAt: new Date().toISOString()};
  ds.entries[cid].push(entry);
  ds.accepted[`${cid} ${b.messageId}`] = {text, response: {entry}};
  return [200, {entry}];
}
// A signed transition or acceptance is sequenced as the entry its body names, and its `next` is
// the conversation's state coordinate.
function transition(text, sequencerDid) {
  ds.transitions.push(text);
  const submitted = JSON.parse(text).signedRequest;
  const signedRequest = {...submitted, signature: {$bytes: bytes(submitted.signature)}};
  const b = signedRequest.body;
  const cid = (b.next || b.prior).conversationId;
  const seq = ++ds.seq[cid];
  const receiptInput = {
    body: b, seq, entryId: b.transitionId, control: true, keyGeneration: ds.keyGeneration};
  if (sequencerDid) receiptInput.sequencerDid = sequencerDid;
  const entry = {$type: `blue.catbird.chat.defs#${b.$type.split('#')[1].replace(/(Transition)?Body$/, 'Entry')}`,
    entryId: b.transitionId, conversationId: cid, seq, signedRequest, receivedAt: b.signedAt,
    sequencerReceipt: JSON.parse(receiptFor(JSON.stringify(receiptInput)))};
  ds.entries[cid].push(entry);
  if (b.next) ds.coords[cid] = b.next;
  return entry;
}
// mls-ds opens an acceptance's add recovery bound to its `next`, reserving one of the KeyPackages
// the accepting device enrolled with, lists it in `getConversationState` and answers with it.
function openRecovery(b) {
  const kp = (ds.kps[b.actorDeviceId] || []).shift();
  if (!kp) return undefined;
  const cid = b.next.conversationId;
  const ids = {conversationId: cid, recoveryRequestId: b.recoveryRequestId, boundCoordinate: b.next,
    requesterDid: b.actorDid, requesterDeviceId: b.actorDeviceId};
  const view = {$type: 'blue.catbird.chat.defs#leafRecoveryView', ...ids,
    recoveryKind: 'add', status: 'open', requestedAt: b.signedAt, expiresAt: '2099-01-01T00:00:00.000Z',
    reservation: {...ids, requesterKeyId: b.keyId, requesterAuthGeneration: b.authGeneration,
      keyPackageRef: kp.keyPackageRef, cipherSuite: 'MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519',
      purpose: 'leafRecovery', status: 'active', expiresAt: '2099-01-01T00:00:00.000Z', keyPackage: kp}};
  (ds.recoveries[cid] ||= []).push(view);
  return view;
}
const entryAt = (cid, seq) => ds.entries[cid].find((e) => e.seq === seq);
export function installDs(receipt, repoOp, didDoc, crossHomeDidDoc) {
  originalFetch = globalThis.fetch;
  receiptFor = receipt;
  pdsRepo = repoOp;
  ds = {records: {}, sends: [], accepted: {}, order: {}, seq: {}, entries: {}, held: [],
    hold: 0, lose: 0, refuse: false, enforce: true, keyGeneration: 1, acks: 0, repoReadAuth: [],
    transitions: [], loseTransition: 0, inventory: {}, welcomes: {}, inbox: {}, welcomeAcks: [],
    floor: {}, kps: {}, coords: {}, recoveries: {}, acked: {},
    nextAcceptanceSequencer: null, nextAcceptanceEntry: null};
  globalThis.fetch = async (request) => {
    const reply = (body, status = 200) => {
      const r = new Response(JSON.stringify(body), {status, headers: {'content-type': 'application/json'}});
      Object.defineProperty(r, 'url', {value: request.url});
      return r;
    };
    const url = new URL(request.url);
    if (url.hostname === 'plc.directory') {
      const did = decodeURIComponent(url.pathname.slice(1));
      return reply(JSON.parse(pdsRepo('doc', did, 'https://pds.catbird.test', '', '')));
    }
    if (url.pathname === '/.well-known/did.json')
      return reply(JSON.parse(url.hostname === 'home-b.catbird.test' ? crossHomeDidDoc : didDoc));
    const nsid = url.pathname.replace('/xrpc/', '');
    const text = request.method === 'POST' ? await request.clone().text() : '';
    const b = text ? JSON.parse(text).signedRequest?.body : undefined;
    const device = url.searchParams.get('actorDeviceId');
    switch (nsid) {
      case 'com.atproto.server.getServiceAuth': return reply({token: 'service-auth'});
      case 'com.atproto.repo.createRecord':
      case 'com.atproto.repo.putRecord': {
        const r = JSON.parse(text);
        const uri = `at://${r.repo}/${r.collection}/${r.rkey}`;
        ds.records[uri] = r.record;
        return reply({uri, cid: pdsRepo('cid', JSON.stringify(r.record), '', '', '')});
      }
      case 'com.atproto.repo.getRecord': {
        const uri = `at://${url.searchParams.get('repo')}/${url.searchParams.get('collection')}/${url.searchParams.get('rkey')}`;
        return uri in ds.records
          ? reply({uri, cid: pdsRepo('cid', JSON.stringify(ds.records[uri]), '', '', ''), value: ds.records[uri]})
          : reply({error: 'RecordNotFound', message: uri}, 400);
      }
      case 'com.atproto.repo.listRecords': {
        ds.repoReadAuth.push(request.headers.get('authorization'));
        const prefix = `at://${url.searchParams.get('repo')}/${url.searchParams.get('collection')}/`;
        return reply({records: Object.entries(ds.records).filter(([uri]) => uri.startsWith(prefix))
          .map(([uri, value]) => ({uri, cid: pdsRepo('cid', JSON.stringify(value), '', '', ''), value}))});
      }
      case 'com.atproto.sync.getRecord': {
        ds.repoReadAuth.push(request.headers.get('authorization'));
        const did = url.searchParams.get('did'), col = url.searchParams.get('collection'), rkey = url.searchParams.get('rkey');
        const uri = `at://${did}/${col}/${rkey}`;
        if (!(uri in ds.records)) return reply({error: 'RecordNotFound'}, 404);
        const b64 = pdsRepo('car', did, col, rkey, JSON.stringify(ds.records[uri]));
        const car = Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0));
        const rc = new Response(car, {status: 200, headers: {'content-type': 'application/vnd.ipld.car'}});
        Object.defineProperty(rc, 'url', {value: request.url});
        return rc;
      }
      case 'blue.catbird.chat.enrollDevice':
        ds.kps[b.deviceId] = b.keyPackages.slice();
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
      // A device reads only the entries from its readable floor on (`readableFrom`).
      case 'blue.catbird.chat.getEntries': {
        const after = Number(url.searchParams.get('afterSeq'));
        return reply({entries: (ds.entries[url.searchParams.get('conversationId')] || [])
          .filter((e) => e.seq > after && e.seq >= (ds.floor[device] || 0)), hasMore: false});
      }
      case 'blue.catbird.chat.acknowledgeEntries': {
        const a = JSON.parse(text);
        ds.acks++;
        ds.acked[`${a.conversationId} ${a.actorDeviceId}`] = a.upToSeq;
        return reply({});
      }
      case 'blue.catbird.chat.submitTransition': {
        const entry = transition(text);
        if (ds.loseTransition > 0) {
          ds.loseTransition--;
          throw new TypeError('submitTransition response lost');
        }
        return reply({coordinates: entry.signedRequest.body.next, entry, welcomes: []});
      }
      case 'blue.catbird.chat.acceptConversation': {
        const sequencerDid = ds.nextAcceptanceSequencer;
        ds.nextAcceptanceSequencer = null;
        const entry = transition(text, sequencerDid);
        const answerEntry = ds.nextAcceptanceEntry || entry;
        ds.nextAcceptanceEntry = null;
        return reply({coordinates: entry.signedRequest.body.next, entry: answerEntry, recovery: openRecovery(b)});
      }
      case 'blue.catbird.chat.acknowledgeWelcome': ds.welcomeAcks.push(b); return reply({});
      case 'blue.catbird.chat.getConversations':
        return reply({items: ds.inventory[device] || [], hasMore: false});
      case 'blue.catbird.chat.getPendingWelcomes':
        return reply({items: ds.welcomes[device] || [], hasMore: false});
      // Requests mls-ds lists to a device as its own; a fulfiller never takes work from here.
      case 'blue.catbird.chat.getLeafRecoveryInbox':
        return reply({items: ds.inbox[device] || [], hasMore: false});
      case 'blue.catbird.chat.getConversationState': {
        const cid = url.searchParams.get('conversationId');
        return reply({state: {conversationId: cid, coordinates: ds.coords[cid]},
          pendingLeafRecoveryRequests: ds.recoveries[cid] || []});
      }
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
// Later receipts are signed by `#mls-receipt-<generation>`; earlier methods stay published.
export function useReceiptKey(generation) { ds.keyGeneration = generation; }
export function appendEntry(cid, entry) {
  const e = JSON.parse(entry);
  e.seq = ++ds.seq[cid];
  if (e.signedRequest && !e.sequencerReceipt) {
    const body = e.signedRequest.body;
    const control = e.$type !== 'blue.catbird.chat.defs#applicationEntry';
    const coordinate = body.next || body.successor || body.retired || body.prior;
    // Deliberately malformed fixtures have no receipt-binding fields.
    if ((!control && body.messageId) || (control && coordinate)) {
      e.sequencerReceipt = JSON.parse(receiptFor(JSON.stringify({
        body, seq: e.seq, entryId: e.entryId, control,
        keyGeneration: ds.keyGeneration})));
    }
  }
  ds.entries[cid].push(e);
  return e.seq;
}
// Remove and return one entry to model a delivery service dropping a tail row.
export function dropEntry(cid, seq) {
  const e = entryAt(cid, seq);
  ds.entries[cid] = ds.entries[cid].filter((x) => x.seq !== seq);
  return JSON.stringify(e);
}
// A receipt altered after signing: its signature no longer verifies.
export function tamperReceipt(cid, seq) { entryAt(cid, seq).sequencerReceipt.issuedAtMs += 1; }
// The `payloadPruned` projection `getEntries` serves once the ciphertext is pruned (O7).
export function pruneEntry(cid, seq) {
  const e = entryAt(cid, seq);
  const pruned = {$type: e.$type, conversationId: e.conversationId, entryId: e.entryId,
    payloadPruned: true, receivedAt: e.receivedAt, seq, sequencerReceipt: e.sequencerReceipt};
  ds.entries[cid][ds.entries[cid].indexOf(e)] = pruned;
}
// The same sequenced entry served again under the next seq.
export function replayEntry(cid, seq) {
  const e = structuredClone(entryAt(cid, seq));
  e.seq = ++ds.seq[cid];
  ds.entries[cid].push(e);
  return e.seq;
}
export function dsSends() { return JSON.stringify(ds.sends); }
export function ackCount() { return ds.acks; }
export function repoReadAuth() { return JSON.stringify(ds.repoReadAuth); }
export function restoreFetch() { globalThis.fetch = originalFetch; }
export function loseNextTransition() { ds.loseTransition += 1; }
export function serveInventory(device, items) { ds.inventory[device] = JSON.parse(items); }
export function nextAcceptanceSequencer(did) { ds.nextAcceptanceSequencer = did; }
export function replayNextAcceptance(entry) { ds.nextAcceptanceEntry = JSON.parse(entry); }
export function serveWelcomes(device, items) { ds.welcomes[device] = JSON.parse(items); }
export function serveInbox(device, items) { ds.inbox[device] = JSON.parse(items); }
// The leaf recoveries `getConversationState` lists for `cid`, replacing what it listed.
export function serveRecoveries(cid, items) { ds.recoveries[cid] = JSON.parse(items); }
export function recoveriesJson(cid) { return JSON.stringify(ds.recoveries[cid] || []); }
// One of `device`'s enrolled KeyPackages, no longer reservable by mls-ds.
export function takeKeyPackage(device) { return JSON.stringify(ds.kps[device].shift()); }
// The highest seq `device` acknowledged in `cid`, 0 before any.
export function ackedUpTo(cid, device) { return ds.acked[`${cid} ${device}`] || 0; }
// `device` joined later: it reads only the entries from `seq` on.
export function readableFrom(device, seq) { ds.floor[device] = seq; }
// Serve `entry` at its own seq, replacing the entry there.
export function setEntry(cid, entry) {
  const e = JSON.parse(entry);
  ds.entries[cid] = ds.entries[cid].filter((x) => x.seq !== e.seq).concat([e])
    .sort((x, y) => x.seq - y.seq);
}
export function entryJson(cid, seq) { return JSON.stringify(entryAt(cid, seq)); }
export function dsTransitions() { return JSON.stringify(ds.transitions); }
export function welcomeAcks() { return JSON.stringify(ds.welcomeAcks); }
"#)]
extern "C" {
    fn installDs(
        receipt: &js_sys::Function,
        repo_op: &js_sys::Function,
        did_doc: &str,
        cross_home_did_doc: &str,
    );
    fn openConversation(cid: &str);
    fn holdNextSend();
    fn loseNextSendResponse();
    fn deliverHeld();
    fn refuseEverySend(refuse: bool);
    fn enforceSendOrder(enforce: bool);
    fn useReceiptKey(generation: u32);
    fn appendEntry(cid: &str, entry: &str) -> u32;
    fn dropEntry(cid: &str, seq: u32) -> String;
    fn tamperReceipt(cid: &str, seq: u32);
    fn pruneEntry(cid: &str, seq: u32);
    fn replayEntry(cid: &str, seq: u32) -> u32;
    fn dsSends() -> String;
    fn ackCount() -> u32;
    fn repoReadAuth() -> String;
    fn restoreFetch();
    fn loseNextTransition();
    fn serveInventory(device: &str, items: &str);
    fn nextAcceptanceSequencer(did: &str);
    fn replayNextAcceptance(entry: &str);
    fn serveWelcomes(device: &str, items: &str);
    fn serveInbox(device: &str, items: &str);
    fn serveRecoveries(cid: &str, items: &str);
    fn recoveriesJson(cid: &str) -> String;
    fn takeKeyPackage(device: &str) -> String;
    fn ackedUpTo(cid: &str, device: &str) -> u32;
    fn readableFrom(device: &str, seq: u32);
    fn setEntry(cid: &str, entry: &str);
    fn entryJson(cid: &str, seq: u32) -> String;
    fn dsTransitions() -> String;
    fn welcomeAcks() -> String;
}
struct RestoreFetch;
impl Drop for RestoreFetch {
    fn drop(&mut self) {
        restoreFetch();
    }
}

const SEQUENCER: &str = "did:web:ds.catbird.test";
const CROSS_HOME_DS: &str = "did:web:home-b.catbird.test";
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const ALICE_DEVICE: &str = "00000000-0000-4000-8000-00000000a001";
const BOB_DEVICE: &str = "00000000-0000-4000-8000-00000000b001";
const CAROL_DEVICE: &str = "00000000-0000-4000-8000-00000000c001";
const DAVE_DEVICE: &str = "00000000-0000-4000-8000-00000000d001";
const ERIN_DEVICE: &str = "00000000-0000-4000-8000-00000000e001";

fn did(name: &str) -> String {
    format!("did:plc:{name:a<24}")
}

fn message_id(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

/// The sequencer's ES256 key for its receipt method `#mls-receipt-<generation>`.
fn sequencer_key(generation: u64) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[18 + generation as u8; 32]).unwrap()
}

fn receipt_kid_for(sequencer_did: &str, generation: u64) -> String {
    format!("{sequencer_did}#mls-receipt-{generation}")
}

fn receipt_kid(generation: u64) -> String {
    receipt_kid_for(SEQUENCER, generation)
}

/// `I13` receipt for a send or control entry the fixture sequenced.
fn receipt_for(request: String) -> String {
    let request: Value = serde_json::from_str(&request).unwrap();
    let sequencer_did = request["sequencerDid"].as_str().unwrap_or(SEQUENCER);
    let body = &request["body"];
    let generation = request["keyGeneration"].as_u64().unwrap();
    let control = request["control"].as_bool().unwrap_or(false);
    let coordinate = if control {
        body.get("next")
            .or_else(|| body.get("successor"))
            .or_else(|| body.get("retired"))
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
        let transcript = SigningTranscript::build_for(kind, &projected).unwrap();
        (text(&request["entryId"]), *transcript.request_digest())
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
        sequencer_did: sequencer_did.into(),
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
    let signed = sign_sequencer_receipt(
        &sequencer_key(generation),
        &receipt_kid_for(sequencer_did, generation),
        &payload,
    )
    .unwrap();
    json!({
        "sequencerDid": payload.sequencer_did, "conversationId": payload.conversation_id,
        "generation": coordinate["generation"], "groupId": STANDARD.encode(&payload.group_id),
        "epoch": payload.epoch, "senderDid": body["actorDid"], "senderDeviceId": body["actorDeviceId"],
        "entryId": payload.entry_id, "archiveCommitment": STANDARD.encode(payload.archive_commitment),
        "seq": payload.seq, "issuedAtMs": payload.issued_at_ms, "kid": signed.key_id,
        "signature": STANDARD.encode(signed.signature),
    })
    .to_string()
}
/// Rebind a fixture entry's `I13` receipt after a test deliberately re-signs its body.
fn with_current_receipt(mut entry: Value) -> Value {
    let control = entry["$type"] != "blue.catbird.chat.defs#applicationEntry";
    let request = json!({
        "body": entry["signedRequest"]["body"],
        "seq": entry["seq"],
        "entryId": entry["entryId"],
        "control": control,
        "keyGeneration": 1,
    });
    entry["sequencerReceipt"] = serde_json::from_str(&receipt_for(request.to_string())).unwrap();
    entry
}

fn pds_repo_key(did: &str) -> p256::SecretKey {
    let mut h = Sha256::new();
    h.update(b"test-pds-repo-key:");
    h.update(did.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&h.finalize());
    seed[0] = (seed[0] & 0x7f) | 1;
    p256::SecretKey::from_slice(&seed).unwrap()
}

fn pds_tid(seq: u64) -> String {
    const ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    let v = (1u64 << 62) | seq;
    (0..13)
        .rev()
        .map(|i| ALPHABET[((v >> (5 * i)) & 31) as usize] as char)
        .collect()
}

fn pds_repo_op(op: String, a: String, b: String, c: String, d: String) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static REV_SEQ: AtomicU64 = AtomicU64::new(1);
    use atproto_spaces::kem::encode_p256_did_key;
    use atproto_spaces::tokens::SpaceSigningKey;
    use catbird_mls::labyrinth::repo_proof::{
        build_repo_proof_car_v1, encode_atproto_json_record_dagcbor,
    };
    match op.as_str() {
        "doc" => {
            let sign_mb = encode_p256_did_key(&pds_repo_key(&a).public_key());
            json!({
                "id": a,
                "verificationMethod": [{
                    "id": format!("{a}#atproto"),
                    "controller": a,
                    "type": "Multikey",
                    "publicKeyMultibase": sign_mb.strip_prefix("did:key:").unwrap(),
                }],
                "service": [{
                    "id": format!("{a}#atproto_pds"),
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": b,
                }],
            })
            .to_string()
        }
        "cid" => {
            let v: Value = serde_json::from_str(&a).unwrap();
            let (cid, _) = encode_atproto_json_record_dagcbor(&v).unwrap();
            cid.to_string()
        }
        "car" => {
            let v: Value = serde_json::from_str(&d).unwrap();
            let (_, dagcbor) = encode_atproto_json_record_dagcbor(&v).unwrap();
            let sk = SpaceSigningKey::from_p256_secret(&pds_repo_key(&a), "#atproto");
            let rev = pds_tid(REV_SEQ.fetch_add(1, Ordering::Relaxed));
            let (_, car) =
                build_repo_proof_car_v1(&a, &rev, &[(format!("{b}/{c}"), dagcbor)], &sk).unwrap();
            STANDARD.encode(car)
        }
        other => panic!("unknown pds_repo_op: {other}"),
    }
}

/// The sequencer DID document retains every receipt method it ever signed with (G3).
fn install_ds() -> RestoreFetch {
    let did_doc = |sequencer_did: &str| {
        let methods: Vec<Value> = (1..=2)
            .map(|generation| {
                let point = sequencer_key(generation)
                    .verifying_key()
                    .to_encoded_point(false);
                json!({
                    "id": receipt_kid_for(sequencer_did, generation),
                    "type": "JsonWebKey2020", "controller": sequencer_did,
                    "publicKeyJwk": {"kty": "EC", "crv": "P-256",
                        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())},
                })
            })
            .collect();
        json!({"id": sequencer_did, "verificationMethod": methods})
    };
    let receipt = Closure::<dyn Fn(String) -> String>::new(receipt_for);
    let repo_op =
        Closure::<dyn Fn(String, String, String, String, String) -> String>::new(pds_repo_op);
    installDs(
        receipt.as_ref().unchecked_ref(),
        repo_op.as_ref().unchecked_ref(),
        &did_doc(SEQUENCER).to_string(),
        &did_doc(CROSS_HOME_DS).to_string(),
    );
    receipt.forget();
    repo_op.forget();
    RestoreFetch
}

async fn open_at_home(did: &str, device_id: &str, home_ds_did: &str) -> WasmMlsClient {
    let client = WasmMlsClient::open_async(
        did.into(),
        device_id.into(),
        home_ds_did.into(),
        "https://ds.catbird.test".into(),
        "https://pds.catbird.test".into(),
        "ab".repeat(32),
    )
    .await
    .unwrap();
    client.set_auth_token(Some("session".into()));
    client
}

async fn open(did: &str, device_id: &str) -> WasmMlsClient {
    open_at_home(did, device_id, SEQUENCER).await
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

/// Enroll `did#device_id` at `home_ds_did`, then close its client.
async fn enroll_at_home(did: &str, device_id: &str, home_ds_did: &str) {
    let client = open_at_home(did, device_id, home_ds_did).await;
    let scopes = serde_wasm_bindgen::to_value(&REQUIRED_LABYRINTH_OAUTH_SCOPES).unwrap();
    client.enroll_device(true, scopes).await.unwrap();
}

/// Enroll `did#device_id`, then close its client.
async fn enroll(did: &str, device_id: &str) {
    enroll_at_home(did, device_id, SEQUENCER).await;
}

/// Enroll every member, then leave each account database the way `createGroup` and the
/// members' Welcome imports do: one MLS group at epoch 1, created by the first member and
/// holding every leaf, conversation at seq 1. Returns the members' clients, in order.
async fn group(members: &[(&str, &str)], cid: &str) -> Vec<WasmMlsClient> {
    for (did, device_id) in members {
        enroll(did, device_id).await;
    }
    let dbs: Vec<_> = members.iter().map(|(did, _)| account_db(did)).collect();
    {
        let ((creator, creator_device), joiners) = members.split_first().unwrap();
        let creator_signer = device_signer(&dbs[0]);
        let creator_mls = dbs[0].openmls_provider().unwrap();
        let packages: Vec<KeyPackage> = joiners
            .iter()
            .zip(&dbs[1..])
            .map(|((did, device_id), db)| {
                let signer = device_signer(db);
                KeyPackage::builder()
                    .leaf_node_capabilities(capabilities())
                    .build(
                        CIPHERSUITE,
                        &db.openmls_provider().unwrap(),
                        &signer,
                        credential(did, device_id, &signer),
                    )
                    .unwrap()
                    .key_package()
                    .clone()
            })
            .collect();
        let create = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(capabilities())
            .use_ratchet_tree_extension(true)
            .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(5)
            .sender_ratchet_configuration(
                catbird_mls::GroupConfig::default().sender_ratchet_configuration(),
            )
            .build();
        let group_id = [
            uuid::Uuid::new_v4().into_bytes(),
            uuid::Uuid::new_v4().into_bytes(),
        ]
        .concat();
        let mut group = MlsGroup::new_with_group_id(
            &creator_mls,
            &creator_signer,
            &create,
            GroupId::from_slice(&group_id),
            credential(creator, creator_device, &creator_signer),
        )
        .unwrap();
        let (_, welcome, _) = group
            .add_members(&creator_mls, &creator_signer, &packages)
            .unwrap();
        group.merge_pending_commit(&creator_mls).unwrap();
        let welcome =
            MlsMessageIn::tls_deserialize_exact(welcome.tls_serialize_detached().unwrap()).unwrap();
        let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
            panic!("expected a Welcome");
        };
        let join = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(5)
            .sender_ratchet_configuration(
                catbird_mls::GroupConfig::default().sender_ratchet_configuration(),
            )
            .build();
        for db in &dbs[1..] {
            let mls = db.openmls_provider().unwrap();
            StagedWelcome::new_from_welcome(&mls, &join, welcome.clone(), None)
                .unwrap()
                .into_group(&mls)
                .unwrap();
        }
        for db in &dbs {
            let mls = db.openmls_provider().unwrap();
            let stored = MlsGroup::load(mls.storage(), &GroupId::from_slice(&group_id))
                .unwrap()
                .unwrap();
            let (gch, ctag) = chat_wire::compute_group_context_hash_and_tag(&stored, &mls).unwrap();
            let coordinates = canonical(
                &json!({
                    "conversationId": cid, "generation": 0, "stateVersion": 0,
                    "lifecycle": "active", "groupId": STANDARD.encode(&group_id),
                    "epoch": 1, "groupContextHash": STANDARD.encode(gch),
                    "confirmationTag": STANDARD.encode(ctag),
                }),
                cid,
            );
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
                })?;
                tx.put_account_meta(
                    &format!("conversation_coords:{cid}"),
                    &coordinates.to_string(),
                    0,
                )
            })
            .unwrap();
        }
    }
    drop(dbs);
    openConversation(cid);
    let mut clients = Vec::new();
    for (did, device_id) in members {
        clients.push(open(did, device_id).await);
    }
    clients
}

/// Alice and Bob's [`group`].
async fn conversation(alice: &str, bob: &str, cid: &str) -> (WasmMlsClient, WasmMlsClient) {
    let mut clients = group(&[(alice, ALICE_DEVICE), (bob, BOB_DEVICE)], cid)
        .await
        .into_iter();
    (clients.next().unwrap(), clients.next().unwrap())
}

/// The signed wrapper of `body` as `operation`, signed by `signer` as the device `body` names.
fn signed(operation: CanonicalOperation, mut body: Value, signer: &SignatureKeyPair) -> Value {
    body["keyId"] = json!(derive_key_id(signer.public()));
    let did = body["actorDid"].as_str().unwrap().to_owned();
    let device_id = body["actorDeviceId"].as_str().unwrap().to_owned();
    let prepared =
        chat_wire::sign_clean_chat_mutation(&did, &device_id, Some(1), operation, &body, signer)
            .unwrap();
    let mut request: Value = serde_json::from_slice(prepared.body.as_deref().unwrap()).unwrap();
    request["signedRequest"].take()
}

/// The entry `getEntries` serves at `seq` of `cid`.
fn entry_at(cid: &str, seq: u32) -> Value {
    serde_json::from_str(&entryJson(cid, seq)).unwrap()
}

/// `entry` with its signed body edited by `edit`, signed again by `signer` as `operation`.
fn resigned(
    entry: &Value,
    operation: CanonicalOperation,
    signer: &SignatureKeyPair,
    edit: impl FnOnce(&mut Value),
) -> Value {
    let mut entry = entry.clone();
    let mut body = entry["signedRequest"]["body"].take();
    edit(&mut body);
    entry["signedRequest"] = signed(operation, body, signer);
    with_current_receipt(entry)
}

/// `entry` altered after signing: its signature no longer verifies.
fn altered(entry: &Value) -> Value {
    let mut entry = entry.clone();
    entry["signedRequest"]["body"]["signedAt"] = json!("2026-11-07T00:00:00.000Z");
    entry
}

fn canonical(coordinate: &Value, cid: &str) -> Value {
    chat_wire::canonicalize_wire_coordinate(coordinate, Some(cid)).unwrap()
}
const RECEIPT_ABSENCE_KINDS: [&str; 3] = [
    "blue.catbird.chat.defs#metadataEntry",
    "blue.catbird.chat.defs#zeroLeafLeaveEntry",
    "blue.catbird.chat.defs#leaveCommitFulfillmentEntry",
];

fn receipt_absence_operation(kind: &str) -> CanonicalOperation {
    match kind {
        "blue.catbird.chat.defs#metadataEntry"
        | "blue.catbird.chat.defs#leaveCommitFulfillmentEntry" => {
            CanonicalOperation::SubmitTransition
        }
        "blue.catbird.chat.defs#zeroLeafLeaveEntry" => CanonicalOperation::RequestLeave,
        _ => unreachable!("receipt-absence fixture kind"),
    }
}

fn wire_fixture_value(value: &Value, schema: &Value, defs: &Value) -> Value {
    match schema["type"].as_str().expect("fixture schema type") {
        "ref" => {
            let name = schema["ref"].as_str().unwrap().strip_prefix('#').unwrap();
            wire_fixture_value(value, &defs[name], defs)
        }
        "union" => {
            let name = value["$type"]
                .as_str()
                .unwrap()
                .strip_prefix("blue.catbird.chat.defs#")
                .unwrap();
            assert!(schema["refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| reference.as_str() == Some(&format!("#{name}"))));
            wire_fixture_value(value, &defs[name], defs)
        }
        "object" => Value::Object(
            value
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, value)| {
                    let converted = if name == "$type" {
                        value.clone()
                    } else {
                        wire_fixture_value(value, &schema["properties"][name], defs)
                    };
                    (name.clone(), converted)
                })
                .collect(),
        ),
        "array" => Value::Array(
            value
                .as_array()
                .unwrap()
                .iter()
                .map(|item| wire_fixture_value(item, &schema["items"], defs))
                .collect(),
        ),
        "bytes" => {
            let marker = value.as_object().expect("semantic source bytes marker");
            let raw = if let Some(encoded) = marker.get("$bytesHex") {
                hex::decode(encoded.as_str().unwrap()).unwrap()
            } else {
                uuid::Uuid::parse_str(marker["$uuid"].as_str().unwrap())
                    .unwrap()
                    .as_bytes()
                    .to_vec()
            };
            json!(STANDARD.encode(raw))
        }
        "string" if value.is_object() => json!(value["$uuid"].as_str().unwrap()),
        "string" | "integer" | "boolean" => value.clone(),
        other => panic!("unsupported source schema {other}"),
    }
}

fn rewrite_conversation_ids(value: &mut Value, cid: &str) {
    match value {
        Value::Array(values) => {
            for value in values {
                rewrite_conversation_ids(value, cid);
            }
        }
        Value::Object(fields) => {
            for (key, value) in fields {
                if key == "conversationId" {
                    *value = if value.is_object() {
                        json!({ "$uuid": cid })
                    } else {
                        json!(cid)
                    };
                } else {
                    rewrite_conversation_ids(value, cid);
                }
            }
        }
        _ => {}
    }
}
fn rewrite_fixture_dids(value: &mut Value, actor: &str) {
    match value {
        Value::String(did) if did.starts_with("did:") => *did = actor.to_owned(),
        Value::Array(values) => {
            for value in values {
                rewrite_fixture_dids(value, actor);
            }
        }
        Value::Object(fields) => {
            for value in fields.values_mut() {
                rewrite_fixture_dids(value, actor);
            }
        }
        _ => {}
    }
}

fn receiptless_corpus_entry(
    kind: &str,
    cid: &str,
    actor: &str,
    device: &str,
    signer: &SignatureKeyPair,
) -> Value {
    let corpus: Value = serde_json::from_str(include_str!(
        "fixtures/mls_chat_control_fingerprint_source.json"
    ))
    .unwrap();
    let case = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["entryKind"] == kind)
        .unwrap_or_else(|| panic!("no control corpus case for {kind}"));
    let mut source_body = case["body"].clone();
    rewrite_conversation_ids(&mut source_body, cid);
    rewrite_fixture_dids(&mut source_body, actor);
    source_body["actorDid"] = json!(actor);
    source_body["actorDeviceId"] = json!(device);
    let lexicon: Value =
        serde_json::from_str(include_str!("../src/generated/blue.catbird.chat.defs.json")).unwrap();
    let body_name = source_body["$type"]
        .as_str()
        .unwrap()
        .strip_prefix("blue.catbird.chat.defs#")
        .unwrap();
    let body = wire_fixture_value(&source_body, &lexicon["defs"][body_name], &lexicon["defs"]);
    json!({
        "$type": kind,
        "entryId": case["entryId"],
        "conversationId": cid,
        "seq": 2,
        "receivedAt": case["receivedAt"],
        "signedRequest": signed(receipt_absence_operation(kind), body, signer),
    })
}

/// `account`'s stored coordinates of `cid`, canonical, from its closed database.
fn stored_coords(account: &str, cid: &str) -> Option<Value> {
    account_db(account)
        .backend()
        .get_account_meta(&format!("conversation_coords:{cid}"))
        .unwrap()
        .map(|raw| canonical(&serde_json::from_str(&raw).unwrap(), cid))
}
fn fork_marker(account: &str, cid: &str) -> Option<String> {
    account_db(account)
        .backend()
        .get_account_meta(&chat_wire::fork_detected_key(cid))
        .unwrap()
}

/// The current coordinate of `account`'s MLS group for `cid`, from its closed database, at
/// `stateVersion` 0 (no transition stored).
fn group_coords(account: &str, cid: &str) -> Value {
    let db = account_db(account);
    let group_id = db
        .backend()
        .get_conversation(cid)
        .unwrap()
        .unwrap()
        .group_id;
    let mls = db.openmls_provider().unwrap();
    let group = MlsGroup::load(mls.storage(), &GroupId::from_slice(&group_id))
        .unwrap()
        .unwrap();
    let (gch, tag) = chat_wire::compute_group_context_hash_and_tag(&group, &mls).unwrap();
    canonical(
        &json!({
            "conversationId": cid, "generation": 0, "stateVersion": 0, "lifecycle": "active",
            "groupId": STANDARD.encode(&group_id), "epoch": group.epoch().as_u64(),
            "groupContextHash": STANDARD.encode(gch), "confirmationTag": STANDARD.encode(tag),
        }),
        cid,
    )
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
/// The three control kinds that previously had no client-side negative evidence each stop at
/// their missing I13 receipt before state, cursor, coordinate or acknowledgement changes.
#[wasm_bindgen_test]
async fn mandatory_control_kinds_require_receipts() {
    let _restore = install_ds();
    let (alice, bob) = (did("kindalice"), did("kindbob"));
    let cid = "00000000-0000-4000-8000-0000000c0022";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    drop(bob_client);
    let signer = device_signer(&account_db(&bob));
    let initial_row = conversation_row(&alice_client, cid);
    drop(alice_client);
    let initial_coords = stored_coords(&alice, cid).unwrap();
    let mut alice_client = open(&alice, ALICE_DEVICE).await;

    for kind in RECEIPT_ABSENCE_KINDS {
        let entry = receiptless_corpus_entry(kind, cid, &bob, BOB_DEVICE, &signer);
        setEntry(cid, &entry.to_string());
        let error = alice_client
            .sync()
            .await
            .expect_err(kind)
            .as_string()
            .unwrap_or_default();
        assert!(
            error.contains("missing sequencerReceipt"),
            "{kind} stopped before its I13 gate: {error}"
        );
        assert_eq!(
            conversation_row(&alice_client, cid),
            initial_row,
            "{kind} changed conversation state"
        );
        assert_eq!(ackedUpTo(cid, ALICE_DEVICE), 0, "{kind} was acknowledged");
        assert!(
            timeline(&alice_client, cid).is_empty(),
            "{kind} wrote a row"
        );
        drop(alice_client);
        assert_eq!(
            stored_coords(&alice, cid),
            Some(initial_coords.clone()),
            "{kind} changed coordinates"
        );
        alice_client = open(&alice, ALICE_DEVICE).await;
    }
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

/// A delivery service cannot move the cursor over a missing sequence. Peer counters need only
/// increase within an epoch: reservations may leave holes, but duplicates and rewinds are refused.
/// Restoring the dropped row proves the contiguous batch still applies.
///
/// Fail-before: sync rejected a valid counter jump that the sequencer accepts.
#[wasm_bindgen_test]
async fn sync_requires_contiguous_entry_seq_and_increasing_peer_send_counter() {
    let _restore = install_ds();
    let (alice, bob) = (did("contiguousalice"), did("contiguousbob"));
    let cid = "00000000-0000-4000-8000-0000000c0020";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    send(&bob_client, cid, 1, "one").await.unwrap();
    send(&bob_client, cid, 2, "two").await.unwrap();

    let dropped = dropEntry(cid, 2);
    let error = alice_client
        .sync()
        .await
        .expect_err("seq 3 cannot cover a missing seq 2")
        .as_string()
        .unwrap_or_default();
    assert!(
        error.contains("non-contiguous conversation sequence"),
        "{error}"
    );
    assert_eq!(
        (
            conversation_row(&alice_client, cid).last_seq,
            ackedUpTo(cid, ALICE_DEVICE)
        ),
        (1, 0)
    );

    setEntry(cid, &dropped);
    alice_client.sync().await.expect("the contiguous batch");
    assert_eq!(
        (
            conversation_row(&alice_client, cid).last_seq,
            ackedUpTo(cid, ALICE_DEVICE)
        ),
        (3, 3)
    );

    drop(bob_client);
    let bob_db = account_db(&bob);
    let bob_signer = device_signer(&bob_db);
    bob_db
        .write_tx(|tx| tx.put_account_meta(&chat_wire::send_counter_key(cid), "3", 0))
        .unwrap();
    drop(bob_db);
    let bob_client = open(&bob, BOB_DEVICE).await;
    send(&bob_client, cid, 3, "counter four").await.unwrap();
    // Counters are monotone reservations, not a gap-free delivery sequence.
    alice_client
        .sync()
        .await
        .expect("peer sendCounter 2 -> 4 advances");
    assert_eq!(
        (
            conversation_row(&alice_client, cid).last_seq,
            ackedUpTo(cid, ALICE_DEVICE)
        ),
        (4, 4)
    );

    send(&bob_client, cid, 4, "counter five").await.unwrap();
    let genuine = entry_at(cid, 5);
    for (counter, label) in [(4, "distinct duplicate"), (3, "rewind")] {
        setEntry(
            cid,
            &resigned(
                &genuine,
                CanonicalOperation::SendMessage,
                &bob_signer,
                |body| body["sendCounter"] = json!(counter),
            )
            .to_string(),
        );
        let error = alice_client
            .sync()
            .await
            .expect_err(&format!("{label} peer counter is refused"))
            .as_string()
            .unwrap_or_default();
        assert!(
            error.contains("non-increasing peer sendCounter"),
            "{label}: {error}"
        );
        assert_eq!(
            (
                conversation_row(&alice_client, cid).last_seq,
                ackedUpTo(cid, ALICE_DEVICE)
            ),
            (4, 4),
            "{label}"
        );
    }
    setEntry(cid, &genuine.to_string());
    alice_client
        .sync()
        .await
        .expect("the genuine increasing counter applies");
    assert_eq!(
        (
            conversation_row(&alice_client, cid).last_seq,
            ackedUpTo(cid, ALICE_DEVICE)
        ),
        (5, 5)
    );
}

/// A conflicting application prior becomes durable fork evidence only after the actor is a
/// PDS-authorized current leaf and the application receipt verifies under its own `kid`, binding
/// this sender, conversation, entry, sequence and archive commitment. An outsider with a valid
/// PDS device and receipt, and a leaf with a forged receipt, are ordinary invalid entries and
/// write no marker. A valid leaf+receipt still records the fork. Restoring the genuine row applies.
#[wasm_bindgen_test]
async fn same_epoch_coordinate_mismatch_is_a_fork_not_an_aead_gap() {
    let _restore = install_ds();
    let (alice, bob, dave) = (did("forkalice"), did("forkbob"), did("forkdave"));
    let cid = "00000000-0000-4000-8000-0000000c0021";
    let (mut alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    send(&bob_client, cid, 1, "genuine").await.unwrap();
    drop(bob_client);
    enroll(&dave, DAVE_DEVICE).await;
    let genuine = entry_at(cid, 2);
    let (bob_signer, dave_signer) = (
        device_signer(&account_db(&bob)),
        device_signer(&account_db(&dave)),
    );
    let valid_fork = resigned(
        &genuine,
        CanonicalOperation::SendMessage,
        &bob_signer,
        |body| body["prior"]["groupContextHash"] = json!(STANDARD.encode([91_u8; 32])),
    );
    let outsider = resigned(
        &genuine,
        CanonicalOperation::SendMessage,
        &dave_signer,
        |body| {
            body["actorDid"] = json!(dave);
            body["actorDeviceId"] = json!(DAVE_DEVICE);
            body["prior"]["groupContextHash"] = json!(STANDARD.encode([91_u8; 32]));
        },
    );
    let mut forged_receipt = valid_fork.clone();
    forged_receipt["sequencerReceipt"]["signature"] = json!(STANDARD.encode([0_u8; 64]));

    let mut invalid_failures = Vec::new();
    for (case, entry, expected) in [
        (
            "a PDS-authorized outsider",
            outsider,
            "not an authorized active participant device",
        ),
        (
            "a leaf with a forged receipt",
            forged_receipt,
            "I13 sequencerReceipt verify failed",
        ),
    ] {
        setEntry(cid, &entry.to_string());
        let result = alice_client.sync().await;
        let failed = result.is_err();
        let error = result
            .err()
            .and_then(|error| error.as_string())
            .unwrap_or_else(|| "sync unexpectedly succeeded".to_owned());
        let cursor = (
            conversation_row(&alice_client, cid).last_seq,
            ackedUpTo(cid, ALICE_DEVICE),
        );
        let timeline_empty = timeline(&alice_client, cid).is_empty();
        drop(alice_client);
        let marker = fork_marker(&alice, cid);
        if !failed
            || !error.contains(expected)
            || error.contains("fork detected")
            || cursor != (1, 0)
            || !timeline_empty
            || marker.is_some()
        {
            invalid_failures.push(format!(
                "{case}: error={error}; cursor={cursor:?}; timeline_empty={timeline_empty}; marker={marker:?}"
            ));
        }
        if marker.is_some() {
            account_db(&alice)
                .write_tx(|tx| tx.delete_account_meta(&chat_wire::fork_detected_key(cid)))
                .unwrap();
        }
        alice_client = open(&alice, ALICE_DEVICE).await;
    }

    setEntry(cid, &valid_fork.to_string());
    let error = alice_client
        .sync()
        .await
        .expect_err("a current leaf with a valid receipt records the fork")
        .as_string()
        .unwrap_or_default();
    assert!(error.contains("fork detected"), "{error}");
    assert_eq!(
        (
            conversation_row(&alice_client, cid).last_seq,
            ackedUpTo(cid, ALICE_DEVICE)
        ),
        (1, 0)
    );
    assert!(timeline(&alice_client, cid).is_empty());
    drop(alice_client);
    assert!(fork_marker(&alice, cid).is_some(), "fork marker");
    alice_client = open(&alice, ALICE_DEVICE).await;

    let tag_fork = resigned(
        &genuine,
        CanonicalOperation::SendMessage,
        &bob_signer,
        |body| body["prior"]["confirmationTag"] = json!(STANDARD.encode([92_u8; 32])),
    );
    setEntry(cid, &tag_fork.to_string());
    let error = alice_client
        .sync()
        .await
        .expect_err("a confirmation-tag divergence is also a fork")
        .as_string()
        .unwrap_or_default();
    assert!(error.contains("fork detected"), "{error}");

    setEntry(cid, &genuine.to_string());
    alice_client.sync().await.expect("the genuine entry");
    assert_eq!(timeline(&alice_client, cid), timeline_of(&[(2, "genuine")]));
    assert_eq!(ackedUpTo(cid, ALICE_DEVICE), 2);
    assert!(
        invalid_failures.is_empty(),
        "{}",
        invalid_failures.join("\n")
    );
}

/// A send held in the network keeps its journal; after a newer send is sequenced, the caller's
/// retry resubmits those exact bytes, `mls-ds` refuses them (`StaleSend`), and the same message
/// id goes out once more as a fresh frame. A reservation alone does not advance the confirmed
/// counter, while each `StaleSend` proves that its counter is already covered by the sequencer.
/// The refused bytes are never sequenced, and a second `StaleSend` is returned rather than
/// retried. Every refusal discards its journal.
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
        [(1, "held"), (1, "stale"), (2, "accepted")]
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
        [(3, "stale"), (4, "stale")].map(|(c, o)| (c, o.to_owned())),
        "exactly one fresh re-encryption"
    );

    refuseEverySend(false);
    let row = send(&bob_client, cid, 4, "refused")
        .await
        .expect("a later retry goes out as a fresh frame");
    let tries = attempts(4);
    assert_eq!(
        tries
            .iter()
            .map(|(counter, outcome, _)| (*counter, outcome.as_str()))
            .collect::<Vec<_>>(),
        [(3, "stale"), (4, "stale"), (5, "accepted")]
    );
    assert!(
        tries[2].2 != tries[0].2 && tries[2].2 != tries[1].2,
        "refused bytes are never resubmitted"
    );
    assert_eq!((row.message_id, row.seq), (message_id(4), 4));
}

/// `mls-ds` sequenced a send whose response was lost. The accepted watermark is unchanged, so
/// the next message first uses the same candidate counter with a new sender generation.
/// `StaleSend` proves the lost send was accepted, and the fresh retry advances to the next counter.
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
    let lost = attempts(1);
    let after_loss = attempts(2);
    assert_eq!(lost[0].0, 1);
    assert_eq!(
        after_loss
            .iter()
            .map(|(counter, outcome, _)| (*counter, outcome.as_str()))
            .collect::<Vec<_>>(),
        [(1, "stale"), (2, "accepted")]
    );
    assert_ne!(
        lost[0].2, after_loss[0].2,
        "the next reservation uses a fresh sender generation"
    );
    assert_ne!(
        after_loss[0].2, after_loss[1].2,
        "the stale candidate is freshly encrypted at the confirmed counter"
    );
    alice_client.sync().await.unwrap();
    let expected = timeline_of(&[(2, "response lost"), (3, "after the loss")]);
    assert_eq!(timeline(&alice_client, cid), expected);
    bob_client.sync().await.unwrap();
    assert_eq!(timeline(&bob_client, cid), expected);
    assert_eq!(conversation_row(&bob_client, cid).last_seq, 3);
}

/// Seed 2323: a send held by the network was sequenced after ten newer sends from the same
/// device, beyond the receiver's sender-ratchet window (10). The receiver records a gap row and
/// evidence, advances its cursor and still applies the later Commit (Bob's signed removal of
/// Carol).
#[wasm_bindgen_test]
async fn undecryptable_current_epoch_entry_is_tombstoned_and_a_later_commit_applies() {
    let _restore = install_ds();
    let (alice, bob, carol) = (did("tombalice"), did("tombbob"), did("tombcarol"));
    let cid = "00000000-0000-4000-8000-0000000c0004";
    let members = [
        (alice.as_str(), ALICE_DEVICE),
        (bob.as_str(), BOB_DEVICE),
        (carol.as_str(), CAROL_DEVICE),
    ];
    let mut clients = group(&members, cid).await.into_iter();
    let (alice_client, bob_client) = (clients.next().unwrap(), clients.next().unwrap());
    // A `mls-ds` without the send-order rule sequences the late send.
    enforceSendOrder(false);
    holdNextSend();
    send(&bob_client, cid, 1, "late").await.unwrap_err();
    for n in 2..=11 {
        send(&bob_client, cid, n, &format!("newer {n}"))
            .await
            .unwrap();
    }
    deliverHeld();
    drop(bob_client);
    let bob_signer = device_signer(&account_db(&bob));
    let late = resigned(
        &entry_at(cid, 12),
        CanonicalOperation::SendMessage,
        &bob_signer,
        |body| body["sendCounter"] = json!(11),
    );
    setEntry(cid, &late.to_string());
    let bob_client = open(&bob, BOB_DEVICE).await;
    bob_client
        .remove_group_member(true, cid.into(), carol.clone())
        .await
        .unwrap();
    assert_eq!(
        entry_at(cid, 13)["$type"],
        "blue.catbird.chat.defs#commitEntry"
    );

    alice_client
        .sync()
        .await
        .expect("an undecryptable entry no longer stops sync");
    let mut expected: Vec<(i64, String)> = (2..=11).map(|n| (n, format!("newer {n}"))).collect();
    expected.push((12, chat_wire::UNDECRYPTABLE_MESSAGE_NOTICE.into()));
    assert_eq!(timeline(&alice_client, cid), expected);
    let rows: Vec<MessageRow> =
        serde_wasm_bindgen::from_value(alice_client.list_messages(cid.into(), None, 50).unwrap())
            .unwrap();
    let gap = rows.iter().find(|row| row.seq == 12).unwrap();
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
        (13, 2, 11),
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
        (12, 1, "TooDistantInThePast", bob.as_str(), BOB_DEVICE)
    );
}

/// A v2 `accountDeletedEntry` the sequencer signs under `#mls-receipt-1`, or unsigned.
fn account_deletion_entry(cid: &str, deleted_did: &str, seq: u64, signed: bool) -> Value {
    let entry_id = uuid::Uuid::new_v4().to_string();
    let received_at = "2026-11-07T12:00:00.000Z";
    let mut entry = json!({
        "$type": "blue.catbird.chat.defs#accountDeletedEntry",
        "conversationId": cid, "deletedDid": deleted_did, "entryId": entry_id,
        "receivedAt": received_at, "sequencerDid": SEQUENCER, "seq": seq,
    });
    if signed {
        use p256::ecdsa::signature::Signer as _;
        let key_id = receipt_kid(1);
        let seq_text = seq.to_string();
        let mut transcript = b"catbird-mls-account-deletion-authority-v2\0".to_vec();
        let field = |bytes: &mut Vec<u8>, text: &str| {
            bytes.extend_from_slice(&(text.len() as u32).to_be_bytes());
            bytes.extend_from_slice(text.as_bytes());
        };
        field(&mut transcript, &key_id);
        transcript.extend_from_slice(b"catbird-mls-account-deletion-v1\0");
        for text in [
            SEQUENCER,
            cid,
            deleted_did,
            seq_text.as_str(),
            entry_id.as_str(),
            received_at,
        ] {
            field(&mut transcript, text);
        }
        let signature: p256::ecdsa::Signature = sequencer_key(1).sign(&transcript);
        let signature = signature.normalize_s().unwrap_or(signature);
        entry["sequencerAuthority"] = json!({
            "sequencerDid": SEQUENCER, "keyId": key_id,
            "signature": STANDARD.encode(signature.to_bytes()),
        });
    }
    entry
}

/// Labyrinth archive is paused, so sync's queue flush leaves every queued row in place.
fn pause_archive(did: &str) {
    let db = account_db(did);
    let raw = db
        .backend()
        .get_labyrinth_state("status_json")
        .unwrap()
        .expect("enrollment writes the archive status");
    let mut status: Value = serde_json::from_slice(&raw).unwrap();
    status["backup_enabled"] = json!(false);
    db.write_tx(|tx| {
        tx.put_labyrinth_state("status_json", &serde_json::to_vec(&status).unwrap(), 0)
    })
    .unwrap();
}

/// A batch whose receipts span a sequencer receipt-key rotation verifies each receipt under the
/// retained method its own `kid` names (G3). Fail-before: the whole batch reused the first
/// receipt's key, so the `#mls-receipt-2` entry failed and sync stopped there.
#[wasm_bindgen_test]
async fn a_batch_spanning_a_receipt_key_rotation_verifies_each_receipt_kid() {
    let _restore = install_ds();
    let (alice, bob) = (did("rotalice"), did("rotbob"));
    let cid = "00000000-0000-4000-8000-0000000c0005";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    send(&bob_client, cid, 1, "under key one").await.unwrap();
    useReceiptKey(2);
    send(&bob_client, cid, 2, "under key two").await.unwrap();
    alice_client
        .sync()
        .await
        .expect("each receipt verifies under its own kid");
    assert_eq!(
        timeline(&alice_client, cid),
        timeline_of(&[(2, "under key one"), (3, "under key two")])
    );
}

/// An undecryptable entry is tombstoned only once it proves itself without its plaintext: its
/// `I13` receipt must sequence exactly that entry. Fail-before: a gap row was written and the
/// cursor moved past an entry whose receipt was forged.
#[wasm_bindgen_test]
async fn an_undecryptable_entry_with_a_forged_receipt_is_never_tombstoned() {
    let _restore = install_ds();
    let (alice, bob) = (did("forgedgapalice"), did("forgedgapbob"));
    let cid = "00000000-0000-4000-8000-0000000c0006";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    enforceSendOrder(false);
    holdNextSend();
    send(&bob_client, cid, 1, "late").await.unwrap_err();
    for n in 2..=11 {
        send(&bob_client, cid, n, &format!("newer {n}"))
            .await
            .unwrap();
    }
    deliverHeld();
    drop(bob_client);
    let bob_signer = device_signer(&account_db(&bob));
    let late = resigned(
        &entry_at(cid, 12),
        CanonicalOperation::SendMessage,
        &bob_signer,
        |body| body["sendCounter"] = json!(11),
    );
    setEntry(cid, &late.to_string());
    tamperReceipt(cid, 12);
    let error = alice_client
        .sync()
        .await
        .expect_err("a forged receipt never records a gap")
        .as_string()
        .unwrap_or_default();
    assert!(error.contains("I13"), "{error}");
    let expected: Vec<(i64, String)> = (2..=11).map(|n| (n, format!("newer {n}"))).collect();
    assert_eq!(timeline(&alice_client, cid), expected, "no gap row");
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 11);
}

/// A full application entry with its receipt removed is refused without state, cursor,
/// coordinate or acknowledgement change. A pruned entry keeps only its signed receipt, which
/// must sequence exactly that entry before the cursor passes it.
#[wasm_bindgen_test]
async fn a_pruned_entry_moves_the_cursor_only_under_its_verified_receipt() {
    let _restore = install_ds();
    let (alice, bob) = (did("prunealice"), did("prunebob"));
    let cid = "00000000-0000-4000-8000-0000000c0007";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    drop(alice_client);
    let initial_coords = stored_coords(&alice, cid);
    let mut alice_client = open(&alice, ALICE_DEVICE).await;
    send(&bob_client, cid, 1, "pruned before delivery")
        .await
        .unwrap();
    let genuine = entry_at(cid, 2);
    let mut receiptless = genuine.clone();
    receiptless
        .as_object_mut()
        .unwrap()
        .remove("sequencerReceipt");
    setEntry(cid, &receiptless.to_string());
    alice_client
        .sync()
        .await
        .expect_err("a full application entry without its receipt");
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 1);
    assert_eq!(ackedUpTo(cid, ALICE_DEVICE), 0);
    assert!(timeline(&alice_client, cid).is_empty());
    drop(alice_client);
    assert_eq!(stored_coords(&alice, cid), initial_coords);
    alice_client = open(&alice, ALICE_DEVICE).await;

    setEntry(cid, &genuine.to_string());
    pruneEntry(cid, 2);
    alice_client
        .sync()
        .await
        .expect("a pruned entry under its receipt");
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 2);
    assert!(timeline(&alice_client, cid).is_empty());

    let forged = json!({
        "$type": "blue.catbird.chat.defs#applicationEntry",
        "entryId": message_id(2), "conversationId": cid,
        "payloadPruned": true, "receivedAt": "2026-11-07T00:00:00.000Z",
    });
    assert_eq!(appendEntry(cid, &forged.to_string()), 3);
    alice_client
        .sync()
        .await
        .expect_err("a pruned entry without its receipt");
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 2);
}

/// A stored message re-presented under another seq must prove that seq with its own receipt
/// against the retained evidence. Fail-before: any stored message id moved the cursor
/// unverified.
#[wasm_bindgen_test]
async fn a_stored_message_replayed_at_another_seq_never_moves_the_cursor() {
    let _restore = install_ds();
    let (alice, bob) = (did("replayalice"), did("replaybob"));
    let cid = "00000000-0000-4000-8000-0000000c0008";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    send(&bob_client, cid, 1, "once").await.unwrap();
    alice_client.sync().await.unwrap();
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 2);
    assert_eq!(replayEntry(cid, 2), 3);
    let error = alice_client
        .sync()
        .await
        .expect_err("its receipt sequences seq 2, not 3")
        .as_string()
        .unwrap_or_default();
    assert!(error.contains("I13"), "{error}");
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 2);
    assert_eq!(timeline(&alice_client, cid), timeline_of(&[(2, "once")]));
}

/// Without the conversation's MLS group there is no roster to authenticate an entry against:
/// the row reads none of its entries, so nothing is applied or acknowledged. Fail-before: the
/// entry counted as applied, the cursor moved and its seq was acknowledged to `mls-ds`.
#[wasm_bindgen_test]
async fn an_entry_without_its_mls_group_is_never_acknowledged() {
    let _restore = install_ds();
    let (alice, bob) = (did("nogroupalice"), did("nogroupbob"));
    let cid = "00000000-0000-4000-8000-0000000c0009";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    send(&bob_client, cid, 1, "unreadable here").await.unwrap();
    drop(alice_client);
    account_db(&alice)
        .write_tx(|tx| {
            let mut row = tx.get_conversation(cid)?.unwrap();
            row.group_id = vec![7; 32];
            tx.upsert_conversation(&row)
        })
        .unwrap();
    let alice_client = open(&alice, ALICE_DEVICE).await;
    // Its sync owes only Alice's own recovery request, from a state this fixture leaves without
    // coordinates: that request is never signed either.
    alice_client
        .sync()
        .await
        .expect_err("no group, nothing applied");
    assert_eq!(ackCount(), 0, "nothing acknowledged");
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 1);
}

/// Sequencer authority alone never authorizes deletion: missing or forged actor authority and
/// cross-conversation evidence remain quarantined, purge nothing, and hold the cursor.
#[wasm_bindgen_test]
async fn account_deletions_remain_quarantined_without_historical_nonrevocation() {
    let _restore = install_ds();
    let (alice, bob, carol) = (did("deletealice"), did("deletebob"), did("deletecarol"));
    let cid = "00000000-0000-4000-8000-0000000c000a";
    let other_cid = "00000000-0000-4000-8000-0000000c000f";
    let members = [
        (alice.as_str(), ALICE_DEVICE),
        (bob.as_str(), BOB_DEVICE),
        (carol.as_str(), CAROL_DEVICE),
    ];
    let mut clients = group(&members, cid).await.into_iter();
    let (alice_client, bob_client, carol_client) = (
        clients.next().unwrap(),
        clients.next().unwrap(),
        clients.next().unwrap(),
    );
    send(&bob_client, cid, 1, "from a living account")
        .await
        .unwrap();
    alice_client.sync().await.unwrap();

    let unsigned = account_deletion_entry(cid, &bob, 3, false);
    assert_eq!(appendEntry(cid, &unsigned.to_string()), 3);
    send(&carol_client, cid, 2, "after the deletion")
        .await
        .unwrap();
    alice_client
        .sync()
        .await
        .expect_err("malformed sequencer authority must stop sync");
    assert_eq!(
        timeline(&alice_client, cid),
        timeline_of(&[(2, "from a living account")])
    );
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 2);

    let signed = account_deletion_entry(cid, &bob, 3, true);
    setEntry(cid, &signed.to_string());
    alice_client
        .sync()
        .await
        .expect_err("a sequencer signature without actor authority remains quarantined");
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 2);
    drop(alice_client);
    let db = account_db(&alice);
    let evidence_key = deletion_authority::unverified_deletion_key(cid, &bob, 3);
    let evidence: UnverifiedAccountDeletion = serde_json::from_slice(
        &db.backend()
            .get_labyrinth_state(&evidence_key)
            .unwrap()
            .expect("unverified deletion evidence"),
    )
    .unwrap();
    assert_eq!(evidence.reason, UnverifiedDeletionReason::NoActorWrite);
    assert!(db
        .backend()
        .get_labyrinth_state(&chat_wire::account_deletion_key(cid, &bob))
        .unwrap()
        .is_none());
    drop(db);
    let alice_client = open(&alice, ALICE_DEVICE).await;

    let mut forged = account_deletion_entry(cid, &bob, 3, true);
    let write_body = serde_json::to_vec(&json!({
        "operationId": "0123456789abcdef0123456789abcdef",
        "actorDeviceId": BOB_DEVICE,
        "endpointNsid": "blue.catbird.labyrinth.deleteAccountData",
        "payloadSha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        "signedAt": "2026-11-07T11:59:00.000Z",
    }))
    .unwrap();
    forged["actorWrite"] = json!({
        "writeBody": STANDARD.encode(write_body),
        "payloadBytes": STANDARD.encode(b"{}"),
        "signature": STANDARD.encode([0x55; 64]),
    });
    forged["keyProof"] = json!(STANDARD.encode([0x44; 32]));
    setEntry(cid, &forged.to_string());
    alice_client
        .sync()
        .await
        .expect_err("forged actor authority must remain quarantined");
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 2);
    assert_eq!(
        timeline(&alice_client, cid),
        timeline_of(&[(2, "from a living account")])
    );

    let elsewhere = account_deletion_entry(other_cid, &bob, 3, true);
    setEntry(cid, &elsewhere.to_string());
    alice_client
        .sync()
        .await
        .expect_err("cross-conversation deletion evidence must not advance this cursor");
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 2);
    assert_eq!(
        timeline(&alice_client, cid),
        timeline_of(&[(2, "from a living account")])
    );
    drop(alice_client);
    let db = account_db(&alice);
    let evidence: UnverifiedAccountDeletion = serde_json::from_slice(
        &db.backend()
            .get_labyrinth_state(&evidence_key)
            .unwrap()
            .expect("cross-conversation evidence"),
    )
    .unwrap();
    assert_eq!(evidence.reason, UnverifiedDeletionReason::OtherConversation);
}

/// Own-echo Commit labels are only a routing hint: the body must verify under this device's
/// signer before a Commit is skipped as already applied. Fail-before: an unsigned entry
/// labelled with Alice's device was skipped and moved her cursor.
#[wasm_bindgen_test]
async fn a_commit_only_labelled_as_an_own_echo_is_rejected() {
    let _restore = install_ds();
    let (alice, bob) = (did("echoalice"), did("echobob"));
    let cid = "00000000-0000-4000-8000-0000000c000b";
    let (alice_client, _bob_client) = conversation(&alice, &bob, cid).await;
    let forged = json!({
        "$type": "blue.catbird.chat.defs#commitEntry",
        "entryId": uuid::Uuid::new_v4().to_string(),
        "conversationId": cid,
        "signedRequest": {"body": {
            "$type": "blue.catbird.chat.defs#commitTransitionBody",
            "actorDid": alice, "actorDeviceId": ALICE_DEVICE,
            "commit": {"bytes": STANDARD.encode([0u8; 4])},
        }},
    });
    assert_eq!(appendEntry(cid, &forged.to_string()), 2);
    alice_client
        .sync()
        .await
        .expect_err("an unsigned own-echo label is not an own Commit");
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 1);
}

/// Device records are public: the session's bearer token never reaches the PDS a DID document
/// names, which may be a peer's. Fail-before: every `listRecords` carried the session bearer.
#[wasm_bindgen_test]
async fn pds_record_reads_never_carry_the_session_bearer() {
    let _restore = install_ds();
    let (alice, bob) = (did("beareralice"), did("bearerbob"));
    let cid = "00000000-0000-4000-8000-0000000c000c";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    send(&bob_client, cid, 1, "hello").await.unwrap();
    alice_client.sync().await.unwrap();
    let auth: Vec<Option<String>> = serde_json::from_str(&repoReadAuth()).unwrap();
    assert!(!auth.is_empty(), "sync read device records");
    assert!(auth.iter().all(Option::is_none), "{auth:?}");
}

/// A received peer message is queued as a witness copy carrying its verified frame nonce,
/// receipt and original-sender attestation, so pre-removal history never depends on its
/// sender flushing (G11). Fail-before: only a sender's own device ever queued a copy.
#[wasm_bindgen_test]
async fn a_received_peer_message_is_queued_as_a_witness_copy() {
    let _restore = install_ds();
    let (alice, bob) = (did("witnessalice"), did("witnessbob"));
    let cid = "00000000-0000-4000-8000-0000000c000d";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    send(&bob_client, cid, 1, "witness me").await.unwrap();
    drop(alice_client);
    pause_archive(&alice);
    let alice_client = open(&alice, ALICE_DEVICE).await;
    alice_client.sync().await.unwrap();
    drop(alice_client);
    let queued = account_db(&alice)
        .backend()
        .list_labyrinth_queue(Some(cid), 10)
        .unwrap();
    assert_eq!(
        queued
            .iter()
            .map(|row| (row.item_id.as_str(), row.seq))
            .collect::<Vec<_>>(),
        [(message_id(1).as_str(), 2)]
    );
    let witness: QueuedLabyrinthArchivePayload =
        serde_json::from_slice(&queued[0].payload_bytes).unwrap();
    assert_eq!(
        (witness.sender_did.as_str(), witness.seq),
        (bob.as_str(), 2)
    );
    assert!(
        witness.frame_nonce_b64.is_some()
            && witness.sequencer_receipt_json.is_some()
            && witness.original_sender_attestation_json.is_some(),
        "committed archive evidence"
    );
}

/// An entry sync cannot classify stops it there, below the cursor: an application entry
/// without a message id, an opening (`directRequestEntry`) past the cursor, and an entry of no
/// known kind, each followed by Bob's genuine message. Fail-before: each was skipped and the
/// later message moved the cursor past it.
#[wasm_bindgen_test]
async fn an_unclassifiable_entry_stops_sync_below_it() {
    let _restore = install_ds();
    let (alice, bob) = (did("unknownalice"), did("unknownbob"));
    let cid = "00000000-0000-4000-8000-0000000c000e";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    let received_at = "2026-11-07T00:00:00.000Z";
    let cases = [
        (
            "an application entry without a message id",
            json!({
                "$type": "blue.catbird.chat.defs#applicationEntry", "seq": 2,
                "conversationId": cid, "receivedAt": received_at,
                "signedRequest": {"body": {"$type": "blue.catbird.chat.defs#applicationSendBody"}},
            }),
        ),
        (
            "an opening past the cursor",
            json!({
                "$type": "blue.catbird.chat.defs#directRequestEntry", "seq": 2,
                "entryId": message_id(9), "conversationId": cid, "receivedAt": received_at,
                "signedRequest": {"body": {
                    "$type": "blue.catbird.chat.defs#directRequestPublicationBody",
                }},
            }),
        ),
        (
            "an entry of no known kind",
            json!({
                "$type": "blue.catbird.chat.defs#mysteryEntry", "seq": 2,
                "entryId": message_id(9), "conversationId": cid, "receivedAt": received_at,
            }),
        ),
    ];
    assert_eq!(appendEntry(cid, &cases[0].1.to_string()), 2);
    send(&bob_client, cid, 1, "after it").await.unwrap();
    for (case, entry) in cases {
        setEntry(cid, &entry.to_string());
        alice_client.sync().await.expect_err(case);
        assert_eq!(conversation_row(&alice_client, cid).last_seq, 1, "{case}");
        assert!(timeline(&alice_client, cid).is_empty(), "{case}");
    }
}

/// A peer Commit applies only from its verified signed body and `I13` receipt: the receipt is
/// present, signed, bound to this entry's seq and request digest; the body verifies under its
/// actor's current leaf; the MLS Commit is that very leaf's; and its signed `next` names the
/// merged local state one `stateVersion` on. Missing, forged and wrong-seq receipts, a body
/// altered after signing, another leaf's signature and a skipped state version all leave Alice
/// at seq 1. The genuine entry then merges. Fail-before: control entries needed no receipt and
/// sync processed whatever Commit an entry carried.
#[wasm_bindgen_test]
async fn a_peer_commit_applies_only_from_its_verified_body() {
    let _restore = install_ds();
    let (alice, bob, carol) = (did("commitalice"), did("commitbob"), did("commitcarol"));
    let cid = "00000000-0000-4000-8000-0000000c000f";
    let members = [
        (alice.as_str(), ALICE_DEVICE),
        (bob.as_str(), BOB_DEVICE),
        (carol.as_str(), CAROL_DEVICE),
    ];
    let mut clients = group(&members, cid).await.into_iter();
    let (alice_client, bob_client) = (clients.next().unwrap(), clients.next().unwrap());
    drop(clients);
    bob_client
        .remove_group_member(true, cid.into(), carol.clone())
        .await
        .unwrap();
    drop(bob_client);
    let genuine = entry_at(cid, 2);
    let mut missing_receipt = genuine.clone();
    missing_receipt
        .as_object_mut()
        .unwrap()
        .remove("sequencerReceipt");
    let mut forged_receipt = genuine.clone();
    forged_receipt["sequencerReceipt"]["signature"] = json!(STANDARD.encode([0_u8; 64]));
    let mut wrong_seq_receipt = genuine.clone();
    wrong_seq_receipt["sequencerReceipt"] = serde_json::from_str(&receipt_for(
        json!({
            "body": genuine["signedRequest"]["body"],
            "seq": 3,
            "entryId": genuine["entryId"],
            "control": true,
            "keyGeneration": 1,
        })
        .to_string(),
    ))
    .unwrap();
    for (case, entry) in [
        ("missing I13 receipt", missing_receipt),
        ("forged I13 receipt", forged_receipt),
        ("I13 receipt bound to another seq", wrong_seq_receipt),
    ] {
        setEntry(cid, &entry.to_string());
        let error = alice_client
            .sync()
            .await
            .expect_err(case)
            .as_string()
            .unwrap_or_default();
        assert!(error.contains("I13"), "{case}: {error}");
        assert_eq!(
            (
                conversation_row(&alice_client, cid).epoch,
                conversation_row(&alice_client, cid).last_seq
            ),
            (1, 1),
            "{case}"
        );
        assert_eq!(ackedUpTo(cid, ALICE_DEVICE), 0, "{case}");
    }
    let (bob_signer, carol_signer) = (
        device_signer(&account_db(&bob)),
        device_signer(&account_db(&carol)),
    );
    let carols = resigned(
        &genuine,
        CanonicalOperation::SubmitTransition,
        &carol_signer,
        |body| {
            body["actorDid"] = json!(carol);
            body["actorDeviceId"] = json!(CAROL_DEVICE);
        },
    );
    let skipping = resigned(
        &genuine,
        CanonicalOperation::SubmitTransition,
        &bob_signer,
        |body| body["next"]["stateVersion"] = json!(2),
    );
    for (case, entry) in [
        ("altered after signing", altered(&genuine)),
        ("Bob's Commit in Carol's body", carols),
        ("a next two versions on", skipping),
    ] {
        setEntry(cid, &entry.to_string());
        alice_client.sync().await.expect_err(case);
        let row = conversation_row(&alice_client, cid);
        assert_eq!((row.epoch, row.last_seq), (1, 1), "{case}");
    }
    setEntry(cid, &genuine.to_string());
    alice_client.sync().await.unwrap();
    let row = conversation_row(&alice_client, cid);
    assert_eq!((row.epoch, row.last_seq), (2, 2));
    drop(alice_client);
    assert_eq!(
        stored_coords(&alice, cid),
        Some(canonical(&genuine["signedRequest"]["body"]["next"], cid))
    );
}

/// A policy entry applies only under a current leaf, one `stateVersion` on. Alice invites
/// Dave; Bob is served her policy altered after signing, signed by Dave (no leaf), and re-signed
/// with a `next` two versions on: each fails his sync with his cursor at 1 and his initial
/// coordinates unchanged. The genuine policy then writes its signed `next`. Fail-before: any
/// policy entry moved the cursor and none wrote its coordinates.
#[wasm_bindgen_test]
async fn a_policy_entry_applies_only_under_a_current_leaf() {
    let _restore = install_ds();
    let (alice, bob, dave) = (did("policyalice"), did("policybob"), did("policydave"));
    let cid = "00000000-0000-4000-8000-0000000c0010";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    drop(bob_client);
    let initial = stored_coords(&bob, cid);
    let bob_client = open(&bob, BOB_DEVICE).await;
    enroll(&dave, DAVE_DEVICE).await;
    alice_client
        .add_group_members(cid.into(), serde_wasm_bindgen::to_value(&[&dave]).unwrap())
        .await
        .unwrap();
    drop(alice_client);
    let genuine = entry_at(cid, 2);
    assert_eq!(genuine["$type"], "blue.catbird.chat.defs#policyEntry");
    let (alice_signer, dave_signer) = (
        device_signer(&account_db(&alice)),
        device_signer(&account_db(&dave)),
    );
    let daves = resigned(
        &genuine,
        CanonicalOperation::SubmitTransition,
        &dave_signer,
        |body| {
            body["actorDid"] = json!(dave);
            body["actorDeviceId"] = json!(DAVE_DEVICE);
        },
    );
    let skipping = resigned(
        &genuine,
        CanonicalOperation::SubmitTransition,
        &alice_signer,
        |body| body["next"]["stateVersion"] = json!(2),
    );
    for (case, entry) in [
        ("altered after signing", altered(&genuine)),
        ("signed by no leaf", daves),
        ("a next two versions on", skipping),
    ] {
        setEntry(cid, &entry.to_string());
        bob_client.sync().await.expect_err(case);
        assert_eq!(conversation_row(&bob_client, cid).last_seq, 1, "{case}");
    }
    drop(bob_client);
    assert_eq!(stored_coords(&bob, cid), initial);
    setEntry(cid, &genuine.to_string());
    let bob_client = open(&bob, BOB_DEVICE).await;
    bob_client.sync().await.unwrap();
    assert_eq!(conversation_row(&bob_client, cid).last_seq, 2);
    drop(bob_client);
    assert_eq!(
        stored_coords(&bob, cid),
        Some(canonical(&genuine["signedRequest"]["body"]["next"], cid))
    );
}

/// `inviter` invites a cross-home `invitee` to `cid`, standing at seq 1 (the policy entry at
/// seq 2), and `invitee`'s client on `device` accepts from its inventory (the participant
/// acceptance at seq 3), whereupon mls-ds lists the acceptance's add recovery.
async fn accept_invitation(inviter: &WasmMlsClient, invitee: &str, device: &str, cid: &str) {
    assert_ne!(CROSS_HOME_DS, SEQUENCER);
    enroll_at_home(invitee, device, CROSS_HOME_DS).await;
    inviter
        .add_group_members(
            cid.into(),
            serde_wasm_bindgen::to_value(&[invitee]).unwrap(),
        )
        .await
        .unwrap();
    let policy = entry_at(cid, 2);
    let body = &policy["signedRequest"]["body"];
    let pending = json!({
        "userDid": invitee, "status": "pending",
        "invitationProvenance": body["participantChanges"][0]["invitationProvenance"],
    });
    let state = json!({
        "conversationKind": "group", "sequencerDid": SEQUENCER,
        "coordinates": body["next"], "participants": [pending],
    });
    serveInventory(device, &json!([{ "state": state }]).to_string());
    open_at_home(invitee, device, CROSS_HOME_DS)
        .await
        .sync()
        .await
        .unwrap();
    serveInventory(device, "[]");
    let acceptance = entry_at(cid, 3);
    assert_eq!(
        acceptance["$type"],
        "blue.catbird.chat.defs#participantAcceptanceEntry"
    );
    assert_eq!(acceptance["sequencerReceipt"]["sequencerDid"], SEQUENCER);
}

/// Alice and Bob's conversation, in which Alice invites Dave and Dave accepts
/// ([`accept_invitation`]). Returns Bob's client.
async fn invitation_accepted(alice: &str, bob: &str, dave: &str, cid: &str) -> WasmMlsClient {
    let (alice_client, bob_client) = conversation(alice, bob, cid).await;
    accept_invitation(&alice_client, dave, DAVE_DEVICE, cid).await;
    bob_client
}

/// A participant acceptance applies only under its actor's PDS-authorized device, one
/// `stateVersion` on, and only when the invitation its signed provenance names verifies under
/// its inviter's device, its historical `I13` receipt and sequence, and names exactly that actor
/// and provenance. Bob's cursor already stands after Alice's policy, so missing, forged and
/// closure-crossing relabelled policy receipts are exercised only through the historical lookup.
/// Those, plus altered or wrongly attributed acceptances, fail with cursor, coordinates and
/// roster unchanged. The genuine pending invitation then succeeds.
///
/// Fail-before: the historical lookup ignored its invitation receipt, and an otherwise invalid
/// participant acceptance could move the cursor and coordinates.
#[wasm_bindgen_test]
async fn a_participant_acceptance_applies_only_under_its_verified_invitation() {
    let _restore = install_ds();
    let (alice, bob, dave, erin) = (
        did("acceptalice"),
        did("acceptbob"),
        did("acceptdave"),
        did("accepterin"),
    );
    let cid = "00000000-0000-4000-8000-0000000c0011";
    let bob_client = invitation_accepted(&alice, &bob, &dave, cid).await;
    drop(bob_client);
    let policy = entry_at(cid, 2);
    let policy_next = canonical(&policy["signedRequest"]["body"]["next"], cid);
    account_db(&bob)
        .write_tx(|tx| {
            let mut row = tx.get_conversation(cid)?.unwrap();
            row.last_seq = 2;
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{cid}"),
                &policy_next.to_string(),
                0,
            )
        })
        .unwrap();
    enroll(&erin, ERIN_DEVICE).await;
    let genuine = entry_at(cid, 3);
    let local_state = || {
        let db = account_db(&bob);
        let backend = db.backend();
        (
            backend.get_conversation(cid).unwrap().unwrap().last_seq,
            backend
                .get_account_meta(&format!("conversation_coords:{cid}"))
                .unwrap(),
            backend
                .get_account_meta(&chat_wire::conversation_roster_key(cid))
                .unwrap(),
            backend
                .get_account_meta(&chat_wire::leaf_recovery_authorization_key(cid))
                .unwrap(),
        )
    };
    let mut historical_missing = policy.clone();
    historical_missing
        .as_object_mut()
        .unwrap()
        .remove("sequencerReceipt");
    let mut historical_forged = policy.clone();
    historical_forged["sequencerReceipt"]["signature"] = json!(STANDARD.encode([9u8; 64]));
    let mut relabelled_after_closure = policy.clone();
    relabelled_after_closure["sequencerReceipt"] = serde_json::from_str(&receipt_for(
        json!({
            "body": policy["signedRequest"]["body"],
            "seq": 1,
            "entryId": policy["entryId"],
            "control": true,
            "keyGeneration": 1,
        })
        .to_string(),
    ))
    .unwrap();
    for (case, invitation, closed) in [
        (
            "missing historical invitation receipt",
            historical_missing,
            false,
        ),
        (
            "forged historical invitation receipt",
            historical_forged,
            false,
        ),
        (
            "invitation relabelled after closure",
            relabelled_after_closure,
            true,
        ),
    ] {
        setEntry(cid, &invitation.to_string());
        if closed {
            account_db(&bob)
                .write_tx(|tx| {
                    tx.put_account_meta(&chat_wire::invitation_closed_key(cid, &dave), "1", 0)
                })
                .unwrap();
        }
        let before = local_state();
        let bob_client = open(&bob, BOB_DEVICE).await;
        let error = bob_client
            .sync()
            .await
            .expect_err(case)
            .as_string()
            .unwrap_or_default();
        drop(bob_client);
        assert!(error.contains("I13"), "{case}: {error}");
        assert_eq!(local_state(), before, "{case}");
        setEntry(cid, &policy.to_string());
        account_db(&bob)
            .write_tx(|tx| tx.delete_account_meta(&chat_wire::invitation_closed_key(cid, &dave)))
            .unwrap();
    }
    let mut missing_receipt = genuine.clone();
    missing_receipt
        .as_object_mut()
        .unwrap()
        .remove("sequencerReceipt");
    let (dave_signer, erin_signer) = (
        device_signer(&account_db(&dave)),
        device_signer(&account_db(&erin)),
    );
    let accept = CanonicalOperation::AcceptConversation;
    let uninvited = resigned(&genuine, accept, &erin_signer, |body| {
        body["actorDid"] = json!(erin);
        body["actorDeviceId"] = json!(ERIN_DEVICE);
    });
    let misattributed = resigned(&genuine, accept, &dave_signer, |body| {
        body["invitationProvenance"]["invitedByDid"] = json!(bob);
        body["invitationProvenance"]["invitedByDeviceId"] = json!(BOB_DEVICE);
    });
    let skipping = resigned(&genuine, accept, &dave_signer, |body| {
        body["next"]["stateVersion"] = json!(3);
    });
    let bob_client = open(&bob, BOB_DEVICE).await;
    for (case, entry) in [
        ("missing I13 receipt", missing_receipt),
        ("altered after signing", altered(&genuine)),
        ("an actor nobody invited", uninvited),
        ("another inviter's provenance", misattributed),
        ("a next two versions on", skipping),
    ] {
        setEntry(cid, &entry.to_string());
        bob_client.sync().await.expect_err(case);
        assert_eq!(conversation_row(&bob_client, cid).last_seq, 2, "{case}");
    }
    drop(bob_client);
    assert_eq!(stored_coords(&bob, cid), Some(policy_next));
    setEntry(cid, &genuine.to_string());
    // mls-ds lists no recovery for Dave here: the acceptance alone applies.
    serveRecoveries(cid, "[]");
    let bob_client = open(&bob, BOB_DEVICE).await;
    bob_client.sync().await.unwrap();
    assert_eq!(conversation_row(&bob_client, cid).last_seq, 3);
    drop(bob_client);
    assert_eq!(
        stored_coords(&bob, cid),
        Some(canonical(&genuine["signedRequest"]["body"]["next"], cid))
    );
}

/// mls-ds never makes a later joiner a recipient of control entries before it joined: when
/// a device's readable history starts after seq 1 and lacks the invitation, the acceptance's
/// device signature and coordinate step stand alone. Bob joined at seq 2 and reads from seq 3:
/// Dave's acceptance applies. Once his history reaches seq 1, an acceptance naming an invitation
/// that history lacks fails his sync. Fail-before: that acceptance applied unverified.
#[wasm_bindgen_test]
async fn a_later_joiner_takes_an_acceptance_whose_invitation_predates_its_history() {
    let _restore = install_ds();
    let (alice, bob, dave) = (did("joineralice"), did("joinerbob"), did("joinerdave"));
    let cid = "00000000-0000-4000-8000-0000000c0012";
    drop(invitation_accepted(&alice, &bob, &dave, cid).await);
    let policy = canonical(&entry_at(cid, 2)["signedRequest"]["body"]["next"], cid);
    account_db(&bob)
        .write_tx(|tx| {
            let mut row = tx.get_conversation(cid)?.unwrap();
            row.last_seq = 2;
            tx.upsert_conversation(&row)?;
            tx.put_account_meta(
                &format!("conversation_coords:{cid}"),
                &policy.to_string(),
                0,
            )
        })
        .unwrap();
    readableFrom(BOB_DEVICE, 3);
    let bob_client = open(&bob, BOB_DEVICE).await;
    bob_client
        .sync()
        .await
        .expect("its signature and step stand alone");
    assert_eq!(conversation_row(&bob_client, cid).last_seq, 3);

    readableFrom(BOB_DEVICE, 0);
    let creation = json!({
        "$type": "blue.catbird.chat.defs#creationEntry", "seq": 1,
        "entryId": uuid::Uuid::new_v4().to_string(), "conversationId": cid,
        "receivedAt": "2026-11-07T00:00:00.000Z",
    });
    setEntry(cid, &creation.to_string());
    let genuine = entry_at(cid, 3);
    let unknown = resigned(
        &genuine,
        CanonicalOperation::AcceptConversation,
        &device_signer(&account_db(&dave)),
        |body| {
            body["prior"] = body["next"].clone();
            body["next"]["stateVersion"] = json!(3);
            body["invitationProvenance"]["invitationTransitionId"] =
                json!(uuid::Uuid::new_v4().to_string());
        },
    );
    assert_eq!(appendEntry(cid, &unknown.to_string()), 4);
    bob_client
        .sync()
        .await
        .expect_err("history from seq 1 lacks the invitation");
    assert_eq!(conversation_row(&bob_client, cid).last_seq, 3);
}

/// A metadata entry applies only under a current leaf, one `stateVersion` on, and its snapshot
/// only from the verified body. Bob renames the conversation; Alice is served his entry altered
/// after signing, signed by Dave (no leaf), and re-signed two versions on: each fails her sync
/// with no title or snapshot, her initial coordinates unchanged and her cursor at 1. The genuine
/// entry then applies. Fail-before: any metadata entry applied its snapshot and coordinates
/// unverified.
#[wasm_bindgen_test]
async fn forged_metadata_never_changes_the_snapshot_or_coordinates() {
    let _restore = install_ds();
    let (alice, bob, dave) = (did("metaalice"), did("metabob"), did("metadave"));
    let cid = "00000000-0000-4000-8000-0000000c0013";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    drop(alice_client);
    let initial = stored_coords(&alice, cid);
    let alice_client = open(&alice, ALICE_DEVICE).await;
    enroll(&dave, DAVE_DEVICE).await;
    bob_client
        .update_group_metadata(cid.into(), "renamed".into(), String::new())
        .await
        .unwrap();
    drop(bob_client);
    let genuine = entry_at(cid, 2);
    assert_eq!(genuine["$type"], "blue.catbird.chat.defs#metadataEntry");
    let (bob_signer, dave_signer) = (
        device_signer(&account_db(&bob)),
        device_signer(&account_db(&dave)),
    );
    let daves = resigned(
        &genuine,
        CanonicalOperation::SubmitTransition,
        &dave_signer,
        |body| {
            body["actorDid"] = json!(dave);
            body["actorDeviceId"] = json!(DAVE_DEVICE);
        },
    );
    let skipping = resigned(
        &genuine,
        CanonicalOperation::SubmitTransition,
        &bob_signer,
        |body| body["next"]["stateVersion"] = json!(2),
    );
    for (case, entry) in [
        ("altered after signing", altered(&genuine)),
        ("signed by no leaf", daves),
        ("a next two versions on", skipping),
    ] {
        setEntry(cid, &entry.to_string());
        alice_client.sync().await.expect_err(case);
        let row = conversation_row(&alice_client, cid);
        assert_eq!((row.title, row.last_seq), (None, 1), "{case}");
    }
    drop(alice_client);
    let snapshot = |account: &str| {
        account_db(account)
            .backend()
            .get_account_meta(&format!("metadata_snapshot_json:{cid}"))
            .unwrap()
    };
    assert_eq!(
        (stored_coords(&alice, cid), snapshot(&alice)),
        (initial, None)
    );
    setEntry(cid, &genuine.to_string());
    let alice_client = open(&alice, ALICE_DEVICE).await;
    alice_client.sync().await.unwrap();
    let row = conversation_row(&alice_client, cid);
    assert_eq!((row.title.as_deref(), row.last_seq), (Some("renamed"), 2));
    drop(alice_client);
    let body = &genuine["signedRequest"]["body"];
    assert_eq!(
        stored_coords(&alice, cid),
        Some(canonical(&body["next"], cid))
    );
    assert_eq!(
        snapshot(&alice).map(|raw| serde_json::from_str::<Value>(&raw).unwrap()),
        Some(body["metadataSnapshot"].clone())
    );
}

/// A verified close is applied as the terminal close: the MLS group and its journals are
/// erased, the signed `retired` coordinate and the closed marker written, the cursor moved and
/// nothing acknowledged; later syncs skip the conversation. A close retiring two versions on
/// fails Alice's sync first with nothing changed. Fail-before: a close only moved the cursor,
/// so the conversation was never closed on web.
#[wasm_bindgen_test]
async fn a_verified_close_is_applied_as_the_terminal_close() {
    let _restore = install_ds();
    let (alice, bob) = (did("closealice"), did("closebob"));
    let cid = "00000000-0000-4000-8000-0000000c0014";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    drop(bob_client);
    let bob_signer = device_signer(&account_db(&bob));
    let prior = group_coords(&bob, cid);
    let close = |retired_version: i64| {
        let mut retired = prior.clone();
        retired["stateVersion"] = json!(retired_version);
        retired["lifecycle"] = json!("superseded");
        let transition = uuid::Uuid::new_v4().to_string();
        let body = json!({
            "$type": "blue.catbird.chat.defs#conversationCloseBody",
            "signatureDomain": "CATBIRD-CHAT-CLOSE\0",
            "transitionId": transition, "idempotencyKey": transition,
            "actorDid": bob, "actorDeviceId": BOB_DEVICE, "authGeneration": 1,
            "conversationKind": "group", "prior": prior, "retired": retired,
            "signedAt": chat_wire::now_rfc3339_millis(),
        });
        let entry = with_current_receipt(json!({
            "$type": "blue.catbird.chat.defs#conversationCloseEntry", "seq": 2,
            "entryId": transition, "conversationId": cid,
            "receivedAt": "2026-11-07T00:00:00.000Z",
            "signedRequest": signed(CanonicalOperation::CloseConversation, body, &bob_signer),
        }));
        (entry, retired)
    };
    let (skipping, _) = close(2);
    setEntry(cid, &skipping.to_string());
    alice_client
        .sync()
        .await
        .expect_err("a close retiring two versions on");
    let row = conversation_row(&alice_client, cid);
    assert_eq!((row.epoch, row.last_seq), (1, 1));

    let (genuine, retired) = close(1);
    setEntry(cid, &genuine.to_string());
    alice_client.sync().await.unwrap();
    assert_eq!(conversation_row(&alice_client, cid).last_seq, 2);
    assert_eq!(
        alice_client.sync().await.unwrap(),
        0,
        "a closed conversation is skipped"
    );
    assert_eq!(ackCount(), 0, "nothing acknowledged");
    drop(alice_client);
    assert_eq!(stored_coords(&alice, cid), Some(retired));
    let db = account_db(&alice);
    assert_eq!(
        db.backend()
            .get_account_meta(&format!("conversation_closed:{cid}"))
            .unwrap()
            .as_deref(),
        Some("true")
    );
    let group_id = db
        .backend()
        .get_conversation(cid)
        .unwrap()
        .unwrap()
        .group_id;
    let mls = db.openmls_provider().unwrap();
    assert!(
        MlsGroup::load(mls.storage(), &GroupId::from_slice(&group_id))
            .unwrap()
            .is_none()
    );
}

/// An own Commit whose answer was lost is merged by its own echo only from its journal: with
/// the Commit unmerged locally and no journal, the echo fails sync and writes nothing (never a
/// `next` over an unmerged epoch); with the journal, the echo applies it and erases it.
/// Fail-before: the echo wrote its `next` and moved the cursor with the epoch unmerged.
#[wasm_bindgen_test]
async fn an_unmerged_own_commit_echo_applies_only_its_journal() {
    let _restore = install_ds();
    let (alice, bob) = (did("journalalice"), did("journalbob"));
    let cid = "00000000-0000-4000-8000-0000000c0015";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    drop(alice_client);
    let initial = stored_coords(&alice, cid);
    let alice_client = open(&alice, ALICE_DEVICE).await;
    drop(bob_client);
    loseNextTransition();
    alice_client
        .remove_group_member(true, cid.into(), bob.clone())
        .await
        .unwrap_err();
    drop(alice_client);
    let transition = &entry_at(cid, 2)["signedRequest"]["body"]["transitionId"];
    let key = format!("commit_transition:{cid}:{}", transition.as_str().unwrap());
    let journal = account_db(&alice)
        .backend()
        .get_account_meta(&key)
        .unwrap()
        .expect("journaled before HTTP");
    account_db(&alice)
        .write_tx(|tx| tx.delete_account_meta(&key))
        .unwrap();
    let alice_client = open(&alice, ALICE_DEVICE).await;
    let error = alice_client
        .sync()
        .await
        .expect_err("an unmerged own Commit without its journal")
        .as_string()
        .unwrap_or_default();
    assert!(error.contains("no recovery journal"), "{error}");
    let row = conversation_row(&alice_client, cid);
    assert_eq!((row.epoch, row.last_seq), (1, 1));
    drop(alice_client);
    assert_eq!(stored_coords(&alice, cid), initial);

    account_db(&alice)
        .write_tx(|tx| tx.put_account_meta(&key, &journal, 0))
        .unwrap();
    let alice_client = open(&alice, ALICE_DEVICE).await;
    alice_client.sync().await.unwrap();
    let row = conversation_row(&alice_client, cid);
    assert_eq!((row.epoch, row.last_seq), (2, 2));
    drop(alice_client);
    let next = &entry_at(cid, 2)["signedRequest"]["body"]["next"];
    assert_eq!(stored_coords(&alice, cid), Some(canonical(next, cid)));
    assert_eq!(
        account_db(&alice).backend().get_account_meta(&key).unwrap(),
        None
    );
}

/// Alice's leaf-recovery fulfillment is journaled before HTTP. Alice invites Carol, Carol
/// accepts, and Alice's sync fulfills the add her acceptance requested (seq 4) with its answer
/// lost: her own echo merges it from the journal, writes its signed `next` and erases the
/// journal. Fail-before: nothing was journaled, so the echo of the unmerged Commit failed her
/// sync for good.
#[wasm_bindgen_test]
async fn a_lost_fulfillment_answer_is_merged_by_its_own_echo() {
    let _restore = install_ds();
    let (alice, bob, carol) = (did("fulfillalice"), did("fulfillbob"), did("fulfillcarol"));
    let cid = "00000000-0000-4000-8000-0000000c0017";
    let (alice_client, _bob_client) = conversation(&alice, &bob, cid).await;
    accept_invitation(&alice_client, &carol, CAROL_DEVICE, cid).await;
    loseNextTransition();
    alice_client
        .sync()
        .await
        .expect_err("the fulfillment answer is lost");
    assert_eq!(conversation_row(&alice_client, cid).epoch, 1);
    alice_client.sync().await.unwrap();
    let row = conversation_row(&alice_client, cid);
    assert_eq!((row.epoch, row.last_seq), (2, 4));
    drop(alice_client);
    let fulfillment = entry_at(cid, 4);
    assert_eq!(
        fulfillment["$type"],
        "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry"
    );
    let body = &fulfillment["signedRequest"]["body"];
    assert_eq!(
        stored_coords(&alice, cid),
        Some(canonical(&body["next"], cid))
    );
    let db = account_db(&alice);
    for key in [
        format!(
            "commit_transition:{cid}:{}",
            body["transitionId"].as_str().unwrap()
        ),
        format!("commit_transitions:{cid}"),
    ] {
        assert_eq!(db.backend().get_account_meta(&key).unwrap(), None, "{key}");
    }
}

/// A generic Welcome joins only as the verified Welcome of the signed leaf-recovery
/// fulfillment sequenced at its `transitionSeq`, at that fulfillment's signed `next`. Alice
/// invites Carol, Carol accepts and Alice fulfills her add (seq 4). Carol's pending Welcome view
/// first names seq 1, where no fulfillment is: nothing joins and nothing is acknowledged. Naming
/// seq 4, she joins at the fulfillment's signed `next` and acknowledges it, whatever
/// coordinates the view forges. Fail-before: the view's Welcome joined at once, at its forged
/// coordinates.
#[wasm_bindgen_test]
async fn a_generic_welcome_joins_only_as_its_verified_fulfillment() {
    let _restore = install_ds();
    let (alice, bob, carol) = (did("welcomealice"), did("welcomebob"), did("welcomecarol"));
    let cid = "00000000-0000-4000-8000-0000000c0016";
    let (alice_client, _bob_client) = conversation(&alice, &bob, cid).await;
    accept_invitation(&alice_client, &carol, CAROL_DEVICE, cid).await;
    alice_client.sync().await.unwrap();
    let fulfillment = entry_at(cid, 4);
    assert_eq!(
        fulfillment["$type"],
        "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry"
    );
    let body = &fulfillment["signedRequest"]["body"];
    let next = canonical(&body["next"], cid);
    let mut forged = next.clone();
    forged["epoch"] = json!(7);
    let view = |transition_seq: u32| {
        json!([{
            "welcomeId": uuid::Uuid::new_v4().to_string(), "conversationId": cid,
            "transitionSeq": transition_seq, "coordinates": forged, "status": "pending",
            "opaqueWelcome": body["manifest"]["welcomeBundle"]["opaqueWelcome"],
            "recipientDid": carol, "recipientDeviceId": CAROL_DEVICE,
        }])
        .to_string()
    };
    let carol_client = open(&carol, CAROL_DEVICE).await;
    let joined = |client: &WasmMlsClient| {
        serde_wasm_bindgen::from_value::<Vec<ConversationRow>>(
            client.list_conversations(None, 10).unwrap(),
        )
        .unwrap()
    };
    serveWelcomes(CAROL_DEVICE, &view(1));
    carol_client.sync().await.unwrap();
    assert!(joined(&carol_client).is_empty(), "no fulfillment at seq 1");
    assert_eq!(welcomeAcks(), "[]");
    let genuine = fulfillment.clone();
    for fault in ["absent", "forged", "relabelled"] {
        let mut bad = genuine.clone();
        let transition_seq = match fault {
            "absent" => {
                bad["sequencerReceipt"] = Value::Null;
                4
            }
            "forged" => {
                bad["sequencerReceipt"]["signature"] = json!(STANDARD.encode([0_u8; 64]));
                4
            }
            "relabelled" => {
                bad["seq"] = json!(5);
                5
            }
            _ => unreachable!(),
        };
        setEntry(cid, &bad.to_string());
        serveWelcomes(CAROL_DEVICE, &view(transition_seq));
        assert_eq!(
            carol_client.sync().await.unwrap(),
            0,
            "{fault}: unverified Welcome reported as joined"
        );
        assert!(joined(&carol_client).is_empty(), "{fault}: installed group");
        assert_eq!(welcomeAcks(), "[]", "{fault}: acknowledged Welcome");
        if transition_seq == 5 {
            dropEntry(cid, 5);
        }
        setEntry(cid, &genuine.to_string());
    }

    serveWelcomes(CAROL_DEVICE, &view(4));
    carol_client.sync().await.unwrap();
    let row = conversation_row(&carol_client, cid);
    assert_eq!((row.last_seq, row.epoch), (4, 2));
    let acks: Vec<Value> = serde_json::from_str(&welcomeAcks()).unwrap();
    assert_eq!(acks.len(), 1);
    assert_eq!(canonical(&acks[0]["coordinates"], cid), next);
    drop(carol_client);
    assert_eq!(stored_coords(&carol, cid), Some(next));
}

/// One conversation's failing entry never stops another conversation's sync. Alice and Bob
/// share two groups; mls-ds serves Alice, in the first, Bob's genuine message and then one
/// altered after signing, and in the second Bob's genuine message. Alice's sync fails naming
/// only the first conversation, its cursor and acknowledgement at the genuine message before
/// the altered one; the second conversation's message applies and is acknowledged. The altered
/// entry keeps failing only its own conversation.
///
/// Fail-before (web `7be78145`): `sync_impl` returned at the first failing conversation (`?` on
/// `sync_conversation_entries`, itself returning before its acknowledgement), so that
/// conversation's verified prefix was never acknowledged and no later conversation was read.
#[wasm_bindgen_test]
async fn one_conversations_failing_entry_never_stops_another() {
    let _restore = install_ds();
    let (alice, bob) = (did("isolatealice"), did("isolatebob"));
    let (first, second) = (
        "00000000-0000-4000-8000-0000000c0018",
        "00000000-0000-4000-8000-0000000c0019",
    );
    drop(conversation(&alice, &bob, first).await);
    let (alice_client, bob_client) = conversation(&alice, &bob, second).await;
    send(&bob_client, first, 1, "genuine").await.unwrap();
    send(&bob_client, first, 2, "altered").await.unwrap();
    send(&bob_client, second, 3, "other").await.unwrap();
    setEntry(first, &altered(&entry_at(first, 3)).to_string());
    for _ in 0..2 {
        let error = alice_client
            .sync()
            .await
            .expect_err("the altered entry fails its conversation")
            .as_string()
            .unwrap_or_default();
        assert!(
            error.starts_with("sync incomplete")
                && error.contains(&format!("conversation {first}: "))
                && !error.contains(second),
            "{error}"
        );
        let first_row = conversation_row(&alice_client, first);
        assert_eq!((first_row.last_seq, ackedUpTo(first, ALICE_DEVICE)), (2, 2));
        assert_eq!(
            timeline(&alice_client, first),
            timeline_of(&[(2, "genuine")])
        );
        let second_row = conversation_row(&alice_client, second);
        assert_eq!(
            (second_row.last_seq, ackedUpTo(second, ALICE_DEVICE)),
            (2, 2)
        );
        assert_eq!(
            timeline(&alice_client, second),
            timeline_of(&[(2, "other")])
        );
    }
}

/// A verified `resetActivationEntry` retires this device's old-generation leaf (`CHAT_PROTOCOL`
/// §6: every old leaf but the activator only closes), from exactly the state this device holds
/// and only under an active admin of its verified roster. Alice renames the conversation (seq 2)
/// and Bob syncs it; Alice then activates a reset (seq 3). With no verified roster Bob's sync
/// fails `RosterUnverified`; with Alice recorded only as a member it fails as not an admin; with
/// her an active admin, an activation retiring a coordinate Bob already left, and one opening
/// its successor on the retired group ID, fail too: each with nothing changed. The genuine one
/// moves his conversation to the successor generation's group, coordinate and cursor in one
/// step, erases the old group and acknowledges nothing. Retired, he reads nothing past the
/// reset: an old-generation message after it, and the activation replayed there, leave his
/// cursor at the reset.
///
/// Fail-before (web `7be78145`): `verify_control_entry` took a reset activation as cursor-only
/// (`binds_only`) under any participant device, so Bob's sync passed it without any roster,
/// kept the retired group as current and went on applying old-generation entries.
#[wasm_bindgen_test]
async fn reset_activation_retires_the_old_leaf_from_exactly_its_current_state() {
    let _restore = install_ds();
    let (alice, bob) = (did("resetalice"), did("resetbob"));
    let cid = "00000000-0000-4000-8000-0000000c001a";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    alice_client
        .update_group_metadata(cid.into(), "before the reset".into(), String::new())
        .await
        .unwrap();
    bob_client.sync().await.unwrap();
    let before = conversation_row(&bob_client, cid);
    drop((alice_client, bob_client));
    let prior = stored_coords(&bob, cid).expect("Bob recorded the rename");
    let generation = prior["generation"].as_i64().unwrap();
    let alice_signer = device_signer(&account_db(&alice));
    let alice_key = alice_signer.public().to_vec();
    let successor_group = [0x5a_u8; 32];
    let activation = |prior: &Value, successor_group: &[u8]| {
        let mut retired = prior.clone();
        retired["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap() + 1);
        retired["lifecycle"] = json!("superseded");
        let bytes = |byte: u8| json!({ "$bytes": STANDARD.encode([byte; 32]) });
        let successor = json!({
            "conversationId": cid, "generation": generation + 1, "stateVersion": 0,
            "groupId": { "$bytes": STANDARD.encode(successor_group) }, "epoch": 0,
            "groupContextHash": bytes(0x61), "confirmationTag": bytes(0x62),
            "lifecycle": "active",
        });
        let transition = uuid::Uuid::new_v4().to_string();
        let (ciphertext, group_info) = ([0x63_u8; 48], [0x64_u8; 64]);
        let body = json!({
            "$type": "blue.catbird.chat.defs#resetActivationBody",
            "signatureDomain": "CATBIRD-CHAT-RESET-ACTIVATE\0",
            "resetRequestId": uuid::Uuid::new_v4().to_string(), "transitionId": transition,
            "idempotencyKey": transition, "actorDid": alice, "actorDeviceId": ALICE_DEVICE,
            "conversationKind": "group", "authGeneration": 1,
            "prior": prior, "retired": retired, "successor": successor,
            "manifest": {
                "participants": [
                    { "userDid": alice, "role": "admin", "status": "active" },
                    { "userDid": bob, "role": "member", "status": "active" },
                ],
                "actorLeaf": { "userDid": alice, "deviceId": ALICE_DEVICE, "leafOrigin": "genesis" },
            },
            "genesisGroupInfo": {
                "framing": "mlsMessage", "contentType": "groupInfo",
                "bytes": { "$bytes": STANDARD.encode(group_info) },
                "sha256": STANDARD.encode(Sha256::digest(group_info)),
            },
            "metadataSnapshot": {
                "authorProof": {
                    "authGenerationAtOrigin": 1, "authorDeviceId": ALICE_DEVICE,
                    "authorDid": alice, "authorKeyId": derive_key_id(&alice_key),
                    "deviceStatusAtOrigin": "active", "originSeq": 1,
                    "originTransitionId": transition, "roleAtOrigin": "admin",
                    "signaturePublicKey": { "$bytes": STANDARD.encode(&alice_key) },
                },
                "ciphertext": { "$bytes": STANDARD.encode(ciphertext) },
                "ciphertextSha256": STANDARD.encode(Sha256::digest(ciphertext)),
                "ciphertextSize": ciphertext.len(),
                "coordinate": {
                    "conversationId": STANDARD.encode(uuid::Uuid::parse_str(cid).unwrap().as_bytes()),
                    "generation": generation + 1, "epoch": 0,
                    "groupId": { "$bytes": STANDARD.encode(successor_group) },
                    "groupContextHash": bytes(0x61), "confirmationTag": bytes(0x62),
                },
                "metadataVersion": 2, "nonce": { "$bytes": STANDARD.encode([0x65_u8; 12]) },
                "originTransitionId": transition,
            },
            "signedAt": "2026-11-07T00:00:00.000Z",
        });
        with_current_receipt(json!({
            "$type": "blue.catbird.chat.defs#resetActivationEntry", "seq": 3,
            "entryId": transition, "conversationId": cid,
            "receivedAt": "2026-11-07T00:00:00.000Z",
            "signedRequest": signed(CanonicalOperation::ActivateReset, body, &alice_signer),
        }))
    };
    // Bob's verified roster, as a creation, verified reset or roster attestation records it.
    let record_roster = |alice_role: &str| {
        let mut roster = json!({});
        roster[alice.as_str()] = json!({ "role": alice_role, "status": "active" });
        roster[bob.as_str()] = json!({ "role": "member", "status": "active" });
        account_db(&bob)
            .write_tx(|tx| {
                tx.put_account_meta(
                    &chat_wire::conversation_roster_key(cid),
                    &roster.to_string(),
                    0,
                )
            })
            .unwrap();
    };
    let members = |client: &WasmMlsClient| {
        serde_wasm_bindgen::from_value::<Vec<Value>>(client.list_members(cid.into()).unwrap())
            .unwrap()
            .len()
    };

    let genuine = activation(&prior, &successor_group);
    let mut left = prior.clone();
    left["stateVersion"] = json!(prior["stateVersion"].as_i64().unwrap() - 1);
    let retired_group = chat_wire::json_bytes(&prior["groupId"]).unwrap();
    assert_eq!(appendEntry(cid, &genuine.to_string()), 3);
    for (case, roster, entry, reason) in [
        (
            "no verified roster",
            None,
            genuine.clone(),
            format!("no verified roster for conversation {cid}"),
        ),
        (
            "a member activator",
            Some("member"),
            genuine.clone(),
            format!("{alice} is not an active admin"),
        ),
        (
            "a prior Bob already left",
            Some("admin"),
            activation(&left, &successor_group),
            "prior is not this device's current coordinate".to_owned(),
        ),
        (
            "a successor on the retired group",
            Some("admin"),
            activation(&prior, &retired_group),
            "successor is not a fresh group".to_owned(),
        ),
    ] {
        if let Some(role) = roster {
            record_roster(role);
        }
        setEntry(cid, &entry.to_string());
        let bob_client = open(&bob, BOB_DEVICE).await;
        let error = bob_client
            .sync()
            .await
            .expect_err(case)
            .as_string()
            .unwrap_or_default();
        assert!(error.contains(&reason), "{case}: {error}");
        assert_eq!(
            (conversation_row(&bob_client, cid), members(&bob_client)),
            (before.clone(), 2),
            "{case}"
        );
        drop(bob_client);
        assert_eq!(stored_coords(&bob, cid), Some(prior.clone()), "{case}");
    }

    setEntry(cid, &genuine.to_string());
    let bob_client = open(&bob, BOB_DEVICE).await;
    bob_client
        .sync()
        .await
        .expect("the genuine activation retires Bob's leaf");
    let retired = conversation_row(&bob_client, cid);
    assert_eq!(
        (
            retired.generation,
            retired.group_id.as_slice(),
            retired.epoch,
            retired.last_seq
        ),
        (generation + 1, successor_group.as_slice(), 0, 3)
    );
    assert_eq!(members(&bob_client), 0, "the old group is erased");
    assert!(send(&bob_client, cid, 9, "retired").await.is_err());
    assert_eq!(
        ackedUpTo(cid, BOB_DEVICE),
        2,
        "nothing acknowledged past the reset"
    );
    bob_client
        .sync()
        .await
        .expect("nothing past the reset is read");
    drop(bob_client);
    let successor = canonical(&genuine["signedRequest"]["body"]["successor"], cid);
    assert_eq!(stored_coords(&bob, cid), Some(successor));

    // Alice's old-generation message is sequenced after the reset (seq 4).
    let alice_client = open(&alice, ALICE_DEVICE).await;
    let _ = send(&alice_client, cid, 1, "old generation").await;
    drop(alice_client);
    let old_generation = entry_at(cid, 4);
    assert_eq!(
        old_generation["$type"],
        "blue.catbird.chat.defs#applicationEntry"
    );
    let mut replayed = genuine;
    replayed["seq"] = json!(4);
    let bob_client = open(&bob, BOB_DEVICE).await;
    for (case, entry) in [
        ("an old-generation message", old_generation),
        ("the activation replayed", replayed),
    ] {
        setEntry(cid, &entry.to_string());
        bob_client
            .sync()
            .await
            .unwrap_or_else(|error| panic!("{case} is never read: {error:?}"));
        assert_eq!(conversation_row(&bob_client, cid).last_seq, 3, "{case}");
    }
}

/// Leaf-recovery fulfillment adds only the requester of a pending invitation this device
/// verified: the add request of a participant acceptance whose invitation verified, for exactly
/// that device, key, auth generation and KeyPackage, at exactly the coordinate the acceptance
/// bound it to, and only once. mls-ds lists Alice a request for Carol, whom nobody invited yet,
/// with one of her own enrolled KeyPackages at the current coordinate, in Alice's inbox and in
/// the conversation state alike: Alice commits nothing and nothing moves. Alice then invites
/// Carol and Carol accepts; mls-ds lists her request with Bob's KeyPackage, Bob's key, another
/// auth generation and Bob's device: each fails that conversation's sync with no Commit sent
/// and Alice's MLS state unchanged. The genuine request adds Carol once; listed again at the
/// new coordinate, it adds nothing.
///
/// Fail-before (web `7be78145`): `fulfill_leaf_recovery_inbox` fulfilled every request
/// `getLeafRecoveryInbox` listed whose KeyPackage was the requesting account's own, so a
/// delivery service could get anyone with a registered device added.
#[wasm_bindgen_test]
async fn leaf_recovery_fulfills_only_a_verified_pending_acceptance() {
    let _restore = install_ds();
    let (alice, bob, carol) = (did("recoveralice"), did("recoverbob"), did("recovercarol"));
    let cid = "00000000-0000-4000-8000-0000000c001b";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    drop(bob_client);
    enroll(&carol, CAROL_DEVICE).await;
    let key_id = |account: &str| derive_key_id(device_signer(&account_db(account)).public());
    let package =
        |device: &str| -> Value { serde_json::from_str(&takeKeyPackage(device)).unwrap() };
    let (bob_key_id, bob_package) = (key_id(&bob), package(BOB_DEVICE));
    let (carol_key_id, carol_package) = (key_id(&carol), package(CAROL_DEVICE));
    let fulfillments = || {
        serde_json::from_str::<Vec<String>>(&dsTransitions())
            .unwrap()
            .iter()
            .filter(|text| text.contains("leafRecoveryFulfillmentBody"))
            .count()
    };
    let local = |client: &WasmMlsClient| {
        let row = conversation_row(client, cid);
        (fulfillments(), row.epoch, row.last_seq)
    };

    // A request for a device nobody invited is no work: nothing is sent or moves.
    let current = group_coords(&bob, cid);
    let injected_id = uuid::Uuid::new_v4().to_string();
    let injected = json!([{
        "$type": "blue.catbird.chat.defs#leafRecoveryView",
        "conversationId": cid, "recoveryRequestId": injected_id,
        "requesterDid": carol, "requesterDeviceId": CAROL_DEVICE,
        "recoveryKind": "add", "boundCoordinate": current, "status": "open",
        "requestedAt": "2026-11-07T00:00:00.000Z", "expiresAt": "2099-01-01T00:00:00.000Z",
        "reservation": {
            "conversationId": cid, "recoveryRequestId": injected_id, "boundCoordinate": current,
            "requesterDid": carol, "requesterDeviceId": CAROL_DEVICE,
            "requesterKeyId": carol_key_id, "requesterAuthGeneration": 1,
            "keyPackageRef": carol_package["keyPackageRef"],
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "purpose": "leafRecovery", "status": "active",
            "expiresAt": "2099-01-01T00:00:00.000Z", "keyPackage": carol_package,
        },
    }])
    .to_string();
    serveInbox(ALICE_DEVICE, &injected);
    serveRecoveries(cid, &injected);
    let before = local(&alice_client);
    alice_client
        .sync()
        .await
        .expect("a request this device cannot authorize is no error");
    assert_eq!(local(&alice_client), before, "nobody invited Carol");
    serveInbox(ALICE_DEVICE, "[]");
    serveRecoveries(cid, "[]");

    // Alice invites Carol and Carol accepts; mls-ds lists her request with any field the
    // acceptance did not authorize.
    accept_invitation(&alice_client, &carol, CAROL_DEVICE, cid).await;
    let genuine = serde_json::from_str::<Vec<Value>>(&recoveriesJson(cid))
        .unwrap()
        .pop()
        .expect("Carol's request");
    assert_eq!(genuine["requesterDid"], carol);
    let forged = |edit: &dyn Fn(&mut Value)| {
        let mut request = genuine.clone();
        edit(&mut request);
        json!([request]).to_string()
    };
    let variants = [
        (
            "another device's KeyPackage",
            forged(&|request| {
                request["reservation"]["keyPackage"] = bob_package.clone();
                request["reservation"]["keyPackageRef"] = bob_package["keyPackageRef"].clone();
            }),
            "not the authorized device's own",
        ),
        (
            "another key",
            forged(&|request| request["reservation"]["requesterKeyId"] = json!(bob_key_id)),
            "not the authorized request",
        ),
        (
            "another auth generation",
            forged(&|request| request["reservation"]["requesterAuthGeneration"] = json!(2)),
            "not the authorized request",
        ),
        (
            "another device",
            forged(&|request| {
                request["requesterDeviceId"] = json!(BOB_DEVICE);
                request["reservation"]["requesterDeviceId"] = json!(BOB_DEVICE);
            }),
            "not the authorized request",
        ),
    ];
    for (case, requests, reason) in variants {
        serveRecoveries(cid, &requests);
        let error = alice_client
            .sync()
            .await
            .expect_err(case)
            .as_string()
            .unwrap_or_default();
        assert!(
            error.contains(&format!("conversation {cid}: ")) && error.contains(reason),
            "{case}: {error}"
        );
        // The acceptance itself applied once; nothing else moved.
        assert_eq!(local(&alice_client), (before.0, before.1, 3), "{case}");
    }

    serveRecoveries(cid, &json!([genuine]).to_string());
    alice_client.sync().await.expect("the authorized add");
    assert_eq!(local(&alice_client), (before.0 + 1, before.1 + 1, 4));
    // Listed again at the new coordinate, the consumed request adds nothing.
    let current = entry_at(cid, 4)["signedRequest"]["body"]["next"].clone();
    let mut again = genuine;
    again["boundCoordinate"] = current.clone();
    again["reservation"]["boundCoordinate"] = current;
    serveRecoveries(cid, &json!([again]).to_string());
    alice_client
        .sync()
        .await
        .expect("a consumed request is no work");
    assert_eq!(local(&alice_client), (before.0 + 1, before.1 + 1, 4));
}

fn serve_own_pending_inventory(account: &str, device: &str, cid: &str, inventory_sequencer: &str) {
    let coordinates = stored_coords(account, cid).unwrap();
    let state = json!({
        "conversationKind": "group",
        "sequencerDid": inventory_sequencer,
        "coordinates": coordinates,
        "participants": [{
            "userDid": account,
            "status": "pending",
            "invitationProvenance": {
                "invitationTransitionId": message_id(0xacc),
                "invitedByDid": account,
                "invitedByDeviceId": device,
            },
        }],
    });
    serveInventory(device, &json!([{ "state": state }]).to_string());
}

fn web_own_acceptance_state(account: &str, cid: &str) -> (i64, Value, Option<String>, String) {
    let db = account_db(account);
    let backend = db.backend();
    let row = backend.get_conversation(cid).unwrap().unwrap();
    let coordinates = backend
        .get_account_meta(&format!("conversation_coords:{cid}"))
        .unwrap()
        .map(|raw| canonical(&serde_json::from_str(&raw).unwrap(), cid))
        .unwrap();
    (
        row.last_seq,
        coordinates,
        backend
            .get_account_meta(&chat_wire::own_leaf_recovery_key(cid))
            .unwrap(),
        row.sequencer_did,
    )
}

/// Unsigned inventory cannot replace a retained sequencer pin for this device's own acceptance.
/// Another sequencer's genuine receipt changes nothing; the pinned sequencer's receipt succeeds.
///
/// Fail-before: the inventory `sequencerDid` selected the receipt authority and its recovery was
/// persisted.
#[wasm_bindgen_test]
async fn own_acceptance_prefers_the_existing_sequencer_pin() {
    let _restore = install_ds();
    let (alice, bob) = (did("pinalice"), did("pinbob"));
    let cid = "00000000-0000-4000-8000-0000000c0020";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    drop(alice_client);
    drop(bob_client);
    serve_own_pending_inventory(&bob, BOB_DEVICE, cid, CROSS_HOME_DS);
    nextAcceptanceSequencer(CROSS_HOME_DS);
    let before = web_own_acceptance_state(&bob, cid);
    let bob_client = open(&bob, BOB_DEVICE).await;
    bob_client
        .sync()
        .await
        .expect_err("another sequencer's otherwise genuine receipt");
    drop(bob_client);
    assert_eq!(web_own_acceptance_state(&bob, cid), before);
    assert_eq!(before.3, SEQUENCER);

    let (alice, bob) = (did("pingoodalice"), did("pingoodbob"));
    let cid = "00000000-0000-4000-8000-0000000c0021";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    drop(alice_client);
    drop(bob_client);
    serve_own_pending_inventory(&bob, BOB_DEVICE, cid, CROSS_HOME_DS);
    let bob_client = open(&bob, BOB_DEVICE).await;
    bob_client
        .sync()
        .await
        .expect("the pinned sequencer's genuine receipt");
    drop(bob_client);
    let state = web_own_acceptance_state(&bob, cid);
    assert!(state.2.is_some());
    assert_eq!(state.3, SEQUENCER);
}

/// An older genuinely signed and receipted acceptance cannot authorize the fresh recovery view
/// returned for a new request. Refusal preserves recovery metadata; an exact answer succeeds.
///
/// Fail-before: the old entry and fresh view were checked independently and the view was kept.
#[wasm_bindgen_test]
async fn own_acceptance_receipt_is_bound_to_the_submitted_request() {
    let _restore = install_ds();
    let (alice, bob) = (did("boundalice"), did("boundbob"));
    let cid = "00000000-0000-4000-8000-0000000c0022";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    drop(alice_client);
    drop(bob_client);
    serve_own_pending_inventory(&bob, BOB_DEVICE, cid, SEQUENCER);
    let bob_client = open(&bob, BOB_DEVICE).await;
    bob_client.sync().await.expect("first exact acceptance");
    drop(bob_client);
    let older = entry_at(cid, 2);
    serve_own_pending_inventory(&bob, BOB_DEVICE, cid, SEQUENCER);
    replayNextAcceptance(&older.to_string());
    let before = web_own_acceptance_state(&bob, cid).2;
    let bob_client = open(&bob, BOB_DEVICE).await;
    let error = bob_client
        .sync()
        .await
        .expect_err("an older acceptance cannot authorize the fresh recovery")
        .as_string()
        .unwrap_or_default();
    drop(bob_client);
    assert!(error.contains("signed request"), "{error}");
    assert_eq!(web_own_acceptance_state(&bob, cid).2, before);

    let (alice, bob) = (did("boundgoodalice"), did("boundgoodbob"));
    let cid = "00000000-0000-4000-8000-0000000c0023";
    let (alice_client, bob_client) = conversation(&alice, &bob, cid).await;
    drop(alice_client);
    drop(bob_client);
    serve_own_pending_inventory(&bob, BOB_DEVICE, cid, SEQUENCER);
    let bob_client = open(&bob, BOB_DEVICE).await;
    bob_client
        .sync()
        .await
        .expect("the exact acceptance answer");
    drop(bob_client);
    assert!(web_own_acceptance_state(&bob, cid).2.is_some());
}
