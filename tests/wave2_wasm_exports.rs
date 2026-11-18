//! Wave-2 browser WASM integration suite (`W2-C`) over real encrypted OPFS (`sqlite3mc` +
//! `opfs-sahpool`) and an in-worker Rust Nov-12 ATProto Spaces + `D-1` CARv1 `repo_proof` +
//! `mls-ds` fixture.
#![cfg(target_arch = "wasm32")]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use atproto_spaces::{
    http_signature::{verify_credential_request, SpaceRequestHeaders},
    kem::{decapsulate_p256, decode_p256_did_key, encode_p256_did_key, P256SecretKey},
    lthash::{compute_dagcbor_cid, LtHash},
    mac::{
        parse_accept_signature, sign_commit_mac, sign_record_mac, MacProfile,
        SpaceMacResponseHeaders, ACCEPT_SIGNATURE_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER,
    },
    star::{validate_canonical_dagcbor_record, write_star_repo, StarRecordEntry},
    tokens::{
        mint_space_token, verify_space_token, SpaceKeyResolver, SpaceSigningKey, SpaceTokenClaims,
        SpaceTokenKind, SpaceVerifyingKey,
    },
    SpaceUri,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::chat_v2::transcript::{
    decode_strict_json, project_signed_body, SignedMutationKind, SigningTranscript,
};
use catbird_mls::client::{
    chat_wire, CircleOwnerStateDto, EnrollmentReceipt,
    LabyrinthBackupStatus, LabyrinthRevocationOutcome, LeaveConversationOutcome,
    MailboxReadStateRecord, OtcInitiatedSession, OtcPairingCompletion, OtcPairingOffer,
    RegisteredDeviceInfo, UploadedConversationAttachment, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls::metadata::{
    decrypt_metadata_snapshot_plaintext, derive_metadata_key_from_group,
    encrypt_metadata_snapshot_plaintext_with_nonce,
};
use catbird_mls::labyrinth::repo_proof::build_repo_proof_car_v1;
use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend as _};
use catbird_mls::storage::MessageRow;
use catbird_mls::MLSMessagePayload;
use catbird_mls_web::{verify_golden_transcript_json, SqliteConn, WasmMlsClient};
use labyrinth::records::EpochPublicDef;
use labyrinth::recovery_code::RecoveryCode;
use labyrinth_protocol::receipt::{sign_sequencer_receipt, SequencerReceiptPayload};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen(inline_js = r#"
let originalFetch;
let rustDispatch;

export function installWave2Fetch(dispatchFn) {
  originalFetch = globalThis.fetch;
  rustDispatch = dispatchFn;
  globalThis.fetch = async (input, init) => {
    const req = input instanceof Request ? input : new Request(input, init);
    const headers = [];
    req.headers.forEach((v, k) => headers.push([k, v]));
    const body = (req.method !== 'GET' && req.method !== 'HEAD')
      ? new Uint8Array(await req.clone().arrayBuffer())
      : new Uint8Array(0);
    const raw = rustDispatch(req.method, req.url, JSON.stringify(headers), body);
    const parsed = JSON.parse(raw);
    const binStr = atob(parsed.bodyBase64);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
    const respHeaders = new Headers();
    for (const [k, v] of parsed.headers) respHeaders.append(k, v);
    const resp = new Response(bytes, { status: parsed.status, headers: respHeaders });
    Object.defineProperty(resp, 'url', { value: req.url });
    return resp;
  };
}

export function restoreWave2Fetch() {
  if (originalFetch) {
    globalThis.fetch = originalFetch;
  }
}
"#)]
extern "C" {
    fn installWave2Fetch(dispatch_fn: &js_sys::Function);
    fn restoreWave2Fetch();
}

struct RestoreFetch;
impl Drop for RestoreFetch {
    fn drop(&mut self) {
        restoreWave2Fetch();
    }
}

const SEQUENCER: &str = "did:web:ds.catbird.test";
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

type SpaceRecordKey = (String, String, String, String);

#[derive(Clone)]
struct StoredRecord {
    value: Value,
    dagcbor: Vec<u8>,
    cid: String,
}

#[derive(Clone)]
struct EnrolledDevice {
    device_id: String,
    key_id: String,
    signature_public_key_b64: String,
    signature_public_key: Vec<u8>,
    auth_generation: i64,
    status: String,
    dr_revision: u32,
    key_packages: Vec<Value>,
    joined_seq: u64,
    removed_seq: Option<u64>,
    revoked_at: Option<String>,
}

#[derive(Clone)]
struct ConversationFixtureState {
    kind: String,
    coordinates: Value,
    participants: Vec<Value>,
    leaves: Vec<Value>,
    pending_leave_requests: Vec<Value>,
    account_deletions: Vec<Value>,
}

#[derive(Default)]
struct Wave2World {
    space_records: BTreeMap<SpaceRecordKey, StoredRecord>,
    space_ops: BTreeMap<(String, String), Vec<Value>>,
    repo_revisions: BTreeMap<(String, String), String>,
    blobs: BTreeMap<(String, String), Vec<u8>>,
    spent_delegations: BTreeSet<String>,
    mailbox_keys: BTreeMap<(String, String), StoredRecord>,
    chat_devices: BTreeMap<(String, String), StoredRecord>,
    chat_device_revocations: BTreeMap<(String, String), StoredRecord>,
    chat_declarations: BTreeMap<String, StoredRecord>,
    ds_devices: BTreeMap<String, Vec<EnrolledDevice>>,
    epoch_heads: BTreeMap<String, Vec<EpochPublicDef>>,
    convo_seq: BTreeMap<String, u64>,
    convo_entries: BTreeMap<String, Vec<Value>>,
    convo_states: BTreeMap<String, ConversationFixtureState>,
    calls: BTreeMap<String, u32>,
    device_calls: BTreeMap<(String, String), u32>,
    repo_proof_fault: Option<(String, String, &'static str)>,
    did_doc_fault: Option<(String, &'static str)>,
    space_apply_fault: bool,
    epoch_publish_not_authorized_once: bool,
    get_own_devices_fault_once: bool,
    delete_account_fault: bool,
    deleted_accounts: BTreeSet<String>,
    deleted_account_proofs: BTreeMap<String, (Vec<u8>, Vec<u8>)>,
    pds_repo_status_for: BTreeMap<String, (u16, String)>,
    blocks_unsupported: bool,
    sequence: u64,
}

impl Wave2World {
    fn next_seq(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }
}

thread_local! {
    static WORLD: RefCell<Wave2World> = RefCell::new(Wave2World::default());
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body_base64: String,
}

impl WireResponse {
    fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body_base64: STANDARD.encode(serde_json::to_vec(&body).unwrap()),
        }
    }

    fn bytes(status: u16, content_type: &str, bytes: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), content_type.into())],
            body_base64: STANDARD.encode(bytes),
        }
    }

    fn with_mac(mut self, mac: SpaceMacResponseHeaders) -> Self {
        self.headers
            .push((mac.covered_header_name.into(), mac.covered_header));
        self.headers
            .push((SIGNATURE_INPUT_HEADER.into(), mac.signature_input));
        self.headers.push((SIGNATURE_HEADER.into(), mac.signature));
        self.headers
            .push(("vary".into(), ACCEPT_SIGNATURE_HEADER.into()));
        self
    }
}

struct FixtureKeys;

#[async_trait::async_trait(?Send)]
impl SpaceKeyResolver for FixtureKeys {
    async fn resolve_atproto_key(
        &self,
        issuer: &str,
        _: bool,
    ) -> atproto_spaces::Result<SpaceVerifyingKey> {
        let did = issuer.split('#').next().unwrap();
        if !atproto_spaces::is_valid_did(did) {
            return Err(atproto_spaces::SpacesError::InvalidDid(did.into()));
        }
        Ok(SpaceSigningKey::from_p256_secret(&p256_key(did, b"sign"), "#atproto").verifying_key())
    }
}

fn p256_key(did: &str, purpose: &[u8]) -> P256SecretKey {
    for attempt in 0u32..128 {
        let mut h = Sha256::new();
        h.update(b"catbird-wave2-wasm-fixture\0");
        h.update(purpose);
        h.update(did.as_bytes());
        h.update(attempt.to_be_bytes());
        if let Ok(secret) = P256SecretKey::from_slice(&h.finalize()) {
            return secret;
        }
    }
    panic!("fixture P-256 key derivation exhausted");
}

fn sequencer_signing_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from(&p256_key(SEQUENCER, b"receipt-1"))
}

fn tid(seq: u64) -> String {
    const ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    let v = (1u64 << 62) | seq;
    (0..13)
        .rev()
        .map(|i| ALPHABET[((v >> (5 * i)) & 31) as usize] as char)
        .collect()
}

fn canonical_record(value: &Value) -> Result<StoredRecord, String> {
    let typed: catbird_atproto::types::value::Data =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    let dagcbor = serde_ipld_dagcbor::to_vec(&typed).map_err(|e| e.to_string())?;
    validate_canonical_dagcbor_record(&dagcbor).map_err(|e| e.to_string())?;
    Ok(StoredRecord {
        value: value.clone(),
        cid: compute_dagcbor_cid(&dagcbor).to_string(),
        dagcbor,
    })
}

fn complete_sync<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = std::pin::pin!(future);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("sync fixture future unexpectedly yielded Pending"),
    }
}

fn build_did_doc(did: &str, base_endpoint: &str) -> Value {
    let sign_mb = encode_p256_did_key(&p256_key(did, b"sign").public_key());
    let kem_mb = encode_p256_did_key(&p256_key(did, b"kem").public_key());
    let mut methods = vec![
        json!({
            "id": format!("{did}#atproto"),
            "controller": did,
            "type": "Multikey",
            "publicKeyMultibase": sign_mb.strip_prefix("did:key:").unwrap(),
        }),
        json!({
            "id": format!("{did}#atproto_kem"),
            "controller": did,
            "type": "Multikey",
            "publicKeyMultibase": kem_mb.strip_prefix("did:key:").unwrap(),
        }),
    ];
    if did == SEQUENCER {
        let receipt_mb = encode_p256_did_key(&p256_key(did, b"receipt-1").public_key());
        methods.push(json!({
            "id": format!("{did}#mls-receipt-1"),
            "controller": did,
            "type": "Multikey",
            "publicKeyMultibase": receipt_mb.strip_prefix("did:key:").unwrap(),
        }));
    }
    json!({
        "id": did,
        "verificationMethod": methods,
        "service": [{
            "id": format!("{did}#atproto_pds"),
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": base_endpoint,
        }],
    })
}

fn mint_i13_receipt(
    body: &Value,
    seq: u64,
    entry_id_override: Option<&str>,
    control: bool,
) -> Value {
    let coordinate = if control {
        body.get("next")
            .or_else(|| body.get("successor"))
            .or_else(|| body.get("retired"))
            .or_else(|| body.get("prior"))
            .expect("control coordinate")
    } else {
        &body["prior"]
    };
    let (entry_id, archive_commitment) = if control {
        let kind = body["$type"]
            .as_str()
            .and_then(SignedMutationKind::from_type_id)
            .expect("SignedMutationKind");
        let strict = decode_strict_json(&serde_json::to_vec(body).unwrap()).unwrap();
        let projected = project_signed_body(kind, &strict).unwrap();
        let transcript = SigningTranscript::build_for(kind, &projected).unwrap();
        let eid = entry_id_override
            .or_else(|| body["transitionId"].as_str())
            .or_else(|| body["leaveRequestId"].as_str())
            .unwrap()
            .to_owned();
        (eid, *transcript.request_digest())
    } else {
        (
            body["messageId"].as_str().unwrap().to_owned(),
            chat_wire::json_bytes(&body["aad"]["archiveCommitment"])
                .unwrap()
                .try_into()
                .unwrap(),
        )
    };
    let payload = SequencerReceiptPayload {
        sequencer_did: SEQUENCER.into(),
        conversation_id: coordinate["conversationId"].as_str().unwrap().into(),
        group_id: chat_wire::json_bytes(&coordinate["groupId"]).unwrap(),
        epoch: coordinate["epoch"].as_u64().unwrap(),
        sender_device_did_url: format!(
            "{}#{}",
            body["actorDid"].as_str().unwrap(),
            body["actorDeviceId"].as_str().unwrap()
        ),
        entry_id,
        archive_commitment,
        seq,
        issued_at_ms: js_sys::Date::now() as i64,
    };
    let kid = format!("{SEQUENCER}#mls-receipt-1");
    let signed = sign_sequencer_receipt(&sequencer_signing_key(), &kid, &payload).unwrap();
    json!({
        "sequencerDid": payload.sequencer_did,
        "conversationId": payload.conversation_id,
        "generation": coordinate["generation"],
        "groupId": STANDARD.encode(&payload.group_id),
        "epoch": payload.epoch,
        "senderDid": body["actorDid"],
        "senderDeviceId": body["actorDeviceId"],
        "entryId": payload.entry_id,
        "archiveCommitment": STANDARD.encode(payload.archive_commitment),
        "seq": payload.seq,
        "issuedAtMs": payload.issued_at_ms,
        "kid": signed.key_id,
        "signature": STANDARD.encode(signed.signature),
    })
}

fn decode_pct(s: &str) -> String {
    let mut bytes = s.bytes();
    let mut out = Vec::with_capacity(s.len());
    while let Some(b) = bytes.next() {
        out.push(match b {
            b'%' => {
                let hi = (bytes.next().unwrap() as char).to_digit(16).unwrap();
                let lo = (bytes.next().unwrap() as char).to_digit(16).unwrap();
                ((hi << 4) | lo) as u8
            }
            b'+' => b' ',
            _ => b,
        });
    }
    String::from_utf8(out).unwrap()
}

fn parse_query_map(query: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(decode_pct(k), decode_pct(v));
        }
    }
    map
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn extract_account_did(headers: &[(String, String)]) -> Option<String> {
    let auth = find_header(headers, "authorization")?;
    let token = auth.strip_prefix("Bearer ")?;
    token
        .strip_prefix("session:")
        .or_else(|| token.strip_prefix("service-auth:"))
        .map(str::to_owned)
}

fn space_commitment(entries: &[(&SpaceRecordKey, &StoredRecord)]) -> [u8; 32] {
    let mut hash = LtHash::empty();
    for ((_, _, collection, rkey), rec) in entries {
        let cid = rec.cid.parse().unwrap();
        hash.add_record(collection, rkey, &cid);
    }
    hash.commitment()
}

fn negotiate_mac_secret(
    writer: &str,
    accept_sig: Option<&str>,
    profile: MacProfile,
) -> Result<(String, String, [u8; 32]), String> {
    let header = accept_sig.ok_or_else(|| "Accept-Signature missing".to_string())?;
    let (label, share) = parse_accept_signature(header, profile).map_err(|e| e.to_string())?;
    let secret = decapsulate_p256(&p256_key(writer, b"kem"), &share).map_err(|e| e.to_string())?;
    Ok((label, share, secret))
}

fn handle_space_apply(account: &str, body: &Value) -> WireResponse {
    let space = SpaceUri::parse_hedged(body["space"].as_str().unwrap()).unwrap();
    let repo = body["repo"].as_str().unwrap();
    if repo != account {
        return WireResponse::json(403, json!({"error": "NotAuthorized"}));
    }
    let writes = body["writes"].as_array().unwrap();
    WORLD.with(|cell| {
        let mut world = cell.borrow_mut();
        let mut records = world.space_records.clone();
        let rev = tid(world.next_seq());
        let mut results = Vec::with_capacity(writes.len());
        let mut ops = Vec::with_capacity(writes.len());
        for (idx, w) in writes.iter().enumerate() {
            let collection = w["collection"].as_str().unwrap();
            let rkey = w["rkey"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| tid(world.sequence + idx as u64 + 1));
            let uri = space.record_uri(repo, collection, &rkey).unwrap();
            let key = (
                space.raw.clone(),
                repo.to_owned(),
                collection.to_owned(),
                rkey.clone(),
            );
            let current = records.get(&key);
            let prev = current.map(|r| r.cid.clone());
            if w.get("swapRecord")
                .and_then(Value::as_str)
                .is_some_and(|swap| Some(swap) != current.map(|r| r.cid.as_str()))
            {
                return WireResponse::json(400, json!({"error": "InvalidSwap"}));
            }
            let action = w["$type"].as_str().unwrap().rsplit('#').next().unwrap();
            let cid = match action {
                "create" if current.is_some() => {
                    return WireResponse::json(400, json!({"error": "RecordAlreadyExists"}));
                }
                "update" | "delete" if current.is_none() => {
                    return WireResponse::json(400, json!({"error": "RecordNotFound"}));
                }
                "create" | "update" => {
                    let rec = canonical_record(w.get("value").unwrap()).unwrap();
                    let cid = rec.cid.clone();
                    records.insert(key, rec);
                    Some(cid)
                }
                "delete" => {
                    records.remove(&key);
                    None
                }
                other => panic!("unsupported Space write action: {other}"),
            };
            let mut res = json!({"$type": format!("com.atproto.space.applyWrites#{action}Result")});
            if let Some(ref c) = cid {
                res["uri"] = json!(uri);
                res["cid"] = json!(c);
            }
            results.push(res);
            ops.push(json!({
                "collection": collection,
                "rkey": rkey,
                "rev": rev,
                "cid": cid,
                "prev": prev,
            }));
        }
        world.space_records = records;
        world
            .repo_revisions
            .insert((space.raw.clone(), repo.to_owned()), rev);
        world
            .space_ops
            .entry((space.raw, repo.to_owned()))
            .or_default()
            .extend(ops);
        WireResponse::json(200, json!({"results": results}))
    })
}

fn handle_space_read(
    caller_account: Option<&str>,
    nsid: &str,
    params: &BTreeMap<String, String>,
    headers: &SpaceRequestHeaders,
    accept_sig: Option<&str>,
    now: u64,
) -> WireResponse {
    let space = SpaceUri::parse_hedged(params.get("space").unwrap()).unwrap();
    let authority_read = matches!(
        nsid,
        "com.atproto.space.getSpace" | "com.atproto.space.listWriters"
    );
    let writer = if authority_read {
        space.authority.as_str()
    } else {
        params.get("repo").unwrap().as_str()
    };
    assert_eq!(headers.atproto_space_audience, writer);
    let jwt = headers
        .authorization
        .strip_prefix("Atproto-Space-Credential ")
        .expect("Atproto-Space-Credential");
    let claims = complete_sync(verify_space_token(
        SpaceTokenKind::Credential,
        jwt,
        &FixtureKeys,
        now,
    ))
    .expect("verify Space credential");
    let claims_space = SpaceUri::parse_hedged(&claims.sub).unwrap().raw;
    assert_eq!(claims.iss, space.authority);
    assert_eq!(claims_space, space.raw);
    let proof = verify_credential_request(
        &headers.to_header_map().unwrap(),
        claims.cnf_kid.as_deref().unwrap(),
        now,
    )
    .expect("verify Space RFC 9421 PoP");
    assert_eq!(proof.credential_jwt, jwt);
    assert_eq!(proof.audience_did, writer);
    if space.space_type == "blue.catbird.labyrinth.mailbox"
        && (caller_account.is_some_and(|acct| acct != space.authority)
            || writer != space.authority
            || space.rkey != "self")
    {
        return WireResponse::json(403, json!({"error": "NotAuthorized"}));
    }

    WORLD.with(|cell| {
        let world = cell.borrow();
        let entries: Vec<_> = world
            .space_records
            .iter()
            .filter(|((s, r, _, _), _)| s == &space.raw && r == writer)
            .collect();
        let rev = world
            .repo_revisions
            .get(&(space.raw.clone(), writer.to_owned()))
            .cloned()
            .unwrap_or_else(|| tid(0));
        let commit = space_commitment(&entries);
        let commit_json = json!({
            "space": space.raw,
            "repo": writer,
            "ver": 1,
            "rev": rev,
            "data": { "$bytes": STANDARD.encode(commit) },
        });
        match nsid {
            "com.atproto.space.getRecord" => {
                let collection = params.get("collection").unwrap();
                let rkey = params.get("rkey").unwrap();
                let Some(rec) = world.space_records.get(&(
                    space.raw.clone(),
                    writer.to_owned(),
                    collection.clone(),
                    rkey.clone(),
                )) else {
                    return WireResponse::json(404, json!({"error": "RecordNotFound"}));
                };
                let uri = space.record_uri(writer, collection, rkey).unwrap();
                let (label, share, secret) =
                    negotiate_mac_secret(writer, accept_sig, MacProfile::Record).unwrap();
                let (mac_headers, _) =
                    sign_record_mac(&secret, &share, &label, &uri, &rec.cid).unwrap();
                WireResponse::json(
                    200,
                    json!({
                        "uri": uri,
                        "cid": rec.cid,
                        "value": rec.value,
                    }),
                )
                .with_mac(mac_headers)
            }
            "com.atproto.space.listRecords" => {
                let collection = params.get("collection");
                let reverse = params.get("reverse").map(String::as_str) == Some("true");
                let mut matching: Vec<_> = entries
                    .into_iter()
                    .filter(|((_, _, c, rk), _)| {
                        let path = format!("{c}/{rk}");
                        collection.is_none_or(|w| c == w)
                            && params.get("cursor").is_none_or(|cur| {
                                if reverse {
                                    &path < cur
                                } else {
                                    &path > cur
                                }
                            })
                    })
                    .collect();
                if reverse {
                    matching.reverse();
                }
                let page_limit = params
                    .get("limit")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(50);
                let more = matching.len() > page_limit;
                matching.truncate(page_limit);
                let cursor = more.then(|| {
                    let ((_, _, c, rk), _) = matching.last().unwrap();
                    format!("{c}/{rk}")
                });
                let records: Vec<_> = matching
                    .into_iter()
                    .map(|((_, _, c, rk), rec)| {
                        let mut item = json!({
                            "collection": c,
                            "rkey": rk,
                            "cid": rec.cid,
                        });
                        if params.get("excludeValues").map(String::as_str) != Some("true") {
                            item["value"] = rec.value.clone();
                        }
                        item
                    })
                    .collect();
                WireResponse::json(200, json!({"records": records, "cursor": cursor}))
            }
            "com.atproto.space.listWriters" => {
                let dids: BTreeSet<_> = world
                    .space_records
                    .keys()
                    .filter(|(s, _, _, _)| s == &space.raw)
                    .map(|(_, d, _, _)| d.clone())
                    .collect();
                let mut inventory = LtHash::empty();
                let mut page = Vec::new();
                for did in dids {
                    let recs: Vec<_> = world
                        .space_records
                        .iter()
                        .filter(|((s, r, _, _), _)| s == &space.raw && r == &did)
                        .collect();
                    let repo_rev = world
                        .repo_revisions
                        .get(&(space.raw.clone(), did.clone()))
                        .cloned()
                        .unwrap_or_else(|| tid(0));
                    let data = space_commitment(&recs);
                    inventory
                        .add_inventory_entry(&did, &repo_rev, &repo_rev, &data)
                        .unwrap();
                    page.push(json!({
                        "$type": "com.atproto.space.defs#repoWrite",
                        "repo": did,
                        "repoRev": repo_rev,
                        "spaceRev": repo_rev,
                        "data": { "$bytes": STANDARD.encode(data) },
                    }));
                }
                let inv_data = inventory.commitment();
                let snap_rev = tid(world.sequence);
                let (label, share, secret) =
                    negotiate_mac_secret(&space.authority, accept_sig, MacProfile::Commit).unwrap();
                let (mac_headers, _) = sign_commit_mac(
                    &secret,
                    &share,
                    &label,
                    &space.raw,
                    &space.authority,
                    &snap_rev,
                    &inv_data,
                )
                .unwrap();
                WireResponse::json(
                    200,
                    json!({
                        "repos": page,
                        "complete": true,
                        "commit": {
                            "space": space.raw,
                            "repo": space.authority,
                            "rev": snap_rev,
                            "ver": 1,
                            "data": { "$bytes": STANDARD.encode(inv_data) },
                        }
                    }),
                )
                .with_mac(mac_headers)
            }
            "com.atproto.space.getSpace" => WireResponse::json(
                200,
                json!({
                    "uri": space.raw,
                    "policy": {
                        "$type": "blue.catbird.labyrinth.conversationPolicy",
                        "authority": space.authority,
                    }
                }),
            ),
            "com.atproto.space.getLatestCommit"
            | "com.atproto.space.getRepo"
            | "com.atproto.space.listRepoOps" => {
                let (label, share, secret) =
                    negotiate_mac_secret(writer, accept_sig, MacProfile::Commit).unwrap();
                let (mac_headers, _) =
                    sign_commit_mac(&secret, &share, &label, &space.raw, writer, &rev, &commit)
                        .unwrap();
                if nsid == "com.atproto.space.getRepo" {
                    let mut star_entries: Vec<_> = entries
                        .into_iter()
                        .map(|((_, _, c, rk), rec)| StarRecordEntry {
                            path: format!("{c}/{rk}"),
                            record_dagcbor: rec.dagcbor.clone(),
                        })
                        .collect();
                    star_entries.sort_by(|a, b| a.path.cmp(&b.path));
                    let bytes =
                        write_star_repo(&space.raw, writer, &rev, &commit, &star_entries).unwrap();
                    return WireResponse::bytes(200, "application/vnd.dasl.star", bytes)
                        .with_mac(mac_headers);
                }
                if nsid == "com.atproto.space.getLatestCommit" {
                    return WireResponse::json(200, json!({"commit": commit_json}))
                        .with_mac(mac_headers);
                }
                let mut ops = world
                    .space_ops
                    .get(&(space.raw.clone(), writer.to_owned()))
                    .cloned()
                    .unwrap_or_default();
                ops.retain(|op| {
                    params
                        .get("since")
                        .is_none_or(|since| op["rev"].as_str().unwrap() > since.as_str())
                });
                if params.get("excludeValues").map(String::as_str) != Some("true") {
                    for op in &mut ops {
                        if let Some(rec) = world.space_records.get(&(
                            space.raw.clone(),
                            writer.to_owned(),
                            op["collection"].as_str().unwrap().to_owned(),
                            op["rkey"].as_str().unwrap().to_owned(),
                        )) {
                            if op["cid"].as_str() == Some(rec.cid.as_str()) {
                                op["value"] = rec.value.clone();
                            }
                        }
                    }
                }
                WireResponse::json(200, json!({"ops": ops, "commit": commit_json}))
                    .with_mac(mac_headers)
            }
            "com.atproto.space.getBlob" => {
                let cid = params.get("cid").unwrap();
                match world.blobs.get(&(writer.to_owned(), cid.clone())) {
                    Some(bytes) => {
                        WireResponse::bytes(200, "application/octet-stream", bytes.clone())
                    }
                    None => WireResponse::json(404, json!({"error": "BlobNotFound"})),
                }
            }
            other => panic!("unsupported Space read endpoint: {other}"),
        }
    })
}

fn dispatch_fetch(method: String, url: String, headers_json: String, body: Vec<u8>) -> String {
    let headers: Vec<(String, String)> = serde_json::from_str(&headers_json).unwrap();
    let resp = dispatch_fetch_inner(&method, &url, &headers, &body);
    serde_json::to_string(&resp).unwrap()
}

fn dispatch_fetch_inner(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> WireResponse {
    if let Some(did) = url.strip_prefix("https://plc.directory/") {
        let fault = WORLD.with(|cell| {
            cell.borrow()
                .did_doc_fault
                .as_ref()
                .filter(|(fault_did, _)| fault_did == did)
                .map(|(_, kind)| *kind)
        });
        if fault == Some("malformed") {
            return WireResponse::json(200, json!({"id": "did:plc:wrongidentityaaaaaaaa"}));
        }
        let mut doc = build_did_doc(did, "https://pds.catbird.test");
        if fault == Some("missing_atproto") {
            doc["verificationMethod"]
                .as_array_mut()
                .unwrap()
                .retain(|method| {
                    method["id"].as_str() != Some(format!("{did}#atproto").as_str())
                });
        }
        return WireResponse::json(200, doc);
    }
    if url.ends_with("/.well-known/did.json") {
        return WireResponse::json(200, build_did_doc(SEQUENCER, "https://ds.catbird.test"));
    }
    let (origin, rest) = url.split_once("/xrpc/").expect("XRPC path");
    let (nsid, query) = rest.split_once('?').unwrap_or((rest, ""));
    let params = parse_query_map(query);
    let account_opt = extract_account_did(headers);
    let now_secs = (js_sys::Date::now().max(0.0) as u64) / 1000;

    WORLD.with(|cell| {
        let mut w = cell.borrow_mut();
        *w.calls.entry(nsid.to_owned()).or_insert(0) += 1;
    });

    match nsid {
        "com.atproto.server.getServiceAuth" => {
            let did = account_opt.expect("session bearer on getServiceAuth");
            WireResponse::json(200, json!({ "token": format!("service-auth:{did}") }))
        }
        "com.atproto.identity.resolveDid" => {
            let did = params.get("did").unwrap();
            let endpoint = if did == SEQUENCER {
                "https://ds.catbird.test"
            } else {
                origin
            };
            WireResponse::json(200, json!({ "didDoc": build_did_doc(did, endpoint) }))
        }
        "com.atproto.sync.getLatestCommit"
        | "com.atproto.sync.getRepo"
        | "com.atproto.sync.getBlocks" => {
            if nsid == "com.atproto.sync.getBlocks" && WORLD.with(|c| c.borrow().blocks_unsupported)
            {
                return WireResponse::json(501, json!({"error":"MethodNotImplemented"}));
            }
            let did = params.get("did").unwrap();
            let records = WORLD.with(|cell| {
                let world = cell.borrow();
                if let Some((status, code)) = world.pds_repo_status_for.get(did) {
                    return Err(WireResponse::json(*status, json!({"error": code})));
                }
                let mut rows = Vec::new();
                for (collection, records) in [
                    (labyrinth::records::nsid::MAILBOX_KEYS, &world.mailbox_keys),
                    ("blue.catbird.chat.device", &world.chat_devices),
                    (
                        "blue.catbird.chat.deviceRevocation",
                        &world.chat_device_revocations,
                    ),
                ] {
                    for ((owner, rkey), record) in records {
                        if owner == did {
                            rows.push((format!("{collection}/{rkey}"), record.dagcbor.clone()));
                        }
                    }
                }
                if let Some(declaration) = world.chat_declarations.get(did) {
                    rows.push((
                        "blue.catbird.chat.declaration/self".into(),
                        declaration.dagcbor.clone(),
                    ));
                }
                Ok(rows)
            });
            let records = match records {
                Ok(rows) => rows,
                Err(response) => return response,
            };
            let key = SpaceSigningKey::from_p256_secret(&p256_key(did, b"sign"), "#atproto");
            let rev = "3lb2zzzzzzzzz";
            let (root, car) = build_repo_proof_car_v1(did, rev, &records, &key).unwrap();
            if nsid == "com.atproto.sync.getLatestCommit" {
                WireResponse::json(200, json!({"cid": root.to_string(), "rev": rev}))
            } else if nsid == "com.atproto.sync.getBlocks" {
                let cid = params.get("cids").unwrap();
                let (_, cid_bytes) = multibase::decode(cid).unwrap();
                let (header_len, rest) = unsigned_varint::decode::usize(&car).unwrap();
                let mut rest = &rest[header_len..];
                while !rest.is_empty() {
                    let (len, data) = unsigned_varint::decode::usize(rest).unwrap();
                    let (block, remaining) = data.split_at(len);
                    if block.starts_with(&cid_bytes) {
                        let header =
                            serde_ipld_dagcbor::to_vec(&json!({"roots":[],"version":1})).unwrap();
                        let mut buffer = unsigned_varint::encode::usize_buffer();
                        let mut one =
                            unsigned_varint::encode::usize(header.len(), &mut buffer).to_vec();
                        one.extend(header);
                        one.extend(unsigned_varint::encode::usize(block.len(), &mut buffer));
                        one.extend(block);
                        return WireResponse::bytes(200, "application/vnd.ipld.car", one);
                    }
                    rest = remaining;
                }
                WireResponse::json(404, json!({"error":"BlockNotFound"}))
            } else {
                WireResponse::bytes(200, "application/vnd.ipld.car", car)
            }
        }
        "com.atproto.sync.getRecord" => {
            let did = params.get("did").unwrap();
            let collection = params.get("collection").unwrap();
            let rkey = params.get("rkey").unwrap();
            let (stored, fault) = WORLD.with(|cell| {
                let w = cell.borrow();
                let fault = w
                    .repo_proof_fault
                    .as_ref()
                    .filter(|(fd, fc, _)| fd == did && fc == collection)
                    .map(|(_, _, k)| *k);
                let rec = if collection == labyrinth::records::nsid::MAILBOX_KEYS {
                    w.mailbox_keys.get(&(did.clone(), rkey.clone())).cloned()
                } else if collection == "blue.catbird.chat.device" {
                    w.chat_devices.get(&(did.clone(), rkey.clone())).cloned()
                } else if collection == "blue.catbird.chat.deviceRevocation" {
                    w.chat_device_revocations
                        .get(&(did.clone(), rkey.clone()))
                        .cloned()
                } else if collection == "blue.catbird.chat.declaration" && rkey == "self" {
                    w.chat_declarations.get(did).cloned()
                } else {
                    None
                };
                (rec, fault)
            });
            if fault == Some("malformed_car") {
                return WireResponse::bytes(200, "application/vnd.ipld.car", vec![0xff; 24]);
            }
            let Some(mut rec) = stored else {
                return WireResponse::json(404, json!({"error": "RecordNotFound"}));
            };
            if fault == Some("tampered_value") {
                let mut mutated = rec.value.clone();
                mutated["createdAt"] = json!("1999-01-01T00:00:00.000Z");
                rec = canonical_record(&mutated).unwrap();
            }
            let signing_did = if fault == Some("wrong_signer") {
                "did:plc:wrongsigner0000000000000"
            } else {
                did.as_str()
            };
            let sk = SpaceSigningKey::from_p256_secret(&p256_key(signing_did, b"sign"), "#atproto");
            let (_, car) = build_repo_proof_car_v1(
                did,
                "3lb2zzzzzzzzz",
                &[(format!("{collection}/{rkey}"), rec.dagcbor)],
                &sk,
            )
            .unwrap();
            WireResponse::bytes(200, "application/vnd.ipld.car", car)
        }
        "com.atproto.repo.createRecord" => {
            let b: Value = serde_json::from_slice(body).unwrap();
            let repo = b["repo"].as_str().unwrap();
            let collection = b["collection"].as_str().unwrap();
            let rkey = b["rkey"].as_str().unwrap_or("self");
            let val = b.get("record").unwrap();
            let rec = canonical_record(val).unwrap();
            let cid = rec.cid.clone();
            WORLD
                .with(|cell| {
                    let mut w = cell.borrow_mut();
                    let key = (repo.to_owned(), rkey.to_owned());
                    let already_exists = if collection == labyrinth::records::nsid::MAILBOX_KEYS {
                        w.mailbox_keys.contains_key(&key)
                    } else if collection == "blue.catbird.chat.device" {
                        w.chat_devices.contains_key(&key)
                    } else if collection == "blue.catbird.chat.deviceRevocation" {
                        w.chat_device_revocations.contains_key(&key)
                    } else if collection == "blue.catbird.chat.declaration" {
                        w.chat_declarations.contains_key(repo)
                    } else {
                        false
                    };
                    if already_exists {
                        return Err(WireResponse::json(
                            400,
                            json!({"error": "RecordAlreadyExists", "message": "record already exists"}),
                        ));
                    }
                    match collection {
                        c if c == labyrinth::records::nsid::MAILBOX_KEYS => {
                            w.mailbox_keys.insert(key, rec);
                        }
                        "blue.catbird.chat.device" => {
                            w.chat_devices.insert(key, rec);
                        }
                        "blue.catbird.chat.deviceRevocation" => {
                            w.chat_device_revocations.insert(key, rec);
                        }
                        "blue.catbird.chat.declaration" => {
                            w.chat_declarations.insert(repo.to_owned(), rec);
                        }
                        _ => {}
                    }
                    Ok(())
                })
                .err()
                .unwrap_or_else(|| {
                    WireResponse::json(
                        200,
                        json!({
                            "uri": format!("at://{repo}/{collection}/{rkey}"),
                            "cid": cid,
                        }),
                    )
                })
        }
        "com.atproto.repo.putRecord" => {
            let b: Value = serde_json::from_slice(body).unwrap();
            let repo = b["repo"].as_str().unwrap();
            let collection = b["collection"].as_str().unwrap();
            let rkey = b["rkey"].as_str().unwrap();
            let val = b.get("record").unwrap();
            let rec = canonical_record(val).unwrap();
            let cid = rec.cid.clone();
            WORLD
                .with(|cell| {
                    let mut w = cell.borrow_mut();
                    match collection {
                        c if c == labyrinth::records::nsid::MAILBOX_KEYS => {
                            let cur = w.mailbox_keys.get(&(repo.to_owned(), rkey.to_owned()));
                            if b.get("swapRecord")
                                .and_then(Value::as_str)
                                .is_some_and(|swap| Some(swap) != cur.map(|r| r.cid.as_str()))
                            {
                                return Err(WireResponse::json(
                                    400,
                                    json!({"error": "InvalidSwap"}),
                                ));
                            }
                            w.mailbox_keys
                                .insert((repo.to_owned(), rkey.to_owned()), rec);
                        }
                        "blue.catbird.chat.device" => {
                            w.chat_devices
                                .insert((repo.to_owned(), rkey.to_owned()), rec);
                        }
                        "blue.catbird.chat.declaration" => {
                            w.chat_declarations.insert(repo.to_owned(), rec);
                        }
                        _ => {}
                    }
                    Ok(())
                })
                .err()
                .unwrap_or_else(|| {
                    WireResponse::json(
                        200,
                        json!({
                            "uri": format!("at://{repo}/{collection}/{rkey}"),
                            "cid": cid,
                        }),
                    )
                })
        }
        "com.atproto.repo.getRecord" => {
            let repo = params.get("repo").unwrap();
            let collection = params.get("collection").unwrap();
            let rkey = params.get("rkey").unwrap();
            WORLD.with(|cell| {
                let w = cell.borrow();
                let found = if collection == labyrinth::records::nsid::MAILBOX_KEYS {
                    w.mailbox_keys.get(&(repo.clone(), rkey.clone()))
                } else if collection == "blue.catbird.chat.device" {
                    w.chat_devices.get(&(repo.clone(), rkey.clone()))
                } else if collection == "blue.catbird.chat.deviceRevocation" {
                    w.chat_device_revocations.get(&(repo.clone(), rkey.clone()))
                } else {
                    None
                };
                match found {
                    Some(rec) => WireResponse::json(
                        200,
                        json!({
                            "uri": format!("at://{repo}/{collection}/{rkey}"),
                            "cid": rec.cid,
                            "value": rec.value,
                        }),
                    ),
                    None => WireResponse::json(404, json!({"error": "RecordNotFound"})),
                }
            })
        }
        "com.atproto.repo.listRecords" => {
            let repo = params.get("repo").unwrap();
            let collection = params.get("collection").unwrap();
            WORLD.with(|cell| {
                let w = cell.borrow();
                if let Some((status, code)) = w.pds_repo_status_for.get(repo) {
                    return WireResponse::json(*status, json!({ "error": code, "message": "mock PDS repo status" }));
                }
                let mut records = Vec::new();
                if collection == labyrinth::records::nsid::MAILBOX_KEYS {
                    for ((owner, rkey), rec) in &w.mailbox_keys {
                        if owner == repo {
                            records.push(json!({
                                "uri": format!("at://{repo}/{collection}/{rkey}"),
                                "cid": rec.cid,
                                "value": rec.value,
                            }));
                        }
                    }
                } else if collection == "blue.catbird.chat.device" {
                    for ((owner, rkey), rec) in &w.chat_devices {
                        if owner == repo {
                            records.push(json!({
                                "uri": format!("at://{repo}/{collection}/{rkey}"),
                                "cid": rec.cid,
                                "value": rec.value,
                            }));
                        }
                    }
                } else if collection == "blue.catbird.chat.deviceRevocation" {
                    for ((owner, rkey), rec) in &w.chat_device_revocations {
                        if owner == repo {
                            records.push(json!({
                                "uri": format!("at://{repo}/{collection}/{rkey}"),
                                "cid": rec.cid,
                                "value": rec.value,
                            }));
                        }
                    }
                }
                WireResponse::json(200, json!({ "records": records }))
            })
        }
        "com.atproto.repo.deleteRecord" => {
            let b: Value = serde_json::from_slice(body).unwrap();
            let repo = b["repo"].as_str().unwrap();
            let collection = b["collection"].as_str().unwrap();
            let rkey = b["rkey"].as_str().unwrap();
            WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                if collection == labyrinth::records::nsid::MAILBOX_KEYS {
                    w.mailbox_keys.remove(&(repo.to_owned(), rkey.to_owned()));
                } else if collection == "blue.catbird.chat.device" {
                    w.chat_devices.remove(&(repo.to_owned(), rkey.to_owned()));
                }
            });
            WireResponse::json(200, json!({}))
        }
        "com.atproto.repo.uploadBlob" => {
            let account = account_opt.expect("uploadBlob bearer");
            let mut cid_bytes = vec![1, 0x55, 0x12, 0x20];
            cid_bytes.extend_from_slice(&Sha256::digest(body));
            let cid = multibase::encode(multibase::Base::Base32Lower, cid_bytes);
            WORLD.with(|cell| {
                cell.borrow_mut()
                    .blobs
                    .insert((account, cid.clone()), body.to_vec());
            });
            WireResponse::json(
                200,
                json!({
                    "blob": {
                        "$type": "blob",
                        "ref": { "$link": cid },
                        "mimeType": "application/octet-stream",
                        "size": body.len(),
                    }
                }),
            )
        }
        "com.atproto.space.getDelegationToken" => {
            let account = account_opt.expect("delegation bearer");
            let space = SpaceUri::parse_hedged(params.get("space").unwrap()).unwrap();
            let seq = WORLD.with(|c| c.borrow_mut().next_seq());
            let claims = SpaceTokenClaims {
                iss: account.clone(),
                sub: space.raw,
                aud: Some(format!("{}#atproto_pds", space.authority)),
                iat: now_secs,
                exp: now_secs + 60,
                jti: format!("del-{seq}"),
                cnf_kid: None,
            };
            let token = mint_space_token(
                SpaceTokenKind::Delegation,
                &SpaceSigningKey::from_p256_secret(&p256_key(&account, b"sign"), "#atproto"),
                &claims,
            )
            .unwrap();
            WireResponse::json(200, json!({ "token": token }))
        }
        "com.atproto.space.authorizeSpaceSync" | "blue.catbird.chat.relaySpaceCredential" => {
            let account = account_opt.expect("credential bearer");
            let b: Value = serde_json::from_slice(body).unwrap();
            let space = SpaceUri::parse_hedged(b["space"].as_str().unwrap()).unwrap();
            if space.space_type == "blue.catbird.labyrinth.mailbox"
                && (space.authority != account || space.rkey != "self")
            {
                return WireResponse::json(403, json!({"error": "NotAuthorized"}));
            }
            let relayed = nsid.starts_with("blue.");
            let kid = b[if relayed { "cnfKey" } else { "credentialKey" }]
                .as_str()
                .unwrap();
            decode_p256_did_key(kid).unwrap();
            let del = complete_sync(verify_space_token(
                SpaceTokenKind::Delegation,
                b["delegationToken"].as_str().unwrap(),
                &FixtureKeys,
                now_secs,
            ))
            .unwrap();
            assert_eq!(del.iss, account);
            let seq = WORLD.with(|c| {
                let mut w = c.borrow_mut();
                assert!(w
                    .spent_delegations
                    .insert(format!("{}:{}", del.iss, del.jti)));
                w.next_seq()
            });
            let claims = SpaceTokenClaims {
                iss: space.authority.clone(),
                sub: space.raw,
                aud: None,
                iat: now_secs,
                exp: now_secs + 600,
                jti: format!("cred-{seq}"),
                cnf_kid: Some(kid.to_owned()),
            };
            let credential = mint_space_token(
                SpaceTokenKind::Credential,
                &SpaceSigningKey::from_p256_secret(
                    &p256_key(&space.authority, b"sign"),
                    "#atproto",
                ),
                &claims,
            )
            .unwrap();
            let expires = chrono::DateTime::from_timestamp(claims.exp as i64, 0)
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            WireResponse::json(
                200,
                json!({ "credential": credential, "expiresAt": expires }),
            )
        }
        "blue.catbird.chat.relaySpaceRead" => {
            let account = account_opt.expect("relaySpaceRead bearer");
            let b: Value = serde_json::from_slice(body).unwrap();
            let inner_nsid = b["nsid"].as_str().unwrap();
            let inner_params = parse_query_map(b["query"].as_str().unwrap_or(""));
            let audience = b["spaceAudience"].as_str().unwrap();
            assert_eq!(b["targetDid"].as_str().unwrap(), audience);
            let space_headers = SpaceRequestHeaders {
                authorization: format!(
                    "Atproto-Space-Credential {}",
                    b["credential"].as_str().unwrap()
                ),
                atproto_space_audience: audience.to_owned(),
                signature_input: b["signatureInput"].as_str().unwrap().to_owned(),
                signature: b["signature"].as_str().unwrap().to_owned(),
            };
            handle_space_read(
                Some(&account),
                inner_nsid,
                &inner_params,
                &space_headers,
                b["acceptSignature"].as_str(),
                now_secs,
            )
        }
        "com.atproto.space.applyWrites" => {
            let account = account_opt.expect("applyWrites bearer");
            if WORLD.with(|cell| cell.borrow().space_apply_fault) {
                return WireResponse::json(
                    500,
                    json!({"error": "InternalServerError", "message": "injected archive failure"}),
                );
            }
            let b: Value = serde_json::from_slice(body).unwrap();
            handle_space_apply(&account, &b)
        }
        "com.atproto.space.deleteRecord" => {
            let account = account_opt.expect("space deleteRecord bearer");
            let b: Value = serde_json::from_slice(body).unwrap();
            let converted = json!({
                "space": b["space"],
                "repo": b["repo"],
                "writes": [{
                    "$type": "com.atproto.space.applyWrites#delete",
                    "collection": b["collection"],
                    "rkey": b["rkey"],
                }]
            });
            handle_space_apply(&account, &converted)
        }
        "com.atproto.space.listSpaces" => {
            let account = account_opt.expect("listSpaces bearer");
            WORLD.with(|cell| {
                let w = cell.borrow();
                let spaces: BTreeSet<_> = w
                    .space_records
                    .keys()
                    .filter(|(_, repo, _, _)| repo == &account)
                    .map(|(s, _, _, _)| s.clone())
                    .collect();
                WireResponse::json(
                    200,
                    json!({
                        "spaces": spaces.into_iter().map(|u| json!({"uri": u})).collect::<Vec<_>>()
                    }),
                )
            })
        }
        _ if nsid.starts_with("com.atproto.space.") && method == "GET" => {
            let space_headers = SpaceRequestHeaders {
                authorization: find_header(headers, "authorization").unwrap().to_owned(),
                atproto_space_audience: find_header(headers, "atproto-space-audience")
                    .unwrap()
                    .to_owned(),
                signature_input: find_header(headers, "signature-input").unwrap().to_owned(),
                signature: find_header(headers, "signature").unwrap().to_owned(),
            };
            let accept_sig = find_header(headers, ACCEPT_SIGNATURE_HEADER);
            handle_space_read(
                account_opt.as_deref(),
                nsid,
                &params,
                &space_headers,
                accept_sig,
                now_secs,
            )
        }
        // --- Labyrinth zero-content mls-ds endpoints ---
        "blue.catbird.labyrinth.publishEpochHead" => {
            let account = account_opt.expect("publishEpochHead bearer");
            let b: Value = serde_json::from_slice(body).unwrap();
            let head: EpochPublicDef = serde_json::from_value(b["epoch"].clone()).unwrap();
            let parsed_pub = head.to_public().expect("valid EpochPublic");
            let attestor_pk = parsed_pub.attestation.transport_public_key;
            let not_authorized_once = WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                std::mem::take(&mut w.epoch_publish_not_authorized_once)
            });
            if not_authorized_once {
                return WireResponse::json(
                    403,
                    json!({
                        "error": "NotAuthorized",
                        "message": "injected pending epoch publication"
                    }),
                );
            }
            WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                let had_prior = w
                    .epoch_heads
                    .get(&account)
                    .is_some_and(|chain| !chain.is_empty());
                let chain = w.epoch_heads.entry(account.clone()).or_default();
                if chain.iter().all(|e| e.epoch_number != head.epoch_number) {
                    chain.push(head);
                    chain.sort_by_key(|e| e.epoch_number);
                }
                if had_prior {
                    if let Some(devs) = w.ds_devices.get_mut(&account) {
                        for d in devs.iter_mut() {
                            if d.signature_public_key.as_slice() == attestor_pk.as_slice()
                                && d.status == "pending_approval"
                            {
                                d.status = "active".to_owned();
                            }
                        }
                    }
                }
            });
            WireResponse::json(200, json!({}))
        }
        "blue.catbird.labyrinth.getEpochHead" => {
            let did = params.get("did").unwrap();
            WORLD.with(|cell| {
                let w = cell.borrow();
                match w
                    .epoch_heads
                    .get(did)
                    .and_then(|c| c.last().map(|l| (l, c)))
                {
                    Some((latest, chain)) => WireResponse::json(
                        200,
                        json!({
                            "epoch": latest,
                            "chain": chain,
                            "floorSeq": 0,
                        }),
                    ),
                    None => {
                        WireResponse::json(404, json!({"error": "EpochNotFound", "message": did}))
                    }
                }
            })
        }
        "blue.catbird.labyrinth.getMailboxKeysRecord" => {
            let did = params.get("did").unwrap();
            let rkey = params.get("rkey").unwrap();
            WORLD.with(|cell| {
                let w = cell.borrow();
                match w.mailbox_keys.get(&(did.clone(), rkey.clone())) {
                    Some(rec) => WireResponse::json(
                        200,
                        json!({
                            "uri": format!("at://{did}/{}/{rkey}", labyrinth::records::nsid::MAILBOX_KEYS),
                            "cid": rec.cid,
                            "value": rec.value,
                        }),
                    ),
                    None => WireResponse::json(404, json!({"error": "RecordNotFound"})),
                }
            })
        }
        "blue.catbird.labyrinth.getChatDeviceKeys" => {
            let did = params.get("did").unwrap();
            WORLD.with(|cell| {
                let w = cell.borrow();
                let items: Vec<_> = w
                    .ds_devices
                    .get(did)
                    .into_iter()
                    .flatten()
                    .map(|d| {
                        let mut item = json!({
                            "keyId": d.key_id,
                            "signingPublicKey": { "$bytes": d.signature_public_key_b64 },
                        });
                        if let Some(rev) = &d.revoked_at {
                            item["revokedAt"] = json!(rev);
                        }
                        item
                    })
                    .collect();
                WireResponse::json(200, json!({ "items": items }))
            })
        }
        "blue.catbird.labyrinth.getMemberDevices" => {
            let did = params.get("did").unwrap();
            WORLD.with(|cell| {
                let w = cell.borrow();
                let items: Vec<_> = w
                    .ds_devices
                    .get(did)
                    .into_iter()
                    .flatten()
                    .filter(|d| d.status != "pending_approval")
                    .map(|d| {
                        json!({
                            "signingPublicKey": { "$bytes": d.signature_public_key_b64 },
                            "joinedSeq": d.joined_seq,
                            "removedSeq": d.removed_seq,
                        })
                    })
                    .collect();
                WireResponse::json(200, json!({ "items": items }))
            })
        }
        "blue.catbird.labyrinth.getRecoveryShareCapabilities" => WireResponse::json(
            200,
            json!({
                "supported": true,
                "version": 1,
                "hpkeSuite": "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
                "keyId": "wave2-recovery-share-key-1",
            }),
        ),
        "blue.catbird.labyrinth.getRecoveryShare" => WireResponse::json(
            400,
            json!({"error": "RecoveryShareUnavailable"}),
        ),
        "blue.catbird.labyrinth.deleteRecoveryShare" => {
            let input: Value = serde_json::from_slice(body).unwrap();
            WireResponse::json(200, json!({"vdeviceId": input["vdeviceId"]}))
        }
        "blue.catbird.labyrinth.purgeMailbox" => WireResponse::json(200, json!({})),
        "blue.catbird.labyrinth.deleteAccountData" => {
            let account = account_opt.expect("deleteAccountData bearer");
            let fault = WORLD.with(|cell| cell.borrow().delete_account_fault);
            if fault {
                return WireResponse::json(
                    500,
                    json!({"error": "InternalServerError", "message": "injected D-3 remote failure"}),
                );
            }
            let decode_hdr = |name: &str| {
                headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .and_then(|(_, v)| {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(v)
                            .ok()
                    })
                    .unwrap_or_default()
            };
            let key_proof = decode_hdr(catbird_mls::labyrinth::write_auth::KEY_PROOF_HEADER);
            let rev_proof = decode_hdr(catbird_mls::labyrinth::write_auth::REVOCATION_PROOF_HEADER);
            WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                w.deleted_accounts.insert(account.clone());
                w.deleted_account_proofs
                    .insert(account.clone(), (key_proof, rev_proof));
                w.epoch_heads.remove(&account);
                w.ds_devices.remove(&account);
            });
            WireResponse::json(200, json!({}))
        }
        // --- Chat mls-ds endpoints ---
        "blue.catbird.chat.getOwnDevices" => {
            let account = account_opt.expect("getOwnDevices bearer");
            let caller_dev = params.get("actorDeviceId").cloned().unwrap_or_default();
            let fault_once = WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                std::mem::take(&mut w.get_own_devices_fault_once)
            });
            if fault_once {
                return WireResponse::json(
                    503,
                    json!({
                        "error": "ServiceUnavailable",
                        "message": "injected activation refresh failure"
                    }),
                );
            }
            WORLD.with(|cell| {
                let w = cell.borrow();
                let items: Vec<_> = w
                    .ds_devices
                    .get(&account)
                    .into_iter()
                    .flatten()
                    .map(|d| {
                        let mut item = json!({
                            "device": {
                                "deviceId": d.device_id,
                                "keyId": d.key_id,
                                "signaturePublicKey": { "$bytes": d.signature_public_key_b64 },
                                "authGeneration": d.auth_generation,
                                "status": d.status,
                                "availablePackageCount": d.key_packages.len(),
                                "reservedPackageCount": 0,
                                "createdAt": "2026-11-14T00:00:00.000Z",
                                "updatedAt": "2026-11-14T00:00:00.000Z",
                                "isCurrentDevice": d.device_id == caller_dev,
                            }
                        });
                        if d.device_id == caller_dev && d.dr_revision > 0 {
                            item["directRequestKeyPool"] = json!({
                                "enabled": true,
                                "revision": d.dr_revision,
                                "usableCount": 8,
                                "reservedCount": 0,
                                "asOf": "2026-11-14T00:00:00.000Z",
                                "usableUntil": "2026-12-20T00:00:00.000Z",
                            });
                        }
                        item
                    })
                    .collect();
                WireResponse::json(
                    200,
                    json!({
                        "items": items,
                        "hasMore": false,
                        "snapshotExpiresAt": "2026-11-14T00:10:00.000Z",
                    }),
                )
            })
        }
        "blue.catbird.chat.enrollDevice" => {
            let account = account_opt.expect("enrollDevice bearer");
            let wire: Value = serde_json::from_slice(body).unwrap();
            let b = &wire["signedRequest"]["body"];
            let dev_id = b["deviceId"].as_str().unwrap().to_owned();
            let key_id = b["keyId"].as_str().unwrap().to_owned();
            let pk_bytes = chat_wire::json_bytes(&b["signaturePublicKey"]).unwrap();
            let pk_b64 = STANDARD.encode(&pk_bytes);
            let kps = b["keyPackages"].as_array().cloned().unwrap_or_default();
            WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                let list = w.ds_devices.entry(account).or_default();
                if list.iter().any(|d| d.device_id == dev_id) {
                    return WireResponse::json(
                        400,
                        json!({"error": "DeviceAlreadyExists", "message": "DeviceAlreadyExists"}),
                    );
                }
                let has_active = list.iter().any(|d| d.status == "active");
                let status = if has_active {
                    "pending_approval"
                } else {
                    "active"
                };
                list.push(EnrolledDevice {
                    device_id: dev_id.clone(),
                    key_id: key_id.clone(),
                    signature_public_key_b64: pk_b64.clone(),
                    signature_public_key: pk_bytes,
                    auth_generation: 1,
                    status: status.to_owned(),
                    dr_revision: 0,
                    key_packages: kps.clone(),
                    joined_seq: 1,
                    removed_seq: None,
                    revoked_at: None,
                });
                WireResponse::json(
                    200,
                    json!({
                        "device": {
                            "deviceId": dev_id,
                            "keyId": key_id,
                            "signaturePublicKey": { "$bytes": pk_b64 },
                            "authGeneration": 1,
                            "status": status,
                            "availablePackageCount": kps.len(),
                            "reservedPackageCount": 0,
                            "createdAt": "2026-11-14T00:00:00.000Z",
                            "updatedAt": "2026-11-14T00:00:00.000Z",
                        }
                    }),
                )
            })
        }
        "blue.catbird.chat.publishDirectRequestKeys" => {
            let account = account_opt.expect("publishDirectRequestKeys bearer");
            let wire: Value = serde_json::from_slice(body).unwrap();
            let b = &wire["signedRequest"]["body"];
            let actor_dev = b["actorDeviceId"].as_str().unwrap().to_owned();
            let rev = b["revision"].as_u64().unwrap() as u32;
            WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                *w.device_calls
                    .entry((nsid.to_owned(), actor_dev.clone()))
                    .or_insert(0) += 1;
                let dev = w
                    .ds_devices
                    .get_mut(&account)
                    .and_then(|l| l.iter_mut().find(|d| d.device_id == actor_dev))
                    .expect("enrolled device");
                if dev.status == "pending_approval" {
                    return WireResponse::json(
                        400,
                        json!({"error": "PreparationConflict", "message": "device is pending_approval"}),
                    );
                }
                dev.dr_revision = rev;
                WireResponse::json(200, json!({"revision": rev, "enabled": true}))
            })
        }
        "blue.catbird.chat.replenishKeyPackages" => {
            let account = account_opt.expect("replenishKeyPackages bearer");
            let wire: Value = serde_json::from_slice(body).unwrap();
            let b = &wire["signedRequest"]["body"];
            let actor_dev = b["actorDeviceId"].as_str().unwrap().to_owned();
            let kps = b["keyPackages"].as_array().cloned().unwrap_or_default();
            WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                *w.device_calls
                    .entry((nsid.to_owned(), actor_dev.clone()))
                    .or_insert(0) += 1;
                let dev = w
                    .ds_devices
                    .get_mut(&account)
                    .and_then(|l| l.iter_mut().find(|d| d.device_id == actor_dev))
                    .expect("enrolled device");
                if dev.status == "pending_approval" {
                    return WireResponse::json(
                        403,
                        json!({"error": "NotAuthorized", "message": "device is pending_approval"}),
                    );
                }
                let accepted = kps.len();
                dev.key_packages.extend(kps);
                WireResponse::json(200, json!({"acceptedCount": accepted}))
            })
        }
        "blue.catbird.chat.approveDevice" => {
            let account = account_opt.expect("approveDevice bearer");
            let wire: Value = serde_json::from_slice(body).unwrap();
            let b = &wire["signedRequest"]["body"];
            assert_eq!(
                b["signatureDomain"].as_str(),
                Some("CATBIRD-CHAT-DEVICE-APPROVE\0")
            );
            let actor_dev = b["actorDeviceId"].as_str().unwrap();
            let target_dev = b["targetDeviceId"].as_str().unwrap();
            let target_pk = chat_wire::json_bytes(&b["targetSignaturePublicKey"]).unwrap();
            WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                let list = w.ds_devices.get_mut(&account).expect("account devices");
                let actor = list
                    .iter()
                    .find(|d| d.device_id == actor_dev)
                    .expect("actor device");
                assert_eq!(actor.status, "active", "approver must be active");
                let target = list
                    .iter_mut()
                    .find(|d| d.device_id == target_dev)
                    .expect("target device");
                assert_eq!(target.signature_public_key, target_pk);
                target.status = "active".to_owned();
                WireResponse::json(
                    200,
                    json!({
                        "device": {
                            "deviceId": target.device_id,
                            "keyId": target.key_id,
                            "signaturePublicKey": { "$bytes": target.signature_public_key_b64 },
                            "authGeneration": target.auth_generation,
                            "status": "active",
                        }
                    }),
                )
            })
        }
        "blue.catbird.chat.revokeDevice" => {
            let account = account_opt.expect("revokeDevice bearer");
            let wire: Value = serde_json::from_slice(body).unwrap();
            let b = &wire["signedRequest"]["body"];
            assert_eq!(
                b["signatureDomain"].as_str(),
                Some("CATBIRD-CHAT-DEVICE-REVOKE\0")
            );
            let target_dev = b["targetDeviceId"].as_str().unwrap();
            WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                let list = w.ds_devices.get_mut(&account).expect("account devices");
                let target = list
                    .iter_mut()
                    .find(|d| d.device_id == target_dev)
                    .expect("target device");
                target.status = "revoked".to_owned();
                target.revoked_at = Some("2026-11-14T00:05:00.000Z".into());
                target.removed_seq = Some(99);
            });
            WireResponse::json(200, json!({}))
        }
        "blue.catbird.chat.createConversation" => {
            let wire: Value = serde_json::from_slice(body).unwrap();
            let submitted = &wire["signedRequest"];
            let b = &submitted["body"];
            let cid = b["conversationId"].as_str().unwrap().to_owned();
            let next_coords = b["next"].clone();
            let participants = b["manifest"]["participants"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let actor_did = b["actorDid"].as_str().unwrap();
            let actor_dev = b["actorDeviceId"].as_str().unwrap();
            let entry = json!({
                "$type": "blue.catbird.chat.defs#creationEntry",
                "entryId": b["transitionId"],
                "conversationId": cid,
                "seq": 1,
                "signedRequest": submitted,
                "receivedAt": b["signedAt"],
                "sequencerReceipt": mint_i13_receipt(b, 1, b["transitionId"].as_str(), true),
            });
            WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                w.convo_seq.insert(cid.clone(), 1);
                w.convo_entries.insert(cid.clone(), vec![entry.clone()]);
                w.convo_states.insert(
                    cid.clone(),
                    ConversationFixtureState {
                        kind: b["conversationKind"].as_str().unwrap_or("group").to_owned(),
                        coordinates: next_coords.clone(),
                        participants,
                        leaves: vec![json!({
                            "userDid": actor_did,
                            "deviceId": actor_dev,
                        })],
                        pending_leave_requests: Vec::new(),
                        account_deletions: Vec::new(),
                    },
                );
            });
            WireResponse::json(
                200,
                json!({
                    "result": {
                        "$type": "blue.catbird.chat.defs#conversationCreatedResult",
                        "coordinates": next_coords,
                        "entry": entry,
                    }
                }),
            )
        }
        "blue.catbird.chat.sendMessage" => {
            let wire: Value = serde_json::from_slice(body).unwrap();
            let submitted = &wire["signedRequest"];
            let b = &submitted["body"];
            let cid = b["prior"]["conversationId"].as_str().unwrap().to_owned();
            let seq = WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                let s = w.convo_seq.entry(cid.clone()).or_insert(1);
                *s += 1;
                *s
            });
            let receipt = mint_i13_receipt(b, seq, None, false);
            let entry = json!({
                "$type": "blue.catbird.chat.defs#applicationEntry",
                "entryId": b["messageId"],
                "conversationId": cid,
                "seq": seq,
                "signedRequest": submitted,
                "sequencerReceipt": receipt,
                "receivedAt": "2026-11-14T00:01:00.000Z",
            });
            WORLD.with(|cell| {
                cell.borrow_mut()
                    .convo_entries
                    .entry(cid)
                    .or_default()
                    .push(entry.clone());
            });
            WireResponse::json(200, json!({ "entry": entry }))
        }
        "blue.catbird.chat.getConversationState" => {
            let cid = params.get("conversationId").unwrap();
            WORLD.with(|cell| {
                let w = cell.borrow();
                let Some(st) = w.convo_states.get(cid) else {
                    return WireResponse::json(
                        404,
                        json!({"error": "ConversationNotFound", "message": cid}),
                    );
                };
                let after = params
                    .get("deletionsAfter")
                    .and_then(|raw| raw.parse::<i64>().ok())
                    .unwrap_or(0);
                let mut rows = st
                    .account_deletions
                    .iter()
                    .filter(|v| v["seq"].as_i64().is_some_and(|seq| seq > after));
                let page: Vec<_> = rows.by_ref().take(100).collect();
                let more = rows.next().is_some();
                let mut result = json!({
                    "sequencerDid": SEQUENCER,
                    "state": {
                        "conversationId": cid,
                        "sequencerDid": SEQUENCER,
                        "conversationKind": st.kind,
                        "coordinates": st.coordinates,
                        "participants": st.participants,
                        "leaves": st.leaves,
                    },
                    "accountDeletions": page,
                    "pendingLeaveRequests": st.pending_leave_requests,
                    "pendingLeafRecoveryRequests": [],
                });
                if more {
                    result["deletionsCursor"] = page.last().unwrap()["seq"].clone();
                }
                WireResponse::json(200, result)
            })
        }
        "blue.catbird.chat.closeConversation" => {
            let wire: Value = serde_json::from_slice(body).unwrap();
            let submitted = &wire["signedRequest"];
            let b = &submitted["body"];
            let cid = b["retired"]["conversationId"].as_str().unwrap().to_owned();
            let seq = WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                let next = {
                    let s = w.convo_seq.entry(cid.clone()).or_insert(1);
                    *s += 1;
                    *s
                };
                if let Some(st) = w.convo_states.get_mut(&cid) {
                    st.coordinates = b["retired"].clone();
                }
                next
            });
            let tombstone = json!({
                "conversationId": cid,
                "conversationKind": b["conversationKind"],
                "retired": b["retired"],
                "closedByDid": b["actorDid"],
                "closedByDeviceId": b["actorDeviceId"],
                "terminalSeq": seq,
                "closedAt": b["signedAt"],
            });
            let mut entry = json!({
                "$type": "blue.catbird.chat.defs#conversationCloseEntry",
                "entryId": b["transitionId"],
                "conversationId": cid,
                "seq": seq,
                "signedRequest": submitted,
                "tombstone": tombstone,
                "receivedAt": b["signedAt"],
            });
            entry["sequencerReceipt"] = mint_i13_receipt(b, seq, b["transitionId"].as_str(), true);
            WireResponse::json(
                200,
                json!({
                    "result": {
                        "$type": "blue.catbird.chat.defs#conversationClosedResult",
                        "coordinates": b["retired"],
                        "tombstone": tombstone,
                        "entry": entry,
                    }
                }),
            )
        }
        "blue.catbird.chat.requestLeave" => {
            let wire: Value = serde_json::from_slice(body).unwrap();
            let submitted = &wire["signedRequest"];
            let b = &submitted["body"];
            let body_type = b["$type"].as_str().unwrap();
            if body_type == "blue.catbird.chat.defs#zeroLeafLeaveBody" {
                let cid = b["next"]["conversationId"].as_str().unwrap().to_owned();
                let seq = WORLD.with(|cell| {
                    let mut w = cell.borrow_mut();
                    let next = {
                        let s = w.convo_seq.entry(cid.clone()).or_insert(1);
                        *s += 1;
                        *s
                    };
                    if let Some(st) = w.convo_states.get_mut(&cid) {
                        st.coordinates = b["next"].clone();
                    }
                    next
                });
                let entry = json!({
                    "$type": "blue.catbird.chat.defs#zeroLeafLeaveEntry",
                    "entryId": b["transitionId"],
                    "conversationId": cid,
                    "seq": seq,
                    "signedRequest": submitted,
                    "receivedAt": b["signedAt"],
                    "sequencerReceipt": mint_i13_receipt(b, seq, b["transitionId"].as_str(), true),
                });
                return WireResponse::json(
                    200,
                    json!({
                        "result": {
                            "$type": "blue.catbird.chat.defs#immediateLeaveResult",
                            "coordinates": b["next"],
                            "entry": entry,
                        }
                    }),
                );
            }
            assert_eq!(body_type, "blue.catbird.chat.defs#leaveRequestBody");
            let cid = b["prior"]["conversationId"].as_str().unwrap().to_owned();
            let req_id = b["leaveRequestId"].as_str().unwrap().to_owned();
            let leave_view = json!({
                "leaveRequestId": req_id,
                "requesterDid": b["actorDid"],
                "requesterDeviceId": b["actorDeviceId"],
                "status": "pending",
                "prior": b["prior"],
                "requestedAt": b["signedAt"],
                "expiresAt": "2099-01-01T00:00:00.000Z",
            });
            WORLD.with(|cell| {
                if let Some(st) = cell.borrow_mut().convo_states.get_mut(&cid) {
                    st.pending_leave_requests.push(leave_view.clone());
                }
            });
            WireResponse::json(
                200,
                json!({
                    "result": {
                        "$type": "blue.catbird.chat.defs#durableLeaveRequestResult",
                        "leaveRequest": leave_view,
                    }
                }),
            )
        }
        "blue.catbird.chat.submitTransition" => {
            let wire: Value = serde_json::from_slice(body).unwrap();
            let submitted = &wire["signedRequest"];
            let b = &submitted["body"];
            let cid = b["next"]["conversationId"].as_str().unwrap().to_owned();
            let body_variant = b["$type"].as_str().unwrap().rsplit('#').next().unwrap();
            let entry_variant = match body_variant {
                "leaveCommitFulfillmentBody" => "leaveCommitFulfillmentEntry",
                "commitTransitionBody" => "commitEntry",
                "metadataTransitionBody" => "metadataEntry",
                other => panic!("unexpected transition variant: {other}"),
            };
            let seq = WORLD.with(|cell| {
                let mut w = cell.borrow_mut();
                let next = {
                    let s = w.convo_seq.entry(cid.clone()).or_insert(1);
                    *s += 1;
                    *s
                };
                if let Some(st) = w.convo_states.get_mut(&cid) {
                    st.coordinates = b["next"].clone();
                    if let Some(leave_id) = b.get("leaveRequestId").and_then(Value::as_str) {
                        st.pending_leave_requests
                            .retain(|r| r["leaveRequestId"].as_str() != Some(leave_id));
                    }
                }
                next
            });
            let entry = json!({
                "$type": format!("blue.catbird.chat.defs#{entry_variant}"),
                "entryId": b["transitionId"],
                "conversationId": cid,
                "seq": seq,
                "signedRequest": submitted,
                "receivedAt": b["signedAt"],
                "sequencerReceipt": mint_i13_receipt(b, seq, b["transitionId"].as_str(), true),
            });
            WireResponse::json(
                200,
                json!({
                    "coordinates": b["next"],
                    "entry": entry,
                    "welcomes": [],
                }),
            )
        }
        "blue.catbird.chat.getConversations" | "blue.catbird.chat.getPendingWelcomes" => {
            WireResponse::json(200, json!({ "items": [], "hasMore": false }))
        }
        other => panic!("unexpected XRPC in Wave-2 WASM test fixture: {method} {other} ({url})"),
    }
}

fn install_fixture() -> RestoreFetch {
    WORLD.with(|cell| *cell.borrow_mut() = Wave2World::default());
    let cb = Closure::<dyn Fn(String, String, String, Vec<u8>) -> String>::new(dispatch_fetch);
    installWave2Fetch(cb.as_ref().unchecked_ref());
    cb.forget();
    RestoreFetch
}

fn make_did(tag: &str) -> String {
    format!("did:plc:{tag:a<24}")
}

fn db_path_for(did: &str, device_id: &str) -> String {
    format!(
        "catbird-mls/{}-{device_id}.db",
        hex::encode(Sha256::digest(did.as_bytes()))
    )
}

async fn open_client(did: &str, device_id: &str) -> WasmMlsClient {
    let db_path = db_path_for(did, device_id);
    let client = WasmMlsClient::open_with_db_path_async(
        did.into(),
        device_id.into(),
        SEQUENCER.into(),
        "https://ds.catbird.test".into(),
        "https://pds.catbird.test".into(),
        "ab".repeat(32),
        &db_path,
    )
    .await
    .unwrap();
    client.set_auth_token(Some(format!("session:{did}")));
    client
}

async fn enroll(client: &WasmMlsClient) -> EnrollmentReceipt {
    let scopes = serde_wasm_bindgen::to_value(&REQUIRED_LABYRINTH_OAUTH_SCOPES).unwrap();
    let val = client.enroll_device(true, scopes).await.unwrap();
    serde_wasm_bindgen::from_value(val).unwrap()
}

fn device_call_count(nsid: &str, device_id: &str) -> u32 {
    WORLD.with(|c| {
        c.borrow()
            .device_calls
            .get(&(nsid.to_owned(), device_id.to_owned()))
            .copied()
            .unwrap_or(0)
    })
}
fn call_count(nsid: &str) -> u32 {
    WORLD.with(|cell| cell.borrow().calls.get(nsid).copied().unwrap_or(0))
}

fn set_declared_home(did: &str, home_ds_did: &str) {
    WORLD.with(|cell| {
        let mut world = cell.borrow_mut();
        let mut value = world
            .chat_declarations
            .get(did)
            .expect("chat declaration")
            .value
            .clone();
        value["deliveryService"] = json!(home_ds_did);
        world
            .chat_declarations
            .insert(did.to_owned(), canonical_record(&value).unwrap());
    });
}

fn seed_fake_v3_bundle(did: &str, code: &RecoveryCode) {
    let vdevice_id = code.vdevice_id(did);
    WORLD.with(|cell| {
        let mut world = cell.borrow_mut();
        let (existing_key, existing) = world
            .space_records
            .iter()
            .find(|((_, repo, collection, _), _)| {
                repo == did && collection == labyrinth::records::nsid::VIRTUAL_DEVICE
            })
            .map(|(key, record)| (key.clone(), record.clone()))
            .expect("existing v2 virtual-device bundle");
        let mut value = existing.value;
        value["vdeviceId"] = json!({"$bytes": STANDARD.encode(vdevice_id)});
        value
            .as_object_mut()
            .expect("virtual-device object")
            .remove("metadataSig");
        let record = canonical_record(&value).unwrap();
        let rkey = hex::encode(vdevice_id);
        let key = (
            existing_key.0.clone(),
            did.to_owned(),
            labyrinth::records::nsid::VIRTUAL_DEVICE.to_owned(),
            rkey.clone(),
        );
        let rev = tid(world.next_seq());
        world.space_records.insert(key, record.clone());
        world
            .repo_revisions
            .insert((existing_key.0.clone(), did.to_owned()), rev.clone());
        world
            .space_ops
            .entry((existing_key.0, did.to_owned()))
            .or_default()
            .push(json!({
                "collection": labyrinth::records::nsid::VIRTUAL_DEVICE,
                "rkey": rkey,
                "rev": rev,
                "cid": record.cid,
                "prev": null,
            }));
    });
}


/// `#87`/`#89` `pending_approval` 2nd-device enrollment seam + `D-1` CARv1 `repo_proof` tamper
/// rejection + sibling `approveDevice` + post-approval promotion + `listDevices` + `revokeDevice`.
#[wasm_bindgen_test]
async fn pending_approval_second_device_car_v1_approval_and_device_revocation() {
    let _fx = install_fixture();
    let did = make_did("wave2pendingdev");
    let dev1_id = "00000000-0000-4000-8000-000000000101";
    let dev2_id = "00000000-0000-4000-8000-000000000102";

    // 1. Primary device enrolls active, publishes DR keys + KPs, and initializes live Labyrinth.
    let dev1 = open_client(&did, dev1_id).await;
    let _ = enroll(&dev1).await;
    assert!(!dev1.is_device_pending_approval().unwrap());
    assert_eq!(
        device_call_count("blue.catbird.chat.publishDirectRequestKeys", dev1_id),
        1
    );
    assert_eq!(
        device_call_count("blue.catbird.chat.replenishKeyPackages", dev1_id),
        1
    );
    let lab_st: LabyrinthBackupStatus =
        serde_wasm_bindgen::from_value(dev1.enable_labyrinth_live().await.unwrap()).unwrap();
    assert_eq!(lab_st.epoch_seq, 0);
    let bootstrap_recovery_code = dev1.create_recovery_code_live().await.unwrap();

    // 2. Second browser device enrolls -> `mls-ds` returns `status: "pending_approval"`.
    let mut dev2 = open_client(&did, dev2_id).await;
    let _ = enroll(&dev2).await;
    assert!(
        dev2.is_device_pending_approval().unwrap(),
        "2nd device must enter pending_approval"
    );
    let calls_before_delete = WORLD.with(|c| c.borrow().calls.clone());
    let error = dev2.delete_account_data().await.unwrap_err();
    assert!(error.as_string().unwrap().contains("DevicePendingApproval"));
    assert!(dev2.is_device_pending_approval().unwrap());
    WORLD.with(|c| assert_eq!(c.borrow().calls, calls_before_delete));
    assert_eq!(
        device_call_count("blue.catbird.chat.publishDirectRequestKeys", dev2_id),
        0,
        "pending_approval device must skip publishDirectRequestKeys (#87/#89)"
    );
    assert_eq!(
        device_call_count("blue.catbird.chat.replenishKeyPackages", dev2_id),
        0,
        "pending_approval device must skip replenishKeyPackages (#87/#89)"
    );
    let replenish_err = dev2
        .replenish_key_packages(4)
        .await
        .expect_err("pending_approval replenish must fail closed")
        .as_string()
        .unwrap();
    assert!(
        replenish_err.contains("DevicePendingApproval"),
        "{replenish_err}"
    );
    let listed_pending: Vec<RegisteredDeviceInfo> =
        serde_wasm_bindgen::from_value(dev2.list_devices().await.unwrap()).unwrap();
    assert_eq!(listed_pending.len(), 2);
    assert!(listed_pending
        .iter()
        .any(|d| d.device_id == dev2_id && d.status == "pending_approval" && d.is_current_device));

    // 3. Sibling `dev1` attempts `approveDevice` while PDS `sync.getRecord` serves a tampered CARv1:
    //    `D-1` CARv1 MST/value verification MUST reject before signing `#deviceApprovalBody`.
    WORLD.with(|c| {
        c.borrow_mut().repo_proof_fault = Some((
            did.clone(),
            "blue.catbird.chat.device".into(),
            "tampered_value",
        ));
    });
    let tamper_err = dev1
        .approve_device(dev2_id.into())
        .await
        .expect_err("tampered CARv1 repo_proof must fail closed (D-1)")
        .as_string()
        .unwrap();
    assert!(
        tamper_err.contains("CARv1") || tamper_err.contains("I4"),
        "{tamper_err}"
    );

    // Clear fault -> `dev1.approve_device(dev2)` verifies CARv1 proof and promotes `dev2`.
    WORLD.with(|c| c.borrow_mut().repo_proof_fault = None);
    dev1.approve_device(dev2_id.into()).await.unwrap();

    // 4. `dev2` re-runs `enrollDevice` -> promotes to active, publishes DR keys + replenishes KPs!
    let _ = enroll(&dev2).await;
    let _: LabyrinthBackupStatus = serde_wasm_bindgen::from_value(
        dev2
            .restore_with_recovery_code_live(bootstrap_recovery_code)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        !dev2.is_device_pending_approval().unwrap(),
        "approved device must clear pending_approval"
    );
    assert_eq!(
        device_call_count("blue.catbird.chat.publishDirectRequestKeys", dev2_id),
        1
    );
    assert_eq!(
        device_call_count("blue.catbird.chat.replenishKeyPackages", dev2_id),
        1
    );
    drop(dev2);

    // 5. A replacement recovery code must survive the unified revoke return. An unproven
    // home-service route fails before the DS mutation, and the durable reminder is explicit.
    let _old_recovery_code = dev1.create_recovery_code_live().await.unwrap();
    let acknowledged: LabyrinthBackupStatus = serde_wasm_bindgen::from_value(
        dev1.acknowledge_recovery_attention().unwrap(),
    )
    .unwrap();
    assert!(!acknowledged.recovery_needs_attention);

    let revoke_calls_before = call_count("blue.catbird.chat.revokeDevice");
    set_declared_home(&did, "did:web:other.catbird.test");
    let pin_err = dev1
        .revoke_device(dev2_id.into())
        .await
        .expect_err("unproven recovery-share home must fail before DS revocation")
        .as_string()
        .unwrap();
    assert!(pin_err.contains("configured service"), "{pin_err}");
    assert_eq!(
        call_count("blue.catbird.chat.revokeDevice"),
        revoke_calls_before
    );
    assert!(WORLD.with(|cell| {
        cell.borrow().ds_devices[&did]
            .iter()
            .any(|device| device.device_id == dev2_id && device.status == "active")
    }));

    set_declared_home(&did, SEQUENCER);
    let self_revoke_err = dev1
        .revoke_device(dev1_id.into())
        .await
        .expect_err("self-revoke must fail closed")
        .as_string()
        .unwrap();
    assert!(
        self_revoke_err.contains("retireCurrentDevice"),
        "{self_revoke_err}"
    );
    WORLD.with(|cell| cell.borrow_mut().space_apply_fault = true);
    let archive_err = dev1
        .revoke_device(dev2_id.into())
        .await
        .expect_err("archive rotation failure must not be reported as revoke success")
        .as_string()
        .unwrap();
    assert!(archive_err.contains("injected archive failure"), "{archive_err}");
    assert_eq!(
        call_count("blue.catbird.chat.revokeDevice"),
        revoke_calls_before + 1
    );
    let failed_status: LabyrinthBackupStatus =
        serde_wasm_bindgen::from_value(dev1.labyrinth_status().unwrap()).unwrap();
    assert!(
        failed_status.recovery_needs_attention,
        "pre-rotation replacement-code reminder must survive archive failure"
    );

    drop(dev1);
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev1_id));
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev2_id));
}

/// Live Recovery Code + Passkey PRF enrollment/restore. Ordinary sync must retry a held epoch even
/// with an empty archive queue, and retain a durable activation retry across reopen.
#[wasm_bindgen_test]
async fn recovery_code_and_passkey_prf_live_restore_promote_pending_approval_device() {
    let _fx = install_fixture();
    let did = make_did("wave2recoverprf");
    let dev1_id = "00000000-0000-4000-8000-000000000201";
    let dev2_id = "00000000-0000-4000-8000-000000000202";
    let dev3_id = "00000000-0000-4000-8000-000000000203";

    let cred_id = b"webauthn-cred-wave2-01";
    let prf_secret = [0x42u8; 32];

    // 1. `dev1` enables Labyrinth live, creates a live 40-char recovery code, and registers Passkey PRF.
    let dev1 = open_client(&did, dev1_id).await;
    let _ = enroll(&dev1).await;
    let _ = dev1.enable_labyrinth_live().await.unwrap();
    let recovery_code = dev1.create_recovery_code_live().await.unwrap();
    assert!(!recovery_code.is_empty());
    let prf_status: LabyrinthBackupStatus = serde_wasm_bindgen::from_value(
        dev1.register_passkey_prf_live(cred_id, &prf_secret)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(prf_status.has_passkey_prf);
    assert!(prf_status.has_recovery_code);
    let share_capabilities_before =
        call_count("blue.catbird.labyrinth.getRecoveryShareCapabilities");

    // 2. `dev2` restores while epoch publication is held. A later ordinary sync publishes the
    //    held head despite an empty archive queue, but its first authoritative mls-ds activation
    //    read fails. Pending local enrollment and the durable refresh intent must survive.
    let dev2 = open_client(&did, dev2_id).await;
    let _ = enroll(&dev2).await;
    assert!(dev2.is_device_pending_approval().unwrap());
    WORLD.with(|cell| {
        let mut world = cell.borrow_mut();
        world.epoch_publish_not_authorized_once = true;
        world.get_own_devices_fault_once = true;
    });
    let restored2: LabyrinthBackupStatus = serde_wasm_bindgen::from_value(
        dev2.restore_with_recovery_code_live(recovery_code)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(restored2.epoch_seq >= 1);
    assert!(
        restored2.pending_directory_epoch.is_some(),
        "NotAuthorized publication must leave a verified held epoch"
    );
    assert!(dev2.is_device_pending_approval().unwrap());
    assert_eq!(
        device_call_count("blue.catbird.chat.publishDirectRequestKeys", dev2_id),
        0
    );
    assert_eq!(
        device_call_count("blue.catbird.chat.replenishKeyPackages", dev2_id),
        0
    );

    assert_eq!(
        dev2.flush_labyrinth_queue().await.unwrap(),
        0,
        "the lifecycle retry must not depend on queued archive work"
    );
    dev2.sync().await.unwrap();
    let published2: LabyrinthBackupStatus =
        serde_wasm_bindgen::from_value(dev2.labyrinth_status().unwrap()).unwrap();
    assert!(
        published2.pending_directory_epoch.is_none(),
        "ordinary sync must publish the held epoch"
    );
    let directory_status = WORLD.with(|cell| {
        cell.borrow()
            .ds_devices
            .get(&did)
            .and_then(|devices| {
                devices
                    .iter()
                    .find(|device| device.device_id == dev2_id)
            })
            .map(|device| device.status.clone())
    });
    assert_eq!(directory_status.as_deref(), Some("active"));
    assert!(
        dev2.is_device_pending_approval().unwrap(),
        "failed authoritative activation refresh must retain local pending state"
    );
    assert_eq!(
        device_call_count("blue.catbird.chat.publishDirectRequestKeys", dev2_id),
        0
    );
    assert_eq!(
        device_call_count("blue.catbird.chat.replenishKeyPackages", dev2_id),
        0
    );

    drop(dev2);
    let dev2 = open_client(&did, dev2_id).await;
    assert!(
        dev2.is_device_pending_approval().unwrap(),
        "local pending state must survive reopen"
    );
    assert_eq!(
        dev2.flush_labyrinth_queue().await.unwrap(),
        0,
        "the durable activation retry must not depend on queued archive work"
    );
    dev2.sync().await.unwrap();
    let retried2: LabyrinthBackupStatus =
        serde_wasm_bindgen::from_value(dev2.labyrinth_status().unwrap()).unwrap();
    assert!(retried2.pending_directory_epoch.is_none());
    assert!(
        !dev2.is_device_pending_approval().unwrap(),
        "durable intent must retry and clear pending only after mls-ds confirms active"
    );
    assert_eq!(
        device_call_count("blue.catbird.chat.publishDirectRequestKeys", dev2_id),
        1
    );
    assert_eq!(
        device_call_count("blue.catbird.chat.replenishKeyPackages", dev2_id),
        1
    );

    // 3. `dev3` enrolls as `pending_approval`, rejects wrong PRF output, then restores + promotes
    //    via `restoreWithPasskeyPrf`!
    let dev3 = open_client(&did, dev3_id).await;
    let _ = enroll(&dev3).await;
    assert!(dev3.is_device_pending_approval().unwrap());
    let wrong_prf = [0x99u8; 32];
    assert!(
        dev3.restore_with_passkey_prf(cred_id, &wrong_prf)
            .await
            .is_err(),
        "wrong Passkey PRF output must fail closed"
    );
    assert!(dev3.is_device_pending_approval().unwrap());

    let restored3: LabyrinthBackupStatus = serde_wasm_bindgen::from_value(
        dev3.restore_with_passkey_prf(cred_id, &prf_secret)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(restored3.epoch_seq >= 2);
    assert!(
        !dev3.is_device_pending_approval().unwrap(),
        "passkey PRF restore must promote pending_approval device"
    );
    assert_eq!(
        device_call_count("blue.catbird.chat.publishDirectRequestKeys", dev3_id),
        1
    );
    drop(dev1);
    drop(dev2);
    assert_eq!(
        call_count("blue.catbird.labyrinth.getRecoveryShareCapabilities"),
        share_capabilities_before,
        "ordinary v2 code and passkey restores must not require a share service"
    );
    drop(dev3);
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev1_id));
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev2_id));
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev3_id));
}

/// A version-3 code is matched against stored bundles before its version controls routing.
/// Its fetch token never reaches a service until the account declaration is proven and pinned.
#[wasm_bindgen_test]
async fn v3_recovery_uses_only_the_proven_home_share_service() {
    let _fx = install_fixture();
    let did = make_did("wave2v3recover");
    let dev1_id = "00000000-0000-4000-8000-000000000211";
    let dev2_id = "00000000-0000-4000-8000-000000000212";

    let dev1 = open_client(&did, dev1_id).await;
    let _ = enroll(&dev1).await;
    let _ = dev1.enable_labyrinth_live().await.unwrap();
    let _v2_code = dev1.create_recovery_code_live().await.unwrap();
    let v3_code = RecoveryCode::from_entropy_symbols_v3(&[7u8; 34]);
    seed_fake_v3_bundle(&did, &v3_code);

    let dev2 = open_client(&did, dev2_id).await;
    let _ = enroll(&dev2).await;
    set_declared_home(&did, "did:web:other.catbird.test");
    let capabilities_before =
        call_count("blue.catbird.labyrinth.getRecoveryShareCapabilities");
    let unproven = dev2
        .restore_with_recovery_code_live(v3_code.to_string())
        .await
        .expect_err("v3 share routing must fail before an unproven home service")
        .as_string()
        .unwrap();
    assert!(unproven.contains("configured service"), "{unproven}");
    assert_eq!(
        call_count("blue.catbird.labyrinth.getRecoveryShareCapabilities"),
        capabilities_before
    );
    assert_eq!(call_count("blue.catbird.labyrinth.getRecoveryShare"), 0);

    set_declared_home(&did, SEQUENCER);
    let missing_share = dev2
        .restore_with_recovery_code_live(v3_code.to_string())
        .await
        .expect_err("known v3 bundle without its server share must fail closed")
        .as_string()
        .unwrap();
    assert!(
        missing_share.contains("RecoveryShareUnavailable")
            || missing_share
                .to_ascii_lowercase()
                .contains("recovery share unavailable"),
        "{missing_share}"
    );
    assert_eq!(
        call_count("blue.catbird.labyrinth.getRecoveryShareCapabilities"),
        capabilities_before + 1
    );
    assert_eq!(call_count("blue.catbird.labyrinth.getRecoveryShare"), 1);
    assert_eq!(call_count("com.atproto.identity.resolveDid"), 0);

    drop(dev1);
    drop(dev2);
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev1_id));
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev2_id));
}

#[wasm_bindgen_test]
async fn labyrinth_only_revoke_returns_replacement_code_and_durable_attention() {
    let _fx = install_fixture();
    let did = make_did("wave2labrevoke");
    let dev1_id = "00000000-0000-4000-8000-000000000221";
    let dev2_id = "00000000-0000-4000-8000-000000000222";

    let dev1 = open_client(&did, dev1_id).await;
    let _ = enroll(&dev1).await;
    let _ = dev1.enable_labyrinth_live().await.unwrap();
    let bootstrap_recovery_code = dev1.create_recovery_code_live().await.unwrap();
    let dev2 = open_client(&did, dev2_id).await;
    let _ = enroll(&dev2).await;
    dev1.approve_device(dev2_id.into()).await.unwrap();
    let _ = enroll(&dev2).await;
    let _: LabyrinthBackupStatus = serde_wasm_bindgen::from_value(
        dev2
            .restore_with_recovery_code_live(bootstrap_recovery_code)
            .await
            .unwrap(),
    )
    .unwrap();

    let devices: Vec<RegisteredDeviceInfo> =
        serde_wasm_bindgen::from_value(dev1.list_devices().await.unwrap()).unwrap();
    let target = devices
        .iter()
        .find(|device| device.device_id == dev2_id)
        .and_then(|device| device.labyrinth_device_key_hex.clone())
        .expect("active sibling Labyrinth device key");
    let _old_code = dev1.create_recovery_code_live().await.unwrap();
    let _: LabyrinthBackupStatus = serde_wasm_bindgen::from_value(
        dev1.acknowledge_recovery_attention().unwrap(),
    )
    .unwrap();

    let outcome: LabyrinthRevocationOutcome = serde_wasm_bindgen::from_value(
        dev1.revoke_labyrinth_device(target).await.unwrap(),
    )
    .unwrap();
    assert!(outcome.rekeyed_recovery_code.is_some());
    assert!(outcome.status.recovery_needs_attention);

    drop(dev1);
    drop(dev2);
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev1_id));
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev2_id));
}

/// An enrolled OTC responder must persist and inspect the reconciled archive status before it
/// exposes a code. `SessionDeps::open` may return a session after a held head retry failed; that
/// suppressed error and pending epoch still forbid the offer. The stateless new-device path does
/// not have an enrolled archive to reconcile.
#[wasm_bindgen_test]
async fn otc_offer_requires_reconciled_persisted_directory_status() {
    let _fx = install_fixture();
    let stateless_did = make_did("wave2otcstateless");
    let stateless_id = "00000000-0000-4000-8000-000000000311";
    let stateless = open_client(&stateless_did, stateless_id).await;
    let stateless_offer: OtcPairingOffer =
        serde_wasm_bindgen::from_value(stateless.initiate_otc_pairing().await.unwrap()).unwrap();
    assert_eq!(stateless_offer.six_digit_code.len(), 6);
    drop(stateless);

    let did = make_did("wave2otcreadiness");
    let dev1_id = "00000000-0000-4000-8000-000000000312";
    let dev2_id = "00000000-0000-4000-8000-000000000313";
    let dev1 = open_client(&did, dev1_id).await;
    let _ = enroll(&dev1).await;
    let _ = dev1.enable_labyrinth_live().await.unwrap();
    let recovery_code = dev1.create_recovery_code_live().await.unwrap();

    let dev2 = open_client(&did, dev2_id).await;
    let _ = enroll(&dev2).await;
    WORLD.with(|cell| cell.borrow_mut().epoch_publish_not_authorized_once = true);
    let held: LabyrinthBackupStatus = serde_wasm_bindgen::from_value(
        dev2.restore_with_recovery_code_live(recovery_code)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(held.pending_directory_epoch.is_some());

    WORLD.with(|cell| cell.borrow_mut().epoch_publish_not_authorized_once = true);
    let error = dev2
        .initiate_otc_pairing()
        .await
        .expect_err("a suppressed directory publication failure must forbid an OTC offer")
        .as_string()
        .unwrap();
    assert!(
        error.contains("archive directory is not ready")
            || error.contains("pending directory publication"),
        "{error}"
    );
    let persisted: LabyrinthBackupStatus =
        serde_wasm_bindgen::from_value(dev2.labyrinth_status().unwrap()).unwrap();
    assert!(persisted.pending_directory_epoch.is_some());
    assert!(persisted.directory_publication_error.is_some());
    assert!(persisted.directory_publication_stalled);

    let offer: OtcPairingOffer =
        serde_wasm_bindgen::from_value(dev2.initiate_otc_pairing().await.unwrap()).unwrap();
    assert_eq!(offer.six_digit_code.len(), 6);
    let reconciled: LabyrinthBackupStatus =
        serde_wasm_bindgen::from_value(dev2.labyrinth_status().unwrap()).unwrap();
    assert!(reconciled.pending_directory_epoch.is_none());
    assert!(reconciled.directory_publication_error.is_none());

    drop(dev1);
    drop(dev2);
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&stateless_did, stateless_id));
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev1_id));
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev2_id));
}

/// Live `D-4` 2-device CPace + ML-KEM-768 OTC pairing (`startOtcPairing`, `initiateOtcPairing`,
/// `respondOtcPairing`, `completeLiveOtcPairing`) + monotonic `readState` (`MAX`) + `circleOwnerState`.
#[wasm_bindgen_test]
async fn live_d4_otc_pairing_and_read_and_circle_owner_state() {
    let _fx = install_fixture();
    let did = make_did("wave2otccircles");
    let dev1_id = "00000000-0000-4000-8000-000000000301";
    let dev2_id = "00000000-0000-4000-8000-000000000302";

    // 1. `dev1` enrolls, enables Labyrinth live, exercises `readState` (`MAX`) and `circleOwnerState`.
    let dev1 = open_client(&did, dev1_id).await;
    let _ = enroll(&dev1).await;
    let _ = dev1.enable_labyrinth_live().await.unwrap();

    let cid = "00000000-0000-4000-8000-0000000c0301";
    let initial_rs: Option<MailboxReadStateRecord> =
        serde_wasm_bindgen::from_value(dev1.get_read_state(cid.into()).await.unwrap()).unwrap();
    assert!(initial_rs.is_none());

    let rs5: MailboxReadStateRecord =
        serde_wasm_bindgen::from_value(dev1.advance_read_state(cid.into(), 5).await.unwrap())
            .unwrap();
    assert_eq!(rs5.read_through_seq, 5);
    let rs12: MailboxReadStateRecord =
        serde_wasm_bindgen::from_value(dev1.advance_read_state(cid.into(), 12).await.unwrap())
            .unwrap();
    assert_eq!(rs12.read_through_seq, 12);
    let rs_regressed: MailboxReadStateRecord =
        serde_wasm_bindgen::from_value(dev1.advance_read_state(cid.into(), 7).await.unwrap())
            .unwrap();
    assert_eq!(
        rs_regressed.read_through_seq, 12,
        "advanceReadState must enforce monotonic MAX"
    );
    let all_rs: Vec<MailboxReadStateRecord> =
        serde_wasm_bindgen::from_value(dev1.list_read_states().await.unwrap()).unwrap();
    assert_eq!(all_rs.len(), 1);
    assert_eq!(all_rs[0].read_through_seq, 12);

    let circle_space = format!("at://{did}/space/blue.catbird.circles.circle/friends");
    let circle_dto = CircleOwnerStateDto {
        circle_id: "friends".into(),
        space_uri: circle_space.clone(),
        current_key_version: 1,
        joined_at_version_json: json!({ &did: 1 }).to_string(),
        pending_ops_json:
            json!({ "__acl__:did:plc:removedpeeraaaaaaaaaaaa": "aclRemovePending:rotated" })
                .to_string(),
        updated_at: "2026-11-14T00:01:00.000Z".into(),
        record_cid: None,
    };
    let circle_cid = dev1
        .put_circle_owner_state(serde_wasm_bindgen::to_value(&circle_dto).unwrap(), None)
        .await
        .unwrap();
    assert!(!circle_cid.is_empty());

    let fetched_circle: CircleOwnerStateDto = serde_wasm_bindgen::from_value(
        dev1.get_circle_owner_state("friends".into()).await.unwrap(),
    )
    .unwrap();
    assert_eq!(fetched_circle.current_key_version, 1);

    let update_dto = CircleOwnerStateDto {
        circle_id: "friends".into(),
        space_uri: circle_space,
        current_key_version: 3,
        joined_at_version_json: json!({ "did:plc:bobcircleaaaaaaaaaaaaaa": 3 }).to_string(),
        pending_ops_json: "{}".into(),
        updated_at: "2026-11-14T00:02:00.000Z".into(),
        record_cid: None,
    };
    let merged_circle: CircleOwnerStateDto = serde_wasm_bindgen::from_value(
        dev1.merge_circle_owner_state(serde_wasm_bindgen::to_value(&update_dto).unwrap())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(merged_circle.current_key_version, 3);

    let cleared_circle: CircleOwnerStateDto = serde_wasm_bindgen::from_value(
        dev1.clear_circle_acl_tombstone("friends".into(), "did:plc:removedpeeraaaaaaaaaaaa".into())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!cleared_circle
        .pending_ops_json
        .contains("__acl__:did:plc:removedpeeraaaaaaaaaaaa"));
    assert!(cleared_circle
        .pending_ops_json
        .contains("__acl_cleared__:did:plc:removedpeeraaaaaaaaaaaa"));
    let all_circles: Vec<CircleOwnerStateDto> =
        serde_wasm_bindgen::from_value(dev1.list_circle_owner_states().await.unwrap()).unwrap();
    assert_eq!(all_circles.len(), 1);

    // 2. `dev1` reconciles its archive, then prepares an OTC offer via `initiateOtcPairing`.
    let offer: OtcPairingOffer =
        serde_wasm_bindgen::from_value(dev1.initiate_otc_pairing().await.unwrap()).unwrap();
    let code = offer.six_digit_code;

    // 3. `dev2` enrolls (`pending_approval`), calls `startOtcPairing(code)` writing `OtcSession` to
    //    `OwnerMailbox` Space, `dev1` calls `respondOtcPairing`, and `dev2` completes via
    //    `completeLiveOtcPairing(code)` -> promotes `dev2` to active!
    let dev2 = open_client(&did, dev2_id).await;
    let _ = enroll(&dev2).await;
    assert!(dev2.is_device_pending_approval().unwrap());
    let initiated: OtcInitiatedSession =
        serde_wasm_bindgen::from_value(dev2.start_otc_pairing(code.clone()).await.unwrap())
            .unwrap();
    assert_eq!(initiated.initiator_mlkem768_ek_len, 1184);

    assert!(
        dev1.respond_otc_pairing(initiated.session_id_hex.clone(), Some("000000".into()))
            .await
            .is_err(),
        "wrong 6-digit code must fail closed on respondOtcPairing"
    );
    dev1.respond_otc_pairing(initiated.session_id_hex.clone(), None)
        .await
        .unwrap();

    assert!(
        dev2.complete_live_otc_pairing("111111".into())
            .await
            .is_err(),
        "wrong code on completeLiveOtcPairing must fail closed without consuming pending initiator"
    );
    let done2: OtcPairingCompletion =
        serde_wasm_bindgen::from_value(dev2.complete_live_otc_pairing(code).await.unwrap())
            .unwrap();
    assert_eq!(done2.initiator_mlkem768_ek_len, 1184);
    assert_eq!(done2.responder_mlkem768_ct_len, 1088);
    assert!(
        !dev2.is_device_pending_approval().unwrap(),
        "completeLiveOtcPairing must promote pending_approval device"
    );
    assert_eq!(
        device_call_count("blue.catbird.chat.publishDirectRequestKeys", dev2_id),
        1
    );
    drop(dev1);
    drop(dev2);
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev1_id));
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&did, dev2_id));
}

/// Space attachments (`FC-07` `"{spaceURI}|{repoDID}|{cid}"`), image & WebAudio/Opus voice sends
/// (`FC-09`, zero `audiopus_sys`), `flushLabyrinthQueue` + `verifyAndReindexHistory`,
/// `leaveConversation` (`LastAdminCannotLeave`, `#zeroLeafLeaveBody`, `#leaveRequestBody`, `direct`
/// close) + `fulfillPendingGroupLeaves` (`#leaveCommitFulfillmentBody`), `retireCurrentDevice`, and
/// `D-3` fail-closed `deleteAccountData`.
#[wasm_bindgen_test]
async fn space_attachments_voice_reindex_leave_and_fail_closed_d3_delete() {
    let _fx = install_fixture();
    let alice = make_did("wave2mediaalice");
    let bob = make_did("wave2mediabob");
    let alice_dev = "00000000-0000-4000-8000-000000000401";
    let bob_dev = "00000000-0000-4000-8000-000000000402";

    // Enroll Bob first so his PDS `blue.catbird.chat.device` record exists for `I4` CARv1 checks.
    let bob_client = open_client(&bob, bob_dev).await;
    let _ = enroll(&bob_client).await;
    let _ = bob_client.enable_labyrinth_live().await.unwrap();
    drop(bob_client);

    // Enroll Alice, enable Labyrinth live, and create a group conversation.
    let alice_client = open_client(&alice, alice_dev).await;
    let _ = enroll(&alice_client).await;
    let _ = alice_client.enable_labyrinth_live().await.unwrap();

    let cid = "00000000-0000-4000-8000-0000000c0401";
    let peers_js = serde_wasm_bindgen::to_value(&vec![bob.clone()]).unwrap();
    let _ = alice_client
        .create_group(
            cid.into(),
            SEQUENCER.into(),
            peers_js,
            Some("Wave-2 Media Group".into()),
            Some("Space attachments + voice".into()),
        )
        .await
        .unwrap();

    // 1. Upload & download encrypted Space image attachment (`FC-07`) + `sendMediaAttachmentMessage`.
    let img_bytes = b"\x89PNG\r\n\x1a\nwave2-encrypted-space-image";
    let uploaded_img_js = alice_client
        .upload_conversation_attachment(cid.into(), img_bytes, "image/png".into())
        .await
        .unwrap();
    let uploaded_img: UploadedConversationAttachment =
        serde_wasm_bindgen::from_value(uploaded_img_js.clone()).unwrap();
    assert_eq!(
        uploaded_img.locator,
        format!("{}|{}|{}", uploaded_img.space_uri, alice, uploaded_img.cid)
    );
    let decrypted_img = alice_client
        .download_conversation_attachment(
            uploaded_img.locator.clone(),
            &uploaded_img.symmetric_key,
            &uploaded_img.iv,
            Some(uploaded_img.ciphertext_sha256.clone()),
        )
        .await
        .unwrap();
    assert_eq!(decrypted_img, img_bytes);

    let mut bad_sha = uploaded_img.ciphertext_sha256.clone();
    bad_sha[0] ^= 0xff;
    assert!(
        alice_client
            .download_conversation_attachment(
                uploaded_img.locator.clone(),
                &uploaded_img.symmetric_key,
                &uploaded_img.iv,
                Some(bad_sha),
            )
            .await
            .is_err(),
        "tampered SHA-256 must fail closed before returning attachment plaintext"
    );

    let img_mid = "00000000-0000-4000-8000-0000000d0401";
    let img_row: MessageRow = serde_wasm_bindgen::from_value(
        alice_client
            .send_media_attachment_message(
                cid.into(),
                img_mid.into(),
                "Check out this photo".into(),
                uploaded_img_js,
                Some(640),
                Some(480),
                Some("A test PNG".into()),
                None,
                JsValue::NULL,
                None,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let img_payload = MLSMessagePayload::decode(img_row.plaintext_json.as_bytes()).unwrap();
    assert_eq!(img_payload.text.as_deref(), Some("Check out this photo"));

    // 2. Upload & send WebAudio/Opus voice message (`FC-09`, `audio/webm;codecs=opus`).
    let opus_bytes = b"\x1a\x45\xdf\xa3webm-opus-voice-clip-payload";
    let uploaded_voice_js = alice_client
        .upload_conversation_attachment(cid.into(), opus_bytes, "audio/webm;codecs=opus".into())
        .await
        .unwrap();
    let uploaded_voice: UploadedConversationAttachment =
        serde_wasm_bindgen::from_value(uploaded_voice_js.clone()).unwrap();
    let voice_mid = "00000000-0000-4000-8000-0000000d0402";
    let waveform_js = serde_wasm_bindgen::to_value(&vec![0.15_f32, 0.55, 0.9, 0.4]).unwrap();
    let voice_row: MessageRow = serde_wasm_bindgen::from_value(
        alice_client
            .send_media_attachment_message(
                cid.into(),
                voice_mid.into(),
                String::new(),
                uploaded_voice_js,
                None,
                None,
                None,
                Some(2_400),
                waveform_js,
                Some("hello from web audio".into()),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(voice_row.plaintext_json.contains(&uploaded_voice.locator));

    // 3. `sendMediaAttachmentMessage` auto-flushes the Labyrinth outbox (`flushed == 0` remaining)
    //    -> wipe local messages + evidence -> `verifyAndReindexHistory`!
    let flushed = alice_client.flush_labyrinth_queue().await.unwrap();
    assert_eq!(flushed, 0);
    assert!(
        WORLD.with(|c| {
            c.borrow()
                .space_records
                .keys()
                .filter(|(_, _, col, _)| col == "blue.catbird.labyrinth.batch")
                .count()
        }) >= 2
    );
    drop(alice_client);

    {
        let db = WasmAccountDb::new(Rc::new(
            SqliteConn::open(&db_path_for(&alice, alice_dev), &"ab".repeat(32)).unwrap(),
        ));
        db.write_tx(|tx| {
            tx.delete_message(cid, img_mid)?;
            tx.delete_message(cid, voice_mid)?;
            let _ = tx.delete_labyrinth_state_key(&format!("native.message:{cid}:{img_mid}"));
            let _ = tx.delete_labyrinth_state_key(&format!("native.message:{cid}:{voice_mid}"));
            Ok(())
        })
        .unwrap();
        assert!(db
            .backend()
            .list_messages(cid, None, 10)
            .unwrap()
            .is_empty());
    }

    let alice_client = open_client(&alice, alice_dev).await;
    let reindexed = alice_client
        .verify_and_reindex_history(cid.into())
        .await
        .unwrap();
    assert_eq!(reindexed, 2);
    WORLD.with(|c| {
        let mut world = c.borrow_mut();
        assert!(world.calls["com.atproto.sync.getBlocks"] >= 2);
        assert!(!world.calls.contains_key("com.atproto.sync.getRepo"));
        world.blocks_unsupported = true;
    });
    alice_client
        .verify_and_reindex_history(cid.into())
        .await
        .unwrap();
    WORLD.with(|c| {
        let mut world = c.borrow_mut();
        assert!(world.calls["com.atproto.sync.getRepo"] >= 1);
        world.blocks_unsupported = false;
    });
    let restored_msgs: Vec<MessageRow> =
        serde_wasm_bindgen::from_value(alice_client.list_messages(cid.into(), None, 10).unwrap())
            .unwrap();
    assert_eq!(restored_msgs.len(), 2);

    let state_calls = WORLD.with(|cell| {
        let mut world = cell.borrow_mut();
        let count = world.calls["blue.catbird.chat.getConversationState"];
        world.convo_states.get_mut(cid).unwrap().account_deletions = (3..=103)
            .map(|seq| {
                json!({
                    "$type": "blue.catbird.chat.defs#accountDeletedEntry",
                    "entryId": "00000000-0000-4000-8000-0000000d04a1",
                    "conversationId": cid,
                    "seq": seq,
                    "deletedDid": bob,
                    "sequencerDid": SEQUENCER,
                    "sequencerAuthority": {},
                    "receivedAt": "2026-11-14T00:02:00.000Z",
                })
            })
            .collect();
        count
    });
    let deletion_error = alice_client
        .verify_and_reindex_history(cid.into())
        .await
        .expect_err("archive reindex must block on unverified listed deletion")
        .as_string()
        .unwrap_or_default();
    assert_eq!(
        WORLD.with(|c| c.borrow().calls["blue.catbird.chat.getConversationState"]),
        state_calls + 2
    );
    assert!(
        deletion_error.contains("ArchiveDeletionUnverified"),
        "{deletion_error}"
    );
    WORLD.with(|cell| {
        cell.borrow_mut()
            .convo_states
            .get_mut(cid)
            .unwrap()
            .account_deletions
            .clear();
    });

    // 4. `leaveConversation` rules:
    //    (a) Sole active admin in multi-member group -> `LastAdminCannotLeave`.
    WORLD.with(|c| {
        let mut w = c.borrow_mut();
        let st = w.convo_states.get_mut(cid).unwrap();
        st.participants = vec![
            json!({"userDid": alice, "status": "active", "role": "admin", "leafCount": 1}),
            json!({"userDid": bob, "status": "active", "role": "member", "leafCount": 1}),
        ];
        st.leaves = vec![
            json!({"userDid": alice, "deviceId": alice_dev, "leafIndex": 0}),
            json!({"userDid": bob, "deviceId": bob_dev, "leafIndex": 1}),
        ];
    });
    let last_admin_err = alice_client
        .leave_conversation(cid.into())
        .await
        .expect_err("sole admin must not strand active group")
        .as_string()
        .unwrap();
    assert!(
        last_admin_err.contains("LastAdminCannotLeave"),
        "{last_admin_err}"
    );

    //    (b) Another active admin exists & Alice has 1 leaf -> `#leaveRequestBody`.
    WORLD.with(|c| {
        let mut w = c.borrow_mut();
        let st = w.convo_states.get_mut(cid).unwrap();
        st.participants = vec![
            json!({"userDid": alice, "status": "active", "role": "admin", "leafCount": 1}),
            json!({"userDid": bob, "status": "active", "role": "admin", "leafCount": 1}),
        ];
    });
    let leave_req_out: LeaveConversationOutcome =
        serde_wasm_bindgen::from_value(alice_client.leave_conversation(cid.into()).await.unwrap())
            .unwrap();
    assert!(!leave_req_out.left_immediately);
    assert!(leave_req_out.leave_request_id.is_some());

    //    (c) Zero-leaf conversation -> `#zeroLeafLeaveBody` (`left_immediately == true`).
    let zero_cid = "00000000-0000-4000-8000-0000000c0402";
    let base_coords = WORLD.with(|c| c.borrow().convo_states[cid].coordinates.clone());
    let mut zero_coords = base_coords.clone();
    zero_coords["conversationId"] = json!(zero_cid);
    WORLD.with(|c| {
        let mut w = c.borrow_mut();
        w.convo_seq.insert(zero_cid.into(), 1);
        w.convo_states.insert(
            zero_cid.into(),
            ConversationFixtureState {
                kind: "group".into(),
                coordinates: zero_coords,
                participants: vec![
                    json!({"userDid": alice, "status": "active", "role": "member", "leafCount": 0}),
                    json!({"userDid": bob, "status": "active", "role": "admin", "leafCount": 1}),
                ],
                leaves: vec![json!({"userDid": bob, "deviceId": bob_dev})],
                pending_leave_requests: vec![],
                account_deletions: vec![],
            },
        );
    });
    let zero_out: LeaveConversationOutcome = serde_wasm_bindgen::from_value(
        alice_client
            .leave_conversation(zero_cid.into())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(zero_out.left_immediately);

    //    (d) `direct` conversation -> `closeConversation` (`left_immediately == true`).
    let direct_cid = "00000000-0000-4000-8000-0000000c0403";
    let mut direct_coords = base_coords.clone();
    direct_coords["conversationId"] = json!(direct_cid);
    WORLD.with(|c| {
        let mut w = c.borrow_mut();
        w.convo_seq.insert(direct_cid.into(), 1);
        w.convo_states.insert(
            direct_cid.into(),
            ConversationFixtureState {
                kind: "direct".into(),
                coordinates: direct_coords,
                participants: vec![
                    json!({"userDid": alice, "status": "active", "role": "member"}),
                    json!({"userDid": bob, "status": "active", "role": "member"}),
                ],
                leaves: vec![],
                pending_leave_requests: vec![],
                account_deletions: vec![],
            },
        );
    });
    let direct_out: LeaveConversationOutcome = serde_wasm_bindgen::from_value(
        alice_client
            .leave_conversation(direct_cid.into())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(direct_out.left_immediately);

    //    (e) `fulfillPendingGroupLeaves`: add Bob's MLS leaf to Alice's group `cid`, inject a
    //        pending leave request from Bob, and verify Alice fulfills it via `#leaveCommitFulfillmentBody`!
    drop(alice_client);
    add_bob_leaf_to_local_group(&alice, alice_dev, &bob, bob_dev, cid);
    let (prior_leave_snapshot, prior_leave_plaintext) = {
        let db = WasmAccountDb::new(Rc::new(
            SqliteConn::open(&db_path_for(&alice, alice_dev), &"ab".repeat(32)).unwrap(),
        ));
        stored_metadata_snapshot_and_plaintext(&db, cid)
    };
    let synced_coords = {
        let db = WasmAccountDb::new(Rc::new(
            SqliteConn::open(&db_path_for(&alice, alice_dev), &"ab".repeat(32)).unwrap(),
        ));
        let raw = db
            .backend()
            .get_account_meta(&format!("conversation_coords:{cid}"))
            .unwrap()
            .unwrap();
        serde_json::from_str::<Value>(&raw).unwrap()
    };
    let mut alice_client = open_client(&alice, alice_dev).await;
    WORLD.with(|c| {
        let mut w = c.borrow_mut();
        let st = w.convo_states.get_mut(cid).unwrap();
        st.coordinates = synced_coords.clone();
        st.participants = vec![
            json!({"userDid": alice, "status": "active", "role": "admin", "leafCount": 1}),
            json!({"userDid": bob, "status": "active", "role": "member", "leafCount": 1}),
        ];
        st.leaves = vec![
            json!({"userDid": alice, "deviceId": alice_dev, "leafIndex": 0}),
            json!({"userDid": bob, "deviceId": bob_dev, "leafIndex": 1}),
        ];
        st.pending_leave_requests = vec![json!({
            "leaveRequestId": "00000000-0000-4000-8000-0000000f0401",
            "requesterDid": bob,
            "requesterDeviceId": bob_dev,
            "status": "pending",
            "prior": synced_coords,
            "requestedAt": "2026-11-14T00:03:00.000Z",
            "expiresAt": "2099-01-01T00:00:00.000Z",
        })];
    });
    let fulfilled = alice_client.fulfill_pending_group_leaves().await.unwrap();
    assert_eq!(fulfilled, 1);
    alice_client.close();
    let (carried_leave_snapshot, carried_leave_plaintext) = {
        let db = WasmAccountDb::new(Rc::new(
            SqliteConn::open(&db_path_for(&alice, alice_dev), &"ab".repeat(32)).unwrap(),
        ));
        stored_metadata_snapshot_and_plaintext(&db, cid)
    };
    assert_eq!(
        carried_leave_plaintext, prior_leave_plaintext,
        "leave Commit must carry exact metadata plaintext"
    );
    let mut preserved_envelope = carried_leave_snapshot.clone();
    for field in [
        "nonce",
        "ciphertext",
        "ciphertextSha256",
        "ciphertextSize",
        "coordinate",
    ] {
        preserved_envelope[field] = prior_leave_snapshot[field].clone();
    }
    assert_eq!(
        preserved_envelope, prior_leave_snapshot,
        "leave Commit changed metadata origin, author proof or envelope"
    );
    assert_ne!(
        carried_leave_snapshot["nonce"],
        prior_leave_snapshot["nonce"]
    );
    assert_eq!(
        chat_wire::json_bytes(&carried_leave_snapshot["ciphertext"])
            .unwrap()
            .len(),
        chat_wire::json_bytes(&prior_leave_snapshot["ciphertext"])
            .unwrap()
            .len(),
        "exact plaintext carry must preserve ciphertext length"
    );
    alice_client = open_client(&alice, alice_dev).await;


    // 5. `D-3` fail-closed `deleteAccountData`:
    //    Inject remote 500 error -> `deleteAccountData` MUST return `Err` AND preserve local OPFS!
    WORLD.with(|c| c.borrow_mut().delete_account_fault = true);
    assert!(
        alice_client.delete_account_data().await.is_err(),
        "D-3 remote delete failure must fail closed"
    );
    let preserved_convos: Vec<Value> =
        serde_wasm_bindgen::from_value(alice_client.list_conversations(None, 20).unwrap()).unwrap();
    assert!(
        !preserved_convos.is_empty(),
        "local OPFS conversations must survive when remote deleteAccountData fails (D-3)"
    );

    //    Lift fault -> `deleteAccountData` purges remote Space/PDS/DS state, sends keyProof +
    //    revocationProof CARv1 headers + publishes self-deletion deviceRevocation, AND wipes local OPFS!
    WORLD.with(|c| c.borrow_mut().delete_account_fault = false);
    alice_client.delete_account_data().await.unwrap();
    assert!(WORLD.with(|c| c.borrow().deleted_accounts.contains(&alice)));
    WORLD.with(|c| {
        let w = c.borrow();
        let rev = w
            .chat_device_revocations
            .get(&(alice.clone(), alice_dev.to_owned()))
            .expect("deleteAccountData must publish self-deletion deviceRevocation on PDS");
        assert!(
            rev.value["reason"]
                .as_str()
                .is_some_and(|r| r.starts_with("deleteAccountData:")),
            "unexpected revocation reason: {:?}",
            rev.value["reason"]
        );
        let (kp, rp) = w
            .deleted_account_proofs
            .get(&alice)
            .expect("deleteAccountData must attach CARv1 proofs");
        assert!(!kp.is_empty(), "keyProof header must be non-empty");
        assert!(!rp.is_empty(), "revocationProof header must be non-empty");
    });
    assert!(
        alice_client.list_conversations(None, 20).is_err(),
        "WasmMlsClient handle must be closed after deleteAccountData"
    );

    // 5b. Sibling-revoked device must fail closed on `deleteAccountData` BEFORE calling DS or wiping DB.
    let dave = make_did("wave2siblingrevokeddave");
    let dave_dev = "00000000-0000-4000-8000-000000000408";
    let mut dave_client = open_client(&dave, dave_dev).await;
    let _ = enroll(&dave_client).await;
    let _ = dave_client.enable_labyrinth_live().await.unwrap();
    WORLD.with(|c| {
        let rec = canonical_record(&json!({
            "$type": "blue.catbird.chat.deviceRevocation",
            "targetDeviceId": dave_dev,
            "actorDeviceId": "00000000-0000-4000-8000-000000000499",
            "signerPublicKey": { "$bytes": STANDARD.encode([0x11u8; 32]) },
            "signature": { "$bytes": STANDARD.encode([0x22u8; 64]) },
            "algorithm": "ed25519",
            "createdAt": "2026-11-16T00:00:00.000Z",
            "reason": "revoked_by_sibling",
        }))
        .unwrap();
        c.borrow_mut()
            .chat_device_revocations
            .insert((dave.clone(), dave_dev.to_owned()), rec);
    });
    assert!(
        dave_client.delete_account_data().await.is_err(),
        "sibling-revoked device must fail closed on deleteAccountData"
    );
    assert!(
        !WORLD.with(|c| c.borrow().deleted_accounts.contains(&dave)),
        "sibling-revoked device must abort BEFORE calling deleteAccountData on DS"
    );
    assert!(
        dave_client.list_conversations(None, 20).is_ok(),
        "sibling-revoked device must keep local OPFS intact"
    );
    drop(dave_client);
    {
        let db = SqliteConn::open(&db_path_for(&dave, dave_dev), &"ab".repeat(32)).unwrap();
        assert!(
            db.get_account_meta("delete_account_retry_state")
                .unwrap()
                .is_none(),
            "sibling-revoked device must not persist delete_account_retry_state"
        );
    }
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&dave, dave_dev));

    // 6. `retireCurrentDevice`: wipes local OPFS and publishes append-only PDS `chat.deviceRevocation` without deleting account.
    let carol = make_did("wave2retirecarol");
    let carol_dev = "00000000-0000-4000-8000-000000000409";
    let mut carol_client = open_client(&carol, carol_dev).await;
    let _ = enroll(&carol_client).await;
    let _ = carol_client.enable_labyrinth_live().await.unwrap();
    carol_client.retire_current_device().await.unwrap();
    assert!(!WORLD.with(|c| c.borrow().deleted_accounts.contains(&carol)));
    assert!(WORLD.with(|c| {
        c.borrow()
            .chat_devices
            .contains_key(&(carol.clone(), carol_dev.to_owned()))
    }));
    assert!(WORLD.with(|c| {
        c.borrow()
            .chat_device_revocations
            .contains_key(&(carol.clone(), carol_dev.to_owned()))
    }));
    let _ = SqliteConn::delete_opfs_database(&db_path_for(&bob, bob_dev));
}

fn stored_metadata_snapshot_and_plaintext(
    db: &WasmAccountDb<Rc<SqliteConn>>,
    cid: &str,
) -> (Value, Vec<u8>) {
    let snapshot: Value = serde_json::from_str(
        &db.backend()
            .get_account_meta(&format!("metadata_snapshot_json:{cid}"))
            .unwrap()
            .expect("metadata snapshot"),
    )
    .unwrap();
    let convo = db.backend().get_conversation(cid).unwrap().unwrap();
    let provider = db.openmls_provider().unwrap();
    let mut group =
        MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
            .unwrap()
            .unwrap();
    let epoch = snapshot["coordinate"]["epoch"].as_u64().unwrap();
    assert_eq!(group.epoch().as_u64(), epoch);
    let version = snapshot["metadataVersion"].as_u64().unwrap();
    let nonce: [u8; 12] = chat_wire::json_bytes(&snapshot["nonce"])
        .unwrap()
        .try_into()
        .unwrap();
    let ciphertext = chat_wire::json_bytes(&snapshot["ciphertext"]).unwrap();
    let key = derive_metadata_key_from_group(
        &mut group,
        provider.crypto(),
        provider.storage(),
        &convo.group_id,
        epoch,
    )
    .unwrap();
    let plaintext = decrypt_metadata_snapshot_plaintext(
        &key,
        &convo.group_id,
        epoch,
        version,
        &nonce,
        &ciphertext,
    )
    .unwrap();
    (snapshot, plaintext)
}

fn add_bob_leaf_to_local_group(alice: &str, alice_dev: &str, bob: &str, bob_dev: &str, cid: &str) {
    let bob_signer: SignatureKeyPair = {
        let bob_db = WasmAccountDb::new(Rc::new(
            SqliteConn::open(&db_path_for(bob, bob_dev), &"ab".repeat(32)).unwrap(),
        ));
        let raw = bob_db
            .backend()
            .get_labyrinth_state("device_signer_json")
            .unwrap()
            .unwrap();
        serde_json::from_slice(&raw).unwrap()
    };
    let db = WasmAccountDb::new(Rc::new(
        SqliteConn::open(&db_path_for(alice, alice_dev), &"ab".repeat(32)).unwrap(),
    ));
    let (prior_snapshot, prior_plaintext) = stored_metadata_snapshot_and_plaintext(&db, cid);
    db.write_tx(|tx| {
        let signer_raw = tx.get_labyrinth_state("device_signer_json")?.unwrap();
        let alice_signer: SignatureKeyPair = serde_json::from_slice(&signer_raw).unwrap();
        let mut convo = tx.get_conversation(cid)?.unwrap();
        let provider = db.openmls_provider()?;

        // Build a KeyPackage using Bob's enrolled device signer so PDS/DS leaf checks match.
        let bob_cred = CredentialWithKey {
            credential: BasicCredential::new(format!("{bob}#{bob_dev}").into_bytes()).into(),
            signature_key: bob_signer.public().into(),
        };
        let now_s = (js_sys::Date::now().max(0.0) as u64) / 1000;
        let caps = Capabilities::new(
            Some(&[ProtocolVersion::Mls10]),
            Some(&[CIPHERSUITE]),
            Some(&[]),
            Some(&[]),
            Some(&[CredentialType::Basic]),
        );
        let kp_bundle = KeyPackage::builder()
            .key_package_lifetime(Lifetime::init(
                now_s.saturating_sub(60),
                now_s + 86_400 * 10,
            ))
            .leaf_node_capabilities(caps)
            .build(CIPHERSUITE, &provider, &bob_signer, bob_cred)
            .unwrap();
        let kp_in = KeyPackageIn::tls_deserialize_exact(
            kp_bundle.key_package().tls_serialize_detached().unwrap(),
        )
        .unwrap();
        let kp = kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .unwrap();

        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
            .unwrap()
            .unwrap();
        let _ = group.add_members(&provider, &alice_signer, &[kp]).unwrap();
        group.merge_pending_commit(&provider).unwrap();

        let next_epoch = group.epoch().as_u64();
        let (gch, ctag) = chat_wire::compute_group_context_hash_and_tag(&group, &provider)?;
        let metadata_version = prior_snapshot["metadataVersion"].as_u64().unwrap();
        let metadata_key = derive_metadata_key_from_group(
            &mut group,
            provider.crypto(),
            provider.storage(),
            &convo.group_id,
            next_epoch,
        )
        .unwrap();
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).unwrap();
        let previous_nonce = chat_wire::json_bytes(&prior_snapshot["nonce"]).unwrap();
        assert_ne!(previous_nonce.as_slice(), nonce.as_slice());
        let ciphertext = encrypt_metadata_snapshot_plaintext_with_nonce(
            &metadata_key,
            &convo.group_id,
            next_epoch,
            metadata_version,
            &nonce,
            &prior_plaintext,
        )
        .unwrap();
        assert_eq!(
            ciphertext.len(),
            chat_wire::json_bytes(&prior_snapshot["ciphertext"])
                .unwrap()
                .len()
        );
        let mut next_snapshot = prior_snapshot.clone();
        next_snapshot["ciphertext"] = json!({ "$bytes": STANDARD.encode(&ciphertext) });
        next_snapshot["ciphertextSha256"] =
            json!(STANDARD.encode(Sha256::digest(&ciphertext)));
        next_snapshot["ciphertextSize"] = json!(ciphertext.len());
        next_snapshot["nonce"] = json!({ "$bytes": STANDARD.encode(nonce) });
        let coordinate = next_snapshot["coordinate"].as_object_mut().unwrap();
        coordinate.insert(
            "conversationId".into(),
            json!(STANDARD.encode(uuid::Uuid::parse_str(cid).unwrap().as_bytes())),
        );
        coordinate.insert("generation".into(), json!(0));
        coordinate.insert("epoch".into(), json!(next_epoch));
        coordinate.insert(
            "groupId".into(),
            json!({ "$bytes": STANDARD.encode(&convo.group_id) }),
        );
        coordinate.insert(
            "groupContextHash".into(),
            json!({ "$bytes": STANDARD.encode(&gch) }),
        );
        coordinate.insert(
            "confirmationTag".into(),
            json!({ "$bytes": STANDARD.encode(&ctag) }),
        );
        convo.epoch = next_epoch as i64;
        tx.upsert_conversation(&convo)?;
        let coords = json!({
            "conversationId": cid,
            "generation": 0,
            "stateVersion": 2,
            "groupId": { "$bytes": STANDARD.encode(&convo.group_id) },
            "epoch": next_epoch,
            "groupContextHash": { "$bytes": STANDARD.encode(gch) },
            "confirmationTag": { "$bytes": STANDARD.encode(&ctag) },
            "lifecycle": "active",
        });
        tx.put_account_meta(
            &format!("metadata_snapshot_json:{cid}"),
            &next_snapshot.to_string(),
            1,
        )?;
        tx.put_account_meta(
            &format!("conversation_coords:{cid}"),
            &serde_json::to_string(&coords).unwrap(),
            1,
        )
    })
    .unwrap();
}

#[wasm_bindgen_test]
fn wave2_golden_50_wasm_conformance_verifies_transcript_and_tamper_fails_closed() {
    let raw = include_str!(
        "../../catbird-sim/fixtures/golden_50/transcript_01_direct_1to1_bootstrap_accept_reply.json"
    );
    let report_js = verify_golden_transcript_json(raw).expect("verify golden transcript #01");
    let report: Value = serde_wasm_bindgen::from_value(report_js).unwrap();
    assert_eq!(report["index"], 1);
    assert_eq!(report["category"], "direct1_to1");
    assert!(report["wireFrameCount"].as_u64().unwrap() > 0);
    assert!(report["conversationCount"].as_u64().unwrap() >= 1);
    assert!(report["openDeviceCount"].as_u64().unwrap() >= 1);

    // Tampered wire_digest_blake3 must fail closed.
    let mut tampered: Value = serde_json::from_str(raw).unwrap();
    tampered["wire_digest_blake3"] = json!("0".repeat(64));
    let err = verify_golden_transcript_json(&serde_json::to_string(&tampered).unwrap())
        .expect_err("tampered wire_digest_blake3 must fail");
    assert!(err
        .as_string()
        .unwrap_or_default()
        .contains("wire_digest_blake3 mismatch"));
}
