//! `WasmMlsClient.enrollDevice` re-enrollment over real encrypted OPFS, against a stateful fetch
//! fixture with the `mls-ds` enrollment rules: `enrollDevice` is create-only
//! (`DeviceAlreadyExists`), request-key revisions advance by one, and `getOwnDevices` reports
//! the registered key. The fixture checks read-claim shape, not signatures, and counts every
//! call, PDS `putRecord` writes included.
#![cfg(target_arch = "wasm32")]
use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::client::{
    EnrollmentReceipt, LabyrinthBackupStatus, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls_web::WasmMlsClient;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen(inline_js = r#"
let originalFetch;
let ds;
export function installDs() {
  originalFetch = globalThis.fetch;
  ds = {keys: {}, revisions: {}, calls: {}, loseEnroll: false, loseKeys: false, answerKey: null};
  globalThis.fetch = async (request) => {
    const reply = (body, status = 200) => {
      const r = new Response(JSON.stringify(body), {status, headers: {'content-type': 'application/json'}});
      Object.defineProperty(r, 'url', {value: request.url});
      return r;
    };
    const fail = (error, status = 400) => reply({error, message: error}, status);
    const nsid = new URL(request.url).pathname.replace('/xrpc/', '');
    ds.calls[nsid] = (ds.calls[nsid] || 0) + 1;
    if (nsid === 'com.atproto.server.getServiceAuth') return reply({token: 'service-auth'});
    if (nsid === 'com.atproto.repo.putRecord') return reply({uri: 'at://fixture', cid: 'bafyfixture'});
    if (nsid === 'blue.catbird.chat.getOwnDevices') {
      const header = request.headers.get('catbird-chat-read');
      if (!header || !request.headers.get('catbird-chat-read-signature')) return fail('InvalidSignature', 401);
      const claim = JSON.parse(atob(header.replace(/-/g, '+').replace(/_/g, '/')));
      if (claim.nsid !== nsid || new URL(request.url).searchParams.get('actorDeviceId') !== claim.deviceId)
        return fail('InvalidSignature', 401);
      const items = Object.entries(ds.keys).map(([deviceId, key]) => {
        const item = {device: {deviceId, keyId: 'k'.repeat(43), signaturePublicKey: {$bytes: key},
          authGeneration: 1, status: 'active', availablePackageCount: 2, reservedPackageCount: 0,
          createdAt: '2026-11-03T00:00:00.000Z', updatedAt: '2026-11-03T00:00:00.000Z'}};
        // Present only for the authenticated device once its request capability exists.
        if (deviceId === claim.deviceId && ds.revisions[deviceId])
          item.directRequestKeyPool = {enabled: true, revision: ds.revisions[deviceId], usableCount: 8,
            reservedCount: 0, asOf: '2026-11-03T00:00:00.000Z', usableUntil: '2026-11-10T00:10:00.000Z'};
        return item;
      });
      return reply({items, hasMore: false, snapshotExpiresAt: '2026-11-03T00:05:00.000Z'});
    }
    const b = JSON.parse(await request.clone().text()).signedRequest.body;
    if (nsid === 'blue.catbird.chat.enrollDevice') {
      if (ds.keys[b.deviceId]) return fail('DeviceAlreadyExists');
      const key = b.signaturePublicKey;
      ds.keys[b.deviceId] = typeof key === 'string' ? key : key.$bytes;
      if (ds.loseEnroll) { ds.loseEnroll = false; throw new Error('enrollDevice response lost'); }
      // `answerKey`: an answer naming another key than the one this request registered.
      const answered = ds.answerKey ? {$bytes: ds.answerKey} : b.signaturePublicKey;
      return reply({device: {deviceId: b.deviceId, keyId: b.keyId, signaturePublicKey: answered,
        authGeneration: 1, status: 'active', availablePackageCount: 2, reservedPackageCount: 0,
        createdAt: '2026-11-03T00:00:00.000Z', updatedAt: '2026-11-03T00:00:00.000Z'}});
    }
    if (nsid === 'blue.catbird.chat.publishDirectRequestKeys') {
      if (b.revision !== (ds.revisions[b.actorDeviceId] || 0) + 1) return fail('InvalidRequest');
      ds.revisions[b.actorDeviceId] = b.revision;
      if (ds.loseKeys) { ds.loseKeys = false; throw new Error('publishDirectRequestKeys response lost'); }
      return reply({revision: b.revision, enabled: true});
    }
    if (nsid === 'blue.catbird.chat.replenishKeyPackages') return reply({acceptedCount: b.keyPackages.length});
    throw new Error('unexpected request: ' + request.url);
  };
}
export function loseNextEnrollResponse() { ds.loseEnroll = true; }
export function loseNextRequestKeysResponse() { ds.loseKeys = true; }
export function holdDeviceKey(deviceId, key) { ds.keys[deviceId] = key; }
export function answerEnrollWithKey(key) { ds.answerKey = key; }
export function dsKey(deviceId) { return ds.keys[deviceId]; }
export function dsRevision(deviceId) { return ds.revisions[deviceId] || 0; }
export function dsCalls(nsid) { return ds.calls[nsid] || 0; }
export function restoreFetch() { globalThis.fetch = originalFetch; }
"#)]
extern "C" {
    fn installDs();
    fn loseNextEnrollResponse();
    fn loseNextRequestKeysResponse();
    fn holdDeviceKey(device_id: &str, key: &str);
    fn answerEnrollWithKey(key: &str);
    fn dsKey(device_id: &str) -> Option<String>;
    fn dsRevision(device_id: &str) -> u32;
    fn dsCalls(nsid: &str) -> u32;
    fn restoreFetch();
}
struct RestoreFetch;
impl Drop for RestoreFetch {
    fn drop(&mut self) {
        restoreFetch();
    }
}

const ENROLL: &str = "blue.catbird.chat.enrollDevice";
const REQUEST_KEYS: &str = "blue.catbird.chat.publishDirectRequestKeys";

async fn open(did: &str, device_id: &str) -> WasmMlsClient {
    let client = WasmMlsClient::open_async(
        did.into(),
        device_id.into(),
        "did:web:ds.catbird.test".into(),
        "https://ds.catbird.test".into(),
        "https://pds.catbird.test".into(),
        "ab".repeat(32),
    )
    .await
    .unwrap();
    client.set_auth_token(Some("session".into()));
    client
}

/// The enrolled signature key, base64 like the DS stores it.
async fn enroll(client: &WasmMlsClient) -> Result<String, JsValue> {
    let scopes = serde_wasm_bindgen::to_value(&REQUIRED_LABYRINTH_OAUTH_SCOPES).unwrap();
    let receipt = client.enroll_device(true, scopes).await?;
    let receipt: EnrollmentReceipt = serde_wasm_bindgen::from_value(receipt).unwrap();
    Ok(STANDARD.encode(receipt.signature_public_key))
}

/// catmos re-enrolls on every worker open: the persisted signer and archive status survive,
/// and the DS sees no second enrollment (it would answer `DeviceAlreadyExists`).
#[wasm_bindgen_test]
async fn reenrolling_after_reopen_keeps_the_signer_and_skips_the_ds() {
    installDs();
    let _restore = RestoreFetch;
    let (did, device) = (
        "did:plc:reenrollaaaaaaaaaaaaaaaa",
        "00000000-0000-4000-8000-00000000e001",
    );
    let client = open(did, device).await;
    let enrolled = enroll(&client).await.unwrap();
    client.setup_recovery_code().unwrap();
    drop(client);
    let client = open(did, device).await;
    let again = enroll(&client)
        .await
        .expect("re-enrolling an enrolled device is idempotent");
    assert_eq!(again, enrolled);
    assert_eq!(dsKey(device).as_deref(), Some(enrolled.as_str()));
    assert_eq!((dsCalls(ENROLL), dsRevision(device)), (1, 1));
    let status: LabyrinthBackupStatus =
        serde_wasm_bindgen::from_value(client.labyrinth_status().unwrap()).unwrap();
    assert!(status.has_recovery_code, "archive status survives");
    drop(client);
    let canonical_spelling = open(did, &device.to_ascii_uppercase()).await;
    assert_eq!(
        enroll(&canonical_spelling)
            .await
            .expect("equivalent UUID spelling retains the enrolled identity"),
        enrolled
    );
    assert_eq!(dsCalls(ENROLL), 1);
    drop(canonical_spelling);
    let rebound = open(did, "00000000-0000-4000-8000-00000000e099").await;
    let error = enroll(&rebound)
        .await
        .expect_err("a completed enrollment cannot be rebound to another device")
        .as_string()
        .unwrap();
    assert!(error.contains("Enrollment device identity"), "{error}");
    assert_eq!(dsCalls(ENROLL), 1, "identity mismatch is rejected locally");
}

/// `mls-ds` applied `enrollDevice` but its response was lost. The retry reuses the persisted
/// signer: it fails closed while the DS holds another key for the device, and adopts the DS
/// enrollment once `getOwnDevices` reports this key, publishing request keys exactly once.
#[wasm_bindgen_test]
async fn retry_after_a_lost_enroll_response_adopts_only_the_same_key() {
    installDs();
    let _restore = RestoreFetch;
    let (did, device) = (
        "did:plc:lostenrollaaaaaaaaaaaaaa",
        "00000000-0000-4000-8000-00000000e002",
    );
    let client = open(did, device).await;
    loseNextEnrollResponse();
    assert!(enroll(&client).await.is_err());
    let registered = dsKey(device).expect("the DS registered the device");
    holdDeviceKey(device, &STANDARD.encode([7_u8; 32]));
    assert!(
        enroll(&client).await.is_err(),
        "another key on the DS fails closed"
    );
    holdDeviceKey(device, &registered);
    drop(client);
    let client = open(did, device).await;
    let key = enroll(&client)
        .await
        .expect("the retry adopts the DS enrollment");
    assert_eq!(key, registered);
    assert_eq!((dsRevision(device), dsCalls(REQUEST_KEYS)), (1, 1));
    enroll(&client)
        .await
        .expect("a completed enrollment is a local no-op");
    assert_eq!(dsCalls(ENROLL), 3);
}

/// Request keys were published but that response was lost: the retry confirms the device and
/// sees its request capability (`directRequestKeyPool`), so revision 1 is not sent again.
#[wasm_bindgen_test]
async fn retry_after_a_lost_request_keys_response_does_not_republish() {
    installDs();
    let _restore = RestoreFetch;
    let (did, device) = (
        "did:plc:lostrequestkeysaaaaaaaaa",
        "00000000-0000-4000-8000-00000000e003",
    );
    let client = open(did, device).await;
    loseNextRequestKeysResponse();
    assert!(enroll(&client).await.is_err());
    let key = enroll(&client)
        .await
        .expect("the retry skips the published request keys");
    assert_eq!(dsKey(device), Some(key));
    assert_eq!((dsRevision(device), dsCalls(REQUEST_KEYS)), (1, 1));
}

/// A key-mismatch refusal writes nothing to the PDS: `mls-ds` must hold the device under this
/// key before either PDS record is written, whether it reports another key for an existing
/// device ID (`DeviceAlreadyExists`) or answers a fresh enrollment naming another key. A device
/// ID registered under another key keeps that key's PDS device record.
///
/// Fail-before: the PDS device and declaration records were written before `enrollDevice`, so
/// both refusals had already replaced the PDS device record with this key.
#[wasm_bindgen_test]
async fn a_key_mismatch_refuses_before_any_pds_write() {
    installDs();
    let _restore = RestoreFetch;
    let other_key = STANDARD.encode([7_u8; 32]);
    let held = "00000000-0000-4000-8000-00000000e004";
    holdDeviceKey(held, &other_key);
    let client = open("did:plc:heldkeyaaaaaaaaaaaaaaaaa", held).await;
    let error = enroll(&client)
        .await
        .expect_err("mls-ds holds the device under another key")
        .as_string()
        .unwrap();
    assert!(error.contains("DeviceAlreadyExists"), "{error}");
    assert_eq!(dsCalls("com.atproto.repo.putRecord"), 0, "{error}");

    answerEnrollWithKey(&other_key);
    let client = open(
        "did:plc:answeredkeyaaaaaaaaaaaaa",
        "00000000-0000-4000-8000-00000000e005",
    )
    .await;
    let error = enroll(&client)
        .await
        .expect_err("mls-ds answered another key")
        .as_string()
        .unwrap();
    assert!(
        error.contains("EnrollmentDeviceIdentityMismatch"),
        "{error}"
    );
    assert_eq!(dsCalls("com.atproto.repo.putRecord"), 0, "{error}");
    assert_eq!(dsKey(held).as_deref(), Some(other_key.as_str()));
}

/// A non-UUIDv4 ID, or a missing session, once selected a local-only group, a receiptless queued
/// send, or a silent membership no-op. All now fail before any local or DS effect.
#[wasm_bindgen_test]
async fn mutations_reject_non_uuid_v4_ids_and_missing_sessions() {
    installDs();
    let _restore = RestoreFetch;
    let (did, device) = (
        "did:plc:offlinesendaaaaaaaaaaaaa",
        "00000000-0000-4000-8000-00000000e004",
    );
    let client = open(did, device).await;
    enroll(&client).await.unwrap();
    let rejected = |result: Result<JsValue, JsValue>, kind: &str| {
        let error = result.expect_err("must reject").as_string().unwrap();
        assert!(error.starts_with(kind), "{error}");
    };
    let valid = "00000000-0000-4000-8000-0000000000c1";
    for cid in ["convo-offline", "00000000-0000-1000-8000-0000000000c1"] {
        rejected(
            client
                .create_group(
                    cid.into(),
                    "did:web:ds.catbird.test".into(),
                    JsValue::NULL,
                    None,
                    None,
                )
                .await,
            "Invalid input",
        );
    }
    for (cid, mid) in [
        ("convo-offline", "msg-offline"),
        (valid, "msg-offline"),
        ("convo-offline", valid),
    ] {
        rejected(
            client
                .send_message(cid.into(), mid.into(), "must not queue".into())
                .await,
            "Invalid input",
        );
    }
    let peer = "did:plc:offlinepeeraaaaaaaaaaaaa";
    let peers = || serde_wasm_bindgen::to_value(&[peer]).unwrap();
    let no_peers = || serde_wasm_bindgen::to_value(&Vec::<String>::new()).unwrap();
    let removed = |result: Result<(), JsValue>| result.map(|()| JsValue::UNDEFINED);
    rejected(
        client
            .add_group_members("convo-offline".into(), peers())
            .await,
        "Invalid input",
    );
    rejected(
        client.add_group_members(valid.into(), no_peers()).await,
        "Invalid input",
    );
    rejected(
        removed(
            client
                .remove_group_member(true, "convo-offline".into(), peer.into())
                .await,
        ),
        "Invalid input",
    );
    // A live session no longer returns success for a conversation this device does not hold.
    rejected(
        client.add_group_members(valid.into(), peers()).await,
        "Group not found",
    );
    rejected(
        removed(
            client
                .remove_group_member(true, valid.into(), peer.into())
                .await,
        ),
        "Group not found",
    );
    client.set_auth_token(None);
    rejected(
        client
            .create_group(
                valid.into(),
                "did:web:ds.catbird.test".into(),
                JsValue::NULL,
                None,
                None,
            )
            .await,
        "Invalid state",
    );
    rejected(
        client
            .send_message(valid.into(), valid.into(), "must not queue".into())
            .await,
        "Invalid state",
    );
    rejected(
        client.add_group_members(valid.into(), peers()).await,
        "Invalid state",
    );
    rejected(
        removed(
            client
                .remove_group_member(true, valid.into(), peer.into())
                .await,
        ),
        "Invalid state",
    );
    let conversations: Vec<catbird_mls::storage::ConversationRow> =
        serde_wasm_bindgen::from_value(client.list_conversations(None, 10).unwrap()).unwrap();
    assert!(conversations.is_empty());
    for cid in ["convo-offline", valid] {
        let messages: Vec<catbird_mls::storage::MessageRow> =
            serde_wasm_bindgen::from_value(client.list_messages(cid.into(), None, 10).unwrap())
                .unwrap();
        assert!(messages.is_empty());
    }
}
