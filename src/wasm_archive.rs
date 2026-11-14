//! Labyrinth Space archival, live `SessionDeps` lifecycle, Space attachments, `D-3` account
//! deletion, `D-4` OTC pairing, device management, `readState`, and `circleOwnerState` for
//! `WasmMlsClient`.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;

use atproto_spaces::did_resolver::DidDocument;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use openmls::prelude::{GroupId, MlsGroup};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer as _, OpenMlsProvider as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use catbird_mls::client::{
    chat_wire, CircleOwnerStateDto, DeviceRevocationReport, LabyrinthBackupStatus,
    LabyrinthRotationExclusion, MailboxReadStateRecord, OtcInitiatedSession, OtcPairingCompletion,
    QueuedLabyrinthArchivePayload, RegisteredDeviceInfo, UploadedConversationAttachment,
};
use catbird_mls::labyrinth::session::{
    LocalConversationAuthority, LocalGroupSnapshot, LocalLeafKeys,
};
use catbird_mls::labyrinth::signer::LatchedTransportSigner;
use catbird_mls::labyrinth::space::{
    thread_placement_key, LabyrinthSpaceGateway, LabyrinthSpaceRequest, LabyrinthSpaceResponse,
    SpaceXrpcTransport, ThreadPlacement,
};
use catbird_mls::labyrinth::transport::{
    map_xrpc_error, MAX_LABYRINTH_XRPC_RESPONSE_BYTES, MAX_PDS_RECORD_BYTES,
};
use catbird_mls::labyrinth::write_auth::{read_headers, ReadClaim};
use catbird_mls::labyrinth::{
    ChatKeySigner, DsDirectoryStore, GatewayXrpcTransport, LabyrinthGateway, LabyrinthRequest,
    LabyrinthSession, SessionDeps, SignerFault, StateVault, XrpcTransportError,
};
use catbird_mls::messaging::receive::OriginalSenderArchiveAttestationEnvelope;
use catbird_mls::orchestrator::canonical_transport::{
    derive_key_id, CanonicalOperation, GatewayResponse, PreparedRequest,
};
use catbird_mls::orchestrator::error::OrchestratorError;
use catbird_mls::orchestrator::MLSMessagePayload;
use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend};
use catbird_mls::storage::{MessageRow, MutationJournalRow, OpenMlsKvProvider, OpenMlsKvStorage};
use catbird_mls::MLSError;
use labyrinth::client::{Clock, CompositeDirectory, LoadedMessage};
use labyrinth::mailbox::EpochPublic;
use labyrinth::mek::{Mek, MekProvenance};
use labyrinth::records::{datetime_from_ms, nsid, MekDistribution};
use labyrinth::store::pds::{PdsDirectory, PublicRepoBackend};
use labyrinth::store::space::{SpaceRef, SpaceRpc as _};
use labyrinth::store::{MailboxDirectory, ThreadStore as _, TimeRange};

use crate::sqlite_conn::SqliteConn;
use crate::wasm_archive_space::{VerifiedArchiveInventory, WASM_UNAUTHENTICATED_DENIAL};
use crate::wasm_client::{now_ms, WasmMlsClient};

const APPLY_WRITES: &str = "/xrpc/com.atproto.space.applyWrites";
const MAILBOX_KEYS_RELAY: &str = "blue.catbird.labyrinth.getMailboxKeysRecord";

/// The enrolled chat device key: Labyrinth transport key and request signer (`[CB-3]`).
pub(crate) struct WebArchiveSigner {
    pub(crate) keys: SignatureKeyPair,
    pub(crate) public: [u8; 32],
}

impl ChatKeySigner for WebArchiveSigner {
    fn public_key(&self) -> [u8; 32] {
        self.public
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], String> {
        self.keys
            .sign(msg)
            .map_err(|e| format!("archive signer: {e:?}"))?
            .try_into()
            .map_err(|_| "archive signature is not 64 bytes".into())
    }
}

struct WasmArchiveClock;

impl Clock for WasmArchiveClock {
    fn now_ms(&self) -> u64 {
        now_ms().max(0) as u64
    }
}

struct WasmArchiveVault {
    db: WasmAccountDb<Rc<SqliteConn>>,
    namespace: &'static str,
}

impl WasmArchiveVault {
    fn state_key(&self, key: &str) -> String {
        format!("{}:{key}", self.namespace)
    }
}

impl StateVault for WasmArchiveVault {
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, MLSError> {
        self.db.backend().get_labyrinth_state(&self.state_key(key))
    }

    fn compare_exchange(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, MLSError> {
        let full = self.state_key(key);
        let ts = now_ms();
        self.db.write_tx(|tx| {
            let current = Zeroizing::new(tx.get_labyrinth_state(&full)?);
            if current.as_deref() != expected {
                return Ok(false);
            }
            tx.put_labyrinth_state(&full, next, ts)?;
            Ok(true)
        })
    }

    fn delete(&self, key: &str) -> Result<(), MLSError> {
        let full = self.state_key(key);
        self.db.write_tx(|tx| tx.delete_labyrinth_state_key(&full))
    }
}

/// Labyrinth directory + Space adapter over this account's PDS and home `mls-ds`, mirroring
/// native `NativeArchiveGateway`.
pub(crate) struct WebArchiveGateway {
    pub(crate) client: WasmMlsClient,
    pub(crate) db: WasmAccountDb<Rc<SqliteConn>>,
    pub(crate) session_token: String,
    pub(crate) device_id: String,
    pub(crate) signer: Arc<WebArchiveSigner>,
    pub(crate) verified_inventories: RefCell<BTreeMap<String, VerifiedArchiveInventory>>,
}

impl WebArchiveGateway {
    async fn send(request: reqwest::RequestBuilder) -> Result<GatewayResponse, String> {
        let response = request.send().await.map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.bytes().await.map_err(|e| e.to_string())?.to_vec();
        Ok(GatewayResponse {
            status,
            content_type,
            body,
        })
    }

    /// `{home DS}{path}` under a service-auth token bound to `nsid`.
    async fn ds(
        &self,
        nsid: &str,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<GatewayResponse, String> {
        let token = self
            .client
            .mint_ds_auth_token(&self.session_token, nsid)
            .await
            .map_err(|e| e.to_string())?;
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
        let mut request = self
            .client
            .http
            .request(method, format!("{}{path}", self.client.ds_base()))
            .bearer_auth(token);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body);
        }
        Self::send(request).await
    }

    async fn verify_peer_mailbox_keys_car_proof_if_atproto_key_present(
        &self,
        did: &str,
        rkey: &str,
        response: &Value,
        expected_cid: &str,
    ) -> labyrinth::Result<()> {
        let doc_bytes = match self
            .client
            .resolve_did_document(&self.session_token, did)
            .await
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(()),
            Err(err) => return Err(labyrinth::Error::Backend(err.to_string())),
        };
        let Ok(doc) = DidDocument::parse_json(did, &doc_bytes) else {
            return Ok(());
        };
        let Some(ref atproto_key) = doc.atproto_key else {
            return Ok(());
        };
        let inline_proof = response.get("proof").and_then(|p| {
            p.as_str()
                .or_else(|| p.get("$bytes").and_then(Value::as_str))
        });
        let car_bytes = if let Some(b64) = inline_proof {
            STANDARD
                .decode(b64)
                .map_err(|_| labyrinth::Error::Malformed("mailboxKeys inline CAR proof"))?
        } else {
            let pds = doc
                .pds_endpoint()
                .map_err(|e| labyrinth::Error::Backend(e.to_string()))?
                .trim_end_matches('/');
            let url = format!(
                "{pds}/xrpc/com.atproto.sync.getRecord?did={}&collection={}&rkey={}",
                chat_wire::urlencode_form_component(did),
                nsid::MAILBOX_KEYS,
                chat_wire::urlencode_form_component(rkey),
            );
            let resp = Self::send(self.client.http.get(url))
                .await
                .map_err(labyrinth::Error::Backend)?;
            if resp.status >= 400 {
                return Err(labyrinth::Error::BadSignature);
            }
            resp.body
        };
        let record_val = response
            .get("value")
            .ok_or(labyrinth::Error::Malformed("getRecord missing value"))?;
        catbird_mls::labyrinth::repo_proof::verify_car_record_json_match(
            &car_bytes,
            did,
            nsid::MAILBOX_KEYS,
            rkey,
            Some(expected_cid),
            record_val,
            atproto_key,
        )
        .map(|_| ())
        .map_err(|_| labyrinth::Error::BadSignature)
    }
}

#[async_trait::async_trait(?Send)]
impl LabyrinthGateway for WebArchiveGateway {
    async fn submit_labyrinth(&self, request: LabyrinthRequest) -> Result<GatewayResponse, String> {
        self.ds(
            &request.nsid,
            &request.method,
            &request.path,
            request.headers,
            request.body,
        )
        .await
    }

    async fn submit_canonical(
        &self,
        request: PreparedRequest,
        extra_headers: Vec<(String, String)>,
    ) -> Result<GatewayResponse, String> {
        let nsid = request.operation.nsid();
        let mut query: Vec<&str> = request
            .path
            .split_once('?')
            .map(|(_, query)| query.split('&').collect())
            .unwrap_or_default();
        query.sort_unstable();
        let mut headers: Vec<(String, String)> = chat_wire::build_chat_read_headers(
            nsid,
            &query.join("&"),
            &self.client.account_did,
            &self.device_id,
            &self.signer.keys,
            now_ms(),
        )
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|header| (header.name, header.value))
        .collect();
        headers.extend(extra_headers);
        self.ds(nsid, &request.method, &request.path, headers, request.body)
            .await
    }

    async fn resolve_did_document(&self, did: &str) -> Result<Option<Vec<u8>>, String> {
        self.client
            .resolve_did_document(&self.session_token, did)
            .await
            .map_err(|e| e.to_string())
    }
}

#[async_trait::async_trait(?Send)]
impl LabyrinthSpaceGateway for WebArchiveGateway {
    async fn submit_space(
        &self,
        request: LabyrinthSpaceRequest,
    ) -> Result<GatewayResponse, String> {
        let resp = self.execute_authenticated_space(request).await?;
        Ok(GatewayResponse {
            status: resp.status,
            content_type: resp.content_type,
            body: resp.body,
        })
    }

    async fn submit_space_with_headers(
        &self,
        request: LabyrinthSpaceRequest,
    ) -> Result<LabyrinthSpaceResponse, String> {
        self.execute_authenticated_space(request).await
    }
}

#[async_trait::async_trait(?Send)]
impl PublicRepoBackend for WebArchiveGateway {
    async fn put_mailbox_keys(
        &self,
        did: &str,
        rkey: &str,
        record: &[u8],
        swap_cid: Option<&str>,
    ) -> labyrinth::Result<String> {
        if did != self.client.account_did {
            return Err(labyrinth::Error::Forbidden);
        }
        if record.len() > MAX_PDS_RECORD_BYTES {
            return Err(labyrinth::Error::Backend(format!(
                "PDS record exceeds {MAX_PDS_RECORD_BYTES} byte limit ({} bytes)",
                record.len()
            )));
        }
        let record_val: Value = serde_json::from_slice(record)
            .map_err(|_| labyrinth::Error::Malformed("mailboxKeys JSON"))?;
        let mut body = json!({
            "repo": did,
            "collection": nsid::MAILBOX_KEYS,
            "rkey": rkey,
            "record": record_val,
        });
        if let Some(cid) = swap_cid {
            body["swapRecord"] = json!(cid);
        }
        let payload =
            serde_json::to_vec(&body).map_err(|e| labyrinth::Error::Backend(e.to_string()))?;
        let (status, resp_bytes) = self
            .client
            .pds_post_json(
                &self.session_token,
                "/xrpc/com.atproto.repo.putRecord",
                payload,
            )
            .await
            .map_err(|e| labyrinth::Error::Backend(e.to_string()))?;
        let parsed: Option<Value> = serde_json::from_slice(&resp_bytes).ok();
        if !(200..300).contains(&status) {
            let err = XrpcTransportError {
                status,
                error: parsed
                    .as_ref()
                    .and_then(|v| v["error"].as_str())
                    .map(str::to_owned),
                message: parsed
                    .as_ref()
                    .and_then(|v| v["message"].as_str())
                    .map(str::to_owned),
            };
            return Err(map_xrpc_error(err));
        }
        let json = parsed.ok_or(labyrinth::Error::Malformed("putRecord JSON"))?;
        json["cid"]
            .as_str()
            .filter(|cid| !cid.is_empty())
            .map(str::to_owned)
            .ok_or(labyrinth::Error::Malformed("putRecord missing CID"))
    }

    async fn get_mailbox_keys(
        &self,
        did: &str,
        rkey: &str,
    ) -> labyrinth::Result<Option<(Vec<u8>, String)>> {
        let enc = chat_wire::urlencode_form_component;
        if did == self.client.account_did {
            let url = format!(
                "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection={}&rkey={}",
                self.client.pds_base(),
                enc(did),
                nsid::MAILBOX_KEYS,
                enc(rkey),
            );
            let response = Self::send(self.client.http.get(url).bearer_auth(&self.session_token))
                .await
                .map_err(labyrinth::Error::Backend)?;
            return mailbox_keys_record_with_json(response, did, rkey)
                .map(|opt| opt.map(|(pair, _)| pair));
        }

        let query = format!("did={}&rkey={}", enc(did), enc(rkey));
        let now = now_ms();
        let mut headers: Vec<(String, String)> = chat_wire::build_chat_read_headers(
            MAILBOX_KEYS_RELAY,
            &query,
            &self.client.account_did,
            &self.device_id,
            &self.signer.keys,
            now,
        )
        .map_err(|e| labyrinth::Error::Backend(e.to_string()))?
        .into_iter()
        .map(|header| (header.name, header.value))
        .collect();
        let claim = ReadClaim::new(
            MAILBOX_KEYS_RELAY,
            &[("did", did.to_owned()), ("rkey", rkey.to_owned())],
            &self.client.account_did,
            &self.device_id,
            now.max(0) as u64,
        )
        .to_json();
        let signature = self
            .signer
            .sign(&ReadClaim::signing_input(&claim))
            .map_err(labyrinth::Error::Backend)?;
        headers.extend(read_headers(&claim, &signature));
        let path = format!("/xrpc/{MAILBOX_KEYS_RELAY}?{query}");
        let response = self
            .ds(MAILBOX_KEYS_RELAY, "GET", &path, headers, None)
            .await
            .map_err(labyrinth::Error::Backend)?;
        let Some(((bytes, cid), raw_json)) = mailbox_keys_record_with_json(response, did, rkey)?
        else {
            return Ok(None);
        };
        self.verify_peer_mailbox_keys_car_proof_if_atproto_key_present(did, rkey, &raw_json, &cid)
            .await?;
        Ok(Some((bytes, cid)))
    }

    async fn delete_all_mailbox_keys(&self, did: &str) -> labyrinth::Result<()> {
        if did != self.client.account_did {
            return Err(labyrinth::Error::Forbidden);
        }
        let enc = chat_wire::urlencode_form_component;
        let prefix = format!("at://{did}/{}/", nsid::MAILBOX_KEYS);
        let mut cursor: Option<String> = None;
        let mut seen = BTreeSet::new();
        loop {
            let mut url = format!(
                "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection={}&limit=100",
                self.client.pds_base(),
                enc(did),
                nsid::MAILBOX_KEYS,
            );
            if let Some(ref cur) = cursor {
                url.push_str(&format!("&cursor={}", enc(cur)));
            }
            let resp = Self::send(self.client.http.get(url).bearer_auth(&self.session_token))
                .await
                .map_err(labyrinth::Error::Backend)?;
            if matches!(resp.status, 400 | 404)
                && serde_json::from_slice::<Value>(&resp.body)
                    .ok()
                    .and_then(|v| v["error"].as_str().map(str::to_owned))
                    .as_deref()
                    == Some("RecordNotFound")
            {
                break;
            }
            if !(200..300).contains(&resp.status) {
                let parsed: Option<Value> = serde_json::from_slice(&resp.body).ok();
                return Err(map_xrpc_error(XrpcTransportError {
                    status: resp.status,
                    error: parsed
                        .as_ref()
                        .and_then(|v| v["error"].as_str())
                        .map(str::to_owned),
                    message: parsed
                        .as_ref()
                        .and_then(|v| v["message"].as_str())
                        .map(str::to_owned),
                }));
            }
            let page: Value = serde_json::from_slice(&resp.body)
                .map_err(|_| labyrinth::Error::Malformed("listRecords JSON"))?;
            let records = page["records"]
                .as_array()
                .ok_or(labyrinth::Error::Malformed("listRecords missing records"))?;
            for record in records {
                let uri = record["uri"]
                    .as_str()
                    .ok_or(labyrinth::Error::Malformed("mailboxKeys URI"))?;
                let rkey = uri
                    .strip_prefix(&prefix)
                    .filter(|key| !key.is_empty() && !key.contains('/'))
                    .ok_or(labyrinth::Error::Malformed("mailboxKeys URI binding"))?;
                let cid = record["cid"]
                    .as_str()
                    .ok_or(labyrinth::Error::Malformed("mailboxKeys CID"))?;
                let del_body = serde_json::to_vec(&json!({
                    "repo": did,
                    "collection": nsid::MAILBOX_KEYS,
                    "rkey": rkey,
                    "swapRecord": cid,
                }))
                .map_err(|e| labyrinth::Error::Backend(e.to_string()))?;
                let (del_status, del_bytes) = self
                    .client
                    .pds_post_json(
                        &self.session_token,
                        "/xrpc/com.atproto.repo.deleteRecord",
                        del_body,
                    )
                    .await
                    .map_err(|e| labyrinth::Error::Backend(e.to_string()))?;
                if !(200..300).contains(&del_status) {
                    let parsed: Option<Value> = serde_json::from_slice(&del_bytes).ok();
                    return Err(map_xrpc_error(XrpcTransportError {
                        status: del_status,
                        error: parsed
                            .as_ref()
                            .and_then(|v| v["error"].as_str())
                            .map(str::to_owned),
                        message: parsed
                            .as_ref()
                            .and_then(|v| v["message"].as_str())
                            .map(str::to_owned),
                    }));
                }
            }
            match page["cursor"].as_str().filter(|s| !s.is_empty()) {
                Some(next) if !records.is_empty() && seen.insert(next.to_owned()) => {
                    cursor = Some(next.to_owned());
                }
                _ => break,
            }
        }
        Ok(())
    }
}

struct WasmLocalConversationAuthority {
    client: WasmMlsClient,
    db: WasmAccountDb<Rc<SqliteConn>>,
    session_token: String,
}

impl WasmLocalConversationAuthority {
    fn group_view(
        &self,
        conversation_id: &str,
    ) -> catbird_mls::orchestrator::error::Result<Option<(Vec<u8>, u64, i64, Vec<(String, Vec<u8>)>)>>
    {
        let backend = self.db.backend();
        let Some(convo) = backend
            .get_conversation(conversation_id)
            .map_err(OrchestratorError::Mls)?
        else {
            return Ok(None);
        };
        let provider = OpenMlsKvProvider::new(OpenMlsKvStorage::new(backend))
            .map_err(OrchestratorError::Mls)?;
        let Some(group) = MlsGroup::load(provider.storage(), &GroupId::from_slice(&convo.group_id))
            .map_err(|e| {
                OrchestratorError::Mls(MLSError::Internal(format!("load group: {e:?}")))
            })?
        else {
            return Ok(None);
        };
        let mut leaves = Vec::new();
        for member in group.members() {
            let identity = std::str::from_utf8(member.credential.serialized_content())
                .map_err(|_| OrchestratorError::Credential("non-UTF8 MLS credential".into()))?;
            let (did, _) = identity
                .split_once('#')
                .filter(|(d, dev)| d.starts_with("did:") && !dev.is_empty())
                .ok_or_else(|| OrchestratorError::Credential("unscoped MLS credential".into()))?;
            leaves.push((did.to_owned(), member.signature_key));
        }
        Ok(Some((
            convo.group_id,
            group.epoch().as_u64(),
            convo.last_seq,
            leaves,
        )))
    }
}

#[async_trait::async_trait(?Send)]
impl LocalConversationAuthority for WasmLocalConversationAuthority {
    async fn current_group_snapshot(
        &self,
        conversation_id: &str,
        queued_group_id_hex: Option<&str>,
    ) -> catbird_mls::orchestrator::error::Result<Option<LocalGroupSnapshot>> {
        let Some((group_id, epoch, _, leaves)) = self.group_view(conversation_id)? else {
            return Ok(None);
        };
        let group_id_hex = hex::encode(group_id);
        if queued_group_id_hex.is_some_and(|expected| expected != group_id_hex) {
            return Ok(None);
        }
        let mut member_dids: Vec<String> = leaves.into_iter().map(|(d, _)| d).collect();
        member_dids.sort();
        member_dids.dedup();
        Ok(Some(LocalGroupSnapshot {
            group_id_hex,
            epoch,
            member_dids,
        }))
    }

    async fn leaf_keys(
        &self,
        conversation_id: &str,
        did: &str,
    ) -> catbird_mls::orchestrator::error::Result<Option<LocalLeafKeys>> {
        let Some((_, _, applied, leaves)) = self.group_view(conversation_id)? else {
            return Ok(None);
        };
        let applied_chat_seq = u64::try_from(applied).unwrap_or(0);
        if applied_chat_seq == 0
            || !leaves
                .iter()
                .any(|(member, _)| *member == self.client.account_did)
        {
            return Ok(None);
        }
        let keys = leaves
            .into_iter()
            .filter(|(member, _)| member == did)
            .map(|(_, key)| {
                <[u8; 32]>::try_from(key.as_slice()).map_err(|_| {
                    OrchestratorError::Credential("MLS leaf signing key is not Ed25519".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(LocalLeafKeys {
            applied_chat_seq,
            keys,
        }))
    }

    async fn authorized_chat_device_keys(
        &self,
        did: &str,
    ) -> catbird_mls::orchestrator::error::Result<Option<Vec<[u8; 32]>>> {
        if did == self.client.account_did {
            return Ok(None);
        }
        if self
            .client
            .resolve_did_document(&self.session_token, did)
            .await
            .map_err(OrchestratorError::Mls)?
            .is_some()
        {
            let pairs = self
                .client
                .verify_peer_device_keys_via_pds(&self.session_token, did)
                .await
                .map_err(OrchestratorError::Mls)?;
            let mut out = Vec::with_capacity(pairs.len());
            for (_, pk) in pairs {
                if let Ok(key) = <[u8; 32]>::try_from(pk.as_slice()) {
                    out.push(key);
                }
            }
            return Ok(Some(out));
        }
        Ok(None)
    }
}

/// A `getRecord` answer for `at://{did}/mailboxKeys/{rkey}` with native
/// `parse_mailbox_keys_record`'s URI, CID and size checks; `RecordNotFound` is `None`.
fn mailbox_keys_record_with_json(
    response: GatewayResponse,
    did: &str,
    rkey: &str,
) -> labyrinth::Result<Option<((Vec<u8>, String), Value)>> {
    if response.body.len() > MAX_LABYRINTH_XRPC_RESPONSE_BYTES {
        return Err(labyrinth::Error::Backend(format!(
            "mailboxKeys response exceeds {MAX_LABYRINTH_XRPC_RESPONSE_BYTES} bytes"
        )));
    }
    let json: Option<Value> = serde_json::from_slice(&response.body).ok();
    if !(200..300).contains(&response.status) {
        let field = |key: &str| {
            json.as_ref()
                .and_then(|v| v[key].as_str())
                .map(str::to_owned)
        };
        let error = XrpcTransportError {
            status: response.status,
            error: field("error"),
            message: field("message"),
        };
        if matches!(error.status, 400 | 404) && error.error.as_deref() == Some("RecordNotFound") {
            return Ok(None);
        }
        return Err(map_xrpc_error(error));
    }
    let json = json.ok_or(labyrinth::Error::Malformed("mailboxKeys getRecord JSON"))?;
    let uri = format!("at://{did}/{}/{rkey}", nsid::MAILBOX_KEYS);
    if json["uri"].as_str() != Some(uri.as_str()) {
        return Err(labyrinth::Error::Malformed("mailboxKeys relay URI binding"));
    }
    let cid = json["cid"]
        .as_str()
        .filter(|cid| !cid.is_empty())
        .ok_or(labyrinth::Error::Malformed("getRecord missing CID"))?
        .to_owned();
    let value = json
        .get("value")
        .ok_or(labyrinth::Error::Malformed("getRecord missing value"))?;
    let bytes = serde_json::to_vec(value).map_err(|e| labyrinth::Error::Backend(e.to_string()))?;
    if bytes.len() > MAX_PDS_RECORD_BYTES {
        return Err(labyrinth::Error::Backend(format!(
            "PDS record exceeds {MAX_PDS_RECORD_BYTES} byte limit ({} bytes)",
            bytes.len()
        )));
    }
    Ok(Some(((bytes, cid), json)))
}

fn wasm_archive_error(error: OrchestratorError) -> MLSError {
    let message = error.to_string();
    if message.contains(WASM_UNAUTHENTICATED_DENIAL) {
        return MLSError::InvalidState("ArchiveRestorePending".into());
    }
    if message.contains("WriterRollback:")
        || message.contains("space writer revision rolled back for ")
    {
        return MLSError::Cryptography(message);
    }
    match error {
        OrchestratorError::Mls(err) => err,
        OrchestratorError::InvalidInput(m) => MLSError::invalid_input(m),
        other => MLSError::Internal(other.to_string()),
    }
}

/// `web.transport_mek:{cid}` holds `secret || roster_hash || space` of the transport MEK this
/// device distributed into `space`; it is reusable only there.
fn stored_transport_mek(raw: &[u8], space: &str, transport_pub: [u8; 32]) -> Option<Mek> {
    let (secret, rest) = raw.split_first_chunk::<32>()?;
    let (roster_hash, stored_space) = rest.split_first_chunk::<32>()?;
    (stored_space == space.as_bytes()).then(|| {
        Mek::from_secret(
            (*secret).into(),
            *roster_hash,
            MekProvenance::Transport {
                transport_pub,
                created_here: true,
            },
        )
    })
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct WasmArchiveEvidence {
    message_id: String,
    conversation_id: String,
    labyrinth_frame_json: String,
    frame_nonce_b64: Option<String>,
    sequencer_receipt_json: Option<String>,
    original_sender_attestation_json: Option<String>,
    created_at_ms: i64,
}

type WasmRestoreCopy = (
    MessageRow,
    WasmArchiveEvidence,
    chat_wire::StoredArchivedReceipt,
);

fn canonical_labyrinth_frame_json(plaintext_json: &str) -> String {
    if let Ok(payload) = MLSMessagePayload::decode(plaintext_json.as_bytes()) {
        if let Ok(encoded) = serde_json::to_string(&payload) {
            return encoded;
        }
    }
    plaintext_json.to_owned()
}

fn wasm_restore_copies(
    conversation_id: &str,
    self_did: &str,
    messages: Vec<LoadedMessage>,
) -> Result<BTreeMap<String, Vec<WasmRestoreCopy>>, MLSError> {
    let mut by_id: BTreeMap<String, Vec<WasmRestoreCopy>> = BTreeMap::new();
    for message in messages {
        let archived = message.archived_receipt.as_ref().ok_or_else(|| {
            MLSError::Cryptography("archive frame missing sequencer receipt".into())
        })?;
        let nonce = message.frame_nonce.ok_or_else(|| {
            MLSError::Cryptography("archive frame missing blinded commitment nonce".into())
        })?;
        let receipt = &archived.signed.payload;
        let (sender_did, sender_device_id) = receipt
            .split_sender_device()
            .map_err(|_| MLSError::Cryptography("archive sender device malformed".into()))?;
        if message.thread_id != conversation_id
            || receipt.conversation_id != conversation_id
            || message.sender.as_deref() != Some(sender_did)
        {
            return Err(MLSError::Cryptography(
                "archive coordinates/attribution conflict".into(),
            ));
        }
        MLSMessagePayload::decode(&message.frame)
            .map_err(|e| MLSError::Cryptography(format!("invalid canonical archive frame: {e}")))?;
        let plaintext_json =
            String::from_utf8(message.frame).map_err(|e| MLSError::Cryptography(e.to_string()))?;
        let row = MessageRow {
            message_id: message.message_id.clone(),
            conversation_id: conversation_id.into(),
            group_id: receipt.group_id.clone(),
            epoch: i64::try_from(receipt.epoch)
                .map_err(|_| MLSError::Cryptography("archive epoch overflow".into()))?,
            seq: i64::try_from(receipt.seq)
                .map_err(|_| MLSError::Cryptography("archive seq overflow".into()))?,
            sender_did: sender_did.into(),
            sender_device_id: sender_device_id.into(),
            plaintext_json,
            created_at_ms: i64::try_from(message.timestamp)
                .map_err(|_| MLSError::Cryptography("archive timestamp overflow".into()))?,
            is_own: sender_did == self_did,
        };
        let stored = chat_wire::StoredArchivedReceipt {
            sequencer_did: receipt.sequencer_did.clone(),
            conversation_id: receipt.conversation_id.clone(),
            group_id: receipt.group_id.clone(),
            epoch: receipt.epoch,
            sender_device_did_url: receipt.sender_device_did_url.clone(),
            entry_id: receipt.entry_id.clone(),
            archive_commitment: receipt.archive_commitment.to_vec(),
            seq: receipt.seq,
            issued_at_ms: receipt.issued_at_ms,
            key_id: archived.signed.key_id.clone(),
            signature: archived.signed.signature.to_vec(),
            generation: archived.generation,
            original_sender_attestation: Some(
                OriginalSenderArchiveAttestationEnvelope::from_labyrinth(
                    &archived.original_sender_attestation,
                ),
            ),
        };
        let evidence = WasmArchiveEvidence {
            message_id: row.message_id.clone(),
            conversation_id: conversation_id.into(),
            labyrinth_frame_json: row.plaintext_json.clone(),
            frame_nonce_b64: Some(STANDARD.encode(nonce)),
            sequencer_receipt_json: Some(
                serde_json::to_string(&stored).map_err(|e| MLSError::Internal(e.to_string()))?,
            ),
            original_sender_attestation_json: Some(
                serde_json::to_string(stored.original_sender_attestation.as_ref().ok_or_else(
                    || {
                        MLSError::Cryptography(
                            "archive copy missing original sender attestation".into(),
                        )
                    },
                )?)
                .map_err(|e| MLSError::Internal(e.to_string()))?,
            ),
            created_at_ms: row.created_at_ms,
        };
        let copies = by_id.entry(row.message_id.clone()).or_default();
        if copies.iter().all(|(kept, _, _)| *kept != row) {
            copies.push((row, evidence, stored));
        }
    }
    Ok(by_id)
}

fn select_wasm_restore_copy<'a>(
    copies: &'a [WasmRestoreCopy],
    local: Option<&MessageRow>,
    local_gap: bool,
) -> Option<&'a WasmRestoreCopy> {
    let Some(local) = local else {
        return match copies {
            [only] => Some(only),
            _ => None,
        };
    };
    let mut matching = copies.iter().filter(|(row, _, _)| {
        local.conversation_id == row.conversation_id
            && local.seq == row.seq
            && local.epoch == row.epoch
            && local.sender_did == row.sender_did
            && local.sender_device_id == row.sender_device_id
            && (local_gap
                || canonical_labyrinth_frame_json(&local.plaintext_json) == row.plaintext_json)
    });
    let first = matching.next()?;
    (!local_gap || matching.next().is_none()).then_some(first)
}

fn hide_deleted_accounts_wasm(
    db: &WasmAccountDb<Rc<SqliteConn>>,
    conversation_id: &str,
    messages: &mut Vec<LoadedMessage>,
) -> Result<usize, MLSError> {
    let senders: BTreeSet<String> = messages.iter().filter_map(|m| m.sender.clone()).collect();
    let mut deleted: BTreeMap<String, u64> = BTreeMap::new();
    for did in &senders {
        if let Some(raw) = db
            .backend()
            .get_labyrinth_state(&chat_wire::account_deletion_key(conversation_id, did))?
        {
            let seq = std::str::from_utf8(&raw)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(u64::MAX);
            deleted.insert(did.clone(), seq);
        }
    }
    let before = messages.len();
    messages.retain(|m| match m.sender.as_deref().and_then(|s| deleted.get(s)) {
        Some(&at) => m
            .archived_receipt
            .as_ref()
            .is_some_and(|r| r.signed.payload.seq > at),
        None => true,
    });
    Ok(before - messages.len())
}

impl WasmMlsClient {
    pub(crate) fn wasm_archive_deps_with_gateway(
        &self,
    ) -> Result<(SessionDeps, Arc<WebArchiveGateway>), MLSError> {
        let db_conn = self.require_db_mls()?.backend().clone();
        let (session_token, device_id) = self.require_live_session()?;
        let (keys, _) = self.load_enrolled_signer_and_auth_gen()?;
        let public: [u8; 32] = keys
            .public()
            .try_into()
            .map_err(|_| MLSError::Cryptography("archive chat key is not Ed25519".into()))?;
        let signer = Arc::new(WebArchiveSigner { keys, public });
        let gateway = Arc::new(WebArchiveGateway {
            client: self.http_view(),
            db: WasmAccountDb::new(db_conn.clone()),
            session_token: session_token.clone(),
            device_id: device_id.clone(),
            signer: signer.clone(),
            verified_inventories: RefCell::new(BTreeMap::new()),
        });
        let transport = Arc::new(
            GatewayXrpcTransport::new(
                gateway.clone(),
                signer.clone(),
                self.account_did.clone(),
                device_id,
            )
            .with_clock(Arc::new(WasmArchiveClock)),
        );
        let deps = SessionDeps {
            did: self.account_did.clone(),
            transport,
            signer,
            vault: Arc::new(WasmArchiveVault {
                db: WasmAccountDb::new(db_conn.clone()),
                namespace: "wasm.session",
            }),
            placements: Arc::new(WasmArchiveVault {
                db: WasmAccountDb::new(db_conn.clone()),
                namespace: "wasm.placements",
            }),
            pds: Some(gateway.clone()),
            space: Some(Arc::new(SpaceXrpcTransport::new(gateway.clone()))),
            local_authority: Some(Arc::new(WasmLocalConversationAuthority {
                client: self.http_view(),
                db: WasmAccountDb::new(db_conn),
                session_token,
            })),
            sequencer_receipt_key: None,
            default_conversation_authority_did: None,
        };
        Ok((deps, gateway))
    }

    fn wasm_archive_deps(&self) -> Result<SessionDeps, MLSError> {
        self.wasm_archive_deps_with_gateway().map(|(deps, _)| deps)
    }

    pub(crate) fn pin_wasm_conversation(&self, conversation_id: &str) -> Result<(), MLSError> {
        let db = self.require_db_mls()?;
        let Some(convo) = db.backend().get_conversation(conversation_id)? else {
            return Ok(());
        };
        if !convo.sequencer_did.starts_with("did:") || convo.sequencer_did.contains('#') {
            return Err(MLSError::Cryptography(
                "archive receipt has an invalid sequencer DID".into(),
            ));
        }
        let generation = u64::try_from(convo.generation).map_err(|_| {
            MLSError::Cryptography("archive conversation generation is negative".into())
        })?;
        let space_ref = match convo.space_uri.as_deref() {
            Some(space) => {
                SpaceRef::parse(space).map_err(|e| MLSError::Cryptography(e.to_string()))?
            }
            None => SpaceRef::conversation(
                &convo.sequencer_did,
                &format!("{conversation_id}-{generation}"),
            ),
        };
        if space_ref.space_did != convo.sequencer_did {
            return Err(MLSError::Cryptography(
                "conversation Space authority differs from pinned sequencer".into(),
            ));
        }
        let space = space_ref.to_string();
        let group_id = hex::encode(&convo.group_id);
        let key = format!(
            "wasm.placements:{}",
            thread_placement_key(&self.account_did)
        );
        let ts = now_ms();
        db.write_tx(|tx| {
            let mut placements: BTreeMap<String, ThreadPlacement> = tx
                .get_labyrinth_state(&key)?
                .map(|raw| serde_json::from_slice(&raw))
                .transpose()
                .map_err(|e| MLSError::Cryptography(format!("invalid archive Space pins: {e}")))?
                .unwrap_or_default();
            if let Some(existing) = placements.get(conversation_id) {
                existing
                    .validate()
                    .map_err(|e| MLSError::Cryptography(e.to_string()))?;
                let existing_space = existing
                    .space
                    .as_deref()
                    .ok_or_else(|| MLSError::Cryptography("archive Space pin is empty".into()))?;
                let existing_ref = SpaceRef::parse(existing_space)
                    .map_err(|e| MLSError::Cryptography(e.to_string()))?;
                if existing_ref.space_did != convo.sequencer_did {
                    return Err(MLSError::Cryptography(
                        "archive receipt cannot replace the pinned sequencer".into(),
                    ));
                }
                if existing.generation > generation {
                    return Ok(());
                }
                if existing.generation == generation {
                    if existing_space != space {
                        return Err(MLSError::Cryptography(
                            "archive receipt conflicts with the pinned Space".into(),
                        ));
                    }
                    match existing.group_id.as_deref() {
                        Some(pinned) if pinned == group_id => return Ok(()),
                        Some(_) => {
                            return Err(MLSError::Cryptography(
                                "archive receipt conflicts with the pinned MLS group".into(),
                            ))
                        }
                        None => {}
                    }
                }
            }
            placements.insert(
                conversation_id.to_owned(),
                ThreadPlacement {
                    space: Some(space),
                    generation,
                    group_id: Some(group_id),
                },
            );
            tx.put_labyrinth_state(
                &key,
                &serde_json::to_vec(&placements).map_err(|e| MLSError::Internal(e.to_string()))?,
                ts,
            )
        })
    }

    fn save_wasm_archive_status(
        &self,
        session: &LabyrinthSession,
        recovery_code: bool,
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        let ts = now_ms();
        let db = self.require_db_mls()?;
        db.write_tx(|tx| {
            let mut status = match tx.get_labyrinth_state("status_json")? {
                Some(raw) => serde_json::from_slice::<LabyrinthBackupStatus>(&raw)
                    .map_err(|e| MLSError::Internal(e.to_string()))?,
                None => LabyrinthBackupStatus {
                    backup_enabled: true,
                    mailbox_space_uri: catbird_mls::client::personal_mailbox_space_uri(
                        &self.account_did,
                    ),
                    has_recovery_code: false,
                    has_passkey_prf: false,
                    epoch_seq: 0,
                    active_device_ids: vec![self.device_id.clone()],
                    recovery_method_stale: false,
                    rotation_exclusions: Vec::new(),
                    pending_directory_epoch: None,
                    directory_publication_stalled: false,
                    directory_publication_retry_count: 0,
                    directory_publication_error: None,
                },
            };
            status.epoch_seq = session.latest_epoch();
            status.recovery_method_stale |= session.recovery_method_stale();
            status.has_recovery_code |= recovery_code;
            if !status.active_device_ids.contains(&self.device_id) {
                status.active_device_ids.push(self.device_id.clone());
            }
            status.pending_directory_epoch = session.pending_directory_epoch();
            if session.directory_publish_attempted() {
                status.directory_publication_retry_count =
                    status.directory_publication_retry_count.saturating_add(1);
            }
            status.directory_publication_error =
                session.directory_publish_error().map(str::to_owned);
            status.directory_publication_stalled = status.pending_directory_epoch.is_some()
                && status.directory_publication_error.is_some();
            if recovery_code {
                status
                    .rotation_exclusions
                    .retain(|exclusion| exclusion.recovery_method.as_deref() != Some("code"));
            }
            tx.put_labyrinth_state(
                "status_json",
                &serde_json::to_vec(&status).map_err(|e| MLSError::Internal(e.to_string()))?,
                ts,
            )?;
            Ok(status)
        })
    }

    async fn finish_pending_approval_after_archive_promotion(&self, promoted: bool) {
        if !promoted || !self.is_device_pending_approval_impl().unwrap_or(false) {
            return;
        }
        if let (Some((session_token, canonical_dev_id)), Ok((signer, _))) = (
            self.live_session(),
            self.load_enrolled_signer_and_auth_gen(),
        ) {
            if self
                .enroll_device_live(&session_token, &canonical_dev_id, &signer)
                .await
                .is_err()
            {
                if let Ok(db) = self.require_db_mls() {
                    let _ = db.write_tx(|tx| tx.delete_account_meta("enrollment_status"));
                }
            }
        }
    }

    pub(crate) async fn enable_labyrinth_live_impl(
        &self,
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        let session = self
            .wasm_archive_deps()?
            .enable()
            .await
            .map_err(wasm_archive_error)?;
        self.save_wasm_archive_status(&session, false)
    }

    pub(crate) async fn create_recovery_code_live_impl(&self) -> Result<String, MLSError> {
        let mut session = self
            .wasm_archive_deps()?
            .enable()
            .await
            .map_err(wasm_archive_error)?;
        let code = session
            .create_recovery_code()
            .await
            .map_err(wasm_archive_error)?;
        self.save_wasm_archive_status(&session, true)?;
        Ok(code)
    }

    pub(crate) async fn restore_with_recovery_code_live_impl(
        &self,
        code: &str,
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        labyrinth::recovery_code::RecoveryCode::candidates(code)
            .map_err(|_| MLSError::invalid_input("invalid 40-character Labyrinth recovery code"))?;
        let session = self
            .wasm_archive_deps()?
            .restore_with_recovery_code(code)
            .await
            .map_err(wasm_archive_error)?;
        let status = self.save_wasm_archive_status(&session, true)?;
        self.finish_pending_approval_after_archive_promotion(
            status.pending_directory_epoch.is_none(),
        )
        .await;
        Ok(status)
    }

    pub(crate) async fn register_passkey_prf_live_impl(
        &self,
        credential_id: &[u8],
        prf_output_32: &[u8],
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        if credential_id.is_empty() || prf_output_32.len() != 32 {
            return Err(MLSError::invalid_input(
                "passkey PRF requires non-empty credential_id and 32-byte PRF output",
            ));
        }
        let prf_zeroizing = Zeroizing::new(prf_output_32.to_vec());
        let mut session = self
            .wasm_archive_deps()?
            .enable()
            .await
            .map_err(wasm_archive_error)?;
        session
            .create_passkey_recovery(&prf_zeroizing, credential_id)
            .await
            .map_err(wasm_archive_error)?;
        let status = self.save_wasm_archive_status(&session, false)?;
        let ts = now_ms();
        self.require_db_mls()?.write_tx(|tx| {
            let mut st = status.clone();
            st.has_passkey_prf = true;
            st.rotation_exclusions
                .retain(|e| e.recovery_method.as_deref() != Some("passkey"));
            tx.put_labyrinth_state("passkey_credential_id", credential_id, ts)?;
            tx.put_labyrinth_state(
                "status_json",
                &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                ts,
            )?;
            Ok(st)
        })
    }

    pub(crate) async fn restore_with_passkey_prf_impl(
        &self,
        credential_id: &[u8],
        prf_output_32: &[u8],
    ) -> Result<LabyrinthBackupStatus, MLSError> {
        if credential_id.is_empty() || prf_output_32.len() != 32 {
            return Err(MLSError::invalid_input(
                "passkey PRF restore requires non-empty credential_id and 32-byte PRF output",
            ));
        }
        let prf_zeroizing = Zeroizing::new(prf_output_32.to_vec());
        if self.live_session().is_some() {
            let session = self
                .wasm_archive_deps()?
                .restore_with_passkey_prf(credential_id, &prf_zeroizing)
                .await
                .map_err(wasm_archive_error)?;
            let status = self.save_wasm_archive_status(&session, false)?;
            let ts = now_ms();
            let updated = self.require_db_mls()?.write_tx(|tx| {
                let mut st = status.clone();
                st.has_passkey_prf = true;
                st.rotation_exclusions
                    .retain(|e| e.recovery_method.as_deref() != Some("passkey"));
                tx.put_labyrinth_state("passkey_credential_id", credential_id, ts)?;
                tx.put_labyrinth_state(
                    "status_json",
                    &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                    ts,
                )?;
                Ok(st)
            })?;
            self.finish_pending_approval_after_archive_promotion(
                updated.pending_directory_epoch.is_none(),
            )
            .await;
            return Ok(updated);
        }

        // Offline Worker mode (no bearer session token): verify against local passkey binding if present.
        let mut expected_digest_hasher = Sha256::new();
        expected_digest_hasher.update(b"catbird.wasm.passkey_prf.v1\0");
        expected_digest_hasher.update(self.account_did.as_bytes());
        expected_digest_hasher.update([0u8]);
        expected_digest_hasher.update(credential_id);
        expected_digest_hasher.update([0u8]);
        expected_digest_hasher.update(&prf_zeroizing);
        let candidate_digest: [u8; 32] = expected_digest_hasher.finalize().into();

        let ts = now_ms();
        self.require_db_mls()?.write_tx(|tx| {
            if let Some(expected_cred) = tx.get_labyrinth_state("passkey_credential_id")? {
                if expected_cred != credential_id {
                    return Err(MLSError::insufficient_permissions(
                        "passkey credential_id does not match registered recovery passkey",
                    ));
                }
            }
            if let Some(expected_digest) = tx.get_labyrinth_state("passkey_prf_digest")? {
                if expected_digest.as_slice() != candidate_digest.as_slice() {
                    return Err(MLSError::insufficient_permissions(
                        "passkey PRF output does not match registered recovery passkey",
                    ));
                }
            }
            tx.put_labyrinth_state("passkey_credential_id", credential_id, ts)?;
            tx.put_labyrinth_state("passkey_prf_digest", &candidate_digest, ts)?;
            let raw = tx.get_labyrinth_state("status_json")?.ok_or_else(|| {
                MLSError::InvalidState("Labyrinth status not initialized".to_string())
            })?;
            let mut st: LabyrinthBackupStatus =
                serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            st.epoch_seq = st.epoch_seq.saturating_add(1);
            st.has_passkey_prf = true;
            if !st.active_device_ids.contains(&self.device_id) {
                st.active_device_ids.push(self.device_id.clone());
            }
            tx.upsert_mutation_journal(&MutationJournalRow {
                journal_id: format!("passkey-restore-epoch-{}", st.epoch_seq),
                op_type: "epoch_rotation".to_string(),
                epoch_seq: st.epoch_seq,
                state_json: json!({ "trigger": "passkey_prf_restore" }).to_string(),
                status: "done".to_string(),
                created_at_ms: ts,
                updated_at_ms: ts,
            })?;
            tx.put_labyrinth_state(
                "status_json",
                &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                ts,
            )?;
            Ok(st)
        })
    }

    pub(crate) async fn start_otc_pairing_impl(
        &self,
        six_digit_code: &str,
    ) -> Result<OtcInitiatedSession, MLSError> {
        let parsed = labyrinth::otc::OneTimeCode::parse(six_digit_code)
            .map_err(|_| MLSError::invalid_input("invalid 6-digit OTC code"))?;
        let code_digest: [u8; 32] = Sha256::digest(parsed.as_str().as_bytes()).into();
        let now_u64 = now_ms().max(0) as u64;
        let (initiator, session_id_hex, expires_at_ms, ek_len) = self
            .wasm_archive_deps()?
            .start_otc_session(parsed.as_str(), now_u64)
            .await
            .map_err(wasm_archive_error)?;
        *self.pending_otc_initiator.borrow_mut() =
            Some((session_id_hex.clone(), initiator, ek_len, code_digest));
        Ok(OtcInitiatedSession {
            session_id_hex,
            expires_at_ms: i64::try_from(expires_at_ms).unwrap_or(i64::MAX),
            initiator_mlkem768_ek_len: ek_len,
        })
    }

    pub(crate) async fn respond_otc_pairing_impl(
        &self,
        session_id_hex: &str,
        six_digit_code: Option<&str>,
    ) -> Result<(), MLSError> {
        let ts = now_ms();
        let mem_digits = self.pending_otc_offer_digits.borrow().clone();
        let db = self.require_db_mls()?;
        let resolved_digits = db.write_tx(|tx| {
            if let Some(raw_offer) = tx.get_labyrinth_state("pending_otc_offer")? {
                let mut offer: Value = serde_json::from_slice(&raw_offer)
                    .map_err(|e| MLSError::Internal(format!("parse pending_otc_offer: {e}")))?;
                let expires_at_ms = offer["expires_at_ms"].as_i64().unwrap_or(0);
                if ts >= expires_at_ms {
                    let _ = tx.delete_labyrinth_state_key("pending_otc_offer");
                    let _ = tx.delete_labyrinth_state_key("pending_otc_digits");
                    return Ok(Err(MLSError::InvalidState("OTC offer expired".into())));
                }
                let attempts = offer["attempts"].as_u64().unwrap_or(0);
                if attempts >= u64::from(labyrinth::otc::MAX_ATTEMPTS) {
                    let _ = tx.delete_labyrinth_state_key("pending_otc_offer");
                    let _ = tx.delete_labyrinth_state_key("pending_otc_digits");
                    return Ok(Err(MLSError::insufficient_permissions(
                        "OTC offer exceeded maximum attempts",
                    )));
                }
                let salt_bytes = hex::decode(
                    offer["salt_hex"].as_str().ok_or_else(|| {
                        MLSError::Internal("pending_otc_offer missing salt_hex".into())
                    })?,
                )
                .map_err(|e| MLSError::Internal(format!("decode OTC salt_hex: {e}")))?;
                let expected_digest = offer["code_digest_hex"]
                    .as_str()
                    .ok_or_else(|| {
                        MLSError::Internal("pending_otc_offer missing code_digest_hex".into())
                    })?
                    .to_owned();
                let candidate = match six_digit_code {
                    Some(provided) => labyrinth::otc::OneTimeCode::parse(provided)
                        .map_err(|_| MLSError::invalid_input("invalid 6-digit OTC code"))?
                        .as_str()
                        .to_owned(),
                    None => mem_digits
                        .as_ref()
                        .map(|z| z.as_str().to_owned())
                        .ok_or_else(|| {
                            MLSError::InvalidState(
                                "Active OTC offer requires six_digit_code after client restart"
                                    .into(),
                            )
                        })?,
                };
                let mut hasher = Sha256::new();
                hasher.update(b"catbird.otc.offer.v1\0");
                hasher.update(&salt_bytes);
                hasher.update(candidate.as_bytes());
                let candidate_digest = hex::encode(hasher.finalize());
                offer["attempts"] = json!(attempts.saturating_add(1));
                tx.put_labyrinth_state(
                    "pending_otc_offer",
                    &serde_json::to_vec(&offer).map_err(|e| MLSError::Internal(e.to_string()))?,
                    ts,
                )?;
                if candidate_digest != expected_digest {
                    return Ok(Err(MLSError::insufficient_permissions(
                        "OTC code does not match active offer",
                    )));
                }
                return Ok(Ok(Zeroizing::new(candidate)));
            }
            let Some(provided) = six_digit_code else {
                return Err(MLSError::InvalidState(
                    "No active OTC offer on this device; pass six_digit_code or call initiateOtcPairing first".into(),
                ));
            };
            let parsed = labyrinth::otc::OneTimeCode::parse(provided)
                .map_err(|_| MLSError::invalid_input("invalid 6-digit OTC code"))?;
            Ok(Ok(Zeroizing::new(parsed.as_str().to_owned())))
        })?;
        let digits = match resolved_digits {
            Ok(d) => d,
            Err(err) => {
                if db
                    .backend()
                    .get_labyrinth_state("pending_otc_offer")?
                    .is_none()
                {
                    *self.pending_otc_offer_digits.borrow_mut() = None;
                }
                return Err(err);
            }
        };

        let deps = self.wasm_archive_deps()?;
        let mailbox = deps.open_mailbox_store().map_err(wasm_archive_error)?;
        let mut session = match deps.clone().open().await.map_err(wasm_archive_error)? {
            Some(s) => s,
            None => deps.enable().await.map_err(wasm_archive_error)?,
        };
        session
            .respond_otc_session(&mailbox, session_id_hex, digits.as_str(), ts.max(0) as u64)
            .await
            .map_err(wasm_archive_error)?;
        self.save_wasm_archive_status(&session, false)?;
        let _ = db.write_tx(|tx| {
            let _ = tx.delete_labyrinth_state_key("pending_otc_offer");
            let _ = tx.delete_labyrinth_state_key("pending_otc_digits");
            Ok(())
        });
        *self.pending_otc_offer_digits.borrow_mut() = None;
        Ok(())
    }

    pub(crate) async fn complete_live_otc_pairing_impl(
        &self,
        six_digit_code: &str,
    ) -> Result<OtcPairingCompletion, MLSError> {
        let parsed = labyrinth::otc::OneTimeCode::parse(six_digit_code)
            .map_err(|_| MLSError::invalid_input("invalid 6-digit OTC code"))?;
        let provided_digest: [u8; 32] = Sha256::digest(parsed.as_str().as_bytes()).into();
        let (session_id_hex, initiator, ek_len) = {
            let mut guard = self.pending_otc_initiator.borrow_mut();
            let Some((_, _, _, expected_digest)) = guard.as_ref() else {
                return Err(MLSError::InvalidState(
                    "No pending live OTC initiator session".into(),
                ));
            };
            if *expected_digest != provided_digest {
                return Err(MLSError::insufficient_permissions(
                    "OTC code does not match initiated session",
                ));
            }
            let (sid, init, ek, _) = guard.take().expect("checked Some");
            (sid, init, ek)
        };
        let session_id = hex::decode(&session_id_hex)
            .map_err(|_| MLSError::Internal("invalid OTC session_id_hex".into()))?;
        let now_u64 = now_ms().max(0) as u64;
        let (session, new_epoch, kem_ct_len) = self
            .wasm_archive_deps()?
            .complete_otc_session(initiator, &session_id_hex, now_u64)
            .await
            .map_err(wasm_archive_error)?;
        let status = self.save_wasm_archive_status(&session, false)?;
        let new_epoch_seq = status.epoch_seq.max(new_epoch);
        let ts = now_ms();
        self.require_db_mls()?.write_tx(|tx| {
            let mut st = status.clone();
            st.epoch_seq = new_epoch_seq;
            if !st.active_device_ids.contains(&self.device_id) {
                st.active_device_ids.push(self.device_id.clone());
            }
            tx.upsert_mutation_journal(&MutationJournalRow {
                journal_id: format!("otc-epoch-{new_epoch_seq}"),
                op_type: "epoch_rotation".to_string(),
                epoch_seq: new_epoch_seq,
                state_json: json!({
                    "trigger": "otc_pq_pairing",
                    "sessionId": session_id_hex,
                })
                .to_string(),
                status: "completed".to_string(),
                created_at_ms: ts,
                updated_at_ms: ts,
            })?;
            tx.put_labyrinth_state(
                "status_json",
                &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                ts,
            )
        })?;
        self.finish_pending_approval_after_archive_promotion(
            status.pending_directory_epoch.is_none(),
        )
        .await;
        Ok(OtcPairingCompletion {
            session_id,
            initiator_mlkem768_ek_len: ek_len,
            responder_mlkem768_ct_len: kem_ct_len,
            new_epoch_seq,
        })
    }

    pub(crate) async fn rearchive_conversation_before_leave_impl(
        &self,
        conversation_id: &str,
    ) -> Result<u32, MLSError> {
        let _ = self.flush_labyrinth_queue_impl().await;
        self.pin_wasm_conversation(conversation_id)?;
        let deps = self.wasm_archive_deps()?;
        let Some(mut session) = deps.open().await.map_err(wasm_archive_error)? else {
            return Ok(0);
        };
        let archived = session
            .rearchive_before_leave(conversation_id)
            .await
            .map_err(wasm_archive_error)?;
        self.save_wasm_archive_status(&session, false)?;
        Ok(u32::try_from(archived).unwrap_or(u32::MAX))
    }

    pub(crate) async fn verify_and_reindex_history_impl(
        &self,
        conversation_id: &str,
    ) -> Result<u32, MLSError> {
        self.pin_wasm_conversation(conversation_id)?;
        let deps = self.wasm_archive_deps()?;
        let mut session = deps
            .open()
            .await
            .map_err(wasm_archive_error)?
            .ok_or_else(|| MLSError::InvalidState("archive is not enrolled".into()))?;
        let page = session
            .load_history(conversation_id, TimeRange::ALL)
            .await
            .map_err(wasm_archive_error)?;
        if page.undecryptable != 0 {
            return Err(MLSError::Cryptography(
                "conversation archive contains corrupt or unverified frames".into(),
            ));
        }
        let mut history = page.messages;
        let db = self.require_db_mls()?;
        hide_deleted_accounts_wasm(db, conversation_id, &mut history)?;
        let copies = wasm_restore_copies(conversation_id, &self.account_did, history)?;
        let ts = now_ms();
        db.write_tx(|tx| {
            let mut chosen_by_id = BTreeMap::new();
            for group in copies.values() {
                let message_id = &group[0].0.message_id;
                let local = tx.get_message(message_id)?;
                let has_local_evidence = tx
                    .get_labyrinth_state(&format!("native.message:{conversation_id}:{message_id}"))?
                    .is_some();
                let gap_key = chat_wire::undecryptable_evidence_key(conversation_id, message_id);
                let gap = local.is_some() && tx.get_labyrinth_state(&gap_key)?.is_some();
                let effective_local = if has_local_evidence {
                    local.as_ref()
                } else {
                    None
                };
                if let Some(copy) = select_wasm_restore_copy(group, effective_local, gap) {
                    chosen_by_id.insert(message_id.clone(), copy);
                }
            }
            let existing_rows = tx.list_messages(conversation_id, None, 100_000)?;
            for existing in &existing_rows {
                let ev_key = format!("native.message:{conversation_id}:{}", existing.message_id);
                if tx.get_labyrinth_state(&ev_key)?.is_some() {
                    continue;
                }
                let matches_verified =
                    chosen_by_id
                        .get(&existing.message_id)
                        .is_some_and(|(row, _, _)| {
                            row.seq == existing.seq
                                && row.sender_did == existing.sender_did
                                && row.plaintext_json == existing.plaintext_json
                        });
                if !matches_verified {
                    tx.delete_message(conversation_id, &existing.message_id)?;
                }
            }
            let mut count = 0u32;
            for (row, evidence, _) in chosen_by_id.into_values() {
                let existing = tx.get_message(&row.message_id)?;
                let gap_key =
                    chat_wire::undecryptable_evidence_key(conversation_id, &row.message_id);
                let gap = existing.is_some() && tx.get_labyrinth_state(&gap_key)?.is_some();
                if existing.is_none() || gap {
                    tx.insert_message(row)?;
                }
                if gap {
                    tx.delete_labyrinth_state_key(&gap_key)?;
                }
                tx.put_labyrinth_state(
                    &format!("native.message:{conversation_id}:{}", row.message_id),
                    &serde_json::to_vec(evidence).map_err(|e| MLSError::Internal(e.to_string()))?,
                    ts,
                )?;
                count = count.saturating_add(1);
            }
            Ok(count)
        })
    }

    pub(crate) async fn upload_conversation_attachment_impl(
        &self,
        conversation_id: &str,
        plaintext: &[u8],
        mime_type: String,
    ) -> Result<UploadedConversationAttachment, MLSError> {
        if conversation_id.trim().is_empty() {
            return Err(MLSError::invalid_input("conversation_id must not be empty"));
        }
        if plaintext.is_empty() {
            return Err(MLSError::invalid_input(
                "attachment plaintext must not be empty",
            ));
        }
        let encrypted = catbird_mls::blob_crypto::encrypt_blob(plaintext)
            .map_err(|e| MLSError::Cryptography(format!("encrypt attachment: {e}")))?;
        let meta = labyrinth::attachment::AttachmentCiphertextMeta::from_ciphertext(
            &encrypted.ciphertext,
            (!mime_type.is_empty()).then(|| mime_type.clone()),
        )
        .map_err(|e| MLSError::invalid_input(format!("attachment metadata: {e}")))?;
        self.pin_wasm_conversation(conversation_id)?;
        let created_at = datetime_from_ms(now_ms().max(0) as u64);
        let (deps, gateway) = self.wasm_archive_deps_with_gateway()?;
        let store = deps.resolving_thread_store().map_err(wasm_archive_error)?;
        let (space_uri, cid, rkey) = store
            .upload_conversation_attachment_blob(
                conversation_id,
                &encrypted.ciphertext,
                &meta,
                &created_at,
            )
            .await
            .map_err(|e| {
                MLSError::Internal(format!("upload conversation Space attachment: {e}"))
            })?;
        let _ = gateway.persist_writer_rev_floors(&store.export_writer_rev_floors());
        let locator = format!("{space_uri}|{}|{cid}", self.account_did);
        Ok(UploadedConversationAttachment {
            locator,
            space_uri,
            repo_did: self.account_did.clone(),
            cid,
            rkey,
            symmetric_key: encrypted.key,
            iv: encrypted.iv,
            ciphertext_sha256: meta.sha256.to_vec(),
            ciphertext_size: meta.ciphertext_size,
            mime_type,
        })
    }

    pub(crate) async fn download_conversation_attachment_impl(
        &self,
        locator: &str,
        symmetric_key: &[u8],
        iv: &[u8],
        expected_sha256: Option<&[u8]>,
    ) -> Result<Vec<u8>, MLSError> {
        let mut parts = locator.splitn(3, '|');
        let (Some(space_uri), Some(repo_did), Some(cid)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(MLSError::invalid_input(
                "attachment locator must be \"{spaceURI}|{repoDID}|{cid}\"",
            ));
        };
        if cid.trim().is_empty() || cid.contains('|') {
            return Err(MLSError::invalid_input("attachment locator CID is invalid"));
        }
        let parsed_space = atproto_spaces::SpaceUri::parse_hedged(space_uri)
            .map_err(|e| MLSError::invalid_input(format!("invalid attachment Space URI: {e}")))?;
        if !atproto_spaces::is_valid_did(repo_did) {
            return Err(MLSError::invalid_input(
                "attachment locator repoDID is invalid",
            ));
        }
        let (_, gateway) = self.wasm_archive_deps_with_gateway()?;
        let space_rpc = SpaceXrpcTransport::new(gateway);
        let ciphertext = space_rpc
            .get_blob(&parsed_space.raw, repo_did, cid)
            .await
            .map_err(|e| MLSError::Cryptography(format!("download Space attachment: {e:?}")))?;
        let actual_sha = Sha256::digest(&ciphertext);
        let expected_sha_hex = if let Some(exp_sha) = expected_sha256.filter(|s| !s.is_empty()) {
            if actual_sha.as_slice() != exp_sha {
                return Err(MLSError::Cryptography(
                    "attachment ciphertext SHA-256 mismatch".into(),
                ));
            }
            hex::encode(exp_sha)
        } else {
            hex::encode(actual_sha)
        };
        catbird_mls::blob_crypto::decrypt_blob(&ciphertext, symmetric_key, iv, &expected_sha_hex)
            .map_err(|e| MLSError::Cryptography(format!("decrypt attachment: {e}")))
    }

    fn extract_own_device_views(resp: &Value) -> Vec<&Value> {
        resp.get("items")
            .and_then(Value::as_array)
            .or_else(|| resp.get("devices").and_then(Value::as_array))
            .map(|arr| {
                arr.iter()
                    .map(|item| item.get("device").unwrap_or(item))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn decode_device_pubkey_field(field: &Value) -> Vec<u8> {
        chat_wire::json_bytes(field)
            .ok()
            .or_else(|| {
                field
                    .get("$bytes")
                    .and_then(Value::as_str)
                    .or_else(|| field.as_str())
                    .and_then(|b64| {
                        STANDARD
                            .decode(b64)
                            .ok()
                            .or_else(|| STANDARD.decode(b64.trim_end_matches('=')).ok())
                    })
            })
            .unwrap_or_default()
    }

    pub(crate) async fn list_devices_impl(&self) -> Result<Vec<RegisteredDeviceInfo>, MLSError> {
        let (session_token, own_device_id) = self.require_live_session()?;
        let (signer, _) = self.load_enrolled_signer_and_auth_gen()?;
        let ds_resp = self
            .ds_signed_get(
                &session_token,
                &own_device_id,
                "blue.catbird.chat.getOwnDevices",
                &[("actorDeviceId", &own_device_id), ("limit", "100")],
                &signer,
            )
            .await?;
        let mailbox_by_transport: BTreeMap<[u8; 32], String> =
            if self.is_device_pending_approval_impl()? {
                BTreeMap::new()
            } else if let Ok(deps) = self.wasm_archive_deps() {
                match deps.list_mailbox_devices().await {
                    Ok(devs) => devs
                        .into_iter()
                        .filter(|d| !d.r#virtual && d.revoked_at.is_none())
                        .filter_map(|d| {
                            let binding = d.chat_binding().ok().flatten()?;
                            Some((
                                binding.transport_public_key,
                                hex::encode(d.device_key_pubkey.0),
                            ))
                        })
                        .collect(),
                    Err(_) => BTreeMap::new(),
                }
            } else {
                BTreeMap::new()
            };
        let mut out = Vec::new();
        for item in Self::extract_own_device_views(&ds_resp) {
            let Some(device_id) = item["deviceId"].as_str().map(str::to_owned) else {
                continue;
            };
            let pubkey_bytes = Self::decode_device_pubkey_field(&item["signaturePublicKey"]);
            let labyrinth_device_key_hex = <[u8; 32]>::try_from(pubkey_bytes.as_slice())
                .ok()
                .and_then(|pk| mailbox_by_transport.get(&pk).cloned());
            let key_id = item["keyId"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| derive_key_id(&pubkey_bytes));
            let is_current = item["isCurrentDevice"]
                .as_bool()
                .unwrap_or_else(|| device_id == own_device_id);
            out.push(RegisteredDeviceInfo {
                device_id,
                device_name: item["deviceName"].as_str().map(str::to_owned),
                signature_public_key: pubkey_bytes,
                key_id,
                auth_generation: item["authGeneration"].as_i64().unwrap_or(1),
                status: item["status"].as_str().unwrap_or("active").to_owned(),
                created_at: item["createdAt"].as_str().unwrap_or("").to_owned(),
                last_active_at: item["lastActiveAt"].as_str().map(str::to_owned),
                dormant_at: item["dormantAt"].as_str().map(str::to_owned),
                labyrinth_device_key_hex,
                is_current_device: is_current,
            });
        }
        Ok(out)
    }

    pub(crate) async fn revoke_device_impl(
        &self,
        target_device_id: &str,
    ) -> Result<DeviceRevocationReport, MLSError> {
        let target_trimmed = target_device_id.trim();
        if target_trimmed.is_empty() {
            return Err(MLSError::invalid_input(
                "target_device_id must not be empty",
            ));
        }
        let (session_token, own_device_id) = self.require_live_session()?;
        if target_trimmed.eq_ignore_ascii_case(&own_device_id) {
            return Err(MLSError::invalid_input(
                "cannot revoke current device via revokeDevice; use retireCurrentDevice to sign out cleanly",
            ));
        }
        let (actor_signer, actor_auth_gen) = self.load_enrolled_signer_and_auth_gen()?;
        let own_devices = self
            .ds_signed_get(
                &session_token,
                &own_device_id,
                "blue.catbird.chat.getOwnDevices",
                &[("actorDeviceId", &own_device_id), ("limit", "100")],
                &actor_signer,
            )
            .await?;
        let target_entry = Self::extract_own_device_views(&own_devices)
            .into_iter()
            .find(|d| d["deviceId"].as_str() == Some(target_trimmed))
            .ok_or_else(|| {
                MLSError::invalid_input("target_device_id not found in getOwnDevices")
            })?;
        let target_auth_gen = target_entry["authGeneration"].as_i64().unwrap_or(1).max(1);
        let target_pubkey_opt: Option<[u8; 32]> = <[u8; 32]>::try_from(
            Self::decode_device_pubkey_field(&target_entry["signaturePublicKey"]).as_slice(),
        )
        .ok();
        let already_revoked = target_entry["status"].as_str() == Some("revoked");

        if !already_revoked {
            let revoke_body = json!({
                "$type": "blue.catbird.chat.defs#deviceRevocationBody",
                "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\0",
                "actorDid": self.account_did,
                "actorDeviceId": own_device_id,
                "authGeneration": actor_auth_gen,
                "targetDeviceId": target_trimmed,
                "targetAuthGeneration": target_auth_gen,
                "idempotencyKey": uuid::Uuid::new_v4().to_string(),
                "keyId": derive_key_id(actor_signer.public()),
                "signedAt": chat_wire::now_rfc3339_millis(),
            });
            let _ = self
                .submit_signed_chat_op(
                    &session_token,
                    &own_device_id,
                    Some(actor_auth_gen),
                    CanonicalOperation::RevokeDevice,
                    &revoke_body,
                    &actor_signer,
                )
                .await?;
        }
        let ds_revoked = true;
        let groups_updated = self
            .remove_specific_device_from_active_groups_impl(target_trimmed)
            .await
            .unwrap_or(0);

        let mut labyrinth_rotated = false;
        let mut new_epoch_seq = None;
        let mut rekeyed_recovery_code = None;
        let mut rekeyed_passkey_ids = Vec::new();
        let mut collected_exclusions = Vec::new();

        if let Some(chat_pubkey) = target_pubkey_opt {
            if let Ok(deps) = self.wasm_archive_deps() {
                if let Ok(Some(mut session)) = deps.open().await {
                    let reports = session
                        .revoke_chat_device(chat_pubkey)
                        .await
                        .map_err(wasm_archive_error)?;
                    self.save_wasm_archive_status(
                        &session,
                        reports.iter().any(|r| r.rekeyed_recovery_code.is_some()),
                    )?;
                    for rep in reports {
                        labyrinth_rotated = true;
                        new_epoch_seq = Some(rep.new_epoch);
                        if rep.rekeyed_recovery_code.is_some() {
                            rekeyed_recovery_code = rep.rekeyed_recovery_code;
                        }
                        for pk_id in rep.rekeyed_passkeys {
                            rekeyed_passkey_ids.push(pk_id.to_vec());
                        }
                        for excluded in rep.exclusions {
                            collected_exclusions.push(LabyrinthRotationExclusion {
                                device_key_hex: excluded.device_key.map(hex::encode),
                                reason: excluded.reason,
                                recovery_method: excluded
                                    .recovery_method
                                    .map(|m| m.as_str().to_owned()),
                            });
                        }
                    }
                }
            }
        }

        let mut pds_record_deleted = false;
        if let Ok(bytes) = serde_json::to_vec(&json!({
            "repo": self.account_did,
            "collection": "blue.catbird.chat.device",
            "rkey": target_trimmed,
        })) {
            if let Ok((st, _)) = self
                .pds_post_json(&session_token, "/xrpc/com.atproto.repo.deleteRecord", bytes)
                .await
            {
                pds_record_deleted = (200..300).contains(&st);
            }
        }

        let ts = now_ms();
        self.require_db_mls()?.write_tx(|tx| {
            let raw = tx
                .get_labyrinth_state("status_json")?
                .ok_or_else(|| MLSError::InvalidState("Labyrinth status not initialized".into()))?;
            let mut st: LabyrinthBackupStatus =
                serde_json::from_slice(&raw).map_err(|e| MLSError::Internal(e.to_string()))?;
            st.active_device_ids.retain(|d| d != target_trimmed);
            if let Some(seq) = new_epoch_seq {
                st.epoch_seq = seq;
            } else {
                st.epoch_seq = st.epoch_seq.saturating_add(1);
            }
            if !collected_exclusions.is_empty() {
                st.rotation_exclusions = collected_exclusions;
            }
            if !rekeyed_passkey_ids.is_empty() {
                st.has_passkey_prf = false;
            }
            if rekeyed_recovery_code.is_some() {
                st.has_recovery_code = true;
            }
            tx.upsert_mutation_journal(&MutationJournalRow {
                journal_id: format!("revoke-{target_trimmed}-{}", st.epoch_seq),
                op_type: "device_revocation".to_string(),
                epoch_seq: st.epoch_seq,
                state_json: json!({ "revokedDeviceId": target_trimmed }).to_string(),
                status: "completed".to_string(),
                created_at_ms: ts,
                updated_at_ms: ts,
            })?;
            tx.put_labyrinth_state(
                "status_json",
                &serde_json::to_vec(&st).map_err(|e| MLSError::Internal(e.to_string()))?,
                ts,
            )?;
            Ok(())
        })?;

        Ok(DeviceRevocationReport {
            target_device_id: target_trimmed.to_owned(),
            ds_revoked,
            groups_updated,
            labyrinth_rotated,
            new_epoch_seq,
            pds_record_deleted,
            rekeyed_recovery_code,
            rekeyed_passkey_ids,
        })
    }

    pub(crate) async fn retire_current_device_pre_wipe(&self) -> Result<(), MLSError> {
        let _ = self.require_db_mls()?;
        let _ = self.flush_labyrinth_queue_impl().await;
        if let Some((session_token, own_device_id)) = self.live_session() {
            if let Ok((signer, _)) = self.load_enrolled_signer_and_auth_gen() {
                let other_active = self
                    .ds_signed_get(
                        &session_token,
                        &own_device_id,
                        "blue.catbird.chat.getOwnDevices",
                        &[("actorDeviceId", &own_device_id), ("limit", "100")],
                        &signer,
                    )
                    .await
                    .ok()
                    .map(|resp| {
                        Self::extract_own_device_views(&resp).into_iter().any(|d| {
                            d["deviceId"].as_str() != Some(own_device_id.as_str())
                                && matches!(d["status"].as_str(), Some("active"))
                        })
                    })
                    .unwrap_or(false);
                if !other_active {
                    if let Ok(db) = self.require_db_mls() {
                        if let Ok(convs) = db.backend().list_conversations(None, 500) {
                            for conv in convs {
                                let _ = self.leave_conversation_impl(&conv.conversation_id).await;
                            }
                        }
                    }
                    if let Ok(bytes) = serde_json::to_vec(&json!({
                        "repo": self.account_did,
                        "collection": "blue.catbird.chat.device",
                        "rkey": own_device_id,
                    })) {
                        let _ = self
                            .pds_post_json(
                                &session_token,
                                "/xrpc/com.atproto.repo.deleteRecord",
                                bytes,
                            )
                            .await;
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn delete_account_data_remote_impl(&self) -> Result<(), MLSError> {
        let _ = self.require_db_mls()?;
        let deps = self.wasm_archive_deps()?;
        deps.delete_account_remote()
            .await
            .map(|_| ())
            .map_err(|e| MLSError::Internal(format!("delete remote account data: {e}")))
    }

    pub(crate) async fn get_read_state_impl(
        &self,
        conversation_id: &str,
    ) -> Result<Option<MailboxReadStateRecord>, MLSError> {
        let mut session = self
            .wasm_archive_deps()?
            .enable()
            .await
            .map_err(wasm_archive_error)?;
        let state = session
            .get_read_state(conversation_id)
            .await
            .map_err(wasm_archive_error)?;
        Ok(state.map(|s| MailboxReadStateRecord {
            conversation_id: s.conversation_id,
            read_through_seq: s.read_through_seq,
            updated_at: s.updated_at,
        }))
    }

    pub(crate) async fn advance_read_state_impl(
        &self,
        conversation_id: &str,
        candidate_seq: u64,
    ) -> Result<MailboxReadStateRecord, MLSError> {
        let mut session = self
            .wasm_archive_deps()?
            .enable()
            .await
            .map_err(wasm_archive_error)?;
        let s = session
            .advance_read_state(conversation_id, candidate_seq)
            .await
            .map_err(wasm_archive_error)?;
        Ok(MailboxReadStateRecord {
            conversation_id: s.conversation_id,
            read_through_seq: s.read_through_seq,
            updated_at: s.updated_at,
        })
    }

    pub(crate) async fn list_read_states_impl(
        &self,
    ) -> Result<Vec<MailboxReadStateRecord>, MLSError> {
        let mut session = self
            .wasm_archive_deps()?
            .enable()
            .await
            .map_err(wasm_archive_error)?;
        let list = session
            .list_read_states()
            .await
            .map_err(wasm_archive_error)?;
        Ok(list
            .into_iter()
            .map(|s| MailboxReadStateRecord {
                conversation_id: s.conversation_id,
                read_through_seq: s.read_through_seq,
                updated_at: s.updated_at,
            })
            .collect())
    }

    fn circle_owner_state_to_dto(
        state: labyrinth::client::CircleOwnerState,
        record_cid: Option<String>,
    ) -> Result<CircleOwnerStateDto, MLSError> {
        Ok(CircleOwnerStateDto {
            circle_id: state.circle_id,
            space_uri: state.space_uri,
            current_key_version: state.current_key_version,
            joined_at_version_json: serde_json::to_string(&state.joined_at_version_by_did)
                .map_err(|e| MLSError::Internal(e.to_string()))?,
            pending_ops_json: serde_json::to_string(&state.pending_ops)
                .map_err(|e| MLSError::Internal(e.to_string()))?,
            updated_at: state.updated_at,
            record_cid,
        })
    }

    fn circle_owner_state_from_dto(
        dto: &CircleOwnerStateDto,
        default_now_rfc3339: &str,
    ) -> Result<labyrinth::client::CircleOwnerState, MLSError> {
        let joined_at_version_by_did: BTreeMap<String, u64> =
            if dto.joined_at_version_json.trim().is_empty() {
                BTreeMap::new()
            } else {
                serde_json::from_str(&dto.joined_at_version_json).map_err(|e| {
                    MLSError::invalid_input(format!("invalid joined_at_version_json: {e}"))
                })?
            };
        let pending_ops: BTreeMap<String, String> = if dto.pending_ops_json.trim().is_empty() {
            BTreeMap::new()
        } else {
            serde_json::from_str(&dto.pending_ops_json)
                .map_err(|e| MLSError::invalid_input(format!("invalid pending_ops_json: {e}")))?
        };
        let updated_at = if dto.updated_at.trim().is_empty() {
            default_now_rfc3339.to_owned()
        } else {
            dto.updated_at.clone()
        };
        let state = labyrinth::client::CircleOwnerState {
            circle_id: dto.circle_id.clone(),
            space_uri: dto.space_uri.clone(),
            current_key_version: dto.current_key_version,
            joined_at_version_by_did,
            pending_ops,
            updated_at,
        };
        state
            .validate()
            .map_err(|e| MLSError::invalid_input(format!("circleOwnerState: {e}")))?;
        Ok(state)
    }

    pub(crate) async fn get_circle_owner_state_impl(
        &self,
        circle_id: &str,
    ) -> Result<Option<CircleOwnerStateDto>, MLSError> {
        let mut session = self
            .wasm_archive_deps()?
            .enable()
            .await
            .map_err(wasm_archive_error)?;
        let found = session
            .get_circle_owner_state(circle_id)
            .await
            .map_err(wasm_archive_error)?;
        found
            .map(|(state, cid)| Self::circle_owner_state_to_dto(state, cid))
            .transpose()
    }

    pub(crate) async fn put_circle_owner_state_impl(
        &self,
        state: CircleOwnerStateDto,
        swap_record_cid: Option<String>,
    ) -> Result<String, MLSError> {
        let now = datetime_from_ms(now_ms().max(0) as u64);
        let parsed = Self::circle_owner_state_from_dto(&state, &now)?;
        let expected_cid = swap_record_cid.or_else(|| state.record_cid.clone());
        let mut session = self
            .wasm_archive_deps()?
            .enable()
            .await
            .map_err(wasm_archive_error)?;
        session
            .put_circle_owner_state(&parsed, expected_cid.as_deref())
            .await
            .map_err(wasm_archive_error)
    }

    pub(crate) async fn merge_circle_owner_state_impl(
        &self,
        update: CircleOwnerStateDto,
    ) -> Result<CircleOwnerStateDto, MLSError> {
        let now = datetime_from_ms(now_ms().max(0) as u64);
        let parsed = Self::circle_owner_state_from_dto(&update, &now)?;
        let mut session = self
            .wasm_archive_deps()?
            .enable()
            .await
            .map_err(wasm_archive_error)?;
        let (merged, cid) = session
            .merge_circle_owner_state(&parsed)
            .await
            .map_err(wasm_archive_error)?;
        Self::circle_owner_state_to_dto(merged, Some(cid))
    }

    pub(crate) async fn clear_circle_acl_tombstone_impl(
        &self,
        circle_id: &str,
        member_did: &str,
    ) -> Result<Option<CircleOwnerStateDto>, MLSError> {
        let mut session = self
            .wasm_archive_deps()?
            .enable()
            .await
            .map_err(wasm_archive_error)?;
        let cleared = session
            .clear_circle_acl_tombstone(circle_id, member_did)
            .await
            .map_err(wasm_archive_error)?;
        cleared
            .map(|(state, cid)| {
                Self::circle_owner_state_to_dto(state, (!cid.is_empty()).then_some(cid))
            })
            .transpose()
    }

    pub(crate) async fn list_circle_owner_states_impl(
        &self,
    ) -> Result<Vec<CircleOwnerStateDto>, MLSError> {
        let mut session = self
            .wasm_archive_deps()?
            .enable()
            .await
            .map_err(wasm_archive_error)?;
        let list = session
            .list_circle_owner_states()
            .await
            .map_err(wasm_archive_error)?;
        list.into_iter()
            .map(|state| Self::circle_owner_state_to_dto(state, None))
            .collect()
    }

    pub(crate) async fn flush_labyrinth_queue_impl(&self) -> Result<u32, MLSError> {
        let Some((session_token, device_id)) = self.live_session() else {
            return Ok(0);
        };
        let db = self.require_db_mls()?;
        if let Some(raw) = db.backend().get_labyrinth_state("status_json")? {
            if let Ok(st) = serde_json::from_slice::<LabyrinthBackupStatus>(&raw) {
                if !st.backup_enabled {
                    return Ok(0);
                }
            }
        }
        let rows = db.backend().list_labyrinth_queue(None, 100)?;
        if rows.is_empty() {
            return Ok(0);
        }
        let (keys, _) = self.load_enrolled_signer_and_auth_gen()?;
        let public: [u8; 32] = keys
            .public()
            .try_into()
            .map_err(|_| MLSError::Cryptography("archive chat key is not Ed25519".into()))?;
        let signer = Arc::new(WebArchiveSigner { keys, public });
        let gateway = Arc::new(WebArchiveGateway {
            client: self.http_view(),
            db: WasmAccountDb::new(db.backend().clone()),
            session_token: session_token.clone(),
            device_id: device_id.clone(),
            signer: signer.clone(),
            verified_inventories: RefCell::new(BTreeMap::new()),
        });
        let repos: Arc<dyn PublicRepoBackend> = gateway.clone();
        let directory = CompositeDirectory::new(
            Box::new(PdsDirectory::new(repos)),
            Box::new(DsDirectoryStore::new(
                Arc::new(GatewayXrpcTransport::new(
                    gateway,
                    signer.clone(),
                    self.account_did.clone(),
                    device_id,
                )),
                None,
            )),
        );

        let mut first_error = None;
        let mut groups: BTreeMap<_, Vec<(String, QueuedLabyrinthArchivePayload)>> = BTreeMap::new();
        for row in rows {
            match serde_json::from_slice::<QueuedLabyrinthArchivePayload>(&row.payload_bytes) {
                Ok(payload) if payload.conversation_id == row.conversation_id => {
                    let space = payload.space_uri.clone().unwrap_or_else(|| {
                        SpaceRef::conversation(
                            &payload.sequencer_did,
                            &format!("{}-0", payload.conversation_id),
                        )
                        .to_string()
                    });
                    let key = (
                        payload.conversation_id.clone(),
                        space,
                        payload.group_id_hex.clone(),
                        payload.epoch,
                        payload.expected_member_dids.clone(),
                    );
                    groups.entry(key).or_default().push((row.item_id, payload));
                }
                _ => {
                    first_error.get_or_insert(MLSError::Internal(format!(
                        "undecodable Labyrinth archive queue row {}",
                        row.item_id
                    )));
                }
            }
        }
        let mut flushed = 0;
        for ((_, space, ..), items) in groups {
            match self
                .archive_group(&session_token, &directory, &signer, &space, &items)
                .await
            {
                Ok(count) => flushed += count,
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(flushed), Err)
    }

    async fn archive_group(
        &self,
        session_token: &str,
        directory: &CompositeDirectory,
        signer: &Arc<WebArchiveSigner>,
        space: &str,
        items: &[(String, QueuedLabyrinthArchivePayload)],
    ) -> Result<u32, MLSError> {
        let first = &items[0].1;
        let cid = first.conversation_id.as_str();
        if !first.expected_member_dids.contains(&first.sender_did) {
            return Err(MLSError::Cryptography(
                "archive missing authenticated send-time roster".into(),
            ));
        }
        let db = self.require_db_mls()?;
        let lab =
            |error: labyrinth::Error| MLSError::Cryptography(format!("Labyrinth archive: {error}"));

        let mut recipients: Vec<(String, EpochPublic)> = Vec::new();
        for did in &first.expected_member_dids {
            let deletion = chat_wire::account_deletion_key(cid, did);
            if db.backend().get_labyrinth_state(&deletion)?.is_some() {
                continue;
            }
            let Some(epoch) = directory.latest(did).await.map_err(lab)? else {
                tracing::warn!(
                    conversation_id = cid,
                    did = %did,
                    "labyrinth: member never enrolled; excluded from the archive MEK"
                );
                continue;
            };
            let devices = self
                .verify_peer_device_keys_via_pds(session_token, did)
                .await?;
            if !devices
                .iter()
                .any(|(_, key)| *key == epoch.attestation.transport_public_key)
            {
                return Err(MLSError::Cryptography(format!(
                    "[CB-18] epoch of {did} is not attested by one of its chat devices"
                )));
            }
            recipients.push((did.clone(), epoch));
        }
        if recipients.is_empty() {
            return Err(MLSError::Cryptography(
                "archive roster has no Labyrinth-enrolled member to read it".into(),
            ));
        }

        let heads: Vec<[u8; 32]> = recipients.iter().map(|(_, epoch)| epoch.head).collect();
        let mek_key = format!("web.transport_mek:{cid}");
        let stored = db
            .backend()
            .get_labyrinth_state(&mek_key)?
            .and_then(|raw| stored_transport_mek(&raw, space, signer.public))
            .filter(|mek| mek.reusable_for(&self.account_did, &heads));
        let mek = match stored {
            Some(mek) => mek,
            None => {
                let mut mek = Mek::generate(&heads).map_err(lab)?;
                let fault = SignerFault::default();
                let record = labyrinth::mek::distribute_transport(
                    cid,
                    &mut mek,
                    &LatchedTransportSigner::new(signer.clone(), fault.clone()),
                    &recipients,
                )
                .map_err(lab)?;
                if let Some(error) = fault.take() {
                    return Err(MLSError::Cryptography(format!(
                        "sign MEK distribution: {error}"
                    )));
                }
                let wire = MekDistribution::from_record(
                    &record,
                    None,
                    datetime_from_ms(now_ms().max(0) as u64),
                )
                .map_err(lab)?;
                let body = serde_json::to_vec(&json!({
                    "space": space,
                    "repo": self.account_did,
                    "validate": false,
                    "writes": [{
                        "$type": "com.atproto.space.applyWrites#create",
                        "collection": nsid::MEK,
                        "rkey": wire.rkey(),
                        "value": wire,
                    }],
                }))
                .map_err(|e| MLSError::Internal(format!("serialize MEK applyWrites: {e}")))?;
                let (status, response) = self
                    .pds_post_json(session_token, APPLY_WRITES, body)
                    .await?;
                if !(200..300).contains(&status) {
                    return Err(MLSError::Internal(format!(
                        "MEK applyWrites returned HTTP {status}: {}",
                        String::from_utf8_lossy(&response)
                    )));
                }
                let kept = [
                    mek.secret().as_slice(),
                    mek.roster_hash().as_slice(),
                    space.as_bytes(),
                ]
                .concat();
                db.write_tx(|tx| tx.put_labyrinth_state(&mek_key, &kept, now_ms()))?;
                mek
            }
        };

        let mut flushed = 0;
        for (item_id, payload) in items {
            let (batch_space, body) = chat_wire::build_space_apply_writes_for_queue_payload(
                payload,
                &mek,
                &signer.keys,
                &self.account_did,
            )?;
            if batch_space != space {
                return Err(MLSError::Internal(
                    "archive batch Space differs from its MEK's Space".into(),
                ));
            }
            let (status, response) = self
                .pds_post_json(session_token, APPLY_WRITES, body)
                .await?;
            let exists = status == 409
                || (status == 400
                    && serde_json::from_slice::<Value>(&response)
                        .is_ok_and(|v| v["error"] == "RecordAlreadyExists"));
            if !(200..300).contains(&status) && !exists {
                return Err(MLSError::Internal(format!(
                    "batch applyWrites returned HTTP {status}: {}",
                    String::from_utf8_lossy(&response)
                )));
            }
            db.write_tx(|tx| tx.dequeue_labyrinth_item(item_id))?;
            flushed += 1;
        }
        Ok(flushed)
    }

    /// This client's account, endpoints and HTTP client without its database.
    fn http_view(&self) -> WasmMlsClient {
        WasmMlsClient {
            account_did: self.account_did.clone(),
            account_did_hash: self.account_did_hash.clone(),
            device_id: self.device_id.clone(),
            home_ds_did: self.home_ds_did.clone(),
            home_ds_endpoint: self.home_ds_endpoint.clone(),
            pds_endpoint: self.pds_endpoint.clone(),
            auth_token: self.auth_token.clone(),
            http: self.http.clone(),
            db: None,
            pending_otc_initiator: RefCell::new(None),
            pending_otc_offer_digits: RefCell::new(None),
        }
    }
}
