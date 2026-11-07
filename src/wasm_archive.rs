//! Labyrinth Space archival of queued own sends and witness copies for `WasmMlsClient`.
//!
//! The browser device is not Labyrinth-enrolled, so it archives as a transport sender (SPEC
//! p.40-41): per conversation it distributes one MEK to the latest epoch of every enrolled
//! member, which the member's PDS and `mls-ds` must both vouch for ([CB-28], [CB-29]) and one of
//! its PDS-authorized chat devices must attest ([CB-18]), then seals each queued frame under that
//! MEK into the conversation Space.

use std::collections::BTreeMap;
use std::sync::Arc;

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer as _;
use serde_json::{json, Value};

use catbird_mls::client::chat_wire;
use catbird_mls::client::{LabyrinthBackupStatus, QueuedLabyrinthArchivePayload};
use catbird_mls::labyrinth::signer::LatchedTransportSigner;
use catbird_mls::labyrinth::transport::{
    map_xrpc_error, MAX_LABYRINTH_XRPC_RESPONSE_BYTES, MAX_PDS_RECORD_BYTES,
};
use catbird_mls::labyrinth::write_auth::{read_headers, ReadClaim};
use catbird_mls::labyrinth::{
    ChatKeySigner, DsDirectoryStore, GatewayXrpcTransport, LabyrinthGateway, LabyrinthRequest,
    SignerFault, XrpcTransportError,
};
use catbird_mls::orchestrator::canonical_transport::{GatewayResponse, PreparedRequest};
use catbird_mls::storage::driver_wasm::WasmSqlBackend;
use catbird_mls::MLSError;
use labyrinth::client::CompositeDirectory;
use labyrinth::mailbox::EpochPublic;
use labyrinth::mek::{Mek, MekProvenance};
use labyrinth::records::{datetime_from_ms, nsid, MekDistribution};
use labyrinth::store::pds::{PdsDirectory, PublicRepoBackend};
use labyrinth::store::space::SpaceRef;
use labyrinth::store::MailboxDirectory;

use crate::wasm_client::{now_ms, WasmMlsClient};

const APPLY_WRITES: &str = "/xrpc/com.atproto.space.applyWrites";
const MAILBOX_KEYS_RELAY: &str = "blue.catbird.labyrinth.getMailboxKeysRecord";

/// The enrolled chat device key: Labyrinth transport key and request signer ([CB-3]).
struct WebArchiveSigner {
    keys: SignatureKeyPair,
    public: [u8; 32],
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

/// Labyrinth directory adapter over this account's PDS and home `mls-ds`, like native
/// `NativeArchiveGateway`. The session bearer only reaches the account's own PDS; `mls-ds`
/// calls carry a service-auth token.
struct WebArchiveGateway {
    /// This client without its database: Labyrinth adapters are `'static`, so they cannot
    /// borrow the JS-owned client.
    client: WasmMlsClient,
    session_token: String,
    device_id: String,
    signer: Arc<WebArchiveSigner>,
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
        // Directory queries carry only canonical DID/UUID coordinates: sort the encoded pairs
        // exactly like chat read signing, as native does.
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
impl PublicRepoBackend for WebArchiveGateway {
    /// Not Labyrinth-enrolled, this device never publishes or retracts an epoch.
    async fn put_mailbox_keys(
        &self,
        _did: &str,
        _rkey: &str,
        _record: &[u8],
        _swap_cid: Option<&str>,
    ) -> labyrinth::Result<String> {
        Err(labyrinth::Error::Forbidden)
    }

    async fn get_mailbox_keys(
        &self,
        did: &str,
        rkey: &str,
    ) -> labyrinth::Result<Option<(Vec<u8>, String)>> {
        let enc = chat_wire::urlencode_form_component;
        let response = if did == self.client.account_did {
            let url = format!(
                "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection={}&rkey={}",
                self.client.pds_base(),
                enc(did),
                nsid::MAILBOX_KEYS,
                enc(rkey),
            );
            Self::send(self.client.http.get(url).bearer_auth(&self.session_token)).await
        } else {
            // A peer's record comes through the home DS relay, as native: a peer-controlled
            // PDS never receives this session's bearer token.
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
            self.ds(MAILBOX_KEYS_RELAY, "GET", &path, headers, None)
                .await
        };
        mailbox_keys_record(response.map_err(labyrinth::Error::Backend)?, did, rkey)
    }

    async fn delete_all_mailbox_keys(&self, _did: &str) -> labyrinth::Result<()> {
        Err(labyrinth::Error::Forbidden)
    }
}

/// A `getRecord` answer for `at://{did}/mailboxKeys/{rkey}` with native
/// `parse_mailbox_keys_record`'s URI, CID and size checks; `RecordNotFound` is `None`.
fn mailbox_keys_record(
    response: GatewayResponse,
    did: &str,
    rkey: &str,
) -> labyrinth::Result<Option<(Vec<u8>, String)>> {
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
    Ok(Some((bytes, cid)))
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

impl WasmMlsClient {
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
        // ponytail: oldest 100 rows per flush, so 100 failing rows of one conversation starve
        // the others; flush per conversation if that shows up.
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
            session_token: session_token.clone(),
            device_id: device_id.clone(),
            signer: signer.clone(),
        });
        // Strict two-source directory: a head only one of PDS and `mls-ds` vouches for fails.
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

    /// Archive queued frames sharing one conversation Space, MLS epoch and authenticated
    /// send-time roster. Any failure keeps the remaining rows queued.
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
            // A verified account deletion purged that mailbox. Only the recorded deletion
            // excludes a member, never a missing head.
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
                // Kept only once its distribution committed: a MEK no member can open is
                // never reused.
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
            // A retried create whose response was lost finds its deterministic rkey taken.
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
        }
    }
}
