//! Authenticated Nov-12 ATProto Spaces wire transport (`atproto_spaces`) for `WasmMlsClient`.
//!
//! Enforces:
//! - Strict `at:space/<did>/<nsid>/<skey>` URI parsing on the wire (`SpaceUri::parse`); stored
//!   pins read leniently (`SpaceUri::parse_hedged`)
//! - Ephemeral P-256 `did:key` delegation -> `authorizeSpaceSync` (personal mailbox) /
//!   `blue.catbird.chat.relaySpaceCredential` (conversation Space)
//! - Signed `catbird-space-denial+jwt` verification on `403` conversation Space credential refusals
//! - RFC 9421 `sign_credential_request_minimal` + deterministic HPKE `0xFFFF` `Accept-Signature`
//! - `Atproto-Space-Record` / `Atproto-Space-Commit` MAC verification, `LtHash` `#repoWrite` /
//!   `#repoRemoved` writer inventory verification, STAR v0.2 authenticated CARv1 repo verification,
//!   CIDv1 raw SHA-256 blob verification, and monotonic `D-5` `writer_rev_floors`.

use std::collections::{BTreeMap, BTreeSet};

use atproto_spaces::{
    did_resolver::DidDocument,
    http_signature::sign_credential_request_minimal,
    kem::{encapsulate_p256_deterministic, encode_p256_did_key, P256SecretKey},
    lthash::{compute_dagcbor_cid, LtHash},
    mac::{
        format_accept_signature, verify_commit_mac, verify_record_mac, MacProfile,
        ACCEPT_SIGNATURE_HEADER, COMMIT_MAC_HEADER, RECORD_MAC_HEADER, SIGNATURE_HEADER,
        SIGNATURE_INPUT_HEADER,
    },
    star::{read_star_repo_authenticated, validate_canonical_dagcbor_record, ParsedStarRepo},
    sync_engine::WriterSyncState,
    tokens::{verify_space_token, SpaceKeyResolver, SpaceTokenKind, SpaceVerifyingKey},
    SpaceUri,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use catbird_atproto::com_atproto::space::{
    get_record::GetRecordOutput, list_records::ListRecordsOutput, list_repo_ops::ListRepoOpsOutput,
};
use catbird_mls::client::chat_wire;
use catbird_mls::labyrinth::space::{thread_placement_key, ThreadPlacement};
use catbird_mls::labyrinth::{LabyrinthSpaceRequest, LabyrinthSpaceResponse};
use catbird_mls::storage::driver_wasm::WasmSqlBackend as _;
use catbird_mls::MLSError;
use http::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::wasm_archive::WebArchiveGateway;
use crate::wasm_client::{now_ms, now_secs};

const GET_RECORD: &str = "com.atproto.space.getRecord";
const GET_REPO: &str = "com.atproto.space.getRepo";
const LIST_RECORDS: &str = "com.atproto.space.listRecords";
const LIST_WRITERS: &str = "com.atproto.space.listWriters";
const LIST_OPS: &str = "com.atproto.space.listRepoOps";
const MAX_BODY: usize = catbird_mls::labyrinth::space::MAX_SPACE_XRPC_RESPONSE_BYTES;
const MAX_INVENTORY_PAGES: usize = 1_000;
const MAX_INVENTORY_WRITERS: usize = 100_000;
const MAX_INVENTORY_BYTES: usize = 64 * 1024 * 1024;
const SPACE_DENIAL_TYP: &str = "catbird-space-denial+jwt";
const SPACE_DENIAL_REASON: &str = "notActiveMember";
const SPACE_DENIAL_MAX_LIFETIME_SECS: u64 = 60;

pub(crate) const WASM_UNAUTHENTICATED_DENIAL: &str = "wasm_space_unauthenticated_denial";

type NegotiatedMacSecret = (String, Zeroizing<[u8; 32]>);

#[derive(Clone)]
pub(crate) struct VerifiedArchiveRecord {
    pub(crate) collection: String,
    pub(crate) rkey: String,
    pub(crate) cid: String,
    pub(crate) value: Value,
}

#[derive(Clone, Default)]
pub(crate) struct VerifiedArchiveInventory {
    pub(crate) writers: BTreeMap<String, Vec<VerifiedArchiveRecord>>,
}

struct Credential {
    jwt: Zeroizing<String>,
    key: P256SecretKey,
    expires_at: u64,
}

struct ReadContext {
    space: SpaceUri,
    writer: String,
    writer_pds: Option<String>,
    personal: bool,
    kem_key: Option<String>,
    credential: Credential,
}

struct AuthorityKeys<'a> {
    gateway: &'a WebArchiveGateway,
    document: DidDocument,
}

#[async_trait::async_trait(?Send)]
impl SpaceKeyResolver for AuthorityKeys<'_> {
    async fn resolve_atproto_key(
        &self,
        issuer: &str,
        refresh: bool,
    ) -> atproto_spaces::Result<SpaceVerifyingKey> {
        if issuer != self.document.id {
            return Err(atproto_spaces::SpacesError::InvalidSpaceCredential(
                "unexpected credential authority".into(),
            ));
        }
        let key = if refresh {
            self.gateway
                .space_document(issuer)
                .await
                .map_err(atproto_spaces::SpacesError::DidResolution)?
                .atproto_key
        } else {
            self.document.atproto_key.clone()
        };
        key.ok_or_else(|| {
            atproto_spaces::SpacesError::DidResolution("authority has no #atproto key".into())
        })
    }
}

#[derive(Deserialize)]
struct TokenOutput {
    token: String,
}
#[derive(Deserialize)]
struct CredentialOutput {
    credential: String,
}
#[derive(Deserialize)]
struct RecordEnvelope {
    uri: String,
    cid: String,
}
#[derive(Deserialize)]
struct ListedRecord {
    collection: String,
    rkey: String,
    cid: String,
    uri: Option<String>,
    repo: Option<String>,
    space: Option<String>,
}
#[derive(Deserialize)]
struct ListedPage {
    records: Vec<ListedRecord>,
    cursor: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Commit {
    space: String,
    repo: String,
    rev: String,
    ver: u64,
    #[serde(with = "catbird_atproto::jacquard_common::serde_bytes_helper")]
    data: catbird_atproto::jacquard_common::deps::bytes::Bytes,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "$type")]
enum InventoryWriterItem {
    #[serde(rename = "com.atproto.space.defs#repoWrite", rename_all = "camelCase")]
    RepoWrite {
        repo: String,
        repo_rev: String,
        space_rev: String,
        #[serde(with = "catbird_atproto::jacquard_common::serde_bytes_helper")]
        data: catbird_atproto::jacquard_common::deps::bytes::Bytes,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prev_space_rev: Option<String>,
    },
    #[serde(
        rename = "com.atproto.space.defs#repoRemoved",
        rename_all = "camelCase"
    )]
    RepoRemoved {
        repo: String,
        space_rev: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prev_space_rev: Option<String>,
    },
}

impl InventoryWriterItem {
    fn repo_did(&self) -> &str {
        match self {
            Self::RepoWrite { repo, .. } | Self::RepoRemoved { repo, .. } => repo,
        }
    }
}

#[derive(Clone, Debug)]
struct ActiveInventoryRepo {
    did: String,
    repo_rev: String,
    space_rev: String,
    data: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct InventoryPage {
    #[serde(default)]
    repos: Vec<InventoryWriterItem>,
    complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    commit: Commit,
}

#[derive(Deserialize)]
struct CommitEnvelope {
    commit: Option<Commit>,
    cursor: Option<String>,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct OpStub {
    collection: String,
    rkey: String,
    rev: String,
    cid: Option<String>,
    prev: Option<String>,
}
#[derive(Deserialize)]
struct OpsPage {
    ops: Vec<OpStub>,
}
#[derive(Deserialize)]
struct ServedValue {
    value: Option<Value>,
}
#[derive(Deserialize)]
struct ServedOps {
    ops: Vec<ServedValue>,
}

impl WebArchiveGateway {
    pub(crate) async fn execute_authenticated_space(
        &self,
        request: LabyrinthSpaceRequest,
    ) -> Result<LabyrinthSpaceResponse, String> {
        let params = parse_query(&request)?;
        if request.method == "POST"
            || (request.method == "GET"
                && request.nsid == "com.atproto.space.listSpaces"
                && request.body.is_none())
        {
            let mut headers = request.headers;
            if let Some(content_type) = request.content_type {
                headers.push(("content-type".into(), content_type));
            }
            return self
                .pds_space_http(&request.method, &request.path, headers, request.body)
                .await
                .and_then(bounded);
        }
        if request.method != "GET" || request.body.is_some() {
            return Err("wasm_space_invalid_read_method".into());
        }
        let writer_endpoint = match request.nsid.as_str() {
            GET_RECORD
            | LIST_RECORDS
            | LIST_OPS
            | "com.atproto.space.getRepo"
            | "com.atproto.space.getLatestCommit"
            | "com.atproto.space.getBlob" => true,
            "com.atproto.space.getSpace" | LIST_WRITERS => false,
            _ => return Err(format!("wasm_space_unsupported_read: {}", request.nsid)),
        };
        if request.headers.iter().any(|(name, _)| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "authorization"
                    | "atproto-space-audience"
                    | "atproto-space-want-mac"
                    | "accept-signature"
                    | "signature"
                    | "signature-input"
            )
        }) {
            return Err("wasm_space_conflicting_auth_headers".into());
        }
        let space = SpaceUri::parse(required(&params, "space")?)
            .map_err(|e| format!("wasm_space_invalid_space: {e}"))?;
        let writer = if writer_endpoint {
            required(&params, "repo")?.to_owned()
        } else {
            space.authority.clone()
        };
        if !atproto_spaces::is_valid_did(&writer) {
            return Err("wasm_space_invalid_writer".into());
        }
        let personal = space.space_type == "blue.catbird.labyrinth.mailbox";
        if personal {
            if space.authority != self.client.account_did
                || space.rkey != "self"
                || writer != self.client.account_did
            {
                return Err("wasm_space_personal_mailbox_binding_mismatch".into());
            }
        } else if space.space_type != "blue.catbird.labyrinth.conversation" {
            return Err("wasm_space_unsupported_space_type".into());
        }
        let authority = self.space_document(&space.authority).await?;
        let authority_kem = authority.atproto_kem_did_key.clone();
        let (kem_key, writer_pds) = if writer == authority.id {
            (
                authority_kem.clone(),
                authority.pds_endpoint().ok().map(str::to_owned),
            )
        } else {
            let writer_doc = self.space_document(&writer).await?;
            let pds = writer_doc.pds_endpoint().ok().map(str::to_owned);
            (writer_doc.atproto_kem_did_key, pds)
        };
        let credential = match self.space_credential(&space, personal, authority).await? {
            Ok(credential) => credential,
            Err(denied) => return Ok(denied),
        };
        let mut context = ReadContext {
            space,
            writer,
            writer_pds,
            personal,
            kem_key,
            credential,
        };
        if context.space.space_type == "blue.catbird.labyrinth.conversation"
            && matches!(request.nsid.as_str(), GET_RECORD | LIST_RECORDS)
        {
            if request.nsid == LIST_RECORDS && !self.inventory_verified(&context.space) {
                self.verify_space_inventory(&mut context, authority_kem)
                    .await?;
            }
            if self.inventory_verified(&context.space) {
                let mut cached = LabyrinthSpaceResponse {
                    status: 200,
                    content_type: Some("application/json".into()),
                    headers: vec![],
                    body: vec![],
                };
                if request.nsid == GET_RECORD {
                    self.release_verified_inventory_record(&context, &params, &mut cached)?;
                } else {
                    self.release_verified_inventory_records(&context, &params, &mut cached)?;
                }
                self.space_credential_live(&context)?;
                return bounded(cached);
            }
        }
        let mac_profile = match request.nsid.as_str() {
            GET_RECORD | LIST_RECORDS | "com.atproto.space.getBlob" => Some(MacProfile::Record),
            LIST_WRITERS | LIST_OPS | GET_REPO | "com.atproto.space.getLatestCommit" => {
                Some(MacProfile::Commit)
            }
            _ => None,
        };
        let (mut response, negotiated) = self
            .space_read(
                &context,
                &request.nsid,
                &request.path,
                request.headers,
                mac_profile,
            )
            .await?;
        if !(200..300).contains(&response.status) {
            return Ok(response);
        }
        match request.nsid.as_str() {
            GET_RECORD => {
                let (full, value) = verify_record(
                    &context,
                    &params,
                    &response,
                    negotiated
                        .as_ref()
                        .ok_or("wasm_space_missing_request_secret")?,
                )?;
                response.body = serde_json::to_vec(&serde_json::json!({
                    "uri": full.uri,
                    "cid": full.cid,
                    "value": value
                }))
                .map_err(|e| format!("wasm_space_encode_record: {e}"))?;
            }
            LIST_RECORDS => {
                self.verify_listed_records(&context, &params, &mut response)
                    .await?
            }
            LIST_WRITERS => self
                .verify_inventory(
                    &mut context,
                    &params,
                    &mut response,
                    negotiated
                        .as_ref()
                        .ok_or("wasm_space_missing_request_secret")?,
                )
                .await
                .map_err(|error| {
                    if error.starts_with("WriterRollback:") {
                        error
                    } else {
                        format!("ArchiveInventoryIncomplete: {error}")
                    }
                })?,
            GET_REPO => {
                let parsed = verify_star(
                    &context,
                    &response,
                    negotiated
                        .as_ref()
                        .ok_or("wasm_space_missing_request_secret")?,
                )?;
                self.observe_writer_rev(&context.space.raw, &context.writer, &parsed.rev)?;
            }
            LIST_OPS => {
                let head = self
                    .verify_repo_ops(
                        &context,
                        &mut response,
                        negotiated
                            .as_ref()
                            .ok_or("wasm_space_missing_request_secret")?,
                    )
                    .await?;
                self.observe_writer_rev(&context.space.raw, &context.writer, &head.rev)?;
            }
            "com.atproto.space.getLatestCommit" => {
                let envelope: CommitEnvelope = decode(&response.body, "commit envelope")?;
                let commit = envelope.commit.ok_or("wasm_space_missing_commit")?;
                verify_commit(
                    &context,
                    &response,
                    negotiated
                        .as_ref()
                        .ok_or("wasm_space_missing_request_secret")?,
                    &commit,
                )?;
                self.observe_writer_rev(&context.space.raw, &context.writer, &commit.rev)?;
                response.body = serde_json::to_vec(&serde_json::json!({"commit": commit}))
                    .map_err(|e| format!("wasm_space_encode_commit: {e}"))?;
            }
            "com.atproto.space.getBlob" => verify_blob(required(&params, "cid")?, &response.body)?,
            _ => {}
        }
        self.space_credential_live(&context)?;
        bounded(response)
    }

    async fn pds_space_http(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<LabyrinthSpaceResponse, String> {
        let base = self.client.pds_base();
        self.space_http_to_base(&base, method, path, headers, body)
            .await
    }

    async fn space_http_to_base(
        &self,
        base: &str,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<LabyrinthSpaceResponse, String> {
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
        let has_auth = headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization"));
        let has_ct = headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
        let mut req = self
            .client
            .http
            .request(method, format!("{}{path}", base.trim_end_matches('/')));
        if !has_auth {
            req = req.bearer_auth(&self.session_token);
        }
        for (name, value) in headers {
            req = req.header(name, value);
        }
        if let Some(body) = body {
            if !has_ct {
                req = req.header("content-type", "application/json");
            }
            req = req.body(body);
        }
        Self::send_space(req).await
    }

    async fn ds_space_post(
        &self,
        nsid: &str,
        body: Vec<u8>,
    ) -> Result<LabyrinthSpaceResponse, String> {
        let token = self
            .client
            .mint_ds_auth_token(&self.session_token, nsid)
            .await
            .map_err(|e| e.to_string())?;
        let req = self
            .client
            .http
            .post(format!("{}/xrpc/{nsid}", self.client.ds_base()))
            .bearer_auth(token)
            .header("content-type", "application/json")
            .body(body);
        Self::send_space(req).await
    }

    async fn send_space(
        request: reqwest::RequestBuilder,
    ) -> Result<LabyrinthSpaceResponse, String> {
        let response = request.send().await.map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let mut content_type = None;
        let mut headers = Vec::new();
        for (name, value) in response.headers() {
            if let Ok(val_str) = value.to_str() {
                if name.as_str().eq_ignore_ascii_case("content-type") {
                    content_type = Some(val_str.to_owned());
                }
                headers.push((name.as_str().to_owned(), val_str.to_owned()));
            }
        }
        let body = response.bytes().await.map_err(|e| e.to_string())?.to_vec();
        Ok(LabyrinthSpaceResponse {
            status,
            content_type,
            headers,
            body,
        })
    }

    fn writer_rev_floors_state_key(&self) -> String {
        format!(
            "wasm.writer_rev_floors:{}",
            thread_placement_key(&self.client.account_did)
        )
    }

    fn writer_rev_floors_placements_key(&self) -> String {
        format!(
            "wasm.placements:writer_rev_floors:{}",
            self.client.account_did
        )
    }

    pub(crate) fn load_persisted_writer_rev_floors(
        &self,
    ) -> Result<BTreeMap<(String, String), String>, String> {
        let key = self.writer_rev_floors_state_key();
        let placements_key = self.writer_rev_floors_placements_key();
        let backend = self.db.backend();
        let raw_a = backend
            .get_labyrinth_state(&key)
            .map_err(|e| e.to_string())?;
        let raw_b = backend
            .get_labyrinth_state(&placements_key)
            .map_err(|e| e.to_string())?;
        let mut out = BTreeMap::new();
        for raw in [raw_a, raw_b].into_iter().flatten() {
            let list: Vec<(String, String, String)> = serde_json::from_slice(&raw)
                .map_err(|e| format!("wasm_space_invalid_writer_rev_floors: {e}"))?;
            for (space, author, rev) in list {
                if labyrinth::store::validate_writer_rev_floor(&space, &author, &rev).is_ok() {
                    let k = (space, author);
                    match out.get(&k) {
                        Some(cur) if cur >= &rev => {}
                        Some(_) => {
                            out.insert(k, rev);
                        }
                        None if out.len() < labyrinth::store::MAX_WRITER_FLOOR_ENTRIES => {
                            out.insert(k, rev);
                        }
                        None => {}
                    }
                }
            }
        }
        Ok(out)
    }

    pub(crate) fn persist_writer_rev_floors(
        &self,
        floors: &BTreeMap<(String, String), String>,
    ) -> Result<(), String> {
        let key = self.writer_rev_floors_state_key();
        let placements_key = self.writer_rev_floors_placements_key();
        let ts = now_ms();
        self.db
            .write_tx(|tx| {
                let mut merged: BTreeMap<(String, String), String> = BTreeMap::new();
                for state_key in [&key, &placements_key] {
                    if let Some(raw) = tx.get_labyrinth_state(state_key)? {
                        for (s, a, r) in
                            serde_json::from_slice::<Vec<(String, String, String)>>(&raw)
                                .unwrap_or_default()
                        {
                            if labyrinth::store::validate_writer_rev_floor(&s, &a, &r).is_ok() {
                                let k = (s, a);
                                if merged.get(&k).is_none_or(|cur| cur < &r) {
                                    merged.insert(k, r);
                                }
                            }
                        }
                    }
                }
                for ((space, author), rev) in floors {
                    if labyrinth::store::validate_writer_rev_floor(space, author, rev).is_err() {
                        continue;
                    }
                    let k = (space.clone(), author.clone());
                    match merged.get(&k) {
                        Some(cur) if cur.as_str() >= rev.as_str() => {}
                        Some(_) => {
                            merged.insert(k, rev.clone());
                        }
                        None if merged.len() < labyrinth::store::MAX_WRITER_FLOOR_ENTRIES => {
                            merged.insert(k, rev.clone());
                        }
                        None => {}
                    }
                }
                let encoded_list: Vec<(&str, &str, &str)> = merged
                    .iter()
                    .map(|((s, a), r)| (s.as_str(), a.as_str(), r.as_str()))
                    .collect();
                let raw = serde_json::to_vec(&encoded_list)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                tx.put_labyrinth_state(&key, &raw, ts)?;
                tx.put_labyrinth_state(&placements_key, &raw, ts)
            })
            .map_err(|e| e.to_string())
    }

    fn observe_writer_rev(&self, space: &str, writer: &str, rev: &str) -> Result<(), String> {
        labyrinth::store::validate_writer_rev_floor(space, writer, rev)
            .map_err(|e| format!("wasm_space_invalid_writer_rev: {e}"))?;
        let current = self.load_persisted_writer_rev_floors()?;
        let key = (space.to_owned(), writer.to_owned());
        if let Some(floor) = current.get(&key) {
            if rev < floor.as_str() {
                return Err(format!(
                    "WriterRollback: space={space} writer={writer} offered={rev} floor={floor}"
                ));
            }
            if rev == floor.as_str() {
                return Ok(());
            }
        }
        let mut updated = current;
        if updated.len() < labyrinth::store::MAX_WRITER_FLOOR_ENTRIES || updated.contains_key(&key)
        {
            updated.insert(key, rev.to_owned());
            self.persist_writer_rev_floors(&updated)?;
        }
        Ok(())
    }

    pub(crate) async fn space_document(&self, did: &str) -> Result<DidDocument, String> {
        let bytes = self
            .client
            .resolve_did_document(&self.session_token, did)
            .await
            .map_err(|error| format!("wasm_space_did_document: {error}"))?
            .ok_or_else(|| "wasm_space_did_document: missing document".to_owned())?;
        DidDocument::parse_json(did, &bytes).map_err(|e| format!("wasm_space_did_document: {e}"))
    }

    fn space_key() -> Result<P256SecretKey, String> {
        for _ in 0..128 {
            let mut bytes = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(bytes.as_mut())
                .map_err(|e| format!("wasm_space_getrandom: {e}"))?;
            if let Ok(key) = P256SecretKey::from_slice(bytes.as_ref()) {
                return Ok(key);
            }
        }
        Err("wasm_space_invalid_entropy".into())
    }

    async fn space_credential(
        &self,
        space: &SpaceUri,
        personal: bool,
        authority: DidDocument,
    ) -> Result<Result<Credential, LabyrinthSpaceResponse>, String> {
        let key = Self::space_key()?;
        let kid = encode_p256_did_key(&key.public_key());
        let delegation_path = format!(
            "/xrpc/com.atproto.space.getDelegationToken?space={}",
            encode(&space.raw)
        );
        let delegation_response = bounded(
            self.pds_space_http("GET", &delegation_path, vec![], None)
                .await?,
        )?;
        require_success(&delegation_response, "getDelegationToken")?;
        let delegation: TokenOutput = decode(&delegation_response.body, "delegation token")?;
        if delegation.token.is_empty()
            || delegation.token.len() > atproto_spaces::tokens::MAX_COMPACT_JWT_BYTES
        {
            return Err("wasm_space_invalid_delegation_token".into());
        }
        let response = if personal {
            let body = serde_json::to_vec(&serde_json::json!({
                "space": space.raw,
                "credentialKey": kid,
                "delegationToken": delegation.token,
            }))
            .map_err(|e| format!("wasm_space_encode_credential_exchange: {e}"))?;
            bounded(
                self.pds_space_http(
                    "POST",
                    "/xrpc/com.atproto.space.authorizeSpaceSync",
                    vec![],
                    Some(body),
                )
                .await?,
            )?
        } else {
            let body = serde_json::to_vec(&serde_json::json!({
                "actorDeviceId": self.device_id,
                "authorityDid": space.authority,
                "space": space.raw,
                "delegationToken": delegation.token,
                "cnfKey": kid,
            }))
            .map_err(|e| format!("wasm_space_encode_credential_exchange: {e}"))?;
            bounded(
                self.ds_space_post("blue.catbird.chat.relaySpaceCredential", body)
                    .await?,
            )?
        };
        if response.status == 403 {
            if !personal {
                self.verify_space_denial(space, &kid, &authority, &response.body)
                    .await
                    .map_err(|error| format!("{WASM_UNAUTHENTICATED_DENIAL}: {error}"))?;
                return Ok(Err(response));
            }
            let denied = serde_json::from_slice::<Value>(&response.body)
                .ok()
                .and_then(|body| body["error"].as_str().map(str::to_owned))
                .is_some_and(|code| {
                    matches!(
                        code.as_str(),
                        "Forbidden" | "NotAuthorized" | "AccountNotAuthorized"
                    )
                });
            if denied {
                return Ok(Err(response));
            }
        }
        require_success(&response, "authorizeSpaceSync")?;
        let output: CredentialOutput = decode(&response.body, "Space credential")?;
        let jwt = Zeroizing::new(output.credential);
        let now = now_secs();
        let resolver = AuthorityKeys {
            gateway: self,
            document: authority,
        };
        let claims = verify_space_token(SpaceTokenKind::Credential, &jwt, &resolver, now)
            .await
            .map_err(|e| format!("wasm_space_invalid_credential: {e}"))?;
        let claims_space = SpaceUri::parse(&claims.sub).ok().map(|s| s.raw);
        if claims.iss != space.authority
            || claims_space.as_deref() != Some(space.raw.as_str())
            || claims.cnf_kid.as_deref() != Some(kid.as_str())
        {
            return Err("wasm_space_credential_binding_mismatch".into());
        }
        if claims.exp <= now {
            return Err("wasm_space_credential_expired".into());
        }
        Ok(Ok(Credential {
            jwt,
            key,
            expires_at: claims.exp,
        }))
    }

    fn space_credential_live(&self, context: &ReadContext) -> Result<(), String> {
        if context.credential.expires_at <= now_secs() {
            return Err("wasm_space_credential_expired".into());
        }
        Ok(())
    }

    async fn verify_space_denial(
        &self,
        space: &SpaceUri,
        kid: &str,
        authority: &DidDocument,
        body: &[u8],
    ) -> Result<(), String> {
        #[derive(Deserialize)]
        struct Refusal {
            denial: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Header {
            alg: String,
            typ: String,
            kid: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Cnf {
            kid: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Claims {
            iss: String,
            sub: String,
            aud: String,
            iat: u64,
            exp: u64,
            jti: String,
            cnf: Cnf,
            conversation_id: String,
            generation: u64,
            group_id: String,
            reason: String,
        }
        let denial = serde_json::from_slice::<Refusal>(body)
            .map_err(|_| "refusal carries no signed denial")?
            .denial;
        if denial.len() > atproto_spaces::tokens::MAX_COMPACT_JWT_BYTES {
            return Err("oversized denial".into());
        }
        let (input, signature) = denial.rsplit_once('.').ok_or("malformed denial")?;
        let (header, claims) = input.split_once('.').ok_or("malformed denial")?;
        let part = |p: &str| {
            URL_SAFE_NO_PAD
                .decode(p)
                .map_err(|_| "malformed denial".to_owned())
        };
        let header: Header =
            serde_json::from_slice(&part(header)?).map_err(|_| "malformed denial header")?;
        let claims: Claims =
            serde_json::from_slice(&part(claims)?).map_err(|_| "malformed denial claims")?;
        let signature = part(signature)?;
        if header.typ != SPACE_DENIAL_TYP || header.kid != atproto_spaces::tokens::ATPROTO_KEY_ID {
            return Err("not a Space denial".into());
        }
        let claims_space = SpaceUri::parse(&claims.sub).ok().map(|s| s.raw);
        if claims.iss != space.authority
            || claims_space.as_deref() != Some(space.raw.as_str())
            || claims.aud != self.client.account_did
            || claims.cnf.kid != kid
            || claims.reason != SPACE_DENIAL_REASON
            || format!("{}-{}", claims.conversation_id, claims.generation) != space.rkey
            || self.pinned_space_group(space)?.as_deref() != Some(claims.group_id.as_str())
            || claims.jti.is_empty()
            || claims.jti.len() > atproto_spaces::tokens::MAX_JTI_BYTES
        {
            return Err("denial binding mismatch".into());
        }
        let now = now_secs();
        if claims.exp <= now
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > SPACE_DENIAL_MAX_LIFETIME_SECS
            || claims.iat > now + atproto_spaces::tokens::MAX_IAT_LEAD_SECS
        {
            return Err("stale denial".into());
        }
        let verifies = |document: &DidDocument| {
            document
                .atproto_key
                .as_ref()
                .is_some_and(|key| key.verify_raw(&header.alg, input.as_bytes(), &signature))
        };
        if verifies(authority) || verifies(&self.space_document(&space.authority).await?) {
            return Ok(());
        }
        Err("denial signature".into())
    }

    fn pinned_space_group(&self, space: &SpaceUri) -> Result<Option<String>, String> {
        let key = format!(
            "wasm.placements:{}",
            thread_placement_key(&self.client.account_did)
        );
        let Some(raw) = self
            .db
            .backend()
            .get_labyrinth_state(&key)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let pins: BTreeMap<String, ThreadPlacement> =
            serde_json::from_slice(&raw).map_err(|e| format!("wasm_space_invalid_pins: {e}"))?;
        Ok(pins
            .into_values()
            .find(|pin| {
                pin.space
                    .as_deref()
                    .and_then(|s| SpaceUri::parse_hedged(s).ok())
                    .is_some_and(|parsed| parsed.raw == space.raw)
            })
            .and_then(|pin| pin.group_id))
    }

    async fn space_read(
        &self,
        context: &ReadContext,
        nsid: &str,
        path: &str,
        mut headers: Vec<(String, String)>,
        mac_profile: Option<MacProfile>,
    ) -> Result<(LabyrinthSpaceResponse, Option<NegotiatedMacSecret>), String> {
        self.space_credential_live(context)?;
        let signed = sign_credential_request_minimal(
            &context.credential.key,
            &context.credential.jwt,
            &context.writer,
        )
        .map_err(|e| format!("wasm_space_request_pop: {e}"))?;
        let negotiated = if let Some(profile) = mac_profile {
            let kem = context
                .kem_key
                .as_deref()
                .ok_or("wasm_space_writer_missing_atproto_kem")?;
            let ephemeral = Self::space_key()?;
            let encap = encapsulate_p256_deterministic(kem, &ephemeral)
                .map_err(|e| format!("wasm_space_request_kem: {e}"))?;
            let accept = format_accept_signature(profile, &encap.key_share_did_key)
                .map_err(|e| format!("wasm_space_accept_signature: {e}"))?;
            Some((
                accept,
                encap.key_share_did_key,
                Zeroizing::new(encap.shared_secret),
            ))
        } else {
            None
        };
        let response = if context.personal {
            headers.extend([
                ("authorization".into(), signed.authorization),
                (
                    "atproto-space-audience".into(),
                    signed.atproto_space_audience,
                ),
                ("signature-input".into(), signed.signature_input),
                ("signature".into(), signed.signature),
            ]);
            if let Some((accept, _, _)) = &negotiated {
                headers.push((ACCEPT_SIGNATURE_HEADER.into(), accept.clone()));
            }
            // Personal Space reads carry `Atproto-Space-Credential` + RFC 9421 HTTP signatures.
            // The BFF gateway strips those headers, so send directly to the account's resolved PDS.
            let fallback_base = self.client.pds_base();
            let target_base = context
                .writer_pds
                .as_deref()
                .unwrap_or(fallback_base.as_str());
            self.space_http_to_base(target_base, "GET", path, headers, None)
                .await?
        } else {
            let query = path.split_once('?').map(|(_, query)| query);
            let body = serde_json::to_vec(&serde_json::json!({
                "actorDeviceId": self.device_id,
                "targetDid": context.writer,
                "nsid": nsid,
                "query": query,
                "credential": context.credential.jwt.as_str(),
                "spaceAudience": signed.atproto_space_audience,
                "signatureInput": signed.signature_input,
                "signature": signed.signature,
                "acceptSignature": negotiated.as_ref().map(|(accept, _, _)| accept.as_str()),
            }))
            .map_err(|e| format!("wasm_space_encode_read_relay: {e}"))?;
            self.ds_space_post("blue.catbird.chat.relaySpaceRead", body)
                .await?
        };
        if !context.personal
            && !(200..300).contains(&response.status)
            && reads_as_space_denial(&response)
        {
            return Err(format!(
                "{WASM_UNAUTHENTICATED_DENIAL}: unsigned HTTP {}",
                response.status
            ));
        }
        self.space_credential_live(context)?;
        Ok((
            bounded(response)?,
            negotiated.map(|(_, ks, secret)| (ks, secret)),
        ))
    }

    fn inventory_verified(&self, space: &SpaceUri) -> bool {
        self.verified_inventories.borrow().contains_key(&space.raw)
    }

    async fn verify_space_inventory(
        &self,
        context: &mut ReadContext,
        authority_kem: Option<String>,
    ) -> Result<(), String> {
        let writer = std::mem::replace(&mut context.writer, context.space.authority.clone());
        let kem_key = std::mem::replace(&mut context.kem_key, authority_kem);
        let params = BTreeMap::from([("space".to_owned(), context.space.raw.clone())]);
        let (mut response, negotiated) = self
            .space_read(
                context,
                LIST_WRITERS,
                &query_path(LIST_WRITERS, &params),
                vec![],
                Some(MacProfile::Commit),
            )
            .await?;
        require_success(&response, "listWriters inventory")?;
        self.verify_inventory(
            context,
            &params,
            &mut response,
            negotiated
                .as_ref()
                .ok_or("wasm_space_missing_request_secret")?,
        )
        .await
        .map_err(|error| {
            if error.starts_with("WriterRollback:") {
                error
            } else {
                format!("ArchiveInventoryIncomplete: {error}")
            }
        })?;
        context.writer = writer;
        context.kem_key = kem_key;
        Ok(())
    }

    async fn verify_inventory(
        &self,
        context: &mut ReadContext,
        params: &BTreeMap<String, String>,
        response: &mut LabyrinthSpaceResponse,
        negotiated: &NegotiatedMacSecret,
    ) -> Result<(), String> {
        if params
            .keys()
            .any(|key| !matches!(key.as_str(), "space" | "cursor" | "limit"))
            || params.contains_key("cursor")
        {
            return Err("wasm_space_inventory_must_start_at_snapshot_head".into());
        }
        let limit = params
            .get("limit")
            .map(|value| value.parse::<usize>())
            .transpose()
            .map_err(|_| "wasm_space_invalid_inventory_limit")?
            .unwrap_or(100);
        if limit == 0 || limit > 1_000 {
            return Err("wasm_space_invalid_inventory_limit".into());
        }
        if context.writer != context.space.authority {
            return Err("wasm_space_inventory_authority_mismatch".into());
        }

        let authority = context.space.authority.clone();
        let authority_kem = context.kem_key.clone();
        self.verified_inventories
            .borrow_mut()
            .remove(&context.space.raw);
        let mut current = LabyrinthSpaceResponse {
            status: response.status,
            content_type: response.content_type.clone(),
            headers: std::mem::take(&mut response.headers),
            body: std::mem::take(&mut response.body),
        };
        let mut current_negotiated = negotiated.clone();
        let mut expected_commit: Option<Commit> = None;
        let mut wire_items = Vec::new();
        let mut active_repos = Vec::new();
        let mut cursors = BTreeSet::new();
        let mut previous_did: Option<String> = None;
        let mut total_bytes = 0usize;
        let mut terminal = false;

        for _ in 0..MAX_INVENTORY_PAGES {
            total_bytes = total_bytes
                .checked_add(current.body.len())
                .ok_or("wasm_space_inventory_bytes_overflow")?;
            if total_bytes > MAX_INVENTORY_BYTES {
                return Err("wasm_space_inventory_bytes_exceeded".into());
            }
            let page: InventoryPage = decode(&current.body, "writer inventory")?;
            if page.repos.len() > limit {
                return Err("wasm_space_inventory_limit_exceeded".into());
            }
            if page.commit.rev.is_empty() {
                return Err("wasm_space_inventory_commit_revision_missing".into());
            }
            verify_commit(context, &current, &current_negotiated, &page.commit)?;
            let _: [u8; 32] = page
                .commit
                .data
                .as_ref()
                .try_into()
                .map_err(|_| "wasm_space_invalid_inventory_commitment")?;
            if expected_commit.is_none() {
                expected_commit = Some(page.commit.clone());
            } else if expected_commit.as_ref() != Some(&page.commit) {
                return Err("wasm_space_inventory_commit_changed".into());
            }

            if page.complete != page.cursor.is_none() {
                return Err("wasm_space_inventory_terminal_cursor_mismatch".into());
            }
            if !page.complete && page.repos.is_empty() {
                return Err("wasm_space_inventory_empty_nonterminal_page".into());
            }
            for item in page.repos {
                let item_did = item.repo_did().to_owned();
                if !atproto_spaces::is_valid_did(&item_did) {
                    return Err("wasm_space_invalid_inventory_row".into());
                }
                if previous_did
                    .as_deref()
                    .is_some_and(|previous| previous >= item_did.as_str())
                {
                    return Err("wasm_space_inventory_not_strictly_ordered".into());
                }
                match &item {
                    InventoryWriterItem::RepoWrite {
                        repo,
                        repo_rev,
                        space_rev,
                        data,
                        ..
                    } => {
                        if repo_rev.is_empty() || space_rev.is_empty() {
                            return Err("wasm_space_invalid_inventory_row".into());
                        }
                        let data_32: [u8; 32] = data
                            .as_ref()
                            .try_into()
                            .map_err(|_| "wasm_space_invalid_inventory_repo_commitment")?;
                        active_repos.push(ActiveInventoryRepo {
                            did: repo.clone(),
                            repo_rev: repo_rev.clone(),
                            space_rev: space_rev.clone(),
                            data: data_32,
                        });
                    }
                    InventoryWriterItem::RepoRemoved { space_rev, .. } => {
                        if space_rev.is_empty() {
                            return Err("wasm_space_invalid_inventory_row".into());
                        }
                    }
                }
                previous_did = Some(item_did);
                wire_items.push(item);
                if wire_items.len() > MAX_INVENTORY_WRITERS {
                    return Err("wasm_space_inventory_writer_limit_exceeded".into());
                }
            }

            let Some(cursor) = page.cursor else {
                terminal = true;
                break;
            };
            check_cursor(Some(&cursor))?;
            if !cursors.insert(cursor.clone()) {
                return Err("wasm_space_inventory_cursor_cycle".into());
            }
            let mut next_params = params.clone();
            next_params.insert("cursor".into(), cursor);
            let (next, next_negotiated) = self
                .space_read(
                    context,
                    LIST_WRITERS,
                    &query_path(LIST_WRITERS, &next_params),
                    vec![],
                    Some(MacProfile::Commit),
                )
                .await?;
            require_success(&next, "listWriters inventory")?;
            current = next;
            current_negotiated = next_negotiated.ok_or("wasm_space_missing_request_secret")?;
        }
        if !terminal {
            return Err("wasm_space_inventory_page_limit_exceeded".into());
        }

        let commit = expected_commit.ok_or("wasm_space_inventory_commit_missing")?;
        let expected_data: [u8; 32] = commit
            .data
            .as_ref()
            .try_into()
            .map_err(|_| "wasm_space_invalid_inventory_commitment")?;
        let mut inventory_hash = LtHash::empty();
        for row in &active_repos {
            inventory_hash
                .add_inventory_entry(&row.did, &row.repo_rev, &row.space_rev, &row.data)
                .map_err(|error| format!("wasm_space_inventory_hash: {error}"))?;
        }
        if inventory_hash.commitment() != expected_data {
            return Err("wasm_space_inventory_commitment_mismatch".into());
        }

        let mut verified = VerifiedArchiveInventory::default();
        let mut verified_bytes = 0usize;
        for row in &active_repos {
            self.observe_writer_rev(&context.space.raw, &row.did, &row.repo_rev)?;
            context.writer = row.did.clone();
            context.kem_key = if row.did == authority {
                authority_kem.clone()
            } else {
                self.space_document(&row.did).await?.atproto_kem_did_key
            };
            let (records, writer_bytes) = self.verify_inventory_writer(context, row).await?;
            verified_bytes = verified_bytes
                .checked_add(writer_bytes)
                .ok_or("wasm_space_inventory_cache_bytes_overflow")?;
            if verified_bytes > MAX_INVENTORY_BYTES {
                return Err("wasm_space_inventory_cache_bytes_exceeded".into());
            }
            if verified.writers.insert(row.did.clone(), records).is_some() {
                return Err("wasm_space_inventory_duplicate_writer".into());
            }
        }
        self.verified_inventories
            .borrow_mut()
            .insert(context.space.raw.clone(), verified);
        context.writer = authority;
        context.kem_key = authority_kem;

        response.status = current.status;
        response.content_type = current.content_type;
        response.headers = std::mem::take(&mut current.headers);
        response.body = serde_json::to_vec(&InventoryPage {
            repos: wire_items,
            complete: true,
            cursor: None,
            commit,
        })
        .map_err(|error| format!("wasm_space_encode_inventory: {error}"))?;
        Ok(())
    }

    async fn verify_inventory_writer(
        &self,
        context: &mut ReadContext,
        row: &ActiveInventoryRepo,
    ) -> Result<(Vec<VerifiedArchiveRecord>, usize), String> {
        let expected_data = row.data;
        let params = BTreeMap::from([
            ("space".into(), context.space.raw.clone()),
            ("repo".into(), row.did.clone()),
        ]);

        let (star_response, star_negotiated) = self
            .space_read(
                context,
                GET_REPO,
                &query_path(GET_REPO, &params),
                vec![],
                Some(MacProfile::Commit),
            )
            .await?;
        require_success(&star_response, "inventory getRepo")?;
        let repo = verify_star(
            context,
            &star_response,
            star_negotiated
                .as_ref()
                .ok_or("wasm_space_missing_request_secret")?,
        )?;
        if repo.rev != row.repo_rev || repo.data != expected_data {
            return Err("wasm_space_inventory_star_head_mismatch".into());
        }

        let mut ops_params = params;
        ops_params.insert("excludeValues".into(), "true".into());
        ops_params.insert("limit".into(), "1000".into());
        let (mut ops_response, ops_negotiated) = self
            .space_read(
                context,
                LIST_OPS,
                &query_path(LIST_OPS, &ops_params),
                vec![],
                Some(MacProfile::Commit),
            )
            .await?;
        require_success(&ops_response, "inventory listRepoOps")?;
        let head = self
            .verify_repo_ops(
                context,
                &mut ops_response,
                ops_negotiated
                    .as_ref()
                    .ok_or("wasm_space_missing_request_secret")?,
            )
            .await?;
        if head.rev != row.repo_rev || head.data.as_ref() != expected_data.as_slice() {
            return Err("wasm_space_inventory_oplog_head_mismatch".into());
        }
        let mut records = Vec::with_capacity(repo.records.len());
        let mut coordinates = BTreeSet::new();
        let mut cached_bytes = 0usize;
        for record in repo.records {
            if !coordinates.insert((record.collection.clone(), record.rkey.clone())) {
                return Err("wasm_space_inventory_duplicate_record".into());
            }
            let get_params = BTreeMap::from([
                ("space".into(), context.space.raw.clone()),
                ("repo".into(), row.did.clone()),
                ("collection".into(), record.collection.clone()),
                ("rkey".into(), record.rkey.clone()),
            ]);
            let (record_response, record_negotiated) = self
                .space_read(
                    context,
                    GET_RECORD,
                    &query_path(GET_RECORD, &get_params),
                    vec![],
                    Some(MacProfile::Record),
                )
                .await?;
            require_success(&record_response, "inventory getRecord")?;
            let (full, value) = verify_record(
                context,
                &get_params,
                &record_response,
                record_negotiated
                    .as_ref()
                    .ok_or("wasm_space_missing_request_secret")?,
            )?;
            let cid = record.cid.to_string();
            if full.cid.as_str() != cid {
                return Err("wasm_space_inventory_record_cid_mismatch".into());
            }
            cached_bytes = cached_bytes
                .checked_add(record_response.body.len())
                .and_then(|size| size.checked_add(record.collection.len()))
                .and_then(|size| size.checked_add(record.rkey.len()))
                .and_then(|size| size.checked_add(cid.len()))
                .ok_or("wasm_space_inventory_cache_bytes_overflow")?;
            records.push(VerifiedArchiveRecord {
                collection: record.collection,
                rkey: record.rkey,
                cid,
                value,
            });
        }
        records.sort_by(|left, right| {
            (&left.collection, &left.rkey).cmp(&(&right.collection, &right.rkey))
        });
        Ok((records, cached_bytes))
    }

    fn release_verified_inventory_record(
        &self,
        context: &ReadContext,
        params: &BTreeMap<String, String>,
        response: &mut LabyrinthSpaceResponse,
    ) -> Result<(), String> {
        if params
            .keys()
            .any(|key| !matches!(key.as_str(), "space" | "repo" | "collection" | "rkey"))
        {
            return Err("wasm_space_inventory_record_parameter_mismatch".into());
        }
        let inventories = self.verified_inventories.borrow();
        let collection = required(params, "collection")?;
        let rkey = required(params, "rkey")?;
        let inventory = inventories
            .get(&context.space.raw)
            .ok_or("wasm_space_inventory_snapshot_missing")?;
        let record = inventory.writers.get(&context.writer).and_then(|records| {
            records
                .iter()
                .find(|record| record.collection == collection && record.rkey == rkey)
        });
        let Some(record) = record else {
            response.status = 404;
            response.body = serde_json::to_vec(&serde_json::json!({
                "error": "RecordNotFound",
            }))
            .map_err(|error| format!("wasm_space_encode_record_absence: {error}"))?;
            return Ok(());
        };
        let uri = context
            .space
            .record_uri(&context.writer, collection, rkey)
            .map_err(|error| format!("wasm_space_record_coordinates: {error}"))?;
        response.body = serde_json::to_vec(&serde_json::json!({
            "uri": uri,
            "cid": record.cid,
            "value": record.value,
        }))
        .map_err(|error| format!("wasm_space_encode_inventory_record: {error}"))?;
        Ok(())
    }

    fn release_verified_inventory_records(
        &self,
        context: &ReadContext,
        params: &BTreeMap<String, String>,
        response: &mut LabyrinthSpaceResponse,
    ) -> Result<(), String> {
        if params.keys().any(|key| {
            !matches!(
                key.as_str(),
                "space" | "repo" | "collection" | "cursor" | "limit" | "reverse" | "excludeValues"
            )
        }) {
            return Err("wasm_space_inventory_list_parameter_mismatch".into());
        }
        let inventories = self.verified_inventories.borrow();
        let inventory = inventories
            .get(&context.space.raw)
            .ok_or("wasm_space_inventory_snapshot_missing")?;
        let records = inventory
            .writers
            .get(&context.writer)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let limit = params
            .get("limit")
            .map(|value| value.parse::<usize>())
            .transpose()
            .map_err(|_| "wasm_space_invalid_list_limit")?
            .unwrap_or(50);
        if limit == 0 || limit > 1_000 {
            return Err("wasm_space_invalid_list_limit".into());
        }
        let reverse = match params.get("reverse").map(String::as_str) {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => return Err("wasm_space_invalid_list_reverse".into()),
        };
        let exclude = match params.get("excludeValues").map(String::as_str) {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => return Err("wasm_space_invalid_exclude_values".into()),
        };
        let cursor = params.get("cursor");
        check_cursor(cursor.map(String::as_str))?;
        let collection = params.get("collection");
        let mut selected: Vec<_> = records
            .iter()
            .filter(|record| {
                collection.is_none_or(|wanted| wanted == &record.collection)
                    && cursor.is_none_or(|cursor| {
                        let path = format!("{}/{}", record.collection, record.rkey);
                        if reverse {
                            path.as_str() < cursor.as_str()
                        } else {
                            path.as_str() > cursor.as_str()
                        }
                    })
            })
            .collect();
        if reverse {
            selected.reverse();
        }
        let more = selected.len() > limit;
        selected.truncate(limit);
        let next = more.then(|| {
            let record = selected
                .last()
                .expect("more records implies a nonempty selected page");
            format!("{}/{}", record.collection, record.rkey)
        });
        let records: Vec<_> = selected
            .into_iter()
            .map(|record| {
                let mut value = serde_json::json!({
                    "collection": record.collection,
                    "rkey": record.rkey,
                    "cid": record.cid,
                });
                if !exclude {
                    value["value"] = record.value.clone();
                }
                value
            })
            .collect();
        let mut body = serde_json::json!({"records": records});
        if let Some(next) = next {
            body["cursor"] = next.into();
        }
        response.headers.clear();
        response.body = serde_json::to_vec(&body)
            .map_err(|error| format!("wasm_space_encode_inventory_records: {error}"))?;
        Ok(())
    }

    async fn verify_listed_records(
        &self,
        context: &ReadContext,
        params: &BTreeMap<String, String>,
        response: &mut LabyrinthSpaceResponse,
    ) -> Result<(), String> {
        if context.space.space_type == "blue.catbird.labyrinth.conversation" {
            return self.release_verified_inventory_records(context, params, response);
        }
        let page: ListedPage = decode(&response.body, "listRecords envelope")?;
        let limit = params
            .get("limit")
            .map(|s| s.parse::<usize>())
            .transpose()
            .map_err(|_| "wasm_space_invalid_list_limit")?
            .unwrap_or(50);
        if limit == 0 || limit > 1000 || page.records.len() > limit {
            return Err("wasm_space_list_limit_exceeded".into());
        }
        check_cursor(page.cursor.as_deref())?;
        let exclude = match params.get("excludeValues").map(String::as_str) {
            None | Some("false") => false,
            Some("true") => true,
            _ => return Err("wasm_space_invalid_exclude_values".into()),
        };
        let mut seen = BTreeSet::new();
        let mut authenticated = Vec::with_capacity(page.records.len());
        for stub in &page.records {
            let expected_uri = context
                .space
                .record_uri(&context.writer, &stub.collection, &stub.rkey)
                .map_err(|e| format!("wasm_space_list_coordinates: {e}"))?;
            let stub_uri_norm = stub.uri.as_deref().map(|u| {
                if let Some((prefix, rest)) = u.split_once(&format!("/{}/", context.writer)) {
                    if let Ok(parsed) = SpaceUri::parse(prefix) {
                        return format!("{}/{}/{rest}", parsed.raw, context.writer);
                    }
                }
                u.to_owned()
            });
            let stub_space_norm = stub
                .space
                .as_deref()
                .and_then(|s| SpaceUri::parse(s).ok().map(|p| p.raw));
            if params
                .get("collection")
                .is_some_and(|c| c != &stub.collection)
                || stub_uri_norm
                    .as_deref()
                    .is_some_and(|uri| uri != expected_uri)
                || stub
                    .repo
                    .as_deref()
                    .is_some_and(|repo| repo != context.writer)
                || stub
                    .space
                    .as_ref()
                    .is_some_and(|_| stub_space_norm.as_deref() != Some(context.space.raw.as_str()))
                || !seen.insert((&stub.collection, &stub.rkey))
            {
                return Err("wasm_space_list_coordinate_mismatch".into());
            }
            let get_params = BTreeMap::from([
                ("space".into(), context.space.raw.clone()),
                ("repo".into(), context.writer.clone()),
                ("collection".into(), stub.collection.clone()),
                ("rkey".into(), stub.rkey.clone()),
            ]);
            let path = query_path(GET_RECORD, &get_params);
            let (record_response, negotiated) = self
                .space_read(context, GET_RECORD, &path, vec![], Some(MacProfile::Record))
                .await?;
            require_success(&record_response, "listed getRecord")?;
            let (full, value) = verify_record(
                context,
                &get_params,
                &record_response,
                negotiated
                    .as_ref()
                    .ok_or("wasm_space_missing_request_secret")?,
            )?;
            if full.cid.as_str() != stub.cid {
                return Err("wasm_space_list_cid_mismatch".into());
            }
            authenticated.push((full, value));
        }
        let full_page: ListRecordsOutput = decode(&response.body, "listRecords values")?;
        let mut records = Vec::with_capacity(authenticated.len());
        for ((listed, (verified, value)), stub) in full_page
            .records
            .into_iter()
            .zip(authenticated)
            .zip(page.records)
        {
            if listed
                .value
                .as_ref()
                .is_some_and(|inline| inline != &verified.value)
                || (!exclude && listed.value.is_none())
            {
                return Err("wasm_space_list_value_mismatch".into());
            }
            let mut record = serde_json::json!({
                "collection": stub.collection,
                "rkey": stub.rkey,
                "cid": verified.cid
            });
            if !exclude {
                record["value"] = value;
            }
            records.push(record);
        }
        let mut body = serde_json::json!({"records": records});
        if let Some(cursor) = page.cursor {
            body["cursor"] = cursor.into();
        }
        response.body =
            serde_json::to_vec(&body).map_err(|e| format!("wasm_space_encode_list: {e}"))?;
        Ok(())
    }

    async fn verify_repo_ops(
        &self,
        context: &ReadContext,
        response: &mut LabyrinthSpaceResponse,
        negotiated: &NegotiatedMacSecret,
    ) -> Result<Commit, String> {
        let requested_head: CommitEnvelope = decode(&response.body, "listRepoOps commit envelope")?;
        check_cursor(requested_head.cursor.as_deref())?;
        if requested_head.commit.is_some() && requested_head.cursor.is_some() {
            return Err("wasm_space_commit_before_oplog_head".into());
        }
        if let Some(commit) = &requested_head.commit {
            verify_commit(context, response, negotiated, commit)?;
        }
        if requested_head.commit.is_none() && requested_head.cursor.is_none() {
            return Err("wasm_space_missing_head_commit".into());
        }
        let requested: OpsPage = decode(&response.body, "listRepoOps coordinates")?;
        if requested.ops.len() > 1000 {
            return Err("wasm_space_ops_limit_exceeded".into());
        }
        let wanted: BTreeMap<_, _> = requested
            .ops
            .iter()
            .map(|op| ((op.rev.clone(), op.collection.clone(), op.rkey.clone()), op))
            .collect();
        if wanted.len() != requested.ops.len() {
            return Err("wasm_space_duplicate_ops".into());
        }
        let mut found = BTreeSet::new();
        let mut state = WriterSyncState::empty();
        let mut cursor: Option<String> = None;
        let mut cursors = BTreeSet::new();
        let mut total_bytes = 0usize;
        for _ in 0..50 {
            let mut params = BTreeMap::from([
                ("space".into(), context.space.raw.clone()),
                ("repo".into(), context.writer.clone()),
                ("excludeValues".into(), "true".into()),
                ("limit".into(), "1000".into()),
            ]);
            if let Some(cursor) = &cursor {
                params.insert("cursor".into(), cursor.clone());
            }
            let (page_response, page_negotiated) = self
                .space_read(
                    context,
                    LIST_OPS,
                    &query_path(LIST_OPS, &params),
                    vec![],
                    Some(MacProfile::Commit),
                )
                .await?;
            require_success(&page_response, "listRepoOps replay")?;
            total_bytes += page_response.body.len();
            if total_bytes > 64 * 1024 * 1024 {
                return Err("wasm_space_ops_replay_bytes_exceeded".into());
            }
            let envelope: CommitEnvelope =
                decode(&page_response.body, "listRepoOps replay envelope")?;
            if let Some(commit) = &envelope.commit {
                if envelope.cursor.is_some() {
                    return Err("wasm_space_commit_before_oplog_head".into());
                }
                verify_commit(
                    context,
                    &page_response,
                    page_negotiated
                        .as_ref()
                        .ok_or("wasm_space_missing_request_secret")?,
                    commit,
                )?;
            }
            let page: OpsPage = decode(&page_response.body, "listRepoOps replay coordinates")?;
            if page.ops.len() > 1000 {
                return Err("wasm_space_ops_limit_exceeded".into());
            }
            for op in page.ops {
                context
                    .space
                    .record_uri(&context.writer, &op.collection, &op.rkey)
                    .map_err(|e| format!("wasm_space_op_coordinates: {e}"))?;
                if op.rev.is_empty() || state.latest_rev.as_ref().is_some_and(|rev| rev > &op.rev) {
                    return Err("wasm_space_nonmonotonic_ops".into());
                }
                state.latest_rev = Some(op.rev.clone());
                let identity = (op.rev.clone(), op.collection.clone(), op.rkey.clone());
                if let Some(expected) = wanted.get(&identity) {
                    if **expected != op || !found.insert(identity) {
                        return Err("wasm_space_requested_op_mismatch".into());
                    }
                }
                let path = format!("{}/{}", op.collection, op.rkey);
                let old = state.cid_by_path.remove(&path);
                let prev = op
                    .prev
                    .as_deref()
                    .map(str::parse)
                    .transpose()
                    .map_err(|_| "wasm_space_invalid_prev_cid")?;
                if old != prev {
                    return Err("wasm_space_op_previous_cid_mismatch".into());
                }
                if let Some(cid) = old {
                    state.lt_hash.remove_record(&op.collection, &op.rkey, &cid);
                }
                if let Some(cid) = op.cid {
                    let cid = cid.parse().map_err(|_| "wasm_space_invalid_op_cid")?;
                    state.lt_hash.add_record(&op.collection, &op.rkey, &cid);
                    state.cid_by_path.insert(path, cid);
                } else if prev.is_none() {
                    return Err("wasm_space_delete_without_record".into());
                }
            }
            if let Some(next) = envelope.cursor {
                check_cursor(Some(&next))?;
                if !cursors.insert(next.clone()) {
                    return Err("wasm_space_oplog_cursor_cycle".into());
                }
                cursor = Some(next);
                continue;
            }
            let head = envelope.commit.ok_or("wasm_space_missing_head_commit")?;
            if state.lt_hash.commitment().as_slice() != head.data.as_ref()
                || state
                    .latest_rev
                    .as_ref()
                    .is_some_and(|rev| rev.as_str() > head.rev.as_str())
            {
                return Err("wasm_space_oplog_commitment_mismatch".into());
            }
            if let Some(requested_head) = &requested_head.commit {
                if requested_head != &head {
                    return Err("wasm_space_oplog_head_changed".into());
                }
            }
            if found.len() != wanted.len() {
                return Err("wasm_space_requested_ops_not_found".into());
            }
            let mut full: ListRepoOpsOutput =
                decode(&response.body, "authenticated listRepoOps values")?;
            for op in &mut full.ops {
                op.extra_data = None;
                if let Some(value) = &op.value {
                    let path = format!("{}/{}", op.collection.as_str(), op.rkey.as_ref());
                    let current = state
                        .cid_by_path
                        .get(&path)
                        .ok_or("wasm_space_stale_op_value")?;
                    let claimed = op
                        .cid
                        .as_ref()
                        .ok_or("wasm_space_stale_op_value")?
                        .as_str()
                        .parse()
                        .map_err(|_| "wasm_space_invalid_op_cid")?;
                    if current != &claimed {
                        return Err("wasm_space_stale_op_value".into());
                    }
                    let bytes = serde_ipld_dagcbor::to_vec(value)
                        .map_err(|e| format!("wasm_space_encode_op_value: {e}"))?;
                    validate_canonical_dagcbor_record(&bytes)
                        .map_err(|e| format!("wasm_space_invalid_op_value: {e}"))?;
                    if &compute_dagcbor_cid(&bytes) != current {
                        return Err("wasm_space_op_value_cid_mismatch".into());
                    }
                }
            }
            full.extra_data = None;
            full.commit.extra_data = None;
            let mut body =
                serde_json::to_value(&full).map_err(|e| format!("wasm_space_encode_ops: {e}"))?;
            let served: ServedOps = decode(&response.body, "authenticated listRepoOps JSON")?;
            for (op, served) in body
                .get_mut("ops")
                .and_then(Value::as_array_mut)
                .into_iter()
                .flatten()
                .zip(served.ops)
            {
                if let Some(value) = served.value {
                    op["value"] = value;
                }
            }
            response.body =
                serde_json::to_vec(&body).map_err(|e| format!("wasm_space_encode_ops: {e}"))?;
            return Ok(head);
        }
        Err("wasm_space_oplog_page_limit_exceeded".into())
    }
}

fn verify_record(
    context: &ReadContext,
    params: &BTreeMap<String, String>,
    response: &LabyrinthSpaceResponse,
    negotiated: &NegotiatedMacSecret,
) -> Result<(GetRecordOutput, Value), String> {
    let (key_share, secret) = negotiated;
    let envelope: RecordEnvelope = decode(&response.body, "getRecord envelope")?;
    let expected = context
        .space
        .record_uri(
            &context.writer,
            required(params, "collection")?,
            required(params, "rkey")?,
        )
        .map_err(|e| format!("wasm_space_record_coordinates: {e}"))?;
    let envelope_uri =
        if let Some((prefix, rest)) = envelope.uri.split_once(&format!("/{}/", context.writer)) {
            if let Ok(parsed) = SpaceUri::parse(prefix) {
                format!("{}/{}/{rest}", parsed.raw, context.writer)
            } else {
                envelope.uri.clone()
            }
        } else {
            envelope.uri.clone()
        };
    if envelope_uri != expected {
        return Err("wasm_space_record_uri_mismatch".into());
    }
    let (_, cid) = multibase::decode(&envelope.cid)
        .map_err(|e| format!("wasm_space_invalid_record_cid: {e}"))?;
    let headers = mac_headers(response, RECORD_MAC_HEADER)?;
    verify_record_mac(secret, key_share, &headers, &envelope.uri, &envelope.cid)
        .map_err(|e| format!("wasm_space_record_mac: {e}"))?;
    let mut full: GetRecordOutput = decode(&response.body, "authenticated getRecord value")?;
    let bytes = serde_ipld_dagcbor::to_vec(&full.value)
        .map_err(|e| format!("wasm_space_encode_record_value: {e}"))?;
    validate_canonical_dagcbor_record(&bytes)
        .map_err(|e| format!("wasm_space_invalid_record_value: {e}"))?;
    if compute_dagcbor_cid(&bytes).to_bytes() != cid {
        return Err("wasm_space_record_value_cid_mismatch".into());
    }
    full.extra_data = None;
    let served: ServedValue = decode(&response.body, "authenticated getRecord JSON")?;
    Ok((full, served.value.ok_or("wasm_space_missing_record_value")?))
}

fn verify_commit(
    context: &ReadContext,
    response: &LabyrinthSpaceResponse,
    negotiated: &NegotiatedMacSecret,
    commit: &Commit,
) -> Result<(), String> {
    let (key_share, secret) = negotiated;
    let commit_space = SpaceUri::parse(&commit.space).ok().map(|s| s.raw);
    if commit_space.as_deref() != Some(context.space.raw.as_str())
        || commit.repo != context.writer
        || commit.ver != 1
    {
        return Err("wasm_space_commit_binding_mismatch".into());
    }
    let data: [u8; 32] = commit
        .data
        .as_ref()
        .try_into()
        .map_err(|_| "wasm_space_invalid_commit_data")?;
    let headers = mac_headers(response, COMMIT_MAC_HEADER)?;
    verify_commit_mac(
        secret,
        key_share,
        &headers,
        &commit.space,
        &context.writer,
        &commit.rev,
        &data,
    )
    .map_err(|e| format!("wasm_space_commit_mac: {e}"))
}

fn verify_star(
    context: &ReadContext,
    response: &LabyrinthSpaceResponse,
    negotiated: &NegotiatedMacSecret,
) -> Result<ParsedStarRepo, String> {
    let (key_share, secret) = negotiated;
    let headers = mac_headers(response, COMMIT_MAC_HEADER)?;
    read_star_repo_authenticated(
        &response.body,
        &context.space.raw,
        &context.writer,
        |meta| {
            verify_commit_mac(
                secret,
                key_share,
                &headers,
                &context.space.raw,
                &context.writer,
                &meta.rev,
                &meta.data,
            )
        },
    )
    .map_err(|e| match e {
        atproto_spaces::SpacesError::MacMismatch(msg) => format!("wasm_space_star_mac: {msg}"),
        atproto_spaces::SpacesError::SetHashMismatch(_) => {
            "wasm_space_star_commitment_mismatch".into()
        }
        other => format!("wasm_space_star_records: {other}"),
    })
}

fn verify_blob(cid: &str, body: &[u8]) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let (_, bytes) =
        multibase::decode(cid).map_err(|e| format!("wasm_space_invalid_blob_cid: {e}"))?;
    if bytes.len() != 36 || bytes[..4] != [1, 0x55, 0x12, 0x20] {
        return Err("wasm_space_unsupported_blob_cid".into());
    }
    if !bool::from(Sha256::digest(body)[..].ct_eq(&bytes[4..])) {
        return Err("wasm_space_blob_cid_mismatch".into());
    }
    Ok(())
}

fn mac_headers(
    response: &LabyrinthSpaceResponse,
    expected_covered: &'static str,
) -> Result<HeaderMap, String> {
    let mut map = HeaderMap::new();
    for required_name in [expected_covered, SIGNATURE_INPUT_HEADER, SIGNATURE_HEADER] {
        let mut matching = response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(required_name));
        let (_, first_val) = matching.next().ok_or("wasm_space_missing_response_mac")?;
        if matching.next().is_some() {
            return Err("wasm_space_duplicate_response_mac".into());
        }
        let hdr_name = HeaderName::from_static(required_name);
        let hdr_val = HeaderValue::from_str(first_val)
            .map_err(|_| "wasm_space_invalid_response_mac_header")?;
        map.insert(hdr_name, hdr_val);
    }
    Ok(map)
}

fn bounded(response: LabyrinthSpaceResponse) -> Result<LabyrinthSpaceResponse, String> {
    if response.body.len() > MAX_BODY {
        return Err("wasm_space_response_too_large".into());
    }
    Ok(response)
}

fn require_success(response: &LabyrinthSpaceResponse, operation: &str) -> Result<(), String> {
    if !(200..300).contains(&response.status) {
        #[derive(Deserialize)]
        struct XrpcError {
            error: String,
        }
        let code = serde_json::from_slice::<XrpcError>(&response.body)
            .ok()
            .map(|e| e.error)
            .unwrap_or_else(|| "UnknownError".into());
        return Err(format!(
            "wasm_space_{operation}: HTTP {} {code}",
            response.status
        ));
    }
    Ok(())
}

fn reads_as_space_denial(response: &LabyrinthSpaceResponse) -> bool {
    let error = serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|body| body["error"].as_str().map(str::to_owned));
    if matches!(response.status, 400 | 404) && error.as_deref() == Some("SpaceNotFound") {
        return true;
    }
    let refusal = labyrinth::store::space::SpaceError {
        status: response.status,
        error,
        message: None,
    };
    matches!(
        labyrinth::store::space::map_space_error(refusal),
        labyrinth::Error::Forbidden
    )
}

fn decode<T: serde::de::DeserializeOwned>(body: &[u8], what: &str) -> Result<T, String> {
    serde_json::from_slice(body).map_err(|e| format!("wasm_space_invalid_{what}: {e}"))
}

fn required<'a>(params: &'a BTreeMap<String, String>, field: &str) -> Result<&'a str, String> {
    params
        .get(field)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("wasm_space_missing_{field}"))
}

fn check_cursor(cursor: Option<&str>) -> Result<(), String> {
    if cursor
        .is_some_and(|s| s.is_empty() || s.len() > 1024 || s.bytes().any(|b| b < 0x20 || b == 0x7f))
    {
        return Err("wasm_space_invalid_cursor".into());
    }
    Ok(())
}

fn encode(value: &str) -> String {
    chat_wire::urlencode_form_component(value)
}

fn query_path(nsid: &str, params: &BTreeMap<String, String>) -> String {
    let query = params
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("/xrpc/{nsid}?{query}")
}

fn parse_query(request: &LabyrinthSpaceRequest) -> Result<BTreeMap<String, String>, String> {
    if !atproto_spaces::is_valid_nsid(&request.nsid)
        || !(request.nsid.starts_with("com.atproto.space.")
            || (request.nsid == "com.atproto.repo.uploadBlob" && request.method == "POST"))
        || request.path.len() > 16 * 1024
        || request
            .path
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || b == b'#')
    {
        return Err("wasm_space_invalid_request_target".into());
    }
    let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
    if path != format!("/xrpc/{}", request.nsid) {
        return Err("wasm_space_nsid_path_mismatch".into());
    }
    let mut params = BTreeMap::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (key, value) = pair
            .split_once('=')
            .ok_or("wasm_space_invalid_query_pair")?;
        let key = decode_component(key)?;
        let value = decode_component(value)?;
        if params.insert(key, value).is_some() {
            return Err("wasm_space_duplicate_query_parameter".into());
        }
    }
    Ok(params)
}

fn decode_component(input: &str) -> Result<String, String> {
    let mut output = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let high = bytes
                    .next()
                    .and_then(|b| (b as char).to_digit(16))
                    .ok_or("wasm_space_invalid_percent_encoding")?;
                let low = bytes
                    .next()
                    .and_then(|b| (b as char).to_digit(16))
                    .ok_or("wasm_space_invalid_percent_encoding")?;
                output.push(((high << 4) | low) as u8);
            }
            b'+' => output.push(b' '),
            _ => output.push(byte),
        }
    }
    let value = String::from_utf8(output).map_err(|_| "wasm_space_invalid_query_utf8")?;
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("wasm_space_invalid_query_control_character".into());
    }
    Ok(value)
}
