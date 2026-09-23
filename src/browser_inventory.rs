//! Exact authenticated inventory fetch and protected replay custody. Only the
//! shared orchestrator may apply inventory or authorize its completion fence.
use std::{collections::HashSet, sync::Arc};

use base64::{engine::general_purpose::STANDARD, Engine};
use catbird_mls::orchestrator::{
    api_client::MLSAPIClient,
    authenticated_inventory::{AppliedInventoryFence, AuthenticatedInventorySnapshot},
    canonical_transport::{CanonicalOperation, PreparedRequest},
    credentials::CredentialStore,
    error::{OrchestratorError, Result},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    api_client::WasmApiClient, request_runtime::BrowserOrchestrator,
    wasm_mls_context::WasmMLSContext,
};

const MAX_PAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_PAGES: usize = 100;

fn invalid(message: impl std::fmt::Display) -> OrchestratorError {
    OrchestratorError::Api(format!("Authenticated inventory: {message}"))
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn fresh(value: &str) -> Result<()> {
    let expiry = chrono::DateTime::parse_from_rfc3339(value).map_err(invalid)?;
    if expiry.timestamp_millis() <= js_sys::Date::now() as i64 {
        return Err(invalid("snapshot expired"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scope {
    supported_protocol_versions: Vec<String>,
    #[serde(deserialize_with = "scope_digest")]
    scope_digest: String,
}
fn scope_digest<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Bytes {
        #[serde(rename = "$bytes")]
        bytes: String,
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire {
        Text(String),
        Bytes(Bytes),
    }
    Ok(match Wire::deserialize(deserializer)? {
        Wire::Text(value) => value,
        Wire::Bytes(value) => value.bytes,
    })
}
impl Scope {
    fn validate(&self) -> Result<()> {
        let bytes = STANDARD.decode(&self.scope_digest).map_err(invalid)?;
        if self.supported_protocol_versions != ["1", "2"]
            || bytes.len() != 32
            || STANDARD.encode(bytes) != self.scope_digest
        {
            return Err(invalid("missing or changed protocol scope"));
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    items: Vec<serde_json::Value>,
    inventory_session_id: String,
    snapshot_event_cursor: String,
    snapshot_expires_at: String,
    has_more: bool,
    next_page_cursor: Option<String>,
    inventory_scope: Scope,
}
#[derive(Default)]
struct Traversal {
    cursors: HashSet<String>,
    pages: usize,
    total_bytes: usize,
}
impl Traversal {
    fn observe(&mut self, raw: &[u8], expected: Option<(&str, &str, &str, &str)>) -> Result<Page> {
        if raw.is_empty() || raw.len() > MAX_PAGE_BYTES {
            return Err(invalid("page byte bound"));
        }
        // Shared ingestion performs the strict recursive schema and signature
        // validation over these unchanged bytes before it applies any item.
        let page: Page = serde_json::from_slice(raw).map_err(invalid)?;
        page.inventory_scope.validate()?;
        if !(32..=512).contains(&page.inventory_session_id.len())
            || page.snapshot_event_cursor.is_empty()
            || page.snapshot_event_cursor.len() > 512
            || page.items.len() > 100
        {
            return Err(invalid("invalid page envelope"));
        }
        fresh(&page.snapshot_expires_at)?;
        if let Some((session, cursor, expiry, scope)) = expected {
            if (
                page.inventory_session_id.as_str(),
                page.snapshot_event_cursor.as_str(),
                page.snapshot_expires_at.as_str(),
                page.inventory_scope.scope_digest.as_str(),
            ) != (session, cursor, expiry, scope)
            {
                return Err(invalid("session, event cursor, expiry or scope changed"));
            }
        }
        self.pages += 1;
        self.total_bytes += raw.len();
        if self.pages > MAX_PAGES || self.total_bytes > MAX_TOTAL_BYTES {
            return Err(invalid("pagination bound"));
        }
        match (page.has_more, page.next_page_cursor.as_deref()) {
            (false, None) => {}
            (true, Some(cursor))
                if !cursor.is_empty()
                    && cursor.len() <= 512
                    && self.pages < MAX_PAGES
                    && self.cursors.insert(cursor.to_owned()) => {}
            _ => return Err(invalid("inconsistent or repeated pagination cursor")),
        }
        Ok(page)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageRef {
    id: String,
    sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    owner: String,
    actor: String,
    auth_generation: i64,
    attempt: String,
    session: String,
    cursor: String,
    expires_at: String,
    scope: String,
    conversations: Vec<PageRef>,
    welcomes: Vec<PageRef>,
    recovery: Vec<PageRef>,
    snapshot_sha256: String,
    applied_digest: Option<String>,
}

pub(crate) struct BrowserSubscriptionTicket {
    pub endpoint: String,
    pub ticket: String,
    pub inventory_session_id: String,
    pub event_cursor: String,
}

async fn identity(
    runtime: &Arc<BrowserOrchestrator>,
    api: &WasmApiClient,
    owner: &str,
    actor: &str,
    generation: i64,
) -> Result<()> {
    crate::request_runtime::current(owner, runtime)
        .map_err(|_| invalid("account runtime changed"))?;
    if !api.is_authenticated_as(owner).await
        || api.actor_device()? != actor
        || runtime
            .credentials()
            .get_device_uuid(owner)
            .await?
            .as_deref()
            != Some(actor)
        || runtime.credentials().get_auth_generation(owner).await? != Some(generation)
        || generation <= 0
    {
        return Err(invalid("authenticated actor changed"));
    }
    Ok(())
}
fn query(
    operation: CanonicalOperation,
    actor: &str,
    session: Option<&str>,
    cursor: Option<&str>,
) -> PreparedRequest {
    let nsid = match operation {
        CanonicalOperation::GetConversations => "getConversations",
        CanonicalOperation::GetPendingWelcomes => "getPendingWelcomes",
        _ => "getLeafRecoveryInbox",
    };
    let mut url = reqwest::Url::parse(&format!(
        "https://inventory.invalid/xrpc/blue.catbird.chat.{nsid}"
    ))
    .expect("literal URL");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("actorDeviceId", actor)
            .append_pair("limit", "100")
            .append_pair("supportedProtocolVersions", "1")
            .append_pair("supportedProtocolVersions", "2");
        if let Some(session) = session {
            q.append_pair("inventorySessionId", session);
        }
        if let Some(cursor) = cursor {
            q.append_pair("pageCursor", cursor);
        }
    }
    PreparedRequest {
        operation,
        method: "GET".into(),
        path: format!("{}?{}", url.path(), url.query().unwrap_or_default()),
        body: None,
    }
}

/// Fetch all three domains without interpreting any conversation or membership.
/// Raw pages are passed unchanged to the single shared ingestion authority.
async fn fetch_scoped_inventory(
    runtime: &Arc<BrowserOrchestrator>,
    api: &WasmApiClient,
    owner: &str,
    actor: &str,
    generation: i64,
) -> Result<AuthenticatedInventorySnapshot> {
    let mut snapshot = AuthenticatedInventorySnapshot {
        owner_did: owner.into(),
        actor_device_id: actor.into(),
        auth_generation: generation,
        inventory_session_id: String::new(),
        event_cursor: String::new(),
        expires_at: String::new(),
        scope_digest: String::new(),
        conversation_pages: vec![],
        welcome_pages: vec![],
        recovery_pages: vec![],
    };
    let mut total = 0usize;
    for operation in [
        CanonicalOperation::GetConversations,
        CanonicalOperation::GetPendingWelcomes,
        CanonicalOperation::GetLeafRecoveryInbox,
    ] {
        let mut traversal = Traversal::default();
        let mut cursor = None;
        loop {
            identity(runtime, api, owner, actor, generation).await?;
            let session = (operation != CanonicalOperation::GetConversations)
                .then_some(snapshot.inventory_session_id.as_str());
            let response = api
                .submit_prepared_request(query(operation, actor, session, cursor.as_deref()))
                .await?;
            identity(runtime, api, owner, actor, generation).await?;
            if response.status != 200 {
                return Err(invalid(format!("inventory HTTP {}", response.status)));
            }
            total = total
                .checked_add(response.body.len())
                .ok_or_else(|| invalid("byte overflow"))?;
            if total > MAX_TOTAL_BYTES {
                return Err(invalid("total byte bound"));
            }
            let expected = (!snapshot.inventory_session_id.is_empty()).then_some((
                snapshot.inventory_session_id.as_str(),
                snapshot.event_cursor.as_str(),
                snapshot.expires_at.as_str(),
                snapshot.scope_digest.as_str(),
            ));
            catbird_mls::orchestrator::canonical_transport::validate_authenticated_inventory_page(
                operation,
                &response.body,
            )
            .map_err(invalid)?;
            let page = traversal.observe(&response.body, expected)?;
            if snapshot.inventory_session_id.is_empty() {
                snapshot.inventory_session_id = page.inventory_session_id;
                snapshot.event_cursor = page.snapshot_event_cursor;
                snapshot.expires_at = page.snapshot_expires_at;
                snapshot.scope_digest = page.inventory_scope.scope_digest;
            }
            cursor = page.next_page_cursor;
            match operation {
                CanonicalOperation::GetConversations => {
                    snapshot.conversation_pages.push(response.body)
                }
                CanonicalOperation::GetPendingWelcomes => {
                    snapshot.welcome_pages.push(response.body)
                }
                _ => snapshot.recovery_pages.push(response.body),
            }
            if !page.has_more {
                break;
            }
        }
    }
    Ok(snapshot)
}

fn snapshot_hash(snapshot: &AuthenticatedInventorySnapshot) -> Result<String> {
    Ok(hex::encode(snapshot.digest()?))
}

fn store_pages(ctx: &WasmMLSContext, namespace: &str, pages: &[Vec<u8>]) -> Result<Vec<PageRef>> {
    pages
        .iter()
        .map(|raw| {
            let sha256 = digest(raw);
            // The protected key is content addressed; a full SHA256 comparison
            // fences the UUID-sized locator and detects even a locator collision.
            let hash = Sha256::digest(raw);
            let mut locator = [0u8; 16];
            locator.copy_from_slice(&hash[..16]);
            locator[6] = (locator[6] & 0x0f) | 0x40;
            locator[8] = (locator[8] & 0x3f) | 0x80;
            let id = uuid::Uuid::from_bytes(locator).to_string();
            if let Some(existing) = ctx.request_value(namespace, &id).map_err(invalid)? {
                if existing != *raw {
                    return Err(invalid("page locator collision"));
                }
            } else {
                if ctx
                    .request_values_total_bytes(namespace)
                    .map_err(invalid)?
                    .saturating_add(raw.len() as u64)
                    > 256 * 1024 * 1024
                {
                    return Err(invalid("protected inventory retention quota reached"));
                }
                if !ctx
                    .request_value_cas(namespace, &id, None, raw)
                    .map_err(invalid)?
                {
                    return Err(invalid("page custody conflict"));
                }
            }
            Ok(PageRef { id, sha256 })
        })
        .collect()
}

fn load_pages(
    ctx: &WasmMLSContext,
    namespace: &str,
    refs: &[PageRef],
    total: &mut usize,
) -> Result<Vec<Vec<u8>>> {
    if refs.is_empty() || refs.len() > MAX_PAGES {
        return Err(invalid("invalid retained page count"));
    }
    refs.iter()
        .map(|reference| {
            let raw = ctx
                .request_value(namespace, &reference.id)
                .map_err(invalid)?
                .ok_or_else(|| invalid("retained page missing"))?;
            *total += raw.len();
            if raw.len() > MAX_PAGE_BYTES
                || *total > MAX_TOTAL_BYTES
                || digest(&raw) != reference.sha256
            {
                return Err(invalid("retained page binding"));
            }
            Ok(raw)
        })
        .collect()
}
fn restore(
    ctx: &WasmMLSContext,
    namespace: &str,
    journal: &Journal,
) -> Result<AuthenticatedInventorySnapshot> {
    let mut total = 0;
    let snapshot = AuthenticatedInventorySnapshot {
        owner_did: journal.owner.clone(),
        actor_device_id: journal.actor.clone(),
        auth_generation: journal.auth_generation,
        inventory_session_id: journal.session.clone(),
        event_cursor: journal.cursor.clone(),
        expires_at: journal.expires_at.clone(),
        scope_digest: journal.scope.clone(),
        conversation_pages: load_pages(ctx, namespace, &journal.conversations, &mut total)?,
        welcome_pages: load_pages(ctx, namespace, &journal.welcomes, &mut total)?,
        recovery_pages: load_pages(ctx, namespace, &journal.recovery, &mut total)?,
    };
    if snapshot_hash(&snapshot)? != journal.snapshot_sha256 {
        return Err(invalid("retained snapshot binding"));
    }
    Ok(snapshot)
}

pub(crate) async fn synchronize_inventory(
    runtime: Arc<BrowserOrchestrator>,
    api: Arc<WasmApiClient>,
    owner: &str,
    actor: &str,
    force_fresh: bool,
) -> Result<AppliedInventoryFence> {
    Ok(synchronize(&runtime, &api, owner, actor, force_fresh)
        .await?
        .1)
}

async fn synchronize(
    runtime: &Arc<BrowserOrchestrator>,
    api: &Arc<WasmApiClient>,
    owner: &str,
    actor: &str,
    force_fresh: bool,
) -> Result<(
    AuthenticatedInventorySnapshot,
    AppliedInventoryFence,
    Vec<u8>,
)> {
    let generation = runtime
        .credentials()
        .get_auth_generation(owner)
        .await?
        .ok_or_else(|| invalid("actor generation unavailable"))?;
    identity(runtime, api, owner, actor, generation).await?;
    let namespace = format!("inventory:{owner}");
    let pages_namespace = format!("inventoryPages:{owner}");
    let old = runtime
        .mls_context()
        .request_value(&namespace, actor)
        .map_err(invalid)?;
    let prior = old
        .as_deref()
        .map(serde_json::from_slice::<Journal>)
        .transpose()
        .map_err(invalid)?;
    let snapshot = if let Some(journal) = prior.as_ref().filter(|j| {
        !force_fresh
            && j.owner == owner
            && j.actor == actor
            && j.auth_generation == generation
            && fresh(&j.expires_at).is_ok()
    }) {
        restore(runtime.mls_context(), &pages_namespace, journal)?
    } else {
        fetch_scoped_inventory(runtime, api, owner, actor, generation).await?
    };
    identity(runtime, api, owner, actor, generation).await?;
    fresh(&snapshot.expires_at)?;
    let mut journal = Journal {
        owner: owner.into(),
        actor: actor.into(),
        auth_generation: generation,
        attempt: uuid::Uuid::new_v4().to_string(),
        session: snapshot.inventory_session_id.clone(),
        cursor: snapshot.event_cursor.clone(),
        expires_at: snapshot.expires_at.clone(),
        scope: snapshot.scope_digest.clone(),
        conversations: store_pages(
            runtime.mls_context(),
            &pages_namespace,
            &snapshot.conversation_pages,
        )?,
        welcomes: store_pages(
            runtime.mls_context(),
            &pages_namespace,
            &snapshot.welcome_pages,
        )?,
        recovery: store_pages(
            runtime.mls_context(),
            &pages_namespace,
            &snapshot.recovery_pages,
        )?,
        snapshot_sha256: snapshot_hash(&snapshot)?,
        applied_digest: None,
    };
    let prepared = serde_json::to_vec(&journal).map_err(invalid)?;
    if !runtime
        .mls_context()
        .request_value_cas(&namespace, actor, old.as_deref(), &prepared)
        .map_err(invalid)?
    {
        return Err(invalid("concurrent inventory replaced this attempt"));
    }
    let applied = runtime
        .ingest_authenticated_inventory_snapshot(&snapshot)
        .await?;
    identity(runtime, api, owner, actor, generation).await?;
    fresh(&snapshot.expires_at)?;
    if !applied.matches_snapshot(&snapshot) {
        return Err(invalid("shared completion does not match exact snapshot"));
    }
    journal.applied_digest = Some(hex::encode(applied.snapshot_digest()));
    let completed = serde_json::to_vec(&journal).map_err(invalid)?;
    if !runtime
        .mls_context()
        .request_value_cas(&namespace, actor, Some(&prepared), &completed)
        .map_err(invalid)?
    {
        return Err(invalid("inventory completion superseded"));
    }
    Ok((snapshot, applied, completed))
}

pub(crate) async fn prepare_subscription(
    runtime: Arc<BrowserOrchestrator>,
    api: Arc<WasmApiClient>,
    owner: &str,
    actor: &str,
) -> Result<BrowserSubscriptionTicket> {
    let (snapshot, _applied, completed) = synchronize(&runtime, &api, owner, actor, false).await?;
    let generation = snapshot.auth_generation;
    let namespace = format!("inventory:{owner}");
    let response=api.submit_prepared_request(PreparedRequest{operation:CanonicalOperation::GetSubscriptionTicket,method:"POST".into(),path:"/xrpc/blue.catbird.chat.getSubscriptionTicket".into(),body:Some(serde_json::to_vec(&serde_json::json!({"actorDeviceId":actor,"inventorySessionId":snapshot.inventory_session_id,"eventCursor":snapshot.event_cursor,"supportedProtocolVersions":["1","2"]})).map_err(invalid)?)}).await?;
    identity(&runtime, &api, owner, actor, generation).await?;
    if runtime
        .mls_context()
        .request_value(&namespace, actor)
        .map_err(invalid)?
        .as_deref()
        != Some(&completed)
    {
        return Err(invalid("ticket attempt superseded"));
    }
    if response.status != 200 {
        return Err(invalid(format!("ticket HTTP {}", response.status)));
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Ticket {
        ticket: String,
        endpoint: String,
        expires_at: String,
        inventory_scope: Scope,
    }
    if response.body.len() > 16384 {
        return Err(invalid("ticket response bound"));
    }
    catbird_mls::chat_v2::transcript::decode_strict_json(&response.body).map_err(invalid)?;
    let ticket: Ticket = serde_json::from_slice(&response.body).map_err(invalid)?;
    ticket.inventory_scope.validate()?;
    fresh(&ticket.expires_at)?;
    fresh(&snapshot.expires_at)?;
    let endpoint = reqwest::Url::parse(&ticket.endpoint).map_err(invalid)?;
    if ticket.inventory_scope.scope_digest != snapshot.scope_digest
        || !(32..=4096).contains(&ticket.ticket.len())
        || endpoint.scheme() != "wss"
        || endpoint.host_str() != Some("chat.catbird.blue")
        || endpoint.port_or_known_default() != Some(443)
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
        || endpoint.query().is_some()
        || endpoint.path() != "/xrpc/blue.catbird.chat.subscribeEvents"
    {
        return Err(invalid("ticket scope or endpoint is invalid"));
    }
    Ok(BrowserSubscriptionTicket {
        endpoint: ticket.endpoint,
        ticket: ticket.ticket,
        inventory_session_id: snapshot.inventory_session_id,
        event_cursor: snapshot.event_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    #[cfg(feature = "inventory-worker-tests")]
    wasm_bindgen_test_configure!(run_in_dedicated_worker);
    fn page(more: bool, next: Option<&str>) -> Vec<u8> {
        let mut value = serde_json::json!({"items":[],"inventorySessionId":"a".repeat(32),"snapshotEventCursor":"fence","snapshotExpiresAt":"2099-01-01T00:00:00.000Z","hasMore":more,"inventoryScope":{"supportedProtocolVersions":["1","2"],"scopeDigest":STANDARD.encode([7u8;32])}});
        if let Some(next) = next {
            value["nextPageCursor"] = next.into();
        }
        serde_json::to_vec(&value).unwrap()
    }
    #[cfg(feature = "inventory-worker-tests")]
    #[wasm_bindgen_test]
    async fn protected_page_manifest_survives_reopen_and_rejects_substitution() {
        use crate::sqlite_conn::SqliteConn;
        use std::rc::Rc;
        SqliteConn::initialize_opfs().await.unwrap();
        let path = format!("inventory-{}.db", uuid::Uuid::new_v4());
        let key = "ac".repeat(32);
        let owner = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        let actor = "00000000-0000-4000-8000-000000000001";
        let ns = format!("inventory:{owner}");
        let page_ns = format!("inventoryPages:{owner}");
        let exact = page(false, None);
        {
            let conn = Rc::new(SqliteConn::open(&path, &key).unwrap());
            crate::mls_storage::WasmSqliteStorage::ensure_schema(&conn).unwrap();
            let ctx = WasmMLSContext::open_with_conn(conn).unwrap();
            ctx.bind_request_owner(owner).unwrap();
            let snapshot = AuthenticatedInventorySnapshot {
                owner_did: owner.into(),
                actor_device_id: actor.into(),
                auth_generation: 7,
                inventory_session_id: "a".repeat(32),
                event_cursor: "fence".into(),
                expires_at: "2099-01-01T00:00:00.000Z".into(),
                scope_digest: STANDARD.encode([7u8; 32]),
                conversation_pages: vec![exact.clone()],
                welcome_pages: vec![exact.clone()],
                recovery_pages: vec![exact.clone()],
            };
            let journal = Journal {
                owner: owner.into(),
                actor: actor.into(),
                auth_generation: 7,
                attempt: uuid::Uuid::new_v4().to_string(),
                session: snapshot.inventory_session_id.clone(),
                cursor: snapshot.event_cursor.clone(),
                expires_at: snapshot.expires_at.clone(),
                scope: snapshot.scope_digest.clone(),
                conversations: store_pages(&ctx, &page_ns, &snapshot.conversation_pages).unwrap(),
                welcomes: store_pages(&ctx, &page_ns, &snapshot.welcome_pages).unwrap(),
                recovery: store_pages(&ctx, &page_ns, &snapshot.recovery_pages).unwrap(),
                snapshot_sha256: snapshot_hash(&snapshot).unwrap(),
                applied_digest: None,
            };
            let raw = serde_json::to_vec(&journal).unwrap();
            assert!(ctx.request_value_cas(&ns, actor, None, &raw).unwrap());
            assert!(!ctx
                .request_value_cas(&ns, actor, None, b"superseded")
                .unwrap());
        }
        let conn = Rc::new(SqliteConn::open(&path, &key).unwrap());
        let ctx = WasmMLSContext::open_with_conn(conn).unwrap();
        assert!(ctx
            .bind_request_owner("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
            .is_err());
        let raw = ctx.request_value(&ns, actor).unwrap().unwrap();
        let journal: Journal = serde_json::from_slice(&raw).unwrap();
        let restored = restore(&ctx, &page_ns, &journal).unwrap();
        assert_eq!(restored.conversation_pages[0], exact);
        assert!(journal.applied_digest.is_none());
        let reference = &journal.welcomes[0];
        assert!(ctx
            .request_value_cas(&page_ns, &reference.id, Some(&exact), b"substituted page")
            .unwrap());
        assert!(restore(&ctx, &page_ns, &journal).is_err());
    }
    #[wasm_bindgen_test]
    fn scoped_pagination_rejects_all_fence_changes_and_repeated_cursor() {
        let mut traversal = Traversal::default();
        let raw = page(true, Some("next"));
        let first = traversal.observe(&raw, None).unwrap();
        let expected = (
            first.inventory_session_id.as_str(),
            first.snapshot_event_cursor.as_str(),
            first.snapshot_expires_at.as_str(),
            first.inventory_scope.scope_digest.as_str(),
        );
        assert!(traversal.observe(&raw, Some(expected)).is_err());
        for field in [
            "inventorySessionId",
            "snapshotEventCursor",
            "snapshotExpiresAt",
        ] {
            let mut value: serde_json::Value = serde_json::from_slice(&page(false, None)).unwrap();
            value[field] = if field == "snapshotExpiresAt" {
                "2098-01-01T00:00:00.000Z".into()
            } else {
                "b".repeat(32).into()
            };
            assert!(
                Traversal::default()
                    .observe(&serde_json::to_vec(&value).unwrap(), Some(expected))
                    .is_err(),
                "{field}"
            );
        }
        let mut value: serde_json::Value = serde_json::from_slice(&page(false, None)).unwrap();
        value["inventoryScope"]["scopeDigest"] = STANDARD.encode([8u8; 32]).into();
        assert!(Traversal::default()
            .observe(&serde_json::to_vec(&value).unwrap(), Some(expected))
            .is_err());
        value["inventoryScope"]["supportedProtocolVersions"] = serde_json::json!(["1"]);
        assert!(Traversal::default()
            .observe(&serde_json::to_vec(&value).unwrap(), None)
            .is_err());
    }
    #[wasm_bindgen_test]
    fn page_envelope_is_closed_bounded_and_requires_exact_completion() {
        for (more, next) in [(true, None), (false, Some("next")), (true, Some(""))] {
            assert!(Traversal::default()
                .observe(&page(more, next), None)
                .is_err());
        }
        let mut value: serde_json::Value = serde_json::from_slice(&page(false, None)).unwrap();
        value["unknown"] = true.into();
        assert!(Traversal::default()
            .observe(&serde_json::to_vec(&value).unwrap(), None)
            .is_err());
        let mut traversal = Traversal {
            pages: 99,
            ..Default::default()
        };
        assert!(traversal.observe(&page(true, Some("next")), None).is_err());
        assert!(Traversal::default()
            .observe(&vec![b' '; MAX_PAGE_BYTES + 1], None)
            .is_err());
        assert!(fresh("2000-01-01T00:00:00Z").is_err());
        assert!(Traversal::default()
            .observe(&page(false, None), None)
            .is_ok());
    }
    #[wasm_bindgen_test]
    fn generated_scope_bytes_wrapper_is_canonical_and_closed() {
        let mut value: serde_json::Value = serde_json::from_slice(&page(false, None)).unwrap();
        value["inventoryScope"]["scopeDigest"] =
            serde_json::json!({"$bytes":STANDARD.encode([7u8;32])});
        assert!(Traversal::default()
            .observe(&serde_json::to_vec(&value).unwrap(), None)
            .is_ok());
        value["inventoryScope"]["scopeDigest"]["other"] = true.into();
        assert!(Traversal::default()
            .observe(&serde_json::to_vec(&value).unwrap(), None)
            .is_err());
        value["inventoryScope"]["scopeDigest"] = STANDARD.encode([7u8; 31]).into();
        assert!(Traversal::default()
            .observe(&serde_json::to_vec(&value).unwrap(), None)
            .is_err());
    }
    #[wasm_bindgen_test]
    fn requests_scope_every_page_and_use_domain_session() {
        let first = query(CanonicalOperation::GetConversations, "actor", None, None);
        assert!(!first.path.contains("inventorySessionId"));
        for operation in [
            CanonicalOperation::GetConversations,
            CanonicalOperation::GetPendingWelcomes,
            CanonicalOperation::GetLeafRecoveryInbox,
        ] {
            let request = query(
                operation,
                "actor",
                Some("session&other"),
                Some("cursor/one"),
            );
            assert!(request
                .path
                .contains("supportedProtocolVersions=1&supportedProtocolVersions=2"));
            assert!(request.path.contains("inventorySessionId=session%26other"));
            assert!(request.path.contains("pageCursor=cursor%2Fone"));
        }
    }
    #[wasm_bindgen_test]
    fn snapshot_digest_binds_raw_pages_and_domain_order() {
        let mut value = AuthenticatedInventorySnapshot {
            owner_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            actor_device_id: "00000000-0000-4000-8000-000000000001".into(),
            auth_generation: 7,
            inventory_session_id: "a".repeat(32),
            event_cursor: "fence".into(),
            expires_at: "2099-01-01T00:00:00.000Z".into(),
            scope_digest: STANDARD.encode([7u8; 32]),
            conversation_pages: vec![page(false, None)],
            welcome_pages: vec![b"welcome".to_vec()],
            recovery_pages: vec![b"recovery".to_vec()],
        };
        let original = snapshot_hash(&value).unwrap();
        value.auth_generation = 8;
        assert_ne!(original, snapshot_hash(&value).unwrap());
        value.auth_generation = 7;
        value.conversation_pages[0].push(b' ');
        assert_ne!(original, snapshot_hash(&value).unwrap());
        value.conversation_pages[0].pop();
        std::mem::swap(&mut value.welcome_pages, &mut value.recovery_pages);
        assert_ne!(original, snapshot_hash(&value).unwrap());
    }
}
