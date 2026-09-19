//! Canonical account-scoped event transport. Events are hints: shared Rust
//! reconciliation verifies effects before protected event progress advances.
use crate::{
    request_runtime::{self, BrowserOrchestrator},
    *,
};
use catbird_mls::orchestrator::mls_provider::MlsCryptoContext;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
};
use wasm_bindgen::closure::Closure;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorFence {
    owner: String,
    actor: String,
    generation: i64,
    session: String,
    connection: String,
    cursor: String,
}
struct Consumer {
    runtime: Arc<BrowserOrchestrator>,
    owner: String,
    actor: String,
    generation: i64,
    selected: String,
    fence: RefCell<(CursorFence, Vec<u8>)>,
    ws: WebSocket,
    queue: RefCell<VecDeque<String>>,
    running: Cell<bool>,
    closed: Cell<bool>,
    on_message: js_sys::Function,
    on_event: js_sys::Function,
    on_status: js_sys::Function,
}
fn error(message: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&message.to_string())
}
fn decode(raw: &str) -> Result<serde_json::Value, JsValue> {
    if raw.len() > 64 * 1024 {
        return Err(error("Subscription frame exceeds bound"));
    }
    crate::strict_projection::validate_read_shape("subscriptionMessage", raw.as_bytes())
        .map_err(error)
}
fn next_cursor(current: &str, value: &serde_json::Value) -> Result<Option<String>, JsValue> {
    if value["$type"] == "blue.catbird.chat.defs#typingEvent" {
        return Ok(None);
    }
    let next = value["cursor"]
        .as_str()
        .ok_or_else(|| error("Missing event cursor"))?;
    if value["previousCursor"] != current || next == current {
        return Err(error("Subscription cursor chain changed"));
    }
    Ok(Some(next.into()))
}
impl Consumer {
    fn stop(&self, status: &str) {
        self.closed.set(true);
        self.queue.borrow_mut().clear();
        let _ = self.ws.close();
        let _ = self
            .on_status
            .call1(&JsValue::NULL, &JsValue::from_str(status));
    }
    async fn current(&self) -> Result<(), JsValue> {
        if self.closed.get() {
            return Err(error("Subscription closed"));
        }
        request_runtime::current(&self.owner, &self.runtime)?;
        if self
            .runtime
            .credentials()
            .get_auth_generation(&self.owner)
            .await
            .map_err(error)?
            != Some(self.generation)
            || self
                .runtime
                .credentials()
                .get_device_uuid(&self.owner)
                .await
                .map_err(error)?
                .as_deref()
                != Some(&self.actor)
        {
            return Err(error("Subscription device authority changed"));
        }
        request_runtime::current(&self.owner, &self.runtime)?;
        let retained = self
            .runtime
            .mls_context()
            .request_value("subscriptionCursor", &self.actor)
            .map_err(error)?;
        if retained.as_deref() != Some(self.fence.borrow().1.as_slice()) {
            return Err(error("Subscription was superseded"));
        }
        Ok(())
    }
    async fn messages_through(&self, cid: &str, target: u64) -> Result<Vec<Message>, JsValue> {
        let ctx = self.runtime.mls_context();
        let previous = ctx.request_value("entryCursor", cid).map_err(error)?;
        let mut cursor = previous
            .as_deref()
            .map(|raw| serde_json::from_slice::<u64>(raw).map_err(error))
            .transpose()?
            .unwrap_or(0);
        let mut exact = previous;
        let mut output = Vec::new();
        for _ in 0..100 {
            if cursor >= target {
                return Ok(output);
            }
            let (messages, next) = self
                .runtime
                .fetch_messages(cid, Some(&cursor.to_string()), 100, None, None, None)
                .await
                .map_err(error)?;
            self.current().await?;
            let next = next
                .ok_or_else(|| error("Message hint not present in verified entries"))?
                .parse::<u64>()
                .map_err(error)?;
            if next <= cursor {
                return Err(error("Message cursor did not advance"));
            }
            ctx.ensure_storage_durable().map_err(error)?;
            let raw = serde_json::to_vec(&next).map_err(error)?;
            if !ctx
                .request_value_cas("entryCursor", cid, exact.as_deref(), &raw)
                .map_err(error)?
            {
                return Err(error("Entry progress changed concurrently"));
            }
            exact = Some(raw);
            cursor = next;
            output.extend(
                messages
                    .into_iter()
                    .filter(|m| m.has_displayable_body())
                    .map(ui_message_from_orchestrator),
            );
        }
        Err(error("Message catch-up exceeded page bound"))
    }
    async fn consume(&self, raw: &str) -> Result<(), JsValue> {
        self.current().await?;
        let value = decode(raw)?;
        let current = self.fence.borrow().0.cursor.clone();
        let Some(next) = next_cursor(&current, &value)? else {
            // Best-effort typing is deliberately omitted from this adapter.
            // It cannot advance a durable cursor or authorize consent.
            return Ok(());
        };
        let payload = &value["payload"];
        let kind = payload["$type"]
            .as_str()
            .ok_or_else(|| error("Missing event payload type"))?;
        let mut messages = Vec::new();
        if kind == "blue.catbird.chat.defs#messageAvailableEvent" {
            let cid = payload["conversationId"]
                .as_str()
                .ok_or_else(|| error("Missing conversation"))?;
            // A new request may arrive before a local row exists. A fresh
            // exact inventory establishes its policy before processing entries.
            if !self.runtime.conversations().lock().await.contains_key(cid) {
                request_runtime::synchronize(&self.owner, &self.runtime, true).await?;
            }
            let target = payload["seq"]
                .as_u64()
                .ok_or_else(|| error("Missing entry sequence"))?;
            messages = self.messages_through(cid, target).await?;
        } else if kind != "blue.catbird.chat.defs#watermarkEvent" {
            if kind == "blue.catbird.chat.defs#accessEndedEvent"
                && (payload["userDid"] != self.owner || payload["deviceId"] != self.actor)
            {
                return Err(error("Foreign access-ended audience"));
            }
            request_runtime::synchronize(&self.owner, &self.runtime, true).await?;
        }
        self.current().await?;
        self.runtime
            .mls_context()
            .ensure_storage_durable()
            .map_err(error)?;
        let (mut fence, expected) = self.fence.borrow().clone();
        fence.cursor = next;
        let encoded = serde_json::to_vec(&fence).map_err(error)?;
        if !self
            .runtime
            .mls_context()
            .request_value_cas("subscriptionCursor", &self.actor, Some(&expected), &encoded)
            .map_err(error)?
        {
            return Err(error("Subscription progress superseded"));
        }
        *self.fence.borrow_mut() = (fence, encoded);
        for message in messages
            .into_iter()
            .filter(|m| m.conversation_id == self.selected)
        {
            let _ = self.on_message.call1(&JsValue::NULL, &to_js(&message)?);
        }
        let event = serde_json::json!({"type":"refresh","data":{"conversationId":payload["conversationId"].as_str(),"source":"canonical"}});
        let _ = self.on_event.call1(&JsValue::NULL, &to_js(&event)?);
        Ok(())
    }
    fn enqueue(self: &Rc<Self>, raw: String) {
        if self.closed.get() {
            return;
        }
        if raw.len() > 64 * 1024 || self.queue.borrow().len() >= 256 {
            self.stop("error");
            return;
        }
        self.queue.borrow_mut().push_back(raw);
        if self.running.replace(true) {
            return;
        }
        let consumer = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                let item = consumer.queue.borrow_mut().pop_front();
                let Some(raw) = item else {
                    consumer.running.set(false);
                    return;
                };
                if consumer.consume(&raw).await.is_err() {
                    consumer.stop("error");
                    consumer.running.set(false);
                    return;
                }
            }
        });
    }
}

#[wasm_bindgen]
pub struct CanonicalSubscription {
    consumer: Rc<Consumer>,
    _open: Closure<dyn FnMut(web_sys::Event)>,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _error: Closure<dyn FnMut(ErrorEvent)>,
    _close: Closure<dyn FnMut(CloseEvent)>,
}
#[wasm_bindgen]
impl CanonicalSubscription {
    pub fn close(&self) {
        self.consumer.stop("disconnected");
    }
    pub fn is_open(&self) -> bool {
        !self.consumer.closed.get() && self.consumer.ws.ready_state() == WebSocket::OPEN
    }
}
impl Drop for CanonicalSubscription {
    fn drop(&mut self) {
        self.consumer.stop("disconnected");
        self.consumer.ws.set_onopen(None);
        self.consumer.ws.set_onmessage(None);
        self.consumer.ws.set_onerror(None);
        self.consumer.ws.set_onclose(None);
    }
}

pub(crate) async fn connect(
    selected: String,
    on_message: js_sys::Function,
    on_event: js_sys::Function,
    on_status: js_sys::Function,
) -> Result<CanonicalSubscription, JsValue> {
    canonical_uuid_string(&selected, "subscription conversation").map_err(error)?;
    let (owner, runtime) = request_runtime::current_engine()?;
    let api = with_state(|s| Ok(s.api_client.clone()))?;
    let actor = runtime
        .credentials()
        .get_device_uuid(&owner)
        .await
        .map_err(error)?
        .ok_or_else(|| error("Enrolled actor missing"))?;
    let generation = runtime
        .credentials()
        .get_auth_generation(&owner)
        .await
        .map_err(error)?
        .ok_or_else(|| error("Enrolled generation missing"))?;
    let ticket =
        crate::browser_inventory::prepare_subscription(runtime.clone(), api, &owner, &actor)
            .await
            .map_err(error)?;
    request_runtime::current(&owner, &runtime)?;
    let previous = runtime
        .mls_context()
        .request_value("subscriptionCursor", &actor)
        .map_err(error)?;
    let fence = CursorFence {
        owner: owner.clone(),
        actor: actor.clone(),
        generation,
        session: ticket.inventory_session_id,
        connection: uuid::Uuid::new_v4().to_string(),
        cursor: ticket.event_cursor.clone(),
    };
    let encoded = serde_json::to_vec(&fence).map_err(error)?;
    if !runtime
        .mls_context()
        .request_value_cas("subscriptionCursor", &actor, previous.as_deref(), &encoded)
        .map_err(error)?
    {
        return Err(error("Concurrent subscription installation"));
    }
    let mut url = reqwest::Url::parse(&ticket.endpoint).map_err(error)?;
    url.query_pairs_mut()
        .append_pair("ticket", &ticket.ticket)
        .append_pair("cursor", &ticket.event_cursor);
    let ws = WebSocket::new(url.as_str())?;
    let consumer = Rc::new(Consumer {
        runtime,
        owner,
        actor,
        generation,
        selected,
        fence: RefCell::new((fence, encoded)),
        ws: ws.clone(),
        queue: RefCell::new(VecDeque::new()),
        running: Cell::new(false),
        closed: Cell::new(false),
        on_message,
        on_event,
        on_status,
    });
    let c = consumer.clone();
    let open = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
        let _ = c
            .on_status
            .call1(&JsValue::NULL, &JsValue::from_str("connected"));
    });
    ws.set_onopen(Some(open.as_ref().unchecked_ref()));
    let c = consumer.clone();
    let message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        if let Some(raw) = event.data().as_string() {
            c.enqueue(raw);
        } else {
            c.stop("error");
        }
    });
    ws.set_onmessage(Some(message.as_ref().unchecked_ref()));
    let c = consumer.clone();
    let err = Closure::<dyn FnMut(ErrorEvent)>::new(move |_| c.stop("error"));
    ws.set_onerror(Some(err.as_ref().unchecked_ref()));
    let c = consumer.clone();
    let close = Closure::<dyn FnMut(CloseEvent)>::new(move |_| c.stop("disconnected"));
    ws.set_onclose(Some(close.as_ref().unchecked_ref()));
    Ok(CanonicalSubscription {
        consumer,
        _open: open,
        _message: message,
        _error: err,
        _close: close,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    #[wasm_bindgen_test]
    fn durable_event_chain_rejects_gap_duplicate_unknown_and_typing_cursor() {
        let raw = r#"{"$type":"blue.catbird.chat.defs#eventEnvelope","previousCursor":"a","cursor":"b","createdAt":"2026-09-19T00:00:00.000Z","payload":{"$type":"blue.catbird.chat.defs#watermarkEvent","issuedAt":"2026-09-19T00:00:00.000Z"}}"#;
        let parsed = decode(raw).unwrap();
        assert_eq!(next_cursor("a", &parsed).unwrap(), Some("b".into()));
        assert!(next_cursor("x", &parsed).is_err());
        assert!(next_cursor("b", &parsed).is_err());
        assert!(decode(&raw.replace("watermarkEvent", "futureEvent")).is_err());
        assert!(
            decode(&raw.replace("\"cursor\":\"b\"", "\"cursor\":\"b\",\"cursor\":\"c\"")).is_err()
        );
    }
}

#[cfg(all(test, feature = "inventory-worker-tests"))]
mod custody_tests {
    use super::*;
    use crate::request_runtime::tests::{
        enqueue, initialize, installRequestFacadeFixture, Restore,
    };
    use serde_json::json;
    use wasm_bindgen_test::*;
    #[wasm_bindgen(inline_js = r#"
    let previousSocket;
    export function installSocketFixture() {
      previousSocket=globalThis.WebSocket;
      globalThis.WebSocket=class {
        constructor(url){this.url=url;this.readyState=1;queueMicrotask(()=>this.onopen?.(new Event('open')));}
        close(){this.readyState=3;}
      };
    }
    export function restoreSocketFixture(){globalThis.WebSocket=previousSocket;}
    export async function yieldSocketFixture(){await new Promise(resolve=>setTimeout(resolve,10));}
    "#)]
    extern "C" {
        fn installSocketFixture();
        fn restoreSocketFixture();
        async fn yieldSocketFixture();
    }
    struct SocketRestore;
    impl Drop for SocketRestore {
        fn drop(&mut self) {
            restoreSocketFixture();
        }
    }
    fn ticket() {
        enqueue(
            "getSubscriptionTicket",
            json!({"ticket":"t".repeat(32),"endpoint":"wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents","expiresAt":"2099-01-01T00:00:00.000Z","inventoryScope":{"supportedProtocolVersions":["1","2"],"scopeDigest":B64.encode([7u8;32])}}),
        );
    }
    fn pages() {
        let page = json!({"items":[],"hasMore":false,"inventorySessionId":"s".repeat(32),"snapshotEventCursor":"cursor","snapshotExpiresAt":"2099-01-01T00:00:00.000Z","inventoryScope":{"supportedProtocolVersions":["1","2"],"scopeDigest":B64.encode([7u8;32])}});
        enqueue("getPendingWelcomes", page.clone());
        enqueue("getLeafRecoveryInbox", page);
    }
    fn frame(previous: &str, next: &str) -> String {
        json!({"$type":"blue.catbird.chat.defs#eventEnvelope","previousCursor":previous,"cursor":next,"createdAt":"2026-09-19T00:00:00.000Z","payload":{"$type":"blue.catbird.chat.defs#watermarkEvent","issuedAt":"2026-09-19T00:00:00.000Z"}}).to_string()
    }
    async fn socket() -> CanonicalSubscription {
        let noop = js_sys::Function::new_no_args("");
        connect(
            uuid::Uuid::new_v4().to_string(),
            noop.clone(),
            noop.clone(),
            noop,
        )
        .await
        .unwrap()
    }
    #[wasm_bindgen_test]
    async fn exact_inventory_subscription_queue_preserves_protected_cursor_on_failure_and_restart()
    {
        installRequestFacadeFixture("{}");
        let _restore = Restore;
        installSocketFixture();
        let _socket_restore = SocketRestore;
        let owner = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        let path = format!("subscription-{}", uuid::Uuid::new_v4());
        initialize(&path, owner).await;
        pages();
        ticket();
        let subscription = socket().await;
        let c = &subscription.consumer;
        c.enqueue(frame("cursor", "second"));
        c.enqueue(frame("second", "third"));
        for _ in 0..100 {
            if !c.running.get() {
                break;
            }
            yieldSocketFixture().await;
        }
        assert!(!c.closed.get());
        assert_eq!(c.fence.borrow().0.cursor, "third");
        let ctx = c.runtime.mls_context();
        let durable = ctx
            .request_value("subscriptionCursor", &c.actor)
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<CursorFence>(&durable)
                .unwrap()
                .cursor,
            "third"
        );
        c.enqueue(frame("gap", "fourth"));
        for _ in 0..100 {
            if !c.running.get() {
                break;
            }
            yieldSocketFixture().await;
        }
        assert!(c.closed.get());
        assert_eq!(
            ctx.request_value("subscriptionCursor", &c.actor)
                .unwrap()
                .unwrap(),
            durable
        );
        let actor = c.actor.clone();
        drop(subscription);
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(&path, owner).await;
        let (_, runtime) = request_runtime::current_engine().unwrap();
        assert_eq!(
            runtime
                .mls_context()
                .request_value("subscriptionCursor", &actor)
                .unwrap()
                .unwrap(),
            durable
        );
        ticket();
        let first = socket().await;
        ticket();
        let second = socket().await;
        assert!(first.consumer.current().await.is_err());
        assert!(second.consumer.current().await.is_ok());
        let exact = second.consumer.fence.borrow().1.clone();
        second
            .consumer
            .enqueue(frame("cursor", "second").replace("watermarkEvent", "unknownEvent"));
        for _ in 0..100 {
            if !second.consumer.running.get() {
                break;
            }
            yieldSocketFixture().await;
        }
        assert!(second.consumer.closed.get());
        assert_eq!(
            runtime
                .mls_context()
                .request_value("subscriptionCursor", &actor)
                .unwrap()
                .unwrap(),
            exact
        );
    }
}
