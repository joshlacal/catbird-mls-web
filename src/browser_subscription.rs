//! Canonical account-scoped event transport. Events are hints: shared Rust
//! reconciliation verifies effects before protected event progress advances.
use crate::{
    request_runtime::{self, BrowserOrchestrator},
    *,
};
use catbird_mls::orchestrator::subscription::SubscriptionDispatchOutcome;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
};
use wasm_bindgen::closure::Closure;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

struct Consumer {
    runtime: Arc<BrowserOrchestrator>,
    session_epoch: u64,
    owner: String,
    connection_id: String,
    selected: String,
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

impl Consumer {
    fn stop(&self, status: &str) {
        self.closed.set(true);
        self.queue.borrow_mut().clear();
        let _ = self.ws.close();
        self.status(status);
    }

    fn status(&self, status: &str) {
        if self.session_epoch == crate::browser_session::generation() {
            if let Ok(value) = to_js(&serde_json::json!({"type": status})) {
                let _ = self.on_status.call1(&JsValue::NULL, &value);
            }
        }
    }

    async fn current(&self) -> Result<(), JsValue> {
        if self.closed.get() || self.session_epoch != crate::browser_session::generation() {
            return Err(error("Subscription closed"));
        }
        request_runtime::current(&self.owner, &self.runtime)?;
        match self
            .runtime
            .current_subscription_cursor()
            .await
            .map_err(error)?
        {
            Some(fence) if fence.connection == self.connection_id => Ok(()),
            _ => Err(error("Subscription was superseded")),
        }
    }

    async fn consume(&self, raw: &str) -> Result<(), JsValue> {
        self.current().await?;
        let outcome = self
            .runtime
            .apply_subscription_frame(raw)
            .await
            .map_err(error)?;
        self.current().await?;

        match outcome {
            SubscriptionDispatchOutcome::Typing {
                conversation_id,
                sender_did,
                is_typing,
            } => {
                if conversation_id == self.selected {
                    let event = serde_json::json!({
                        "type": "typing",
                        "data": {
                            "conversationId": conversation_id,
                            "senderDid": sender_did,
                            "isTyping": is_typing,
                        }
                    });
                    let _ = self.on_event.call1(&JsValue::NULL, &to_js(&event)?);
                }
            }
            SubscriptionDispatchOutcome::MessageAvailable {
                conversation_id,
                messages,
                ..
            } => {
                for message in messages
                    .into_iter()
                    .filter(|m| m.conversation_id == self.selected)
                {
                    let _ = self.on_message.call1(
                        &JsValue::NULL,
                        &to_js(&ui_message_from_orchestrator(message))?,
                    );
                }
                let event = serde_json::json!({
                    "type": "fetchNeeded",
                    "reason": "canonical",
                    "data": {
                        "conversationId": conversation_id,
                        "source": "canonical"
                    }
                });
                let _ = self.on_event.call1(&JsValue::NULL, &to_js(&event)?);
            }
            SubscriptionDispatchOutcome::Watermark { .. } => {
                let event = serde_json::json!({
                    "type": "fetchNeeded",
                    "reason": "canonical",
                    "data": {
                        "conversationId": serde_json::Value::Null,
                        "source": "canonical"
                    }
                });
                let _ = self.on_event.call1(&JsValue::NULL, &to_js(&event)?);
            }
            SubscriptionDispatchOutcome::AccessEnded { .. } => {
                let event = serde_json::json!({
                    "type": "fetchNeeded",
                    "reason": "canonical",
                    "data": {
                        "conversationId": serde_json::Value::Null,
                        "source": "canonical"
                    }
                });
                let _ = self.on_event.call1(&JsValue::NULL, &to_js(&event)?);
            }
            SubscriptionDispatchOutcome::OtherEvent {
                conversation_id, ..
            } => {
                let event = serde_json::json!({
                    "type": "fetchNeeded",
                    "reason": "canonical",
                    "data": {
                        "conversationId": conversation_id,
                        "source": "canonical"
                    }
                });
                let _ = self.on_event.call1(&JsValue::NULL, &to_js(&event)?);
            }
        }
        Ok(())
    }

    fn enqueue(self: &Rc<Self>, raw: String) {
        if self.closed.get() || self.session_epoch != crate::browser_session::generation() {
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
        crate::browser_session::spawn(async move {
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
        self.consumer.stop("closed");
    }
    pub fn is_open(&self) -> bool {
        !self.consumer.closed.get() && self.consumer.ws.ready_state() == WebSocket::OPEN
    }
}

impl Drop for CanonicalSubscription {
    fn drop(&mut self) {
        self.consumer.stop("closed");
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
    let ticket = runtime.prepare_subscription().await.map_err(error)?;
    request_runtime::current(&owner, &runtime)?;

    let fence = runtime
        .initialize_subscription_cursor(&ticket)
        .await
        .map_err(error)?;

    let mut url = reqwest::Url::parse(&ticket.endpoint).map_err(error)?;
    url.query_pairs_mut()
        .append_pair("ticket", &ticket.ticket)
        .append_pair("cursor", &ticket.event_cursor);

    let ws = WebSocket::new(url.as_str())?;
    let consumer = Rc::new(Consumer {
        runtime,
        session_epoch: crate::browser_session::generation(),
        owner,
        connection_id: fence.connection,
        selected,
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
        c.status("connected");
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
    let close = Closure::<dyn FnMut(CloseEvent)>::new(move |_| c.stop("closed"));
    ws.set_onclose(Some(close.as_ref().unchecked_ref()));

    Ok(CanonicalSubscription {
        consumer,
        _open: open,
        _message: message,
        _error: err,
        _close: close,
    })
}

#[cfg(all(test, feature = "inventory-worker-tests"))]
mod custody_tests {
    use super::*;
    use crate::request_runtime::tests::{
        enqueue, initialize, installRequestFacadeFixture, Restore,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde_json::json;
    use wasm_bindgen_test::*;
    // Crate-wide runner for the `inventory-worker-tests` feature (OPFS needs a worker).
    wasm_bindgen_test_configure!(run_in_dedicated_worker);

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
        let current = c
            .runtime
            .current_subscription_cursor()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.cursor, "third");

        c.enqueue(frame("gap", "fourth"));
        for _ in 0..100 {
            if !c.running.get() {
                break;
            }
            yieldSocketFixture().await;
        }
        assert!(c.closed.get());
        let current = c
            .runtime
            .current_subscription_cursor()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.cursor, "third");

        drop(subscription);
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(&path, owner).await;
        let (_, runtime) = request_runtime::current_engine().unwrap();
        let restored = runtime
            .current_subscription_cursor()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.cursor, "third");

        ticket();
        let first = socket().await;
        ticket();
        let second = socket().await;
        assert!(first.consumer.current().await.is_err());
        assert!(second.consumer.current().await.is_ok());

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
        let retained = runtime
            .current_subscription_cursor()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.cursor, "cursor");
        assert_eq!(retained.connection, second.consumer.connection_id);
    }

    #[wasm_bindgen_test]
    async fn protected_page_manifest_survives_reopen_and_rejects_substitution() {
        installRequestFacadeFixture("{}");
        let _restore = Restore;
        let owner = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        let path = format!("inventory-{}", uuid::Uuid::new_v4());
        initialize(&path, owner).await;
        pages();
        let (_, runtime) = request_runtime::current_engine().unwrap();
        let applied = runtime
            .synchronize_authenticated_inventory(false)
            .await
            .unwrap();
        drop(runtime);

        // Reopen the protected OPFS store. No welcome/recovery pages are queued,
        // so a network fetch would fail: success proves protected replay.
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(&path, owner).await;
        let (_, runtime) = request_runtime::current_engine().unwrap();
        let restored = runtime
            .synchronize_authenticated_inventory(false)
            .await
            .unwrap();
        assert_eq!(
            restored.inventory_session_id(),
            applied.inventory_session_id()
        );
        assert_eq!(restored.event_cursor(), applied.event_cursor());

        let actor = runtime.require_actor_device_id().await.unwrap();
        let ctx = runtime.mls_context();
        let journal: serde_json::Value = serde_json::from_slice(
            &ctx.request_value(&format!("inventory:{owner}"), &actor)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let id = journal["welcomes"][0]["id"].as_str().unwrap();
        let pages_ns = format!("inventoryPages:{owner}");
        let exact = ctx.request_value(&pages_ns, id).unwrap().unwrap();
        assert!(ctx
            .request_value_cas(&pages_ns, id, Some(&exact), b"substituted page")
            .unwrap());
        assert!(runtime
            .synchronize_authenticated_inventory(false)
            .await
            .is_err());
    }
}
