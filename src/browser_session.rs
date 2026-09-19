//! Poll-scoped browser session authority. Logout/rebinding invalidates suspended
//! work even when the account DID and protected database remain the same.
use std::{
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    rc::{Rc, Weak},
    task::{Context, Poll, Waker},
};
use wasm_bindgen::JsValue;

thread_local! {
    static GENERATION: Cell<u64> = const { Cell::new(1) };
    static WAITERS: RefCell<Vec<Weak<RefCell<Option<Waker>>>>> = const { RefCell::new(Vec::new()) };
    static POLLED: Cell<Option<u64>> = const { Cell::new(None) };
}

pub(crate) fn advance() {
    GENERATION.with(|value| {
        value.set(
            value
                .get()
                .checked_add(1)
                .expect("browser session exhausted"),
        )
    });
    let waiters = WAITERS.with(|slot| std::mem::take(&mut *slot.borrow_mut()));
    for waiter in waiters.into_iter().filter_map(|item| item.upgrade()) {
        if let Some(waker) = waiter.borrow_mut().take() {
            waker.wake();
        }
    }
}
pub(crate) fn generation() -> u64 {
    GENERATION.with(Cell::get)
}
pub(crate) fn check() -> Result<(), &'static str> {
    if POLLED
        .with(Cell::get)
        .is_some_and(|captured| captured != generation())
    {
        Err("Browser session changed; suspended operation was cancelled")
    } else {
        Ok(())
    }
}
struct SessionFuture<F> {
    generation: u64,
    future: Pin<Box<F>>,
    wake: Rc<RefCell<Option<Waker>>>,
}
impl<F, T> Future for SessionFuture<F>
where
    F: Future<Output = Result<T, JsValue>>,
{
    type Output = Result<T, JsValue>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.generation != generation() {
            return Poll::Ready(Err(JsValue::from_str(
                "Browser session changed; suspended operation was cancelled",
            )));
        }
        *self.wake.borrow_mut() = Some(cx.waker().clone());
        let previous = POLLED.with(|slot| slot.replace(Some(self.generation)));
        struct Restore(Option<u64>);
        impl Drop for Restore {
            fn drop(&mut self) {
                POLLED.with(|slot| slot.set(self.0));
            }
        }
        let _restore = Restore(previous);
        let result = self.future.as_mut().poll(cx);
        if self.generation != generation() {
            Poll::Ready(Err(JsValue::from_str(
                "Browser session changed; suspended operation was cancelled",
            )))
        } else {
            result
        }
    }
}
pub(crate) fn run<F, T>(future: F) -> impl Future<Output = Result<T, JsValue>>
where
    F: Future<Output = Result<T, JsValue>>,
{
    let wake = Rc::new(RefCell::new(None));
    WAITERS.with(|slot| {
        let mut waiters = slot.borrow_mut();
        waiters.retain(|value| value.strong_count() > 0);
        waiters.push(Rc::downgrade(&wake));
    });
    SessionFuture {
        wake,
        generation: POLLED.with(Cell::get).unwrap_or_else(generation),
        future: Box::pin(future),
    }
}
pub(crate) fn spawn(future: impl Future<Output = ()> + 'static) {
    let guarded = run(async move {
        future.await;
        Ok(())
    });
    wasm_bindgen_futures::spawn_local(async move {
        let _ = guarded.await;
    });
}
