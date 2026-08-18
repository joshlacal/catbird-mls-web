# catbird-mls-web

Universal browser WASM package wrapping `catbird-mls` for web apps.

## Build

```bash
./build.sh        # release (with wasm-opt if available)
./build-dev.sh    # dev (faster, debug symbols)
./test-native.sh  # host crate smoke tests; WASM-only dependencies excluded
./test-wasm.sh    # wasm-bindgen tests in headless Firefox
```

The Unix WASM build/test scripts inject a target-local archiver probe for
`wasm32-unknown-unknown`. This avoids relying on a toolchain-manager shim such
as `~/.swiftly/bin/llvm-ar`; `build-tools/wasm-ar` selects a usable LLVM
archiver from the active Rust toolchain or another installed Rust toolchain.
There is no unconditional `.cargo/config.toml` archiver override, so native
Windows Cargo builds retain Cargo's platform default. Run
`./test-tooling-config.sh` to check this invariant.
The encrypted `sqlite-wasm-rs` dependency and shared `catbird_mls` adapter are
WASM-target-only. This keeps host smoke tests from building the OPFS SQLite
amalgamation, native Opus, or its CMake dependency at all.

Output lands in `pkg/`.

## JS Integration: Recovery Loop

Browser apps **MUST** start the crate-owned background task loop once after
setup. This drives the deferred-recovery state machine that adopts
server-initiated `groupResetEvent`s (spec §8.5 Phase 1) — without it, a
conversation that lands in `ResetPending` will never finish healing.

```ts
import {
  catbird_mls_start_background_tasks,
  catbird_mls_stop_background_tasks,
  catbird_mls_run_deferred_recovery,
} from "catbird-mls-web";

// After catbird_mls_init / set_auth / setup — the crate owns the timer.
// Runs one recovery tick immediately, then every 30s. Per-tick errors are
// logged to the console and swallowed; one failed tick never kills the loop.
// Calling start again replaces the running timer (restart semantics — timers
// never stack). interval_ms must be > 0.
catbird_mls_start_background_tasks(30_000);

// Browsers throttle timers in background tabs, so also run an on-demand tick
// when the user returns to the tab:
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    void catbird_mls_run_deferred_recovery().catch((err) =>
      console.warn("[catbird-mls-web] deferred recovery failed:", err)
    );
  }
});

// On logout/teardown (idempotent; terminating the Worker also kills it):
catbird_mls_stop_background_tasks();
```

> **Note (Workers):** the WASM module runs inside a Web Worker — call
> `catbird_mls_start_background_tasks` from *inside* the Worker (it uses the
> global `setInterval`, available in both Window and Worker scopes), but the
> `visibilitychange` listener must live on the main thread (`document` does
> not exist in Workers) and forward to the Worker.

`catbird_mls_run_deferred_recovery()` remains exported for on-demand ticks
(visibility changes, tests, "retry now" buttons); hand-rolling your own
`setInterval` around it is no longer the contract. It shares the loop's
re-entrancy guard: if a recovery pass is already in flight it resolves to a
benign `{ touched: 0, alreadyRunning: true }` instead of running a second
pass concurrently. Every pass (timer or manual) runs under a deadline
(2× `interval_ms` for timer ticks; 60s for manual calls) — a stalled pass is
cancelled with `{ touched: 0, timedOut: true }` so the loop never wedges.
`catbird_mls_background_tasks_running()` reports whether the loop is active.

Each recovery tick is a no-op when no conversations are in `ResetPending`, so
a 30s cadence is cheap. Each tick:

1. Lists all conversations for the current user.
2. For each in `ResetPending`, tries Welcome → External Commit
   (`try_join_group_internal`).
3. If both fail, runs first-responder bootstrap: fetches the roster via
   `getConvos`, builds a local MLS group at the predetermined `newGroupId`
   via `WasmMLSContext::create_group_with_id`, and submits to
   `bootstrapResetGroup`. Race-winner clears `reset_pending`; race-loser
   (HTTP 409 `AlreadyBootstrapped`) drops the local pre-bootstrap group and
   leaves `reset_pending` for the next loop's Welcome retry.
