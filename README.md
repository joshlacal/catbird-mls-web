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

## Clean-slate client and contract artifacts

`WasmMlsClient` (`src/wasm_client*.rs`) is the clean-slate browser client: `openAsync`, `evaluateSpacesEligibility(pdsSupportsSpaces, grantedScopes)`, `enrollDevice(pdsSupportsSpaces, grantedScopes)`, conversation, message and request calls, and Labyrinth (`labyrinthStatus`, `flushLabyrinthQueue`, recovery-code restore). Eligibility uses Rust `catbird_mls::REQUIRED_LABYRINTH_OAUTH_SCOPES`. A session holding only the retired Labyrinth Space scopes (`space:blue.catbird.labyrinth.mailbox?manage=create&manage=delete`, `space:blue.catbird.labyrinth.conversation?authority=*`) is ineligible, and `enrollDevice` refuses it until the user re-authorizes with the explicit `action=`/`collection=` scopes. `enrollDevice` is idempotent: an enrolled device keeps its signer, and a retry after a lost `enrollDevice` response resumes from what the DS already holds.

The strict chat schema (`src/generated/blue.catbird.chat.defs.json`) and the signing/contract vector fixtures are copied verbatim from `catbird-mls`. `tests/fixtures/chat-artifact-provenance.json` records the source commit and hashes, and `cargo test --test provenance` fails on any drift from the sibling. After a `catbird-mls` contract change, re-sync and rebuild:

```bash
python3 scripts/sync-chat-artifacts.py --core-revision <catbird-mls revision>
./build.sh
```

The current unsealed Task 4 R2 artifact candidate records exact `catbird-mls` revision `e9f56c44878c0797b37724e425a02301649f8312`; its local `pkg/` was rebuilt with `catbird-atproto` `a6986331eee54f3f0ce16e7ea07dda63ab581dd7` and `labyrinth` `c8a6f6c76fd3ffe84137b5508a20a8258496f2ba`. This is not a published or release-qualified artifact; re-sync and rebuild after any source change. The browser build uses `catbird_mls` with `default-features = false, features = ["browser"]` (Labyrinth on, `sim` off), so `buggify!` is `false` and planted bugs cannot activate.

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
