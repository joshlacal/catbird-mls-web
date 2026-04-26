# catbird-mls-web

Universal browser WASM package wrapping `catbird-mls` for web apps.

## Build

```bash
./build.sh        # release (with wasm-opt if available)
./build-dev.sh    # dev (faster, debug symbols)
```

Output lands in `pkg/`.

## JS Integration: Recovery Loop

Browser apps **MUST** call `catbird_mls_run_deferred_recovery()` on a periodic
cadence. This drives the deferred-recovery state machine that adopts
server-initiated `groupResetEvent`s (spec §8.5 Phase 1) — without it, a
conversation that lands in `ResetPending` will never finish healing.

Recommended cadence:

- **Every 30 seconds** via `setInterval` while the page is in the foreground.
- **On `visibilitychange="visible"`** so the loop runs immediately when the
  user returns to the tab (the periodic timer is paused/throttled in
  background tabs by browsers).

Example:

```ts
import { catbird_mls_run_deferred_recovery } from "catbird-mls-web";

const RECOVERY_INTERVAL_MS = 30_000;
let timer: number | undefined;

async function tick() {
  try {
    const result = await catbird_mls_run_deferred_recovery();
    // result is { touched: number } — count of ResetPending convos processed.
  } catch (err) {
    console.warn("[catbird-mls-web] deferred recovery failed:", err);
  }
}

function start() {
  if (timer) return;
  timer = window.setInterval(tick, RECOVERY_INTERVAL_MS);
  void tick(); // run immediately on start
}

function stop() {
  if (timer) {
    window.clearInterval(timer);
    timer = undefined;
  }
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    void tick();
    start();
  } else {
    stop();
  }
});

// Kick off after init.
start();
```

The function is a no-op when no conversations are in `ResetPending`, so
running it every 30s is cheap. Each call:

1. Lists all conversations for the current user.
2. For each in `ResetPending`, tries Welcome → External Commit
   (`try_join_group_internal`).
3. If both fail, runs first-responder bootstrap: fetches the roster via
   `getConvos`, builds a local MLS group at the predetermined `newGroupId`
   via `WasmMLSContext::create_group_with_id`, and submits to
   `bootstrapResetGroup`. Race-winner clears `reset_pending`; race-loser
   (HTTP 409 `AlreadyBootstrapped`) drops the local pre-bootstrap group and
   leaves `reset_pending` for the next loop's Welcome retry.
