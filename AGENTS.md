# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with `catbird-mls-web`.

## Overview

`catbird-mls-web` is the **browser WASM wrapper** around the shared `catbird-mls` MLS orchestrator. It compiles the same Rust core that powers Catbird iOS and catmos desktop into a `wasm32-unknown-unknown` `cdylib`, exposing a flat `#[wasm_bindgen]` API for any web app to consume.

- Crate: `catbird-mls-web` (`crate-type = ["cdylib"]`), edition 2021.
- Core dependency: `catbird_mls = { path = "../catbird-mls", default-features = false, features = ["browser"] }`. `browser` enables `labyrinth`; the deterministic-simulation features (`sim`, `plant_*`, `test-utils`) are never enabled here, so `buggify!` compiles to `false` and planted bugs cannot activate. This crate is a **thin adapter** — it does NOT reimplement MLS. It provides browser-native implementations of the orchestrator's traits (storage, credentials, API client) and re-exports the orchestrator surface as WASM functions. For MLS internals (epoch handling, recovery policy, OpenMLS), see `../catbird-mls/AGENTS.md`.
- ATProto request/response types come from `catbird-atproto` (shared generated Jacquard types).

Don't duplicate orchestrator logic here. If a behavior should be shared across iOS/desktop/web, it belongs in `catbird-mls`; this crate only owns the browser adapters and the JS-facing ABI.

## Build

Requires `wasm-pack` and the `wasm32-unknown-unknown` target (pinned in `rust-toolchain.toml`).

```bash
./build.sh        # release — wasm-pack build --release, then wasm-opt -Oz if available
./build-dev.sh    # dev — wasm-pack build --dev (faster, debug symbols)
./test-native.sh  # native crate smoke tests; WASM-only dependencies excluded
./test-wasm.sh    # wasm-bindgen tests in headless Firefox
./test-tooling-config.sh # guard against Unix-only global Cargo overrides
```

Both emit to `pkg/` (gitignored, regenerated from source). `build.sh` runs `wasm-opt -Oz` only if `wasm-opt` is on `PATH` and skips that final pass otherwise; install binaryen for size-sensitive builds.

Fast iteration without producing a package:

```bash
AR_wasm32_unknown_unknown="$PWD/build-tools/wasm-ar" \
cargo check --target wasm32-unknown-unknown       # Unix type-check only
cargo test --lib                                      # non-wasm unit tests
./test-wasm.sh                                      # wasm-bindgen-test (archiver configured)
```

The Unix WASM build/test scripts route `AR_wasm32_unknown_unknown` through
`build-tools/wasm-ar`. This keeps `sqlite-wasm-rs` from invoking a broken
toolchain-manager `~/.swiftly/bin/llvm-ar` shim; the probe selects LLVM tools
from the active Rust toolchain or another installed Rust toolchain. There is
no unconditional `.cargo/config.toml` override, preserving Cargo's native
Windows archiver default. `test-tooling-config.sh` guards this invariant. The
`sqlite-wasm-rs` and shared `catbird_mls` crates are declared only for
`wasm32`, keeping native smoke tests from pulling in `audiopus_sys` or CMake.

If a transitive dep pulls `audiopus_sys` (or any CMake 4.x policy error like `CMP0114`), prefix with `CMAKE_POLICY_VERSION_MINIMUM=3.5` (see workspace AGENTS.md backlog item N2).

## WASM API Surface

The generated `pkg/catbird_mls_web.d.ts` is the **single source of truth** for the JS/TS contract. There is no hand-written `.d.ts` shim. Regenerate it by rebuilding — never hand-edit `pkg/`.

Entry points are defined with `#[wasm_bindgen]` in `src/lib.rs` (~45 exports). Grouped:

- **Lifecycle / session / auth**: `init` (`#[wasm_bindgen(start)]` panic hook), `catbird_mls_init(config)`, `catbird_mls_set_auth(did, token)`, `catbird_mls_clear_auth()`, `catbird_mls_try_restore_session()`, `catbird_mls_setup()`, `catbird_mls_ping()`.
- **Conversations**: `catbird_mls_list_conversations`, `catbird_mls_create_conversation`, `catbird_mls_join_group`, `catbird_mls_leave_conversation`, `catbird_mls_get_group_metadata`, `catbird_mls_update_group_metadata`, `catbird_mls_update_cursor`.
- **Messages**: `catbird_mls_send_message`, `catbird_mls_messages`, `catbird_mls_fetch_new_messages`, `catbird_mls_send_reaction`, `catbird_mls_send_typing`.
- **Attachments**: `catbird_mls_send_image`, `catbird_mls_get_image_attachment`.
- **Members / roster**: `catbird_mls_get_members`, `catbird_mls_add_group_members`, `catbird_mls_add_participants`, `catbird_mls_remove_participants`, `catbird_mls_promote_member`, `catbird_mls_demote_member`, `catbird_mls_check_opt_in_status`, `catbird_mls_search_users`, `catbird_mls_get_profiles`.
- **Realtime (WebSocket)**: `catbird_mls_subscribe(convo_id, on_message, on_event, on_status)` / `catbird_mls_unsubscribe`, plus lower-level `connect(...)` returning a `WsSubscription` handle (call `.close()` to disconnect).
- **Key packages / recovery**: `catbird_mls_replenish_key_packages`, `catbird_mls_start_background_tasks(interval_ms)` / `catbird_mls_stop_background_tasks()` / `catbird_mls_background_tasks_running()` (crate-owned deferred-recovery timer — the default contract), `catbird_mls_run_deferred_recovery` (manual/on-demand tick; see Consumers).
- **Field-level (envelope) crypto** (`js_name` camelCase): `setContentRootKey`, `clearContentRootKey`, `encryptMessagePayload`, `decryptMessagePayload`, `computeMessageHmac`, `verifyMessageHmac` — the per-conversation payload encryption layer, wire-compatible with catmos desktop.
- **Clean-slate client** (`WasmMlsClient`, `src/wasm_client.rs`, `wasm_client_mutations.rs`, `wasm_client_sync.rs`): `openAsync`, `setAuthToken`, `evaluateSpacesEligibility(pdsSupportsSpaces, grantedScopes)`, `enrollDevice(pdsSupportsSpaces, grantedScopes)`, conversations/messages/requests/members, direct-request accept/decline, `acknowledgeEntriesUpTo`, and Labyrinth (`labyrinthStatus`, `flushLabyrinthQueue`, `setupRecoveryCode`, `restoreWithRecoveryCode`). Eligibility uses Rust `catbird_mls::REQUIRED_LABYRINTH_OAUTH_SCOPES`: sessions holding only the retired `space:blue.catbird.labyrinth.mailbox?manage=create&manage=delete` / `space:blue.catbird.labyrinth.conversation?authority=*` scopes are ineligible and must re-authorize. `enrollDevice` is idempotent (keeps an enrolled signer; a retry after a lost response resumes from the DS's state). A C33 opening pruned before import is verified, recorded once with consent `C33_OPENING_UNAVAILABLE`, and never re-fetched; `acceptDirectRequest` on it fails with `OpeningUnavailable`.
- `WasmMlsClient.createGroup`, `sendMessage`, `addGroupMembers` and `removeGroupMember` have no local-only or silent no-op path. A conversation, message or device ID that is not UUIDv4 fails with `Invalid input`, and so does an `addGroupMembers` call with no other account. A missing auth token fails with `Invalid state`. Both are checked before any local or DS effect. A conversation missing locally fails with `Group not found`. On remove, a target with no leaf fails with `Member not found` and an unenrolled device with `Invalid state`. A receiptless queued row is never written.
- `WasmMlsClient.sendMessage` reserves the MLS sender generation, the next `sendCounter` (`account_meta` `send_counter:{conversationId}`, signed into the body) and a send journal (`account_meta` `application_send:{conversationId}:{messageId}`) in one write transaction before any HTTP. A retry of the same message ID resubmits the journaled bytes. A `StaleSend` refusal discards them and the message goes out once more as a fresh frame with a new counter. A second refusal fails with `Invalid state: StaleSend`. When a response was lost, sync restores the send from its journal, because a device cannot decrypt its own ciphertext.
- Sync records a current-epoch application entry that OpenMLS can never decrypt (`UnableToDecrypt`, for example a generation outside the sender-ratchet window) only if its outer signed request verifies. It writes a `message.undecryptable` gap row and `labyrinth_state` evidence (`native.undecryptable:{conversationId}:{messageId}`), advances the cursor, and keeps applying later entries. It never replaces a stored row and never forces a rejoin.
- The `catbird_mls_*` functions are re-exported through `src/browser_exports.rs`, which captures the session before creating each Promise, so neither direct calls nor queued Worker calls can adopt a replacement session.

### Init ordering (load-bearing)

```ts
await catbird_mls_init(config);             // open encrypted SQLite, load groups
catbird_mls_set_auth(did, token);           // inject ATProto bearer token
await catbird_mls_setup();                  // register device / replenish key packages
catbird_mls_start_background_tasks(30_000); // crate-owned deferred-recovery timer
```

`InitConfig` (deserialized from a JS object, camelCase keys):

| field | default | notes |
|-------|---------|-------|
| `baseUrl` | — (required) | mls-ds base URL |
| `storagePrefix` | `"catbird_mls"` | localStorage key prefix |
| `dbPrefix` | `"catbird-mls"` | SQLite file prefix (`<dbPrefix>-app.db`) |
| `proxyDid` | `did:web:chat.catbird.blue#atproto_mls` (`api_client::DEFAULT_ATPROTO_PROXY_DID`) | ATProto proxy DID header |
| `mlsDbKey` | localStorage-derived | hex 256-bit DB key. **REQUIRED in Worker mode** (localStorage is inaccessible there). |

## Architecture (browser adapters)

All persistent state lives in **one shared encrypted SQLite database** (`sqlite-wasm-rs` + `sqlite3mc` ChaCha20, backed by the **OPFS SAH (SyncAccessHandle pool) VFS**). A single `SqliteConn` (`src/sqlite_conn.rs`) is opened in `catbird_mls_init()` and shared via `Rc` across three trait adapters — each owns its tables, all `ensure_schema` are idempotent:

| Adapter | File | Implements (from `catbird_mls::orchestrator`) | Tables |
|---------|------|-----------------------------------------------|--------|
| Storage | `src/storage.rs` | `MLSStorageBackend` | `conversations`, `messages`, `sync_cursors`, `group_states` |
| OpenMLS KV | `src/mls_storage.rs` | OpenMLS `StorageProvider` | OpenMLS key-value rows |
| Credentials | `src/credentials.rs` | `CredentialStore` | `credentials` (signing key, MLS DID, device UUID — as encrypted BLOBs) |

- **MLS context**: `src/wasm_mls_context.rs` (`WasmMLSContext`) — the WASM equivalent of the native `MLSContext`, driving OpenMLS (`openmls` `js` feature, `libcrux` crypto). On `init` it reloads persisted groups from `group_states` into the in-memory cache so they survive page refreshes.
- **Network**: `src/api_client.rs` (`WasmApiClient` impl `MLSAPIClient`) — `reqwest` with `rustls-tls-webpki-roots`, fetch-backed in WASM. Uses `catbird-atproto` lexicon types. Sends the ATProto proxy DID header.
- **WebSocket**: `src/websocket.rs` — browser-native `web_sys::WebSocket` event callbacks (no tokio). Single-threaded; handler closures run on the JS event loop. MLS-encrypted frames are decrypted inline via the thread-local `STATE`; undecryptable frames (wrong epoch / pre-join) are silently skipped.
- **Auth / session**: bearer token injected via `catbird_mls_set_auth` and persisted to `localStorage` (`src/lib.rs`); the MLS DB key is derived/persisted in `localStorage` keyed by `storagePrefix` (or supplied via `mlsDbKey` for Workers).
- **State**: WASM is single-threaded — global `AppState` is a `thread_local!` + `RefCell`, no `Mutex`.

## Consumers

`catmos` (Tauri 2 + SvelteKit) is the primary consumer. It resolves `import … from 'catbird-mls-web'` two ways, both pointing at this crate's `pkg/`:

- **Bundling**: `catmos/vite.config.ts` → `resolve.alias['catbird-mls-web'] = '../catbird-mls-web/pkg/catbird_mls_web.js'` (plus `server.fs.allow` for the out-of-root path).
- **Type-checking**: `catmos` `tsconfig` `paths['catbird-mls-web'] = '../catbird-mls-web/pkg/catbird_mls_web.d.ts'`. (`svelte.config.js` is `adapter-static` only — there is no `kit.alias`.)

catmos loads the module inside a Comlink-wrapped Web Worker (`catmos/src/lib/mls-worker.ts`). Because Workers have no `localStorage`, catmos passes `mlsDbKey` in `InitConfig`. See `catmos/AGENTS.md` for the desktop↔web bridge (`src/lib/wasm.ts`).

After changing the Rust ABI, rebuild `pkg/` and re-run `npm run check` in catmos to catch type drift before declaring done.

### Deferred-recovery loop (required, not optional)

Browser apps **MUST** call `catbird_mls_start_background_tasks(interval_ms)` once after `catbird_mls_setup()` (recommended: `30_000`). The crate then owns the repeating timer that drives the deferred-recovery state machine adopting server-initiated `groupResetEvent`s (spec §8.5 Phase 1). Without it, a conversation in `ResetPending` never heals. Each tick is a no-op when nothing is pending (cheap); per-tick errors are logged and swallowed so one failure never kills the loop; restarting replaces the existing timer (never stacks); `catbird_mls_stop_background_tasks()` tears it down (idempotent).

`catbird_mls_run_deferred_recovery()` remains exported for **on-demand** ticks — call it on `visibilitychange === "visible"` so recovery runs immediately when the user returns to a throttled background tab. Hand-rolling your own `setInterval` around it is no longer the contract. The manual export shares the loop's re-entrancy guard (a call while a pass is in flight resolves to `{ touched: 0, alreadyRunning: true }` rather than running concurrently), and every pass runs under a deadline (2× `interval_ms` for timer ticks, 60s for manual calls) that cancels a stalled pass (`{ touched: 0, timedOut: true }`) so a hung fetch can never wedge the loop. Full rationale and a copy-paste TS snippet are in `README.md`.

## Gotchas

- **Worker context is required; COOP/COEP is NOT.** `catbird_mls_init()` must run inside a Web Worker (lib logs "Ensure `catbird_mls_init()` runs inside a Worker" when SQLite is unavailable). The OPFS SAH-pool VFS uses synchronous `SyncAccessHandle`s and deliberately avoids `SharedArrayBuffer`/Atomics, so **cross-origin isolation (COOP/COEP) is not needed** — catmos ships none. (Contrast: `SharedArrayBuffer`-based VFS approaches would require it.)
- **ABI drift vs `catbird-atproto`.** `api_client.rs` and `wasm_mls_context.rs` consume generated Jacquard types; when `catbird-atproto` regenerates (renamed/removed fields), `cargo check --target wasm32-unknown-unknown` breaks. Reconcile against the regenerated core / lexicon — never hand-patch generated types.
- **No state portability with desktop.** Web uses OPFS-backed SQLite; catmos desktop uses native SQLCipher. The field-level envelope crypto is wire-compatible, but the on-disk databases are not interchangeable. Document any divergence you find.
- **No IndexedDB migration.** Storage moved from IndexedDB to encrypted SQLite; there is no migration path — users with old IndexedDB data must re-login. Old IDBs are left for browser GC.
- **Voice/media not exposed.** No audio codecs in the WASM surface; `audiopus_sys` is not a dependency of this crate.
- **getrandom triple-pin.** `Cargo.toml` declares `getrandom` 0.2 (`js`), 0.3 and 0.4 (`wasm_js`) under aliases so Cargo unifies WASM RNG features across semver-incompatible versions pulled by `hpke-rs`/`rand`. Don't remove these.
- `wasm-opt` absence silently downgrades `build.sh` to a non-optimized release artifact — install binaryen for size-sensitive builds.
- **Vendored contract artifacts.** `src/generated/blue.catbird.chat.defs.json` and the signing/contract vector fixtures are byte copies from `catbird-mls`, synced by `python3 scripts/sync-chat-artifacts.py --core-revision <rev>` (which also rewrites `tests/fixtures/chat-artifact-provenance.json`). `cargo test --test provenance` (native) fails on drift. The current unsealed Task 4 R3 artifact candidate records exact `catbird-mls` revision `f609cd3413eff8dc291f25e607290627c16c4a0e`; `pkg/` was rebuilt from that source with `catbird-atproto` `971fd048b4ab2128b8d5b2c35f1be7885abfa1ce` and `labyrinth` `276c0972a05eb96f87509e8916e0e51ac46ac154`. It is not a published or release-qualified artifact; re-sync and rebuild after any source change.
- **Known WASM failures.** The Task 4 R3 artifact gate retains only the same three dedicated-worker OPFS window-runner failures and two unsupported blob-operation fixtures as the exact R2 baseline; every other Firefox target passes.

## Coding Style

- `cargo fmt` + `cargo clippy --target wasm32-unknown-unknown` before committing.
- WASM is single-threaded: prefer `Rc`/`RefCell`/`thread_local!` over `Arc`/`Mutex`; never block the JS event loop.
- Keep this crate a thin adapter — push shared logic into `catbird-mls`.
- Errors cross the boundary as `JsValue` (string); use the `js_err!` macro in `lib.rs`.
- Adapter modules implement orchestrator traits — match those signatures exactly rather than inventing parallel surfaces.
