//! Real Firefox `worker.terminate()` mid-transaction crash durability proof.
//!
//! Reproduces the exact encrypted OPFS SAH-pool crash scenario:
//! 1. Dedicated Worker #1 initializes `multipleciphers-opfs-sahpool` (`sqlite3mc` ChaCha20),
//!    commits 200 baseline 64-KiB rows (`12.5 MiB`), sets `PRAGMA cache_size = 5` and
//!    `PRAGMA cache_spill = ON`, begins an `IMMEDIATE` transaction, mutates 50 rows (`3.125 MiB`)
//!    so dirty encrypted pages spill into the OPFS database slot while pre-images populate the
//!    rollback journal slot, and signals the main page WITHOUT committing or closing.
//! 2. The main browser page calls `worker.terminate()` abruptly, killing Worker #1 mid-write
//!    with zero Rust `Drop`, `ROLLBACK`, or `sqlite3_close` execution.
//! 3. Dedicated Worker #2 confirms the hot journal slot still exists on OPFS prior to open,
//!    reopens the database with the same ChaCha20 key (`xCheckReservedLock == false` on fresh
//!    handle), verifies the hot journal was replayed and unlinked, runs `PRAGMA integrity_check`,
//!    and verifies all 200 × 64-KiB rows match the exact pre-transaction baseline byte-for-byte.
#![cfg(target_arch = "wasm32")]

use std::cell::RefCell;

use catbird_mls_web::{SqliteConn, WasmSqliteError, WasmSqliteStorage};
use rsqlite_vfs::VfsFilesManager;
use wasm_bindgen::{closure::Closure, prelude::wasm_bindgen, JsCast, JsValue};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const BASELINE_ROWS: usize = 200;
const MUTATED_ROWS: usize = 50;
const VALUE_LEN: usize = 64 * 1024;

thread_local! {
    // Intentionally holds the live connection in Worker #1 across postMessage so `Drop`
    // (`sqlite3_close`) never runs before `worker.terminate()` kills the Worker thread.
    static HELD_OPEN_TX_CONN: RefCell<Option<SqliteConn>> = const { RefCell::new(None) };
}

fn row_key(index: usize) -> Vec<u8> {
    format!("durability-row-{index:04}").into_bytes()
}

fn baseline_payload(index: usize) -> Vec<u8> {
    let mut out = vec![0u8; VALUE_LEN];
    let seed = (index as u32).wrapping_mul(0x9E37_79B9) ^ 0xA55A_5AA5;
    for (offset, byte) in out.iter_mut().enumerate() {
        let mix = seed
            .wrapping_add(offset as u32)
            .rotate_left(((offset ^ index) & 15) as u32);
        *byte = (mix ^ (mix >> 16)) as u8;
    }
    out
}

fn mutated_payload(index: usize) -> Vec<u8> {
    let mut out = baseline_payload(index);
    for byte in &mut out {
        *byte ^= 0xFF;
    }
    out
}

#[wasm_bindgen]
pub async fn opfs_crash_worker_stage_and_spill(
    db_path: String,
    key_hex: String,
) -> Result<JsValue, JsValue> {
    SqliteConn::initialize_opfs()
        .await
        .map_err(|err| JsValue::from_str(&format!("init_opfs: {err}")))?;
    let pool = sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        false,
    )
    .await
    .map_err(|err| JsValue::from_str(&format!("pool_install: {err}")))?;

    let conn = SqliteConn::open(&db_path, &key_hex)
        .map_err(|err| JsValue::from_str(&format!("open: {err}")))?;
    WasmSqliteStorage::ensure_schema(&conn)
        .map_err(|err| JsValue::from_str(&format!("ensure_schema: {err}")))?;

    let journal_mode = conn
        .query_text("PRAGMA journal_mode;", &[], 1)
        .map_err(|err| JsValue::from_str(&format!("journal_mode: {err}")))?;
    if journal_mode != vec![vec![Some("delete".to_string())]] {
        return Err(JsValue::from_str(&format!(
            "unexpected journal_mode: {journal_mode:?}"
        )));
    }

    conn.transaction(|| -> Result<(), WasmSqliteError> {
        for idx in 0..BASELINE_ROWS {
            conn.put(&row_key(idx), &baseline_payload(idx))?;
        }
        Ok(())
    })
    .map_err(|err| JsValue::from_str(&format!("baseline_commit: {err}")))?;
    conn.ensure_durable()
        .map_err(|err| JsValue::from_str(&format!("ensure_durable: {err}")))?;

    // Force dirty pages in the upcoming uncommitted transaction to spill straight into the
    // encrypted OPFS database file while pre-images are written to `<db_path>-journal`.
    conn.exec_raw("PRAGMA cache_size = 5; PRAGMA cache_spill = ON;")
        .map_err(|err| JsValue::from_str(&format!("cache_spill_pragma: {err}")))?;
    conn.exec_raw("BEGIN IMMEDIATE;")
        .map_err(|err| JsValue::from_str(&format!("begin_immediate: {err}")))?;

    for idx in 0..MUTATED_ROWS {
        conn.put(&row_key(idx), &mutated_payload(idx))
            .map_err(|err| JsValue::from_str(&format!("spill_put({idx}): {err}")))?;
    }

    // Prove the transaction is genuinely open and uncommitted, and that the hot rollback
    // journal slot exists on OPFS before the main page terminates this Worker.
    if conn.ensure_durable().is_ok() {
        return Err(JsValue::from_str(
            "expected ensure_durable() to fail while transaction is open",
        ));
    }
    let journal_name = format!("{db_path}-journal");
    let has_journal = pool
        .contains(&journal_name)
        .map_err(|err| JsValue::from_str(&format!("pool.contains(journal): {err}")))?;
    if !has_journal {
        return Err(JsValue::from_str(
            "expected spilled hot rollback journal in OPFS before worker.terminate()",
        ));
    }

    HELD_OPEN_TX_CONN.with(|slot| {
        *slot.borrow_mut() = Some(conn);
    });

    Ok(JsValue::from_str(
        &serde_json::json!({
            "staged_baseline_rows": BASELINE_ROWS,
            "spilled_mutated_rows": MUTATED_ROWS,
            "hot_journal_present_before_kill": has_journal,
        })
        .to_string(),
    ))
}

#[wasm_bindgen]
pub async fn opfs_crash_worker_reopen_and_verify(
    db_path: String,
    key_hex: String,
) -> Result<JsValue, JsValue> {
    SqliteConn::initialize_opfs()
        .await
        .map_err(|err| JsValue::from_str(&format!("TransientInit:{err}")))?;
    let pool = sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        false,
    )
    .await
    .map_err(|err| JsValue::from_str(&format!("TransientInit:{err}")))?;

    let journal_name = format!("{db_path}-journal");
    let had_hot_journal_before_open = pool
        .contains(&journal_name)
        .map_err(|err| JsValue::from_str(&format!("pool.contains pre-open: {err}")))?;
    if !had_hot_journal_before_open {
        return Err(JsValue::from_str(
            "hot rollback journal missing before reopen; worker termination did not interrupt an active spilled transaction",
        ));
    }

    // Critical gate: must NOT retry `SqliteConn::open`. On `sqlite-wasm-vfs 0.2.0` this single
    // open failed with SQLite code 11 (`database disk image is malformed`).
    let conn = SqliteConn::open(&db_path, &key_hex)
        .map_err(|err| JsValue::from_str(&format!("ReopenCorrupt: {err}")))?;

    let journal_remains_after_open = pool
        .contains(&journal_name)
        .map_err(|err| JsValue::from_str(&format!("pool.contains post-open: {err}")))?;
    if journal_remains_after_open {
        return Err(JsValue::from_str(
            "hot rollback journal still present after reopen; rollback journal was not replayed and unlinked",
        ));
    }

    let integrity = conn
        .query_text("PRAGMA integrity_check;", &[], 1)
        .map_err(|err| JsValue::from_str(&format!("integrity_check: {err}")))?;
    if integrity != vec![vec![Some("ok".to_string())]] {
        return Err(JsValue::from_str(&format!(
            "integrity_check failed: {integrity:?}",
        )));
    }

    let total_rows = conn
        .kv_count_all_rows()
        .map_err(|err| JsValue::from_str(&format!("kv_count_all_rows: {err}")))?;
    if total_rows != BASELINE_ROWS {
        return Err(JsValue::from_str(&format!(
            "expected {BASELINE_ROWS} rows after hot-journal rollback, got {total_rows}"
        )));
    }

    for idx in 0..BASELINE_ROWS {
        let actual = conn
            .get(&row_key(idx))
            .map_err(|err| JsValue::from_str(&format!("get({idx}): {err}")))?
            .ok_or_else(|| JsValue::from_str(&format!("missing baseline row {idx}")))?;
        let expected = baseline_payload(idx);
        if actual != expected {
            let matched_mutated = actual == mutated_payload(idx);
            return Err(JsValue::from_str(&format!(
                "row {idx} mismatch after worker.terminate() (len={}, matched_uncommitted_mutation={matched_mutated})",
                actual.len()
            )));
        }
    }

    // Confirm the recovered encrypted database remains writable for subsequent commits.
    conn.transaction(|| conn.put(b"post-recovery-canary", b"healthy"))
        .map_err(|err| JsValue::from_str(&format!("post_recovery_write: {err}")))?;
    conn.ensure_durable()
        .map_err(|err| JsValue::from_str(&format!("post_recovery_durable: {err}")))?;
    conn.remove(b"post-recovery-canary")
        .map_err(|err| JsValue::from_str(&format!("post_recovery_cleanup: {err}")))?;
    drop(conn);

    Ok(JsValue::from_str(
        &serde_json::json!({
            "had_hot_journal_before_open": had_hot_journal_before_open,
            "journal_remains_after_open": journal_remains_after_open,
            "integrity_check": "ok",
            "verified_rows": BASELINE_ROWS,
            "value_bytes_each": VALUE_LEN,
        })
        .to_string(),
    ))
}

fn eval_worker_driver_promise(db_path: &str, key_hex: &str) -> js_sys::Promise {
    let script = r#"
        (async (dbPath, keyHex) => {
            const origin = globalThis.location.origin;
            const resources = performance.getEntriesByType('resource').map(r => r.name);
            let jsUrl = resources.find(u => u.includes('wasm-bindgen-test') && !u.endsWith('.wasm'));
            let wasmUrl = resources.find(u => u.endsWith('.wasm'));
            if (!jsUrl) {
                for (const s of Array.from(document.querySelectorAll('script'))) {
                    if (s.src && s.src.includes('wasm-bindgen-test')) {
                        jsUrl = s.src;
                        break;
                    }
                }
            }
            if (!jsUrl) jsUrl = `${origin}/wasm-bindgen-test`;
            if (!wasmUrl) wasmUrl = `${origin}/wasm-bindgen-test_bg.wasm`;

            const isClassicGlobal = typeof globalThis.wasm_bindgen === 'function';
            const workerBootstrap = isClassicGlobal
                ? `
                    importScripts(${JSON.stringify(jsUrl)});
                    await wasm_bindgen(${JSON.stringify(wasmUrl)});
                    const api = wasm_bindgen;
                    self.postMessage({ type: 'ready' });
                    self.onmessage = async ({ data }) => {
                        try {
                            const out = await api[data.fn](data.dbPath, data.keyHex);
                            self.postMessage({ type: 'ok', value: out });
                        } catch (err) {
                            self.postMessage({ type: 'err', error: String(err && err.message ? err.message : err) });
                        }
                    };
                `
                : `
                    const mod = await import(${JSON.stringify(jsUrl)});
                    await mod.default(${JSON.stringify(wasmUrl)});
                    self.postMessage({ type: 'ready' });
                    self.onmessage = async ({ data }) => {
                        try {
                            const out = await mod[data.fn](data.dbPath, data.keyHex);
                            self.postMessage({ type: 'ok', value: out });
                        } catch (err) {
                            self.postMessage({ type: 'err', error: String(err && err.message ? err.message : err) });
                        }
                    };
                `;

            const spawnWorker = async () => {
                const blob = new Blob([workerBootstrap], { type: 'text/javascript' });
                const blobUrl = URL.createObjectURL(blob);
                const worker = isClassicGlobal
                    ? new Worker(blobUrl)
                    : new Worker(blobUrl, { type: 'module' });
                await new Promise((resolve, reject) => {
                    worker.onmessage = (ev) => {
                        if (ev.data && ev.data.type === 'ready') resolve();
                        else if (ev.data && ev.data.type === 'err') reject(new Error(ev.data.error));
                    };
                    worker.onerror = (ev) => reject(new Error(ev.message || 'worker bootstrap error'));
                });
                URL.revokeObjectURL(blobUrl);
                return worker;
            };

            const callWorker = (worker, fn) => new Promise((resolve, reject) => {
                worker.onmessage = ({ data }) => {
                    if (data.type === 'ok') resolve(JSON.parse(data.value));
                    else reject(new Error(data.error));
                };
                worker.onerror = (ev) => reject(new Error(ev.message || 'worker runtime error'));
                worker.postMessage({ fn, dbPath, keyHex });
            });

            // 1. Stage 200 baseline rows and spill 50 uncommitted 64-KiB mutations in Worker #1.
            const worker1 = await spawnWorker();
            const stageSummary = await callWorker(worker1, 'opfs_crash_worker_stage_and_spill');

            // 2. Abruptly kill Worker #1 mid-transaction (`worker.terminate()`).
            worker1.terminate();

            // 3. Spawn fresh Worker #2. Firefox releases a terminated Worker's Web Lock and
            // SyncAccessHandles asynchronously; retry ONLY transient pool-acquisition contention,
            // never database open/corruption errors.
            let verifySummary = null;
            for (let attempt = 0; attempt < 40; attempt++) {
                const worker2 = await spawnWorker();
                try {
                    verifySummary = await callWorker(worker2, 'opfs_crash_worker_reopen_and_verify');
                    worker2.terminate();
                    break;
                } catch (err) {
                    worker2.terminate();
                    const msg = String(err && err.message ? err.message : err);
                    if (msg.includes('TransientInit:') && attempt + 1 < 40) {
                        await new Promise(r => setTimeout(r, 100));
                        continue;
                    }
                    throw err;
                }
            }
            return JSON.stringify({
                userAgent: navigator.userAgent,
                stage: stageSummary,
                worker_terminated: true,
                reopen: verifySummary,
            });
        })
    "#;

    let factory = js_sys::eval(script).expect("valid worker driver JS");
    let func: js_sys::Function = factory.dyn_into().expect("async driver function");
    func.call2(
        &JsValue::UNDEFINED,
        &JsValue::from_str(db_path),
        &JsValue::from_str(key_hex),
    )
    .expect("driver invocation")
    .dyn_into()
    .expect("Promise return")
}

#[wasm_bindgen_test]
async fn firefox_worker_terminate_mid_transaction_rolls_back_hot_journal_without_corruption() {
    // Run two independent full `worker.terminate()` cycles against the same encrypted database
    // (matching the two-attempt Firefox reproduction in WEB-DUR-1).
    let _keep_closure_type_linked: Option<Closure<dyn FnMut(JsValue)>> = None;
    let db_path = format!("web-dur-1-{}.db", uuid::Uuid::new_v4());
    let key_hex = "c7".repeat(32);

    for cycle in 1..=2 {
        let raw =
            wasm_bindgen_futures::JsFuture::from(eval_worker_driver_promise(&db_path, &key_hex))
                .await
                .unwrap_or_else(|err| {
                    panic!("cycle {cycle} failed after worker.terminate(): {err:?}")
                });
        let summary_str = raw.as_string().expect("JSON summary string");
        web_sys::console::log_1(&JsValue::from_str(&format!(
            "WEB-DUR-1 cycle {cycle}: {summary_str}"
        )));
        let summary: serde_json::Value =
            serde_json::from_str(&summary_str).expect("valid JSON summary");
        assert_eq!(summary["worker_terminated"], true);
        assert_eq!(summary["stage"]["hot_journal_present_before_kill"], true);
        assert_eq!(summary["reopen"]["had_hot_journal_before_open"], true);
        assert_eq!(summary["reopen"]["journal_remains_after_open"], false);
        assert_eq!(summary["reopen"]["integrity_check"], "ok");
        assert_eq!(summary["reopen"]["verified_rows"], BASELINE_ROWS);
    }
}
