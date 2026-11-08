//! Real dedicated-Worker OPFS checks. These are not host smoke tests.
#![cfg(target_arch = "wasm32")]
use std::rc::Rc;

use catbird_mls::{
    storage::driver_wasm::{WasmAccountDb, WasmSqlBackend},
    MLSError,
};
use catbird_mls_web::{SqliteConn, WasmSqliteError, WasmSqliteStorage};
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn encrypted_transaction_reopens_and_rollback_preserves_previous_state() {
    SqliteConn::initialize_opfs().await.unwrap();
    let pool = sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        false,
    )
    .await
    .unwrap();
    assert!(pool.get_capacity() >= 128);
    let path = format!("transaction-{}.db", uuid::Uuid::new_v4());
    let key = "ab".repeat(32);
    {
        let conn = SqliteConn::open(&path, &key).unwrap();
        WasmSqliteStorage::ensure_schema(&conn).unwrap();
        assert_eq!(
            conn.query_text("PRAGMA journal_mode;", &[], 1).unwrap(),
            vec![vec![Some("delete".into())]]
        );
        assert_eq!(
            conn.query_text("PRAGMA synchronous;", &[], 1).unwrap(),
            vec![vec![Some("2".into())]]
        );
        assert!(
            matches!(
                SqliteConn::open(&path, &key),
                Err(WasmSqliteError::Sqlite { code: 5, .. })
            ),
            "a second live connection must not take the same OPFS handle"
        );
        conn.transaction(|| -> Result<(), WasmSqliteError> {
            conn.put(b"crypto", b"prepared")?;
            conn.put(b"journal", b"exact signed bytes")
        })
        .unwrap();
        conn.ensure_durable().unwrap();
        let rollback: Result<(), WasmSqliteError> = conn.transaction(|| {
            conn.put(b"crypto", b"wrong")?;
            assert!(conn.ensure_durable().is_err());
            Err(WasmSqliteError::Serialization("injected failure".into()))
        });
        assert!(rollback.is_err());
    }
    let rollback_modes = (
        journal_mode_rollback_results("delete"),
        journal_mode_rollback_results("persist"),
        journal_mode_rollback_results("truncate"),
    );
    assert_eq!(
        rollback_modes,
        ([true; 3], [false, true, false], [false, true, false]),
        "the pinned VFS must preserve DELETE rollback and retain its known PERSIST/TRUNCATE defect"
    );
    // Drop and reacquire the actual OPFS SyncAccessHandles before reopening.
    let pool = sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        false,
    )
    .await
    .unwrap();
    pool.pause_vfs().unwrap();
    pool.unpause_vfs().await.unwrap();
    let conn = SqliteConn::open(&path, &key).unwrap();
    assert_eq!(conn.get(b"crypto").unwrap().unwrap(), b"prepared");
    assert_eq!(
        conn.get(b"journal").unwrap().unwrap(),
        b"exact signed bytes"
    );
    drop(conn);
    assert!(SqliteConn::open(&path, &"cd".repeat(32)).is_err());
    assert!(SqliteConn::open(&path, "").is_err());
}

fn open_with_journal_mode(mode: &str, scenario: &str) -> Rc<SqliteConn> {
    let path = format!("{scenario}-{mode}-{}.db", uuid::Uuid::new_v4());
    let conn = Rc::new(SqliteConn::open(&path, &"ef".repeat(32)).unwrap());
    conn.exec_raw(&format!("PRAGMA journal_mode = {mode};"))
        .unwrap();
    assert_eq!(
        conn.query_text("PRAGMA journal_mode;", &[], 1).unwrap(),
        vec![vec![Some(mode.into())]]
    );
    conn
}

fn raw_multi_page_rollback(mode: &str) -> bool {
    let conn = open_with_journal_mode(mode, "raw-rollback");
    let original = vec![b'o'; 16 * 1024];
    let changed = vec![b'x'; 16 * 1024];
    conn.transaction(|| -> Result<(), WasmSqliteError> {
        for key in [b"raw-a".as_slice(), b"raw-b", b"raw-c"] {
            conn.put(key, &original)?;
        }
        Ok(())
    })
    .unwrap();
    conn.exec_raw("BEGIN IMMEDIATE").unwrap();
    for key in [b"raw-a".as_slice(), b"raw-b", b"raw-c"] {
        conn.put(key, &changed).unwrap();
    }
    conn.exec_raw("ROLLBACK").unwrap();
    [b"raw-a".as_slice(), b"raw-b", b"raw-c"]
        .into_iter()
        .all(|key| conn.get(key).ok().flatten().as_deref() == Some(original.as_slice()))
}

fn write_tx_error_rollback(mode: &str) -> bool {
    let conn = open_with_journal_mode(mode, "write-tx-error");
    let db = WasmAccountDb::new(conn);
    let changed = "x".repeat(16 * 1024);
    let failed: Result<(), MLSError> = db.write_tx(|tx| {
        for key in ["error-a", "error-b", "error-c"] {
            tx.put_account_meta(key, &changed, 1)?;
        }
        Err(MLSError::Internal("injected rollback".into()))
    });
    failed.is_err()
        && ["error-a", "error-b", "error-c"]
            .into_iter()
            .all(|key| matches!(db.backend().get_account_meta(key), Ok(None)))
}

fn rollback_after_commit(mode: &str) -> bool {
    let conn = open_with_journal_mode(mode, "rollback-after-commit");
    let db = WasmAccountDb::new(conn);
    let original = "o".repeat(16 * 1024);
    let changed = "x".repeat(16 * 1024);
    db.write_tx(|tx| {
        for key in ["prior-a", "prior-b", "prior-c"] {
            tx.put_account_meta(key, &original, 2)?;
        }
        Ok(())
    })
    .unwrap();
    let failed: Result<(), MLSError> = db.write_tx(|tx| {
        for key in ["prior-a", "prior-b", "prior-c"] {
            tx.put_account_meta(key, &changed, 3)?;
        }
        Err(MLSError::Internal("injected rollback after commit".into()))
    });
    failed.is_err()
        && ["prior-a", "prior-b", "prior-c"].into_iter().all(|key| {
            db.backend().get_account_meta(key).ok().flatten().as_deref() == Some(original.as_str())
        })
}

fn journal_mode_rollback_results(mode: &str) -> [bool; 3] {
    [
        raw_multi_page_rollback(mode),
        write_tx_error_rollback(mode),
        rollback_after_commit(mode),
    ]
}
