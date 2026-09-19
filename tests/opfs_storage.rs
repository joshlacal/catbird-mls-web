//! Real dedicated-Worker OPFS checks. These are not host smoke tests.
#![cfg(target_arch = "wasm32")]
use catbird_mls_web::{SqliteConn, WasmSqliteError, WasmSqliteStorage};
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn encrypted_transaction_reopens_and_rollback_preserves_previous_state() {
    SqliteConn::initialize_opfs().await.unwrap();
    let path = format!("transaction-{}.db", uuid::Uuid::new_v4());
    let key = "ab".repeat(32);
    {
        let conn = SqliteConn::open(&path, &key).unwrap();
        WasmSqliteStorage::ensure_schema(&conn).unwrap();
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
