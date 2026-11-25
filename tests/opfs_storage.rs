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
    assert!(pool.capacity() >= 128);
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
        ([true; 3], [true; 3], [true; 3]),
        "the 512-sector OPFS adapter must preserve sqlite3mc rollback across DELETE, PERSIST, and TRUNCATE"
    );
    // Drop and reacquire the actual OPFS SyncAccessHandles before reopening.
    let pool = sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        false,
    )
    .await
    .unwrap();
    pool.pause().unwrap();
    pool.resume().await.unwrap();
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

#[wasm_bindgen_test]
fn verified_erasure_scrubs_only_covered_frames_including_orphans() {
    use catbird_mls::client::deletion_authority::{AppliedAccountDeletion, StoredAccountDeletion};
    use catbird_mls::storage::{LabyrinthQueueRow, MessageRow};
    use serde_json::json;

    let db = WasmAccountDb::new(SqliteConn::open_in_memory(&"ad".repeat(32)).unwrap());
    let sender = "did:plc:fixture";
    let cid = "fixture-conversation";
    let applied = AppliedAccountDeletion {
        seq: 10,
        signed_at_ms: 1_000_000,
        operation_id: "first".into(),
        actor_device_id: Some("phone".into()),
    };
    let cutoff = applied.purge_bound_ms();
    let marker = StoredAccountDeletion::Signed(applied);
    db.write_tx(|tx| {
        for (id, seq, issued) in [("before", 1, cutoff), ("orphan", 2, cutoff),
                                   ("later", 3, cutoff + 1), ("afterseq", 11, cutoff)] {
            let receipt = json!({"sender_device_did_url": format!("{sender}#phone"),
                "seq": seq, "issued_at_ms": issued}).to_string();
            let evidence = json!({"labyrinth_frame_json":"fixture frame", "sequencer_receipt_json": receipt,
                "sender_did":sender, "created_at_ms":1});
            if id != "orphan" {
                tx.insert_message(&MessageRow {message_id: id.into(), conversation_id: cid.into(),
                    group_id: vec![], epoch: 1, seq, sender_did: sender.into(), sender_device_id: "phone".into(),
                    plaintext_json: "fixture frame".into(), created_at_ms: 1, is_own: false})?;
            }
            tx.put_labyrinth_state(&format!("native.message:{cid}:{id}"), &serde_json::to_vec(&evidence)?, 1)?;
            tx.enqueue_labyrinth_item(&LabyrinthQueueRow {item_id:id.into(), conversation_id:cid.into(),
                group_id_hex:"00".into(), seq, payload_bytes: serde_json::to_vec(&evidence)?, created_at_ms:1})?;
        }
        // The previous browser writer could leave orphan plaintext after deleting display rows.
        // Reopening with an already applied marker must repair exactly the same covered frames.
        tx.put_labyrinth_state(&catbird_mls::client::chat_wire::account_deletion_key(cid, sender),
            &marker.encode().unwrap(), 1)?;
        tx.repair_legacy_erasure_evidence(2)?;
        tx.repair_legacy_erasure_evidence(3)?;
        for (id, retained) in [("before",false),("orphan",false),("later",true),("afterseq",true)] {
            assert_eq!(tx.get_message(id)?.is_some(), retained);
            assert_eq!(tx.get_labyrinth_state(&format!("native.message:{cid}:{id}"))?.is_some(), retained);
        }
        let queue = tx.list_labyrinth_queue(Some(cid), 100)?;
        assert_eq!(queue.iter().map(|r| r.item_id.as_str()).collect::<Vec<_>>(), ["later","afterseq"]);
        Ok(())
    }).unwrap();
}

#[wasm_bindgen_test]
async fn space_uri_rewrite_covers_send_journals_and_staged_openings() {
    use catbird_mls::storage::space_uri_rewrite::SPACE_URI_REWRITE_MARKER_KEY;
    SqliteConn::initialize_opfs().await.unwrap();
    let path = format!("space-uri-rewrite-{}.db", uuid::Uuid::new_v4());
    let key = "ac".repeat(32);
    let legacy = "at://did:web:ds.example/space/blue.catbird.labyrinth.conversation/c1-0";
    let current = "at:space/did:web:ds.example/blue.catbird.labyrinth.conversation/c1-0";
    // Signed bytes that happen to hold a legacy-form URI must survive unchanged.
    let send = serde_json::json!({
        "body": {"$type": "blue.catbird.chat.defs#applicationSendBody", "sendCounter": 7,
                 "aad": {"note": legacy}},
        "archive": {"space_uri": legacy, "labyrinth_frame_json": format!("{{\"s\":\"{legacy}\"}}")},
    });
    let opening = serde_json::json!({
        "space_uri": legacy,
        "labyrinth_frame_json": format!("{{\"s\":\"{legacy}\"}}"),
        "sequencer_receipt_json": format!("{{\"space\":\"{legacy}\"}}"),
    });
    let rows = [
        ("application_send:c1:m1", send.to_string()),
        ("c33_pending_opening:c1", opening.to_string()),
        ("c33_pending_opening:c2", "archived".to_string()),
        // A similar key outside the journal prefixes is not touched.
        ("xapplication_send:c1:m1", send.to_string()),
    ];
    {
        let conn = SqliteConn::open(&path, &key).unwrap();
        for (k, v) in &rows {
            conn.exec_with_text_params(
                "INSERT OR REPLACE INTO account_meta(key, value_json, updated_at_ms) VALUES(?1, ?2, 0)",
                &[(1, *k), (2, v.as_str())],
            )
            .unwrap();
        }
        // A fresh database is already marked; clear it to model a pre-rewrite database.
        conn.exec_with_text_params(
            "DELETE FROM account_meta WHERE key = ?1",
            &[(1, SPACE_URI_REWRITE_MARKER_KEY)],
        )
        .unwrap();
    }
    let read = |conn: &SqliteConn, k: &str| -> String {
        conn.query_text(
            "SELECT value_json FROM account_meta WHERE key = ?1",
            &[(1, k)],
            1,
        )
        .unwrap()[0][0]
            .clone()
            .unwrap()
    };
    let expect = |conn: &SqliteConn| {
        let send_after: serde_json::Value =
            serde_json::from_str(&read(conn, "application_send:c1:m1")).unwrap();
        assert_eq!(send_after["archive"]["space_uri"], current);
        assert_eq!(
            send_after["body"], send["body"],
            "signed request body unchanged"
        );
        assert_eq!(
            send_after["archive"]["labyrinth_frame_json"],
            send["archive"]["labyrinth_frame_json"]
        );
        let opening_after: serde_json::Value =
            serde_json::from_str(&read(conn, "c33_pending_opening:c1")).unwrap();
        assert_eq!(opening_after["space_uri"], current);
        assert_eq!(
            opening_after["labyrinth_frame_json"],
            opening["labyrinth_frame_json"]
        );
        assert_eq!(
            opening_after["sequencer_receipt_json"],
            opening["sequencer_receipt_json"]
        );
        assert_eq!(read(conn, "c33_pending_opening:c2"), "archived");
        let other: serde_json::Value =
            serde_json::from_str(&read(conn, "xapplication_send:c1:m1")).unwrap();
        assert_eq!(other["archive"]["space_uri"], legacy);
        assert_eq!(read(conn, SPACE_URI_REWRITE_MARKER_KEY), "1");
    };
    {
        let conn = SqliteConn::open(&path, &key).unwrap();
        expect(&conn);
        // Re-running over already rewritten values changes nothing.
        conn.exec_with_text_params(
            "DELETE FROM account_meta WHERE key = ?1",
            &[(1, SPACE_URI_REWRITE_MARKER_KEY)],
        )
        .unwrap();
    }
    let conn = SqliteConn::open(&path, &key).unwrap();
    expect(&conn);
}
