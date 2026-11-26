//! Browser databases written before 2026-11-24 hold Space URIs in the alpha form
//! `at://{did}/space/{type}/{skey}`. A PDS now accepts only `at:space/{did}/{type}/{skey}`, so
//! the stored bookkeeping is rewritten once when the database is opened. The native driver
//! has the same rewrite (`catbird-mls/tests/space_uri_rewrite_on_open.rs`).
#![cfg(target_arch = "wasm32")]

use catbird_mls::storage::driver_wasm::{WasmAccountDb, WasmSqlBackend as _};
use catbird_mls_web::SqliteConn;
use serde_json::{json, Value};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DID: &str = "did:plc:alice";
const SEQ: &str = "did:web:ds.example.test";

fn old(authority: &str, rest: &str) -> String {
    format!("at://{authority}/space/{rest}")
}

fn new(authority: &str, rest: &str) -> String {
    format!("at:space/{authority}/{rest}")
}

fn text(conn: &SqliteConn, sql: &str) -> String {
    conn.query_text(sql, &[], 1).unwrap()[0][0].clone().unwrap()
}

fn state(conn: &SqliteConn, key: &str) -> Value {
    serde_json::from_slice(&conn.get_labyrinth_state(key).unwrap().unwrap()).unwrap()
}

#[wasm_bindgen_test]
fn stored_space_uris_move_to_the_new_form_once() {
    let db = WasmAccountDb::new(SqliteConn::open_in_memory(&"ad".repeat(32)).unwrap());
    let conn = db.backend();
    let convo = "blue.catbird.labyrinth.conversation/c1-0";
    let mailbox = "blue.catbird.labyrinth.mailbox/self";
    // A record URI in an ordinary repository: has `/space/` nowhere, must not change.
    let post = "at://did:plc:alice/app.bsky.feed.post/3kabc";

    conn.exec_with_text_params(
        "INSERT INTO conversations(conversation_id, group_id, space_uri) VALUES(?1, x'00', ?2)",
        &[(1, "c1"), (2, &old(SEQ, convo))],
    )
    .unwrap();
    conn.exec_with_text_params(
        "INSERT INTO conversations(conversation_id, group_id, space_uri) VALUES(?1, x'00', ?2)",
        &[
            (1, "c2"),
            (2, &new(SEQ, "blue.catbird.labyrinth.conversation/c2-0")),
        ],
    )
    .unwrap();
    let pending = json!({
        "archive": { "space_uri": old(SEQ, convo) },
        "note": old(SEQ, convo),
    });
    conn.exec_with_text_params(
        "INSERT INTO pending_ops(op_kind, op_key, payload_json) VALUES('send', 'k1', ?1)",
        &[(1, &pending.to_string())],
    )
    .unwrap();
    let queued = json!({ "space_uri": old(SEQ, convo), "body": { "quoted": old(SEQ, convo) } });
    conn.exec_with_text_and_blob_params(
        "INSERT INTO labyrinth_queue(item_id, conversation_id, group_id_hex, seq, payload_bytes, \
         created_at_ms) VALUES(?1, 'c1', '00', 1, ?2, 0)",
        &[(1, "q1")],
        &[(2, queued.to_string().as_bytes())],
    )
    .unwrap();
    for (key, value) in [
        (
            "status_json",
            json!({ "mailbox_space_uri": old(DID, mailbox), "epoch_seq": 3 }),
        ),
        (
            "wasm.placements:acct",
            json!({ "c1": { "space": old(SEQ, convo) } }),
        ),
        (
            "wasm.writer_rev_floors:acct",
            json!({ old(SEQ, convo): "3lrev", post: "keep" }),
        ),
        (
            "device_signer_json",
            json!({ "untouched": old(SEQ, convo) }),
        ),
    ] {
        conn.put_labyrinth_state(key, value.to_string().as_bytes(), 0)
            .unwrap();
    }
    conn.put_account_meta(
        "direct_request_value_v2:labyrinthMailboxPlacement:r1",
        &json!({ "mailbox": old(DID, mailbox) }).to_string(),
        0,
    )
    .unwrap();
    conn.put_account_meta(
        "c33_pending_opening:c1",
        &json!({ "space_uri": old(SEQ, convo), "frame": old(SEQ, convo) }).to_string(),
        0,
    )
    .unwrap();

    db.write_tx(|tx| tx.rewrite_legacy_space_uris(7)).unwrap();

    assert_eq!(
        text(
            conn,
            "SELECT space_uri FROM conversations WHERE conversation_id = 'c1'"
        ),
        new(SEQ, convo)
    );
    assert_eq!(
        text(
            conn,
            "SELECT space_uri FROM conversations WHERE conversation_id = 'c2'"
        ),
        new(SEQ, "blue.catbird.labyrinth.conversation/c2-0")
    );
    let pending: Value =
        serde_json::from_str(&text(conn, "SELECT payload_json FROM pending_ops")).unwrap();
    assert_eq!(pending["archive"]["space_uri"], new(SEQ, convo));
    assert_eq!(
        pending["note"],
        old(SEQ, convo),
        "only the archive Space URI changes"
    );
    let queued: Value = serde_json::from_slice(
        &conn
            .query_blob("SELECT payload_bytes FROM labyrinth_queue", &[])
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(queued["space_uri"], new(SEQ, convo));
    assert_eq!(
        queued["body"]["quoted"],
        old(SEQ, convo),
        "the queued body is not touched"
    );

    assert_eq!(
        state(conn, "status_json")["mailbox_space_uri"],
        new(DID, mailbox)
    );
    assert_eq!(state(conn, "status_json")["epoch_seq"], 3);
    assert_eq!(
        state(conn, "wasm.placements:acct")["c1"]["space"],
        new(SEQ, convo)
    );
    let floors = state(conn, "wasm.writer_rev_floors:acct");
    assert_eq!(floors[new(SEQ, convo)], "3lrev");
    assert_eq!(floors[post], "keep");
    assert!(floors.get(old(SEQ, convo)).is_none());
    assert_eq!(
        state(conn, "device_signer_json")["untouched"],
        old(SEQ, convo)
    );

    let placement: Value = serde_json::from_str(
        &conn
            .get_account_meta("direct_request_value_v2:labyrinthMailboxPlacement:r1")
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(placement["mailbox"], new(DID, mailbox));
    let opening: Value = serde_json::from_str(
        &conn
            .get_account_meta("c33_pending_opening:c1")
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(opening["space_uri"], new(SEQ, convo));
    assert_eq!(opening["frame"], old(SEQ, convo));

    // Once marked, a later open leaves old-form values alone: the rewrite runs once.
    conn.exec_with_text_params(
        "UPDATE conversations SET space_uri = ?1 WHERE conversation_id = 'c1'",
        &[(1, &old(SEQ, convo))],
    )
    .unwrap();
    db.write_tx(|tx| tx.rewrite_legacy_space_uris(8)).unwrap();
    assert_eq!(
        text(
            conn,
            "SELECT space_uri FROM conversations WHERE conversation_id = 'c1'"
        ),
        old(SEQ, convo)
    );
}
