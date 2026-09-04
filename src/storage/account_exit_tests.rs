use super::*;
use wasm_bindgen_test::*;

const OWNER: &str = "did:plc:account-exit-test";
const CID: &str = "5e31af63-9148-46c5-907b-1788fb2bcb49";
const OLD: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NEW: &str = "2222222222222222222222222222222222222222222222222222222222222222";

async fn fixture() -> WasmStorageBackend {
    let conn = Rc::new(
        SqliteConn::open(
            &format!("exit-{}.db", uuid::Uuid::new_v4()),
            &"12".repeat(32),
        )
        .unwrap(),
    );
    WasmStorageBackend::ensure_schema(&conn).unwrap();
    conn.exec_raw("CREATE TABLE IF NOT EXISTS exit_key_sentinel (value BLOB); INSERT INTO exit_key_sentinel VALUES (x'1234')").unwrap();
    let storage = WasmStorageBackend::new(conn);
    storage
        .ensure_conversation_exists(OWNER, CID, OLD)
        .await
        .unwrap();
    storage
        .set_group_state(&GroupState {
            group_id: OLD.into(),
            conversation_id: CID.into(),
            epoch: 3,
            members: vec![OWNER.into()],
        })
        .await
        .unwrap();
    storage.set_content_root_key(vec![7; 32]);
    storage
        .store_message(&Message {
            id: "exit-history".into(),
            conversation_id: CID.into(),
            sender_did: OWNER.into(),
            text: "retained history".into(),
            timestamp: chrono::Utc::now(),
            epoch: 3,
            sequence_number: 4,
            is_own: true,
            delivery_status: None,
            payload_json: None,
        })
        .await
        .unwrap();
    storage
}

fn snapshot(storage: &WasmStorageBackend) -> String {
    serde_json::to_string(&storage.conn.query_text("SELECT group_id, state, reset_new_group_id, reset_generation, reset_notified_at_ms, needs_rejoin, reset_high_water_generation, reset_high_water_group_id, terminal_epoch, state_version FROM conversations", &[], 10).unwrap()).unwrap()
}

#[wasm_bindgen_test]
async fn account_exit_preserves_history_and_fences_both_terminal_states() {
    for terminal in [ConversationState::Closed, ConversationState::DeviceRemoved] {
        let storage = fixture().await;
        storage.mark_reset_pending(CID, NEW, 7, 123).await.unwrap();
        let message_before = storage
            .conn
            .query_text(
                "SELECT hex(payload_encrypted), hex(entry_hmac) FROM messages",
                &[],
                2,
            )
            .unwrap();
        assert!(storage
            .complete_account_exit(CID, NEW, Some(7), 9, terminal.clone())
            .await
            .unwrap());
        assert_eq!(
            storage.get_conversation_state(CID).await.unwrap(),
            Some(terminal.clone())
        );
        let view = storage.get_conversation(OWNER, CID).await.unwrap().unwrap();
        assert_eq!((view.group_id.as_str(), view.epoch), (NEW, 9));
        assert_eq!(
            storage.get_group_state(OLD).await.unwrap().unwrap().epoch,
            3
        );
        assert_eq!(
            storage.get_messages(CID, 10, None).await.unwrap()[0].text,
            "retained history"
        );
        assert_eq!(
            storage
                .conn
                .query_text(
                    "SELECT hex(payload_encrypted), hex(entry_hmac) FROM messages",
                    &[],
                    2
                )
                .unwrap(),
            message_before
        );
        assert_eq!(
            storage
                .conn
                .query_text("SELECT hex(value) FROM exit_key_sentinel", &[], 1)
                .unwrap()[0][0]
                .as_deref(),
            Some("1234")
        );
        let after = snapshot(&storage);
        assert!(storage
            .complete_account_exit(CID, NEW, Some(7), 9, terminal.clone())
            .await
            .unwrap());
        assert!(!storage
            .complete_account_exit(CID, NEW, Some(8), 9, terminal.clone())
            .await
            .unwrap());
        assert!(!storage
            .complete_account_exit(CID, NEW, Some(7), 8, terminal)
            .await
            .unwrap());
        assert_eq!(snapshot(&storage), after);
        storage.mark_reset_pending(CID, NEW, 7, 123).await.unwrap();
        assert_eq!(
            snapshot(&storage),
            after,
            "replayed reset must not reopen terminal state"
        );
        assert!(storage
            .conversation_group_aliases(OWNER, CID)
            .unwrap()
            .contains(&OLD.to_owned()));
    }
}

#[wasm_bindgen_test]
async fn account_exit_rejects_stale_torn_and_cross_tenant_authority() {
    let storage = fixture().await;
    storage.mark_reset_pending(CID, NEW, 7, 123).await.unwrap();
    let before = snapshot(&storage);
    for (target, generation, epoch, state) in [
        (OLD, Some(7), 9, ConversationState::Closed),
        (NEW, Some(6), 9, ConversationState::Closed),
        (NEW, None, 9, ConversationState::Closed),
        (NEW, Some(7), u64::MAX, ConversationState::Closed),
        (NEW, Some(7), 9, ConversationState::Active),
    ] {
        assert!(!storage
            .complete_account_exit(CID, target, generation, epoch, state)
            .await
            .unwrap());
    }
    storage.set_active_user_did(Some("did:plc:other".into()));
    assert!(!storage
        .complete_account_exit(CID, NEW, Some(7), 9, ConversationState::Closed)
        .await
        .unwrap());
    storage.set_active_user_did(Some(OWNER.into()));
    assert_eq!(snapshot(&storage), before);
    storage
        .conn
        .exec_raw("UPDATE conversations SET reset_notified_at_ms = NULL")
        .unwrap();
    let torn = snapshot(&storage);
    assert!(!storage
        .complete_account_exit(CID, NEW, Some(7), 9, ConversationState::Closed)
        .await
        .unwrap());
    assert_eq!(snapshot(&storage), torn);
}

#[wasm_bindgen_test]
async fn account_exit_no_reset_accepts_historical_highwater_and_rolls_back_write_failure() {
    let storage = fixture().await;
    storage.conn.exec_raw("UPDATE conversations SET reset_high_water_generation = 4, reset_high_water_group_id = group_id").unwrap();
    storage.conn.exec_raw("CREATE TRIGGER fail_exit BEFORE UPDATE OF terminal_epoch ON conversations BEGIN SELECT RAISE(ABORT, 'fixture'); END").unwrap();
    let before = snapshot(&storage);
    assert!(storage
        .complete_account_exit(CID, OLD, None, 4, ConversationState::DeviceRemoved)
        .await
        .is_err());
    assert_eq!(snapshot(&storage), before);
    storage.conn.exec_raw("DROP TRIGGER fail_exit").unwrap();
    assert!(storage
        .complete_account_exit(CID, OLD, None, 4, ConversationState::DeviceRemoved)
        .await
        .unwrap());
    assert_eq!(
        storage.get_conversation_state(CID).await.unwrap(),
        Some(ConversationState::DeviceRemoved)
    );
}

#[wasm_bindgen_test]
async fn account_exit_advances_device_removal_only_with_dedicated_authority() {
    let storage = fixture().await;
    let active = snapshot(&storage);
    assert!(!storage
        .complete_account_exit(CID, OLD, None, 2, ConversationState::Closed)
        .await
        .unwrap());
    assert_eq!(snapshot(&storage), active);
    assert!(storage
        .complete_account_exit(CID, OLD, None, 4, ConversationState::DeviceRemoved)
        .await
        .unwrap());
    assert!(storage
        .set_conversation_state(CID, ConversationState::Active)
        .await
        .is_err());
    let removed = snapshot(&storage);
    assert!(!storage
        .complete_account_exit(CID, OLD, None, 3, ConversationState::Closed)
        .await
        .unwrap());
    assert_eq!(snapshot(&storage), removed);
    assert!(storage
        .complete_account_exit(CID, OLD, None, 5, ConversationState::DeviceRemoved)
        .await
        .unwrap());
    assert!(storage
        .complete_account_exit(CID, OLD, None, 6, ConversationState::Closed)
        .await
        .unwrap());
    let closed = snapshot(&storage);
    assert!(!storage
        .complete_account_exit(CID, OLD, None, 7, ConversationState::Closed)
        .await
        .unwrap());
    assert!(!storage
        .complete_account_exit(CID, OLD, None, 6, ConversationState::DeviceRemoved)
        .await
        .unwrap());
    assert!(storage.mark_reset_pending(CID, NEW, 8, 456).await.is_err());
    assert_eq!(snapshot(&storage), closed);
}

#[wasm_bindgen_test]
async fn account_exit_retained_generation_cannot_authorize_a_new_terminal_record() {
    let storage = fixture().await;
    storage.mark_reset_pending(CID, NEW, 7, 123).await.unwrap();
    assert!(storage
        .complete_account_exit(CID, NEW, Some(7), 3, ConversationState::DeviceRemoved)
        .await
        .unwrap());
    assert!(!storage
        .complete_account_exit(CID, NEW, Some(8), 4, ConversationState::Closed)
        .await
        .unwrap());
    assert!(!storage
        .complete_account_exit(CID, NEW, Some(7), 4, ConversationState::Closed)
        .await
        .unwrap());
    assert!(storage
        .complete_account_exit(CID, NEW, None, 4, ConversationState::Closed)
        .await
        .unwrap());
}
