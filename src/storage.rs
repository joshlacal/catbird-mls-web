//! WasmStorageBackend — implements MLSStorageBackend using encrypted SQLite.
//!
//! Replaces the previous IndexedDB implementation. All data is now stored in
//! the same encrypted SQLite database (OPFS SAH VFS + sqlite3mc ChaCha20) as
//! OpenMLS state, via the shared `SqliteConn` from `sqlite_conn.rs`.
//!
//! # Migration Note
//!
//! No migration from the old IndexedDB database is performed. Users with
//! existing data will need to re-login. The old IndexedDB databases are
//! intentionally left in place (browser will garbage-collect them or the
//! user can clear site data).
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS conversations (...);
//! CREATE TABLE IF NOT EXISTS messages (...);
//! CREATE TABLE IF NOT EXISTS sync_cursors (...);
//! CREATE TABLE IF NOT EXISTS group_states (...);
//! ```

use async_trait::async_trait;
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::storage::MLSStorageBackend;
use catbird_mls::orchestrator::types::*;
use std::cell::RefCell;
use std::rc::Rc;

use crate::sqlite_conn::SqliteConn;

/// JSON-shaped canonical plaintext sealed by the field-level encryption
/// layer before persistence. Mirrors the catmos-desktop format so encrypted
/// rows produced by either client are wire-compatible. Storing the rich
/// payload (rather than the bare `text` column) preserves `payload_json`
/// across an encrypt/decrypt round-trip while the legacy `text NOT NULL`
/// constraint is satisfied by writing an empty string in the legacy column.
#[derive(serde::Serialize, serde::Deserialize)]
struct CanonicalMessageBody<'a> {
    text: &'a str,
    payload_json: Option<&'a str>,
}

#[derive(serde::Deserialize)]
struct CanonicalMessageBodyOwned {
    text: String,
    payload_json: Option<String>,
}

/// Version tag stamped into `payload_key_version` on every encrypted row.
const PAYLOAD_KEY_VERSION_V1: i64 = 1;

pub struct WasmStorageBackend {
    conn: Rc<SqliteConn>,
    /// Per-user 32-byte content root key for the field-level (envelope)
    /// encryption layer. Installed via `set_content_root_key` after the
    /// platform layer resolves it (localStorage on web) and the WASM
    /// context has it. Held by-value here so storage methods don't have to
    /// reach back into `STATE` (avoiding re-entrant `RefCell` borrows).
    ///
    /// `None` during the bootstrap window before login completes; in that
    /// case write/read paths fall back to legacy plaintext columns so the
    /// orchestrator can keep functioning.
    content_root_key: RefCell<Option<Vec<u8>>>,
}

impl WasmStorageBackend {
    /// Create a new storage backend wrapping the shared SQLite connection.
    ///
    /// The caller must have already called [`Self::ensure_schema`] on this
    /// connection.
    pub fn new(conn: Rc<SqliteConn>) -> Self {
        Self {
            conn,
            content_root_key: RefCell::new(None),
        }
    }

    /// Install the per-user 32-byte content root key. Called from
    /// `catbird_mls_set_content_root_key` in `lib.rs` so the same key
    /// already pushed into the WASM MLS context is also available to the
    /// storage layer for write-time encryption + read-time decryption.
    /// Idempotent; later calls replace the binding.
    pub fn set_content_root_key(&self, key: Vec<u8>) {
        *self.content_root_key.borrow_mut() = Some(key);
    }

    /// Clear the cached content root key. Called on logout via
    /// `catbird_mls_clear_content_root_key` in `lib.rs`.
    pub fn clear_content_root_key(&self) {
        *self.content_root_key.borrow_mut() = None;
    }

    /// Snapshot the content root key (cloned) so callers can use it without
    /// holding the `RefCell` borrow for the duration of the SQLite I/O.
    fn content_root_key_snapshot(&self) -> Option<Vec<u8>> {
        self.content_root_key.borrow().clone()
    }

    /// Read the most recent (highest sequence_number) `entry_hmac` for a
    /// conversation so the next encrypted row can extend the HMAC chain.
    /// Returns `None` for the first row in a conversation (chain seed = 32
    /// zero bytes is supplied by the Rust core when `prev_hmac=None`) or
    /// when prior rows are legacy plaintext (no chain).
    fn last_entry_hmac(&self, conversation_id: &str) -> Option<Vec<u8>> {
        self.conn
            .query_blob(
                "SELECT entry_hmac FROM messages
                 WHERE conversation_id = ?1 AND entry_hmac IS NOT NULL
                 ORDER BY sequence_number DESC LIMIT 1",
                &[(1, conversation_id)],
            )
            .ok()
            .flatten()
            .filter(|b| !b.is_empty())
    }

    /// Seal a `Message` body for storage. Returns `None` when the content
    /// root key isn't installed yet — callers fall back to legacy plaintext
    /// columns with a warning so the orchestrator can keep functioning
    /// during the bootstrap window (initial sync may run before the JS
    /// layer pushes the key in).
    fn try_encrypt_message_body(&self, message: &Message) -> Option<(Vec<u8>, Vec<u8>)> {
        let root = self.content_root_key_snapshot()?;
        let body = CanonicalMessageBody {
            text: &message.text,
            payload_json: message.payload_json.as_deref(),
        };
        let plaintext = match serde_json::to_vec(&body) {
            Ok(v) => v,
            Err(err) => {
                web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(&format!(
                    "[catbird-mls-web] try_encrypt_message_body: canonical body serialize failed: {} (falling back to plaintext)",
                    err
                )));
                return None;
            }
        };
        let encrypted = match catbird_mls::field_encryption::encrypt_payload(
            &root,
            &message.conversation_id,
            &plaintext,
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(&format!(
                    "[catbird-mls-web] try_encrypt_message_body: encrypt_payload failed: {:?} (falling back to plaintext)",
                    err
                )));
                return None;
            }
        };
        let prev_hmac = self.last_entry_hmac(&message.conversation_id);
        let entry_hmac = match catbird_mls::field_encryption::compute_entry_hmac(
            &root,
            &message.conversation_id,
            prev_hmac.as_deref(),
            &message.id,
            &encrypted,
        ) {
            Ok(tag) => tag.to_vec(),
            Err(err) => {
                web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(&format!(
                    "[catbird-mls-web] try_encrypt_message_body: compute_entry_hmac failed: {:?} (falling back to plaintext)",
                    err
                )));
                return None;
            }
        };
        Some((encrypted, entry_hmac))
    }

    /// Attempt to decrypt a sealed message body. Returns the canonical
    /// (text, payload_json) tuple on success. Returns `None` when the
    /// content root key isn't installed or the wire bytes don't match.
    /// Callers fall back to the legacy `text` / `payload_json` columns in
    /// that case.
    fn try_decrypt_message_body(
        &self,
        conversation_id: &str,
        wire: &[u8],
        message_id: &str,
    ) -> Option<(String, Option<String>)> {
        let root = self.content_root_key_snapshot()?;
        let plaintext = match catbird_mls::field_encryption::decrypt_payload(
            &root,
            conversation_id,
            wire,
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(&format!(
                    "[catbird-mls-web] decrypt_payload failed for {}: {:?} (falling back to legacy columns)",
                    message_id, err
                )));
                return None;
            }
        };
        match serde_json::from_slice::<CanonicalMessageBodyOwned>(&plaintext) {
            Ok(body) => Some((body.text, body.payload_json)),
            Err(err) => {
                web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(&format!(
                    "[catbird-mls-web] canonical body deserialize failed for {}: {} (falling back to legacy columns)",
                    message_id, err
                )));
                None
            }
        }
    }

    /// Create all required tables on the shared connection.
    pub fn ensure_schema(conn: &SqliteConn) -> std::result::Result<(), String> {
        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS conversations (
                conversation_id        TEXT NOT NULL,
                user_did               TEXT NOT NULL,
                group_id               TEXT NOT NULL,
                join_method            TEXT,
                join_epoch             INTEGER,
                needs_rejoin           INTEGER DEFAULT 0,
                state                  TEXT DEFAULT 'active',
                reset_new_group_id     TEXT,
                reset_generation       INTEGER,
                reset_notified_at_ms   INTEGER,
                PRIMARY KEY (conversation_id, user_did)
            );",
        )
        .map_err(|e| format!("conversations table: {}", e))?;

        // Migration: add state column for existing databases.
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN state TEXT DEFAULT 'active';",
        );

        // Migration (spec §8.6 / §8.1 RESET_PENDING): persist the payload
        // shipped by `GroupResetEvent` so deferred recovery survives reload.
        // Three additive ALTERs — ignore errors if columns already exist.
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN reset_new_group_id TEXT;",
        );
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN reset_generation INTEGER;",
        );
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN reset_notified_at_ms INTEGER;",
        );

        // Migration (MLS metadata cutover): persist decrypted group metadata
        // locally. Server has no plaintext title / description / avatar; the
        // encrypted-blob path (catbird_mls::metadata) is the only source of
        // truth. We store the decrypted result here so the conversation
        // list can render display names without re-fetching every load.
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN title TEXT;",
        );
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN description TEXT;",
        );
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN metadata_version INTEGER;",
        );
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN avatar_blob_locator TEXT;",
        );
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN avatar_content_type TEXT;",
        );
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN avatar_bytes BLOB;",
        );

        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS messages (
                id              TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_did      TEXT NOT NULL,
                text            TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                epoch           INTEGER NOT NULL,
                created_at      TEXT NOT NULL,
                is_own          INTEGER DEFAULT 0,
                delivery_status TEXT DEFAULT 'delivered'
            );",
        )
        .map_err(|e| format!("messages table: {}", e))?;

        conn.exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_messages_convo_seq
                ON messages(conversation_id, sequence_number);",
        )
        .map_err(|e| format!("messages index: {}", e))?;

        // Migration (MLS field-level encryption): persist the sealed
        // canonical body alongside the HMAC chain so the on-disk
        // representation matches catmos desktop / iOS / Android. ALTER
        // calls are idempotent — if the column already exists SQLite errors
        // and we swallow it via `let _ =`, matching the established pattern
        // for additive migrations above.
        let _ = conn.exec_raw("ALTER TABLE messages ADD COLUMN payload_encrypted BLOB;");
        let _ = conn.exec_raw("ALTER TABLE messages ADD COLUMN entry_hmac BLOB;");
        let _ = conn.exec_raw("ALTER TABLE messages ADD COLUMN payload_key_version INTEGER;");
        // `payload_json` lives in the canonical body once sealed; persist it
        // on the row too so legacy plaintext writes (bootstrap window) and
        // the catmos-desktop schema stay aligned.
        let _ = conn.exec_raw("ALTER TABLE messages ADD COLUMN payload_json TEXT;");
        // Tombstone parity with iOS/Android: catmos-web doesn't yet expose
        // user-initiated deletes, but the columns ship now so a later
        // soft-delete path can land without another schema migration
        // breaking the HMAC chain.
        let _ = conn.exec_raw(
            "ALTER TABLE messages ADD COLUMN is_tombstone INTEGER NOT NULL DEFAULT 0;",
        );
        let _ = conn.exec_raw("ALTER TABLE messages ADD COLUMN deleted_at INTEGER;");

        // One-shot drop of any pre-field-encryption rows. Matches the
        // `MLSPlaintextHeaderMigration` precedent on iOS / Android / desktop:
        // existing transcripts cannot satisfy the encrypted-row invariants
        // (no HMAC chain seed, no per-conversation content key derivation
        // history), so we drop them once and record the migration in a
        // `migration_status` table so it is never re-run.
        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS migration_status (
                name TEXT PRIMARY KEY,
                applied_at INTEGER NOT NULL
            );",
        )
        .map_err(|e| format!("migration_status table: {}", e))?;
        let already = conn
            .query_text(
                "SELECT name FROM migration_status WHERE name = ?1",
                &[(1, "MLSMessageFieldMigrationV1")],
                1,
            )
            .map_err(|e| format!("migration_status query: {}", e))?;
        if already.is_empty() {
            conn.exec_raw("DELETE FROM messages;")
                .map_err(|e| format!("migration v1 DELETE messages: {}", e))?;
            conn.exec_with_text_params(
                "INSERT INTO migration_status (name, applied_at) \
                 VALUES (?1, strftime('%s','now'))",
                &[(1, "MLSMessageFieldMigrationV1")],
            )
            .map_err(|e| format!("migration_status INSERT: {}", e))?;
        }

        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS sync_cursors (
                user_did TEXT PRIMARY KEY,
                conversations_cursor TEXT,
                messages_cursor      TEXT
            );",
        )
        .map_err(|e| format!("sync_cursors table: {}", e))?;

        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS group_states (
                group_id        TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                epoch           INTEGER NOT NULL,
                members_json    TEXT NOT NULL
            );",
        )
        .map_err(|e| format!("group_states table: {}", e))?;

        Ok(())
    }

    fn store_err(e: impl std::fmt::Debug) -> OrchestratorError {
        OrchestratorError::Storage(format!("{:?}", e))
    }

    /// Adopt a new MLS group id for a conversation after a server-initiated
    /// group reset (spec §8.5). The websocket handler calls this so the
    /// subsequent External Commit (driven by deferred recovery / JS-triggered
    /// sync) targets the new group instead of the pre-reset one.
    ///
    /// Wraps the swap in BEGIN/COMMIT and deletes the orphaned `group_states`
    /// row keyed by the old `group_id` (when it differs from the new one) so
    /// stale OpenMLS state doesn't linger after adoption.
    ///
    /// Inherent method (not on `MLSStorageBackend`) — mirrors the catmos
    /// Tauri `Storage::update_conversation_group_id` shape.
    //
    // TODO(test-gap): no unit coverage — `catbird-mls-web` has cdylib-only
    // crate-type and uses sqlite-wasm-rs OPFS VFS that doesn't run on host.
    // Adding a wasm-bindgen-test would require :memory: VFS shim. Tracked
    // in spec docs/superpowers/specs/2026-04-26-mls-auto-reset-phase1-design.md
    pub fn update_conversation_group_id(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
    ) -> std::result::Result<(), String> {
        self.conn
            .exec_raw("BEGIN")
            .map_err(|e| format!("update_conversation_group_id BEGIN: {:?}", e))?;

        let result = (|| -> std::result::Result<(), String> {
            let rows = self
                .conn
                .query_text(
                    "SELECT group_id FROM conversations WHERE conversation_id = ?1",
                    &[(1, conversation_id)],
                    1,
                )
                .map_err(|e| format!("update_conversation_group_id SELECT: {:?}", e))?;
            let old_group_id: Option<String> = rows
                .into_iter()
                .next()
                .and_then(|r| r.into_iter().next().flatten());

            self.conn
                .exec_with_text_params(
                    "UPDATE conversations SET group_id = ?1 WHERE conversation_id = ?2",
                    &[(1, new_group_id_hex), (2, conversation_id)],
                )
                .map_err(|e| format!("update_conversation_group_id UPDATE: {:?}", e))?;

            if let Some(old) = old_group_id {
                if old != new_group_id_hex {
                    self.conn
                        .exec_with_text_params(
                            "DELETE FROM group_states WHERE group_id = ?1",
                            &[(1, &old)],
                        )
                        .map_err(|e| {
                            format!("update_conversation_group_id DELETE: {:?}", e)
                        })?;
                }
            }
            Ok(())
        })();

        match result {
            Ok(()) => self
                .conn
                .exec_raw("COMMIT")
                .map_err(|e| format!("update_conversation_group_id COMMIT: {:?}", e)),
            Err(e) => {
                let _ = self.conn.exec_raw("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Upsert decrypted metadata for a conversation (MLS metadata cutover).
    ///
    /// `title`, `description`, `metadata_version`, `avatar_blob_locator`
    /// come from `GroupMetadataV1` after decrypting the server blob.
    /// `avatar_bytes` and `avatar_content_type` are persisted so the UI
    /// can render the avatar from a locally stored Blob URL without
    /// re-fetching every load.
    ///
    /// Looks up the conversation_id by group_id_hex (works for both pre-
    /// and post-reset groups since the conversations row's group_id is
    /// kept in sync via `update_conversation_group_id`).
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_metadata(
        &self,
        group_id_hex: &str,
        title: Option<&str>,
        description: Option<&str>,
        metadata_version: i64,
        avatar_blob_locator: Option<&str>,
        avatar_content_type: Option<&str>,
        avatar_bytes: Option<&[u8]>,
    ) -> std::result::Result<(), String> {
        let title_val = title.unwrap_or("");
        let desc_val = description.unwrap_or("");
        let avatar_locator_val = avatar_blob_locator.unwrap_or("");
        let avatar_ct_val = avatar_content_type.unwrap_or("");

        if let Some(bytes) = avatar_bytes {
            self.conn
                .exec_with_text_and_blob_params(
                    "UPDATE conversations
                       SET title = ?1,
                           description = ?2,
                           metadata_version = ?3,
                           avatar_blob_locator = ?4,
                           avatar_content_type = ?5,
                           avatar_bytes = ?6
                     WHERE group_id = ?7",
                    &[
                        (1, title_val),
                        (2, desc_val),
                        (4, avatar_locator_val),
                        (5, avatar_ct_val),
                        (7, group_id_hex),
                    ],
                    &[(6, bytes)],
                )
                .map_err(|e| format!("upsert_metadata UPDATE: {:?}", e))?;
            // The mixed_params helper wraps text+int; emulate version write
            // separately so we don't need a 4-way binder.
            self.conn
                .exec_with_mixed_params(
                    "UPDATE conversations SET metadata_version = ?1 WHERE group_id = ?2",
                    &[(2, group_id_hex)],
                    &[(1, metadata_version)],
                )
                .map_err(|e| format!("upsert_metadata version: {:?}", e))?;
        } else {
            self.conn
                .exec_with_text_params(
                    "UPDATE conversations
                       SET title = ?1,
                           description = ?2,
                           avatar_blob_locator = ?3,
                           avatar_content_type = ?4
                     WHERE group_id = ?5",
                    &[
                        (1, title_val),
                        (2, desc_val),
                        (3, avatar_locator_val),
                        (4, avatar_ct_val),
                        (5, group_id_hex),
                    ],
                )
                .map_err(|e| format!("upsert_metadata UPDATE: {:?}", e))?;
            self.conn
                .exec_with_mixed_params(
                    "UPDATE conversations SET metadata_version = ?1 WHERE group_id = ?2",
                    &[(2, group_id_hex)],
                    &[(1, metadata_version)],
                )
                .map_err(|e| format!("upsert_metadata version: {:?}", e))?;
        }
        Ok(())
    }

    /// Read decrypted title/description for a conversation by group_id_hex.
    /// Returns `(title, description)` tuple of optional strings; both may
    /// be `None` if the conversation row exists but no metadata bootstrap
    /// has run yet.
    pub fn get_metadata_text(
        &self,
        group_id_hex: &str,
    ) -> std::result::Result<Option<(Option<String>, Option<String>)>, String> {
        let rows = self
            .conn
            .query_text(
                "SELECT title, description FROM conversations WHERE group_id = ?1",
                &[(1, group_id_hex)],
                2,
            )
            .map_err(|e| format!("get_metadata_text: {:?}", e))?;
        Ok(rows.into_iter().next().map(|row| {
            let mut iter = row.into_iter();
            let title = iter.next().flatten();
            let description = iter.next().flatten();
            (title, description)
        }))
    }

    /// Read decrypted avatar bytes + content type for a group_id_hex.
    pub fn get_metadata_avatar(
        &self,
        group_id_hex: &str,
    ) -> std::result::Result<Option<(Vec<u8>, Option<String>)>, String> {
        let bytes = self
            .conn
            .query_blob(
                "SELECT avatar_bytes FROM conversations WHERE group_id = ?1",
                &[(1, group_id_hex)],
            )
            .map_err(|e| format!("get_metadata_avatar bytes: {:?}", e))?;
        let bytes = match bytes {
            Some(b) if !b.is_empty() => b,
            _ => return Ok(None),
        };
        let ct_rows = self
            .conn
            .query_text(
                "SELECT avatar_content_type FROM conversations WHERE group_id = ?1",
                &[(1, group_id_hex)],
                1,
            )
            .map_err(|e| format!("get_metadata_avatar content_type: {:?}", e))?;
        let content_type = ct_rows
            .into_iter()
            .next()
            .and_then(|row| row.into_iter().next().flatten());
        Ok(Some((bytes, content_type)))
    }

    /// List all group IDs from the `group_states` table.
    ///
    /// Returns the group_id strings stored by `set_group_state`. Used by
    /// `catbird_mls_init` to reload persisted MLS groups into the in-memory
    /// cache at startup.
    pub fn list_group_ids(&self) -> std::result::Result<Vec<String>, String> {
        let rows = self
            .conn
            .query_text("SELECT group_id FROM group_states;", &[], 1)
            .map_err(|e| format!("list_group_ids: {}", e))?;
        Ok(rows
            .into_iter()
            .filter_map(|row| row.into_iter().next().flatten())
            .collect())
    }
}

#[async_trait(?Send)]
impl MLSStorageBackend for WasmStorageBackend {
    async fn ensure_conversation_exists(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> Result<()> {
        // Check if exists first
        let exists = self
            .conn
            .exists(
                "SELECT 1 FROM conversations WHERE conversation_id = ?1 AND user_did = ?2",
                &[(1, conversation_id), (2, user_did)],
            )
            .map_err(Self::store_err)?;

        if exists {
            return Ok(());
        }

        self.conn
            .exec_with_text_params(
                "INSERT INTO conversations (conversation_id, user_did, group_id, needs_rejoin)
                 VALUES (?1, ?2, ?3, 0)",
                &[(1, conversation_id), (2, user_did), (3, group_id)],
            )
            .map_err(Self::store_err)
    }

    async fn update_join_info(
        &self,
        conversation_id: &str,
        user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> Result<()> {
        let method_str = serde_json::to_string(&join_method)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        self.conn
            .exec_with_mixed_params(
                "UPDATE conversations SET join_method = ?1, join_epoch = ?2
                 WHERE conversation_id = ?3 AND user_did = ?4",
                &[(1, &method_str), (3, conversation_id), (4, user_did)],
                &[(2, join_epoch as i64)],
            )
            .map_err(Self::store_err)
    }

    async fn get_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationView>> {
        let rows = self
            .conn
            .query_text(
                "SELECT group_id FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2",
                &[(1, conversation_id), (2, user_did)],
                1,
            )
            .map_err(Self::store_err)?;

        if rows.is_empty() {
            return Ok(None);
        }

        let group_id = rows[0][0].clone().unwrap_or_default();

        // Look up group state for epoch/members
        let gs_rows = self
            .conn
            .query_text(
                "SELECT epoch, members_json FROM group_states WHERE group_id = ?1",
                &[(1, &group_id)],
                2,
            )
            .map_err(Self::store_err)?;

        let (epoch, members) = if gs_rows.is_empty() {
            (0u64, vec![])
        } else {
            let epoch: u64 = gs_rows[0][0]
                .as_ref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let members: Vec<MemberView> = gs_rows[0][1]
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            (epoch, members)
        };

        Ok(Some(ConversationView {
            group_id: group_id.clone(),
            // TODO(§1.4): persist conversation_id separately once pyramid
            // wiring (#15) lands. For pre-reset convos group_id == conversation_id.
            conversation_id: group_id,
            epoch,
            members,
            metadata: None,
            created_at: None,
            updated_at: None,
            // WS-4 rung 2: not yet persisted in this platform's storage
            // (2026-06-11 WS-4 plan §3.4); absence = sequencer unknown.
            sequencer_did: None,
        }))
    }

    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>> {
        let rows = self
            .conn
            .query_text(
                "SELECT conversation_id, group_id FROM conversations WHERE user_did = ?1",
                &[(1, user_did)],
                2,
            )
            .map_err(Self::store_err)?;

        let mut views = Vec::with_capacity(rows.len());
        for row in rows {
            let group_id = row[1].clone().unwrap_or_default();

            let gs_rows = self
                .conn
                .query_text(
                    "SELECT epoch, members_json FROM group_states WHERE group_id = ?1",
                    &[(1, &group_id)],
                    2,
                )
                .map_err(Self::store_err)?;

            let (epoch, members) = if gs_rows.is_empty() {
                (0u64, vec![])
            } else {
                let epoch: u64 = gs_rows[0][0]
                    .as_ref()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let members: Vec<MemberView> = gs_rows[0][1]
                    .as_ref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_default();
                (epoch, members)
            };

            views.push(ConversationView {
                group_id: group_id.clone(),
                // TODO(§1.4): persist conversation_id separately (see #15).
                conversation_id: group_id,
                epoch,
                members,
                metadata: None,
                created_at: None,
                updated_at: None,
                // WS-4 rung 2: not yet persisted in this platform's storage
                // (2026-06-11 WS-4 plan §3.4); absence = sequencer unknown.
                sequencer_did: None,
            });
        }
        Ok(views)
    }

    async fn delete_conversations(&self, user_did: &str, ids: &[&str]) -> Result<()> {
        for id in ids {
            self.conn
                .exec_with_text_params(
                    "DELETE FROM conversations WHERE conversation_id = ?1 AND user_did = ?2",
                    &[(1, id), (2, user_did)],
                )
                .map_err(Self::store_err)?;
        }
        Ok(())
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> Result<()> {
        // Spec §8.6 / §8.1: when state == ResetPending, persist the payload
        // (new_group_id, reset_generation, notified_at_ms) alongside the tag
        // so deferred recovery survives reload. For all other variants, NULL
        // the reset columns to avoid stale payload bleed-through after a
        // successful adoption.
        let state_str = state.tag();
        match state {
            ConversationState::ResetPending {
                ref new_group_id,
                reset_generation,
                notified_at_ms,
            } => self
                .conn
                .exec_with_mixed_params(
                    "UPDATE conversations
                     SET state = ?1,
                         reset_new_group_id = ?2,
                         reset_generation = ?3,
                         reset_notified_at_ms = ?4
                     WHERE conversation_id = ?5",
                    &[(1, state_str), (2, new_group_id.as_str()), (5, conversation_id)],
                    &[(3, reset_generation as i64), (4, notified_at_ms)],
                )
                .map_err(Self::store_err),
            _ => self
                .conn
                .exec_with_text_params(
                    "UPDATE conversations
                     SET state = ?1,
                         reset_new_group_id = NULL,
                         reset_generation = NULL,
                         reset_notified_at_ms = NULL
                     WHERE conversation_id = ?2",
                    &[(1, state_str), (2, conversation_id)],
                )
                .map_err(Self::store_err),
        }
    }

    /// Read persisted state (spec §8.2). The WASM backend stores the state
    /// tag in `state` and reset payload in three nullable columns; we
    /// reconstruct `ConversationState` from whichever applies.
    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<ConversationState>> {
        let rows = self
            .conn
            .query_text(
                "SELECT state, reset_new_group_id, reset_generation, reset_notified_at_ms
                 FROM conversations WHERE conversation_id = ?1 LIMIT 1",
                &[(1, conversation_id)],
                4,
            )
            .map_err(Self::store_err)?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let tag = row.first().and_then(|c| c.as_deref()).unwrap_or("");
        match tag {
            "" => Ok(None),
            "initializing" => Ok(Some(ConversationState::Initializing)),
            "active" => Ok(Some(ConversationState::Active)),
            "fork_detected" => Ok(Some(ConversationState::ForkDetected)),
            "needs_rejoin" => Ok(Some(ConversationState::NeedsRejoin)),
            "failed" => Ok(Some(ConversationState::Failed)),
            "reset_pending" => {
                let new_group_id = row.get(1).and_then(|c| c.clone());
                let reset_generation = row.get(2).and_then(|c| c.as_deref()).and_then(|s| s.parse::<i32>().ok());
                let notified_at_ms = row.get(3).and_then(|c| c.as_deref()).and_then(|s| s.parse::<i64>().ok());
                match (new_group_id, reset_generation, notified_at_ms) {
                    (Some(g), Some(r), Some(t)) if !g.is_empty() => {
                        Ok(Some(ConversationState::ResetPending {
                            new_group_id: g,
                            reset_generation: r,
                            notified_at_ms: t,
                        }))
                    }
                    // Tag says reset_pending but payload columns are missing —
                    // treat as NeedsRejoin so deferred recovery still runs.
                    _ => Ok(Some(ConversationState::NeedsRejoin)),
                }
            }
            _ => {
                // Unknown tag (forward-compat): treat as no state.
                Ok(None)
            }
        }
    }

    async fn mark_reset_pending(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> Result<()> {
        // Spec §8.6: persist the GroupResetEvent payload so Phase-1 recovery
        // can rehydrate ResetPending after orchestrator restart.
        self.conn
            .exec_with_mixed_params(
                "UPDATE conversations
                 SET state = 'reset_pending',
                     reset_new_group_id = ?1,
                     reset_generation = ?2,
                     reset_notified_at_ms = ?3
                 WHERE conversation_id = ?4",
                &[(1, new_group_id_hex), (4, conversation_id)],
                &[(2, reset_generation as i64), (3, notified_at_ms)],
            )
            .map_err(Self::store_err)
    }

    async fn clear_reset_pending(&self, conversation_id: &str) -> Result<()> {
        self.conn
            .exec_with_text_params(
                "UPDATE conversations
                 SET reset_new_group_id = NULL,
                     reset_generation = NULL,
                     reset_notified_at_ms = NULL
                 WHERE conversation_id = ?1",
                &[(1, conversation_id)],
            )
            .map_err(Self::store_err)
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()> {
        self.conn
            .exec_with_text_params(
                "UPDATE conversations SET needs_rejoin = 1 WHERE conversation_id = ?1",
                &[(1, conversation_id)],
            )
            .map_err(Self::store_err)
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> Result<bool> {
        let rows = self
            .conn
            .query_text(
                "SELECT needs_rejoin FROM conversations WHERE conversation_id = ?1 LIMIT 1",
                &[(1, conversation_id)],
                1,
            )
            .map_err(Self::store_err)?;

        if rows.is_empty() {
            return Ok(false);
        }
        Ok(rows[0][0].as_deref() == Some("1"))
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()> {
        self.conn
            .exec_with_text_params(
                "UPDATE conversations SET needs_rejoin = 0 WHERE conversation_id = ?1",
                &[(1, conversation_id)],
            )
            .map_err(Self::store_err)
    }

    async fn store_message(&self, message: &Message) -> Result<()> {
        let delivery_status_str = message
            .delivery_status
            .as_ref()
            .map(|ds| serde_json::to_string(ds).unwrap_or_else(|_| "\"delivered\"".to_string()))
            .unwrap_or_else(|| "\"delivered\"".to_string());

        let timestamp_str = message.timestamp.to_rfc3339();
        let is_own_str = if message.is_own { "1" } else { "0" };

        // Field-level encryption (Phase F): try to seal the canonical body
        // under the per-DID content root key. Falls back to legacy plaintext
        // columns when the key isn't installed yet (bootstrap window). The
        // helper emits a console warning in the fallback path.
        let sealed = self.try_encrypt_message_body(message);

        match sealed {
            Some((encrypted, entry_hmac)) => {
                // text/payload_json stay blank when the sealed payload is
                // the source of truth — `text NOT NULL` forces empty string.
                self.conn
                    .exec_with_text_int_blob_params(
                        "INSERT OR REPLACE INTO messages
                         (id, conversation_id, sender_did, text, sequence_number, epoch,
                          created_at, is_own, delivery_status, payload_json,
                          payload_encrypted, entry_hmac, payload_key_version)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11, ?12)",
                        &[
                            (1, &*message.id),
                            (2, &*message.conversation_id),
                            (3, &*message.sender_did),
                            (4, ""),
                            (7, &*timestamp_str),
                            (8, is_own_str),
                            (9, &*delivery_status_str),
                        ],
                        &[
                            (5, message.sequence_number as i64),
                            (6, message.epoch as i64),
                            (12, PAYLOAD_KEY_VERSION_V1),
                        ],
                        &[(10, &encrypted[..]), (11, &entry_hmac[..])],
                    )
                    .map_err(Self::store_err)
            }
            None => {
                let payload_json = message.payload_json.as_deref().unwrap_or("");
                self.conn
                    .exec_with_mixed_params(
                        "INSERT OR REPLACE INTO messages
                         (id, conversation_id, sender_did, text, sequence_number, epoch,
                          created_at, is_own, delivery_status, payload_json,
                          payload_encrypted, entry_hmac, payload_key_version)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, NULL)",
                        &[
                            (1, &*message.id),
                            (2, &*message.conversation_id),
                            (3, &*message.sender_did),
                            (4, &*message.text),
                            (7, &*timestamp_str),
                            (8, is_own_str),
                            (9, &*delivery_status_str),
                            (10, payload_json),
                        ],
                        &[
                            (5, message.sequence_number as i64),
                            (6, message.epoch as i64),
                        ],
                    )
                    .map_err(Self::store_err)
            }
        }
    }

    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> Result<Vec<Message>> {
        // Columns (0-based): 0 id, 1 conv, 2 sender, 3 text, 4 seq, 5 epoch,
        // 6 created_at, 7 is_own, 8 delivery_status, 9 payload_json (TEXT),
        // 10 payload_encrypted (BLOB).
        // `is_tombstone` filtered server-side via COALESCE so legacy rows
        // (with the column NULL pre-migration) still surface.
        let blob_cols = [10usize];
        let rows = if let Some(before) = before_sequence {
            self.conn
                .query_text_int_blob(
                    "SELECT id, conversation_id, sender_did, text, sequence_number, epoch,
                            created_at, is_own, delivery_status, payload_json, payload_encrypted
                     FROM messages
                     WHERE conversation_id = ?1 AND sequence_number < ?2
                       AND COALESCE(is_tombstone, 0) = 0
                     ORDER BY sequence_number DESC
                     LIMIT ?3",
                    &[(1, conversation_id)],
                    &[(2, before as i64), (3, limit as i64)],
                    11,
                    &blob_cols,
                )
                .map_err(Self::store_err)?
        } else {
            self.conn
                .query_text_int_blob(
                    "SELECT id, conversation_id, sender_did, text, sequence_number, epoch,
                            created_at, is_own, delivery_status, payload_json, payload_encrypted
                     FROM messages
                     WHERE conversation_id = ?1
                       AND COALESCE(is_tombstone, 0) = 0
                     ORDER BY sequence_number DESC
                     LIMIT ?2",
                    &[(1, conversation_id)],
                    &[(2, limit as i64)],
                    11,
                    &blob_cols,
                )
                .map_err(Self::store_err)?
        };

        let mut messages: Vec<Message> = rows
            .into_iter()
            .map(|row| {
                let id = row[0].0.clone().unwrap_or_default();
                let convo_id = row[1].0.clone().unwrap_or_default();
                let sender = row[2].0.clone().unwrap_or_default();
                let legacy_text = row[3].0.clone().unwrap_or_default();
                let seq: u64 =
                    row[4].0.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                let epoch: u64 =
                    row[5].0.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                let created_at = row[6].0.clone().unwrap_or_default();
                let is_own = row[7].0.as_deref() == Some("1");
                let delivery_status: Option<DeliveryStatus> = row[8]
                    .0
                    .as_ref()
                    .and_then(|s| serde_json::from_str(s).ok());
                let legacy_payload_json = row[9].0.clone();
                let payload_encrypted = row[10].1.clone();

                let timestamp = created_at
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap_or_else(|_| chrono::Utc::now());

                // Prefer the sealed column when present and we have a key;
                // fall back to legacy plaintext columns on either miss.
                let (text, payload_json) = match payload_encrypted.as_ref() {
                    Some(wire) if !wire.is_empty() => {
                        match self.try_decrypt_message_body(&convo_id, wire, &id) {
                            Some((t, pj)) => (t, pj),
                            None => (legacy_text, legacy_payload_json),
                        }
                    }
                    _ => (legacy_text, legacy_payload_json),
                };

                Message {
                    id,
                    conversation_id: convo_id,
                    sender_did: sender,
                    text,
                    timestamp,
                    epoch,
                    sequence_number: seq,
                    is_own,
                    delivery_status,
                    payload_json,
                }
            })
            .collect();

        // Reverse to chronological order (we fetched DESC for LIMIT)
        messages.reverse();
        Ok(messages)
    }

    async fn message_exists(&self, message_id: &str) -> Result<bool> {
        self.conn
            .exists(
                "SELECT 1 FROM messages WHERE id = ?1",
                &[(1, message_id)],
            )
            .map_err(Self::store_err)
    }

    async fn get_sync_cursor(&self, user_did: &str) -> Result<SyncCursor> {
        let rows = self
            .conn
            .query_text(
                "SELECT conversations_cursor, messages_cursor FROM sync_cursors WHERE user_did = ?1",
                &[(1, user_did)],
                2,
            )
            .map_err(Self::store_err)?;

        if rows.is_empty() {
            return Ok(SyncCursor::default());
        }

        Ok(SyncCursor {
            conversations_cursor: rows[0][0].clone(),
            messages_cursor: rows[0][1].clone(),
        })
    }

    async fn set_sync_cursor(&self, user_did: &str, cursor: &SyncCursor) -> Result<()> {
        let convos_cursor = cursor
            .conversations_cursor
            .as_deref()
            .unwrap_or("");
        let msgs_cursor = cursor.messages_cursor.as_deref().unwrap_or("");
        self.conn
            .exec_with_text_params(
                "INSERT OR REPLACE INTO sync_cursors (user_did, conversations_cursor, messages_cursor)
                 VALUES (?1, ?2, ?3)",
                &[(1, user_did), (2, convos_cursor), (3, msgs_cursor)],
            )
            .map_err(Self::store_err)
    }

    async fn set_group_state(&self, state: &GroupState) -> Result<()> {
        let members_json = serde_json::to_string(&state.members)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        self.conn
            .exec_with_mixed_params(
                "INSERT OR REPLACE INTO group_states (group_id, conversation_id, epoch, members_json)
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    (1, &*state.group_id),
                    (2, &*state.conversation_id),
                    (4, &*members_json),
                ],
                &[(3, state.epoch as i64)],
            )
            .map_err(Self::store_err)
    }

    async fn get_group_state(&self, group_id: &str) -> Result<Option<GroupState>> {
        let rows = self
            .conn
            .query_text(
                "SELECT conversation_id, epoch, members_json FROM group_states WHERE group_id = ?1",
                &[(1, group_id)],
                3,
            )
            .map_err(Self::store_err)?;

        if rows.is_empty() {
            return Ok(None);
        }

        let conversation_id = rows[0][0].clone().unwrap_or_default();
        let epoch: u64 = rows[0][1]
            .as_ref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let members: Vec<String> = rows[0][2]
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        Ok(Some(GroupState {
            group_id: group_id.to_string(),
            conversation_id,
            epoch,
            members,
        }))
    }

    async fn delete_group_state(&self, group_id: &str) -> Result<()> {
        self.conn
            .exec_with_text_params(
                "DELETE FROM group_states WHERE group_id = ?1",
                &[(1, group_id)],
            )
            .map_err(Self::store_err)
    }
}
