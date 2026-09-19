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
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
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

/// Opaque, versioned history cursor. Sequence numbers restart when an MLS
/// group is reset, so sequence alone cannot page a stable conversation. The
/// tuple is ordered deterministically (sequence, stored alias, epoch, id) and
/// retains the exact stored alias id used for field-encryption AAD.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct MessageHistoryCursor {
    version: u8,
    sequence_number: u64,
    epoch: u64,
    conversation_id: String,
    id: String,
}

pub struct WasmStorageBackend {
    conn: Rc<SqliteConn>,
    /// The authenticated tenant used by callbacks whose shared storage trait
    /// only carries a conversation id. Keeping this binding in the backend
    /// prevents an implicit callback from accidentally reading another user's
    /// projection after an account switch.
    active_user_did: RefCell<Option<String>>,
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

/// Small rollback guard for schema bundles. SQLite DDL is transactional, but
/// a sequence of `ALTER`/`CREATE` calls otherwise leaves a partially migrated
/// database when one later statement fails. Identity tables and their alias
/// backfill are installed under this guard as one versioned bundle.
struct SqliteTransactionGuard<'a> {
    conn: &'a SqliteConn,
    committed: bool,
}

impl<'a> SqliteTransactionGuard<'a> {
    fn begin(conn: &'a SqliteConn, label: &str) -> std::result::Result<Self, String> {
        conn.exec_raw("BEGIN IMMEDIATE")
            .map_err(|error| format!("{} BEGIN: {:?}", label, error))?;
        Ok(Self {
            conn,
            committed: false,
        })
    }

    fn commit(mut self, label: &str) -> std::result::Result<(), String> {
        self.conn
            .exec_raw("COMMIT")
            .map_err(|error| format!("{} COMMIT: {:?}", label, error))?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for SqliteTransactionGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.conn.exec_raw("ROLLBACK");
        }
    }
}

impl WasmStorageBackend {
    fn write_recovery_value(&self, id: &str, value: &str) -> Result<()> {
        let owner = self
            .active_user_did
            .borrow()
            .clone()
            .ok_or_else(|| OrchestratorError::Storage("recovery owner unavailable".into()))?;
        self.conn
            .exec_with_text_params(
                "INSERT OR REPLACE INTO browser_recovery_v2(owner,id,value) VALUES(?1,?2,?3)",
                &[(1, &owner), (2, id), (3, value)],
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        self.conn
            .ensure_durable()
            .map_err(|e| OrchestratorError::Storage(e.to_string()))
    }

    /// Create a new storage backend wrapping the shared SQLite connection.
    ///
    /// The caller must have already called [`Self::ensure_schema`] on this
    /// connection.
    pub fn new(conn: Rc<SqliteConn>) -> Self {
        Self {
            conn,
            active_user_did: RefCell::new(None),
            content_root_key: RefCell::new(None),
        }
    }

    /// Bind implicit-owner storage callbacks to the currently authenticated
    /// DID. The binding is replaced atomically on account switch and cleared
    /// on logout.
    pub fn set_active_user_did(&self, user_did: Option<String>) {
        *self.active_user_did.borrow_mut() = user_did;
    }

    fn active_user_did(&self) -> std::result::Result<String, String> {
        self.active_user_did
            .borrow()
            .clone()
            .filter(|did| !did.is_empty())
            .ok_or_else(|| "active authenticated user is not bound".to_string())
    }

    /// Verify that a group coordinate belongs to exactly one conversation of
    /// the currently authenticated tenant. Trait callbacks such as
    /// `get_group_state` carry only the group id, so they must not infer an
    /// owner from an unscoped database row after an account switch.
    fn require_active_group_owner(&self, group_id: &str) -> std::result::Result<String, String> {
        let user_did = self.active_user_did()?;
        let rows = self
            .conn
            .query_text(
                "SELECT conversation_id FROM conversations
                 WHERE user_did = ?1 AND (group_id = ?2 OR reset_new_group_id = ?2)
                 UNION
                 SELECT conversation_id FROM conversation_group_aliases
                 WHERE user_did = ?1 AND group_id = ?2",
                &[(1, &user_did), (2, group_id)],
                1,
            )
            .map_err(|e| format!("group owner lookup: {:?}", e))?;
        let mut owners = rows
            .into_iter()
            .filter_map(|row| row.into_iter().next().flatten())
            .collect::<Vec<_>>();
        owners.sort();
        owners.dedup();
        match owners.as_slice() {
            [owner] => Ok(owner.clone()),
            [] => Err(format!(
                "group {} has no mapping for active user {}",
                group_id, user_did
            )),
            _ => Err(format!(
                "group {} has ambiguous owners for active user {}",
                group_id, user_did
            )),
        }
    }

    fn require_active_conversation_owner(
        &self,
        conversation_id: &str,
    ) -> std::result::Result<String, String> {
        let user_did = self.active_user_did()?;
        let mapping = self
            .resolve_conversation_mapping(&user_did, conversation_id)?
            .map(|mapping| mapping.0);
        if mapping.is_none() {
            // Pre-fix rows may still have a raw group coordinate as their
            // conversation key. That legacy handle is safe for storage
            // ownership checks when its exact alias has one owner, but it is
            // deliberately not returned as a synthesized UI/API identity by
            // `resolve_conversation_mapping`.
            let alias_rows = self
                .conn
                .query_text(
                    "SELECT conversation_id FROM conversation_group_aliases
                     WHERE user_did = ?1 AND group_id = ?2",
                    &[(1, &user_did), (2, conversation_id)],
                    1,
                )
                .map_err(|e| format!("conversation alias owner lookup: {:?}", e))?;
            let mut owners = alias_rows
                .into_iter()
                .filter_map(|row| row.into_iter().next().flatten())
                .collect::<Vec<_>>();
            owners.sort();
            owners.dedup();
            if owners.len() != 1 {
                return Err(format!(
                    "conversation {} has no unique persisted mapping for active user {}",
                    conversation_id, user_did
                ));
            }
        }
        Ok(user_did)
    }

    fn ensure_owner_matches_active(&self, user_did: &str) -> std::result::Result<(), String> {
        if let Some(active) = self.active_user_did.borrow().clone() {
            if active != user_did {
                return Err(format!(
                    "storage owner {} does not match active user {}",
                    user_did, active
                ));
            }
        }
        Ok(())
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
        // Schema creation, additive migrations, legacy backfill, and the
        // version marker form one coherent bundle. A failure in any later
        // DDL/backfill step must not leave an apparently migrated database
        // with only half of the identity contract installed.
        let schema_tx = SqliteTransactionGuard::begin(conn, "conversation schema")?;
        conn.exec_raw("CREATE TABLE IF NOT EXISTS browser_recovery_v2 (owner TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(owner,id));").map_err(|e|format!("recovery schema: {e}"))?;
        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS conversations (
                conversation_id        TEXT NOT NULL,
                user_did               TEXT NOT NULL,
                group_id               TEXT NOT NULL,
                join_method            TEXT,
                join_epoch             INTEGER,
                needs_rejoin           INTEGER DEFAULT 0,
                state                  TEXT DEFAULT 'active',
                sequencer_did          TEXT,
                reset_new_group_id     TEXT,
                reset_generation       INTEGER,
                reset_notified_at_ms   INTEGER,
                conversation_kind     TEXT,
                PRIMARY KEY (conversation_id, user_did)
            );",
        )
        .map_err(|e| format!("conversations table: {}", e))?;

        // Terminal epochs cannot be reconstructed from a removed device's
        // retained pre-removal MLS group state.
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN terminal_epoch INTEGER;");

        // Migration: add state column for existing databases.
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN state TEXT DEFAULT 'active';");
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN sequencer_did TEXT;");

        // Migration (spec §8.6 / §8.1 RESET_PENDING): persist the payload
        // shipped by `GroupResetEvent` so deferred recovery survives reload.
        // Three additive ALTERs — ignore errors if columns already exist.
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN reset_new_group_id TEXT;");
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN reset_generation INTEGER;");
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN reset_notified_at_ms INTEGER;");
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN conversation_kind TEXT;");

        // Migration (MLS metadata cutover): persist decrypted group metadata
        // locally. Server has no plaintext title / description / avatar; the
        // encrypted-blob path (catbird_mls::metadata) is the only source of
        // truth. We store the decrypted result here so the conversation
        // list can render display names without re-fetching every load.
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN title TEXT;");
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN description TEXT;");
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN metadata_version INTEGER;");
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN avatar_blob_locator TEXT;");
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN avatar_content_type TEXT;");
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN avatar_bytes BLOB;");
        // Identity/recovery migration: the stable conversation id is the
        // projection key while every MLS group coordinate remains a durable
        // historical alias. `state_version` fences stale list/reset writers.
        let _ = conn.exec_raw(
            "ALTER TABLE conversations ADD COLUMN state_version INTEGER NOT NULL DEFAULT 0;",
        );
        // Canonical protocol coordinates are distinct from the host's local
        // state_version/reset counters. Preserve the verified policy as a whole.
        let _ = conn.exec_raw("ALTER TABLE conversations ADD COLUMN canonical_state_json TEXT;");
        // Reset high-water coordinates survive completion. The pending
        // columns describe the currently actionable target; these columns
        // describe the greatest accepted generation/target and must never be
        // cleared by a winner commit.
        let _ = conn
            .exec_raw("ALTER TABLE conversations ADD COLUMN reset_high_water_generation INTEGER;");
        let _ =
            conn.exec_raw("ALTER TABLE conversations ADD COLUMN reset_high_water_group_id TEXT;");
        let _ = conn.exec_raw(
            "UPDATE conversations SET reset_high_water_generation = reset_generation,
                reset_high_water_group_id = reset_new_group_id
             WHERE reset_high_water_generation IS NULL AND reset_generation IS NOT NULL;",
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
        let _ = conn
            .exec_raw("ALTER TABLE messages ADD COLUMN is_tombstone INTEGER NOT NULL DEFAULT 0;");
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

        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS conversation_group_aliases (
                user_did          TEXT NOT NULL,
                conversation_id   TEXT NOT NULL,
                group_id          TEXT NOT NULL,
                first_seen_epoch  INTEGER NOT NULL DEFAULT 0,
                last_seen_epoch   INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_did, group_id)
            );",
        )
        .map_err(|e| format!("conversation_group_aliases table: {}", e))?;
        conn.exec_raw(
            "CREATE INDEX IF NOT EXISTS idx_conversation_group_aliases_conversation
                ON conversation_group_aliases(user_did, conversation_id);",
        )
        .map_err(|e| format!("conversation_group_aliases index: {}", e))?;
        // Backfill aliases for rows written before this table existed. A
        // legacy raw-group row is retained as evidence until a server
        // snapshot supplies its canonical stable UUID; identity resolution
        // below refuses to authorize that noncanonical owner by itself.
        let legacy_rows = conn
            .query_text(
                "SELECT user_did, conversation_id, group_id FROM conversations",
                &[],
                3,
            )
            .map_err(|e| format!("conversation_group_aliases backfill query: {}", e))?;
        for row in legacy_rows {
            let Some(user_did) = row.first().and_then(|value| value.as_deref()) else {
                continue;
            };
            let Some(conversation_id) = row.get(1).and_then(|value| value.as_deref()) else {
                continue;
            };
            let Some(group_id) = row.get(2).and_then(|value| value.as_deref()) else {
                continue;
            };
            let existing = conn
                .query_text(
                    "SELECT conversation_id FROM conversation_group_aliases
                     WHERE user_did = ?1 AND group_id = ?2",
                    &[(1, user_did), (2, group_id)],
                    1,
                )
                .map_err(|e| format!("conversation_group_aliases backfill lookup: {}", e))?;
            if existing.is_empty() {
                conn.exec_with_text_params(
                    "INSERT INTO conversation_group_aliases
                        (user_did, conversation_id, group_id, first_seen_epoch, last_seen_epoch)
                     VALUES (?1, ?2, ?3, 0, 0)",
                    &[(1, user_did), (2, conversation_id), (3, group_id)],
                )
                .map_err(|e| format!("conversation_group_aliases backfill insert: {}", e))?;
            } else if existing.iter().any(|owner| {
                owner
                    .first()
                    .and_then(|value| value.as_deref())
                    .is_some_and(|owner| owner != conversation_id)
            }) && !Self::is_legacy_group_owner(conversation_id, group_id)
            {
                return Err(format!(
                    "conversation_group_aliases backfill conflict for group {}",
                    group_id
                ));
            }
        }

        // Roster rows use the same MemberView JSON representation as the
        // server. The legacy `group_states.members_json` column remains for
        // OpenMLS compatibility, but this table preserves roles and creator
        // membership across reset/list/create projections.
        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS conversation_rosters (
                group_id        TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                members_json    TEXT NOT NULL
            );",
        )
        .map_err(|e| format!("conversation_rosters table: {}", e))?;

        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS conversation_cleanup_intents (
                user_did        TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                group_id        TEXT NOT NULL,
                reason          TEXT NOT NULL,
                created_at_ms   INTEGER NOT NULL,
                PRIMARY KEY (user_did, group_id)
            );",
        )
        .map_err(|e| format!("conversation_cleanup_intents table: {}", e))?;

        // Version the whole identity bundle. The marker is written last so a
        // mid-migration failure cannot advertise a partially installed alias
        // / roster / cleanup schema on the next startup.
        conn.exec_raw(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                name TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                applied_at INTEGER NOT NULL
            );",
        )
        .map_err(|e| format!("schema_migrations table: {}", e))?;
        conn.exec_with_mixed_params(
            "INSERT INTO schema_migrations (name, version, applied_at)
             VALUES (?1, ?2, strftime('%s','now'))
             ON CONFLICT(name) DO UPDATE SET version = excluded.version,
                 applied_at = excluded.applied_at",
            &[(1, "ConversationIdentityBundle")],
            &[(2, 2)],
        )
        .map_err(|e| format!("schema_migrations identity marker: {}", e))?;
        schema_tx.commit("conversation schema")?;

        Ok(())
    }

    fn store_err(e: impl std::fmt::Debug) -> OrchestratorError {
        OrchestratorError::Storage(format!("{:?}", e))
    }

    /// Write a group-state row without destructive replace semantics. Group
    /// state is mutable for one authorized group coordinate, but its owner is
    /// an identity invariant and may not be rebound by a duplicate write.
    fn write_group_state_checked(
        &self,
        group_id: &str,
        conversation_id: &str,
        epoch: u64,
        members_json: &str,
    ) -> std::result::Result<(), String> {
        let existing = self
            .conn
            .query_text(
                "SELECT conversation_id FROM group_states WHERE group_id = ?1 LIMIT 1",
                &[(1, group_id)],
                1,
            )
            .map_err(|e| format!("group state lookup: {:?}", e))?;
        if let Some(owner) = existing
            .first()
            .and_then(|row| row.first().and_then(|value| value.as_deref()))
        {
            if owner != conversation_id && !Self::is_legacy_group_owner(owner, group_id) {
                return Err(format!(
                    "group state {} is owned by conversation {}",
                    group_id, owner
                ));
            }
            self.conn
                .exec_with_mixed_params(
                    "UPDATE group_states SET conversation_id = ?1, epoch = ?2,
                        members_json = ?3 WHERE group_id = ?4",
                    &[(1, conversation_id), (3, members_json), (4, group_id)],
                    &[(2, epoch as i64)],
                )
                .map_err(|e| format!("group state update: {:?}", e))?;
        } else {
            self.conn
                .exec_with_mixed_params(
                    "INSERT INTO group_states
                        (group_id, conversation_id, epoch, members_json)
                     VALUES (?1, ?2, ?3, ?4)",
                    &[(1, group_id), (2, conversation_id), (4, members_json)],
                    &[(3, epoch as i64)],
                )
                .map_err(|e| format!("group state insert: {:?}", e))?;
        }
        Ok(())
    }

    fn write_roster_checked(
        &self,
        group_id: &str,
        conversation_id: &str,
        roster_json: &str,
    ) -> std::result::Result<(), String> {
        let existing = self
            .conn
            .query_text(
                "SELECT conversation_id FROM conversation_rosters WHERE group_id = ?1 LIMIT 1",
                &[(1, group_id)],
                1,
            )
            .map_err(|e| format!("roster lookup: {:?}", e))?;
        if let Some(owner) = existing
            .first()
            .and_then(|row| row.first().and_then(|value| value.as_deref()))
        {
            if owner != conversation_id && !Self::is_legacy_group_owner(owner, group_id) {
                return Err(format!(
                    "roster {} is owned by conversation {}",
                    group_id, owner
                ));
            }
            self.conn
                .exec_with_text_params(
                    "UPDATE conversation_rosters SET conversation_id = ?1,
                        members_json = ?2 WHERE group_id = ?3",
                    &[(1, conversation_id), (2, roster_json), (3, group_id)],
                )
                .map_err(|e| format!("roster update: {:?}", e))?;
        } else {
            self.conn
                .exec_with_text_params(
                    "INSERT INTO conversation_rosters
                        (group_id, conversation_id, members_json)
                     VALUES (?1, ?2, ?3)",
                    &[(1, group_id), (2, conversation_id), (3, roster_json)],
                )
                .map_err(|e| format!("roster insert: {:?}", e))?;
        }
        Ok(())
    }

    /// Return the aliases observed for one stable conversation. The current
    /// group is read from `conversations`; historical groups are retained in
    /// `conversation_group_aliases` so message history and legacy handles
    /// continue to resolve after a reset.
    pub fn conversation_group_aliases(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> std::result::Result<Vec<String>, String> {
        self.ensure_owner_matches_active(user_did)?;
        let rows = self
            .conn
            .query_text(
                "SELECT group_id FROM conversation_group_aliases
                 WHERE user_did = ?1 AND conversation_id = ?2
                 ORDER BY first_seen_epoch, group_id",
                &[(1, user_did), (2, conversation_id)],
                1,
            )
            .map_err(|e| format!("conversation_group_aliases: {:?}", e))?;
        Ok(rows
            .into_iter()
            .filter_map(|row| row.into_iter().next().flatten())
            .collect())
    }

    /// Read the optimistic-concurrency coordinate for a stable projection.
    /// Reset winners pass this value back to the atomic completion primitive so
    /// a list/create writer cannot clear a newer reset generation.
    pub fn conversation_state_version(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> std::result::Result<Option<i64>, String> {
        self.ensure_owner_matches_active(user_did)?;
        let rows = self
            .conn
            .query_text(
                "SELECT state_version FROM conversations
                 WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                &[(1, user_did), (2, conversation_id)],
                1,
            )
            .map_err(|e| format!("conversation state version: {:?}", e))?;
        Ok(rows.first().and_then(|row| {
            row.first()
                .and_then(|value| value.as_deref())
                .and_then(|value| value.parse::<i64>().ok())
        }))
    }

    pub fn conversation_kind(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> std::result::Result<Option<String>, String> {
        self.ensure_owner_matches_active(user_did)?;
        let rows = self
            .conn
            .query_text(
                "SELECT conversation_kind FROM conversations
                 WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                &[(1, user_did), (2, conversation_id)],
                1,
            )
            .map_err(|e| format!("conversation kind lookup: {:?}", e))?;
        Ok(rows
            .first()
            .and_then(|row| row.first().and_then(|value| value.clone())))
    }

    fn merge_legacy_projection(
        &self,
        user_did: &str,
        stable_id: &str,
        legacy_id: &str,
    ) -> std::result::Result<(), String> {
        // Do not discard any application/recovery column when converging an
        // old group-keyed row. The canonical row wins on conflicting values,
        // while missing metadata and recovery coordinates are copied across.
        self.conn
            .exec_with_text_params(
                "UPDATE conversations SET
                    join_method = COALESCE(join_method, (SELECT join_method FROM conversations
                        WHERE user_did = ?1 AND conversation_id = ?2)),
                    join_epoch = COALESCE(join_epoch, (SELECT join_epoch FROM conversations
                        WHERE user_did = ?1 AND conversation_id = ?2)),
                    needs_rejoin = MAX(COALESCE(needs_rejoin, 0), COALESCE((SELECT needs_rejoin
                        FROM conversations WHERE user_did = ?1 AND conversation_id = ?2), 0)),
                    state = CASE
                        WHEN state IS NULL OR state = 'active' THEN COALESCE((SELECT state
                            FROM conversations WHERE user_did = ?1 AND conversation_id = ?2), state, 'active')
                        ELSE state END,
                    sequencer_did = COALESCE(sequencer_did, (SELECT sequencer_did FROM conversations
                        WHERE user_did = ?1 AND conversation_id = ?2)),
                    reset_new_group_id = COALESCE(reset_new_group_id, (SELECT reset_new_group_id
                        FROM conversations WHERE user_did = ?1 AND conversation_id = ?2)),
                    reset_generation = MAX(COALESCE(reset_generation, 0), COALESCE((SELECT reset_generation
                        FROM conversations WHERE user_did = ?1 AND conversation_id = ?2), 0)),
                    reset_notified_at_ms = COALESCE(reset_notified_at_ms, (SELECT reset_notified_at_ms
                        FROM conversations WHERE user_did = ?1 AND conversation_id = ?2)),
                    reset_high_water_generation = MAX(COALESCE(reset_high_water_generation, 0),
                        COALESCE((SELECT reset_high_water_generation FROM conversations
                            WHERE user_did = ?1 AND conversation_id = ?2), 0)),
                    reset_high_water_group_id = COALESCE(reset_high_water_group_id,
                        (SELECT reset_high_water_group_id FROM conversations
                            WHERE user_did = ?1 AND conversation_id = ?2)),
                    conversation_kind = COALESCE(conversation_kind, (SELECT conversation_kind
                        FROM conversations WHERE user_did = ?1 AND conversation_id = ?2)),
                    title = COALESCE(title, (SELECT title FROM conversations
                        WHERE user_did = ?1 AND conversation_id = ?2)),
                    description = COALESCE(description, (SELECT description FROM conversations
                        WHERE user_did = ?1 AND conversation_id = ?2)),
                    metadata_version = MAX(COALESCE(metadata_version, 0), COALESCE((SELECT metadata_version
                        FROM conversations WHERE user_did = ?1 AND conversation_id = ?2), 0)),
                    avatar_blob_locator = COALESCE(avatar_blob_locator, (SELECT avatar_blob_locator
                        FROM conversations WHERE user_did = ?1 AND conversation_id = ?2)),
                    avatar_content_type = COALESCE(avatar_content_type, (SELECT avatar_content_type
                        FROM conversations WHERE user_did = ?1 AND conversation_id = ?2)),
                    avatar_bytes = COALESCE(avatar_bytes, (SELECT avatar_bytes FROM conversations
                        WHERE user_did = ?1 AND conversation_id = ?2)),
                    state_version = MAX(COALESCE(state_version, 0), COALESCE((SELECT state_version
                        FROM conversations WHERE user_did = ?1 AND conversation_id = ?2), 0))
                 WHERE user_did = ?3 AND conversation_id = ?4",
                &[
                    (1, user_did),
                    (2, legacy_id),
                    (3, user_did),
                    (4, stable_id),
                ],
            )
            .map_err(|e| format!("merge legacy projection: {:?}", e))
    }

    /// Rows written by the pre-identity implementation used the raw group
    /// coordinate as `conversation_id`. During the first canonical snapshot
    /// that alias is expected to be temporarily owned by the same legacy row;
    /// it is safe to converge it in the transaction below. Any other owner is
    /// a real identity conflict and must fail closed.
    fn is_legacy_group_owner(owner: &str, group_id: &str) -> bool {
        if owner != group_id {
            return false;
        }
        uuid::Uuid::parse_str(owner)
            .map(|uuid| uuid.hyphenated().to_string() != owner)
            .unwrap_or(true)
    }

    fn insert_group_alias(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> std::result::Result<(), String> {
        let owners = self
            .conn
            .query_text(
                "SELECT conversation_id FROM conversation_group_aliases
                 WHERE user_did = ?1 AND group_id = ?2",
                &[(1, user_did), (2, group_id)],
                1,
            )
            .map_err(|e| format!("group alias ownership lookup: {:?}", e))?;
        if let Some(owner) = owners
            .iter()
            .filter_map(|row| row.first().and_then(|value| value.as_deref()))
            .find(|owner| {
                *owner != conversation_id && !Self::is_legacy_group_owner(owner, group_id)
            })
        {
            return Err(format!(
                "group alias {} is already owned by stable conversation {}",
                group_id, owner
            ));
        }

        if owners.is_empty() {
            self.conn
                .exec_with_text_params(
                    "INSERT INTO conversation_group_aliases
                        (user_did, conversation_id, group_id, first_seen_epoch, last_seen_epoch)
                     VALUES (?1, ?2, ?3, 0, 0)",
                    &[(1, user_did), (2, conversation_id), (3, group_id)],
                )
                .map_err(|e| format!("group alias insert: {:?}", e))?;
        } else if owners.iter().any(|owner| {
            owner
                .first()
                .and_then(|value| value.as_deref())
                .is_some_and(|owner| owner == conversation_id)
        }) {
            // Idempotent replay: preserve the observed epoch bounds rather
            // than replacing the row or silently changing its owner.
            self.conn
                .exec_with_text_params(
                    "UPDATE conversation_group_aliases SET conversation_id = ?1
                     WHERE user_did = ?2 AND group_id = ?3 AND conversation_id = ?1",
                    &[(1, conversation_id), (2, user_did), (3, group_id)],
                )
                .map_err(|e| format!("group alias idempotent update: {:?}", e))?;
        } else if owners.iter().all(|owner| {
            owner
                .first()
                .and_then(|value| value.as_deref())
                .is_some_and(|owner| Self::is_legacy_group_owner(owner, group_id))
        }) {
            // The one permitted ownership transition is the first canonical
            // projection adopting a pre-fix row keyed by its raw group id.
            self.conn
                .exec_with_text_params(
                    "UPDATE conversation_group_aliases SET conversation_id = ?1
                     WHERE user_did = ?2 AND group_id = ?3",
                    &[(1, conversation_id), (2, user_did), (3, group_id)],
                )
                .map_err(|e| format!("group alias legacy adoption: {:?}", e))?;
        } else {
            return Err(format!(
                "group alias {} has no authorized owner for {}",
                group_id, conversation_id
            ));
        }
        Ok(())
    }

    fn upsert_conversation_mapping_in_transaction(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> std::result::Result<(), String> {
        if conversation_id.is_empty() || group_id.is_empty() {
            return Err("stable conversation and group ids are required".to_string());
        }

        let stable_rows = self
            .conn
            .query_text(
                "SELECT group_id FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                &[(1, conversation_id), (2, user_did)],
                1,
            )
            .map_err(|e| format!("mapping stable lookup: {:?}", e))?;
        let old_group_id = stable_rows
            .first()
            .and_then(|row| row.first().and_then(|value| value.clone()));

        if old_group_id.as_deref().is_some_and(|old| old != group_id) {
            // Once a reset commits, the predecessor is a durable historical
            // alias. A late list/create snapshot carrying that predecessor is
            // stale and must not move the stable projection backwards. The
            // reset winner is the only path allowed to change the current
            // group coordinate after the alias is recorded.
            let historical = self
                .conn
                .query_text(
                    "SELECT 1 FROM conversation_group_aliases
                     WHERE user_did = ?1 AND conversation_id = ?2 AND group_id = ?3 LIMIT 1",
                    &[(1, user_did), (2, conversation_id), (3, group_id)],
                    1,
                )
                .map_err(|e| format!("mapping historical alias lookup: {:?}", e))?;
            if !historical.is_empty() {
                return Err(format!(
                    "stale projection would regress {} from current group {} to historical alias {}",
                    conversation_id, old_group_id.as_deref().unwrap_or(""), group_id
                ));
            }
        }

        // A group alias is a per-user one-to-one identity relation. Refuse
        // ambiguity rather than selecting whichever row SQLite happens to
        // return first.
        let owners = self
            .conn
            .query_text(
                "SELECT conversation_id FROM conversation_group_aliases
                 WHERE user_did = ?1 AND group_id = ?2",
                &[(1, user_did), (2, group_id)],
                1,
            )
            .map_err(|e| format!("mapping alias lookup: {:?}", e))?;
        if let Some(owner) = owners
            .iter()
            .filter_map(|row| row.first().and_then(|value| value.as_deref()))
            .find(|owner| {
                *owner != conversation_id && !Self::is_legacy_group_owner(owner, group_id)
            })
        {
            return Err(format!(
                "ambiguous group alias {} belongs to {}",
                group_id, owner
            ));
        }

        let legacy_rows = self
            .conn
            .query_text(
                "SELECT conversation_id FROM conversations
                 WHERE user_did = ?1 AND group_id = ?2 AND conversation_id != ?3",
                &[(1, user_did), (2, group_id), (3, conversation_id)],
                1,
            )
            .map_err(|e| format!("mapping legacy lookup: {:?}", e))?;

        if stable_rows.is_empty() {
            let mut legacy_ids = legacy_rows
                .iter()
                .filter_map(|row| row.first().and_then(|value| value.as_deref()))
                .collect::<Vec<_>>();
            legacy_ids.sort_unstable();
            legacy_ids.dedup();
            if legacy_ids.len() > 1 {
                return Err(format!(
                    "group {} has ambiguous legacy conversation owners",
                    group_id
                ));
            }
            if let Some(legacy_id) = legacy_rows
                .first()
                .and_then(|row| row.first().and_then(|value| value.as_deref()))
            {
                // Renaming the row in place preserves every column and its
                // recovery coordinates. The old group alias is installed
                // below before the row is exposed under the stable key.
                self.conn
                    .exec_with_text_params(
                        "UPDATE conversations SET conversation_id = ?1
                         WHERE user_did = ?2 AND conversation_id = ?3",
                        &[(1, conversation_id), (2, user_did), (3, legacy_id)],
                    )
                    .map_err(|e| format!("mapping legacy rename: {:?}", e))?;
            } else {
                self.conn
                    .exec_with_text_params(
                        "INSERT INTO conversations
                            (conversation_id, user_did, group_id, needs_rejoin, state_version)
                         VALUES (?1, ?2, ?3, 0, 0)",
                        &[(1, conversation_id), (2, user_did), (3, group_id)],
                    )
                    .map_err(|e| format!("mapping insert: {:?}", e))?;
            }
        } else {
            for legacy_id in legacy_rows
                .iter()
                .filter_map(|row| row.first().and_then(|value| value.as_deref()))
            {
                self.merge_legacy_projection(user_did, conversation_id, legacy_id)?;
                self.conn
                    .exec_with_text_params(
                        "DELETE FROM conversations
                         WHERE user_did = ?1 AND conversation_id = ?2",
                        &[(1, user_did), (2, legacy_id)],
                    )
                    .map_err(|e| format!("mapping legacy delete: {:?}", e))?;
            }

            let changed = old_group_id.as_deref() != Some(group_id);
            if changed {
                self.conn
                    .exec_with_text_params(
                        "UPDATE conversations SET group_id = ?1,
                            state_version = COALESCE(state_version, 0) + 1
                         WHERE user_did = ?2 AND conversation_id = ?3",
                        &[(1, group_id), (2, user_did), (3, conversation_id)],
                    )
                    .map_err(|e| format!("mapping group update: {:?}", e))?;
            }
        }

        if let Some(old) = old_group_id.as_deref() {
            self.insert_group_alias(user_did, conversation_id, old)?;
        }
        self.insert_group_alias(user_did, conversation_id, group_id)
    }

    /// Adopt a new MLS group id for a conversation after a server-initiated
    /// reset. This is a durable alias-preserving transaction: the old group
    /// state and all application columns remain available for historical
    /// decryption/AAD, while the stable row points at the new group.
    pub fn update_conversation_group_id(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
    ) -> std::result::Result<(), String> {
        let active_user_did = self.active_user_did()?;
        self.conn
            .exec_raw("BEGIN IMMEDIATE")
            .map_err(|e| format!("update_conversation_group_id BEGIN: {:?}", e))?;

        let result = (|| -> std::result::Result<(), String> {
            let rows = self
                .conn
                .query_text(
                    "SELECT user_did FROM conversations
                     WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                    &[(1, conversation_id), (2, &active_user_did)],
                    1,
                )
                .map_err(|e| format!("update_conversation_group_id SELECT: {:?}", e))?;
            let user_did = rows
                .into_iter()
                .next()
                .and_then(|row| row.into_iter().next().flatten())
                .ok_or_else(|| format!("conversation {} does not exist", conversation_id))?;
            self.upsert_conversation_mapping_in_transaction(
                &user_did,
                conversation_id,
                new_group_id_hex,
            )
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
        self.upsert_metadata_fenced(
            group_id_hex,
            None,
            title,
            description,
            metadata_version,
            avatar_blob_locator,
            avatar_content_type,
            avatar_bytes,
        )
    }

    /// Transactional metadata write fenced to one authenticated conversation
    /// projection. A reset/list writer cannot publish metadata to a group
    /// coordinate that is no longer owned by the active tenant or regress a
    /// newer state/metadata version.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_metadata_fenced(
        &self,
        group_id_hex: &str,
        expected_state_version: Option<i64>,
        title: Option<&str>,
        description: Option<&str>,
        metadata_version: i64,
        avatar_blob_locator: Option<&str>,
        avatar_content_type: Option<&str>,
        avatar_bytes: Option<&[u8]>,
    ) -> std::result::Result<(), String> {
        let active_user_did = self.active_user_did()?;
        let title_val = title.unwrap_or("");
        let desc_val = description.unwrap_or("");
        let avatar_locator_val = avatar_blob_locator.unwrap_or("");
        let avatar_ct_val = avatar_content_type.unwrap_or("");
        self.conn
            .exec_raw("BEGIN IMMEDIATE")
            .map_err(|e| format!("upsert_metadata BEGIN: {:?}", e))?;
        let result = (|| -> std::result::Result<(), String> {
            let conversation_id = self
                .resolve_conversation_mapping(&active_user_did, group_id_hex)?
                .map(|(conversation_id, _)| conversation_id)
                .ok_or_else(|| {
                    format!(
                        "metadata group {} has no active-user conversation mapping",
                        group_id_hex
                    )
                })?;
            let rows = self
                .conn
                .query_text(
                    "SELECT metadata_version, state_version
                     FROM conversations
                     WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                    &[(1, &active_user_did), (2, &conversation_id)],
                    2,
                )
                .map_err(|e| format!("upsert_metadata owner lookup: {:?}", e))?;
            let Some(row) = rows.first() else {
                return Err(format!(
                    "metadata group {} has no active-user conversation mapping",
                    group_id_hex
                ));
            };
            let current_metadata_version = row
                .first()
                .and_then(|value| value.as_deref())
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0);
            let state_version = row
                .get(1)
                .and_then(|value| value.as_deref())
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0);
            if metadata_version < current_metadata_version {
                return Err(format!(
                    "metadata version {} regresses stored version {}",
                    metadata_version, current_metadata_version
                ));
            }
            if expected_state_version.is_some_and(|expected| expected != state_version) {
                return Err(format!(
                    "metadata state-version fence mismatch: expected {:?}, found {}",
                    expected_state_version, state_version
                ));
            }
            if let Some(bytes) = avatar_bytes {
                self.conn
                    .exec_with_text_int_blob_params(
                        "UPDATE conversations
                           SET title = ?1, description = ?2,
                               avatar_blob_locator = ?3, avatar_content_type = ?4,
                               avatar_bytes = ?5, metadata_version = ?6
                         WHERE user_did = ?7 AND conversation_id = ?8
                           AND state_version = ?9",
                        &[
                            (1, title_val),
                            (2, desc_val),
                            (3, avatar_locator_val),
                            (4, avatar_ct_val),
                            (7, &active_user_did),
                            (8, &conversation_id),
                        ],
                        &[(6, metadata_version), (9, state_version)],
                        &[(5, bytes)],
                    )
                    .map_err(|e| format!("upsert_metadata UPDATE: {:?}", e))?;
            } else {
                self.conn
                    .exec_with_mixed_params(
                        "UPDATE conversations
                           SET title = ?1, description = ?2,
                               avatar_blob_locator = ?3, avatar_content_type = ?4,
                               metadata_version = ?5
                         WHERE user_did = ?6 AND conversation_id = ?7
                           AND state_version = ?8",
                        &[
                            (1, title_val),
                            (2, desc_val),
                            (3, avatar_locator_val),
                            (4, avatar_ct_val),
                            (6, &active_user_did),
                            (7, &conversation_id),
                        ],
                        &[(5, metadata_version), (8, state_version)],
                    )
                    .map_err(|e| format!("upsert_metadata UPDATE: {:?}", e))?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => self
                .conn
                .exec_raw("COMMIT")
                .map_err(|e| format!("upsert_metadata COMMIT: {:?}", e)),
            Err(error) => {
                let _ = self.conn.exec_raw("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Read decrypted title/description for a conversation by group_id_hex.
    /// Returns `(title, description)` tuple of optional strings; both may
    /// be `None` if the conversation row exists but no metadata bootstrap
    /// has run yet.
    pub fn get_metadata_text(
        &self,
        group_id_hex: &str,
    ) -> std::result::Result<Option<(Option<String>, Option<String>)>, String> {
        let active_user_did = self.active_user_did()?;
        let conversation_id = self
            .resolve_conversation_mapping(&active_user_did, group_id_hex)?
            .map(|(conversation_id, _)| conversation_id);
        let Some(conversation_id) = conversation_id else {
            return Err(format!(
                "metadata group {} has no active-user conversation mapping",
                group_id_hex
            ));
        };
        let rows = self
            .conn
            .query_text(
                "SELECT title, description FROM conversations
                 WHERE user_did = ?1 AND conversation_id = ?2",
                &[(1, &active_user_did), (2, &conversation_id)],
                2,
            )
            .map_err(|e| format!("get_metadata_text: {:?}", e))?;
        let row = rows.into_iter().next().ok_or_else(|| {
            format!(
                "metadata projection for conversation {} disappeared during lookup",
                conversation_id
            )
        })?;
        Ok(Some({
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
        let active_user_did = self.active_user_did()?;
        let conversation_id = self
            .resolve_conversation_mapping(&active_user_did, group_id_hex)?
            .map(|(conversation_id, _)| conversation_id);
        let Some(conversation_id) = conversation_id else {
            return Err(format!(
                "metadata group {} has no active-user conversation mapping",
                group_id_hex
            ));
        };
        let projection_exists = self
            .conn
            .exists(
                "SELECT 1 FROM conversations
                 WHERE user_did = ?1 AND conversation_id = ?2",
                &[(1, &active_user_did), (2, &conversation_id)],
            )
            .map_err(|e| format!("get_metadata_avatar projection lookup: {:?}", e))?;
        if !projection_exists {
            return Err(format!(
                "metadata projection for conversation {} disappeared during lookup",
                conversation_id
            ));
        }
        let bytes = self
            .conn
            .query_blob(
                "SELECT avatar_bytes FROM conversations
                 WHERE user_did = ?1 AND conversation_id = ?2",
                &[(1, &active_user_did), (2, &conversation_id)],
            )
            .map_err(|e| format!("get_metadata_avatar bytes: {:?}", e))?;
        let bytes = match bytes {
            Some(b) if !b.is_empty() => b,
            _ => return Ok(None),
        };
        let ct_rows = self
            .conn
            .query_text(
                "SELECT avatar_content_type FROM conversations
                 WHERE user_did = ?1 AND conversation_id = ?2",
                &[(1, &active_user_did), (2, &conversation_id)],
                1,
            )
            .map_err(|e| format!("get_metadata_avatar content_type: {:?}", e))?;
        let content_type = ct_rows
            .into_iter()
            .next()
            .and_then(|row| row.into_iter().next().flatten());
        Ok(Some((bytes, content_type)))
    }

    /// Read metadata retained on the stable projection, independent of its
    /// current group alias. Reset migration keeps this row's application
    /// columns intact so republish can source the pre-reset values.
    pub fn get_metadata_for_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> std::result::Result<
        (
            Option<String>,
            Option<String>,
            Option<(Vec<u8>, Option<String>)>,
            Option<i64>,
        ),
        String,
    > {
        self.ensure_owner_matches_active(user_did)?;
        let rows = self
            .conn
            .query_text(
                "SELECT title, description, avatar_content_type, metadata_version
                 FROM conversations WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                &[(1, user_did), (2, conversation_id)],
                4,
            )
            .map_err(|e| format!("metadata conversation lookup: {:?}", e))?;
        let Some(row) = rows.first() else {
            return Err(format!(
                "conversation {} has no metadata projection",
                conversation_id
            ));
        };
        let avatar_bytes = self
            .conn
            .query_blob(
                "SELECT avatar_bytes FROM conversations
                 WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                &[(1, user_did), (2, conversation_id)],
            )
            .map_err(|e| format!("metadata conversation avatar lookup: {:?}", e))?;
        let avatar = avatar_bytes.filter(|bytes| !bytes.is_empty()).map(|bytes| {
            let content_type = row.get(2).and_then(|value| value.clone());
            (bytes, content_type)
        });
        Ok((
            row.first().and_then(|value| value.clone()),
            row.get(1).and_then(|value| value.clone()),
            avatar,
            row.get(3)
                .and_then(|value| value.as_deref())
                .and_then(|value| value.parse::<i64>().ok()),
        ))
    }

    /// List all group IDs from the `group_states` table.
    ///
    /// Returns the group_id strings stored by `set_group_state`. Used by
    /// `catbird_mls_init` to reload persisted MLS groups into the in-memory
    /// cache at startup.
    pub fn list_group_ids(&self) -> std::result::Result<Vec<String>, String> {
        // Initialization can precede authentication, in which case the MLS
        // context needs every persisted group merely to reopen OpenMLS state.
        // Once a tenant is bound, restrict the reload set to that tenant's
        // current and historical aliases.
        let rows = if let Some(user_did) = self.active_user_did.borrow().clone() {
            self.conn
                .query_text(
                    "SELECT DISTINCT gs.group_id FROM group_states gs
                     JOIN conversations c ON c.conversation_id = gs.conversation_id
                     WHERE c.user_did = ?1
                     UNION
                     SELECT DISTINCT gs.group_id FROM group_states gs
                     JOIN conversation_group_aliases a ON a.group_id = gs.group_id
                     WHERE a.user_did = ?1",
                    &[(1, &user_did)],
                    1,
                )
                .map_err(|e| format!("list_group_ids: {}", e))?
        } else {
            self.conn
                .query_text("SELECT group_id FROM group_states;", &[], 1)
                .map_err(|e| format!("list_group_ids: {}", e))?
        };
        Ok(rows
            .into_iter()
            .filter_map(|row| row.into_iter().next().flatten())
            .collect())
    }

    /// Persist the stable conversation identity and its current MLS group
    /// coordinate as one mapping. The stable id is the application/API key;
    /// the group id is the mutable crypto key and may change after reset.
    ///
    /// Existing rows are updated in place so a server conversation list can
    /// repair a stale group mapping without creating a second projection.
    pub fn upsert_conversation_mapping(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> std::result::Result<(), String> {
        self.ensure_owner_matches_active(user_did)?;
        self.conn
            .exec_raw("BEGIN IMMEDIATE")
            .map_err(|e| format!("upsert_conversation_mapping BEGIN: {:?}", e))?;
        let result =
            self.upsert_conversation_mapping_in_transaction(user_did, conversation_id, group_id);
        match result {
            Ok(()) => self
                .conn
                .exec_raw("COMMIT")
                .map_err(|e| format!("upsert_conversation_mapping COMMIT: {:?}", e)),
            Err(e) => {
                let _ = self.conn.exec_raw("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Atomically install the stable projection, current group state, roster,
    /// and alias for one conversation. `expected_generation` and
    /// `expected_state_version` are optional CAS coordinates used by reset
    /// recovery; a stale writer fails before any row is changed.
    pub fn upsert_conversation_projection(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
        epoch: u64,
        members: &[MemberView],
        expected_generation: Option<i32>,
        expected_state_version: Option<i64>,
    ) -> std::result::Result<(), String> {
        self.ensure_owner_matches_active(user_did)?;
        let members_json = serde_json::to_string(
            &members
                .iter()
                .map(|member| member.did.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(|e| format!("projection member serialization: {}", e))?;
        let roster_json = serde_json::to_string(members)
            .map_err(|e| format!("projection roster serialization: {}", e))?;
        let conversation_kind = Self::validate_member_views(members)?;

        self.conn
            .exec_raw("BEGIN IMMEDIATE")
            .map_err(|e| format!("projection BEGIN: {:?}", e))?;
        let result = (|| -> std::result::Result<(), String> {
            let coords = self
                .conn
                .query_text(
                    "SELECT group_id, state, reset_generation, state_version
                     FROM conversations
                     WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                    &[(1, user_did), (2, conversation_id)],
                    4,
                )
                .map_err(|e| format!("projection coordinate lookup: {:?}", e))?;
            if let Some(row) = coords.first() {
                let state = row
                    .get(1)
                    .and_then(|value| value.as_deref())
                    .unwrap_or("active");
                let generation = row
                    .get(2)
                    .and_then(|value| value.as_deref())
                    .and_then(|value| value.parse::<i32>().ok());
                let state_version = row
                    .get(3)
                    .and_then(|value| value.as_deref())
                    .and_then(|value| value.parse::<i64>().ok())
                    .unwrap_or(0);
                if let Some(expected) = expected_generation {
                    if generation != Some(expected) {
                        return Err(format!(
                            "stale reset generation: expected {}, found {:?}",
                            expected, generation
                        ));
                    }
                }
                if let Some(expected) = expected_state_version {
                    if state_version != expected {
                        return Err(format!(
                            "stale conversation state version: expected {}, found {}",
                            expected, state_version
                        ));
                    }
                }
                if expected_generation.is_none()
                    && state == "reset_pending"
                    && row.first().and_then(|value| value.as_deref()) != Some(group_id)
                {
                    return Err("reset_pending projection requires its CAS winner".to_string());
                }
            }

            self.upsert_conversation_mapping_in_transaction(user_did, conversation_id, group_id)?;
            self.write_group_state_checked(group_id, conversation_id, epoch, &members_json)?;
            self.write_roster_checked(group_id, conversation_id, &roster_json)?;
            let existing_kind = self
                .conn
                .query_text(
                    "SELECT conversation_kind FROM conversations
                     WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                    &[(1, user_did), (2, conversation_id)],
                    1,
                )
                .map_err(|e| format!("projection conversation kind lookup: {:?}", e))?;
            if let Some(kind) = existing_kind
                .first()
                .and_then(|row| row.first().and_then(|value| value.as_deref()))
            {
                if kind != conversation_kind {
                    return Err(format!(
                        "conversation {} kind changed from {} to {}",
                        conversation_id, kind, conversation_kind
                    ));
                }
            } else {
                self.conn
                    .exec_with_text_params(
                        "UPDATE conversations SET conversation_kind = ?1
                         WHERE user_did = ?2 AND conversation_id = ?3",
                        &[(1, conversation_kind), (2, user_did), (3, conversation_id)],
                    )
                    .map_err(|e| format!("projection conversation kind: {:?}", e))?;
            }
            Ok(())
        })();

        match result {
            Ok(()) => self
                .conn
                .exec_raw("COMMIT")
                .map_err(|e| format!("projection COMMIT: {:?}", e)),
            Err(error) => {
                let _ = self.conn.exec_raw("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Atomically complete a reset winner. The reset authority is cleared only
    /// after the stable mapping, historical alias, group state, and roster are
    /// all committed under the exact generation/state-version fence.
    pub fn complete_reset_pending_projection(
        &self,
        user_did: &str,
        conversation_id: &str,
        expected_generation: i32,
        expected_state_version: Option<i64>,
        new_group_id: &str,
        epoch: u64,
        members: &[MemberView],
    ) -> std::result::Result<bool, String> {
        self.ensure_owner_matches_active(user_did)?;
        let new_group_id = crate::decode_group_coordinate(new_group_id)
            .map(|bytes| hex::encode(bytes))
            .ok_or_else(|| {
                "reset completion target is not a supported group coordinate".to_string()
            })?;
        self.conn
            .exec_raw("BEGIN IMMEDIATE")
            .map_err(|e| format!("reset completion BEGIN: {:?}", e))?;
        let result = (|| -> std::result::Result<bool, String> {
            let rows = self
                .conn
                .query_text(
                    "SELECT group_id, state, reset_new_group_id, reset_generation,
                            state_version
                     FROM conversations
                     WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                    &[(1, user_did), (2, conversation_id)],
                    5,
                )
                .map_err(|e| format!("reset completion lookup: {:?}", e))?;
            let Some(row) = rows.first() else {
                return Ok(false);
            };
            let generation = row
                .get(3)
                .and_then(|value| value.as_deref())
                .and_then(|value| value.parse::<i32>().ok());
            let state_version = row
                .get(4)
                .and_then(|value| value.as_deref())
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0);
            let target = row.get(2).and_then(|value| value.as_deref());
            if row.get(1).and_then(|value| value.as_deref()) != Some("reset_pending")
                || generation != Some(expected_generation)
                || target != Some(new_group_id.as_str())
                || expected_state_version.is_some_and(|expected| expected != state_version)
            {
                return Ok(false);
            }

            // Validate and serialize the roster only after the generation /
            // state-version CAS has matched. A stale winner must return the
            // typed `false` outcome without turning an otherwise irrelevant
            // roster defect into a storage error; a matching winner still
            // fails closed and leaves RESET_PENDING intact on any roster
            // failure.
            let members_json = serde_json::to_string(
                &members
                    .iter()
                    .map(|member| member.did.clone())
                    .collect::<Vec<_>>(),
            )
            .map_err(|e| format!("reset member serialization: {}", e))?;
            let roster_json = serde_json::to_string(members)
                .map_err(|e| format!("reset roster serialization: {}", e))?;
            let conversation_kind = Self::validate_member_views(members)?;

            self.upsert_conversation_mapping_in_transaction(
                user_did,
                conversation_id,
                &new_group_id,
            )?;
            self.write_group_state_checked(&new_group_id, conversation_id, epoch, &members_json)?;
            self.write_roster_checked(&new_group_id, conversation_id, &roster_json)?;
            let existing_kind = self
                .conn
                .query_text(
                    "SELECT conversation_kind FROM conversations
                     WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                    &[(1, user_did), (2, conversation_id)],
                    1,
                )
                .map_err(|e| format!("reset conversation kind lookup: {:?}", e))?;
            if let Some(kind) = existing_kind
                .first()
                .and_then(|row| row.first().and_then(|value| value.as_deref()))
            {
                if kind != conversation_kind {
                    return Err(format!(
                        "conversation {} kind changed from {} to {}",
                        conversation_id, kind, conversation_kind
                    ));
                }
            } else {
                self.conn
                    .exec_with_text_params(
                        "UPDATE conversations SET conversation_kind = ?1
                         WHERE user_did = ?2 AND conversation_id = ?3",
                        &[(1, conversation_kind), (2, user_did), (3, conversation_id)],
                    )
                    .map_err(|e| format!("reset conversation kind: {:?}", e))?;
            }
            self.conn
                .exec_with_text_params(
                    "UPDATE conversations SET state = 'active',
                        reset_new_group_id = NULL, reset_generation = NULL,
                        reset_notified_at_ms = NULL, needs_rejoin = 0,
                        state_version = COALESCE(state_version, 0) + 1
                     WHERE user_did = ?1 AND conversation_id = ?2
                       AND state = 'reset_pending' AND reset_generation = ?3",
                    &[
                        (1, user_did),
                        (2, conversation_id),
                        (3, &expected_generation.to_string()),
                    ],
                )
                .map_err(|e| format!("reset completion clear authority: {:?}", e))?;
            Ok(true)
        })();
        match result {
            Ok(committed) => {
                self.conn
                    .exec_raw("COMMIT")
                    .map_err(|e| format!("reset completion COMMIT: {:?}", e))?;
                Ok(committed)
            }
            Err(error) => {
                let _ = self.conn.exec_raw("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Resolve either the stable conversation id or a legacy group id to the
    /// authoritative `(conversation_id, group_id)` pair for one user.
    pub fn resolve_conversation_mapping(
        &self,
        user_did: &str,
        identifier: &str,
    ) -> std::result::Result<Option<(String, String)>, String> {
        self.ensure_owner_matches_active(user_did)?;
        // Only canonical UUID text is a stable identity. A legacy row keyed
        // by its raw group bytes must flow through the alias table instead;
        // returning that row here would synthesize a second logical identity
        // from a crypto coordinate and defeat fail-closed resolution.
        if Self::strict_canonical_uuid_v4(identifier) {
            let stable = self
                .conn
                .query_text(
                    "SELECT conversation_id, group_id FROM conversations
                     WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                    &[(1, identifier), (2, user_did)],
                    2,
                )
                .map_err(|e| format!("resolve_conversation_mapping stable: {:?}", e))?;
            if let Some(row) = stable.into_iter().next() {
                let conversation_id = row.first().and_then(|v| v.clone()).unwrap_or_default();
                let group_id = row.get(1).and_then(|v| v.clone()).unwrap_or_default();
                return Ok(Some((conversation_id, group_id)));
            }
        }

        let aliases = self
            .conn
            .query_text(
                "SELECT conversation_id FROM conversation_group_aliases
                 WHERE group_id = ?1 AND user_did = ?2",
                &[(1, identifier), (2, user_did)],
                1,
            )
            .map_err(|e| format!("resolve_conversation_mapping alias: {:?}", e))?;
        let owners: Vec<String> = aliases
            .into_iter()
            .filter_map(|row| row.into_iter().next().flatten())
            .collect();
        let first = owners.first().cloned();
        if owners.iter().any(|owner| Some(owner) != first.as_ref()) {
            return Err(format!(
                "ambiguous group alias {} has {} stable owners",
                identifier,
                owners.len()
            ));
        }
        let Some(conversation_id) = first else {
            // A pre-alias database may still have a canonical stable row whose
            // alias migration was interrupted. Only a canonical UUID may be
            // recovered here; never invent a stable id from group bytes.
            return Ok(None);
        };

        if !Self::strict_canonical_uuid_v4(&conversation_id) {
            return Ok(None);
        }

        let current = self
            .conn
            .query_text(
                "SELECT group_id FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                &[(1, &conversation_id), (2, user_did)],
                1,
            )
            .map_err(|e| format!("resolve_conversation_mapping current: {:?}", e))?;
        Ok(current.first().and_then(|row| {
            row.first()
                .and_then(|value| value.clone())
                .map(|group_id| (conversation_id.clone(), group_id))
        }))
    }

    /// Remove a speculative conversation projection addressed by its current
    /// MLS group coordinate. This is used when createConversation loses a
    /// direct-conversation race: the fresh group is discarded, while the
    /// existing stable conversation projection is retained.
    pub fn delete_conversation_by_group(
        &self,
        user_did: &str,
        group_id: &str,
    ) -> std::result::Result<(), String> {
        self.ensure_owner_matches_active(user_did)?;
        self.conn
            .exec_with_text_params(
                "DELETE FROM conversations WHERE group_id = ?1 AND user_did = ?2",
                &[(1, group_id), (2, user_did)],
            )
            .map_err(|e| format!("delete_conversation_by_group: {:?}", e))
    }

    pub fn mark_cleanup_intent(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
        reason: &str,
    ) -> std::result::Result<(), String> {
        self.ensure_owner_matches_active(user_did)?;
        let existing = self
            .conn
            .query_text(
                "SELECT conversation_id, reason FROM conversation_cleanup_intents
                 WHERE user_did = ?1 AND group_id = ?2 LIMIT 1",
                &[(1, user_did), (2, group_id)],
                2,
            )
            .map_err(|e| format!("cleanup intent lookup: {:?}", e))?;
        if let Some(row) = existing.first() {
            let same_conversation =
                row.first().and_then(|value| value.as_deref()) == Some(conversation_id);
            let same_reason = row.get(1).and_then(|value| value.as_deref()) == Some(reason);
            if same_conversation && same_reason {
                return Ok(());
            }
            return Err(format!(
                "cleanup intent {} has a conflicting owner/fingerprint",
                group_id
            ));
        }
        self.conn
            .exec_with_mixed_params(
                "INSERT INTO conversation_cleanup_intents
                    (user_did, conversation_id, group_id, reason, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, strftime('%s','now') * 1000)",
                &[
                    (1, user_did),
                    (2, conversation_id),
                    (3, group_id),
                    (4, reason),
                ],
                &[],
            )
            .map_err(|e| format!("mark cleanup intent: {:?}", e))
    }

    pub fn clear_cleanup_intent(
        &self,
        user_did: &str,
        group_id: &str,
    ) -> std::result::Result<(), String> {
        self.ensure_owner_matches_active(user_did)?;
        self.conn
            .exec_with_text_params(
                "DELETE FROM conversation_cleanup_intents
                 WHERE user_did = ?1 AND group_id = ?2",
                &[(1, user_did), (2, group_id)],
            )
            .map_err(|e| format!("clear cleanup intent: {:?}", e))
    }

    pub fn list_cleanup_intents(
        &self,
        user_did: &str,
    ) -> std::result::Result<Vec<(String, String, String)>, String> {
        self.ensure_owner_matches_active(user_did)?;
        let rows = self
            .conn
            .query_text(
                "SELECT conversation_id, group_id, reason
                 FROM conversation_cleanup_intents
                 WHERE user_did = ?1 ORDER BY created_at_ms, group_id",
                &[(1, user_did)],
                3,
            )
            .map_err(|e| format!("cleanup intents list: {:?}", e))?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                Some((
                    row.first()?.clone()?,
                    row.get(1)?.clone()?,
                    row.get(2)?.clone()?,
                ))
            })
            .collect())
    }

    /// Synchronous reset arm used by browser event callbacks. The callback
    /// must finish this transaction before it emits a UI event; otherwise a
    /// reset can be rendered even when the durable CAS rejected it.
    pub fn mark_reset_pending_sync(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> std::result::Result<(), String> {
        if reset_generation < 0 {
            return Err("reset generation must be nonnegative".to_string());
        }
        let new_group_id_hex = crate::decode_group_coordinate(new_group_id_hex)
            .map(|bytes| hex::encode(bytes))
            .ok_or_else(|| "reset target is not a supported group coordinate".to_string())?;
        let active_user_did = self.active_user_did()?;
        self.conn
            .exec_raw("BEGIN IMMEDIATE")
            .map_err(|e| format!("reset arm BEGIN: {:?}", e))?;
        let result = (|| -> std::result::Result<(), String> {
            let rows = self
                .conn
                .query_text(
                    "SELECT state, reset_generation, reset_new_group_id,
                            reset_high_water_generation, reset_high_water_group_id
                     FROM conversations WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                    &[(1, conversation_id), (2, &active_user_did)],
                    5,
                )
                .map_err(|e| format!("reset arm lookup: {:?}", e))?;
            let Some(row) = rows.first() else {
                return Err(format!("conversation {} does not exist", conversation_id));
            };
            let pending_generation = row
                .get(1)
                .and_then(|value| value.as_deref())
                .and_then(|value| value.parse::<i32>().ok());
            let pending_target = row.get(2).and_then(|value| value.as_deref());
            let high_generation = row
                .get(3)
                .and_then(|value| value.as_deref())
                .and_then(|value| value.parse::<i32>().ok());
            let high_target = row.get(4).and_then(|value| value.as_deref());
            let accepted_generation = high_generation.or(pending_generation);
            if let Some(accepted) = accepted_generation {
                if accepted > reset_generation {
                    return Err(format!(
                        "stale reset generation {} (current high-water {})",
                        reset_generation, accepted
                    ));
                }
                if accepted == reset_generation {
                    let accepted_target = high_target.or(pending_target);
                    if accepted_target == Some(new_group_id_hex.as_str()) {
                        // Replaying a completed generation is an idempotent
                        // no-op; crucially it does not reopen RESET_PENDING.
                        return Ok(());
                    }
                    return Err("conflicting reset target for accepted generation".to_string());
                }
            }
            if row.first().and_then(|value| value.as_deref()) == Some("closed") {
                return Err("closed conversation cannot enter reset recovery".into());
            }
            self.conn
                .exec_with_mixed_params(
                    "UPDATE conversations SET state = 'reset_pending',
                        reset_new_group_id = ?1, reset_generation = ?2,
                        reset_notified_at_ms = ?3, needs_rejoin = 1,
                        reset_high_water_generation = ?2,
                        reset_high_water_group_id = ?1,
                        state_version = COALESCE(state_version, 0) + 1
                     WHERE conversation_id = ?4 AND user_did = ?5",
                    &[
                        (1, &new_group_id_hex),
                        (4, conversation_id),
                        (5, &active_user_did),
                    ],
                    &[(2, reset_generation as i64), (3, notified_at_ms)],
                )
                .map_err(|e| format!("reset arm update: {:?}", e))
        })();
        match result {
            Ok(()) => self
                .conn
                .exec_raw("COMMIT")
                .map_err(|e| format!("reset arm COMMIT: {:?}", e)),
            Err(error) => {
                let _ = self.conn.exec_raw("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Return the durable pending/high-water target for a generation so a
    /// replay can reuse the original candidate instead of minting a second
    /// speculative group.
    pub fn reset_target_for_generation(
        &self,
        conversation_id: &str,
        generation: i32,
    ) -> std::result::Result<Option<String>, String> {
        let active_user_did = self.active_user_did()?;
        let rows = self
            .conn
            .query_text(
                "SELECT reset_generation, reset_new_group_id,
                        reset_high_water_generation, reset_high_water_group_id
                 FROM conversations WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                &[(1, conversation_id), (2, &active_user_did)],
                4,
            )
            .map_err(|e| format!("reset target lookup: {:?}", e))?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let pending_generation = row
            .first()
            .and_then(|value| value.as_deref())
            .and_then(|value| value.parse::<i32>().ok());
        let high_generation = row
            .get(2)
            .and_then(|value| value.as_deref())
            .and_then(|value| value.parse::<i32>().ok());
        if pending_generation == Some(generation) {
            return Ok(row.get(1).and_then(|value| value.clone()));
        }
        if high_generation == Some(generation) {
            return Ok(row.get(3).and_then(|value| value.clone()));
        }
        Ok(None)
    }

    fn roster_members_sync(&self, group_id: &str) -> Vec<MemberView> {
        self.conn
            .query_text(
                "SELECT members_json FROM conversation_rosters WHERE group_id = ?1 LIMIT 1",
                &[(1, group_id)],
                1,
            )
            .ok()
            .and_then(|rows| {
                rows.first()
                    .and_then(|row| row.first().and_then(|value| value.clone()))
            })
            .and_then(|json| serde_json::from_str::<Vec<MemberView>>(&json).ok())
            .or_else(|| {
                self.conn
                    .query_text(
                        "SELECT members_json FROM group_states WHERE group_id = ?1 LIMIT 1",
                        &[(1, group_id)],
                        1,
                    )
                    .ok()
                    .and_then(|rows| {
                        rows.first()
                            .and_then(|row| row.first().and_then(|value| value.clone()))
                    })
                    .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
                    .map(|dids| {
                        let active_user = self.active_user_did.borrow().clone();
                        dids.into_iter()
                            .enumerate()
                            .map(|(index, did)| MemberView {
                                // Legacy group-state rows predate persisted
                                // roles. Preserve a useful creator/admin
                                // projection by preferring the authenticated
                                // owner, otherwise the first stored member.
                                role: if active_user.as_deref() == Some(did.as_str())
                                    || (active_user.is_none() && index == 0)
                                {
                                    MemberRole::Admin
                                } else {
                                    MemberRole::Member
                                },
                                did,
                            })
                            .collect()
                    })
            })
            .unwrap_or_default()
    }

    fn roster_members_checked(
        &self,
        group_id: &str,
    ) -> std::result::Result<Vec<MemberView>, String> {
        let rows = self
            .conn
            .query_text(
                "SELECT members_json FROM conversation_rosters
                 WHERE group_id = ?1 LIMIT 1",
                &[(1, group_id)],
                1,
            )
            .map_err(|e| format!("roster lookup: {:?}", e))?;
        let Some(json) = rows
            .first()
            .and_then(|row| row.first().and_then(|value| value.as_deref()))
        else {
            return Err(format!("roster for group {} is not persisted", group_id));
        };
        let members: Vec<MemberView> = serde_json::from_str(json)
            .map_err(|error| format!("roster for group {} is invalid: {}", group_id, error))?;
        Self::validate_member_views(&members)?;
        Ok(members)
    }

    fn validate_member_views(members: &[MemberView]) -> std::result::Result<&'static str, String> {
        if members.is_empty() {
            return Err("conversation roster must not be empty".to_string());
        }
        let mut dids = std::collections::HashSet::new();
        let admins = members
            .iter()
            .filter(|member| {
                !member.did.is_empty()
                    && dids.insert(member.did.clone())
                    && matches!(member.role, MemberRole::Admin)
            })
            .count();
        if dids.len() != members.len() || admins == 0 {
            return Err(
                "conversation roster must have unique DIDs and at least one admin".to_string(),
            );
        }
        Ok(if members.len() == 2 {
            "direct"
        } else {
            "group"
        })
    }

    fn strict_canonical_uuid_v4(value: &str) -> bool {
        let Ok(uuid) = uuid::Uuid::parse_str(value) else {
            return false;
        };
        uuid.get_version() == Some(uuid::Version::Random)
            && uuid.get_variant() == uuid::Variant::RFC4122
            && uuid.to_string() == value
    }

    fn projection_canonical_state(
        &self,
        owner: &str,
        cid: &str,
    ) -> std::result::Result<Option<catbird_atproto::blue_catbird::chat::ConversationState>, String>
    {
        let rows = self.conn.query_text("SELECT canonical_state_json FROM conversations WHERE user_did = ?1 AND conversation_id = ?2", &[(1, owner), (2, cid)], 1).map_err(|e| format!("Canonical policy lookup: {e:?}"))?;
        rows.first()
            .and_then(|r| r.first())
            .and_then(|v| v.as_deref())
            .map(|raw| {
                catbird_mls::orchestrator::canonical_transport::decode_conversation_state(
                    raw.as_bytes(),
                )
                .map_err(|e| format!("Invalid retained canonical policy: {e}"))
            })
            .transpose()
    }
    fn projection_lifecycle_matches(
        &self,
        user_did: &str,
        conversation_id: &str,
        fence: &ProjectionLifecycleFence,
        live: bool,
    ) -> std::result::Result<bool, String> {
        let rows = self
            .conn
            .query_text(
                "SELECT state, reset_new_group_id, reset_generation, state_version
                 FROM conversations
                 WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                &[(1, user_did), (2, conversation_id)],
                4,
            )
            .map_err(|e| format!("projection lifecycle lookup: {:?}", e))?;
        let Some(row) = rows.first() else {
            return Ok(false);
        };
        let state = row
            .first()
            .and_then(|value| value.as_deref())
            .unwrap_or("active");
        let target = row.get(1).and_then(|value| value.as_deref());
        let reset_generation = row
            .get(2)
            .and_then(|value| value.as_deref())
            .and_then(|value| value.parse::<i32>().ok());
        let policy = self.projection_canonical_state(user_did, conversation_id)?;
        let coordinates = policy.as_ref().map(|p| &p.coordinates);
        let protocol_matches = match (fence.generation, fence.state_version, coordinates) {
            (None, None, _) => true,
            (Some(generation), Some(version), Some(actual)) => {
                generation == actual.generation
                    && if live {
                        version >= actual.state_version
                    } else {
                        version == actual.state_version
                    }
            }
            (Some(_), Some(_), None) => live && state != "reset_pending",
            _ => false,
        };
        if !protocol_matches
            || fence
                .reset_generation
                .is_some_and(|expected| Some(expected) != reset_generation)
            || fence
                .reset_pending_target_group_id
                .as_deref()
                .is_some_and(|expected| Some(expected) != target)
        {
            return Ok(false);
        }

        // Unknown lifecycle coordinates are not enough to authorize a
        // projection while reset authority is pending.
        if state == "reset_pending"
            && (fence.reset_generation.is_none()
                || fence.reset_pending_target_group_id.as_deref() != target)
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn projection_incarnation(
        &self,
        group_id: &str,
        conversation_id: &str,
    ) -> std::result::Result<Option<u64>, String> {
        let rows = self
            .conn
            .query_text(
                "SELECT epoch FROM group_states WHERE group_id = ?1 AND conversation_id = ?2 LIMIT 1",
                &[(1, group_id), (2, conversation_id)],
                1,
            )
            .map_err(|e| format!("projection incarnation lookup: {:?}", e))?;
        Ok(rows.first().and_then(|row| {
            row.first()
                .and_then(|value| value.as_deref())
                .and_then(|value| value.parse::<u64>().ok())
        }))
    }

    fn existing_message_fingerprint(
        &self,
        message: &Message,
        delivery_status: &str,
        timestamp: &str,
    ) -> std::result::Result<Option<bool>, OrchestratorError> {
        let rows = self
            .conn
            .query_text(
                "SELECT conversation_id, sender_did, text, sequence_number, epoch,
                        created_at, is_own, delivery_status, payload_json
                 FROM messages WHERE id = ?1 LIMIT 1",
                &[(1, &message.id)],
                9,
            )
            .map_err(Self::store_err)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let sequence = message.sequence_number.to_string();
        let epoch = message.epoch.to_string();
        let stored_conversation_id = row.first().and_then(|value| value.as_deref()).unwrap_or("");
        let conversation_match = if stored_conversation_id == message.conversation_id {
            true
        } else {
            self.active_user_did()
                .ok()
                .and_then(|user_did| {
                    let stored = self
                        .resolve_conversation_mapping(&user_did, stored_conversation_id)
                        .ok()
                        .flatten();
                    let incoming = self
                        .resolve_conversation_mapping(&user_did, &message.conversation_id)
                        .ok()
                        .flatten();
                    Some(stored.map(|mapping| mapping.0) == incoming.map(|mapping| mapping.0))
                })
                .unwrap_or(false)
        };
        let scalar_match = row
            .first()
            .and_then(|value| value.as_deref())
            .is_some_and(|_| conversation_match)
            && row.get(1).and_then(|value| value.as_deref()) == Some(message.sender_did.as_str())
            && row.get(3).and_then(|value| value.as_deref()) == Some(sequence.as_str())
            && row.get(4).and_then(|value| value.as_deref()) == Some(epoch.as_str())
            && row.get(5).and_then(|value| value.as_deref()) == Some(timestamp)
            && row.get(6).and_then(|value| value.as_deref())
                == Some(if message.is_own { "1" } else { "0" })
            && row.get(7).and_then(|value| value.as_deref()) == Some(delivery_status);
        if !scalar_match {
            return Ok(Some(false));
        }
        let stored_text = row.get(2).and_then(|value| value.as_deref()).unwrap_or("");
        let stored_payload = row.get(8).and_then(|value| value.as_deref()).unwrap_or("");
        if stored_text == message.text
            && stored_payload == message.payload_json.as_deref().unwrap_or("")
        {
            return Ok(Some(true));
        }
        // Sealed rows intentionally leave the legacy text/payload columns
        // blank. Re-open the authenticated body to compare the logical
        // fingerprint; a same-id ciphertext must never be replaced merely
        // because its random nonce differs. Use the stored conversation ID
        // as AAD: historical aliases are part of the authenticated binding.
        let decrypted = self
            .conn
            .query_blob(
                "SELECT payload_encrypted FROM messages WHERE id = ?1",
                &[(1, &message.id)],
            )
            .map_err(Self::store_err)?
            .and_then(|wire| {
                self.try_decrypt_message_body(stored_conversation_id, &wire, &message.id)
            });
        Ok(Some(decrypted.is_some_and(|(text, payload)| {
            text == message.text
                && payload.as_deref().unwrap_or("") == message.payload_json.as_deref().unwrap_or("")
        })))
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
        // Tests and pre-auth bootstrap paths may reach the storage trait
        // directly; binding here still ensures subsequent implicit-owner
        // callbacks remain tenant-scoped until the next auth switch.
        self.set_active_user_did(Some(user_did.to_owned()));
        self.upsert_conversation_mapping(user_did, conversation_id, group_id)
            .map_err(OrchestratorError::Storage)
    }

    async fn update_join_info(
        &self,
        conversation_id: &str,
        user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> Result<()> {
        self.ensure_owner_matches_active(user_did)
            .map_err(OrchestratorError::Storage)?;
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
        self.ensure_owner_matches_active(user_did)
            .map_err(OrchestratorError::Storage)?;
        let rows = self
            .conn
            .query_text(
                "SELECT group_id, sequencer_did, state, terminal_epoch FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2",
                &[(1, conversation_id), (2, user_did)],
                4,
            )
            .map_err(Self::store_err)?;

        if rows.is_empty() {
            return Ok(None);
        }

        let group_id = rows[0][0].clone().unwrap_or_default();
        let sequencer_did = rows[0][1].clone();

        // Look up group state for epoch/members
        let gs_rows = self
            .conn
            .query_text(
                "SELECT epoch, members_json FROM group_states
                 WHERE group_id = ?1 AND conversation_id = ?2",
                &[(1, &group_id), (2, conversation_id)],
                2,
            )
            .map_err(Self::store_err)?;

        let epoch = if gs_rows.is_empty() {
            0u64
        } else {
            let epoch: u64 = gs_rows[0][0]
                .as_ref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            epoch
        };
        let epoch = if matches!(rows[0][2].as_deref(), Some("closed" | "device_removed")) {
            rows[0][3]
                .as_deref()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| {
                    OrchestratorError::Storage("terminal conversation has no accepted epoch".into())
                })?
        } else {
            epoch
        };
        let members = self.roster_members_sync(&group_id);
        let canonical_state = self
            .projection_canonical_state(user_did, conversation_id)
            .map_err(OrchestratorError::Storage)?;
        if canonical_state.as_ref().is_some_and(|state| {
            state.coordinates.conversation_id.as_str() != conversation_id
                || hex::encode(&state.coordinates.group_id) != group_id
                || state.coordinates.epoch < 0
                || state.coordinates.epoch as u64 > epoch
        }) {
            return Err(OrchestratorError::Storage(
                "Canonical policy does not match durable host identity/epoch".into(),
            ));
        }

        Ok(Some(ConversationView {
            group_id: group_id.clone(),
            conversation_id: conversation_id.to_string(),
            epoch,
            members,
            metadata: None,
            created_at: None,
            updated_at: None,
            sequencer_did,
            canonical_state,
        }))
    }

    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>> {
        self.ensure_owner_matches_active(user_did)
            .map_err(OrchestratorError::Storage)?;
        let rows = self
            .conn
            .query_text(
                "SELECT conversation_id, group_id, sequencer_did FROM conversations WHERE user_did = ?1",
                &[(1, user_did)],
                3,
            )
            .map_err(Self::store_err)?;

        let mut views = Vec::with_capacity(rows.len());
        for row in rows {
            let conversation_id = row[0].as_deref().ok_or_else(|| {
                OrchestratorError::Storage("conversation row has no stable id".into())
            })?;
            if let Some(view) = self.get_conversation(user_did, conversation_id).await? {
                views.push(view);
            }
        }
        Ok(views)
    }

    async fn commit_conversation_projection(
        &self,
        request: &ConversationProjectionCommitRequest,
    ) -> Result<ConversationProjectionCommitOutcome> {
        self.ensure_owner_matches_active(&request.owner_user_did)
            .map_err(OrchestratorError::Storage)?;
        self.conn
            .exec_raw("BEGIN IMMEDIATE")
            .map_err(Self::store_err)?;

        let result = (|| -> std::result::Result<ConversationProjectionCommitOutcome, String> {
            let canonical = request.canonical.as_ref();
            match request.mode {
                ConversationProjectionCommitMode::Live if canonical.is_none() => {
                    return Err("live projection commit is missing canonical view".to_string());
                }
                ConversationProjectionCommitMode::Replay if canonical.is_some() => {
                    return Err("replay projection commit must omit canonical view".to_string());
                }
                _ => {}
            }

            let canonical_id = canonical
                .map(|view| view.conversation_id.as_str())
                .or_else(|| {
                    request
                        .aliases
                        .first()
                        .map(|authority| authority.canonical_conversation_id.as_str())
                });
            let canonical_group = canonical.map(|view| view.group_id.as_str()).or_else(|| {
                request
                    .aliases
                    .first()
                    .map(|authority| authority.canonical_group_id.as_str())
            });
            let Some(canonical_id) = canonical_id else {
                return Err("projection commit is missing canonical identity".to_string());
            };
            let Some(canonical_group) = canonical_group else {
                return Err("projection commit is missing canonical group".to_string());
            };
            if request.owner_user_did.is_empty()
                || !Self::strict_canonical_uuid_v4(canonical_id)
                || crate::decode_group_coordinate(canonical_group).is_none()
            {
                return Err("projection commit has invalid canonical identity".to_string());
            }

            let mut alias_ids = std::collections::HashSet::new();
            for authority in &request.aliases {
                if authority.owner_user_did != request.owner_user_did
                    || authority.canonical_conversation_id != canonical_id
                    || authority.canonical_group_id != canonical_group
                    || authority.alias_conversation_id != authority.alias_group_id
                    || authority.canonical_conversation_id == authority.alias_conversation_id
                    || Self::strict_canonical_uuid_v4(&authority.alias_conversation_id)
                    || crate::decode_group_coordinate(&authority.canonical_group_id).is_none()
                    || authority.canonical_group_id != authority.alias_group_id
                    || authority.alias_incarnation > authority.canonical_incarnation
                    || !alias_ids.insert(authority.alias_conversation_id.clone())
                {
                    return Err("projection commit has invalid alias authority".to_string());
                }
                if let Some(view) = canonical {
                    if view.epoch != authority.canonical_incarnation {
                        return Err(
                            "canonical incarnation does not match alias authority".to_string()
                        );
                    }
                }
            }

            // A group can never have two distinct canonical UUID owners. This
            // check runs before any upsert/deletion so an ambiguity is typed
            // and leaves every projection unchanged.
            let group_rows = self
                .conn
                .query_text(
                    "SELECT conversation_id FROM conversations
                     WHERE user_did = ?1 AND group_id = ?2
                     UNION SELECT conversation_id FROM conversation_group_aliases
                     WHERE user_did = ?1 AND group_id = ?2",
                    &[(1, &request.owner_user_did), (2, canonical_group)],
                    1,
                )
                .map_err(|e| format!("projection canonical-owner lookup: {:?}", e))?;
            let mut canonical_ids = Vec::new();
            for id in group_rows
                .into_iter()
                .filter_map(|row| row.into_iter().next().flatten())
            {
                if Self::strict_canonical_uuid_v4(&id)
                    && !canonical_ids.iter().any(|existing| existing == &id)
                {
                    canonical_ids.push(id);
                }
            }
            if !canonical_ids.iter().any(|id| id == canonical_id) {
                if canonical.is_some() {
                    canonical_ids.push(canonical_id.to_string());
                }
            }
            if canonical_ids.len() > 1 {
                canonical_ids.sort();
                return Ok(ConversationProjectionCommitOutcome::Ambiguous {
                    canonical_ids,
                    affected_rows: 0,
                });
            }

            if let Some(view) = canonical {
                catbird_mls::orchestrator::admission::validate_conversation_view(view)
                    .map_err(|e| e.to_string())?;
                if let Some(state) = &view.canonical_state {
                    if !state
                        .participants
                        .iter()
                        .any(|p| p.user_did.as_str() == request.owner_user_did)
                        || request.canonical_lifecycle.generation
                            != Some(state.coordinates.generation)
                        || request.canonical_lifecycle.state_version
                            != Some(state.coordinates.state_version)
                    {
                        return Err("Canonical coordinate fence or audience mismatch".into());
                    }
                } else if !request.canonical_lifecycle.is_unknown() {
                    return Err("Missing canonical policy for lifecycle fence".into());
                }
                if let Some(old) =
                    self.projection_canonical_state(&request.owner_user_did, canonical_id)?
                {
                    let next = view
                        .canonical_state
                        .as_ref()
                        .ok_or("Cannot discard canonical policy")?;
                    let merged =
                        catbird_mls::orchestrator::admission::merge_protected_conversation_policy(
                            Some(&old),
                            next,
                        )
                        .map_err(|e| e.to_string())?;
                    if merged.as_ref().is_some_and(|merged| merged != next)
                        || merged.is_none() && old != *next
                    {
                        return Ok(ConversationProjectionCommitOutcome::FenceMismatch {
                            affected_rows: 0,
                        });
                    }
                }
            }

            // Validate every lifecycle/incarnation fence before the first
            // mutation. Unknown lifecycle coordinates are acceptable for an
            // active row but cannot authorize a RESET_PENDING projection.
            let canonical_rows = self
                .conn
                .query_text(
                    "SELECT group_id FROM conversations
                     WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                    &[(1, &request.owner_user_did), (2, canonical_id)],
                    1,
                )
                .map_err(|e| format!("projection canonical lookup: {:?}", e))?;
            if !canonical_rows.is_empty() {
                if canonical_rows[0].first().and_then(|value| value.as_deref())
                    != Some(canonical_group)
                {
                    return Ok(ConversationProjectionCommitOutcome::FenceMismatch {
                        affected_rows: 0,
                    });
                }
                if let Some(view) = canonical {
                    if self
                        .projection_incarnation(canonical_group, canonical_id)?
                        .is_some_and(|epoch| epoch > view.epoch)
                    {
                        return Ok(ConversationProjectionCommitOutcome::FenceMismatch {
                            affected_rows: 0,
                        });
                    }
                    let states = self.conn.query_text("SELECT state FROM conversations WHERE user_did = ?1 AND conversation_id = ?2", &[(1, &request.owner_user_did), (2, canonical_id)], 1).map_err(|e| format!("Projection lifecycle read: {e:?}"))?;
                    if states
                        .first()
                        .and_then(|r| r.first())
                        .and_then(|v| v.as_deref())
                        .is_some_and(|state| matches!(state, "closed" | "device_removed"))
                        && view
                            .canonical_state
                            .as_ref()
                            .is_none_or(|state| state.coordinates.lifecycle.as_str() == "active")
                    {
                        return Ok(ConversationProjectionCommitOutcome::FenceMismatch {
                            affected_rows: 0,
                        });
                    }
                }
                let fence = if request.mode == ConversationProjectionCommitMode::Replay {
                    request
                        .aliases
                        .first()
                        .map(|authority| &authority.canonical_lifecycle)
                        .unwrap_or(&request.canonical_lifecycle)
                } else {
                    &request.canonical_lifecycle
                };
                if !self.projection_lifecycle_matches(
                    &request.owner_user_did,
                    canonical_id,
                    fence,
                    request.mode == ConversationProjectionCommitMode::Live,
                )? {
                    return Ok(ConversationProjectionCommitOutcome::FenceMismatch {
                        affected_rows: 0,
                    });
                }
                if request.mode == ConversationProjectionCommitMode::Replay {
                    let expected_incarnation = request
                        .aliases
                        .first()
                        .map(|authority| authority.canonical_incarnation)
                        .unwrap_or(0);
                    if self
                        .projection_incarnation(canonical_group, canonical_id)?
                        .unwrap_or(0)
                        != expected_incarnation
                    {
                        return Ok(ConversationProjectionCommitOutcome::FenceMismatch {
                            affected_rows: 0,
                        });
                    }
                }
            } else if request.mode == ConversationProjectionCommitMode::Replay {
                return Ok(ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 });
            }

            for authority in &request.aliases {
                let alias_rows = self
                    .conn
                    .query_text(
                        "SELECT group_id FROM conversations
                         WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                        &[
                            (1, &request.owner_user_did),
                            (2, &authority.alias_conversation_id),
                        ],
                        1,
                    )
                    .map_err(|e| format!("projection alias lookup: {:?}", e))?;
                if let Some(row) = alias_rows.first() {
                    let actual_group = row.first().and_then(|value| value.as_deref());
                    if actual_group != Some(authority.alias_group_id.as_str())
                        || !self.projection_lifecycle_matches(
                            &request.owner_user_did,
                            &authority.alias_conversation_id,
                            &authority.alias_lifecycle,
                            false,
                        )?
                        || self
                            .projection_incarnation(
                                &authority.alias_group_id,
                                &authority.alias_conversation_id,
                            )?
                            .unwrap_or(0)
                            != authority.alias_incarnation
                    {
                        return Ok(ConversationProjectionCommitOutcome::FenceMismatch {
                            affected_rows: 0,
                        });
                    }
                } else if authority.alias_incarnation != 0 {
                    // An already-retired alias is acceptable only when its
                    // authority carried the zero/unknown incarnation used by
                    // older web projections; a nonzero fence needs proof.
                    continue;
                }
            }

            let mut affected_rows = 0u32;
            if let Some(view) = canonical {
                // Defer roster validation until identity ambiguity and all
                // lifecycle fences have been checked. Ambiguous ownership is
                // a typed, no-mutation outcome even when the candidate view
                // is malformed; a unique authorized projection still fails
                // closed before its first write.
                let legacy_kind = Self::validate_member_views(&view.members)?;
                let conversation_kind = view
                    .canonical_state
                    .as_ref()
                    .map(|state| state.conversation_kind.as_str())
                    .unwrap_or(legacy_kind);
                self.upsert_conversation_mapping_in_transaction(
                    &request.owner_user_did,
                    &view.conversation_id,
                    &view.group_id,
                )?;
                affected_rows = affected_rows.saturating_add(1);
                if let Some(state) = &view.canonical_state {
                    let raw =
                        catbird_mls::orchestrator::canonical_transport::encode_conversation_state(
                            state,
                        )
                        .map_err(|e| e.to_string())?;
                    let raw = String::from_utf8(raw).map_err(|e| e.to_string())?;
                    self.conn.exec_with_text_params("UPDATE conversations SET canonical_state_json = ?1 WHERE user_did = ?2 AND conversation_id = ?3", &[(1, &raw), (2, &request.owner_user_did), (3, &view.conversation_id)]).map_err(|e| format!("Canonical policy write: {e:?}"))?;
                }

                let members_json = serde_json::to_string(
                    &view
                        .members
                        .iter()
                        .map(|member| member.did.clone())
                        .collect::<Vec<_>>(),
                )
                .map_err(|e| format!("projection member serialization: {}", e))?;
                let roster_json = serde_json::to_string(&view.members)
                    .map_err(|e| format!("projection roster serialization: {}", e))?;
                self.write_group_state_checked(
                    &view.group_id,
                    &view.conversation_id,
                    view.epoch,
                    &members_json,
                )?;
                self.write_roster_checked(&view.group_id, &view.conversation_id, &roster_json)?;
                let kind_rows = self
                    .conn
                    .query_text(
                        "SELECT conversation_kind FROM conversations
                         WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                        &[(1, &request.owner_user_did), (2, &view.conversation_id)],
                        1,
                    )
                    .map_err(|e| format!("projection conversation kind lookup: {:?}", e))?;
                if let Some(existing_kind) = kind_rows
                    .first()
                    .and_then(|row| row.first().and_then(|value| value.as_deref()))
                {
                    if existing_kind != conversation_kind {
                        return Err(format!(
                            "conversation {} kind changed from {} to {}",
                            view.conversation_id, existing_kind, conversation_kind
                        ));
                    }
                } else {
                    self.conn
                        .exec_with_text_params(
                            "UPDATE conversations SET conversation_kind = ?1
                             WHERE user_did = ?2 AND conversation_id = ?3",
                            &[
                                (1, conversation_kind),
                                (2, &request.owner_user_did),
                                (3, &view.conversation_id),
                            ],
                        )
                        .map_err(|e| format!("projection conversation kind: {:?}", e))?;
                }
                if let Some(metadata) = &view.metadata {
                    if let Some(name) = metadata.name.as_deref() {
                        self.conn
                            .exec_with_text_params(
                                "UPDATE conversations SET title = ?1
                                 WHERE user_did = ?2 AND conversation_id = ?3",
                                &[
                                    (1, name),
                                    (2, &request.owner_user_did),
                                    (3, &view.conversation_id),
                                ],
                            )
                            .map_err(|e| format!("projection metadata title: {:?}", e))?;
                    }
                    if let Some(description) = metadata.description.as_deref() {
                        self.conn
                            .exec_with_text_params(
                                "UPDATE conversations SET description = ?1
                                 WHERE user_did = ?2 AND conversation_id = ?3",
                                &[
                                    (1, description),
                                    (2, &request.owner_user_did),
                                    (3, &view.conversation_id),
                                ],
                            )
                            .map_err(|e| format!("projection metadata description: {:?}", e))?;
                    }
                    if let Some(avatar_url) = metadata.avatar_url.as_deref() {
                        self.conn
                            .exec_with_text_params(
                                "UPDATE conversations SET avatar_blob_locator = ?1
                                 WHERE user_did = ?2 AND conversation_id = ?3",
                                &[
                                    (1, avatar_url),
                                    (2, &request.owner_user_did),
                                    (3, &view.conversation_id),
                                ],
                            )
                            .map_err(|e| format!("projection metadata avatar: {:?}", e))?;
                    }
                }
                if let Some(sequencer_did) = &view.sequencer_did {
                    self.conn
                        .exec_with_text_params(
                            "UPDATE conversations SET sequencer_did = ?1
                             WHERE user_did = ?2 AND conversation_id = ?3",
                            &[
                                (1, sequencer_did),
                                (2, &request.owner_user_did),
                                (3, &view.conversation_id),
                            ],
                        )
                        .map_err(|e| format!("projection sequencer: {:?}", e))?;
                }
            }

            let mut retired_any = false;
            for authority in &request.aliases {
                // The canonical upsert may have converged a legacy row in
                // place. Either way, retain the historical group alias under
                // the canonical owner before retiring the duplicate row.
                self.insert_group_alias(
                    &request.owner_user_did,
                    canonical_id,
                    &authority.alias_group_id,
                )?;
                let alias_rows = self
                    .conn
                    .query_text(
                        "SELECT group_id FROM conversations
                         WHERE user_did = ?1 AND conversation_id = ?2 LIMIT 1",
                        &[
                            (1, &request.owner_user_did),
                            (2, &authority.alias_conversation_id),
                        ],
                        1,
                    )
                    .map_err(|e| format!("projection alias recheck: {:?}", e))?;
                if let Some(row) = alias_rows.first() {
                    if row.first().and_then(|value| value.as_deref())
                        == Some(authority.alias_group_id.as_str())
                    {
                        self.conn
                            .exec_with_text_params(
                                "DELETE FROM conversations
                                 WHERE user_did = ?1 AND conversation_id = ?2
                                   AND group_id = ?3",
                                &[
                                    (1, &request.owner_user_did),
                                    (2, &authority.alias_conversation_id),
                                    (3, &authority.alias_group_id),
                                ],
                            )
                            .map_err(|e| format!("projection alias retire: {:?}", e))?;
                        retired_any = true;
                        affected_rows = affected_rows.saturating_add(1);
                    }
                }
            }

            if retired_any {
                Ok(ConversationProjectionCommitOutcome::Retired { affected_rows })
            } else {
                Ok(ConversationProjectionCommitOutcome::AlreadyAbsent { affected_rows })
            }
        })();

        match result {
            Ok(outcome) => {
                self.conn.exec_raw("COMMIT").map_err(Self::store_err)?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = self.conn.exec_raw("ROLLBACK");
                Err(OrchestratorError::Storage(error))
            }
        }
    }

    async fn delete_conversations(&self, user_did: &str, ids: &[&str]) -> Result<()> {
        self.ensure_owner_matches_active(user_did)
            .map_err(OrchestratorError::Storage)?;
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
        let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
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
                .mark_reset_pending_sync(
                    conversation_id,
                    new_group_id,
                    reset_generation,
                    notified_at_ms,
                )
                .map_err(OrchestratorError::Storage),
            _ => {
                // A generic state setter is not allowed to erase an
                // authoritative RESET_PENDING payload. Only the fenced
                // winner commit (which also installs stable mapping, group
                // state, and roster) may clear that recovery authority.
                self.conn
                    .exec_raw("BEGIN IMMEDIATE")
                    .map_err(Self::store_err)?;
                let result = (|| -> std::result::Result<(), OrchestratorError> {
                    let rows = self
                        .conn
                        .query_text(
                            "SELECT state FROM conversations
                             WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                            &[(1, conversation_id), (2, &active_user_did)],
                            1,
                        )
                        .map_err(Self::store_err)?;
                    if rows
                        .first()
                        .and_then(|row| row.first())
                        .and_then(|value| value.as_deref())
                        == Some("reset_pending")
                    {
                        return Err(OrchestratorError::Storage(
                            "reset_pending recovery may only be cleared by the fenced winner"
                                .to_string(),
                        ));
                    }
                    if let Some(current) = rows
                        .first()
                        .and_then(|row| row.first())
                        .and_then(|value| value.as_deref())
                    {
                        if matches!(current, "closed" | "device_removed") && current != state_str {
                            return Err(OrchestratorError::Storage(
                                "terminal state requires accepted account-exit authority".into(),
                            ));
                        }
                    }
                    self.conn
                        .exec_with_text_params(
                            "UPDATE conversations
                             SET state = ?1,
                                 reset_new_group_id = NULL,
                                 reset_generation = NULL,
                                 reset_notified_at_ms = NULL,
                                 state_version = COALESCE(state_version, 0) + 1
                             WHERE conversation_id = ?2 AND user_did = ?3",
                            &[(1, state_str), (2, conversation_id), (3, &active_user_did)],
                        )
                        .map_err(Self::store_err)
                })();
                match result {
                    Ok(()) => self.conn.exec_raw("COMMIT").map_err(Self::store_err),
                    Err(error) => {
                        let _ = self.conn.exec_raw("ROLLBACK");
                        Err(error)
                    }
                }
            }
        }
    }

    /// Read persisted state (spec §8.2). The WASM backend stores the state
    /// tag in `state` and reset payload in three nullable columns; we
    /// reconstruct `ConversationState` from whichever applies.
    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<ConversationState>> {
        let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
        let rows = self
            .conn
            .query_text(
                "SELECT state, reset_new_group_id, reset_generation, reset_notified_at_ms
                 FROM conversations WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                &[(1, conversation_id), (2, &active_user_did)],
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
            "closed" | "device_removed" => {
                if row.iter().skip(1).any(Option::is_some) {
                    return Err(OrchestratorError::Storage(
                        "terminal state contains live reset work".into(),
                    ));
                }
                Ok(Some(if tag == "closed" {
                    ConversationState::Closed
                } else {
                    ConversationState::DeviceRemoved
                }))
            }
            "reset_pending" => {
                let new_group_id = row.get(1).and_then(|c| c.clone());
                let reset_generation = row
                    .get(2)
                    .and_then(|c| c.as_deref())
                    .and_then(|s| s.parse::<i32>().ok());
                let notified_at_ms = row
                    .get(3)
                    .and_then(|c| c.as_deref())
                    .and_then(|s| s.parse::<i64>().ok());
                match (new_group_id, reset_generation, notified_at_ms) {
                    (Some(g), Some(r), Some(t)) if !g.is_empty() => {
                        Ok(Some(ConversationState::ResetPending {
                            new_group_id: g,
                            reset_generation: r,
                            notified_at_ms: t,
                        }))
                    }
                    // A reset tag without its complete durable payload is not
                    // authoritative. Fail closed instead of reinterpreting a
                    // torn write as NeedsRejoin and risking a stale winner.
                    _ => Err(OrchestratorError::Storage(
                        "reset_pending conversation is missing its durable payload".to_string(),
                    )),
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
        self.mark_reset_pending_sync(
            conversation_id,
            new_group_id_hex,
            reset_generation,
            notified_at_ms,
        )
        .map_err(OrchestratorError::Storage)
    }

    async fn adopt_reset_pending_target(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_old_target: &str,
        authoritative_new_target: &str,
    ) -> Result<bool> {
        let expected_old_target = crate::decode_group_coordinate(expected_old_target)
            .map(|bytes| hex::encode(bytes))
            .ok_or_else(|| {
                OrchestratorError::Storage(
                    "old reset target is not a supported group coordinate".to_string(),
                )
            })?;
        let authoritative_new_target = crate::decode_group_coordinate(authoritative_new_target)
            .map(|bytes| hex::encode(bytes))
            .ok_or_else(|| {
                OrchestratorError::Storage(
                    "authoritative reset target is not a supported group coordinate".to_string(),
                )
            })?;
        let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
        self.conn
            .exec_raw("BEGIN IMMEDIATE")
            .map_err(Self::store_err)?;
        let result = (|| -> Result<bool> {
            let rows = self
                .conn
                .query_text(
                    "SELECT reset_generation, reset_new_group_id, state,
                            reset_high_water_generation, reset_high_water_group_id
                     FROM conversations WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                    &[(1, conversation_id), (2, &active_user_did)],
                    5,
                )
                .map_err(Self::store_err)?;
            let Some(row) = rows.first() else {
                return Ok(false);
            };
            let generation = row
                .first()
                .and_then(|value| value.as_deref())
                .and_then(|value| value.parse::<i32>().ok());
            let target = row.get(1).and_then(|value| value.as_deref());
            if generation != Some(expected_generation)
                || row.get(2).and_then(|value| value.as_deref()) != Some("reset_pending")
                || target != Some(expected_old_target.as_str())
            {
                return Ok(false);
            }
            if expected_old_target == authoritative_new_target {
                return Ok(true);
            }
            self.conn
                .exec_with_text_params(
                    "UPDATE conversations SET reset_new_group_id = ?1,
                        reset_high_water_generation = ?3,
                        reset_high_water_group_id = ?1,
                        state_version = COALESCE(state_version, 0) + 1
                     WHERE conversation_id = ?2 AND state = 'reset_pending'
                       AND user_did = ?5 AND reset_generation = ?3 AND reset_new_group_id = ?4",
                    &[
                        (1, &authoritative_new_target),
                        (2, conversation_id),
                        (3, &expected_generation.to_string()),
                        (4, &expected_old_target),
                        (5, &active_user_did),
                    ],
                )
                .map_err(Self::store_err)?;
            Ok(true)
        })();
        match result {
            Ok(value) => {
                self.conn.exec_raw("COMMIT").map_err(Self::store_err)?;
                Ok(value)
            }
            Err(error) => {
                let _ = self.conn.exec_raw("ROLLBACK");
                Err(error)
            }
        }
    }

    async fn complete_reset_pending(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_new_group_id_hex: &str,
        landed_epoch: u64,
    ) -> Result<bool> {
        let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
        let user_did = self
            .conn
            .query_text(
                "SELECT user_did FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                &[(1, conversation_id), (2, &active_user_did)],
                1,
            )
            .map_err(Self::store_err)?
            .first()
            .and_then(|row| row.first().and_then(|value| value.clone()))
            .ok_or_else(|| {
                OrchestratorError::Storage(format!(
                    "conversation {} does not exist",
                    conversation_id
                ))
            })?;
        let members = self
            .roster_members_checked(expected_new_group_id_hex)
            .map_err(OrchestratorError::Storage)?;
        let expected_state_version = self
            .conversation_state_version(&user_did, conversation_id)
            .map_err(OrchestratorError::Storage)?;
        self.complete_reset_pending_projection(
            &user_did,
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_new_group_id_hex,
            landed_epoch,
            &members,
        )
        .map_err(OrchestratorError::Storage)
    }

    async fn complete_account_exit(
        &self,
        conversation_id: &str,
        expected_group_id_hex: &str,
        expected_reset_generation: Option<i32>,
        terminal_epoch: u64,
        terminal_state: ConversationState,
    ) -> Result<bool> {
        if !Self::strict_canonical_uuid_v4(conversation_id)
            || expected_group_id_hex.len() != 64
            || !expected_group_id_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || expected_reset_generation.is_some_and(|generation| generation <= 0)
            || !matches!(
                terminal_state,
                ConversationState::Closed | ConversationState::DeviceRemoved
            )
        {
            return Ok(false);
        }
        if terminal_epoch > 9_007_199_254_740_991 {
            return Ok(false);
        }
        let Ok(epoch_sql) = i64::try_from(terminal_epoch) else {
            return Ok(false);
        };
        let owner = self.active_user_did().map_err(OrchestratorError::Storage)?;
        let tx = SqliteTransactionGuard::begin(&self.conn, "account exit")
            .map_err(OrchestratorError::Storage)?;
        let rows = self
            .conn
            .query_text(
                "SELECT group_id, state, reset_new_group_id, reset_generation,
                    reset_notified_at_ms, needs_rejoin, reset_high_water_generation,
                    reset_high_water_group_id, terminal_epoch
             FROM conversations WHERE user_did = ?1 AND conversation_id = ?2",
                &[(1, &owner), (2, conversation_id)],
                9,
            )
            .map_err(Self::store_err)?;
        let Some(row) = rows.first() else {
            return Ok(false);
        };
        let value = |index: usize| row.get(index).and_then(|value| value.as_deref());
        let pending = value(1) == Some("reset_pending")
            || value(2).is_some()
            || value(3).is_some()
            || value(4).is_some();
        let generation = expected_reset_generation.map(|generation| generation.to_string());
        let terminal_tag = terminal_state.tag();
        if value(6).is_some_and(|generation| {
            !generation
                .parse::<i32>()
                .is_ok_and(|generation| generation > 0)
        }) {
            return Ok(false);
        }
        if value(6).is_some() != value(7).is_some()
            || value(7).is_some_and(|group| crate::decode_group_coordinate(group).is_none())
        {
            return Ok(false);
        }
        if value(0) == Some(expected_group_id_hex) {
            let current_epoch = if matches!(value(1), Some("closed" | "device_removed")) {
                value(8).and_then(|epoch| epoch.parse::<u64>().ok())
            } else {
                let epochs = self.conn.query_text(
                    "SELECT epoch FROM group_states WHERE group_id = ?1 AND conversation_id = ?2",
                    &[(1, expected_group_id_hex), (2, conversation_id)], 1,
                ).map_err(Self::store_err)?;
                match epochs.first() {
                    None => None, // No durable epoch exists to compare; fail closed.
                    Some(row) => row
                        .first()
                        .and_then(|value| value.as_deref())
                        .and_then(|epoch| epoch.parse::<u64>().ok()),
                }
            };
            if !current_epoch.is_some_and(|epoch| epoch <= terminal_epoch) {
                return Ok(false);
            }
        }
        let exact_terminal = value(0) == Some(expected_group_id_hex)
            && value(1) == Some(terminal_tag)
            && value(8).and_then(|epoch| epoch.parse::<u64>().ok()) == Some(terminal_epoch)
            && !pending
            && value(5) == Some("0");
        if exact_terminal {
            return Ok(expected_reset_generation.is_none()
                || (value(6) == generation.as_deref() && value(7) == Some(expected_group_id_hex)));
        }
        if value(1) == Some("closed") {
            return Ok(false);
        }
        match expected_reset_generation {
            Some(_) => {
                if value(1) != Some("reset_pending")
                    || value(2) != Some(expected_group_id_hex)
                    || value(3) != generation.as_deref()
                    || !value(4)
                        .and_then(|timestamp| timestamp.parse::<i64>().ok())
                        .is_some_and(|timestamp| timestamp >= 0)
                    || value(5) != Some("1")
                    || value(6) != generation.as_deref()
                    || value(7) != Some(expected_group_id_hex)
                {
                    return Ok(false);
                }
            }
            None => {
                if pending || value(0) != Some(expected_group_id_hex) {
                    return Ok(false);
                }
            }
        }
        // Retain both old and terminal group coordinates, without touching
        // MLS keys, group state, rosters or alias-bound encrypted history.
        let Some(old_group) = value(0) else {
            return Ok(false);
        };
        self.insert_group_alias(&owner, conversation_id, old_group)
            .map_err(OrchestratorError::Storage)?;
        self.insert_group_alias(&owner, conversation_id, expected_group_id_hex)
            .map_err(OrchestratorError::Storage)?;
        self.conn
            .exec_with_mixed_params(
                "UPDATE conversations SET group_id = ?1, state = ?2, terminal_epoch = ?3,
                 reset_new_group_id = NULL, reset_generation = NULL,
                 reset_notified_at_ms = NULL, needs_rejoin = 0,
                 state_version = COALESCE(state_version, 0) + 1
             WHERE user_did = ?4 AND conversation_id = ?5",
                &[
                    (1, expected_group_id_hex),
                    (2, terminal_tag),
                    (4, &owner),
                    (5, conversation_id),
                ],
                &[(3, epoch_sql)],
            )
            .map_err(Self::store_err)?;
        tx.commit("account exit")
            .map_err(OrchestratorError::Storage)?;
        Ok(true)
    }

    async fn clear_reset_pending_for_delete(
        &self,
        conversation_id: &str,
        expected_generation: i32,
    ) -> Result<bool> {
        let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
        self.conn
            .exec_raw("BEGIN IMMEDIATE")
            .map_err(Self::store_err)?;
        let result = (|| -> Result<bool> {
            // Cleanup is itself a fenced state transition.  Keep the
            // high-water generation/target intact so a late reset replay
            // cannot reopen an older candidate after this cancellation.
            self.conn
                .exec_with_text_params(
                    "UPDATE conversations
                     SET reset_new_group_id = NULL,
                         reset_generation = NULL,
                         reset_notified_at_ms = NULL,
                         state_version = COALESCE(state_version, 0) + 1
                     WHERE conversation_id = ?1 AND user_did = ?3
                       AND state = 'reset_pending' AND reset_generation = ?2",
                    &[
                        (1, conversation_id),
                        (2, &expected_generation.to_string()),
                        (3, &active_user_did),
                    ],
                )
                .map_err(Self::store_err)?;
            let changed = self
                .conn
                .query_text("SELECT changes()", &[], 1)
                .map_err(Self::store_err)?
                .first()
                .and_then(|row| row.first().and_then(|value| value.as_deref()))
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0);
            Ok(changed > 0)
        })();
        match result {
            Ok(value) => {
                self.conn.exec_raw("COMMIT").map_err(Self::store_err)?;
                Ok(value)
            }
            Err(error) => {
                let _ = self.conn.exec_raw("ROLLBACK");
                Err(error)
            }
        }
    }

    async fn set_conversation_sequencer(
        &self,
        conversation_id: &str,
        sequencer_did: &str,
    ) -> Result<()> {
        let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
        self.conn
            .exec_with_text_params(
                "UPDATE conversations SET sequencer_did = ?1
                 WHERE conversation_id = ?2 AND user_did = ?3",
                &[
                    (1, sequencer_did),
                    (2, conversation_id),
                    (3, &active_user_did),
                ],
            )
            .map_err(Self::store_err)
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()> {
        let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
        self.conn
            .exec_with_text_params(
                "UPDATE conversations SET needs_rejoin = 1
                 WHERE conversation_id = ?1 AND user_did = ?2",
                &[(1, conversation_id), (2, &active_user_did)],
            )
            .map_err(Self::store_err)
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> Result<bool> {
        let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
        let rows = self
            .conn
            .query_text(
                "SELECT needs_rejoin FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                &[(1, conversation_id), (2, &active_user_did)],
                1,
            )
            .map_err(Self::store_err)?;

        if rows.is_empty() {
            return Ok(false);
        }
        Ok(rows[0][0].as_deref() == Some("1"))
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()> {
        let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
        self.conn
            .exec_with_text_params(
                "UPDATE conversations SET needs_rejoin = 0
                 WHERE conversation_id = ?1 AND user_did = ?2",
                &[(1, conversation_id), (2, &active_user_did)],
            )
            .map_err(Self::store_err)
    }

    async fn store_message(&self, message: &Message) -> Result<()> {
        // `Message` does not carry a tenant field because the shared trait
        // predates browser multi-account storage. Bind the implicit owner
        // before touching the row; a stale callback after logout/account
        // switch must fail closed instead of writing into another tenant's
        // transcript.
        self.require_active_conversation_owner(&message.conversation_id)
            .map_err(OrchestratorError::Storage)?;
        let delivery_status_str = message
            .delivery_status
            .as_ref()
            .map(|ds| serde_json::to_string(ds).unwrap_or_else(|_| "\"delivered\"".to_string()))
            .unwrap_or_else(|| "\"delivered\"".to_string());

        let timestamp_str = message.timestamp.to_rfc3339();
        let is_own_str = if message.is_own { "1" } else { "0" };

        if let Some(same) =
            self.existing_message_fingerprint(message, &delivery_status_str, &timestamp_str)?
        {
            if same {
                return Ok(());
            }
            return Err(OrchestratorError::Storage(format!(
                "message {} already exists with a conflicting fingerprint",
                message.id
            )));
        }

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
                        "INSERT INTO messages
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
                        "INSERT INTO messages
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
        let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
        // During the identity migration, old rows may still be keyed by any
        // historical group id. Query the complete alias set and keep each
        // message row's stored id for field-level decryption/AAD.
        let stable_rows = self
            .conn
            .query_text(
                "SELECT conversation_id, user_did FROM conversations
                 WHERE conversation_id = ?1 AND user_did = ?2 LIMIT 1",
                &[(1, conversation_id), (2, &active_user_did)],
                2,
            )
            .map_err(Self::store_err)?;
        let (stable_id, user_did) = if let Some(row) = stable_rows.first() {
            (
                row.first().and_then(|value| value.clone()),
                row.get(1).and_then(|value| value.clone()),
            )
        } else {
            // Preserve the legacy group-id entry point when it has exactly
            // one durable owner. A group alias shared by multiple users is
            // ambiguous without an authenticated user and must fail closed.
            let alias_rows = self
                .conn
                .query_text(
                    "SELECT conversation_id, user_did FROM conversation_group_aliases
                     WHERE group_id = ?1 AND user_did = ?2",
                    &[(1, conversation_id), (2, &active_user_did)],
                    2,
                )
                .map_err(Self::store_err)?;
            let owners: Vec<(String, String)> = alias_rows
                .into_iter()
                .filter_map(|row| Some((row.first()?.clone()?, row.get(1)?.clone()?)))
                .collect();
            if owners.len() > 1 && owners.windows(2).any(|pair| pair[0] != pair[1]) {
                return Err(OrchestratorError::Storage(format!(
                    "ambiguous message group alias {}",
                    conversation_id
                )));
            }
            owners
                .first()
                .map(|(stable, user)| (Some(stable.clone()), Some(user.clone())))
                .unwrap_or((None, None))
        };
        let stable_id = stable_id.ok_or_else(|| {
            OrchestratorError::Storage(format!(
                "conversation {} has no unique persisted mapping for active user",
                conversation_id
            ))
        })?;
        let mut message_ids = vec![stable_id.clone()];
        if !message_ids.iter().any(|id| id == conversation_id) {
            message_ids.push(conversation_id.to_owned());
        }
        let owner_did = user_did.unwrap_or(active_user_did);
        for alias in self
            .conversation_group_aliases(&owner_did, &stable_id)
            .map_err(OrchestratorError::Storage)?
        {
            if !message_ids.contains(&alias) {
                message_ids.push(alias);
            }
        }
        let placeholders = (1..=message_ids.len())
            .map(|index| format!("?{}", index))
            .collect::<Vec<_>>()
            .join(", ");
        let text_params: Vec<(i32, &str)> = message_ids
            .iter()
            .enumerate()
            .map(|(index, value)| ((index + 1) as i32, value.as_str()))
            .collect();
        let before_index = (message_ids.len() + 1) as i32;
        let limit_index = (message_ids.len() + 2) as i32;

        // Columns (0-based): 0 id, 1 conv, 2 sender, 3 text, 4 seq, 5 epoch,
        // 6 created_at, 7 is_own, 8 delivery_status, 9 payload_json (TEXT),
        // 10 payload_encrypted (BLOB).
        // `is_tombstone` filtered server-side via COALESCE so legacy rows
        // (with the column NULL pre-migration) still surface.
        let blob_cols = [10usize];
        let rows = if let Some(before) = before_sequence {
            self.conn
                .query_text_int_blob(
                    &format!(
                        "SELECT id, conversation_id, sender_did, text, sequence_number, epoch,
                                created_at, is_own, delivery_status, payload_json, payload_encrypted
                         FROM messages
                         WHERE conversation_id IN ({}) AND sequence_number < ?{}
                           AND COALESCE(is_tombstone, 0) = 0
                                ORDER BY sequence_number DESC, conversation_id DESC,
                                         epoch DESC, id DESC
                         LIMIT ?{}",
                        placeholders, before_index, limit_index
                    ),
                    &text_params,
                    &[(before_index, before as i64), (limit_index, limit as i64)],
                    11,
                    &blob_cols,
                )
                .map_err(Self::store_err)?
        } else {
            self.conn
                .query_text_int_blob(
                    &format!(
                        "SELECT id, conversation_id, sender_did, text, sequence_number, epoch,
                                created_at, is_own, delivery_status, payload_json, payload_encrypted
                         FROM messages
                         WHERE conversation_id IN ({})
                           AND COALESCE(is_tombstone, 0) = 0
                         ORDER BY sequence_number DESC, conversation_id DESC,
                                    epoch DESC, id DESC
                         LIMIT ?{}",
                        placeholders, before_index
                    ),
                    &text_params,
                    &[(before_index, limit as i64)],
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
                let seq: u64 = row[4].0.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                let epoch: u64 = row[5].0.as_ref().and_then(|s| s.parse().ok()).unwrap_or(0);
                let created_at = row[6].0.clone().unwrap_or_default();
                let is_own = row[7].0.as_deref() == Some("1");
                let delivery_status: Option<DeliveryStatus> =
                    row[8].0.as_ref().and_then(|s| serde_json::from_str(s).ok());
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
        let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
        self.conn
            .exists(
                "SELECT 1 FROM messages m
                 WHERE m.id = ?1 AND EXISTS (
                   SELECT 1 FROM conversations c
                   WHERE c.user_did = ?2 AND (
                     c.conversation_id = m.conversation_id OR EXISTS (
                       SELECT 1 FROM conversation_group_aliases a
                       WHERE a.user_did = ?2 AND a.conversation_id = c.conversation_id
                         AND a.group_id = m.conversation_id
                     )
                   )
                 )",
                &[(1, message_id), (2, &active_user_did)],
            )
            .map_err(Self::store_err)
    }

    async fn get_sync_cursor(&self, user_did: &str) -> Result<SyncCursor> {
        self.ensure_owner_matches_active(user_did)
            .map_err(OrchestratorError::Storage)?;
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
        self.ensure_owner_matches_active(user_did)
            .map_err(OrchestratorError::Storage)?;
        let convos_cursor = cursor.conversations_cursor.as_deref().unwrap_or("");
        let msgs_cursor = cursor.messages_cursor.as_deref().unwrap_or("");
        self.conn
            .exec_raw("BEGIN IMMEDIATE")
            .map_err(Self::store_err)?;
        let result = (|| -> std::result::Result<(), OrchestratorError> {
            self.conn
                .exec_with_text_params(
                    "UPDATE sync_cursors SET conversations_cursor = ?2,
                            messages_cursor = ?3 WHERE user_did = ?1",
                    &[(1, user_did), (2, convos_cursor), (3, msgs_cursor)],
                )
                .map_err(Self::store_err)?;
            let changed = self
                .conn
                .query_text("SELECT changes()", &[], 1)
                .map_err(Self::store_err)?
                .first()
                .and_then(|row| row.first().and_then(|value| value.as_deref()))
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0);
            if changed == 0 {
                self.conn
                    .exec_with_text_params(
                        "INSERT INTO sync_cursors
                            (user_did, conversations_cursor, messages_cursor)
                         VALUES (?1, ?2, ?3)",
                        &[(1, user_did), (2, convos_cursor), (3, msgs_cursor)],
                    )
                    .map_err(Self::store_err)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => self.conn.exec_raw("COMMIT").map_err(Self::store_err),
            Err(error) => {
                let _ = self.conn.exec_raw("ROLLBACK");
                Err(error)
            }
        }
    }

    async fn set_group_state(&self, state: &GroupState) -> Result<()> {
        let owner = self
            .require_active_group_owner(&state.group_id)
            .map_err(OrchestratorError::Storage)?;
        if owner != state.conversation_id {
            return Err(OrchestratorError::Storage(format!(
                "group {} is owned by conversation {}, not {}",
                state.group_id, owner, state.conversation_id
            )));
        }
        let members_json = serde_json::to_string(&state.members)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        self.write_group_state_checked(
            &state.group_id,
            &state.conversation_id,
            state.epoch,
            &members_json,
        )
        .map_err(OrchestratorError::Storage)
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
        self.require_active_group_owner(group_id)
            .map_err(OrchestratorError::Storage)?;

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
        let exists = self
            .conn
            .exists(
                "SELECT 1 FROM group_states WHERE group_id = ?1",
                &[(1, group_id)],
            )
            .map_err(Self::store_err)?;
        if !exists {
            return Ok(());
        }
        self.require_active_group_owner(group_id)
            .map_err(OrchestratorError::Storage)?;
        self.conn
            .exec_with_text_params(
                "DELETE FROM group_states WHERE group_id = ?1",
                &[(1, group_id)],
            )
            .map_err(Self::store_err)
    }

    async fn get_recovery_state(&self) -> Result<PersistedRecoveryState> {
        let owner = self
            .active_user_did
            .borrow()
            .clone()
            .ok_or_else(|| OrchestratorError::Storage("recovery owner unavailable".into()))?;
        let rows = self
            .conn
            .query_text(
                "SELECT id,value FROM browser_recovery_v2 WHERE owner=?1",
                &[(1, &owner)],
                2,
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        let mut state = PersistedRecoveryState::default();
        for row in rows {
            let id = row[0]
                .as_deref()
                .ok_or_else(|| OrchestratorError::Storage("corrupt recovery key".into()))?;
            let raw = row[1]
                .as_deref()
                .ok_or_else(|| OrchestratorError::Storage("corrupt recovery value".into()))?;
            if id == "global" {
                state.last_global_rejoin_attempt_at_ms =
                    Some(serde_json::from_str(raw).map_err(|e| {
                        OrchestratorError::Storage(format!("recovery timestamp: {e}"))
                    })?);
            } else {
                let entry: PersistedRecoveryBackoff = serde_json::from_str(raw)
                    .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
                if entry.conversation_id != id {
                    return Err(OrchestratorError::Storage(
                        "recovery identity mismatch".into(),
                    ));
                }
                state.entries.push(entry);
            }
        }
        Ok(state)
    }
    async fn set_recovery_backoff(&self, entry: &PersistedRecoveryBackoff) -> Result<()> {
        self.write_recovery_value(
            &entry.conversation_id,
            &serde_json::to_string(entry).map_err(|e| OrchestratorError::Storage(e.to_string()))?,
        )
    }
    async fn clear_recovery_backoff(&self, id: &str) -> Result<()> {
        let owner = self
            .active_user_did
            .borrow()
            .clone()
            .ok_or_else(|| OrchestratorError::Storage("recovery owner unavailable".into()))?;
        self.conn
            .exec_with_text_params(
                "DELETE FROM browser_recovery_v2 WHERE owner=?1 AND id=?2",
                &[(1, &owner), (2, id)],
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        self.conn
            .ensure_durable()
            .map_err(|e| OrchestratorError::Storage(e.to_string()))
    }
    async fn set_last_global_rejoin_attempt_at(&self, at_ms: i64) -> Result<()> {
        self.write_recovery_value("global", &at_ms.to_string())
    }

    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[
            "get_recovery_state",
            "set_recovery_backoff",
            "clear_recovery_backoff",
            "set_last_global_rejoin_attempt_at",
            "commit_conversation_projection",
            "get_conversation_state",
            "mark_reset_pending",
            "adopt_reset_pending_target",
            "complete_reset_pending",
            "complete_account_exit",
            "clear_reset_pending_for_delete",
            "set_conversation_sequencer",
        ]
    }
}

impl WasmStorageBackend {
    /// Encode a message's exact stored identity into a deterministic,
    /// versioned cursor. The stored conversation id is intentionally not
    /// replaced with the stable UI id: encrypted rows may be authenticated
    /// against a historical group alias.
    pub fn encode_history_cursor(message: &Message) -> std::result::Result<String, String> {
        let cursor = MessageHistoryCursor {
            version: 1,
            sequence_number: message.sequence_number,
            epoch: message.epoch,
            conversation_id: message.conversation_id.clone(),
            id: message.id.clone(),
        };
        let bytes = serde_json::to_vec(&cursor)
            .map_err(|error| format!("history cursor encode: {}", error))?;
        Ok(format!("v1.{}", URL_SAFE_NO_PAD.encode(bytes)))
    }

    fn decode_history_cursor(value: &str) -> std::result::Result<MessageHistoryCursor, String> {
        let encoded = value
            .strip_prefix("v1.")
            .ok_or_else(|| "history cursor has an unsupported version".to_string())?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| format!("history cursor is not valid base64: {}", error))?;
        let cursor: MessageHistoryCursor = serde_json::from_slice(&bytes)
            .map_err(|error| format!("history cursor payload is invalid: {}", error))?;
        if cursor.version != 1 || cursor.conversation_id.is_empty() || cursor.id.is_empty() {
            return Err("history cursor has invalid identity fields".to_string());
        }
        Ok(cursor)
    }

    /// Fetch rows strictly before a composite cursor. The shared storage
    /// trait still exposes numeric `before_sequence` for desktop parity; the
    /// browser-facing API uses this method so reset generations with reused
    /// sequence numbers cannot duplicate or skip history rows.
    pub async fn get_messages_before_cursor(
        &self,
        conversation_id: &str,
        limit: u32,
        before: Option<&str>,
    ) -> Result<Vec<Message>> {
        let limit = limit.min(10_000);
        let legacy_sequence = before
            .filter(|value| !value.starts_with("v1."))
            .map(|value| {
                value.parse::<u64>().map_err(|_| {
                    OrchestratorError::Storage(
                        "history cursor is neither a versioned cursor nor a legacy sequence"
                            .to_string(),
                    )
                })
            })
            .transpose()?;
        let cursor = before
            .filter(|value| value.starts_with("v1."))
            .map(Self::decode_history_cursor)
            .transpose()
            .map_err(OrchestratorError::Storage)?;
        if let Some(cursor) = cursor.as_ref() {
            // A cursor is scoped to one stable conversation, even though its
            // stored coordinate may be a historical group alias for AAD. Do
            // not silently apply a cursor copied from another tenant or
            // conversation to the requested history stream.
            let active_user_did = self.active_user_did().map_err(OrchestratorError::Storage)?;
            let requested = self
                .resolve_conversation_mapping(&active_user_did, conversation_id)
                .map_err(OrchestratorError::Storage)?
                .ok_or_else(|| {
                    OrchestratorError::Storage(format!(
                        "history conversation {} has no active-user mapping",
                        conversation_id
                    ))
                })?;
            let cursor_owner = self
                .resolve_conversation_mapping(&active_user_did, &cursor.conversation_id)
                .map_err(OrchestratorError::Storage)?
                .ok_or_else(|| {
                    OrchestratorError::Storage(
                        "history cursor is not bound to an authorized alias".to_string(),
                    )
                })?;
            if requested.0 != cursor_owner.0 {
                return Err(OrchestratorError::Storage(
                    "history cursor conversation does not match requested conversation".to_string(),
                ));
            }
        }
        if let Some(sequence) = legacy_sequence {
            return MLSStorageBackend::get_messages(self, conversation_id, limit, Some(sequence))
                .await;
        }
        let probe_before = cursor
            .as_ref()
            .and_then(|cursor| cursor.sequence_number.checked_add(1));
        let probe_limit = if cursor.is_some() { 10_000 } else { limit };
        let mut messages =
            MLSStorageBackend::get_messages(self, conversation_id, probe_limit, probe_before)
                .await?;
        if let Some(cursor) = cursor {
            messages.retain(|message| {
                (
                    message.sequence_number,
                    message.conversation_id.as_str(),
                    message.epoch,
                    message.id.as_str(),
                ) < (
                    cursor.sequence_number,
                    cursor.conversation_id.as_str(),
                    cursor.epoch,
                    cursor.id.as_str(),
                )
            });
        }
        messages.truncate(limit as usize);
        Ok(messages)
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[cfg(not(feature = "inventory-worker-tests"))]
    wasm_bindgen_test_configure!(run_in_browser);

    const TEST_DB_KEY: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    async fn new_storage() -> WasmStorageBackend {
        SqliteConn::initialize_opfs()
            .await
            .expect("initialize protected Worker OPFS");
        let db_path = format!("catbird-mls-web-test-{}.db", uuid::Uuid::new_v4());
        let conn = SqliteConn::open(&db_path, TEST_DB_KEY).expect("open sqlite");
        WasmStorageBackend::ensure_schema(&conn).expect("ensure schema");
        WasmStorageBackend::new(Rc::new(conn))
    }

    #[wasm_bindgen_test]
    async fn conversation_sequencer_did_round_trips() {
        let storage = new_storage().await;
        let user_did = "did:plc:alice";
        let conversation_id = "conv-sequencer";
        let group_id = conversation_id;
        let sequencer_did = "did:web:ds-b.example";

        storage
            .ensure_conversation_exists(user_did, conversation_id, group_id)
            .await
            .expect("create conversation");
        storage
            .set_conversation_sequencer(conversation_id, sequencer_did)
            .await
            .expect("persist sequencer");
        assert!(
            storage
                .implemented_optional_methods()
                .contains(&"set_conversation_sequencer"),
            "storage capabilities should report sequencer persistence"
        );

        let got = storage
            .get_conversation(user_did, conversation_id)
            .await
            .expect("load conversation")
            .expect("conversation exists");
        assert_eq!(got.sequencer_did.as_deref(), Some(sequencer_did));

        let listed = storage
            .list_conversations(user_did)
            .await
            .expect("list conversations");
        let listed = listed
            .into_iter()
            .find(|c| c.conversation_id == conversation_id)
            .expect("listed conversation");
        assert_eq!(listed.sequencer_did.as_deref(), Some(sequencer_did));
    }

    #[wasm_bindgen_test]
    async fn conversation_storage_preserves_stable_id_and_current_group_id() {
        let storage = new_storage().await;
        let user_did = "did:plc:alice";
        let conversation_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let group_id = "00112233445566778899aabbccddeeff";

        // A pre-fix database could have keyed the row by its group id. The
        // stable projection must migrate that row instead of adding a second
        // logical conversation.
        storage
            .ensure_conversation_exists(user_did, group_id, group_id)
            .await
            .expect("persist legacy group-id conversation mapping");
        storage
            .set_group_state(&GroupState {
                group_id: group_id.to_owned(),
                conversation_id: group_id.to_owned(),
                epoch: 2,
                members: vec![user_did.to_owned()],
            })
            .await
            .expect("persist legacy group state");
        storage
            .ensure_conversation_exists(user_did, conversation_id, group_id)
            .await
            .expect("persist stable conversation mapping");
        storage
            .set_group_state(&GroupState {
                group_id: group_id.to_owned(),
                conversation_id: conversation_id.to_owned(),
                epoch: 3,
                members: vec![user_did.to_owned()],
            })
            .await
            .expect("persist group state");

        let loaded = storage
            .get_conversation(user_did, conversation_id)
            .await
            .expect("load stable conversation")
            .expect("stable conversation exists");
        assert_eq!(loaded.conversation_id, conversation_id);
        assert_eq!(loaded.group_id, group_id);

        let listed = storage
            .list_conversations(user_did)
            .await
            .expect("list stable conversations");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].conversation_id, conversation_id);
        assert_eq!(listed[0].group_id, group_id);

        storage
            .store_message(&Message {
                id: "legacy-message".to_owned(),
                conversation_id: group_id.to_owned(),
                sender_did: user_did.to_owned(),
                text: "legacy body".to_owned(),
                timestamp: chrono::Utc::now(),
                epoch: 3,
                sequence_number: 1,
                is_own: true,
                delivery_status: None,
                payload_json: None,
            })
            .await
            .expect("persist legacy message");
        let messages = storage
            .get_messages(conversation_id, 50, None)
            .await
            .expect("read messages through stable identity");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, "legacy-message");
        assert_eq!(messages[0].conversation_id, group_id);

        let new_group_id = "ffeeddccbbaa99887766554433221100";
        storage
            .ensure_conversation_exists(user_did, conversation_id, new_group_id)
            .await
            .expect("adopt current group mapping");
        storage
            .set_group_state(&GroupState {
                group_id: new_group_id.to_owned(),
                conversation_id: conversation_id.to_owned(),
                epoch: 4,
                members: vec![user_did.to_owned()],
            })
            .await
            .expect("persist adopted group state");

        let resolved = storage
            .resolve_conversation_mapping(user_did, conversation_id)
            .expect("resolve stable conversation")
            .expect("stable mapping exists");
        assert_eq!(
            resolved,
            (conversation_id.to_owned(), new_group_id.to_owned())
        );
        let listed = storage
            .list_conversations(user_did)
            .await
            .expect("list adopted conversation");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].conversation_id, conversation_id);
        assert_eq!(listed[0].group_id, new_group_id);
    }

    #[wasm_bindgen_test]
    async fn conversation_storage_keeps_pre_reset_history_by_stable_identity() {
        let storage = new_storage().await;
        let user_did = "did:plc:history";
        let conversation_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let old_group_id = "00112233445566778899aabbccddeeff";
        let new_group_id = "ffeeddccbbaa99887766554433221100";

        storage
            .ensure_conversation_exists(user_did, conversation_id, old_group_id)
            .await
            .expect("create stable conversation");
        storage
            .store_message(&Message {
                id: "before-reset".to_owned(),
                conversation_id: old_group_id.to_owned(),
                sender_did: user_did.to_owned(),
                text: "before reset".to_owned(),
                timestamp: chrono::Utc::now(),
                epoch: 7,
                sequence_number: 1,
                is_own: true,
                delivery_status: None,
                payload_json: None,
            })
            .await
            .expect("store pre-reset message");

        storage
            .ensure_conversation_exists(user_did, conversation_id, new_group_id)
            .await
            .expect("adopt post-reset group");
        storage
            .store_message(&Message {
                id: "after-reset".to_owned(),
                conversation_id: new_group_id.to_owned(),
                sender_did: user_did.to_owned(),
                text: "after reset".to_owned(),
                timestamp: chrono::Utc::now(),
                epoch: 1,
                sequence_number: 1,
                is_own: true,
                delivery_status: None,
                payload_json: None,
            })
            .await
            .expect("store post-reset message");

        let messages = storage
            .get_messages(conversation_id, 50, None)
            .await
            .expect("read stable conversation history");
        let ids: Vec<_> = messages.iter().map(|message| message.id.as_str()).collect();
        assert_eq!(ids, vec!["before-reset", "after-reset"]);

        // The historical group remains a valid legacy handle, but both group
        // coordinates resolve to the one stable conversation.
        assert_eq!(
            storage
                .resolve_conversation_mapping(user_did, old_group_id)
                .expect("resolve old group")
                .map(|(stable, _)| stable),
            Some(conversation_id.to_owned())
        );
    }

    #[wasm_bindgen_test]
    async fn group_reset_preserves_old_group_state_and_projection_columns() {
        let storage = new_storage().await;
        let user_did = "did:plc:atomic";
        let conversation_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let old_group_id = "00112233445566778899aabbccddeeff";
        let new_group_id = "ffeeddccbbaa99887766554433221100";

        storage
            .ensure_conversation_exists(user_did, conversation_id, old_group_id)
            .await
            .expect("create conversation");
        storage
            .update_join_info(conversation_id, user_did, JoinMethod::Welcome, 9)
            .await
            .expect("store join fields");
        storage
            .set_group_state(&GroupState {
                group_id: old_group_id.to_owned(),
                conversation_id: conversation_id.to_owned(),
                epoch: 9,
                members: vec![user_did.to_owned()],
            })
            .await
            .expect("store old group state");

        storage
            .ensure_conversation_exists(user_did, conversation_id, new_group_id)
            .await
            .expect("adopt reset group");

        let old_state = storage
            .get_group_state(old_group_id)
            .await
            .expect("read old group state");
        assert!(
            old_state.is_some(),
            "historical group state is needed for AAD/decryption"
        );
        let projection = storage
            .conn
            .query_text(
                "SELECT group_id, join_epoch FROM conversations
                 WHERE user_did = ?1 AND conversation_id = ?2",
                &[(1, user_did), (2, conversation_id)],
                2,
            )
            .expect("read projection columns");
        assert_eq!(projection[0][0].as_deref(), Some(new_group_id));
        assert_eq!(projection[0][1].as_deref(), Some("9"));
    }

    #[wasm_bindgen_test]
    async fn completed_reset_reads_history_from_old_and_new_crypto_aliases() {
        let storage = new_storage().await;
        let user_did = "did:plc:reset-history";
        let conversation_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let old_group_id = "00112233445566778899aabbccddeeff";
        let new_group_id = "ffeeddccbbaa99887766554433221100";

        storage
            .ensure_conversation_exists(user_did, conversation_id, old_group_id)
            .await
            .expect("create conversation");
        storage
            .set_group_state(&GroupState {
                group_id: old_group_id.to_owned(),
                conversation_id: conversation_id.to_owned(),
                epoch: 4,
                members: vec![user_did.to_owned()],
            })
            .await
            .expect("persist old group state");
        storage
            .store_message(&Message {
                id: "pre-reset-aad-bound".to_owned(),
                conversation_id: old_group_id.to_owned(),
                sender_did: user_did.to_owned(),
                text: "before reset".to_owned(),
                timestamp: chrono::Utc::now(),
                epoch: 4,
                sequence_number: 1,
                is_own: true,
                delivery_status: None,
                payload_json: None,
            })
            .await
            .expect("persist old-alias message");

        storage
            .mark_reset_pending(conversation_id, new_group_id, 11, 1234)
            .await
            .expect("persist reset authority");
        let state_version = storage
            .conn
            .query_text(
                "SELECT state_version FROM conversations
                 WHERE user_did = ?1 AND conversation_id = ?2",
                &[(1, user_did), (2, conversation_id)],
                1,
            )
            .expect("read reset state version")[0][0]
            .as_deref()
            .and_then(|value| value.parse::<i64>().ok())
            .expect("state version");
        let roster = vec![
            MemberView {
                did: user_did.to_owned(),
                role: MemberRole::Admin,
            },
            MemberView {
                did: "did:plc:invitee".to_owned(),
                role: MemberRole::Member,
            },
        ];
        assert!(storage
            .complete_reset_pending_projection(
                user_did,
                conversation_id,
                11,
                Some(state_version),
                new_group_id,
                1,
                &roster,
            )
            .expect("complete reset transaction"));

        storage
            .store_message(&Message {
                id: "post-reset-aad-bound".to_owned(),
                conversation_id: new_group_id.to_owned(),
                sender_did: user_did.to_owned(),
                text: "after reset".to_owned(),
                timestamp: chrono::Utc::now(),
                epoch: 1,
                sequence_number: 1,
                is_own: true,
                delivery_status: None,
                payload_json: None,
            })
            .await
            .expect("persist new-alias message");

        let messages = storage
            .get_messages(conversation_id, 50, None)
            .await
            .expect("read both crypto aliases after reset");
        assert_eq!(
            messages
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            vec!["pre-reset-aad-bound", "post-reset-aad-bound"]
        );
        assert_eq!(messages[0].conversation_id, old_group_id);
        assert_eq!(messages[1].conversation_id, new_group_id);
        assert!(storage
            .get_group_state(old_group_id)
            .await
            .unwrap()
            .is_some());

        let loaded = storage
            .get_conversation(user_did, conversation_id)
            .await
            .expect("load completed reset")
            .expect("completed reset exists");
        assert_eq!(loaded.group_id, new_group_id);
        assert_eq!(loaded.members.len(), 2);
        assert!(matches!(loaded.members[0].role, MemberRole::Admin));
        let listed = storage
            .list_conversations(user_did)
            .await
            .expect("list completed reset");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].conversation_id, conversation_id);
        assert_eq!(listed[0].members.len(), 2);
    }

    #[wasm_bindgen_test]
    async fn history_cursor_is_composite_and_stable_across_reset_aliases() {
        let storage = new_storage().await;
        let user_did = "did:plc:history-cursor";
        let conversation_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let old_group_id = "00112233445566778899aabbccddeeff";
        let new_group_id = "ffeeddccbbaa99887766554433221100";
        storage
            .ensure_conversation_exists(user_did, conversation_id, old_group_id)
            .await
            .expect("create stable conversation");
        for (id, group, epoch, text) in [
            ("cursor-old-a", old_group_id, 2, "old-a"),
            ("cursor-old-b", old_group_id, 2, "old-b"),
        ] {
            storage
                .store_message(&Message {
                    id: id.to_owned(),
                    conversation_id: group.to_owned(),
                    sender_did: user_did.to_owned(),
                    text: text.to_owned(),
                    timestamp: chrono::Utc::now(),
                    epoch,
                    sequence_number: 1,
                    is_own: true,
                    delivery_status: None,
                    payload_json: None,
                })
                .await
                .expect("store old cursor row");
        }
        storage
            .ensure_conversation_exists(user_did, conversation_id, new_group_id)
            .await
            .expect("adopt reset group");
        storage
            .store_message(&Message {
                id: "cursor-new".to_owned(),
                conversation_id: new_group_id.to_owned(),
                sender_did: user_did.to_owned(),
                text: "new".to_owned(),
                timestamp: chrono::Utc::now(),
                epoch: 1,
                sequence_number: 1,
                is_own: true,
                delivery_status: None,
                payload_json: None,
            })
            .await
            .expect("store new cursor row");

        let all = storage
            .get_messages(conversation_id, 20, None)
            .await
            .expect("read cursor history");
        assert_eq!(all.len(), 3);
        let cursor = WasmStorageBackend::encode_history_cursor(all.last().unwrap())
            .expect("encode composite cursor");
        assert!(
            cursor.split('.').count() == 2,
            "cursor is opaque versioned data"
        );
        let before = storage
            .get_messages_before_cursor(conversation_id, 20, Some(&cursor))
            .await
            .expect("read before composite cursor");
        assert_eq!(before.len(), 2);
        assert!(before.iter().all(|message| message.id != "cursor-new"));
        assert!(storage
            .get_messages_before_cursor(conversation_id, 20, Some("not-a-cursor"))
            .await
            .is_err());
    }

    #[wasm_bindgen_test]
    async fn completed_reset_keeps_a_high_water_generation_and_rejects_replays() {
        let storage = new_storage().await;
        let user_did = "did:plc:reset-high-water";
        let conversation_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let old_group_id = "00112233445566778899aabbccddeeff";
        let reset_group_id = "ffeeddccbbaa99887766554433221100";
        let older_group_id = "11223344556677889900aabbccddeeff";

        storage
            .ensure_conversation_exists(user_did, conversation_id, old_group_id)
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, reset_group_id, 11, 1234)
            .await
            .expect("arm reset");
        let state_version = storage
            .conversation_state_version(user_did, conversation_id)
            .expect("read state version")
            .expect("state version exists");
        assert!(storage
            .complete_reset_pending_projection(
                user_did,
                conversation_id,
                11,
                Some(state_version),
                reset_group_id,
                1,
                &[MemberView {
                    did: user_did.to_owned(),
                    role: MemberRole::Admin,
                }],
            )
            .expect("complete reset"));

        let stale = storage
            .mark_reset_pending(conversation_id, older_group_id, 10, 9999)
            .await;
        assert!(
            stale.is_err(),
            "completed reset must retain a generation high-water mark"
        );
        let conflicting = storage
            .mark_reset_pending(conversation_id, older_group_id, 11, 9999)
            .await;
        assert!(
            conflicting.is_err(),
            "same generation with a different target must fail closed after completion"
        );
        assert_eq!(
            storage
                .resolve_conversation_mapping(user_did, conversation_id)
                .expect("resolve winner"),
            Some((conversation_id.to_owned(), reset_group_id.to_owned()))
        );
    }

    #[wasm_bindgen_test]
    async fn reset_completion_retains_pending_authority_when_roster_is_missing() {
        let storage = new_storage().await;
        let user_did = "did:plc:roster-failure";
        let conversation_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let old_group_id = "00112233445566778899aabbccddeeff";
        let new_group_id = "ffeeddccbbaa99887766554433221100";
        storage
            .ensure_conversation_exists(user_did, conversation_id, old_group_id)
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, new_group_id, 5, 100)
            .await
            .expect("arm reset");
        let result = MLSStorageBackend::complete_reset_pending(
            &storage,
            conversation_id,
            5,
            new_group_id,
            1,
        )
        .await;
        assert!(
            result.is_err(),
            "a missing roster must block reset completion"
        );
        let state = storage
            .get_conversation_state(conversation_id)
            .await
            .expect("read pending state")
            .expect("pending state remains");
        assert!(matches!(state, ConversationState::ResetPending { .. }));
    }

    #[wasm_bindgen_test]
    async fn conflicting_duplicate_message_preserves_the_original_fingerprint() {
        let storage = new_storage().await;
        let user_did = "did:plc:message-fingerprint";
        let conversation_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let group_id = "00112233445566778899aabbccddeeff";
        storage
            .ensure_conversation_exists(user_did, conversation_id, group_id)
            .await
            .expect("create conversation");

        let original = Message {
            id: "immutable-message".to_owned(),
            conversation_id: group_id.to_owned(),
            sender_did: user_did.to_owned(),
            text: "original".to_owned(),
            timestamp: chrono::Utc::now(),
            epoch: 2,
            sequence_number: 7,
            is_own: false,
            delivery_status: None,
            payload_json: None,
        };
        storage
            .store_message(&original)
            .await
            .expect("store original");
        let mut conflicting = original.clone();
        conflicting.text = "tampered".to_owned();
        assert!(
            storage.store_message(&conflicting).await.is_err(),
            "same message id with a different payload must not overwrite the row"
        );
        let rows = storage
            .get_messages(conversation_id, 10, None)
            .await
            .expect("read original");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text, "original");
    }

    #[wasm_bindgen_test]
    async fn conflicting_cleanup_intent_preserves_the_original_owner_fingerprint() {
        let storage = new_storage().await;
        let user_did = "did:plc:cleanup-owner";
        let group_id = "00112233445566778899aabbccddeeff";
        storage
            .mark_cleanup_intent(user_did, "conversation-a", group_id, "create")
            .expect("record cleanup intent");
        assert!(
            storage
                .mark_cleanup_intent(user_did, "conversation-b", group_id, "reset")
                .is_err(),
            "a cleanup target cannot be rebound to another operation"
        );
        let row = storage
            .conn
            .query_text(
                "SELECT conversation_id, reason FROM conversation_cleanup_intents
                 WHERE user_did = ?1 AND group_id = ?2",
                &[(1, user_did), (2, group_id)],
                2,
            )
            .expect("read cleanup intent");
        assert_eq!(row[0][0].as_deref(), Some("conversation-a"));
        assert_eq!(row[0][1].as_deref(), Some("create"));
    }

    #[wasm_bindgen_test]
    async fn projection_rollback_preserves_mapping_state_and_alias_owner() {
        let storage = new_storage().await;
        let user_did = "did:plc:rollback";
        let first = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let second = "018f3f6a-7b2c-4d91-8a5e-0f123456789b";
        let first_group = "00112233445566778899aabbccddeeff";
        let second_group = "ffeeddccbbaa99887766554433221100";

        storage
            .ensure_conversation_exists(user_did, first, first_group)
            .await
            .expect("first mapping");
        storage
            .set_group_state(&GroupState {
                group_id: first_group.to_owned(),
                conversation_id: first.to_owned(),
                epoch: 8,
                members: vec![user_did.to_owned()],
            })
            .await
            .expect("first group state");
        storage
            .ensure_conversation_exists(user_did, second, second_group)
            .await
            .expect("second mapping");

        let result = storage.upsert_conversation_projection(
            user_did,
            first,
            second_group,
            99,
            &[],
            None,
            None,
        );
        assert!(result.is_err(), "alias ownership conflict must fail closed");
        assert_eq!(
            storage
                .resolve_conversation_mapping(user_did, first)
                .unwrap(),
            Some((first.to_owned(), first_group.to_owned()))
        );
        assert!(storage
            .get_group_state(first_group)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            storage
                .resolve_conversation_mapping(user_did, second_group)
                .unwrap(),
            Some((second.to_owned(), second_group.to_owned()))
        );
    }

    #[wasm_bindgen_test]
    async fn stale_list_projection_cannot_clear_or_regress_reset_authority() {
        let storage = new_storage().await;
        let user_did = "did:plc:cas";
        let conversation_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let old_group_id = "00112233445566778899aabbccddeeff";
        let reset_group_id = "ffeeddccbbaa99887766554433221100";
        let stale_group_id = "11223344556677889900aabbccddeeff";

        storage
            .ensure_conversation_exists(user_did, conversation_id, old_group_id)
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, reset_group_id, 7, 99)
            .await
            .expect("record reset winner coordinates");
        let state_version = storage
            .conn
            .query_text(
                "SELECT state_version FROM conversations
                 WHERE user_did = ?1 AND conversation_id = ?2",
                &[(1, user_did), (2, conversation_id)],
                1,
            )
            .unwrap()[0][0]
            .as_deref()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap();

        let stale = storage.upsert_conversation_projection(
            user_did,
            conversation_id,
            stale_group_id,
            3,
            &[],
            Some(6),
            Some(state_version),
        );
        assert!(stale.is_err(), "older list generation must lose the CAS");
        let pending = storage
            .get_conversation_state(conversation_id)
            .await
            .unwrap()
            .expect("reset authority remains");
        match pending {
            ConversationState::ResetPending {
                new_group_id,
                reset_generation,
                ..
            } => {
                assert_eq!(new_group_id, reset_group_id);
                assert_eq!(reset_generation, 7);
            }
            other => panic!("stale list changed reset state: {:?}", other),
        }
        assert!(!storage
            .complete_reset_pending_projection(
                user_did,
                conversation_id,
                6,
                Some(state_version),
                stale_group_id,
                3,
                &[],
            )
            .unwrap());
    }

    #[wasm_bindgen_test]
    async fn projection_commit_retire_is_atomic_and_preserves_alias_history() {
        let storage = new_storage().await;
        let user_did = "did:plc:projection-cas";
        let stable_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let group_id = "00112233445566778899aabbccddeeff";

        storage
            .ensure_conversation_exists(user_did, group_id, group_id)
            .await
            .expect("seed raw alias row");
        storage
            .set_group_state(&GroupState {
                group_id: group_id.to_owned(),
                conversation_id: group_id.to_owned(),
                epoch: 7,
                members: vec![user_did.to_owned()],
            })
            .await
            .expect("seed shared group state");
        storage
            .store_message(&Message {
                id: "alias-bound-message".to_owned(),
                conversation_id: group_id.to_owned(),
                sender_did: user_did.to_owned(),
                text: "historical body".to_owned(),
                timestamp: chrono::Utc::now(),
                epoch: 7,
                sequence_number: 1,
                is_own: true,
                delivery_status: None,
                payload_json: None,
            })
            .await
            .expect("seed alias-bound message");

        let canonical = ConversationView {
            group_id: group_id.to_owned(),
            conversation_id: stable_id.to_owned(),
            epoch: 7,
            members: vec![MemberView {
                did: user_did.to_owned(),
                role: MemberRole::Admin,
            }],
            metadata: None,
            created_at: None,
            updated_at: None,
            sequencer_did: None,
            canonical_state: None,
        };
        let alias = ConversationView {
            conversation_id: group_id.to_owned(),
            ..canonical.clone()
        };
        let authority = AliasRetirementAuthority::from_views(user_did, &canonical, &alias)
            .expect("construct explicit alias authority");

        let outcome = storage
            .commit_conversation_projection(&ConversationProjectionCommitRequest::live(
                user_did,
                canonical,
                vec![authority],
            ))
            .await
            .expect("projection CAS commit");
        assert!(matches!(
            outcome,
            ConversationProjectionCommitOutcome::Retired { .. }
                | ConversationProjectionCommitOutcome::AlreadyAbsent { .. }
        ));
        assert!(storage
            .get_conversation(user_did, stable_id)
            .await
            .expect("read canonical projection")
            .is_some());
        assert!(storage
            .get_conversation(user_did, group_id)
            .await
            .expect("read retired alias")
            .is_none());
        assert!(storage
            .get_group_state(group_id)
            .await
            .expect("read preserved group state")
            .is_some());
        let messages = storage
            .get_messages(stable_id, 50, None)
            .await
            .expect("read preserved alias history");
        assert_eq!(messages[0].conversation_id, group_id);
    }

    #[wasm_bindgen_test]
    async fn canonical_policy_projection_keeps_protocol_fences_separate_and_monotonic() {
        let storage = new_storage().await;
        let policy = catbird_mls::orchestrator::canonical_transport::decode_conversation_state(
            include_bytes!(
                "../../catbird-mls/tests/fixtures/swift_pending_conversation_state.json"
            ),
        )
        .unwrap();
        let owner = policy.participants[0].user_did.as_str();
        let cid = policy.coordinates.conversation_id.as_str();
        let group = hex::encode(&policy.coordinates.group_id);
        storage
            .ensure_conversation_exists(owner, cid, &group)
            .await
            .unwrap();
        storage
            .conn
            .exec_raw("UPDATE conversations SET state_version=900")
            .unwrap();
        let mut view = ConversationView {
            conversation_id: cid.into(),
            group_id: group.clone(),
            epoch: policy.coordinates.epoch as u64,
            members: policy
                .participants
                .iter()
                .map(|p| MemberView {
                    did: p.user_did.as_str().into(),
                    role: if p.role.as_str() == "admin" {
                        MemberRole::Admin
                    } else {
                        MemberRole::Member
                    },
                })
                .collect(),
            metadata: None,
            created_at: None,
            updated_at: None,
            sequencer_did: None,
            canonical_state: Some(policy.clone()),
        };
        let request = ConversationProjectionCommitRequest::live(owner, view.clone(), Vec::new());
        assert!(matches!(
            storage
                .commit_conversation_projection(&request)
                .await
                .unwrap(),
            ConversationProjectionCommitOutcome::AlreadyAbsent { .. }
        ));
        assert_eq!(
            storage
                .get_conversation(owner, cid)
                .await
                .unwrap()
                .unwrap()
                .canonical_state,
            Some(policy.clone())
        );
        assert_eq!(
            storage
                .conn
                .query_text(
                    "SELECT conversation_kind FROM conversations WHERE conversation_id=?1",
                    &[(1, cid)],
                    1
                )
                .unwrap()[0][0]
                .as_deref(),
            Some("group")
        );
        let mut wrong = request.clone();
        wrong.canonical_lifecycle.generation = Some(7);
        assert!(storage
            .commit_conversation_projection(&wrong)
            .await
            .is_err());
        view.canonical_state
            .as_mut()
            .unwrap()
            .coordinates
            .state_version += 1;
        let next = ConversationProjectionCommitRequest::live(owner, view.clone(), Vec::new());
        assert!(matches!(
            storage.commit_conversation_projection(&next).await.unwrap(),
            ConversationProjectionCommitOutcome::AlreadyAbsent { .. }
        ));
        assert!(matches!(
            storage
                .commit_conversation_projection(&request)
                .await
                .unwrap(),
            ConversationProjectionCommitOutcome::FenceMismatch { .. }
        ));
        storage
            .set_conversation_state(cid, ConversationState::Closed)
            .await
            .unwrap();
        assert!(matches!(
            storage.commit_conversation_projection(&next).await.unwrap(),
            ConversationProjectionCommitOutcome::FenceMismatch { .. }
        ));
    }

    #[wasm_bindgen_test]
    async fn projection_catchup_preserves_observed_alias_epoch_for_atomic_retirement() {
        SqliteConn::initialize_opfs().await.unwrap();
        let storage = new_storage().await;
        let owner = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        let cid = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let group = "00112233445566778899aabbccddeeff";
        storage
            .ensure_conversation_exists(owner, group, group)
            .await
            .unwrap();
        storage
            .set_group_state(&GroupState {
                group_id: group.into(),
                conversation_id: group.into(),
                epoch: 7,
                members: vec![owner.into()],
            })
            .await
            .unwrap();
        let alias = storage
            .get_conversation(owner, group)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alias.epoch, 7);
        let canonical = ConversationView {
            conversation_id: cid.into(),
            epoch: 8,
            members: vec![MemberView {
                did: owner.into(),
                role: MemberRole::Admin,
            }],
            ..alias.clone()
        };
        let authority = AliasRetirementAuthority::from_views(owner, &canonical, &alias).unwrap();
        let mut stale = authority.clone();
        stale.alias_incarnation = 8;
        let mismatch = storage
            .commit_conversation_projection(&ConversationProjectionCommitRequest::live(
                owner,
                canonical.clone(),
                vec![stale],
            ))
            .await
            .unwrap();
        assert!(matches!(
            mismatch,
            ConversationProjectionCommitOutcome::FenceMismatch { affected_rows: 0 }
        ));
        assert_eq!(
            storage
                .get_conversation(owner, group)
                .await
                .unwrap()
                .unwrap()
                .epoch,
            7
        );
        assert!(storage
            .get_conversation(owner, cid)
            .await
            .unwrap()
            .is_none());
        let applied = storage
            .commit_conversation_projection(&ConversationProjectionCommitRequest::live(
                owner,
                canonical,
                vec![authority.clone()],
            ))
            .await
            .unwrap();
        assert!(matches!(
            applied,
            ConversationProjectionCommitOutcome::Retired { .. }
                | ConversationProjectionCommitOutcome::AlreadyAbsent { .. }
        ));
        assert!(storage
            .get_conversation(owner, group)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            storage
                .get_conversation(owner, cid)
                .await
                .unwrap()
                .unwrap()
                .epoch,
            8
        );
        let replay = storage
            .commit_conversation_projection(&ConversationProjectionCommitRequest::replay(authority))
            .await
            .unwrap();
        assert!(matches!(
            replay,
            ConversationProjectionCommitOutcome::AlreadyAbsent { .. }
        ));
    }

    #[wasm_bindgen_test]
    async fn projection_replay_without_canonical_proof_fails_closed() {
        let storage = new_storage().await;
        let user_did = "did:plc:projection-replay";
        let group_id = "ffeeddccbbaa99887766554433221100";
        storage
            .ensure_conversation_exists(user_did, group_id, group_id)
            .await
            .expect("seed raw alias row");
        let canonical = ConversationView {
            group_id: group_id.to_owned(),
            conversation_id: "018f3f6a-7b2c-4d91-8a5e-0f123456789b".to_owned(),
            epoch: 0,
            members: vec![],
            metadata: None,
            created_at: None,
            updated_at: None,
            sequencer_did: None,
            canonical_state: None,
        };
        let alias = ConversationView {
            conversation_id: group_id.to_owned(),
            ..canonical.clone()
        };
        let authority = AliasRetirementAuthority::from_views(user_did, &canonical, &alias)
            .expect("construct replay authority");
        let outcome = storage
            .commit_conversation_projection(&ConversationProjectionCommitRequest::replay(authority))
            .await
            .expect("replay returns typed outcome");
        assert!(matches!(
            outcome,
            ConversationProjectionCommitOutcome::FenceMismatch { .. }
                | ConversationProjectionCommitOutcome::AlreadyAbsent { .. }
        ));
        assert!(storage
            .get_conversation(user_did, group_id)
            .await
            .expect("alias remains after unproven replay")
            .is_some());
    }

    #[wasm_bindgen_test]
    async fn stale_post_reset_list_cannot_rewind_historical_group_alias() {
        let storage = new_storage().await;
        let user_did = "did:plc:projection-stale-list";
        let stable_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let old_group = "00112233445566778899aabbccddeeff";
        let new_group = "ffeeddccbbaa99887766554433221100";
        storage
            .ensure_conversation_exists(user_did, stable_id, old_group)
            .await
            .expect("seed stable projection");
        storage
            .mark_reset_pending(stable_id, new_group, 4, 100)
            .await
            .expect("publish reset authority");
        let version = storage
            .conversation_state_version(user_did, stable_id)
            .expect("read reset version");
        assert!(storage
            .complete_reset_pending_projection(
                user_did,
                stable_id,
                4,
                version,
                new_group,
                1,
                &[MemberView {
                    did: user_did.to_owned(),
                    role: MemberRole::Admin,
                }],
            )
            .expect("complete reset"));

        let stale = storage.upsert_conversation_projection(
            user_did,
            stable_id,
            old_group,
            0,
            &[],
            None,
            None,
        );
        assert!(stale.is_err(), "stale list must not rewind reset mapping");
        assert_eq!(
            storage
                .resolve_conversation_mapping(user_did, stable_id)
                .expect("resolve current mapping"),
            Some((stable_id.to_owned(), new_group.to_owned()))
        );
    }

    #[wasm_bindgen_test]
    async fn reset_target_adoption_advances_state_version_for_stale_winner() {
        let storage = new_storage().await;
        let user_did = "did:plc:projection-adopt";
        let stable_id = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let old_group = "00112233445566778899aabbccddeeff";
        let first_target = "ffeeddccbbaa99887766554433221100";
        let authoritative_target = "102132435465768798a9bacbdcedfe00";
        storage
            .ensure_conversation_exists(user_did, stable_id, old_group)
            .await
            .expect("seed stable projection");
        storage
            .mark_reset_pending(stable_id, first_target, 9, 100)
            .await
            .expect("publish reset authority");
        let stale_version = storage
            .conversation_state_version(user_did, stable_id)
            .expect("read stale winner version");
        assert!(storage
            .adopt_reset_pending_target(stable_id, 9, first_target, authoritative_target,)
            .await
            .expect("adopt authoritative target"));
        let current_version = storage
            .conversation_state_version(user_did, stable_id)
            .expect("read adopted target version");
        assert!(current_version > stale_version);
        assert!(!storage
            .complete_reset_pending_projection(
                user_did,
                stable_id,
                9,
                stale_version,
                authoritative_target,
                1,
                &[],
            )
            .expect("stale winner must lose CAS"));
    }

    #[wasm_bindgen_test]
    async fn projection_commit_reports_ambiguous_canonical_group_without_mutation() {
        let storage = new_storage().await;
        let user_did = "did:plc:projection-ambiguous";
        let first = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
        let second = "018f3f6a-7b2c-4d91-8a5e-0f123456789b";
        let group_id = "11223344556677889900aabbccddeeff";
        for stable_id in [first, second] {
            storage
                .conn
                .exec_with_text_params(
                    "INSERT INTO conversations
                        (conversation_id, user_did, group_id, state, state_version)
                     VALUES (?1, ?2, ?3, 'active', 0)",
                    &[(1, stable_id), (2, user_did), (3, group_id)],
                )
                .expect("seed duplicate canonical rows");
        }
        let canonical = ConversationView {
            group_id: group_id.to_owned(),
            conversation_id: first.to_owned(),
            epoch: 0,
            members: vec![],
            metadata: None,
            created_at: None,
            updated_at: None,
            sequencer_did: None,
            canonical_state: None,
        };
        let outcome = storage
            .commit_conversation_projection(&ConversationProjectionCommitRequest::live(
                user_did,
                canonical,
                vec![],
            ))
            .await
            .expect("ambiguous projection returns typed outcome");
        assert!(matches!(
            outcome,
            ConversationProjectionCommitOutcome::Ambiguous { .. }
        ));
        let rows = storage
            .conn
            .query_text(
                "SELECT conversation_id FROM conversations
                 WHERE user_did = ?1 AND group_id = ?2",
                &[(1, user_did), (2, group_id)],
                1,
            )
            .expect("read duplicate rows");
        assert_eq!(rows.len(), 2, "ambiguity must preserve both projections");
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod account_exit_tests;
