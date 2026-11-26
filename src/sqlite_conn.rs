//! Shared SQLite connection wrapper for WASM (OPFS SAH VFS + sqlite3mc ChaCha20).
//!
//! Provides `SqliteConn` — a thin safe wrapper around the raw `sqlite3*` handle
//! from `sqlite-wasm-rs`. Used by:
//!   - `mls_storage.rs` — OpenMLS KV storage
//!   - `storage.rs` — conversation/message/sync storage
//!   - `credentials.rs` — credential storage
//!
//! All three share the same encrypted database file when the connection is
//! created once in `catbird_mls_init()` and passed via `Rc`.

use sqlite_wasm_rs::*;
use std::ffi::CString;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the WASM SQLite storage layer.
#[derive(Debug, thiserror::Error)]
pub enum WasmSqliteError {
    #[error("SQLite error ({code}): {message}")]
    Sqlite { code: i32, message: String },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Null pointer from SQLite")]
    NullPointer,
}

impl From<serde_json::Error> for WasmSqliteError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// SQLITE_TRANSIENT helper
// ---------------------------------------------------------------------------

/// Returns the SQLITE_TRANSIENT destructor constant, which tells SQLite to
/// make its own copy of the data immediately.
///
/// In the C API this is defined as `((sqlite3_destructor_type)-1)`.
pub fn sqlite_transient() -> Option<unsafe extern "C" fn(*mut std::ffi::c_void)> {
    // SQLITE_TRANSIENT = ((sqlite3_destructor_type)-1)
    unsafe {
        Some(std::mem::transmute::<
            isize,
            unsafe extern "C" fn(*mut std::ffi::c_void),
        >(-1))
    }
}

// ---------------------------------------------------------------------------
// Safe SQLite wrapper (thin layer over sqlite-wasm-rs raw FFI)
// ---------------------------------------------------------------------------

/// Safe wrapper around a raw `sqlite3*` handle.
///
/// All methods that operate on the database are `&self` because SQLite compiled
/// with `SQLITE_THREADSAFE=0` is single-threaded (fine for WASM).
pub struct SqliteConn {
    db: *mut sqlite3,
    db_path: String,
}

thread_local! {
    static OPEN_DATABASES: std::cell::RefCell<std::collections::HashSet<String>> = std::cell::RefCell::new(std::collections::HashSet::new());
    static OPFS_OWNER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Use the signed archive time when available. Older queued records may lack a receipt.
pub(crate) fn archive_frame_position(
    frame: &catbird_mls::client::QueuedLabyrinthArchivePayload,
) -> Result<(i64, i64), catbird_mls::MLSError> {
    use catbird_mls::client::chat_wire::StoredArchivedReceipt;
    use catbird_mls::MLSError;

    let Some(raw) = frame.sequencer_receipt_json.as_deref() else {
        return Ok((frame.seq, frame.created_at_ms));
    };
    let receipt: StoredArchivedReceipt = serde_json::from_str(raw)?;
    if receipt.conversation_id != frame.conversation_id
        || receipt.seq != frame.seq as u64
        || receipt.sender_device_did_url
            != format!("{}#{}", frame.sender_did, frame.sender_device_id)
    {
        return Err(MLSError::Cryptography(
            "inconsistent stored archive receipt".into(),
        ));
    }
    Ok((frame.seq, receipt.issued_at_ms))
}

/// Origin-wide exclusive owner of the persistent SAH pool. The pool itself does
/// not exclude other Workers or tabs: on a cold directory each context creates
/// its own backing files for the same database name (split brain). The Web Lock
/// is held until this Worker's global is destroyed (terminate, reload, close).
async fn acquire_opfs_owner() -> Result<(), WasmSqliteError> {
    use wasm_bindgen::{closure::Closure, JsCast, JsValue};
    if OPFS_OWNER.with(std::cell::Cell::get) {
        return Ok(());
    }
    let unavailable = |detail: &str| WasmSqliteError::Sqlite {
        code: SQLITE_CANTOPEN,
        message: format!("Protected storage owner lock unavailable: {detail}"),
    };
    let navigator = js_sys::Reflect::get(&js_sys::global(), &"navigator".into())
        .map_err(|_| unavailable("no navigator"))?;
    let locks = js_sys::Reflect::get(&navigator, &"locks".into())
        .ok()
        .filter(|value| value.is_object())
        .ok_or_else(|| unavailable("Web Locks API missing"))?;
    let request: js_sys::Function = js_sys::Reflect::get(&locks, &"request".into())
        .ok()
        .and_then(|value| value.dyn_into().ok())
        .ok_or_else(|| unavailable("Web Locks API missing"))?;
    let mut granted_resolve = None;
    let granted = js_sys::Promise::new(&mut |resolve, _| granted_resolve = Some(resolve));
    let granted_resolve = granted_resolve.ok_or_else(|| unavailable("promise"))?;
    let callback = Closure::once_into_js(move |lock: JsValue| -> JsValue {
        let _ = granted_resolve.call1(&JsValue::UNDEFINED, &JsValue::from_bool(!lock.is_null()));
        if lock.is_null() {
            JsValue::UNDEFINED
        } else {
            // Never settles: the lock lives until this Worker global terminates/reloads,
            // allowing subsequent Workers/reloads to queue cleanly via Web Locks.
            js_sys::Promise::new(&mut |_, _| {}).into()
        }
    });
    request
        .call2(
            &locks,
            &"catbird-mls-web:opfs-sahpool-owner".into(),
            &callback,
        )
        .map_err(|_| unavailable("request rejected"))?;
    let owned = wasm_bindgen_futures::JsFuture::from(granted)
        .await
        .map_err(|_| unavailable("request failed"))?;
    if owned.as_bool() != Some(true) {
        return Err(WasmSqliteError::Sqlite {
            code: SQLITE_BUSY,
            message: "Protected OPFS storage lock was not granted".into(),
        });
    }
    OPFS_OWNER.with(|owner| owner.set(true));
    Ok(())
}
const OPFS_RAW_VFS_NAME: &std::ffi::CStr = c"opfs-sahpool";
const OPFS_SECTOR512_VFS_NAME: &std::ffi::CStr = c"opfs-sahpool-mc";
const ENCRYPTED_OPFS_VFS_NAME: &std::ffi::CStr = c"multipleciphers-opfs-sahpool-mc";

/// Thin SQLite VFS adapter between `sqlite3mc` and `opfs-sahpool` that reports
/// SQLite's standard 512-byte sector size (`SQLITE_DEFAULT_SECTOR_SIZE`) while
/// forwarding all file and namespace operations unchanged to `opfs-sahpool`.
///
/// Why this is required:
/// `sqlite-wasm-vfs`'s `opfs-sahpool` advertises `xSectorSize = 4096`, matching
/// our 4096-byte ChaCha20 database `page_size`. In `sqlite3mc` 2.x,
/// `mcWriteMainJournal` leaves `mcFile->pageNo` set to the trailing 4-byte
/// journal record checksum after each page record and encrypts any subsequent
/// write whose byte length equals `pageSize` (`4096`). Whenever SQLite writes a
/// second journal header (`cache_spill`, large multi-chunk transactions, or
/// retained journals) with `JOURNAL_HDR_SZ == 4096 == pageSize`,
/// `mcWriteMainJournal` mistakenly encrypts the plaintext journal header,
/// corrupting `cksumInit` and aborting hot-journal crash recovery early.
/// Reporting `xSectorSize = 512` sets `JOURNAL_HDR_SZ = 512 != 4096` without
/// altering `opfs-sahpool`'s physical 4096-byte slot header offset or on-disk
/// database format.
mod opfs_sector512_vfs {
    use super::{OPFS_RAW_VFS_NAME, OPFS_SECTOR512_VFS_NAME};
    use sqlite_wasm_rs::*;
    use std::ffi::{c_char, c_int, c_void};

    const SQLITE_SECTOR_SIZE_512: c_int = 512;

    #[repr(C, align(8))]
    struct Sector512File {
        base: sqlite3_file,
    }

    #[inline]
    unsafe fn inner_file(p_file: *mut sqlite3_file) -> *mut sqlite3_file {
        p_file.cast::<Sector512File>().add(1).cast::<sqlite3_file>()
    }

    #[inline]
    unsafe fn raw_opfs_vfs() -> *mut sqlite3_vfs {
        sqlite3_vfs_find(OPFS_RAW_VFS_NAME.as_ptr())
    }

    static SECTOR512_IO_METHODS: sqlite3_io_methods = sqlite3_io_methods {
        iVersion: 1,
        xClose: Some(io_close),
        xRead: Some(io_read),
        xWrite: Some(io_write),
        xTruncate: Some(io_truncate),
        xSync: Some(io_sync),
        xFileSize: Some(io_file_size),
        xLock: Some(io_lock),
        xUnlock: Some(io_unlock),
        xCheckReservedLock: Some(io_check_reserved_lock),
        xFileControl: Some(io_file_control),
        xSectorSize: Some(io_sector_size),
        xDeviceCharacteristics: Some(io_device_characteristics),
        xShmMap: None,
        xShmLock: None,
        xShmBarrier: None,
        xShmUnmap: None,
        xFetch: None,
        xUnfetch: None,
    };

    unsafe extern "C" fn io_close(p_file: *mut sqlite3_file) -> c_int {
        let inner = inner_file(p_file);
        let rc = match (*inner).pMethods.as_ref().and_then(|m| m.xClose) {
            Some(close) => close(inner),
            None => SQLITE_OK,
        };
        (*p_file).pMethods = std::ptr::null();
        rc
    }

    unsafe extern "C" fn io_read(
        p_file: *mut sqlite3_file,
        buf: *mut c_void,
        amt: c_int,
        offset: sqlite3_int64,
    ) -> c_int {
        let inner = inner_file(p_file);
        ((*(*inner).pMethods).xRead.expect("inner xRead"))(inner, buf, amt, offset)
    }

    unsafe extern "C" fn io_write(
        p_file: *mut sqlite3_file,
        buf: *const c_void,
        amt: c_int,
        offset: sqlite3_int64,
    ) -> c_int {
        let inner = inner_file(p_file);
        ((*(*inner).pMethods).xWrite.expect("inner xWrite"))(inner, buf, amt, offset)
    }

    unsafe extern "C" fn io_truncate(p_file: *mut sqlite3_file, size: sqlite3_int64) -> c_int {
        let inner = inner_file(p_file);
        ((*(*inner).pMethods).xTruncate.expect("inner xTruncate"))(inner, size)
    }

    unsafe extern "C" fn io_sync(p_file: *mut sqlite3_file, flags: c_int) -> c_int {
        let inner = inner_file(p_file);
        ((*(*inner).pMethods).xSync.expect("inner xSync"))(inner, flags)
    }

    unsafe extern "C" fn io_file_size(
        p_file: *mut sqlite3_file,
        p_size: *mut sqlite3_int64,
    ) -> c_int {
        let inner = inner_file(p_file);
        ((*(*inner).pMethods).xFileSize.expect("inner xFileSize"))(inner, p_size)
    }

    unsafe extern "C" fn io_lock(p_file: *mut sqlite3_file, lock: c_int) -> c_int {
        let inner = inner_file(p_file);
        ((*(*inner).pMethods).xLock.expect("inner xLock"))(inner, lock)
    }

    unsafe extern "C" fn io_unlock(p_file: *mut sqlite3_file, lock: c_int) -> c_int {
        let inner = inner_file(p_file);
        ((*(*inner).pMethods).xUnlock.expect("inner xUnlock"))(inner, lock)
    }

    unsafe extern "C" fn io_check_reserved_lock(
        p_file: *mut sqlite3_file,
        p_res_out: *mut c_int,
    ) -> c_int {
        let inner = inner_file(p_file);
        ((*(*inner).pMethods)
            .xCheckReservedLock
            .expect("inner xCheckReservedLock"))(inner, p_res_out)
    }

    unsafe extern "C" fn io_file_control(
        p_file: *mut sqlite3_file,
        op: c_int,
        p_arg: *mut c_void,
    ) -> c_int {
        let inner = inner_file(p_file);
        ((*(*inner).pMethods)
            .xFileControl
            .expect("inner xFileControl"))(inner, op, p_arg)
    }

    unsafe extern "C" fn io_sector_size(_p_file: *mut sqlite3_file) -> c_int {
        SQLITE_SECTOR_SIZE_512
    }

    unsafe extern "C" fn io_device_characteristics(p_file: *mut sqlite3_file) -> c_int {
        let inner = inner_file(p_file);
        match (*(*inner).pMethods).xDeviceCharacteristics {
            Some(dc) => dc(inner),
            None => 0,
        }
    }

    unsafe extern "C" fn vfs_open(
        _p_vfs: *mut sqlite3_vfs,
        z_name: sqlite3_filename,
        p_file: *mut sqlite3_file,
        flags: c_int,
        p_out_flags: *mut c_int,
    ) -> c_int {
        (*p_file).pMethods = std::ptr::null();
        let real = raw_opfs_vfs();
        if real.is_null() {
            return SQLITE_CANTOPEN;
        }
        let inner = inner_file(p_file);
        let rc = ((*real).xOpen.expect("real xOpen"))(real, z_name, inner, flags, p_out_flags);
        if rc == SQLITE_OK {
            (*p_file).pMethods = &SECTOR512_IO_METHODS;
        }
        rc
    }

    unsafe extern "C" fn vfs_delete(
        _p_vfs: *mut sqlite3_vfs,
        z_name: *const c_char,
        sync_dir: c_int,
    ) -> c_int {
        let real = raw_opfs_vfs();
        if real.is_null() {
            return SQLITE_IOERR_DELETE;
        }
        ((*real).xDelete.expect("real xDelete"))(real, z_name, sync_dir)
    }

    unsafe extern "C" fn vfs_access(
        _p_vfs: *mut sqlite3_vfs,
        z_name: *const c_char,
        flags: c_int,
        p_res_out: *mut c_int,
    ) -> c_int {
        let real = raw_opfs_vfs();
        if real.is_null() {
            return SQLITE_IOERR_ACCESS;
        }
        ((*real).xAccess.expect("real xAccess"))(real, z_name, flags, p_res_out)
    }

    unsafe extern "C" fn vfs_full_pathname(
        _p_vfs: *mut sqlite3_vfs,
        z_name: *const c_char,
        n_out: c_int,
        z_out: *mut c_char,
    ) -> c_int {
        let real = raw_opfs_vfs();
        if real.is_null() {
            return SQLITE_CANTOPEN;
        }
        ((*real).xFullPathname.expect("real xFullPathname"))(real, z_name, n_out, z_out)
    }

    unsafe extern "C" fn vfs_randomness(
        _p_vfs: *mut sqlite3_vfs,
        n_byte: c_int,
        z_out: *mut c_char,
    ) -> c_int {
        let real = raw_opfs_vfs();
        if real.is_null() {
            return 0;
        }
        match (*real).xRandomness {
            Some(randomness) => randomness(real, n_byte, z_out),
            None => 0,
        }
    }

    unsafe extern "C" fn vfs_sleep(_p_vfs: *mut sqlite3_vfs, microseconds: c_int) -> c_int {
        let real = raw_opfs_vfs();
        if real.is_null() {
            return 0;
        }
        match (*real).xSleep {
            Some(sleep) => sleep(real, microseconds),
            None => 0,
        }
    }

    unsafe extern "C" fn vfs_current_time(_p_vfs: *mut sqlite3_vfs, p_out: *mut f64) -> c_int {
        let real = raw_opfs_vfs();
        if real.is_null() {
            return SQLITE_ERROR;
        }
        match (*real).xCurrentTime {
            Some(current_time) => current_time(real, p_out),
            None => SQLITE_ERROR,
        }
    }

    unsafe extern "C" fn vfs_get_last_error(
        _p_vfs: *mut sqlite3_vfs,
        n_buf: c_int,
        z_buf: *mut c_char,
    ) -> c_int {
        let real = raw_opfs_vfs();
        if real.is_null() {
            return 0;
        }
        match (*real).xGetLastError {
            Some(last_err) => last_err(real, n_buf, z_buf),
            None => 0,
        }
    }

    unsafe extern "C" fn vfs_current_time_int64(
        _p_vfs: *mut sqlite3_vfs,
        p_out: *mut sqlite3_int64,
    ) -> c_int {
        let real = raw_opfs_vfs();
        if real.is_null() {
            return SQLITE_ERROR;
        }
        match (*real).xCurrentTimeInt64 {
            Some(current_time) => current_time(real, p_out),
            None => SQLITE_ERROR,
        }
    }

    pub unsafe fn ensure_registered() -> c_int {
        if !sqlite3_vfs_find(OPFS_SECTOR512_VFS_NAME.as_ptr()).is_null() {
            return SQLITE_OK;
        }
        let real = raw_opfs_vfs();
        if real.is_null() {
            return SQLITE_CANTOPEN;
        }
        let sz_os_file =
            (std::mem::size_of::<Sector512File>() as c_int).saturating_add((*real).szOsFile);
        let vfs = Box::leak(Box::new(sqlite3_vfs {
            iVersion: 2,
            szOsFile: sz_os_file,
            mxPathname: (*real).mxPathname,
            pNext: std::ptr::null_mut(),
            zName: OPFS_SECTOR512_VFS_NAME.as_ptr(),
            pAppData: std::ptr::null_mut(),
            xOpen: Some(vfs_open),
            xDelete: Some(vfs_delete),
            xAccess: Some(vfs_access),
            xFullPathname: Some(vfs_full_pathname),
            xDlOpen: None,
            xDlError: None,
            xDlSym: None,
            xDlClose: None,
            xRandomness: Some(vfs_randomness),
            xSleep: Some(vfs_sleep),
            xCurrentTime: Some(vfs_current_time),
            xGetLastError: Some(vfs_get_last_error),
            xCurrentTimeInt64: Some(vfs_current_time_int64),
            xSetSystemCall: None,
            xGetSystemCall: None,
            xNextSystemCall: None,
        }));
        sqlite3_vfs_register(vfs, 0)
    }
}

impl SqliteConn {
    /// Register persistent OPFS storage in a dedicated Worker. A locked or
    /// unavailable pool is an error; never fall back to the default RAM VFS.
    /// Exactly one Worker per origin may own the pool at a time.
    pub async fn initialize_opfs() -> Result<(), WasmSqliteError> {
        acquire_opfs_owner().await?;
        if unsafe { !sqlite3_vfs_find(ENCRYPTED_OPFS_VFS_NAME.as_ptr()).is_null() } {
            return Ok(());
        }
        let pool = sqlite_wasm_vfs::sahpool::install::<WasmOsCallback>(
            &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
            false,
        )
        .await
        .map_err(|error| WasmSqliteError::Sqlite {
            code: SQLITE_CANTOPEN,
            message: format!("OPFS initialization failed: {error}"),
        })?;
        // DELETE releases the journal entry after each transaction, so the
        // original 128 slots still hold 128 persistent account databases.
        // ensure_capacity grows existing smaller pools in place.
        pool.ensure_capacity(128)
            .await
            .map_err(|error| WasmSqliteError::Sqlite {
                code: SQLITE_CANTOPEN,
                message: format!("Protected OPFS capacity unavailable: {error}"),
            })?;
        let shim_rc = unsafe { opfs_sector512_vfs::ensure_registered() };
        if shim_rc != SQLITE_OK {
            return Err(WasmSqliteError::Sqlite {
                code: shim_rc,
                message: "cannot register 512-sector OPFS VFS adapter".into(),
            });
        }
        // sqlite3mc encryption requires its wrapper around the persistent VFS,
        // not an open directly against the underlying OPFS implementation.
        if unsafe { sqlite3_vfs_find(ENCRYPTED_OPFS_VFS_NAME.as_ptr()) }.is_null() {
            let result = unsafe { sqlite3mc_vfs_create(OPFS_SECTOR512_VFS_NAME.as_ptr(), 0) };
            if result != SQLITE_OK {
                return Err(WasmSqliteError::Sqlite {
                    code: result,
                    message: "cannot register encrypted OPFS VFS".into(),
                });
            }
        }
        Ok(())
    }

    /// Open a database at the given path with sqlite3mc ChaCha20 encryption
    /// (`PRAGMA cipher = 'chacha20';` BEFORE `PRAGMA key = "x'<64-hex>'";`,
    /// rollback journal `DELETE` so closed transactions release OPFS SAH slots; never `WAL`).
    pub fn open(db_path: &str, key: &str) -> Result<Self, WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(WasmSqliteError::Serialization(
                "database key must be 64 hexadecimal characters".into(),
            ));
        }
        let decoded_key = hex::decode(key)
            .map_err(|e| WasmSqliteError::Serialization(format!("invalid hex key: {e}")))?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&decoded_key);

        if OPEN_DATABASES.with(|paths| paths.borrow().contains(db_path)) {
            return Err(WasmSqliteError::Sqlite {
                code: SQLITE_BUSY,
                message: "Protected database already has a live owner in this Worker".into(),
            });
        }
        let c_path =
            CString::new(db_path).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut db: *mut sqlite3 = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_open_v2(
                c_path.as_ptr().cast(),
                &mut db as *mut _,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                ENCRYPTED_OPFS_VFS_NAME.as_ptr().cast(),
            )
        };

        if ret != SQLITE_OK || db.is_null() {
            if !db.is_null() {
                unsafe {
                    sqlite3_close(db);
                }
            }
            return Err(WasmSqliteError::Sqlite {
                code: ret,
                message: "Failed to open database".to_string(),
            });
        }

        OPEN_DATABASES.with(|paths| {
            paths.borrow_mut().insert(db_path.to_owned());
        });
        let conn = Self {
            db,
            db_path: db_path.to_owned(),
        };

        // Canonical WASM sqlite3mc pragma order:
        // 1. PRAGMA cipher = 'chacha20';
        // 2. PRAGMA key = "x'<64-hex>'";
        // 3. PRAGMA page_size = 4096;
        // 4. PRAGMA journal_mode = DELETE; (releases journal SAH slot after commit; never WAL)
        // 5. PRAGMA synchronous = FULL;
        // sqlite-wasm-vfs 0.3.0 reports LockLevel::None on fresh opens for hot-journal
        // recovery and flushes the OPFS slot header when unlinking the rollback journal;
        // opfs_sector512_vfs keeps JOURNAL_HDR_SZ = 512 != page_size so sqlite3mc never
        // encrypts multi-chunk rollback journal headers.
        let init_pragmas = catbird_mls::storage::wasm_sqlite3mc_init_pragmas(&key_bytes);
        conn.exec_raw(&init_pragmas)?;
        // Force key validation now, before callers can reserve remote work.
        conn.exec_raw("SELECT count(*) FROM sqlite_master;")?;
        // Ensure the unified 15-table schema (`Spec §6.1`).
        conn.exec_raw(catbird_mls::storage::UNIFIED_SCHEMA_DDL)?;

        Ok(conn)
    }

    /// Open an isolated in-memory unified SQLite database (`:memory:`) for
    /// deterministic WASM conformance replay (`T7-GOLDEN-50` / `Spec §6.1`).
    pub fn open_in_memory(key: &str) -> Result<Self, WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(WasmSqliteError::Serialization(
                "database key must be 64 hexadecimal characters".into(),
            ));
        }
        let decoded_key = hex::decode(key)
            .map_err(|e| WasmSqliteError::Serialization(format!("invalid hex key: {e}")))?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&decoded_key);

        let mut db: *mut sqlite3 = std::ptr::null_mut();
        let ret = unsafe {
            sqlite3_open_v2(
                c":memory:".as_ptr().cast(),
                &mut db as *mut _,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MEMORY,
                std::ptr::null(),
            )
        };
        if ret != SQLITE_OK || db.is_null() {
            if !db.is_null() {
                unsafe {
                    sqlite3_close(db);
                }
            }
            return Err(WasmSqliteError::Sqlite {
                code: ret,
                message: "Failed to open in-memory database".to_string(),
            });
        }

        let conn = Self {
            db,
            db_path: ":memory:".to_owned(),
        };
        let init_pragmas = catbird_mls::storage::wasm_sqlite3mc_init_pragmas(&key_bytes);
        let _ = conn.exec_raw(&init_pragmas);
        conn.exec_raw("SELECT count(*) FROM sqlite_master;")?;
        conn.exec_raw(catbird_mls::storage::UNIFIED_SCHEMA_DDL)?;
        Ok(conn)
    }

    /// Synchronous transaction on this shared connection. Never await inside
    /// the closure: the OPFS connection belongs to a single Worker.
    /// Nested transactions fail before running the closure.
    pub fn transaction<T, E>(&self, operation: impl FnOnce() -> Result<T, E>) -> Result<T, E>
    where
        E: From<WasmSqliteError>,
    {
        self.exec_raw("BEGIN IMMEDIATE").map_err(E::from)?;
        struct Rollback<'a>(&'a SqliteConn, bool);
        impl Drop for Rollback<'_> {
            fn drop(&mut self) {
                if self.1 {
                    let _ = self.0.exec_raw("ROLLBACK");
                }
            }
        }
        let mut rollback = Rollback(self, true);
        let value = operation()?;
        self.exec_raw("COMMIT").map_err(E::from)?;
        rollback.1 = false;
        Ok(value)
    }

    /// Refuse to certify uncommitted data; completed FULL-synchronous SQLite
    /// transactions already request the VFS durability barrier. Flush any
    /// remaining cache pages and propagate locked/storage errors.
    pub fn ensure_durable(&self) -> Result<(), WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        if unsafe { sqlite3_get_autocommit(self.db) } == 0 {
            return Err(WasmSqliteError::Sqlite {
                code: SQLITE_BUSY,
                message: "durability requested inside an open transaction".into(),
            });
        }
        let result = unsafe { sqlite3_db_cacheflush(self.db) };
        if result != SQLITE_OK {
            return Err(self.last_error(result));
        }
        Ok(())
    }

    /// Execute a SQL statement with no parameters and no result.
    pub fn exec_raw(&self, sql: &str) -> Result<(), WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        let c_sql = CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let ret = unsafe {
            sqlite3_exec(
                self.db,
                c_sql.as_ptr().cast(),
                None,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }
        Ok(())
    }

    /// Read a value by key from `openmls_kv` (default scope `""`, version `1`).
    pub fn get(&self, storage_key: &[u8]) -> Result<Option<Vec<u8>>, WasmSqliteError> {
        self.kv_get_scoped(1, "", storage_key)
    }

    /// Upsert a key-value pair into `openmls_kv` (default scope `""`, version `1`).
    pub fn put(&self, storage_key: &[u8], value: &[u8]) -> Result<(), WasmSqliteError> {
        self.kv_put_scoped(1, "", storage_key, value)
    }

    /// Delete a key from `openmls_kv` (default scope `""`, version `1`).
    pub fn remove(&self, storage_key: &[u8]) -> Result<(), WasmSqliteError> {
        self.kv_delete_scoped(1, "", storage_key)
    }

    /// Scoped read on `(version, scope, key_bytes)` in unified `openmls_kv`.
    pub fn kv_get_scoped(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        let sql = c"SELECT value_bytes FROM openmls_kv WHERE version = ?1 AND scope = ?2 AND key_bytes = ?3";
        let c_scope =
            CString::new(scope).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        if unsafe { sqlite3_bind_int64(stmt, 1, version as i64) } != SQLITE_OK
            || unsafe {
                sqlite3_bind_text(
                    stmt,
                    2,
                    c_scope.as_ptr().cast(),
                    scope.len() as i32,
                    sqlite_transient(),
                )
            } != SQLITE_OK
            || unsafe {
                sqlite3_bind_blob(
                    stmt,
                    3,
                    key.as_ptr().cast(),
                    key.len() as i32,
                    sqlite_transient(),
                )
            } != SQLITE_OK
        {
            let err = self.last_error(SQLITE_ERROR);
            unsafe { sqlite3_finalize(stmt) };
            return Err(err);
        }

        let step = unsafe { sqlite3_step(stmt) };
        let result = if step == SQLITE_ROW {
            let blob_ptr = unsafe { sqlite3_column_blob(stmt, 0) };
            let blob_len = unsafe { sqlite3_column_bytes(stmt, 0) } as usize;
            if blob_ptr.is_null() || blob_len == 0 {
                Ok(Some(Vec::new()))
            } else {
                let slice = unsafe { std::slice::from_raw_parts(blob_ptr.cast::<u8>(), blob_len) };
                Ok(Some(slice.to_vec()))
            }
        } else if step == SQLITE_DONE {
            Ok(None)
        } else {
            Err(self.last_error(step))
        };

        unsafe { sqlite3_finalize(stmt) };
        result
    }

    /// Scoped upsert on `(version, scope, key_bytes, value_bytes)` in unified `openmls_kv`.
    pub fn kv_put_scoped(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), WasmSqliteError> {
        self.exec_with_text_int_blob_params(
            "INSERT OR REPLACE INTO openmls_kv (version, scope, key_bytes, value_bytes) VALUES (?1, ?2, ?3, ?4)",
            &[(2, scope)],
            &[(1, version as i64)],
            &[(3, key), (4, value)],
        )
    }

    /// Scoped delete on `(version, scope, key_bytes)` in unified `openmls_kv`.
    pub fn kv_delete_scoped(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
    ) -> Result<(), WasmSqliteError> {
        self.exec_with_text_int_blob_params(
            "DELETE FROM openmls_kv WHERE version = ?1 AND scope = ?2 AND key_bytes = ?3",
            &[(2, scope)],
            &[(1, version as i64)],
            &[(3, key)],
        )
    }

    /// List all `key_bytes` in `(version, scope)` in unified `openmls_kv`.
    pub fn kv_list_keys_scoped(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<Vec<u8>>, WasmSqliteError> {
        let rows = self.query_text_int_blob(
            "SELECT key_bytes FROM openmls_kv WHERE version = ?1 AND scope = ?2 ORDER BY key_bytes ASC",
            &[(2, scope)],
            &[(1, version as i64)],
            1,
            &[0],
        )?;
        Ok(rows
            .into_iter()
            .map(|mut r| r.pop().and_then(|(_, b)| b).unwrap_or_default())
            .collect())
    }

    /// List all `(key_bytes, value_bytes)` in `(version, scope)` in unified `openmls_kv`.
    pub fn kv_list_entries_scoped(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, WasmSqliteError> {
        let rows = self.query_text_int_blob(
            "SELECT key_bytes, value_bytes FROM openmls_kv WHERE version = ?1 AND scope = ?2 ORDER BY key_bytes ASC",
            &[(2, scope)],
            &[(1, version as i64)],
            2,
            &[0, 1],
        )?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let k = r.first().and_then(|(_, b)| b.clone()).unwrap_or_default();
                let v = r.get(1).and_then(|(_, b)| b.clone()).unwrap_or_default();
                (k, v)
            })
            .collect())
    }

    /// Count all rows in `openmls_kv`.
    pub fn kv_count_all_rows(&self) -> Result<usize, WasmSqliteError> {
        let rows = self.query_text("SELECT COUNT(*) FROM openmls_kv", &[], 1)?;
        let count = rows
            .first()
            .and_then(|r| r.first())
            .and_then(|v| v.as_deref())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        Ok(count)
    }

    /// Prepare a SQL statement, bind text parameters, execute, and return nothing.
    ///
    /// `params` is a list of `(index, value)` pairs where index is 1-based.
    pub fn exec_with_text_params(
        &self,
        sql: &str,
        params: &[(i32, &str)],
    ) -> Result<(), WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        let c_sql = CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let step = unsafe { sqlite3_step(stmt) };
        unsafe { sqlite3_finalize(stmt) };

        if step != SQLITE_DONE {
            return Err(self.last_error(step));
        }
        Ok(())
    }

    /// Prepare a SQL statement, bind text and integer parameters, execute.
    pub fn exec_with_mixed_params(
        &self,
        sql: &str,
        text_params: &[(i32, &str)],
        int_params: &[(i32, i64)],
    ) -> Result<(), WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        let c_sql = CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in text_params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        for &(idx, val) in int_params {
            let ret = unsafe { sqlite3_bind_int64(stmt, idx, val) };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let step = unsafe { sqlite3_step(stmt) };
        unsafe { sqlite3_finalize(stmt) };

        if step != SQLITE_DONE {
            return Err(self.last_error(step));
        }
        Ok(())
    }

    /// Prepare a SQL statement, bind text and blob parameters, execute.
    /// Exec a statement with text + int + blob params. Each `(idx, value)`
    /// tuple binds the value at the 1-based SQL placeholder index.
    /// Indices must be globally unique across the three slices.
    ///
    /// Used by the encrypted message insert path which needs to bind the
    /// row's text columns (id, conv, ...), int columns (sequence, epoch,
    /// payload_key_version), and BLOB columns (payload_encrypted,
    /// entry_hmac) in a single statement.
    pub fn exec_with_text_int_blob_params(
        &self,
        sql: &str,
        text_params: &[(i32, &str)],
        int_params: &[(i32, i64)],
        blob_params: &[(i32, &[u8])],
    ) -> Result<(), WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        let c_sql = CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in text_params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        for &(idx, val) in int_params {
            let ret = unsafe { sqlite3_bind_int64(stmt, idx, val) };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        for &(idx, val) in blob_params {
            let ret = unsafe {
                sqlite3_bind_blob(
                    stmt,
                    idx,
                    val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let step = unsafe { sqlite3_step(stmt) };
        unsafe { sqlite3_finalize(stmt) };

        if step != SQLITE_DONE {
            return Err(self.last_error(step));
        }
        Ok(())
    }

    pub fn exec_with_text_and_blob_params(
        &self,
        sql: &str,
        text_params: &[(i32, &str)],
        blob_params: &[(i32, &[u8])],
    ) -> Result<(), WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        let c_sql = CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in text_params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        for &(idx, val) in blob_params {
            let ret = unsafe {
                sqlite3_bind_blob(
                    stmt,
                    idx,
                    val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let step = unsafe { sqlite3_step(stmt) };
        unsafe { sqlite3_finalize(stmt) };

        if step != SQLITE_DONE {
            return Err(self.last_error(step));
        }
        Ok(())
    }

    /// Query rows with text params. Returns column values as strings for each row.
    pub fn query_text(
        &self,
        sql: &str,
        params: &[(i32, &str)],
        col_count: usize,
    ) -> Result<Vec<Vec<Option<String>>>, WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        let c_sql = CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let mut rows = Vec::new();
        loop {
            let step = unsafe { sqlite3_step(stmt) };
            if step == SQLITE_ROW {
                let mut row = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let ptr = unsafe { sqlite3_column_text(stmt, i as i32) };
                    if ptr.is_null() {
                        row.push(None);
                    } else {
                        let c_str = unsafe { std::ffi::CStr::from_ptr(ptr.cast()) };
                        row.push(Some(c_str.to_string_lossy().into_owned()));
                    }
                }
                rows.push(row);
            } else if step == SQLITE_DONE {
                break;
            } else {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(step));
            }
        }

        unsafe { sqlite3_finalize(stmt) };
        Ok(rows)
    }

    /// Query rows with mixed text/int params. Returns column values as strings.
    pub fn query_text_mixed(
        &self,
        sql: &str,
        text_params: &[(i32, &str)],
        int_params: &[(i32, i64)],
        col_count: usize,
    ) -> Result<Vec<Vec<Option<String>>>, WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        let c_sql = CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in text_params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        for &(idx, val) in int_params {
            let ret = unsafe { sqlite3_bind_int64(stmt, idx, val) };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let mut rows = Vec::new();
        loop {
            let step = unsafe { sqlite3_step(stmt) };
            if step == SQLITE_ROW {
                let mut row = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let ptr = unsafe { sqlite3_column_text(stmt, i as i32) };
                    if ptr.is_null() {
                        row.push(None);
                    } else {
                        let c_str = unsafe { std::ffi::CStr::from_ptr(ptr.cast()) };
                        row.push(Some(c_str.to_string_lossy().into_owned()));
                    }
                }
                rows.push(row);
            } else if step == SQLITE_DONE {
                break;
            } else {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(step));
            }
        }

        unsafe { sqlite3_finalize(stmt) };
        Ok(rows)
    }

    /// Query rows with text + int params, returning a heterogeneous row
    /// shape where some columns are textual and some are BLOBs.
    ///
    /// `text_cols` is the set of column indices (0-based) that should be
    /// decoded as UTF-8 strings via `sqlite3_column_text`. Every other
    /// column up to `col_count` is read as a raw BLOB via
    /// `sqlite3_column_blob`. Each row is returned as a vector of
    /// `(Option<String>, Option<Vec<u8>>)` where exactly one side of the
    /// tuple is populated per column.
    ///
    /// Used by the message read path so the same SELECT can pull metadata
    /// (id, sender_did, ...) plus the encrypted `payload_encrypted` /
    /// `entry_hmac` BLOBs in a single statement.
    pub fn query_text_int_blob(
        &self,
        sql: &str,
        text_params: &[(i32, &str)],
        int_params: &[(i32, i64)],
        col_count: usize,
        blob_cols: &[usize],
    ) -> Result<Vec<Vec<(Option<String>, Option<Vec<u8>>)>>, WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        let c_sql = CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in text_params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        for &(idx, val) in int_params {
            let ret = unsafe { sqlite3_bind_int64(stmt, idx, val) };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let blob_set: std::collections::HashSet<usize> = blob_cols.iter().copied().collect();
        let mut rows = Vec::new();
        loop {
            let step = unsafe { sqlite3_step(stmt) };
            if step == SQLITE_ROW {
                let mut row = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    if blob_set.contains(&i) {
                        let blob_ptr = unsafe { sqlite3_column_blob(stmt, i as i32) };
                        let blob_len = unsafe { sqlite3_column_bytes(stmt, i as i32) } as usize;
                        if blob_ptr.is_null() || blob_len == 0 {
                            row.push((None, None));
                        } else {
                            let slice = unsafe {
                                std::slice::from_raw_parts(blob_ptr.cast::<u8>(), blob_len)
                            };
                            row.push((None, Some(slice.to_vec())));
                        }
                    } else {
                        let ptr = unsafe { sqlite3_column_text(stmt, i as i32) };
                        if ptr.is_null() {
                            row.push((None, None));
                        } else {
                            let c_str = unsafe { std::ffi::CStr::from_ptr(ptr.cast()) };
                            row.push((Some(c_str.to_string_lossy().into_owned()), None));
                        }
                    }
                }
                rows.push(row);
            } else if step == SQLITE_DONE {
                break;
            } else {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(step));
            }
        }

        unsafe { sqlite3_finalize(stmt) };
        Ok(rows)
    }

    /// Query that returns blob data from column 0.
    pub fn query_blob(
        &self,
        sql: &str,
        text_params: &[(i32, &str)],
    ) -> Result<Option<Vec<u8>>, WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        let c_sql = CString::new(sql).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let mut stmt: *mut sqlite3_stmt = std::ptr::null_mut();

        let ret = unsafe {
            sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr().cast(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if ret != SQLITE_OK {
            return Err(self.last_error(ret));
        }

        for &(idx, val) in text_params {
            let c_val =
                CString::new(val).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
            let ret = unsafe {
                sqlite3_bind_text(
                    stmt,
                    idx,
                    c_val.as_ptr().cast(),
                    val.len() as i32,
                    sqlite_transient(),
                )
            };
            if ret != SQLITE_OK {
                unsafe { sqlite3_finalize(stmt) };
                return Err(self.last_error(ret));
            }
        }

        let step = unsafe { sqlite3_step(stmt) };
        let result = if step == SQLITE_ROW {
            let blob_ptr = unsafe { sqlite3_column_blob(stmt, 0) };
            let blob_len = unsafe { sqlite3_column_bytes(stmt, 0) } as usize;
            if blob_ptr.is_null() || blob_len == 0 {
                Ok(Some(Vec::new()))
            } else {
                let slice = unsafe { std::slice::from_raw_parts(blob_ptr.cast::<u8>(), blob_len) };
                Ok(Some(slice.to_vec()))
            }
        } else if step == SQLITE_DONE {
            Ok(None)
        } else {
            Err(self.last_error(step))
        };

        unsafe { sqlite3_finalize(stmt) };
        result
    }

    /// Check if a row exists (returns true if query returns at least one row).
    pub fn exists(&self, sql: &str, params: &[(i32, &str)]) -> Result<bool, WasmSqliteError> {
        crate::browser_session::check()
            .map_err(|error| WasmSqliteError::Serialization(error.into()))?;
        let rows = self.query_text(sql, params, 1)?;
        Ok(!rows.is_empty())
    }

    /// The stored message `message_id`, whatever its conversation or seq.
    pub fn get_message(
        &self,
        message_id: &str,
    ) -> Result<Option<catbird_mls::storage::MessageRow>, catbird_mls::MLSError> {
        let rows = self
            .query_text_int_blob(
                "SELECT message_id, conversation_id, group_id, epoch, seq, sender_did, sender_device_id, plaintext_json, created_at_ms, is_own \
                 FROM messages WHERE message_id = ?1",
                &[(1, message_id)],
                &[],
                10,
                &[2],
            )
            .map_err(map_wasm_mls_err)?;
        Ok(rows.first().map(|row| message_row(row)))
    }

    /// Upgrade earlier browser databases that removed display rows but retained receipt-backed
    /// decrypted frames. The caller commits the scrub and its completion flag together.
    pub fn repair_legacy_erasure_evidence(&self, ts: i64) -> Result<(), catbird_mls::MLSError> {
        use catbird_mls::client::deletion_authority::AppliedAccountDeletion;
        use catbird_mls::storage::driver_wasm::WasmSqlBackend;
        use catbird_mls::MLSError;
        const DONE: &str = "browser.deletion_evidence_scrub_v2";
        if self.get_account_meta(DONE)?.as_deref() == Some("1") {
            return Ok(());
        }
        let prefix = "native.account_deleted:";
        let rows = self.query_text_int_blob(
            "SELECT state_key, value_bytes FROM labyrinth_state WHERE substr(state_key, 1, length(?1)) = ?1",
            &[(1, prefix)], &[], 2, &[1],
        ).map_err(map_wasm_mls_err)?;
        for row in rows {
            let (cid, did) = row[0]
                .0
                .as_deref()
                .and_then(|s| s.strip_prefix(prefix))
                .and_then(|s| s.find(":did:").map(|n| (&s[..n], &s[n + 1..])))
                .ok_or_else(|| MLSError::Internal("invalid stored deletion key".into()))?;
            let marker = row[1]
                .1
                .as_deref()
                .and_then(AppliedAccountDeletion::decode)
                .ok_or_else(|| MLSError::Internal("invalid stored deletion marker".into()))?;
            self.purge_covered_account_data(cid, did, &marker)?;
        }
        self.put_account_meta(DONE, "1", ts)
    }

    /// Rewrites stored alpha-form Space URIs (`at://{did}/space/...`) to `at:space/{did}/...`
    /// once per browser database. The browser counterpart of the native driver's rewrite in
    /// `catbird_mls::storage::driver_native`: same rows, plus the browser's own `wasm.*`
    /// bookkeeping and the backup status. Only local bookkeeping changes; signed or encrypted
    /// bytes, MLS state and message content are never touched. The caller commits the rewrite
    /// and its marker together, so an interrupted run starts again on the next open.
    /// TODO: remove before beta.
    pub fn rewrite_legacy_space_uris(&self, ts: i64) -> Result<(), catbird_mls::MLSError> {
        use catbird_mls::storage::driver_wasm::WasmSqlBackend;
        use catbird_mls::storage::space_uri_rewrite::{
            from_legacy_space_uri, rewrite_json_space_uris, SPACE_URI_REWRITE_MARKER_KEY,
        };
        use catbird_mls::MLSError;
        use serde_json::Value;

        if self.get_account_meta(SPACE_URI_REWRITE_MARKER_KEY)?.is_some() {
            return Ok(());
        }
        let encode = |value: &Value| {
            serde_json::to_vec(value)
                .map_err(|e| MLSError::Internal(format!("space uri rewrite: {e}")))
        };
        // Rewrites one named top-level or nested string field, leaving the rest of the JSON alone.
        let rewrite_field = |value: &mut Value, pointer: &str| -> bool {
            let Some(slot) = value.pointer_mut(pointer) else {
                return false;
            };
            match slot.as_str().and_then(from_legacy_space_uri) {
                Some(new) => {
                    *slot = Value::String(new);
                    true
                }
                None => false,
            }
        };

        // conversations.space_uri: a plain Space URI column.
        let rows = self
            .query_text(
                "SELECT conversation_id, space_uri FROM conversations \
                 WHERE space_uri LIKE 'at://%/space/%'",
                &[],
                2,
            )
            .map_err(map_wasm_mls_err)?;
        for row in rows {
            let (Some(cid), Some(uri)) = (row[0].as_deref(), row[1].as_deref()) else {
                continue;
            };
            if let Some(new_uri) = from_legacy_space_uri(uri) {
                self.exec_with_text_params(
                    "UPDATE conversations SET space_uri = ?2 WHERE conversation_id = ?1",
                    &[(1, cid), (2, &new_uri)],
                )
                .map_err(map_wasm_mls_err)?;
            }
        }

        // pending_ops: the queued archive's `$.archive.space_uri`, nothing else in the payload.
        let rows = self
            .query_text(
                "SELECT op_kind, op_key, payload_json FROM pending_ops \
                 WHERE payload_json LIKE '%at://%/space/%'",
                &[],
                3,
            )
            .map_err(map_wasm_mls_err)?;
        for row in rows {
            let (Some(kind), Some(key), Some(raw)) =
                (row[0].as_deref(), row[1].as_deref(), row[2].as_deref())
            else {
                continue;
            };
            let Ok(mut value) = serde_json::from_str::<Value>(raw) else {
                continue;
            };
            if rewrite_field(&mut value, "/archive/space_uri") {
                self.exec_with_text_params(
                    "UPDATE pending_ops SET payload_json = ?3 WHERE op_kind = ?1 AND op_key = ?2",
                    &[(1, kind), (2, key), (3, &value.to_string())],
                )
                .map_err(map_wasm_mls_err)?;
            }
        }

        // labyrinth_queue: the outbox envelope's top-level `space_uri` only.
        let rows = self
            .query_text_int_blob(
                "SELECT item_id, payload_bytes FROM labyrinth_queue",
                &[],
                &[],
                2,
                &[1],
            )
            .map_err(map_wasm_mls_err)?;
        for row in rows {
            let (Some(item_id), Some(raw)) = (row[0].0.as_deref(), row[1].1.as_deref()) else {
                continue;
            };
            let Ok(mut value) = serde_json::from_slice::<Value>(raw) else {
                continue;
            };
            if rewrite_field(&mut value, "/space_uri") {
                self.exec_with_text_and_blob_params(
                    "UPDATE labyrinth_queue SET payload_bytes = ?2 WHERE item_id = ?1",
                    &[(1, item_id)],
                    &[(2, &encode(&value)?)],
                )
                .map_err(map_wasm_mls_err)?;
            }
        }

        // Space pins and writer revision floors (JSON keyed or valued by Space URI), and the
        // backup status, whose `mailbox_space_uri` is shown to the owner.
        let rows = self
            .query_text_int_blob(
                "SELECT state_key, value_bytes FROM labyrinth_state \
                 WHERE state_key = 'status_json' \
                 OR state_key LIKE 'wasm.placements:%' \
                 OR state_key LIKE 'wasm.writer_rev_floors:%' \
                 OR state_key LIKE 'native.placements:%' \
                 OR state_key LIKE 'native.writer_rev_floors:%'",
                &[],
                &[],
                2,
                &[1],
            )
            .map_err(map_wasm_mls_err)?;
        for row in rows {
            let (Some(state_key), Some(raw)) = (row[0].0.as_deref(), row[1].1.as_deref()) else {
                continue;
            };
            let Ok(mut value) = serde_json::from_slice::<Value>(raw) else {
                continue;
            };
            if rewrite_json_space_uris(&mut value) {
                self.exec_with_text_and_blob_params(
                    "UPDATE labyrinth_state SET value_bytes = ?2 WHERE state_key = ?1",
                    &[(1, state_key)],
                    &[(2, &encode(&value)?)],
                )
                .map_err(map_wasm_mls_err)?;
            }
        }

        // account_meta: mailbox placement request values (whole JSON), and the two journals
        // that later become archive queue items unchanged: a send journal's
        // `$.archive.space_uri` and a staged C33 opening's top-level `space_uri`. The signed
        // request body, frame, receipt and attestation in them are left as they are.
        let rows = self
            .query_text(
                "SELECT key, value_json FROM account_meta \
                 WHERE key LIKE 'direct_request_value_v2:labyrinthMailboxPlacement:%' \
                 OR key LIKE 'c33_pending_opening:%' \
                 OR key LIKE 'application_send:%'",
                &[],
                2,
            )
            .map_err(map_wasm_mls_err)?;
        for row in rows {
            let (Some(key), Some(raw)) = (row[0].as_deref(), row[1].as_deref()) else {
                continue;
            };
            let Ok(mut value) = serde_json::from_str::<Value>(raw) else {
                continue;
            };
            let changed = if key.starts_with("c33_pending_opening:") {
                rewrite_field(&mut value, "/space_uri")
            } else if key.starts_with("application_send:") {
                rewrite_field(&mut value, "/archive/space_uri")
            } else {
                rewrite_json_space_uris(&mut value)
            };
            if changed {
                self.exec_with_text_params(
                    "UPDATE account_meta SET value_json = ?2 WHERE key = ?1",
                    &[(1, key), (2, &value.to_string())],
                )
                .map_err(map_wasm_mls_err)?;
            }
        }

        self.put_account_meta(SPACE_URI_REWRITE_MARKER_KEY, "1", ts)
    }

    pub fn all_conversation_ids(&self) -> Result<Vec<String>, catbird_mls::MLSError> {
        self.query_text(
            "SELECT conversation_id FROM conversations ORDER BY conversation_id",
            &[],
            1,
        )
        .map(|rows| rows.into_iter().flatten().flatten().collect())
        .map_err(map_wasm_mls_err)
    }

    /// Intake and acceptance both run under the same write transaction as the erasure.
    pub(crate) fn applied_deletion_marker(
        &self,
        cid: &str,
        did: &str,
    ) -> Result<
        Option<catbird_mls::client::deletion_authority::StoredAccountDeletion>,
        catbird_mls::MLSError,
    > {
        use catbird_mls::client::{chat_wire, deletion_authority::AppliedAccountDeletion};
        use catbird_mls::storage::driver_wasm::WasmSqlBackend;

        self.get_labyrinth_state(&chat_wire::account_deletion_key(cid, did))?
            .as_deref()
            .map(|raw| {
                AppliedAccountDeletion::decode(raw).ok_or_else(|| {
                    catbird_mls::MLSError::Cryptography("corrupt account deletion marker".into())
                })
            })
            .transpose()
    }

    pub(crate) fn archive_frame_covered(
        &self,
        frame: &catbird_mls::client::QueuedLabyrinthArchivePayload,
    ) -> Result<bool, catbird_mls::MLSError> {
        let Some(marker) =
            self.applied_deletion_marker(&frame.conversation_id, &frame.sender_did)?
        else {
            return Ok(false);
        };
        let (seq, issued) = archive_frame_position(frame)?;
        Ok(marker.covers(seq, Some(issued)))
    }

    fn scrub_direct_request_openings(
        &self,
        cid: &str,
        did: &str,
        marker: &catbird_mls::client::deletion_authority::StoredAccountDeletion,
    ) -> Result<(), catbird_mls::MLSError> {
        use catbird_mls::client::QueuedLabyrinthArchivePayload;
        use catbird_mls::storage::driver_wasm::WasmSqlBackend;
        use catbird_mls::MLSError;

        let stage_key = format!("c33_pending_opening:{cid}");
        let stage = self
            .get_account_meta(&stage_key)?
            .filter(|raw| !raw.is_empty() && raw != "archived")
            .map(|raw| serde_json::from_str::<QueuedLabyrinthArchivePayload>(&raw))
            .transpose()?
            .filter(|frame| frame.conversation_id == cid && frame.sender_did == did);
        let stage_position = stage.as_ref().map(archive_frame_position).transpose()?;

        // The signed opening receipt, archived evidence, queued copy, and display row also
        // cover accepted requests whose pending frame was replaced by the "archived" sentinel.
        let rows = self.query_text(
            "WITH openings AS (
                SELECT r.request_id AS id, r.first_message_id AS mid,
                    COALESCE(CAST(s.value_bytes AS TEXT),
                        json_extract(CAST(e.value_bytes AS TEXT), '$.sequencer_receipt_json'),
                        json_extract(CAST(q.payload_bytes AS TEXT), '$.sequencer_receipt_json')) AS receipt,
                    COALESCE(m.seq, q.seq) AS seq, COALESCE(m.created_at_ms, q.created_at_ms) AS stamp
                FROM requests r
                LEFT JOIN labyrinth_state s ON s.state_key = 'c33_opening_receipt:' || ?1 || ':' || r.first_message_id
                LEFT JOIN labyrinth_state e ON e.state_key = 'native.message:' || ?1 || ':' || r.first_message_id
                LEFT JOIN labyrinth_queue q ON q.item_id = r.first_message_id AND q.conversation_id = ?1
                LEFT JOIN messages m ON m.message_id = r.first_message_id AND m.conversation_id = ?1
                WHERE r.conversation_id = ?1 AND r.sender_did = ?2 AND r.first_message_id IS NOT NULL
            ) SELECT id, mid, json_extract(receipt, '$.seq'), json_extract(receipt, '$.issued_at_ms'), seq, stamp
              FROM openings",
            &[(1, cid), (2, did)], 6,
        ).map_err(map_wasm_mls_err)?;
        for row in rows {
            let id = row[0]
                .as_deref()
                .ok_or_else(|| MLSError::Internal("missing request id".into()))?;
            let mid = row[1]
                .as_deref()
                .ok_or_else(|| MLSError::Internal("missing opening id".into()))?;
            let number = |index: usize| {
                row[index]
                    .as_deref()
                    .map(str::parse::<i64>)
                    .transpose()
                    .map_err(|_| MLSError::Internal("invalid stored opening coordinates".into()))
            };
            let staged = stage
                .as_ref()
                .filter(|frame| frame.message_id == mid)
                .and(stage_position);
            // A legacy display-only request whose originating frame was already removed has
            // unknown coordinates. The shared conservative rule holds that orphan preview.
            let seq = number(2)?
                .or(staged.map(|(seq, _)| seq))
                .or(number(4)?)
                .unwrap_or(0);
            let issued = number(3)?.or(staged.map(|(_, stamp)| stamp)).or(number(5)?);
            if marker.covers(seq, issued) {
                self.exec_with_text_params(
                    "UPDATE requests SET payload_json = '{}' WHERE request_id = ?1",
                    &[(1, id)],
                )
                .map_err(map_wasm_mls_err)?;
                self.delete_message(cid, mid)?;
                self.delete_labyrinth_state_key(&format!("native.message:{cid}:{mid}"))?;
                self.delete_labyrinth_state_key(
                    &catbird_mls::client::chat_wire::undecryptable_evidence_key(cid, mid),
                )?;
                self.delete_labyrinth_state_key(
                    &catbird_mls::client::chat_wire::unavailable_message_key(cid, mid),
                )?;
                self.dequeue_labyrinth_item(mid)?;
            }
        }
        if stage_position.is_some_and(|(seq, issued)| marker.covers(seq, Some(issued))) {
            self.delete_account_meta(&stage_key)?;
        }
        Ok(())
    }

    /// Erase display rows, archive evidence (including orphan frames), and queued copies in the
    /// caller's transaction. Prefer the verified receipt's issue time over local insertion time.
    pub fn purge_covered_account_data(
        &self,
        cid: &str,
        did: &str,
        marker: &catbird_mls::client::deletion_authority::StoredAccountDeletion,
    ) -> Result<(), catbird_mls::MLSError> {
        use catbird_mls::client::chat_wire;
        use catbird_mls::storage::driver_wasm::WasmSqlBackend;
        use catbird_mls::MLSError;

        self.scrub_direct_request_openings(cid, did, marker)?;
        let rows = self.query_text(
            "SELECT m.message_id, m.seq, COALESCE(
                json_extract(CAST(s.value_bytes AS TEXT), '$.issued_at_ms'),
                json_extract(json_extract(CAST(e.value_bytes AS TEXT), '$.sequencer_receipt_json'), '$.issued_at_ms'),
                json_extract(CAST(u.value_bytes AS TEXT), '$.receipt.issuedAtMs'), m.created_at_ms)
             FROM messages m
             LEFT JOIN labyrinth_state s ON s.state_key = 'c33_opening_receipt:' || ?1 || ':' || m.message_id
             LEFT JOIN labyrinth_state e ON e.state_key = 'native.message:' || ?1 || ':' || m.message_id
             LEFT JOIN labyrinth_state u ON u.state_key = 'native.unavailable:' || ?1 || ':' || m.message_id
             WHERE m.conversation_id = ?1 AND m.sender_did = ?2",
            &[(1, cid), (2, did)], 3,
        ).map_err(map_wasm_mls_err)?;
        let covered = |row: &[Option<String>]| -> Result<bool, MLSError> {
            let seq = row[1]
                .as_deref()
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| MLSError::Internal("missing deletion candidate sequence".into()))?;
            let issued = row[2]
                .as_deref()
                .map(str::parse::<i64>)
                .transpose()
                .map_err(|_| MLSError::Internal("invalid deletion candidate issue time".into()))?;
            Ok(marker.covers(seq, issued))
        };
        for row in rows {
            if covered(&row)? {
                let id = row[0]
                    .as_deref()
                    .ok_or_else(|| MLSError::Internal("missing message id".into()))?;
                self.delete_message(cid, id)?;
                self.delete_labyrinth_state_key(&format!("native.message:{cid}:{id}"))?;
                self.delete_labyrinth_state_key(&chat_wire::unavailable_message_key(cid, id))?;
                self.delete_labyrinth_state_key(&chat_wire::undecryptable_evidence_key(cid, id))?;
            }
        }
        let prefix = format!("native.message:{cid}:");
        let evidence = self.query_text(
            "WITH frames AS (
                SELECT state_key, json_extract(CAST(value_bytes AS TEXT), '$.sequencer_receipt_json') AS receipt
                FROM labyrinth_state WHERE substr(state_key, 1, length(?1)) = ?1
             ) SELECT state_key, json_extract(receipt, '$.seq'), json_extract(receipt, '$.issued_at_ms')
             FROM frames WHERE substr(json_extract(receipt, '$.sender_device_did_url'), 1, length(?2)+1) = ?2 || '#'",
            &[(1, &prefix), (2, did)], 3,
        ).map_err(map_wasm_mls_err)?;
        for row in evidence {
            if covered(&row)? {
                let key = row[0]
                    .as_deref()
                    .ok_or_else(|| MLSError::Internal("missing frame key".into()))?;
                self.delete_labyrinth_state_key(key)?;
            }
        }
        let queued = self.query_text(
            "SELECT item_id, seq, COALESCE(
                json_extract(json_extract(CAST(payload_bytes AS TEXT), '$.sequencer_receipt_json'), '$.issued_at_ms'),
                json_extract(CAST(payload_bytes AS TEXT), '$.created_at_ms'))
             FROM labyrinth_queue WHERE conversation_id = ?1 AND json_extract(CAST(payload_bytes AS TEXT), '$.sender_did') = ?2",
            &[(1, cid), (2, did)], 3,
        ).map_err(map_wasm_mls_err)?;
        for row in queued {
            if covered(&row)? {
                let id = row[0]
                    .as_deref()
                    .ok_or_else(|| MLSError::Internal("missing queue id".into()))?;
                self.dequeue_labyrinth_item(id)?;
            }
        }
        Ok(())
    }

    /// Database path inside the OPFS SAH pool.
    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    /// Delete one `labyrinth_state` row by key.
    pub fn delete_labyrinth_state_key(&self, state_key: &str) -> Result<(), catbird_mls::MLSError> {
        self.exec_with_text_params(
            "DELETE FROM labyrinth_state WHERE state_key = ?1",
            &[(1, state_key)],
        )
        .map_err(map_wasm_mls_err)
    }

    /// Wipe all rows across all 15 unified schema tables inside one immediate transaction.
    pub fn wipe_all_tables(&self) -> Result<(), catbird_mls::MLSError> {
        self.transaction(|| {
            for table in [
                "openmls_kv",
                "account_meta",
                "conversations",
                "messages",
                "requests",
                "participant_profiles",
                "group_metadata_cache",
                "epoch_secrets",
                "sequencer_receipts",
                "recovery_state",
                "pending_ops",
                "mutation_journal",
                "routing_cache",
                "labyrinth_state",
                "labyrinth_queue",
            ] {
                self.exec_raw(&format!("DELETE FROM {table};"))?;
            }
            Ok::<(), WasmSqliteError>(())
        })
        .map_err(map_wasm_mls_err)?;
        self.ensure_durable().map_err(map_wasm_mls_err)
    }

    /// Unlink a closed database path from the encrypted OPFS SAH pool VFS.
    pub fn delete_opfs_database(db_path: &str) -> Result<(), WasmSqliteError> {
        if OPEN_DATABASES.with(|paths| paths.borrow().contains(db_path)) {
            return Err(WasmSqliteError::Sqlite {
                code: SQLITE_BUSY,
                message: "Cannot delete an open OPFS database".into(),
            });
        }
        let c_path =
            CString::new(db_path).map_err(|e| WasmSqliteError::Serialization(e.to_string()))?;
        let vfs = unsafe { sqlite3_vfs_find(ENCRYPTED_OPFS_VFS_NAME.as_ptr()) };
        if vfs.is_null() {
            return Ok(());
        }
        let rc = unsafe {
            match (*vfs).xDelete {
                Some(del) => del(vfs, c_path.as_ptr(), 1),
                None => SQLITE_OK,
            }
        };
        if rc == SQLITE_OK || rc == SQLITE_IOERR_DELETE_NOENT {
            Ok(())
        } else {
            Err(WasmSqliteError::Sqlite {
                code: rc,
                message: format!("Failed to delete OPFS database {db_path}"),
            })
        }
    }

    /// Extract the last error message from the database handle.
    pub fn last_error(&self, code: i32) -> WasmSqliteError {
        let msg = unsafe {
            let ptr = sqlite3_errmsg(self.db);
            if ptr.is_null() {
                "unknown error".to_string()
            } else {
                let c_str = std::ffi::CStr::from_ptr(ptr.cast());
                c_str.to_string_lossy().into_owned()
            }
        };
        WasmSqliteError::Sqlite { code, message: msg }
    }

    pub fn delete_message(
        &self,
        conversation_id: &str,
        message_id: &str,
    ) -> Result<(), catbird_mls::MLSError> {
        self.exec_with_text_params(
            "DELETE FROM messages WHERE conversation_id = ?1 AND message_id = ?2",
            &[(1, conversation_id), (2, message_id)],
        )
        .map_err(map_wasm_mls_err)
    }
}

impl Drop for SqliteConn {
    fn drop(&mut self) {
        if !self.db.is_null() {
            unsafe {
                if sqlite3_close(self.db) == SQLITE_OK {
                    OPEN_DATABASES.with(|paths| {
                        paths.borrow_mut().remove(&self.db_path);
                    });
                }
            }
        }
    }
}

fn map_wasm_kv_err(err: WasmSqliteError) -> catbird_mls::storage::openmls_kv::OpenMlsKvError {
    catbird_mls::storage::openmls_kv::OpenMlsKvError::Sql(err.to_string())
}

fn map_wasm_mls_err(err: WasmSqliteError) -> catbird_mls::MLSError {
    catbird_mls::MLSError::Internal(err.to_string())
}

/// A `messages` row selected as `message_id, conversation_id, group_id (blob), epoch, seq,
/// sender_did, sender_device_id, plaintext_json, created_at_ms, is_own`.
fn message_row(r: &[(Option<String>, Option<Vec<u8>>)]) -> catbird_mls::storage::MessageRow {
    catbird_mls::storage::MessageRow {
        message_id: r[0].0.clone().unwrap_or_default(),
        conversation_id: r[1].0.clone().unwrap_or_default(),
        group_id: r[2].1.clone().unwrap_or_default(),
        epoch: r[3].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        seq: r[4].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        sender_did: r[5].0.clone().unwrap_or_default(),
        sender_device_id: r[6].0.clone().unwrap_or_default(),
        plaintext_json: r[7].0.clone().unwrap_or_default(),
        created_at_ms: r[8].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        is_own: r[9].0.as_deref() == Some("1"),
    }
}

impl catbird_mls::storage::openmls_kv::KvBackend for SqliteConn {
    fn kv_get(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, catbird_mls::storage::openmls_kv::OpenMlsKvError> {
        self.kv_get_scoped(version, scope, key)
            .map_err(map_wasm_kv_err)
    }

    fn kv_put(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), catbird_mls::storage::openmls_kv::OpenMlsKvError> {
        self.kv_put_scoped(version, scope, key, value)
            .map_err(map_wasm_kv_err)
    }

    fn kv_delete(
        &self,
        version: u16,
        scope: &str,
        key: &[u8],
    ) -> Result<(), catbird_mls::storage::openmls_kv::OpenMlsKvError> {
        self.kv_delete_scoped(version, scope, key)
            .map_err(map_wasm_kv_err)
    }

    fn kv_list_keys_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<Vec<u8>>, catbird_mls::storage::openmls_kv::OpenMlsKvError> {
        self.kv_list_keys_scoped(version, scope)
            .map_err(map_wasm_kv_err)
    }

    fn kv_list_entries_in_scope(
        &self,
        version: u16,
        scope: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, catbird_mls::storage::openmls_kv::OpenMlsKvError> {
        self.kv_list_entries_scoped(version, scope)
            .map_err(map_wasm_kv_err)
    }

    fn kv_count_all(&self) -> Result<usize, catbird_mls::storage::openmls_kv::OpenMlsKvError> {
        self.kv_count_all_rows().map_err(map_wasm_kv_err)
    }
}

impl catbird_mls::storage::driver_wasm::WasmSqlBackend for SqliteConn {
    fn begin_immediate(&self) -> Result<(), catbird_mls::MLSError> {
        self.exec_raw("BEGIN IMMEDIATE").map_err(map_wasm_mls_err)
    }

    fn commit_tx(&self) -> Result<(), catbird_mls::MLSError> {
        self.exec_raw("COMMIT").map_err(map_wasm_mls_err)
    }

    fn rollback_tx(&self) -> Result<(), catbird_mls::MLSError> {
        self.exec_raw("ROLLBACK").map_err(map_wasm_mls_err)
    }

    fn get_account_meta(&self, key: &str) -> Result<Option<String>, catbird_mls::MLSError> {
        let rows = self
            .query_text(
                "SELECT value_json FROM account_meta WHERE key = ?1 LIMIT 1",
                &[(1, key)],
                1,
            )
            .map_err(map_wasm_mls_err)?;
        Ok(rows.into_iter().next().and_then(|mut r| r.pop().flatten()))
    }

    fn put_account_meta(
        &self,
        key: &str,
        value_json: &str,
        updated_at_ms: i64,
    ) -> Result<(), catbird_mls::MLSError> {
        self.exec_with_mixed_params(
            "INSERT OR REPLACE INTO account_meta (key, value_json, updated_at_ms) VALUES (?1, ?2, ?3)",
            &[(1, key), (2, value_json)],
            &[(3, updated_at_ms)],
        )
        .map_err(map_wasm_mls_err)
    }

    fn delete_account_meta(&self, key: &str) -> Result<(), catbird_mls::MLSError> {
        self.exec_with_text_params("DELETE FROM account_meta WHERE key = ?1", &[(1, key)])
            .map_err(map_wasm_mls_err)
    }

    fn upsert_conversation(
        &self,
        row: &catbird_mls::storage::ConversationRow,
    ) -> Result<(), catbird_mls::MLSError> {
        let space_uri = row.space_uri.as_deref().unwrap_or("");
        let title = row.title.as_deref().unwrap_or("");
        self.exec_with_text_int_blob_params(
            "INSERT INTO conversations (conversation_id, group_id, generation, epoch, last_seq, sequencer_did, space_uri, title, unread_count, updated_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULLIF(?7, ''), NULLIF(?8, ''), ?9, ?10) \
             ON CONFLICT(conversation_id) DO UPDATE SET \
                group_id = excluded.group_id, generation = excluded.generation, epoch = excluded.epoch, \
                last_seq = MAX(conversations.last_seq, excluded.last_seq), sequencer_did = excluded.sequencer_did, \
                space_uri = excluded.space_uri, title = excluded.title, \
                unread_count = excluded.unread_count, updated_at_ms = excluded.updated_at_ms",
            &[
                (1, &row.conversation_id),
                (6, &row.sequencer_did),
                (7, space_uri),
                (8, title),
            ],
            &[
                (3, row.generation),
                (4, row.epoch),
                (5, row.last_seq),
                (9, row.unread_count),
                (10, row.updated_at_ms),
            ],
            &[(2, &row.group_id)],
        )
        .map_err(map_wasm_mls_err)
    }

    fn get_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<Option<catbird_mls::storage::ConversationRow>, catbird_mls::MLSError> {
        let rows = self
            .query_text_int_blob(
                "SELECT conversation_id, group_id, generation, epoch, last_seq, sequencer_did, space_uri, title, unread_count, updated_at_ms \
                 FROM conversations WHERE conversation_id = ?1 LIMIT 1",
                &[(1, conversation_id)],
                &[],
                10,
                &[1],
            )
            .map_err(map_wasm_mls_err)?;
        let Some(r) = rows.into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(catbird_mls::storage::ConversationRow {
            conversation_id: r[0].0.clone().unwrap_or_default(),
            group_id: r[1].1.clone().unwrap_or_default(),
            generation: r[2].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            epoch: r[3].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            last_seq: r[4].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            sequencer_did: r[5].0.clone().unwrap_or_default(),
            space_uri: r[6].0.clone(),
            title: r[7].0.clone(),
            unread_count: r[8].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            updated_at_ms: r[9].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        }))
    }

    fn list_conversations(
        &self,
        before_updated_ms: Option<i64>,
        limit: usize,
    ) -> Result<Vec<catbird_mls::storage::ConversationRow>, catbird_mls::MLSError> {
        let bound = before_updated_ms.unwrap_or(i64::MAX);
        let rows = self
            .query_text_int_blob(
                "SELECT conversation_id, group_id, generation, epoch, last_seq, sequencer_did, space_uri, title, unread_count, updated_at_ms \
                 FROM conversations WHERE updated_at_ms < ?1 ORDER BY updated_at_ms DESC, conversation_id ASC LIMIT ?2",
                &[],
                &[(1, bound), (2, limit as i64)],
                10,
                &[1],
            )
            .map_err(map_wasm_mls_err)?;
        Ok(rows
            .into_iter()
            .map(|r| catbird_mls::storage::ConversationRow {
                conversation_id: r[0].0.clone().unwrap_or_default(),
                group_id: r[1].1.clone().unwrap_or_default(),
                generation: r[2].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
                epoch: r[3].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
                last_seq: r[4].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
                sequencer_did: r[5].0.clone().unwrap_or_default(),
                space_uri: r[6].0.clone(),
                title: r[7].0.clone(),
                unread_count: r[8].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
                updated_at_ms: r[9].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            })
            .collect())
    }

    fn delete_conversation(&self, conversation_id: &str) -> Result<(), catbird_mls::MLSError> {
        self.exec_with_text_params(
            "DELETE FROM conversations WHERE conversation_id = ?1",
            &[(1, conversation_id)],
        )
        .map_err(map_wasm_mls_err)
    }

    fn insert_message(
        &self,
        row: &catbird_mls::storage::MessageRow,
    ) -> Result<(), catbird_mls::MLSError> {
        self.exec_with_text_int_blob_params(
            "INSERT OR REPLACE INTO messages \
             (message_id, conversation_id, group_id, epoch, seq, sender_did, sender_device_id, plaintext_json, created_at_ms, is_own) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            &[
                (1, &row.message_id),
                (2, &row.conversation_id),
                (6, &row.sender_did),
                (7, &row.sender_device_id),
                (8, &row.plaintext_json),
            ],
            &[
                (4, row.epoch),
                (5, row.seq),
                (9, row.created_at_ms),
                (10, i64::from(row.is_own)),
            ],
            &[(3, &row.group_id)],
        )
        .map_err(map_wasm_mls_err)
    }

    fn list_messages(
        &self,
        conversation_id: &str,
        before_seq: Option<i64>,
        limit: usize,
    ) -> Result<Vec<catbird_mls::storage::MessageRow>, catbird_mls::MLSError> {
        let bound = before_seq.unwrap_or(i64::MAX);
        let rows = self
            .query_text_int_blob(
                "SELECT message_id, conversation_id, group_id, epoch, seq, sender_did, sender_device_id, plaintext_json, created_at_ms, is_own \
                 FROM messages WHERE conversation_id = ?1 AND seq < ?2 ORDER BY seq DESC LIMIT ?3",
                &[(1, conversation_id)],
                &[(2, bound), (3, limit as i64)],
                10,
                &[2],
            )
            .map_err(map_wasm_mls_err)?;
        Ok(rows.iter().map(|row| message_row(row)).collect())
    }

    fn purge_messages_from_sender(
        &self,
        conversation_id: Option<&str>,
        sender_did: &str,
    ) -> Result<usize, catbird_mls::MLSError> {
        if let Some(cid) = conversation_id {
            self.exec_with_text_params(
                "DELETE FROM messages WHERE conversation_id = ?1 AND sender_did = ?2",
                &[(1, cid), (2, sender_did)],
            )
            .map_err(map_wasm_mls_err)?;
        } else {
            self.exec_with_text_params(
                "DELETE FROM messages WHERE sender_did = ?1",
                &[(1, sender_did)],
            )
            .map_err(map_wasm_mls_err)?;
        }
        Ok(0)
    }

    fn upsert_request(
        &self,
        row: &catbird_mls::storage::RequestRow,
    ) -> Result<(), catbird_mls::MLSError> {
        let first_id = row.first_message_id.as_deref().unwrap_or("");
        self.exec_with_mixed_params(
            "INSERT OR REPLACE INTO requests \
             (request_id, conversation_id, sender_did, recipient_did, consent, first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, NULLIF(?6, ''), ?7, ?8, ?9, ?10)",
            &[
                (1, &row.request_id),
                (2, &row.conversation_id),
                (3, &row.sender_did),
                (4, &row.recipient_did),
                (5, &row.consent),
                (6, first_id),
                (8, &row.payload_json),
            ],
            &[
                (7, i64::from(row.first_message_archived)),
                (9, row.expires_at_ms),
                (10, row.updated_at_ms),
            ],
        )
        .map_err(map_wasm_mls_err)
    }

    fn get_request(
        &self,
        request_id: &str,
    ) -> Result<Option<catbird_mls::storage::RequestRow>, catbird_mls::MLSError> {
        let rows = self
            .query_text(
                "SELECT request_id, conversation_id, sender_did, recipient_did, consent, first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms \
                 FROM requests WHERE request_id = ?1 LIMIT 1",
                &[(1, request_id)],
                10,
            )
            .map_err(map_wasm_mls_err)?;
        let Some(r) = rows.into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(catbird_mls::storage::RequestRow {
            request_id: r[0].clone().unwrap_or_default(),
            conversation_id: r[1].clone().unwrap_or_default(),
            sender_did: r[2].clone().unwrap_or_default(),
            recipient_did: r[3].clone().unwrap_or_default(),
            consent: r[4].clone().unwrap_or_default(),
            first_message_id: r[5].clone(),
            first_message_archived: r[6].as_deref() == Some("1"),
            payload_json: r[7].clone().unwrap_or_default(),
            expires_at_ms: r[8].as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            updated_at_ms: r[9].as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        }))
    }

    fn list_requests(
        &self,
        consent_filter: Option<&str>,
    ) -> Result<Vec<catbird_mls::storage::RequestRow>, catbird_mls::MLSError> {
        let rows = if let Some(filter) = consent_filter {
            match filter {
                "pending" => self.query_text(
                    "SELECT request_id, conversation_id, sender_did, recipient_did, consent, first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms \
                     FROM requests WHERE consent IN ('pending', 'incomingPending', 'outgoingPending', 'incoming_pending', 'outgoing_pending') ORDER BY updated_at_ms DESC, request_id ASC",
                    &[],
                    10,
                ),
                "incomingPending" | "incoming_pending" => self.query_text(
                    "SELECT request_id, conversation_id, sender_did, recipient_did, consent, first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms \
                     FROM requests WHERE consent IN ('incomingPending', 'incoming_pending') ORDER BY updated_at_ms DESC, request_id ASC",
                    &[],
                    10,
                ),
                "outgoingPending" | "outgoing_pending" => self.query_text(
                    "SELECT request_id, conversation_id, sender_did, recipient_did, consent, first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms \
                     FROM requests WHERE consent IN ('outgoingPending', 'outgoing_pending') ORDER BY updated_at_ms DESC, request_id ASC",
                    &[],
                    10,
                ),
                "declined" | "closed" => self.query_text(
                    "SELECT request_id, conversation_id, sender_did, recipient_did, consent, first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms \
                     FROM requests WHERE consent IN ('declined', 'closed') ORDER BY updated_at_ms DESC, request_id ASC",
                    &[],
                    10,
                ),
                _ => self.query_text(
                    "SELECT request_id, conversation_id, sender_did, recipient_did, consent, first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms \
                     FROM requests WHERE consent = ?1 ORDER BY updated_at_ms DESC, request_id ASC",
                    &[(1, filter)],
                    10,
                ),
            }
        } else {
            self.query_text(
                "SELECT request_id, conversation_id, sender_did, recipient_did, consent, first_message_id, first_message_archived, payload_json, expires_at_ms, updated_at_ms \
                 FROM requests ORDER BY updated_at_ms DESC, request_id ASC",
                &[],
                10,
            )
        }
        .map_err(map_wasm_mls_err)?;
        Ok(rows
            .into_iter()
            .map(|r| catbird_mls::storage::RequestRow {
                request_id: r[0].clone().unwrap_or_default(),
                conversation_id: r[1].clone().unwrap_or_default(),
                sender_did: r[2].clone().unwrap_or_default(),
                recipient_did: r[3].clone().unwrap_or_default(),
                consent: r[4].clone().unwrap_or_default(),
                first_message_id: r[5].clone(),
                first_message_archived: r[6].as_deref() == Some("1"),
                payload_json: r[7].clone().unwrap_or_default(),
                expires_at_ms: r[8].as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
                updated_at_ms: r[9].as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            })
            .collect())
    }

    fn upsert_group_metadata(
        &self,
        row: &catbird_mls::storage::GroupMetadataRow,
    ) -> Result<(), catbird_mls::MLSError> {
        let title = row.title.as_deref().unwrap_or("");
        let desc = row.description.as_deref().unwrap_or("");
        let setter = row.avatar_setter_did.as_deref().unwrap_or("");
        let cid = row.avatar_blob_cid.as_deref().unwrap_or("");
        let mime = row.avatar_mime_type.as_deref().unwrap_or("");
        let sym = row.avatar_sym_key.as_deref().unwrap_or(&[]);
        let sha = row.avatar_sha256.as_deref().unwrap_or(&[]);
        self.exec_with_text_int_blob_params(
            "INSERT OR REPLACE INTO group_metadata_cache \
             (conversation_id, metadata_version, epoch, title, description, avatar_setter_did, avatar_blob_cid, avatar_sym_key, avatar_sha256, avatar_mime_type, metadata_json, updated_at_ms) \
             VALUES (?1, ?2, ?3, NULLIF(?4, ''), NULLIF(?5, ''), NULLIF(?6, ''), NULLIF(?7, ''), ?8, ?9, NULLIF(?10, ''), ?11, ?12)",
            &[
                (1, &row.conversation_id),
                (4, title),
                (5, desc),
                (6, setter),
                (7, cid),
                (10, mime),
                (11, &row.metadata_json),
            ],
            &[
                (2, row.metadata_version),
                (3, row.epoch),
                (12, row.updated_at_ms),
            ],
            &[(8, sym), (9, sha)],
        )
        .map_err(map_wasm_mls_err)
    }

    fn get_group_metadata(
        &self,
        conversation_id: &str,
    ) -> Result<Option<catbird_mls::storage::GroupMetadataRow>, catbird_mls::MLSError> {
        let rows = self
            .query_text_int_blob(
                "SELECT conversation_id, metadata_version, epoch, title, description, avatar_setter_did, avatar_blob_cid, avatar_sym_key, avatar_sha256, avatar_mime_type, metadata_json, updated_at_ms \
                 FROM group_metadata_cache WHERE conversation_id = ?1 LIMIT 1",
                &[(1, conversation_id)],
                &[],
                12,
                &[7, 8],
            )
            .map_err(map_wasm_mls_err)?;
        let Some(r) = rows.into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(catbird_mls::storage::GroupMetadataRow {
            conversation_id: r[0].0.clone().unwrap_or_default(),
            metadata_version: r[1].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            epoch: r[2].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            title: r[3].0.clone(),
            description: r[4].0.clone(),
            avatar_setter_did: r[5].0.clone(),
            avatar_blob_cid: r[6].0.clone(),
            avatar_sym_key: r[7].1.clone().filter(|b| !b.is_empty()),
            avatar_sha256: r[8].1.clone().filter(|b| !b.is_empty()),
            avatar_mime_type: r[9].0.clone(),
            metadata_json: r[10].0.clone().unwrap_or_default(),
            updated_at_ms: r[11].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        }))
    }

    fn upsert_mutation_journal(
        &self,
        row: &catbird_mls::storage::MutationJournalRow,
    ) -> Result<(), catbird_mls::MLSError> {
        self.exec_with_mixed_params(
            "INSERT OR REPLACE INTO mutation_journal \
             (journal_id, op_type, epoch_seq, state_json, status, created_at_ms, updated_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                (1, &row.journal_id),
                (2, &row.op_type),
                (4, &row.state_json),
                (5, &row.status),
            ],
            &[
                (3, row.epoch_seq as i64),
                (6, row.created_at_ms),
                (7, row.updated_at_ms),
            ],
        )
        .map_err(map_wasm_mls_err)
    }

    fn list_mutation_journal_pending(
        &self,
    ) -> Result<Vec<catbird_mls::storage::MutationJournalRow>, catbird_mls::MLSError> {
        let rows = self
            .query_text(
                "SELECT journal_id, op_type, epoch_seq, state_json, status, created_at_ms, updated_at_ms \
                 FROM mutation_journal WHERE status != 'done' ORDER BY created_at_ms ASC",
                &[],
                7,
            )
            .map_err(map_wasm_mls_err)?;
        Ok(rows
            .into_iter()
            .map(|r| catbird_mls::storage::MutationJournalRow {
                journal_id: r[0].clone().unwrap_or_default(),
                op_type: r[1].clone().unwrap_or_default(),
                epoch_seq: r[2].as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
                state_json: r[3].clone().unwrap_or_default(),
                status: r[4].clone().unwrap_or_default(),
                created_at_ms: r[5].as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
                updated_at_ms: r[6].as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            })
            .collect())
    }

    fn delete_mutation_journal(&self, journal_id: &str) -> Result<(), catbird_mls::MLSError> {
        self.exec_with_text_params(
            "DELETE FROM mutation_journal WHERE journal_id = ?1",
            &[(1, journal_id)],
        )
        .map_err(map_wasm_mls_err)
    }

    fn upsert_routing_cache(
        &self,
        row: &catbird_mls::storage::RoutingCacheRow,
    ) -> Result<(), catbird_mls::MLSError> {
        let ds_ep = row.home_ds_endpoint.as_deref().unwrap_or("");
        let pds_ep = row.pds_endpoint.as_deref().unwrap_or("");
        self.exec_with_mixed_params(
            "INSERT OR REPLACE INTO routing_cache \
             (did, home_ds_did, home_ds_endpoint, pds_endpoint, resolved_at_ms) \
             VALUES (?1, ?2, NULLIF(?3, ''), NULLIF(?4, ''), ?5)",
            &[
                (1, &row.did),
                (2, &row.home_ds_did),
                (3, ds_ep),
                (4, pds_ep),
            ],
            &[(5, row.resolved_at_ms)],
        )
        .map_err(map_wasm_mls_err)
    }

    fn get_routing_cache(
        &self,
        did: &str,
    ) -> Result<Option<catbird_mls::storage::RoutingCacheRow>, catbird_mls::MLSError> {
        let rows = self
            .query_text(
                "SELECT did, home_ds_did, home_ds_endpoint, pds_endpoint, resolved_at_ms \
                 FROM routing_cache WHERE did = ?1 LIMIT 1",
                &[(1, did)],
                5,
            )
            .map_err(map_wasm_mls_err)?;
        let Some(r) = rows.into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(catbird_mls::storage::RoutingCacheRow {
            did: r[0].clone().unwrap_or_default(),
            home_ds_did: r[1].clone().unwrap_or_default(),
            home_ds_endpoint: r[2].clone(),
            pds_endpoint: r[3].clone(),
            resolved_at_ms: r[4].as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        }))
    }

    fn put_labyrinth_state(
        &self,
        state_key: &str,
        value_bytes: &[u8],
        updated_at_ms: i64,
    ) -> Result<(), catbird_mls::MLSError> {
        self.exec_with_text_int_blob_params(
            "INSERT OR REPLACE INTO labyrinth_state (state_key, value_bytes, updated_at_ms) VALUES (?1, ?2, ?3)",
            &[(1, state_key)],
            &[(3, updated_at_ms)],
            &[(2, value_bytes)],
        )
        .map_err(map_wasm_mls_err)
    }

    fn get_labyrinth_state(
        &self,
        state_key: &str,
    ) -> Result<Option<Vec<u8>>, catbird_mls::MLSError> {
        self.query_blob(
            "SELECT value_bytes FROM labyrinth_state WHERE state_key = ?1 LIMIT 1",
            &[(1, state_key)],
        )
        .map_err(map_wasm_mls_err)
    }

    fn enqueue_labyrinth_item(
        &self,
        row: &catbird_mls::storage::LabyrinthQueueRow,
    ) -> Result<(), catbird_mls::MLSError> {
        self.exec_with_text_int_blob_params(
            "INSERT OR REPLACE INTO labyrinth_queue \
             (item_id, conversation_id, group_id_hex, seq, payload_bytes, created_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                (1, &row.item_id),
                (2, &row.conversation_id),
                (3, &row.group_id_hex),
            ],
            &[(4, row.seq), (6, row.created_at_ms)],
            &[(5, &row.payload_bytes)],
        )
        .map_err(map_wasm_mls_err)
    }

    fn list_labyrinth_queue(
        &self,
        conversation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<catbird_mls::storage::LabyrinthQueueRow>, catbird_mls::MLSError> {
        let rows = if let Some(cid) = conversation_id {
            self.query_text_int_blob(
                "SELECT item_id, conversation_id, group_id_hex, seq, payload_bytes, created_at_ms \
                 FROM labyrinth_queue WHERE conversation_id = ?1 ORDER BY created_at_ms ASC LIMIT ?2",
                &[(1, cid)],
                &[(2, limit as i64)],
                6,
                &[4],
            )
        } else {
            self.query_text_int_blob(
                "SELECT item_id, conversation_id, group_id_hex, seq, payload_bytes, created_at_ms \
                 FROM labyrinth_queue ORDER BY created_at_ms ASC LIMIT ?1",
                &[],
                &[(1, limit as i64)],
                6,
                &[4],
            )
        }
        .map_err(map_wasm_mls_err)?;
        Ok(rows
            .into_iter()
            .map(|r| catbird_mls::storage::LabyrinthQueueRow {
                item_id: r[0].0.clone().unwrap_or_default(),
                conversation_id: r[1].0.clone().unwrap_or_default(),
                group_id_hex: r[2].0.clone().unwrap_or_default(),
                seq: r[3].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
                payload_bytes: r[4].1.clone().unwrap_or_default(),
                created_at_ms: r[5].0.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            })
            .collect())
    }

    fn dequeue_labyrinth_item(&self, item_id: &str) -> Result<(), catbird_mls::MLSError> {
        self.exec_with_text_params(
            "DELETE FROM labyrinth_queue WHERE item_id = ?1",
            &[(1, item_id)],
        )
        .map_err(map_wasm_mls_err)
    }
}
