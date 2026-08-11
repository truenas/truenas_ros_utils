//! Hand-written declarations for the parts of `liblmdb` this crate uses.
//!
//! Bound directly rather than generated: no `bindgen`, so no `libclang` at
//! build time and nothing to re-check after a toolchain bump. Everything here
//! is a plain declaration — the `unsafe` calls, and their `// SAFETY:` notes,
//! live in the safe wrappers in [`env`](crate::env) and [`db`](crate::db).
//!
//! Verified against `/usr/include/lmdb.h` from Debian's `liblmdb-dev` 0.9.31.
//! The values are stable across the 0.9 series (the vendored 0.9.35 in
//! `truenas_jsonrpc` agrees), but they are ABI, so any change here must be
//! checked against the header rather than remembered.
#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_uint, c_void};

// Opaque C handles — only ever held behind a pointer.
pub enum MDB_env {}
pub enum MDB_txn {}
pub enum MDB_cursor {}

/// A database handle: a small integer, valid within its environment.
pub type MDB_dbi = c_uint;

/// `lmdb.h:178` — `typedef mode_t mdb_mode_t` on Unix.
pub type mdb_mode_t = libc::mode_t;

/// A key or value: a length and a pointer. On the way in it borrows the
/// caller's buffer; on the way out it points into the environment's mmap and
/// is valid only until the transaction ends.
#[repr(C)]
pub struct MDB_val {
    pub mv_size: usize, // size_t
    pub mv_data: *mut c_void,
}

// --- mdb_env_open flags (lmdb.h:285-305) ---------------------------------

/// Don't fsync after commit; a crash can lose the most recent transactions.
pub const MDB_NOSYNC: c_uint = 0x10000;
/// Flush data but not the meta page on commit.
pub const MDB_NOMETASYNC: c_uint = 0x40000;
/// Don't use a per-thread reader slot — a read transaction is tied to the
/// transaction object instead of the thread that created it.
pub const MDB_NOTLS: c_uint = 0x200000;
/// Turn off readahead. Helps when the database is larger than RAM.
pub const MDB_NORDAHEAD: c_uint = 0x800000;

// --- mdb_dbi_open flags (lmdb.h:325) -------------------------------------

/// Create the named database if it does not already exist.
pub const MDB_CREATE: c_uint = 0x40000;

// --- mdb_txn_begin flags (lmdb.h:291) ------------------------------------

/// Begin a read-only transaction.
pub const MDB_RDONLY: c_uint = 0x20000;

// --- mdb_put flags (lmdb.h:332) ------------------------------------------

/// Fail with `MDB_KEYEXIST` rather than overwriting an existing key.
pub const MDB_NOOVERWRITE: c_uint = 0x10;

// --- return codes (lmdb.h:401-450) ---------------------------------------
// Anything outside this range and above zero is a system errno LMDB passed
// through from a syscall.

pub const MDB_SUCCESS: c_int = 0;
pub const MDB_KEYEXIST: c_int = -30799;
pub const MDB_NOTFOUND: c_int = -30798;
pub const MDB_PAGE_NOTFOUND: c_int = -30797;
pub const MDB_CORRUPTED: c_int = -30796;
pub const MDB_PANIC: c_int = -30795;
pub const MDB_VERSION_MISMATCH: c_int = -30794;
pub const MDB_INVALID: c_int = -30793;
pub const MDB_MAP_FULL: c_int = -30792;
pub const MDB_DBS_FULL: c_int = -30791;
pub const MDB_READERS_FULL: c_int = -30790;
pub const MDB_TLS_FULL: c_int = -30789;
pub const MDB_TXN_FULL: c_int = -30788;
pub const MDB_CURSOR_FULL: c_int = -30787;
pub const MDB_PAGE_FULL: c_int = -30786;
pub const MDB_MAP_RESIZED: c_int = -30785;
pub const MDB_INCOMPATIBLE: c_int = -30784;
pub const MDB_BAD_RSLOT: c_int = -30783;
pub const MDB_BAD_TXN: c_int = -30782;
pub const MDB_BAD_VALSIZE: c_int = -30781;
pub const MDB_BAD_DBI: c_int = -30780;

// --- MDB_cursor_op ordinals (lmdb.h's enum, in declaration order) --------

/// Position at the first key/value pair.
pub const MDB_FIRST: c_uint = 0;
/// Position at the next pair.
pub const MDB_NEXT: c_uint = 8;

extern "C" {
    pub fn mdb_version(
        major: *mut c_int,
        minor: *mut c_int,
        patch: *mut c_int,
    ) -> *const c_char;

    /// Used only by the test that pins [`MdbCode::message`] to the linked
    /// library — the crate renders errors from its own table so that nothing
    /// on the normal path has to cross the FFI boundary.
    ///
    /// [`MdbCode::message`]: crate::MdbCode::message
    #[allow(dead_code)]
    pub fn mdb_strerror(err: c_int) -> *const c_char;

    pub fn mdb_env_create(env: *mut *mut MDB_env) -> c_int;
    pub fn mdb_env_set_mapsize(env: *mut MDB_env, size: usize) -> c_int;
    pub fn mdb_env_set_maxdbs(env: *mut MDB_env, dbs: MDB_dbi) -> c_int;
    pub fn mdb_env_set_maxreaders(env: *mut MDB_env, readers: c_uint) -> c_int;
    pub fn mdb_env_open(
        env: *mut MDB_env,
        path: *const c_char,
        flags: c_uint,
        mode: mdb_mode_t,
    ) -> c_int;
    pub fn mdb_env_sync(env: *mut MDB_env, force: c_int) -> c_int;
    pub fn mdb_env_close(env: *mut MDB_env);

    pub fn mdb_txn_begin(
        env: *mut MDB_env,
        parent: *mut MDB_txn,
        flags: c_uint,
        txn: *mut *mut MDB_txn,
    ) -> c_int;
    /// Frees the handle whatever it returns — the transaction must not be
    /// touched again, not even to abort it.
    pub fn mdb_txn_commit(txn: *mut MDB_txn) -> c_int;
    pub fn mdb_txn_abort(txn: *mut MDB_txn);

    pub fn mdb_dbi_open(
        txn: *mut MDB_txn,
        name: *const c_char,
        flags: c_uint,
        dbi: *mut MDB_dbi,
    ) -> c_int;
    pub fn mdb_drop(txn: *mut MDB_txn, dbi: MDB_dbi, del: c_int) -> c_int;

    pub fn mdb_get(
        txn: *mut MDB_txn,
        dbi: MDB_dbi,
        key: *mut MDB_val,
        data: *mut MDB_val,
    ) -> c_int;
    pub fn mdb_put(
        txn: *mut MDB_txn,
        dbi: MDB_dbi,
        key: *mut MDB_val,
        data: *mut MDB_val,
        flags: c_uint,
    ) -> c_int;
    pub fn mdb_del(
        txn: *mut MDB_txn,
        dbi: MDB_dbi,
        key: *mut MDB_val,
        data: *mut MDB_val,
    ) -> c_int;

    pub fn mdb_cursor_open(
        txn: *mut MDB_txn,
        dbi: MDB_dbi,
        cursor: *mut *mut MDB_cursor,
    ) -> c_int;
    pub fn mdb_cursor_get(
        cursor: *mut MDB_cursor,
        key: *mut MDB_val,
        data: *mut MDB_val,
        op: c_uint,
    ) -> c_int;
    pub fn mdb_cursor_close(cursor: *mut MDB_cursor);
}
