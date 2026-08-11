//! [`Db`] — one database inside an [`Env`], and the operations on it.
//!
//! # Safety model
//!
//! This module calls into `liblmdb`, so it lifts the workspace's
//! `deny(unsafe_code)`; every block carries a `// SAFETY:` note. The invariants
//! it upholds:
//!
//! - Every transaction is wrapped in [`TxnGuard`] — `commit` consumes it, and
//!   `Drop` aborts anything not committed — and every cursor in
//!   [`CursorGuard`], which closes on `Drop` and is declared after its
//!   transaction so it drops first. No transaction or cursor outlives its
//!   guard, on any path including `?`.
//! - `mdb_get` and the cursor return pointers **into the environment's mmap**,
//!   valid only until the transaction ends. Every one of them is either copied
//!   out before the guard drops or handed to a callback that runs inside the
//!   transaction. None escapes.
#![allow(unsafe_code)]

use crate::env::Env;
use crate::error::{check, Error, MdbCode, Result};
use crate::ffi::*;
use std::ffi::CString;
use std::ops::ControlFlow;
use std::os::raw::{c_char, c_uint, c_void};
use std::ptr;

bitflags::bitflags! {
    /// Flags for [`Db::put`].
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct PutFlags: u32 {
        /// Don't overwrite an existing key: fail with
        /// [`MdbCode::KeyExist`](crate::MdbCode::KeyExist) instead.
        const NO_OVERWRITE = MDB_NOOVERWRITE;
    }
}

/// Borrow `bytes` as an `MDB_val` for the duration of a call. LMDB treats
/// input values as read-only despite the non-const pointer.
fn val_of(bytes: &[u8]) -> MDB_val {
    MDB_val {
        mv_size: bytes.len(),
        mv_data: bytes.as_ptr().cast::<c_void>().cast_mut(),
    }
}

/// An `MDB_val` for LMDB to fill in.
fn empty_val() -> MDB_val {
    MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    }
}

/// View an LMDB-filled `MDB_val` as a slice.
///
/// # Safety
///
/// `val` must have been filled by a successful LMDB read, and the transaction
/// that produced it must still be live — the pointer is into its mmap.
unsafe fn as_slice<'t>(val: &MDB_val) -> &'t [u8] {
    if val.mv_size == 0 {
        // A stored value may legitimately be empty, and LMDB is free to hand
        // back a null pointer for it — which `from_raw_parts` will not accept.
        return &[];
    }
    // SAFETY: the caller guarantees a live region of `mv_size` bytes.
    unsafe { std::slice::from_raw_parts(val.mv_data.cast::<u8>(), val.mv_size) }
}

/// A transaction, aborted on drop unless it was committed.
struct TxnGuard {
    txn: *mut MDB_txn,
    committed: bool,
}

impl TxnGuard {
    fn begin(env: &Env, read_only: bool) -> Result<TxnGuard> {
        let flags = if read_only { MDB_RDONLY } else { 0 };
        let mut txn: *mut MDB_txn = ptr::null_mut();
        // SAFETY: a valid environment, no parent, and an out-param for the
        // new transaction.
        check(unsafe {
            mdb_txn_begin(env.ptr(), ptr::null_mut(), flags, &mut txn)
        })?;
        Ok(TxnGuard {
            txn,
            committed: false,
        })
    }

    /// Commit, consuming the guard.
    ///
    /// `mdb_txn_commit` frees the handle whatever it returns, so the flag is
    /// set *before* the call: the transaction must not be aborted afterwards
    /// even on failure. (`truenas_zfsrewrited`'s `lmdb_utils.c:332` does abort
    /// there, which is a use-after-free; consuming `self` here makes that
    /// unwritable.)
    fn commit(mut self) -> Result<()> {
        self.committed = true;
        // SAFETY: a live transaction, finished exactly once here.
        check(unsafe { mdb_txn_commit(self.txn) })
    }
}

impl Drop for TxnGuard {
    fn drop(&mut self) {
        if !self.committed {
            // SAFETY: a live transaction that was neither committed nor
            // aborted; abort finishes it exactly once.
            unsafe { mdb_txn_abort(self.txn) };
        }
    }
}

/// A cursor, closed on drop.
struct CursorGuard {
    cursor: *mut MDB_cursor,
}

impl CursorGuard {
    fn open(txn: &TxnGuard, dbi: MDB_dbi) -> Result<CursorGuard> {
        let mut cursor: *mut MDB_cursor = ptr::null_mut();
        // SAFETY: a live transaction and a valid handle, plus an out-param.
        check(unsafe { mdb_cursor_open(txn.txn, dbi, &mut cursor) })?;
        Ok(CursorGuard { cursor })
    }
}

impl Drop for CursorGuard {
    fn drop(&mut self) {
        // SAFETY: a live cursor, closed exactly once. Declared after its
        // `TxnGuard`, so it drops before the transaction it belongs to.
        unsafe { mdb_cursor_close(self.cursor) };
    }
}

/// Open a database handle inside its own transaction and commit it.
///
/// The handle is private to the transaction until it commits — aborting closes
/// it again (`mdb_txn_end` applies `MDB_END_UPDATE` only on the commit path) —
/// so this must commit even when the transaction is read-only.
fn open_dbi(
    env: &Env,
    name: *const c_char,
    flags: c_uint,
    read_only: bool,
) -> Result<MDB_dbi> {
    let txn = TxnGuard::begin(env, read_only)?;
    let mut dbi: MDB_dbi = 0;
    // SAFETY: a live transaction, a valid C string (or null for the main
    // database), and an out-param for the handle.
    check(unsafe { mdb_dbi_open(txn.txn, name, flags, &mut dbi) })?;
    txn.commit()?;
    Ok(dbi)
}

/// One database inside an [`Env`]: either a named one or the unnamed main
/// database.
///
/// Every operation runs in its own transaction, begun and finished inside the
/// call, so a `Db` is cheap to share and there is nothing to commit by hand.
/// The cost is that operations cannot be grouped: two `put`s are two
/// transactions, not one atomic change.
///
/// Cloning is cheap (it shares the environment) and `Db` is `Send + Sync`, so
/// one can be handed to as many threads as you like — LMDB serializes writers
/// itself, and a `put` blocks while another thread's `put` is in flight.
#[derive(Clone)]
pub struct Db {
    env: Env,
    dbi: MDB_dbi,
}

impl Db {
    /// Open a database in `env`.
    ///
    /// `name` is `None` for the environment's unnamed main database, or
    /// `Some(name)` for one of the named databases that
    /// [`EnvOptions::max_dbs`](crate::EnvOptions::max_dbs) budgets for. With
    /// `create` set, a named database that does not exist yet is created;
    /// without it, opening a missing one fails with
    /// [`MdbCode::NotFound`](crate::MdbCode::NotFound).
    ///
    /// Opening an existing database takes no writer lock: the handle is looked
    /// up in a read-only transaction first, and only a genuine creation
    /// escalates to a write transaction. An environment has exactly one
    /// writer, so that distinction matters under load.
    pub fn open(env: &Env, name: Option<&str>, create: bool) -> Result<Db> {
        let cname = name
            .map(CString::new)
            .transpose()
            .map_err(|_| Error::Os(libc::EINVAL))?;
        let name_ptr = cname.as_ref().map_or(ptr::null(), |c| c.as_ptr());

        // `lmdb.h`: mdb_dbi_open "must not be called from multiple concurrent
        // transactions in the same process". One lock per environment, so
        // opening a database in one does not serialize against another.
        let _dbi_guard = env.lock_dbi();

        let dbi = match open_dbi(env, name_ptr, 0, true) {
            Ok(dbi) => dbi,
            Err(Error::Mdb(MdbCode::NotFound)) if create => {
                open_dbi(env, name_ptr, MDB_CREATE, false)?
            }
            Err(e) => return Err(e),
        };
        Ok(Db {
            env: env.clone(),
            dbi,
        })
    }

    /// The environment this database lives in.
    pub fn env(&self) -> &Env {
        &self.env
    }

    /// Fetch `key`, or `None` if it is not present.
    ///
    /// The value is copied out of the mmap before the transaction ends, so
    /// this allocates. [`Db::get_into`] reuses a buffer instead, and
    /// [`Db::traverse`] avoids the copy altogether.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let txn = TxnGuard::begin(&self.env, true)?;
        // Copied here, while `txn` is still live — the slice points into the
        // mmap and dies with the transaction.
        Ok(self.raw_get(&txn, key)?.map(<[u8]>::to_vec))
    }

    /// Fetch `key` into `out`, replacing its contents, and report whether the
    /// key was present. `out` is left empty on a miss.
    ///
    /// The allocation-free `get`: a caller looping over many keys can hand the
    /// same `Vec` back each time and reuse its capacity.
    pub fn get_into(&self, key: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        out.clear();
        let txn = TxnGuard::begin(&self.env, true)?;
        match self.raw_get(&txn, key)? {
            Some(value) => {
                out.extend_from_slice(value);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Whether `key` is present.
    pub fn contains_key(&self, key: &[u8]) -> Result<bool> {
        let txn = TxnGuard::begin(&self.env, true)?;
        Ok(self.raw_get(&txn, key)?.is_some())
    }

    /// Store `value` under `key`, overwriting any previous value unless
    /// [`PutFlags::NO_OVERWRITE`] is set — in which case an existing key fails
    /// with [`MdbCode::KeyExist`](crate::MdbCode::KeyExist).
    ///
    /// The value is stored byte for byte: this crate adds no header, envelope,
    /// or encoding of its own, so another process reading the same database
    /// sees exactly these bytes.
    pub fn put(&self, key: &[u8], value: &[u8], flags: PutFlags) -> Result<()> {
        let txn = TxnGuard::begin(&self.env, false)?;
        let mut k = val_of(key);
        let mut d = val_of(value);
        // SAFETY: a live write transaction and a valid handle; `k` and `d`
        // borrow the caller's buffers, which outlive the call.
        check(unsafe {
            mdb_put(txn.txn, self.dbi, &mut k, &mut d, flags.bits())
        })?;
        txn.commit()
    }

    /// Remove `key`, reporting whether it was there.
    pub fn del(&self, key: &[u8]) -> Result<bool> {
        let txn = TxnGuard::begin(&self.env, false)?;
        let mut k = val_of(key);
        // SAFETY: a live write transaction and a valid handle; `k` borrows the
        // caller's buffer, and a null data pointer means "delete by key".
        let rc = unsafe { mdb_del(txn.txn, self.dbi, &mut k, ptr::null_mut()) };
        let existed = match rc {
            MDB_SUCCESS => true,
            MDB_NOTFOUND => false,
            _ => return Err(Error::from_raw(rc)),
        };
        txn.commit()?;
        Ok(existed)
    }

    /// Remove every entry, keeping the database itself.
    pub fn clear(&self) -> Result<()> {
        let txn = TxnGuard::begin(&self.env, false)?;
        // SAFETY: a live write transaction and a valid handle; `del = 0`
        // empties the database and keeps the handle open.
        check(unsafe { mdb_drop(txn.txn, self.dbi, 0) })?;
        txn.commit()
    }

    /// Visit every entry in key order, calling `f(key, value)`.
    ///
    /// Return [`ControlFlow::Break`] to stop early with a value; `Ok(None)`
    /// means every entry was visited. The two slices borrow **straight out of
    /// the environment's mmap** and are valid for the duration of the call, so
    /// a scan copies nothing — but they cannot be kept, and `f` must not touch
    /// this database (it is inside the read transaction).
    ///
    /// ```no_run
    /// # use std::ops::ControlFlow;
    /// # use truenas_mdb::{Db, Env, EnvOptions};
    /// # let env = Env::open("/var/db/x".as_ref(), &EnvOptions::default())?;
    /// # let db = Db::open(&env, Some("state"), true)?;
    /// // Count entries whose key starts with a prefix, without copying.
    /// let mut n = 0usize;
    /// db.traverse(|key, _value| {
    ///     if key.starts_with(b"job@") {
    ///         n += 1;
    ///     }
    ///     ControlFlow::<()>::Continue(())
    /// })?;
    /// # Ok::<(), truenas_mdb::Error>(())
    /// ```
    pub fn traverse<B>(
        &self,
        mut f: impl FnMut(&[u8], &[u8]) -> ControlFlow<B>,
    ) -> Result<Option<B>> {
        let txn = TxnGuard::begin(&self.env, true)?;
        let cursor = CursorGuard::open(&txn, self.dbi)?;
        let mut op = MDB_FIRST;
        loop {
            let mut k = empty_val();
            let mut d = empty_val();
            // SAFETY: a live cursor, and two out-params LMDB fills with
            // pointers into the mmap.
            let rc =
                unsafe { mdb_cursor_get(cursor.cursor, &mut k, &mut d, op) };
            match rc {
                MDB_SUCCESS => {}
                MDB_NOTFOUND => break, // walked off the end
                _ => return Err(Error::from_raw(rc)),
            }
            op = MDB_NEXT;
            // SAFETY: the call succeeded, so both vals describe live regions
            // of the mmap; `txn` is still open, and neither slice outlives
            // this iteration.
            let (key, value) = unsafe { (as_slice(&k), as_slice(&d)) };
            if let ControlFlow::Break(b) = f(key, value) {
                return Ok(Some(b));
            }
        }
        Ok(None)
    }

    /// `mdb_get` into the transaction's mmap. The slice lives only as long as
    /// `txn`, which is what keeps every caller honest about copying.
    fn raw_get<'t>(
        &self,
        txn: &'t TxnGuard,
        key: &[u8],
    ) -> Result<Option<&'t [u8]>> {
        let mut k = val_of(key);
        let mut d = empty_val();
        // SAFETY: a live transaction and a valid handle; `k` borrows the
        // caller's buffer, and `d` is an out-param LMDB fills with a pointer
        // into the mmap, live for `'t`.
        let rc = unsafe { mdb_get(txn.txn, self.dbi, &mut k, &mut d) };
        match rc {
            // SAFETY: the call succeeded, so `d` describes a live region of
            // the mmap, valid for as long as `txn` — that is, for `'t`.
            MDB_SUCCESS => Ok(Some(unsafe { as_slice(&d) })),
            MDB_NOTFOUND => Ok(None),
            _ => Err(Error::from_raw(rc)),
        }
    }
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The dbi is an environment-local integer; the path is what identifies
        // this database to a reader of the log.
        f.debug_struct("Db")
            .field("env", &self.env.path())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EnvOptions;

    fn scratch() -> (tempfile::TempDir, Env) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::open(
            &dir.path().join("env"),
            &EnvOptions {
                map_size: 1 << 20,
                max_dbs: 4,
                ..Default::default()
            },
        )
        .unwrap();
        (dir, env)
    }

    #[test]
    fn a_name_with_an_interior_nul_is_rejected_before_lmdb() {
        let (_dir, env) = scratch();
        assert_eq!(
            Db::open(&env, Some("sta\0te"), true).unwrap_err(),
            Error::Os(libc::EINVAL)
        );
    }

    #[test]
    fn opening_a_missing_database_without_create_reports_not_found() {
        let (_dir, env) = scratch();
        assert_eq!(
            Db::open(&env, Some("absent"), false).unwrap_err(),
            Error::Mdb(MdbCode::NotFound)
        );
        // ...and with `create` it appears, after which the read-only lookup
        // path finds it.
        Db::open(&env, Some("absent"), true).unwrap();
        Db::open(&env, Some("absent"), false).unwrap();
    }

    #[test]
    fn the_main_database_needs_no_name_and_always_exists() {
        let (_dir, env) = scratch();
        let db = Db::open(&env, None, false).unwrap();
        db.put(b"k", b"v", PutFlags::empty()).unwrap();
        assert_eq!(db.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
    }
}
