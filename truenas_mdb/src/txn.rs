// SPDX-License-Identifier: MIT
//! Internal RAII wrappers for transactions and cursors, and the `MDB_val`
//! helpers.
//!
//! # One transaction per thread per environment
//!
//! `lmdb.h`: "A thread can only use one transaction at a time". Attempting a
//! second one has no safe outcome:
//!
//! - A read transaction needs the thread's reader lock-table slot, which the
//!   first one holds, and fails with `MDB_BAD_RSLOT`.
//! - A write transaction blocks on the environment's writer mutex, which is
//!   process-shared and not recursive, so the thread waits on itself. It also
//!   needs `MDB_env`'s single preallocated write transaction, which the first
//!   one is using.
//!
//! [`TxnGuard::begin`] therefore refuses up front with `EDEADLK` when this
//! thread already holds a transaction on this environment. Different
//! environments have separate reader tables and writer mutexes, so the slot is
//! per environment, not global.
//!
//! Callers reach this through the two APIs that hold a transaction open across
//! caller code: the closures given to `Db::scan`/`Db::with_value`, and a live
//! `Db::iter`. Both must finish before the thread touches that environment
//! again.
//!
//! # Safety
//!
//! This module calls `liblmdb`, so it lifts the workspace's
//! `deny(unsafe_code)`. Every transaction and cursor this crate creates is
//! wrapped here, so none can be leaked or finished twice on any path,
//! including early return through `?` and unwinding. A transaction never
//! crosses a thread: guards hold raw pointers, so they are neither `Send` nor
//! `Sync`, and the only guard a caller can hold is inside a `Db::iter`.
#![allow(unsafe_code)]

use crate::env::Env;
use crate::error::{Error, Result, check};
use crate::ffi::*;
use std::cell::RefCell;
use std::os::raw::c_void;
use std::ptr;

thread_local! {
    /// Environments this thread currently holds a transaction on, by handle
    /// address. Tiny and short-lived: a linear scan beats hashing.
    static ACTIVE: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// Claim this thread's transaction slot for `env`, or fail if it is taken.
fn claim(env: usize) -> Result<()> {
    ACTIVE.with_borrow_mut(|active| {
        if active.contains(&env) {
            // Resource deadlock avoided: proceeding would either self-deadlock
            // on the writer mutex or fail with MDB_BAD_RSLOT.
            return Err(Error::Os(libc::EDEADLK));
        }
        active.push(env);
        Ok(())
    })
}

/// Release this thread's transaction slot for `env`.
///
/// Sound only because [`TxnGuard`] holds a raw pointer and is therefore
/// neither `Send` nor `Sync`: a guard is always dropped on the thread that
/// claimed the slot, so this never touches another thread's list.
fn release(env: usize) {
    ACTIVE.with_borrow_mut(|active| {
        if let Some(i) = active.iter().rposition(|e| *e == env) {
            active.swap_remove(i);
        }
    });
}

/// Borrow `bytes` as an `MDB_val` for the duration of a call. LMDB treats
/// input values as read-only despite the non-const pointer.
pub(crate) fn val_of(bytes: &[u8]) -> MDB_val {
    MDB_val {
        mv_size: bytes.len(),
        mv_data: bytes.as_ptr().cast::<c_void>().cast_mut(),
    }
}

/// An `MDB_val` for LMDB to fill in.
pub(crate) fn empty_val() -> MDB_val {
    MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    }
}

/// View an LMDB-filled `MDB_val` as a slice.
///
/// # Safety
///
/// `val` must have been filled by a successful LMDB read whose transaction is
/// still live: the pointer is into that transaction's mmap.
pub(crate) unsafe fn as_slice<'t>(val: &MDB_val) -> &'t [u8] {
    if val.mv_size == 0 {
        // A stored value may be empty, and LMDB may report it with a null
        // pointer, which `from_raw_parts` does not accept.
        return &[];
    }
    // SAFETY: the caller guarantees a live region of `mv_size` bytes.
    unsafe { std::slice::from_raw_parts(val.mv_data.cast::<u8>(), val.mv_size) }
}

/// A transaction, aborted on drop unless committed, holding this thread's
/// transaction slot for its environment for as long as it lives.
pub(crate) struct TxnGuard {
    pub(crate) txn: *mut MDB_txn,
    /// The environment whose slot this guard holds, for [`release`].
    env: usize,
    committed: bool,
}

impl TxnGuard {
    pub(crate) fn begin(env: &Env, read_only: bool) -> Result<TxnGuard> {
        let handle = env.ptr() as usize;
        claim(handle)?;
        let flags = if read_only { MDB_RDONLY } else { 0 };
        let mut txn: *mut MDB_txn = ptr::null_mut();
        // SAFETY: a valid environment, no parent, out-param for the new
        // transaction.
        let begun = check(unsafe {
            mdb_txn_begin(env.ptr(), ptr::null_mut(), flags, &mut txn)
        });
        if let Err(e) = begun {
            // No guard exists to drop, so hand the slot back here.
            release(handle);
            return Err(e);
        }
        Ok(TxnGuard {
            txn,
            env: handle,
            committed: false,
        })
    }

    /// Commit, consuming the guard.
    ///
    /// `mdb_txn_commit` frees the handle whatever it returns, so the flag is
    /// set before the call: the transaction must not be aborted afterwards
    /// even on failure.
    pub(crate) fn commit(mut self) -> Result<()> {
        self.committed = true;
        // SAFETY: a live transaction, finished exactly once here.
        check(unsafe { mdb_txn_commit(self.txn) })
    }
}

impl Drop for TxnGuard {
    fn drop(&mut self) {
        if !self.committed {
            // SAFETY: a live transaction, neither committed nor aborted;
            // abort finishes it exactly once.
            unsafe { mdb_txn_abort(self.txn) };
        }
        // Runs on both paths, since `commit` consumes the guard into a drop.
        release(self.env);
    }
}

/// A cursor, closed on drop. Must be declared before the [`TxnGuard`] it was
/// opened in, so that it drops first.
pub(crate) struct CursorGuard {
    pub(crate) cursor: *mut MDB_cursor,
}

impl CursorGuard {
    pub(crate) fn open(txn: &TxnGuard, dbi: MDB_dbi) -> Result<CursorGuard> {
        let mut cursor: *mut MDB_cursor = ptr::null_mut();
        // SAFETY: a live transaction and a valid handle, plus an out-param.
        check(unsafe { mdb_cursor_open(txn.txn, dbi, &mut cursor) })?;
        Ok(CursorGuard { cursor })
    }

    /// Move the cursor and return the pair it landed on, or `None` at the end.
    ///
    /// # Safety
    ///
    /// The returned slices point into the transaction's mmap and are valid
    /// only while it lives; `'t` must not outlive the [`TxnGuard`] this cursor
    /// belongs to. `start` is read only when `op` positions by key.
    pub(crate) unsafe fn step<'t>(
        &self,
        op: std::os::raw::c_uint,
        start: Option<&[u8]>,
    ) -> Result<Option<(&'t [u8], &'t [u8])>> {
        let mut k = match start {
            Some(key) => val_of(key),
            None => empty_val(),
        };
        let mut d = empty_val();
        // SAFETY: a live cursor; `k` either borrows `start` for the call or is
        // an out-param, and `d` is an out-param. Both are filled with pointers
        // into the mmap on success.
        let rc = unsafe { mdb_cursor_get(self.cursor, &mut k, &mut d, op) };
        match rc {
            MDB_SUCCESS => {
                // SAFETY: the call succeeded, so both describe live mmap
                // regions; the caller bounds `'t` by the transaction.
                Ok(Some(unsafe { (as_slice(&k), as_slice(&d)) }))
            }
            MDB_NOTFOUND => Ok(None),
            _ => Err(crate::Error::from_raw(rc)),
        }
    }
}

impl Drop for CursorGuard {
    fn drop(&mut self) {
        // SAFETY: a live cursor, closed exactly once, before its transaction.
        unsafe { mdb_cursor_close(self.cursor) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EnvOptions;

    #[test]
    fn a_second_transaction_on_one_thread_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let env =
            Env::open_with(dir.path().join("env"), &EnvOptions::default())
                .unwrap();

        // All four nestings are refused, including write-inside-write, which
        // the public API cannot reach but which would self-deadlock on the
        // writer mutex if it ever could.
        for held_ro in [true, false] {
            for want_ro in [true, false] {
                let held = TxnGuard::begin(&env, held_ro).unwrap();
                // `.err()` rather than `unwrap_err()`: the guard is internal
                // and deliberately has no Debug impl.
                assert_eq!(
                    TxnGuard::begin(&env, want_ro).err(),
                    Some(Error::Os(libc::EDEADLK)),
                    "held read_only={held_ro}, wanted read_only={want_ro}"
                );
                drop(held);
                // Dropping the first hands the slot back.
                TxnGuard::begin(&env, want_ro).unwrap();
            }
        }
    }

    #[test]
    fn committing_releases_the_slot() {
        let dir = tempfile::tempdir().unwrap();
        let env =
            Env::open_with(dir.path().join("env"), &EnvOptions::default())
                .unwrap();

        // `commit` consumes the guard into a drop, which is what frees the
        // slot; a leak here would wedge the thread after one write.
        for _ in 0..4 {
            TxnGuard::begin(&env, false).unwrap().commit().unwrap();
        }
        TxnGuard::begin(&env, true).unwrap();
    }

    #[test]
    fn the_slot_is_per_environment() {
        let dir = tempfile::tempdir().unwrap();
        let a = Env::open_with(dir.path().join("a"), &EnvOptions::default())
            .unwrap();
        let b = Env::open_with(dir.path().join("b"), &EnvOptions::default())
            .unwrap();

        // Separate reader tables and writer mutexes, so holding one says
        // nothing about the other.
        let _held = TxnGuard::begin(&a, false).unwrap();
        let _other = TxnGuard::begin(&b, false).unwrap();
        assert_eq!(
            TxnGuard::begin(&a, true).err(),
            Some(Error::Os(libc::EDEADLK))
        );
    }
}
