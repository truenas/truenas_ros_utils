//! Internal RAII wrappers for transactions and cursors, and the `MDB_val`
//! helpers.
//!
//! # Safety
//!
//! This module calls `liblmdb`, so it lifts the workspace's
//! `deny(unsafe_code)`. Every transaction and cursor this crate creates is
//! wrapped here, so none can be leaked or finished twice on any path,
//! including early return through `?` and unwinding.
#![allow(unsafe_code)]

use crate::env::Env;
use crate::error::{check, Result};
use crate::ffi::*;
use std::os::raw::c_void;
use std::ptr;

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

/// A transaction, aborted on drop unless committed.
pub(crate) struct TxnGuard {
    pub(crate) txn: *mut MDB_txn,
    committed: bool,
}

impl TxnGuard {
    pub(crate) fn begin(env: &Env, read_only: bool) -> Result<TxnGuard> {
        let flags = if read_only { MDB_RDONLY } else { 0 };
        let mut txn: *mut MDB_txn = ptr::null_mut();
        // SAFETY: a valid environment, no parent, out-param for the new
        // transaction.
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
