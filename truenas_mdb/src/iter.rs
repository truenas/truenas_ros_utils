//! [`Iter`] — an owning iterator over a database.
//!
//! # Safety
//!
//! The cursor's slices point into the mmap of the transaction held in this
//! struct, so they stay valid for the whole iteration; each is copied before
//! being yielded, so none escapes. Field order matters: `cursor` is declared
//! before `txn`, which is declared before `db`, so they drop in that order —
//! a cursor must close before its transaction, and both before the
//! environment can close.
#![allow(unsafe_code)]

use crate::db::Db;
use crate::error::Result;
use crate::ffi::{MDB_dbi, MDB_FIRST, MDB_NEXT, MDB_SET_RANGE};
use crate::txn::{CursorGuard, TxnGuard};

/// An iterator over a database's entries in key order, yielding owned
/// `(key, value)` pairs.
///
/// Created by [`Db::iter`], [`Db::iter_from`], or [`Db::iter_prefix`]. It
/// holds a read transaction open for its lifetime, so it iterates a consistent
/// snapshot but occupies a reader slot and prevents superseded pages from
/// being reused; drop it promptly.
///
/// Iteration stops after the first error, and after a yielded `Err` the
/// iterator is exhausted.
pub struct Iter {
    cursor: CursorGuard,
    txn: TxnGuard,
    /// Keeps the environment open for as long as the transaction lives.
    db: Db,
    /// Key to seek to on the first step; `None` starts at the beginning.
    start: Option<Box<[u8]>>,
    /// Only yield keys with this prefix.
    prefix: Option<Box<[u8]>>,
    started: bool,
    done: bool,
}

impl Iter {
    pub(crate) fn new(
        db: Db,
        dbi: MDB_dbi,
        start: Option<Box<[u8]>>,
        prefix: Option<Box<[u8]>>,
    ) -> Result<Iter> {
        let txn = TxnGuard::begin(db.env(), true)?;
        let cursor = CursorGuard::open(&txn, dbi)?;
        Ok(Iter {
            cursor,
            txn,
            db,
            start,
            prefix,
            started: false,
            done: false,
        })
    }

    /// The database being iterated.
    pub fn db(&self) -> &Db {
        &self.db
    }

    fn step(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let (op, from) = if self.started {
            (MDB_NEXT, None)
        } else {
            self.started = true;
            // An empty start key is a full scan: LMDB rejects a zero-length
            // key, and "greater than or equal to nothing" is the beginning.
            match &self.start {
                Some(key) if !key.is_empty() => (MDB_SET_RANGE, Some(&**key)),
                _ => (MDB_FIRST, None),
            }
        };
        // SAFETY: `self.txn` is live for as long as `self`, and the slices are
        // copied below rather than escaping.
        let Some((key, value)) = (unsafe { self.cursor.step(op, from) })?
        else {
            return Ok(None);
        };
        let _ = &self.txn; // the borrow above is bounded by this transaction
        if self.prefix.as_deref().is_some_and(|p| !key.starts_with(p)) {
            return Ok(None); // sorted order: past the prefix means done
        }
        Ok(Some((key.to_vec(), value.to_vec())))
    }
}

impl Iterator for Iter {
    type Item = Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.step() {
            Ok(Some(pair)) => Some(Ok(pair)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

impl std::iter::FusedIterator for Iter {}

impl std::fmt::Debug for Iter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Iter")
            .field("db", &self.db)
            .field("prefix", &self.prefix)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}
