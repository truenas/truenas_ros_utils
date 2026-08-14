// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
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
use crate::ffi::MDB_dbi;
use crate::txn::{CursorGuard, TxnGuard};

/// An iterator over a database's entries in key order, yielding owned
/// `(key, value)` pairs.
///
/// Created by [`Db::iter`], [`Db::iter_from`], or [`Db::iter_prefix`]. It
/// holds a read transaction open for its lifetime, so it iterates a consistent
/// snapshot, and it prevents superseded pages from being reused; drop it
/// promptly.
///
/// While it is alive this thread holds the environment's one transaction slot,
/// so any other operation on that environment from this thread — including a
/// second iterator — fails with `EDEADLK`. Collect what is needed and drop the
/// iterator before writing back. Other threads and other environments are
/// unaffected; the iterator itself is neither `Send` nor `Sync`, because LMDB
/// ties a read transaction to the thread that began it.
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
        // SAFETY: `self.txn` is live for as long as `self`, and the slices are
        // copied below rather than escaping.
        let stepped = unsafe {
            self.cursor.walk(
                &mut self.started,
                self.start.as_deref(),
                self.prefix.as_deref(),
            )
        }?;
        let _ = &self.txn; // the borrow above is bounded by this transaction
        Ok(stepped.map(|(key, value)| (key.to_vec(), value.to_vec())))
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
