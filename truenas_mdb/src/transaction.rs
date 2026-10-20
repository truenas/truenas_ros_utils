// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`ReadTxn`], [`WriteTxn`] and [`Cursor`] — one transaction over any number
//! of databases, and the [`Stat`] a transaction can read.
//!
//! # Safety
//!
//! This module calls `liblmdb`, so it lifts the workspace's
//! `deny(unsafe_code)`; every block carries a `// SAFETY:` note. The
//! transaction and cursor handles are [`crate::txn`]'s guards, so none leaks.
//! Every slice handed out points into the environment's mmap and is bounded
//! by the borrow of the transaction it came from: a read transaction's pages
//! are stable for its whole life, and every method of a write transaction
//! that modifies takes `&mut self`, so no slice read from one is live across
//! a later write, which is when LMDB may move the page it points into.
#![allow(unsafe_code)]

use crate::db::Db;
use crate::env::Env;
use crate::error::{Error, MdbCode, Result, check};
use crate::ffi::*;
use crate::txn::{CursorGuard, TxnGuard, as_slice, empty_val, val_of};
use std::marker::PhantomData;
use std::os::raw::c_uint;
use std::ptr;

/// A database's B-tree statistics, from `mdb_stat`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct Stat {
    /// The page size, which is the system's.
    pub page_size: u32,
    /// Levels in the tree: 0 for an empty database, 1 for a single leaf.
    pub depth: u32,
    /// Interior pages.
    pub branch_pages: u64,
    /// Leaf pages.
    pub leaf_pages: u64,
    /// Pages holding values too large to share a leaf.
    pub overflow_pages: u64,
    /// Entries, counted as [`Db::len`] counts.
    pub entries: u64,
}

impl Stat {
    pub(crate) fn read(txn: &TxnGuard, dbi: MDB_dbi) -> Result<Stat> {
        let mut stat = MDB_stat::default();
        // SAFETY: a live transaction, a valid handle, and an out-param.
        check(unsafe { mdb_stat(txn.txn, dbi, &mut stat) })?;
        Ok(Stat {
            page_size: stat.ms_psize,
            depth: stat.ms_depth,
            branch_pages: stat.ms_branch_pages as u64,
            leaf_pages: stat.ms_leaf_pages as u64,
            overflow_pages: stat.ms_overflow_pages as u64,
            entries: stat.ms_entries as u64,
        })
    }
}

/// What the two transaction types share: the guard, and the environment it
/// is on.
struct Inner<'e> {
    guard: TxnGuard,
    env: &'e Env,
}

impl<'e> Inner<'e> {
    fn begin(env: &'e Env, read_only: bool) -> Result<Inner<'e>> {
        Ok(Inner {
            guard: TxnGuard::begin(env, read_only)?,
            env,
        })
    }

    /// `db` must belong to this transaction's environment. LMDB has no check
    /// of its own: a handle from another environment is a small integer that
    /// names an arbitrary database in this one.
    fn dbi(&self, db: &Db) -> Result<MDB_dbi> {
        if !ptr::eq(db.env().ptr(), self.env.ptr()) {
            return Err(Error::Os(libc::EINVAL));
        }
        Ok(db.dbi())
    }

    fn get<'t>(&'t self, db: &Db, key: &[u8]) -> Result<Option<&'t [u8]>> {
        let dbi = self.dbi(db)?;
        let mut k = val_of(key);
        let mut d = empty_val();
        // SAFETY: a live transaction and a valid handle; `k` borrows the
        // caller's buffer for the call, `d` is an out-param LMDB fills with a
        // pointer into the mmap, live for `'t`.
        let rc = unsafe { mdb_get(self.guard.txn, dbi, &mut k, &mut d) };
        match rc {
            // SAFETY: the call succeeded, so `d` describes a live mmap region
            // valid as long as the transaction, which `'t` borrows.
            MDB_SUCCESS => Ok(Some(unsafe { as_slice(&d) })),
            MDB_NOTFOUND => Ok(None),
            _ => Err(Error::from_raw(rc)),
        }
    }

    fn cursor<'t>(&'t self, db: &Db) -> Result<Cursor<'t>> {
        let dbi = self.dbi(db)?;
        Ok(Cursor {
            guard: CursorGuard::open(&self.guard, dbi)?,
            _txn: PhantomData,
        })
    }

    fn stat(&self, db: &Db) -> Result<Stat> {
        Stat::read(&self.guard, self.dbi(db)?)
    }
}

/// A read transaction: one snapshot of every database in an [`Env`], from
/// [`Env::read`].
///
/// Values and cursors borrow the mmap and live as long as the transaction,
/// so nothing is copied unless the caller copies it. While it lives, this
/// thread's [`Db`] operations on the environment fail with `EDEADLK`; the
/// transaction's own methods take their place. A `Db` from another
/// environment is refused with `EINVAL`.
///
/// Bound to the thread that began it, as LMDB binds every transaction:
///
/// ```compile_fail
/// fn send<T: Send>(_: T) {}
/// fn f(txn: truenas_mdb::ReadTxn<'_>) {
///     send(txn)
/// }
/// ```
pub struct ReadTxn<'e>(Inner<'e>);

impl<'e> ReadTxn<'e> {
    pub(crate) fn begin(env: &'e Env) -> Result<ReadTxn<'e>> {
        Ok(ReadTxn(Inner::begin(env, true)?))
    }

    /// The value stored under `key` in `db`, or `None` if absent.
    pub fn get<'t>(
        &'t self,
        db: &Db,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<&'t [u8]>> {
        self.0.get(db, key.as_ref())
    }

    /// Whether `key` is present in `db`.
    pub fn contains_key(&self, db: &Db, key: impl AsRef<[u8]>) -> Result<bool> {
        Ok(self.0.get(db, key.as_ref())?.is_some())
    }

    /// A cursor over `db`, positioned before its first pair.
    pub fn cursor<'t>(&'t self, db: &Db) -> Result<Cursor<'t>> {
        self.0.cursor(db)
    }

    /// `db`'s statistics as of this snapshot.
    pub fn stat(&self, db: &Db) -> Result<Stat> {
        self.0.stat(db)
    }

    /// The environment this transaction is on.
    pub fn env(&self) -> &'e Env {
        self.0.env
    }
}

impl std::fmt::Debug for ReadTxn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadTxn")
            .field("env", &self.0.env.path())
            .finish_non_exhaustive()
    }
}

/// A write transaction over every database in an [`Env`], from
/// [`Env::write`].
///
/// Reads see this transaction's own writes. Every method that modifies takes
/// `&mut self`, so a value or cursor read from the transaction cannot be
/// held across a write. The environment's single writer lock is held for the
/// transaction's whole life, and this thread's [`Db`] operations on the
/// environment fail with `EDEADLK` meanwhile. A `Db` from another environment
/// is refused with `EINVAL`.
///
/// Bound to the thread that began it, as LMDB binds every transaction:
///
/// ```compile_fail
/// fn send<T: Send>(_: T) {}
/// fn f(txn: truenas_mdb::WriteTxn<'_>) {
///     send(txn)
/// }
/// ```
pub struct WriteTxn<'e>(Inner<'e>);

impl<'e> WriteTxn<'e> {
    pub(crate) fn begin(env: &'e Env) -> Result<WriteTxn<'e>> {
        Ok(WriteTxn(Inner::begin(env, false)?))
    }

    pub(crate) fn commit(self) -> Result<()> {
        self.0.guard.commit()
    }

    /// The value stored under `key` in `db`, or `None` if absent.
    pub fn get<'t>(
        &'t self,
        db: &Db,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<&'t [u8]>> {
        self.0.get(db, key.as_ref())
    }

    /// Whether `key` is present in `db`.
    pub fn contains_key(&self, db: &Db, key: impl AsRef<[u8]>) -> Result<bool> {
        Ok(self.0.get(db, key.as_ref())?.is_some())
    }

    /// A cursor over `db`, positioned before its first pair. The transaction
    /// cannot write while the cursor lives.
    pub fn cursor<'t>(&'t self, db: &Db) -> Result<Cursor<'t>> {
        self.0.cursor(db)
    }

    /// `db`'s statistics, this transaction's writes included.
    pub fn stat(&self, db: &Db) -> Result<Stat> {
        self.0.stat(db)
    }

    /// The environment this transaction is on.
    pub fn env(&self) -> &'e Env {
        self.0.env
    }

    /// Store `value` under `key` in `db`, replacing any previous value.
    pub fn put(
        &mut self,
        db: &Db,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.put_flags(db, key.as_ref(), value.as_ref(), 0)
    }

    /// Store `value` under `key` in `db` only if the key is absent. Returns
    /// whether it was stored.
    pub fn put_if_absent(
        &mut self,
        db: &Db,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool> {
        match self.put_flags(db, key.as_ref(), value.as_ref(), MDB_NOOVERWRITE)
        {
            Ok(()) => Ok(true),
            Err(Error::Mdb(MdbCode::KeyExist)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Store `value` under `key` in `db`, where `key` sorts after every key
    /// the database holds.
    ///
    /// LMDB then places the pair at the end without a search and fills each
    /// leaf page before starting the next, so a database loaded this way
    /// from sorted input is written once, with full pages. A key that does
    /// not sort last fails with [`MdbCode::KeyExist`] and stores nothing.
    pub fn put_append(
        &mut self,
        db: &Db,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.put_flags(db, key.as_ref(), value.as_ref(), MDB_APPEND)
    }

    /// Remove `key` from `db`, reporting whether it was present.
    pub fn del(&mut self, db: &Db, key: impl AsRef<[u8]>) -> Result<bool> {
        let dbi = self.0.dbi(db)?;
        let mut k = val_of(key.as_ref());
        // SAFETY: a live write transaction and a valid handle; `k` borrows
        // the caller's buffer for the call, and a null data pointer deletes
        // by key.
        let rc =
            unsafe { mdb_del(self.0.guard.txn, dbi, &mut k, ptr::null_mut()) };
        match rc {
            MDB_SUCCESS => Ok(true),
            MDB_NOTFOUND => Ok(false),
            _ => Err(Error::from_raw(rc)),
        }
    }

    /// Remove every entry from `db`, keeping the database.
    pub fn clear(&mut self, db: &Db) -> Result<()> {
        let dbi = self.0.dbi(db)?;
        // SAFETY: a live write transaction and a valid handle; `del = 0`
        // empties the database and keeps the handle open.
        check(unsafe { mdb_drop(self.0.guard.txn, dbi, 0) })
    }

    fn put_flags(
        &mut self,
        db: &Db,
        key: &[u8],
        value: &[u8],
        flags: c_uint,
    ) -> Result<()> {
        let dbi = self.0.dbi(db)?;
        let mut k = val_of(key);
        let mut d = val_of(value);
        // SAFETY: a live write transaction and a valid handle; `k` and `d`
        // borrow the caller's buffers, which outlive the call.
        check(unsafe { mdb_put(self.0.guard.txn, dbi, &mut k, &mut d, flags) })
    }
}

impl std::fmt::Debug for WriteTxn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteTxn")
            .field("env", &self.0.env.path())
            .finish_non_exhaustive()
    }
}

/// A cursor over one database inside a transaction, from [`ReadTxn::cursor`]
/// or [`WriteTxn::cursor`].
///
/// Each method positions the cursor and returns the pair it landed on, or
/// `None` where there is none. The slices live as long as the transaction's
/// borrow, not the cursor, so a pair can be kept after the cursor is dropped.
/// A cursor on a [`WriteTxn`] holds a shared borrow of it, so the transaction
/// cannot write while the cursor lives; drop the cursor first.
///
/// Bound to its transaction's thread:
///
/// ```compile_fail
/// fn send<T: Send>(_: T) {}
/// fn f(cursor: truenas_mdb::Cursor<'_>) {
///     send(cursor)
/// }
/// ```
pub struct Cursor<'t> {
    guard: CursorGuard,
    _txn: PhantomData<&'t ()>,
}

/// A key and its value, borrowed from the transaction.
pub type Pair<'t> = (&'t [u8], &'t [u8]);

// `next` and `prev` are the names of a cursor that moves both ways and seeks,
// as `std::collections::btree_map::Cursor` spells them; `Iterator::next` would
// describe one direction of a type that has two.
#[allow(clippy::should_implement_trait)]
impl<'t> Cursor<'t> {
    fn step(&self, op: c_uint, key: Option<&[u8]>) -> Result<Option<Pair<'t>>> {
        // SAFETY: `'t` is the borrow of the transaction this cursor was
        // opened in, so the slices cannot outlive it.
        unsafe { self.guard.step(op, key) }
    }

    /// The first pair.
    pub fn first(&mut self) -> Result<Option<Pair<'t>>> {
        self.step(MDB_FIRST, None)
    }

    /// The last pair.
    pub fn last(&mut self) -> Result<Option<Pair<'t>>> {
        self.step(MDB_LAST, None)
    }

    /// The pair after the current one; the first, on a cursor not yet
    /// positioned.
    pub fn next(&mut self) -> Result<Option<Pair<'t>>> {
        self.step(MDB_NEXT, None)
    }

    /// The pair before the current one; the last, on a cursor not yet
    /// positioned.
    pub fn prev(&mut self) -> Result<Option<Pair<'t>>> {
        self.step(MDB_PREV, None)
    }

    /// The pair at the current position. `EINVAL` on a cursor not yet
    /// positioned, and `None` once it has stepped past either end.
    pub fn current(&self) -> Result<Option<Pair<'t>>> {
        self.step(MDB_GET_CURRENT, None)
    }

    /// The first pair whose key is greater than or equal to `key`. An empty
    /// `key` is before every key, so it positions at the first pair.
    pub fn seek(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Pair<'t>>> {
        match key.as_ref() {
            [] => self.step(MDB_FIRST, None),
            key => self.step(MDB_SET_RANGE, Some(key)),
        }
    }

    /// The pair stored under exactly `key`, or `None`. Nothing is stored
    /// under an empty key, so an empty `key` is `None`.
    pub fn seek_exact(
        &mut self,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<Pair<'t>>> {
        match key.as_ref() {
            [] => Ok(None),
            key => self.step(MDB_SET_KEY, Some(key)),
        }
    }
}

impl std::fmt::Debug for Cursor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cursor").finish_non_exhaustive()
    }
}
