// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Db`] — one database in an [`Env`], and the operations on it.
//!
//! # Safety
//!
//! This module calls `liblmdb`, so it lifts the workspace's
//! `deny(unsafe_code)`; every block carries a `// SAFETY:` note. Transactions
//! and cursors come from [`crate::txn`]'s guards, so none leaks. `mdb_get` and
//! the cursor return pointers into the environment's mmap, valid only until
//! the transaction ends: each is either copied out before its guard drops or
//! handed to a callback that runs inside the transaction, and none escapes.
#![allow(unsafe_code)]

use crate::env::Env;
use crate::error::{Error, MdbCode, Result, check};
use crate::ffi::*;
use crate::iter::Iter;
use crate::txn::{CursorGuard, TxnGuard, empty_val, val_of};
use std::ffi::CString;
use std::ops::ControlFlow;
use std::ptr;

/// One database in an [`Env`]: a named one, or the environment's main
/// database.
///
/// Every operation runs in its own transaction, begun and finished inside the
/// call. Nothing has to be committed by hand; the cost is that operations
/// cannot be grouped, so two [`put`](Db::put)s are two transactions and a
/// reader can observe the first without the second.
///
/// `Db` is `Send + Sync` and cheap to clone (it shares the environment). LMDB
/// serializes writers itself: a write blocks while another thread's write to
/// the same environment is in flight. Reads never block.
///
/// A thread may hold only one transaction on an environment at a time, so an
/// operation attempted while this thread is inside a [`scan`](Db::scan) or
/// [`with_value`](Db::with_value) callback, or while it holds a live
/// [`Iter`], fails with `EDEADLK` rather than deadlocking. Other environments,
/// and other threads, are unaffected.
///
/// Keys must be 1..=511 bytes. Values are stored byte for byte, with no
/// header or encoding added.
#[derive(Clone)]
pub struct Db {
    env: Env,
    dbi: MDB_dbi,
    name: Option<Box<str>>,
}

impl Db {
    /// Open the environment's main (unnamed) database, which always exists.
    ///
    /// It shares its key space with the index of named databases, so a
    /// [`scan`](Db::scan) over it also yields their names. Prefer a named
    /// database unless the environment has only one.
    pub fn main(env: &Env) -> Result<Db> {
        Db::open_dbi(env, None, false)
    }

    /// Open the named database `name`, which must already exist.
    ///
    /// Fails with [`MdbCode::NotFound`] if it does not. Takes no writer lock.
    pub fn open(env: &Env, name: &str) -> Result<Db> {
        Db::open_dbi(env, Some(name), false)
    }

    /// Open the named database `name`, creating it if absent.
    ///
    /// Creating takes the environment's single writer lock; opening one that
    /// already exists does not.
    pub fn create(env: &Env, name: &str) -> Result<Db> {
        Db::open_dbi(env, Some(name), true)
    }

    /// The environment this database belongs to.
    pub fn env(&self) -> &Env {
        &self.env
    }

    /// The database's name, or `None` for the main database.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The value stored under `key`, or `None` if absent.
    ///
    /// Copies out of the mmap, so this allocates. [`get_into`](Db::get_into)
    /// reuses a buffer; [`with_value`](Db::with_value) avoids the copy.
    pub fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>> {
        let txn = TxnGuard::begin(&self.env, true)?;
        // Copied while `txn` is live: the slice dies with the transaction.
        Ok(self.raw_get(&txn, key.as_ref())?.map(<[u8]>::to_vec))
    }

    /// Read `key` into `out`, replacing its contents, and report whether the
    /// key was present. `out` is emptied on a miss.
    ///
    /// Reuses `out`'s capacity, so a loop over many keys allocates once.
    pub fn get_into(
        &self,
        key: impl AsRef<[u8]>,
        out: &mut Vec<u8>,
    ) -> Result<bool> {
        out.clear();
        let txn = TxnGuard::begin(&self.env, true)?;
        match self.raw_get(&txn, key.as_ref())? {
            Some(value) => {
                out.extend_from_slice(value);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Call `f` with the value stored under `key`, or with `None`, and return
    /// what it returns.
    ///
    /// The slice borrows the mmap directly, so nothing is copied. `f` runs
    /// inside the read transaction, so it must not touch this environment:
    /// any operation on it from within `f` fails with `EDEADLK`.
    ///
    /// ```
    /// # use truenas_mdb::{Db, Env};
    /// # let dir = tempfile::tempdir().unwrap();
    /// # let env = Env::open(dir.path().join("env"))?;
    /// # let db = Db::create(&env, "example")?;
    /// db.put("k", "12345")?;
    /// let len = db.with_value("k", |v| v.map(<[u8]>::len))?;
    /// assert_eq!(len, Some(5));
    /// # Ok::<(), truenas_mdb::Error>(())
    /// ```
    pub fn with_value<R>(
        &self,
        key: impl AsRef<[u8]>,
        f: impl FnOnce(Option<&[u8]>) -> R,
    ) -> Result<R> {
        let txn = TxnGuard::begin(&self.env, true)?;
        Ok(f(self.raw_get(&txn, key.as_ref())?))
    }

    /// Whether `key` is present.
    pub fn contains_key(&self, key: impl AsRef<[u8]>) -> Result<bool> {
        let txn = TxnGuard::begin(&self.env, true)?;
        Ok(self.raw_get(&txn, key.as_ref())?.is_some())
    }

    /// Store `value` under `key`, replacing any previous value.
    pub fn put(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.put_flags(key.as_ref(), value.as_ref(), 0)
    }

    /// Store `value` under `key` only if the key is absent. Returns whether it
    /// was stored.
    ///
    /// Atomic: the check and the write share one transaction.
    pub fn put_if_absent(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool> {
        match self.put_flags(key.as_ref(), value.as_ref(), MDB_NOOVERWRITE) {
            Ok(()) => Ok(true),
            Err(Error::Mdb(MdbCode::KeyExist)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Remove `key`, reporting whether it was present.
    pub fn del(&self, key: impl AsRef<[u8]>) -> Result<bool> {
        let txn = TxnGuard::begin(&self.env, false)?;
        let mut k = val_of(key.as_ref());
        // SAFETY: a live write transaction and a valid handle; `k` borrows the
        // caller's buffer for the call, and a null data pointer deletes by key.
        let rc = unsafe { mdb_del(txn.txn, self.dbi, &mut k, ptr::null_mut()) };
        let existed = match rc {
            MDB_SUCCESS => true,
            MDB_NOTFOUND => false,
            _ => return Err(Error::from_raw(rc)),
        };
        txn.commit()?;
        Ok(existed)
    }

    /// Remove every entry, keeping the database.
    pub fn clear(&self) -> Result<()> {
        let txn = TxnGuard::begin(&self.env, false)?;
        // SAFETY: a live write transaction and a valid handle; `del = 0`
        // empties the database and keeps the handle open.
        check(unsafe { mdb_drop(txn.txn, self.dbi, 0) })?;
        txn.commit()
    }

    /// The number of entries.
    pub fn len(&self) -> Result<u64> {
        let txn = TxnGuard::begin(&self.env, true)?;
        let mut stat = MDB_stat::default();
        // SAFETY: a live transaction, a valid handle, and an out-param.
        check(unsafe { mdb_stat(txn.txn, self.dbi, &mut stat) })?;
        Ok(stat.ms_entries as u64)
    }

    /// Whether the database has no entries.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Visit every entry in key order, calling `f(key, value)`.
    ///
    /// Return [`ControlFlow::Break`] to stop early with a value; `Ok(None)`
    /// means every entry was visited. The slices borrow the mmap directly, so
    /// a scan copies nothing, and they cannot be kept past the call. `f` runs
    /// inside the read transaction, so it must not touch this environment:
    /// any operation on it from within `f` fails with `EDEADLK`.
    ///
    /// [`iter`](Db::iter) is the allocating equivalent, usable with `for`.
    ///
    /// ```
    /// # use std::ops::ControlFlow;
    /// # use truenas_mdb::{Db, Env};
    /// # let dir = tempfile::tempdir().unwrap();
    /// # let env = Env::open(dir.path().join("env"))?;
    /// # let db = Db::create(&env, "example")?;
    /// db.put("a", "1")?;
    /// db.put("b", "22")?;
    /// let mut bytes = 0;
    /// db.scan(|_key, value| {
    ///     bytes += value.len();
    ///     ControlFlow::<()>::Continue(())
    /// })?;
    /// assert_eq!(bytes, 3);
    /// # Ok::<(), truenas_mdb::Error>(())
    /// ```
    pub fn scan<B>(
        &self,
        f: impl FnMut(&[u8], &[u8]) -> ControlFlow<B>,
    ) -> Result<Option<B>> {
        self.scan_impl(None, None, f)
    }

    /// Like [`scan`](Db::scan), but starting at the first key greater than or
    /// equal to `start`.
    pub fn scan_from<B>(
        &self,
        start: impl AsRef<[u8]>,
        f: impl FnMut(&[u8], &[u8]) -> ControlFlow<B>,
    ) -> Result<Option<B>> {
        self.scan_impl(Some(start.as_ref()), None, f)
    }

    /// Like [`scan`](Db::scan), but visiting only keys starting with `prefix`.
    ///
    /// Seeks to the prefix rather than walking from the beginning, and stops
    /// at the first key past it.
    pub fn scan_prefix<B>(
        &self,
        prefix: impl AsRef<[u8]>,
        f: impl FnMut(&[u8], &[u8]) -> ControlFlow<B>,
    ) -> Result<Option<B>> {
        let prefix = prefix.as_ref();
        self.scan_impl(Some(prefix), Some(prefix), f)
    }

    /// An iterator over every entry in key order, yielding owned pairs.
    ///
    /// Holds a read transaction open for its lifetime, so it iterates a
    /// consistent snapshot — and so this thread cannot touch this environment
    /// again until it is dropped: any operation meanwhile fails with
    /// `EDEADLK`. Drop it promptly, since it also keeps superseded pages from
    /// being reused. [`scan`](Db::scan) is the non-allocating equivalent, and
    /// collecting the iterator first is the way to write back what it yields.
    ///
    /// ```
    /// # use truenas_mdb::{Db, Env};
    /// # let dir = tempfile::tempdir().unwrap();
    /// # let env = Env::open(dir.path().join("env"))?;
    /// # let db = Db::create(&env, "example")?;
    /// db.put("a", "1")?;
    /// db.put("b", "2")?;
    /// let all = db.iter()?.collect::<Result<Vec<_>, _>>()?;
    /// assert_eq!(all.len(), 2);
    /// # Ok::<(), truenas_mdb::Error>(())
    /// ```
    pub fn iter(&self) -> Result<Iter> {
        Iter::new(self.clone(), self.dbi, None, None)
    }

    /// Like [`iter`](Db::iter), but starting at the first key greater than or
    /// equal to `start`.
    pub fn iter_from(&self, start: impl AsRef<[u8]>) -> Result<Iter> {
        Iter::new(self.clone(), self.dbi, Some(start.as_ref().into()), None)
    }

    /// Like [`iter`](Db::iter), but yielding only keys starting with `prefix`.
    pub fn iter_prefix(&self, prefix: impl AsRef<[u8]>) -> Result<Iter> {
        let prefix: Box<[u8]> = prefix.as_ref().into();
        Iter::new(self.clone(), self.dbi, Some(prefix.clone()), Some(prefix))
    }

    // --- internals -------------------------------------------------------

    fn open_dbi(env: &Env, name: Option<&str>, create: bool) -> Result<Db> {
        let cname = name
            .map(CString::new)
            .transpose()
            .map_err(|_| Error::Os(libc::EINVAL))?;
        let name_ptr = cname.as_ref().map_or(ptr::null(), |c| c.as_ptr());

        // `lmdb.h` forbids concurrent `mdb_dbi_open` in one process. One lock
        // per environment, so opening in one does not block another.
        let _dbi_guard = env.lock_dbi();

        // Look the handle up in a read transaction first: an environment has
        // one writer, and finding an existing database must not queue behind
        // it. Only a genuine create escalates.
        let dbi = match dbi_open(env, name_ptr, 0, true) {
            Ok(dbi) => dbi,
            Err(Error::Mdb(MdbCode::NotFound)) if create => {
                dbi_open(env, name_ptr, MDB_CREATE, false)?
            }
            Err(e) => return Err(e),
        };
        Ok(Db {
            env: env.clone(),
            dbi,
            name: name.map(Box::from),
        })
    }

    fn put_flags(
        &self,
        key: &[u8],
        value: &[u8],
        flags: std::os::raw::c_uint,
    ) -> Result<()> {
        let txn = TxnGuard::begin(&self.env, false)?;
        let mut k = val_of(key);
        let mut d = val_of(value);
        // SAFETY: a live write transaction and a valid handle; `k` and `d`
        // borrow the caller's buffers, which outlive the call.
        check(unsafe { mdb_put(txn.txn, self.dbi, &mut k, &mut d, flags) })?;
        txn.commit()
    }

    /// `mdb_get` into the transaction's mmap. The slice lives only as long as
    /// `txn`, which is what keeps callers honest about copying.
    fn raw_get<'t>(
        &self,
        txn: &'t TxnGuard,
        key: &[u8],
    ) -> Result<Option<&'t [u8]>> {
        let mut k = val_of(key);
        let mut d = empty_val();
        // SAFETY: a live transaction and a valid handle; `k` borrows the
        // caller's buffer for the call, `d` is an out-param LMDB fills with a
        // pointer into the mmap, live for `'t`.
        let rc = unsafe { mdb_get(txn.txn, self.dbi, &mut k, &mut d) };
        match rc {
            // SAFETY: the call succeeded, so `d` describes a live mmap region
            // valid as long as `txn`, that is for `'t`.
            MDB_SUCCESS => Ok(Some(unsafe { crate::txn::as_slice(&d) })),
            MDB_NOTFOUND => Ok(None),
            _ => Err(Error::from_raw(rc)),
        }
    }

    fn scan_impl<B>(
        &self,
        start: Option<&[u8]>,
        prefix: Option<&[u8]>,
        mut f: impl FnMut(&[u8], &[u8]) -> ControlFlow<B>,
    ) -> Result<Option<B>> {
        let txn = TxnGuard::begin(&self.env, true)?;
        let cursor = CursorGuard::open(&txn, self.dbi)?;
        // An empty start key is a full scan: LMDB rejects a zero-length key,
        // and "greater than or equal to nothing" is the beginning anyway.
        let (mut op, mut from) = match start {
            Some(key) if !key.is_empty() => (MDB_SET_RANGE, Some(key)),
            _ => (MDB_FIRST, None),
        };
        // SAFETY: `txn` outlives every borrow below, and the slices do not
        // escape an iteration.
        while let Some((key, value)) = (unsafe { cursor.step(op, from) })? {
            (op, from) = (MDB_NEXT, None);
            if prefix.is_some_and(|p| !key.starts_with(p)) {
                break; // sorted order: past the prefix means done
            }
            if let ControlFlow::Break(b) = f(key, value) {
                return Ok(Some(b));
            }
        }
        Ok(None)
    }
}

/// Open a database handle in its own transaction and commit it.
///
/// The handle is private to the transaction until it commits: aborting closes
/// it again, so this commits even when read-only.
fn dbi_open(
    env: &Env,
    name: *const std::os::raw::c_char,
    flags: std::os::raw::c_uint,
    read_only: bool,
) -> Result<MDB_dbi> {
    let txn = TxnGuard::begin(env, read_only)?;
    let mut dbi: MDB_dbi = 0;
    // SAFETY: a live transaction, a valid C string or null for the main
    // database, and an out-param for the handle.
    check(unsafe { mdb_dbi_open(txn.txn, name, flags, &mut dbi) })?;
    txn.commit()?;
    Ok(dbi)
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("name", &self.name)
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
        let env = Env::open_with(
            dir.path().join("env"),
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
            Db::create(&env, "sta\0te").unwrap_err(),
            Error::Os(libc::EINVAL)
        );
        assert_eq!(
            Db::open(&env, "sta\0te").unwrap_err(),
            Error::Os(libc::EINVAL)
        );
    }

    #[test]
    fn open_requires_the_database_to_exist_and_create_makes_it() {
        let (_dir, env) = scratch();
        assert_eq!(
            Db::open(&env, "absent").unwrap_err(),
            Error::Mdb(MdbCode::NotFound)
        );
        Db::create(&env, "absent").unwrap();
        // Now the read-only lookup path finds it.
        Db::open(&env, "absent").unwrap();
        // And create on an existing database is a no-op open.
        Db::create(&env, "absent").unwrap();
    }

    #[test]
    fn the_main_database_needs_no_name() {
        let (_dir, env) = scratch();
        let db = Db::main(&env).unwrap();
        assert_eq!(db.name(), None);
        db.put("k", "v").unwrap();
        assert_eq!(db.get("k").unwrap().as_deref(), Some(&b"v"[..]));
    }

    #[test]
    fn a_named_database_reports_its_name() {
        let (_dir, env) = scratch();
        let db = Db::create(&env, "state").unwrap();
        assert_eq!(db.name(), Some("state"));
        assert_eq!(db.env().path(), env.path());
        assert!(format!("{db:?}").contains("state"));
    }
}
