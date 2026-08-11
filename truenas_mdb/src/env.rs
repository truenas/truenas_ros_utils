// SPDX-License-Identifier: MIT
//! [`Env`] — an open LMDB environment, and the pool keeping one per path.
//!
//! # Safety
//!
//! This module calls `liblmdb`, so it lifts the workspace's
//! `deny(unsafe_code)`; every block carries a `// SAFETY:` note. Invariants:
//!
//! - A `*mut MDB_env` comes from `mdb_env_create`, is never handed out, and is
//!   created and closed only while the pool mutex is held.
//! - LMDB requires one open per environment per process — a second open takes
//!   its own `fcntl` advisory locks and invalidates the first's — so every
//!   [`Env::open`] of a path shares one handle, reference counted, closed
//!   exactly once when the last handle drops.
//! - An `MDB_env` may be used from any thread and LMDB serializes its own
//!   writers, so the handle is sound to send and share. What is thread-bound is
//!   a *transaction*, and [`crate::txn`] enforces that one never crosses a
//!   thread or overlaps another on the same thread.
#![allow(unsafe_code)]

use crate::error::{Result, check};
use crate::ffi::*;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::DirBuilder;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

bitflags::bitflags! {
    /// Environment flags for [`Env::open_with`], fixed for the environment's
    /// lifetime by whichever process opens it first.
    ///
    /// Only durability and readahead are exposed. `MDB_WRITEMAP` and
    /// `MDB_MAPASYNC` are omitted because `lmdb.h` forbids mixing processes
    /// with and without them on one environment; `MDB_NOSUBDIR` because the
    /// directory layout is fixed; `MDB_NOLOCK` because it hands locking to the
    /// caller; and `MDB_NOTLS` because LMDB's per-thread reader slots are what
    /// make [`crate::txn`]'s one-transaction-per-thread rule enforceable.
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct EnvFlags: u32 {
        /// No fsync on commit. Faster; a crash can lose recent transactions
        /// but not corrupt the database.
        const NOSYNC = MDB_NOSYNC;
        /// Flush data but not the meta page on commit. A crash loses at most
        /// the last transaction.
        const NOMETASYNC = MDB_NOMETASYNC;
        /// No readahead. Useful when the database exceeds RAM.
        const NORDAHEAD = MDB_NORDAHEAD;
    }
}

/// Options for [`Env::open_with`].
///
/// ```no_run
/// use truenas_mdb::{Env, EnvOptions};
///
/// let env = Env::open_with(
///     "/var/db/example",
///     &EnvOptions { max_dbs: 4, ..Default::default() },
/// )?;
/// # Ok::<(), truenas_mdb::Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EnvOptions {
    /// Size of the memory map, and so the ceiling on the database. Default
    /// 1 GiB.
    ///
    /// Shared with every other process on the environment. LMDB records it in
    /// the meta page, but a process configuring its own overrides that (the
    /// stored value is used only when none was set, and the map is raised to
    /// at least the committed data size). So an undersized process still opens
    /// and reads, then hits [`MdbCode::MapFull`] early, or
    /// [`MdbCode::MapResized`] when another process grows past its map. Costs
    /// address space, not memory.
    ///
    /// [`MdbCode::MapResized`]: crate::MdbCode::MapResized
    /// [`MdbCode::MapFull`]: crate::MdbCode::MapFull
    pub map_size: usize,
    /// Named databases the environment may hold, default 8. Exceeding it gives
    /// [`MdbCode::DbsFull`](crate::MdbCode::DbsFull); the main database does
    /// not count.
    pub max_dbs: u32,
    /// Reader lock-table slots. `0` (the default) keeps LMDB's own limit of
    /// 126.
    ///
    /// A slot is tied to the thread that first reads, and is released when
    /// that thread exits, so this bounds the number of *threads* that ever
    /// read from the environment, not the number of concurrent reads.
    pub max_readers: u32,
    /// Mode for the environment's files before `umask`, default `0o600`.
    pub mode: libc::mode_t,
    /// Mode for the environment directory if this call creates it, before
    /// `umask`. Default `0o700`.
    pub dir_mode: libc::mode_t,
    /// Environment flags, empty by default (durable commits, readahead on).
    pub flags: EnvFlags,
}

impl Default for EnvOptions {
    fn default() -> EnvOptions {
        EnvOptions {
            map_size: 1024 * 1024 * 1024,
            max_dbs: 8,
            max_readers: 0,
            mode: 0o600,
            dir_mode: 0o700,
            flags: EnvFlags::empty(),
        }
    }
}

/// A pooled environment: the handle, the count of live [`Env`]s sharing it, and
/// the mutex serializing `mdb_dbi_open` on it.
struct EnvSlot {
    env: *mut MDB_env,
    refcnt: usize,
    dbi_lock: Arc<Mutex<()>>,
}

// SAFETY: the handle is created and closed only under the pool mutex, is never
// exposed, and is used exactly as in `Env`.
unsafe impl Send for EnvSlot {}

/// Canonical directory -> its one open environment.
fn env_pool() -> &'static Mutex<HashMap<PathBuf, EnvSlot>> {
    static POOL: OnceLock<Mutex<HashMap<PathBuf, EnvSlot>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Lock the pool, recovering from poisoning: the map is consistent at every
/// point a panic could unwind through, so the guard is taken rather than the
/// poison propagated to every later open.
fn lock_pool() -> MutexGuard<'static, HashMap<PathBuf, EnvSlot>> {
    env_pool().lock().unwrap_or_else(|e| e.into_inner())
}

/// An open environment: a directory holding `data.mdb` and `lock.mdb`, with one
/// writer and many readers.
///
/// Reference counted per canonical path: opening a path already open in this
/// process yields another handle to the same environment, which is what LMDB
/// requires. Cloning shares the handle; the last drop syncs and closes it.
pub struct Env {
    /// Canonical pool key, and the environment's directory.
    key: PathBuf,
    /// The pooled handle, valid while this `Env` lives.
    env: *mut MDB_env,
    /// Serializes `mdb_dbi_open`, which `lmdb.h` forbids running in concurrent
    /// transactions in one process.
    dbi_lock: Arc<Mutex<()>>,
}

// SAFETY: an MDB_env may be used from any thread (LMDB serializes writers
// itself); only transactions are thread-bound, and `crate::txn` keeps every one
// of them inside the thread and call that created it. The pointer is never
// exposed and is closed only under the pool mutex when the last handle drops.
unsafe impl Send for Env {}
unsafe impl Sync for Env {}

impl Env {
    /// Open the environment at `path` with [`EnvOptions::default`], creating
    /// the directory if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Env> {
        Env::open_with(path, &EnvOptions::default())
    }

    /// Open the environment at `path`, creating the directory if needed.
    ///
    /// If this process already has that path open, the existing handle is
    /// shared and `opts` is ignored: environment parameters are fixed by the
    /// first open.
    pub fn open_with(path: impl AsRef<Path>, opts: &EnvOptions) -> Result<Env> {
        let path = path.as_ref();
        DirBuilder::new()
            .recursive(true)
            .mode(opts.dir_mode)
            .create(path)
            .map_err(io_to_error)?;
        // Canonicalize so two spellings of one directory share a pool slot.
        let key = std::fs::canonicalize(path).map_err(io_to_error)?;

        let mut pool = lock_pool();
        if let Some(slot) = pool.get_mut(&key) {
            slot.refcnt += 1;
            return Ok(Env {
                key,
                env: slot.env,
                dbi_lock: Arc::clone(&slot.dbi_lock),
            });
        }

        let cpath = CString::new(key.as_os_str().as_bytes())
            .map_err(|_| crate::Error::Os(libc::EINVAL))?;
        let mut env: *mut MDB_env = ptr::null_mut();
        // SAFETY: out-param for a freshly created handle.
        check(unsafe { mdb_env_create(&mut env) })?;

        // SAFETY: `env` is valid and not yet opened, which is what each of
        // these configuration calls requires.
        let configured =
            check(unsafe { mdb_env_set_maxdbs(env, opts.max_dbs) })
                .and_then(|()| {
                    check(unsafe { mdb_env_set_mapsize(env, opts.map_size) })
                })
                .and_then(|()| match opts.max_readers {
                    0 => Ok(()), // keep LMDB's default
                    n => check(unsafe { mdb_env_set_maxreaders(env, n) }),
                })
                .and_then(|()| {
                    check(unsafe {
                        mdb_env_open(
                            env,
                            cpath.as_ptr(),
                            opts.flags.bits(),
                            opts.mode,
                        )
                    })
                });
        if let Err(e) = configured {
            // Nothing was pooled, so this handle is ours alone to close.
            // SAFETY: from `mdb_env_create`, non-null, closed exactly once.
            unsafe { mdb_env_close(env) };
            return Err(e);
        }

        let dbi_lock = Arc::new(Mutex::new(()));
        pool.insert(
            key.clone(),
            EnvSlot {
                env,
                refcnt: 1,
                dbi_lock: Arc::clone(&dbi_lock),
            },
        );
        Ok(Env { key, env, dbi_lock })
    }

    /// Flush to disk. Only meaningful with [`EnvFlags::NOSYNC`] or
    /// [`EnvFlags::NOMETASYNC`]; otherwise every commit has already synced.
    /// `force` requests a synchronous flush.
    pub fn sync(&self, force: bool) -> Result<()> {
        // SAFETY: a live `Env` keeps the environment open.
        check(unsafe { mdb_env_sync(self.env, force as std::os::raw::c_int) })
    }

    /// The environment's directory, canonicalized.
    pub fn path(&self) -> &Path {
        &self.key
    }

    pub(crate) fn ptr(&self) -> *mut MDB_env {
        self.env
    }

    pub(crate) fn lock_dbi(&self) -> MutexGuard<'_, ()> {
        self.dbi_lock.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Clone for Env {
    fn clone(&self) -> Env {
        let mut pool = lock_pool();
        // A live `self` guarantees the slot exists; its refcount counts us.
        if let Some(slot) = pool.get_mut(&self.key) {
            slot.refcnt += 1;
        }
        Env {
            key: self.key.clone(),
            env: self.env,
            dbi_lock: Arc::clone(&self.dbi_lock),
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let mut pool = lock_pool();
        let Some(slot) = pool.get_mut(&self.key) else {
            return;
        };
        slot.refcnt -= 1;
        if slot.refcnt != 0 {
            return;
        }
        // Last handle: sync (which matters under NOSYNC) and close, both under
        // the pool lock, so a concurrent open of this path blocks, finds the
        // slot gone, and opens a fresh environment instead of observing a
        // half-closed one.
        // SAFETY: `slot.env == self.env`, valid and open, closed exactly once.
        unsafe {
            mdb_env_sync(self.env, 1);
            mdb_env_close(self.env);
        }
        pool.remove(&self.key);
    }
}

impl std::fmt::Debug for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Env")
            .field("path", &self.key)
            .finish_non_exhaustive()
    }
}

/// Map an `io::Error` from the directory work onto this crate's error. These
/// are syscall failures, so they always carry an `errno`.
fn io_to_error(e: std::io::Error) -> crate::Error {
    crate::Error::Os(e.raw_os_error().unwrap_or(libc::EIO))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This path's refcount, or `None` if nothing is pooled for it.
    fn refcnt(path: &Path) -> Option<usize> {
        let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.into());
        lock_pool().get(&key).map(|s| s.refcnt)
    }

    fn opts() -> EnvOptions {
        EnvOptions {
            map_size: 1 << 20,
            max_dbs: 4,
            ..Default::default()
        }
    }

    #[test]
    fn same_path_shares_one_env_and_closes_on_last_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");

        let a = Env::open_with(&path, &opts()).unwrap();
        assert_eq!(refcnt(&path), Some(1));

        let b = Env::open_with(&path, &opts()).unwrap();
        assert_eq!(refcnt(&path), Some(2));
        assert_eq!(a.ptr(), b.ptr());

        drop(a);
        assert_eq!(refcnt(&path), Some(1));
        drop(b);
        assert_eq!(refcnt(&path), None);

        // Reopening after a full close gives a fresh environment.
        let c = Env::open_with(&path, &opts()).unwrap();
        assert_eq!(refcnt(&path), Some(1));
        drop(c);
        assert_eq!(refcnt(&path), None);
    }

    #[test]
    fn a_different_spelling_of_one_directory_shares_the_slot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");
        let a = Env::open_with(&path, &opts()).unwrap();

        let indirect = path.join("..").join("env");
        let b = Env::open_with(&indirect, &opts()).unwrap();
        assert_eq!(refcnt(&path), Some(2));
        assert_eq!(a.ptr(), b.ptr());
        assert_eq!(a.path(), b.path());
    }

    #[test]
    fn clone_bumps_the_refcount() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");

        let a = Env::open_with(&path, &opts()).unwrap();
        let b = a.clone();
        assert_eq!(refcnt(&path), Some(2));
        assert_eq!(a.ptr(), b.ptr());

        drop(b);
        assert_eq!(refcnt(&path), Some(1));
        drop(a);
        assert_eq!(refcnt(&path), None);
    }

    #[test]
    fn concurrent_open_and_close_is_race_free() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");

        let mut handles = Vec::new();
        for _ in 0..8 {
            let p = path.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let e = Env::open_with(&p, &opts()).unwrap();
                    e.sync(false).unwrap();
                    drop(e);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(refcnt(&path), None);
    }

    #[test]
    fn a_failed_open_pools_nothing() {
        // /proc is not writable, so the directory step fails before LMDB.
        let path = Path::new("/proc/truenas_mdb_test");
        let err = Env::open_with(path, &opts()).unwrap_err();
        assert!(matches!(err, crate::Error::Os(_)), "{err:?}");
        assert_eq!(err.as_mdb(), None);
        assert_eq!(refcnt(path), None);
    }

    #[test]
    fn a_failed_lmdb_open_pools_nothing() {
        // map_size 0 is rejected by mdb_env_open, after the handle exists, so
        // this exercises the close-and-return path rather than the directory
        // one. Whatever it returns, nothing may be left pooled.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");
        let bad = EnvOptions {
            map_size: 0,
            ..Default::default()
        };
        let _ = Env::open_with(&path, &bad);
        assert_eq!(refcnt(&path), None, "a failed open must pool nothing");

        // ...and the path is still usable afterwards.
        let ok = Env::open_with(&path, &opts()).unwrap();
        assert_eq!(refcnt(&path), Some(1));
        drop(ok);
    }
}
