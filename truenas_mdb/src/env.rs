//! [`Env`] — an open LMDB environment, and the process-wide pool that keeps
//! there being exactly one of them per path.
//!
//! # Safety model
//!
//! This module calls into `liblmdb`, so it lifts the workspace's
//! `deny(unsafe_code)`; every block carries a `// SAFETY:` note. The invariants
//! it upholds:
//!
//! - A `*mut MDB_env` is created by `mdb_env_create`, never handed out, and is
//!   created and closed only while the pool mutex is held.
//! - LMDB forbids opening the *same* environment twice in one process — doing
//!   so corrupts the lock table — so every [`Env::open`] of a path shares one
//!   handle, reference-counted, closed (and force-synced) exactly once when the
//!   last handle for it drops.
//! - The handle is opened with `MDB_NOTLS` and LMDB serializes its own writers,
//!   so it is sound to send and share across threads.
#![allow(unsafe_code)]

use crate::error::{check, Result};
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
    /// Environment-level flags for [`Env::open`], fixed for the lifetime of the
    /// environment by whichever process opens it first.
    ///
    /// Deliberately incomplete. `MDB_WRITEMAP` and `MDB_MAPASYNC` are absent
    /// because `lmdb.h` warns "Do not mix processes with and without
    /// MDB_WRITEMAP on the same environment", and these environments are shared
    /// with Python and C processes that do not use it. `MDB_NOSUBDIR` is absent
    /// because the directory layout is part of the interop contract, and
    /// `MDB_NOLOCK` because nothing here should be inventing its own locking.
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct EnvFlags: u32 {
        /// Skip the fsync after each commit. Much faster, and a crash can lose
        /// the most recent transactions — but never corrupt the database.
        const NOSYNC = MDB_NOSYNC;
        /// Flush data but not the meta page on commit. A middle ground: a crash
        /// loses at most the last transaction.
        const NOMETASYNC = MDB_NOMETASYNC;
        /// Don't tie a read transaction to a thread-local reader slot. On by
        /// default here — see [`EnvOptions::flags`].
        const NOTLS = MDB_NOTLS;
        /// Turn off readahead. Worth setting when the database is larger than
        /// RAM and access is random.
        const NORDAHEAD = MDB_NORDAHEAD;
    }
}

/// How to open an [`Env`].
///
/// Defaults match `truenas_zfsrewrited`'s state environments so the two agree
/// on any database they share: a 1 GiB map, mode `0600` files under a `0700`
/// directory. Construct with `..Default::default()` and override what differs.
///
/// ```no_run
/// use truenas_mdb::{Env, EnvOptions};
///
/// let env = Env::open(
///     "/var/db/myservice".as_ref(),
///     &EnvOptions { max_dbs: 4, ..Default::default() },
/// )?;
/// # Ok::<(), truenas_mdb::Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EnvOptions {
    /// Size of the memory map, and so the hard ceiling on the database.
    ///
    /// This is a **cross-process contract, not a local preference**. LMDB does
    /// record it in the meta page, but a process that configures its own wins
    /// over that — the stored value is only consulted when none was set, and
    /// the map is merely raised to at least the committed data size. So an
    /// undersized process still *opens* the environment and reads what is
    /// there; it then hits [`MdbCode::MapFull`] long before the others do, and
    /// [`MdbCode::MapResized`] when another process grows past its map.
    ///
    /// Python's `lmdb` module defaults to 10 MiB, far below the 1 GiB default
    /// here, so whoever opens the same environment must be told the number. It
    /// costs address space, not memory, so err high.
    ///
    /// [`MdbCode::MapResized`]: crate::MdbCode::MapResized
    /// [`MdbCode::MapFull`]: crate::MdbCode::MapFull
    pub map_size: usize,
    /// How many named databases the environment may hold. Opening more than
    /// this fails with [`MdbCode::DbsFull`](crate::MdbCode::DbsFull); the
    /// unnamed main database does not count.
    pub max_dbs: u32,
    /// How many concurrent read transactions the environment allows. `0` keeps
    /// LMDB's own default of 126.
    pub max_readers: u32,
    /// Mode for the environment's files, before `umask`.
    pub mode: libc::mode_t,
    /// Mode for the environment directory when this call creates it, before
    /// `umask`.
    pub dir_mode: libc::mode_t,
    /// Environment flags. The default is [`EnvFlags::NOTLS`]: without it LMDB
    /// parks each reader in a thread-local slot that is only released when the
    /// thread exits, so a thread pool larger than `max_readers` eventually
    /// deadlocks. With it, a slot is held only for the life of a transaction —
    /// which suits this crate, whose transactions never outlive one call.
    pub flags: EnvFlags,
}

impl Default for EnvOptions {
    fn default() -> EnvOptions {
        EnvOptions {
            map_size: 1024 * 1024 * 1024, // 1 GiB, = STATE_ENV_MAPSIZE
            max_dbs: 8,
            max_readers: 0, // LMDB's own default (126)
            mode: 0o600,
            dir_mode: 0o700,
            flags: EnvFlags::NOTLS,
        }
    }
}

/// One pooled environment: the raw handle, a count of the live [`Env`] handles
/// sharing it, and the mutex serializing `mdb_dbi_open` on it.
struct EnvSlot {
    env: *mut MDB_env,
    refcnt: usize,
    dbi_lock: Arc<Mutex<()>>,
}

// SAFETY: the handle is created and closed only under the pool mutex, is never
// exposed, and is used exactly as in `Env` (opened with MDB_NOTLS; LMDB
// serializes writers). So a slot is safe to keep in the shared pool.
unsafe impl Send for EnvSlot {}

/// The process-wide pool: canonical directory → its one open environment.
fn env_pool() -> &'static Mutex<HashMap<PathBuf, EnvSlot>> {
    static POOL: OnceLock<Mutex<HashMap<PathBuf, EnvSlot>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Lock the pool, recovering from poisoning — a panic mid-update leaves the map
/// itself intact, and a poisoned pool would make every later open fail.
fn lock_pool() -> MutexGuard<'static, HashMap<PathBuf, EnvSlot>> {
    env_pool().lock().unwrap_or_else(|e| e.into_inner())
}

/// An open LMDB environment: one directory holding `data.mdb` and `lock.mdb`,
/// with one writer and many readers.
///
/// Reference-counted through a process-wide per-path pool. Cloning shares the
/// one handle; dropping the last one force-syncs and closes it. Opening the
/// same path twice therefore does the right thing rather than corrupting the
/// lock table, which is what LMDB does if you actually open it twice.
pub struct Env {
    /// Canonical pool key, and this environment's directory.
    key: PathBuf,
    /// The pooled handle, valid while this `Env` lives (its existence holds the
    /// slot's `refcnt` at 1 or more).
    env: *mut MDB_env,
    /// Serializes `mdb_dbi_open` on this environment — `lmdb.h` requires that
    /// it not run in concurrent transactions in one process.
    dbi_lock: Arc<Mutex<()>>,
}

// SAFETY: `env` is opened with MDB_NOTLS (read transactions are not pinned to
// the thread that made them) and LMDB serializes writers; the pointer is never
// exposed and is closed only under the pool mutex when the last handle drops.
unsafe impl Send for Env {}
unsafe impl Sync for Env {}

impl Env {
    /// Open the environment at `path`, creating the directory if needed.
    ///
    /// If this process already has that path open, this shares the existing
    /// handle and **`opts` is ignored** — environment-level parameters are
    /// fixed by the first open, and a later one only bumps the reference count.
    pub fn open(path: &Path, opts: &EnvOptions) -> Result<Env> {
        DirBuilder::new()
            .recursive(true)
            .mode(opts.dir_mode)
            .create(path)
            .map_err(io_to_error)?;
        // Canonicalize so two spellings of one directory share a pool slot
        // rather than opening the environment twice.
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

        // Configure, then open. Everything before `mdb_env_open` must happen
        // on a created-but-unopened handle, which is what we have here.
        // SAFETY: `env` is a valid, not-yet-opened handle for each call.
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
            // SAFETY: `env` came from `mdb_env_create`, is non-null, and is
            // closed exactly once here.
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

    /// Flush the environment to disk.
    ///
    /// Only meaningful for an environment opened with [`EnvFlags::NOSYNC`] or
    /// [`EnvFlags::NOMETASYNC`]; otherwise every commit has already synced.
    /// `force` requests a synchronous flush.
    pub fn sync(&self, force: bool) -> Result<()> {
        // SAFETY: a live `Env` keeps the environment open.
        check(unsafe { mdb_env_sync(self.env, force as std::os::raw::c_int) })
    }

    /// This environment's directory, canonicalized.
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
        // A live `self` guarantees the slot exists — its refcount counts us.
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
        // Last handle for this path. Force a final flush (which matters for a
        // NOSYNC environment) and close — both under the pool lock, so a
        // concurrent open of this path cannot observe a half-closed
        // environment: it blocks, finds the slot gone, and opens a fresh one.
        // SAFETY: `slot.env == self.env`, a valid open environment, closed
        // exactly once here.
        unsafe {
            mdb_env_sync(self.env, 1);
            mdb_env_close(self.env);
        }
        pool.remove(&self.key);
    }
}

impl std::fmt::Debug for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The raw handle is deliberately not shown: it is an implementation
        // detail and printing a pointer invites someone to use it.
        f.debug_struct("Env")
            .field("path", &self.key)
            .finish_non_exhaustive()
    }
}

/// Map an `io::Error` from the directory work onto this crate's error. Every
/// failure here is a real syscall failure, so it always has an `errno`.
fn io_to_error(e: std::io::Error) -> crate::Error {
    crate::Error::Os(e.raw_os_error().unwrap_or(libc::EIO))
}

#[cfg(test)]
mod tests {
    //! The per-path pool: one `MDB_env` per path per process, reference
    //! counted, closed on last drop. Mirrors the pool in
    //! `truenas_zfsrewrited/src/ext/lmdb_utils.c`, including its concurrency.
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

        let a = Env::open(&path, &opts()).unwrap();
        assert_eq!(refcnt(&path), Some(1));

        // A second open of the same path shares the one handle — this is the
        // whole point, since opening it twice for real corrupts the lock table.
        let b = Env::open(&path, &opts()).unwrap();
        assert_eq!(refcnt(&path), Some(2));
        assert_eq!(a.ptr(), b.ptr());

        drop(a);
        assert_eq!(refcnt(&path), Some(1), "one handle left, env stays open");
        drop(b);
        assert_eq!(refcnt(&path), None, "last drop closes and unpools it");

        // Reopening after a full close gives a fresh environment.
        let c = Env::open(&path, &opts()).unwrap();
        assert_eq!(refcnt(&path), Some(1));
        drop(c);
        assert_eq!(refcnt(&path), None);
    }

    #[test]
    fn a_different_spelling_of_the_same_directory_shares_the_slot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");
        let a = Env::open(&path, &opts()).unwrap();

        // ./env and env/../env are the same directory; canonicalizing the key
        // is what keeps them from becoming two environments.
        let indirect = path.join("..").join("env");
        let b = Env::open(&indirect, &opts()).unwrap();
        assert_eq!(refcnt(&path), Some(2));
        assert_eq!(a.ptr(), b.ptr());
        assert_eq!(a.path(), b.path(), "both canonicalize to one path");
    }

    #[test]
    fn clone_bumps_the_refcount() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");

        let a = Env::open(&path, &opts()).unwrap();
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
        // Mirrors the reference's multithreaded test: threads hammer
        // open -> use -> drop on one path. The pool must keep the refcount
        // consistent and never double-open or double-close.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");

        let mut handles = Vec::new();
        for _ in 0..8 {
            let p = path.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let e = Env::open(&p, &opts()).unwrap();
                    e.sync(false).unwrap(); // touch the shared handle
                    drop(e);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(refcnt(&path), None, "every handle was released");
    }

    #[test]
    fn opening_a_path_that_cannot_be_created_reports_the_errno() {
        // /proc is not writable, so the directory step fails before LMDB is
        // reached — and the failure must surface as the real errno.
        let err = Env::open(Path::new("/proc/truenas_mdb_test"), &opts())
            .expect_err("must not be able to create a directory under /proc");
        assert!(matches!(err, crate::Error::Os(_)), "{err:?}");
        assert_eq!(err.as_mdb(), None);
    }
}
