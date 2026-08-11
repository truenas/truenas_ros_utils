//! Bindings to the system LMDB (`liblmdb`): a pooled environment and a
//! byte-oriented key/value store.
//!
//! [`Env`] is a memory-mapped environment — a directory holding `data.mdb` and
//! `lock.mdb`. [`Db`] is one database inside it. Keys and values are arbitrary
//! bytes, stored verbatim: this crate adds no header, envelope, or encoding,
//! so another reader of the same database sees exactly what was written.
//!
//! ```
//! use truenas_mdb::{Db, Env};
//!
//! # let dir = tempfile::tempdir().unwrap();
//! # let path = dir.path().join("example");
//! let env = Env::open(&path)?;
//! let db = Db::create(&env, "state")?;
//!
//! db.put("last_run", "2026-08-11")?;
//! assert_eq!(db.get("last_run")?.as_deref(), Some(&b"2026-08-11"[..]));
//! assert!(!db.put_if_absent("last_run", "ignored")?);
//!
//! for entry in db.iter()? {
//!     let (key, value) = entry?;
//!     println!("{} = {}", key.escape_ascii(), value.escape_ascii());
//! }
//! # Ok::<(), truenas_mdb::Error>(())
//! ```
//!
//! # One transaction per call
//!
//! Every operation begins and finishes its own transaction, so there is no
//! transaction type to thread through an API and nothing to commit by hand.
//! Operations cannot be grouped: two [`Db::put`]s are two transactions, and
//! there is no way to write two databases atomically. [`Db::put_if_absent`] is
//! atomic because the check and the write share one transaction.
//!
//! Reads have two forms. [`Db::get`] and [`Db::iter`] allocate, because their
//! transaction ends before the data reaches the caller. [`Db::with_value`] and
//! [`Db::scan`] pass borrowed slices to a callback that runs inside the
//! transaction, and copy nothing.
//!
//! # One transaction per thread
//!
//! LMDB allows a thread only one transaction on an environment at a time.
//! Two of this crate's APIs hold one open across caller code — the closures
//! given to [`Db::scan`] and [`Db::with_value`], and a live [`Iter`] — and
//! while either is in flight, any further operation on that environment from
//! the same thread returns `EDEADLK` instead of proceeding. Left to LMDB it
//! would be an unexplained `MDB_BAD_RSLOT` for a read, or a self-deadlock on
//! the writer mutex for a write.
//!
//! So this reads and writes back in two steps rather than one:
//!
//! ```
//! # use truenas_mdb::{Db, Env};
//! # let dir = tempfile::tempdir().unwrap();
//! # let env = Env::open(dir.path().join("env"))?;
//! # let src = Db::create(&env, "src")?;
//! # let dst = Db::create(&env, "dst")?;
//! # src.put("k", "v")?;
//! let batch = src.iter()?.collect::<Result<Vec<_>, _>>()?; // iterator dropped
//! for (key, value) in batch {
//!     dst.put(key, value)?;
//! }
//! # Ok::<(), truenas_mdb::Error>(())
//! ```
//!
//! Other threads and other environments are never blocked by this: the limit
//! is per thread per environment, and [`Env`] and [`Db`] are `Send + Sync`.
//!
//! # One environment per path, per process
//!
//! LMDB corrupts its lock table if one process opens the same environment
//! twice, so [`Env::open`] keeps a process-wide pool keyed by canonical path.
//! Opening an already-open path returns another handle to the same
//! environment, ignoring the [`EnvOptions`] the first open fixed. The
//! environment is synced and closed when the last handle drops.
//!
//! # Sharing an environment between processes
//!
//! LMDB is multi-process safe, and this crate links the system `liblmdb`
//! rather than vendoring one, so a database can be shared with any other
//! process using the same library. Four constraints apply, none of which LMDB
//! diagnoses:
//!
//! - Environments are directories (`MDB_NOSUBDIR` is not offered), matching
//!   the default layout elsewhere.
//! - `MDB_WRITEMAP` is not offered: `lmdb.h` forbids mixing processes with and
//!   without it on one environment.
//! - [`EnvOptions::map_size`] is shared state. Every process sets its own, and
//!   the smallest one governs in practice — see its documentation.
//! - Exactly one copy of LMDB may mediate an environment within a process.
//!   Linking a second, statically bundled copy alongside the system library is
//!   unsound; [`version`] reports which one this process got.
//!
//! # Requirements
//!
//! `liblmdb-dev` to build, `liblmdb0` to run. Checked against 0.9.31.

mod db;
mod env;
mod error;
mod ffi;
mod iter;
mod txn;

pub use db::Db;
pub use env::{Env, EnvFlags, EnvOptions};
pub use error::{Error, MdbCode, Result};
pub use iter::Iter;

/// The `(major, minor, patch)` version of the `liblmdb` this process linked.
///
/// Worth comparing against what any other LMDB user in the same process
/// reports: two copies of the library over one environment is unsound, and a
/// version mismatch is the cheapest way to notice one.
///
/// ```
/// let (major, minor, _patch) = truenas_mdb::version();
/// assert_eq!((major, minor), (0, 9));
/// ```
pub fn version() -> (i32, i32, i32) {
    let (mut major, mut minor, mut patch) = (0, 0, 0);
    // SAFETY: three out-params LMDB writes; the returned string is ignored.
    #[allow(unsafe_code)]
    unsafe {
        ffi::mdb_version(&mut major, &mut minor, &mut patch)
    };
    (major, minor, patch)
}
