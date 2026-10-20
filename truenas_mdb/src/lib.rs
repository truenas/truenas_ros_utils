// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
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
//! # Transactions
//!
//! Every operation on a [`Db`] begins and finishes its own transaction, so a
//! single read or write has nothing to commit by hand. Two [`Db::put`]s are
//! two transactions; [`Db::put_if_absent`] is atomic because its check and
//! write share one.
//!
//! Work that spans operations or databases runs in an explicit transaction.
//! [`Env::read`] hands a closure a [`ReadTxn`]: one snapshot of every
//! database in the environment, with [`Cursor`]s and borrowed values that
//! live as long as it. [`Env::write`] hands a closure a [`WriteTxn`]: its
//! puts and deletes, on any databases, commit together when the closure
//! returns `Ok` and are discarded when it returns `Err` or unwinds.
//!
//! ```
//! # use truenas_mdb::{Db, Env};
//! # let dir = tempfile::tempdir().unwrap();
//! # let env = Env::open(dir.path().join("env"))?;
//! # let src = Db::create(&env, "src")?;
//! # let dst = Db::create(&env, "dst")?;
//! # src.put("k", "v")?;
//! env.write(|txn| {
//!     let mut cursor = txn.cursor(&src)?;
//!     let mut pairs = Vec::new();
//!     while let Some((key, value)) = cursor.next()? {
//!         pairs.push((key.to_vec(), value.to_vec()));
//!     }
//!     drop(cursor);
//!     for (key, value) in pairs {
//!         txn.put(&dst, key, value)?;
//!     }
//!     Ok(())
//! })?;
//! assert_eq!(dst.get("k")?.as_deref(), Some(&b"v"[..]));
//! # Ok::<(), truenas_mdb::Error>(())
//! ```
//!
//! Reads have two forms. [`Db::get`] and [`Db::iter`] allocate, because their
//! transaction ends before the data reaches the caller. [`Db::with_value`],
//! [`Db::scan`] and the methods of a [`ReadTxn`] pass borrowed slices that
//! live inside the transaction, and copy nothing.
//!
//! # One transaction per thread
//!
//! LMDB allows a thread only one transaction on an environment at a time.
//! The APIs that hold one open across caller code — the closures given to
//! [`Env::read`], [`Env::write`], [`Db::scan`] and [`Db::with_value`], and a
//! live [`Iter`] — make it the thread's only one: while it is in flight, any
//! [`Db`] operation on that environment from the same thread returns
//! `EDEADLK` rather than attempting a second transaction, which LMDB cannot
//! serve. Inside [`Env::read`] and [`Env::write`] the transaction's own
//! methods take the place of the `Db` ones.
//!
//! Other threads and other environments are never blocked by this: the limit
//! is per thread per environment, and [`Env`] and [`Db`] are `Send + Sync`.
//!
//! # One environment per path, per process
//!
//! LMDB requires one open per environment per process, so [`Env::open`] keeps
//! a process-wide pool keyed by canonical path. Opening an already-open path
//! returns another handle to the same environment, ignoring the
//! [`EnvOptions`] the first open fixed. The environment is synced and closed
//! when the last handle drops.
//!
//! # Sharing an environment between processes
//!
//! LMDB is multi-process safe, and this crate links the system `liblmdb`, so a
//! database can be shared with any other process using that library. Four
//! constraints apply, and LMDB reports none of them:
//!
//! - Environments are directories; `MDB_NOSUBDIR` is not offered.
//! - `MDB_WRITEMAP` is not offered: `lmdb.h` forbids mixing processes with and
//!   without it on one environment.
//! - [`EnvOptions::map_size`] is shared state. Every process sets its own, and
//!   the smallest one governs in practice — see its documentation.
//! - Exactly one copy of LMDB may mediate an environment within a process, so
//!   a statically bundled copy must not be loaded alongside the system
//!   library. [`version`] reports which one this process linked.
//!
//! # Trusting the environment directory
//!
//! An environment directory and its files are trusted like the process's own
//! memory: LMDB dereferences the mapped pages directly, and a value's length
//! is data on them. Open only an environment this process controls. The
//! [`EnvOptions`] defaults create the directory `0o700` and its files
//! `0o600`, both before `umask`.
//!
//! # Requirements
//!
//! `liblmdb-dev` to build, `liblmdb0` to run. Checked against 0.9.31.

mod db;
mod env;
mod error;
mod ffi;
mod iter;
mod transaction;
mod txn;

pub use db::Db;
pub use env::{Env, EnvFlags, EnvInfo, EnvOptions};
pub use error::{Error, MdbCode, Result};
pub use iter::Iter;
pub use transaction::{Cursor, Pair, ReadTxn, Stat, WriteTxn};

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
