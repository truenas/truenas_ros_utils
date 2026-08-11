//! Bindings to the system LMDB (`liblmdb`) — a pooled environment and a flat,
//! raw-bytes key/value store.
//!
//! [`Env`] is a memory-mapped environment (one directory holding `data.mdb`
//! and `lock.mdb`); [`Db`] is one database inside it, either named or the
//! unnamed main one. Values are `&[u8]` in and `Vec<u8>` out — this crate adds
//! no header, envelope, or encoding of its own, so what another process reads
//! is exactly what you wrote.
//!
//! ```no_run
//! use truenas_mdb::{Db, Env, EnvOptions, PutFlags};
//!
//! let env = Env::open("/var/db/myservice".as_ref(), &EnvOptions::default())?;
//! let state = Db::open(&env, Some("state"), true)?;
//!
//! state.put(b"last_run", b"2026-08-11", PutFlags::empty())?;
//! assert_eq!(state.get(b"last_run")?.as_deref(), Some(&b"2026-08-11"[..]));
//! # Ok::<(), truenas_mdb::Error>(())
//! ```
//!
//! # One transaction per call
//!
//! Every operation begins and finishes its own transaction inside the call.
//! Nothing has to be committed by hand, and there is no transaction type to
//! thread through an API — but operations cannot be grouped either. Two
//! [`Db::put`]s are two transactions, so a reader can observe the first
//! without the second, and there is no way to write two databases atomically.
//! A caller that needs that wants a transactional layer this crate does not
//! yet have.
//!
//! Reads are the exception worth knowing about: [`Db::traverse`] runs its
//! callback *inside* the read transaction and hands it slices borrowed
//! straight out of the mmap, so a whole scan copies nothing. [`Db::get`] has
//! to copy, because its transaction ends when it returns; [`Db::get_into`]
//! at least reuses your buffer.
//!
//! # One environment per path, per process
//!
//! LMDB forbids opening the same environment twice in one process — it
//! corrupts the lock table — so [`Env::open`] keeps a process-wide pool keyed
//! by canonical path. Opening a path already open returns another handle onto
//! the same environment (and ignores the [`EnvOptions`], which the first open
//! fixed); the environment is force-synced and closed when the last handle
//! drops.
//!
//! # Sharing an environment with other processes
//!
//! This crate links the **system** `liblmdb` rather than vendoring a copy,
//! because these databases are shared: `truenas_zfsrewrited`'s C extension and
//! Python's `lmdb` module open the same directories. LMDB's correctness rests
//! on one copy of the library mediating an environment, and a vendored static
//! copy in the same address space would be a second one.
//!
//! Sharing imposes four constraints, none of which LMDB will diagnose for you:
//!
//! - **The directory layout is part of the contract.** An environment is a
//!   directory containing `data.mdb` and `lock.mdb` (`MDB_NOSUBDIR` is not
//!   offered), matching the C and Python defaults.
//! - **Never `MDB_WRITEMAP`.** `lmdb.h`: "Do not mix processes with and
//!   without MDB_WRITEMAP on the same environment." Nothing else on these
//!   databases uses it, so it is absent from [`EnvFlags`] entirely.
//! - **[`EnvOptions::map_size`] is a cross-process contract**, not a local
//!   preference. Every process sets its own, and the smallest one wins in
//!   practice: opening succeeds regardless (LMDB raises the map to at least
//!   the committed data size), but a process that asked for less than the
//!   others will hit [`MdbCode::MapFull`] far earlier than they do, and
//!   [`MdbCode::MapResized`] if another process grows past its map. Python's
//!   `lmdb` defaults to 10 MiB against the 1 GiB default here, so whoever
//!   opens the environment has to be told the number.
//! - **One `liblmdb` per process.** Debian's `python3-lmdb` links `liblmdb0`
//!   and is fine; `pip install lmdb` bundles its own LMDB, and must not be
//!   loaded into a process that also holds `liblmdb0` over the same
//!   environment.
//!
//! # Requirements
//!
//! `liblmdb-dev` to build, `liblmdb0` to run. Verified against 0.9.31; the
//! constants are stable across the 0.9 series.

mod db;
mod env;
mod error;
mod ffi;

pub use db::{Db, PutFlags};
pub use env::{Env, EnvFlags, EnvOptions};
pub use error::{Error, MdbCode, Result};

/// The `(major, minor, patch)` version of the `liblmdb` this process linked.
///
/// Worth checking against what any other library in the same process reports:
/// two different copies of LMDB over one environment is the failure mode this
/// crate avoids by not vendoring, and comparing versions is the cheapest way
/// to notice one has crept in. Debian's `python3-lmdb` links `liblmdb0` and
/// so agrees; a `pip install lmdb` bundles its own and will not.
///
/// ```
/// let (major, minor, _patch) = truenas_mdb::version();
/// assert_eq!((major, minor), (0, 9));
/// ```
pub fn version() -> (i32, i32, i32) {
    let (mut major, mut minor, mut patch) = (0, 0, 0);
    // SAFETY: three out-params LMDB writes to; the returned string is ignored.
    #[allow(unsafe_code)]
    unsafe {
        ffi::mdb_version(&mut major, &mut minor, &mut patch)
    };
    (major, minor, patch)
}
