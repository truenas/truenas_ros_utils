//! [`Error`], the LMDB-specific [`MdbCode`], and this crate's [`Result`].
//!
//! LMDB returns one `int` from every call, and that `int` is drawn from two
//! disjoint spaces: its own codes in the `-30799 ..= -30780` range, and system
//! `errno` values passed straight through from whatever syscall failed
//! underneath. [`Error`] keeps them apart so a caller can match on the LMDB
//! condition it cares about without decoding a magic number.
//!
//! [`MdbCode`]'s variants and their messages are LMDB's own, so a log line here
//! matches one from the C or from Python's `lmdb` module. The set is the same
//! as the `MDBCode` IntEnum that `truenas_zfsrewrited` exposes.

use crate::ffi;
use std::os::raw::c_int;
use std::{error, fmt, io};

/// The result type used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// An error from an LMDB operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// An LMDB-specific condition (the `-3079x` range).
    Mdb(MdbCode),
    /// A system `errno`, passed through from a failing syscall — most often
    /// `ENOENT`, `EACCES`, or `ENOSPC` while opening or growing the files.
    Os(i32),
}

impl Error {
    /// Classify a raw LMDB return code. Never call this with `MDB_SUCCESS`;
    /// use [`check`] instead, which turns `0` into `Ok`.
    pub(crate) fn from_raw(rc: c_int) -> Error {
        match MdbCode::from_raw(rc) {
            Some(code) => Error::Mdb(code),
            None => Error::Os(rc),
        }
    }

    /// The raw code LMDB returned.
    pub fn raw(self) -> i32 {
        match self {
            Error::Mdb(code) => code.raw(),
            Error::Os(e) => e,
        }
    }

    /// The LMDB-specific code, if this is one — `None` for a system `errno`.
    ///
    /// ```
    /// # use truenas_mdb::{Error, MdbCode};
    /// let e = Error::Mdb(MdbCode::MapFull);
    /// assert_eq!(e.as_mdb(), Some(MdbCode::MapFull));
    /// assert_eq!(Error::Os(libc::ENOENT).as_mdb(), None);
    /// ```
    pub fn as_mdb(self) -> Option<MdbCode> {
        match self {
            Error::Mdb(code) => Some(code),
            Error::Os(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Mdb(code) => f.write_str(code.message()),
            Error::Os(e) => write!(f, "{}", io::Error::from_raw_os_error(*e)),
        }
    }
}

impl error::Error for Error {}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        match err {
            Error::Os(e) => io::Error::from_raw_os_error(e),
            // No errno describes "the mapsize is too small" or "this file is
            // not an LMDB file", so the LMDB half keeps its message and lands
            // under a kind rather than being flattened onto a wrong errno.
            Error::Mdb(MdbCode::NotFound) => {
                io::Error::new(io::ErrorKind::NotFound, err)
            }
            Error::Mdb(MdbCode::KeyExist) => {
                io::Error::new(io::ErrorKind::AlreadyExists, err)
            }
            other => io::Error::other(other),
        }
    }
}

/// An LMDB-specific error code.
///
/// The variants, their values, and their messages are LMDB's own (`lmdb.h`
/// and `mdb_strerror`), so they line up with the `MDBCode` enum that
/// `truenas_zfsrewrited` exposes to Python.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(i32)]
#[non_exhaustive]
pub enum MdbCode {
    /// The key (or key/data pair) is already present. Returned by a `put`
    /// with [`PutFlags::NO_OVERWRITE`](crate::PutFlags::NO_OVERWRITE).
    KeyExist = ffi::MDB_KEYEXIST,
    /// No matching key. This crate reports absence as `Ok(None)` or
    /// `Ok(false)`, so a caller normally never sees this variant.
    NotFound = ffi::MDB_NOTFOUND,
    /// A requested page was not found — the database is damaged.
    PageNotFound = ffi::MDB_PAGE_NOTFOUND,
    /// A page was the wrong type — the database is damaged.
    Corrupted = ffi::MDB_CORRUPTED,
    /// A meta-page update failed, or the environment hit a fatal error. The
    /// environment must be closed and reopened.
    Panic = ffi::MDB_PANIC,
    /// The on-disk format does not match this build of LMDB.
    VersionMismatch = ffi::MDB_VERSION_MISMATCH,
    /// The file is not an LMDB database.
    Invalid = ffi::MDB_INVALID,
    /// The environment is full: raise
    /// [`EnvOptions::map_size`](crate::EnvOptions::map_size). Remember it is a
    /// contract shared with every other process on the environment.
    MapFull = ffi::MDB_MAP_FULL,
    /// Out of named databases: raise
    /// [`EnvOptions::max_dbs`](crate::EnvOptions::max_dbs).
    DbsFull = ffi::MDB_DBS_FULL,
    /// Out of reader slots: raise
    /// [`EnvOptions::max_readers`](crate::EnvOptions::max_readers), or find
    /// the reader that is not finishing its transactions.
    ReadersFull = ffi::MDB_READERS_FULL,
    /// Out of thread-local storage keys — too many environments open.
    TlsFull = ffi::MDB_TLS_FULL,
    /// The write transaction has too many dirty pages; it is too big.
    TxnFull = ffi::MDB_TXN_FULL,
    /// Internal: the cursor stack limit was reached.
    CursorFull = ffi::MDB_CURSOR_FULL,
    /// Internal: a page has no more space.
    PageFull = ffi::MDB_PAGE_FULL,
    /// Another process grew the database past this process's `map_size`.
    MapResized = ffi::MDB_MAP_RESIZED,
    /// The operation and the database are incompatible, or its flags changed.
    Incompatible = ffi::MDB_INCOMPATIBLE,
    /// A reader lock-table slot was reused invalidly.
    BadRslot = ffi::MDB_BAD_RSLOT,
    /// The transaction must abort, has a child, or is invalid.
    BadTxn = ffi::MDB_BAD_TXN,
    /// An unsupported key, database-name, or value size. Keys are capped at
    /// 511 bytes by default, and a zero-length key is rejected.
    BadValsize = ffi::MDB_BAD_VALSIZE,
    /// The database handle was closed or changed unexpectedly.
    BadDbi = ffi::MDB_BAD_DBI,
}

impl MdbCode {
    /// The `MdbCode` for a raw LMDB return code, or `None` if it is not one of
    /// LMDB's own (i.e. it is a system `errno` or success).
    pub const fn from_raw(rc: i32) -> Option<MdbCode> {
        Some(match rc {
            ffi::MDB_KEYEXIST => MdbCode::KeyExist,
            ffi::MDB_NOTFOUND => MdbCode::NotFound,
            ffi::MDB_PAGE_NOTFOUND => MdbCode::PageNotFound,
            ffi::MDB_CORRUPTED => MdbCode::Corrupted,
            ffi::MDB_PANIC => MdbCode::Panic,
            ffi::MDB_VERSION_MISMATCH => MdbCode::VersionMismatch,
            ffi::MDB_INVALID => MdbCode::Invalid,
            ffi::MDB_MAP_FULL => MdbCode::MapFull,
            ffi::MDB_DBS_FULL => MdbCode::DbsFull,
            ffi::MDB_READERS_FULL => MdbCode::ReadersFull,
            ffi::MDB_TLS_FULL => MdbCode::TlsFull,
            ffi::MDB_TXN_FULL => MdbCode::TxnFull,
            ffi::MDB_CURSOR_FULL => MdbCode::CursorFull,
            ffi::MDB_PAGE_FULL => MdbCode::PageFull,
            ffi::MDB_MAP_RESIZED => MdbCode::MapResized,
            ffi::MDB_INCOMPATIBLE => MdbCode::Incompatible,
            ffi::MDB_BAD_RSLOT => MdbCode::BadRslot,
            ffi::MDB_BAD_TXN => MdbCode::BadTxn,
            ffi::MDB_BAD_VALSIZE => MdbCode::BadValsize,
            ffi::MDB_BAD_DBI => MdbCode::BadDbi,
            _ => return None,
        })
    }

    /// The raw value LMDB uses for this code.
    pub const fn raw(self) -> i32 {
        self as i32
    }

    /// LMDB's own message, e.g.
    /// `"MDB_MAP_FULL: Environment mapsize limit reached"` — byte-identical to
    /// what `mdb_strerror` returns, so logs match the C and Python consumers.
    pub const fn message(self) -> &'static str {
        match self {
            MdbCode::KeyExist => "MDB_KEYEXIST: Key/data pair already exists",
            MdbCode::NotFound => {
                "MDB_NOTFOUND: No matching key/data pair found"
            }
            MdbCode::PageNotFound => {
                "MDB_PAGE_NOTFOUND: Requested page not found"
            }
            MdbCode::Corrupted => "MDB_CORRUPTED: Located page was wrong type",
            MdbCode::Panic => {
                "MDB_PANIC: Update of meta page failed or environment had \
                 fatal error"
            }
            MdbCode::VersionMismatch => {
                "MDB_VERSION_MISMATCH: Database environment version mismatch"
            }
            MdbCode::Invalid => "MDB_INVALID: File is not an LMDB file",
            MdbCode::MapFull => {
                "MDB_MAP_FULL: Environment mapsize limit reached"
            }
            MdbCode::DbsFull => {
                "MDB_DBS_FULL: Environment maxdbs limit reached"
            }
            MdbCode::ReadersFull => {
                "MDB_READERS_FULL: Environment maxreaders limit reached"
            }
            MdbCode::TlsFull => {
                "MDB_TLS_FULL: Thread-local storage keys full - too many \
                 environments open"
            }
            MdbCode::TxnFull => {
                "MDB_TXN_FULL: Transaction has too many dirty pages - \
                 transaction too big"
            }
            MdbCode::CursorFull => {
                "MDB_CURSOR_FULL: Internal error - cursor stack limit reached"
            }
            MdbCode::PageFull => {
                "MDB_PAGE_FULL: Internal error - page has no more space"
            }
            MdbCode::MapResized => {
                "MDB_MAP_RESIZED: Database contents grew beyond environment \
                 mapsize"
            }
            MdbCode::Incompatible => {
                "MDB_INCOMPATIBLE: Operation and DB incompatible, or DB flags \
                 changed"
            }
            MdbCode::BadRslot => {
                "MDB_BAD_RSLOT: Invalid reuse of reader locktable slot"
            }
            MdbCode::BadTxn => {
                "MDB_BAD_TXN: Transaction must abort, has a child, or is \
                 invalid"
            }
            MdbCode::BadValsize => {
                "MDB_BAD_VALSIZE: Unsupported size of key/DB name/data, or \
                 wrong DUPFIXED size"
            }
            MdbCode::BadDbi => {
                "MDB_BAD_DBI: The specified DBI handle was closed/changed \
                 unexpectedly"
            }
        }
    }

    /// The upstream symbol, e.g. `"MDB_MAP_FULL"` — the same spelling as the
    /// `MDBCode` IntEnum member in `truenas_zfsrewrited`.
    ///
    /// ```
    /// # use truenas_mdb::MdbCode;
    /// assert_eq!(MdbCode::MapFull.name(), "MDB_MAP_FULL");
    /// ```
    pub fn name(self) -> &'static str {
        let msg = self.message();
        msg.split_once(':').map_or(msg, |(name, _)| name)
    }
}

impl fmt::Display for MdbCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl error::Error for MdbCode {}

/// Turn a raw LMDB return code into a `Result`.
pub(crate) fn check(rc: c_int) -> Result<()> {
    if rc == ffi::MDB_SUCCESS {
        Ok(())
    } else {
        Err(Error::from_raw(rc))
    }
}

#[cfg(test)]
mod tests {
    //! One test here calls `mdb_strerror`, so this module lifts the crate's
    //! `deny(unsafe_code)` — the library itself needs none of it.
    #![allow(unsafe_code)]

    use super::*;

    /// Every variant, for the exhaustiveness of the table checks below.
    const ALL: [MdbCode; 20] = [
        MdbCode::KeyExist,
        MdbCode::NotFound,
        MdbCode::PageNotFound,
        MdbCode::Corrupted,
        MdbCode::Panic,
        MdbCode::VersionMismatch,
        MdbCode::Invalid,
        MdbCode::MapFull,
        MdbCode::DbsFull,
        MdbCode::ReadersFull,
        MdbCode::TlsFull,
        MdbCode::TxnFull,
        MdbCode::CursorFull,
        MdbCode::PageFull,
        MdbCode::MapResized,
        MdbCode::Incompatible,
        MdbCode::BadRslot,
        MdbCode::BadTxn,
        MdbCode::BadValsize,
        MdbCode::BadDbi,
    ];

    #[test]
    fn messages_match_the_linked_liblmdb() {
        // `message()` is hand-written so the crate needs no FFI to render an
        // error. That is only safe if it agrees with the library actually
        // linked — this is the test that catches a version bump changing the
        // wording underneath us.
        for code in ALL {
            // SAFETY: `mdb_strerror` returns a valid static NUL-terminated
            // string for any code, and never null for one of LMDB's own.
            let ptr = unsafe { ffi::mdb_strerror(code.raw()) };
            assert!(!ptr.is_null(), "{}", code.name());
            // SAFETY: a valid NUL-terminated static C string, borrowed only
            // for this comparison.
            let upstream = unsafe { std::ffi::CStr::from_ptr(ptr) };
            assert_eq!(
                code.message(),
                upstream.to_str().unwrap(),
                "{} drifted from liblmdb",
                code.name()
            );
        }
    }

    #[test]
    fn every_variant_is_reachable_from_its_raw_value() {
        for code in ALL {
            assert_eq!(MdbCode::from_raw(code.raw()), Some(code));
        }
        // The variants cover the whole documented block with no holes.
        let mut raws: Vec<i32> = ALL.iter().map(|c| c.raw()).collect();
        raws.sort_unstable();
        assert_eq!(raws.first(), Some(&-30799));
        assert_eq!(raws.last(), Some(&-30780));
        assert_eq!(raws.len(), 20, "the block is 20 codes wide");
        assert!(
            raws.windows(2).all(|w| w[1] == w[0] + 1),
            "no gaps: {raws:?}"
        );
    }

    #[test]
    fn codes_round_trip_through_their_raw_values() {
        // Every variant maps back to itself, and the values are the ones in
        // lmdb.h rather than whatever the enum's declaration order implies.
        for (code, raw) in [
            (MdbCode::KeyExist, -30799),
            (MdbCode::NotFound, -30798),
            (MdbCode::MapFull, -30792),
            (MdbCode::ReadersFull, -30790),
            (MdbCode::BadDbi, -30780),
        ] {
            assert_eq!(code.raw(), raw);
            assert_eq!(MdbCode::from_raw(raw), Some(code));
        }
    }

    #[test]
    fn non_mdb_codes_are_system_errnos() {
        // Either side of the LMDB block, and a plausible passed-through errno.
        assert_eq!(MdbCode::from_raw(-30800), None);
        assert_eq!(MdbCode::from_raw(-30779), None);
        assert_eq!(MdbCode::from_raw(libc::ENOENT), None);

        assert_eq!(Error::from_raw(libc::ENOENT), Error::Os(libc::ENOENT));
        assert_eq!(Error::from_raw(-30792), Error::Mdb(MdbCode::MapFull));
    }

    #[test]
    fn success_is_ok_and_everything_else_is_not() {
        assert!(check(0).is_ok());
        assert_eq!(check(-30792), Err(Error::Mdb(MdbCode::MapFull)));
        assert_eq!(check(libc::EACCES), Err(Error::Os(libc::EACCES)));
    }

    #[test]
    fn names_and_messages_are_lmdbs_own() {
        assert_eq!(MdbCode::MapFull.name(), "MDB_MAP_FULL");
        assert_eq!(
            MdbCode::MapFull.message(),
            "MDB_MAP_FULL: Environment mapsize limit reached"
        );
        // Every message is "MDB_NAME: text", so `name` never falls back.
        for code in [MdbCode::KeyExist, MdbCode::Panic, MdbCode::BadValsize] {
            assert!(code.name().starts_with("MDB_"));
            assert!(!code.name().contains(' '));
        }
    }

    #[test]
    fn display_and_io_error_keep_the_two_spaces_apart() {
        assert_eq!(
            Error::Mdb(MdbCode::Invalid).to_string(),
            "MDB_INVALID: File is not an LMDB file"
        );
        let os: io::Error = Error::Os(libc::ENOENT).into();
        assert_eq!(os.raw_os_error(), Some(libc::ENOENT));
        // An LMDB code has no errno, so it must not invent one.
        let mdb: io::Error = Error::Mdb(MdbCode::MapFull).into();
        assert_eq!(mdb.raw_os_error(), None);
        assert_eq!(
            io::Error::from(Error::Mdb(MdbCode::NotFound)).kind(),
            io::ErrorKind::NotFound
        );
    }
}
