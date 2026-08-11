// SPDX-License-Identifier: MIT
//! [`Error`], [`MdbCode`], and this crate's [`Result`].
//!
//! LMDB returns one `int` per call, drawn from two disjoint spaces: its own
//! codes in `-30799 ..= -30780`, and system `errno` values passed through from
//! a failing syscall. [`Error`] keeps them apart.

use crate::ffi;
use std::os::raw::c_int;
use std::{error, fmt, io};

/// This crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// An error from an LMDB operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// An LMDB condition.
    Mdb(MdbCode),
    /// A system `errno` from a failing syscall.
    Os(i32),
}

impl Error {
    /// Classify a raw non-zero return code.
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

    /// The LMDB code, or `None` for a system `errno`.
    ///
    /// ```
    /// # use truenas_mdb::{Error, MdbCode};
    /// assert_eq!(Error::Mdb(MdbCode::MapFull).as_mdb(), Some(MdbCode::MapFull));
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
            // No errno means "map is too small" or "not an LMDB file", so the
            // LMDB half keeps its message rather than being mapped onto a
            // misleading errno.
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

/// An LMDB error code. Values and messages are LMDB's own.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(i32)]
#[non_exhaustive]
pub enum MdbCode {
    /// Key already present. From [`Db::put_if_absent`](crate::Db::put_if_absent)
    /// only, which reports it as `Ok(false)`.
    KeyExist = ffi::MDB_KEYEXIST,
    /// No matching key. Reported as `Ok(None)`/`Ok(false)` by the read and
    /// delete operations; reaches a caller only from
    /// [`Db::open`](crate::Db::open).
    NotFound = ffi::MDB_NOTFOUND,
    /// Requested page not found; the database is damaged.
    PageNotFound = ffi::MDB_PAGE_NOTFOUND,
    /// A page was the wrong type; the database is damaged.
    Corrupted = ffi::MDB_CORRUPTED,
    /// Fatal environment error. Close and reopen the environment.
    Panic = ffi::MDB_PANIC,
    /// On-disk format does not match this build of LMDB.
    VersionMismatch = ffi::MDB_VERSION_MISMATCH,
    /// Not an LMDB file.
    Invalid = ffi::MDB_INVALID,
    /// Environment full: raise
    /// [`EnvOptions::map_size`](crate::EnvOptions::map_size).
    MapFull = ffi::MDB_MAP_FULL,
    /// Out of named databases: raise
    /// [`EnvOptions::max_dbs`](crate::EnvOptions::max_dbs).
    DbsFull = ffi::MDB_DBS_FULL,
    /// Out of reader slots: raise
    /// [`EnvOptions::max_readers`](crate::EnvOptions::max_readers), or find the
    /// reader holding a transaction open.
    ReadersFull = ffi::MDB_READERS_FULL,
    /// Out of thread-local storage keys; too many environments open.
    TlsFull = ffi::MDB_TLS_FULL,
    /// Write transaction has too many dirty pages.
    TxnFull = ffi::MDB_TXN_FULL,
    /// Cursor stack limit reached.
    CursorFull = ffi::MDB_CURSOR_FULL,
    /// A page has no more space.
    PageFull = ffi::MDB_PAGE_FULL,
    /// Another process grew the database past this process's `map_size`.
    MapResized = ffi::MDB_MAP_RESIZED,
    /// Operation and database incompatible, or database flags changed.
    Incompatible = ffi::MDB_INCOMPATIBLE,
    /// Invalid reuse of a reader lock-table slot.
    BadRslot = ffi::MDB_BAD_RSLOT,
    /// Transaction must abort, has a child, or is invalid.
    BadTxn = ffi::MDB_BAD_TXN,
    /// Unsupported key, database-name, or value size. Keys must be 1..=511
    /// bytes by default.
    BadValsize = ffi::MDB_BAD_VALSIZE,
    /// Database handle closed or changed unexpectedly.
    BadDbi = ffi::MDB_BAD_DBI,
}

impl MdbCode {
    /// The code for a raw return value, or `None` if it is not one of LMDB's
    /// own (success, or a system `errno`).
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

    /// LMDB's message, e.g. `"MDB_MAP_FULL: Environment mapsize limit
    /// reached"`. Identical to `mdb_strerror`.
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

    /// The upstream symbol, e.g. `"MDB_MAP_FULL"`.
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

/// Turn a raw return code into a `Result`.
pub(crate) fn check(rc: c_int) -> Result<()> {
    if rc == ffi::MDB_SUCCESS {
        Ok(())
    } else {
        Err(Error::from_raw(rc))
    }
}

#[cfg(test)]
mod tests {
    //! One test calls `mdb_strerror`, so this module lifts the crate's
    //! `deny(unsafe_code)`. The library itself needs none.
    #![allow(unsafe_code)]

    use super::*;

    /// Every variant, for the exhaustiveness checks below.
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
        // `message()` is hand-written so error rendering needs no FFI. This
        // catches it drifting from the library actually linked.
        for code in ALL {
            // SAFETY: `mdb_strerror` returns a valid static NUL-terminated
            // string for any code.
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
    fn the_code_block_is_contiguous_and_complete() {
        for code in ALL {
            assert_eq!(MdbCode::from_raw(code.raw()), Some(code));
        }
        let mut raws: Vec<i32> = ALL.iter().map(|c| c.raw()).collect();
        raws.sort_unstable();
        assert_eq!(raws.first(), Some(&-30799));
        assert_eq!(raws.last(), Some(&-30780));
        assert_eq!(raws.len(), 20);
        assert!(raws.windows(2).all(|w| w[1] == w[0] + 1), "{raws:?}");
    }

    #[test]
    fn raw_values_are_lmdbs_own() {
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
    fn codes_outside_the_block_are_system_errnos() {
        assert_eq!(MdbCode::from_raw(-30800), None);
        assert_eq!(MdbCode::from_raw(-30779), None);
        assert_eq!(MdbCode::from_raw(libc::ENOENT), None);

        assert_eq!(Error::from_raw(libc::ENOENT), Error::Os(libc::ENOENT));
        assert_eq!(Error::from_raw(-30792), Error::Mdb(MdbCode::MapFull));
        assert_eq!(Error::Os(libc::ENOENT).raw(), libc::ENOENT);
        assert_eq!(Error::Mdb(MdbCode::MapFull).raw(), -30792);
    }

    #[test]
    fn check_maps_success_and_failure() {
        assert!(check(0).is_ok());
        assert_eq!(check(-30792), Err(Error::Mdb(MdbCode::MapFull)));
        assert_eq!(check(libc::EACCES), Err(Error::Os(libc::EACCES)));
    }

    #[test]
    fn names_are_the_message_prefix() {
        assert_eq!(MdbCode::MapFull.name(), "MDB_MAP_FULL");
        for code in ALL {
            assert!(code.name().starts_with("MDB_"));
            assert!(!code.name().contains(' '));
            assert!(code.message().starts_with(code.name()));
        }
    }

    #[test]
    fn display_renders_both_halves() {
        assert_eq!(
            Error::Mdb(MdbCode::Invalid).to_string(),
            "MDB_INVALID: File is not an LMDB file"
        );
        assert_eq!(
            MdbCode::Invalid.to_string(),
            "MDB_INVALID: File is not an LMDB file"
        );
        assert_eq!(
            Error::Os(libc::ENOENT).to_string(),
            io::Error::from_raw_os_error(libc::ENOENT).to_string()
        );
    }

    #[test]
    fn io_error_conversion_keeps_the_two_spaces_apart() {
        let os: io::Error = Error::Os(libc::ENOENT).into();
        assert_eq!(os.raw_os_error(), Some(libc::ENOENT));

        // An LMDB code has no errno, so none is invented.
        let mdb: io::Error = Error::Mdb(MdbCode::MapFull).into();
        assert_eq!(mdb.raw_os_error(), None);
        assert!(mdb.to_string().contains("MDB_MAP_FULL"));

        assert_eq!(
            io::Error::from(Error::Mdb(MdbCode::NotFound)).kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            io::Error::from(Error::Mdb(MdbCode::KeyExist)).kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn errors_expose_a_source_chain_entry_point() {
        // Both types implement std::error::Error, so `?` into a Box<dyn Error>
        // and anyhow-style chaining work.
        fn boxed(e: Error) -> Box<dyn error::Error> {
            Box::new(e)
        }
        assert!(
            boxed(Error::Mdb(MdbCode::Panic))
                .to_string()
                .contains("MDB_PANIC")
        );
    }
}
