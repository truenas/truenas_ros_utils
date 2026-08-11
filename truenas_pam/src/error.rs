// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Error`], [`PamCode`], and this crate's [`Result`].
//!
//! libpam returns one `int` per call, drawn from the contiguous block `0..32`
//! that the standard defines. Nothing outside that block is meaningful, so
//! [`Error`] keeps such a value apart rather than guessing at it. The two
//! remaining variants are this crate's own: a step that ran out of time, and
//! an argument that cannot cross the C boundary at all.

use crate::ffi;
use std::os::raw::c_int;
use std::{error, fmt, io};

/// This crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// An error from a PAM operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// A condition libpam reported. Never [`PamCode::Success`].
    Pam(PamCode),
    /// A return code outside the block the standard defines.
    Unknown(i32),
    /// A system `errno` from a syscall this crate made on its own account,
    /// not through libpam.
    Os(i32),
    /// A module sent a message style this crate does not implement. The four
    /// styles of [`MsgStyle`](crate::MsgStyle) are the whole of it; a binary
    /// or radio prompt needs a conversation this crate does not provide, and
    /// answering it with nothing would be wrong.
    UnknownMsgStyle(i32),
    /// A conversation step did not finish within its deadline.
    Timeout,
    /// An argument held an interior NUL, so it has no C string form.
    NulByte,
    /// An environment variable name is empty or holds a `=`.
    InvalidName,
    /// A string libpam returned is not UTF-8.
    NotUtf8,
    /// An operation was asked for at a point in the sequence where it has no
    /// meaning: answering a conversation that is not waiting, or opening a
    /// session before authenticating.
    OutOfSequence,
}

impl Error {
    /// Classify a raw non-zero return code.
    pub(crate) fn from_raw(rc: c_int) -> Error {
        match PamCode::from_raw(rc) {
            Some(code) => Error::Pam(code),
            None => Error::Unknown(rc),
        }
    }

    /// The raw code libpam returned, or `None` for an error this crate raised
    /// on its own.
    ///
    /// ```
    /// # use truenas_pam::{Error, PamCode};
    /// assert_eq!(Error::Pam(PamCode::AuthErr).raw(), Some(7));
    /// assert_eq!(Error::Timeout.raw(), None);
    /// ```
    pub fn raw(self) -> Option<i32> {
        match self {
            Error::Pam(code) => Some(code.raw()),
            Error::Unknown(rc) => Some(rc),
            _ => None,
        }
    }

    /// The PAM code, or `None` for anything else.
    ///
    /// ```
    /// # use truenas_pam::{Error, PamCode};
    /// assert_eq!(Error::Pam(PamCode::MaxTries).as_pam(), Some(PamCode::MaxTries));
    /// assert_eq!(Error::Unknown(-1).as_pam(), None);
    /// ```
    pub fn as_pam(self) -> Option<PamCode> {
        match self {
            Error::Pam(code) => Some(code),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Pam(code) => f.write_str(code.message()),
            Error::Unknown(rc) => {
                write!(f, "PAM return code outside the defined block: {rc}")
            }
            Error::Os(e) => write!(f, "{}", io::Error::from_raw_os_error(*e)),
            Error::UnknownMsgStyle(style) => {
                write!(f, "Unsupported conversation message style: {style}")
            }
            Error::Timeout => {
                f.write_str("Timed out waiting for the PAM stack")
            }
            Error::NulByte => {
                f.write_str("Argument contains an interior NUL byte")
            }
            Error::InvalidName => {
                f.write_str("Environment variable name is empty or holds '='")
            }
            Error::NotUtf8 => f.write_str("PAM returned a non-UTF-8 string"),
            Error::OutOfSequence => {
                f.write_str("Operation is out of sequence for this transaction")
            }
        }
    }
}

impl error::Error for Error {}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        match err {
            Error::Os(e) => io::Error::from_raw_os_error(e),
            Error::Timeout => io::Error::new(io::ErrorKind::TimedOut, err),
            Error::NulByte | Error::InvalidName => {
                io::Error::new(io::ErrorKind::InvalidInput, err)
            }
            Error::NotUtf8 | Error::UnknownMsgStyle(_) => {
                io::Error::new(io::ErrorKind::InvalidData, err)
            }
            Error::OutOfSequence => {
                io::Error::new(io::ErrorKind::InvalidInput, err)
            }
            // Only the codes with one unambiguous kind are mapped. The rest
            // keep their own message rather than being flattened onto a
            // misleading one.
            Error::Pam(
                PamCode::PermDenied
                | PamCode::AuthErr
                | PamCode::CredInsufficient,
            ) => io::Error::new(io::ErrorKind::PermissionDenied, err),
            Error::Pam(PamCode::UserUnknown) => {
                io::Error::new(io::ErrorKind::NotFound, err)
            }
            Error::Pam(PamCode::BufErr) => {
                io::Error::new(io::ErrorKind::OutOfMemory, err)
            }
            other => io::Error::other(other),
        }
    }
}

/// A PAM return code. Values and messages are libpam's own.
///
/// Not every code is a fault. [`Ignore`](PamCode::Ignore) and
/// [`NewAuthtokReqd`](PamCode::NewAuthtokReqd) in particular are outcomes an
/// application acts on; this crate reports each one as it comes and never
/// reinterprets it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(i32)]
#[non_exhaustive]
pub enum PamCode {
    /// The operation succeeded. Never carried by [`Error`].
    Success = ffi::PAM_SUCCESS,
    /// A module could not be loaded.
    OpenErr = ffi::PAM_OPEN_ERR,
    /// A module lacked a symbol the stack needed.
    SymbolErr = ffi::PAM_SYMBOL_ERR,
    /// A module reported an internal fault.
    ServiceErr = ffi::PAM_SERVICE_ERR,
    /// A system call a module made failed.
    SystemErr = ffi::PAM_SYSTEM_ERR,
    /// Allocation failed.
    BufErr = ffi::PAM_BUF_ERR,
    /// The stack refused the request outright.
    PermDenied = ffi::PAM_PERM_DENIED,
    /// The credentials presented were wrong.
    AuthErr = ffi::PAM_AUTH_ERR,
    /// The application lacks the privilege to read the authentication data.
    CredInsufficient = ffi::PAM_CRED_INSUFFICIENT,
    /// The authenticating service could not be reached.
    AuthinfoUnavail = ffi::PAM_AUTHINFO_UNAVAIL,
    /// No such user, as far as the stack is concerned.
    UserUnknown = ffi::PAM_USER_UNKNOWN,
    /// The retry limit was reached.
    MaxTries = ffi::PAM_MAXTRIES,
    /// Authentication succeeded but the token must be changed before the
    /// account can be used. Run [`Transaction::chauthtok`](
    /// crate::Transaction::chauthtok).
    NewAuthtokReqd = ffi::PAM_NEW_AUTHTOK_REQD,
    /// The account has expired.
    AcctExpired = ffi::PAM_ACCT_EXPIRED,
    /// A session entry could not be made or removed.
    SessionErr = ffi::PAM_SESSION_ERR,
    /// User credentials could not be retrieved.
    CredUnavail = ffi::PAM_CRED_UNAVAIL,
    /// User credentials have expired.
    CredExpired = ffi::PAM_CRED_EXPIRED,
    /// Setting user credentials failed.
    CredErr = ffi::PAM_CRED_ERR,
    /// A module asked for data it had never stored.
    NoModuleData = ffi::PAM_NO_MODULE_DATA,
    /// The conversation failed. Also what this crate returns to the stack when
    /// a [`Conversation`](crate::Conversation) errors, panics, or answers with
    /// the wrong number of responses.
    ConvErr = ffi::PAM_CONV_ERR,
    /// Manipulating the authentication token failed.
    AuthtokErr = ffi::PAM_AUTHTOK_ERR,
    /// The old authentication token could not be recovered.
    AuthtokRecoveryErr = ffi::PAM_AUTHTOK_RECOVERY_ERR,
    /// The authentication token is locked by another process; retry later.
    AuthtokLockBusy = ffi::PAM_AUTHTOK_LOCK_BUSY,
    /// Token aging is disabled for this account.
    AuthtokDisableAging = ffi::PAM_AUTHTOK_DISABLE_AGING,
    /// The password service's preliminary check failed; retry later.
    TryAgain = ffi::PAM_TRY_AGAIN,
    /// The module declined to take part. The dispatcher absorbs it: a stack
    /// in which nothing reaches a decision returns
    /// [`PermDenied`](PamCode::PermDenied) rather than this.
    Ignore = ffi::PAM_IGNORE,
    /// The stack asked to be abandoned. Finish the transaction.
    Abort = ffi::PAM_ABORT,
    /// The authentication token has expired.
    AuthtokExpired = ffi::PAM_AUTHTOK_EXPIRED,
    /// No module by that name.
    ModuleUnknown = ffi::PAM_MODULE_UNKNOWN,
    /// The item type is not one this handle accepts.
    BadItem = ffi::PAM_BAD_ITEM,
    /// The conversation is event driven and has not yet finished.
    ConvAgain = ffi::PAM_CONV_AGAIN,
    /// The stack needs the same call again to make further progress.
    Incomplete = ffi::PAM_INCOMPLETE,
}

impl PamCode {
    /// The code for a raw return value, or `None` if it is outside the block
    /// the standard defines.
    pub const fn from_raw(rc: i32) -> Option<PamCode> {
        Some(match rc {
            ffi::PAM_SUCCESS => PamCode::Success,
            ffi::PAM_OPEN_ERR => PamCode::OpenErr,
            ffi::PAM_SYMBOL_ERR => PamCode::SymbolErr,
            ffi::PAM_SERVICE_ERR => PamCode::ServiceErr,
            ffi::PAM_SYSTEM_ERR => PamCode::SystemErr,
            ffi::PAM_BUF_ERR => PamCode::BufErr,
            ffi::PAM_PERM_DENIED => PamCode::PermDenied,
            ffi::PAM_AUTH_ERR => PamCode::AuthErr,
            ffi::PAM_CRED_INSUFFICIENT => PamCode::CredInsufficient,
            ffi::PAM_AUTHINFO_UNAVAIL => PamCode::AuthinfoUnavail,
            ffi::PAM_USER_UNKNOWN => PamCode::UserUnknown,
            ffi::PAM_MAXTRIES => PamCode::MaxTries,
            ffi::PAM_NEW_AUTHTOK_REQD => PamCode::NewAuthtokReqd,
            ffi::PAM_ACCT_EXPIRED => PamCode::AcctExpired,
            ffi::PAM_SESSION_ERR => PamCode::SessionErr,
            ffi::PAM_CRED_UNAVAIL => PamCode::CredUnavail,
            ffi::PAM_CRED_EXPIRED => PamCode::CredExpired,
            ffi::PAM_CRED_ERR => PamCode::CredErr,
            ffi::PAM_NO_MODULE_DATA => PamCode::NoModuleData,
            ffi::PAM_CONV_ERR => PamCode::ConvErr,
            ffi::PAM_AUTHTOK_ERR => PamCode::AuthtokErr,
            ffi::PAM_AUTHTOK_RECOVERY_ERR => PamCode::AuthtokRecoveryErr,
            ffi::PAM_AUTHTOK_LOCK_BUSY => PamCode::AuthtokLockBusy,
            ffi::PAM_AUTHTOK_DISABLE_AGING => PamCode::AuthtokDisableAging,
            ffi::PAM_TRY_AGAIN => PamCode::TryAgain,
            ffi::PAM_IGNORE => PamCode::Ignore,
            ffi::PAM_ABORT => PamCode::Abort,
            ffi::PAM_AUTHTOK_EXPIRED => PamCode::AuthtokExpired,
            ffi::PAM_MODULE_UNKNOWN => PamCode::ModuleUnknown,
            ffi::PAM_BAD_ITEM => PamCode::BadItem,
            ffi::PAM_CONV_AGAIN => PamCode::ConvAgain,
            ffi::PAM_INCOMPLETE => PamCode::Incomplete,
            _ => return None,
        })
    }

    /// The raw value libpam uses for this code.
    pub const fn raw(self) -> i32 {
        self as i32
    }

    /// The upstream symbol and libpam's message for it. One table, because
    /// PAM's messages carry no symbol prefix to recover the name from.
    const fn entry(self) -> (&'static str, &'static str) {
        match self {
            PamCode::Success => ("PAM_SUCCESS", "Success"),
            PamCode::OpenErr => ("PAM_OPEN_ERR", "Failed to load module"),
            PamCode::SymbolErr => ("PAM_SYMBOL_ERR", "Symbol not found"),
            PamCode::ServiceErr => {
                ("PAM_SERVICE_ERR", "Error in service module")
            }
            PamCode::SystemErr => ("PAM_SYSTEM_ERR", "System error"),
            PamCode::BufErr => ("PAM_BUF_ERR", "Memory buffer error"),
            PamCode::PermDenied => ("PAM_PERM_DENIED", "Permission denied"),
            PamCode::AuthErr => ("PAM_AUTH_ERR", "Authentication failure"),
            PamCode::CredInsufficient => (
                "PAM_CRED_INSUFFICIENT",
                "Insufficient credentials to access authentication data",
            ),
            PamCode::AuthinfoUnavail => (
                "PAM_AUTHINFO_UNAVAIL",
                "Authentication service cannot retrieve authentication info",
            ),
            PamCode::UserUnknown => (
                "PAM_USER_UNKNOWN",
                "User not known to the underlying authentication module",
            ),
            PamCode::MaxTries => (
                "PAM_MAXTRIES",
                "Have exhausted maximum number of retries for service",
            ),
            PamCode::NewAuthtokReqd => (
                "PAM_NEW_AUTHTOK_REQD",
                "Authentication token is no longer valid; new one required",
            ),
            PamCode::AcctExpired => {
                ("PAM_ACCT_EXPIRED", "User account has expired")
            }
            PamCode::SessionErr => (
                "PAM_SESSION_ERR",
                "Cannot make/remove an entry for the specified session",
            ),
            PamCode::CredUnavail => (
                "PAM_CRED_UNAVAIL",
                "Authentication service cannot retrieve user credentials",
            ),
            PamCode::CredExpired => {
                ("PAM_CRED_EXPIRED", "User credentials expired")
            }
            PamCode::CredErr => {
                ("PAM_CRED_ERR", "Failure setting user credentials")
            }
            PamCode::NoModuleData => {
                ("PAM_NO_MODULE_DATA", "No module specific data is present")
            }
            PamCode::ConvErr => ("PAM_CONV_ERR", "Conversation error"),
            PamCode::AuthtokErr => {
                ("PAM_AUTHTOK_ERR", "Authentication token manipulation error")
            }
            PamCode::AuthtokRecoveryErr => (
                "PAM_AUTHTOK_RECOVERY_ERR",
                "Authentication information cannot be recovered",
            ),
            PamCode::AuthtokLockBusy => {
                ("PAM_AUTHTOK_LOCK_BUSY", "Authentication token lock busy")
            }
            PamCode::AuthtokDisableAging => (
                "PAM_AUTHTOK_DISABLE_AGING",
                "Authentication token aging disabled",
            ),
            PamCode::TryAgain => (
                "PAM_TRY_AGAIN",
                "Failed preliminary check by password service",
            ),
            PamCode::Ignore => (
                "PAM_IGNORE",
                "The return value should be ignored by PAM dispatch",
            ),
            PamCode::Abort => ("PAM_ABORT", "Critical error - immediate abort"),
            PamCode::AuthtokExpired => {
                ("PAM_AUTHTOK_EXPIRED", "Authentication token expired")
            }
            PamCode::ModuleUnknown => {
                ("PAM_MODULE_UNKNOWN", "Module is unknown")
            }
            PamCode::BadItem => {
                ("PAM_BAD_ITEM", "Bad item passed to pam_*_item()")
            }
            PamCode::ConvAgain => {
                ("PAM_CONV_AGAIN", "Conversation is waiting for event")
            }
            PamCode::Incomplete => {
                ("PAM_INCOMPLETE", "Application needs to call libpam again")
            }
        }
    }

    /// The upstream symbol, e.g. `"PAM_AUTH_ERR"`.
    ///
    /// ```
    /// # use truenas_pam::PamCode;
    /// assert_eq!(PamCode::AuthErr.name(), "PAM_AUTH_ERR");
    /// ```
    pub const fn name(self) -> &'static str {
        self.entry().0
    }

    /// libpam's message, e.g. `"Authentication failure"`. Identical to
    /// `pam_strerror` in the `C` locale.
    ///
    /// ```
    /// # use truenas_pam::PamCode;
    /// assert_eq!(PamCode::AuthErr.message(), "Authentication failure");
    /// ```
    pub const fn message(self) -> &'static str {
        self.entry().1
    }
}

impl fmt::Display for PamCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl error::Error for PamCode {}

/// Turn a raw return code into a `Result`.
pub(crate) fn check(rc: c_int) -> Result<()> {
    if rc == ffi::PAM_SUCCESS {
        Ok(())
    } else {
        Err(Error::from_raw(rc))
    }
}

#[cfg(test)]
mod tests {
    //! One test calls `pam_strerror`, so this module lifts the crate's
    //! `deny(unsafe_code)`. The library itself needs none.
    #![allow(unsafe_code)]

    use super::*;
    use std::ffi::CStr;

    /// Every variant, for the exhaustiveness checks below.
    const ALL: [PamCode; 32] = [
        PamCode::Success,
        PamCode::OpenErr,
        PamCode::SymbolErr,
        PamCode::ServiceErr,
        PamCode::SystemErr,
        PamCode::BufErr,
        PamCode::PermDenied,
        PamCode::AuthErr,
        PamCode::CredInsufficient,
        PamCode::AuthinfoUnavail,
        PamCode::UserUnknown,
        PamCode::MaxTries,
        PamCode::NewAuthtokReqd,
        PamCode::AcctExpired,
        PamCode::SessionErr,
        PamCode::CredUnavail,
        PamCode::CredExpired,
        PamCode::CredErr,
        PamCode::NoModuleData,
        PamCode::ConvErr,
        PamCode::AuthtokErr,
        PamCode::AuthtokRecoveryErr,
        PamCode::AuthtokLockBusy,
        PamCode::AuthtokDisableAging,
        PamCode::TryAgain,
        PamCode::Ignore,
        PamCode::Abort,
        PamCode::AuthtokExpired,
        PamCode::ModuleUnknown,
        PamCode::BadItem,
        PamCode::ConvAgain,
        PamCode::Incomplete,
    ];

    /// The table is this crate's own, so it can drift from the library that is
    /// actually linked. Rendering an error must not need an FFI call, but it
    /// must still say what every other PAM application says.
    ///
    /// The process never calls `setlocale`, so libc stays in the `C` locale
    /// and libpam's `gettext` calls return the untranslated strings.
    #[test]
    fn messages_match_the_linked_libpam() {
        for code in ALL {
            // SAFETY: Linux-PAM ignores the handle argument, and the returned
            // pointer is to a static string it owns.
            let msg = unsafe {
                let p = ffi::pam_strerror(std::ptr::null_mut(), code.raw());
                assert!(!p.is_null(), "{}: null message", code.name());
                CStr::from_ptr(p)
            };
            assert_eq!(
                msg.to_str().unwrap(),
                code.message(),
                "{} drifted from the linked libpam",
                code.name()
            );
        }
    }

    /// A code missing from the enum would be reported as `Unknown` and lose
    /// its message.
    #[test]
    fn the_code_block_is_contiguous_and_complete() {
        let mut raw: Vec<i32> = ALL.iter().map(|c| c.raw()).collect();
        raw.sort_unstable();
        assert_eq!(raw.first(), Some(&0));
        assert_eq!(raw.last(), Some(&(ffi::PAM_RETURN_VALUES - 1)));
        assert_eq!(raw.len(), ffi::PAM_RETURN_VALUES as usize);
        assert!(raw.windows(2).all(|w| w[1] == w[0] + 1));
    }

    /// Written out by hand rather than read from `ffi`, so a typo in the
    /// declarations cannot agree with itself.
    #[test]
    fn raw_values_are_pams_own() {
        assert_eq!(PamCode::Success.raw(), 0);
        assert_eq!(PamCode::AuthErr.raw(), 7);
        assert_eq!(PamCode::UserUnknown.raw(), 10);
        assert_eq!(PamCode::NewAuthtokReqd.raw(), 12);
        assert_eq!(PamCode::ConvErr.raw(), 19);
        assert_eq!(PamCode::Abort.raw(), 26);
        assert_eq!(PamCode::Incomplete.raw(), 31);
    }

    /// The two spaces stay apart: a PAM code is never rendered as an errno,
    /// and an errno never gets a PAM code invented for it.
    #[test]
    fn a_system_errno_keeps_its_own_meaning() {
        let err = Error::Os(libc::ENOMEM);
        assert_eq!(err.as_pam(), None);
        assert_eq!(err.raw(), None);
        assert_eq!(io::Error::from(err).raw_os_error(), Some(libc::ENOMEM));
        assert_eq!(
            io::Error::from(Error::Pam(PamCode::BufErr)).raw_os_error(),
            None
        );
    }

    #[test]
    fn codes_outside_the_block_are_unknown() {
        assert_eq!(PamCode::from_raw(-1), None);
        assert_eq!(PamCode::from_raw(ffi::PAM_RETURN_VALUES), None);
        assert_eq!(Error::from_raw(-1), Error::Unknown(-1));
        assert_eq!(Error::from_raw(32), Error::Unknown(32));
        assert_eq!(Error::Unknown(32).as_pam(), None);
    }

    #[test]
    fn check_maps_success_and_failure() {
        assert!(check(ffi::PAM_SUCCESS).is_ok());
        assert_eq!(check(ffi::PAM_AUTH_ERR), Err(Error::Pam(PamCode::AuthErr)));
        // PAM_IGNORE is not success, so it must reach the caller rather than
        // being absorbed here.
        assert_eq!(check(ffi::PAM_IGNORE), Err(Error::Pam(PamCode::Ignore)));
    }

    #[test]
    fn names_are_the_upstream_symbols() {
        assert_eq!(PamCode::Success.name(), "PAM_SUCCESS");
        assert_eq!(PamCode::MaxTries.name(), "PAM_MAXTRIES");
        assert_eq!(
            PamCode::AuthtokDisableAging.name(),
            "PAM_AUTHTOK_DISABLE_AGING"
        );
        for code in ALL {
            assert!(code.name().starts_with("PAM_"), "{code:?}");
        }
    }

    #[test]
    fn display_renders_every_variant() {
        for code in ALL {
            assert_eq!(Error::Pam(code).to_string(), code.message());
            assert_eq!(code.to_string(), code.message());
        }
        assert!(Error::Unknown(99).to_string().contains("99"));
        assert!(Error::UnknownMsgStyle(7).to_string().contains('7'));
        assert!(!Error::Timeout.to_string().is_empty());
        assert!(!Error::NulByte.to_string().is_empty());
        assert!(!Error::InvalidName.to_string().is_empty());
        assert!(!Error::NotUtf8.to_string().is_empty());
    }

    /// The variants this crate raises itself carry no libpam code, so nothing
    /// downstream can mistake one for a stack result.
    #[test]
    fn own_errors_carry_no_pam_code() {
        for err in [
            Error::Timeout,
            Error::NulByte,
            Error::InvalidName,
            Error::NotUtf8,
        ] {
            assert_eq!(err.raw(), None, "{err:?}");
            assert_eq!(err.as_pam(), None, "{err:?}");
        }
        assert_eq!(Error::UnknownMsgStyle(7).raw(), None);
    }

    /// The two halves must stay apart: an `ErrorKind` is only assigned where
    /// the PAM code has one unambiguous meaning, and no errno is invented.
    #[test]
    fn io_error_conversion_keeps_its_message() {
        let denied = io::Error::from(Error::Pam(PamCode::PermDenied));
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(denied.raw_os_error(), None);

        assert_eq!(
            io::Error::from(Error::Pam(PamCode::UserUnknown)).kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            io::Error::from(Error::Timeout).kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            io::Error::from(Error::Pam(PamCode::SystemErr)).kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn errors_expose_a_source_chain_entry_point() {
        let boxed: Box<dyn error::Error> = Box::new(Error::Pam(PamCode::Abort));
        assert_eq!(boxed.to_string(), PamCode::Abort.message());
    }
}
