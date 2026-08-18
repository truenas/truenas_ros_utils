// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Error`], [`NssStatus`], and this crate's [`Result`].
//!
//! An NSS service function reports two things at once: a status from the
//! five-value `nss_status` block, and an errno through its out-parameter.
//! [`Error::Call`] carries both, because classification needs both — an
//! errno outranks any status, and a status without an errno is a failure in
//! its own right. The remaining variants are this crate's own: a module that
//! could not be loaded or lacks a symbol, an enumeration slot already in
//! use, and arguments or results that cannot cross the C boundary.

use crate::ffi;
use std::{error, fmt, io};

/// This crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// An NSS service status. Values are `enum nss_status` from `nss.h`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum NssStatus {
    /// The call should be retried. An errno, when the module reported one
    /// through the out-parameter, says why.
    TryAgain = ffi::NSS_STATUS_TRYAGAIN,
    /// The service is not able to answer at all. The fan-out lookups skip a
    /// module reporting this and try the next.
    Unavail = ffi::NSS_STATUS_UNAVAIL,
    /// No entry. Surfaced as `Ok(None)`, never as an error.
    NotFound = ffi::NSS_STATUS_NOTFOUND,
    /// The call succeeded. Never carried by [`Error`].
    Success = ffi::NSS_STATUS_SUCCESS,
    /// A glibc-internal action code; a service module has no business
    /// returning it, so reaching it here is a fault.
    Return = ffi::NSS_STATUS_RETURN,
}

impl NssStatus {
    /// The status for a raw return value, or `None` if it is outside the
    /// block `nss.h` defines.
    ///
    /// ```
    /// # use truenas_nss::NssStatus;
    /// assert_eq!(NssStatus::from_raw(-1), Some(NssStatus::Unavail));
    /// assert_eq!(NssStatus::from_raw(3), None);
    /// ```
    pub const fn from_raw(rc: i32) -> Option<NssStatus> {
        Some(match rc {
            -2 => NssStatus::TryAgain,
            -1 => NssStatus::Unavail,
            0 => NssStatus::NotFound,
            1 => NssStatus::Success,
            2 => NssStatus::Return,
            _ => return None,
        })
    }

    /// The raw `enum nss_status` value.
    pub const fn raw(self) -> i32 {
        self as i32
    }

    /// The upstream symbol, e.g. `"NSS_STATUS_UNAVAIL"`.
    ///
    /// ```
    /// # use truenas_nss::NssStatus;
    /// assert_eq!(NssStatus::TryAgain.name(), "NSS_STATUS_TRYAGAIN");
    /// ```
    pub const fn name(self) -> &'static str {
        match self {
            NssStatus::TryAgain => "NSS_STATUS_TRYAGAIN",
            NssStatus::Unavail => "NSS_STATUS_UNAVAIL",
            NssStatus::NotFound => "NSS_STATUS_NOTFOUND",
            NssStatus::Success => "NSS_STATUS_SUCCESS",
            NssStatus::Return => "NSS_STATUS_RETURN",
        }
    }
}

impl fmt::Display for NssStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An error from an NSS operation.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// A service call failed. `errno` is what the call reported through its
    /// errno out-parameter; when it is `0`, the status alone is the failure.
    /// `status` is the raw return value, kept raw so that a value outside
    /// the defined block is not lost.
    Call {
        /// The module's name, e.g. `"FILES"`.
        module: &'static str,
        /// The operation's symbol suffix, e.g. `"getpwnam_r"`.
        op: &'static str,
        /// The raw `enum nss_status` return value.
        status: i32,
        /// The errno the call reported, or `0`.
        errno: i32,
    },
    /// `dlopen(3)` could not load the module.
    Load {
        /// The module's name.
        module: &'static str,
        /// The `dlerror(3)` text.
        reason: Box<str>,
    },
    /// The module lacks the symbol for the requested operation.
    Symbol {
        /// The module's name.
        module: &'static str,
        /// The full symbol name, e.g. `"_nss_files_getpwent_r"`.
        symbol: Box<str>,
    },
    /// An enumeration whose cursor this one would share is already live on
    /// this thread. Finish or drop the other iterator first.
    Busy {
        /// The module's name.
        module: &'static str,
    },
    /// An argument held an interior NUL, so it has no C string form.
    NulByte,
    /// An identity field — an entry's name, or a member — is not UTF-8,
    /// so it cannot round-trip into a lookup. Descriptive fields decode
    /// lossily instead of raising this.
    NotUtf8,
    /// A successful call left an entry's name null. The name is the
    /// entry's identity; without one there is nothing to return.
    NullName,
}

impl Error {
    /// The decoded status, for a [`Call`](Error::Call) whose raw value is in
    /// the defined block; `None` for anything else.
    ///
    /// ```
    /// # use truenas_nss::{Error, NssStatus};
    /// let err = Error::Call {
    ///     module: "SSS", op: "getpwnam_r", status: -1, errno: 0,
    /// };
    /// assert_eq!(err.status(), Some(NssStatus::Unavail));
    /// assert_eq!(Error::NulByte.status(), None);
    /// ```
    pub fn status(&self) -> Option<NssStatus> {
        match self {
            Error::Call { status, .. } => NssStatus::from_raw(*status),
            _ => None,
        }
    }

    /// The errno a [`Call`](Error::Call) carried, or `None` when there was
    /// none.
    pub fn errno(&self) -> Option<i32> {
        match self {
            Error::Call { errno, .. } if *errno != 0 => Some(*errno),
            _ => None,
        }
    }

    /// Whether this is the condition the fan-out lookups skip: a service
    /// call that reported [`NssStatus::Unavail`].
    pub fn is_unavail(&self) -> bool {
        self.status() == Some(NssStatus::Unavail)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Call {
                module,
                op,
                status,
                errno: 0,
            } => {
                write!(f, "{module} {op}: ")?;
                match NssStatus::from_raw(*status) {
                    Some(s) => write!(f, "{}", s.name()),
                    None => write!(f, "status {status} outside nss_status"),
                }
            }
            Error::Call {
                module,
                op,
                status,
                errno,
            } => {
                write!(
                    f,
                    "{module} {op}: {} (status {status})",
                    io::Error::from_raw_os_error(*errno)
                )
            }
            Error::Load { module, reason } => {
                write!(f, "Failed to load NSS module {module}: {reason}")
            }
            Error::Symbol { module, symbol } => {
                write!(f, "NSS module {module} has no symbol {symbol}")
            }
            Error::Busy { module } => {
                write!(
                    f,
                    "An enumeration of NSS module {module} is already live \
                     on this thread"
                )
            }
            Error::NulByte => {
                f.write_str("Argument contains an interior NUL byte")
            }
            Error::NotUtf8 => {
                f.write_str("NSS module returned a non-UTF-8 name")
            }
            Error::NullName => {
                f.write_str("NSS module returned an entry with no name")
            }
        }
    }
}

impl error::Error for Error {}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        match err {
            // Only an errno-carrying call failure maps onto an OS error; the
            // rest keep their own message rather than inventing an errno.
            Error::Call { errno, .. } if errno != 0 => {
                io::Error::from_raw_os_error(errno)
            }
            Error::Busy { .. } => {
                io::Error::new(io::ErrorKind::WouldBlock, err)
            }
            Error::NulByte => io::Error::new(io::ErrorKind::InvalidInput, err),
            Error::NotUtf8 | Error::NullName => {
                io::Error::new(io::ErrorKind::InvalidData, err)
            }
            other => io::Error::other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant, for the checks below.
    const ALL_STATUS: [NssStatus; 5] = [
        NssStatus::TryAgain,
        NssStatus::Unavail,
        NssStatus::NotFound,
        NssStatus::Success,
        NssStatus::Return,
    ];

    /// Written out by hand rather than read back from `raw()`, so a typo in
    /// the discriminants cannot agree with itself. Values are `nss.h`'s.
    #[test]
    fn raw_values_are_glibcs_own() {
        assert_eq!(NssStatus::TryAgain.raw(), -2);
        assert_eq!(NssStatus::Unavail.raw(), -1);
        assert_eq!(NssStatus::NotFound.raw(), 0);
        assert_eq!(NssStatus::Success.raw(), 1);
        assert_eq!(NssStatus::Return.raw(), 2);
    }

    /// A bare status renders as its upstream symbol, written out by hand as
    /// `nss.h` has it. The `Error` cases below carry a raw status through
    /// `Error`'s `Display`, so nothing there reaches the impl a caller
    /// logging a status of its own would use.
    #[test]
    fn a_status_displays_as_its_upstream_symbol() {
        assert_eq!(NssStatus::TryAgain.to_string(), "NSS_STATUS_TRYAGAIN");
        assert_eq!(NssStatus::Unavail.to_string(), "NSS_STATUS_UNAVAIL");
        assert_eq!(NssStatus::NotFound.to_string(), "NSS_STATUS_NOTFOUND");
        assert_eq!(NssStatus::Success.to_string(), "NSS_STATUS_SUCCESS");
        assert_eq!(NssStatus::Return.to_string(), "NSS_STATUS_RETURN");
    }

    /// A raw value outside the block must come back `None`, not be forced
    /// onto the nearest variant.
    #[test]
    fn from_raw_round_trips_and_rejects() {
        for status in ALL_STATUS {
            assert_eq!(NssStatus::from_raw(status.raw()), Some(status));
        }
        assert_eq!(NssStatus::from_raw(-3), None);
        assert_eq!(NssStatus::from_raw(3), None);
    }

    /// The fan-out skip must fire on exactly one condition: a call that
    /// reported UNAVAIL. A load failure looks similar but must propagate.
    #[test]
    fn only_an_unavail_call_is_skippable() {
        let unavail = Error::Call {
            module: "SSS",
            op: "getpwnam_r",
            status: NssStatus::Unavail.raw(),
            errno: 0,
        };
        assert!(unavail.is_unavail());

        let with_errno = Error::Call {
            module: "SSS",
            op: "getpwnam_r",
            status: NssStatus::Unavail.raw(),
            errno: libc::ECONNREFUSED,
        };
        assert!(with_errno.is_unavail());

        let tryagain = Error::Call {
            module: "SSS",
            op: "getpwnam_r",
            status: NssStatus::TryAgain.raw(),
            errno: libc::EAGAIN,
        };
        assert!(!tryagain.is_unavail());

        let load = Error::Load {
            module: "SSS",
            reason: "no sssd".into(),
        };
        assert!(!load.is_unavail());
        assert!(!Error::Busy { module: "FILES" }.is_unavail());
        assert!(!Error::NulByte.is_unavail());
    }

    /// `errno()` reports only a real errno; `0` means the status alone
    /// failed the call and must not read as "errno 0".
    #[test]
    fn errno_zero_is_no_errno() {
        let status_only = Error::Call {
            module: "WINBIND",
            op: "getgrgid_r",
            status: NssStatus::Unavail.raw(),
            errno: 0,
        };
        assert_eq!(status_only.errno(), None);
        assert_eq!(status_only.status(), Some(NssStatus::Unavail));

        let with_errno = Error::Call {
            module: "WINBIND",
            op: "getgrgid_r",
            status: NssStatus::TryAgain.raw(),
            errno: libc::EAGAIN,
        };
        assert_eq!(with_errno.errno(), Some(libc::EAGAIN));
    }

    /// A status outside the defined block stays visible raw instead of
    /// being decoded to nothing and lost.
    #[test]
    fn an_undefined_status_stays_raw() {
        let err = Error::Call {
            module: "FILES",
            op: "getpwuid_r",
            status: 7,
            errno: 0,
        };
        assert_eq!(err.status(), None);
        assert!(err.to_string().contains('7'));
    }

    /// The io conversion keeps the two spaces apart: only an errno-carrying
    /// failure surfaces as a raw OS error.
    #[test]
    fn io_error_conversion_keeps_errno_apart() {
        let with_errno = Error::Call {
            module: "SSS",
            op: "getpwnam_r",
            status: NssStatus::TryAgain.raw(),
            errno: libc::EAGAIN,
        };
        assert_eq!(
            io::Error::from(with_errno).raw_os_error(),
            Some(libc::EAGAIN)
        );

        let status_only = Error::Call {
            module: "SSS",
            op: "getpwnam_r",
            status: NssStatus::Unavail.raw(),
            errno: 0,
        };
        assert_eq!(io::Error::from(status_only).raw_os_error(), None);

        assert_eq!(
            io::Error::from(Error::Busy { module: "FILES" }).kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            io::Error::from(Error::NulByte).kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            io::Error::from(Error::NotUtf8).kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            io::Error::from(Error::NullName).kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            io::Error::from(Error::Load {
                module: "SSS",
                reason: "gone".into(),
            })
            .raw_os_error(),
            None
        );
    }

    /// Rendering an error must never panic and must name what failed.
    #[test]
    fn display_renders_every_variant() {
        for status in ALL_STATUS {
            let msg = Error::Call {
                module: "FILES",
                op: "getpwnam_r",
                status: status.raw(),
                errno: 0,
            }
            .to_string();
            assert!(msg.contains("FILES"), "{msg}");
            assert!(msg.contains(status.name()), "{msg}");
        }
        let msg = Error::Call {
            module: "SSS",
            op: "setpwent",
            status: NssStatus::Unavail.raw(),
            errno: libc::ECONNREFUSED,
        }
        .to_string();
        assert!(msg.contains("SSS"), "{msg}");
        assert!(msg.contains("setpwent"), "{msg}");

        let msg = Error::Load {
            module: "WINBIND",
            reason: "why".into(),
        }
        .to_string();
        assert!(msg.contains("WINBIND") && msg.contains("why"), "{msg}");

        let msg = Error::Symbol {
            module: "FILES",
            symbol: "_nss_files_getpwent_r".into(),
        }
        .to_string();
        assert!(msg.contains("_nss_files_getpwent_r"), "{msg}");

        assert!(
            Error::Busy { module: "FILES" }
                .to_string()
                .contains("FILES")
        );
        assert!(!Error::NulByte.to_string().is_empty());
        assert!(!Error::NotUtf8.to_string().is_empty());
        assert!(!Error::NullName.to_string().is_empty());
    }
}
