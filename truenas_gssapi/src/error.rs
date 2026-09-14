// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Error`], [`RoutineError`], and this crate's [`Result`].
//!
//! A GSSAPI call reports one major status — calling errors, one routine
//! error, and supplementary bits packed into an `OM_uint32` — plus a
//! mechanism-specific minor status. [`Error`] keeps both raw values and
//! captures the library's rendering of each at the failing call, where the
//! mechanism that produced the minor status is still known.
#![allow(unsafe_code)]

use crate::ffi;
use crate::oid::Oid;
use std::{error, fmt};

/// This crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// An error from a GSSAPI call: the raw major and minor status, and the
/// library's message for both.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    major: u32,
    minor: u32,
    message: Box<str>,
}

impl Error {
    /// An error this crate raises itself, carried in the same shape.
    pub(crate) fn synthetic(major: u32, message: String) -> Error {
        Error {
            major,
            minor: 0,
            message: message.into_boxed_str(),
        }
    }

    /// The raw major status.
    pub fn major(&self) -> u32 {
        self.major
    }

    /// The raw mechanism minor status.
    pub fn minor(&self) -> u32 {
        self.minor
    }

    /// The routine error, or `None` when the major carries a value this
    /// build does not name (or none at all — a calling error alone).
    pub fn routine(&self) -> Option<RoutineError> {
        RoutineError::from_major(self.major)
    }

    /// The message the library rendered at the failing call: the major's
    /// text, then the minor's where one was set.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl error::Error for Error {}

/// Declares [`RoutineError`] and its round trip from one list.
macro_rules! routine_table {
    ($($(#[doc = $doc:literal])* $name:ident = $value:literal,)+) => {
        /// A routine error from a major status (RFC 2744 §3.9.1), named as
        /// the C bindings name them minus the `GSS_S_` prefix — kept
        /// verbatim, so the naming lint is lifted for this enum.
        #[allow(non_camel_case_types)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        #[repr(u32)]
        #[non_exhaustive]
        pub enum RoutineError {
            $($(#[doc = $doc])* $name = $value,)+
        }

        impl RoutineError {
            /// The routine error packed in a major status, or `None`.
            pub const fn from_major(major: u32) -> Option<RoutineError> {
                let field = (major >> ffi::GSS_C_ROUTINE_ERROR_OFFSET)
                    & ffi::GSS_C_ROUTINE_ERROR_MASK;
                Some(match field {
                    $($value => RoutineError::$name,)+
                    _ => return None,
                })
            }

            /// The upstream macro name, e.g. `"GSS_S_DEFECTIVE_TOKEN"`.
            pub const fn name(self) -> &'static str {
                match self {
                    $(RoutineError::$name =>
                        concat!("GSS_S_", stringify!($name)),)+
                }
            }
        }
    };
}

// Values are the header's routine-error field values, before the shift.
routine_table! {
    /// An unsupported mechanism was requested.
    BAD_MECH = 1,
    /// An invalid name was supplied.
    BAD_NAME = 2,
    /// A supplied name was of an unsupported type.
    BAD_NAMETYPE = 3,
    /// Incorrect channel bindings were supplied.
    BAD_BINDINGS = 4,
    /// An invalid status code was supplied.
    BAD_STATUS = 5,
    /// A token had an invalid MIC.
    BAD_SIG = 6,
    /// No credentials were supplied, or they were unavailable.
    NO_CRED = 7,
    /// No context has been established.
    NO_CONTEXT = 8,
    /// A token was invalid.
    DEFECTIVE_TOKEN = 9,
    /// A credential was invalid.
    DEFECTIVE_CREDENTIAL = 10,
    /// The referenced credentials have expired.
    CREDENTIALS_EXPIRED = 11,
    /// The context has expired.
    CONTEXT_EXPIRED = 12,
    /// The underlying mechanism reported the minor-status failure.
    FAILURE = 13,
    /// The quality-of-protection requested could not be provided.
    BAD_QOP = 14,
    /// The operation is forbidden by local security policy.
    UNAUTHORIZED = 15,
    /// The operation or option is unavailable.
    UNAVAILABLE = 16,
    /// The requested credential element already exists.
    DUPLICATE_ELEMENT = 17,
    /// The provided name was not a mechanism name.
    NAME_NOT_MN = 18,
    /// A mechanism attribute was invalid (`gssapi_ext.h`).
    BAD_MECH_ATTR = 19,
}

/// Capture an error at the failing call: render the major, and the minor
/// under the mechanism that produced it when one is known.
pub(crate) fn capture(major: u32, minor: u32, mech: Option<&Oid>) -> Error {
    let mut message = render(major, ffi::GSS_C_GSS_CODE, None);
    if minor != 0 {
        let detail = render(minor, ffi::GSS_C_MECH_CODE, mech);
        if !detail.is_empty() {
            if !message.is_empty() {
                message.push_str(": ");
            }
            message.push_str(&detail);
        }
    }
    if message.is_empty() {
        message = format!("GSSAPI error {major:#010x}/{minor}");
    }
    Error {
        major,
        minor,
        message: message.into_boxed_str(),
    }
}

/// Drive `gss_display_status` to exhaustion for one code.
fn render(code: u32, kind: std::os::raw::c_int, mech: Option<&Oid>) -> String {
    let mut text = String::new();
    let mut context: ffi::OM_uint32 = 0;
    let mech_desc = mech.map(Oid::as_desc);
    loop {
        let mut minor: ffi::OM_uint32 = 0;
        let mut buffer = ffi::gss_buffer_desc {
            length: 0,
            value: std::ptr::null_mut(),
        };
        // SAFETY: out-parameters and a descriptor borrowed for the call;
        // the returned buffer is released with the paired call below.
        let major = unsafe {
            ffi::gss_display_status(
                &mut minor,
                code,
                kind,
                mech_desc.as_ref().map_or(std::ptr::null_mut(), |d| {
                    std::ptr::from_ref(d).cast_mut()
                }),
                &mut context,
                &mut buffer,
            )
        };
        if major != ffi::GSS_S_COMPLETE {
            break;
        }
        if !buffer.value.is_null() && buffer.length > 0 {
            // SAFETY: the successful call filled the buffer with `length`
            // readable bytes.
            let chunk = unsafe {
                std::slice::from_raw_parts(
                    buffer.value.cast::<u8>(),
                    buffer.length,
                )
            };
            if !text.is_empty() {
                text.push_str("; ");
            }
            text.push_str(&String::from_utf8_lossy(chunk));
        }
        // SAFETY: releasing the buffer the call above allocated.
        unsafe {
            let mut minor: ffi::OM_uint32 = 0;
            ffi::gss_release_buffer(&mut minor, &mut buffer);
        }
        if context == 0 {
            break;
        }
    }
    text
}

/// Turn a call's statuses into a `Result`, treating any calling or routine
/// error as failure; supplementary bits alone are success.
pub(crate) fn check(major: u32, minor: u32, mech: Option<&Oid>) -> Result<u32> {
    const ERROR_BITS: u32 = (ffi::GSS_C_CALLING_ERROR_MASK
        << ffi::GSS_C_CALLING_ERROR_OFFSET)
        | (ffi::GSS_C_ROUTINE_ERROR_MASK << ffi::GSS_C_ROUTINE_ERROR_OFFSET);
    if major & ERROR_BITS != 0 {
        Err(capture(major, minor, mech))
    } else {
        Ok(major & ffi::GSS_C_SUPPLEMENTARY_MASK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routine_errors_unpack_from_the_major() {
        let major = 9 << ffi::GSS_C_ROUTINE_ERROR_OFFSET;
        assert_eq!(
            RoutineError::from_major(major),
            Some(RoutineError::DEFECTIVE_TOKEN)
        );
        // Supplementary bits and calling errors do not disturb the field.
        assert_eq!(
            RoutineError::from_major(major | 1 | (1 << 24)),
            Some(RoutineError::DEFECTIVE_TOKEN)
        );
        assert_eq!(RoutineError::from_major(0), None);
        assert_eq!(RoutineError::from_major(1), None);
        assert_eq!(
            RoutineError::from_major(20 << ffi::GSS_C_ROUTINE_ERROR_OFFSET),
            None
        );
    }

    #[test]
    fn names_carry_the_upstream_prefix() {
        assert_eq!(
            RoutineError::DEFECTIVE_TOKEN.name(),
            "GSS_S_DEFECTIVE_TOKEN"
        );
        assert_eq!(RoutineError::NAME_NOT_MN.name(), "GSS_S_NAME_NOT_MN");
    }

    #[test]
    fn check_separates_errors_from_supplements() {
        assert_eq!(check(ffi::GSS_S_COMPLETE, 0, None), Ok(0));
        assert_eq!(
            check(ffi::GSS_S_CONTINUE_NEEDED, 0, None),
            Ok(ffi::GSS_S_CONTINUE_NEEDED)
        );
        let err =
            check(13 << ffi::GSS_C_ROUTINE_ERROR_OFFSET, 0, None).unwrap_err();
        assert_eq!(err.routine(), Some(RoutineError::FAILURE));
    }

    #[test]
    fn display_status_renders_known_codes() {
        // "An unsupported mechanism was requested" in the C bindings'
        // wording; hold only to non-emptiness and the code round trip, the
        // wording is the library's.
        let err = capture(1 << ffi::GSS_C_ROUTINE_ERROR_OFFSET, 0, None);
        assert_eq!(err.major(), 1 << 16);
        assert_eq!(err.minor(), 0);
        assert_eq!(err.routine(), Some(RoutineError::BAD_MECH));
        assert!(!err.to_string().is_empty());
    }
}
