// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Small shared plumbing.

use crate::error::{Error, Result};
use crate::ffi;
use std::ffi::CString;

/// A `CString` for the FFI boundary. An interior NUL cannot be expressed
/// to the library, so it is refused as a calling error — the class the C
/// bindings give an unreadable parameter.
pub(crate) fn cstring(s: &str, what: &str) -> Result<CString> {
    CString::new(s).map_err(|_| {
        Error::synthetic(
            1 << ffi::GSS_C_CALLING_ERROR_OFFSET,
            format!("interior NUL in {what}"),
        )
    })
}
