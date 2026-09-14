// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The library context every other handle hangs off, and the error-message
//! capture that must happen while the failing context is still at hand.
//!
//! libkrb5 requires a handle to be used with the context that produced it,
//! from one thread at a time. Every public type of this crate therefore owns
//! a context of its own and never lends it out, which is also what keeps
//! those types `Send` but not `Sync`.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use crate::ffi;
use std::ffi::{CStr, CString};

/// An owned `krb5_context`.
pub(crate) struct Context {
    raw: ffi::krb5_context,
}

// SAFETY: a context may move between threads; libkrb5 forbids only
// concurrent use, which `Context` prevents by being `!Sync` (raw pointer
// field) and never sharing the pointer.
unsafe impl Send for Context {}

impl Context {
    /// Create a context (`krb5_init_context`), reading the host Kerberos
    /// configuration the way every other consumer does.
    pub(crate) fn new() -> Result<Context> {
        let mut raw: ffi::krb5_context = std::ptr::null_mut();
        // SAFETY: out-parameter for a fresh context; on failure nothing was
        // allocated and `raw` stays null.
        let code = unsafe { ffi::krb5_init_context(&mut raw) };
        if code != 0 {
            // No context exists to ask for a message;
            // `krb5_get_error_message` accepts a null context and returns a
            // generic `"Unknown code …"` string for the code, which is the
            // best available when the library itself would not start.
            return Err(error_with(std::ptr::null_mut(), code));
        }
        Ok(Context { raw })
    }

    pub(crate) fn raw(&self) -> ffi::krb5_context {
        self.raw
    }

    /// Capture `code`'s message from this context, now — the extended
    /// message is only valid until the next call on the context.
    pub(crate) fn error(&self, code: ffi::krb5_error_code) -> Error {
        error_with(self.raw, code)
    }

    /// Turn a raw return code into a `Result`, capturing the message on
    /// failure.
    pub(crate) fn check(&self, code: ffi::krb5_error_code) -> Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(self.error(code))
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: `raw` came from `krb5_init_context` and is dropped exactly
        // once; no handle created from it outlives its owner, because every
        // owning type frees its handle before this field.
        unsafe { ffi::krb5_free_context(self.raw) };
    }
}

/// Message capture that also serves the no-context failure of
/// `krb5_init_context` itself.
fn error_with(ctx: ffi::krb5_context, code: ffi::krb5_error_code) -> Error {
    // SAFETY: valid (or deliberately null) context; the returned string is
    // the library's, copied before release and released with the paired
    // free, on the same context.
    let message = unsafe {
        let ptr = ffi::krb5_get_error_message(ctx, code);
        if ptr.is_null() {
            format!("krb5 error {code}").into_boxed_str()
        } else {
            let text = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, ptr);
            text.into_boxed_str()
        }
    };
    Error::new(code, message)
}

/// A `CString` for the FFI boundary. An interior NUL cannot be expressed to
/// the library, so it is refused as `EINVAL` — com_err passes system errno
/// values through, which keeps the code in-band.
pub(crate) fn cstring(s: &str, what: &str) -> Result<CString> {
    CString::new(s).map_err(|_| {
        Error::new(libc::EINVAL, format!("interior NUL in {what}").into())
    })
}

/// Overwrite secret bytes before release. Volatile, so the writes are not
/// elided as dead stores ahead of a free.
pub(crate) fn scrub(bytes: &mut [u8]) {
    for b in bytes {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}
