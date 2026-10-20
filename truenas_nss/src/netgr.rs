// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Netgroup membership through glibc's `innetgr(3)`.
//!
//! The netgroup service functions of a module take a structure glibc does
//! not install, so membership is asked of the libc frontend instead. It
//! reads `nsswitch.conf` and walks nested netgroups itself, unlike the
//! passwd and group lookups of this crate.
//!
//! # Safety
//!
//! `innetgr` reads its four arguments as NUL-terminated strings or null
//! and keeps none of them past the call. glibc documents it as unsafe
//! across threads over the process's netgroup state, so every call holds
//! one lock.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::Mutex;

unsafe extern "C" {
    #[link_name = "innetgr"]
    fn libc_innetgr(
        netgroup: *const c_char,
        host: *const c_char,
        user: *const c_char,
        domain: *const c_char,
    ) -> c_int;
}

/// Held across every call of `innetgr`.
static LOCK: Mutex<()> = Mutex::new(());

/// Whether `netgroup` holds the triple of `host`, `user` and `domain`.
///
/// `None` in a position accepts any value there, and so does an empty
/// field of the netgroup's own triple. `false` covers a netgroup that does
/// not exist, one that holds no such triple and a lookup that failed,
/// which `innetgr` does not tell apart.
///
/// ```
/// let member = truenas_nss::innetgr("no-such-netgroup", Some("host"), None, None)?;
/// assert!(!member);
/// # Ok::<(), truenas_nss::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::NulByte`] when an argument holds an interior NUL.
pub fn innetgr(
    netgroup: &str,
    host: Option<&str>,
    user: Option<&str>,
    domain: Option<&str>,
) -> Result<bool> {
    let c = |s: &str| CString::new(s).map_err(|_| Error::NulByte);
    let netgroup = c(netgroup)?;
    let (host, user, domain) = (
        host.map(c).transpose()?,
        user.map(c).transpose()?,
        domain.map(c).transpose()?,
    );
    let ptr =
        |s: &Option<CString>| s.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    let _held = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: each pointer is null or a NUL-terminated string owned above,
    // which outlives the call, and LOCK serializes every call.
    let found = unsafe {
        libc_innetgr(netgroup.as_ptr(), ptr(&host), ptr(&user), ptr(&domain))
    };
    Ok(found == 1)
}
