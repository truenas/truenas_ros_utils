// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`AcceptorCred`]: the credential an acceptor authenticates with.
#![allow(unsafe_code)]

use crate::error::{Result, check};
use crate::ffi;
use crate::name::Name;
use crate::util::cstring;

/// An acceptor credential — the key-table-backed identity tokens are
/// accepted against.
///
/// Acquired for every mechanism the glue offers (Kerberos, SPNEGO, and
/// whatever else the host carries), so it accepts any mechanism the peer
/// offers.
pub struct AcceptorCred {
    raw: ffi::gss_cred_id_t,
}

// SAFETY: an acquired credential is read-only; it may move between
// threads, and the raw-pointer field already denies `Sync`.
unsafe impl Send for AcceptorCred {}

impl AcceptorCred {
    /// Acquire from the host default key table, optionally for one
    /// acceptor principal (`None` accepts for any principal the table
    /// holds keys for).
    pub fn acquire(principal: Option<&Name>) -> Result<AcceptorCred> {
        acquire_with(principal, None)
    }

    /// Acquire from an explicit key table, by the same name syntax
    /// `krb5.conf` uses (`FILE:/path`, or a bare path), optionally for
    /// one acceptor principal.
    pub fn from_keytab(
        keytab: &str,
        principal: Option<&Name>,
    ) -> Result<AcceptorCred> {
        acquire_with(principal, Some(keytab))
    }

    pub(crate) fn raw(&self) -> ffi::gss_cred_id_t {
        self.raw
    }
}

fn acquire_with(
    principal: Option<&Name>,
    keytab: Option<&str>,
) -> Result<AcceptorCred> {
    let desired = principal.map_or(std::ptr::null_mut(), Name::raw);
    let mut raw: ffi::gss_cred_id_t = std::ptr::null_mut();
    let mut minor: ffi::OM_uint32 = 0;
    let major = match keytab {
        None => {
            // SAFETY: optional live name; null mech set means every
            // mechanism; the optional outs are declared optional by the C
            // bindings. The out credential is owned by the returned value.
            unsafe {
                ffi::gss_acquire_cred(
                    &mut minor,
                    desired,
                    ffi::GSS_C_INDEFINITE,
                    std::ptr::null_mut(),
                    ffi::GSS_C_ACCEPT,
                    &mut raw,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            }
        }
        Some(keytab) => {
            let value = cstring(keytab, "keytab name")?;
            let mut element = ffi::gss_key_value_element_desc {
                key: c"keytab".as_ptr(),
                value: value.as_ptr(),
            };
            let store = ffi::gss_key_value_set_desc {
                count: 1,
                elements: &mut element,
            };
            // SAFETY: as above; the credential store borrows this call's
            // strings only.
            unsafe {
                ffi::gss_acquire_cred_from(
                    &mut minor,
                    desired,
                    ffi::GSS_C_INDEFINITE,
                    std::ptr::null_mut(),
                    ffi::GSS_C_ACCEPT,
                    &store,
                    &mut raw,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            }
        }
    };
    check(major, minor, None)?;
    Ok(AcceptorCred { raw })
}

impl Drop for AcceptorCred {
    fn drop(&mut self) {
        // SAFETY: owned credential, released exactly once; the pointer is
        // nulled by the call.
        unsafe {
            let mut minor: ffi::OM_uint32 = 0;
            ffi::gss_release_cred(&mut minor, &mut self.raw);
        }
    }
}

impl std::fmt::Debug for AcceptorCred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptorCred").finish_non_exhaustive()
    }
}
