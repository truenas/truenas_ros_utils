// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Name`]: a GSSAPI internal name.
#![allow(unsafe_code)]

use crate::buf::{OwnedBuffer, borrowed};
use crate::error::{Result, check};
use crate::ffi;
use crate::oid::Oid;

/// An internal-form name: imported from text, or produced by the acceptor
/// for the authenticated initiator.
pub struct Name {
    raw: ffi::gss_name_t,
}

// SAFETY: a name is immutable once constructed and may move between
// threads; the raw-pointer field already denies `Sync`, so no call can
// race another on the same name.
unsafe impl Send for Name {}

impl Name {
    pub(crate) fn from_raw(raw: ffi::gss_name_t) -> Name {
        Name { raw }
    }

    pub(crate) fn raw(&self) -> ffi::gss_name_t {
        self.raw
    }

    /// Import a name of the given type, e.g. `HTTP@nas.example.test` as
    /// [`Oid::nt_hostbased_service`], or `user@EXAMPLE.TEST` as
    /// [`Oid::nt_krb5_principal`].
    pub fn import(text: &str, name_type: &Oid) -> Result<Name> {
        let mut buffer = borrowed(text.as_bytes());
        let mut kind = name_type.as_desc();
        let mut raw: ffi::gss_name_t = std::ptr::null_mut();
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: descriptors borrow `text` and the OID octets for this
        // call; on success the out name is owned by the returned value.
        let major = unsafe {
            ffi::gss_import_name(&mut minor, &mut buffer, &mut kind, &mut raw)
        };
        check(major, minor, None)?;
        Ok(Name { raw })
    }

    /// The display form.
    pub fn display(&self) -> Result<String> {
        let mut out = OwnedBuffer::empty();
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live name; the out buffer is released by `OwnedBuffer`.
        // The output name type is not requested.
        let major = unsafe {
            ffi::gss_display_name(
                &mut minor,
                self.raw,
                out.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        };
        check(major, minor, None)?;
        Ok(out.to_text())
    }

    /// Canonicalize to a mechanism name under `mech`, the step
    /// [`Name::export`] requires.
    pub fn canonicalize(&self, mech: &Oid) -> Result<Name> {
        let mut mech_desc = mech.as_desc();
        let mut raw: ffi::gss_name_t = std::ptr::null_mut();
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live name and a descriptor borrowed for the call; the
        // out name is owned by the returned value.
        let major = unsafe {
            ffi::gss_canonicalize_name(
                &mut minor,
                self.raw,
                &mut mech_desc,
                &mut raw,
            )
        };
        check(major, minor, Some(mech))?;
        Ok(Name { raw })
    }

    /// The exported form (RFC 2743 §3.2): a self-describing byte string
    /// fit for storage and comparison, re-importable as
    /// [`Oid::nt_export_name`]. The name must be a mechanism name — see
    /// [`Name::canonicalize`].
    pub fn export(&self) -> Result<Vec<u8>> {
        let mut out = OwnedBuffer::empty();
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live name; the out buffer is released by `OwnedBuffer`.
        let major = unsafe {
            ffi::gss_export_name(&mut minor, self.raw, out.as_mut_ptr())
        };
        check(major, minor, None)?;
        Ok(out.to_vec())
    }

    /// The local user name this name maps to under a mechanism's own
    /// rules — for Kerberos, `auth_to_local` in `krb5.conf`. `None` asks
    /// across mechanisms. An unmappable name is an error, never a guess.
    pub fn localname(&self, mech: Option<&Oid>) -> Result<String> {
        let mut mech_desc = mech.map(Oid::as_desc);
        let mut out = OwnedBuffer::empty();
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live name and an optionally borrowed descriptor; the out
        // buffer is released by `OwnedBuffer`.
        let major = unsafe {
            ffi::gss_localname(
                &mut minor,
                self.raw,
                mech_desc
                    .as_mut()
                    .map_or(std::ptr::null_mut(), std::ptr::from_mut),
                out.as_mut_ptr(),
            )
        };
        check(major, minor, mech)?;
        Ok(out.to_text())
    }

    /// Whether two names refer to the same entity, as far as the library
    /// can tell.
    pub fn matches(&self, other: &Name) -> Result<bool> {
        let mut equal: std::os::raw::c_int = 0;
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: two live names and an out-parameter.
        let major = unsafe {
            ffi::gss_compare_name(&mut minor, self.raw, other.raw, &mut equal)
        };
        check(major, minor, None)?;
        Ok(equal != 0)
    }
}

impl Drop for Name {
    fn drop(&mut self) {
        // SAFETY: owned name, released exactly once; the pointer is nulled
        // by the call.
        unsafe {
            let mut minor: ffi::OM_uint32 = 0;
            ffi::gss_release_name(&mut minor, &mut self.raw);
        }
    }
}

impl std::fmt::Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.display() {
            Ok(text) => write!(f, "Name({text})"),
            Err(_) => f.write_str("Name(<undisplayable>)"),
        }
    }
}
