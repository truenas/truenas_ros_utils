// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The passwd database: [`Passwd`], the lookups, and [`PasswdIter`].
//!
//! # Safety
//!
//! Every call here goes through a function pointer resolved for the NSS
//! service ABI. A `_r` call fills a `libc::passwd` whose string pointers
//! alias the scratch buffer passed alongside it; the shared drivers copy
//! the entry into owned memory before that buffer is released.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use crate::service::{self, Database, EnumSlot, Service, Source};
use std::ffi::CString;
use std::fmt;

/// A passwd entry, stamped with the module that produced it.
///
/// There is no password field: the hash lives in the shadow database, and
/// the placeholder `passwd` carries invites misuse.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct Passwd {
    /// Login name. Identity: refused rather than altered when it is
    /// missing or not UTF-8.
    pub name: String,
    /// User ID.
    pub uid: u32,
    /// Primary group ID.
    pub gid: u32,
    /// Real name / GECOS field. Descriptive: decoded lossily.
    pub gecos: String,
    /// Home directory. Descriptive: decoded lossily.
    pub dir: String,
    /// Login shell. Descriptive: decoded lossily.
    pub shell: String,
    /// The module that provided this entry.
    pub source: Source,
}

impl Passwd {
    /// Whether the entry is local to the host: provided by
    /// [`Source::Files`].
    pub fn is_local(&self) -> bool {
        self.source.is_local()
    }
}

/// Copy an entry out of the module's scratch buffer into owned memory.
///
/// # Safety
///
/// `pw` was filled by a successful service call, and every pointer in it
/// is null or a NUL-terminated string live for this call.
unsafe fn extract_passwd(pw: &libc::passwd, source: Source) -> Result<Passwd> {
    // `pw_passwd` is deliberately never read; see [`Passwd`].
    Ok(Passwd {
        // SAFETY: the caller's contract covers each field.
        name: unsafe { service::name_field(pw.pw_name) }?,
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        // SAFETY: as above.
        gecos: unsafe { service::text_field(pw.pw_gecos) },
        // SAFETY: as above.
        dir: unsafe { service::text_field(pw.pw_dir) },
        // SAFETY: as above.
        shell: unsafe { service::text_field(pw.pw_shell) },
        source,
    })
}

impl Service {
    /// Look up a passwd entry by name. `Ok(None)` is not-found.
    pub fn getpwnam(&self, name: &str) -> Result<Option<Passwd>> {
        let f = self
            .fns()
            .getpwnam_r
            .ok_or_else(|| self.missing("getpwnam_r"))?;
        let name = CString::new(name).map_err(|_| Error::NulByte)?;
        service::lookup_entry(
            self,
            "getpwnam_r",
            |pw, buf, len, errnop| {
                // SAFETY: a resolved `_nss_*_getpwnam_r`; every pointer
                // is live for the call.
                unsafe { f(name.as_ptr(), pw, buf, len, errnop) }
            },
            extract_passwd,
        )
    }

    /// Look up a passwd entry by user ID. `Ok(None)` is not-found.
    pub fn getpwuid(&self, uid: u32) -> Result<Option<Passwd>> {
        let f = self
            .fns()
            .getpwuid_r
            .ok_or_else(|| self.missing("getpwuid_r"))?;
        service::lookup_entry(
            self,
            "getpwuid_r",
            |pw, buf, len, errnop| {
                // SAFETY: a resolved `_nss_*_getpwuid_r`; every pointer
                // is live for the call.
                unsafe { f(uid, pw, buf, len, errnop) }
            },
            extract_passwd,
        )
    }

    /// Enumerate the module's passwd database.
    ///
    /// One enumeration per cursor: a second same-thread iterator that
    /// would share this one's cursor is [`Error::Busy`], and for a
    /// process-scoped module another thread's enumeration waits until the
    /// iterator is dropped.
    pub fn passwd_entries(&'static self) -> Result<PasswdIter> {
        let fns = self.fns();
        let setent = fns.setpwent.ok_or_else(|| self.missing("setpwent"))?;
        let getent =
            fns.getpwent_r.ok_or_else(|| self.missing("getpwent_r"))?;
        let endent = fns.endpwent.ok_or_else(|| self.missing("endpwent"))?;
        let slot = EnumSlot::acquire(self, Database::Passwd)?;
        // On failure the slot drops here and the claim is released.
        service::call_ent(self.module(), "setpwent", || {
            // SAFETY: a resolved `_nss_*_setpwent`; stayopen 0 is what the
            // glibc dispatcher passes.
            unsafe { setent(0) }
        })?;
        Ok(PasswdIter(service::EntIter::new(
            slot,
            getent,
            endent,
            "getpwent_r",
            "endpwent",
            extract_passwd,
        )))
    }
}

impl Source {
    /// Look up a passwd entry by name in this module. `Ok(None)` is
    /// not-found.
    pub fn getpwnam(self, name: &str) -> Result<Option<Passwd>> {
        self.service()?.getpwnam(name)
    }

    /// Look up a passwd entry by user ID in this module. `Ok(None)` is
    /// not-found.
    pub fn getpwuid(self, uid: u32) -> Result<Option<Passwd>> {
        self.service()?.getpwuid(uid)
    }

    /// Enumerate this module's passwd database. See
    /// [`Service::passwd_entries`].
    pub fn passwd_entries(self) -> Result<PasswdIter> {
        self.service()?.passwd_entries()
    }
}

/// Look up a passwd entry by name across
/// [`Source::LOOKUP_ORDER`]. First hit wins; a module reporting
/// unavailable is skipped; any other failure — including a module that
/// cannot be loaded — propagates. `Ok(None)` means no module holds the
/// entry.
///
/// ```no_run
/// let root = truenas_nss::getpwnam("root")?;
/// # Ok::<(), truenas_nss::Error>(())
/// ```
pub fn getpwnam(name: &str) -> Result<Option<Passwd>> {
    service::fan_out(|source| source.getpwnam(name))
}

/// Look up a passwd entry by user ID across [`Source::LOOKUP_ORDER`]; the
/// same walk as [`getpwnam`].
pub fn getpwuid(uid: u32) -> Result<Option<Passwd>> {
    service::fan_out(|source| source.getpwuid(uid))
}

/// An enumeration of one module's passwd database. Yields
/// `Result<Passwd>`. The enumeration ends when the data runs out, when a
/// service call faults, or when the iterator is dropped; an entry that
/// cannot be converted is yielded as an error and the walk goes on.
///
/// The cursor may live in the module's thread-local state, so the iterator
/// stays on the thread that made it:
///
/// ```compile_fail,E0277
/// fn assert_send<T: Send>() {}
/// assert_send::<truenas_nss::PasswdIter>();
/// ```
pub struct PasswdIter(service::EntIter<libc::passwd, Passwd>);

impl Iterator for PasswdIter {
    type Item = Result<Passwd>;

    fn next(&mut self) -> Option<Result<Passwd>> {
        self.0.next()
    }
}

impl fmt::Debug for PasswdIter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswdIter")
            .field("open", &self.0.is_open())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn entry(
        name: &'static CStr,
        passwd: &'static CStr,
        gecos: Option<&'static CStr>,
    ) -> libc::passwd {
        // Zeroed rather than a struct literal: null pointers everywhere a
        // field is not set below.
        // SAFETY: all-zero bytes are a valid `libc::passwd` — null
        // pointers and zero IDs.
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        pw.pw_name = name.as_ptr().cast_mut();
        pw.pw_passwd = passwd.as_ptr().cast_mut();
        pw.pw_uid = 1000;
        pw.pw_gid = 2000;
        pw.pw_gecos =
            gecos.map_or(std::ptr::null_mut(), |g| g.as_ptr().cast_mut());
        pw.pw_dir = c"/home/alice".as_ptr().cast_mut();
        pw.pw_shell = c"/bin/sh".as_ptr().cast_mut();
        pw
    }

    /// Field order and copy-out: each Rust field must come from its C
    /// counterpart, as owned memory.
    #[test]
    fn extraction_copies_every_field() {
        let pw = entry(c"alice", c"x", Some(c"Alice A"));
        // SAFETY: every pointer refers to a static literal.
        let out = unsafe { extract_passwd(&pw, Source::Sss) }.unwrap();
        assert_eq!(out.name, "alice");
        assert_eq!(out.uid, 1000);
        assert_eq!(out.gid, 2000);
        assert_eq!(out.gecos, "Alice A");
        assert_eq!(out.dir, "/home/alice");
        assert_eq!(out.shell, "/bin/sh");
        assert_eq!(out.source, Source::Sss);
        assert!(!out.is_local());
    }

    /// A null field reads as empty, and FILES entries are local.
    #[test]
    fn a_null_gecos_reads_as_empty() {
        let pw = entry(c"bob", c"x", None);
        // SAFETY: pointers are static literals or null.
        let out = unsafe { extract_passwd(&pw, Source::Files) }.unwrap();
        assert_eq!(out.gecos, "");
        assert!(out.is_local());
    }

    /// A non-UTF-8 name cannot round-trip into a lookup, so it must error
    /// rather than be silently mangled.
    #[test]
    fn a_non_utf8_name_is_refused() {
        const BAD: &[u8] = b"b\xffad\0";
        let bad = CStr::from_bytes_with_nul(BAD).unwrap();
        let pw = entry(bad, c"x", None);
        // SAFETY: pointers are static literals or null.
        let out = unsafe { extract_passwd(&pw, Source::Files) };
        assert_eq!(out, Err(Error::NotUtf8));
    }

    /// A name identifies the entry; a successful call that left it null
    /// has returned nothing usable.
    #[test]
    fn a_null_name_is_refused() {
        let mut pw = entry(c"x", c"x", None);
        pw.pw_name = std::ptr::null_mut();
        // SAFETY: pointers are static literals or null.
        let out = unsafe { extract_passwd(&pw, Source::Files) };
        assert_eq!(out, Err(Error::NullName));
    }

    /// A descriptive field only describes; a stray byte in one must not
    /// deny the identity, so it decodes lossily rather than erroring.
    #[test]
    fn a_non_utf8_gecos_decodes_lossily() {
        const BAD: &[u8] = b"g\xffecos\0";
        let bad = CStr::from_bytes_with_nul(BAD).unwrap();
        let pw = entry(c"alice", c"x", Some(bad));
        // SAFETY: pointers are static literals or null.
        let out = unsafe { extract_passwd(&pw, Source::Files) }.unwrap();
        assert_eq!(out.name, "alice");
        assert_eq!(out.gecos, "g\u{fffd}ecos");
    }

    /// The password field must never be read: a pointer to non-UTF-8
    /// content there cannot fail the extraction.
    #[test]
    fn the_password_field_is_never_read() {
        const JUNK: &[u8] = b"\xff\xfe\0";
        let junk = CStr::from_bytes_with_nul(JUNK).unwrap();
        let pw = entry(c"carol", junk, Some(c""));
        // SAFETY: pointers are static literals or null.
        let out = unsafe { extract_passwd(&pw, Source::Files) }.unwrap();
        assert_eq!(out.name, "carol");
    }

    /// `libc::uid_t` widening or narrowing would corrupt IDs above
    /// `i32::MAX`, which winbind allocates freely.
    #[test]
    fn large_ids_survive() {
        let mut pw = entry(c"big", c"x", None);
        pw.pw_uid = 4_000_000_000;
        pw.pw_gid = 4_000_000_001;
        // SAFETY: pointers are static literals or null.
        let out = unsafe { extract_passwd(&pw, Source::Winbind) }.unwrap();
        assert_eq!(out.uid, 4_000_000_000);
        assert_eq!(out.gid, 4_000_000_001);
    }
}
