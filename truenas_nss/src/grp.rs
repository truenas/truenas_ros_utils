// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The group database: [`Group`], the lookups, and [`GroupIter`].
//!
//! # Safety
//!
//! Every call here goes through a function pointer resolved for the NSS
//! service ABI. A `_r` call fills a `libc::group` whose string pointers —
//! and whose member array — alias the scratch buffer passed alongside it;
//! the shared drivers copy the entry into owned memory before that
//! buffer is released.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use crate::service::{self, Database, EnumSlot, Service, Source};
use std::ffi::CString;
use std::fmt;

/// A group entry, stamped with the module that produced it.
///
/// There is no password field: the group password mechanism has no place
/// here, for the same reason [`Passwd`](crate::Passwd) carries no hash.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct Group {
    /// Group name. Identity: refused rather than altered when it is
    /// missing or not UTF-8.
    pub name: String,
    /// Group ID.
    pub gid: u32,
    /// Member login names. Identities like [`name`](Group::name): a
    /// member that is not UTF-8 refuses the entry, because membership is
    /// authorization input.
    pub members: Vec<String>,
    /// The module that provided this entry.
    pub source: Source,
}

impl Group {
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
/// `gr` was filled by a successful service call: its string pointers are
/// null or NUL-terminated and live, and `gr_mem` is null or a
/// null-terminated array of such pointers.
unsafe fn extract_group(gr: &libc::group, source: Source) -> Result<Group> {
    // `gr_passwd` is deliberately never read; see [`Group`].
    let mut members = Vec::new();
    if !gr.gr_mem.is_null() {
        let mut cursor = gr.gr_mem;
        loop {
            // SAFETY: the caller's contract: `cursor` is within the
            // null-terminated array, whose terminator has not been seen.
            let member = unsafe { *cursor };
            if member.is_null() {
                break;
            }
            // SAFETY: non-terminator entries are NUL-terminated strings.
            members.push(unsafe { service::name_field(member) }?);
            // SAFETY: the terminator has not been seen, so one past
            // `cursor` is still within the array.
            cursor = unsafe { cursor.add(1) };
        }
    }
    Ok(Group {
        // SAFETY: the caller's contract covers each field.
        name: unsafe { service::name_field(gr.gr_name) }?,
        gid: gr.gr_gid,
        members,
        source,
    })
}

impl Service {
    /// Look up a group entry by name. `Ok(None)` is not-found.
    pub fn getgrnam(&self, name: &str) -> Result<Option<Group>> {
        let f = self
            .fns()
            .getgrnam_r
            .ok_or_else(|| self.missing("getgrnam_r"))?;
        let name = CString::new(name).map_err(|_| Error::NulByte)?;
        service::lookup_entry(
            self,
            "getgrnam_r",
            |gr, buf, len, errnop| {
                // SAFETY: a resolved `_nss_*_getgrnam_r`; every pointer
                // is live for the call.
                unsafe { f(name.as_ptr(), gr, buf, len, errnop) }
            },
            extract_group,
        )
    }

    /// Look up a group entry by group ID. `Ok(None)` is not-found.
    pub fn getgrgid(&self, gid: u32) -> Result<Option<Group>> {
        let f = self
            .fns()
            .getgrgid_r
            .ok_or_else(|| self.missing("getgrgid_r"))?;
        service::lookup_entry(
            self,
            "getgrgid_r",
            |gr, buf, len, errnop| {
                // SAFETY: a resolved `_nss_*_getgrgid_r`; every pointer
                // is live for the call.
                unsafe { f(gid, gr, buf, len, errnop) }
            },
            extract_group,
        )
    }

    /// The groups `name` belongs to in this module, as `getgrouplist(3)`
    /// reports them: `gid` — the caller's primary gid, from the passwd
    /// entry — leads, the module's memberships follow in its order, and
    /// the list is deduplicated. The list is unbounded; a caller with a
    /// ceiling checks the length, where exceeding it is visible.
    ///
    /// The seed alone means no memberships are known here. The service
    /// ABI does not distinguish an unknown user from a member of nothing,
    /// so existence is [`getpwnam`](Service::getpwnam)'s question.
    pub fn getgrouplist(&self, name: &str, gid: u32) -> Result<Vec<u32>> {
        Ok(service::dedup_gids(self.grouplist_raw(name, gid)?))
    }

    /// The list as the module reports it, repeats kept: the union walk
    /// dedups once over the whole, so the per-module pass belongs only
    /// to the single-module answer above.
    pub(crate) fn grouplist_raw(
        &self,
        name: &str,
        gid: u32,
    ) -> Result<Vec<u32>> {
        let f = self
            .fns()
            .initgroups_dyn
            .ok_or_else(|| self.missing("initgroups_dyn"))?;
        let name = CString::new(name).map_err(|_| Error::NulByte)?;
        service::call_initgroups(self.module(), f, &name, gid)
    }

    /// Enumerate the module's group database.
    ///
    /// One enumeration per cursor: a second same-thread iterator that
    /// would share this one's cursor is [`Error::Busy`], and for a
    /// process-scoped module another thread's enumeration waits until the
    /// iterator is dropped.
    pub fn group_entries(&'static self) -> Result<GroupIter> {
        let fns = self.fns();
        let setent = fns.setgrent.ok_or_else(|| self.missing("setgrent"))?;
        let getent =
            fns.getgrent_r.ok_or_else(|| self.missing("getgrent_r"))?;
        let endent = fns.endgrent.ok_or_else(|| self.missing("endgrent"))?;
        let slot = EnumSlot::acquire(self, Database::Group)?;
        // On failure the slot drops here and the claim is released.
        service::call_ent(self.module(), "setgrent", || {
            // SAFETY: a resolved `_nss_*_setgrent`; stayopen 0 is what the
            // glibc dispatcher passes.
            unsafe { setent(0) }
        })?;
        Ok(GroupIter(service::EntIter::new(
            slot,
            getent,
            endent,
            "getgrent_r",
            "endgrent",
            extract_group,
        )))
    }
}

impl Source {
    /// Look up a group entry by name in this module. `Ok(None)` is
    /// not-found.
    pub fn getgrnam(self, name: &str) -> Result<Option<Group>> {
        self.service()?.getgrnam(name)
    }

    /// Look up a group entry by group ID in this module. `Ok(None)` is
    /// not-found.
    pub fn getgrgid(self, gid: u32) -> Result<Option<Group>> {
        self.service()?.getgrgid(gid)
    }

    /// The groups `name` belongs to in this module. See
    /// [`Service::getgrouplist`].
    pub fn getgrouplist(self, name: &str, gid: u32) -> Result<Vec<u32>> {
        self.service()?.getgrouplist(name, gid)
    }

    /// Enumerate this module's group database. See
    /// [`Service::group_entries`].
    pub fn group_entries(self) -> Result<GroupIter> {
        self.service()?.group_entries()
    }
}

/// Look up a group entry by name across [`Source::LOOKUP_ORDER`]. First
/// hit wins; a module reporting unavailable is skipped; any other failure
/// — including a module that cannot be loaded — propagates. `Ok(None)`
/// means no module holds the entry.
pub fn getgrnam(name: &str) -> Result<Option<Group>> {
    service::fan_out(|source| source.getgrnam(name))
}

/// Look up a group entry by group ID across [`Source::LOOKUP_ORDER`]; the
/// same walk as [`getgrnam`].
pub fn getgrgid(gid: u32) -> Result<Option<Group>> {
    service::fan_out(|source| source.getgrgid(gid))
}

/// The groups `name` belongs to across [`Source::LOOKUP_ORDER`]: `gid`
/// leads and every module's memberships follow, deduplicated in first-seen
/// order. Membership is additive, so this is a union of all three modules
/// — not the first-hit walk of the entry lookups — under the same skip
/// rule: a module reporting unavailable contributes nothing, and any other
/// failure, a module that cannot be loaded included, propagates. A partial
/// union must not pass for a whole one: supplementary groups both grant
/// and, where a group carries a deny, withhold.
pub fn getgrouplist(name: &str, gid: u32) -> Result<Vec<u32>> {
    service::fan_out_groups(gid, |source| {
        source.service()?.grouplist_raw(name, gid)
    })
}

/// An enumeration of one module's group database. Yields `Result<Group>`.
/// The enumeration ends when the data runs out, when a service call faults,
/// or when the iterator is dropped; an entry that cannot be converted is
/// yielded as an error and the walk goes on.
///
/// The cursor may live in the module's thread-local state, so the iterator
/// stays on the thread that made it:
///
/// ```compile_fail,E0277
/// fn assert_send<T: Send>() {}
/// assert_send::<truenas_nss::GroupIter>();
/// ```
pub struct GroupIter(service::EntIter<libc::group, Group>);

impl Iterator for GroupIter {
    type Item = Result<Group>;

    fn next(&mut self) -> Option<Result<Group>> {
        self.0.next()
    }
}

impl fmt::Debug for GroupIter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupIter")
            .field("open", &self.0.is_open())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::os::raw::c_char;
    use std::ptr;

    fn entry(
        name: &'static CStr,
        passwd: &'static CStr,
        members: *mut *mut c_char,
    ) -> libc::group {
        // SAFETY: all-zero bytes are a valid `libc::group` — null pointers
        // and a zero ID.
        let mut gr: libc::group = unsafe { std::mem::zeroed() };
        gr.gr_name = name.as_ptr().cast_mut();
        gr.gr_passwd = passwd.as_ptr().cast_mut();
        gr.gr_gid = 3000;
        gr.gr_mem = members;
        gr
    }

    /// The member walk must copy each entry and stop exactly at the
    /// terminator.
    #[test]
    fn extraction_walks_the_member_array() {
        let mut members = [
            c"alice".as_ptr().cast_mut(),
            c"bob".as_ptr().cast_mut(),
            ptr::null_mut(),
        ];
        let gr = entry(c"alpha", c"x", members.as_mut_ptr());
        // SAFETY: pointers are static literals and a live local array.
        let out = unsafe { extract_group(&gr, Source::Winbind) }.unwrap();
        assert_eq!(out.name, "alpha");
        assert_eq!(out.gid, 3000);
        assert_eq!(out.members, ["alice", "bob"]);
        assert_eq!(out.source, Source::Winbind);
        assert!(!out.is_local());
    }

    /// An empty member array and a null one both read as no members.
    #[test]
    fn empty_and_null_member_arrays_read_as_none() {
        let mut empty = [ptr::null_mut::<c_char>()];
        let gr = entry(c"empty", c"x", empty.as_mut_ptr());
        // SAFETY: pointers are static literals and a live local array.
        let out = unsafe { extract_group(&gr, Source::Files) }.unwrap();
        assert!(out.members.is_empty());

        let gr = entry(c"nullmem", c"x", ptr::null_mut());
        // SAFETY: pointers are static literals or null.
        let out = unsafe { extract_group(&gr, Source::Files) }.unwrap();
        assert!(out.members.is_empty());
        assert!(out.is_local());
    }

    /// A name identifies the entry; a successful call that left it null
    /// has returned nothing usable.
    #[test]
    fn a_null_name_is_refused() {
        let mut gr = entry(c"x", c"x", ptr::null_mut());
        gr.gr_name = ptr::null_mut();
        // SAFETY: pointers are static literals or null.
        let out = unsafe { extract_group(&gr, Source::Files) };
        assert_eq!(out, Err(Error::NullName));
    }

    /// A non-UTF-8 member name must error, exactly as a non-UTF-8 group
    /// name does: membership is authorization input, and an altered name
    /// would change it silently.
    #[test]
    fn a_non_utf8_member_is_refused() {
        const BAD: &[u8] = b"b\xffad\0";
        let bad = CStr::from_bytes_with_nul(BAD).unwrap();
        let mut members = [bad.as_ptr().cast_mut(), ptr::null_mut::<c_char>()];
        let gr = entry(c"alpha", c"x", members.as_mut_ptr());
        // SAFETY: pointers are static literals and a live local array.
        let out = unsafe { extract_group(&gr, Source::Files) };
        assert_eq!(out, Err(Error::NotUtf8));
    }

    /// The password field must never be read: a pointer to non-UTF-8
    /// content there cannot fail the extraction.
    #[test]
    fn the_password_field_is_never_read() {
        const JUNK: &[u8] = b"\xff\xfe\0";
        let junk = CStr::from_bytes_with_nul(JUNK).unwrap();
        let gr = entry(c"beta", junk, ptr::null_mut());
        // SAFETY: pointers are static literals or null.
        let out = unsafe { extract_group(&gr, Source::Files) }.unwrap();
        assert_eq!(out.name, "beta");
    }
}
