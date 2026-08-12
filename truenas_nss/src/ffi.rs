// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The NSS service-module ABI: status values and function signatures.
//!
//! A service module exports `_nss_<module>_<op>` functions with the
//! signatures below; glibc's frontends call them and so does this crate.
//! Values and shapes are ABI, taken from `nss.h` and glibc's service-module
//! interface. Nothing here is declared `extern`: the functions are resolved
//! with `dlsym(3)` at run time, and `dlopen`/`dlsym`/`dlerror`, `struct
//! passwd`, and `struct group` all come from the `libc` crate.
//!
//! The `set*ent` type takes the `stayopen` int glibc's dispatcher passes.
//! Modules that declare theirs `(void)` ignore the register the argument
//! arrives in; passing it is how every caller of this ABI behaves.

use std::os::raw::{c_char, c_int, c_long};

// --- enum nss_status -------------------------------------------------------

pub const NSS_STATUS_TRYAGAIN: c_int = -2;
pub const NSS_STATUS_UNAVAIL: c_int = -1;
pub const NSS_STATUS_NOTFOUND: c_int = 0;
pub const NSS_STATUS_SUCCESS: c_int = 1;
pub const NSS_STATUS_RETURN: c_int = 2;

// --- service function signatures -------------------------------------------
// Each `_r` call fills the caller's entry struct with pointers into the
// caller's scratch buffer and reports its errno through the out-parameter.

pub type GetpwnamRFn = unsafe extern "C" fn(
    *const c_char,
    *mut libc::passwd,
    *mut c_char,
    libc::size_t,
    *mut c_int,
) -> c_int;

pub type GetpwuidRFn = unsafe extern "C" fn(
    libc::uid_t,
    *mut libc::passwd,
    *mut c_char,
    libc::size_t,
    *mut c_int,
) -> c_int;

/// `_nss_<module>_getpwent_r` and `_nss_<module>_getgrent_r`: one cursor
/// step, filling the caller's entry struct through the scratch buffer.
pub type GetentRFn<C> = unsafe extern "C" fn(
    *mut C,
    *mut c_char,
    libc::size_t,
    *mut c_int,
) -> c_int;

pub type GetpwentRFn = GetentRFn<libc::passwd>;

pub type GetgrnamRFn = unsafe extern "C" fn(
    *const c_char,
    *mut libc::group,
    *mut c_char,
    libc::size_t,
    *mut c_int,
) -> c_int;

pub type GetgrgidRFn = unsafe extern "C" fn(
    libc::gid_t,
    *mut libc::group,
    *mut c_char,
    libc::size_t,
    *mut c_int,
) -> c_int;

pub type GetgrentRFn = GetentRFn<libc::group>;

/// `_nss_<module>_initgroups_dyn`: append the gids of the groups `user`
/// belongs to, skipping `group`, to the caller's array.
///
/// The array protocol differs from the `_r` calls: `*groupsp` is a
/// `malloc`-owned `gid_t` array of `*size` entries with `*start` of them
/// filled; the module appends at `*start` and advances it, and may
/// `realloc` the array — growing `*size` — up to `limit` entries when
/// `limit` is positive. It never frees the array.
pub type InitgroupsDynFn = unsafe extern "C" fn(
    *const c_char,
    libc::gid_t,
    *mut c_long,
    *mut c_long,
    *mut *mut libc::gid_t,
    c_long,
    *mut c_int,
) -> c_int;

/// `_nss_<module>_setpwent` and `_nss_<module>_setgrent`.
pub type SetentFn = unsafe extern "C" fn(c_int) -> c_int;

/// `_nss_<module>_endpwent` and `_nss_<module>_endgrent`.
pub type EndentFn = unsafe extern "C" fn() -> c_int;
