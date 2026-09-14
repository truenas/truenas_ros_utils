// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Initial credentials: `kinit` with a key table or a password, stored
//! straight into a credential cache.
#![allow(unsafe_code)]

use crate::ccache::Ccache;
use crate::context::{Context, cstring, scrub};
use crate::error::Result;
use crate::ffi;
use crate::principal::RawPrincipal;

/// Acquire initial credentials for `principal` using a key in a key table,
/// and store them in a credential cache. `keytab` and `ccache` are resolved
/// by name; `None` means the host default. Returns the cache written.
pub fn kinit_keytab(
    principal: &str,
    keytab: Option<&str>,
    ccache: Option<&str>,
) -> Result<Ccache> {
    kinit(principal, ccache, |ctx, client, creds, opt| {
        let mut kt: ffi::krb5_keytab = std::ptr::null_mut();
        let code = match keytab {
            Some(name) => {
                let cname = cstring(name, "keytab name")?;
                // SAFETY: valid context, NUL-terminated name,
                // out-parameter.
                unsafe {
                    ffi::krb5_kt_resolve(ctx.raw(), cname.as_ptr(), &mut kt)
                }
            }
            // SAFETY: valid context and out-parameter.
            None => unsafe { ffi::krb5_kt_default(ctx.raw(), &mut kt) },
        };
        ctx.check(code)?;

        // SAFETY: every handle here was created on `ctx`; `creds` is a
        // zeroed out-parameter the call fills.
        let code = unsafe {
            ffi::krb5_get_init_creds_keytab(
                ctx.raw(),
                creds,
                client.raw(),
                kt,
                0,
                std::ptr::null(),
                opt,
            )
        };
        // SAFETY: resolved above, closed exactly once whatever the
        // acquisition returned.
        unsafe { ffi::krb5_kt_close(ctx.raw(), kt) };
        ctx.check(code)
    })
}

/// Acquire initial credentials for `principal` with a password, and store
/// them in a credential cache. `ccache` is resolved by name; `None` means
/// the host default. Returns the cache written.
pub fn kinit_password(
    principal: &str,
    password: &str,
    ccache: Option<&str>,
) -> Result<Ccache> {
    kinit(principal, ccache, |ctx, client, creds, opt| {
        let cpassword = cstring(password, "password")?;
        // SAFETY: every handle here was created on `ctx`; the password is
        // NUL-terminated and read only during the call; no prompter is
        // installed, so an expired or absent password fails rather than
        // prompting.
        let code = unsafe {
            ffi::krb5_get_init_creds_password(
                ctx.raw(),
                creds,
                client.raw(),
                cpassword.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                opt,
            )
        };
        // The library kept its own copies; this one is scrubbed before
        // release.
        scrub(&mut cpassword.into_bytes());
        ctx.check(code)
    })
}

/// The shared shape: resolve the output cache, point the options at it —
/// which makes the library initialize the cache and store the result — and
/// run the mechanism-specific acquisition.
fn kinit(
    principal: &str,
    ccache: Option<&str>,
    acquire: impl FnOnce(
        &Context,
        &RawPrincipal,
        *mut ffi::krb5_creds,
        *mut ffi::krb5_get_init_creds_opt,
    ) -> Result<()>,
) -> Result<Ccache> {
    let ctx = Context::new()?;
    let client = RawPrincipal::parse(&ctx, principal)?;

    let mut cc: ffi::krb5_ccache = std::ptr::null_mut();
    let code = match ccache {
        Some(name) => {
            let cname = cstring(name, "ccache name")?;
            // SAFETY: valid context, NUL-terminated name, out-parameter.
            unsafe { ffi::krb5_cc_resolve(ctx.raw(), cname.as_ptr(), &mut cc) }
        }
        // SAFETY: valid context and out-parameter.
        None => unsafe { ffi::krb5_cc_default(ctx.raw(), &mut cc) },
    };
    ctx.check(code)?;
    // From here the cache owns the context and the handle is owed a close on
    // every path. `client` holds a raw pointer to that same context, so it
    // must be dropped while the cache is still alive and before the cache is
    // — hence the explicit `drop(client)` below, ahead of returning or
    // dropping `cache`.
    let cache = Ccache::from_parts(ctx, cc);
    let result = acquire_into(cache.context(), &client, cc, acquire);
    drop(client);
    result.map(|()| cache)
}

/// The options/acquire/cleanup half, on the cache's own context. Split out so
/// the borrowed `client` principal is dropped between this returning and the
/// cache being handled, never after the cache frees the context.
fn acquire_into(
    ctx: &Context,
    client: &RawPrincipal,
    cc: ffi::krb5_ccache,
    acquire: impl FnOnce(
        &Context,
        &RawPrincipal,
        *mut ffi::krb5_creds,
        *mut ffi::krb5_get_init_creds_opt,
    ) -> Result<()>,
) -> Result<()> {
    let mut opt: *mut ffi::krb5_get_init_creds_opt = std::ptr::null_mut();
    // SAFETY: valid context and out-parameter; a successful alloc is paired
    // with the free below.
    let code =
        unsafe { ffi::krb5_get_init_creds_opt_alloc(ctx.raw(), &mut opt) };
    ctx.check(code)?;

    // SAFETY: options and cache are live on this context. With an out ccache
    // set, a successful acquisition initializes the cache and stores the
    // credentials itself. `opt` is freed once below whatever this returns.
    let code = unsafe {
        ffi::krb5_get_init_creds_opt_set_out_ccache(ctx.raw(), opt, cc)
    };
    let result = ctx.check(code).and_then(|()| {
        let mut creds = std::mem::MaybeUninit::<ffi::krb5_creds>::zeroed();
        let result = acquire(ctx, client, creds.as_mut_ptr(), opt);
        if result.is_ok() {
            // SAFETY: the successful acquisition filled the credentials; the
            // cache holds its own copy, so this one is released.
            unsafe {
                ffi::krb5_free_cred_contents(ctx.raw(), creds.as_mut_ptr());
            }
        }
        result
    });

    // SAFETY: allocated above, freed exactly once.
    unsafe { ffi::krb5_get_init_creds_opt_free(ctx.raw(), opt) };
    result
}
