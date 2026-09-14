// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Ccache`]: a credential cache, and the owned form of the credentials
//! it holds.
#![allow(unsafe_code)]

use crate::context::{Context, cstring};
use crate::error::Result;
use crate::ffi;
use crate::principal::{Principal, read_principal};
use crate::types::{
    Address, AuthData, KeyInfo, TicketFlags, TicketTimes, widen_timestamp,
};

/// One credential read from a cache.
#[derive(Clone, Debug)]
pub struct Credential {
    /// The client the credential was issued to.
    pub client: Principal,
    /// The service it is for (`krbtgt/REALM@REALM` for a TGT).
    pub server: Principal,
    /// Lifetime info.
    pub times: TicketTimes,
    /// The session key.
    pub keyblock: KeyInfo,
    /// True when the ticket is encrypted in another ticket's session key.
    pub is_skey: bool,
    /// Flags in the ticket.
    pub ticket_flags: TicketFlags,
    /// Addresses the ticket is bound to; empty for addressless tickets.
    pub addresses: Vec<Address>,
    /// Authorization data carried in the ticket.
    pub authdata: Vec<AuthData>,
}

/// A credential cache handle. Owns its library context, so it is `Send`
/// but not `Sync`.
pub struct Ccache {
    ctx: Context,
    handle: ffi::krb5_ccache,
}

// SAFETY: the context and handle move together and are only ever used from
// the thread that holds the `Ccache`; raw-pointer fields already deny
// `Sync`.
unsafe impl Send for Ccache {}

impl Ccache {
    pub(crate) fn from_parts(ctx: Context, handle: ffi::krb5_ccache) -> Ccache {
        Ccache { ctx, handle }
    }

    pub(crate) fn context(&self) -> &Context {
        &self.ctx
    }

    /// Resolve a cache by name, e.g. `FILE:/tmp/krb5cc_0` or
    /// `KEYRING:persistent:0`.
    pub fn open(name: &str) -> Result<Ccache> {
        let ctx = Context::new()?;
        let cname = cstring(name, "ccache name")?;
        let mut handle: ffi::krb5_ccache = std::ptr::null_mut();
        // SAFETY: valid context, NUL-terminated name, out-parameter.
        let code = unsafe {
            ffi::krb5_cc_resolve(ctx.raw(), cname.as_ptr(), &mut handle)
        };
        ctx.check(code)?;
        Ok(Ccache { ctx, handle })
    }

    /// Resolve the default cache (`KRB5CCNAME`, or the host default).
    pub fn system_default() -> Result<Ccache> {
        let ctx = Context::new()?;
        let mut handle: ffi::krb5_ccache = std::ptr::null_mut();
        // SAFETY: valid context and out-parameter.
        let code = unsafe { ffi::krb5_cc_default(ctx.raw(), &mut handle) };
        ctx.check(code)?;
        Ok(Ccache { ctx, handle })
    }

    /// The cache name, without its type prefix.
    pub fn name(&self) -> String {
        // SAFETY: live handle; the returned string is owned by the handle,
        // copied before the borrow ends.
        unsafe {
            let ptr = ffi::krb5_cc_get_name(self.ctx.raw(), self.handle);
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }

    /// The cache type, e.g. `"FILE"`.
    pub fn cc_type(&self) -> String {
        // SAFETY: as for `name`.
        unsafe {
            let ptr = ffi::krb5_cc_get_type(self.ctx.raw(), self.handle);
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }

    /// Iterate the credentials. Fails up front on a cache that does not
    /// exist yet.
    pub fn credentials(&self) -> Result<Credentials<'_>> {
        let mut cursor: ffi::krb5_cc_cursor = std::ptr::null_mut();
        // SAFETY: live handle and out-cursor; a successful start is paired
        // with `krb5_cc_end_seq_get` in `Credentials::drop`.
        let code = unsafe {
            ffi::krb5_cc_start_seq_get(self.ctx.raw(), self.handle, &mut cursor)
        };
        self.ctx.check(code)?;
        Ok(Credentials {
            cc: self,
            cursor,
            done: false,
        })
    }

    /// Destroy the cache: remove its backing store and release the handle
    /// (`kdestroy`).
    pub fn destroy(mut self) -> Result<()> {
        // SAFETY: live handle; `krb5_cc_destroy` frees it whatever it
        // returns.
        let code = unsafe { ffi::krb5_cc_destroy(self.ctx.raw(), self.handle) };
        let result = self.ctx.check(code);
        // Nulling the handle makes the impending drop skip `krb5_cc_close`
        // on the freed handle, while still dropping the context field — a
        // `mem::forget` would leak that context.
        self.handle = std::ptr::null_mut();
        result
    }
}

impl Drop for Ccache {
    fn drop(&mut self) {
        if self.handle.is_null() {
            return;
        }
        // SAFETY: handle from resolve/default on `self.ctx`, closed exactly
        // once, before the context it belongs to.
        unsafe { ffi::krb5_cc_close(self.ctx.raw(), self.handle) };
    }
}

impl std::fmt::Debug for Ccache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ccache")
            .field("type", &self.cc_type())
            .field("name", &self.name())
            .finish()
    }
}

/// Iterator over a cache's credentials.
#[derive(Debug)]
pub struct Credentials<'cc> {
    cc: &'cc Ccache,
    cursor: ffi::krb5_cc_cursor,
    done: bool,
}

impl Iterator for Credentials<'_> {
    type Item = Result<Credential>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            let mut creds = std::mem::MaybeUninit::<ffi::krb5_creds>::zeroed();
            // SAFETY: live handle and cursor; on 0 the creds are filled and
            // owed a `krb5_free_cred_contents`, on KRB5_CC_END nothing was
            // written.
            let code = unsafe {
                ffi::krb5_cc_next_cred(
                    self.cc.ctx.raw(),
                    self.cc.handle,
                    &mut self.cursor,
                    creds.as_mut_ptr(),
                )
            };
            match code {
                0 => {
                    // SAFETY: the successful call filled it.
                    let mut creds = unsafe { creds.assume_init() };
                    // A modern cache stores metadata as config
                    // pseudo-credentials under the `X-CACHECONF:` realm;
                    // skip them so only real tickets are yielded.
                    // SAFETY: `creds.server` is a live principal for the
                    // duration of this call.
                    let is_config = unsafe {
                        ffi::krb5_is_config_principal(
                            self.cc.ctx.raw(),
                            creds.server,
                        ) != 0
                    };
                    let converted = (!is_config).then(|| convert(&creds));
                    // SAFETY: filled above, freed exactly once.
                    unsafe {
                        ffi::krb5_free_cred_contents(
                            self.cc.ctx.raw(),
                            &mut creds,
                        )
                    };
                    match converted {
                        Some(converted) => return Some(converted),
                        None => continue,
                    }
                }
                ffi::KRB5_CC_END => {
                    self.done = true;
                    return None;
                }
                _ => {
                    // The cursor did not advance; a retry could only repeat
                    // the fault.
                    self.done = true;
                    return Some(Err(self.cc.ctx.error(code)));
                }
            }
        }
    }
}

impl Drop for Credentials<'_> {
    fn drop(&mut self) {
        // SAFETY: cursor from a successful start on this handle, released
        // exactly once.
        unsafe {
            ffi::krb5_cc_end_seq_get(
                self.cc.ctx.raw(),
                self.cc.handle,
                &mut self.cursor,
            )
        };
    }
}

/// Read one filled `krb5_creds` out as owned data.
fn convert(creds: &ffi::krb5_creds) -> Result<Credential> {
    // SAFETY: the library filled `creds`; every pointer read here is one
    // it owns, within the lengths it states, live until the free below the
    // call site.
    unsafe {
        Ok(Credential {
            client: read_principal(creds.client)?,
            server: read_principal(creds.server)?,
            times: TicketTimes {
                authtime: widen_timestamp(creds.times.authtime),
                starttime: widen_timestamp(creds.times.starttime),
                endtime: widen_timestamp(creds.times.endtime),
                renew_till: widen_timestamp(creds.times.renew_till),
            },
            keyblock: KeyInfo {
                enctype: creds.keyblock.enctype,
                contents: bytes(creds.keyblock.contents, creds.keyblock.length),
            },
            is_skey: creds.is_skey != 0,
            ticket_flags: TicketFlags::from_bits_retain(creds.ticket_flags),
            addresses: array(creds.addresses, |a| Address {
                addrtype: a.addrtype,
                contents: bytes(a.contents, a.length),
            }),
            authdata: array(creds.authdata, |a| AuthData {
                ad_type: a.ad_type,
                contents: bytes(a.contents, a.length),
            }),
        })
    }
}

/// Copy a counted byte buffer.
///
/// # Safety
/// `ptr` must describe `length` readable bytes, or be null with zero
/// length.
unsafe fn bytes(ptr: *mut u8, length: std::os::raw::c_uint) -> Vec<u8> {
    if ptr.is_null() || length == 0 {
        return Vec::new();
    }
    // SAFETY: caller's contract.
    unsafe { std::slice::from_raw_parts(ptr, length as usize) }.to_vec()
}

/// Walk a null-terminated array of element pointers.
///
/// # Safety
/// `head` must be null or point at a null-terminated array of valid
/// element pointers.
unsafe fn array<T, U>(head: *mut *mut T, mut f: impl FnMut(&T) -> U) -> Vec<U> {
    let mut out = Vec::new();
    if head.is_null() {
        return out;
    }
    let mut cursor = head;
    // SAFETY: caller's contract — each slot is readable until the null.
    unsafe {
        while !(*cursor).is_null() {
            out.push(f(&**cursor));
            cursor = cursor.add(1);
        }
    }
    out
}
