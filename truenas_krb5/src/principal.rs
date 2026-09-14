// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Principal`]: a parsed Kerberos principal, owned as plain data.
//!
//! Parsing and unparsing are the library's — its quoting rules are the wire
//! contract (`\` escapes `/`, `@`, and itself inside a component) — so both
//! directions go through libkrb5 rather than reimplementing the grammar.
//! The parsed form is plain Rust data: realm, components, and the raw name
//! type.
//!
//! Components and realm must be UTF-8. They are identity — they round-trip
//! into lookups and stand in authorization decisions — so a stray byte in
//! one is refused rather than decoded lossily.
#![allow(unsafe_code)]

use crate::context::{Context, cstring};
use crate::error::{Error, Result};
use crate::ffi;
use crate::types::PrincipalType;
use std::ffi::CStr;

/// A parsed principal: realm, components, and the library's name type.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Principal {
    /// The realm, without the `@`.
    pub realm: String,
    /// The name components, unquoted.
    pub components: Vec<String>,
    /// The raw name type; parsing yields `KRB5_NT_PRINCIPAL`, entries read
    /// from a key table or cache carry whatever was stored.
    pub name_type: i32,
}

impl Principal {
    /// Parse a principal string (`user@REALM`, `svc/host@REALM`, …) with
    /// the library's quoting rules. A name without a realm takes the host
    /// default realm, and fails where none is configured.
    pub fn parse(name: &str) -> Result<Principal> {
        let ctx = Context::new()?;
        let raw = RawPrincipal::parse(&ctx, name)?;
        raw.to_owned(&ctx)
    }

    /// Render the principal back to its string form, with the library's
    /// quoting rules.
    pub fn unparse(&self) -> Result<String> {
        let ctx = Context::new()?;
        let raw = RawPrincipal::build(&ctx, self)?;
        raw.unparse(&ctx)
    }

    /// The typed name type, or `None` when the raw value is not one the
    /// library names.
    pub fn principal_type(&self) -> Option<PrincipalType> {
        PrincipalType::from_raw(self.name_type)
    }
}

/// A `krb5_principal` bound to a context, freed on drop.
pub(crate) struct RawPrincipal {
    raw: ffi::krb5_principal,
    ctx: ffi::krb5_context,
}

impl RawPrincipal {
    /// Parse on the given context.
    pub(crate) fn parse(ctx: &Context, name: &str) -> Result<RawPrincipal> {
        let cname = cstring(name, "principal")?;
        let mut raw: ffi::krb5_principal = std::ptr::null_mut();
        // SAFETY: valid context, NUL-terminated name, out-parameter; on
        // failure nothing is allocated.
        let code = unsafe {
            ffi::krb5_parse_name(ctx.raw(), cname.as_ptr(), &mut raw)
        };
        ctx.check(code)?;
        Ok(RawPrincipal {
            raw,
            ctx: ctx.raw(),
        })
    }

    /// Build a raw principal carrying `principal`'s components and name
    /// type, by unparsing this crate's own escaping into the library's
    /// grammar and letting `krb5_parse_name` own the allocation.
    pub(crate) fn build(
        ctx: &Context,
        principal: &Principal,
    ) -> Result<RawPrincipal> {
        let mut text = String::new();
        for (i, component) in principal.components.iter().enumerate() {
            if i > 0 {
                text.push('/');
            }
            escape_into(&mut text, component);
        }
        text.push('@');
        escape_into(&mut text, &principal.realm);

        let raw = RawPrincipal::parse(ctx, &text)?;
        // SAFETY: `raw` points at a live principal owned by this value; the
        // name type is plain data the parse defaulted.
        unsafe { (*raw.raw).r#type = principal.name_type };
        Ok(raw)
    }

    pub(crate) fn raw(&self) -> ffi::krb5_principal {
        self.raw
    }

    /// Read the principal out as owned data.
    pub(crate) fn to_owned(&self, ctx: &Context) -> Result<Principal> {
        let _ = ctx;
        // SAFETY: `raw` is a live principal for the whole call.
        unsafe { read_principal(self.raw) }
    }

    /// Unparse on the owning context.
    pub(crate) fn unparse(&self, ctx: &Context) -> Result<String> {
        let mut name: *mut std::os::raw::c_char = std::ptr::null_mut();
        // SAFETY: live principal and context; the out string is the
        // library's, copied then released with the paired free.
        unsafe {
            let code = ffi::krb5_unparse_name(ctx.raw(), self.raw, &mut name);
            ctx.check(code)?;
            let text = CStr::from_ptr(name).to_string_lossy().into_owned();
            ffi::krb5_free_unparsed_name(ctx.raw(), name);
            Ok(text)
        }
    }
}

impl Drop for RawPrincipal {
    fn drop(&mut self) {
        // SAFETY: `raw` came from `krb5_parse_name` on `ctx`, which the
        // owning wrapper keeps alive for this value's whole life.
        unsafe { ffi::krb5_free_principal(self.ctx, self.raw) };
    }
}

/// Escape one component (or the realm) into the library's parse grammar:
/// `\` quotes the separators and itself. Everything else — including
/// whitespace and control characters — passes through literally, which is
/// how `krb5_parse_name` reads it.
fn escape_into(out: &mut String, component: &str) {
    for ch in component.chars() {
        if matches!(ch, '\\' | '/' | '@') {
            out.push('\\');
        }
        out.push(ch);
    }
}

/// Read a live `krb5_principal` — owned by an entry, a credential, or a
/// [`RawPrincipal`] — out as owned data.
///
/// # Safety
/// `raw` must point at a principal the library filled, live for the whole
/// call.
pub(crate) unsafe fn read_principal(
    raw: ffi::krb5_principal,
) -> Result<Principal> {
    // The standard cache and key-table backends never store a null
    // principal, so they cannot return one; refuse rather than dereference
    // if some backend ever hands one back.
    if raw.is_null() {
        return Err(Error::new(libc::EINVAL, "null principal".into()));
    }
    // SAFETY: non-null per the check above; realm and the component array
    // are read within the lengths the struct states.
    unsafe {
        let p = &*raw;
        let realm = utf8(&p.realm, "realm")?;
        let count = usize::try_from(p.length).unwrap_or(0);
        let mut components = Vec::with_capacity(count);
        for i in 0..count {
            components.push(utf8(&*p.data.add(i), "principal component")?);
        }
        Ok(Principal {
            realm,
            components,
            name_type: p.r#type,
        })
    }
}

/// Read a `krb5_data` as UTF-8 identity text.
///
/// # Safety
/// `data` must describe `length` readable bytes.
unsafe fn utf8(data: &ffi::krb5_data, what: &str) -> Result<String> {
    let bytes = if data.length == 0 {
        &[][..]
    } else {
        // SAFETY: caller's contract — the library filled this descriptor.
        unsafe {
            std::slice::from_raw_parts(
                data.data.cast::<u8>(),
                data.length as usize,
            )
        }
    };
    std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| {
        Error::new(libc::EINVAL, format!("{what} not UTF-8").into())
    })
}
