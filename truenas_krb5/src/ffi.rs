// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Declarations for the parts of `libkrb5` this crate uses.
//!
//! Plain declarations; the `unsafe` calls and their `// SAFETY:` notes live
//! in the safe wrappers.
//!
//! These types and values are ABI, taken from `krb5/krb5.h` in `libkrb5-dev`
//! 1.21.3. Tests pin the constants, and the error table in
//! [`crate::ErrCode`], against the linked library.
#![allow(non_camel_case_types)]
// The `unsafe extern` block below is itself an unsafe item, so this module
// lifts the workspace's `deny(unsafe_code)` as the wrapper modules do.
#![allow(unsafe_code)]

use std::os::raw::{c_char, c_uint, c_void};

// Fixed-width typedefs, verbatim from the header.
pub type krb5_octet = u8;
pub type krb5_int32 = i32;
pub type krb5_error_code = krb5_int32;
pub type krb5_magic = krb5_error_code;
pub type krb5_boolean = c_uint;
pub type krb5_kvno = c_uint;
pub type krb5_addrtype = krb5_int32;
pub type krb5_enctype = krb5_int32;
pub type krb5_authdatatype = krb5_int32;
pub type krb5_flags = krb5_int32;
pub type krb5_timestamp = krb5_int32;
pub type krb5_deltat = krb5_int32;

// Opaque handles, only held behind a pointer. The typedefs in the header are
// themselves pointers, mirrored here so a declaration reads like the C one.
pub enum krb5_context_st {}
pub type krb5_context = *mut krb5_context_st;
pub enum krb5_kt_st {}
pub type krb5_keytab = *mut krb5_kt_st;
pub enum krb5_ccache_st {}
pub type krb5_ccache = *mut krb5_ccache_st;
pub enum krb5_get_init_creds_opt {}
/// `krb5_prompter_fct`; always passed as null, so the signature is not
/// spelled out.
pub type krb5_prompter_fct = *mut c_void;

/// Cursor for key-table iteration (`krb5_kt_cursor` is `krb5_pointer`).
pub type krb5_kt_cursor = *mut c_void;
/// Cursor for credential-cache iteration.
pub type krb5_cc_cursor = *mut c_void;

/// A counted byte string. `data` is `char *` in C; lengths are unsigned.
#[repr(C)]
pub struct krb5_data {
    pub magic: krb5_magic,
    pub length: c_uint,
    pub data: *mut c_char,
}

/// The body a `krb5_principal` points at: a realm and an array of
/// component strings.
#[repr(C)]
pub struct krb5_principal_data {
    pub magic: krb5_magic,
    pub realm: krb5_data,
    pub data: *mut krb5_data,
    pub length: krb5_int32,
    pub r#type: krb5_int32,
}

pub type krb5_principal = *mut krb5_principal_data;

/// Exposed contents of a key.
#[repr(C)]
pub struct krb5_keyblock {
    pub magic: krb5_magic,
    pub enctype: krb5_enctype,
    pub length: c_uint,
    pub contents: *mut krb5_octet,
}

/// A key-table entry.
#[repr(C)]
pub struct krb5_keytab_entry {
    pub magic: krb5_magic,
    pub principal: krb5_principal,
    pub timestamp: krb5_timestamp,
    pub vno: krb5_kvno,
    pub key: krb5_keyblock,
}

/// Ticket start time, end time, and renewal duration.
#[repr(C)]
pub struct krb5_ticket_times {
    pub authtime: krb5_timestamp,
    pub starttime: krb5_timestamp,
    pub endtime: krb5_timestamp,
    pub renew_till: krb5_timestamp,
}

/// A network address carried in a ticket.
#[repr(C)]
pub struct krb5_address {
    pub magic: krb5_magic,
    pub addrtype: krb5_addrtype,
    pub length: c_uint,
    pub contents: *mut krb5_octet,
}

/// One authorization-data element.
#[repr(C)]
pub struct krb5_authdata {
    pub magic: krb5_magic,
    pub ad_type: krb5_authdatatype,
    pub length: c_uint,
    pub contents: *mut krb5_octet,
}

/// Credentials: ticket, session key, and lifetime info. Field order is the
/// header's — `authdata` is last, after the two ticket strings.
#[repr(C)]
pub struct krb5_creds {
    pub magic: krb5_magic,
    pub client: krb5_principal,
    pub server: krb5_principal,
    pub keyblock: krb5_keyblock,
    pub times: krb5_ticket_times,
    pub is_skey: krb5_boolean,
    pub ticket_flags: krb5_flags,
    pub addresses: *mut *mut krb5_address,
    pub ticket: krb5_data,
    pub second_ticket: krb5_data,
    pub authdata: *mut *mut krb5_authdata,
}

// --- iteration end codes -------------------------------------------------
// The two iterators report exhaustion as these errors rather than through an
// out-parameter.

pub const KRB5_KT_END: krb5_error_code = -1765328202;
pub const KRB5_CC_END: krb5_error_code = -1765328242;

// Every declaration here is `unsafe` to call: raw pointers, no lifetimes,
// and libkrb5's own preconditions — chiefly that every handle is used with
// the context that produced it, from one thread at a time. The safe wrappers
// uphold those.
unsafe extern "C" {
    pub fn krb5_init_context(context: *mut krb5_context) -> krb5_error_code;
    pub fn krb5_free_context(context: krb5_context);

    /// The returned string is owned by the library; release it with
    /// `krb5_free_error_message`, never `free`.
    pub fn krb5_get_error_message(
        ctx: krb5_context,
        code: krb5_error_code,
    ) -> *const c_char;
    pub fn krb5_free_error_message(ctx: krb5_context, msg: *const c_char);

    pub fn krb5_parse_name(
        context: krb5_context,
        name: *const c_char,
        principal_out: *mut krb5_principal,
    ) -> krb5_error_code;
    pub fn krb5_unparse_name(
        context: krb5_context,
        principal: krb5_principal,
        name: *mut *mut c_char,
    ) -> krb5_error_code;
    pub fn krb5_free_principal(context: krb5_context, val: krb5_principal);
    pub fn krb5_free_unparsed_name(context: krb5_context, val: *mut c_char);
    #[allow(dead_code)]
    pub fn krb5_principal_compare(
        context: krb5_context,
        princ1: krb5_principal,
        princ2: krb5_principal,
    ) -> krb5_boolean;
    /// True for a cache's config entries (`X-CACHECONF:` realm), which are
    /// stored as pseudo-credentials and are not real tickets.
    pub fn krb5_is_config_principal(
        context: krb5_context,
        principal: krb5_principal,
    ) -> krb5_boolean;

    pub fn krb5_kt_resolve(
        context: krb5_context,
        name: *const c_char,
        ktid: *mut krb5_keytab,
    ) -> krb5_error_code;
    pub fn krb5_kt_default(
        context: krb5_context,
        id: *mut krb5_keytab,
    ) -> krb5_error_code;
    pub fn krb5_kt_get_name(
        context: krb5_context,
        keytab: krb5_keytab,
        name: *mut c_char,
        namelen: c_uint,
    ) -> krb5_error_code;
    pub fn krb5_kt_get_type(
        context: krb5_context,
        keytab: krb5_keytab,
    ) -> *const c_char;
    pub fn krb5_kt_close(
        context: krb5_context,
        keytab: krb5_keytab,
    ) -> krb5_error_code;
    pub fn krb5_kt_start_seq_get(
        context: krb5_context,
        keytab: krb5_keytab,
        cursor: *mut krb5_kt_cursor,
    ) -> krb5_error_code;
    /// Argument order differs from the ccache iterator: entry before cursor.
    pub fn krb5_kt_next_entry(
        context: krb5_context,
        keytab: krb5_keytab,
        entry: *mut krb5_keytab_entry,
        cursor: *mut krb5_kt_cursor,
    ) -> krb5_error_code;
    pub fn krb5_kt_end_seq_get(
        context: krb5_context,
        keytab: krb5_keytab,
        cursor: *mut krb5_kt_cursor,
    ) -> krb5_error_code;
    pub fn krb5_free_keytab_entry_contents(
        context: krb5_context,
        entry: *mut krb5_keytab_entry,
    ) -> krb5_error_code;
    pub fn krb5_kt_add_entry(
        context: krb5_context,
        id: krb5_keytab,
        entry: *mut krb5_keytab_entry,
    ) -> krb5_error_code;
    pub fn krb5_kt_remove_entry(
        context: krb5_context,
        id: krb5_keytab,
        entry: *mut krb5_keytab_entry,
    ) -> krb5_error_code;

    pub fn krb5_c_string_to_key(
        context: krb5_context,
        enctype: krb5_enctype,
        string: *const krb5_data,
        salt: *const krb5_data,
        key: *mut krb5_keyblock,
    ) -> krb5_error_code;
    pub fn krb5_principal2salt(
        context: krb5_context,
        pr: krb5_principal,
        ret: *mut krb5_data,
    ) -> krb5_error_code;
    pub fn krb5_free_keyblock_contents(
        context: krb5_context,
        key: *mut krb5_keyblock,
    );
    pub fn krb5_free_data_contents(context: krb5_context, val: *mut krb5_data);

    pub fn krb5_cc_resolve(
        context: krb5_context,
        name: *const c_char,
        cache: *mut krb5_ccache,
    ) -> krb5_error_code;
    pub fn krb5_cc_default(
        context: krb5_context,
        ccache: *mut krb5_ccache,
    ) -> krb5_error_code;
    /// Returns a pointer owned by the cache handle; not freed by the caller.
    pub fn krb5_cc_get_name(
        context: krb5_context,
        cache: krb5_ccache,
    ) -> *const c_char;
    pub fn krb5_cc_get_type(
        context: krb5_context,
        cache: krb5_ccache,
    ) -> *const c_char;
    pub fn krb5_cc_close(
        context: krb5_context,
        cache: krb5_ccache,
    ) -> krb5_error_code;
    /// Frees the handle whatever it returns: the cache must not be touched
    /// afterwards, not even to close it.
    pub fn krb5_cc_destroy(
        context: krb5_context,
        cache: krb5_ccache,
    ) -> krb5_error_code;
    pub fn krb5_cc_start_seq_get(
        context: krb5_context,
        cache: krb5_ccache,
        cursor: *mut krb5_cc_cursor,
    ) -> krb5_error_code;
    /// Argument order differs from the keytab iterator: cursor before creds.
    pub fn krb5_cc_next_cred(
        context: krb5_context,
        cache: krb5_ccache,
        cursor: *mut krb5_cc_cursor,
        creds: *mut krb5_creds,
    ) -> krb5_error_code;
    pub fn krb5_cc_end_seq_get(
        context: krb5_context,
        cache: krb5_ccache,
        cursor: *mut krb5_cc_cursor,
    ) -> krb5_error_code;
    pub fn krb5_free_cred_contents(context: krb5_context, val: *mut krb5_creds);

    pub fn krb5_get_init_creds_opt_alloc(
        context: krb5_context,
        opt: *mut *mut krb5_get_init_creds_opt,
    ) -> krb5_error_code;
    pub fn krb5_get_init_creds_opt_free(
        context: krb5_context,
        opt: *mut krb5_get_init_creds_opt,
    );
    pub fn krb5_get_init_creds_opt_set_out_ccache(
        context: krb5_context,
        opt: *mut krb5_get_init_creds_opt,
        ccache: krb5_ccache,
    ) -> krb5_error_code;
    pub fn krb5_get_init_creds_keytab(
        context: krb5_context,
        creds: *mut krb5_creds,
        client: krb5_principal,
        arg_keytab: krb5_keytab,
        start_time: krb5_deltat,
        in_tkt_service: *const c_char,
        k5_gic_options: *mut krb5_get_init_creds_opt,
    ) -> krb5_error_code;
    pub fn krb5_get_init_creds_password(
        context: krb5_context,
        creds: *mut krb5_creds,
        client: krb5_principal,
        password: *const c_char,
        prompter: krb5_prompter_fct,
        data: *mut c_void,
        start_time: krb5_deltat,
        in_tkt_service: *const c_char,
        k5_gic_options: *mut krb5_get_init_creds_opt,
    ) -> krb5_error_code;
}
