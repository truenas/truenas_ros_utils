// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Declarations for the parts of `libgssapi_krb5` this crate uses.
//!
//! Plain declarations; the `unsafe` calls and their `// SAFETY:` notes live
//! in the safe wrappers.
//!
//! These types and values are ABI, taken from `gssapi/gssapi.h` and
//! `gssapi/gssapi_ext.h` in `libkrb5-dev` 1.21.3 (RFC 2744's C bindings
//! plus the credential-store extension). Tests pin this crate's OID tables
//! against the OIDs the linked library exports.
#![allow(non_camel_case_types)]
// The `unsafe extern` blocks below are themselves unsafe items, so this
// module lifts the workspace's `deny(unsafe_code)` as the wrapper modules
// do.
#![allow(unsafe_code)]

use std::os::raw::{c_char, c_int, c_void};

pub type OM_uint32 = u32;
pub type gss_cred_usage_t = c_int;

// Opaque handles, only held behind a pointer.
pub enum gss_name_struct {}
pub type gss_name_t = *mut gss_name_struct;
pub enum gss_cred_id_struct {}
pub type gss_cred_id_t = *mut gss_cred_id_struct;
pub enum gss_ctx_id_struct {}
pub type gss_ctx_id_t = *mut gss_ctx_id_struct;
pub enum gss_channel_bindings_struct {}
pub type gss_channel_bindings_t = *mut gss_channel_bindings_struct;

/// A counted byte string. Outputs are allocated by the library and owed a
/// `gss_release_buffer`.
#[repr(C)]
pub struct gss_buffer_desc {
    pub length: usize,
    pub value: *mut c_void,
}
pub type gss_buffer_t = *mut gss_buffer_desc;

/// An object identifier: the BER arc octets, without tag or length.
#[repr(C)]
pub struct gss_OID_desc {
    pub length: OM_uint32,
    pub elements: *mut c_void,
}
pub type gss_OID = *mut gss_OID_desc;

/// A counted set of OIDs.
#[repr(C)]
pub struct gss_OID_set_desc {
    pub count: usize,
    pub elements: gss_OID,
}
pub type gss_OID_set = *mut gss_OID_set_desc;

/// One credential-store element (`gssapi_ext.h`).
#[repr(C)]
pub struct gss_key_value_element_desc {
    pub key: *const c_char,
    pub value: *const c_char,
}

/// A credential store: counted key/value elements (`gssapi_ext.h`).
#[repr(C)]
pub struct gss_key_value_set_desc {
    pub count: OM_uint32,
    pub elements: *mut gss_key_value_element_desc,
}

// --- major-status layout --------------------------------------------------
// One OM_uint32: calling errors in bits 24..32, routine errors in 16..24,
// supplementary bits in 0..16.

pub const GSS_S_COMPLETE: OM_uint32 = 0;
pub const GSS_C_CALLING_ERROR_OFFSET: u32 = 24;
pub const GSS_C_ROUTINE_ERROR_OFFSET: u32 = 16;
pub const GSS_C_CALLING_ERROR_MASK: OM_uint32 = 0o377;
pub const GSS_C_ROUTINE_ERROR_MASK: OM_uint32 = 0o377;
pub const GSS_C_SUPPLEMENTARY_MASK: OM_uint32 = 0o177777;
pub const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;

// --- request/return flags -------------------------------------------------

pub const GSS_C_DELEG_FLAG: OM_uint32 = 1;
pub const GSS_C_MUTUAL_FLAG: OM_uint32 = 2;
pub const GSS_C_REPLAY_FLAG: OM_uint32 = 4;
pub const GSS_C_SEQUENCE_FLAG: OM_uint32 = 8;
pub const GSS_C_CONF_FLAG: OM_uint32 = 16;
pub const GSS_C_INTEG_FLAG: OM_uint32 = 32;
pub const GSS_C_ANON_FLAG: OM_uint32 = 64;
pub const GSS_C_PROT_READY_FLAG: OM_uint32 = 128;
pub const GSS_C_TRANS_FLAG: OM_uint32 = 256;

// --- assorted constants ---------------------------------------------------

/// Acceptor credential usage.
pub const GSS_C_ACCEPT: gss_cred_usage_t = 2;
/// "As long as possible" for `time_req`.
pub const GSS_C_INDEFINITE: OM_uint32 = 0xffff_ffff;
/// `gss_display_status`: the code is a major status.
pub const GSS_C_GSS_CODE: c_int = 1;
/// `gss_display_status`: the code is a mechanism minor status.
pub const GSS_C_MECH_CODE: c_int = 2;

// Every declaration here is `unsafe` to call: raw pointers, no lifetimes,
// and the C bindings' own preconditions. The safe wrappers uphold those.
unsafe extern "C" {
    pub fn gss_release_buffer(
        minor_status: *mut OM_uint32,
        buffer: gss_buffer_t,
    ) -> OM_uint32;

    pub fn gss_display_status(
        minor_status: *mut OM_uint32,
        status_value: OM_uint32,
        status_type: c_int,
        mech_type: gss_OID,
        message_context: *mut OM_uint32,
        status_string: gss_buffer_t,
    ) -> OM_uint32;

    pub fn gss_import_name(
        minor_status: *mut OM_uint32,
        input_name_buffer: gss_buffer_t,
        input_name_type: gss_OID,
        output_name: *mut gss_name_t,
    ) -> OM_uint32;
    pub fn gss_display_name(
        minor_status: *mut OM_uint32,
        input_name: gss_name_t,
        output_name_buffer: gss_buffer_t,
        output_name_type: *mut gss_OID,
    ) -> OM_uint32;
    pub fn gss_export_name(
        minor_status: *mut OM_uint32,
        input_name: gss_name_t,
        exported_name: gss_buffer_t,
    ) -> OM_uint32;
    pub fn gss_canonicalize_name(
        minor_status: *mut OM_uint32,
        input_name: gss_name_t,
        mech_type: gss_OID,
        output_name: *mut gss_name_t,
    ) -> OM_uint32;
    pub fn gss_compare_name(
        minor_status: *mut OM_uint32,
        name1: gss_name_t,
        name2: gss_name_t,
        name_equal: *mut c_int,
    ) -> OM_uint32;
    pub fn gss_release_name(
        minor_status: *mut OM_uint32,
        input_name: *mut gss_name_t,
    ) -> OM_uint32;

    /// From `gssapi_ext.h`: map a mechanism name to a local user name,
    /// through the mechanism's own rules (for Kerberos, `auth_to_local`).
    pub fn gss_localname(
        minor: *mut OM_uint32,
        name: gss_name_t,
        mech_type: gss_OID,
        localname: gss_buffer_t,
    ) -> OM_uint32;

    pub fn gss_acquire_cred(
        minor_status: *mut OM_uint32,
        desired_name: gss_name_t,
        time_req: OM_uint32,
        desired_mechs: gss_OID_set,
        cred_usage: gss_cred_usage_t,
        output_cred_handle: *mut gss_cred_id_t,
        actual_mechs: *mut gss_OID_set,
        time_rec: *mut OM_uint32,
    ) -> OM_uint32;
    /// From `gssapi_ext.h`: acquire against an explicit credential store —
    /// here always a `keytab` element.
    pub fn gss_acquire_cred_from(
        minor_status: *mut OM_uint32,
        desired_name: gss_name_t,
        time_req: OM_uint32,
        desired_mechs: gss_OID_set,
        cred_usage: gss_cred_usage_t,
        cred_store: *const gss_key_value_set_desc,
        output_cred_handle: *mut gss_cred_id_t,
        actual_mechs: *mut gss_OID_set,
        time_rec: *mut OM_uint32,
    ) -> OM_uint32;
    pub fn gss_release_cred(
        minor_status: *mut OM_uint32,
        cred_handle: *mut gss_cred_id_t,
    ) -> OM_uint32;

    pub fn gss_accept_sec_context(
        minor_status: *mut OM_uint32,
        context_handle: *mut gss_ctx_id_t,
        acceptor_cred_handle: gss_cred_id_t,
        input_token_buffer: gss_buffer_t,
        input_chan_bindings: gss_channel_bindings_t,
        src_name: *mut gss_name_t,
        mech_type: *mut gss_OID,
        output_token: gss_buffer_t,
        ret_flags: *mut OM_uint32,
        time_rec: *mut OM_uint32,
        delegated_cred_handle: *mut gss_cred_id_t,
    ) -> OM_uint32;
    pub fn gss_delete_sec_context(
        minor_status: *mut OM_uint32,
        context_handle: *mut gss_ctx_id_t,
        output_token: gss_buffer_t,
    ) -> OM_uint32;
}

// The library's exported OID variables, declared for the tests that pin
// this crate's own OID tables against them.
#[allow(dead_code)]
unsafe extern "C" {
    pub static gss_mech_krb5: gss_OID;
    pub static GSS_C_NT_HOSTBASED_SERVICE: gss_OID;
    pub static GSS_C_NT_USER_NAME: gss_OID;
    pub static GSS_C_NT_EXPORT_NAME: gss_OID;
    pub static GSS_KRB5_NT_PRINCIPAL_NAME: gss_OID;
}
