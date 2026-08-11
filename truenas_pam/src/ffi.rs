// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Declarations for the parts of `libpam` this crate uses.
//!
//! Plain declarations; the `unsafe` calls and their `// SAFETY:` notes live in
//! the safe wrappers.
//!
//! These values are ABI, taken from `security/_pam_types.h` and
//! `security/pam_appl.h` in `libpam0g-dev` 1.7.0. Tests pin them, and
//! `PamCode`'s message table, against the linked library.
#![allow(non_camel_case_types)]
// The `unsafe extern` block below is itself an unsafe item, so this module
// lifts the workspace's `deny(unsafe_code)` as the wrapper modules do.
#![allow(unsafe_code)]

use std::os::raw::{c_char, c_int, c_uint, c_void};

/// An opaque transaction handle, only held behind a pointer.
pub enum pam_handle_t {}

/// One prompt or notice from a module. Allocated and freed by libpam; the
/// pointer is valid only for the duration of the conversation call.
#[repr(C)]
pub struct pam_message {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

/// One answer to a [`pam_message`]. Allocated by the application with
/// `malloc`, freed by the module stack with `free`.
#[repr(C)]
pub struct pam_response {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

/// The conversation callback.
///
/// `msg` is an array of `num_msg` pointers to [`pam_message`] — the layout
/// Linux-PAM passes, equivalent to `const struct pam_message *msg[]`.
pub type pam_conv_fn = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *const *const pam_message,
    resp: *mut *mut pam_response,
    appdata_ptr: *mut c_void,
) -> c_int;

/// The callback and its opaque argument, as handed to `pam_start_confdir`.
/// libpam copies the struct but not what `appdata_ptr` points at, so the
/// pointee must outlive the transaction.
#[repr(C)]
pub struct pam_conv {
    pub conv: Option<pam_conv_fn>,
    pub appdata_ptr: *mut c_void,
}

// --- return codes --------------------------------------------------------
// A contiguous block, 0 through 31. Anything else is outside the space the
// standard defines.

pub const PAM_SUCCESS: c_int = 0;
pub const PAM_OPEN_ERR: c_int = 1;
pub const PAM_SYMBOL_ERR: c_int = 2;
pub const PAM_SERVICE_ERR: c_int = 3;
pub const PAM_SYSTEM_ERR: c_int = 4;
pub const PAM_BUF_ERR: c_int = 5;
pub const PAM_PERM_DENIED: c_int = 6;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_CRED_INSUFFICIENT: c_int = 8;
pub const PAM_AUTHINFO_UNAVAIL: c_int = 9;
pub const PAM_USER_UNKNOWN: c_int = 10;
pub const PAM_MAXTRIES: c_int = 11;
pub const PAM_NEW_AUTHTOK_REQD: c_int = 12;
pub const PAM_ACCT_EXPIRED: c_int = 13;
pub const PAM_SESSION_ERR: c_int = 14;
pub const PAM_CRED_UNAVAIL: c_int = 15;
pub const PAM_CRED_EXPIRED: c_int = 16;
pub const PAM_CRED_ERR: c_int = 17;
pub const PAM_NO_MODULE_DATA: c_int = 18;
pub const PAM_CONV_ERR: c_int = 19;
pub const PAM_AUTHTOK_ERR: c_int = 20;
pub const PAM_AUTHTOK_RECOVERY_ERR: c_int = 21;
pub const PAM_AUTHTOK_LOCK_BUSY: c_int = 22;
pub const PAM_AUTHTOK_DISABLE_AGING: c_int = 23;
pub const PAM_TRY_AGAIN: c_int = 24;
pub const PAM_IGNORE: c_int = 25;
pub const PAM_ABORT: c_int = 26;
pub const PAM_AUTHTOK_EXPIRED: c_int = 27;
pub const PAM_MODULE_UNKNOWN: c_int = 28;
pub const PAM_BAD_ITEM: c_int = 29;
pub const PAM_CONV_AGAIN: c_int = 30;
pub const PAM_INCOMPLETE: c_int = 31;

/// One past the last code the standard defines. Used only by the test pinning
/// the shape of the block; `PamCode` is what the crate reads codes through.
#[allow(dead_code)]
pub const PAM_RETURN_VALUES: c_int = 32;

// --- operation flags -----------------------------------------------------

/// Suppress informational messages. Composes with every other flag.
pub const PAM_SILENT: c_int = 0x8000;
/// `pam_authenticate`: refuse an empty authentication token.
pub const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x0001;
/// `pam_chauthtok`: change only a token that has expired.
pub const PAM_CHANGE_EXPIRED_AUTHTOK: c_int = 0x0020;

// --- pam_setcred operations ----------------------------------------------
// Mutually exclusive; each may be OR'd with PAM_SILENT.

pub const PAM_ESTABLISH_CRED: c_int = 0x0002;
pub const PAM_DELETE_CRED: c_int = 0x0004;
pub const PAM_REINITIALIZE_CRED: c_int = 0x0008;
pub const PAM_REFRESH_CRED: c_int = 0x0010;

// --- item types ----------------------------------------------------------
// A partial set: the items this crate exposes. See `Transaction` for the ones
// deliberately left out.

/// The service name. Fixed at `pam_start_confdir`; read-only here.
pub const PAM_SERVICE: c_int = 1;
/// The name of the user the service is for.
pub const PAM_USER: c_int = 2;
/// The terminal name.
pub const PAM_TTY: c_int = 3;
/// The host the request came from.
pub const PAM_RHOST: c_int = 4;
/// The name of the user on the requesting host.
pub const PAM_RUSER: c_int = 8;

// --- conversation message styles -----------------------------------------

/// Prompt for a string, echoing nothing.
pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
/// Prompt for a string, echoing it.
pub const PAM_PROMPT_ECHO_ON: c_int = 2;
/// Display an error message.
pub const PAM_ERROR_MSG: c_int = 3;
/// Display informational text.
pub const PAM_TEXT_INFO: c_int = 4;

// --- conversation limits -------------------------------------------------

/// The most messages one conversation call may carry.
pub const PAM_MAX_NUM_MSG: c_int = 32;

// Every declaration here is `unsafe` to call: raw pointers, no lifetimes, and
// libpam's own preconditions. The safe wrappers uphold those.
unsafe extern "C" {
    /// Begins a transaction, reading service files from `confdir` instead of
    /// the system directory when it is non-null.
    pub fn pam_start_confdir(
        service_name: *const c_char,
        user: *const c_char,
        pam_conversation: *const pam_conv,
        confdir: *const c_char,
        pamh: *mut *mut pam_handle_t,
    ) -> c_int;

    /// Frees the handle whatever it returns: the transaction must not be
    /// touched afterwards. `pam_status` is reported to every module's cleanup
    /// handler, so it must be the status of the last operation.
    pub fn pam_end(pamh: *mut pam_handle_t, pam_status: c_int) -> c_int;

    pub fn pam_authenticate(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_setcred(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_acct_mgmt(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_open_session(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_close_session(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_chauthtok(pamh: *mut pam_handle_t, flags: c_int) -> c_int;

    pub fn pam_set_item(
        pamh: *mut pam_handle_t,
        item_type: c_int,
        item: *const c_void,
    ) -> c_int;
    /// The item stays owned by libpam and is replaced or freed by the next
    /// call that changes it, so it must be copied before control returns to
    /// the library.
    pub fn pam_get_item(
        pamh: *const pam_handle_t,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;

    /// Linux-PAM ignores the handle, so this is callable with a null one.
    /// Used only by the test pinning `PamCode::message` to the linked library;
    /// errors are rendered from this crate's own table.
    #[allow(dead_code)]
    pub fn pam_strerror(
        pamh: *mut pam_handle_t,
        errnum: c_int,
    ) -> *const c_char;

    /// Sets, replaces, or (given a bare name with no `=`) deletes one variable.
    pub fn pam_putenv(
        pamh: *mut pam_handle_t,
        name_value: *const c_char,
    ) -> c_int;
    /// The string belongs to libpam and is valid until the environment changes.
    pub fn pam_getenv(
        pamh: *mut pam_handle_t,
        name: *const c_char,
    ) -> *const c_char;
    /// A null-terminated array of `name=value` strings. Both the strings and
    /// the array are the caller's to `free`.
    pub fn pam_getenvlist(pamh: *mut pam_handle_t) -> *mut *mut c_char;

    pub fn pam_fail_delay(
        pamh: *mut pam_handle_t,
        musec_delay: c_uint,
    ) -> c_int;
}
