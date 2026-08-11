// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Transaction`] — one PAM transaction, `pam_start_confdir` to `pam_end`.
//!
//! # One thread at a time
//!
//! A `pam_handle_t` is not a thread-safe object: libpam does no internal
//! locking and its entry points refuse a call made while another is already in
//! progress on the handle. Every operation here therefore takes `&mut self`:
//! a transaction is driven only by whoever holds it. Give each concurrent
//! authentication its own.
//!
//! A module may itself be unsafe to run concurrently, in which case one
//! transaction per thread is not enough and the consumer needs one lock
//! covering all of them.
//!
//! # Safety
//!
//! This module calls `libpam`, so it lifts the workspace's
//! `deny(unsafe_code)`; every block carries a `// SAFETY:` note. Invariants:
//!
//! - The handle comes from `pam_start_confdir`, is never handed out, and is
//!   ended exactly once, in [`Drop`].
//! - The conversation slot is `Box::into_raw`ed so its address is fixed for
//!   the life of the handle: libpam copies the `pam_conv` struct at
//!   `pam_start_confdir` but not what its `appdata_ptr` points at. It is freed
//!   after `pam_end`, because a module's cleanup handler may converse.
//! - No `&mut ConvSlot` is live across a `pam_*()` call, so the one the
//!   trampoline forms is unique.
//! - Items borrow libpam's own storage, which the next call that changes them
//!   frees. The borrow is bounded by `&self`, so no such call can run while it
//!   is live.
#![allow(unsafe_code)]

use crate::conv::{
    ConvSlot, Conversation, Failure, OwnedMessage, Unattended, trampoline,
};
use crate::error::{Error, PamCode, Result, check};
use crate::ffi::*;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Duration;

bitflags::bitflags! {
    /// Flags for the stack operations.
    ///
    /// One set covers every operation: each honours the flags meaningful to
    /// it and ignores the rest. [`SILENT`](Flags::SILENT) composes with every
    /// other flag.
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct Flags: c_int {
        /// Do not send informational messages. Prompting is unaffected: a
        /// module still asks for whatever it needs.
        const SILENT = PAM_SILENT;
        /// [`Transaction::authenticate`] and [`Transaction::setcred`]: refuse
        /// an account whose authentication token is empty.
        const DISALLOW_NULL_AUTHTOK = PAM_DISALLOW_NULL_AUTHTOK;
        /// [`Transaction::chauthtok`]: change the token only if it has
        /// expired.
        const CHANGE_EXPIRED_AUTHTOK = PAM_CHANGE_EXPIRED_AUTHTOK;
    }
}

/// What [`Transaction::setcred`] should do with the user's credentials. The
/// four are mutually exclusive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum CredOp {
    /// Grant the credentials the modules established.
    Establish = PAM_ESTABLISH_CRED,
    /// Revoke them.
    Delete = PAM_DELETE_CRED,
    /// Revoke and grant again, for a session changing hands.
    Reinitialize = PAM_REINITIALIZE_CRED,
    /// Extend the lifetime of the existing ones.
    Refresh = PAM_REFRESH_CRED,
}

impl CredOp {
    /// The raw value libpam uses for this operation.
    pub const fn raw(self) -> i32 {
        self as i32
    }
}

/// Assembles a [`Transaction`].
///
/// The service name fixes which stack of modules runs, so it must be a
/// constant of the program and never anything the user can influence.
///
/// The stack is read here, so a service the configuration does not name, and
/// has no `other` to fall back to, fails at this point rather than at the
/// first operation.
///
/// ```no_run
/// # use truenas_pam::Transaction;
/// let transaction = Transaction::builder("truenas")
///     .user("alice")
///     .rhost("198.51.100.7")
///     .build()?;
///
/// assert_eq!(transaction.service()?, Some("truenas"));
/// # Ok::<(), truenas_pam::Error>(())
/// ```
pub struct Builder {
    service: String,
    user: Option<String>,
    confdir: Option<PathBuf>,
    ruser: Option<String>,
    rhost: Option<String>,
    tty: Option<String>,
    fail_delay: Option<Duration>,
    conversation: Option<Box<dyn Conversation>>,
}

impl Builder {
    /// The name of the user the service is for.
    ///
    /// Leaving it unset is legitimate: the stack then asks for it through the
    /// conversation, with a [`PromptEchoOn`](crate::MsgStyle::PromptEchoOn)
    /// message.
    pub fn user(mut self, user: &str) -> Builder {
        self.user = Some(user.to_owned());
        self
    }

    /// Read service files from this directory instead of the system one.
    pub fn confdir(mut self, dir: &Path) -> Builder {
        self.confdir = Some(dir.to_owned());
        self
    }

    /// The name of the user on the requesting host.
    ///
    /// Set it only when the requesting identity is actually known; how far it
    /// is trusted is then the administrator's decision, and a module may
    /// override it with something it can verify.
    pub fn ruser(mut self, ruser: &str) -> Builder {
        self.ruser = Some(ruser.to_owned());
        self
    }

    /// The host the request came from. `localhost` means the local system;
    /// leaving it unset means unknown.
    pub fn rhost(mut self, rhost: &str) -> Builder {
        self.rhost = Some(rhost.to_owned());
        self
    }

    /// The terminal the request came from.
    pub fn tty(mut self, tty: &str) -> Builder {
        self.tty = Some(tty.to_owned());
        self
    }

    /// How long the stack should pause after a failure, before returning.
    ///
    /// libpam applies a random jitter of up to 25% and takes the largest
    /// request any module made. Rounded down to whole microseconds and capped
    /// at what `unsigned int` holds.
    pub fn fail_delay(mut self, delay: Duration) -> Builder {
        self.fail_delay = Some(delay);
        self
    }

    /// The conversation modules will reach the application through. Defaults
    /// to [`Unattended`].
    pub fn conversation(mut self, conv: Box<dyn Conversation>) -> Builder {
        self.conversation = Some(conv);
        self
    }

    /// Begin the transaction.
    pub fn build(self) -> Result<Transaction> {
        let service = cstring(&self.service)?;
        let user = self.user.as_deref().map(cstring).transpose()?;
        let confdir = self.confdir.as_deref().map(cpath).transpose()?;

        let conv = self.conversation.unwrap_or_else(|| Box::new(Unattended));
        let slot = Box::into_raw(Box::new(ConvSlot::new(conv)));
        let registered = pam_conv {
            conv: Some(trampoline),
            appdata_ptr: slot as *mut c_void,
        };

        let mut hdl: *mut pam_handle_t = ptr::null_mut();
        // SAFETY: NUL-terminated strings that outlive the call, a conversation
        // whose `appdata_ptr` outlives the handle, and an out-parameter for
        // the new handle.
        let rc = unsafe {
            pam_start_confdir(
                service.as_ptr(),
                user.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                &registered,
                confdir.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                &mut hdl,
            )
        };
        if let Err(e) = check(rc) {
            // Nothing was started, so only the slot is ours to reclaim.
            // SAFETY: from `Box::into_raw` above, never handed to libpam for
            // longer than the failed call, and freed exactly once.
            drop(unsafe { Box::from_raw(slot) });
            return Err(e);
        }

        // Configuration failures below return through `?`, so the transaction
        // must already exist for its `Drop` to end the handle. Nothing has run
        // yet, so `PAM_ABORT` is what any such teardown reports.
        let mut txn = Transaction {
            hdl,
            slot,
            last: PAM_ABORT,
        };
        if let Some(v) = &self.ruser {
            txn.set_ruser(v)?;
        }
        if let Some(v) = &self.rhost {
            txn.set_rhost(v)?;
        }
        if let Some(v) = &self.tty {
            txn.set_tty(v)?;
        }
        if let Some(d) = self.fail_delay {
            txn.set_fail_delay(d)?;
        }
        txn.last = PAM_SUCCESS;
        Ok(txn)
    }
}

impl std::fmt::Debug for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder")
            .field("service", &self.service)
            .field("user", &self.user)
            .field("confdir", &self.confdir)
            .finish_non_exhaustive()
    }
}

/// One PAM transaction.
///
/// Ended when it drops, reporting the status of the last operation to every
/// module's cleanup handler.
pub struct Transaction {
    hdl: *mut pam_handle_t,
    /// The `appdata_ptr` libpam captured. Owned here; see the module note.
    slot: *mut ConvSlot,
    /// The status handed to `pam_end`.
    last: c_int,
}

// SAFETY: the handle is owned exclusively — every operation takes `&mut self`
// and it is never exposed — so at most one thread uses it at a time whichever
// thread that is. libpam keeps no per-thread state for a handle. Not `Sync`:
// there is no shared use of one to make sound.
unsafe impl Send for Transaction {}

impl Transaction {
    /// Start assembling a transaction for `service`, the name of the stack in
    /// `/etc/pam.d` to run.
    pub fn builder(service: &str) -> Builder {
        Builder {
            service: service.to_owned(),
            user: None,
            confdir: None,
            ruser: None,
            rhost: None,
            tty: None,
            fail_delay: None,
            conversation: None,
        }
    }

    // --- stack operations ------------------------------------------------

    /// Authenticate the user, prompting through the conversation.
    ///
    /// Honours [`SILENT`](Flags::SILENT) and
    /// [`DISALLOW_NULL_AUTHTOK`](Flags::DISALLOW_NULL_AUTHTOK).
    pub fn authenticate(&mut self, flags: Flags) -> Result<()> {
        self.stack_op(pam_authenticate, flags.bits())
    }

    /// Check that the account is valid: not expired, not locked, permitted at
    /// this time and from this host.
    ///
    /// Run it after authentication succeeds. [`NewAuthtokReqd`](
    /// crate::PamCode::NewAuthtokReqd) means the account is good but its
    /// password must be changed before it can be used.
    ///
    /// Honours [`SILENT`](Flags::SILENT).
    pub fn acct_mgmt(&mut self, flags: Flags) -> Result<()> {
        self.stack_op(pam_acct_mgmt, flags.bits())
    }

    /// Change the authentication token, prompting through the conversation.
    ///
    /// Honours [`SILENT`](Flags::SILENT) and
    /// [`CHANGE_EXPIRED_AUTHTOK`](Flags::CHANGE_EXPIRED_AUTHTOK).
    pub fn chauthtok(&mut self, flags: Flags) -> Result<()> {
        self.stack_op(pam_chauthtok, flags.bits())
    }

    /// Establish, revoke, or refresh the user's credentials.
    ///
    /// Run [`CredOp::Establish`] after authentication and before opening a
    /// session, and [`CredOp::Delete`] after closing it.
    ///
    /// Honours [`SILENT`](Flags::SILENT).
    pub fn setcred(&mut self, op: CredOp, flags: Flags) -> Result<()> {
        self.stack_op(pam_setcred, op.raw() | flags.bits())
    }

    /// Open a session for the authenticated user.
    ///
    /// Honours [`SILENT`](Flags::SILENT).
    pub fn open_session(&mut self, flags: Flags) -> Result<()> {
        self.stack_op(pam_open_session, flags.bits())
    }

    /// Close the session.
    ///
    /// Honours [`SILENT`](Flags::SILENT).
    pub fn close_session(&mut self, flags: Flags) -> Result<()> {
        self.stack_op(pam_close_session, flags.bits())
    }

    // --- items -----------------------------------------------------------
    //
    // A partial set. `PAM_AUTHTOK` and `PAM_OLDAUTHTOK` are omitted: a
    // password reaches a module through the conversation, and writing one into
    // the handle leaves it there for every later module to read. `PAM_CONV` is
    // omitted because this crate owns it — swap a conversation with
    // `set_conversation`. The `PAM_FAIL_DELAY` function pointer is omitted in
    // favour of `Builder::fail_delay`. `PAM_XDISPLAY`, `PAM_XAUTHDATA`,
    // `PAM_USER_PROMPT`, and `PAM_AUTHTOK_TYPE` are omitted as having no
    // bearing on a network service.

    /// The service name, fixed when the transaction began.
    pub fn service(&self) -> Result<Option<&str>> {
        self.item_str(PAM_SERVICE)
    }

    /// The name of the user the service is for.
    ///
    /// Read it again after every operation rather than caching it: a module
    /// may rewrite it, and a stack that maps or canonicalises names does.
    pub fn user(&self) -> Result<Option<&str>> {
        self.item_str(PAM_USER)
    }

    /// Set the user name.
    pub fn set_user(&mut self, user: &str) -> Result<()> {
        self.set_item_str(PAM_USER, user)
    }

    /// The name of the user on the requesting host.
    pub fn ruser(&self) -> Result<Option<&str>> {
        self.item_str(PAM_RUSER)
    }

    /// Set the requesting user name. See [`Builder::ruser`].
    pub fn set_ruser(&mut self, ruser: &str) -> Result<()> {
        self.set_item_str(PAM_RUSER, ruser)
    }

    /// The host the request came from.
    pub fn rhost(&self) -> Result<Option<&str>> {
        self.item_str(PAM_RHOST)
    }

    /// Set the requesting host.
    pub fn set_rhost(&mut self, rhost: &str) -> Result<()> {
        self.set_item_str(PAM_RHOST, rhost)
    }

    /// The terminal the request came from.
    pub fn tty(&self) -> Result<Option<&str>> {
        self.item_str(PAM_TTY)
    }

    /// Set the terminal.
    pub fn set_tty(&mut self, tty: &str) -> Result<()> {
        self.set_item_str(PAM_TTY, tty)
    }

    /// How long the stack should pause after a failure. See
    /// [`Builder::fail_delay`].
    pub fn set_fail_delay(&mut self, delay: Duration) -> Result<()> {
        let usec = delay.as_micros().min(u32::MAX as u128) as u32;
        // SAFETY: a live handle.
        check(unsafe { pam_fail_delay(self.hdl, usec) })
    }

    // --- the PAM environment ---------------------------------------------
    //
    // Built on `pam_putenv` alone. `libpam_misc` is not linked, so
    // `pam_misc_setenv`'s read-only variables are not offered.

    /// One variable of the PAM environment.
    ///
    /// This environment is what modules pass to each other and to the
    /// application; an application may go on to put it in the session's own
    /// environment, so it must not be used to carry anything secret.
    pub fn getenv(&self, name: &str) -> Result<Option<&str>> {
        let name = cstring(name)?;
        // SAFETY: a live handle and a NUL-terminated name.
        let p = unsafe { pam_getenv(self.hdl, name.as_ptr()) };
        if p.is_null() {
            return Ok(None);
        }
        // SAFETY: NUL-terminated and owned by libpam until the environment
        // changes, which needs `&mut self` and so cannot happen while this
        // borrow of `&self` is live.
        let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
        std::str::from_utf8(bytes)
            .map(Some)
            .map_err(|_| Error::NotUtf8)
    }

    /// Set a variable, replacing any previous value.
    pub fn putenv(&mut self, name: &str, value: &str) -> Result<()> {
        check_env_name(name)?;
        self.raw_putenv(&format!("{name}={value}"))
    }

    /// Remove a variable, reporting whether it was there.
    ///
    /// Removing one that was never set is `Ok(false)`, not an error: libpam
    /// distinguishes the two with `PAM_BAD_ITEM`, which says only that the
    /// name was absent.
    pub fn unsetenv(&mut self, name: &str) -> Result<bool> {
        check_env_name(name)?;
        match self.raw_putenv(name) {
            Ok(()) => Ok(true),
            Err(Error::Pam(PamCode::BadItem)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// The whole PAM environment, in the order libpam holds it.
    pub fn env(&self) -> Result<Vec<(String, String)>> {
        // SAFETY: a live handle. The array and every string in it become ours.
        let list = unsafe { pam_getenvlist(self.hdl) };
        if list.is_null() {
            return Err(Error::Pam(PamCode::BufErr));
        }
        let mut out = Vec::new();
        // Freeing continues past a malformed entry: the allocation is ours
        // whether or not the contents can be read.
        let mut failed = None;
        let mut i = 0;
        loop {
            // SAFETY: a null-terminated array of pointers.
            let entry = unsafe { *list.add(i) };
            if entry.is_null() {
                break;
            }
            // SAFETY: NUL-terminated, and ours to free.
            let bytes = unsafe { CStr::from_ptr(entry) }.to_bytes();
            match split_env(bytes) {
                Ok(pair) => out.push(pair),
                Err(e) => failed = failed.or(Some(e)),
            }
            // SAFETY: from libpam's own allocator, freed exactly once.
            unsafe { libc::free(entry as *mut c_void) };
            i += 1;
        }
        // SAFETY: the array itself, freed exactly once after its contents.
        unsafe { libc::free(list as *mut c_void) };
        match failed {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    // --- the conversation ------------------------------------------------

    /// Install a different conversation, returning the one it displaced.
    pub fn set_conversation(
        &mut self,
        conv: Box<dyn Conversation>,
    ) -> Box<dyn Conversation> {
        self.slot_mut().replace_conv(conv)
    }

    /// Every conversation round so far, oldest first, one entry per call the
    /// stack made.
    ///
    /// Recorded whatever conversation is installed, so a prompt that went
    /// unanswered is here too. This is how a failure gets read after the fact:
    /// the code says the stack refused, the messages say what it said.
    pub fn messages(&self) -> &[Vec<OwnedMessage>] {
        // SAFETY: the slot is live for the whole transaction, and the borrow
        // is bounded by `&self`.
        unsafe { (*self.slot).log() }
    }

    /// Take the recorded rounds, leaving none behind.
    pub fn take_messages(&mut self) -> Vec<Vec<OwnedMessage>> {
        let taken = self.messages().to_vec();
        self.slot_mut().clear_log();
        taken
    }

    // --- internals -------------------------------------------------------

    /// Run one stack operation, recording its status for `pam_end` and
    /// preferring the conversation's own reason over `PAM_CONV_ERR`.
    fn stack_op(
        &mut self,
        op: unsafe extern "C" fn(*mut pam_handle_t, c_int) -> c_int,
        flags: c_int,
    ) -> Result<()> {
        // SAFETY: a live handle. The trampoline may run inside this call and
        // forms the only reference to the slot, since none is live here.
        let rc = unsafe { op(self.hdl, flags) };
        self.last = rc;
        self.take_conv_failure()?;
        check(rc)
    }

    /// Report why the conversation stopped, if it did.
    ///
    /// A conversation failure is reported ahead of the stack's own code,
    /// since `PAM_CONV_ERR` is all a module can be told. A panic resumes here,
    /// on the thread that drove the call, once libpam has unwound its own
    /// frames.
    fn take_conv_failure(&mut self) -> Result<()> {
        match self.slot_mut().take_failure() {
            None => Ok(()),
            Some(Failure::Err(e)) => Err(e),
            Some(Failure::Panic(payload)) => std::panic::resume_unwind(payload),
        }
    }

    fn slot_mut(&mut self) -> &mut ConvSlot {
        // SAFETY: the slot is live for the whole transaction, and no libpam
        // call is in progress, so no other reference to it exists.
        unsafe { &mut *self.slot }
    }

    fn item_str(&self, item_type: c_int) -> Result<Option<&str>> {
        let mut item: *const c_void = ptr::null();
        // SAFETY: a live handle and an out-parameter. The item stays owned by
        // libpam.
        check(unsafe { pam_get_item(self.hdl, item_type, &mut item) })?;
        if item.is_null() {
            return Ok(None);
        }
        // SAFETY: every item read here is a NUL-terminated string, valid until
        // a call that replaces it — which needs `&mut self`, so it cannot
        // happen while this borrow of `&self` is live.
        let bytes = unsafe { CStr::from_ptr(item as *const c_char) }.to_bytes();
        std::str::from_utf8(bytes)
            .map(Some)
            .map_err(|_| Error::NotUtf8)
    }

    fn set_item_str(&mut self, item_type: c_int, value: &str) -> Result<()> {
        let value = cstring(value)?;
        // SAFETY: a live handle and a NUL-terminated string, which libpam
        // copies before returning.
        check(unsafe {
            pam_set_item(self.hdl, item_type, value.as_ptr() as *const c_void)
        })
    }

    fn raw_putenv(&mut self, entry: &str) -> Result<()> {
        let entry = cstring(entry)?;
        // SAFETY: a live handle and a NUL-terminated string, which libpam
        // copies before returning.
        check(unsafe { pam_putenv(self.hdl, entry.as_ptr()) })
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        // SAFETY: a live handle, ended exactly once.
        unsafe { pam_end(self.hdl, self.last) };
        // After `pam_end`, never before: it runs every module's cleanup
        // handler, and a handler may converse.
        // SAFETY: from `Box::into_raw` in `Builder::build`, unreachable from
        // libpam now, and freed exactly once.
        drop(unsafe { Box::from_raw(self.slot) });
    }
}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("service", &self.service().ok().flatten())
            .field("user", &self.user().ok().flatten())
            .finish_non_exhaustive()
    }
}

/// Borrow a Rust string as a C one.
fn cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::NulByte)
}

/// Borrow a path as a C string.
fn cpath(p: &Path) -> Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| Error::NulByte)
}

/// An environment variable name must be non-empty and hold no `=`: libpam
/// splits its entries at the first one.
fn check_env_name(name: &str) -> Result<()> {
    if name.is_empty() || name.contains('=') {
        return Err(Error::InvalidName);
    }
    Ok(())
}

/// Split one `name=value` entry. libpam emits nothing else, so an entry with
/// no `=` is taken as a name with an empty value rather than discarded.
fn split_env(entry: &[u8]) -> Result<(String, String)> {
    let (name, value) = match entry.iter().position(|b| *b == b'=') {
        Some(i) => (&entry[..i], &entry[i + 1..]),
        None => (entry, &[][..]),
    };
    let name = std::str::from_utf8(name).map_err(|_| Error::NotUtf8)?;
    let value = std::str::from_utf8(value).map_err(|_| Error::NotUtf8)?;
    Ok((name.to_owned(), value.to_owned()))
}

#[cfg(test)]
mod tests {
    //! Behaviour needing a live stack is in `tests/`; these cover the pieces
    //! that stand alone.
    use super::*;

    #[test]
    fn flags_carry_pams_own_bits() {
        // Written out by hand: a typo in `ffi` must not agree with itself.
        assert_eq!(Flags::SILENT.bits(), 0x8000);
        assert_eq!(Flags::DISALLOW_NULL_AUTHTOK.bits(), 0x0001);
        assert_eq!(Flags::CHANGE_EXPIRED_AUTHTOK.bits(), 0x0020);
        assert_eq!(Flags::empty().bits(), 0);
        // ADG 3.3: PAM_SILENT is OR'd with whatever else the call takes.
        assert_eq!(
            (Flags::SILENT | Flags::DISALLOW_NULL_AUTHTOK).bits(),
            0x8001
        );
    }

    #[test]
    fn cred_ops_carry_pams_own_values() {
        assert_eq!(CredOp::Establish.raw(), 0x0002);
        assert_eq!(CredOp::Delete.raw(), 0x0004);
        assert_eq!(CredOp::Reinitialize.raw(), 0x0008);
        assert_eq!(CredOp::Refresh.raw(), 0x0010);
        // The operation and the flags share one argument.
        assert_eq!(CredOp::Establish.raw() | Flags::SILENT.bits(), 0x8002);
    }

    /// A name holding `=` names a different variable than the caller meant,
    /// and an empty one names nothing.
    #[test]
    fn environment_names_are_checked() {
        assert_eq!(check_env_name("PATH"), Ok(()));
        assert_eq!(check_env_name(""), Err(Error::InvalidName));
        assert_eq!(check_env_name("A=B"), Err(Error::InvalidName));
    }

    #[test]
    fn entries_split_at_the_first_equals() {
        assert_eq!(
            split_env(b"NAME=value"),
            Ok(("NAME".into(), "value".into()))
        );
        // A value may itself contain `=`.
        assert_eq!(split_env(b"N=a=b"), Ok(("N".into(), "a=b".into())));
        assert_eq!(split_env(b"N="), Ok(("N".into(), String::new())));
        assert_eq!(split_env(b"N"), Ok(("N".into(), String::new())));
        assert_eq!(split_env(&[0xff, b'=']), Err(Error::NotUtf8));
    }

    #[test]
    fn strings_with_an_interior_nul_are_refused() {
        assert_eq!(cstring("a\0b"), Err(Error::NulByte));
        assert_eq!(cpath(Path::new("a\0b")), Err(Error::NulByte));
    }
}
