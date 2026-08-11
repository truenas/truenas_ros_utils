// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The conversation: how a module asks the application a question.
//!
//! A module calls the application back through the function it registered at
//! `pam_start_confdir`, passing an array of messages and expecting an array of
//! responses. [`trampoline`] is that function; it turns the call into a
//! [`Conversation::converse`] and marshals the answers back.
//!
//! # Safety
//!
//! This module is called *by* C, so it lifts the workspace's
//! `deny(unsafe_code)`. Invariants:
//!
//! - `appdata_ptr` is the address of a [`ConvSlot`] that outlives the handle.
//!   [`crate::txn`] keeps it boxed and frees it only after `pam_end`, because
//!   a module's cleanup handler may converse.
//! - The trampoline runs only from inside a `pam_*()` call, which holds
//!   `&mut Transaction` for its whole duration, so the `&mut ConvSlot` it
//!   forms is the only live reference to that slot.
//! - The messages borrow libpam's own buffers and are valid for the call only.
//!   Every copy that outlives it is taken here.
//! - Responses are allocated with `malloc`, never Rust's allocator: once the
//!   array is handed over, the module stack frees it with `free`. Any array
//!   this crate keeps is scrubbed and freed here instead.
//! - No panic crosses the boundary. Unwinding into C is undefined, and
//!   aborting would skip `pam_end` and leave the stack's own state behind.
#![allow(unsafe_code)]

use crate::error::{Error, PamCode, Result};
use crate::ffi;
use crate::secret::{Secret, scrub};
use std::any::Any;
use std::borrow::Cow;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::panic::{self, AssertUnwindSafe};
use std::{mem, ptr, slice};

/// What one message asks of the application.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(i32)]
#[non_exhaustive]
pub enum MsgStyle {
    /// Obtain a string without echoing it. A password prompt.
    PromptEchoOff = ffi::PAM_PROMPT_ECHO_OFF,
    /// Obtain a string, echoing it. A user name prompt.
    PromptEchoOn = ffi::PAM_PROMPT_ECHO_ON,
    /// Display an error message. Expects no response.
    ErrorMsg = ffi::PAM_ERROR_MSG,
    /// Display informational text. Expects no response.
    TextInfo = ffi::PAM_TEXT_INFO,
}

impl MsgStyle {
    /// The style for a raw value, or `None` for one outside the four the
    /// standard defines.
    pub const fn from_raw(style: i32) -> Option<MsgStyle> {
        Some(match style {
            ffi::PAM_PROMPT_ECHO_OFF => MsgStyle::PromptEchoOff,
            ffi::PAM_PROMPT_ECHO_ON => MsgStyle::PromptEchoOn,
            ffi::PAM_ERROR_MSG => MsgStyle::ErrorMsg,
            ffi::PAM_TEXT_INFO => MsgStyle::TextInfo,
            _ => return None,
        })
    }

    /// The raw value libpam uses for this style.
    pub const fn raw(self) -> i32 {
        self as i32
    }

    /// Whether a message of this style is asking for something back.
    ///
    /// A response to a message that asks nothing is permitted and ignored, so
    /// this is guidance for building an answer, not a rule the stack enforces.
    ///
    /// ```
    /// # use truenas_pam::MsgStyle;
    /// assert!(MsgStyle::PromptEchoOff.wants_response());
    /// assert!(!MsgStyle::TextInfo.wants_response());
    /// ```
    pub const fn wants_response(self) -> bool {
        matches!(self, MsgStyle::PromptEchoOff | MsgStyle::PromptEchoOn)
    }
}

/// One message from a module, borrowed for the length of the conversation
/// call.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Message<'a> {
    style: MsgStyle,
    text: &'a [u8],
}

impl<'a> Message<'a> {
    /// What the message asks for.
    pub fn style(&self) -> MsgStyle {
        self.style
    }

    /// The text as libpam holds it, without its terminator. A module sending
    /// no text at all is reported as empty.
    pub fn bytes(&self) -> &'a [u8] {
        self.text
    }

    /// The text, with invalid UTF-8 replaced.
    ///
    /// Lossy on purpose: prompts are translated at runtime and carry whatever
    /// the module's catalogue holds, so a caller matching on prompt text must
    /// not have to handle an encoding error to do it.
    pub fn text(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.text)
    }

    /// A copy that outlives the call.
    pub fn into_owned(self) -> OwnedMessage {
        OwnedMessage {
            style: self.style,
            text: self.text.into(),
        }
    }
}

/// A message copied out of the conversation call that produced it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OwnedMessage {
    style: MsgStyle,
    text: Box<[u8]>,
}

impl OwnedMessage {
    /// Build one, for a caller driving a conversation of its own.
    pub fn new(style: MsgStyle, text: impl Into<Vec<u8>>) -> OwnedMessage {
        OwnedMessage {
            style,
            text: text.into().into_boxed_slice(),
        }
    }

    /// What the message asks for.
    pub fn style(&self) -> MsgStyle {
        self.style
    }

    /// The text, without its terminator.
    pub fn bytes(&self) -> &[u8] {
        &self.text
    }

    /// The text, with invalid UTF-8 replaced. See [`Message::text`].
    pub fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.text)
    }

    /// Borrow it as a [`Message`].
    pub fn as_message(&self) -> Message<'_> {
        Message {
            style: self.style,
            text: &self.text,
        }
    }
}

/// How the application answers a module.
///
/// `converse` returns one response per message, in the same order.
/// [`None`] answers a message that asks nothing. Returning the wrong number of
/// responses fails the conversation.
///
/// An implementation must not call back into the [`Transaction`](
/// crate::Transaction) that is driving it: the call that reached here still
/// owns the handle.
pub trait Conversation: Send {
    /// Answer one round of messages.
    fn converse(
        &mut self,
        messages: &[Message<'_>],
    ) -> Result<Vec<Option<Secret>>>;
}

/// The conversation for a transaction with nobody to ask: it answers every
/// message with nothing.
///
/// Messages still reach [`Transaction::messages`](
/// crate::Transaction::messages), which records every round whatever
/// conversation is installed, so an unanswered prompt stays visible.
///
/// This is the default. Account and session stacks inform rather than ask, so
/// they run under it with no thread parked in a prompt.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unattended;

impl Conversation for Unattended {
    fn converse(
        &mut self,
        messages: &[Message<'_>],
    ) -> Result<Vec<Option<Secret>>> {
        Ok(messages.iter().map(|_| None).collect())
    }
}

/// Why a conversation did not complete. `PAM_CONV_ERR` is the only code a
/// module can be given, so the reason is held here until the driving `pam_*()`
/// call returns.
pub(crate) enum Failure {
    /// The conversation returned an error, or this module rejected the round.
    Err(Error),
    /// The conversation panicked.
    Panic(Box<dyn Any + Send>),
}

/// What `appdata_ptr` points at.
///
/// Boxed by [`crate::txn`] so its address is fixed: libpam copies the
/// `pam_conv` struct at `pam_start_confdir` but not what it points at.
pub(crate) struct ConvSlot {
    conv: Box<dyn Conversation>,
    log: Vec<Vec<OwnedMessage>>,
    failure: Option<Failure>,
}

impl ConvSlot {
    pub(crate) fn new(conv: Box<dyn Conversation>) -> ConvSlot {
        ConvSlot {
            conv,
            log: Vec::new(),
            failure: None,
        }
    }

    /// Install a different conversation, returning the one displaced.
    pub(crate) fn replace_conv(
        &mut self,
        conv: Box<dyn Conversation>,
    ) -> Box<dyn Conversation> {
        mem::replace(&mut self.conv, conv)
    }

    /// Every round so far, oldest first.
    pub(crate) fn log(&self) -> &[Vec<OwnedMessage>] {
        &self.log
    }

    /// Discard the recorded rounds.
    pub(crate) fn clear_log(&mut self) {
        self.log.clear();
    }

    /// Take the failure, if the last call produced one.
    pub(crate) fn take_failure(&mut self) -> Option<Failure> {
        self.failure.take()
    }

    /// Record a failure. The first one wins: a module that keeps converting
    /// after a refusal must not overwrite the reason for it.
    fn fail(&mut self, failure: Failure) {
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
    }
}

/// The function registered with libpam.
///
/// # Safety
///
/// Called only by libpam, with the arguments `pam_conv` specifies: `msg` an
/// array of `num_msg` message pointers, `resp` an out-parameter for one
/// response array, and `appdata_ptr` the value handed to `pam_start_confdir`.
pub(crate) unsafe extern "C" fn trampoline(
    num_msg: c_int,
    msg: *const *const ffi::pam_message,
    resp: *mut *mut ffi::pam_response,
    appdata: *mut c_void,
) -> c_int {
    // Nothing here can be reported anywhere: there is no slot to record it in
    // and no handle to raise it on.
    if appdata.is_null() || msg.is_null() || resp.is_null() {
        return ffi::PAM_CONV_ERR;
    }
    // ADG 3.2.1: the array holds num_msg entries. Zero or fewer is not a
    // question, and PAM_MAX_NUM_MSG is the ceiling the header sets.
    if !(1..=ffi::PAM_MAX_NUM_MSG).contains(&num_msg) {
        return ffi::PAM_CONV_ERR;
    }
    let count = num_msg as usize;
    let slot = appdata as *mut ConvSlot;

    // AssertUnwindSafe: on a panic the round is abandoned and the payload is
    // re-raised once libpam has unwound its own frames. `ConvSlot`'s own
    // fields are a `Vec` and a `Box`, each consistent at every point the
    // closure could unwind through.
    let built = panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the sole live reference to the slot; see the module note.
        let slot = unsafe { &mut *slot };
        // SAFETY: libpam passes `num_msg` initialised pointers here.
        let raw = unsafe { slice::from_raw_parts(msg, count) };

        let mut messages = Vec::with_capacity(count);
        for &m in raw {
            if m.is_null() {
                return Err(Error::Pam(PamCode::ConvErr));
            }
            // SAFETY: non-null and initialised by libpam, valid for the call.
            let m = unsafe { &*m };
            let style = MsgStyle::from_raw(m.msg_style)
                .ok_or(Error::UnknownMsgStyle(m.msg_style))?;
            let text: &[u8] = if m.msg.is_null() {
                // A module may send a style with no text; `strlen` on null is
                // not an option.
                &[]
            } else {
                // SAFETY: non-null, NUL-terminated, and owned by libpam for
                // the duration of this call.
                unsafe { CStr::from_ptr(m.msg) }.to_bytes()
            };
            messages.push(Message { style, text });
        }

        // Recorded before the answer, so a round that fails is still visible.
        slot.log
            .push(messages.iter().map(|m| m.into_owned()).collect());

        let answers = slot.conv.converse(&messages)?;
        // ADG 3.2.1: the number of responses is always equal to num_msg.
        if answers.len() != count {
            return Err(Error::Pam(PamCode::ConvErr));
        }
        responses_to_c(&answers)
    }));

    // SAFETY: as above. The closure's borrow has ended, by return or by
    // unwinding.
    let slot = unsafe { &mut *slot };
    match built {
        Ok(Ok(array)) => {
            // SAFETY: a valid out-parameter; ownership of the array passes to
            // the module stack, which frees it.
            unsafe { *resp = array };
            ffi::PAM_SUCCESS
        }
        Ok(Err(e)) => {
            slot.fail(Failure::Err(e));
            ffi::PAM_CONV_ERR
        }
        Err(payload) => {
            slot.fail(Failure::Panic(payload));
            ffi::PAM_CONV_ERR
        }
    }
}

/// Copy `answers` into an array the module stack can free.
///
/// `calloc` and `malloc`, not Rust's allocator: ADG 3.2.1 has the module stack
/// release the array and every string in it with `free(3)`. Nothing partial is
/// returned; a failure scrubs and frees what was built.
fn responses_to_c(
    answers: &[Option<Secret>],
) -> Result<*mut ffi::pam_response> {
    let count = answers.len();
    // SAFETY: a non-zero count of a sized type. `calloc` zeroes, so every
    // `resp` starts null and `resp_retcode` starts at the zero the standard
    // expects.
    let array = unsafe {
        libc::calloc(count, mem::size_of::<ffi::pam_response>())
            as *mut ffi::pam_response
    };
    if array.is_null() {
        return Err(Error::Pam(PamCode::BufErr));
    }

    for (i, answer) in answers.iter().enumerate() {
        let Some(secret) = answer else { continue };
        let bytes = secret.as_bytes();
        // The module reads a C string, so the answer must hold no NUL.
        if bytes.contains(&0) {
            // SAFETY: built here, not yet handed over.
            unsafe { free_responses(array, count) };
            return Err(Error::NulByte);
        }
        // SAFETY: a non-zero size; the result is checked below.
        let buf = unsafe { libc::malloc(bytes.len() + 1) as *mut c_char };
        if buf.is_null() {
            // SAFETY: built here, not yet handed over.
            unsafe { free_responses(array, count) };
            return Err(Error::Pam(PamCode::BufErr));
        }
        // SAFETY: `buf` holds len + 1 bytes and does not overlap `bytes`;
        // `i < count`, so the element is within the array.
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                buf as *mut u8,
                bytes.len(),
            );
            *buf.add(bytes.len()) = 0;
            (*array.add(i)).resp = buf;
        }
    }
    Ok(array)
}

/// Scrub and free a response array that will never reach a module.
///
/// # Safety
///
/// `array` must be a `calloc`ed array of `count` responses whose non-null
/// `resp` pointers came from `malloc` and are NUL-terminated, and it must not
/// have been handed to libpam.
unsafe fn free_responses(array: *mut ffi::pam_response, count: usize) {
    for i in 0..count {
        // SAFETY: `i < count`, so the element is within the array.
        let p = unsafe { (*array.add(i)).resp };
        if p.is_null() {
            continue;
        }
        // SAFETY: NUL-terminated, so `strlen` is in bounds; the buffer is
        // writable for that length and is freed exactly once.
        unsafe {
            scrub(p as *mut u8, libc::strlen(p));
            libc::free(p as *mut c_void);
        }
    }
    // SAFETY: from `calloc` above, freed exactly once.
    unsafe { libc::free(array as *mut c_void) };
}

#[cfg(test)]
mod tests {
    //! The marshalling is exercised directly here. Driving it through a real
    //! module is `tests/adg.rs`.
    use super::*;

    /// Read back what a module would see, then release it the way the module
    /// stack would.
    ///
    /// # Safety
    ///
    /// `array` must be what `responses_to_c` returned for `count` answers.
    unsafe fn read_back(
        array: *mut ffi::pam_response,
        count: usize,
    ) -> Vec<Option<Vec<u8>>> {
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            // SAFETY: `i < count`, within the array.
            let r = unsafe { &*array.add(i) };
            assert_eq!(r.resp_retcode, 0, "the standard expects zero here");
            out.push(if r.resp.is_null() {
                None
            } else {
                // SAFETY: non-null and NUL-terminated.
                Some(unsafe { CStr::from_ptr(r.resp) }.to_bytes().to_vec())
            });
        }
        // SAFETY: exactly what the module stack does with it.
        unsafe {
            for i in 0..count {
                libc::free((*array.add(i)).resp as *mut c_void);
            }
            libc::free(array as *mut c_void);
        }
        out
    }

    #[test]
    fn answers_reach_the_array_in_order() {
        let answers = vec![
            Some(Secret::from("first")),
            None,
            Some(Secret::from("third")),
        ];
        let array = responses_to_c(&answers).unwrap();
        // SAFETY: just built for three answers.
        let seen = unsafe { read_back(array, 3) };
        assert_eq!(
            seen,
            vec![Some(b"first".to_vec()), None, Some(b"third".to_vec()),]
        );
    }

    /// An empty answer is a real answer and must arrive as an empty string,
    /// not as the absence of one — `DISALLOW_NULL_AUTHTOK` turns on the
    /// difference.
    #[test]
    fn an_empty_answer_is_not_a_missing_one() {
        let answers = vec![Some(Secret::from("")), None];
        let array = responses_to_c(&answers).unwrap();
        // SAFETY: just built for two answers.
        let seen = unsafe { read_back(array, 2) };
        assert_eq!(seen, vec![Some(Vec::new()), None]);
    }

    /// A truncated password would be checked against the wrong string, so the
    /// round fails instead.
    #[test]
    fn an_interior_nul_is_refused() {
        let answers = vec![Some(Secret::new(vec![b'a', 0, b'b']))];
        assert_eq!(responses_to_c(&answers), Err(Error::NulByte));
    }

    #[test]
    fn styles_outside_the_four_are_rejected() {
        assert_eq!(MsgStyle::from_raw(0), None);
        // PAM_RADIO_TYPE and PAM_BINARY_PROMPT: Linux-PAM extensions that need
        // a conversation this crate does not provide.
        assert_eq!(MsgStyle::from_raw(5), None);
        assert_eq!(MsgStyle::from_raw(7), None);
        assert_eq!(
            MsgStyle::from_raw(ffi::PAM_TEXT_INFO),
            Some(MsgStyle::TextInfo)
        );
    }

    #[test]
    fn message_text_is_lossy_but_bytes_are_not() {
        let owned = OwnedMessage::new(MsgStyle::TextInfo, vec![b'a', 0xff]);
        assert_eq!(owned.bytes(), &[b'a', 0xff]);
        assert_eq!(owned.text(), "a\u{fffd}");
        assert_eq!(owned.as_message().style(), MsgStyle::TextInfo);
        assert_eq!(owned.as_message().into_owned(), owned);
    }

    // --- the trampoline ---------------------------------------------------
    //
    // Driven with message arrays built by hand, for the shapes no module can
    // be configured to send: a null message pointer, a message with no text, a
    // style outside the four, and a count at the edges of what the standard
    // allows.

    /// Answers each prompt with the index it arrived at, so a response landing
    /// in the wrong slot is visible.
    struct ByIndex;

    impl Conversation for ByIndex {
        fn converse(
            &mut self,
            messages: &[Message<'_>],
        ) -> Result<Vec<Option<Secret>>> {
            Ok(messages
                .iter()
                .enumerate()
                .map(|(i, m)| {
                    m.style()
                        .wants_response()
                        .then(|| Secret::from(i.to_string()))
                })
                .collect())
        }
    }

    /// Call the trampoline as libpam does, then release the responses as the
    /// module stack does.
    ///
    /// `num_msg` is passed separately from the array so the count checks can
    /// be reached with a well-formed one.
    ///
    /// # Safety
    ///
    /// `slot` must be a live `ConvSlot`.
    unsafe fn converse_raw(
        slot: *mut ConvSlot,
        msgs: &[(c_int, Option<&CStr>)],
        num_msg: c_int,
    ) -> (c_int, Vec<Option<Vec<u8>>>) {
        let owned: Vec<ffi::pam_message> = msgs
            .iter()
            .map(|(style, text)| ffi::pam_message {
                msg_style: *style,
                msg: text.map_or(ptr::null(), |t| t.as_ptr()),
            })
            .collect();
        let ptrs: Vec<*const ffi::pam_message> =
            owned.iter().map(|m| m as *const ffi::pam_message).collect();
        let mut resp: *mut ffi::pam_response = ptr::null_mut();
        // SAFETY: the messages outlive the call and `resp` is a valid
        // out-parameter.
        let rc = unsafe {
            trampoline(num_msg, ptrs.as_ptr(), &mut resp, slot as *mut c_void)
        };
        if rc != ffi::PAM_SUCCESS {
            assert!(resp.is_null(), "nothing is handed over on failure");
            return (rc, Vec::new());
        }
        // SAFETY: on success the trampoline wrote an array of `num_msg`.
        (rc, unsafe { read_back(resp, num_msg as usize) })
    }

    fn slot() -> Box<ConvSlot> {
        Box::new(ConvSlot::new(Box::new(ByIndex)))
    }

    /// ADG 3.2.1: the index of the responses corresponds directly to the
    /// prompt index in the message array.
    #[test]
    fn responses_line_up_with_the_prompts_that_asked() {
        let mut slot = slot();
        let text = c"prompt";
        // SAFETY: the slot is live for the call.
        let (rc, seen) = unsafe {
            converse_raw(
                &mut *slot,
                &[
                    (ffi::PAM_TEXT_INFO, Some(text)),
                    (ffi::PAM_PROMPT_ECHO_OFF, Some(text)),
                    (ffi::PAM_ERROR_MSG, Some(text)),
                    (ffi::PAM_PROMPT_ECHO_ON, Some(text)),
                ],
                4,
            )
        };
        assert_eq!(rc, ffi::PAM_SUCCESS);
        assert_eq!(
            seen,
            vec![None, Some(b"1".to_vec()), None, Some(b"3".to_vec())]
        );
        assert_eq!(slot.log().len(), 1, "one round recorded");
        assert_eq!(slot.log()[0].len(), 4);
    }

    /// A module may send a style with no text at all. Reading it as a string
    /// would dereference null.
    #[test]
    fn a_message_with_no_text_arrives_empty() {
        let mut slot = slot();
        // SAFETY: the slot is live for the call.
        let (rc, _) = unsafe {
            converse_raw(&mut *slot, &[(ffi::PAM_TEXT_INFO, None)], 1)
        };
        assert_eq!(rc, ffi::PAM_SUCCESS);
        assert_eq!(slot.log()[0][0].bytes(), b"");
        assert_eq!(slot.log()[0][0].text(), "");
    }

    /// ADG 3.2.1: the array holds `num_msg` entries. Zero is not a question,
    /// and `PAM_MAX_NUM_MSG` is the ceiling the header sets.
    #[test]
    fn a_count_outside_the_permitted_range_is_refused() {
        let mut slot = slot();
        let text = c"prompt";
        let one = [(ffi::PAM_TEXT_INFO, Some(text))];
        for count in [0, -1] {
            // SAFETY: the slot is live for the call.
            let (rc, _) = unsafe { converse_raw(&mut *slot, &one, count) };
            assert_eq!(rc, ffi::PAM_CONV_ERR, "count {count}");
        }

        let many = vec![
            (ffi::PAM_TEXT_INFO, Some(text));
            ffi::PAM_MAX_NUM_MSG as usize + 1
        ];
        // SAFETY: the slot is live for the call.
        let (rc, _) = unsafe {
            converse_raw(&mut *slot, &many, ffi::PAM_MAX_NUM_MSG + 1)
        };
        assert_eq!(rc, ffi::PAM_CONV_ERR);

        // The ceiling itself is allowed.
        // SAFETY: the slot is live for the call.
        let (rc, seen) = unsafe {
            converse_raw(
                &mut *slot,
                &many[..ffi::PAM_MAX_NUM_MSG as usize],
                ffi::PAM_MAX_NUM_MSG,
            )
        };
        assert_eq!(rc, ffi::PAM_SUCCESS);
        assert_eq!(seen.len(), ffi::PAM_MAX_NUM_MSG as usize);

        // A refused round is not recorded and never reaches the conversation.
        assert_eq!(slot.log().len(), 1);
    }

    /// Answering a binary or radio prompt with nothing would look like a
    /// reply, so the round fails and says why.
    #[test]
    fn a_style_outside_the_four_fails_the_round() {
        let mut slot = slot();
        let text = c"prompt";
        // PAM_BINARY_PROMPT.
        // SAFETY: the slot is live for the call.
        let (rc, _) =
            unsafe { converse_raw(&mut *slot, &[(7, Some(text))], 1) };
        assert_eq!(rc, ffi::PAM_CONV_ERR);
        assert!(matches!(
            slot.take_failure(),
            Some(Failure::Err(Error::UnknownMsgStyle(7)))
        ));
    }

    /// A null entry inside the array is not something the standard permits,
    /// and following it would dereference null.
    #[test]
    fn a_null_message_pointer_is_refused() {
        let mut slot = slot();
        let owned = ffi::pam_message {
            msg_style: ffi::PAM_TEXT_INFO,
            msg: c"prompt".as_ptr(),
        };
        let ptrs: [*const ffi::pam_message; 2] = [&owned, ptr::null()];
        let mut resp: *mut ffi::pam_response = ptr::null_mut();
        // SAFETY: a two-entry array matching the count, and a valid
        // out-parameter.
        let rc = unsafe {
            trampoline(
                2,
                ptrs.as_ptr(),
                &mut resp,
                (&mut *slot) as *mut ConvSlot as *mut c_void,
            )
        };
        assert_eq!(rc, ffi::PAM_CONV_ERR);
        assert!(resp.is_null());
    }

    /// Neither argument is optional, and there is nowhere to record a
    /// complaint about them.
    #[test]
    fn null_arguments_are_refused() {
        let mut slot = slot();
        let mut resp: *mut ffi::pam_response = ptr::null_mut();
        let appdata = (&mut *slot) as *mut ConvSlot as *mut c_void;
        // SAFETY: each call passes one null where libpam never would; the
        // trampoline returns before reading any of them.
        unsafe {
            assert_eq!(
                trampoline(1, ptr::null(), &mut resp, appdata),
                ffi::PAM_CONV_ERR
            );
            assert_eq!(
                trampoline(1, ptr::null(), ptr::null_mut(), appdata),
                ffi::PAM_CONV_ERR
            );
            assert_eq!(
                trampoline(1, ptr::null(), &mut resp, ptr::null_mut()),
                ffi::PAM_CONV_ERR
            );
        }
    }

    #[test]
    fn unattended_answers_nothing_for_every_message() {
        let msgs = [
            OwnedMessage::new(MsgStyle::PromptEchoOff, "Password: "),
            OwnedMessage::new(MsgStyle::TextInfo, "hello"),
        ];
        let borrowed: Vec<Message<'_>> =
            msgs.iter().map(|m| m.as_message()).collect();
        let answers = Unattended.converse(&borrowed).unwrap();
        assert_eq!(answers.len(), 2);
        assert!(answers.iter().all(|a| a.is_none()));
    }
}
