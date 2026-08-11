// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The Linux-PAM Application Developers' Guide, clause by clause.
//!
//! Each test names the section it comes from. The guide ships in `libpam-doc`
//! as `/usr/share/doc/libpam-doc/html/adg-*.html`, and as
//! `Linux-PAM_ADG.pdf.gz` beside it.
//!
//! The modules driving these stacks are stock `libpam-modules`; that they
//! behave as their own documentation says is taken as given. What is under
//! test is that this crate presents what they do faithfully.

mod common;

use common::{confdir, modules};
use truenas_pam::{
    Conversation, Error, Flags, Message, MsgStyle, OwnedMessage, PamCode,
    Result, Secret, Transaction,
};

/// Answers the prompts of each round by their position within it: a round
/// asking once is the current token, a round asking twice is a new token and
/// its confirmation.
///
/// The module compares the two answers of the second round, so a response
/// delivered to the wrong prompt changes the outcome.
struct ByPosition {
    new: &'static str,
    confirm: &'static str,
}

impl Conversation for ByPosition {
    fn converse(
        &mut self,
        messages: &[Message<'_>],
    ) -> Result<Vec<Option<Secret>>> {
        let prompts: Vec<usize> = messages
            .iter()
            .enumerate()
            .filter(|(_, m)| m.style().wants_response())
            .map(|(i, _)| i)
            .collect();
        let answers: &[&str] = match prompts.len() {
            0 => &[],
            1 => &["current-token"],
            _ => &[self.new, self.confirm],
        };
        let mut out: Vec<Option<Secret>> =
            messages.iter().map(|_| None).collect();
        for (at, answer) in prompts.iter().zip(answers) {
            out[*at] = Some(Secret::from(*answer));
        }
        Ok(out)
    }
}

/// Answers every prompt with the same string.
struct Always(&'static str);

impl Conversation for Always {
    fn converse(
        &mut self,
        messages: &[Message<'_>],
    ) -> Result<Vec<Option<Secret>>> {
        Ok(messages
            .iter()
            .map(|m| m.style().wants_response().then(|| Secret::from(self.0)))
            .collect())
    }
}

fn styles(rounds: &[Vec<OwnedMessage>]) -> Vec<MsgStyle> {
    rounds.iter().flatten().map(OwnedMessage::style).collect()
}

// --- 3.2.1 The conversation function -------------------------------------

/// "The index of the responses corresponds directly to the prompt index in
/// the pam_message array."
///
/// Proved by what the module does with them: it compares the two answers it
/// asked for and refuses the change when they differ. Matching answers must
/// therefore succeed, and swapped or shifted ones must not.
#[test]
fn adg_3_2_1_responses_are_matched_to_prompts_by_position() {
    let Some(()) = modules() else { return };
    let dir = confdir();

    let mut agreeing = Transaction::builder("stress")
        .user("alice")
        .confdir(dir.path())
        .conversation(Box::new(ByPosition {
            new: "new-token",
            confirm: "new-token",
        }))
        .build()
        .unwrap();
    agreeing.chauthtok(Flags::empty()).unwrap();

    let mut differing = Transaction::builder("stress")
        .user("alice")
        .confdir(dir.path())
        .conversation(Box::new(ByPosition {
            new: "new-token",
            confirm: "something-else",
        }))
        .build()
        .unwrap();
    assert!(
        differing.chauthtok(Flags::empty()).is_err(),
        "the module must see two different answers"
    );
}

/// "The point of having an array of messages is that it becomes possible to
/// pass a number of things to the application in a single call."
///
/// Linux-PAM passes an array of message pointers. A binding that read it as
/// a pointer to one message agrees with that for a single-message round and
/// diverges here.
#[test]
fn adg_3_2_1_one_round_may_carry_several_messages() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("stress")
        .user("alice")
        .confdir(dir.path())
        .conversation(Box::new(ByPosition {
            new: "new-token",
            confirm: "new-token",
        }))
        .build()
        .unwrap();
    txn.chauthtok(Flags::empty()).unwrap();

    let rounds = txn.messages();
    assert!(
        rounds.iter().any(|round| round.len() > 1),
        "no round carried more than one message: {rounds:?}"
    );
    assert!(
        rounds.iter().any(|round| {
            round.iter().filter(|m| m.style().wants_response()).count() > 1
        }),
        "no round asked more than one question: {rounds:?}"
    );
}

/// "Each message can have one of four types, specified by the msg_style
/// member." A prompt that arrived as the wrong style would be echoed when it
/// should not be.
#[test]
fn adg_3_2_1_prompt_styles_arrive_as_the_module_sent_them() {
    let Some(()) = modules() else { return };
    let dir = confdir();

    // With a user set, the stack asks only for the token, without echo.
    let mut named = Transaction::builder("stress")
        .user("alice")
        .confdir(dir.path())
        .conversation(Box::new(Always("token")))
        .build()
        .unwrap();
    named.authenticate(Flags::empty()).unwrap();
    assert!(
        styles(named.messages()).contains(&MsgStyle::PromptEchoOff),
        "{:?}",
        named.messages()
    );

    // With none set, the stack must ask for the name first, and a name is
    // echoed.
    let mut anonymous = Transaction::builder("stress")
        .confdir(dir.path())
        .conversation(Box::new(Always("alice")))
        .build()
        .unwrap();
    anonymous.authenticate(Flags::empty()).unwrap();
    assert!(
        styles(anonymous.messages()).contains(&MsgStyle::PromptEchoOn),
        "{:?}",
        anonymous.messages()
    );
}

// --- 3.3 Programming notes -----------------------------------------------

/// "all of the authentication service function calls accept the token
/// PAM_SILENT [...] This token can be logically OR'd with any one of the
/// permitted tokens specific to the individual function calls. PAM_SILENT
/// does not override the prompting of the user for passwords etc., it only
/// stops informative messages from being generated."
#[test]
fn adg_3_3_silent_stops_informative_messages_and_composes() {
    let Some(()) = modules() else { return };
    let dir = confdir();

    let mut loud = Transaction::builder("echo")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    loud.authenticate(Flags::empty()).unwrap();
    assert_eq!(styles(loud.messages()), vec![MsgStyle::TextInfo]);

    let mut quiet = Transaction::builder("echo")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    quiet.authenticate(Flags::SILENT).unwrap();
    assert!(quiet.messages().is_empty(), "{:?}", quiet.messages());

    // OR'd with the flag specific to this call, it still silences.
    let mut both = Transaction::builder("echo")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    both.authenticate(Flags::SILENT | Flags::DISALLOW_NULL_AUTHTOK)
        .unwrap();
    assert!(both.messages().is_empty(), "{:?}", both.messages());

    // Prompting is untouched: the stack still asks, and still gets an answer.
    let mut asked = Transaction::builder("stress")
        .user("alice")
        .confdir(dir.path())
        .conversation(Box::new(Always("token")))
        .build()
        .unwrap();
    asked.authenticate(Flags::SILENT).unwrap();
    assert!(
        styles(asked.messages()).contains(&MsgStyle::PromptEchoOff),
        "{:?}",
        asked.messages()
    );
}

// --- 4.4 The identity of the user ----------------------------------------

/// "modules can change the values of PAM_USER and PAM_RUSER during any of the
/// pam_*() library calls. For this reason, the application should take care
/// to use the pam_get_item() every time it wishes to establish who the
/// authenticated user is."
///
/// pam_permit documents that it sets the name to `nobody` when the
/// application supplied none, so the item read after the call differs from
/// the one read before it. A binding that cached the name at construction
/// would report the wrong user for the whole session.
#[test]
fn adg_4_4_the_user_item_is_read_again_after_every_call() {
    let Some(()) = modules() else { return };
    let dir = confdir();

    // Nothing names the user: not the application, and not the answer the
    // stack's own prompt gets.
    let mut txn = Transaction::builder("permit")
        .confdir(dir.path())
        .conversation(Box::new(Always("")))
        .build()
        .unwrap();

    assert_eq!(txn.user().unwrap(), None);
    txn.authenticate(Flags::empty()).unwrap();
    assert_eq!(txn.user().unwrap(), Some("nobody"));

    // The same holds when the answer does name someone: the name the
    // application ends up with came from the exchange, not from the builder.
    let mut answered = Transaction::builder("permit")
        .confdir(dir.path())
        .conversation(Box::new(Always("alice")))
        .build()
        .unwrap();
    answered.authenticate(Flags::empty()).unwrap();
    assert_eq!(answered.user().unwrap(), Some("alice"));
}

// --- 3.1 The public interface --------------------------------------------

/// `pam_acct_mgmt` returning PAM_NEW_AUTHTOK_REQD is the one outcome that is
/// neither success nor refusal: the account is good, and unusable until its
/// token changes. Collapsing it into a failure would leave the user with no
/// way back in.
#[test]
fn adg_3_1_acct_mgmt_can_require_a_new_token() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("stress-expired")
        .user("alice")
        .confdir(dir.path())
        .conversation(Box::new(Always("token")))
        .build()
        .unwrap();

    txn.authenticate(Flags::empty()).unwrap();
    assert_eq!(
        txn.acct_mgmt(Flags::empty()),
        Err(Error::Pam(PamCode::NewAuthtokReqd))
    );
}

// --- Chapter 8, An example application -----------------------------------

/// The guide's example: start, authenticate, check the account if that
/// succeeded, and end reporting whichever status it stopped at.
///
/// Reproduced as its call sequence, not its text. `pam_end` is [`Drop`] here,
/// and it is given the last status either way.
#[test]
fn adg_ch8_the_example_call_sequence() {
    let Some(()) = modules() else { return };
    let dir = confdir();

    fn check_user(confdir: &std::path::Path, service: &str) -> bool {
        let Ok(mut txn) = Transaction::builder(service)
            .user("nobody")
            .confdir(confdir)
            .conversation(Box::new(Always("token")))
            .build()
        else {
            return false;
        };
        txn.authenticate(Flags::empty())
            .and_then(|()| txn.acct_mgmt(Flags::empty()))
            .is_ok()
    }

    assert!(check_user(dir.path(), "permit"), "Authenticated");
    assert!(!check_user(dir.path(), "deny"), "Not Authenticated");
    // A service with no file of its own runs `other`, which denies.
    assert!(!check_user(dir.path(), "check_user"), "Not Authenticated");
}
