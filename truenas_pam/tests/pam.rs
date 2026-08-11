// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! This crate's own decisions, driven through a real stack: error
//! classification, items, the PAM environment, the message record, and what
//! happens to a conversation that fails or panics.
//!
//! What the standard requires of the binding is `tests/adg.rs`. That the
//! modules here behave as their documentation says is taken as given.

mod common;

use common::{confdir, modules};
use std::panic::{self, AssertUnwindSafe};
use std::time::{Duration, Instant};
use truenas_pam::{
    Conversation, CredOp, Error, Flags, Message, MsgStyle, PamCode, Result,
    Secret, Transaction,
};

// --- types ---------------------------------------------------------------

/// A transaction is moved onto a worker thread to be driven step by step, so
/// it must be `Send`. It must not be `Sync`: libpam does no locking, so two
/// threads in one handle would corrupt it.
#[test]
fn a_transaction_is_send_and_errors_are_shareable() {
    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send::<Transaction>();
    assert_send::<Secret>();
    assert_send_sync::<Error>();
    assert_send_sync::<PamCode>();
    assert_send_sync::<Flags>();
}

// --- driving a stack -----------------------------------------------------

#[test]
fn a_permitting_stack_runs_every_operation() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("permit")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();

    txn.authenticate(Flags::empty()).unwrap();
    txn.acct_mgmt(Flags::empty()).unwrap();
    txn.setcred(CredOp::Establish, Flags::empty()).unwrap();
    txn.open_session(Flags::empty()).unwrap();
    txn.close_session(Flags::empty()).unwrap();
    txn.setcred(CredOp::Delete, Flags::empty()).unwrap();
    txn.chauthtok(Flags::empty()).unwrap();
}

/// A service with no file of its own falls through to `other`, which denies.
/// A binding that reported success here would authenticate against nothing.
#[test]
fn an_unnamed_service_falls_back_to_other() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("no-such-service")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    assert!(txn.authenticate(Flags::empty()).is_err());
}

/// Each stack is configured to return a different code. A binding that
/// collapsed them, or read the wrong one back, would report the same result
/// for all six.
#[test]
fn every_stack_reports_its_own_code() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("debug-codes")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();

    assert_eq!(
        txn.authenticate(Flags::empty()),
        Err(Error::Pam(PamCode::UserUnknown))
    );
    assert_eq!(
        txn.acct_mgmt(Flags::empty()),
        Err(Error::Pam(PamCode::AcctExpired))
    );
    assert_eq!(
        txn.setcred(CredOp::Establish, Flags::empty()),
        Err(Error::Pam(PamCode::CredExpired))
    );
    assert_eq!(
        txn.open_session(Flags::empty()),
        Err(Error::Pam(PamCode::SessionErr))
    );
    assert_eq!(
        txn.close_session(Flags::empty()),
        Err(Error::Pam(PamCode::SessionErr))
    );
    // The password stack runs twice, and the preliminary pass is the one that
    // stops here.
    assert_eq!(
        txn.chauthtok(Flags::empty()),
        Err(Error::Pam(PamCode::TryAgain))
    );
}

/// Every module in this stack declines to take part, so the stack reaches no
/// decision at all. The dispatcher turns that into `PAM_PERM_DENIED`, and a
/// binding that read "no decision" as a grant would authenticate anyone
/// against a misconfigured service.
#[test]
fn a_stack_that_decides_nothing_denies() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("debug-ignore")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    assert_eq!(
        txn.authenticate(Flags::empty()),
        Err(Error::Pam(PamCode::PermDenied))
    );
}

/// The raw layer runs what it is asked, in the order it is asked, and leaves
/// the sequence to the stack. Refusing an out-of-order call is
/// `Authenticator`'s job, so a check here would put the same rule in two
/// places and disagree with whichever stack does not want it.
#[test]
fn the_raw_layer_imposes_no_sequence_of_its_own() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("permit")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();

    // No authentication has happened, and none of these are refused here.
    txn.open_session(Flags::empty()).unwrap();
    txn.open_session(Flags::empty()).unwrap();
    txn.close_session(Flags::empty()).unwrap();
    txn.close_session(Flags::empty()).unwrap();
    txn.acct_mgmt(Flags::empty()).unwrap();
    txn.setcred(CredOp::Delete, Flags::empty()).unwrap();
}

/// A transaction is not spent by one operation. Repeating authentication on
/// one handle is what a second attempt at the same login is.
#[test]
fn an_operation_may_be_repeated_on_one_transaction() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("stress")
        .user("alice")
        .confdir(dir.path())
        .conversation(Box::new(Fixed("token")))
        .build()
        .unwrap();

    for _ in 0..3 {
        txn.authenticate(Flags::empty()).unwrap();
    }
    assert_eq!(txn.messages().len(), 3, "one round recorded per attempt");

    let mut denied = Transaction::builder("deny")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    for _ in 0..3 {
        assert_eq!(
            denied.authenticate(Flags::empty()),
            Err(Error::Pam(PamCode::AuthErr))
        );
    }
}

/// All four credential operations share one argument with the flags, so an
/// encoding that dropped or merged bits would send the wrong one.
#[test]
fn every_credential_operation_reaches_the_stack() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("permit")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();

    for op in [
        CredOp::Establish,
        CredOp::Reinitialize,
        CredOp::Refresh,
        CredOp::Delete,
    ] {
        txn.setcred(op, Flags::empty()).unwrap();
        txn.setcred(op, Flags::SILENT).unwrap();
    }
}

/// Time one refusal by the `deny` stack, with or without a requested pause.
fn refusal(dir: &std::path::Path, delay: Option<Duration>) -> Duration {
    let mut builder = Transaction::builder("deny").user("alice").confdir(dir);
    if let Some(delay) = delay {
        builder = builder.fail_delay(delay);
    }
    let mut txn = builder.build().unwrap();
    let began = Instant::now();
    assert!(txn.authenticate(Flags::empty()).is_err());
    began.elapsed()
}

/// The pause an application asks for reaches libpam and is applied to a
/// refusal.
///
/// Measured as the difference between two refusals rather than against the
/// clock: the pause is real time, which an instrumented run does not scale,
/// while everything around it is. libpam varies the pause by up to 25%, so
/// half of what was asked for is the bound.
#[test]
fn a_fail_delay_is_applied_to_a_refusal() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let requested = Duration::from_millis(600);

    // Loading the stack is paid for here, so neither measurement carries it.
    refusal(dir.path(), None);

    let undelayed = refusal(dir.path(), None);
    let delayed = refusal(dir.path(), Some(requested));
    assert!(
        delayed > undelayed + requested / 2,
        "no pause: {undelayed:?} without, {delayed:?} with"
    );
}

/// A password change takes flags of its own. The preliminary pass and the
/// update are separate runs of the stack, and `debug-codes` answers them
/// differently, so a binding that ran only one would report the other's code.
#[test]
fn a_password_change_runs_two_passes_and_takes_its_flags() {
    let Some(()) = modules() else { return };
    let dir = confdir();

    let mut txn = Transaction::builder("debug-codes")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    assert_eq!(
        txn.chauthtok(Flags::empty()),
        Err(Error::Pam(PamCode::TryAgain)),
        "the preliminary pass is the one that stops here"
    );

    // The flags meaningful to this call, alone and composed.
    let mut stress = Transaction::builder("stress")
        .user("alice")
        .confdir(dir.path())
        .conversation(Box::new(Fixed("token")))
        .build()
        .unwrap();
    stress.chauthtok(Flags::CHANGE_EXPIRED_AUTHTOK).unwrap();
    stress
        .chauthtok(Flags::CHANGE_EXPIRED_AUTHTOK | Flags::SILENT)
        .unwrap();
}

// --- items ---------------------------------------------------------------

#[test]
fn items_round_trip() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("permit")
        .user("alice")
        .ruser("bob")
        .rhost("198.51.100.7")
        .tty("pts/3")
        .confdir(dir.path())
        .build()
        .unwrap();

    assert_eq!(txn.service().unwrap(), Some("permit"));
    assert_eq!(txn.user().unwrap(), Some("alice"));
    assert_eq!(txn.ruser().unwrap(), Some("bob"));
    assert_eq!(txn.rhost().unwrap(), Some("198.51.100.7"));
    assert_eq!(txn.tty().unwrap(), Some("pts/3"));

    txn.set_user("carol").unwrap();
    txn.set_rhost("localhost").unwrap();
    assert_eq!(txn.user().unwrap(), Some("carol"));
    assert_eq!(txn.rhost().unwrap(), Some("localhost"));
}

/// An item nobody set reads as absent rather than as an empty string.
#[test]
fn unset_items_are_absent() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let txn = Transaction::builder("permit")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    assert_eq!(txn.ruser().unwrap(), None);
    assert_eq!(txn.rhost().unwrap(), None);
    assert_eq!(txn.tty().unwrap(), None);
}

#[test]
fn an_item_with_an_interior_nul_is_refused() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("permit")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    assert_eq!(txn.set_user("a\0b"), Err(Error::NulByte));
    // The refusal happens before libpam is reached, so nothing changed.
    assert_eq!(txn.user().unwrap(), Some("alice"));
}

/// Items are bytes to libpam, not identifiers. An empty one is a value, and a
/// name outside ASCII must survive the round trip unchanged.
#[test]
fn items_take_empty_and_non_ascii_values() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("permit")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();

    txn.set_ruser("").unwrap();
    assert_eq!(txn.ruser().unwrap(), Some(""));

    for name in ["зоя", "李雷", "renée", "a b\tc"] {
        txn.set_user(name).unwrap();
        assert_eq!(txn.user().unwrap(), Some(name));
    }
}

/// An item read after an operation is the one libpam holds then, not a copy
/// taken when the transaction was built.
#[test]
fn items_survive_a_stack_operation() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("stress")
        .user("alice")
        .ruser("bob")
        .rhost("198.51.100.7")
        .tty("pts/3")
        .confdir(dir.path())
        .conversation(Box::new(Fixed("token")))
        .build()
        .unwrap();

    txn.authenticate(Flags::empty()).unwrap();
    txn.acct_mgmt(Flags::empty()).unwrap();

    assert_eq!(txn.user().unwrap(), Some("alice"));
    assert_eq!(txn.ruser().unwrap(), Some("bob"));
    assert_eq!(txn.rhost().unwrap(), Some("198.51.100.7"));
    assert_eq!(txn.tty().unwrap(), Some("pts/3"));
    assert_eq!(txn.service().unwrap(), Some("stress"));
}

/// A service name or directory holding a NUL has no C string form, so the
/// transaction is refused before libpam is reached.
#[test]
fn a_builder_argument_with_an_interior_nul_is_refused() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    assert_eq!(
        Transaction::builder("per\0mit")
            .confdir(dir.path())
            .build()
            .map(|_| ()),
        Err(Error::NulByte)
    );
    assert_eq!(
        Transaction::builder("permit")
            .user("al\0ice")
            .confdir(dir.path())
            .build()
            .map(|_| ()),
        Err(Error::NulByte)
    );
    assert_eq!(
        Transaction::builder("permit")
            .confdir(std::path::Path::new("/no\0where"))
            .build()
            .map(|_| ()),
        Err(Error::NulByte)
    );
}

/// The items are set after the handle exists, so a bad one there is refused
/// with a transaction already open. Whatever it allocated has to come back,
/// and the stack has to be told the login was abandoned rather than completed.
/// Repeated, so anything held per attempt accumulates where memcheck sees it.
#[test]
fn a_builder_that_fails_after_starting_ends_the_transaction() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    for bad in [
        Transaction::builder("permit").ruser("a\0b"),
        Transaction::builder("permit").rhost("a\0b"),
        Transaction::builder("permit").tty("a\0b"),
    ] {
        assert_eq!(
            bad.user("alice").confdir(dir.path()).build().map(|_| ()),
            Err(Error::NulByte)
        );
    }
    for _ in 0..64 {
        assert_eq!(
            Transaction::builder("permit")
                .user("alice")
                .tty("a\0b")
                .confdir(dir.path())
                .build()
                .map(|_| ()),
            Err(Error::NulByte)
        );
    }
}

// --- the PAM environment -------------------------------------------------

#[test]
fn the_environment_round_trips() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("permit")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();

    assert_eq!(txn.getenv("ABSENT").unwrap(), None);
    assert!(txn.env().unwrap().is_empty());

    // A value holding `=` and braces: the split is at the first `=` only.
    txn.putenv("SESSION_DATA", r#"{"origin":"unix","k":"a=b"}"#)
        .unwrap();
    txn.putenv("EMPTY", "").unwrap();
    assert_eq!(
        txn.getenv("SESSION_DATA").unwrap(),
        Some(r#"{"origin":"unix","k":"a=b"}"#)
    );
    assert_eq!(txn.getenv("EMPTY").unwrap(), Some(""));

    let env = txn.env().unwrap();
    assert!(env.contains(&(
        "SESSION_DATA".into(),
        r#"{"origin":"unix","k":"a=b"}"#.into()
    )));
    assert!(env.contains(&("EMPTY".into(), String::new())));

    // Replacing keeps one entry, not two.
    txn.putenv("SESSION_DATA", "replaced").unwrap();
    assert_eq!(txn.getenv("SESSION_DATA").unwrap(), Some("replaced"));
    let env = txn.env().unwrap();
    assert_eq!(env.iter().filter(|(n, _)| n == "SESSION_DATA").count(), 1);

    assert!(txn.unsetenv("SESSION_DATA").unwrap());
    assert_eq!(txn.getenv("SESSION_DATA").unwrap(), None);
    // Absence is an outcome, not a fault: removing what was never there says
    // so rather than raising.
    assert!(!txn.unsetenv("NEVER_SET").unwrap());
    assert!(!txn.unsetenv("SESSION_DATA").unwrap());
}

#[test]
fn environment_names_are_refused_before_libpam_sees_them() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("permit")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    assert_eq!(txn.putenv("A=B", "c"), Err(Error::InvalidName));
    assert_eq!(txn.putenv("", "c"), Err(Error::InvalidName));
    assert_eq!(txn.unsetenv("A=B"), Err(Error::InvalidName));
    assert!(txn.env().unwrap().is_empty());
}

// --- the message record --------------------------------------------------

/// Answers every prompt with a fixed string and records nothing itself, so
/// what the transaction recorded is the only account of the exchange.
struct Fixed(&'static str);

impl Conversation for Fixed {
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

/// A failure carries a code and nothing else. A record that dropped rounds,
/// or lost the text of one, would leave nothing to explain the refusal.
#[test]
fn every_round_is_recorded() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("echo")
        .user("alice")
        .rhost("198.51.100.7")
        .confdir(dir.path())
        .conversation(Box::new(Fixed("unused")))
        .build()
        .unwrap();

    assert!(txn.messages().is_empty());
    txn.authenticate(Flags::empty()).unwrap();

    let rounds = txn.messages();
    assert_eq!(rounds.len(), 1, "pam_echo sends one message");
    let msg = &rounds[0][0];
    assert_eq!(msg.style(), MsgStyle::TextInfo);
    // pam_echo expands these from the items, so their arrival proves the
    // builder's items reached the stack.
    assert_eq!(
        msg.text().trim_end(),
        "user=alice service=echo rhost=198.51.100.7"
    );

    // Taking them leaves the record empty for the next phase.
    let taken = txn.take_messages();
    assert_eq!(taken.len(), 1);
    assert!(txn.messages().is_empty());

    txn.open_session(Flags::empty()).unwrap();
    assert_eq!(txn.messages().len(), 1, "the session stack echoes too");
}

// --- a conversation that does not answer ---------------------------------

/// Counts the rounds it is asked, and answers each prompt with the count.
struct Counting(usize);

impl Conversation for Counting {
    fn converse(
        &mut self,
        messages: &[Message<'_>],
    ) -> Result<Vec<Option<Secret>>> {
        self.0 += 1;
        let round = self.0.to_string();
        Ok(messages
            .iter()
            .map(|m| m.style().wants_response().then(|| Secret::from(&*round)))
            .collect())
    }
}

/// One conversation serves the whole transaction and keeps its own state
/// between rounds. A conversation rebuilt per round would answer every one as
/// though it were the first.
#[test]
fn a_conversation_keeps_its_state_across_rounds() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    // No user, so the stack asks for the name and then for the token.
    let mut txn = Transaction::builder("stress")
        .confdir(dir.path())
        .conversation(Box::new(Counting(0)))
        .build()
        .unwrap();

    txn.authenticate(Flags::empty()).unwrap();
    assert!(txn.messages().len() >= 2);
    // The name it settled on is the answer the second call gave, so the
    // counter advanced between rounds.
    assert_eq!(txn.user().unwrap(), Some("1"));
}

/// Fails every round with a distinctive error.
struct Failing;

impl Conversation for Failing {
    fn converse(
        &mut self,
        _messages: &[Message<'_>],
    ) -> Result<Vec<Option<Secret>>> {
        Err(Error::NotUtf8)
    }
}

/// A module can only be told `PAM_CONV_ERR`, which says nothing about why.
/// The reason this side already has must reach the caller instead.
#[test]
fn a_conversations_own_error_is_reported_not_the_stacks_code() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("stress")
        .user("alice")
        .confdir(dir.path())
        .conversation(Box::new(Failing))
        .build()
        .unwrap();
    assert_eq!(txn.authenticate(Flags::empty()), Err(Error::NotUtf8));
}

/// Answers with the wrong number of responses.
struct Miscounting;

impl Conversation for Miscounting {
    fn converse(
        &mut self,
        _messages: &[Message<'_>],
    ) -> Result<Vec<Option<Secret>>> {
        Ok(Vec::new())
    }
}

#[test]
fn a_short_answer_fails_the_conversation() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("stress")
        .user("alice")
        .confdir(dir.path())
        .conversation(Box::new(Miscounting))
        .build()
        .unwrap();
    assert_eq!(
        txn.authenticate(Flags::empty()),
        Err(Error::Pam(PamCode::ConvErr))
    );
}

/// Panics on the first round.
struct Panicking;

impl Conversation for Panicking {
    fn converse(
        &mut self,
        _messages: &[Message<'_>],
    ) -> Result<Vec<Option<Secret>>> {
        panic!("conversation panicked");
    }
}

/// Unwinding into C is undefined and aborting would skip `pam_end`, so the
/// panic is held until libpam has unwound its own frames and then resumed
/// here. The process must survive, and the transaction must still end.
#[test]
fn a_panicking_conversation_resumes_on_this_thread() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("stress")
        .user("alice")
        .confdir(dir.path())
        .conversation(Box::new(Panicking))
        .build()
        .unwrap();

    let previous = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let caught = panic::catch_unwind(AssertUnwindSafe(|| {
        txn.authenticate(Flags::empty())
    }));
    panic::set_hook(previous);

    let payload = caught.expect_err("the panic must reach this thread");
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"conversation panicked")
    );
    // The round still went on the record, and the handle is still usable
    // enough to end.
    assert_eq!(txn.messages().len(), 1);
}
