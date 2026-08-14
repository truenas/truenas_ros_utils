// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The login sequence: the order it runs in, and what it refuses.

mod common;

use common::{confdir, modules};
use std::path::Path;
use std::time::Duration;
use truenas_pam::{
    Authenticator, Error, Flags, PamCode, Secret, Stage, Step, Stepped,
    Transaction,
};

fn login(dir: &Path, service: &str, user: &str) -> Authenticator {
    let txn = Transaction::builder(service)
        .user(user)
        .confdir(dir)
        .build()
        .unwrap();
    Authenticator::new(txn)
}

/// Answer every round with the same string until the exchange ends.
fn run(auth: &mut Authenticator, with: &str) -> Result<(), Error> {
    let mut step = auth.begin()?;
    while let Step::Prompt(messages) = step {
        let answers = messages
            .iter()
            .map(|m| m.style().wants_response().then(|| Secret::from(with)))
            .collect();
        step = auth.respond(answers)?;
    }
    Ok(())
}

/// Start, authenticate, check the account, grant and open, close and revoke.
#[test]
fn the_sequence_runs_in_order() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut auth = login(dir.path(), "stress", "alice");

    assert_eq!(auth.stage(), Stage::Start);
    run(&mut auth, "token").unwrap();
    assert_eq!(auth.stage(), Stage::Authenticated);

    auth.acct_mgmt().unwrap();
    assert_eq!(auth.stage(), Stage::AccountChecked);

    auth.login().unwrap();
    assert_eq!(auth.stage(), Stage::SessionOpen);

    auth.logout().unwrap();
    assert_eq!(auth.stage(), Stage::Ended);

    // The transaction is available throughout, and at the end.
    let txn = auth.into_transaction().unwrap();
    assert_eq!(txn.user().unwrap(), Some("alice"));
}

/// Every step out of order is refused rather than run against a stack that
/// is not ready for it, opening a session for an unauthenticated user most of
/// all.
#[test]
fn steps_out_of_order_are_refused() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut auth = login(dir.path(), "stress", "alice");

    assert_eq!(auth.acct_mgmt(), Err(Error::OutOfSequence));
    assert_eq!(auth.login(), Err(Error::OutOfSequence));
    assert_eq!(auth.logout(), Err(Error::OutOfSequence));
    assert_eq!(auth.respond(Vec::new()), Err(Error::OutOfSequence));

    // Mid-exchange, the transaction belongs to the stack.
    let step = auth.begin().unwrap();
    assert_eq!(auth.stage(), Stage::Authenticating);
    assert!(auth.transaction().is_err());
    assert_eq!(auth.begin(), Err(Error::OutOfSequence));
    assert_eq!(auth.login(), Err(Error::OutOfSequence));

    let Step::Prompt(messages) = step else {
        panic!("expected a prompt")
    };
    let answers = messages
        .iter()
        .map(|_| Some(Secret::from("token")))
        .collect();
    assert_eq!(auth.respond(answers), Ok(Step::Done));

    // Authenticated, but the session has not been opened.
    assert_eq!(auth.logout(), Err(Error::OutOfSequence));
    // The account check is a step of the sequence, not an option: a login
    // that skipped it would open a session for an expired or locked
    // account the account stack was never asked about.
    assert_eq!(auth.login(), Err(Error::OutOfSequence));
    auth.acct_mgmt().unwrap();
    auth.login().unwrap();
    // And not twice.
    assert_eq!(auth.login(), Err(Error::OutOfSequence));
    auth.logout().unwrap();
    assert_eq!(auth.logout(), Err(Error::OutOfSequence));
}

/// The per-step timeout reaches the exchange underneath. Without it a login
/// that a module never answers would hold its session open indefinitely.
#[test]
fn a_step_timeout_bounds_each_round() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let txn = Transaction::builder("slow-deny")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    let mut auth = Authenticator::new(txn).timeout(Duration::from_secs(10));

    // The first round runs under a bound that does not fire. The tight
    // bound goes on the round that runs into the slow module, and only
    // there: anywhere earlier it races the machine, not the module.
    let step = auth.begin().unwrap();
    let Step::Prompt(messages) = step else {
        panic!("expected a prompt")
    };
    let answers = messages
        .iter()
        .map(|_| Some(Secret::from("token")))
        .collect();
    let mut auth = auth.timeout(Duration::from_millis(50));
    assert_eq!(auth.respond(answers), Err(Error::Timeout));
    assert_eq!(auth.stage(), Stage::Failed);

    // The module is still in flight, so the transaction is not here:
    // respond returned on the timeout instead of joining the worker,
    // which would have recovered it and held this thread for the
    // module's whole delay.
    assert!(auth.transaction().is_err());

    // Taking it back is the blocking step, and still recovers it once
    // the module returns.
    assert!(auth.into_transaction().is_ok());
}

/// A refusal leaves the transaction readable. A sequence that dropped it on
/// failure would leave the caller with a code and no account of it.
#[test]
fn a_refusal_leaves_the_record_readable() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut auth = login(dir.path(), "echo-deny", "alice");

    assert_eq!(run(&mut auth, "token"), Err(Error::Pam(PamCode::AuthErr)));
    assert_eq!(auth.stage(), Stage::Failed);

    let txn = auth.transaction().unwrap();
    let said: Vec<String> = txn
        .messages()
        .iter()
        .flatten()
        .map(|m| m.text().into_owned())
        .collect();
    assert!(
        said.iter().any(|m| m.contains("no room at the inn")),
        "the stack's own words are lost: {said:?}"
    );

    // Nothing further follows a refusal.
    assert_eq!(auth.acct_mgmt(), Err(Error::OutOfSequence));
    assert_eq!(auth.login(), Err(Error::OutOfSequence));
}

/// A stack may accept the credentials and still refuse the account. The two
/// are separate questions, and ADG 3.1 has the application ask both.
#[test]
fn an_authenticated_user_can_still_be_refused_an_account() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut auth = login(dir.path(), "stress-expired", "alice");

    run(&mut auth, "token").unwrap();
    assert_eq!(auth.stage(), Stage::Authenticated);
    assert_eq!(auth.acct_mgmt(), Err(Error::Pam(PamCode::NewAuthtokReqd)));
    // The stage does not move: the account is good, and the caller's next move
    // is a password change, not a refusal.
    assert_eq!(auth.stage(), Stage::Authenticated);

    // Which it drives over the same transaction.
    let txn = auth.into_transaction().unwrap();
    let mut change = Stepped::begin_chauthtok(txn, Flags::empty()).unwrap();
    let mut step = change.wait(None).unwrap();
    while let Step::Prompt(messages) = step {
        let answers = messages
            .iter()
            .map(|m| m.style().wants_response().then(|| Secret::from("new")))
            .collect();
        step = change.respond(answers, None).unwrap();
    }
    assert_eq!(step, Step::Done);
}

/// A refused authentication may be tried again on the same transaction.
#[test]
fn a_refusal_can_be_tried_again() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut auth = login(dir.path(), "deny", "alice");

    assert_eq!(run(&mut auth, "token"), Err(Error::Pam(PamCode::AuthErr)));
    assert_eq!(auth.stage(), Stage::Failed);
    assert_eq!(run(&mut auth, "token"), Err(Error::Pam(PamCode::AuthErr)));
    assert_eq!(auth.stage(), Stage::Failed);
}

/// Credentials granted for a session that never opened are revoked again
/// rather than left behind.
#[test]
fn a_session_that_will_not_open_does_not_leave_credentials_granted() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut auth = login(dir.path(), "no-session", "alice");

    run(&mut auth, "token").unwrap();
    auth.acct_mgmt().unwrap();
    assert_eq!(auth.login(), Err(Error::Pam(PamCode::SessionErr)));
    // The sequence stays where it was, so the caller may try again or give up.
    assert_eq!(auth.stage(), Stage::AccountChecked);
    assert_eq!(auth.logout(), Err(Error::OutOfSequence));
}

/// The environment set before the exchange reaches the stack, and what a
/// module leaves behind is readable after it. Moving the transaction to the
/// worker and back must not lose either.
#[test]
fn the_environment_crosses_the_exchange() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut txn = Transaction::builder("permit")
        .user("alice")
        .confdir(dir.path())
        .build()
        .unwrap();
    txn.putenv("SESSION_DATA", r#"{"origin":"unix"}"#).unwrap();

    let mut auth = Authenticator::new(txn);
    run(&mut auth, "token").unwrap();
    auth.acct_mgmt().unwrap();
    auth.login().unwrap();

    assert_eq!(
        auth.transaction().unwrap().getenv("SESSION_DATA").unwrap(),
        Some(r#"{"origin":"unix"}"#)
    );
    auth.logout().unwrap();
}
