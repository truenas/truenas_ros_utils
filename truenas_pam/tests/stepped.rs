// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Authentication driven one round at a time: the exchange, what a timeout
//! does and does not stop, and what abandoning one costs.

mod common;

use common::{confdir, modules};
use std::path::Path;
use std::time::{Duration, Instant};
use truenas_pam::{
    CredOp, Error, Flags, MsgStyle, PamCode, Secret, Step, Stepped, Transaction,
};

/// Answer every message that asked for something, and nothing else.
fn answer(step: &Step, with: &str) -> Vec<Option<Secret>> {
    let Step::Prompt(messages) = step else {
        panic!("not a prompt: {step:?}");
    };
    messages
        .iter()
        .map(|m| m.style().wants_response().then(|| Secret::from(with)))
        .collect()
}

fn start(dir: &Path, service: &str, user: Option<&str>) -> Stepped {
    let mut builder = Transaction::builder(service).confdir(dir);
    if let Some(user) = user {
        builder = builder.user(user);
    }
    Stepped::begin(builder.build().unwrap(), Flags::empty()).unwrap()
}

/// A round is delivered, answered, and the stack carries on from where it
/// parked. Nothing about the exchange happens on the caller's thread.
#[test]
fn an_exchange_runs_round_by_round_to_completion() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    // No user, so the stack asks for the name and then for the token: two
    // rounds.
    let mut auth = start(dir.path(), "stress", None);

    let mut step = auth.wait(None).unwrap();
    let mut rounds = 0;
    while let Step::Prompt(ref messages) = step {
        rounds += 1;
        assert!(rounds < 10, "the exchange is not converging");
        let with =
            if messages.iter().any(|m| m.style() == MsgStyle::PromptEchoOn) {
                "alice"
            } else {
                "token"
            };
        step = auth.respond(answer(&step, with), None).unwrap();
    }
    assert_eq!(step, Step::Done);
    assert!(
        rounds >= 2,
        "expected a name and a token, got {rounds} round(s)"
    );

    // The transaction comes back, carrying what the exchange established.
    let mut txn = auth.finish().unwrap();
    assert_eq!(txn.user().unwrap(), Some("alice"));
    assert_eq!(txn.messages().len(), rounds);
    // And it is still a transaction: the rest of the sequence runs on it.
    txn.acct_mgmt(Flags::empty()).unwrap();
    txn.setcred(CredOp::Establish, Flags::empty()).unwrap();
    txn.open_session(Flags::empty()).unwrap();
    txn.close_session(Flags::empty()).unwrap();
}

/// The transaction's record and what each round delivered are the same
/// messages. A record built from somewhere else could drift from what the
/// caller was actually asked.
#[test]
fn the_record_matches_what_each_round_delivered() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut auth = start(dir.path(), "stress", None);

    let mut delivered = Vec::new();
    let mut step = auth.wait(None).unwrap();
    while let Step::Prompt(ref messages) = step {
        delivered.push(messages.clone());
        let with =
            if messages.iter().any(|m| m.style() == MsgStyle::PromptEchoOn) {
                "alice"
            } else {
                "token"
            };
        step = auth.respond(answer(&step, with), None).unwrap();
    }

    let txn = auth.finish().unwrap();
    assert_eq!(txn.messages(), delivered.as_slice());
    assert!(delivered.len() >= 2);
}

/// A refused authentication is reported when the stack reaches its end, not
/// when a round is answered.
#[test]
fn a_refusal_arrives_at_the_end_of_the_exchange() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut auth = start(dir.path(), "deny", Some("alice"));
    assert_eq!(auth.wait(None), Err(Error::Pam(PamCode::AuthErr)));

    // The transaction still comes back, so the messages behind the refusal
    // can be read.
    let txn = auth.finish().unwrap();
    assert!(txn.user().unwrap().is_some());
}

/// The timeout bounds the wait for the stack to reach its next stopping
/// point. It does not stop the module: `finish` still waits for it.
#[test]
fn a_timeout_ends_the_exchange_but_still_waits_for_the_module() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut auth = start(dir.path(), "slow-deny", Some("alice"));

    // The first round arrives at once.
    let step = auth.wait(Some(Duration::from_secs(10))).unwrap();
    assert!(matches!(step, Step::Prompt(_)));

    // Answering it sends the stack into a module that will not come back for
    // a second. Timing out is itself the proof the wait was bounded: a wait
    // that ran to completion would carry the stack's own result instead.
    let began = Instant::now();
    assert_eq!(
        auth.respond(answer(&step, "token"), Some(Duration::from_millis(50))),
        Err(Error::Timeout)
    );

    // Nothing further can be asked of it.
    assert_eq!(auth.wait(None), Err(Error::OutOfSequence));
    assert_eq!(auth.respond(Vec::new(), None), Err(Error::OutOfSequence));

    // Finishing waits for the module to return, however long it takes.
    let txn = auth.finish().unwrap();
    assert!(began.elapsed() >= Duration::from_millis(500));
    assert!(!txn.messages().is_empty(), "the round is still on record");
}

/// Dropping an exchange in progress cancels it. The worker is parked inside
/// a module, so a cancellation that never reached it would deadlock.
#[test]
fn abandoning_an_exchange_cancels_it() {
    let Some(()) = modules() else { return };
    let dir = confdir();

    let mut auth = start(dir.path(), "stress", Some("alice"));
    let step = auth.wait(None).unwrap();
    assert!(matches!(step, Step::Prompt(_)));
    // The test completing at all is the assertion: a cancellation that never
    // reached the parked worker would hang here forever.
    drop(auth);

    // The same, one step later.
    let mut auth = start(dir.path(), "stress", None);
    let step = auth.wait(None).unwrap();
    let _ = auth.respond(answer(&step, "alice"), None).unwrap();
    drop(auth);
}

/// Abandoning before waiting at all still tears down cleanly.
#[test]
fn abandoning_before_the_first_round_cancels_it() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    drop(start(dir.path(), "stress", Some("alice")));
}

#[test]
fn answering_a_conversation_that_is_not_waiting_is_refused() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut auth = start(dir.path(), "stress", Some("alice"));

    // Nothing has been asked yet.
    assert_eq!(
        auth.respond(vec![Some(Secret::from("token"))], None),
        Err(Error::OutOfSequence)
    );

    let step = auth.wait(None).unwrap();
    // The first round has already been waited for.
    assert_eq!(auth.wait(None), Err(Error::OutOfSequence));

    assert_eq!(auth.respond(answer(&step, "token"), None), Ok(Step::Done));
    // And the exchange is over.
    assert_eq!(auth.respond(Vec::new(), None), Err(Error::OutOfSequence));
}

/// A wrong-sized answer fails the round rather than being padded or truncated.
#[test]
fn a_miscounted_answer_fails_the_exchange() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let mut auth = start(dir.path(), "stress", Some("alice"));
    let _ = auth.wait(None).unwrap();
    assert_eq!(
        auth.respond(Vec::new(), None),
        Err(Error::Pam(PamCode::ConvErr))
    );
}

/// Each transaction has its own handle and its own worker. State shared
/// between them would show up as one exchange answering another's prompt.
#[test]
fn exchanges_run_side_by_side() {
    let Some(()) = modules() else { return };
    let dir = confdir();
    let names = ["alice", "bob", "carol", "dave"];

    // Every exchange is parked at its own prompt before any is answered.
    let mut running: Vec<(Stepped, Step, &str)> = names
        .iter()
        .map(|name| {
            let mut auth = start(dir.path(), "stress", Some(name));
            let step = auth.wait(None).unwrap();
            (auth, step, *name)
        })
        .collect();
    assert!(running.iter().all(|(_, s, _)| matches!(s, Step::Prompt(_))));

    for (mut auth, step, name) in running.drain(..) {
        assert_eq!(auth.respond(answer(&step, "token"), None), Ok(Step::Done));
        let txn = auth.finish().unwrap();
        assert_eq!(txn.user().unwrap(), Some(name));
    }
}
