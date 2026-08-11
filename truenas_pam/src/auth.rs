// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Authenticator`] — the login sequence, in the order the standard sets out.
//!
//! ADG 3.1 fixes what an application does around an authentication: check the
//! account once the credentials are accepted, grant the credentials before
//! opening a session, and revoke them after closing it. This puts that order
//! in one place, over a [`Stepped`] exchange, and refuses anything out of
//! sequence.
//!
//! It decides nothing. Which service to run, what a prompt means, whether a
//! refusal should be retried against a different stack — all of that is policy
//! and belongs to the consumer.

use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::step::{Step, Stepped};
use crate::txn::{CredOp, Flags, Transaction};
use std::mem;
use std::time::Duration;

/// How far through the sequence an [`Authenticator`] is.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Stage {
    /// Nothing has run.
    Start,
    /// An exchange is under way; the stack is waiting to be answered.
    Authenticating,
    /// The credentials were accepted.
    Authenticated,
    /// A session is open.
    SessionOpen,
    /// The session has been closed.
    Ended,
    /// Something refused. The transaction is still readable.
    Failed,
}

/// Where the transaction is: held here, or on the exchange's worker.
enum Held {
    Transaction(Transaction),
    Exchange(Stepped),
    /// The exchange could not be started, so there is nothing left to hold.
    Nothing,
}

/// Drives one login from end to end.
///
/// ```no_run
/// use truenas_pam::{Authenticator, Secret, Stage, Step, Transaction};
/// use std::time::Duration;
///
/// let txn = Transaction::builder("truenas").user("alice").build()?;
/// let mut login = Authenticator::new(txn).timeout(Duration::from_secs(10));
///
/// let mut step = login.begin()?;
/// while let Step::Prompt(messages) = step {
///     let answers = messages
///         .iter()
///         .map(|m| m.style().wants_response().then(|| Secret::from("hunter2")))
///         .collect();
///     step = login.respond(answers)?;
/// }
///
/// login.acct_mgmt()?;
/// login.login()?;
/// assert_eq!(login.stage(), Stage::SessionOpen);
/// // ... the session runs ...
/// login.logout()?;
/// # Ok::<(), truenas_pam::Error>(())
/// ```
pub struct Authenticator {
    held: Held,
    stage: Stage,
    flags: Flags,
    timeout: Option<Duration>,
}

impl Authenticator {
    /// Take over a transaction.
    ///
    /// Anything the stack needs before it runs — items, and the PAM
    /// environment a module reads — goes on the transaction first.
    pub fn new(transaction: Transaction) -> Authenticator {
        Authenticator {
            held: Held::Transaction(transaction),
            stage: Stage::Start,
            flags: Flags::empty(),
            timeout: None,
        }
    }

    /// Flags for every operation in the sequence. Each honours the ones
    /// meaningful to it; see [`Flags`].
    pub fn flags(mut self, flags: Flags) -> Authenticator {
        self.flags = flags;
        self
    }

    /// How long to wait for each round of the exchange. Unset waits
    /// indefinitely.
    ///
    /// This bounds the wait, not the module behind it; see [`Stepped`].
    pub fn timeout(mut self, timeout: Duration) -> Authenticator {
        self.timeout = Some(timeout);
        self
    }

    /// How far the sequence has got.
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// Start authenticating.
    ///
    /// Returns the first round to answer, or [`Step::Done`] if the stack
    /// wanted nothing. A refusal leaves the stage at [`Stage::Failed`], from
    /// where this may be called again to try afresh — against the same
    /// service, since a transaction is bound to one.
    pub fn begin(&mut self) -> Result<Step> {
        if !matches!(self.stage, Stage::Start | Stage::Failed) {
            return Err(Error::OutOfSequence);
        }
        let Held::Transaction(txn) =
            mem::replace(&mut self.held, Held::Nothing)
        else {
            return Err(Error::OutOfSequence);
        };
        match Stepped::begin(txn, self.flags) {
            Ok(exchange) => {
                self.held = Held::Exchange(exchange);
                self.stage = Stage::Authenticating;
            }
            Err(e) => {
                self.stage = Stage::Failed;
                return Err(e);
            }
        }
        self.step(None)
    }

    /// Answer the round in hand.
    ///
    /// One response per message of the [`Step::Prompt`] being answered, in the
    /// same order; [`None`] for a message that asked nothing.
    pub fn respond(&mut self, responses: Vec<Option<Secret>>) -> Result<Step> {
        if self.stage != Stage::Authenticating {
            return Err(Error::OutOfSequence);
        }
        self.step(Some(responses))
    }

    /// Check that the account is usable: not expired, not locked, permitted
    /// from here and now.
    ///
    /// ADG 3.1 puts this after authentication and before anything is granted.
    /// [`NewAuthtokReqd`](crate::PamCode::NewAuthtokReqd) means the account is
    /// good and its password must change first; the stage is left where it
    /// was, so the caller can take the transaction and drive
    /// [`Stepped::begin_chauthtok`] over it.
    pub fn acct_mgmt(&mut self) -> Result<()> {
        if self.stage != Stage::Authenticated {
            return Err(Error::OutOfSequence);
        }
        let flags = self.flags;
        self.transaction_mut()?.acct_mgmt(flags)
    }

    /// Grant the user's credentials and open a session, in that order.
    ///
    /// Credentials granted for a session that does not open are revoked
    /// again.
    pub fn login(&mut self) -> Result<()> {
        if self.stage != Stage::Authenticated {
            return Err(Error::OutOfSequence);
        }
        let flags = self.flags;
        let txn = self.transaction_mut()?;
        txn.setcred(CredOp::Establish, flags)?;
        if let Err(e) = txn.open_session(flags) {
            let _ = txn.setcred(CredOp::Delete, flags);
            return Err(e);
        }
        self.stage = Stage::SessionOpen;
        Ok(())
    }

    /// Close the session and revoke the credentials, in that order.
    ///
    /// The credentials are revoked whether or not the session closed
    /// cleanly. The first error of the two is reported.
    pub fn logout(&mut self) -> Result<()> {
        if self.stage != Stage::SessionOpen {
            return Err(Error::OutOfSequence);
        }
        let flags = self.flags;
        let txn = self.transaction_mut()?;
        let closed = txn.close_session(flags);
        let revoked = txn.setcred(CredOp::Delete, flags);
        self.stage = Stage::Ended;
        closed.and(revoked)
    }

    /// The transaction, for reading what the stack established: the user it
    /// settled on, the environment a module left behind, the messages it
    /// sent.
    ///
    /// Unavailable while an exchange is running, because it belongs to the
    /// stack until the round is answered.
    pub fn transaction(&self) -> Result<&Transaction> {
        match &self.held {
            Held::Transaction(txn) => Ok(txn),
            _ => Err(Error::OutOfSequence),
        }
    }

    /// The transaction, mutably. See [`transaction`](Authenticator::transaction).
    pub fn transaction_mut(&mut self) -> Result<&mut Transaction> {
        match &mut self.held {
            Held::Transaction(txn) => Ok(txn),
            _ => Err(Error::OutOfSequence),
        }
    }

    /// Give up the sequence and take the transaction back.
    pub fn into_transaction(self) -> Result<Transaction> {
        match self.held {
            Held::Transaction(txn) => Ok(txn),
            Held::Exchange(exchange) => exchange.finish(),
            Held::Nothing => Err(Error::OutOfSequence),
        }
    }

    /// Advance the exchange: wait for the first round, or answer the one in
    /// hand.
    fn step(&mut self, responses: Option<Vec<Option<Secret>>>) -> Result<Step> {
        let Held::Exchange(exchange) = &mut self.held else {
            return Err(Error::OutOfSequence);
        };
        let step = match responses {
            None => exchange.wait(self.timeout),
            Some(responses) => exchange.respond(responses, self.timeout),
        };
        match step {
            Ok(Step::Prompt(messages)) => {
                self.stage = Stage::Authenticating;
                Ok(Step::Prompt(messages))
            }
            Ok(Step::Done) => {
                self.settle(Stage::Authenticated);
                Ok(Step::Done)
            }
            Err(e) => {
                self.settle(Stage::Failed);
                Err(e)
            }
        }
    }

    /// Take the transaction back from the exchange and record where the
    /// sequence stopped.
    fn settle(&mut self, stage: Stage) {
        if let Held::Exchange(exchange) =
            mem::replace(&mut self.held, Held::Nothing)
        {
            // A finish that yields nothing leaves `Nothing`, which every
            // accessor reports as out of sequence.
            if let Ok(txn) = exchange.finish() {
                self.held = Held::Transaction(txn);
            }
        }
        self.stage = stage;
    }
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("stage", &self.stage)
            .field("flags", &self.flags)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}
