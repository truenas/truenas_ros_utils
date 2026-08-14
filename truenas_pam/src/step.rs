// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Stepped`] — authentication driven one round at a time.
//!
//! `pam_authenticate` does not return between prompts: it calls down into the
//! stack, which calls back up through the conversation, and only returns once
//! the whole exchange is over. A server that has to ask its client for a
//! second factor cannot answer from inside that callback.
//!
//! So the call runs on a worker thread. Its conversation is a channel: it
//! hands the messages to whoever holds the [`Stepped`] and blocks until the
//! answers come back. The stack is parked mid-prompt, and the caller is free.
//!
//! # Where the transaction is
//!
//! The [`Transaction`] moves onto the worker and comes back from
//! [`finish`](Stepped::finish). While the exchange runs it belongs to the
//! stack: items and the environment are read and written before
//! [`begin`](Stepped::begin) and after `finish`, never in between.
//!
//! # Cancellation is cooperative
//!
//! A module cannot be stopped mid-call, so a cancellation takes effect only
//! when the module next comes back to the conversation, and the join that
//! follows is unbounded. A module blocked in I/O is waited for.
//!
//! A `timeout` therefore bounds the round trip, not the module. When one
//! fires, the exchange is abandoned and the driver takes no further step;
//! `finish` and [`Drop`] still wait for the worker to unwind. Both block.

use crate::conv::{Conversation, Message, OwnedMessage};
use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::txn::{Flags, Transaction};
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use std::{mem, ptr};

/// Where the stack got to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Step {
    /// It is parked in the conversation, waiting for these to be answered.
    /// One response per message, in the same order.
    Prompt(Vec<OwnedMessage>),
    /// It finished, and the operation succeeded.
    Done,
}

/// What the worker sends back.
enum Event {
    Prompt(Vec<OwnedMessage>),
    Finished,
}

/// What the worker returns: the transaction, and how the operation ended — or
/// the panic that stopped it.
type Outcome = (Transaction, std::thread::Result<Result<()>>);

/// Which of the two prompting operations the worker runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Op {
    Authenticate,
    Chauthtok,
}

impl Op {
    fn run(self, txn: &mut Transaction, flags: Flags) -> Result<()> {
        match self {
            Op::Authenticate => txn.authenticate(flags),
            Op::Chauthtok => txn.chauthtok(flags),
        }
    }
}

/// The conversation the worker runs: hand the round over, wait for answers.
struct Channel {
    events: SyncSender<Event>,
    answers: Receiver<Vec<Option<Secret>>>,
}

impl Conversation for Channel {
    fn converse(
        &mut self,
        messages: &[Message<'_>],
    ) -> Result<Vec<Option<Secret>>> {
        let round = messages.iter().map(|m| m.into_owned()).collect();
        // Either end failing means the driver has let go: it timed out, or
        // it was dropped. Both are a cancellation, and the stack unwinds.
        if self.events.send(Event::Prompt(round)).is_err() {
            return Err(Error::Timeout);
        }
        self.answers.recv().map_err(|_| Error::Timeout)
    }
}

/// Keep asynchronous signals off the worker.
///
/// A consumer's handlers belong on its own threads, and a module blocked in
/// I/O must not be interrupted mid-call. The synchronous fault signals stay
/// unblocked: blocking one does not stop it reaching the thread that caused
/// it, it only removes the chance of handling it.
fn block_signals() {
    // SAFETY: `set` is filled by `sigfillset` before anything reads it, and
    // the calls that follow only read and write that one value.
    #[allow(unsafe_code)]
    unsafe {
        let mut set = mem::MaybeUninit::<libc::sigset_t>::uninit();
        libc::sigfillset(set.as_mut_ptr());
        let mut set = set.assume_init();
        for signal in [libc::SIGSEGV, libc::SIGBUS, libc::SIGFPE, libc::SIGILL]
        {
            libc::sigdelset(&mut set, signal);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, ptr::null_mut());
    }
}

/// An authentication in progress, suspended at each conversation.
///
/// ```no_run
/// use truenas_pam::{Flags, Secret, Step, Stepped, Transaction};
/// use std::time::Duration;
///
/// let txn = Transaction::builder("truenas").user("alice").build()?;
/// let mut auth = Stepped::begin(txn, Flags::empty())?;
/// let limit = Some(Duration::from_secs(10));
///
/// let mut step = auth.wait(limit)?;
/// while let Step::Prompt(messages) = step {
///     let answers = messages
///         .iter()
///         .map(|m| m.style().wants_response().then(|| Secret::from("hunter2")))
///         .collect();
///     step = auth.respond(answers, limit)?;
/// }
///
/// let txn = auth.finish()?;
/// println!("authenticated {:?}", txn.user()?);
/// # Ok::<(), truenas_pam::Error>(())
/// ```
pub struct Stepped {
    worker: Option<JoinHandle<Outcome>>,
    answers: Option<SyncSender<Vec<Option<Secret>>>>,
    events: Option<Receiver<Event>>,
    phase: Phase,
    /// Held once the worker has handed the transaction back.
    done: Option<Transaction>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    /// Running, and the first round has not been waited for.
    Started,
    /// Parked in the conversation.
    Prompting,
    /// The operation returned.
    Ended,
    /// Abandoned. Only `finish` and `Drop` remain.
    Stopped,
}

impl Stepped {
    /// Start `pam_authenticate` on a worker thread.
    ///
    /// Nothing is waited for here; the first round comes from
    /// [`wait`](Stepped::wait). Honours the same flags as
    /// [`Transaction::authenticate`].
    ///
    /// Fails only if the thread cannot be created, in which case the stack has
    /// not run and the transaction is ended.
    pub fn begin(txn: Transaction, flags: Flags) -> Result<Stepped> {
        Stepped::run(txn, flags, Op::Authenticate).map_err(|(txn, e)| {
            drop(txn); // the documented contract: the transaction is ended
            e
        })
    }

    /// Start `pam_chauthtok` on a worker thread, driven the same way.
    ///
    /// A password change is an exchange in the same way: the stack asks for
    /// the old token, then the new one twice. Honours the same flags as
    /// [`Transaction::chauthtok`].
    pub fn begin_chauthtok(txn: Transaction, flags: Flags) -> Result<Stepped> {
        Stepped::run(txn, flags, Op::Chauthtok).map_err(|(txn, e)| {
            drop(txn); // as `begin`: the transaction is ended
            e
        })
    }

    /// [`begin`](Stepped::begin), except a spawn failure hands the
    /// transaction back instead of ending it, so a sequencer holding the
    /// only handle can keep it for a retry.
    pub(crate) fn begin_recover(
        txn: Transaction,
        flags: Flags,
    ) -> std::result::Result<Stepped, (Transaction, Error)> {
        Stepped::run(txn, flags, Op::Authenticate)
    }

    fn run(
        mut txn: Transaction,
        flags: Flags,
        op: Op,
    ) -> std::result::Result<Stepped, (Transaction, Error)> {
        // Rendezvous on both: the worker must not run ahead of the caller, and
        // a send that finds nobody there is how a cancellation is noticed.
        let (event_tx, event_rx) = sync_channel::<Event>(0);
        let (answer_tx, answer_rx) = sync_channel(0);

        let restore = txn.set_conversation(Box::new(Channel {
            events: event_tx.clone(),
            answers: answer_rx,
        }));

        // The transaction rides to the worker in a parcel this side keeps
        // a handle to: a failed spawn never ran the closure, so the parcel
        // still holds the transaction for taking back.
        let parcel = Arc::new(Mutex::new(Some((txn, restore))));
        let theirs = Arc::clone(&parcel);
        let spawned = std::thread::Builder::new()
            .name("pam-exchange".into())
            .spawn(move || {
                block_signals();
                let (mut txn, restore) = theirs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                    .expect("the parcel is taken only by the worker");
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    op.run(&mut txn, flags)
                }));
                // Put the caller's conversation back before handing the
                // transaction over.
                txn.set_conversation(restore);
                // The driver may already have gone.
                let _ = event_tx.send(Event::Finished);
                (txn, result)
            });
        let worker = match spawned {
            Ok(worker) => worker,
            Err(e) => {
                let (mut txn, restore) = parcel
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take()
                    .expect("a failed spawn never ran the worker");
                txn.set_conversation(restore);
                let e = Error::Os(e.raw_os_error().unwrap_or(libc::EAGAIN));
                return Err((txn, e));
            }
        };

        Ok(Stepped {
            worker: Some(worker),
            answers: Some(answer_tx),
            events: Some(event_rx),
            phase: Phase::Started,
            done: None,
        })
    }

    /// Wait for the first round, or for the stack to finish without one.
    ///
    /// `timeout` bounds this wait only; see the module note on what it does
    /// not bound. `None` waits indefinitely.
    pub fn wait(&mut self, timeout: Option<Duration>) -> Result<Step> {
        if self.phase != Phase::Started {
            return Err(Error::OutOfSequence);
        }
        self.collect(timeout)
    }

    /// Answer the round in hand and wait for the next, or for the end.
    ///
    /// One response per message of the [`Step::Prompt`] being answered, in the
    /// same order; [`None`] for a message that asked nothing.
    pub fn respond(
        &mut self,
        responses: Vec<Option<Secret>>,
        timeout: Option<Duration>,
    ) -> Result<Step> {
        if self.phase != Phase::Prompting {
            return Err(Error::OutOfSequence);
        }
        let sent = match &self.answers {
            Some(answers) => answers.send(responses).is_ok(),
            None => false,
        };
        if !sent {
            // The worker is gone, so its result is the answer to this.
            self.phase = Phase::Ended;
            return self.reap().map(|()| Step::Done);
        }
        self.phase = Phase::Started;
        self.collect(timeout)
    }

    /// Wait for the worker to reach its next stopping point.
    fn collect(&mut self, timeout: Option<Duration>) -> Result<Step> {
        let events = self.events.as_ref().ok_or(Error::OutOfSequence)?;
        let event = match timeout {
            Some(limit) => events.recv_timeout(limit),
            None => events.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match event {
            Ok(Event::Prompt(messages)) => {
                self.phase = Phase::Prompting;
                Ok(Step::Prompt(messages))
            }
            Ok(Event::Finished) => {
                self.phase = Phase::Ended;
                self.reap().map(|()| Step::Done)
            }
            // The worker dropped its end without saying so: it panicked
            // outside the conversation, or was torn down.
            Err(RecvTimeoutError::Disconnected) => {
                self.phase = Phase::Ended;
                self.reap().map(|()| Step::Done)
            }
            Err(RecvTimeoutError::Timeout) => {
                self.phase = Phase::Stopped;
                Err(Error::Timeout)
            }
        }
    }

    /// Wait for the worker, keeping the transaction and reporting how the
    /// operation ended.
    fn reap(&mut self) -> Result<()> {
        // Releasing both ends is what a parked worker sees as a cancellation.
        self.answers = None;
        self.events = None;
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        match worker.join() {
            Ok((txn, result)) => {
                self.done = Some(txn);
                match result {
                    Ok(result) => result,
                    // Raised in the conversation, held while libpam unwound
                    // its own frames, and resumed here on the caller's thread.
                    Err(payload) => panic::resume_unwind(payload),
                }
            }
            // The worker itself came apart, not the conversation inside it.
            Err(payload) => panic::resume_unwind(payload),
        }
    }

    /// Stop, and take the transaction back.
    ///
    /// Abandoning an exchange in progress cancels it, which means waiting for
    /// the stack to come back to the conversation. The transaction is returned
    /// however it ended, so its [`messages`](Transaction::messages) can still
    /// be read.
    pub fn finish(mut self) -> Result<Transaction> {
        // The transaction is returned whatever the result was: that has
        // already been reported, and the record has not.
        let outcome = self.reap();
        match self.done.take() {
            Some(txn) => Ok(txn),
            None => Err(outcome.err().unwrap_or(Error::OutOfSequence)),
        }
    }
}

impl Drop for Stepped {
    fn drop(&mut self) {
        // Cancel and wait, as `finish` does. A panic must not escape a
        // drop, so a payload that reached the worker is discarded here.
        self.answers = None;
        self.events = None;
        if let Some(worker) = self.worker.take() {
            let joined = worker.join();
            if let Ok((txn, _)) = joined {
                drop(txn);
            }
        }
    }
}

impl std::fmt::Debug for Stepped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stepped")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
