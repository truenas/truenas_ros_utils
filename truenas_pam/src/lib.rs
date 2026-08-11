// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! A PAM client: transactions against the system `libpam`, and a login
//! sequence driven one round at a time.
//!
//! [`Transaction`] is one exchange with a service's stack of modules, from
//! `pam_start_confdir` to `pam_end`. [`Authenticator`] runs the sequence a
//! login is made of, in the order the standard sets out. [`Stepped`] is what
//! sits underneath it: `pam_authenticate` on a worker thread, parked at each
//! prompt so the caller can answer at its own pace.
//!
//! ```
//! use truenas_pam::{Authenticator, Secret, Stage, Step, Transaction};
//!
//! # let dir = tempfile::tempdir()?;
//! # std::fs::write(
//! #     dir.path().join("example"),
//! #     "auth required pam_permit.so\naccount required pam_permit.so\n\
//! #      session required pam_permit.so\n",
//! # )?;
//! let transaction = Transaction::builder("example")
//!     .user("alice")
//!     .rhost("198.51.100.7")
//! #   .confdir(dir.path())
//!     .build()?;
//!
//! let mut login = Authenticator::new(transaction);
//! let mut step = login.begin()?;
//! while let Step::Prompt(messages) = step {
//!     let answers = messages
//!         .iter()
//!         .map(|m| m.style().wants_response().then(|| Secret::from("hunter2")))
//!         .collect();
//!     step = login.respond(answers)?;
//! }
//!
//! login.acct_mgmt()?;
//! login.login()?;
//! assert_eq!(login.stage(), Stage::SessionOpen);
//! // ... the session runs ...
//! login.logout()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # The conversation
//!
//! A module does not return a question and wait to be called again. It calls
//! back into the application, through the function registered when the
//! transaction began, with an array of messages; the application answers all
//! of them at once and the module carries on from where it was.
//!
//! [`Conversation`] is that function. One response per message, in the same
//! order, [`None`] for a message that asked nothing. Answers are handed to
//! the module stack, which frees them; the ones it never sees are overwritten
//! before they are released, because they hold whatever the user typed.
//!
//! [`Unattended`] is the default and answers nothing. Account and session
//! stacks inform rather than ask, so they run under it with nobody waiting.
//!
//! # One thread at a time
//!
//! A `pam_handle_t` is not thread-safe. libpam does no locking and refuses a
//! call made while another is in progress on the handle. Every operation takes
//! `&mut self`, so a transaction is driven only by whoever holds it. Give each
//! concurrent login its own.
//!
//! A module may itself be unsafe to run concurrently, in which case one
//! transaction per thread is not enough and the consumer needs one lock
//! covering all of them.
//!
//! # Driving an exchange step by step
//!
//! `pam_authenticate` returns only when the whole exchange is over, so a
//! server that must ask its client for a second factor cannot answer from
//! inside the callback. [`Stepped`] runs the call on a worker thread whose
//! conversation is a channel: it hands each round over and blocks, leaving the
//! stack parked mid-prompt and the caller free.
//!
//! The transaction moves onto that worker and comes back from
//! [`Stepped::finish`]. Items and the environment are read and written before
//! the exchange and after it, never during.
//!
//! A module cannot be stopped mid-call, so a cancellation takes effect only
//! when it next returns to the conversation, and the wait for that is
//! unbounded. A step timeout bounds the round trip; tearing the exchange down
//! still waits for the module.
//!
//! # What this crate does not do
//!
//! It knows PAM and nothing above it. Which service to run, what a prompt
//! means, whether a refusal should be retried against another stack, what to
//! make of an account that is locked rather than wrong — all of that is policy
//! and belongs to the consumer. What is here is the transaction, the
//! conversation, the sequence, and the record of what the stack said
//! ([`Transaction::messages`]).
//!
//! # Requirements
//!
//! `libpam0g-dev` to build, `libpam0g` to run, plus whichever modules the
//! service files in use name. Checked against 1.7.0.
//!
//! Conforms to the Linux-PAM Application Developers' Guide, which ships in
//! `libpam-doc`. [`pam_start_confdir`][confdir] is the entry point, so a
//! transaction may be pointed at service files of its own instead of
//! `/etc/pam.d`. It needs libpam 1.4 or newer.
//!
//! [confdir]: Builder::confdir

mod auth;
mod conv;
mod error;
mod ffi;
mod secret;
mod step;
mod txn;

pub use auth::{Authenticator, Stage};
pub use conv::{Conversation, Message, MsgStyle, OwnedMessage, Unattended};
pub use error::{Error, PamCode, Result};
pub use secret::Secret;
pub use step::{Step, Stepped};
pub use txn::{Builder, CredOp, Flags, Transaction};
