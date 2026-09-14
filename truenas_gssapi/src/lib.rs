// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! A GSSAPI acceptor over the system `libgssapi_krb5`: names, key-table
//! credentials, and the accept-side security-context loop, for SPNEGO and
//! Kerberos.
//!
//! [`AcceptorCred`] holds the identity tokens are checked against, drawn
//! from a key table.
//! [`Acceptor`] runs the accept side one token at a time. [`Name`] carries
//! the authenticated initiator and maps it to a local account. There is no
//! initiator side and no per-message wrap/unwrap: an HTTP `Negotiate`
//! exchange authenticates and stops.
//!
//! ```no_run
//! use truenas_gssapi::{AcceptorCred, Oid, Step};
//!
//! // Accept for HTTP/<host> out of a key table.
//! let cred = AcceptorCred::from_keytab("FILE:/etc/krb5.keytab", None)?;
//! let mut acceptor = truenas_gssapi::Acceptor::new(&cred);
//!
//! // `token` is the initiator's Negotiate blob (base64-decoded).
//! # let token = &b""[..];
//! match acceptor.step(token)? {
//!     Step::Continue { token } => { /* send as the next challenge */ }
//!     Step::Complete { .. } => {
//!         let who = acceptor.source_name().unwrap();
//!         let user = who.localname(Some(&Oid::krb5()))?; // auth_to_local
//!         let _ = user;
//!     }
//! }
//! # Ok::<(), truenas_gssapi::Error>(())
//! ```
//!
//! # Identity comes from the mechanism, not a claim
//!
//! The authenticated name is whatever the initiator's ticket proves. To
//! reach a Unix account, [`Name::localname`] applies the mechanism's own
//! mapping — for Kerberos, the `auth_to_local` rules in `krb5.conf` — and
//! an unmappable name is an error, never a guess. Feeding that account to
//! a name service is the caller's step.
//!
//! # Handles are `Send`, not `Sync`
//!
//! Every handle wraps a library object used from one thread at a time.
//! [`AcceptorCred`] and [`Name`] are `Send` (immutable once built);
//! [`Acceptor`] borrows a credential and is stepped in place, so one
//! exchange stays on one thread. Nothing shares a handle across threads.
//!
//! # Errors
//!
//! [`Error`] carries the raw major and minor status and the library's
//! rendering of both, captured at the failing call under the mechanism
//! that produced the minor status; the routine field classifies as
//! [`RoutineError`], whose variants keep the C bindings' `GSS_S_` names.
//!
//! # Requirements
//!
//! `libkrb5-dev` to build; `libgssapi-krb5-2` to run. Checked against MIT
//! Kerberos 1.21.3. A live exchange needs the host's Kerberos state — a
//! key table with the acceptor's key, and `/etc/krb5.conf`.

mod accept;
mod buf;
mod cred;
mod error;
mod ffi;
mod name;
mod oid;
mod util;

pub use accept::{Acceptor, ContextFlags, Step};
pub use cred::AcceptorCred;
pub use error::{Error, Result, RoutineError};
pub use name::Name;
pub use oid::Oid;
