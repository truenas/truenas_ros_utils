// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! chronyd's monitoring protocol, for the local daemon: whether the clock
//! is synchronized, how well, and to authenticated time.
//!
//! [`Request`] encodes a request and decodes its reply without I/O;
//! [`Client`] sends requests over chronyd's Unix socket. Nothing that
//! changes the daemon's state is sent.
//!
//! | [`Request`] / [`Client`] | Report |
//! |---|---|
//! | `tracking` | [`Tracking`]: synchronization, offsets, root distance, chronyd's time |
//! | `source_count`, `source` ([`Client::sources`] for all) | [`Source`]: a source's state and latest sample |
//! | `selection` | [`Selection`]: how the last selection treated a source |
//! | `authentication` | [`Authentication`]: an NTP source's NTS or key state |
//!
//! Sources are addressed by index for the list and selection, and by
//! [`Address`] for authentication; reference clocks have no address.
//!
//! # Trusting the clock
//!
//! Admit only NTS-authenticated time within the caller's thresholds; an
//! error means the state could not be read.
//!
//! ```no_run
//! use std::time::SystemTime;
//! use truenas_chrony::{AuthMode, Client, SourceMode, SourceState};
//!
//! const MAX_DISTANCE: f64 = 1.0; // seconds
//! const MAX_CORRECTION: f64 = 1.0; // seconds
//!
//! let mut chronyd = Client::local()?;
//! let tracking = chronyd.tracking()?;
//! let now = tracking.corrected(SystemTime::now());
//!
//! let mut trusted = tracking.is_synchronized()
//!     && tracking.root_distance() < MAX_DISTANCE
//!     && tracking.correction.abs() < MAX_CORRECTION;
//! let mut used = 0;
//! for source in chronyd.sources()? {
//!     if !matches!(source.state, SourceState::Selected | SourceState::Combined)
//!     {
//!         continue;
//!     }
//!     used += 1;
//!     if source.mode == SourceMode::RefClock {
//!         trusted = false;
//!         continue;
//!     }
//!     let auth = chronyd.authentication(source.address)?;
//!     trusted &= auth.mode == AuthMode::Nts && auth.key_bits > 0;
//! }
//! trusted &= used > 0;
//! println!("chronyd's time: {now:?}; trusted: {trusted}");
//! # Ok::<(), truenas_chrony::Error>(())
//! ```
//!
//! Each check catches what the others miss. After a system clock reset,
//! chronyd reports itself synchronized while it slews the error out of
//! [`correction`](Tracking::correction). After losing its sources it still
//! reports itself synchronized, with no source contributing. Under
//! `authselectmode mix`, chronyd's default, a plain source can contribute
//! beside NTS ones; `prefer` and `require` keep plain sources out while an
//! NTS source is configured.
//!
//! # Without I/O
//!
//! ```
//! use truenas_chrony::{Request, Verdict};
//!
//! let request = Request::tracking(0x1234_5678);
//! let datagram = request.as_bytes(); // send this to chronyd
//! assert_eq!(datagram.len(), 104);
//!
//! # let received: &[u8] = &[];
//! match request.decode(received) {
//!     Verdict::Unrelated => { /* not the reply; keep waiting */ }
//!     Verdict::Answer(report) => { /* the report, or why not */ }
//! }
//! ```
//!
//! # Versions
//!
//! Protocol version 6. Each report read here has had one layout since
//! chronyd 4.0; the floor is 4.6.1. A changed layout, a missing command,
//! or another protocol version is an error [`Error::is_unsupported`]
//! recognizes. Unknown enumerated values and flag bits are kept, and
//! trailing bytes are ignored.
//!
//! # Wire format
//!
//! Integers are big-endian. Floats are a 7-bit signed exponent over a
//! 25-bit signed coefficient, `coef * 2^(exp - 25)`, exact as `f64`. An
//! elapsed-seconds count of all ones means none and decodes as `None`.

#![forbid(unsafe_code)]

mod auth;
mod client;
mod error;
mod request;
mod source;
mod tracking;
mod types;
mod wire;

pub use auth::{Algorithm, AuthMode, Authentication};
pub use client::{Client, DEFAULT_SOCKET};
pub use error::{Error, Result, Status};
pub use request::{Request, Verdict};
pub use source::{
    SelectOptions, SelectState, Selection, Source, SourceMode, SourceState,
};
pub use tracking::Tracking;
pub use types::{Address, Leap, RefId};
