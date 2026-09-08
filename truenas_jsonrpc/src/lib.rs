// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! JSON-RPC 2.0, both roles, without doing any I/O.
//!
//! Bytes in, bytes out. The crate turns one frame into what it held and
//! turns what a caller decided back into a frame. It never reads a socket,
//! owns a runtime, spawns anything, or holds a connection — a consumer
//! drives it with bytes it obtained however it likes and writes the bytes
//! it gets back.
//!
//! Nothing here departs from the specification. There is no dialect, no
//! extension and no configuration: what §4 admits is accepted and what §5
//! requires is emitted.
//!
//! # The four things it does
//!
//! | | |
//! |---|---|
//! | [`frame`] | find where one message ends in a stream |
//! | [`parse`] | read an inbound request, notification, or batch |
//! | [`Response`] / [`batch_frame`] | build the answer to one |
//! | [`Caller`] / [`parse_answer`] | make a call, and read the answer |
//!
//! The first is needed only on a byte stream. Where the transport already
//! delimits messages, [`parse`] takes what it delivered.
//!
//! # Serving
//!
//! ```
//! use truenas_jsonrpc::{Call, ErrorObject, Incoming, Response};
//!
//! let frame = br#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
//! let reply = match truenas_jsonrpc::parse(frame) {
//!     Incoming::Single(Call::Valid(request)) => match request.id() {
//!         // §4.1: a notification must not be answered.
//!         None => None,
//!         Some(id) => Some(match request.method() {
//!             "ping" => Response::success(id.clone(), &"pong")
//!                 .expect("a string always encodes"),
//!             _ => Response::error(
//!                 id.clone(),
//!                 ErrorObject::method_not_found(),
//!             ),
//!         }),
//!     },
//!     Incoming::Single(Call::Invalid { id, error, .. }) => {
//!         Some(Response::error(id, error))
//!     }
//!     Incoming::Invalid { error, .. } => {
//!         Some(Response::error(truenas_jsonrpc::Id::Null, error))
//!     }
//!     // Answer each element, then assemble with `batch_frame`.
//!     Incoming::Batch(_) => None,
//! };
//! assert_eq!(
//!     reply.unwrap().to_bytes(),
//!     br#"{"jsonrpc":"2.0","result":"pong","id":1}"#,
//! );
//! ```
//!
//! # Calling
//!
//! ```
//! use truenas_jsonrpc::{Answer, Caller, Outcome};
//!
//! let mut caller = Caller::new();
//! let (id, frame) = caller
//!     .request("subtract", Some(&[42, 23]))
//!     .expect("a slice of integers is an Array");
//! assert_eq!(
//!     frame,
//!     br#"{"jsonrpc":"2.0","method":"subtract","params":[42,23],"id":1}"#,
//! );
//!
//! // ... the transport carries `frame` and brings back bytes ...
//! let inbound = br#"{"jsonrpc":"2.0","result":19,"id":1}"#;
//! let Answer::Single(reply) = truenas_jsonrpc::parse_answer(inbound) else {
//!     panic!("one response object");
//! };
//! // §5 requires the same id back; matching them is the caller's map.
//! assert_eq!(reply.id(), &id);
//! match reply.outcome() {
//!     Outcome::Result(raw) => assert_eq!(raw.get(), "19"),
//!     Outcome::Failure(error) => panic!("{error}"),
//! }
//! ```
//!
//! # Driving a byte-stream transport
//!
//! On a stream there is no message boundary to inherit — JSON-RPC 2.0
//! defines none — so [`frame`] finds one, and its three verdicts are what
//! a transport's framer has to answer. Against `truenas_ros`'s framer
//! contract the mapping is one for one:
//!
//! ```text
//! Frame::Complete(n) -> Framing::Complete { header_len: 0, body_len: n }
//! Frame::Incomplete  -> Framing::More / MoreInMessage
//! Frame::Invalid     -> Framing::Invalid
//! ```
//!
//! Once bytes of a message have been seen, answer `MoreInMessage` rather
//! than `More`: the two read identically, but `More` puts the connection
//! back on the idle clock and disarms its receipt budget, so a peer that
//! sends half a message and stops is then held by nothing.
//!
//! A transport that carries a length prefix needs none of this. Its own
//! prefix framer delimits the message and [`parse`] takes the body.
//!
//! This crate never buffers, so it imposes no ceiling on a message. A peer
//! can hold [`Frame::Incomplete`] open indefinitely, and the transport's
//! own limit on a buffered message is what bounds that.
//!
//! # Deliberate omissions
//!
//! No transport, no framing policy, no authentication, no session state,
//! no method registry and no dispatch. Which methods exist, what one does,
//! and how long it may run need the application; anything long-running
//! needs to own concurrency. Correlating an answer to its call is a map
//! from [`Id`] to whatever the caller wants resumed, which only the caller
//! knows.
//!
//! `params` and `result` cross the boundary as
//! [`RawValue`](serde_json::value::RawValue), so an inbound payload is
//! decoded once by whoever knows its type and an outbound one encoded once
//! by whoever built it. Neither is ever materialized as a
//! [`Value`](serde_json::Value).

#![forbid(unsafe_code)]

mod client;
mod error;
mod frame;
mod id;
mod reply;
mod request;
mod response;

pub use client::{BuildError, Caller, batch_of};
pub use error::{
    ErrorObject, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST,
    METHOD_NOT_FOUND, PARSE_ERROR, RESERVED_MAX, RESERVED_MIN,
    SERVER_ERROR_MAX, SERVER_ERROR_MIN,
};
pub use frame::{Frame, frame};
pub use id::Id;
pub use reply::{Answer, Outcome, Reply, parse_answer};
pub use request::{Call, Incoming, Params, Reason, Request, parse};
pub use response::{Response, batch_frame};

/// The value the `jsonrpc` member must carry, in a request and a response
/// alike (§4, §5).
pub const VERSION: &str = "2.0";

/// The method-name prefix §4 reserves for rpc-internal methods and
/// extensions, and §8 restates. A name carrying it is well-formed — the
/// reservation says what a name may mean, not what may be parsed — so
/// [`Request::is_reserved_method`] reports it and nothing here refuses it.
pub const RESERVED_PREFIX: &str = "rpc.";
