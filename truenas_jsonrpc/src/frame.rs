// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Finding where one message ends in a stream of bytes.
//!
//! JSON-RPC 2.0 defines no message boundary, so a stream transport has to
//! find one. Where the transport already delimits messages — a length
//! prefix, a datagram — this module is not needed and
//! [`parse`](crate::parse) takes the delivered bytes directly.

/// Where the first message in a buffer ends.
///
/// The three verdicts are what a byte-stream transport needs to be told,
/// and nothing more: read on, here is a message, or this cannot be one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Frame {
    /// A complete value occupies the first `n` bytes of the buffer,
    /// leading whitespace included. Hand `buf[..n]` to
    /// [`parse`](crate::parse) and keep `buf[n..]` for the next message.
    Complete(usize),
    /// No complete value yet. Read more and ask again.
    ///
    /// A peer can hold this state open by sending an unterminated value
    /// forever, so the transport's own ceiling on a buffered message is
    /// what bounds it. This layer never allocates, so it has no ceiling of
    /// its own to apply.
    Incomplete,
    /// The bytes cannot begin a message: the first non-whitespace byte is
    /// neither `{` nor `[`.
    ///
    /// §4 makes a request an Object and §6 makes a batch an Array, so those
    /// two are the only shapes a frame can take — and, being brace- and
    /// bracket-delimited, the only shapes whose end can be found without
    /// knowing what follows. A bare Number has no end until something that
    /// is not a digit arrives, which on a stream may be the next message or
    /// may be nothing yet.
    Invalid,
}

/// Find the end of the first message in `buf`.
///
/// Scanning is structural: brace and bracket depth, with string contents
/// and backslash escapes skipped so a delimiter inside a string does not
/// count. It does not validate the JSON — matching `{` against `]` is left
/// to [`parse`](crate::parse), which has to parse the bytes anyway. What
/// this decides is only where to cut.
///
/// # Driving a `truenas_ros` connection
///
/// The verdicts map onto that crate's framer contract one for one, so the
/// adapter is the whole of the integration:
///
/// ```text
/// Frame::Complete(n) -> Framing::Complete { header_len: 0, body_len: n }
/// Frame::Incomplete  -> Framing::More        (or MoreInMessage, once
///                                             bytes of this message have
///                                             already been seen)
/// Frame::Invalid     -> Framing::Invalid
/// ```
///
/// Answering `More` rather than `MoreInMessage` mid-message costs the
/// connection its request and receipt clocks, so a framer that has already
/// seen part of a message must say so.
///
/// A transport carrying a length prefix does not need this at all: its own
/// prefix framer delimits the message and `parse` takes the body.
pub fn frame(buf: &[u8]) -> Frame {
    let mut i = 0;
    while i < buf.len() && is_ws(buf[i]) {
        i += 1;
    }
    if i == buf.len() {
        return Frame::Incomplete;
    }
    if !matches!(buf[i], b'{' | b'[') {
        return Frame::Invalid;
    }

    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (at, &byte) in buf.iter().enumerate().skip(i) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                // The scan starts on `{` or `[`, so depth is at least one
                // by the time any closer is seen and cannot underflow.
                depth -= 1;
                if depth == 0 {
                    return Frame::Complete(at + 1);
                }
            }
            _ => {}
        }
    }
    Frame::Incomplete
}

/// The four bytes JSON counts as whitespace between tokens.
fn is_ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}
