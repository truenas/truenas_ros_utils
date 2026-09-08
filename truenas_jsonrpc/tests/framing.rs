// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Finding where one message ends in a stream of bytes.
//!
//! JSON-RPC 2.0 defines no message boundary, so what is asserted here is
//! this crate's own decision: an Object or an Array is delimited by its
//! own braces, and nothing else can be delimited without knowing what
//! follows.

use truenas_jsonrpc::{Frame, frame};

/// A complete Object is delimited at its closing brace, and the length
/// reported is the whole of it.
#[test]
fn a_complete_object_is_delimited() {
    let buf = br#"{"jsonrpc":"2.0","method":"m","id":1}"#;
    assert_eq!(frame(buf), Frame::Complete(buf.len()));
}

/// A complete Array likewise — a batch is one message.
#[test]
fn a_complete_array_is_delimited() {
    let buf = br#"[{"jsonrpc":"2.0","method":"m","id":1}]"#;
    assert_eq!(frame(buf), Frame::Complete(buf.len()));
}

/// Every prefix of a message is incomplete, and the whole of it is
/// complete at exactly one length: the boundary is found once, not
/// approximated.
#[test]
fn every_short_prefix_is_incomplete_and_the_boundary_is_exact() {
    let buf = br#"{"jsonrpc":"2.0","params":{"a":[1,2]},"id":1}"#;
    for cut in 1..buf.len() {
        assert_eq!(frame(&buf[..cut]), Frame::Incomplete, "cut at {cut}");
    }
    assert_eq!(frame(buf), Frame::Complete(buf.len()));
}

/// Bytes after the first message are not consumed: the verdict names the
/// first message's length so the rest stays for the next call.
#[test]
fn trailing_bytes_are_left_for_the_next_message() {
    let first = br#"{"jsonrpc":"2.0","method":"a","id":1}"#;
    let mut buf = first.to_vec();
    buf.extend_from_slice(br#"{"jsonrpc":"2.0","method":"b","id":2}"#);
    assert_eq!(frame(&buf), Frame::Complete(first.len()));

    // And the remainder frames on its own.
    let rest = &buf[first.len()..];
    assert_eq!(frame(rest), Frame::Complete(rest.len()));
}

/// A brace or bracket inside a string is text, not structure. This is the
/// case a naive depth counter gets wrong.
#[test]
fn a_delimiter_inside_a_string_is_not_structure() {
    for buf in [
        br#"{"method":"}"}"#.to_vec(),
        br#"{"method":"{{{["}"#.to_vec(),
        br#"{"method":"]"}"#.to_vec(),
        br#"{"params":["}]"]}"#.to_vec(),
    ] {
        assert_eq!(frame(&buf), Frame::Complete(buf.len()), "{buf:?}");
    }
}

/// An escaped quote does not end the string, and an escaped backslash does
/// not escape the quote that follows it.
#[test]
fn escapes_inside_a_string_are_honoured() {
    let buf = br#"{"method":"a\"}\"b"}"#;
    assert_eq!(frame(buf), Frame::Complete(buf.len()));

    // The backslash is escaped, so the quote after it closes the string.
    let buf = br#"{"method":"a\\"}"#;
    assert_eq!(frame(buf), Frame::Complete(buf.len()));
}

/// Leading whitespace is skipped, and counted in the length so the caller
/// can discard exactly what was consumed.
#[test]
fn leading_whitespace_is_consumed_with_the_message() {
    let buf = b" \t\r\n{\"jsonrpc\":\"2.0\"}";
    assert_eq!(frame(buf), Frame::Complete(buf.len()));
}

/// Whitespace alone is not yet a message.
#[test]
fn whitespace_alone_is_incomplete() {
    assert_eq!(frame(b""), Frame::Incomplete);
    assert_eq!(frame(b"   "), Frame::Incomplete);
    assert_eq!(frame(b"\r\n\t "), Frame::Incomplete);
}

/// Anything that is not an Object or an Array cannot be framed. §4 makes a
/// request an Object and §6 makes a batch an Array, and those are also the
/// only shapes whose end is knowable without the next byte: a bare Number
/// has no end until a non-digit arrives.
#[test]
fn a_message_that_is_not_an_object_or_array_cannot_be_framed() {
    for buf in [
        &b"1"[..],
        b"123",
        b"null",
        b"true",
        b"\"a string\"",
        b"x",
        b",",
        b"}",
        b"]",
    ] {
        assert_eq!(frame(buf), Frame::Invalid, "{buf:?}");
    }
}

/// Nesting is tracked to any depth: the scan is iterative, so a deep
/// message is delimited rather than overflowing a stack.
#[test]
fn deep_nesting_is_delimited() {
    for depth in [1usize, 8, 1024, 100_000] {
        let buf = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(
            frame(buf.as_bytes()),
            Frame::Complete(buf.len()),
            "depth {depth}",
        );
        // One closer short is incomplete, however deep.
        let short = &buf.as_bytes()[..buf.len() - 1];
        assert_eq!(frame(short), Frame::Incomplete, "depth {depth}");
    }
}

/// Framing finds a boundary; it does not validate JSON. A mismatched pair
/// is delimited here and refused by `parse`, which has to read the bytes
/// anyway — so the check is not paid for twice.
#[test]
fn framing_delimits_without_validating() {
    let buf = br#"{"a":1]"#;
    assert_eq!(frame(buf), Frame::Complete(buf.len()));
    // And the parse that follows is what refuses it.
    assert!(matches!(
        truenas_jsonrpc::parse(buf),
        truenas_jsonrpc::Incoming::Invalid { .. },
    ));
}

/// A stream delivered one byte at a time yields each message exactly once,
/// which is the property a transport actually relies on.
#[test]
fn a_byte_at_a_time_stream_yields_each_message_once() {
    let wire = br#"{"jsonrpc":"2.0","method":"a","id":1}[{"jsonrpc":"2.0","method":"b"}]  {"jsonrpc":"2.0","method":"c","id":2}"#;
    let mut buf: Vec<u8> = Vec::new();
    let mut messages = Vec::new();
    for &byte in wire.iter() {
        buf.push(byte);
        while let Frame::Complete(n) = frame(&buf) {
            messages.push(buf[..n].to_vec());
            buf.drain(..n);
        }
    }
    assert_eq!(messages.len(), 3);
    // Every message that came out parses, and the buffer holds only
    // whitespace at the end.
    for message in &messages {
        assert!(!matches!(
            truenas_jsonrpc::parse(message),
            truenas_jsonrpc::Incoming::Invalid { .. },
        ));
    }
    assert!(buf.iter().all(u8::is_ascii_whitespace), "{buf:?}");
}
