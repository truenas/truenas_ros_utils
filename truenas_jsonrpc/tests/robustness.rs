// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Totality: every frame is classified and answered, and none panics.
//!
//! A parser reached by an unauthenticated peer must return a verdict on
//! anything. These suites do not assert *which* verdict for a hostile
//! frame — the clause-by-clause suites do that — only that one comes back
//! and that whatever comes back can be rendered.

use truenas_jsonrpc::{
    Answer, Call, Caller, ErrorObject, Frame, Id, Incoming, Response, frame,
};

/// Put a frame through every entry point the crate has, panicking
/// nowhere: the framer, the serving parse, and the calling parse.
fn drive(bytes: &[u8]) {
    // Framing must return a verdict, and a length it reports must be
    // within the buffer — a caller slices with it.
    match frame(bytes) {
        Frame::Complete(n) => {
            assert!(n <= bytes.len(), "{n} > {}", bytes.len())
        }
        Frame::Incomplete | Frame::Invalid => {}
    }

    match truenas_jsonrpc::parse(bytes) {
        Incoming::Invalid { error, reason } => {
            assert!(!reason.is_empty());
            let _ = Response::error(Id::Null, error).to_bytes();
        }
        Incoming::Single(call) => render(call),
        Incoming::Batch(calls) => {
            // A batch is never empty, which is what makes the "return
            // nothing at all" rule reachable only through notifications.
            assert!(!calls.is_empty());
            for call in calls {
                render(call);
            }
        }
    }

    // The same bytes read as an answer rather than as a call. A client is
    // reached by whatever the peer sends, so this half is exposed too.
    match truenas_jsonrpc::parse_answer(bytes) {
        Answer::Invalid(reason) => assert!(!reason.is_empty()),
        Answer::Single(reply) => {
            let _ = reply.outcome();
            let _ = reply.id().has_fractional_part();
        }
        Answer::Batch(replies) => {
            assert!(!replies.is_empty());
            for reply in replies {
                let _ = reply.outcome();
            }
        }
    }
}

fn render(call: Call<'_>) {
    match call {
        Call::Invalid { id, error, reason } => {
            assert!(!reason.is_empty());
            let _ = Response::error(id, error).to_bytes();
        }
        Call::Valid(request) => {
            // Whatever the payload, reading it must not panic either.
            if let Some(params) = request.params() {
                let _ = params.get().get().len();
                let _ = params.deserialize::<serde_json::Value>();
            }
            let _ = request.is_reserved_method();
            if let Some(id) = request.id() {
                let _ = id.has_fractional_part();
                let _ = Response::success(id.clone(), &"ok")
                    .expect("a string always encodes")
                    .to_bytes();
                let _ =
                    Response::error(id.clone(), ErrorObject::internal_error())
                        .to_bytes();
            }
        }
    }
}

/// Building a call must not panic on a hostile method name either.
#[test]
fn a_hostile_method_name_still_builds_or_refuses() {
    let mut caller = Caller::new();
    for method in [
        "",
        "rpc.internal",
        "a\"b",
        "a\\b",
        "\u{0}",
        "\u{feff}",
        &"x".repeat(1 << 16),
    ] {
        let built = caller.request::<()>(method, None);
        let frame = built.expect("a name is a String, whatever is in it");
        // Whatever went in comes back out, unchanged.
        let Incoming::Single(Call::Valid(request)) =
            truenas_jsonrpc::parse(&frame.1)
        else {
            panic!("the frame we just built must parse: {method:?}");
        };
        assert_eq!(request.method(), method);
    }
}

/// A corpus of frames that are malformed, hostile, or merely strange.
#[test]
fn every_frame_gets_a_verdict() {
    let frames: Vec<&[u8]> = vec![
        b"",
        b" ",
        b"\n\t\r ",
        b"null",
        b"true",
        b"false",
        b"0",
        b"-0",
        b"1e400",
        b"\"a string\"",
        b"{",
        b"}",
        b"[",
        b"]",
        b"[,]",
        b"{}",
        b"{\"jsonrpc\":\"2.0\"}",
        b"{\"jsonrpc\":\"2.0\",\"method\":\"m\"} trailing",
        b"{\"jsonrpc\":\"2.0\",\"method\":\"m\"}{\"jsonrpc\":\"2.0\"}",
        // A duplicate member: JSON does not define which wins.
        b"{\"jsonrpc\":\"2.0\",\"method\":\"a\",\"method\":\"b\",\"id\":1}",
        // Member names written with escapes, so they cannot be borrowed.
        b"{\"jsonrpc\":\"2.0\",\"m\\u0065thod\":\"m\",\"id\":1}",
        // A NUL inside a string, and a lone surrogate escape.
        b"{\"jsonrpc\":\"2.0\",\"method\":\"a\\u0000b\",\"id\":1}",
        b"{\"jsonrpc\":\"2.0\",\"method\":\"\\ud800\",\"id\":1}",
        // Numbers at and past the edges of the integer types.
        b"{\"jsonrpc\":\"2.0\",\"method\":\"m\",\"id\":9223372036854775807}",
        b"{\"jsonrpc\":\"2.0\",\"method\":\"m\",\"id\":9223372036854775808}",
        b"{\"jsonrpc\":\"2.0\",\"method\":\"m\",\"id\":-9223372036854775809}",
        b"{\"jsonrpc\":\"2.0\",\"method\":\"m\",\"id\":1e308}",
        // Not UTF-8, so not JSON.
        b"\xff\xfe\x00\x00",
        b"{\"jsonrpc\":\"2.0\",\"method\":\"\xff\xff\",\"id\":1}",
        // A byte-order mark, which JSON does not admit as leading content.
        b"\xef\xbb\xbf{\"jsonrpc\":\"2.0\",\"method\":\"m\",\"id\":1}",
    ];
    for frame in frames {
        drive(frame);
    }
}

/// A valid frame truncated at every byte boundary. Each prefix is either
/// refused or, by luck of the cut, valid — never a panic.
#[test]
fn every_prefix_of_a_valid_frame_gets_a_verdict() {
    let full =
        br#"{"jsonrpc":"2.0","method":"subtract","params":{"a":1},"id":"x"}"#;
    for cut in 0..=full.len() {
        drive(&full[..cut]);
    }
    let batch = br#"[{"jsonrpc":"2.0","method":"m","id":1},{"jsonrpc":"2.0","method":"n"}]"#;
    for cut in 0..=batch.len() {
        drive(&batch[..cut]);
    }
}

/// Deep nesting must be bounded rather than recursing to a stack
/// overflow, in `params` and in a batch element alike.
#[test]
fn deep_nesting_is_bounded() {
    for depth in [8usize, 64, 256, 4096, 100_000] {
        let deep = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let frame = format!(
            r#"{{"jsonrpc":"2.0","method":"m","params":{deep},"id":1}}"#
        );
        drive(frame.as_bytes());

        // The same depth reached through the batch path.
        drive(format!("[{frame}]").as_bytes());
    }
}

/// A batch of many elements is classified without recursing per element.
#[test]
fn a_wide_batch_gets_a_verdict() {
    let element = r#"{"jsonrpc":"2.0","method":"m","id":1}"#;
    let wide = format!("[{}]", [element; 2000].join(","));
    drive(wide.as_bytes());
}

/// A long string is carried, not truncated and not rejected for length:
/// neither §4 nor §4.2 sets a size, so a bound belongs to the framing
/// layer above, where it can be enforced before the bytes are buffered.
#[test]
fn a_long_payload_is_carried() {
    let big = "x".repeat(1 << 20);
    let frame = format!(
        r#"{{"jsonrpc":"2.0","method":"m","params":["{big}"],"id":1}}"#
    );
    match truenas_jsonrpc::parse(frame.as_bytes()) {
        Incoming::Single(Call::Valid(request)) => {
            let args: Vec<String> =
                request.params().unwrap().deserialize().unwrap();
            assert_eq!(args[0].len(), 1 << 20);
        }
        other => panic!("expected a valid request, got {other:?}"),
    }
}
