// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The client's half: building §4's Request object, and reading §5's
//! Response object.
//!
//! Every expected value is written out from the specification.

use truenas_jsonrpc::{
    Answer, BuildError, Call, Caller, ErrorObject, Id, Incoming, Outcome,
    batch_of, parse_answer,
};

// --- §4: building a request ------------------------------------------

/// §4: the members of a Request object, in the order §7 prints them.
#[test]
fn a_request_carries_the_version_method_params_and_id() {
    let mut caller = Caller::new();
    let (id, frame) = caller
        .request("subtract", Some(&[42, 23]))
        .expect("a slice of integers encodes to an Array");
    assert_eq!(id, Id::from_i64(1));
    assert_eq!(
        frame,
        br#"{"jsonrpc":"2.0","method":"subtract","params":[42,23],"id":1}"#,
    );
}

/// §4: `params` MAY be omitted, and omitting it is not the same as sending
/// an empty structure.
#[test]
fn a_request_may_carry_no_params() {
    let mut caller = Caller::new();
    let (_, frame) = caller
        .request::<()>("get_data", None)
        .expect("no params to encode");
    assert_eq!(frame, br#"{"jsonrpc":"2.0","method":"get_data","id":1}"#);

    let (_, frame) = caller
        .request("get_data", Some(&Vec::<i32>::new()))
        .expect("an empty Array still encodes");
    assert_eq!(
        frame,
        br#"{"jsonrpc":"2.0","method":"get_data","params":[],"id":2}"#,
    );
}

/// §4.1: a notification is a request with no `id` member.
#[test]
fn a_notification_carries_no_id() {
    let caller = Caller::new();
    let frame = caller
        .notification("update", Some(&[1, 2, 3, 4, 5]))
        .expect("encodes");
    assert_eq!(
        frame,
        br#"{"jsonrpc":"2.0","method":"update","params":[1,2,3,4,5]}"#,
    );
    // And it is read back as a notification, not as a request.
    let Incoming::Single(Call::Valid(request)) = truenas_jsonrpc::parse(&frame)
    else {
        panic!("a valid notification");
    };
    assert!(request.is_notification());
}

/// §4.1: a notification mints nothing, so it cannot consume an id and
/// leave a gap that looks like a lost call.
#[test]
fn a_notification_does_not_consume_an_id() {
    let mut caller = Caller::new();
    let _ = caller.notification::<()>("a", None).expect("encodes");
    let (id, _) = caller.request::<()>("b", None).expect("encodes");
    assert_eq!(id, Id::from_i64(1));
}

/// Ids count up, so no two outstanding calls collide.
#[test]
fn ids_are_minted_in_sequence() {
    let mut caller = Caller::new();
    let mut seen = Vec::new();
    for _ in 0..5 {
        let (id, _) = caller.request::<()>("m", None).expect("encodes");
        seen.push(id);
    }
    let expected: Vec<Id> = (1..=5).map(Id::from_i64).collect();
    assert_eq!(seen, expected);
    assert_eq!(caller.peek_id(), Id::from_i64(6));
}

/// §4.2: parameters MUST be an Array or an Object, so a scalar is refused
/// here rather than sent for the peer to refuse.
#[test]
fn params_that_are_not_structured_are_refused_before_the_wire() {
    let mut caller = Caller::new();
    for attempt in [
        caller.request("m", Some(&7)).err(),
        caller.request("m", Some("a string")).err(),
        caller.request("m", Some(&true)).err(),
        caller.request::<Option<i32>>("m", Some(&None)).err(),
    ] {
        assert!(
            matches!(attempt, Some(BuildError::ParamsNotStructured)),
            "{attempt:?}",
        );
    }
    // A refused build must not have consumed an id.
    assert_eq!(caller.peek_id(), Id::from_i64(1));
}

/// §4 admits a String or Null id as well as a Number, and a caller that
/// has its own scheme can use one.
#[test]
fn a_caller_may_supply_its_own_id() {
    let caller = Caller::new();
    let frame = caller
        .request_with_id::<()>(Id::from_string("abc"), "m", None)
        .expect("encodes");
    assert_eq!(frame, br#"{"jsonrpc":"2.0","method":"m","id":"abc"}"#);

    let frame = caller
        .request_with_id::<()>(Id::Null, "m", None)
        .expect("encodes");
    assert_eq!(frame, br#"{"jsonrpc":"2.0","method":"m","id":null}"#);
}

/// A method name is written as JSON, so one carrying a quote or a
/// backslash is escaped rather than breaking the frame.
#[test]
fn a_method_name_is_escaped() {
    let caller = Caller::new();
    let frame = caller
        .request_with_id::<()>(Id::from_i64(1), r#"a"b\c"#, None)
        .expect("encodes");
    assert_eq!(frame, br#"{"jsonrpc":"2.0","method":"a\"b\\c","id":1}"#,);
    // And it survives the round trip unchanged.
    let Incoming::Single(Call::Valid(request)) = truenas_jsonrpc::parse(&frame)
    else {
        panic!("a valid request");
    };
    assert_eq!(request.method(), r#"a"b\c"#);
}

/// §6: several calls travel as one Array, and there is no empty batch to
/// send.
#[test]
fn calls_batch_into_one_array() {
    let mut caller = Caller::new();
    let (_, one) = caller.request("sum", Some(&[1, 2, 4])).expect("encodes");
    let two = caller.notification("notify_hello", Some(&[7])).expect("ok");
    let frame = batch_of(&[one, two]).expect("two calls");
    assert_eq!(
        frame,
        &br#"[{"jsonrpc":"2.0","method":"sum","params":[1,2,4],"id":1},{"jsonrpc":"2.0","method":"notify_hello","params":[7]}]"#[..],
    );
    assert_eq!(batch_of(&[]), None);

    // The peer reads it as a two-element batch.
    let Incoming::Batch(calls) = truenas_jsonrpc::parse(&frame) else {
        panic!("a batch");
    };
    assert_eq!(calls.len(), 2);
}

// --- §5: reading a response ------------------------------------------

/// §5: a response carries the version, one of result and error, and the
/// id it answers.
#[test]
fn a_success_response_is_read() {
    let Answer::Single(reply) =
        parse_answer(br#"{"jsonrpc":"2.0","result":19,"id":1}"#)
    else {
        panic!("one response object");
    };
    assert_eq!(reply.id(), &Id::from_i64(1));
    assert!(reply.is_success());
    match reply.outcome() {
        Outcome::Result(raw) => assert_eq!(raw.get(), "19"),
        Outcome::Failure(e) => panic!("{e}"),
    }
}

/// §5.1: an error response carries the code, the message, and optionally
/// `data`.
#[test]
fn an_error_response_is_read() {
    let frame = br#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":"1"}"#;
    let Answer::Single(reply) = parse_answer(frame) else {
        panic!("one response object");
    };
    assert_eq!(reply.id(), &Id::from_string("1"));
    assert!(!reply.is_success());
    let error = reply.error().expect("an error");
    assert_eq!(error.code(), -32601);
    assert_eq!(error.message(), "Method not found");
    assert!(error.data().is_none());

    let frame = br#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params","data":{"missing":"minuend"}},"id":1}"#;
    let Answer::Single(reply) = parse_answer(frame) else {
        panic!("one response object");
    };
    let error = reply.error().expect("an error");
    assert_eq!(
        error.data().and_then(|d| d.get("missing")),
        Some(&serde_json::Value::String("minuend".into())),
    );
}

/// §5: either result or error MUST be included, and both MUST NOT be.
#[test]
fn a_response_carrying_both_or_neither_is_refused() {
    for frame in [
        &br#"{"jsonrpc":"2.0","result":1,"error":{"code":-1,"message":"m"},"id":1}"#[..],
        b"{\"jsonrpc\":\"2.0\",\"id\":1}",
    ] {
        assert!(matches!(parse_answer(frame), Answer::Invalid(_)), "{frame:?}");
    }
}

/// §5: the id member is REQUIRED in a response — unlike a request, where
/// its absence means a notification.
#[test]
fn a_response_without_an_id_is_refused() {
    let frame = br#"{"jsonrpc":"2.0","result":1}"#;
    assert!(matches!(parse_answer(frame), Answer::Invalid(_)));
}

/// §5: a response whose id the server could not determine carries Null,
/// and that is a legitimate answer a client must be able to read.
#[test]
fn a_null_id_response_is_read() {
    let frame = br#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}"#;
    let Answer::Single(reply) = parse_answer(frame) else {
        panic!("one response object");
    };
    assert_eq!(reply.id(), &Id::Null);
}

/// §4/§5: `jsonrpc` MUST be exactly "2.0" in a response too.
#[test]
fn a_response_with_the_wrong_version_is_refused() {
    for frame in [
        &br#"{"jsonrpc":"1.0","result":1,"id":1}"#[..],
        br#"{"result":1,"id":1}"#,
        br#"{"jsonrpc":2.0,"result":1,"id":1}"#,
    ] {
        assert!(
            matches!(parse_answer(frame), Answer::Invalid(_)),
            "{frame:?}"
        );
    }
}

/// §5.1: the code MUST be an integer Number and the message a String.
#[test]
fn a_malformed_error_object_is_refused() {
    for frame in [
        &br#"{"jsonrpc":"2.0","error":{"code":"-32601","message":"m"},"id":1}"#
            [..],
        br#"{"jsonrpc":"2.0","error":{"code":-32601.5,"message":"m"},"id":1}"#,
        br#"{"jsonrpc":"2.0","error":{"message":"m"},"id":1}"#,
        br#"{"jsonrpc":"2.0","error":{"code":-32601},"id":1}"#,
        br#"{"jsonrpc":"2.0","error":{"code":-32601,"message":7},"id":1}"#,
        br#"{"jsonrpc":"2.0","error":"Method not found","id":1}"#,
    ] {
        assert!(
            matches!(parse_answer(frame), Answer::Invalid(_)),
            "{frame:?}"
        );
    }
}

/// §6: a batch is answered with an Array, whose elements may arrive in any
/// order — so a client matches them by id, not by position.
#[test]
fn a_batch_answer_is_read_and_matched_by_id() {
    let frame = br#"[{"jsonrpc":"2.0","result":19,"id":"2"},{"jsonrpc":"2.0","result":7,"id":"1"}]"#;
    let Answer::Batch(replies) = parse_answer(frame) else {
        panic!("a batch answer");
    };
    assert_eq!(replies.len(), 2);
    // Position does not carry the correspondence; the id does.
    assert_eq!(replies[0].id(), &Id::from_string("2"));
    assert_eq!(replies[1].id(), &Id::from_string("1"));
    let found = replies
        .iter()
        .find(|r| r.id() == &Id::from_string("1"))
        .expect("the reply to call 1");
    assert_eq!(found.result().map(|r| r.get()), Some("7"));
}

/// §6: a server must never send an empty Array, so one is refused rather
/// than reported as a batch of nothing.
#[test]
fn an_empty_batch_answer_is_refused() {
    assert!(matches!(parse_answer(b"[]"), Answer::Invalid(_)));
}

/// A frame that is not a response at all is reported, not answered: a
/// client has nothing to send back.
#[test]
fn a_frame_that_is_not_a_response_is_reported() {
    for frame in [
        &b"not json"[..],
        b"null",
        b"7",
        b"\"a string\"",
        b"{",
        b"[1,2]",
    ] {
        assert!(
            matches!(parse_answer(frame), Answer::Invalid(_)),
            "{frame:?}"
        );
    }
}

// --- the round trip --------------------------------------------------

/// One call, served and answered, through nothing but this crate: the two
/// halves have to agree on the wire even though neither shares code with
/// the other.
#[test]
fn a_call_survives_the_round_trip() {
    let mut caller = Caller::new();
    let (id, outbound) = caller
        .request("subtract", Some(&[42, 23]))
        .expect("encodes");

    // The serving half reads it.
    let Incoming::Single(Call::Valid(request)) =
        truenas_jsonrpc::parse(&outbound)
    else {
        panic!("a valid request");
    };
    assert_eq!(request.method(), "subtract");
    let args: Vec<i64> = request
        .params()
        .expect("params present")
        .deserialize()
        .expect("an Array of integers");
    let answer = args[0] - args[1];

    // ... answers it ...
    let inbound = truenas_jsonrpc::Response::success(
        request.id().unwrap().clone(),
        &answer,
    )
    .expect("encodes")
    .to_bytes();

    // ... and the calling half reads that.
    let Answer::Single(reply) = parse_answer(&inbound) else {
        panic!("one response object");
    };
    assert_eq!(reply.id(), &id);
    assert_eq!(
        reply.result().expect("a result").get().parse::<i64>().ok(),
        Some(19),
    );
}

/// An error travels back intact: the code, the message and the data a
/// server chose all arrive as they were sent.
#[test]
fn an_error_survives_the_round_trip() {
    let sent =
        ErrorObject::invalid_params().with_reason("'minuend' is required");
    let inbound =
        truenas_jsonrpc::Response::error(Id::from_i64(4), sent.clone())
            .to_bytes();
    let Answer::Single(reply) = parse_answer(&inbound) else {
        panic!("one response object");
    };
    let got = reply.error().expect("an error");
    assert_eq!(got.code(), sent.code());
    assert_eq!(got.message(), sent.message());
    assert_eq!(got.data(), sent.data());
}
