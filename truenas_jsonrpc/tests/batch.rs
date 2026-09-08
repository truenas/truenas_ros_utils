// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! §6 Batch, and the §7 examples that exercise it.
//!
//! Every expected value is written out from the document.

use truenas_jsonrpc::{
    Call, ErrorObject, INVALID_REQUEST, Id, Incoming, PARSE_ERROR, Response,
    batch_frame,
};

fn parse(frame: &str) -> Incoming<'_> {
    truenas_jsonrpc::parse(frame.as_bytes())
}

/// The calls a batch frame held.
fn calls(frame: &str) -> Vec<Call<'_>> {
    match parse(frame) {
        Incoming::Batch(calls) => calls,
        other => panic!("expected a batch, got {other:?}"),
    }
}

/// As in the conformance suite: the document prints its examples with
/// whitespace JSON gives no meaning, so the comparison is on parsed values.
fn same_json(ours: &[u8], from_the_spec: &str) {
    let ours: serde_json::Value =
        serde_json::from_slice(ours).expect("our own frame must be JSON");
    let theirs: serde_json::Value = serde_json::from_str(from_the_spec)
        .expect("the specification's frame must be JSON");
    assert_eq!(ours, theirs);
}

/// §6: a batch is an Array of Request objects, and each is judged on its
/// own — one refusal does not condemn its neighbours.
#[test]
fn a_batch_judges_every_element_separately() {
    let calls = calls(
        r#"[{"jsonrpc":"2.0","method":"a","id":1},
             {"nope":true},
             {"jsonrpc":"2.0","method":"b","id":2}]"#,
    );
    assert_eq!(calls.len(), 3);
    assert!(matches!(calls[0], Call::Valid(_)));
    assert!(matches!(calls[1], Call::Invalid { .. }));
    assert!(matches!(calls[2], Call::Valid(_)));
}

/// §4.1: the server MUST NOT reply to a notification, those within a batch
/// included. §6: with no responses to send, it must not return an empty
/// Array and should return nothing at all.
#[test]
fn a_batch_of_only_notifications_is_answered_with_nothing() {
    let calls = calls(
        r#"[{"jsonrpc":"2.0","method":"notify_sum","params":[1,2,4]},
             {"jsonrpc":"2.0","method":"notify_hello","params":[7]}]"#,
    );
    assert_eq!(calls.len(), 2);
    for call in &calls {
        let Call::Valid(request) = call else {
            panic!("both elements are valid notifications");
        };
        assert!(request.is_notification());
    }
    // Nothing was answerable, so there is no frame to send.
    assert_eq!(batch_frame(&[]), None);
}

/// §6: if the batch call itself fails to be recognized as valid JSON or as
/// an Array with at least one value, the response MUST be a single
/// Response object — not an Array of one.
#[test]
fn an_unrecognizable_batch_is_answered_with_one_response_object() {
    // Not valid JSON.
    let Incoming::Invalid { error, .. } =
        parse(r#"[{"jsonrpc":"2.0","method"]"#)
    else {
        panic!("expected a single refusal");
    };
    assert_eq!(error.code(), PARSE_ERROR);

    // An Array, but without at least one value.
    let Incoming::Invalid { error, .. } = parse("[]") else {
        panic!("expected a single refusal");
    };
    assert_eq!(error.code(), INVALID_REQUEST);
}

/// §6: `batch_frame` renders the Array. A batch that produced responses is
/// answered with them; one that produced none is answered with nothing.
#[test]
fn the_batch_frame_is_an_array_and_never_an_empty_one() {
    let one = [Response::success(Id::from_i64(1), &7).unwrap()];
    same_json(
        &batch_frame(&one).expect("one response"),
        r#"[{"jsonrpc":"2.0","result":7,"id":1}]"#,
    );
    assert_eq!(batch_frame(&[]), None);
}

// --- §7 Examples -----------------------------------------------------

/// §7, "rpc call Batch, invalid JSON".
#[test]
fn spec_example_batch_invalid_json() {
    let frame = r#"[
  {"jsonrpc": "2.0", "method": "sum", "params": [1,2,4], "id": "1"},
  {"jsonrpc": "2.0", "method"
]"#;
    let Incoming::Invalid { error, .. } = parse(frame) else {
        panic!("expected a single refusal");
    };
    assert_eq!(error.code(), PARSE_ERROR);
    same_json(
        &Response::error(Id::Null, ErrorObject::parse_error()).to_bytes(),
        r#"{"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": null}"#,
    );
}

/// §7, "rpc call with an empty Array".
#[test]
fn spec_example_empty_array() {
    let Incoming::Invalid { error, .. } = parse("[]") else {
        panic!("expected a single refusal, not an Array of one");
    };
    assert_eq!(error.code(), INVALID_REQUEST);
    same_json(
        &Response::error(Id::Null, ErrorObject::invalid_request()).to_bytes(),
        r#"{"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}"#,
    );
}

/// §7, "rpc call with an invalid Batch (but not empty)" — `[1]`. One value
/// is enough to be a batch, so the answer is an Array of one refusal, not
/// a lone Response object.
#[test]
fn spec_example_invalid_but_not_empty_batch() {
    let calls = calls("[1]");
    assert_eq!(calls.len(), 1);
    let Call::Invalid { id, error, .. } = &calls[0] else {
        panic!("a Number is not a Request object");
    };
    assert_eq!(error.code(), INVALID_REQUEST);
    assert_eq!(id, &Id::Null);

    let answers = [Response::error(Id::Null, ErrorObject::invalid_request())];
    same_json(
        &batch_frame(&answers).expect("one refusal"),
        r#"[{"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}]"#,
    );
}

/// §7, "rpc call with invalid Batch" — `[1,2,3]` answers three refusals.
#[test]
fn spec_example_invalid_batch_of_three() {
    let calls = calls("[1,2,3]");
    assert_eq!(calls.len(), 3);
    let mut answers = Vec::new();
    for call in &calls {
        let Call::Invalid { id, error, .. } = call else {
            panic!("a Number is not a Request object");
        };
        assert_eq!(error.code(), INVALID_REQUEST);
        answers.push(Response::error(id.clone(), error.clone()));
    }
    same_json(
        &batch_frame(&answers).expect("three refusals"),
        r#"[
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null},
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null},
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}
    ]"#,
    );
}

/// §7, "rpc call Batch" — the mixed batch, driven end to end.
///
/// Six elements in, five responses out: the notification contributes none,
/// the member-less Object is refused against a Null id, and the rest are
/// answered with exactly the results the document prints.
#[test]
fn spec_example_mixed_batch() {
    let frame = r#"[
        {"jsonrpc": "2.0", "method": "sum", "params": [1,2,4], "id": "1"},
        {"jsonrpc": "2.0", "method": "notify_hello", "params": [7]},
        {"jsonrpc": "2.0", "method": "subtract", "params": [42,23], "id": "2"},
        {"foo": "boo"},
        {"jsonrpc": "2.0", "method": "foo.get", "params": {"name": "myself"}, "id": "5"},
        {"jsonrpc": "2.0", "method": "get_data", "id": "9"}
    ]"#;
    let calls = calls(frame);
    assert_eq!(calls.len(), 6);

    // The methods the document's server knows, and what it answers.
    let mut answers = Vec::new();
    for call in &calls {
        match call {
            Call::Invalid { id, error, .. } => {
                answers.push(Response::error(id.clone(), error.clone()));
            }
            Call::Valid(request) => {
                let Some(id) = request.id().cloned() else {
                    // §4.1: notify_hello is answered with nothing at all.
                    assert_eq!(request.method(), "notify_hello");
                    continue;
                };
                let answer = match request.method() {
                    "sum" => {
                        let args: Vec<i64> =
                            request.params().unwrap().deserialize().unwrap();
                        Response::success(id, &args.iter().sum::<i64>())
                            .unwrap()
                    }
                    "subtract" => {
                        let args: Vec<i64> =
                            request.params().unwrap().deserialize().unwrap();
                        Response::success(id, &(args[0] - args[1])).unwrap()
                    }
                    "get_data" => Response::success(
                        id,
                        &(serde_json::json!(["hello", 5])),
                    )
                    .unwrap(),
                    // The document's server does not have this one.
                    "foo.get" => {
                        Response::error(id, ErrorObject::method_not_found())
                    }
                    other => panic!("unexpected method {other:?}"),
                };
                answers.push(answer);
            }
        }
    }
    assert_eq!(answers.len(), 5);
    same_json(
        &batch_frame(&answers).expect("five responses"),
        r#"[
        {"jsonrpc": "2.0", "result": 7, "id": "1"},
        {"jsonrpc": "2.0", "result": 19, "id": "2"},
        {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null},
        {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "5"},
        {"jsonrpc": "2.0", "result": ["hello", 5], "id": "9"}
    ]"#,
    );
}
