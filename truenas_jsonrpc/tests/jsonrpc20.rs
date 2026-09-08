// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! JSON-RPC 2.0, clause by clause, and every worked example from its §7.
//!
//! Each case names the section it comes from, and every expected value is
//! written out from the document rather than captured from a run.

use truenas_jsonrpc::{
    Call, ErrorObject, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, Id,
    Incoming, METHOD_NOT_FOUND, PARSE_ERROR, RESERVED_MAX, RESERVED_MIN,
    Request, Response, SERVER_ERROR_MAX, SERVER_ERROR_MIN,
};

/// Parse one frame.
fn parse(frame: &str) -> Incoming<'_> {
    truenas_jsonrpc::parse(frame.as_bytes())
}

/// The single valid request a frame held, or a panic naming what came out
/// instead.
fn valid(frame: &str) -> Request<'_> {
    match parse(frame) {
        Incoming::Single(Call::Valid(r)) => r,
        other => panic!("expected one valid request, got {other:?}"),
    }
}

/// The refusal a frame earned: its code, and the id it is answered
/// against.
fn refused(frame: &str) -> (i64, Id) {
    match parse(frame) {
        Incoming::Single(Call::Invalid { id, error, .. }) => (error.code(), id),
        Incoming::Invalid { error, .. } => (error.code(), Id::Null),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Assert a frame this crate produced says the same thing as one written
/// out in the specification.
///
/// The document prints its examples with a space after every `:` and `,`.
/// JSON gives whitespace between tokens no meaning, so the comparison is
/// made on the parsed values; member order is asserted separately, against
/// bytes, by the tests that care about it.
fn same_json(ours: &[u8], from_the_spec: &str) {
    let ours: serde_json::Value =
        serde_json::from_slice(ours).expect("our own frame must be JSON");
    let theirs: serde_json::Value = serde_json::from_str(from_the_spec)
        .expect("the specification's frame must be JSON");
    assert_eq!(ours, theirs);
}

// --- §3 Compatibility ------------------------------------------------

/// §3: 2.0 always carries a `jsonrpc` member of `"2.0"` and 1.0 does not,
/// which is how the versions are told apart. A 1.0-shaped request is not a
/// valid 2.0 Request object.
#[test]
fn a_request_without_the_version_member_is_not_2_0() {
    let (code, _) = refused(r#"{"method":"subtract","params":[42,23],"id":1}"#);
    assert_eq!(code, INVALID_REQUEST);
}

// --- §4 Request object -----------------------------------------------

/// §4: `jsonrpc` MUST be exactly `"2.0"` — not another version, not the
/// Number 2.0, not absent.
#[test]
fn the_version_member_must_be_exactly_the_string_2_0() {
    for frame in [
        r#"{"jsonrpc":"1.0","method":"m","id":1}"#,
        r#"{"jsonrpc":"2","method":"m","id":1}"#,
        r#"{"jsonrpc":"2.0.0","method":"m","id":1}"#,
        r#"{"jsonrpc":2.0,"method":"m","id":1}"#,
        r#"{"jsonrpc":null,"method":"m","id":1}"#,
        r#"{"method":"m","id":1}"#,
    ] {
        let (code, id) = refused(frame);
        assert_eq!(code, INVALID_REQUEST, "{frame}");
        // §5: the id was readable, so the refusal is answered against it.
        assert_eq!(id, Id::from_i64(1), "{frame}");
    }
    assert!(
        valid(r#"{"jsonrpc":"2.0","method":"m","id":1}"#)
            .id()
            .is_some()
    );
}

/// §4: `method` MUST be a String.
#[test]
fn the_method_member_must_be_a_string() {
    for frame in [
        r#"{"jsonrpc":"2.0","method":1,"id":1}"#,
        r#"{"jsonrpc":"2.0","method":null,"id":1}"#,
        r#"{"jsonrpc":"2.0","method":["m"],"id":1}"#,
        r#"{"jsonrpc":"2.0","method":{"name":"m"},"id":1}"#,
        r#"{"jsonrpc":"2.0","id":1}"#,
    ] {
        assert_eq!(refused(frame).0, INVALID_REQUEST, "{frame}");
    }
}

/// §4 names the method a String and sets no minimum length, so an empty
/// name is a well-formed request for a method that does not exist. §5.1
/// has a code for that, and it is not the envelope's.
#[test]
fn an_empty_method_name_parses_and_is_the_callers_to_refuse() {
    let request = valid(r#"{"jsonrpc":"2.0","method":"","id":1}"#);
    assert_eq!(request.method(), "");
}

/// §4: member names considered for matching are case-sensitive (§2), so a
/// method name differing only in case is a different method and the
/// envelope carries it through unchanged.
#[test]
fn a_method_name_is_carried_case_sensitively() {
    assert_eq!(
        valid(r#"{"jsonrpc":"2.0","method":"Subtract","id":1}"#).method(),
        "Subtract",
    );
}

/// §4: an `id`, when included, MUST be a String, a Number, or Null.
#[test]
fn an_id_may_be_a_string_a_number_or_null() {
    let string = valid(r#"{"jsonrpc":"2.0","method":"m","id":"abc"}"#);
    assert_eq!(string.id(), Some(&Id::from_string("abc")));

    let number = valid(r#"{"jsonrpc":"2.0","method":"m","id":42}"#);
    assert_eq!(number.id(), Some(&Id::from_i64(42)));

    let negative = valid(r#"{"jsonrpc":"2.0","method":"m","id":-7}"#);
    assert_eq!(negative.id(), Some(&Id::from_i64(-7)));

    // §4 discourages a null id but admits it, and it is distinct from an
    // absent one: this is a request, not a notification.
    let null = valid(r#"{"jsonrpc":"2.0","method":"m","id":null}"#);
    assert_eq!(null.id(), Some(&Id::Null));
    assert!(!null.is_notification());
}

/// §4 admits three types for an id and no others, so a Boolean, an Array,
/// and an Object are each refused — and, the id being unreadable, §5 says
/// the refusal is answered against Null.
#[test]
fn an_id_of_any_other_type_is_refused_against_a_null_id() {
    for frame in [
        r#"{"jsonrpc":"2.0","method":"m","id":true}"#,
        r#"{"jsonrpc":"2.0","method":"m","id":false}"#,
        r#"{"jsonrpc":"2.0","method":"m","id":[1]}"#,
        r#"{"jsonrpc":"2.0","method":"m","id":{"n":1}}"#,
    ] {
        let (code, id) = refused(frame);
        assert_eq!(code, INVALID_REQUEST, "{frame}");
        assert_eq!(id, Id::Null, "{frame}");
    }
}

/// §4 says a Number id SHOULD NOT carry a fractional part, which is advice
/// to the client and not a rule the server enforces. It is carried, and
/// reported, so a server that wants to object can.
#[test]
fn a_fractional_number_id_is_carried_and_reported() {
    let request = valid(r#"{"jsonrpc":"2.0","method":"m","id":1.5}"#);
    let id = request.id().expect("a request, not a notification");
    assert!(id.has_fractional_part());
    assert!(!Id::from_i64(1).has_fractional_part());
}

/// §5: the response MUST carry the same id value as the request. A Number
/// id is therefore echoed as it was written, not narrowed to an integer.
#[test]
fn a_number_id_is_echoed_exactly_as_written() {
    let request = valid(r#"{"jsonrpc":"2.0","method":"m","id":1.0}"#);
    let id = request.id().expect("a request").clone();
    let reply = Response::success(id, &"ok").expect("encode");
    assert_eq!(
        reply.to_bytes(),
        br#"{"jsonrpc":"2.0","result":"ok","id":1.0}"#,
    );
}

/// §4: a member the document does not define is not forbidden, so it is
/// ignored rather than making the request invalid.
#[test]
fn an_unknown_member_is_ignored() {
    let request =
        valid(r#"{"jsonrpc":"2.0","method":"m","id":1,"extra":{"a":1}}"#);
    assert_eq!(request.method(), "m");
}

// --- §4.1 Notification -----------------------------------------------

/// §4.1: a Notification is a Request object without an `id` member.
#[test]
fn a_request_without_an_id_member_is_a_notification() {
    let notification = valid(r#"{"jsonrpc":"2.0","method":"update"}"#);
    assert!(notification.is_notification());
    assert_eq!(notification.id(), None);
}

// --- §4.2 Parameter Structures ---------------------------------------

/// §4.2: by-position parameters MUST be an Array, by-name MUST be an
/// Object, and the two are distinguishable.
#[test]
fn params_are_by_position_in_an_array_and_by_name_in_an_object() {
    let positional =
        valid(r#"{"jsonrpc":"2.0","method":"m","params":[42,23],"id":1}"#);
    let params = positional.params().expect("params present");
    assert!(params.is_positional());
    assert_eq!(params.get().get(), "[42,23]");
    assert_eq!(params.deserialize::<Vec<i32>>().unwrap(), vec![42, 23]);

    let named =
        valid(r#"{"jsonrpc":"2.0","method":"m","params":{"a":1},"id":1}"#);
    let params = named.params().expect("params present");
    assert!(params.is_named());
    assert_eq!(params.get().get(), r#"{"a":1}"#);
}

/// §4: `params` MAY be omitted, which is distinct from an empty structure.
#[test]
fn params_may_be_omitted() {
    assert!(
        valid(r#"{"jsonrpc":"2.0","method":"m","id":1}"#)
            .params()
            .is_none()
    );

    let empty = valid(r#"{"jsonrpc":"2.0","method":"m","params":[],"id":1}"#);
    assert!(empty.params().is_some());
}

/// §4.2: parameters MUST be provided as a Structured value. A scalar is
/// not one, `null` included — the member is left out to mean "none".
#[test]
fn params_of_a_primitive_type_are_refused() {
    for frame in [
        r#"{"jsonrpc":"2.0","method":"m","params":"bar","id":1}"#,
        r#"{"jsonrpc":"2.0","method":"m","params":7,"id":1}"#,
        r#"{"jsonrpc":"2.0","method":"m","params":true,"id":1}"#,
        r#"{"jsonrpc":"2.0","method":"m","params":null,"id":1}"#,
    ] {
        assert_eq!(refused(frame).0, INVALID_REQUEST, "{frame}");
    }
}

// --- §5 Response object ----------------------------------------------

/// §5: a successful response carries `jsonrpc`, `result`, and the id.
#[test]
fn a_success_response_carries_result_and_the_id() {
    let reply = Response::success(Id::from_i64(1), &19).expect("encode");
    assert!(reply.is_success());
    assert_eq!(reply.result().map(|r| r.get()), Some("19"));
    assert!(reply.error_object().is_none());
    assert_eq!(reply.to_bytes(), br#"{"jsonrpc":"2.0","result":19,"id":1}"#);
}

/// §5: a failed response carries `jsonrpc`, `error`, and the id. `data` is
/// omitted when there is none, rather than written as `null`.
#[test]
fn an_error_response_carries_error_and_the_id() {
    let reply =
        Response::error(Id::from_string("1"), ErrorObject::method_not_found());
    assert!(!reply.is_success());
    assert!(reply.result().is_none());
    assert_eq!(
        reply.to_bytes(),
        br#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":"1"}"#,
    );
}

/// §5.1: `data` is a Primitive or Structured value carrying more about the
/// error, and it is present only when set.
#[test]
fn error_data_is_written_only_when_present() {
    let reply = Response::error(
        Id::Null,
        ErrorObject::invalid_params().with_reason("'minuend' is required"),
    );
    assert_eq!(
        reply.to_bytes(),
        br#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params","data":"'minuend' is required"},"id":null}"#,
    );
}

/// §5: where the id could not be determined, the response's id MUST be
/// Null. A frame that is not JSON at all is that case.
#[test]
fn an_undeterminable_id_is_answered_as_null() {
    let (code, id) = refused(r#"{"jsonrpc":"2.0","method":"foobar,"#);
    assert_eq!(code, PARSE_ERROR);
    assert_eq!(id, Id::Null);
}

// --- §5.1 Error object -----------------------------------------------

/// §5.1: the codes the document assigns, with the messages it pairs them
/// with, written out from its table.
#[test]
fn the_predefined_codes_and_messages_are_the_documents_own() {
    for (error, code, message) in [
        (ErrorObject::parse_error(), -32700, "Parse error"),
        (ErrorObject::invalid_request(), -32600, "Invalid Request"),
        (ErrorObject::method_not_found(), -32601, "Method not found"),
        (ErrorObject::invalid_params(), -32602, "Invalid params"),
        (ErrorObject::internal_error(), -32603, "Internal error"),
    ] {
        assert_eq!(error.code(), code);
        assert_eq!(error.message(), message);
        assert!(error.is_predefined());
        assert!(error.is_reserved());
    }
    assert_eq!(PARSE_ERROR, -32700);
    assert_eq!(INVALID_REQUEST, -32600);
    assert_eq!(METHOD_NOT_FOUND, -32601);
    assert_eq!(INVALID_PARAMS, -32602);
    assert_eq!(INTERNAL_ERROR, -32603);
}

/// §5.1: -32768 to -32000 inclusive is reserved for pre-defined errors,
/// and -32000 to -32099 of that is the implementation-defined server-error
/// range. The remainder of the space is available to the application.
#[test]
fn the_reserved_and_server_error_ranges_are_the_documents_own() {
    assert_eq!((RESERVED_MIN, RESERVED_MAX), (-32768, -32000));
    assert_eq!((SERVER_ERROR_MIN, SERVER_ERROR_MAX), (-32099, -32000));

    // Inside the server-error range: a server may take these.
    for code in [-32000, -32050, -32099] {
        let error = ErrorObject::new(code, "server error");
        assert!(error.is_server_error(), "{code}");
        assert!(error.is_reserved(), "{code}");
        assert!(!error.is_reserved_unassigned(), "{code}");
    }
    // Reserved, but neither assigned by the table nor in the server-error
    // range: the document keeps this space for future use.
    for code in [-32768, -32700 + 1, -32100, -32604] {
        let error = ErrorObject::new(code, "reserved");
        assert!(error.is_reserved(), "{code}");
        assert!(error.is_reserved_unassigned(), "{code}");
    }
    // Outside the reserved range entirely: the application's own.
    for code in [-32769, -31999, 0, 1, 42] {
        let error = ErrorObject::new(code, "application");
        assert!(!error.is_reserved(), "{code}");
        assert!(!error.is_reserved_unassigned(), "{code}");
    }
}

// --- §7 Examples -----------------------------------------------------

/// §7, "rpc call with positional parameters" — both exchanges.
#[test]
fn spec_example_positional_parameters() {
    for (frame, id, args, result, reply) in [
        (
            r#"{"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": 1}"#,
            1,
            vec![42, 23],
            19,
            r#"{"jsonrpc": "2.0", "result": 19, "id": 1}"#,
        ),
        (
            r#"{"jsonrpc": "2.0", "method": "subtract", "params": [23, 42], "id": 2}"#,
            2,
            vec![23, 42],
            -19,
            r#"{"jsonrpc": "2.0", "result": -19, "id": 2}"#,
        ),
    ] {
        let request = valid(frame);
        assert_eq!(request.method(), "subtract");
        assert_eq!(request.id(), Some(&Id::from_i64(id)));
        let params = request.params().expect("params present");
        assert!(params.is_positional());
        assert_eq!(params.deserialize::<Vec<i32>>().unwrap(), args);

        let answer = Response::success(Id::from_i64(id), &result).unwrap();
        same_json(&answer.to_bytes(), reply);
    }
}

/// §7, "rpc call with named parameters" — both exchanges, which differ
/// only in member order and must therefore answer identically.
#[test]
fn spec_example_named_parameters() {
    for (frame, id) in [
        (
            r#"{"jsonrpc": "2.0", "method": "subtract", "params": {"subtrahend": 23, "minuend": 42}, "id": 3}"#,
            3,
        ),
        (
            r#"{"jsonrpc": "2.0", "method": "subtract", "params": {"minuend": 42, "subtrahend": 23}, "id": 4}"#,
            4,
        ),
    ] {
        let request = valid(frame);
        assert_eq!(request.method(), "subtract");
        let params = request.params().expect("params present");
        assert!(params.is_named());

        #[derive(serde::Deserialize)]
        struct Args {
            minuend: i32,
            subtrahend: i32,
        }
        let args: Args = params.deserialize().unwrap();
        assert_eq!((args.minuend, args.subtrahend), (42, 23));

        let answer = Response::success(Id::from_i64(id), &19).unwrap();
        same_json(
            &answer.to_bytes(),
            &format!(r#"{{"jsonrpc": "2.0", "result": 19, "id": {id}}}"#),
        );
    }
}

/// §7, "a Notification" — both frames, with and without params.
#[test]
fn spec_example_notifications() {
    let with_params = valid(
        r#"{"jsonrpc": "2.0", "method": "update", "params": [1,2,3,4,5]}"#,
    );
    assert!(with_params.is_notification());
    assert_eq!(
        with_params
            .params()
            .unwrap()
            .deserialize::<Vec<i32>>()
            .unwrap(),
        vec![1, 2, 3, 4, 5],
    );

    let bare = valid(r#"{"jsonrpc": "2.0", "method": "foobar"}"#);
    assert!(bare.is_notification());
    assert!(bare.params().is_none());
}

/// §7, "rpc call of non-existent method". The envelope is valid, so this
/// layer accepts it; the reply is the one the document prints.
#[test]
fn spec_example_non_existent_method() {
    let request = valid(r#"{"jsonrpc": "2.0", "method": "foobar", "id": "1"}"#);
    assert_eq!(request.method(), "foobar");
    assert_eq!(request.id(), Some(&Id::from_string("1")));

    let answer =
        Response::error(Id::from_string("1"), ErrorObject::method_not_found());
    same_json(
        &answer.to_bytes(),
        r#"{"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "1"}"#,
    );
}

/// §7, "rpc call with invalid JSON" — the document's own malformed frame.
#[test]
fn spec_example_invalid_json() {
    let frame =
        r#"{"jsonrpc": "2.0", "method": "foobar, "params": "bar", "baz]"#;
    let Incoming::Invalid { error, .. } = parse(frame) else {
        panic!("a malformed frame is a single refusal");
    };
    assert_eq!(error.code(), PARSE_ERROR);
    assert_eq!(error.message(), "Parse error");

    let answer = Response::error(Id::Null, ErrorObject::parse_error());
    same_json(
        &answer.to_bytes(),
        r#"{"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": null}"#,
    );
}

/// §7, "rpc call with invalid Request object" — `method` is a Number.
#[test]
fn spec_example_invalid_request_object() {
    let frame = r#"{"jsonrpc": "2.0", "method": 1, "params": "bar"}"#;
    let (code, id) = refused(frame);
    assert_eq!(code, INVALID_REQUEST);
    // No id member, so §5's Null.
    assert_eq!(id, Id::Null);

    let answer = Response::error(Id::Null, ErrorObject::invalid_request());
    same_json(
        &answer.to_bytes(),
        r#"{"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}"#,
    );
}

// --- what §5.1 leaves to the server ---------------------------------

/// §5.1 makes `data` optional and its value the server's to define, and
/// every §7 example answers with `code` and `message` alone. So a refusal
/// this crate produces carries no `data`: the reason travels beside the
/// error, and putting it on the wire is the server's decision.
///
/// This also keeps parse detail — which validation step refused a frame —
/// away from an unauthenticated peer unless it is sent deliberately.
#[test]
fn a_refusal_carries_no_data_member_of_its_own() {
    let frame = r#"{"jsonrpc":"1.0","method":"m","id":1}"#;
    let Incoming::Single(Call::Invalid { id, error, reason }) = parse(frame)
    else {
        panic!("expected a refusal");
    };
    assert_eq!(error.code(), INVALID_REQUEST);
    assert_eq!(error.message(), "Invalid Request");
    assert!(error.data().is_none(), "nothing fills `data` in for us");
    // The reason is available, and says which rule refused the frame.
    assert!(reason.contains("jsonrpc"), "{reason}");

    // On the wire, that is §5.1's error object and nothing more.
    assert_eq!(
        Response::error(id.clone(), error.clone()).to_bytes(),
        br#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":1}"#,
    );

    // A server that wants the detail sent attaches it itself.
    let told = Response::error(id, error.with_reason(reason.to_string()));
    assert!(told.error_object().expect("an error").data().is_some());
}
