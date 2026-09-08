// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Reading §5's Response object — the client's half of the exchange.

use serde_json::Value;
use serde_json::value::RawValue;

use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::VERSION;
use crate::error::ErrorObject;
use crate::id::Id;

/// What a response said: a result, or an error.
///
/// §5 requires exactly one of the two members and forbids both, which is
/// why this is an enum rather than a pair of options — a response carrying
/// neither, or carrying both, is not a Response object and never reaches
/// here.
#[derive(Clone, Copy, Debug)]
pub enum Outcome<'a> {
    /// The `result` member, unparsed. Decode it into the type the method
    /// returns.
    Result(&'a RawValue),
    /// The `error` member.
    Failure(&'a ErrorObject),
}

/// One Response object (§5): the id it answers, and its outcome.
#[derive(Clone, Debug)]
pub struct Reply<'a> {
    id: Id,
    result: Option<&'a RawValue>,
    error: Option<ErrorObject>,
}

impl<'a> Reply<'a> {
    /// The id this answers. §5 makes the member required, so it is always
    /// present — though it may be [`Id::Null`], which is what a server
    /// sends when it could not read the id it was answering.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// What the response said.
    pub fn outcome(&self) -> Outcome<'_> {
        match (&self.result, &self.error) {
            (Some(raw), None) => Outcome::Result(raw),
            (None, Some(error)) => Outcome::Failure(error),
            // Construction admits exactly one, so neither other pairing
            // can be built.
            _ => unreachable!("a reply carries exactly one of the two"),
        }
    }

    /// Whether the call succeeded.
    pub fn is_success(&self) -> bool {
        self.result.is_some()
    }

    /// The `result` member, or `None` on a failure.
    pub fn result(&self) -> Option<&'a RawValue> {
        self.result
    }

    /// The `error` member, or `None` on a success.
    pub fn error(&self) -> Option<&ErrorObject> {
        self.error.as_ref()
    }
}

/// What one inbound frame held, read as responses.
#[derive(Clone, Debug)]
pub enum Answer<'a> {
    /// A lone Response object.
    Single(Reply<'a>),
    /// The Array answering a batch, never empty: §6 forbids a server
    /// returning an empty Array, so one is refused rather than reported.
    ///
    /// §6 also allows the responses to arrive in any order, so a client
    /// matches them to its calls by id and not by position.
    Batch(Vec<Reply<'a>>),
    /// The frame is not a Response object, or an Array of them.
    ///
    /// There is nothing to send back: a client cannot answer a malformed
    /// answer. The reason is for a log, and the call it belonged to — if it
    /// can still be told — has to be failed by the caller.
    Invalid(Cow<'static, str>),
}

/// Read one inbound frame as a response, or as the Array answering a batch.
///
/// The frame must hold exactly one JSON value; anything after it is a
/// parse failure rather than being ignored.
pub fn parse_answer(frame: &[u8]) -> Answer<'_> {
    let Ok(text) = std::str::from_utf8(frame) else {
        return Answer::Invalid(Cow::Borrowed("not UTF-8"));
    };
    if let Err(e) = serde_json::from_str::<&RawValue>(text) {
        return Answer::Invalid(Cow::Owned(e.to_string()));
    }
    let first = text
        .bytes()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'));
    match first {
        Some(b'{') => match one(text) {
            Ok(reply) => Answer::Single(reply),
            Err(reason) => Answer::Invalid(reason),
        },
        Some(b'[') => batch(text),
        _ => Answer::Invalid(Cow::Borrowed(
            "a response must be an Object and a batch answer an Array",
        )),
    }
}

/// The Array answering a batch.
fn batch(text: &str) -> Answer<'_> {
    let Ok(elements) = serde_json::from_str::<Vec<&RawValue>>(text) else {
        return Answer::Invalid(Cow::Borrowed(
            "a batch answer must be an Array of Response objects",
        ));
    };
    if elements.is_empty() {
        return Answer::Invalid(Cow::Borrowed(
            "a batch answer must not be an empty Array",
        ));
    }
    let mut replies = Vec::with_capacity(elements.len());
    for raw in elements {
        match one(raw.get()) {
            Ok(reply) => replies.push(reply),
            Err(reason) => return Answer::Invalid(reason),
        }
    }
    Answer::Batch(replies)
}

/// Validate one Response object against §5.
fn one(text: &str) -> Result<Reply<'_>, Cow<'static, str>> {
    let members = serde_json::from_str::<BTreeMap<String, &RawValue>>(text)
        .map_err(|_| Cow::Borrowed("not an Object"))?;

    if members.get("jsonrpc").and_then(|r| as_str(r)).as_deref()
        != Some(VERSION)
    {
        return Err(Cow::Borrowed("'jsonrpc' must be exactly \"2.0\""));
    }

    // §5: the id member is REQUIRED in a response, unlike in a request
    // where its absence means a notification.
    let raw_id = members
        .get("id")
        .ok_or(Cow::Borrowed("'id' is required in a response"))?;
    let id = Id::from_raw(raw_id)
        .ok_or(Cow::Borrowed("'id' must be a String, a Number, or Null"))?;

    // §5: either result or error MUST be included, and both MUST NOT be.
    match (members.get("result"), members.get("error")) {
        (Some(result), None) => Ok(Reply {
            id,
            result: Some(result),
            error: None,
        }),
        (None, Some(raw)) => {
            let error = error_object(raw)?;
            Ok(Reply {
                id,
                result: None,
                error: Some(error),
            })
        }
        (Some(_), Some(_)) => {
            Err(Cow::Borrowed("'result' and 'error' must not both appear"))
        }
        (None, None) => {
            Err(Cow::Borrowed("one of 'result' and 'error' is required"))
        }
    }
}

/// Validate §5.1's error object.
fn error_object(raw: &RawValue) -> Result<ErrorObject, Cow<'static, str>> {
    let Ok(Value::Object(members)) = serde_json::from_str::<Value>(raw.get())
    else {
        return Err(Cow::Borrowed("'error' must be an Object"));
    };
    // §5.1: the code is a Number that MUST be an integer.
    let code = members
        .get("code")
        .and_then(Value::as_i64)
        .ok_or(Cow::Borrowed("'code' must be an integer Number"))?;
    let Some(Value::String(message)) = members.get("message") else {
        return Err(Cow::Borrowed("'message' must be a String"));
    };
    let mut error = ErrorObject::new(code, message.clone());
    // §5.1: data is optional, and any JSON value.
    if let Some(data) = members.get("data") {
        error = error.with_data(data.clone());
    }
    Ok(error)
}

/// The value of a JSON String, or `None` if it is not a String.
fn as_str(raw: &RawValue) -> Option<String> {
    serde_json::from_str::<String>(raw.get()).ok()
}
