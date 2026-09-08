// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Building §5's Response object, and §6's Array of them.

use serde::Serialize;
use serde_json::value::{RawValue, to_raw_value};

use crate::VERSION;
use crate::error::ErrorObject;
use crate::id::Id;

/// Which of the two members §5 requires — exactly one, never both.
#[derive(Clone, Debug)]
enum Payload {
    Result(Box<RawValue>),
    Error(ErrorObject),
}

/// A Response object (§5): the `jsonrpc` member, exactly one of `result`
/// and `error`, and the `id` of the request it answers.
///
/// `result` is held serialized. A handler's value is encoded once, when the
/// response is built, so a failing `Serialize` is reported at that point
/// rather than part-way through writing a frame — where half an envelope
/// would already be on the wire.
#[derive(Clone, Debug)]
pub struct Response {
    payload: Payload,
    id: Id,
}

impl Response {
    /// A successful response carrying `result`.
    ///
    /// The error is `serde_json`'s, from encoding `result`. §5.1's
    /// [`INTERNAL_ERROR`](crate::INTERNAL_ERROR) is what to answer with
    /// then: the request was valid and the fault is the server's.
    pub fn success<T>(id: Id, result: &T) -> Result<Self, serde_json::Error>
    where
        T: ?Sized + Serialize,
    {
        Ok(Self {
            payload: Payload::Result(to_raw_value(result)?),
            id,
        })
    }

    /// A successful response carrying already-encoded JSON, for a result
    /// forwarded rather than built here.
    pub fn success_raw(id: Id, result: Box<RawValue>) -> Self {
        Self {
            payload: Payload::Result(result),
            id,
        }
    }

    /// A failed response carrying `error`.
    pub fn error(id: Id, error: ErrorObject) -> Self {
        Self {
            payload: Payload::Error(error),
            id,
        }
    }

    /// The id this answers against.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Whether this carries `result`.
    pub fn is_success(&self) -> bool {
        matches!(self.payload, Payload::Result(_))
    }

    /// The `result` member, or `None` on a failed response.
    pub fn result(&self) -> Option<&RawValue> {
        match &self.payload {
            Payload::Result(raw) => Some(raw),
            Payload::Error(_) => None,
        }
    }

    /// The `error` member, or `None` on a successful response.
    pub fn error_object(&self) -> Option<&ErrorObject> {
        match &self.payload {
            Payload::Error(e) => Some(e),
            Payload::Result(_) => None,
        }
    }

    /// The wire bytes of this response.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_into(&mut out);
        out
    }

    /// Append the wire bytes to `out`, so a connection can reuse one
    /// buffer across replies instead of allocating per reply.
    ///
    /// Member order is §7's throughout: `jsonrpc`, then `result` or
    /// `error`, then `id`; and within an error, `code`, `message`, `data`.
    /// JSON does not give member order a meaning, so nothing may depend on
    /// it — it is fixed here only so one input always produces one output,
    /// which is what makes a byte comparison in a test worth making.
    pub fn write_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(br#"{"jsonrpc":""#);
        out.extend_from_slice(VERSION.as_bytes());
        out.extend_from_slice(br#"","#);
        match &self.payload {
            Payload::Result(raw) => {
                out.extend_from_slice(br#""result":"#);
                out.extend_from_slice(raw.get().as_bytes());
            }
            Payload::Error(e) => {
                out.extend_from_slice(br#""error":{"code":"#);
                out.extend_from_slice(e.code().to_string().as_bytes());
                out.extend_from_slice(br#","message":"#);
                write_json(out, e.message());
                if let Some(data) = e.data() {
                    out.extend_from_slice(br#","data":"#);
                    write_json(out, data);
                }
                out.push(b'}');
            }
        }
        out.extend_from_slice(br#","id":"#);
        write_json(out, &self.id);
        out.push(b'}');
    }
}

/// Append `value` as JSON.
///
/// The write cannot fail: the sink is a `Vec`, which never reports an I/O
/// error, and every type reaching here — a `str`, a `Value`, an [`Id`] —
/// has an infallible `Serialize`. A failure would be a defect in this
/// crate or in `serde_json`, not a condition a caller could handle.
fn write_json<T: ?Sized + Serialize>(out: &mut Vec<u8>, value: &T) {
    serde_json::to_writer(&mut *out, value)
        .expect("serializing into a Vec cannot fail");
}

/// Assemble the Array a batch is answered with (§6).
///
/// `None` when `responses` is empty. §6 is explicit that a server must not
/// return an empty Array and should return nothing at all, which is the
/// case a batch holding only notifications reaches: §4.1 forbids answering
/// any of them, so there is nothing to put in the Array.
pub fn batch_frame(responses: &[Response]) -> Option<Vec<u8>> {
    if responses.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    out.push(b'[');
    for (i, response) in responses.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        response.write_into(&mut out);
    }
    out.push(b']');
    Some(out)
}
