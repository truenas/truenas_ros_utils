// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Reading one inbound frame: §4's Request object, §4.1's notification,
//! and §6's batch.

use serde::Deserialize;
use serde_json::value::RawValue;

use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::error::ErrorObject;
use crate::id::Id;
use crate::{RESERVED_PREFIX, VERSION};

/// The `params` member, still unparsed, tagged with which of §4.2's two
/// structures it arrived as.
#[derive(Clone, Copy, Debug)]
pub enum Params<'a> {
    /// By-position: a JSON Array holding the values in the order the
    /// method expects.
    Positional(&'a RawValue),
    /// By-name: a JSON Object whose member names match the method's
    /// parameter names, exactly and case-sensitively.
    Named(&'a RawValue),
}

impl<'a> Params<'a> {
    /// The unparsed JSON, whichever structure it is.
    pub fn get(&self) -> &'a RawValue {
        match self {
            Self::Positional(raw) | Self::Named(raw) => raw,
        }
    }

    /// Whether these are by-position parameters.
    pub fn is_positional(&self) -> bool {
        matches!(self, Self::Positional(_))
    }

    /// Whether these are by-name parameters.
    pub fn is_named(&self) -> bool {
        matches!(self, Self::Named(_))
    }

    /// Decode into the method's own parameter type.
    ///
    /// The error is the one `serde_json` reports. §5.1 pairs a parameter
    /// that will not decode with [`INVALID_PARAMS`](crate::INVALID_PARAMS),
    /// which is the caller's to build, since only the caller knows what the
    /// method expected.
    pub fn deserialize<T: Deserialize<'a>>(
        &self,
    ) -> Result<T, serde_json::Error> {
        serde_json::from_str(self.get().get())
    }
}

/// A structurally valid request, or a structurally valid notification when
/// [`Request::id`] is `None`.
///
/// Structurally valid means what §4 requires of the envelope: `jsonrpc` is
/// exactly `"2.0"`, `method` is a String, any `id` is one of the three
/// types §4 admits, and any `params` is one of the two structures §4.2
/// admits. Whether the method exists, and whether the parameters suit it,
/// this layer cannot know.
#[derive(Clone, Debug)]
pub struct Request<'a> {
    id: Option<Id>,
    method: String,
    params: Option<Params<'a>>,
}

impl<'a> Request<'a> {
    /// The id, or `None` for a notification.
    pub fn id(&self) -> Option<&Id> {
        self.id.as_ref()
    }

    /// The method name.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The parameters, or `None` when the member was omitted. §4 makes
    /// `params` optional, so `None` means "the method was called with
    /// none" — distinct from an empty Array or Object, which are present
    /// and empty.
    pub fn params(&self) -> Option<Params<'a>> {
        self.params
    }

    /// Whether this is a notification: §4.1's request without an `id`
    /// member, which the server MUST NOT answer — inside a batch included.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// Whether the method name carries the `rpc.` prefix §4 reserves for
    /// rpc-internal methods and extensions. Parsing does not refuse one:
    /// the reservation governs what a name may be used for, so an
    /// unrecognised `rpc.` method is
    /// [`METHOD_NOT_FOUND`](crate::METHOD_NOT_FOUND) like any other.
    pub fn is_reserved_method(&self) -> bool {
        self.method.starts_with(RESERVED_PREFIX)
    }

    /// Take the id, leaving the request without one. Answering a request
    /// needs an owned id and the request usually outlives that moment by
    /// nothing, so this saves the clone.
    pub fn take_id(&mut self) -> Option<Id> {
        self.id.take()
    }
}

/// Why a frame, or one element of it, was refused.
///
/// This travels *beside* the error object rather than inside it. §5.1
/// leaves the `error` member's optional `data` to the server, and every
/// worked example in §7 answers with `code` and `message` alone — so
/// nothing here fills `data` in on the server's behalf. Detail describing
/// which validation step refused a frame also tells an unauthenticated
/// peer about the validator rather than helping a legitimate caller, so
/// attaching it is a decision, not a default.
///
/// Log it, or attach it deliberately with
/// [`ErrorObject::with_reason`](crate::ErrorObject::with_reason).
pub type Reason = Cow<'static, str>;

/// One element of a frame: a request to act on, or a refusal to send back.
#[derive(Clone, Debug)]
pub enum Call<'a> {
    /// Structurally valid.
    Valid(Request<'a>),
    /// Not a valid Request object. `id` is what §5 says to answer against:
    /// the request's own id when it could be read, and [`Id::Null`] when it
    /// could not.
    Invalid {
        /// The id to answer against.
        id: Id,
        /// The error to answer with, carrying §5.1's own code and message.
        error: ErrorObject,
        /// Why it was refused, for a log or a deliberate `data` member.
        reason: Reason,
    },
}

/// What one frame held.
#[derive(Clone, Debug)]
pub enum Incoming<'a> {
    /// A lone Request object.
    Single(Call<'a>),
    /// A §6 batch, never empty: an empty Array is not "an Array with at
    /// least one value", so it arrives as [`Incoming::Invalid`].
    Batch(Vec<Call<'a>>),
    /// The frame is not JSON, or is JSON but neither an Object nor a
    /// non-empty Array. §6 requires a **single** Response object here,
    /// against [`Id::Null`], even when the frame looked like a batch.
    Invalid {
        /// The error to answer with.
        error: ErrorObject,
        /// Why the frame was refused.
        reason: Reason,
    },
}

/// The first byte of `text` that JSON does not count as whitespace.
fn first_token(text: &str) -> Option<u8> {
    text.bytes()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
}

/// The value of a JSON String, or `None` if it is not a String.
fn as_str(raw: &RawValue) -> Option<String> {
    serde_json::from_str::<String>(raw.get()).ok()
}

/// Parse one frame.
///
/// The frame must hold exactly one JSON value; trailing content after it is
/// a parse error rather than being ignored, because a framing layer that
/// delivered two values in one frame has a bug this would hide.
pub fn parse(frame: &[u8]) -> Incoming<'_> {
    // JSON is a UTF-8 text format, so a frame that is not UTF-8 cannot be
    // JSON. Checked here so the rest of the parse can borrow `&str` and
    // hand out zero-copy `params`.
    let Ok(text) = std::str::from_utf8(frame) else {
        return Incoming::Invalid {
            error: ErrorObject::parse_error(),
            reason: Cow::Borrowed("not UTF-8"),
        };
    };
    if let Err(e) = serde_json::from_str::<&RawValue>(text) {
        return Incoming::Invalid {
            error: ErrorObject::parse_error(),
            reason: Cow::Owned(e.to_string()),
        };
    }
    match first_token(text) {
        Some(b'{') => Incoming::Single(one(text)),
        Some(b'[') => batch(text),
        // Valid JSON, but a scalar is not a Request object and §6 admits an
        // Array only as a batch.
        _ => Incoming::Invalid {
            error: ErrorObject::invalid_request(),
            reason: Cow::Borrowed(
                "a request must be an Object and a batch a non-empty Array",
            ),
        },
    }
}

/// A §6 batch. The array parsed as JSON above, so it deserializes here.
fn batch<'a>(text: &'a str) -> Incoming<'a> {
    let Ok(elements) = serde_json::from_str::<Vec<&'a RawValue>>(text) else {
        return Incoming::Invalid {
            error: ErrorObject::invalid_request(),
            reason: Cow::Borrowed(
                "a batch must be an Array of Request objects",
            ),
        };
    };
    if elements.is_empty() {
        return Incoming::Invalid {
            error: ErrorObject::invalid_request(),
            reason: Cow::Borrowed("an empty batch"),
        };
    }
    Incoming::Batch(
        elements
            .into_iter()
            .map(|raw| match first_token(raw.get()) {
                Some(b'{') => one(raw.get()),
                // §6 judges each element on its own, so a non-Object
                // element is one refusal and not the batch's.
                _ => Call::Invalid {
                    id: Id::Null,
                    error: ErrorObject::invalid_request(),
                    reason: Cow::Borrowed("a batch element must be an Object"),
                },
            })
            .collect(),
    )
}

/// Validate one Request object. `text` is known to be a JSON Object.
fn one<'a>(text: &'a str) -> Call<'a> {
    let Ok(members) =
        serde_json::from_str::<BTreeMap<String, &'a RawValue>>(text)
    else {
        // Reached only if the object's members cannot be walked, which a
        // validated JSON Object always can.
        return Call::Invalid {
            id: Id::Null,
            error: ErrorObject::invalid_request(),
            reason: Cow::Borrowed("unreadable Object"),
        };
    };

    // §5: answer against the request's own id where it can be read, and
    // against Null only where it cannot. So the id is resolved first, and
    // every later refusal is attributed to it.
    let id = match members.get("id") {
        None => None,
        Some(raw) => match Id::from_raw(raw) {
            Some(id) => Some(id),
            None => {
                return Call::Invalid {
                    id: Id::Null,
                    error: ErrorObject::invalid_request(),
                    reason: Cow::Borrowed(
                        "'id' must be a String, a Number, or Null",
                    ),
                };
            }
        },
    };
    let answer_to = id.clone().unwrap_or(Id::Null);

    // §4: `jsonrpc` MUST be exactly "2.0". A missing member is how a
    // 1.0 request is told apart from a 2.0 one (§3).
    if members.get("jsonrpc").and_then(|r| as_str(r)).as_deref()
        != Some(VERSION)
    {
        return Call::Invalid {
            id: answer_to,
            error: ErrorObject::invalid_request(),
            reason: Cow::Borrowed("'jsonrpc' must be exactly \"2.0\""),
        };
    }

    // §4: `method` MUST be a String. Emptiness is not excluded, so an
    // empty name parses and is answered METHOD_NOT_FOUND by the caller.
    let Some(method) = members.get("method").and_then(|r| as_str(r)) else {
        return Call::Invalid {
            id: answer_to,
            error: ErrorObject::invalid_request(),
            reason: Cow::Borrowed("'method' must be a String"),
        };
    };

    // §4.2: when present, `params` MUST be a Structured value — an Array
    // or an Object. A scalar is refused, `null` included: the member is
    // omitted to mean "no parameters".
    let params = match members.get("params") {
        None => None,
        Some(raw) => match first_token(raw.get()) {
            Some(b'[') => Some(Params::Positional(raw)),
            Some(b'{') => Some(Params::Named(raw)),
            _ => {
                return Call::Invalid {
                    id: answer_to,
                    error: ErrorObject::invalid_request(),
                    reason: Cow::Borrowed(
                        "'params' must be an Array or an Object",
                    ),
                };
            }
        },
    };

    Call::Valid(Request { id, method, params })
}
