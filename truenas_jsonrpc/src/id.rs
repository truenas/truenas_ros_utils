// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The `id` member of a request and of the response that answers it.

use serde::{Serialize, Serializer};
use serde_json::value::RawValue;
use serde_json::{Number, Value};

use std::fmt;

/// A request identifier: §4 admits a String, a Number, or Null, and
/// nothing else. A request with no `id` member at all is a notification,
/// which is `Option::None` rather than [`Id::Null`] — §4.1 makes the
/// absence of the member the thing that means "expect no answer", so a
/// present `null` is an id like any other.
///
/// A Number keeps the [`Number`] it arrived as instead of being narrowed to
/// an integer, because §5 requires the response's id to be *the same value*
/// as the request's. Narrowing would answer `1` to a request that asked as
/// `1.0`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Id {
    /// A Number id. §4's note on fractional parts discourages one; it does not
    /// forbid one, so one is carried rather than refused. Ask
    /// [`Id::has_fractional_part`] when that matters.
    Number(Number),
    /// A String id.
    String(String),
    /// An explicit `null` id. §4 discourages this: a response whose id
    /// could not be determined also carries `null`, so the two are
    /// indistinguishable to the client that sent it.
    Null,
}

impl Id {
    /// An id from a signed integer.
    pub fn from_i64(n: i64) -> Self {
        Self::Number(Number::from(n))
    }

    /// An id from a string.
    pub fn from_string(s: impl Into<String>) -> Self {
        Self::String(s.into())
    }

    /// Whether this is the explicit `null` id.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Whether this is a Number carrying a fractional part, which §4 says
    /// a client SHOULD NOT send: not every decimal fraction has an exact
    /// binary form, so such an id may not survive a round trip through a
    /// peer that stores it as a float.
    pub fn has_fractional_part(&self) -> bool {
        match self {
            Self::Number(n) => n.as_i64().is_none() && n.as_u64().is_none(),
            _ => false,
        }
    }

    /// Read an id from the raw JSON of an `id` member, returning `None` for
    /// a Boolean, Array, or Object — the three JSON types §4 excludes.
    pub(crate) fn from_raw(raw: &RawValue) -> Option<Self> {
        match serde_json::from_str::<Value>(raw.get()) {
            Ok(Value::Null) => Some(Self::Null),
            Ok(Value::String(s)) => Some(Self::String(s)),
            Ok(Value::Number(n)) => Some(Self::Number(n)),
            _ => None,
        }
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "{s}"),
            Self::Null => f.write_str("null"),
        }
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Number(n) => n.serialize(s),
            Self::String(v) => s.serialize_str(v),
            Self::Null => s.serialize_none(),
        }
    }
}
