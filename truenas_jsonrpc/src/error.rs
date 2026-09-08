// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The error object §5.1 defines, and the codes it assigns.

use serde_json::Value;

use std::fmt;

/// Invalid JSON was received. §5.1 pairs this code with the message
/// `"Parse error"`.
pub const PARSE_ERROR: i64 = -32700;

/// The JSON sent is not a valid Request object. §5.1 pairs this code with
/// the message `"Invalid Request"`.
pub const INVALID_REQUEST: i64 = -32600;

/// The method does not exist or is not available. §5.1 pairs this code
/// with the message `"Method not found"`.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// Invalid method parameters. §5.1 pairs this code with the message
/// `"Invalid params"`.
pub const INVALID_PARAMS: i64 = -32602;

/// An internal JSON-RPC error. §5.1 pairs this code with the message
/// `"Internal error"`.
pub const INTERNAL_ERROR: i64 = -32603;

/// Lower inclusive bound of the range §5.1 reserves for pre-defined
/// errors. A code inside the reserved range that §5.1 does not assign is
/// reserved for future use, so a server must not invent one — see
/// [`ErrorObject::is_reserved_unassigned`].
pub const RESERVED_MIN: i64 = -32768;

/// Upper inclusive bound of the reserved range.
pub const RESERVED_MAX: i64 = -32000;

/// Lower inclusive bound of the implementation-defined server-error range
/// §5.1 sets aside inside the reserved range. §5.1 writes it "-32000 to
/// -32099"; ordered as numbers that is `-32099..=-32000`.
pub const SERVER_ERROR_MIN: i64 = -32099;

/// Upper inclusive bound of the server-error range.
pub const SERVER_ERROR_MAX: i64 = -32000;

/// The `error` member of a failed response (§5.1).
///
/// `code` is an `i64` rather than an enumeration of the assigned codes: the
/// server-error range and the whole application-defined space outside the
/// reserved range are numbers a server chooses, so an enumeration would
/// have to carry an escape variant and gain nothing. The predicates below
/// classify a code instead.
///
/// `data` is a [`Value`], not the unparsed form `result` uses: it is
/// diagnostic, built by the server that reports the error rather than
/// forwarded, and never on a hot path.
#[derive(Clone, Debug, PartialEq)]
pub struct ErrorObject {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl ErrorObject {
    /// An error with any code and message. §5.1 requires the code to be an
    /// integer and recommends the message be one concise sentence; neither
    /// is checked here, because a server may legitimately carry a code from
    /// the application-defined space.
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// `-32700 Parse error`, with §5.1's message.
    pub fn parse_error() -> Self {
        Self::new(PARSE_ERROR, "Parse error")
    }

    /// `-32600 Invalid Request`, with §5.1's message.
    pub fn invalid_request() -> Self {
        Self::new(INVALID_REQUEST, "Invalid Request")
    }

    /// `-32601 Method not found`, with §5.1's message.
    pub fn method_not_found() -> Self {
        Self::new(METHOD_NOT_FOUND, "Method not found")
    }

    /// `-32602 Invalid params`, with §5.1's message.
    pub fn invalid_params() -> Self {
        Self::new(INVALID_PARAMS, "Invalid params")
    }

    /// `-32603 Internal error`, with §5.1's message.
    pub fn internal_error() -> Self {
        Self::new(INTERNAL_ERROR, "Internal error")
    }

    /// Attach the optional `data` member, replacing any already set.
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Attach `data` as a string, the common case for a reason a client can
    /// read.
    pub fn with_reason(self, reason: impl Into<String>) -> Self {
        self.with_data(Value::String(reason.into()))
    }

    /// The numeric code.
    pub fn code(&self) -> i64 {
        self.code
    }

    /// The message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The optional `data` member.
    pub fn data(&self) -> Option<&Value> {
        self.data.as_ref()
    }

    /// Whether the code lies in the range §5.1 reserves for pre-defined
    /// errors.
    pub fn is_reserved(&self) -> bool {
        (RESERVED_MIN..=RESERVED_MAX).contains(&self.code)
    }

    /// Whether the code lies in the implementation-defined server-error
    /// range.
    pub fn is_server_error(&self) -> bool {
        (SERVER_ERROR_MIN..=SERVER_ERROR_MAX).contains(&self.code)
    }

    /// Whether the code is one §5.1 assigns a meaning to.
    pub fn is_predefined(&self) -> bool {
        matches!(
            self.code,
            PARSE_ERROR
                | INVALID_REQUEST
                | METHOD_NOT_FOUND
                | INVALID_PARAMS
                | INTERNAL_ERROR
        )
    }

    /// Whether the code is inside the reserved range but is neither
    /// assigned by §5.1 nor within the server-error range — the space
    /// §5.1 keeps for future use, which a server must not take.
    pub fn is_reserved_unassigned(&self) -> bool {
        self.is_reserved() && !self.is_server_error() && !self.is_predefined()
    }
}

impl fmt::Display for ErrorObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for ErrorObject {}
