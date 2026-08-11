//! [`Error`] and this crate's [`Result`].

use serde::{de, ser};
use std::fmt;

/// This crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// An error encoding or decoding XDR.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before a value was complete.
    Eof {
        /// Further bytes needed.
        need: usize,
    },
    /// A wire value did not fit the target type, such as an out-of-range
    /// 32-bit value decoded into an `i16`.
    Range,
    /// A padding byte was non-zero. [`Strictness::Strict`] only.
    ///
    /// [`Strictness::Strict`]: crate::Strictness::Strict
    NonZeroPadding,
    /// A decoded string contained a NUL. [`Strictness::Strict`] only.
    ///
    /// [`Strictness::Strict`]: crate::Strictness::Strict
    EmbeddedNul,
    /// A decoded string was not valid UTF-8.
    Utf8,
    /// Input remained after a value was decoded by
    /// [`from_bytes`](crate::from_bytes).
    TrailingBytes {
        /// Bytes left unread.
        rest: usize,
    },
    /// A construct XDR cannot represent: a map, a sequence of unknown length,
    /// or a request for self-describing decoding.
    Unsupported(&'static str),
    /// A write to the output failed, carrying the `io::Error`'s message.
    Io(String),
    /// A `custom` message from serde.
    Message(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Eof { need } => {
                write!(f, "unexpected end of input, need {need} more byte(s)")
            }
            Error::Range => f.write_str("value out of range for target type"),
            Error::NonZeroPadding => f.write_str("non-zero padding byte"),
            Error::EmbeddedNul => f.write_str("embedded NUL in string"),
            Error::Utf8 => f.write_str("invalid UTF-8 in string"),
            Error::TrailingBytes { rest } => {
                write!(f, "{rest} trailing byte(s) after value")
            }
            Error::Unsupported(what) => {
                write!(f, "XDR does not support {what}")
            }
            Error::Io(msg) | Error::Message(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> std::io::Error {
        use std::io::ErrorKind;
        let kind = match err {
            Error::Eof { .. } => ErrorKind::UnexpectedEof,
            Error::Unsupported(_) => ErrorKind::Unsupported,
            _ => ErrorKind::InvalidData,
        };
        std::io::Error::new(kind, err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_renders() {
        let cases = [
            (Error::Eof { need: 3 }, "need 3 more"),
            (Error::Range, "out of range"),
            (Error::NonZeroPadding, "non-zero padding"),
            (Error::EmbeddedNul, "embedded NUL"),
            (Error::Utf8, "invalid UTF-8"),
            (Error::TrailingBytes { rest: 7 }, "7 trailing"),
            (Error::Unsupported("map"), "does not support map"),
            (Error::Io("disk gone".into()), "disk gone"),
            (Error::Message("boom".into()), "boom"),
        ];
        for (err, want) in cases {
            let rendered = err.to_string();
            assert!(rendered.contains(want), "{rendered:?} lacks {want:?}");
        }
    }

    #[test]
    fn serde_custom_errors_carry_their_message() {
        assert_eq!(
            <Error as ser::Error>::custom("ser side"),
            Error::Message("ser side".into())
        );
        assert_eq!(
            <Error as de::Error>::custom("de side"),
            Error::Message("de side".into())
        );
    }

    #[test]
    fn io_conversion_picks_a_matching_kind() {
        use std::io::ErrorKind;
        let eof: std::io::Error = Error::Eof { need: 1 }.into();
        assert_eq!(eof.kind(), ErrorKind::UnexpectedEof);
        let unsup: std::io::Error = Error::Unsupported("map").into();
        assert_eq!(unsup.kind(), ErrorKind::Unsupported);
        let other: std::io::Error = Error::Utf8.into();
        assert_eq!(other.kind(), ErrorKind::InvalidData);
        assert!(other.to_string().contains("UTF-8"));
    }

    #[test]
    fn errors_are_comparable_and_boxable() {
        assert_eq!(Error::Eof { need: 2 }, Error::Eof { need: 2 });
        assert_ne!(Error::Eof { need: 2 }, Error::Eof { need: 3 });
        let boxed: Box<dyn std::error::Error> = Box::new(Error::Range);
        assert!(boxed.to_string().contains("out of range"));
    }
}
