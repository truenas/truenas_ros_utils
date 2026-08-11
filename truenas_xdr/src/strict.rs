// SPDX-License-Identifier: MIT
//! Decode strictness.

/// How strictly the decoder treats input that RFC 4506 does not permit an
/// encoder to produce.
///
/// Encoding does not vary with this: padding is always zero, booleans are
/// always 0 or 1, and an encoder never emits a NUL it was not given. Only
/// decoding differs, so the mode is chosen per decode.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Strictness {
    /// Accept what a well-formed encoder would not emit: padding that is not
    /// zero, a string containing NUL bytes, and any non-zero boolean read as
    /// true.
    ///
    /// The default, because it is what interoperating with encoders that leave
    /// padding uninitialised or write a C `int` for a boolean requires.
    #[default]
    Lenient,
    /// Hold the input to what the standard allows:
    ///
    /// - a non-zero padding byte is
    ///   [`Error::NonZeroPadding`](crate::Error::NonZeroPadding) (§3);
    /// - a boolean or optional-data discriminant other than 0 or 1 is
    ///   [`Error::InvalidBool`](crate::Error::InvalidBool) (§4.3, §4.4, §4.19);
    /// - a string containing a NUL is
    ///   [`Error::EmbeddedNul`](crate::Error::EmbeddedNul).
    ///
    /// The last is not in the standard — §4.11 defines a string as counted
    /// bytes with no terminator — but a decoder handing such a string to C
    /// would truncate it, so it is rejected here.
    Strict,
}
