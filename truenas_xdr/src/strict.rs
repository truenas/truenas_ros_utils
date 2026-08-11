//! Decode strictness.

/// How strictly the decoder treats padding and string contents.
///
/// Encoding does not vary with this: canonical padding is always zero, and an
/// encoder never emits a NUL it was not given. Only decoding differs, so the
/// mode is chosen per decode.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Strictness {
    /// Ignore the padding after opaque and string fields, and accept a string
    /// containing NUL bytes. The default, and what a decoder must use to
    /// accept messages from encoders that leave padding uninitialised.
    #[default]
    Lenient,
    /// Reject a non-zero padding byte with
    /// [`Error::NonZeroPadding`](crate::Error::NonZeroPadding), and a string
    /// containing a NUL with
    /// [`Error::EmbeddedNul`](crate::Error::EmbeddedNul).
    Strict,
}
