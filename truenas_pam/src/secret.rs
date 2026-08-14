// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Secret`] — the bytes of one conversation response.
//!
//! # Safety
//!
//! This module writes through raw pointers to overwrite buffers that are about
//! to be released, so it lifts the workspace's `deny(unsafe_code)`. The writes
//! are volatile and followed by a compiler fence, because a plain store to
//! memory nothing reads again is dead and may be removed.
#![allow(unsafe_code)]

use std::sync::atomic::{Ordering, compiler_fence};

/// The answer to one prompt, overwritten when it is dropped.
///
/// Scrubbing covers this buffer and a by-value source: a `String` or `Vec`
/// moved in is burned to its full capacity once its bytes are copied
/// across. What remains the caller's to manage is any copy the caller
/// still holds — the `&str` a `Secret::from` borrowed, an earlier clone.
///
/// ```
/// # use truenas_pam::Secret;
/// let s = Secret::from("hunter2");
/// assert_eq!(s.as_bytes(), b"hunter2");
/// assert_eq!(format!("{s:?}"), "Secret(..)");
/// ```
pub struct Secret(Box<[u8]>);

impl Secret {
    /// Take ownership of `bytes`.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Secret {
        let mut src = bytes.into();
        if src.capacity() == src.len() {
            // Exact already: boxing keeps the allocation in place.
            return Secret(src.into_boxed_slice());
        }
        // Spare capacity: `into_boxed_slice` would move the bytes to an
        // exact-length block and free this one unscrubbed. Copy across,
        // then burn the source's whole buffer before it is released.
        let boxed: Box<[u8]> = src.as_slice().into();
        // SAFETY: `src` uniquely owns `capacity` writable bytes.
        unsafe { scrub(src.as_mut_ptr(), src.capacity()) };
        Secret(boxed)
    }

    /// The bytes, as they will reach the module.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// How many bytes the answer is.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the answer is the empty string, which is distinct from having
    /// no answer at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Secret {
        Secret::new(s.as_bytes())
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Secret {
        Secret::new(s.into_bytes())
    }
}

impl From<&[u8]> for Secret {
    fn from(b: &[u8]) -> Secret {
        Secret::new(b)
    }
}

impl From<Vec<u8>> for Secret {
    fn from(b: Vec<u8>) -> Secret {
        Secret::new(b)
    }
}

/// Prints no content: a `Secret` reaching a log must not carry the answer with
/// it.
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: a live, uniquely owned allocation of exactly this length.
        unsafe { scrub(self.0.as_mut_ptr(), self.0.len()) };
    }
}

/// Overwrite `len` bytes at `p` with zeroes.
///
/// # Safety
///
/// `p` must be valid for writes of `len` bytes.
pub(crate) unsafe fn scrub(p: *mut u8, len: usize) {
    for i in 0..len {
        // SAFETY: `i < len`, so this is within the caller's guaranteed range.
        unsafe { p.add(i).write_volatile(0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_source_keeps_the_bytes_verbatim() {
        assert_eq!(Secret::from("ab").as_bytes(), b"ab");
        assert_eq!(Secret::from(String::from("ab")).as_bytes(), b"ab");
        assert_eq!(Secret::from(&b"ab"[..]).as_bytes(), b"ab");
        assert_eq!(Secret::from(vec![b'a', b'b']).as_bytes(), b"ab");
        // Bytes are not text: an answer may be any byte string, and nothing
        // here validates or normalises it.
        assert_eq!(Secret::new(vec![0xff, 0x00]).as_bytes(), &[0xff, 0x00]);
    }

    /// An empty answer is a real answer — `pam_authenticate` with
    /// `DISALLOW_NULL_AUTHTOK` distinguishes it from no answer.
    #[test]
    fn empty_is_not_absent() {
        let s = Secret::from("");
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.as_bytes(), b"");
    }

    /// A `Debug` that printed the answer would put it in every log line that
    /// formats a response vector.
    #[test]
    fn debug_hides_the_answer() {
        let s = Secret::from("hunter2");
        assert_eq!(format!("{s:?}"), "Secret(..)");
        assert_eq!(format!("{:?}", Some(s)), "Some(Secret(..))");
    }

    #[test]
    fn scrub_clears_the_whole_buffer() {
        let mut buf = *b"password";
        // SAFETY: a live local array of exactly this length.
        unsafe { scrub(buf.as_mut_ptr(), buf.len()) };
        assert_eq!(buf, [0; 8]);
    }

    /// A source with spare capacity takes the copy-and-burn path; the
    /// bytes must come through it verbatim, as they do the in-place one.
    #[test]
    fn a_source_with_spare_capacity_round_trips() {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(b"hunter2");
        assert!(v.capacity() > v.len());
        assert_eq!(Secret::from(v).as_bytes(), b"hunter2");

        let mut s = String::with_capacity(32);
        s.push_str("pw");
        assert_eq!(Secret::from(s).as_bytes(), b"pw");
    }
}
