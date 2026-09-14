// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Buffer plumbing for the FFI boundary: borrowed descriptors going in,
//! released-on-drop ownership coming out.
#![allow(unsafe_code)]

use crate::ffi;

/// A descriptor borrowing the caller's bytes for one call.
pub(crate) fn borrowed(bytes: &[u8]) -> ffi::gss_buffer_desc {
    ffi::gss_buffer_desc {
        length: bytes.len(),
        value: bytes.as_ptr().cast_mut().cast(),
    }
}

/// A library-allocated buffer, released on drop.
pub(crate) struct OwnedBuffer {
    desc: ffi::gss_buffer_desc,
}

impl OwnedBuffer {
    /// An empty descriptor for the library to fill.
    pub(crate) fn empty() -> OwnedBuffer {
        OwnedBuffer {
            desc: ffi::gss_buffer_desc {
                length: 0,
                value: std::ptr::null_mut(),
            },
        }
    }

    pub(crate) fn as_mut_ptr(&mut self) -> ffi::gss_buffer_t {
        &mut self.desc
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        if self.desc.value.is_null() || self.desc.length == 0 {
            return &[];
        }
        // SAFETY: the library filled this descriptor; `value` carries
        // `length` readable bytes until the release in drop.
        unsafe {
            std::slice::from_raw_parts(
                self.desc.value.cast::<u8>(),
                self.desc.length,
            )
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    /// The bytes as UTF-8 text, lossily: buffers read here are display
    /// strings, not identity (identity stays in [`crate::Name`] form).
    pub(crate) fn to_text(&self) -> String {
        String::from_utf8_lossy(self.as_slice()).into_owned()
    }
}

impl Drop for OwnedBuffer {
    fn drop(&mut self) {
        if self.desc.value.is_null() {
            return;
        }
        // SAFETY: the descriptor was filled by a successful library call
        // and is released exactly once with the paired call.
        unsafe {
            let mut minor: ffi::OM_uint32 = 0;
            ffi::gss_release_buffer(&mut minor, &mut self.desc);
        }
    }
}
