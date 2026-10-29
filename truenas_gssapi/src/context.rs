// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Context`], an established security context and its per message
//! calls.
#![allow(unsafe_code)]

use std::ops::Range;
use std::os::raw::c_int;
use std::time::Duration;

use crate::accept::ContextFlags;
use crate::buf::{OwnedBuffer, borrowed};
use crate::error::{Error, Result, check};
use crate::ffi;
use crate::name::Name;
use crate::oid::Oid;

/// An established security context, taken out of an acceptor that
/// completed with [`Acceptor::into_context`](crate::Acceptor::into_context).
///
/// It signs and checks messages with GSS_GetMIC and GSS_VerifyMIC, and
/// seals and opens them with GSS_Wrap and GSS_Unwrap, under the default
/// quality of protection of the mechanism. The calls that take a message
/// and give back a buffer copy once. The calls that work in place,
/// [`get_mic_into`](Context::get_mic_into),
/// [`wrap_in_place`](Context::wrap_in_place) and
/// [`unwrap_in_place`](Context::unwrap_in_place), write where the caller
/// says and copy nothing, for a message too large to copy. The credential
/// the context was accepted with is no longer needed, so the context owns
/// itself and may outlive it.
///
/// The per message calls take `&mut self`, since each advances the
/// context's own sequence state in the library.
pub struct Context {
    raw: ffi::gss_ctx_id_t,
    source: Option<Name>,
    mech: Option<Oid>,
    flags: ContextFlags,
}

// SAFETY: the context is used from one thread at a time, which the raw
// pointer field guarantees by denying `Sync`, and the library binds it to
// no thread, so it may move between threads.
unsafe impl Send for Context {}

impl Context {
    pub(crate) fn new(
        raw: ffi::gss_ctx_id_t,
        source: Option<Name>,
        mech: Option<Oid>,
        flags: ContextFlags,
    ) -> Context {
        Context {
            raw,
            source,
            mech,
            flags,
        }
    }

    /// The authenticated initiator, the name to map to a local account
    /// with [`Name::localname`].
    pub fn source_name(&self) -> Option<&Name> {
        self.source.as_ref()
    }

    /// The mechanism that settled the context.
    pub fn mechanism(&self) -> Option<&Oid> {
        self.mech.as_ref()
    }

    /// The flags the context reports.
    pub fn flags(&self) -> ContextFlags {
        self.flags
    }

    /// How much longer the context is valid, which the initiator's ticket
    /// bounds. `None` is a context that never runs out. A context that ran
    /// out is an error whose routine is `CONTEXT_EXPIRED`.
    pub fn lifetime(&self) -> Result<Option<Duration>> {
        let mut left: ffi::OM_uint32 = 0;
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live context and an out-parameter.
        let major =
            unsafe { ffi::gss_context_time(&mut minor, self.raw, &mut left) };
        check(major, minor, self.mech.as_ref())?;
        Ok((left != ffi::GSS_C_INDEFINITE)
            .then(|| Duration::from_secs(u64::from(left))))
    }

    /// The checksum of `message`, as GSS_GetMIC gives it under the default
    /// quality of protection.
    pub fn get_mic(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut input = borrowed(message);
        let mut out = OwnedBuffer::empty();
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live context, an input borrowing the caller's bytes for
        // this call, and an out buffer released by `OwnedBuffer`.
        let major = unsafe {
            ffi::gss_get_mic(
                &mut minor,
                self.raw,
                ffi::GSS_C_QOP_DEFAULT,
                &mut input,
                out.as_mut_ptr(),
            )
        };
        check(major, minor, self.mech.as_ref())?;
        Ok(out.to_vec())
    }

    /// Checks `mic` against `message`, as GSS_VerifyMIC does, and gives the
    /// quality of protection the checksum was made under, as the
    /// mechanism numbers it. A checksum that does not match is an error
    /// whose routine is `BAD_SIG`.
    pub fn verify_mic(&mut self, message: &[u8], mic: &[u8]) -> Result<u32> {
        let mut input = borrowed(message);
        let mut token = borrowed(mic);
        let mut qop: ffi::gss_qop_t = 0;
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live context, two inputs borrowing the caller's bytes for
        // this call, and an out-parameter.
        let major = unsafe {
            ffi::gss_verify_mic(
                &mut minor, self.raw, &mut input, &mut token, &mut qop,
            )
        };
        check(major, minor, self.mech.as_ref())?;
        Ok(qop)
    }

    /// Seals `message`, as GSS_Wrap does under the default quality of
    /// protection, encrypted when `confidential` is set and signed either
    /// way. Returns the token and whether the message was encrypted in it.
    pub fn wrap(
        &mut self,
        confidential: bool,
        message: &[u8],
    ) -> Result<(Vec<u8>, bool)> {
        let mut input = borrowed(message);
        let mut out = OwnedBuffer::empty();
        let mut sealed: c_int = 0;
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live context, an input borrowing the caller's bytes for
        // this call, an out-parameter, and an out buffer released by
        // `OwnedBuffer`.
        let major = unsafe {
            ffi::gss_wrap(
                &mut minor,
                self.raw,
                c_int::from(confidential),
                ffi::GSS_C_QOP_DEFAULT,
                &mut input,
                &mut sealed,
                out.as_mut_ptr(),
            )
        };
        check(major, minor, self.mech.as_ref())?;
        Ok((out.to_vec(), sealed != 0))
    }

    /// Opens a token GSS_Wrap made, as GSS_Unwrap does. A token that was
    /// not made under this context, or was changed, is an error whose
    /// routine is `BAD_SIG` or `DEFECTIVE_TOKEN`.
    pub fn unwrap(&mut self, token: &[u8]) -> Result<Unwrapped> {
        let mut input = borrowed(token);
        let mut out = OwnedBuffer::empty();
        let mut sealed: c_int = 0;
        let mut qop: ffi::gss_qop_t = 0;
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live context, an input borrowing the caller's bytes for
        // this call, two out-parameters, and an out buffer released by
        // `OwnedBuffer`.
        let major = unsafe {
            ffi::gss_unwrap(
                &mut minor,
                self.raw,
                &mut input,
                out.as_mut_ptr(),
                &mut sealed,
                &mut qop,
            )
        };
        check(major, minor, self.mech.as_ref())?;
        Ok(Unwrapped {
            message: out.to_vec(),
            confidential: sealed != 0,
            qop,
        })
    }
}

impl Context {
    /// Appends the checksum of `message` to `out`, the same bytes
    /// [`Context::get_mic`] gives, written into `out` where they will stay.
    /// On an error `out` is as it was.
    pub fn get_mic_into(
        &mut self,
        message: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let mut iov = [
            iov(
                ffi::GSS_IOV_BUFFER_TYPE_DATA,
                message.as_ptr().cast_mut(),
                message.len(),
            ),
            iov(ffi::GSS_IOV_BUFFER_TYPE_MIC_TOKEN, std::ptr::null_mut(), 0),
        ];
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live context, and a list of two descriptors borrowing
        // `message` for this call, of which the query sets lengths alone.
        let major = unsafe {
            ffi::gss_get_mic_iov_length(
                &mut minor,
                self.raw,
                ffi::GSS_C_QOP_DEFAULT,
                iov.as_mut_ptr(),
                2,
            )
        };
        check(major, minor, self.mech.as_ref())?;
        let start = out.len();
        out.resize(start + iov[1].buffer.length, 0);
        iov[1].buffer.value = out[start..].as_mut_ptr().cast();
        // SAFETY: as above, with the checksum descriptor borrowing the new
        // tail of `out`, which has the length the query asked for.
        let major = unsafe {
            ffi::gss_get_mic_iov(
                &mut minor,
                self.raw,
                ffi::GSS_C_QOP_DEFAULT,
                iov.as_mut_ptr(),
                2,
            )
        };
        if let Err(e) = check(major, minor, self.mech.as_ref()) {
            out.truncate(start);
            return Err(e);
        }
        out.truncate(start + iov[1].buffer.length);
        Ok(())
    }

    /// Appends to `out` the checksum of the bytes of `out` in `message`,
    /// which must lie before its end, as [`Context::get_mic_into`] does
    /// for a message held elsewhere, so that a reply signs its own results
    /// without copying them. On an error `out` is as it was.
    pub fn get_mic_within(
        &mut self,
        out: &mut Vec<u8>,
        message: Range<usize>,
    ) -> Result<()> {
        let start = out.len();
        let held = out[message.clone()].len();
        let mut iov = [
            iov(ffi::GSS_IOV_BUFFER_TYPE_DATA, std::ptr::null_mut(), held),
            iov(ffi::GSS_IOV_BUFFER_TYPE_MIC_TOKEN, std::ptr::null_mut(), 0),
        ];
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live context, and a list of two descriptors of which the
        // query reads and sets lengths alone.
        let major = unsafe {
            ffi::gss_get_mic_iov_length(
                &mut minor,
                self.raw,
                ffi::GSS_C_QOP_DEFAULT,
                iov.as_mut_ptr(),
                2,
            )
        };
        check(major, minor, self.mech.as_ref())?;
        out.resize(start + iov[1].buffer.length, 0);
        // Both descriptors point into `out` from one pointer taken after
        // the resize, the message where it lies and the checksum at the
        // new tail.
        let base = out.as_mut_ptr();
        // SAFETY: `message` lies within `out` and the tail has the length
        // the query asked for, and the two do not overlap.
        unsafe {
            iov[0].buffer.value = base.add(message.start).cast();
            iov[1].buffer.value = base.add(start).cast();
        }
        // SAFETY: as above, with the descriptors borrowing `out` for the
        // call.
        let major = unsafe {
            ffi::gss_get_mic_iov(
                &mut minor,
                self.raw,
                ffi::GSS_C_QOP_DEFAULT,
                iov.as_mut_ptr(),
                2,
            )
        };
        if let Err(e) = check(major, minor, self.mech.as_ref()) {
            out.truncate(start);
            return Err(e);
        }
        out.truncate(start + iov[1].buffer.length);
        Ok(())
    }

    /// The bytes a token sealing `message` bytes needs around them, for
    /// [`Context::wrap_in_place`].
    pub fn wrap_lengths(
        &mut self,
        confidential: bool,
        message: usize,
    ) -> Result<WrapLengths> {
        let null = std::ptr::null_mut();
        let mut iov = [
            iov(ffi::GSS_IOV_BUFFER_TYPE_HEADER, null, 0),
            iov(ffi::GSS_IOV_BUFFER_TYPE_DATA, null, message),
            iov(ffi::GSS_IOV_BUFFER_TYPE_PADDING, null, 0),
            iov(ffi::GSS_IOV_BUFFER_TYPE_TRAILER, null, 0),
        ];
        let mut sealed: c_int = 0;
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live context, an out-parameter, and a list of four
        // descriptors of which the query reads and sets lengths alone.
        let major = unsafe {
            ffi::gss_wrap_iov_length(
                &mut minor,
                self.raw,
                c_int::from(confidential),
                ffi::GSS_C_QOP_DEFAULT,
                &mut sealed,
                iov.as_mut_ptr(),
                4,
            )
        };
        check(major, minor, self.mech.as_ref())?;
        Ok(WrapLengths {
            header: iov[0].buffer.length,
            padding: iov[2].buffer.length,
            trailer: iov[3].buffer.length,
        })
    }

    /// Seals the message that lies in `token` after `lengths.header` bytes
    /// and before its last `lengths.padding + lengths.trailer` bytes, in
    /// place, and writes the header, the padding and the trailer around
    /// it, so that `token` becomes what [`Context::wrap`] gives for that
    /// message. `lengths` must be what [`Context::wrap_lengths`] gave for
    /// the message's length under the same `confidential`. Returns whether
    /// the message was encrypted. A token shorter than its lengths is a
    /// calling error.
    pub fn wrap_in_place(
        &mut self,
        confidential: bool,
        lengths: WrapLengths,
        token: &mut [u8],
    ) -> Result<bool> {
        let around = lengths.header + lengths.padding + lengths.trailer;
        let Some(message) = token.len().checked_sub(around) else {
            return Err(Error::synthetic(
                3 << ffi::GSS_C_CALLING_ERROR_OFFSET,
                format!(
                    "a token of {} bytes holds no message under {around} \
                     bytes around it",
                    token.len()
                ),
            ));
        };
        let (header, rest) = token.split_at_mut(lengths.header);
        let (data, rest) = rest.split_at_mut(message);
        let (padding, trailer) = rest.split_at_mut(lengths.padding);
        let mut iov = [
            iov(
                ffi::GSS_IOV_BUFFER_TYPE_HEADER,
                header.as_mut_ptr(),
                header.len(),
            ),
            iov(ffi::GSS_IOV_BUFFER_TYPE_DATA, data.as_mut_ptr(), data.len()),
            iov(
                ffi::GSS_IOV_BUFFER_TYPE_PADDING,
                padding.as_mut_ptr(),
                padding.len(),
            ),
            iov(
                ffi::GSS_IOV_BUFFER_TYPE_TRAILER,
                trailer.as_mut_ptr(),
                trailer.len(),
            ),
        ];
        let mut sealed: c_int = 0;
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live context, an out-parameter, and four descriptors
        // borrowing disjoint parts of `token` for this call, each rewritten
        // within its own length.
        let major = unsafe {
            ffi::gss_wrap_iov(
                &mut minor,
                self.raw,
                c_int::from(confidential),
                ffi::GSS_C_QOP_DEFAULT,
                &mut sealed,
                iov.as_mut_ptr(),
                4,
            )
        };
        check(major, minor, self.mech.as_ref())?;
        Ok(sealed != 0)
    }

    /// Opens a token GSS_Wrap made where it stands, so that no copy of the
    /// message is made. The message then lies inside `token` at the range
    /// returned, and the rest of `token` is spent. A token that was not
    /// made under this context, or was changed, is an error whose routine
    /// is `BAD_SIG` or `DEFECTIVE_TOKEN`.
    pub fn unwrap_in_place(&mut self, token: &mut [u8]) -> Result<Opened> {
        let mut iov = [
            iov(
                ffi::GSS_IOV_BUFFER_TYPE_STREAM,
                token.as_mut_ptr(),
                token.len(),
            ),
            iov(ffi::GSS_IOV_BUFFER_TYPE_DATA, std::ptr::null_mut(), 0),
        ];
        let mut sealed: c_int = 0;
        let mut qop: ffi::gss_qop_t = 0;
        let mut minor: ffi::OM_uint32 = 0;
        // SAFETY: live context, two out-parameters, a descriptor borrowing
        // `token` for this call and rewritten within its length, and a
        // descriptor the library points into `token` or, when it chose to
        // allocate, fills with a copy released below.
        let major = unsafe {
            ffi::gss_unwrap_iov(
                &mut minor,
                self.raw,
                &mut sealed,
                &mut qop,
                iov.as_mut_ptr(),
                2,
            )
        };
        check(major, minor, self.mech.as_ref())?;
        let data = &iov[1];
        let len = data.buffer.length;
        let inside = (data.type_ & ffi::GSS_IOV_BUFFER_FLAG_ALLOCATED == 0)
            .then(|| {
                let start = (data.buffer.value as usize)
                    .checked_sub(token.as_ptr() as usize)?;
                (start.checked_add(len)? <= token.len()).then_some(start)
            })
            .flatten();
        let message = match inside {
            Some(start) => start..start + len,
            None => {
                // The library made a copy, so the message moves to the
                // front of the token, whose bytes are spent, and the copy
                // is released.
                let copied = len.min(token.len());
                // SAFETY: a buffer the library filled with `len` readable
                // bytes, released once with the paired call.
                unsafe {
                    let copy = std::slice::from_raw_parts(
                        data.buffer.value.cast::<u8>(),
                        len,
                    );
                    token[..copied].copy_from_slice(&copy[..copied]);
                    ffi::gss_release_iov_buffer(
                        &mut minor,
                        iov.as_mut_ptr(),
                        2,
                    );
                }
                if copied != len {
                    return Err(Error::synthetic(
                        3 << ffi::GSS_C_CALLING_ERROR_OFFSET,
                        format!(
                            "a message of {len} bytes from a token of {}",
                            token.len()
                        ),
                    ));
                }
                0..len
            }
        };
        Ok(Opened {
            message,
            confidential: sealed != 0,
            qop,
        })
    }
}

/// One descriptor of an in place call.
fn iov(
    kind: ffi::OM_uint32,
    bytes: *mut u8,
    len: usize,
) -> ffi::gss_iov_buffer_desc {
    ffi::gss_iov_buffer_desc {
        type_: kind,
        buffer: ffi::gss_buffer_desc {
            length: len,
            value: bytes.cast(),
        },
    }
}

/// The bytes a sealed token needs around its message, from
/// [`Context::wrap_lengths`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrapLengths {
    /// The bytes before the message.
    pub header: usize,
    /// The bytes after the message and before the trailer.
    pub padding: usize,
    /// The bytes at the end.
    pub trailer: usize,
}

impl WrapLengths {
    /// The length of the token that seals a message of `message` bytes.
    pub fn token_len(&self, message: usize) -> usize {
        self.header + message + self.padding + self.trailer
    }
}

/// What [`Context::unwrap_in_place`] found in a token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Opened {
    /// Where the message now lies in the token.
    pub message: Range<usize>,
    /// Whether the message was encrypted in the token.
    pub confidential: bool,
    /// The quality of protection the token was made under, as the
    /// mechanism numbers it.
    pub qop: u32,
}

/// What [`Context::unwrap`] found in a token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unwrapped {
    /// The message the token carried.
    pub message: Vec<u8>,
    /// Whether the message was encrypted in the token.
    pub confidential: bool,
    /// The quality of protection the token was made under, as the
    /// mechanism numbers it.
    pub qop: u32,
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: an owned context, deleted exactly once; no output token
        // is requested.
        unsafe {
            let mut minor: ffi::OM_uint32 = 0;
            ffi::gss_delete_sec_context(
                &mut minor,
                &mut self.raw,
                std::ptr::null_mut(),
            );
        }
    }
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("source", &self.source)
            .field("mechanism", &self.mech)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}
