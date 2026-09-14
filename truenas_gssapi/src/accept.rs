// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Acceptor`]: the accept-side security context and its step loop.
#![allow(unsafe_code)]

use crate::buf::{OwnedBuffer, borrowed};
use crate::cred::AcceptorCred;
use crate::error::Result;
use crate::ffi;
use crate::name::Name;
use crate::oid::Oid;

bitflags::bitflags! {
    /// Flags a completed context reports (RFC 2744 §3.7's `ret_flags`).
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    pub struct ContextFlags: u32 {
        /// The initiator delegated credentials.
        const DELEGATED = ffi::GSS_C_DELEG_FLAG;
        /// The initiator authenticated the acceptor in turn.
        const MUTUAL = ffi::GSS_C_MUTUAL_FLAG;
        /// Replay detection is active for per-message tokens.
        const REPLAY = ffi::GSS_C_REPLAY_FLAG;
        /// Sequencing is enforced for per-message tokens.
        const SEQUENCE = ffi::GSS_C_SEQUENCE_FLAG;
        /// Confidentiality is available.
        const CONF = ffi::GSS_C_CONF_FLAG;
        /// Integrity is available.
        const INTEG = ffi::GSS_C_INTEG_FLAG;
        /// The initiator is anonymous.
        const ANON = ffi::GSS_C_ANON_FLAG;
        /// Per-message protection is ready before the context completes.
        const PROT_READY = ffi::GSS_C_PROT_READY_FLAG;
        /// The context may be exported and imported elsewhere.
        const TRANS = ffi::GSS_C_TRANS_FLAG;

        // A mechanism may set flags this build does not name.
        const _ = !0;
    }
}

/// One outcome of feeding a token to the acceptor.
#[derive(Debug)]
pub enum Step {
    /// The handshake needs another leg: send these bytes to the initiator
    /// and feed its reply back to [`Acceptor::step`]. A `Negotiate`
    /// endpoint returns them in a `WWW-Authenticate: Negotiate <base64>`
    /// challenge.
    Continue {
        /// The token to send the initiator; never empty on a continue.
        token: Vec<u8>,
    },
    /// The context is established. `token`, when non-empty, is the final
    /// leg still owed to the initiator (mutual authentication). The
    /// established identity is read from the [`Acceptor`].
    Complete {
        /// The final token owed to the initiator, or empty when none is.
        token: Vec<u8>,
    },
}

/// An accept-side security context, stepped one token at a time.
///
/// Kerberos completes in a single step; SPNEGO may take an extra leg to
/// settle the mechanism. Either way the loop is the same: feed the
/// initiator's token, send back any token the step yields, and stop when
/// the step completes.
pub struct Acceptor<'cred> {
    cred: &'cred AcceptorCred,
    context: ffi::gss_ctx_id_t,
    established: bool,
    source: Option<Name>,
    mech: Option<Oid>,
    flags: ContextFlags,
}

impl<'cred> Acceptor<'cred> {
    /// Start an acceptor against a credential (see
    /// [`AcceptorCred::acquire`]).
    pub fn new(cred: &'cred AcceptorCred) -> Acceptor<'cred> {
        Acceptor {
            cred,
            context: std::ptr::null_mut(),
            established: false,
            source: None,
            mech: None,
            flags: ContextFlags::empty(),
        }
    }

    /// Feed one initiator token.
    ///
    /// On failure this returns `Err` and drops any error token the mechanism
    /// produced: a `Negotiate` endpoint answers a rejected exchange with an
    /// HTTP status, not a further token, so the token is not relayed.
    ///
    /// Calling again after [`Step::Complete`] is a usage error the library
    /// reports, not a panic here.
    pub fn step(&mut self, token: &[u8]) -> Result<Step> {
        let mut input = borrowed(token);
        let mut out = OwnedBuffer::empty();
        let mut src: ffi::gss_name_t = std::ptr::null_mut();
        let mut mech: ffi::gss_OID = std::ptr::null_mut();
        let mut ret_flags: ffi::OM_uint32 = 0;
        let mut minor: ffi::OM_uint32 = 0;

        // SAFETY: the context handle is null on the first call and owned by
        // this value afterwards; input borrows the caller's token; the out
        // token is released by `OwnedBuffer`; src/mech are library-owned
        // outputs handled below. No channel bindings, no delegation
        // out-parameter.
        let major = unsafe {
            ffi::gss_accept_sec_context(
                &mut minor,
                &mut self.context,
                self.cred.raw(),
                &mut input,
                std::ptr::null_mut(),
                &mut src,
                &mut mech,
                out.as_mut_ptr(),
                &mut ret_flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        // The source name is owned by us when set; wrap it before any
        // error return so it cannot leak.
        if !src.is_null() {
            self.source = Some(Name::from_raw(src));
        }
        // `mech` points at a static the library owns; copy, never free.
        // SAFETY: null or a static descriptor the library keeps.
        if let Some(oid) = unsafe { Oid::from_raw(mech) } {
            self.mech = Some(oid);
        }

        // `check` renders any failure's minor status under the mechanism
        // just settled; on success it yields the supplementary bits.
        let supplementary =
            crate::error::check(major, minor, self.mech.as_ref())?;

        self.flags = ContextFlags::from_bits_retain(ret_flags);
        if supplementary & ffi::GSS_S_CONTINUE_NEEDED != 0 {
            Ok(Step::Continue {
                token: out.to_vec(),
            })
        } else {
            self.established = true;
            Ok(Step::Complete {
                token: out.to_vec(),
            })
        }
    }

    /// Whether the context is established.
    pub fn is_established(&self) -> bool {
        self.established
    }

    /// The authenticated initiator, once established — `None` mid-handshake,
    /// so a caller cannot read an identity the exchange has not yet proven.
    /// This is the name to map to a local account with
    /// [`Name::localname`](crate::Name::localname).
    pub fn source_name(&self) -> Option<&Name> {
        self.established.then_some(self.source.as_ref()).flatten()
    }

    /// The mechanism that settled the context (Kerberos, once SPNEGO has
    /// negotiated it).
    pub fn mechanism(&self) -> Option<&Oid> {
        self.mech.as_ref()
    }

    /// The flags the established context reports.
    pub fn flags(&self) -> ContextFlags {
        self.flags
    }
}

impl Drop for Acceptor<'_> {
    fn drop(&mut self) {
        if self.context.is_null() {
            return;
        }
        // SAFETY: a context this value established or partly established,
        // deleted exactly once; no output token is requested.
        unsafe {
            let mut minor: ffi::OM_uint32 = 0;
            ffi::gss_delete_sec_context(
                &mut minor,
                &mut self.context,
                std::ptr::null_mut(),
            );
        }
    }
}

impl std::fmt::Debug for Acceptor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Acceptor")
            .field("established", &self.established)
            .field("mechanism", &self.mech)
            .finish_non_exhaustive()
    }
}
