// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Acceptor`]: context construction, the accept path, and the
//! engagement check.
//!
//! # Safety
//!
//! - The handshake runs over a socket BIO created with `BIO_NOCLOSE`, so
//!   the BIO never owns or closes the caller's descriptor. Freeing the
//!   `SSL` frees the BIO; the kernel's TLS state stays on the socket.
//! - Raw libssl calls are made on pointers obtained from live safe
//!   wrappers, under the signatures `openssl-sys` declares.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use foreign_types::ForeignType;
use openssl::error::ErrorStack;
use openssl::ssl::{
    NameType, Ssl, SslAcceptor, SslFiletype, SslMethod, SslOptions,
};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::os::raw::c_int;
use std::path::Path;
use std::{fmt, io};

/// `BIO_new_socket` close flag: the BIO does not own or close the fd.
const BIO_NOCLOSE: c_int = 0;

/// `SSL_OP_ENABLE_KTLS` = `SSL_OP_BIT(3)`; the `openssl` crate names no
/// constant for it.
const SSL_OP_ENABLE_KTLS: u64 = 1 << 3;

/// `SSL_R_UNEXPECTED_EOF_WHILE_READING` from `<openssl/sslerr.h>`;
/// `openssl-sys` exports no SSL reason codes.
const SSL_R_UNEXPECTED_EOF: c_int = 294;

/// A TLS server context that accepts connections onto kernel TLS.
///
/// Cloning shares the underlying context by reference count, and an
/// accept in flight keeps its context alive on its own: certificate
/// rotation is building a new acceptor and swapping which one the
/// caller uses, with nothing torn mid-handshake.
#[derive(Clone)]
pub struct Acceptor {
    inner: SslAcceptor,
}

impl fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Acceptor").finish_non_exhaustive()
    }
}

/// What an accepted handshake negotiated. Data only: by the time this
/// exists, no userspace object stands between the socket and its consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Handshake {
    /// The negotiated protocol version, e.g. `"TLSv1.3"`.
    pub version: String,
    /// The negotiated cipher suite's name.
    pub cipher: String,
    /// The server name the client sent, when it sent one.
    pub server_name: Option<String>,
}

impl Acceptor {
    /// Build an acceptor from a PEM certificate chain and private key.
    ///
    /// The context asks libssl to install kernel TLS when a handshake
    /// completes; [`accept`](Acceptor::accept) verifies per connection
    /// that it did. The key must match the certificate, checked at
    /// construction. Session tickets are disabled: nothing retains the
    /// session state resumption would need.
    pub fn from_pem_files(
        cert_chain: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> Result<Acceptor> {
        let mut builder =
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
                .map_err(setup)?;
        builder
            .set_certificate_chain_file(cert_chain.as_ref())
            .map_err(setup)?;
        builder
            .set_private_key_file(key.as_ref(), SslFiletype::PEM)
            .map_err(setup)?;
        builder.check_private_key().map_err(setup)?;
        builder.set_num_tickets(0).map_err(setup)?;
        builder.set_options(SslOptions::from_bits_retain(SSL_OP_ENABLE_KTLS));
        Ok(Acceptor {
            inner: builder.build(),
        })
    }

    /// Run the server handshake on a connected socket and hand the
    /// connection to the kernel.
    ///
    /// Blocks until the handshake settles; the caller bounds the wait
    /// with `SO_RCVTIMEO`/`SO_SNDTIMEO` on the socket, and an elapsed
    /// timeout surfaces as [`Error::Stalled`]. On success the kernel
    /// encrypts and decrypts the socket from here on — plain reads and
    /// writes on the descriptor carry the connection — and nothing of
    /// this call remains to release. The connection is refused with
    /// [`Error::NotEngaged`] unless the kernel holds crypto state in
    /// both directions.
    ///
    /// One handshake per connection. TLS control records after the
    /// handshake — the close alert included — are the caller's, sent
    /// through the kernel's own record interface.
    pub fn accept(&self, fd: BorrowedFd<'_>) -> Result<Handshake> {
        let ssl = Ssl::new(self.inner.context())
            .map_err(|err| Error::Handshake(stack_text(&err)))?;
        let raw = fd.as_raw_fd();
        // SAFETY: `raw` is a live descriptor for the borrow's duration,
        // and BIO_NOCLOSE keeps the BIO from ever closing it. `SSL_set_bio`
        // hands the BIO's one reference to the SSL, which frees it.
        let rc = unsafe {
            let bio = openssl_sys::BIO_new_socket(raw, BIO_NOCLOSE);
            if bio.is_null() {
                return Err(Error::Handshake(drain_stack()));
            }
            openssl_sys::SSL_set_bio(ssl.as_ptr(), bio, bio);
            openssl_sys::SSL_accept(ssl.as_ptr())
        };
        // errno first: it belongs to the call just made, and the
        // classification below must not read one a later call replaced.
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if rc <= 0 {
            // SAFETY: a live SSL and the return value of its own accept.
            let code = unsafe { openssl_sys::SSL_get_error(ssl.as_ptr(), rc) };
            return Err(classify(code, errno));
        }
        confirm_engaged(raw)?;
        Ok(Handshake {
            version: ssl.version_str().to_owned(),
            cipher: ssl
                .current_cipher()
                .map(|cipher| cipher.name().to_owned())
                .unwrap_or_default(),
            server_name: ssl.servername(NameType::HOST_NAME).map(str::to_owned),
        })
    }
}

/// A context-construction failure, with the error-stack text.
fn setup(err: ErrorStack) -> Error {
    Error::Setup(stack_text(&err))
}

/// The text of an already-drained error stack.
fn stack_text(err: &ErrorStack) -> Box<str> {
    let text = err.to_string();
    if text.is_empty() {
        Box::from("libssl reported no detail")
    } else {
        text.into_boxed_str()
    }
}

/// Drain this thread's libssl error queue into text.
fn drain_stack() -> Box<str> {
    stack_text(&ErrorStack::get())
}

/// Classify a failed `SSL_accept` from its `SSL_get_error` code and the
/// errno captured at the call.
fn classify(code: c_int, errno: i32) -> Error {
    match code {
        // On a blocking socket, want-read/want-write only ever means the
        // socket timeout elapsed mid-wait.
        openssl_sys::SSL_ERROR_WANT_READ
        | openssl_sys::SSL_ERROR_WANT_WRITE => Error::Stalled,
        openssl_sys::SSL_ERROR_ZERO_RETURN => Error::Disconnected,
        openssl_sys::SSL_ERROR_SYSCALL => match errno {
            // EOF arrives with no errno; a reset or a broken pipe is
            // also the peer vanishing.
            0 | libc::ECONNRESET | libc::EPIPE => Error::Disconnected,
            errno => Error::Io {
                op: "SSL_accept",
                errno,
            },
        },
        _ => {
            let stack = ErrorStack::get();
            // libssl reports a peer that vanished mid-handshake as an
            // SSL-level error, not a syscall EOF; the reason code is its
            // stable name.
            if stack
                .errors()
                .iter()
                .any(|err| err.reason_code() == SSL_R_UNEXPECTED_EOF)
            {
                Error::Disconnected
            } else {
                Error::Handshake(stack_text(&stack))
            }
        }
    }
}

/// Refuse unless the kernel holds TLS crypto state for both directions
/// on `fd`. The option alone is a request; this readback is the fact.
fn confirm_engaged(fd: RawFd) -> Result<()> {
    for (option, direction) in [(libc::TLS_TX, "TX"), (libc::TLS_RX, "RX")] {
        // The fixed header of the kernel's crypto-info record: version
        // and cipher, enough to prove state is installed.
        let mut info = [0u8; 4];
        let mut len = info.len() as libc::socklen_t;
        // SAFETY: `getsockopt` writes at most `len` bytes into `info`
        // and updates `len`.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_TLS,
                option,
                info.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(Error::NotEngaged {
                direction,
                errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// The engagement check must refuse a socket the kernel holds no TLS
    /// state for, naming the transmit direction it checks first. This is
    /// the fail-closed core: without it, a handshake whose kTLS request
    /// was silently ignored would hand over a socket that transmits
    /// plaintext.
    #[test]
    fn a_plain_socket_is_not_engaged() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap());
        let (server, _) = listener.accept().unwrap();
        drop(client);

        match confirm_engaged(server.as_raw_fd()) {
            Err(Error::NotEngaged { direction, errno }) => {
                assert_eq!(direction, "TX");
                assert_ne!(errno, 0);
            }
            other => panic!("expected NotEngaged, got {other:?}"),
        }
    }

    /// The classification contract, written out: each `SSL_get_error`
    /// code lands on the error a consumer routes on.
    #[test]
    fn classification_matches_the_contract() {
        assert_eq!(
            classify(openssl_sys::SSL_ERROR_WANT_READ, 0),
            Error::Stalled
        );
        assert_eq!(
            classify(openssl_sys::SSL_ERROR_WANT_WRITE, 0),
            Error::Stalled
        );
        assert_eq!(
            classify(openssl_sys::SSL_ERROR_ZERO_RETURN, 0),
            Error::Disconnected
        );
        assert_eq!(
            classify(openssl_sys::SSL_ERROR_SYSCALL, 0),
            Error::Disconnected
        );
        assert_eq!(
            classify(openssl_sys::SSL_ERROR_SYSCALL, libc::ECONNRESET),
            Error::Disconnected
        );
        assert_eq!(
            classify(openssl_sys::SSL_ERROR_SYSCALL, libc::EPIPE),
            Error::Disconnected
        );
        assert_eq!(
            classify(openssl_sys::SSL_ERROR_SYSCALL, libc::ENETDOWN),
            Error::Io {
                op: "SSL_accept",
                errno: libc::ENETDOWN,
            }
        );
        assert!(matches!(
            classify(openssl_sys::SSL_ERROR_SSL, 0),
            Error::Handshake(_)
        ));
    }
}
