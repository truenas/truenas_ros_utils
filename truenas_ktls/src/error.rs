// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Error`] and this crate's [`Result`].

use std::{error, fmt, io};

/// This crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// An error from building an [`Acceptor`](crate::Acceptor) or accepting a
/// connection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The acceptor could not be built: a certificate or key file that is
    /// missing or malformed, or a key that does not match the certificate.
    /// Carries the libssl error-stack text.
    Setup(Box<str>),
    /// The handshake failed at the TLS level: the peer spoke something
    /// other than TLS, or negotiation broke down. Carries the libssl
    /// error-stack text.
    Handshake(Box<str>),
    /// The peer closed the connection before the handshake finished.
    Disconnected,
    /// The handshake stopped waiting for the peer. The wait is bounded by
    /// `SO_RCVTIMEO`/`SO_SNDTIMEO` on the socket, which the caller sets;
    /// a peer that connects and goes silent surfaces here.
    Stalled,
    /// The socket has `O_NONBLOCK` set. The handshake runs as blocking
    /// I/O bounded by the socket's timeouts, so it needs a blocking
    /// descriptor; checked before the handshake starts.
    NonBlocking,
    /// The handshake completed but the kernel holds no TLS crypto state
    /// for this direction, so the socket cannot carry the connection.
    NotEngaged {
        /// `"TX"` or `"RX"`.
        direction: &'static str,
        /// The errno from reading the kernel's record back.
        errno: i32,
    },
    /// A system call under the handshake failed.
    Io {
        /// The call that failed.
        op: &'static str,
        /// Its errno.
        errno: i32,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Setup(text) => {
                write!(f, "Building the TLS context failed: {text}")
            }
            Error::Handshake(text) => {
                write!(f, "TLS handshake failed: {text}")
            }
            Error::Disconnected => {
                f.write_str("Peer disconnected during the TLS handshake")
            }
            Error::Stalled => f.write_str(
                "TLS handshake stopped waiting for the peer \
                 (socket timeout elapsed)",
            ),
            Error::NonBlocking => f.write_str(
                "The socket is non-blocking; the TLS handshake needs a \
                 blocking socket",
            ),
            Error::NotEngaged { direction, errno } => {
                write!(
                    f,
                    "Kernel TLS did not engage for {direction} ({}); \
                     refusing the connection",
                    io::Error::from_raw_os_error(*errno)
                )
            }
            Error::Io { op, errno } => {
                write!(
                    f,
                    "{op} failed during the TLS handshake: {}",
                    io::Error::from_raw_os_error(*errno)
                )
            }
        }
    }
}

impl error::Error for Error {}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        match err {
            // Errno-carrying failures surface as the OS error they are.
            Error::Io { errno, .. } => io::Error::from_raw_os_error(errno),
            Error::Stalled => io::Error::new(io::ErrorKind::TimedOut, err),
            Error::Disconnected => {
                io::Error::new(io::ErrorKind::UnexpectedEof, err)
            }
            Error::Handshake(_) | Error::NotEngaged { .. } => {
                io::Error::new(io::ErrorKind::InvalidData, err)
            }
            Error::NonBlocking => {
                io::Error::new(io::ErrorKind::InvalidInput, err)
            }
            other => io::Error::other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rendering must never panic and must name what failed.
    #[test]
    fn display_renders_every_variant() {
        let setup = Error::Setup("no such file".into()).to_string();
        assert!(setup.contains("no such file"), "{setup}");

        let hs = Error::Handshake("wrong version number".into()).to_string();
        assert!(hs.contains("wrong version number"), "{hs}");

        assert!(!Error::Disconnected.to_string().is_empty());
        assert!(Error::Stalled.to_string().contains("timeout"));
        assert!(Error::NonBlocking.to_string().contains("non-blocking"));

        let ne = Error::NotEngaged {
            direction: "RX",
            errno: libc::ENOPROTOOPT,
        }
        .to_string();
        assert!(ne.contains("RX"), "{ne}");

        let io = Error::Io {
            op: "SSL_accept",
            errno: libc::ENETDOWN,
        }
        .to_string();
        assert!(io.contains("SSL_accept"), "{io}");
    }

    /// The io conversion keeps the classes apart: a timeout must read as
    /// one, and a disconnect as an EOF.
    #[test]
    fn io_error_conversion_keeps_kinds_apart() {
        assert_eq!(
            io::Error::from(Error::Stalled).kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            io::Error::from(Error::Disconnected).kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            io::Error::from(Error::Io {
                op: "getsockopt",
                errno: libc::EBADF,
            })
            .raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(
            io::Error::from(Error::NotEngaged {
                direction: "TX",
                errno: libc::ENOPROTOOPT,
            })
            .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            io::Error::from(Error::Handshake("x".into())).kind(),
            io::ErrorKind::InvalidData
        );
        // Caller misuse, not peer behaviour: it must not read as a
        // timeout or a protocol fault.
        assert_eq!(
            io::Error::from(Error::NonBlocking).kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            io::Error::from(Error::Setup("x".into())).raw_os_error(),
            None
        );
    }
}
