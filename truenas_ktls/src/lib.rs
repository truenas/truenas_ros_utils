// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Kernel TLS for accepted connections.
//!
//! Nothing here implements TLS: the handshake belongs to the system
//! libssl. This crate drives that handshake over a caller's connected
//! socket with kernel TLS enabled, verifies that the kernel installed
//! crypto state in both directions, and refuses the connection when it
//! did not. After [`Acceptor::accept`] returns, plain reads and writes
//! on the socket are encrypted and decrypted by the kernel, and no
//! userspace object stands between the socket and its consumer.
//!
//! ```no_run
//! use std::net::TcpListener;
//! use std::os::fd::AsFd;
//! use truenas_ktls::Acceptor;
//!
//! let acceptor = Acceptor::from_pem_files("cert.pem", "key.pem")?;
//! let listener = TcpListener::bind("0.0.0.0:443")?;
//! let (conn, _) = listener.accept()?;
//! let handshake = acceptor.accept(conn.as_fd())?;
//! // The kernel now carries the connection: this write is encrypted.
//! # use std::io::Write;
//! # let mut conn = conn;
//! conn.write_all(b"hello")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # The socket is the caller's
//!
//! [`Acceptor::accept`] borrows the descriptor and closes nothing. It
//! blocks until the handshake settles, so the caller runs it off any
//! event loop and bounds it with the socket's own timeouts — an elapsed
//! `SO_RCVTIMEO` surfaces as [`Error::Stalled`]. One handshake per
//! connection.
//!
//! # Rotation
//!
//! [`Acceptor`] is `Clone + Send + Sync` over a reference-counted
//! context. Rotating certificates is building a new acceptor and
//! swapping which one the caller hands connections to; a handshake in
//! flight holds its own reference, so nothing tears.
//!
//! # Requirements
//!
//! Building needs `libssl-dev`. Engaging a connection needs a kernel
//! with the `tls` upper-layer protocol and a libssl (3.0 or later) built
//! with kTLS support; where either is absent the handshake completes and
//! [`Acceptor::accept`] refuses the connection as
//! [`Error::NotEngaged`] — plaintext never passes for TLS. Checked
//! against OpenSSL 3.5.

mod acceptor;
mod error;

pub use acceptor::{Acceptor, Handshake};
pub use error::{Error, Result};
