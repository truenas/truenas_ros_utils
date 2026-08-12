// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The accept path against a userspace TLS peer over loopback TCP.
//!
//! Setup and pre-engagement failures run anywhere. The engagement cases
//! — the ones that prove the kernel carries the connection — go through
//! [`common::engaged`], whose skip `TRUENAS_KTLS_REQUIRE_SYSTEM=1`
//! turns into a failure.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::time::Duration;
use truenas_ktls::{Acceptor, Error};

/// An acceptor over fresh material, plus the listener its cases accept
/// from.
fn rig(dir: &std::path::Path, cn: &str) -> (Acceptor, TcpListener) {
    let (cert, key) = common::cert_pair(dir, cn);
    let acceptor = Acceptor::from_pem_files(&cert, &key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    (acceptor, listener)
}

/// Construction must refuse bad material outright — a missing file, a
/// file that is not PEM, and above all a key that does not match the
/// certificate, which would otherwise fail every handshake one
/// connection at a time.
#[test]
fn setup_refuses_bad_material() {
    let dir = tempfile::tempdir().unwrap();

    let missing = dir.path().join("absent.pem");
    let err = Acceptor::from_pem_files(&missing, &missing).unwrap_err();
    assert!(matches!(err, Error::Setup(_)), "got {err:?}");

    let garbage = dir.path().join("garbage.pem");
    std::fs::write(&garbage, b"not a certificate").unwrap();
    let err = Acceptor::from_pem_files(&garbage, &garbage).unwrap_err();
    assert!(matches!(err, Error::Setup(_)), "got {err:?}");

    let (cert_a, _key_a) = common::cert_pair(dir.path(), "alpha");
    let (_cert_b, key_b) = common::cert_pair(dir.path(), "beta");
    let err = Acceptor::from_pem_files(&cert_a, &key_b).unwrap_err();
    assert!(matches!(err, Error::Setup(_)), "got {err:?}");
}

/// The failures that settle before engagement, each classified as the
/// error a consumer routes on: a peer that does not speak TLS, a peer
/// that vanishes, and a peer that connects and goes silent against the
/// socket's own timeout. None of these needs kernel TLS, so they hold
/// everywhere.
#[test]
fn pre_engagement_failures_classify() {
    let dir = tempfile::tempdir().unwrap();
    let (acceptor, listener) = rig(dir.path(), "classify");
    let addr = listener.local_addr().unwrap();

    // Not TLS at all.
    let talker = std::thread::spawn(move || {
        let mut conn = TcpStream::connect(addr).unwrap();
        conn.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        // Hold the socket open until the server has classified; closing
        // early could race the read to an EOF instead.
        let mut sink = Vec::new();
        let _ = conn.read_to_end(&mut sink);
    });
    let (conn, _) = listener.accept().unwrap();
    let err = acceptor.accept(conn.as_fd()).unwrap_err();
    assert!(matches!(err, Error::Handshake(_)), "got {err:?}");
    drop(conn);
    talker.join().unwrap();

    // Connects, then leaves before saying anything.
    let leaver = std::thread::spawn(move || {
        drop(TcpStream::connect(addr).unwrap());
    });
    let (conn, _) = listener.accept().unwrap();
    leaver.join().unwrap();
    let err = acceptor.accept(conn.as_fd()).unwrap_err();
    assert_eq!(err, Error::Disconnected);

    // Connects and goes silent; the socket timeout bounds the wait.
    let holder = TcpStream::connect(addr).unwrap();
    let (conn, _) = listener.accept().unwrap();
    conn.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let err = acceptor.accept(conn.as_fd()).unwrap_err();
    assert_eq!(err, Error::Stalled);
    drop(holder);
}

/// After an accept, plain writes on the descriptor arrive at a
/// userspace TLS peer as ciphertext it can decrypt, and the peer's
/// ciphertext arrives as plain reads — the kernel holds both
/// directions. The handshake summary carries what was negotiated, and
/// the client's server name comes through when sent and stays `None`
/// when not.
#[test]
fn an_accepted_socket_carries_kernel_crypto() {
    let Some(()) = common::engaged() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (acceptor, listener) = rig(dir.path(), "kernel");
    let addr = listener.local_addr().unwrap();

    let client = std::thread::spawn(move || {
        let mut tls =
            common::connect(TcpStream::connect(addr).unwrap(), Some("named"));
        tls.write_all(b"from the client").unwrap();
        let mut plain = [0u8; 15];
        tls.read_exact(&mut plain).unwrap();
        assert_eq!(&plain, b"from the kernel");
    });

    let (mut conn, _) = listener.accept().unwrap();
    let handshake = acceptor.accept(conn.as_fd()).unwrap();
    assert_eq!(handshake.version, "TLSv1.3");
    assert!(!handshake.cipher.is_empty());
    assert_eq!(handshake.server_name.as_deref(), Some("named"));

    // Plain I/O on the socket: the kernel wraps and unwraps the records.
    conn.write_all(b"from the kernel").unwrap();
    let mut plain = [0u8; 15];
    conn.read_exact(&mut plain).unwrap();
    assert_eq!(&plain, b"from the client");
    client.join().unwrap();

    // A client that sends no server name yields none.
    let client = std::thread::spawn(move || {
        common::connect(TcpStream::connect(addr).unwrap(), None);
    });
    let (conn, _) = listener.accept().unwrap();
    let handshake = acceptor.accept(conn.as_fd()).unwrap();
    assert_eq!(handshake.server_name, None);
    client.join().unwrap();
}

/// Rotation is a swap of acceptors, and clones share a context by
/// reference: connections accepted through a clone present the same
/// certificate after the original is dropped, and a second acceptor
/// presents its own.
#[test]
fn rotation_swaps_certificates_without_tearing() {
    let Some(()) = common::engaged() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (old, listener) = rig(dir.path(), "old-cert");
    let addr = listener.local_addr().unwrap();

    let serve = |acceptor: &Acceptor| {
        let client = std::thread::spawn(move || {
            let tls = common::connect(TcpStream::connect(addr).unwrap(), None);
            common::peer_cn(&tls)
        });
        let (conn, _) = listener.accept().unwrap();
        acceptor.accept(conn.as_fd()).unwrap();
        client.join().unwrap()
    };

    assert_eq!(serve(&old), "old-cert");

    // The clone serves on after the original is gone.
    let held = old.clone();
    drop(old);
    assert_eq!(serve(&held), "old-cert");

    // The rotated-in acceptor presents its material, the held one still
    // its own.
    let (cert, key) = common::cert_pair(dir.path(), "new-cert");
    let new = Acceptor::from_pem_files(&cert, &key).unwrap();
    assert_eq!(serve(&new), "new-cert");
    assert_eq!(serve(&held), "old-cert");
}
