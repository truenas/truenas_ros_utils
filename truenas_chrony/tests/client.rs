// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The client against a scripted daemon: its reply socket, what it
//! sends, how it waits and retries, and how failures surface.

mod common;

use std::io;
use std::net::Ipv4Addr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Fake, be16, be32, cat, ipv4, ok, status};
use truenas_chrony::{Client, Error, Request, Status};

/// Tracking data with the stratum set to `stratum`.
fn tracking_data(stratum: u16) -> Vec<u8> {
    let mut data = vec![0; 76];
    data[24..26].copy_from_slice(&be16(stratum));
    data
}

/// Entries in `dir` other than the daemon's socket.
fn leftovers(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap() != "chronyd.sock")
        .collect()
}

/// The reply socket, `sock` at 0666 in `truenas_chrony.` and sixteen hex
/// digits at 0711, sits beside the daemon's and goes on drop. Catches a
/// socket the daemon cannot write, one others can reach, and leftovers.
#[test]
fn reply_socket() {
    let seen = Arc::new(Mutex::new(None));
    let record = seen.clone();
    let fake = Fake::answering(move |r| {
        let sock = std::fs::symlink_metadata(&r.from).unwrap();
        let dir = std::fs::metadata(r.from.parent().unwrap()).unwrap();
        *record.lock().unwrap() = Some((
            r.from.clone(),
            sock.file_type().is_socket(),
            sock.permissions().mode() & 0o7777,
            dir.permissions().mode() & 0o7777,
        ));
        ok(&r.bytes, 5, &tracking_data(2))
    });
    let mut client = Client::connect(fake.path()).unwrap();
    assert_eq!(client.tracking().unwrap().stratum, 2);
    let (from, is_socket, sock_mode, dir_mode) =
        seen.lock().unwrap().clone().unwrap();
    assert!(is_socket);
    assert_eq!(sock_mode, 0o666);
    assert_eq!(dir_mode, 0o711);
    assert_eq!(from.file_name().unwrap(), "sock");
    let dir = from.parent().unwrap();
    assert_eq!(dir.parent().unwrap(), fake.dir());
    let name = dir.file_name().unwrap().to_str().unwrap();
    let tag = name.strip_prefix("truenas_chrony.").unwrap();
    assert_eq!(tag.len(), 16);
    assert!(tag.bytes().all(|b| b.is_ascii_hexdigit()));

    // A second client gets a directory of its own.
    let other = Client::connect(fake.path()).unwrap();
    assert_eq!(leftovers(fake.dir()).len(), 2);
    drop(other);
    drop(client);
    assert!(leftovers(fake.dir()).is_empty());
}

/// A daemon that is not running: no socket is `NotFound`, a socket
/// nothing is bound to is `ConnectionRefused`. Nothing is left behind.
#[test]
fn absent_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chronyd.sock");
    match Client::connect(&path).unwrap_err() {
        Error::Io(err) => assert_eq!(err.kind(), io::ErrorKind::NotFound),
        other => panic!("{other:?}"),
    }
    drop(UnixDatagram::bind(&path).unwrap());
    match Client::connect(&path).unwrap_err() {
        Error::Io(err) => {
            assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused)
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(leftovers(dir.path()), Vec::<PathBuf>::new());
}

/// The client sends exactly the datagram `Request` builds, with a fresh
/// random sequence number per request.
#[test]
fn sends_what_request_builds() {
    let fake = Fake::answering(|r| status(&r.bytes, 4));
    let mut client = fake.client();
    let _ = client.authentication(Ipv4Addr::new(192, 0, 2, 1));
    let _ = client.authentication(Ipv4Addr::new(192, 0, 2, 1));
    let log = fake.finish();
    for r in &log {
        let seq = u32::from_be_bytes(r.sequence());
        let built = Request::authentication(Ipv4Addr::new(192, 0, 2, 1), seq);
        assert_eq!(r.bytes, built.as_bytes());
    }
    assert_ne!(log[0].sequence(), log[1].sequence());
}

/// An unanswered request is sent again, with the attempt counter raised
/// and a new sequence number.
#[test]
fn retries() {
    let fake = Fake::start(|r, n| match n {
        0 => vec![],
        _ => vec![ok(&r.bytes, 5, &tracking_data(4))],
    });
    let mut client = Client::connect(fake.path()).unwrap();
    client.set_timeout(Duration::from_millis(50));
    assert_eq!(client.tracking().unwrap().stratum, 4);
    let log = fake.finish();
    assert_eq!(log.len(), 2);
    assert_eq!((log[0].attempt(), log[1].attempt()), (0, 1));
    assert_ne!(log[0].sequence(), log[1].sequence());
}

/// A late reply to an earlier transmission is not taken for the current
/// one.
#[test]
fn late_replies_are_ignored() {
    let first = Arc::new(Mutex::new(None));
    let keep = first.clone();
    let fake = Fake::start(move |r, n| match n {
        0 => {
            *keep.lock().unwrap() = Some(r.bytes.clone());
            vec![]
        }
        _ => {
            let earlier = keep.lock().unwrap().clone().unwrap();
            vec![
                ok(&earlier, 5, &tracking_data(9)),
                ok(&r.bytes, 5, &tracking_data(5)),
            ]
        }
    });
    let mut client = Client::connect(fake.path()).unwrap();
    client.set_timeout(Duration::from_millis(50));
    assert_eq!(client.tracking().unwrap().stratum, 5);
}

/// Datagrams that are not the reply leave the client waiting for it.
#[test]
fn unrelated_datagrams_are_skipped() {
    let fake = Fake::start(|r, _| {
        let mut wrong_sequence = ok(&r.bytes, 5, &tracking_data(9));
        wrong_sequence[19] ^= 1;
        let mut wrong_command = ok(&r.bytes, 5, &tracking_data(9));
        wrong_command[5] = 34;
        vec![
            b"garbage".to_vec(),
            wrong_sequence,
            wrong_command,
            ok(&r.bytes, 5, &tracking_data(6)),
        ]
    });
    assert_eq!(fake.client().tracking().unwrap().stratum, 6);
}

/// With no reply, the client gives up after its attempts, each wait
/// double the last.
#[test]
fn timeout() {
    let fake = Fake::start(|_, _| vec![]);
    let mut client = Client::connect(fake.path()).unwrap();
    client.set_timeout(Duration::from_millis(40));
    client.set_attempts(3);
    let start = Instant::now();
    assert!(matches!(client.tracking(), Err(Error::Timeout)));
    assert!(start.elapsed() >= Duration::from_millis(40 + 80 + 160));
    let log = fake.finish();
    let attempts: Vec<u16> = log.iter().map(|r| r.attempt()).collect();
    assert_eq!(attempts, [0, 1, 2]);
}

/// Zero attempts and timeout are raised to one attempt and a millisecond.
#[test]
fn settings_floor() {
    let fake = Fake::start(|_, _| vec![]);
    let mut client = Client::connect(fake.path()).unwrap();
    client.set_attempts(0);
    client.set_timeout(Duration::ZERO);
    assert!(matches!(client.tracking(), Err(Error::Timeout)));
    assert_eq!(fake.finish().len(), 1);
}

/// A source list entry for 192.0.2.`n`.
fn entry(n: u8) -> Vec<u8> {
    cat(&[&ipv4([192, 0, 2, n]), &be16(6), &be16(2), &[0; 24]])
}

/// The addresses `sources` returned.
fn addresses(sources: &[truenas_chrony::Source]) -> Vec<String> {
    sources.iter().map(|s| s.address.to_string()).collect()
}

/// `sources` reads the count, each index, and the count again; a list
/// that holds still is returned as is.
#[test]
fn sources() {
    let fake = Fake::answering(|r| match r.command() {
        14 => ok(&r.bytes, 2, &be32(3)),
        15 => ok(&r.bytes, 3, &entry(r.data()[3] + 1)),
        other => panic!("command {other}"),
    });
    let sources = fake.client().sources().unwrap();
    assert_eq!(addresses(&sources), ["192.0.2.1", "192.0.2.2", "192.0.2.3"]);
    let commands: Vec<u16> =
        fake.finish().iter().map(|r| r.command()).collect();
    assert_eq!(commands, [14, 15, 15, 15, 14]);
}

/// A walk that overlaps a removal or an addition is repeated, not
/// returned short.
#[test]
fn sources_walk_again_when_the_list_changes() {
    // A source is removed while the list is walked: index 2 is gone.
    let walks = Arc::new(Mutex::new(0));
    let seen = walks.clone();
    let fake = Fake::answering(move |r| {
        let mut walks = seen.lock().unwrap();
        match r.command() {
            14 => {
                *walks += 1;
                ok(&r.bytes, 2, &be32(if *walks == 1 { 3 } else { 2 }))
            }
            15 => match (*walks, r.data()[3]) {
                (1, 2) => status(&r.bytes, 4),
                (_, n) => ok(&r.bytes, 3, &entry(n + 1)),
            },
            other => panic!("command {other}"),
        }
    });
    let sources = fake.client().sources().unwrap();
    assert_eq!(addresses(&sources), ["192.0.2.1", "192.0.2.2"]);

    // A source is added while the list is walked: the count moves.
    let counts = Arc::new(Mutex::new(vec![2u32, 3, 3, 3].into_iter()));
    let next = counts.clone();
    let fake = Fake::answering(move |r| match r.command() {
        14 => ok(&r.bytes, 2, &be32(next.lock().unwrap().next().unwrap())),
        15 => ok(&r.bytes, 3, &entry(r.data()[3] + 1)),
        other => panic!("command {other}"),
    });
    let sources = fake.client().sources().unwrap();
    assert_eq!(addresses(&sources), ["192.0.2.1", "192.0.2.2", "192.0.2.3"]);
}

/// A list that changes on every walk is an error after three walks.
#[test]
fn sources_that_never_settle() {
    let count = Arc::new(Mutex::new(0u32));
    let bump = count.clone();
    let fake = Fake::answering(move |r| match r.command() {
        14 => {
            let mut count = bump.lock().unwrap();
            *count += 1;
            ok(&r.bytes, 2, &be32(*count))
        }
        15 => ok(&r.bytes, 3, &entry(r.data()[3] + 1)),
        other => panic!("command {other}"),
    });
    assert!(matches!(fake.client().sources(), Err(Error::Changed)));
    let counts = fake.finish().iter().filter(|r| r.command() == 14).count();
    assert_eq!(counts, 6);
}

/// A failure other than a vanished index is the caller's.
#[test]
fn sources_pass_other_failures() {
    let fake = Fake::answering(|r| match r.command() {
        14 => ok(&r.bytes, 2, &be32(2)),
        _ => status(&r.bytes, 1),
    });
    assert!(matches!(
        fake.client().sources(),
        Err(Error::Status(Status::Failed))
    ));
}

/// A daemon that goes away after the client connected surfaces as an
/// I/O error on the next request, not as a timeout.
#[test]
fn daemon_gone() {
    let fake = Fake::start(|_, _| vec![]);
    let mut client = fake.client();
    let path = fake.path().to_path_buf();
    drop(fake);
    assert!(!path.exists());
    match client.tracking() {
        Err(Error::Io(err)) => assert!(
            matches!(
                err.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ),
            "{err:?}"
        ),
        other => panic!("{other:?}"),
    }
}
