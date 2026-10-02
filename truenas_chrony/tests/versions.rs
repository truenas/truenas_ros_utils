// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Replies from other chronyd releases. A changed layout, a missing
//! command, and a version mismatch must each be an error `is_unsupported`
//! recognizes; additions within a layout must still decode.

mod common;

use std::fmt::Debug;

use common::{be16, be32, cat, ipv4, ok, reply, status};
use truenas_chrony::{
    Address, Algorithm, AuthMode, Error, Leap, Request, Result, SelectOptions,
    SelectState, SourceMode, SourceState, Status, Verdict,
};

const SEQ: u32 = 0x5eed_5eed;

fn decode<T: Debug>(request: &Request<T>, datagram: &[u8]) -> Result<T> {
    match request.decode(datagram) {
        Verdict::Answer(result) => result,
        Verdict::Unrelated => {
            panic!("a reply to the request read as unrelated")
        }
    }
}

/// Status 18 in the daemon's own version, 4 or later, is a version error
/// rather than silence; older versions are not heard.
#[test]
fn version_mismatch() {
    let request = Request::tracking(SEQ);
    let mismatch = |version: u8| {
        let mut datagram = status(request.as_bytes(), 18);
        datagram[0] = version;
        datagram
    };
    for version in [4, 5, 7, 255] {
        let err = decode(&request, &mismatch(version)).unwrap_err();
        assert!(matches!(err, Error::Version(v) if v == version), "{err:?}");
        assert!(err.is_unsupported());
    }
    assert!(matches!(request.decode(&mismatch(3)), Verdict::Unrelated));
    // Any other status in another version is not a reply.
    let mut other = status(request.as_bytes(), 3);
    other[0] = 5;
    assert!(matches!(request.decode(&other), Verdict::Unrelated));
    // Status 18 in version 6 is a status like any other.
    let err = decode(&request, &status(request.as_bytes(), 18)).unwrap_err();
    assert!(matches!(err, Error::Status(Status::BadPacketVersion)));
    assert!(err.is_unsupported());
}

/// A reply code not read for the request is unexpected, a success with
/// no data (code 1) included.
#[test]
fn unknown_layouts() {
    fn unexpected<T: Debug>(request: Request<T>, code: u16) {
        let err = decode(&request, &ok(request.as_bytes(), code, &[0; 128]))
            .unwrap_err();
        assert!(
            matches!(err, Error::UnexpectedReply(c) if c == code),
            "{err:?}"
        );
        assert!(err.is_unsupported());
    }
    unexpected(Request::tracking(SEQ), 99);
    unexpected(Request::authentication(Address::Id(1), SEQ), 27);
    unexpected(Request::source(0, SEQ), 1);
    // Another report's code is not this one's.
    unexpected(Request::selection(0, SEQ), 3);
}

/// An unknown command (3) and a too-short request (19) are unsupported;
/// other refusals are not.
#[test]
fn refusals_by_revision() {
    let request = Request::selection(0, SEQ);
    for (code, unsupported) in [
        (3, true),
        (19, true),
        (1, false),
        (2, false),
        (4, false),
        (6, false),
        (13, false),
        (15, false),
    ] {
        let err =
            decode(&request, &status(request.as_bytes(), code)).unwrap_err();
        assert_eq!(err.is_unsupported(), unsupported, "status {code}");
    }
    assert!(!Error::Timeout.is_unsupported());
    assert!(!Error::Changed.is_unsupported());
    assert!(!Error::Malformed("x").is_unsupported());
}

/// Codes added within a layout are kept, not refused.
#[test]
fn unknown_codes_are_kept() {
    let request = Request::source(0, SEQ);
    let data = cat(&[
        &ipv4([192, 0, 2, 1]),
        &be16(0),
        &be16(1),
        &be16(9),
        &be16(7),
        &[0; 20],
    ]);
    let s = decode(&request, &ok(request.as_bytes(), 3, &data)).unwrap();
    assert_eq!(s.state, SourceState::Unknown(9));
    assert_eq!(s.mode, SourceMode::Unknown(7));
    assert_eq!(s.stratum, 1);

    let request = Request::tracking(SEQ);
    let mut data = vec![0; 76];
    data[26..28].copy_from_slice(&be16(4));
    let t = decode(&request, &ok(request.as_bytes(), 5, &data)).unwrap();
    assert_eq!(t.leap, Leap::Unknown(4));

    let request = Request::selection(0, SEQ);
    let mut data = vec![0; 48];
    data[24] = b'Q';
    data[28..30].copy_from_slice(&be16(0x0031));
    let s = decode(&request, &ok(request.as_bytes(), 23, &data)).unwrap();
    assert_eq!(s.state, SelectState::Unknown(b'Q'));
    assert_eq!(s.configured_options.bits(), 0x0031);
    assert!(s.configured_options.contains(SelectOptions::NOSELECT));

    let request = Request::authentication(Address::Id(1), SEQ);
    let data = cat(&[&be16(3), &be16(99), &[0; 20]]);
    let a = decode(&request, &ok(request.as_bytes(), 20, &data)).unwrap();
    assert_eq!(a.mode, AuthMode::Unknown(3));
    assert_eq!(a.algorithm, Algorithm::Unknown(99));
}

/// Padding is not read, whatever it holds, and a reply longer than its
/// layout is read to the layout's end.
#[test]
fn padding_and_trailing_bytes() {
    let request = Request::authentication(Address::Id(1), SEQ);
    let mut data = cat(&[&be16(2), &be16(15), &[0; 18], &[0x5a, 0x5a]]);
    data.extend_from_slice(&[0xa5; 40]);
    let a = decode(&request, &ok(request.as_bytes(), 20, &data)).unwrap();
    assert_eq!(a.mode, AuthMode::Nts);
    assert!(!a.nak);

    let request = Request::source_count(SEQ);
    let datagram =
        cat(&[&reply(request.as_bytes(), 2, 0, &be32(3)), &[0xff; 8]]);
    assert_eq!(decode(&request, &datagram).unwrap(), 3);
}
