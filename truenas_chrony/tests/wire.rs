// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The wire format: requests byte for byte, and replies written out by
//! hand in chronyd 4.6.1's layout, floats encoded from the format's
//! definition.

mod common;

use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{be16, be32, cat, ipv4, ok, status};
use truenas_chrony::{
    Address, Algorithm, AuthMode, Error, Leap, RefId, Request, Result,
    SelectOptions, SelectState, SourceMode, SourceState, Status, Verdict,
};

const SEQ: u32 = 0x0a0b_0c0d;

/// Decode `data` as a successful reply, code `code`, to `request`.
fn answer<T: Debug>(request: &Request<T>, code: u16, data: &[u8]) -> Result<T> {
    decode(request, &ok(request.as_bytes(), code, data))
}

/// Decode `datagram` as the reply to `request`, which it must be.
fn decode<T: Debug>(request: &Request<T>, datagram: &[u8]) -> Result<T> {
    match request.decode(datagram) {
        Verdict::Answer(result) => result,
        Verdict::Unrelated => {
            panic!("a reply to the request read as unrelated")
        }
    }
}

/// Tracking data with the given address, reference, and float fields.
fn tracking_data(
    address: &[u8; 20],
    reference: u32,
    floats: [u32; 9],
) -> Vec<u8> {
    let mut data = cat(&[
        &be32(reference),
        address,
        &be16(3),
        &be16(1),
        &be32(0),
        &be32(1_700_000_000),
        &be32(500),
    ]);
    for f in floats {
        data.extend_from_slice(&be32(f));
    }
    assert_eq!(data.len(), 76);
    data
}

/// The request header: version 6, type 1, two zero bytes, command,
/// attempt, sequence, eight zero bytes. Catches a misplaced field.
#[test]
fn request_header() {
    let request = Request::tracking(SEQ).with_attempt(2);
    let bytes = request.as_bytes();
    assert_eq!(&bytes[..4], &[6, 1, 0, 0]);
    assert_eq!(&bytes[4..6], &[0, 33]);
    assert_eq!(&bytes[6..8], &[0, 2]);
    assert_eq!(&bytes[8..12], &[0x0a, 0x0b, 0x0c, 0x0d]);
    assert_eq!(&bytes[12..20], &[0; 8]);
    assert_eq!(request.sequence(), SEQ);
    assert_eq!(Request::tracking(SEQ).as_bytes()[6..8], [0, 0]);
}

/// Each request's command, data, and length, zero-padded to its reply's
/// (28-byte header plus data). A wrong length loses the report.
#[test]
fn requests_by_command() {
    let v4 = Ipv4Addr::new(192, 0, 2, 1);
    let cases: [(Vec<u8>, u16, usize, Vec<u8>); 5] = [
        (
            Request::tracking(SEQ).as_bytes().to_vec(),
            33,
            28 + 76,
            vec![],
        ),
        (
            Request::source_count(SEQ).as_bytes().to_vec(),
            14,
            28 + 4,
            vec![],
        ),
        (
            Request::source(5, SEQ).as_bytes().to_vec(),
            15,
            28 + 48,
            be32(5).to_vec(),
        ),
        (
            Request::selection(5, SEQ).as_bytes().to_vec(),
            69,
            28 + 48,
            be32(5).to_vec(),
        ),
        (
            Request::authentication(v4, SEQ).as_bytes().to_vec(),
            67,
            28 + 24,
            ipv4(v4.octets()).to_vec(),
        ),
    ];
    for (bytes, command, len, data) in cases {
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), command);
        assert_eq!(bytes.len(), len, "command {command}");
        let (head, padding) = bytes[20..].split_at(data.len());
        assert_eq!(head, &data[..], "command {command}");
        assert!(padding.iter().all(|&b| b == 0), "command {command}");
    }
}

/// A request's address: 16 bytes (IPv4 and identifiers in the first
/// four), the family (1 IPv4, 2 IPv6, 3 identifier, 0 none), two zero
/// bytes. Catches a wrong family or byte order.
#[test]
fn addresses_in_requests() {
    let field = |a: Address| {
        Request::authentication(a, SEQ).as_bytes()[20..40].to_vec()
    };
    assert_eq!(
        field(Ipv4Addr::new(192, 0, 2, 1).into()),
        cat(&[&[192, 0, 2, 1], &[0; 12], &[0, 1], &[0, 0]])
    );
    assert_eq!(
        field("2001:db8::1".parse::<Ipv6Addr>().unwrap().into()),
        cat(&[
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            &[0, 2],
            &[0, 0],
        ])
    );
    assert_eq!(
        field(Address::Id(0x0102_0304)),
        cat(&[&[1, 2, 3, 4], &[0; 12], &[0, 3], &[0, 0]])
    );
    assert_eq!(field(Address::Unspecified), vec![0; 20]);
}

/// In version 6, a datagram replies only as type 2 with zero reserved
/// bytes and the request's command and sequence; anything else is
/// unrelated.
/// Catches another request's reply, or garbage, taken for this one.
#[test]
fn reply_header() {
    let request = Request::tracking(SEQ);
    let good = ok(
        request.as_bytes(),
        5,
        &tracking_data(&ipv4([0; 4]), 0, [0; 9]),
    );
    assert!(matches!(request.decode(&good), Verdict::Answer(Ok(_))));
    let with = |at: usize, value: u8| {
        let mut d = good.clone();
        d[at] = value;
        d
    };
    let unrelated = [
        good[..27].to_vec(),
        Vec::new(),
        with(0, 5),
        with(0, 7),
        with(1, 1),
        with(2, 1),
        with(3, 1),
        with(5, 34),
        with(19, 0x0e),
    ];
    for datagram in unrelated {
        assert!(
            matches!(request.decode(&datagram), Verdict::Unrelated),
            "{datagram:?}"
        );
    }
}

/// The reply header's zero padding is not checked: it carries nothing.
#[test]
fn reply_header_padding_is_ignored() {
    let request = Request::source_count(SEQ);
    let mut datagram = ok(request.as_bytes(), 2, &be32(9));
    datagram[10..16].fill(0xff);
    datagram[20..28].fill(0xff);
    assert_eq!(decode(&request, &datagram).unwrap(), 9);
}

/// Each status code to its status. Catches a table off by one.
#[test]
fn status_codes() {
    let cases: [(u16, Status); 23] = [
        (1, Status::Failed),
        (2, Status::Unauthorized),
        (3, Status::Invalid),
        (4, Status::NoSuchSource),
        (5, Status::InvalidTimestamp),
        (6, Status::NotEnabled),
        (7, Status::BadSubnet),
        (8, Status::AccessAllowed),
        (9, Status::AccessDenied),
        (10, Status::NoHostAccess),
        (11, Status::SourceAlreadyKnown),
        (12, Status::TooManySources),
        (13, Status::NoRtc),
        (14, Status::BadRtcFile),
        (15, Status::Inactive),
        (16, Status::BadSample),
        (17, Status::InvalidAddressFamily),
        (18, Status::BadPacketVersion),
        (19, Status::BadPacketLength),
        (21, Status::InvalidName),
        (20, Status::Unknown(20)),
        (22, Status::Unknown(22)),
        (0xffff, Status::Unknown(0xffff)),
    ];
    let request = Request::tracking(SEQ);
    for (code, expected) in cases {
        match decode(&request, &status(request.as_bytes(), code)) {
            Err(Error::Status(got)) => {
                assert_eq!(got, expected);
                assert_eq!(got.code(), code);
            }
            other => panic!("{code}: {other:?}"),
        }
    }
}

/// The tracking report, every field at its offset.
#[test]
fn tracking() {
    let data = tracking_data(
        &ipv4([192, 0, 2, 1]),
        0xc000_0201,
        [
            0x0280_0000, // 0.5
            0x0580_0000, // -1.0
            0xc880_0000, // 2^-30
            0x06c0_0000, // 3.0
            0x0780_0000, // -2.0
            0x0480_0000, // 1.0
            0x0080_0000, // 0.25
            0xfe80_0000, // 0.125
            0x1080_0000, // 64.0
        ],
    );
    let t = answer(&Request::tracking(SEQ), 5, &data).unwrap();
    assert_eq!(t.reference_id, RefId(0xc000_0201));
    assert_eq!(t.address, Address::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(t.stratum, 3);
    assert_eq!(t.leap, Leap::InsertSecond);
    assert_eq!(
        t.reference_time,
        UNIX_EPOCH + Duration::new(1_700_000_000, 500)
    );
    assert_eq!(t.correction, 0.5);
    assert_eq!(t.last_offset, -1.0);
    assert_eq!(t.rms_offset, 2f64.powi(-30));
    assert_eq!(t.frequency_ppm, 3.0);
    assert_eq!(t.residual_frequency_ppm, -2.0);
    assert_eq!(t.skew_ppm, 1.0);
    assert_eq!(t.root_delay, 0.25);
    assert_eq!(t.root_dispersion, 0.125);
    assert_eq!(t.update_interval, 64.0);
    // Half the root delay plus the root dispersion.
    assert_eq!(t.root_distance(), 0.25);
}

/// chronyd's time is the clock reading plus the correction, later while
/// the clock is behind. Catches the correction applied with the wrong
/// sign.
#[test]
fn corrected_time() {
    let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let last = UNIX_EPOCH + Duration::from_secs(i64::MAX as u64);
    let cases: [(SystemTime, u32, Option<SystemTime>); 4] = [
        (at, 0x0280_0000, Some(at + Duration::from_millis(500))),
        (at, 0x0580_0000, Some(at - Duration::from_secs(1))),
        (at, 0x0000_0000, Some(at)),
        // A second past the last representable one.
        (last, 0x0480_0000, None),
    ];
    let request = Request::tracking(SEQ);
    for (system, raw, expected) in cases {
        let mut floats = [0; 9];
        floats[0] = raw;
        let t = answer(&request, 5, &tracking_data(&ipv4([0; 4]), 0, floats))
            .unwrap();
        assert_eq!(t.corrected(system), expected, "{raw:#010x}");
    }
}

/// The float format: both fields signed, the coefficient unnormalized,
/// both ends of the exponent. Catches an unsigned field or a biased
/// exponent.
#[test]
fn floating_point() {
    let cases: [(u32, f64); 12] = [
        (0x0000_0000, 0.0),
        (0x0480_0000, 1.0),
        (0x0580_0000, -1.0),
        (0x0280_0000, 0.5),
        (0x06c0_0000, 3.0),
        (0xc880_0000, 2f64.powi(-30)),
        // Exponent 0, coefficient 1 and -1.
        (0x0000_0001, 2f64.powi(-25)),
        (0x01ff_ffff, -(2f64.powi(-25))),
        // Exponent 63, the largest and most negative coefficients, and
        // -1: bit 24 is the coefficient's sign.
        (0x7eff_ffff, (2f64.powi(24) - 1.0) * 2f64.powi(38)),
        (0x7f00_0000, -(2f64.powi(62))),
        (0x7fff_ffff, -(2f64.powi(38))),
        // Exponent -64, coefficient 1.
        (0x8000_0001, 2f64.powi(-89)),
    ];
    let request = Request::tracking(SEQ);
    for (raw, value) in cases {
        let mut floats = [0; 9];
        floats[0] = raw;
        let t = answer(&request, 5, &tracking_data(&ipv4([0; 4]), 0, floats))
            .unwrap();
        assert_eq!(t.correction, value, "{raw:#010x}");
    }
}

/// Timestamps: high and low seconds words, then nanoseconds. A high word
/// of 0x7fffffff reads as zero, nanoseconds clamp to 999999999, and a set
/// top bit is before the epoch.
#[test]
fn timestamps() {
    let cases: [(u32, u32, u32, SystemTime); 6] = [
        (0, 0, 0, UNIX_EPOCH),
        (
            0,
            1_700_000_000,
            500,
            UNIX_EPOCH + Duration::new(1_700_000_000, 500),
        ),
        (
            0x7fff_ffff,
            1_700_000_000,
            0,
            UNIX_EPOCH + Duration::new(1_700_000_000, 0),
        ),
        (1, 0, 0, UNIX_EPOCH + Duration::from_secs(1 << 32)),
        (
            0,
            0,
            1_000_000_000,
            UNIX_EPOCH + Duration::from_nanos(999_999_999),
        ),
        (
            0xffff_ffff,
            0xffff_ffff,
            0,
            UNIX_EPOCH - Duration::from_secs(1),
        ),
    ];
    let request = Request::tracking(SEQ);
    for (high, low, nsec, time) in cases {
        let mut data = tracking_data(&ipv4([0; 4]), 0, [0; 9]);
        data[28..40].copy_from_slice(&cat(&[
            &be32(high),
            &be32(low),
            &be32(nsec),
        ]));
        let t = answer(&request, 5, &data).unwrap();
        assert_eq!(t.reference_time, time, "{high:#x} {low:#x} {nsec}");
    }
}

/// An address in a reply, each family; an unknown family code reads as
/// no address.
#[test]
fn addresses_in_replies() {
    let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let cases: [([u8; 20], Address); 5] = [
        (
            ipv4([192, 0, 2, 1]),
            Address::V4(Ipv4Addr::new(192, 0, 2, 1)),
        ),
        (
            cat(&[&v6, &[0, 2], &[0, 0]]).try_into().unwrap(),
            Address::V6("2001:db8::1".parse().unwrap()),
        ),
        (
            cat(&[&[0, 0, 0, 42], &[0; 12], &[0, 3], &[0, 0]])
                .try_into()
                .unwrap(),
            Address::Id(42),
        ),
        ([0; 20], Address::Unspecified),
        (
            cat(&[&[192, 0, 2, 1], &[0; 12], &[0, 9], &[0, 0]])
                .try_into()
                .unwrap(),
            Address::Unspecified,
        ),
    ];
    let request = Request::tracking(SEQ);
    for (field, address) in cases {
        let t = answer(&request, 5, &tracking_data(&field, 0, [0; 9])).unwrap();
        assert_eq!(t.address, address);
    }
}

/// Synchronized means following an NTP source or a reference clock, not
/// a local reference (127.127.1.1) or nothing.
#[test]
fn tracking_synchronization() {
    let cases: [([u8; 20], u32, bool); 4] = [
        (ipv4([192, 0, 2, 1]), 0xc000_0201, true),
        ([0; 20], u32::from_be_bytes(*b"PPS\0"), true),
        ([0; 20], 0x7f7f_0101, false),
        ([0; 20], 0, false),
    ];
    let request = Request::tracking(SEQ);
    for (address, reference, synchronized) in cases {
        let t =
            answer(&request, 5, &tracking_data(&address, reference, [0; 9]))
                .unwrap();
        assert_eq!(t.is_synchronized(), synchronized, "{reference:#x}");
    }
    assert_eq!(RefId::LOCAL, RefId(0x7f7f_0101));
}

/// The source count.
#[test]
fn source_count() {
    assert_eq!(answer(&Request::source_count(SEQ), 2, &be32(5)).unwrap(), 5);
}

/// Source entries for an NTP server and a reference clock, its identifier
/// in the address field; a sample age of all ones means none.
#[test]
fn source() {
    let server = cat(&[
        &ipv4([192, 0, 2, 1]),
        &be16(0xfffe),      // poll -2
        &be16(2),           // stratum
        &be16(0),           // state: selected
        &be16(0),           // mode: server
        &be16(0),           // unused
        &be16(0o377),       // reachability
        &be32(12),          // last sample ago
        &be32(0x0580_0000), // measured offset -1.0
        &be32(0x0280_0000), // adjusted offset 0.5
        &be32(0x0080_0000), // offset error 0.25
    ]);
    assert_eq!(server.len(), 48);
    let s = answer(&Request::source(0, SEQ), 3, &server).unwrap();
    assert_eq!(s.address, Address::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(s.poll, -2);
    assert_eq!(s.stratum, 2);
    assert_eq!(s.state, SourceState::Selected);
    assert_eq!(s.mode, SourceMode::Server);
    assert_eq!(s.reachability, 0o377);
    assert_eq!(s.last_sample_ago, Some(12));
    assert_eq!(s.adjusted_offset, 0.5);
    assert_eq!(s.measured_offset, -1.0);
    assert_eq!(s.offset_error, 0.25);
    assert_eq!(s.refclock_id(), None);

    let refclock = cat(&[
        &ipv4(*b"PPS\0"),
        &be16(4),
        &be16(0),
        &be16(1), // state: unusable
        &be16(2), // mode: reference clock
        &be16(0),
        &be16(0),
        &be32(0xffff_ffff), // no sample yet
        &[0; 12],
    ]);
    let r = answer(&Request::source(1, SEQ), 3, &refclock).unwrap();
    assert_eq!(r.mode, SourceMode::RefClock);
    assert_eq!(r.state, SourceState::Unusable);
    assert_eq!(r.last_sample_ago, None);
    assert_eq!(r.refclock_id(), Some(RefId(0x5050_5300)));
    assert_eq!(r.refclock_id().unwrap().name(), "PPS");
}

/// Source state and mode codes. Catches a table off by one.
#[test]
fn source_codes() {
    let states = [
        (0, SourceState::Selected),
        (1, SourceState::Unusable),
        (2, SourceState::Falseticker),
        (3, SourceState::Jittery),
        (4, SourceState::Combined),
        (5, SourceState::Selectable),
        (6, SourceState::Unknown(6)),
    ];
    let modes = [
        (0, SourceMode::Server),
        (1, SourceMode::Peer),
        (2, SourceMode::RefClock),
        (3, SourceMode::Unknown(3)),
    ];
    let request = Request::source(0, SEQ);
    for (n, (state_code, state)) in states.into_iter().enumerate() {
        let (mode_code, mode) = modes[n % modes.len()];
        let data = cat(&[
            &ipv4([0; 4]),
            &be16(0),
            &be16(0),
            &be16(state_code),
            &be16(mode_code),
            &[0; 20],
        ]);
        let s = answer(&request, 3, &data).unwrap();
        assert_eq!((s.state, s.mode), (state, mode));
    }
}

/// Selection data, with option bits 0x1 noselect, 0x2 prefer, 0x4
/// trust, 0x8 require.
#[test]
fn selection() {
    let data = cat(&[
        &be32(0xc000_0201),
        &ipv4([192, 0, 2, 1]),
        b"*",               // state
        &[1],               // authentication enabled
        &[0],               // leap
        &[0],               // padding
        &be16(0x0002),      // configured options
        &be16(0x000e),      // effective options
        &be32(4),           // last sample ago
        &be32(0x0480_0000), // score 1.0
        &be32(0x0580_0000), // lower limit -1.0
        &be32(0x0280_0000), // upper limit 0.5
    ]);
    assert_eq!(data.len(), 48);
    let s = answer(&Request::selection(0, SEQ), 23, &data).unwrap();
    assert_eq!(s.reference_id, RefId(0xc000_0201));
    assert_eq!(s.address, Address::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(s.state, SelectState::Selected);
    assert!(s.authenticated);
    assert_eq!(s.leap, Leap::Normal);
    assert_eq!(s.configured_options, SelectOptions::PREFER);
    assert_eq!(
        s.effective_options,
        SelectOptions::PREFER | SelectOptions::TRUST | SelectOptions::REQUIRE
    );
    assert_eq!(s.last_sample_ago, Some(4));
    assert_eq!(s.score, 1.0);
    assert_eq!(s.lower_limit, -1.0);
    assert_eq!(s.upper_limit, 0.5);
    assert_eq!(SelectOptions::NOSELECT.bits(), 0x1);
}

/// Selection state characters, each way.
#[test]
fn selection_states() {
    let cases: [(u8, SelectState); 19] = [
        (b'N', SelectState::NoSelect),
        (b'M', SelectState::MissingSamples),
        (b's', SelectState::Unsynchronized),
        (b'r', SelectState::BadStratum),
        (b'd', SelectState::BadDistance),
        (b'~', SelectState::Jittery),
        (b'w', SelectState::WaitsSamples),
        (b'S', SelectState::Stale),
        (b'O', SelectState::Orphan),
        (b'T', SelectState::Untrusted),
        (b'x', SelectState::Falseticker),
        (b'W', SelectState::WaitsSources),
        (b'P', SelectState::NonPreferred),
        (b'U', SelectState::WaitsUpdate),
        (b'D', SelectState::Distant),
        (b'L', SelectState::Outlier),
        (b'+', SelectState::Combined),
        (b'*', SelectState::Selected),
        (b'?', SelectState::Unknown(b'?')),
    ];
    let request = Request::selection(0, SEQ);
    for (code, state) in cases {
        let mut data = vec![0; 48];
        data[24] = code;
        let s = answer(&request, 23, &data).unwrap();
        assert_eq!(s.state, state);
        assert_eq!(s.state.code(), code);
    }
}

/// Authentication data for an NTS source with keys.
#[test]
fn authentication() {
    let data = cat(&[
        &be16(2),    // mode: NTS
        &be16(15),   // algorithm: AES-SIV-CMAC-256
        &be32(3),    // key ID
        &be16(256),  // key bits
        &be16(1),    // NTS-KE attempts
        &be32(1800), // last NTS-KE ago
        &be16(8),    // cookies
        &be16(100),  // cookie length
        &be16(1),    // NAK
        &be16(0),    // padding
    ]);
    assert_eq!(data.len(), 24);
    let a = answer(
        &Request::authentication(Ipv4Addr::new(192, 0, 2, 1), SEQ),
        20,
        &data,
    )
    .unwrap();
    assert_eq!(a.mode, AuthMode::Nts);
    assert_eq!(a.algorithm, Algorithm::AesSivCmac256);
    assert_eq!(a.key_id, 3);
    assert_eq!(a.key_bits, 256);
    assert_eq!(a.ke_attempts, 1);
    assert_eq!(a.last_ke_ago, Some(1800));
    assert_eq!(a.cookies, 8);
    assert_eq!(a.cookie_length, 100);
    assert!(a.nak);
}

/// Authentication modes and algorithm numbers. Without keys the last
/// NTS-KE age reads all ones.
#[test]
fn authentication_codes() {
    let modes = [
        (0, AuthMode::None),
        (1, AuthMode::SymmetricKey),
        (2, AuthMode::Nts),
        (3, AuthMode::Unknown(3)),
    ];
    let algorithms: [(u16, Algorithm); 20] = [
        (0, Algorithm::None),
        (1, Algorithm::Md5),
        (2, Algorithm::Sha1),
        (3, Algorithm::Sha256),
        (4, Algorithm::Sha384),
        (5, Algorithm::Sha512),
        (6, Algorithm::Sha3_224),
        (7, Algorithm::Sha3_256),
        (8, Algorithm::Sha3_384),
        (9, Algorithm::Sha3_512),
        (10, Algorithm::Tiger),
        (11, Algorithm::Whirlpool),
        (13, Algorithm::Aes128),
        (14, Algorithm::Aes256),
        (15, Algorithm::AesSivCmac256),
        (16, Algorithm::AesSivCmac384),
        (17, Algorithm::AesSivCmac512),
        (30, Algorithm::Aes128GcmSiv),
        (31, Algorithm::Aes256GcmSiv),
        (12, Algorithm::Unknown(12)),
    ];
    let request = Request::authentication(Address::Id(1), SEQ);
    for (n, (code, algorithm)) in algorithms.into_iter().enumerate() {
        let (mode_code, mode) = modes[n % modes.len()];
        let data = cat(&[
            &be16(mode_code),
            &be16(code),
            &[0; 8],
            &be32(0xffff_ffff),
            &[0; 8],
        ]);
        let a = answer(&request, 20, &data).unwrap();
        assert_eq!(a.mode, mode);
        assert_eq!(a.algorithm, algorithm);
        assert_eq!(a.algorithm.code(), code);
        assert_eq!(a.last_ke_ago, None);
        assert!(!a.nak);
    }
}

/// A reply shorter than its layout is malformed, for every report.
/// Catches a decoder that reads past the datagram or zero-fills it.
#[test]
fn short_replies_are_malformed() {
    fn short<T: Debug>(request: Request<T>, code: u16, len: usize) {
        let result = answer(&request, code, &vec![0; len - 1]);
        assert!(
            matches!(result, Err(Error::Malformed(_))),
            "code {code}: {result:?}"
        );
    }
    short(Request::tracking(SEQ), 5, 76);
    short(Request::source_count(SEQ), 2, 4);
    short(Request::source(0, SEQ), 3, 48);
    short(Request::selection(0, SEQ), 23, 48);
    short(Request::authentication(Address::Id(1), SEQ), 20, 24);
}

/// How shared values render, and that a reference name keeps printable
/// ASCII only.
#[test]
fn value_rendering() {
    assert_eq!(
        Address::V4(Ipv4Addr::new(192, 0, 2, 1)).to_string(),
        "192.0.2.1"
    );
    assert_eq!(
        Address::V6("2001:db8::1".parse().unwrap()).to_string(),
        "2001:db8::1"
    );
    assert_eq!(Address::Id(42).to_string(), "ID#0000000042");
    assert_eq!(Address::Unspecified.to_string(), "[UNSPEC]");
    assert_eq!(
        Address::from(IpAddr::V6(Ipv6Addr::LOCALHOST)).ip(),
        Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
    );
    assert_eq!(Address::Id(1).ip(), None);
    assert_eq!(RefId(0xc000_0201).to_string(), "C0000201");
    assert_eq!(RefId::from(u32::from_be_bytes(*b"GPS\0")).name(), "GPS");
    assert_eq!(RefId(0x0147_0a50).name(), "GP");
    // Both ends of the printable range: space is kept, 0x7f is not.
    assert_eq!(RefId::from(u32::from_be_bytes(*b"GPS ")).name(), "GPS ");
    assert_eq!(RefId::LOCAL.name(), "");
    assert_eq!(Status::NoSuchSource.to_string(), "source not found (4)");
    assert_eq!(Status::Unknown(20).to_string(), "status 20");
}
