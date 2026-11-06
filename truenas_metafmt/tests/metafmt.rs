// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The bytes of the record, written out by hand from the XDR definition in
//! the crate documentation, and each comparison result.
//!
//! Order of the fields in version 1: magic, version, filename_charset,
//! smb_sfm_normalized, streams present and, behind that, stream_prefix,
//! stream_suffix, stream_extra_null.

use truenas_metafmt::{
    Error, FILENAME_CHARSET_MAX, MAGIC, MetaFmt, STREAM_AFFIX_MAX,
    StreamFormat, VERSION, Verdict, XATTR_NAME,
};
use truenas_xdr::Error as XdrError;

const SUFFIXED: &[u8] = b"TNMF\0\0\0\x01\
    \0\0\0\x05UTF-8\0\0\0\
    \0\0\0\0\
    \0\0\0\x01\
    \0\0\0\x0fuser.DosStream.\0\
    \0\0\0\x06:$DATA\0\0\
    \0\0\0\x01";

const BARE: &[u8] = b"TNMF\0\0\0\x01\
    \0\0\0\x05UTF-8\0\0\0\
    \0\0\0\x01\
    \0\0\0\x01\
    \0\0\0\x05user.\0\0\0\
    \0\0\0\0\
    \0\0\0\0";

const NO_STREAMS: &[u8] = b"TNMF\0\0\0\x01\
    \0\0\0\x05UTF-8\0\0\0\
    \0\0\0\0\
    \0\0\0\0";

fn suffixed() -> MetaFmt {
    MetaFmt {
        filename_charset: "UTF-8".to_owned(),
        smb_sfm_normalized: false,
        streams: Some(StreamFormat {
            stream_prefix: "user.DosStream.".to_owned(),
            stream_suffix: ":$DATA".to_owned(),
            stream_extra_null: true,
        }),
    }
}

fn bare() -> MetaFmt {
    MetaFmt {
        filename_charset: "UTF-8".to_owned(),
        smb_sfm_normalized: true,
        streams: Some(StreamFormat {
            stream_prefix: "user.".to_owned(),
            stream_suffix: String::new(),
            stream_extra_null: false,
        }),
    }
}

fn no_streams() -> MetaFmt {
    MetaFmt {
        filename_charset: "UTF-8".to_owned(),
        smb_sfm_normalized: false,
        streams: None,
    }
}

fn samples() -> [(MetaFmt, &'static [u8]); 3] {
    [
        (suffixed(), SUFFIXED),
        (bare(), BARE),
        (no_streams(), NO_STREAMS),
    ]
}

/// `bytes` with the byte at `at` replaced.
fn with_byte(bytes: &[u8], at: usize, value: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] = value;
    out
}

/// `bytes` with the four bytes at `at` replaced by `value`.
fn with_u32(bytes: &[u8], at: usize, value: u32) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at..at + 4].copy_from_slice(&value.to_be_bytes());
    out
}

// Each of these would orphan the records already on disk if it changed.
#[test]
fn the_names_on_disk_are_fixed() {
    assert_eq!(XATTR_NAME, "trusted.truenas_metafmt");
    assert_eq!(&MAGIC.to_be_bytes(), b"TNMF");
    assert_eq!(VERSION, 1);
    assert_eq!(FILENAME_CHARSET_MAX, 64);
    assert_eq!(STREAM_AFFIX_MAX, 255);
}

// Catches a change to the wire layout, which needs a new version.
#[test]
fn a_record_has_the_bytes_of_the_definition() {
    for (fmt, bytes) in samples() {
        assert_eq!(fmt.pack().unwrap(), bytes, "{fmt}");
        assert_eq!(MetaFmt::unpack(bytes).unwrap(), fmt, "{fmt}");
    }
}

// Catches a value cut short being read as a shorter record.
#[test]
fn a_truncated_record_is_refused() {
    for (fmt, bytes) in samples() {
        for len in 0..bytes.len() {
            assert!(
                matches!(
                    MetaFmt::unpack(&bytes[..len]),
                    Err(Error::Xdr(XdrError::Eof { .. }))
                ),
                "{fmt}: {len} bytes"
            );
        }
    }
}

#[test]
fn bytes_after_the_record_are_refused() {
    for (_, bytes) in samples() {
        let mut longer = bytes.to_vec();
        longer.extend_from_slice(&[0; 4]);
        assert_eq!(
            MetaFmt::unpack(&longer),
            Err(Error::Xdr(XdrError::TrailingBytes { rest: 4 }))
        );
    }
}

#[test]
fn another_magic_is_not_a_record() {
    assert_eq!(
        MetaFmt::unpack(&with_byte(SUFFIXED, 0, b'X')),
        Err(Error::NotARecord)
    );
}

#[test]
fn version_0_is_not_a_record() {
    assert_eq!(
        MetaFmt::unpack(&with_u32(SUFFIXED, 4, 0)),
        Err(Error::NotARecord)
    );
}

// A later version may lay out its body in any way, so the version must be
// reported before any of the body is read.
#[test]
fn a_later_version_is_reported_whatever_follows_it() {
    for version in [2, 0x8000_0000, u32::MAX] {
        let record = with_u32(SUFFIXED, 4, version);
        assert_eq!(MetaFmt::unpack(&record), Err(Error::NewerVersion(version)));
        assert_eq!(
            MetaFmt::unpack(&record[..8]),
            Err(Error::NewerVersion(version))
        );
    }
}

// Catches a decode that lets a second encoding of the same settings through.
#[test]
fn only_what_pack_writes_is_read() {
    for (at, value, want) in [
        (19, 1, XdrError::NonZeroPadding),
        (47, 1, XdrError::NonZeroPadding),
        (59, 1, XdrError::NonZeroPadding),
        (23, 2, XdrError::InvalidBool { value: 2 }),
        (27, 2, XdrError::InvalidBool { value: 2 }),
        (63, 2, XdrError::InvalidBool { value: 2 }),
        (14, 0, XdrError::EmbeddedNul),
        (34, 0, XdrError::EmbeddedNul),
        (54, 0, XdrError::EmbeddedNul),
        (14, 0xff, XdrError::Utf8),
        (34, 0xff, XdrError::Utf8),
        (54, 0xff, XdrError::Utf8),
    ] {
        assert_eq!(
            MetaFmt::unpack(&with_byte(SUFFIXED, at, value)),
            Err(Error::Xdr(want)),
            "byte {at} = {value}"
        );
    }
}

#[test]
fn a_length_over_its_bound_is_refused_when_read() {
    for (at, len, max) in [(8, 65, 64), (28, 256, 255), (48, 256, 255)] {
        assert_eq!(
            MetaFmt::unpack(&with_u32(SUFFIXED, at, len)),
            Err(Error::Xdr(XdrError::TooLong {
                len: len as usize,
                max,
            })),
            "length at {at}"
        );
    }
}

/// `suffixed()` with its three strings set to the lengths given.
fn with_lengths(charset: usize, prefix: usize, suffix: usize) -> MetaFmt {
    MetaFmt {
        filename_charset: "c".repeat(charset),
        smb_sfm_normalized: false,
        streams: Some(StreamFormat {
            stream_prefix: "p".repeat(prefix),
            stream_suffix: "s".repeat(suffix),
            stream_extra_null: true,
        }),
    }
}

#[test]
fn a_string_at_its_bound_is_written_and_read() {
    let fmt = with_lengths(64, 255, 255);
    assert_eq!(MetaFmt::unpack(&fmt.pack().unwrap()), Ok(fmt));
}

#[test]
fn a_string_over_its_bound_is_refused_when_written() {
    for (fmt, len, max) in [
        (with_lengths(65, 255, 255), 65, 64),
        (with_lengths(64, 256, 255), 256, 255),
        (with_lengths(64, 255, 256), 256, 255),
    ] {
        assert_eq!(fmt.pack(), Err(Error::Xdr(XdrError::TooLong { len, max })));
    }
}

// Catches a record that is written and can then never be read.
#[test]
fn a_string_with_a_nul_is_refused_when_written() {
    let nul = Err(Error::Xdr(XdrError::EmbeddedNul));

    let mut fmt = suffixed();
    fmt.filename_charset = "UTF\0-8".to_owned();
    assert_eq!(fmt.pack(), nul);

    for field in 0..2 {
        let mut fmt = suffixed();
        let streams = fmt.streams.as_mut().unwrap();
        let affix = [&mut streams.stream_prefix, &mut streams.stream_suffix]
            .into_iter()
            .nth(field)
            .unwrap();
        affix.push('\0');
        assert_eq!(fmt.pack(), nul, "field {field}");
    }
}

#[test]
fn no_xattr_is_unstamped() {
    assert_eq!(suffixed().compare_stored(None), Verdict::Unstamped);
}

#[test]
fn the_same_settings_are_the_same() {
    for (fmt, bytes) in samples() {
        assert_eq!(fmt.compare_stored(Some(bytes)), Verdict::Same, "{fmt}");
    }
}

// Each field counts on its own, and no streams differs from any streams.
#[test]
fn a_change_to_any_field_differs_and_names_the_stored_settings() {
    let stored = suffixed();
    let edits: [fn(&mut MetaFmt); 6] = [
        |f| f.filename_charset = "ISO-8859-1".to_owned(),
        |f| f.smb_sfm_normalized = true,
        |f| f.streams = None,
        |f| f.streams.as_mut().unwrap().stream_prefix = "user.".to_owned(),
        |f| f.streams.as_mut().unwrap().stream_suffix = String::new(),
        |f| f.streams.as_mut().unwrap().stream_extra_null = false,
    ];
    for (n, edit) in edits.iter().enumerate() {
        let mut want = suffixed();
        edit(&mut want);
        assert_eq!(
            want.compare_stored(Some(SUFFIXED)),
            Verdict::Differs(stored.clone()),
            "edit {n}"
        );
    }
}

// A later version must stay apart from damage: its fields may be fine.
#[test]
fn a_later_version_is_newer_and_not_unreadable() {
    let record = with_u32(SUFFIXED, 4, 2);
    assert_eq!(suffixed().compare_stored(Some(&record)), Verdict::Newer(2));
}

#[test]
fn what_cannot_be_read_is_unreadable() {
    let want = suffixed();
    assert_eq!(
        want.compare_stored(Some(&with_byte(SUFFIXED, 0, b'X'))),
        Verdict::Unreadable(Error::NotARecord)
    );
    assert!(matches!(
        want.compare_stored(Some(&[])),
        Verdict::Unreadable(Error::Xdr(XdrError::Eof { .. }))
    ));
    assert_eq!(
        want.compare_stored(Some(&with_byte(SUFFIXED, 23, 2))),
        Verdict::Unreadable(Error::Xdr(XdrError::InvalidBool { value: 2 }))
    );
}

#[test]
fn settings_print_every_field() {
    assert_eq!(
        suffixed().to_string(),
        "filename_charset = UTF-8, smb_sfm_normalized = false, \
         stream_prefix = 'user.DosStream.', stream_suffix = ':$DATA', \
         stream_extra_null = true"
    );
    assert_eq!(
        no_streams().to_string(),
        "filename_charset = UTF-8, smb_sfm_normalized = false, no streams"
    );
}

#[test]
fn every_error_prints_and_only_a_codec_error_has_a_source() {
    use std::error::Error as _;

    assert_eq!(Error::NotARecord.to_string(), "not a metafmt record");
    assert_eq!(
        Error::NewerVersion(2).to_string(),
        "metafmt record version 2 is not known"
    );
    assert_eq!(
        Error::Xdr(XdrError::Utf8).to_string(),
        "damaged metafmt record: invalid UTF-8 in string"
    );
    assert!(Error::NotARecord.source().is_none());
    assert!(Error::NewerVersion(2).source().is_none());
    assert!(Error::Xdr(XdrError::Utf8).source().is_some());
}
