// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The record of how a dataset's files are laid out on disk, kept in the
//! [`XATTR_NAME`] xattr of the dataset's root.
//!
//! One record describes the dataset, whichever protocol writes to it.
//!
//! This crate does no I/O. The caller reads and writes the xattr, which needs
//! `CAP_SYS_ADMIN`, and decides what a [`Verdict`] means for it.
//!
//! ```
//! use truenas_metafmt::{MetaFmt, StreamFormat, Verdict};
//!
//! let want = MetaFmt {
//!     filename_charset: "UTF-8".to_owned(),
//!     smb_sfm_normalized: false,
//!     streams: Some(StreamFormat {
//!         stream_prefix: "user.DosStream.".to_owned(),
//!         stream_suffix: ":$DATA".to_owned(),
//!         stream_extra_null: true,
//!     }),
//! };
//! assert_eq!(want.compare_stored(None), Verdict::Unstamped);
//!
//! let stored = want.pack()?;
//! assert_eq!(want.compare_stored(Some(&stored)), Verdict::Same);
//! # Ok::<(), truenas_metafmt::Error>(())
//! ```
//!
//! # Wire format
//!
//! The record is XDR (RFC 4506):
//!
//! ```text
//! const METAFMT_MAGIC = 0x544E4D46;       /* "TNMF" */
//!
//! struct stream_format {
//!     string stream_prefix<255>;
//!     string stream_suffix<255>;
//!     bool stream_extra_null;
//! };
//!
//! struct metafmt_v1 {
//!     string filename_charset<64>;
//!     bool smb_sfm_normalized;
//!     stream_format *streams;
//! };
//!
//! union metafmt_body switch (unsigned int version) {
//! case 1:
//!     metafmt_v1 v1;
//! };
//!
//! struct metafmt {
//!     unsigned int magic;
//!     metafmt_body body;
//! };
//! ```
//!
//! # Versions
//!
//! A change to the fields or to their meaning is a new version.
//! [`MetaFmt::pack`] writes [`VERSION`]. [`MetaFmt::unpack`] converts every
//! version up to [`VERSION`] to the current fields, so a comparison goes by
//! the fields and not by the bytes. A record of an older version with the
//! wanted settings is [`Verdict::Same`].
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;
use truenas_xdr::{
    Bounded, Strictness, from_bytes_with, from_prefix_with, to_bytes,
};

/// The name of the xattr that holds the record.
pub const XATTR_NAME: &str = "trusted.truenas_metafmt";

/// The first four bytes of a record, "TNMF" in ASCII.
pub const MAGIC: u32 = 0x544E_4D46;

/// The version that [`MetaFmt::pack`] writes, and the newest that
/// [`MetaFmt::unpack`] reads.
pub const VERSION: u32 = 1;

/// The maximum length in bytes of [`MetaFmt::filename_charset`].
pub const FILENAME_CHARSET_MAX: usize = 64;

/// The maximum length in bytes of [`StreamFormat::stream_prefix`] and of
/// [`StreamFormat::stream_suffix`].
pub const STREAM_AFFIX_MAX: usize = 255;

/// How a named stream is stored: as an xattr of the file, called
/// `stream_prefix` + the name of the stream + `stream_suffix`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StreamFormat {
    /// The start of the name of the xattr, with its namespace.
    pub stream_prefix: String,
    /// The end of the name of the xattr.
    pub stream_suffix: String,
    /// The value of the xattr ends in one NUL byte that is not part of the
    /// stream.
    pub stream_extra_null: bool,
}

/// The settings that decide how a dataset's files are laid out on disk.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MetaFmt {
    /// The charset of file names on disk, for example `UTF-8`.
    pub filename_charset: String,
    /// A file name that an SMB client sends with characters in the Services
    /// for Macintosh private range is stored with the ASCII characters they
    /// stand for.
    pub smb_sfm_normalized: bool,
    /// How named streams are stored. `None` if the writer has no named
    /// streams.
    pub streams: Option<StreamFormat>,
}

/// An error from [`MetaFmt::pack`] or [`MetaFmt::unpack`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes do not start with [`MAGIC`] and a version of 1 or above.
    NotARecord,
    /// The version of the record is above [`VERSION`], so its fields are not
    /// known.
    NewerVersion(u32),
    /// A field has no encoding, or the bytes after the version are damaged.
    Xdr(truenas_xdr::Error),
}

impl From<truenas_xdr::Error> for Error {
    fn from(error: truenas_xdr::Error) -> Error {
        Error::Xdr(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotARecord => f.write_str("not a metafmt record"),
            Error::NewerVersion(version) => {
                write!(f, "metafmt record version {version} is not known")
            }
            Error::Xdr(error) => write!(f, "damaged metafmt record: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Xdr(error) => Some(error),
            _ => None,
        }
    }
}

/// How a stored record relates to the settings that a writer wants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// No record is stored.
    Unstamped,
    /// The stored record holds the wanted settings.
    Same,
    /// The stored record holds these other settings.
    Differs(MetaFmt),
    /// The stored record has this version, above [`VERSION`], so its settings
    /// are not known.
    Newer(u32),
    /// The stored bytes are not a record, or are damaged. This error is never
    /// [`Error::NewerVersion`], which is [`Verdict::Newer`].
    Unreadable(Error),
}

/// The start of every version.
#[derive(Deserialize)]
struct Header {
    magic: u32,
    version: u32,
}

#[derive(Serialize)]
struct Packed<'a> {
    magic: u32,
    version: u32,
    body: BodyV1<'a>,
}

#[derive(Deserialize, Serialize)]
struct BodyV1<'a> {
    #[serde(borrow)]
    filename_charset: Bounded<&'a str, FILENAME_CHARSET_MAX>,
    smb_sfm_normalized: bool,
    #[serde(borrow)]
    streams: Option<StreamsV1<'a>>,
}

#[derive(Deserialize, Serialize)]
struct StreamsV1<'a> {
    #[serde(borrow)]
    stream_prefix: Bounded<&'a str, STREAM_AFFIX_MAX>,
    #[serde(borrow)]
    stream_suffix: Bounded<&'a str, STREAM_AFFIX_MAX>,
    stream_extra_null: bool,
}

impl<'a> From<&'a MetaFmt> for BodyV1<'a> {
    fn from(fmt: &'a MetaFmt) -> BodyV1<'a> {
        BodyV1 {
            filename_charset: Bounded(&fmt.filename_charset),
            smb_sfm_normalized: fmt.smb_sfm_normalized,
            streams: fmt.streams.as_ref().map(|streams| StreamsV1 {
                stream_prefix: Bounded(&streams.stream_prefix),
                stream_suffix: Bounded(&streams.stream_suffix),
                stream_extra_null: streams.stream_extra_null,
            }),
        }
    }
}

impl From<BodyV1<'_>> for MetaFmt {
    fn from(body: BodyV1<'_>) -> MetaFmt {
        MetaFmt {
            filename_charset: body.filename_charset.0.to_owned(),
            smb_sfm_normalized: body.smb_sfm_normalized,
            streams: body.streams.map(|streams| StreamFormat {
                stream_prefix: streams.stream_prefix.0.to_owned(),
                stream_suffix: streams.stream_suffix.0.to_owned(),
                stream_extra_null: streams.stream_extra_null,
            }),
        }
    }
}

impl MetaFmt {
    /// The record of these settings, at [`VERSION`].
    ///
    /// # Errors
    ///
    /// [`Error::Xdr`] if a string is over its bound or holds a NUL.
    /// [`MetaFmt::unpack`] refuses both, so no record is written that cannot
    /// be read.
    pub fn pack(&self) -> Result<Vec<u8>, Error> {
        let affixes = self
            .streams
            .iter()
            .flat_map(|s| [&s.stream_prefix, &s.stream_suffix]);
        if std::iter::once(&self.filename_charset)
            .chain(affixes)
            .any(|s| s.contains('\0'))
        {
            return Err(truenas_xdr::Error::EmbeddedNul.into());
        }
        Ok(to_bytes(&Packed {
            magic: MAGIC,
            version: VERSION,
            body: self.into(),
        })?)
    }

    /// The settings that a record holds.
    ///
    /// The whole of `bytes` must be one record. It is held to what
    /// [`MetaFmt::pack`] writes, so non-zero padding, a boolean other than 0
    /// or 1 and a string with a NUL are errors.
    ///
    /// # Errors
    ///
    /// [`Error::NotARecord`], [`Error::NewerVersion`] or [`Error::Xdr`], as
    /// each describes.
    pub fn unpack(bytes: &[u8]) -> Result<MetaFmt, Error> {
        let (header, body): (Header, _) =
            from_prefix_with(bytes, Strictness::Strict)?;
        if header.magic != MAGIC {
            return Err(Error::NotARecord);
        }
        match header.version {
            0 => Err(Error::NotARecord),
            VERSION => {
                let body: BodyV1<'_> =
                    from_bytes_with(body, Strictness::Strict)?;
                Ok(body.into())
            }
            newer => Err(Error::NewerVersion(newer)),
        }
    }

    /// How `stored`, the value of the xattr, relates to these settings.
    /// `None` means that the xattr does not exist.
    pub fn compare_stored(&self, stored: Option<&[u8]>) -> Verdict {
        let Some(bytes) = stored else {
            return Verdict::Unstamped;
        };
        match MetaFmt::unpack(bytes) {
            Ok(found) if found == *self => Verdict::Same,
            Ok(found) => Verdict::Differs(found),
            Err(Error::NewerVersion(version)) => Verdict::Newer(version),
            Err(error) => Verdict::Unreadable(error),
        }
    }
}

impl fmt::Display for MetaFmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "filename_charset = {}, smb_sfm_normalized = {}, ",
            self.filename_charset, self.smb_sfm_normalized,
        )?;
        match &self.streams {
            None => f.write_str("no streams"),
            Some(streams) => write!(
                f,
                "stream_prefix = '{}', stream_suffix = '{}', \
                 stream_extra_null = {}",
                streams.stream_prefix,
                streams.stream_suffix,
                streams.stream_extra_null,
            ),
        }
    }
}
