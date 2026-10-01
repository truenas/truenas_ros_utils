// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Error`], the reply statuses it carries, and this crate's [`Result`].

use std::{error, fmt, io};

/// This crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// A failure to obtain a report.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A system call failed: setting up the reply socket, sending, or
    /// receiving.
    Io(io::Error),
    /// No answer within the configured attempts.
    Timeout,
    /// The reply carried a status other than success.
    Status(Status),
    /// The daemon speaks another protocol version, this one.
    Version(u8),
    /// The source list kept changing while walked; a later read may
    /// succeed.
    Changed,
    /// A reply layout not read for this request, by reply code.
    UnexpectedReply(u16),
    /// The reply is shorter than its layout, or holds a value that cannot
    /// be represented.
    Malformed(&'static str),
}

impl Error {
    /// Whether the daemon's protocol revision differs: it lacks the
    /// command, wants a longer request, replies in another layout, or
    /// speaks another version.
    pub fn is_unsupported(&self) -> bool {
        matches!(
            self,
            Error::Version(_)
                | Error::UnexpectedReply(_)
                | Error::Status(
                    Status::Invalid
                        | Status::BadPacketLength
                        | Status::BadPacketVersion
                )
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "chronyd socket: {err}"),
            Error::Timeout => f.write_str("chronyd did not answer"),
            Error::Status(status) => write!(f, "chronyd refused: {status}"),
            Error::Version(version) => {
                write!(f, "chronyd speaks protocol version {version}, not 6")
            }
            Error::Changed => {
                f.write_str("chronyd's source list changed while read")
            }
            Error::UnexpectedReply(code) => {
                write!(f, "chronyd replied with unknown reply code {code}")
            }
            Error::Malformed(what) => {
                write!(f, "malformed reply from chronyd: {what}")
            }
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

/// A reply status other than success, by its code. All are named, so an
/// unexpected one reads as itself; unassigned codes are
/// [`Unknown`](Status::Unknown).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Status {
    /// 1: the command failed.
    Failed,
    /// 2: the command is not allowed from this client.
    Unauthorized,
    /// 3: the daemon has no such command.
    Invalid,
    /// 4: no source at that index or address.
    NoSuchSource,
    /// 5: a bad timestamp.
    InvalidTimestamp,
    /// 6: the feature is off in the configuration.
    NotEnabled,
    /// 7: a bad subnet.
    BadSubnet,
    /// 8: an access check allowed.
    AccessAllowed,
    /// 9: an access check denied.
    AccessDenied,
    /// 10: no command access from this host.
    NoHostAccess,
    /// 11: the source is already present.
    SourceAlreadyKnown,
    /// 12: too many sources.
    TooManySources,
    /// 13: the daemon does not track the RTC.
    NoRtc,
    /// 14: the RTC file could not be written.
    BadRtcFile,
    /// 15: the client log is off.
    Inactive,
    /// 16: a sample index out of range.
    BadSample,
    /// 17: a bad address family.
    InvalidAddressFamily,
    /// 18: the request's protocol version is not the daemon's.
    BadPacketVersion,
    /// 19: the request is shorter than the command requires.
    BadPacketLength,
    /// 21: a bad name.
    InvalidName,
    /// Any other code.
    Unknown(u16),
}

impl Status {
    /// The status for a non-zero code.
    pub(crate) fn from_code(code: u16) -> Status {
        match code {
            1 => Status::Failed,
            2 => Status::Unauthorized,
            3 => Status::Invalid,
            4 => Status::NoSuchSource,
            5 => Status::InvalidTimestamp,
            6 => Status::NotEnabled,
            7 => Status::BadSubnet,
            8 => Status::AccessAllowed,
            9 => Status::AccessDenied,
            10 => Status::NoHostAccess,
            11 => Status::SourceAlreadyKnown,
            12 => Status::TooManySources,
            13 => Status::NoRtc,
            14 => Status::BadRtcFile,
            15 => Status::Inactive,
            16 => Status::BadSample,
            17 => Status::InvalidAddressFamily,
            18 => Status::BadPacketVersion,
            19 => Status::BadPacketLength,
            21 => Status::InvalidName,
            other => Status::Unknown(other),
        }
    }

    /// The code on the wire.
    pub fn code(&self) -> u16 {
        match self {
            Status::Failed => 1,
            Status::Unauthorized => 2,
            Status::Invalid => 3,
            Status::NoSuchSource => 4,
            Status::InvalidTimestamp => 5,
            Status::NotEnabled => 6,
            Status::BadSubnet => 7,
            Status::AccessAllowed => 8,
            Status::AccessDenied => 9,
            Status::NoHostAccess => 10,
            Status::SourceAlreadyKnown => 11,
            Status::TooManySources => 12,
            Status::NoRtc => 13,
            Status::BadRtcFile => 14,
            Status::Inactive => 15,
            Status::BadSample => 16,
            Status::InvalidAddressFamily => 17,
            Status::BadPacketVersion => 18,
            Status::BadPacketLength => 19,
            Status::InvalidName => 21,
            Status::Unknown(code) => *code,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Status::Failed => "command failed",
            Status::Unauthorized => "not allowed",
            Status::Invalid => "unknown command",
            Status::NoSuchSource => "source not found",
            Status::InvalidTimestamp => "bad timestamp",
            Status::NotEnabled => "not enabled",
            Status::BadSubnet => "bad subnet",
            Status::AccessAllowed => "access allowed",
            Status::AccessDenied => "access denied",
            Status::NoHostAccess => "host not allowed",
            Status::SourceAlreadyKnown => "source exists",
            Status::TooManySources => "source limit reached",
            Status::NoRtc => "RTC not tracked",
            Status::BadRtcFile => "RTC file not written",
            Status::Inactive => "client log off",
            Status::BadSample => "sample index out of range",
            Status::InvalidAddressFamily => "bad address family",
            Status::BadPacketVersion => "protocol version differs",
            Status::BadPacketLength => "request too short",
            Status::InvalidName => "bad name",
            Status::Unknown(code) => return write!(f, "status {code}"),
        };
        write!(f, "{text} ({})", self.code())
    }
}
