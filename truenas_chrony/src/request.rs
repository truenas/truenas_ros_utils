// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Requests and replies without I/O: [`Request`] is the datagram asking
//! for a report, and [`Request::decode`] reads its reply.

use std::fmt;

use crate::auth::Authentication;
use crate::error::{Error, Result, Status};
use crate::source::{Selection, Source};
use crate::tracking::Tracking;
use crate::types::Address;
use crate::wire::{
    self, Layout, OLDEST_MISMATCH_VERSION, REPLY_HEADER, REQUEST_HEADER,
    STATUS_BAD_VERSION, STATUS_OK, TYPE_REPLY, TYPE_REQUEST, VERSION,
    put_address,
};

/// A request for one report of type `T`, encoded as the datagram to send.
///
/// The reply echoes the sequence number: use a fresh random one for every
/// datagram, retries included, so a late reply cannot pass for the
/// current one. Requests are padded to their reply's length; chronyd
/// refuses shorter ones.
pub struct Request<T> {
    command: u16,
    sequence: u32,
    bytes: Vec<u8>,
    decode: fn(u16, &[u8]) -> Result<T>,
}

/// The request for `T` carrying `data`.
fn build<T: Layout>(data: &[u8], sequence: u32) -> Request<T> {
    let len = REPLY_HEADER + T::LEN;
    debug_assert!(REQUEST_HEADER + data.len() <= len);
    let mut bytes = Vec::with_capacity(len);
    bytes.extend_from_slice(&[VERSION, TYPE_REQUEST, 0, 0]);
    bytes.extend_from_slice(&T::COMMAND.to_be_bytes());
    // The attempt counter, then the sequence number and two zero words.
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(data);
    bytes.resize(len, 0);
    Request {
        command: T::COMMAND,
        sequence,
        bytes,
        decode: wire::decode::<T>,
    }
}

/// The request for `T` about the source at `address`.
fn about<T: Layout>(address: Address, sequence: u32) -> Request<T> {
    let mut data = Vec::with_capacity(20);
    put_address(&mut data, address);
    build(&data, sequence)
}

impl Request<Tracking> {
    /// Ask for the system clock's synchronization state.
    pub fn tracking(sequence: u32) -> Request<Tracking> {
        build(&[], sequence)
    }
}

impl Request<u32> {
    /// Ask how many sources there are.
    pub fn source_count(sequence: u32) -> Request<u32> {
        build(&[], sequence)
    }
}

impl Request<Source> {
    /// Ask for the source at `index`, counting from zero.
    pub fn source(index: u32, sequence: u32) -> Request<Source> {
        build(&index.to_be_bytes(), sequence)
    }
}

impl Request<Selection> {
    /// Ask for the last selection's view of the source at `index`.
    pub fn selection(index: u32, sequence: u32) -> Request<Selection> {
        build(&index.to_be_bytes(), sequence)
    }
}

impl Request<Authentication> {
    /// Ask how the NTP source at `address` is authenticated.
    pub fn authentication(
        address: impl Into<Address>,
        sequence: u32,
    ) -> Request<Authentication> {
        about(address.into(), sequence)
    }
}

impl<T> Request<T> {
    /// Mark the request as transmission `attempt`, from zero.
    pub fn with_attempt(mut self, attempt: u16) -> Request<T> {
        self.bytes[6..8].copy_from_slice(&attempt.to_be_bytes());
        self
    }

    /// The sequence number a reply must echo.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// The datagram to send.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Read a received datagram as the reply to this request: a version-6
    /// reply with zero reserved bytes echoing the command and sequence
    /// number, or a version-mismatch status in any version from 4 on.
    pub fn decode(&self, datagram: &[u8]) -> Verdict<T> {
        let Some((header, data)) = datagram.split_first_chunk::<REPLY_HEADER>()
        else {
            return Verdict::Unrelated;
        };
        let u16_at = |i: usize| u16::from_be_bytes([header[i], header[i + 1]]);
        let version = header[0];
        let command = u16_at(4);
        let reply = u16_at(6);
        let status = u16_at(8);
        let sequence = u32::from_be_bytes([
            header[16], header[17], header[18], header[19],
        ]);
        let mismatch = version != VERSION
            && version >= OLDEST_MISMATCH_VERSION
            && status == STATUS_BAD_VERSION;
        if (version != VERSION && !mismatch)
            || header[1] != TYPE_REPLY
            || header[2] != 0
            || header[3] != 0
            || command != self.command
            || sequence != self.sequence
        {
            return Verdict::Unrelated;
        }
        Verdict::Answer(if mismatch {
            Err(Error::Version(version))
        } else if status != STATUS_OK {
            Err(Error::Status(Status::from_code(status)))
        } else {
            (self.decode)(reply, data)
        })
    }
}

impl<T> fmt::Debug for Request<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("command", &self.command)
            .field("sequence", &self.sequence)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// What a received datagram is to a request.
#[derive(Debug)]
pub enum Verdict<T> {
    /// Not its reply: keep waiting.
    Unrelated,
    /// The reply, decoded.
    Answer(Result<T>),
}
