// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The per-source reports: the source count and list, and selection
//! state.

use crate::error::Result;
use crate::types::{Address, Leap, RefId};
use crate::wire::{Layout, Reader};

/// Command 14, reply 2; 4 bytes of data: the source count.
impl Layout for u32 {
    const COMMAND: u16 = 14;
    const REPLY: u16 = 2;
    const LEN: usize = 4;

    fn read(r: &mut Reader<'_>) -> Result<u32> {
        r.u32()
    }
}

/// One entry of the source list.
///
/// Offsets are in seconds.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Source {
    /// The source's address; for a reference clock, its identifier in the
    /// shape of an IPv4 address, which [`refclock_id`](Self::refclock_id)
    /// reads.
    pub address: Address,
    /// The polling interval, as a base-2 logarithm of seconds.
    pub poll: i16,
    /// The stratum of the source's latest sample.
    pub stratum: u16,
    /// The source's standing after the last selection.
    pub state: SourceState,
    /// What the source is.
    pub mode: SourceMode,
    /// The reachability register: a bit per poll, newest lowest, set when
    /// the poll got a valid answer.
    pub reachability: u16,
    /// Seconds since the latest sample; `None` before the first.
    pub last_sample_ago: Option<u32>,
    /// The latest sample's offset, corrected for clock adjustments made
    /// since it was measured.
    pub adjusted_offset: f64,
    /// The latest sample's offset as measured.
    pub measured_offset: f64,
    /// The latest sample's error bound.
    pub offset_error: f64,
}

impl Source {
    /// A reference clock's identifier, carried in the address field;
    /// `None` for an NTP source.
    pub fn refclock_id(&self) -> Option<RefId> {
        match (self.mode, self.address) {
            (SourceMode::RefClock, Address::V4(ip)) => {
                Some(RefId(u32::from(ip)))
            }
            _ => None,
        }
    }
}

/// Command 15, reply 3; 48 bytes of data.
impl Layout for Source {
    const COMMAND: u16 = 15;
    const REPLY: u16 = 3;
    const LEN: usize = 48;

    fn read(r: &mut Reader<'_>) -> Result<Source> {
        let address = r.address()?;
        let poll = r.i16()?;
        let stratum = r.u16()?;
        let state = SourceState::from_code(r.u16()?);
        let mode = SourceMode::from_code(r.u16()?);
        // Two unused bytes.
        r.skip::<2>()?;
        let reachability = r.u16()?;
        let last_sample_ago = r.ago()?;
        // The measured offset precedes the adjusted one on the wire.
        let measured_offset = r.float()?;
        Ok(Source {
            address,
            poll,
            stratum,
            state,
            mode,
            reachability,
            last_sample_ago,
            adjusted_offset: r.float()?,
            measured_offset,
            offset_error: r.float()?,
        })
    }
}

/// What a source is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SourceMode {
    /// 0: an NTP server, polled as its client.
    Server,
    /// 1: an NTP peer, in symmetric mode.
    Peer,
    /// 2: a reference clock attached to this host.
    RefClock,
    /// Any other code.
    Unknown(u16),
}

impl SourceMode {
    fn from_code(code: u16) -> SourceMode {
        match code {
            0 => SourceMode::Server,
            1 => SourceMode::Peer,
            2 => SourceMode::RefClock,
            other => SourceMode::Unknown(other),
        }
    }
}

/// A source's standing after the last selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SourceState {
    /// 0: the source the clock is synchronized to.
    Selected,
    /// 1: not eligible, for instance unreachable, unsynchronized, or
    /// short of samples.
    Unusable,
    /// 2: disagrees with the majority.
    Falseticker,
    /// 3: too noisy to use.
    Jittery,
    /// 4: used together with the selected source.
    Combined,
    /// 5: eligible, but not in use.
    Selectable,
    /// Any other code.
    Unknown(u16),
}

impl SourceState {
    fn from_code(code: u16) -> SourceState {
        match code {
            0 => SourceState::Selected,
            1 => SourceState::Unusable,
            2 => SourceState::Falseticker,
            3 => SourceState::Jittery,
            4 => SourceState::Combined,
            5 => SourceState::Selectable,
            other => SourceState::Unknown(other),
        }
    }
}

bitflags::bitflags! {
    /// A source's selection options. Unassigned bits are kept.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct SelectOptions: u16 {
        /// `noselect`: never used for synchronization.
        const NOSELECT = 0x1;
        /// `prefer`: chosen over sources without it.
        const PREFER = 0x2;
        /// `trust`: taken as correct when sources conflict.
        const TRUST = 0x4;
        /// `require`: nothing is selected unless this source is
        /// selectable.
        const REQUIRE = 0x8;
    }
}

/// A source's part in the last selection, in more detail than
/// [`Source::state`].
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Selection {
    /// The source's reference identifier; a reference clock's name.
    pub reference_id: RefId,
    /// The source's address; [`Address::Unspecified`] for a reference
    /// clock.
    pub address: Address,
    /// Why the selection treated the source as it did.
    pub state: SelectState,
    /// Whether authentication, NTS or a symmetric key, is enabled for the
    /// source.
    pub authenticated: bool,
    /// The leap status the source announces;
    /// [`Leap::Unsynchronized`] until it has a valid measurement.
    pub leap: Leap,
    /// The selection options configured.
    pub configured_options: SelectOptions,
    /// The selection options applied, which `authselectmode` can make
    /// differ from the configured ones.
    pub effective_options: SelectOptions,
    /// Seconds from the source's latest measurement to the selection;
    /// zero, not `None`, before the first.
    pub last_sample_ago: Option<u32>,
    /// How the source has compared with the selected one; at 10 the
    /// selection moves to it.
    pub score: f64,
    /// Low end of the interval the source puts the true offset in, in
    /// seconds.
    pub lower_limit: f64,
    /// High end of that interval, in seconds.
    pub upper_limit: f64,
}

/// Command 69, reply 23; 48 bytes of data.
impl Layout for Selection {
    const COMMAND: u16 = 69;
    const REPLY: u16 = 23;
    const LEN: usize = 48;

    fn read(r: &mut Reader<'_>) -> Result<Selection> {
        let reference_id = RefId(r.u32()?);
        let address = r.address()?;
        let state = SelectState::from_code(r.u8()?);
        let authenticated = r.u8()? != 0;
        let leap = Leap::from_code(r.u8()?.into());
        r.skip::<1>()?;
        Ok(Selection {
            reference_id,
            address,
            state,
            authenticated,
            leap,
            configured_options: SelectOptions::from_bits_retain(r.u16()?),
            effective_options: SelectOptions::from_bits_retain(r.u16()?),
            last_sample_ago: r.ago()?,
            score: r.float()?,
            lower_limit: r.float()?,
            upper_limit: r.float()?,
        })
    }
}

/// Why the last selection treated a source as it did: one character on
/// the wire, [`Unknown`](SelectState::Unknown) if unlisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SelectState {
    /// `N`: configured `noselect`.
    NoSelect,
    /// `M`: too few measurements yet.
    MissingSamples,
    /// `s`: the source itself is not synchronized.
    Unsynchronized,
    /// `r`: stratum outside `minstratum` to `maxstratum`.
    BadStratum,
    /// `d`: root distance over `maxdistance`.
    BadDistance,
    /// `~`: jitter over `maxjitter`.
    Jittery,
    /// `w`: held back until other sources have measurements.
    WaitsSamples,
    /// `S`: its measurements lag the reachable sources', or it has been
    /// unreachable longer than `maxunreach` allows.
    Stale,
    /// `O`: at or beyond the orphan stratum set by `local`.
    Orphan,
    /// `T`: conflicts with a source marked `trust`.
    Untrusted,
    /// `x`: outside the interval the majority agrees on.
    Falseticker,
    /// `W`: usable, but too few sources are (`minsources`, or a source
    /// marked `require`).
    WaitsSources,
    /// `P`: usable, but passed over for a source marked `prefer`.
    NonPreferred,
    /// `U`: usable, held until it measures again after the best source
    /// changed.
    WaitsUpdate,
    /// `D`: usable, but too distant to combine (`combinelimit`).
    Distant,
    /// `L`: set aside as an outlier.
    Outlier,
    /// `+`: combined into the clock update.
    Combined,
    /// `*`: the best source, which the clock follows.
    Selected,
    /// Any other character, `?` among them.
    Unknown(u8),
}

impl SelectState {
    fn from_code(code: u8) -> SelectState {
        match code {
            b'N' => SelectState::NoSelect,
            b'M' => SelectState::MissingSamples,
            b's' => SelectState::Unsynchronized,
            b'r' => SelectState::BadStratum,
            b'd' => SelectState::BadDistance,
            b'~' => SelectState::Jittery,
            b'w' => SelectState::WaitsSamples,
            b'S' => SelectState::Stale,
            b'O' => SelectState::Orphan,
            b'T' => SelectState::Untrusted,
            b'x' => SelectState::Falseticker,
            b'W' => SelectState::WaitsSources,
            b'P' => SelectState::NonPreferred,
            b'U' => SelectState::WaitsUpdate,
            b'D' => SelectState::Distant,
            b'L' => SelectState::Outlier,
            b'+' => SelectState::Combined,
            b'*' => SelectState::Selected,
            other => SelectState::Unknown(other),
        }
    }

    /// The character on the wire.
    pub fn code(&self) -> u8 {
        match self {
            SelectState::NoSelect => b'N',
            SelectState::MissingSamples => b'M',
            SelectState::Unsynchronized => b's',
            SelectState::BadStratum => b'r',
            SelectState::BadDistance => b'd',
            SelectState::Jittery => b'~',
            SelectState::WaitsSamples => b'w',
            SelectState::Stale => b'S',
            SelectState::Orphan => b'O',
            SelectState::Untrusted => b'T',
            SelectState::Falseticker => b'x',
            SelectState::WaitsSources => b'W',
            SelectState::NonPreferred => b'P',
            SelectState::WaitsUpdate => b'U',
            SelectState::Distant => b'D',
            SelectState::Outlier => b'L',
            SelectState::Combined => b'+',
            SelectState::Selected => b'*',
            SelectState::Unknown(code) => *code,
        }
    }
}
