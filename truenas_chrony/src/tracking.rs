// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The tracking report: the system clock's synchronization state.

use std::time::{Duration, SystemTime};

use crate::error::Result;
use crate::types::{Address, Leap, RefId};
use crate::wire::{Layout, Reader};

/// The system clock's synchronization state.
///
/// Offsets and intervals are in seconds, frequencies in parts per
/// million.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Tracking {
    /// What the clock follows: a source's reference identifier, a
    /// reference clock's name, [`RefId::LOCAL`] under a local reference,
    /// or zero when unsynchronized.
    pub reference_id: RefId,
    /// The NTP source the clock follows; [`Address::Unspecified`] for a
    /// reference clock, a local reference, or none.
    pub address: Address,
    /// The clock's stratum; zero with no reference, and the configured one
    /// under a local reference.
    pub stratum: u16,
    /// The leap status chronyd passes on to its own NTP clients.
    pub leap: Leap,
    /// When the clock was last updated from its reference; the epoch if
    /// never.
    pub reference_time: SystemTime,
    /// The offset still being slewed out of the system clock; positive
    /// while the clock is behind.
    pub correction: f64,
    /// The offset measured at the last clock update.
    pub last_offset: f64,
    /// Root mean square of the measured offsets.
    pub rms_offset: f64,
    /// The uncorrected clock's frequency error; positive when it runs
    /// fast.
    pub frequency_ppm: f64,
    /// The frequency error left relative to the reference.
    pub residual_frequency_ppm: f64,
    /// The bound on the frequency estimate's error.
    pub skew_ppm: f64,
    /// Round-trip delay accumulated to the stratum-1 source.
    pub root_delay: f64,
    /// Dispersion accumulated to the stratum-1 source.
    pub root_dispersion: f64,
    /// The time between the last two clock updates.
    pub update_interval: f64,
}

impl Tracking {
    /// Whether chronyd follows a source: an NTP server or peer, or a
    /// reference clock. A local reference, [`RefId::LOCAL`], does not
    /// count; [`leap`](Self::leap) stays [`Leap::Normal`] under one.
    pub fn is_synchronized(&self) -> bool {
        self.address != Address::Unspecified
            || (self.reference_id != RefId(0)
                && self.reference_id != RefId::LOCAL)
    }

    /// The bound on the clock's error, in seconds: half the root delay
    /// plus the root dispersion.
    pub fn root_distance(&self) -> f64 {
        self.root_delay / 2.0 + self.root_dispersion
    }

    /// chronyd's time for `system`, a reading of this host's clock taken
    /// close to the report: the reading plus the
    /// [`correction`](Self::correction) still being slewed out. `None` if
    /// unrepresentable.
    pub fn corrected(&self, system: SystemTime) -> Option<SystemTime> {
        let shift = Duration::try_from_secs_f64(self.correction.abs()).ok()?;
        if self.correction >= 0.0 {
            system.checked_add(shift)
        } else {
            system.checked_sub(shift)
        }
    }
}

/// Command 33, reply 5; 76 bytes of data.
impl Layout for Tracking {
    const COMMAND: u16 = 33;
    const REPLY: u16 = 5;
    const LEN: usize = 76;

    fn read(r: &mut Reader<'_>) -> Result<Tracking> {
        Ok(Tracking {
            reference_id: RefId(r.u32()?),
            address: r.address()?,
            stratum: r.u16()?,
            leap: Leap::from_code(r.u16()?),
            reference_time: r.timestamp()?,
            correction: r.float()?,
            last_offset: r.float()?,
            rms_offset: r.float()?,
            frequency_ppm: r.float()?,
            residual_frequency_ppm: r.float()?,
            skew_ppm: r.float()?,
            root_delay: r.float()?,
            root_dispersion: r.float()?,
            update_interval: r.float()?,
        })
    }
}
