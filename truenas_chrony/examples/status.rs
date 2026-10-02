// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Print chronyd's time, its synchronization, and how each source is
//! used and authenticated.
//!
//! ```text
//! cargo run -p truenas_chrony --example status [-- /path/to/chronyd.sock]
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use truenas_chrony::{Address, Client, DEFAULT_SOCKET, Error, SourceMode};

fn main() -> Result<(), Error> {
    let path = std::env::args().nth(1);
    let mut chronyd =
        Client::connect(path.as_deref().unwrap_or(DEFAULT_SOCKET))?;

    let tracking = chronyd.tracking()?;
    let now = tracking.corrected(SystemTime::now());
    println!("time:         {}", now.map_or("-".into(), utc));
    println!("synchronized: {}", tracking.is_synchronized());
    let reference = match tracking.address {
        Address::Unspecified => tracking.reference_id.name(),
        address => address.to_string(),
    };
    println!("reference:    {reference}, stratum {}", tracking.stratum);
    println!("leap:         {:?}", tracking.leap);
    println!("correction:   {:+.9} s", tracking.correction);
    println!("distance:     {:.9} s", tracking.root_distance());
    println!("last update:  {}", utc(tracking.reference_time));

    for (index, source) in (0u32..).zip(chronyd.sources()?) {
        let name = match source.refclock_id() {
            Some(id) => id.name(),
            None => source.address.to_string(),
        };
        let selection = chronyd.selection(index)?;
        print!(
            "{name:<40} {:?} ({}) reach {:03o}",
            source.state,
            char::from(selection.state.code()),
            source.reachability
        );
        if matches!(source.mode, SourceMode::Server | SourceMode::Peer) {
            let auth = chronyd.authentication(source.address)?;
            print!(
                " {:?} {:?} {} bits, {} cookies",
                auth.mode, auth.algorithm, auth.key_bits, auth.cookies
            );
        }
        println!();
    }
    Ok(())
}

/// `t` as an RFC 3339 UTC timestamp.
fn utc(t: SystemTime) -> String {
    let Ok(since) = t.duration_since(UNIX_EPOCH) else {
        return "before 1970".into();
    };
    let secs = since.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Days since the epoch to a civil date (proleptic Gregorian).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:09}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since.subsec_nanos()
    )
}
