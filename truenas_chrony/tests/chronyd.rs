// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The client against real chronyd, scenario by scenario, without touching
//! the system clock: NTS servers on 127.0.0.1 and 127.0.0.3, a plain one
//! on 127.0.0.2, and a client daemon configured per scenario, each put to
//! the gate from the crate's documentation.
//!
//! One scenario checks every report against chronyc's reading of the same
//! daemon. The resets run the client daemon under libfaketime. As root,
//! the packaged scenario lays chronyd out as the Debian package runs it and
//! runs the client as root and, re-executing this binary, as other users.
//! The `openssl` command makes the certificates once per run.
//!
//! chronyd and chronyc must be 4.6.1 or later, chronyd built with NTS. The
//! suite skips without chronyd, chronyc, or openssl, the resets without
//! libfaketime, and the packaged scenario without root and the chrony
//! user. TRUENAS_CHRONY_REQUIRE_CHRONYD=1 makes the first two failures,
//! TRUENAS_CHRONY_REQUIRE_ROOT=1 the last. TRUENAS_CHRONY_CHRONYD,
//! TRUENAS_CHRONY_CHRONYC, and TRUENAS_CHRONY_FAKETIME override the search
//! for them.

use std::fs::{self, File};
use std::io;
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use truenas_chrony::{
    Address, Algorithm, AuthMode, Client, Error, Leap, RefId, SelectOptions,
    SelectState, Selection, SourceMode, SourceState, Status, Tracking,
};

const REQUIRE: &str = "TRUENAS_CHRONY_REQUIRE_CHRONYD";
const REQUIRE_ROOT: &str = "TRUENAS_CHRONY_REQUIRE_ROOT";

/// The daemon socket a child case connects to.
const CHILD_SOCKET: &str = "TRUENAS_CHRONY_CHILD_SOCKET";

/// The oldest chronyd release this crate is held to.
const FLOOR: (u32, u32, u32) = (4, 6, 1);

const NTS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const PLAIN: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const NTS_2: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);

/// How long a daemon gets to reach a state.
const PATIENCE: Duration = Duration::from_secs(30);

/// A check of the gate in the crate's documentation that refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Unsynchronized,
    Distance,
    Correction,
    NoSource,
    RefClock,
    Unauthenticated,
}

/// The gate's thresholds, in seconds.
#[derive(Clone, Copy)]
struct Limits {
    distance: f64,
    correction: f64,
}

/// The thresholds in the crate's documentation.
const DOCUMENTED: Limits = Limits {
    distance: 1.0,
    correction: 1.0,
};

/// The gate from the crate's documentation, naming each check that
/// refused, in the order it makes them; none means trusted.
fn refusals(
    chronyd: &mut Client,
    limits: Limits,
) -> truenas_chrony::Result<Vec<Refusal>> {
    let tracking = chronyd.tracking()?;
    let mut refused = Vec::new();
    if !tracking.is_synchronized() {
        refused.push(Refusal::Unsynchronized);
    }
    // Admitted only below the bound, so a NaN refuses.
    let close = tracking.root_distance() < limits.distance;
    if !close {
        refused.push(Refusal::Distance);
    }
    let corrected = tracking.correction.abs() < limits.correction;
    if !corrected {
        refused.push(Refusal::Correction);
    }
    let mut used = 0;
    for source in chronyd.sources()? {
        if !matches!(
            source.state,
            SourceState::Selected | SourceState::Combined
        ) {
            continue;
        }
        used += 1;
        let refusal = if source.mode == SourceMode::RefClock {
            Refusal::RefClock
        } else {
            let auth = chronyd.authentication(source.address)?;
            if auth.mode == AuthMode::Nts && auth.key_bits > 0 {
                continue;
            }
            Refusal::Unauthenticated
        };
        if !refused.contains(&refusal) {
            refused.push(refusal);
        }
    }
    if used == 0 {
        refused.push(Refusal::NoSource);
    }
    Ok(refused)
}

/// The gate's verdict under the documented thresholds, failing on an
/// error.
fn judge(chronyd: &mut Client) -> Vec<Refusal> {
    refusals(chronyd, DOCUMENTED).unwrap()
}

/// Following the NTS server at 127.0.0.1 with keys, and settled: the
/// first updates carry a root distance near a second.
fn follows_nts(client: &mut Client) -> bool {
    client.tracking().is_ok_and(|t| {
        t.address == Address::V4(NTS) && t.root_distance() < 0.01
    }) && client.authentication(NTS).is_ok_and(|a| a.key_bits > 0)
}

/// NTS-authenticated time is admitted, and every report agrees with
/// chronyc's reading of the same daemon.
#[test]
fn nts_time_is_trusted() {
    let Some(tools) = Tools::get() else { return };
    let mut lab = Lab::new(&tools);
    let nts = lab.nts_server(NTS);
    let plain = lab.plain_server();
    let refclock = lab.dir.join("refclock.sock");
    let socket = lab.client(
        &format!(
            "authselectmode require\n{}\n{}\nrefclock SOCK {} refid TEST\n",
            nts.line(),
            plain.line(),
            refclock.display()
        ),
        None,
    );
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("NTS synchronization", || {
        follows_nts(&mut client)
            && client.sources().is_ok_and(|sources| {
                sources.iter().any(|s| {
                    s.address == Address::V4(PLAIN)
                        && s.last_sample_ago.is_some()
                })
            })
    });

    let tracking = client.tracking().unwrap();
    assert!(tracking.is_synchronized());
    assert_eq!(tracking.address, Address::V4(NTS));
    assert_eq!(tracking.reference_id.0, u32::from(NTS));
    assert_eq!(tracking.stratum, 2);
    assert_eq!(tracking.leap, Leap::Normal);
    assert!(tracking.root_distance() < 0.01, "{tracking:?}");
    // Every daemon here reads the host clock unadjusted, so chronyd's time
    // is that clock's.
    assert_near(
        tracking.corrected(SystemTime::now()),
        SystemTime::now(),
        0.01,
    );

    let auth = client.authentication(NTS).unwrap();
    assert_eq!(auth.mode, AuthMode::Nts);
    assert!(matches!(
        auth.algorithm,
        Algorithm::AesSivCmac256 | Algorithm::Aes128GcmSiv
    ));
    assert!(auth.key_bits > 0);
    assert!(auth.key_id >= 1);
    assert!((1..=8).contains(&auth.cookies));
    assert!(auth.cookie_length > 0);
    assert!(auth.last_ke_ago.is_some());
    assert!(!auth.nak);
    let plain_auth = client.authentication(PLAIN).unwrap();
    assert_eq!(plain_auth.mode, AuthMode::None);
    assert_eq!(plain_auth.algorithm, Algorithm::None);
    assert_eq!((plain_auth.key_bits, plain_auth.cookies), (0, 0));
    assert_eq!(plain_auth.last_ke_ago, None);
    assert!(matches!(
        client.authentication(Ipv4Addr::new(192, 0, 2, 1)),
        Err(Error::Status(Status::NoSuchSource))
    ));

    // The plain source cannot be selected, so the clock follows only
    // NTS-authenticated time.
    let sources = client.sources().unwrap();
    let plain_source = sources.iter().find(|s| s.address == Address::V4(PLAIN));
    assert!(!matches!(
        plain_source.unwrap().state,
        SourceState::Selected | SourceState::Combined
    ));
    assert_eq!(judge(&mut client), []);

    // Hold the daemon's state still: with its sources offline, only
    // time-dependent fields move between readings.
    let out = tools.chronyc(&socket, &["offline"]);
    assert_eq!(out.trim(), "200 OK", "{out}");
    thread::sleep(Duration::from_millis(500));
    cross_check_tracking(&tools, &socket, &mut client);
    cross_check_sources(&tools, &socket, &mut client);
    cross_check_authentication(&tools, &socket, &mut client);

    // The client leaves nothing behind in the daemons' directory.
    drop(client);
    assert_eq!(leftovers(&lab.dir), [] as [String; 0]);
}

/// `prefer` with no NTS source configured leaves plain sources
/// selectable: chronyd synchronizes to one, and the time is refused.
#[test]
fn plain_ntp_is_refused() {
    let Some(tools) = Tools::get() else { return };
    let mut lab = Lab::new(&tools);
    let plain = lab.plain_server();
    let socket =
        lab.client(&format!("authselectmode prefer\n{}\n", plain.line()), None);
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("synchronization to the plain server", || {
        client.tracking().is_ok_and(|t| {
            t.address == Address::V4(PLAIN) && t.root_distance() < 0.01
        })
    });

    assert_eq!(client.authentication(PLAIN).unwrap().mode, AuthMode::None);
    assert!(!client.selection(0).unwrap().authenticated);
    assert_eq!(judge(&mut client), [Refusal::Unauthenticated]);
}

/// An NTS server nobody answers for: no keys, no time, refused.
#[test]
fn unreachable_nts_server_is_refused() {
    let Some(tools) = Tools::get() else { return };
    let mut lab = Lab::new(&tools);
    let nobody = Server::absent(NTS, true);
    let socket = lab.client(&nobody.line(), None);
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("an NTS-KE attempt", || {
        client.authentication(NTS).is_ok_and(|a| a.ke_attempts >= 1)
    });
    assert_no_keys(&mut client);
    assert_unsynchronized(&client.tracking().unwrap());
    let source = &client.sources().unwrap()[0];
    assert_eq!(source.state, SourceState::Unusable);
    assert_eq!((source.reachability, source.last_sample_ago), (0, None));
    assert_eq!(
        judge(&mut client),
        [
            Refusal::Unsynchronized,
            Refusal::Distance,
            Refusal::NoSource
        ]
    );
}

/// An NTS server whose certificate the client does not trust: key
/// establishment fails, and the time is refused.
#[test]
fn untrusted_nts_certificate_is_refused() {
    let Some(tools) = Tools::get() else { return };
    let mut lab = Lab::new(&tools);
    let nts = lab.nts_server(NTS);
    let untrusted = lab.dir.join("untrusted.pem");
    let socket = lab.client(
        &format!("{}\nntstrustedcerts {}\n", nts.line(), untrusted.display()),
        None,
    );
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("an NTS-KE attempt", || {
        client.authentication(NTS).is_ok_and(|a| a.ke_attempts >= 1)
    });
    assert_no_keys(&mut client);
    assert_unsynchronized(&client.tracking().unwrap());
    assert_eq!(
        judge(&mut client),
        [
            Refusal::Unsynchronized,
            Refusal::Distance,
            Refusal::NoSource
        ]
    );
}

/// A local reference: a normal leap status and a distance the gate
/// admits, but unsynchronized, with no source contributing.
#[test]
fn local_reference_is_refused() {
    let Some(tools) = Tools::get() else { return };
    let mut lab = Lab::new(&tools);
    let nobody = Server::absent(PLAIN, false);
    let socket =
        lab.client(&format!("local stratum 10\n{}\n", nobody.line()), None);
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("the local reference", || {
        client
            .tracking()
            .is_ok_and(|t| t.reference_id == RefId::LOCAL)
    });
    let tracking = client.tracking().unwrap();
    assert!(!tracking.is_synchronized());
    assert_eq!(tracking.leap, Leap::Normal);
    assert_eq!(tracking.stratum, 10);
    assert_eq!(tracking.address, Address::Unspecified);
    assert!(
        tracking.root_distance() < DOCUMENTED.distance,
        "{tracking:?}"
    );
    assert_eq!(
        judge(&mut client),
        [Refusal::Unsynchronized, Refusal::NoSource]
    );
}

/// A reference clock synchronizes chronyd without NTP; its time is not
/// NTS-authenticated, and is refused.
#[test]
fn reference_clock_is_refused() {
    let Some(tools) = Tools::get() else { return };
    let mut lab = Lab::new(&tools);
    let path = lab.dir.join("refclock.sock");
    let socket = lab.client(
        &format!(
            "refclock SOCK {} refid TEST poll 0 dpoll -2 filter 4\n",
            path.display()
        ),
        None,
    );
    let stop = Arc::new(AtomicBool::new(false));
    let feeder = feed_refclock(path, stop.clone());
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("synchronization to the reference clock", || {
        client.tracking().is_ok_and(|t| t.is_synchronized())
    });
    let tracking = client.tracking().unwrap();
    assert_eq!(tracking.address, Address::Unspecified);
    assert_eq!(tracking.reference_id.name(), "TEST");
    assert_eq!(tracking.stratum, 1);
    let source = &client.sources().unwrap()[0];
    assert_eq!(source.mode, SourceMode::RefClock);
    assert_eq!(source.state, SourceState::Selected);
    assert_eq!(source.refclock_id().unwrap().name(), "TEST");
    assert_eq!(judge(&mut client), [Refusal::RefClock]);
    stop.store(true, Ordering::Relaxed);
    feeder.join().unwrap();
}

/// A client daemon with an NTS server and a plain server marked `prefer`,
/// under `authselectmode` `mode`, once both are sampled and one selected;
/// with both sources' selection reports.
fn select_under(
    tools: &Tools,
    mode: &str,
) -> (Lab, Client, Selection, Selection) {
    let mut lab = Lab::new(tools);
    let nts = lab.nts_server(NTS);
    let plain = lab.plain_server();
    let socket = lab.client(
        &format!(
            "authselectmode {mode}\n{}\n{} prefer\n",
            nts.line(),
            plain.line()
        ),
        None,
    );
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("both sources sampled and one selected", || {
        client.authentication(NTS).is_ok_and(|a| a.key_bits > 0)
            && client.tracking().is_ok_and(|t| t.root_distance() < 0.01)
            && client.sources().is_ok_and(|sources| {
                sources.len() == 2
                    && sources.iter().all(|s| s.last_sample_ago.is_some())
                    && sources.iter().any(|s| s.state == SourceState::Selected)
            })
    });
    let selection = |client: &mut Client, ip: Ipv4Addr| {
        (0..2)
            .map(|index| client.selection(index).unwrap())
            .find(|s| s.address == Address::V4(ip))
            .unwrap()
    };
    let nts = selection(&mut client, NTS);
    let plain = selection(&mut client, PLAIN);
    (lab, client, nts, plain)
}

/// `require`: unauthenticated sources get `noselect`, so even a
/// preferred plain server never drives the clock.
#[test]
fn authentication_required() {
    let Some(tools) = Tools::get() else { return };
    let (_lab, mut client, _, plain) = select_under(&tools, "require");
    assert!(plain.effective_options.contains(SelectOptions::NOSELECT));
    assert_eq!(judge(&mut client), []);
}

/// `prefer`: with an NTS source configured, unauthenticated sources get
/// `noselect` as under `require`.
#[test]
fn authentication_preferred() {
    let Some(tools) = Tools::get() else { return };
    let (_lab, mut client, _, plain) = select_under(&tools, "prefer");
    assert!(plain.effective_options.contains(SelectOptions::NOSELECT));
    assert_eq!(judge(&mut client), []);
}

/// `ignore`: authentication plays no part in selection, so the preferred
/// plain server drives the clock beside a working NTS server.
#[test]
fn authentication_ignored() {
    let Some(tools) = Tools::get() else { return };
    let (_lab, mut client, _, plain) = select_under(&tools, "ignore");
    assert!(!plain.effective_options.contains(SelectOptions::NOSELECT));
    assert_eq!(plain.state, SelectState::Selected);
    assert_eq!(judge(&mut client), [Refusal::Unauthenticated]);
}

/// `mix`, chronyd's default: NTS sources get `require` and `trust`, and a
/// plain source is used only while it agrees with them, which the lab
/// does not control. Either way, only a contributing plain source
/// refuses the time.
#[test]
fn authentication_mixed() {
    let Some(tools) = Tools::get() else { return };
    let (_lab, mut client, nts, plain) = select_under(&tools, "mix");
    let required = SelectOptions::REQUIRE | SelectOptions::TRUST;
    assert!(nts.effective_options.contains(required), "{nts:?}");
    assert!(!plain.effective_options.intersects(required), "{plain:?}");
    assert!(!plain.effective_options.contains(SelectOptions::NOSELECT));
    let refused = judge(&mut client);
    assert!(
        refused.is_empty() || refused == [Refusal::Unauthenticated],
        "{refused:?}"
    );
}

/// `prefer` decides from the configuration: with an NTS source
/// configured, plain sources get `noselect` even while it is unreachable,
/// so chronyd stays unsynchronized rather than follow a plain server.
#[test]
fn preferred_authentication_never_falls_back() {
    let Some(tools) = Tools::get() else { return };
    let mut lab = Lab::new(&tools);
    let nobody = Server::absent(NTS, true);
    let plain = lab.plain_server();
    let socket = lab.client(
        &format!(
            "authselectmode prefer\n{}\n{}\n",
            nobody.line(),
            plain.line()
        ),
        None,
    );
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("an NTS-KE attempt and a plain sample", || {
        client.authentication(NTS).is_ok_and(|a| a.ke_attempts >= 1)
            && client.sources().is_ok_and(|sources| {
                sources.iter().any(|s| {
                    s.address == Address::V4(PLAIN)
                        && s.last_sample_ago.is_some()
                })
            })
    });
    assert!(
        plain_selection(&mut client)
            .effective_options
            .contains(SelectOptions::NOSELECT)
    );
    assert_unsynchronized(&client.tracking().unwrap());
    assert_eq!(
        judge(&mut client),
        [
            Refusal::Unsynchronized,
            Refusal::Distance,
            Refusal::NoSource
        ]
    );
}

/// `require` gives plain sources `noselect` even with no NTS source
/// configured, so chronyd never synchronizes to one.
#[test]
fn required_authentication_without_nts() {
    let Some(tools) = Tools::get() else { return };
    let mut lab = Lab::new(&tools);
    let plain = lab.plain_server();
    let socket = lab
        .client(&format!("authselectmode require\n{}\n", plain.line()), None);
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("a plain sample", || {
        client
            .sources()
            .is_ok_and(|sources| sources[0].last_sample_ago.is_some())
    });
    assert!(
        plain_selection(&mut client)
            .effective_options
            .contains(SelectOptions::NOSELECT)
    );
    assert_unsynchronized(&client.tracking().unwrap());
    assert_eq!(
        judge(&mut client),
        [
            Refusal::Unsynchronized,
            Refusal::Distance,
            Refusal::NoSource
        ]
    );
}

/// The selection report of the plain server at 127.0.0.2.
fn plain_selection(client: &mut Client) -> Selection {
    let count = client.sources().unwrap().len() as u32;
    (0..count)
        .map(|index| client.selection(index).unwrap())
        .find(|s| s.address == Address::V4(PLAIN))
        .unwrap()
}

/// Two NTS servers: whichever drives the clock, and whether or not the
/// other is combined with it, the time is trusted.
#[test]
fn two_nts_servers_are_trusted() {
    let Some(tools) = Tools::get() else { return };
    let mut lab = Lab::new(&tools);
    let first = lab.nts_server(NTS);
    let second = lab.nts_server(NTS_2);
    let socket = lab.client(
        &format!(
            "authselectmode require\n{}\n{}\n",
            first.line(),
            second.line()
        ),
        None,
    );
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("NTS synchronization with keys from both", || {
        client.authentication(NTS).is_ok_and(|a| a.key_bits > 0)
            && client.authentication(NTS_2).is_ok_and(|a| a.key_bits > 0)
            && client
                .tracking()
                .is_ok_and(|t| t.is_synchronized() && t.root_distance() < 0.01)
    });
    assert_eq!(judge(&mut client), []);
}

/// The only NTS server stops answering after synchronization. chronyd
/// keeps reporting itself synchronized, but drops the source after eight
/// unanswered polls, and the time is refused from then on.
#[test]
fn lost_nts_server_is_refused() {
    let Some(tools) = Tools::get() else { return };
    let mut lab = Lab::new(&tools);
    let nts = lab.nts_server(NTS);
    let socket =
        lab.client(&format!("authselectmode require\n{}\n", nts.line()), None);
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("NTS synchronization", || follows_nts(&mut client));
    assert_eq!(judge(&mut client), []);

    lab.kill(&nts);
    lab.wait("the lost source's refusal", || {
        refusals(&mut client, DOCUMENTED)
            .is_ok_and(|r| r == [Refusal::NoSource])
    });
    assert!(client.tracking().unwrap().is_synchronized());
}

/// The distance threshold is applied: a nanosecond bound refuses time
/// otherwise trusted.
#[test]
fn distance_bound_is_applied() {
    let Some(tools) = Tools::get() else { return };
    let mut lab = Lab::new(&tools);
    let nts = lab.nts_server(NTS);
    let socket =
        lab.client(&format!("authselectmode require\n{}\n", nts.line()), None);
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("NTS synchronization", || follows_nts(&mut client));
    let tight = Limits {
        distance: 1e-9,
        ..DOCUMENTED
    };
    assert_eq!(refusals(&mut client, tight).unwrap(), [Refusal::Distance]);
    assert_eq!(judge(&mut client), []);
}

/// A reset of the client's clock by an hour, and back. chronyd reports
/// itself unsynchronized from the next request; once it has measured
/// again it reports itself synchronized with the error in the correction,
/// which the gate refuses, and its corrected time is true time. Put back,
/// the clock is trusted again.
#[test]
fn clock_reset_is_refused() {
    let Some(tools) = Tools::get() else { return };
    let Some(fake) = tools.fake_clock() else {
        return;
    };
    let mut lab = Lab::new(&tools);
    let nts = lab.nts_server(NTS);
    let clock = lab.fake_clock(&fake);
    let socket = lab.client(
        &format!("authselectmode require\n{}\n", nts.line()),
        Some(&clock),
    );
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("NTS synchronization", || follows_nts(&mut client));
    assert_eq!(judge(&mut client), []);

    for (offset, refused) in [(3600, vec![Refusal::Correction]), (0, vec![])] {
        clock.set(offset);
        assert_unsynchronized(&client.tracking().unwrap());
        assert_eq!(
            judge(&mut client),
            [
                Refusal::Unsynchronized,
                Refusal::Distance,
                Refusal::NoSource
            ]
        );

        lab.wait("synchronization after the reset", || {
            follows_nts(&mut client)
                && client
                    .tracking()
                    .is_ok_and(|t| (t.correction + offset as f64).abs() < 0.01)
        });
        // chronyd's clock reads `offset` seconds past true time; its
        // corrected time is true time.
        let tracking = client.tracking().unwrap();
        let theirs = shift(SystemTime::now(), offset);
        assert_near(tracking.corrected(theirs), SystemTime::now(), 0.05);
        assert_eq!(judge(&mut client), refused);
    }
}

/// A reset by five seconds: once chronyd has measured again it holds the
/// error in the correction, and its corrected time is true time. The
/// documented bound refuses that correction; a looser one admits it.
#[test]
fn small_clock_reset_is_refused() {
    let Some(tools) = Tools::get() else { return };
    let Some(fake) = tools.fake_clock() else {
        return;
    };
    let mut lab = Lab::new(&tools);
    let nts = lab.nts_server(NTS);
    let clock = lab.fake_clock(&fake);
    let socket = lab.client(
        &format!("authselectmode require\n{}\n", nts.line()),
        Some(&clock),
    );
    let mut client = Client::connect(&socket).unwrap();
    lab.wait("NTS synchronization", || follows_nts(&mut client));

    clock.set(5);
    // The first update after a reset can carry a dispersion over a
    // second; wait for it to settle.
    lab.wait("the correction", || {
        follows_nts(&mut client)
            && client
                .tracking()
                .is_ok_and(|t| (t.correction + 5.0).abs() < 0.05)
    });
    let tracking = client.tracking().unwrap();
    assert!(tracking.is_synchronized());
    let theirs = shift(SystemTime::now(), 5);
    assert_near(tracking.corrected(theirs), SystemTime::now(), 0.1);
    assert_eq!(judge(&mut client), [Refusal::Correction]);
    let loose = Limits {
        correction: 10.0,
        ..DOCUMENTED
    };
    assert_eq!(refusals(&mut client, loose).unwrap(), []);
}

/// chronyd as the Debian package runs it. Root and the chrony user reach
/// it and trust the time; anyone else, the chrony group included, gets
/// `PermissionDenied`. A killed daemon leaves its socket, and the client
/// gets `ConnectionRefused`.
#[test]
fn packaged_layout() {
    let Some(tools) = Tools::get() else { return };
    let Some(system) = System::get() else { return };
    let mut lab = Lab::new(&tools);
    let nts = lab.nts_server(NTS);
    let mut packaged = Packaged::start(&lab, &system, &nts);
    let mut client = Client::connect(&packaged.socket).unwrap();
    lab.wait("NTS synchronization", || follows_nts(&mut client));
    assert_eq!(judge(&mut client), []);
    drop(client);

    let chrony = &system.chrony;
    let nobody = &system.nobody;
    packaged.child("child_trusts_the_clock", chrony.uid, chrony.gid);
    packaged.child("child_is_refused", nobody.uid, nobody.gid);
    packaged.child("child_is_refused", nobody.uid, chrony.gid);
    assert_eq!(
        leftovers(packaged.socket.parent().unwrap()),
        [] as [String; 0]
    );

    packaged.daemon.kill();
    assert!(packaged.socket.exists());
    let err = Client::connect(&packaged.socket).unwrap_err();
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::ConnectionRefused),
        "{err:?}"
    );
}

/// Run by `packaged_layout` as the chrony user: the client reaches
/// chronyd and the time is trusted.
#[test]
#[ignore = "child case, run by packaged_layout"]
fn child_trusts_the_clock() {
    let socket =
        std::env::var_os(CHILD_SOCKET).expect("the parent names the socket");
    let mut client = Client::connect(socket).unwrap();
    assert_eq!(judge(&mut client), []);
}

/// Run by `packaged_layout` as users the socket's directory refuses.
#[test]
#[ignore = "child case, run by packaged_layout"]
fn child_is_refused() {
    let socket =
        std::env::var_os(CHILD_SOCKET).expect("the parent names the socket");
    let err = Client::connect(socket).unwrap_err();
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::PermissionDenied),
        "{err:?}"
    );
}

/// An NTS source that has no keys.
fn assert_no_keys(client: &mut Client) {
    let auth = client.authentication(NTS).unwrap();
    assert_eq!(auth.mode, AuthMode::Nts);
    assert_eq!(auth.algorithm, Algorithm::None);
    assert_eq!((auth.key_bits, auth.cookies), (0, 0));
    assert_eq!(auth.last_ke_ago, None);
}

/// Tracking with no reference, which chronyd reports with a root delay
/// and dispersion of a second each.
fn assert_unsynchronized(tracking: &Tracking) {
    assert!(!tracking.is_synchronized(), "{tracking:?}");
    assert_eq!(tracking.leap, Leap::Unsynchronized);
    assert_eq!(tracking.reference_id, RefId(0));
    assert_eq!(tracking.address, Address::Unspecified);
    assert_eq!(tracking.stratum, 0);
    assert_eq!(tracking.reference_time, UNIX_EPOCH);
    assert_eq!((tracking.root_delay, tracking.root_dispersion), (1.0, 1.0));
}

/// The client's reply directories left in `dir`.
fn leftovers(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("truenas_chrony."))
        .collect()
}

/// `time` `secs` seconds later.
fn shift(time: SystemTime, secs: i64) -> SystemTime {
    let by = Duration::from_secs(secs.unsigned_abs());
    if secs >= 0 { time + by } else { time - by }
}

fn assert_near(ours: Option<SystemTime>, expected: SystemTime, secs: f64) {
    let ours = ours.unwrap();
    let apart = match ours.duration_since(expected) {
        Ok(ahead) => ahead,
        Err(behind) => behind.duration(),
    };
    assert!(apart.as_secs_f64() < secs, "{ours:?} vs {expected:?}");
}

/// Send the reference clock at `path` a sample every 100 ms, saying the
/// system clock is right, until `stop`. A sample, in native byte order:
/// the measurement time as 64-bit seconds and microseconds, the offset of
/// true time from it as an `f64`, a pulse flag and a leap indicator as
/// 32-bit integers, four bytes of padding, and the magic 0x534f434b.
fn feed_refclock(
    path: PathBuf,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let socket = UnixDatagram::unbound().unwrap();
        while !stop.load(Ordering::Relaxed) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let mut sample = Vec::with_capacity(40);
            sample.extend_from_slice(&(now.as_secs() as i64).to_ne_bytes());
            sample.extend_from_slice(
                &i64::from(now.subsec_micros()).to_ne_bytes(),
            );
            sample.extend_from_slice(&0f64.to_ne_bytes());
            sample.extend_from_slice(&0i32.to_ne_bytes());
            sample.extend_from_slice(&0i32.to_ne_bytes());
            sample.extend_from_slice(&0i32.to_ne_bytes());
            sample.extend_from_slice(&0x534f_434bi32.to_ne_bytes());
            let _ = socket.send_to(&sample, &path);
            thread::sleep(Duration::from_millis(100));
        }
    })
}

fn cross_check_tracking(tools: &Tools, socket: &Path, client: &mut Client) {
    let t = client.tracking().unwrap();
    let row = &tools.csv(socket, &["tracking"])[0];
    assert_eq!(row[0], format!("{:08X}", t.reference_id.0));
    assert_eq!(row[1], t.address.to_string());
    assert_eq!(row[2], t.stratum.to_string());
    assert_eq!(row[3], timestamp(t.reference_time));
    // The correction and the root dispersion move with time.
    near(t.correction, &row[4], 1e-6, "correction");
    same(t.last_offset, &row[5], "last offset");
    same(t.rms_offset, &row[6], "rms offset");
    same(t.frequency_ppm, &row[7], "frequency");
    same(t.residual_frequency_ppm, &row[8], "residual frequency");
    same(t.skew_ppm, &row[9], "skew");
    same(t.root_delay, &row[10], "root delay");
    near(t.root_dispersion, &row[11], 1e-4, "root dispersion");
    same(t.update_interval, &row[12], "update interval");
    assert_eq!(row[13], leap(t.leap));
}

fn cross_check_sources(tools: &Tools, socket: &Path, client: &mut Client) {
    let sources = client.sources().unwrap();
    let rows = tools.csv(socket, &["sources", "-a"]);
    assert_eq!(sources.len(), 3);
    assert_eq!(rows.len(), sources.len());
    for (s, row) in sources.iter().zip(&rows) {
        let mode = match s.mode {
            SourceMode::Server => "^",
            SourceMode::Peer => "=",
            SourceMode::RefClock => "#",
            other => panic!("{other:?}"),
        };
        let state = match s.state {
            SourceState::Selected => "*",
            SourceState::Unusable => "?",
            SourceState::Falseticker => "x",
            SourceState::Jittery => "~",
            SourceState::Combined => "+",
            SourceState::Selectable => "-",
            other => panic!("{other:?}"),
        };
        assert_eq!((row[0].as_str(), row[1].as_str()), (mode, state));
        let name = match s.refclock_id() {
            Some(id) => id.name(),
            None => s.address.to_string(),
        };
        assert_eq!(row[2], name);
        assert_eq!(row[3], s.stratum.to_string());
        assert_eq!(row[4], s.poll.to_string());
        assert_eq!(row[5], format!("{:o}", s.reachability));
        ago(s.last_sample_ago, &row[6], "last sample");
        same(s.adjusted_offset, &row[7], "adjusted offset");
        same(s.measured_offset, &row[8], "measured offset");
        same(s.offset_error, &row[9], "offset error");
    }
    let index = |address: Ipv4Addr| {
        (0u32..)
            .zip(&sources)
            .find(|(_, s)| s.address == Address::V4(address))
            .unwrap()
            .0
    };
    let (nts, plain) = (index(NTS), index(PLAIN));
    let refclock = sources.iter().find(|s| s.mode == SourceMode::RefClock);
    assert_eq!(refclock.unwrap().refclock_id().unwrap().name(), "TEST");
    let (n, p) = (&sources[nts as usize], &sources[plain as usize]);
    assert_eq!((n.stratum, p.stratum), (1, 2));
    assert_eq!((n.poll, p.poll), (-2, -2));

    let rows = tools.csv(socket, &["selectdata", "-a"]);
    for (index, row) in (0u32..).zip(&rows) {
        let s = client.selection(index).unwrap();
        assert_eq!(row[0], char::from(s.state.code()).to_string());
        let name = match s.address {
            Address::Unspecified => s.reference_id.name(),
            address => address.to_string(),
        };
        assert_eq!(row[1], name);
        assert_eq!(row[2], if s.authenticated { "Y" } else { "N" });
        assert_eq!(row[3..8], options(s.configured_options.bits()));
        assert_eq!(row[8..13], options(s.effective_options.bits()));
        assert_eq!(row[13], s.last_sample_ago.unwrap_or(u32::MAX).to_string());
        same(s.score, &row[14], "score");
        same(s.lower_limit, &row[15], "lower limit");
        same(s.upper_limit, &row[16], "upper limit");
        assert_eq!(row[17], leap(s.leap));
    }
    assert!(client.selection(nts).unwrap().authenticated);
    let plain = client.selection(plain).unwrap();
    assert!(!plain.authenticated);
    assert!(!matches!(
        plain.state,
        SelectState::Selected | SelectState::Combined
    ));
}

fn cross_check_authentication(
    tools: &Tools,
    socket: &Path,
    client: &mut Client,
) {
    let rows = tools.csv(socket, &["authdata", "-a"]);
    assert_eq!(rows.len(), 2);
    for row in &rows {
        let ip: Ipv4Addr = row[0].parse().unwrap();
        let a = client.authentication(ip).unwrap();
        let mode = match a.mode {
            AuthMode::None => "-",
            AuthMode::SymmetricKey => "SK",
            AuthMode::Nts => "NTS",
            other => panic!("{other:?}"),
        };
        assert_eq!(row[1], mode);
        assert_eq!(row[2], a.key_id.to_string());
        assert_eq!(row[3], a.algorithm.code().to_string());
        assert_eq!(row[4], a.key_bits.to_string());
        ago(a.last_ke_ago, &row[5], "last NTS-KE");
        assert_eq!(row[6], a.ke_attempts.to_string());
        assert_eq!(row[7], u16::from(a.nak).to_string());
        assert_eq!(row[8], a.cookies.to_string());
        assert_eq!(row[9], a.cookie_length.to_string());
    }
}

/// `ours`, which chronyc printed as `theirs`: equal to it within half a
/// unit of its last printed digit.
fn same(ours: f64, theirs: &str, what: &str) {
    let decimals = theirs.split_once('.').map_or(0, |(_, d)| d.len());
    near(
        ours,
        theirs,
        0.5 * 10f64.powi(-(decimals as i32)) * 1.000_001,
        what,
    );
}

fn near(ours: f64, theirs: &str, tolerance: f64, what: &str) {
    let value: f64 = theirs
        .parse()
        .unwrap_or_else(|_| panic!("{what}: {theirs:?}"));
    assert!(
        (ours - value).abs() <= tolerance,
        "{what}: ours {ours}, chronyc {theirs}"
    );
}

/// An elapsed time chronyc printed, all ones for none, read a moment
/// apart from ours.
fn ago(ours: Option<u32>, theirs: &str, what: &str) {
    let theirs: u32 = theirs.parse().unwrap();
    match ours {
        None => assert_eq!(theirs, u32::MAX, "{what}"),
        Some(ours) => assert!(
            theirs >= ours && theirs - ours <= 3,
            "{what}: ours {ours}, chronyc {theirs}"
        ),
    }
}

fn timestamp(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap();
    format!("{}.{:09}", d.as_secs(), d.subsec_nanos())
}

fn leap(leap: Leap) -> &'static str {
    match leap {
        Leap::Normal => "Normal",
        Leap::InsertSecond => "Insert second",
        Leap::DeleteSecond => "Delete second",
        Leap::Unsynchronized => "Not synchronised",
        Leap::Unknown(code) => panic!("leap {code}"),
    }
}

/// Selection options as chronyc prints them: N, P, T, R, and a fifth
/// column it leaves `-`.
fn options(bits: u16) -> [String; 5] {
    let flag =
        |bit: u16, c: &'static str| if bits & bit != 0 { c } else { "-" };
    [flag(1, "N"), flag(2, "P"), flag(4, "T"), flag(8, "R"), "-"]
        .map(String::from)
}

/// Skip the scenario, or fail it when `require` is set.
fn skip(require: &str, why: &str) {
    if std::env::var_os(require).is_some() {
        panic!("{require} is set but {why}");
    }
    eprintln!("skipped: {why}");
}

/// The host's chronyd, chronyc, and libfaketime, and the test
/// certificates.
struct Tools {
    chronyd: PathBuf,
    chronyc: PathBuf,
    faketime: Option<PathBuf>,
    certificates: &'static Certificates,
}

impl Tools {
    /// The tools, held to the floor; `None`, having said so, to skip.
    fn get() -> Option<Tools> {
        let chronyd = locate("TRUENAS_CHRONY_CHRONYD", "chronyd", None);
        let chronyc = chronyd.as_deref().and_then(|d| {
            locate("TRUENAS_CHRONY_CHRONYC", "chronyc", d.parent())
        });
        let (Some(chronyd), Some(chronyc)) = (chronyd, chronyc) else {
            skip(REQUIRE, "chronyd and chronyc are not installed");
            return None;
        };
        let Some(certificates) = certificates() else {
            skip(REQUIRE, "openssl is not installed");
            return None;
        };
        let tools = Tools {
            chronyd,
            chronyc,
            faketime: locate_faketime(),
            certificates,
        };
        tools.check_floor();
        Some(tools)
    }

    /// libfaketime; `None`, having said so, to skip.
    fn fake_clock(&self) -> Option<PathBuf> {
        if self.faketime.is_none() {
            skip(REQUIRE, "libfaketime is not installed");
        }
        self.faketime.clone()
    }

    /// Hold both binaries to the floor, and chronyd to NTS support.
    fn check_floor(&self) {
        for tool in [&self.chronyd, &self.chronyc] {
            let out = Command::new(tool).arg("-v").output().unwrap();
            let text = String::from_utf8_lossy(&out.stdout).into_owned()
                + &String::from_utf8_lossy(&out.stderr);
            let version = parse_version(&text).unwrap_or_else(|| {
                panic!("{}: no version in {text:?}", tool.display())
            });
            assert!(
                version >= FLOOR,
                "{} is version {}.{}.{}; this crate is held to chronyd \
                 {}.{}.{} and later",
                tool.display(),
                version.0,
                version.1,
                version.2,
                FLOOR.0,
                FLOOR.1,
                FLOOR.2,
            );
            if *tool == self.chronyd {
                assert!(
                    text.contains("+NTS"),
                    "{} is built without NTS: {text}",
                    tool.display()
                );
            }
        }
    }

    /// Run chronyc against the daemon at `socket`.
    fn chronyc(&self, socket: &Path, args: &[&str]) -> String {
        let out = Command::new(&self.chronyc)
            .args(["-n", "-h"])
            .arg(socket)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "chronyc {args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }

    /// chronyc's CSV report, split into rows of fields.
    fn csv(&self, socket: &Path, args: &[&str]) -> Vec<Vec<String>> {
        let mut all = vec!["-c"];
        all.extend_from_slice(args);
        self.chronyc(socket, &all)
            .lines()
            .map(|l| l.split(',').map(String::from).collect())
            .collect()
    }
}

/// The test certificates, as PEM.
struct Certificates {
    /// For 127.0.0.1 and 127.0.0.3, presented by the NTS servers.
    cert: String,
    key: String,
    /// One no server presents.
    untrusted: String,
}

/// The test certificates, made once per process by the `openssl` command;
/// `None` if it is not installed. They are valid for two days from their
/// making; the scenarios move clocks forward by an hour at most.
fn certificates() -> Option<&'static Certificates> {
    static MADE: OnceLock<Option<Certificates>> = OnceLock::new();
    MADE.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let make = |name: &str| {
            let cert = dir.path().join(format!("{name}.pem"));
            let key = dir.path().join(format!("{name}.key"));
            let made = Command::new("openssl")
                .args(["req", "-x509", "-newkey", "ec", "-pkeyopt"])
                .args(["ec_paramgen_curve:P-256", "-nodes", "-days", "2"])
                .args(["-subj", "/CN=127.0.0.1", "-addext"])
                .arg("subjectAltName=IP:127.0.0.1,IP:127.0.0.3")
                .arg("-keyout")
                .arg(&key)
                .arg("-out")
                .arg(&cert)
                .stdin(Stdio::null())
                .output();
            match made {
                Err(err) if err.kind() == io::ErrorKind::NotFound => None,
                made => {
                    let made = made.unwrap();
                    assert!(made.status.success(), "openssl: {made:?}");
                    let read = |path| fs::read_to_string(path).unwrap();
                    Some((read(&cert), read(&key)))
                }
            }
        };
        let (cert, key) = make("nts")?;
        let (untrusted, _) = make("untrusted")?;
        Some(Certificates {
            cert,
            key,
            untrusted,
        })
    })
    .as_ref()
}

/// A binary named by `env`, else `name` beside `sibling`, in the PATH,
/// or in the sbin directories a test environment's PATH often lacks.
fn locate(env: &str, name: &str, sibling: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(env) {
        return Some(PathBuf::from(path));
    }
    let path = std::env::var("PATH").unwrap_or_default();
    sibling
        .into_iter()
        .map(Path::to_path_buf)
        .chain(path.split(':').filter(|d| !d.is_empty()).map(PathBuf::from))
        .chain(["/usr/sbin", "/sbin", "/usr/bin"].map(PathBuf::from))
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// libfaketime as TRUENAS_CHRONY_FAKETIME names it, or where Debian and
/// its relatives install it.
fn locate_faketime() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("TRUENAS_CHRONY_FAKETIME") {
        return Some(PathBuf::from(path));
    }
    let multiarch = fs::read_dir("/usr/lib")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with("-linux-gnu"));
    multiarch
        .chain(["/usr/lib", "/usr/lib64"].map(PathBuf::from))
        .map(|dir| dir.join("faketime/libfaketime.so.1"))
        .find(|candidate| candidate.is_file())
}

/// `major.minor[.patch]` after "version " in `-v` output; a pre-release
/// suffix is dropped.
fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let word = text.split("version ").nth(1)?.split_whitespace().next()?;
    let mut parts = word.split('.').map(|p| {
        p.chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u32>()
    });
    let major = parts.next()?.ok()?;
    let minor = parts.next()?.ok()?;
    let patch = parts.next().and_then(Result::ok).unwrap_or(0);
    Some((major, minor, patch))
}

/// An upstream NTP server, and its daemon when one runs.
struct Server {
    ip: Ipv4Addr,
    port: u16,
    /// The NTS-KE port, for an NTS server.
    ke_port: Option<u16>,
    daemon: Option<usize>,
}

impl Server {
    /// A server with nothing behind its ports.
    fn absent(ip: Ipv4Addr, nts: bool) -> Server {
        Server {
            ip,
            port: free_udp(ip),
            ke_port: nts.then(|| free_tcp(ip)),
            daemon: None,
        }
    }

    /// The client configuration line for it, polled four times a second.
    fn line(&self) -> String {
        let nts = match self.ke_port {
            Some(port) => format!(" nts ntsport {port}"),
            None => String::new(),
        };
        format!(
            "server {} port {}{nts} iburst minpoll -2 maxpoll -2",
            self.ip, self.port
        )
    }
}

/// The offset file of a client daemon run under libfaketime. An offset
/// must exceed a second; smaller ones are not measured faithfully under
/// libfaketime.
struct FakeClock {
    library: PathBuf,
    file: PathBuf,
}

impl FakeClock {
    /// Set the daemon's clock `secs` seconds past true time. The file is
    /// replaced whole, so the daemon never reads it half written.
    fn set(&self, secs: i64) {
        let next = self.file.with_extension("next");
        fs::write(&next, format!("{secs:+}\n")).unwrap();
        fs::rename(&next, &self.file).unwrap();
    }
}

/// One daemon, killed when dropped.
struct Daemon {
    child: Child,
    log: PathBuf,
}

impl Daemon {
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Daemons in a temporary directory, killed and removed when dropped.
struct Lab {
    // Daemons go before their directory.
    daemons: Vec<Daemon>,
    dir: PathBuf,
    chronyd: PathBuf,
    user: String,
    _tmp: tempfile::TempDir,
}

impl Lab {
    fn new(tools: &Tools) -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        // chronyd disables a command socket whose directory others can
        // reach.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        // A private copy: confinement profiles attach to the installed
        // path, and would keep the daemon from this directory.
        let chronyd = dir.join("chronyd");
        fs::copy(&tools.chronyd, &chronyd).unwrap();
        let certificates = tools.certificates;
        fs::write(dir.join("nts.pem"), &certificates.cert).unwrap();
        fs::write(dir.join("untrusted.pem"), &certificates.untrusted).unwrap();
        let key = dir.join("nts.key");
        fs::write(&key, &certificates.key).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        Lab {
            daemons: Vec::new(),
            dir,
            chronyd,
            user: user_name(own_uid()),
            _tmp: tmp,
        }
    }

    /// An NTS server at `ip`, stratum 1, presenting the test certificate.
    fn nts_server(&mut self, ip: Ipv4Addr) -> Server {
        let mut server = Server::absent(ip, true);
        let d = &self.dir;
        let config = format!(
            "bindaddress {ip}\nport {}\nallow 127.0.0.0/8\nlocal stratum 1\n\
             ntsserverkey {}\nntsservercert {}\nntsport {}\n\
             ntsprocesses 0\n",
            server.port,
            d.join("nts.key").display(),
            d.join("nts.pem").display(),
            server.ke_port.unwrap()
        );
        self.start(&format!("nts{}", ip.octets()[3]), config, None);
        server.daemon = Some(self.daemons.len() - 1);
        server
    }

    /// A plain NTP server on 127.0.0.2 at stratum 2.
    fn plain_server(&mut self) -> Server {
        let mut server = Server::absent(PLAIN, false);
        let config = format!(
            "bindaddress {PLAIN}\nport {}\nallow 127.0.0.0/8\n\
             local stratum 2\n",
            server.port
        );
        self.start("plain", config, None);
        server.daemon = Some(self.daemons.len() - 1);
        server
    }

    /// Stop `server`'s daemon.
    fn kill(&mut self, server: &Server) {
        self.daemons[server.daemon.unwrap()].kill();
    }

    /// An offset file for a client daemon's clock, starting at true time.
    fn fake_clock(&self, library: &Path) -> FakeClock {
        let clock = FakeClock {
            library: library.to_path_buf(),
            file: self.dir.join("faketime"),
        };
        clock.set(0);
        clock
    }

    /// The client daemon under test: `config`, trusting the test
    /// certificate unless it names certificates of its own. Returns its
    /// command socket.
    fn client(&mut self, config: &str, clock: Option<&FakeClock>) -> PathBuf {
        let trust = if config.contains("ntstrustedcerts") {
            String::new()
        } else {
            format!("ntstrustedcerts {}\n", self.dir.join("nts.pem").display())
        };
        self.start("client", format!("port 0\n{trust}{config}\n"), clock)
    }

    /// Start a daemon with `config` and wait for its command socket.
    fn start(
        &mut self,
        name: &str,
        config: String,
        clock: Option<&FakeClock>,
    ) -> PathBuf {
        let d = &self.dir;
        let conf = d.join(format!("{name}.conf"));
        let socket = d.join(format!("{name}.sock"));
        let log = d.join(format!("{name}.log"));
        let config = format!(
            "pidfile {}\nbindcmdaddress {}\ncmdport 0\n{config}",
            d.join(format!("{name}.pid")).display(),
            socket.display()
        );
        fs::write(&conf, config).unwrap();
        let out = File::create(&log).unwrap();
        let mut command = Command::new(&self.chronyd);
        command
            .args(["-d", "-x", "-U", "-u", &self.user, "-f"])
            .arg(&conf)
            .stdin(Stdio::null())
            .stdout(out.try_clone().unwrap())
            .stderr(out);
        if let Some(clock) = clock {
            command
                .env("LD_PRELOAD", &clock.library)
                .env("FAKETIME_TIMESTAMP_FILE", &clock.file)
                .env("FAKETIME_NO_CACHE", "1")
                .env("FAKETIME_DONT_FAKE_MONOTONIC", "1");
        }
        let child = spawn(&mut command);
        self.daemons.push(Daemon { child, log });
        let daemon = self.daemons.last_mut().unwrap();
        await_socket(daemon, &socket, name);
        socket
    }

    /// Wait for `ready`, failing with the daemons' logs if it does not
    /// come.
    fn wait(&self, what: &str, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + PATIENCE;
        while !ready() {
            if Instant::now() >= deadline {
                let logs: Vec<String> = self
                    .daemons
                    .iter()
                    .map(|d| fs::read_to_string(&d.log).unwrap_or_default())
                    .collect();
                panic!("no {what} in {PATIENCE:?}\n{}", logs.join("\n"));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Wait for a daemon's command socket to answer.
fn await_socket(daemon: &mut Daemon, socket: &Path, name: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(mut client) = Client::connect(socket)
            && client.tracking().is_ok()
        {
            return;
        }
        let exited = daemon.child.try_wait().unwrap();
        assert!(
            exited.is_none() && Instant::now() < deadline,
            "chronyd {name} did not come up ({exited:?}):\n{}",
            fs::read_to_string(&daemon.log).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(50));
    }
}

/// A user account from the password file.
struct Account {
    name: String,
    uid: u32,
    gid: u32,
}

/// What the packaged scenario needs: root, the chrony package's user,
/// and an account with no part in chrony.
struct System {
    chrony: Account,
    nobody: Account,
}

impl System {
    /// The accounts; `None`, having said so, to skip.
    fn get() -> Option<System> {
        if own_uid() != 0 {
            skip(REQUIRE_ROOT, "the suite is not running as root");
            return None;
        }
        // Debian's name for the chrony user, then other distributions'.
        let Some(chrony) = account("_chrony").or_else(|| account("chrony"))
        else {
            skip(REQUIRE_ROOT, "the chrony package's user does not exist");
            return None;
        };
        let nobody = account("nobody").expect("an account named nobody");
        Some(System { chrony, nobody })
    }
}

/// chronyd as the Debian package runs it, under a temporary root: started
/// as root under the package's seccomp filter, dropping to the chrony
/// user, its socket in `run/chrony` (0700, that user's). The test binary
/// is copied in for every user to run.
struct Packaged {
    // The daemon goes before its directory.
    daemon: Daemon,
    socket: PathBuf,
    test: PathBuf,
    _root: tempfile::TempDir,
}

impl Packaged {
    fn start(lab: &Lab, system: &System, upstream: &Server) -> Packaged {
        let root = tempfile::tempdir().unwrap();
        let open = |path: &Path| {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                .unwrap()
        };
        open(root.path());
        let (etc, run) = (root.path().join("etc"), root.path().join("run"));
        for dir in [&etc, &run] {
            fs::create_dir(dir).unwrap();
            open(dir);
        }
        let socket_dir = run.join("chrony");
        fs::create_dir(&socket_dir).unwrap();
        fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o700))
            .unwrap();
        let chrony = &system.chrony;
        std::os::unix::fs::chown(
            &socket_dir,
            Some(chrony.uid),
            Some(chrony.gid),
        )
        .unwrap();

        let cert = etc.join("nts.pem");
        fs::copy(lab.dir.join("nts.pem"), &cert).unwrap();
        let socket = socket_dir.join("chronyd.sock");
        let conf = etc.join("chrony.conf");
        let config = format!(
            "pidfile {}\nbindcmdaddress {}\ncmdport 0\nport 0\n\
             authselectmode require\n{}\nntstrustedcerts {}\n",
            socket_dir.join("chronyd.pid").display(),
            socket.display(),
            upstream.line(),
            cert.display()
        );
        fs::write(&conf, config).unwrap();
        let log = root.path().join("chronyd.log");
        let out = File::create(&log).unwrap();
        let child = spawn(
            Command::new(&lab.chronyd)
                .args(["-d", "-x", "-F", "1", "-u", &chrony.name, "-f"])
                .arg(&conf)
                .stdin(Stdio::null())
                .stdout(out.try_clone().unwrap())
                .stderr(out),
        );
        let mut daemon = Daemon { child, log };
        await_socket(&mut daemon, &socket, "packaged");

        let test = root.path().join("test");
        fs::copy(std::env::current_exe().unwrap(), &test).unwrap();
        open(&test);
        Packaged {
            daemon,
            socket,
            test,
            _root: root,
        }
    }

    /// Run child case `case` as `uid`:`gid`, with no supplementary groups,
    /// against this daemon.
    fn child(&self, case: &str, uid: u32, gid: u32) {
        let output = spawn(
            Command::new(&self.test)
                .arg(case)
                .args(["--exact", "--ignored"])
                .env(CHILD_SOCKET, &self.socket)
                .current_dir("/")
                .uid(uid)
                .gid(gid)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
        .wait_with_output()
        .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "case {case} as {uid}:{gid} failed\nstdout:\n{stdout}\n\
             stderr:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        // A filter that matches nothing exits zero, so a renamed case
        // must not pass for one that ran.
        assert!(
            stdout.contains("1 passed"),
            "case {case} did not run\nstdout:\n{stdout}"
        );
    }
}

/// Spawn `command`, retrying while its executable is busy: a binary just
/// copied here stays open for writing in children other threads have
/// forked but not yet executed.
fn spawn(command: &mut Command) -> Child {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match command.spawn() {
            Err(err)
                if err.kind() == io::ErrorKind::ExecutableFileBusy
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            spawned => return spawned.unwrap(),
        }
    }
}

/// The effective user ID: the owner of a file created now.
fn own_uid() -> u32 {
    tempfile::tempfile().unwrap().metadata().unwrap().uid()
}

/// `name`'s entry in the password file.
fn account(name: &str) -> Option<Account> {
    fs::read_to_string("/etc/passwd")
        .unwrap()
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            (fields.len() > 3 && fields[0] == name).then(|| Account {
                name: name.to_string(),
                uid: fields[2].parse().unwrap(),
                gid: fields[3].parse().unwrap(),
            })
        })
}

/// The name chronyd's `-u` needs for `uid`.
fn user_name(uid: u32) -> String {
    fs::read_to_string("/etc/passwd")
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let id: u32 = fields.nth(1)?.parse().ok()?;
            (id == uid).then(|| name.to_string())
        })
        .unwrap_or_else(|| panic!("uid {uid} has no /etc/passwd entry"))
}

fn free_udp(ip: Ipv4Addr) -> u16 {
    UdpSocket::bind((ip, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_tcp(ip: Ipv4Addr) -> u16 {
    TcpListener::bind((ip, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
