// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Every decode returns, never panics, whatever reaches the reply socket.
//! With its own reply code and enough data, the only failure allowed is
//! `Malformed`.

mod common;

use std::fmt::Debug;

use common::reply;
use truenas_chrony::{Address, Error, Request, Verdict};

/// xorshift64*, seeded fixed so a failure reproduces.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// Feed `request`, with reply code `code` and data length `len`, the
/// corpus.
fn drive<T: Debug>(request: Request<T>, code: u16, len: usize, rng: &mut Rng) {
    let render = |verdict: Verdict<T>| {
        if let Verdict::Answer(result) = verdict {
            let _ = format!("{result:?}");
            if let Err(err) = result {
                let _ = (err.to_string(), err.is_unsupported());
            }
        }
    };
    for _ in 0..500 {
        // Arbitrary datagrams.
        let n = rng.below(700);
        render(request.decode(&rng.bytes(n)));

        // Replies to the request with arbitrary codes and statuses.
        let reply_code = [code, 1, 2, 3, 20, 23, 0xffff][rng.below(7)];
        let status = [0, 0, 0, 3, 18, 19, 0xffff][rng.below(7)];
        let n = rng.below(len + 64);
        let mut datagram =
            reply(request.as_bytes(), reply_code, status, &rng.bytes(n));
        if rng.below(4) == 0 {
            datagram[0] = rng.next() as u8;
        }
        render(request.decode(&datagram));

        // Its own code over arbitrary data, at least the layout's length.
        let n = len + rng.below(32);
        let datagram = reply(request.as_bytes(), code, 0, &rng.bytes(n));
        match request.decode(&datagram) {
            Verdict::Answer(Ok(report)) => drop(format!("{report:?}")),
            Verdict::Answer(Err(Error::Malformed(_))) => {}
            other => panic!("code {code}: {other:?}"),
        }
    }
}

#[test]
fn every_request_survives_hostile_replies() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..4 {
        let seq = rng.next() as u32;
        let addr = Address::Id(rng.next() as u32);
        drive(Request::tracking(seq), 5, 76, &mut rng);
        drive(Request::source_count(seq), 2, 4, &mut rng);
        drive(Request::source(1, seq), 3, 48, &mut rng);
        drive(Request::selection(1, seq), 23, 48, &mut rng);
        drive(Request::authentication(addr, seq), 20, 24, &mut rng);
    }
}
