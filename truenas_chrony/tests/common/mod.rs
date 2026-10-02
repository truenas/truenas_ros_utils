// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! A scripted stand-in for chronyd, answering each request at its sender's
//! address, and replies written out by hand.

// Not every suite uses every helper.
#![allow(dead_code)]

use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use truenas_chrony::Client;

/// A request as the stand-in received it.
#[derive(Clone, Debug)]
pub struct Received {
    pub bytes: Vec<u8>,
    pub from: PathBuf,
}

impl Received {
    /// The command code, bytes 4 and 5.
    pub fn command(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }

    /// The attempt counter, bytes 6 and 7.
    pub fn attempt(&self) -> u16 {
        u16::from_be_bytes([self.bytes[6], self.bytes[7]])
    }

    /// The sequence number, bytes 8 to 11.
    pub fn sequence(&self) -> [u8; 4] {
        self.bytes[8..12].try_into().unwrap()
    }

    /// The request's data, after the 20-byte header.
    pub fn data(&self) -> &[u8] {
        &self.bytes[20..]
    }
}

/// The stand-in daemon.
pub struct Fake {
    dir: tempfile::TempDir,
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Vec<Received>>>,
}

impl Fake {
    /// Serve with `script`: given each request and how many came before,
    /// it returns the datagrams to answer with.
    pub fn start<F>(mut script: F) -> Fake
    where
        F: FnMut(&Received, usize) -> Vec<Vec<u8>> + Send + 'static,
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chronyd.sock");
        let socket = UnixDatagram::bind(&path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = thread::spawn(move || {
            let mut log = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                // Read before the receive, so a request sent before the
                // stop is received before the loop can end.
                let stopped = stopping.load(Ordering::SeqCst);
                let Ok((len, from)) = socket.recv_from(&mut buf) else {
                    if stopped {
                        break;
                    }
                    continue;
                };
                let request = Received {
                    bytes: buf[..len].to_vec(),
                    from: from.as_pathname().unwrap().to_path_buf(),
                };
                for reply in script(&request, log.len()) {
                    // The client may have gone; that is its test's concern.
                    let _ = socket.send_to(&reply, &request.from);
                }
                log.push(request);
            }
            log
        });
        Fake {
            dir,
            path,
            stop,
            thread: Some(thread),
        }
    }

    /// Serve every request with the reply `answer` builds from it.
    pub fn answering<F>(mut answer: F) -> Fake
    where
        F: FnMut(&Received) -> Vec<u8> + Send + 'static,
    {
        Fake::start(move |request, _| vec![answer(request)])
    }

    /// The daemon socket's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The directory clients of this daemon reply to.
    pub fn replies(&self) -> PathBuf {
        self.dir.path().join("replies")
    }

    /// A client of this daemon.
    pub fn connect(&self) -> Client {
        Client::connect_in(&self.path, self.replies()).unwrap()
    }

    /// A client of this daemon that gives up quickly.
    pub fn client(&self) -> Client {
        let mut client = self.connect();
        client.set_timeout(Duration::from_millis(200));
        client.set_attempts(1);
        client
    }

    /// Stop serving, and return every request received.
    pub fn finish(mut self) -> Vec<Received> {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A reply to the request `request` (its bytes), written out field by
/// field: version 6, packet type 2, two zero reserved bytes, the
/// request's command, `code`, `status`, three zero halfwords, the
/// request's sequence number, two zero words, then `data`.
pub fn reply(request: &[u8], code: u16, status: u16, data: &[u8]) -> Vec<u8> {
    let mut out = vec![6, 2, 0, 0];
    out.extend_from_slice(&request[4..6]);
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    out.extend_from_slice(&request[8..12]);
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(data);
    out
}

/// A successful reply with reply code `code` carrying `data`.
pub fn ok(request: &[u8], code: u16, data: &[u8]) -> Vec<u8> {
    reply(request, code, 0, data)
}

/// A failed reply with `status`: reply code 1 and no data, as chronyd
/// sends one.
pub fn status(request: &[u8], status: u16) -> Vec<u8> {
    reply(request, 1, status, &[])
}

/// An address field holding an IPv4 address: the four octets, twelve
/// zero bytes, family 1, two zero bytes.
pub fn ipv4(a: [u8; 4]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[..4].copy_from_slice(&a);
    out[17] = 1;
    out
}

/// Concatenate byte strings.
pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// A `u16`, big-endian.
pub fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

/// A `u32`, big-endian.
pub fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// A `u64`, big-endian: the high word, then the low.
pub fn be64(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}
