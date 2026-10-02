// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Client`]: [`Request`]s over chronyd's Unix socket, one at a time.

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::auth::Authentication;
use crate::error::{Error, Result, Status};
use crate::request::{Request, Verdict};
use crate::source::{Selection, Source};
use crate::tracking::Tracking;
use crate::types::Address;

/// chronyd's command socket on TrueNAS and Debian.
pub const DEFAULT_SOCKET: &str = "/run/chrony/chronyd.sock";

/// The directory [`Client::connect`] binds its reply socket in.
pub const DEFAULT_REPLY_DIR: &str = "/run/truenas_chrony";

/// Room for any reply; the longest read here is 104 bytes.
const RECV_BUF: usize = 1024;

/// Walks of the source list before a list that keeps changing is an
/// error.
const SOURCE_WALKS: u32 = 3;

/// A connection to chronyd's command socket.
///
/// chronyd replies to the sender's address, so the client binds a reply
/// socket, sixteen random hex digits and `.sock` (mode 0666, for a daemon
/// running as another user), in a directory of its own (mode 0711, made
/// if missing). The socket is removed on drop, or by a later client if
/// its own never dropped; the directory is kept.
///
/// Modes are set and stale sockets removed by path, so the directory must
/// be on a path only the caller can modify. chronyd must reach it, which
/// rules out `/tmp` under Debian's unit. The directory's path plus 22
/// bytes must fit in 107 bytes. Where AppArmor mediates sends to pathname
/// sockets, a profile confining chronyd must allow it to write the reply
/// socket, as `@{run}/truenas_chrony/*.sock w,` does for
/// [`DEFAULT_REPLY_DIR`]. Reaching the daemon's socket in `/run/chrony`
/// needs root or the chrony user.
///
/// Calls take `&mut self`: one request at a time. An unanswered request
/// is resent with a fresh sequence number, each wait double the last.
#[derive(Debug)]
pub struct Client {
    // Fields drop in order: the socket is closed before its file is
    // removed.
    socket: UnixDatagram,
    _reply: ReplySocket,
    urandom: File,
    timeout: Duration,
    attempts: u32,
}

impl Client {
    /// Connect to chronyd at [`DEFAULT_SOCKET`].
    pub fn local() -> Result<Client> {
        Client::connect(DEFAULT_SOCKET)
    }

    /// Connect to chronyd's command socket at `path`, with the reply
    /// socket in [`DEFAULT_REPLY_DIR`], which needs root.
    ///
    /// A daemon that is not running fails here: [`Error::Io`] with
    /// `NotFound` (no socket) or `ConnectionRefused` (a stale one).
    pub fn connect(path: impl AsRef<Path>) -> Result<Client> {
        Client::connect_in(path, DEFAULT_REPLY_DIR)
    }

    /// Connect to chronyd's command socket at `path`, with the reply
    /// socket in `dir`. A daemon that is not running fails as for
    /// [`connect`](Self::connect), before `dir` is touched.
    pub fn connect_in(
        path: impl AsRef<Path>,
        dir: impl AsRef<Path>,
    ) -> Result<Client> {
        let mut urandom = File::open("/dev/urandom")?;
        let (socket, reply) =
            bind_reply_socket(path.as_ref(), dir.as_ref(), &mut urandom)?;
        Ok(Client {
            socket,
            _reply: reply,
            urandom,
            timeout: Duration::from_secs(1),
            attempts: 3,
        })
    }

    /// The wait for a first reply; each retry waits twice as long. One
    /// second by default, at least a millisecond.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout.max(Duration::from_millis(1));
    }

    /// Sends of a request before [`Error::Timeout`]. Three by default, at
    /// least one.
    pub fn set_attempts(&mut self, attempts: u32) {
        self.attempts = attempts.max(1);
    }

    /// The system clock's synchronization state.
    pub fn tracking(&mut self) -> Result<Tracking> {
        self.exchange(Request::tracking)
    }

    /// The number of sources: NTP servers and peers, resolved or not, and
    /// reference clocks.
    pub fn source_count(&mut self) -> Result<u32> {
        self.exchange(Request::source_count)
    }

    /// The source at `index`, counting from zero.
    pub fn source(&mut self, index: u32) -> Result<Source> {
        self.exchange(|seq| Request::source(index, seq))
    }

    /// Every source, in index order.
    ///
    /// chronyd shifts later sources down when it removes one, so a walk
    /// that overlaps a change is repeated; three unsettled walks are
    /// [`Error::Changed`].
    pub fn sources(&mut self) -> Result<Vec<Source>> {
        for _ in 0..SOURCE_WALKS {
            let count = self.source_count()?;
            let mut sources = Vec::new();
            let mut whole = true;
            for index in 0..count {
                match self.source(index) {
                    Ok(source) => sources.push(source),
                    Err(Error::Status(Status::NoSuchSource)) => {
                        whole = false;
                        break;
                    }
                    Err(err) => return Err(err),
                }
            }
            if whole && self.source_count()? == count {
                return Ok(sources);
            }
        }
        Err(Error::Changed)
    }

    /// The last selection's view of the source at `index`.
    pub fn selection(&mut self, index: u32) -> Result<Selection> {
        self.exchange(|seq| Request::selection(index, seq))
    }

    /// How the NTP source at `address` is authenticated.
    pub fn authentication(
        &mut self,
        address: impl Into<Address>,
    ) -> Result<Authentication> {
        let address = address.into();
        self.exchange(|seq| Request::authentication(address, seq))
    }

    /// Send `make`'s request, with a fresh sequence number per attempt,
    /// until it is answered or the attempts run out.
    fn exchange<T>(&mut self, make: impl Fn(u32) -> Request<T>) -> Result<T> {
        let mut buf = [0u8; RECV_BUF];
        let mut wait = self.timeout;
        for attempt in 0..self.attempts {
            let mut sequence = [0u8; 4];
            self.urandom.read_exact(&mut sequence)?;
            let request = make(u32::from_ne_bytes(sequence))
                .with_attempt(u16::try_from(attempt).unwrap_or(u16::MAX));
            let deadline = Instant::now().checked_add(wait);
            self.socket.set_write_timeout(Some(wait))?;
            match self.socket.send(request.as_bytes()) {
                Ok(_) => {}
                // The daemon's queue is full: it is not reading.
                Err(err) if timed_out(&err) => {
                    wait = wait.saturating_mul(2);
                    continue;
                }
                Err(err) => return Err(err.into()),
            }
            loop {
                let left = match deadline {
                    Some(deadline) => {
                        match deadline.checked_duration_since(Instant::now()) {
                            Some(left) if !left.is_zero() => Some(left),
                            _ => break,
                        }
                    }
                    None => None,
                };
                self.socket.set_read_timeout(left)?;
                let len = match self.socket.recv(&mut buf) {
                    Ok(len) => len,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                        continue;
                    }
                    Err(err) if timed_out(&err) => break,
                    Err(err) => return Err(err.into()),
                };
                if let Verdict::Answer(answer) = request.decode(&buf[..len]) {
                    return answer;
                }
            }
            wait = wait.saturating_mul(2);
        }
        Err(Error::Timeout)
    }
}

/// Whether a socket call stopped at its timeout.
fn timed_out(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// The client's reply socket file, removed when dropped.
#[derive(Debug)]
struct ReplySocket(PathBuf);

impl Drop for ReplySocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Bind the client's reply socket in `dir`, and connect it to the
/// daemon's at `server`.
fn bind_reply_socket(
    server: &Path,
    dir: &Path,
    urandom: &mut File,
) -> Result<(UnixDatagram, ReplySocket)> {
    // Reach the daemon before creating anything.
    UnixDatagram::unbound()?.connect(server)?;

    // chronyd resolves the reply socket's path from its own working
    // directory, so the path must be absolute.
    let dir = std::path::absolute(dir)?;
    if let Err(err) = DirBuilder::new().mode(0o711).create(&dir)
        && err.kind() != io::ErrorKind::AlreadyExists
    {
        return Err(err.into());
    }
    // Whatever the umask or an earlier mode left: the bind needs the
    // search bit, and so does chronyd.
    fs::set_permissions(&dir, Permissions::from_mode(0o711))?;
    sweep(&dir);

    let mut tag = [0u8; 8];
    urandom.read_exact(&mut tag)?;
    let name: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    let path = dir.join(format!("{name}.sock"));
    let socket = UnixDatagram::bind(&path)?;
    let reply = ReplySocket(path);
    fs::set_permissions(&reply.0, Permissions::from_mode(0o666))?;
    socket.connect(server)?;
    Ok((socket, reply))
}

/// Remove the reply sockets in `dir` that refuse a connection: no client
/// is bound to them, so one exited without dropping its own.
fn sweep(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let stale = entry.file_type().is_ok_and(|t| t.is_socket())
            && is_reply_name(&entry.file_name())
            && UnixDatagram::unbound().is_ok_and(|probe| {
                probe.connect(&path).is_err_and(|e| {
                    e.kind() == io::ErrorKind::ConnectionRefused
                })
            });
        if stale {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Whether `name` is a reply socket's: sixteen hex digits and `.sock`.
fn is_reply_name(name: &OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_suffix(".sock"))
        .is_some_and(|tag| {
            tag.len() == 16 && tag.bytes().all(|b| b.is_ascii_hexdigit())
        })
}
