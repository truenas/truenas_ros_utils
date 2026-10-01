// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Client`]: [`Request`]s over chronyd's Unix socket, one at a time.

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{
    DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
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

/// Room for any reply; the longest read here is 104 bytes.
const RECV_BUF: usize = 1024;

/// Walks of the source list before a list that keeps changing is an
/// error.
const SOURCE_WALKS: u32 = 3;

/// The reply socket's name inside its directory.
const REPLY_SOCKET: &str = "sock";

/// A connection to chronyd's command socket.
///
/// chronyd replies to the sender's address, so the client binds `sock`
/// (mode 0666, for a daemon running as another user) in a directory
/// beside the daemon's socket, `truenas_chrony.` and sixteen random hex
/// digits (mode 0711). Both are removed on drop.
///
/// That needs write access to the daemon's socket directory (root or the
/// chrony user for `/run/chrony`), and the reply socket's path, the
/// directory's plus 37 bytes, must fit in 107 bytes. The daemon owns that
/// directory, so the client checks that the directory it opened is the
/// one it created and changes the socket's mode through it, not by path.
/// Under AppArmor, chronyd needs write access to `@{run}/chrony/**`.
///
/// Calls take `&mut self`: one request at a time. An unanswered request
/// is resent with a fresh sequence number, each wait double the last.
#[derive(Debug)]
pub struct Client {
    // Fields drop in order: the socket is closed before its file and
    // directory are removed.
    socket: UnixDatagram,
    _dir: ReplyDir,
    urandom: File,
    timeout: Duration,
    attempts: u32,
}

impl Client {
    /// Connect to chronyd at [`DEFAULT_SOCKET`].
    pub fn local() -> Result<Client> {
        Client::connect(DEFAULT_SOCKET)
    }

    /// Connect to chronyd's command socket at `path`.
    ///
    /// A daemon that is not running fails here: [`Error::Io`] with
    /// `NotFound` (no socket) or `ConnectionRefused` (a stale one).
    pub fn connect(path: impl AsRef<Path>) -> Result<Client> {
        let mut urandom = File::open("/dev/urandom")?;
        let (socket, dir) = bind_reply_socket(path.as_ref(), &mut urandom)?;
        Ok(Client {
            socket,
            _dir: dir,
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

/// The directory holding the client's reply socket. Dropping it removes
/// the socket and the directory.
#[derive(Debug)]
struct ReplyDir {
    path: PathBuf,
    /// The directory, opened and checked; `None` until then.
    dir: Option<File>,
}

impl ReplyDir {
    /// `name` in the open directory, by a path through its descriptor,
    /// whatever has since happened to the path it was created at.
    fn through(dir: &File, name: &str) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}/{name}", dir.as_raw_fd()))
    }
}

impl Drop for ReplyDir {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir {
            let _ = fs::remove_file(ReplyDir::through(dir, REPLY_SOCKET));
        }
        let _ = fs::remove_dir(&self.path);
    }
}

/// Bind the client's reply socket beside the daemon's at `server`, and
/// connect it there.
fn bind_reply_socket(
    server: &Path,
    urandom: &mut File,
) -> Result<(UnixDatagram, ReplyDir)> {
    // chronyd replies to the reply socket's path as bound, resolved from
    // its own working directory, so the path must be absolute.
    let server = std::path::absolute(server)?;

    // Reach the daemon before creating anything beside it.
    let probe = UnixDatagram::unbound()?;
    probe.connect(&server)?;
    // A new socket's inode belongs to its creator's filesystem uid, which
    // is also the owner a new directory gets.
    let owner = File::from(probe.as_fd().try_clone_to_owned()?)
        .metadata()?
        .uid();
    drop(probe);

    let parent = server.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "socket path has no parent")
    })?;
    let mut tag = [0u8; 8];
    urandom.read_exact(&mut tag)?;
    let tag: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    let path = parent.join(format!("truenas_chrony.{tag}"));
    DirBuilder::new().mode(0o711).create(&path)?;
    let mut reply_dir = ReplyDir { path, dir: None };

    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&reply_dir.path)?;
    let meta = dir.metadata()?;
    // The umask can only remove bits from 0711, so other bits or another
    // owner mean a directory swapped in after the mkdir.
    if !meta.is_dir()
        || meta.mode() & 0o777 & !0o711 != 0
        || meta.uid() != owner
    {
        return Err(Error::Io(io::Error::other(
            "reply socket directory replaced before it was opened",
        )));
    }
    let socket = UnixDatagram::bind(reply_dir.path.join(REPLY_SOCKET))?;
    let dir = reply_dir.dir.insert(dir);
    // Through the descriptor: a redirected path finds no socket and
    // fails, rather than changing the mode of whatever it reaches.
    fs::set_permissions(
        ReplyDir::through(dir, REPLY_SOCKET),
        Permissions::from_mode(0o666),
    )?;
    dir.set_permissions(Permissions::from_mode(0o711))?;
    socket.connect(&server)?;
    Ok((socket, reply_dir))
}
