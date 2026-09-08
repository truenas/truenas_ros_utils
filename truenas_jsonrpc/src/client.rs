// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Building §4's Request object — the client's outbound half.

use serde::Serialize;
use serde_json::value::to_raw_value;

use std::fmt;

use crate::VERSION;
use crate::id::Id;

/// Why a call could not be built.
#[derive(Debug)]
pub enum BuildError {
    /// `params` encoded to something other than an Array or an Object.
    /// §4.2 admits only those two: by-position through an Array, by-name
    /// through an Object.
    ParamsNotStructured,
    /// The value's `Serialize` implementation failed.
    Encode(serde_json::Error),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParamsNotStructured => {
                f.write_str("'params' must be an Array or an Object")
            }
            Self::Encode(e) => write!(f, "encoding failed: {e}"),
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(e) => Some(e),
            Self::ParamsNotStructured => None,
        }
    }
}

impl From<serde_json::Error> for BuildError {
    fn from(e: serde_json::Error) -> Self {
        Self::Encode(e)
    }
}

/// Mints ids and builds request frames.
///
/// The ids are Numbers counting up from one. §4 admits a String or Null
/// too, and [`Caller::request_with_id`] takes either; what a counter buys
/// is that no two outstanding calls on one connection can collide, which
/// is what makes matching an answer to its call sound.
///
/// Correlation itself is the caller's: this hands back the [`Id`] it
/// minted, and what that id maps to — a channel, a waker, a continuation —
/// only the caller knows. A map from [`Id`] to that is the whole of it.
#[derive(Clone, Debug)]
pub struct Caller {
    next: u64,
}

impl Caller {
    /// A caller whose first id is `1`.
    pub fn new() -> Self {
        Self { next: 1 }
    }

    /// The id the next request will take, without taking it.
    pub fn peek_id(&self) -> Id {
        Id::Number(self.next.into())
    }

    /// Build a request, taking the next id, and hand back both.
    ///
    /// Pass `None` for `params` to omit the member, which §4 allows and
    /// which is distinct from sending an empty Array or Object.
    pub fn request<T>(
        &mut self,
        method: &str,
        params: Option<&T>,
    ) -> Result<(Id, Vec<u8>), BuildError>
    where
        T: ?Sized + Serialize,
    {
        let id = self.peek_id();
        // Only advance once the frame is built: a failed encode has not
        // used its id, and skipping one would leave a gap that looks like
        // a lost call.
        let frame = self.request_with_id(id.clone(), method, params)?;
        self.next = self.next.saturating_add(1);
        Ok((id, frame))
    }

    /// Build a request carrying an id the caller chose.
    pub fn request_with_id<T>(
        &self,
        id: Id,
        method: &str,
        params: Option<&T>,
    ) -> Result<Vec<u8>, BuildError>
    where
        T: ?Sized + Serialize,
    {
        let mut out = Vec::new();
        open(&mut out, method, params)?;
        out.extend_from_slice(br#","id":"#);
        serde_json::to_writer(&mut out, &id).map_err(BuildError::Encode)?;
        out.push(b'}');
        Ok(out)
    }

    /// Build a notification: §4.1's request with no `id` member, which the
    /// server must not answer. Nothing is minted, so nothing is pending.
    pub fn notification<T>(
        &self,
        method: &str,
        params: Option<&T>,
    ) -> Result<Vec<u8>, BuildError>
    where
        T: ?Sized + Serialize,
    {
        let mut out = Vec::new();
        open(&mut out, method, params)?;
        out.push(b'}');
        Ok(out)
    }
}

impl Default for Caller {
    fn default() -> Self {
        Self::new()
    }
}

/// Write `{"jsonrpc":"2.0","method":<method>[,"params":<params>]`, leaving
/// the object open for an `id` member or a closing brace.
fn open<T>(
    out: &mut Vec<u8>,
    method: &str,
    params: Option<&T>,
) -> Result<(), BuildError>
where
    T: ?Sized + Serialize,
{
    out.extend_from_slice(br#"{"jsonrpc":""#);
    out.extend_from_slice(VERSION.as_bytes());
    out.extend_from_slice(br#"","method":"#);
    serde_json::to_writer(&mut *out, method).map_err(BuildError::Encode)?;
    if let Some(params) = params {
        let raw = to_raw_value(params).map_err(BuildError::Encode)?;
        // §4.2 admits an Array or an Object and nothing else, so a scalar
        // is refused here rather than put on the wire for the peer to
        // refuse with INVALID_REQUEST.
        if !matches!(raw.get().as_bytes().first(), Some(b'[' | b'{')) {
            return Err(BuildError::ParamsNotStructured);
        }
        out.extend_from_slice(br#","params":"#);
        out.extend_from_slice(raw.get().as_bytes());
    }
    Ok(())
}

/// Wrap already-encoded request or response objects into one §6 batch
/// Array.
///
/// `None` when there are none: a batch has to hold at least one value to
/// be recognised as one, and on the answering side §6 forbids returning an
/// empty Array.
pub fn batch_of(objects: &[Vec<u8>]) -> Option<Vec<u8>> {
    if objects.is_empty() {
        return None;
    }
    let extra = objects.len() + 1;
    let mut out =
        Vec::with_capacity(objects.iter().map(Vec::len).sum::<usize>() + extra);
    out.push(b'[');
    for (i, object) in objects.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(object);
    }
    out.push(b']');
    Some(out)
}
