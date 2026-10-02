// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The authentication report: how a source's packets are authenticated,
//! and the state of its NTS key establishment.

use crate::error::Result;
use crate::wire::{Layout, Reader};

/// How an NTP source's packets are authenticated.
///
/// An NTS source has keys once [`key_bits`](Self::key_bits) is non-zero.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Authentication {
    /// The mechanism.
    pub mode: AuthMode,
    /// The algorithm.
    pub algorithm: Algorithm,
    /// Symmetric key: the key's ID in the key file. NTS: the number of
    /// successful key establishments.
    pub key_id: u32,
    /// Key length in bits; zero for NTS until keys are established.
    pub key_bits: u16,
    /// NTS-KE attempts since the last success.
    pub ke_attempts: u16,
    /// Seconds since the last successful NTS-KE; `None` if there has been
    /// none, and for other mechanisms.
    pub last_ke_ago: Option<u32>,
    /// NTS cookies held, at most eight. A request spends one and its
    /// response replaces it.
    pub cookies: u16,
    /// Length in bytes of the cookie the next request carries.
    pub cookie_length: u16,
    /// Whether the last request drew an NTS NAK: the server rejected the
    /// cookie, and keys have to be established again.
    pub nak: bool,
}

/// Command 67, reply 20; 24 bytes of data, the last two padding.
impl Layout for Authentication {
    const COMMAND: u16 = 67;
    const REPLY: u16 = 20;
    const LEN: usize = 24;

    fn read(r: &mut Reader<'_>) -> Result<Authentication> {
        let auth = Authentication {
            mode: AuthMode::from_code(r.u16()?),
            algorithm: Algorithm::from_code(r.u16()?),
            key_id: r.u32()?,
            key_bits: r.u16()?,
            ke_attempts: r.u16()?,
            last_ke_ago: r.ago()?,
            cookies: r.u16()?,
            cookie_length: r.u16()?,
            nak: r.u16()? != 0,
        };
        r.skip::<2>()?;
        Ok(auth)
    }
}

/// An authentication mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthMode {
    /// 0: none.
    None,
    /// 1: a symmetric key from the key file.
    SymmetricKey,
    /// 2: Network Time Security, RFC 8915.
    Nts,
    /// Any other code.
    Unknown(u16),
}

impl AuthMode {
    fn from_code(code: u16) -> AuthMode {
        match code {
            0 => AuthMode::None,
            1 => AuthMode::SymmetricKey,
            2 => AuthMode::Nts,
            other => AuthMode::Unknown(other),
        }
    }
}

/// An authentication algorithm.
///
/// Symmetric keys report chronyd's hash and cipher numbers (1 to 14);
/// NTS reports the negotiated AEAD by its IANA number (15 and up).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// 0: no key, or NTS keys not established yet.
    None,
    /// 1.
    Md5,
    /// 2.
    Sha1,
    /// 3.
    Sha256,
    /// 4.
    Sha384,
    /// 5.
    Sha512,
    /// 6.
    Sha3_224,
    /// 7.
    Sha3_256,
    /// 8.
    Sha3_384,
    /// 9.
    Sha3_512,
    /// 10.
    Tiger,
    /// 11.
    Whirlpool,
    /// 13: AES-128 CMAC.
    Aes128,
    /// 14: AES-256 CMAC.
    Aes256,
    /// 15: AEAD_AES_SIV_CMAC_256.
    AesSivCmac256,
    /// 16: AEAD_AES_SIV_CMAC_384.
    AesSivCmac384,
    /// 17: AEAD_AES_SIV_CMAC_512.
    AesSivCmac512,
    /// 30: AEAD_AES_128_GCM_SIV.
    Aes128GcmSiv,
    /// 31: AEAD_AES_256_GCM_SIV.
    Aes256GcmSiv,
    /// Any other number.
    Unknown(u16),
}

impl Algorithm {
    fn from_code(code: u16) -> Algorithm {
        match code {
            0 => Algorithm::None,
            1 => Algorithm::Md5,
            2 => Algorithm::Sha1,
            3 => Algorithm::Sha256,
            4 => Algorithm::Sha384,
            5 => Algorithm::Sha512,
            6 => Algorithm::Sha3_224,
            7 => Algorithm::Sha3_256,
            8 => Algorithm::Sha3_384,
            9 => Algorithm::Sha3_512,
            10 => Algorithm::Tiger,
            11 => Algorithm::Whirlpool,
            13 => Algorithm::Aes128,
            14 => Algorithm::Aes256,
            15 => Algorithm::AesSivCmac256,
            16 => Algorithm::AesSivCmac384,
            17 => Algorithm::AesSivCmac512,
            30 => Algorithm::Aes128GcmSiv,
            31 => Algorithm::Aes256GcmSiv,
            other => Algorithm::Unknown(other),
        }
    }

    /// The number on the wire.
    pub fn code(&self) -> u16 {
        match self {
            Algorithm::None => 0,
            Algorithm::Md5 => 1,
            Algorithm::Sha1 => 2,
            Algorithm::Sha256 => 3,
            Algorithm::Sha384 => 4,
            Algorithm::Sha512 => 5,
            Algorithm::Sha3_224 => 6,
            Algorithm::Sha3_256 => 7,
            Algorithm::Sha3_384 => 8,
            Algorithm::Sha3_512 => 9,
            Algorithm::Tiger => 10,
            Algorithm::Whirlpool => 11,
            Algorithm::Aes128 => 13,
            Algorithm::Aes256 => 14,
            Algorithm::AesSivCmac256 => 15,
            Algorithm::AesSivCmac384 => 16,
            Algorithm::AesSivCmac512 => 17,
            Algorithm::Aes128GcmSiv => 30,
            Algorithm::Aes256GcmSiv => 31,
            Algorithm::Unknown(code) => *code,
        }
    }
}
