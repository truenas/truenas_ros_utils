// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The value vocabularies a key table or credential cache speaks:
//! encryption types, principal name types, ticket flags, and the owned
//! forms of the small structs entries carry.
//!
//! Variant names throughout are the library's own macro names, kept
//! verbatim — they are the vocabulary `krb5.conf`, KDC logs, and RFC 4120
//! use — so the naming lint is lifted per enum. Values are ABI, taken from
//! `krb5/krb5.h` in `libkrb5-dev` 1.21.3.
#![allow(unsafe_code)] // the key scrub in `KeyInfo::drop`

use crate::context::scrub;
use std::fmt;

/// Declares an `i32`-valued vocabulary enum with its raw-value round trip,
/// so the enum, `from_raw`, and `name` cannot drift apart.
macro_rules! vocabulary {
    ($(#[$doc:meta])* $vis:vis enum $enum_name:ident {
        $($name:ident = $value:literal,)+
    }) => {
        $(#[$doc])*
        #[allow(non_camel_case_types)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        #[repr(i32)]
        #[non_exhaustive]
        $vis enum $enum_name {
            $(
                #[allow(missing_docs)]
                $name = $value,
            )+
        }

        impl $enum_name {
            /// The value for a raw integer, or `None` if the library does
            /// not name it.
            pub const fn from_raw(raw: i32) -> Option<$enum_name> {
                Some(match raw {
                    $($value => $enum_name::$name,)+
                    _ => return None,
                })
            }

            /// The raw value the library uses.
            pub const fn raw(self) -> i32 {
                self as i32
            }

            /// The upstream macro name.
            pub const fn name(self) -> &'static str {
                match self {
                    $($enum_name::$name => stringify!($name),)+
                }
            }

            /// Every variant, in header order.
            pub const ALL: &[$enum_name] = &[$($enum_name::$name,)+];
        }

        impl fmt::Display for $enum_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.name())
            }
        }
    };
}

vocabulary! {
    /// An encryption type (`ENCTYPE_*`).
    pub enum EncType {
        ENCTYPE_NULL = 0,
        ENCTYPE_DES_CBC_CRC = 1,
        ENCTYPE_DES_CBC_MD4 = 2,
        ENCTYPE_DES_CBC_MD5 = 3,
        ENCTYPE_DES_CBC_RAW = 4,
        ENCTYPE_DES3_CBC_SHA = 5,
        ENCTYPE_DES3_CBC_RAW = 6,
        ENCTYPE_DES_HMAC_SHA1 = 8,
        ENCTYPE_DSA_SHA1_CMS = 9,
        ENCTYPE_MD5_RSA_CMS = 10,
        ENCTYPE_SHA1_RSA_CMS = 11,
        ENCTYPE_RC2_CBC_ENV = 12,
        ENCTYPE_RSA_ENV = 13,
        ENCTYPE_RSA_ES_OAEP_ENV = 14,
        ENCTYPE_DES3_CBC_ENV = 15,
        ENCTYPE_DES3_CBC_SHA1 = 16,
        ENCTYPE_AES128_CTS_HMAC_SHA1_96 = 17,
        ENCTYPE_AES256_CTS_HMAC_SHA1_96 = 18,
        ENCTYPE_AES128_CTS_HMAC_SHA256_128 = 19,
        ENCTYPE_AES256_CTS_HMAC_SHA384_192 = 20,
        ENCTYPE_ARCFOUR_HMAC = 23,
        ENCTYPE_ARCFOUR_HMAC_EXP = 24,
        ENCTYPE_CAMELLIA128_CTS_CMAC = 25,
        ENCTYPE_CAMELLIA256_CTS_CMAC = 26,
        ENCTYPE_UNKNOWN = 511,
    }
}

impl EncType {
    /// Whether MIT krb5 has withdrawn this enctype from its default
    /// permitted set: the single-DES family, triple-DES, and RC4 — the
    /// types a modern KDC only speaks when `allow_weak_crypto`,
    /// `allow_des3`, or `allow_rc4` is set.
    pub const fn deprecated(self) -> bool {
        matches!(
            self,
            EncType::ENCTYPE_DES_CBC_CRC
                | EncType::ENCTYPE_DES_CBC_MD4
                | EncType::ENCTYPE_DES_CBC_MD5
                | EncType::ENCTYPE_DES_CBC_RAW
                | EncType::ENCTYPE_DES3_CBC_SHA
                | EncType::ENCTYPE_DES3_CBC_RAW
                | EncType::ENCTYPE_DES_HMAC_SHA1
                | EncType::ENCTYPE_DES3_CBC_SHA1
                | EncType::ENCTYPE_ARCFOUR_HMAC
                | EncType::ENCTYPE_ARCFOUR_HMAC_EXP
        )
    }
}

vocabulary! {
    /// A principal name type (`KRB5_NT_*`).
    pub enum PrincipalType {
        KRB5_NT_UNKNOWN = 0,
        KRB5_NT_PRINCIPAL = 1,
        KRB5_NT_SRV_INST = 2,
        KRB5_NT_SRV_HST = 3,
        KRB5_NT_SRV_XHST = 4,
        KRB5_NT_UID = 5,
        KRB5_NT_X500_PRINCIPAL = 6,
        KRB5_NT_SMTP_NAME = 7,
        KRB5_NT_ENTERPRISE_PRINCIPAL = 10,
        KRB5_NT_WELLKNOWN = 11,
        KRB5_NT_MS_PRINCIPAL = -128,
        KRB5_NT_MS_PRINCIPAL_AND_ID = -129,
        KRB5_NT_ENT_PRINCIPAL_AND_ID = -130,
    }
}

bitflags::bitflags! {
    /// Flags in a ticket (`TKT_FLG_*`).
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    pub struct TicketFlags: i32 {
        /// May be forwarded to another address.
        const FORWARDABLE = 0x4000_0000;
        /// Was forwarded.
        const FORWARDED = 0x2000_0000;
        /// May be issued as a proxy ticket.
        const PROXIABLE = 0x1000_0000;
        /// Is a proxy ticket.
        const PROXY = 0x0800_0000;
        /// May be postdated.
        const MAY_POSTDATE = 0x0400_0000;
        /// Is postdated.
        const POSTDATED = 0x0200_0000;
        /// Not yet valid; must be validated before use.
        const INVALID = 0x0100_0000;
        /// May be renewed until `renew_till`.
        const RENEWABLE = 0x0080_0000;
        /// Was issued by the AS exchange, not from a TGT.
        const INITIAL = 0x0040_0000;
        /// The client pre-authenticated.
        const PRE_AUTH = 0x0020_0000;
        /// Pre-authentication involved hardware.
        const HW_AUTH = 0x0010_0000;
        /// The KDC checked the transited-realm list.
        const TRANSIT_POLICY_CHECKED = 0x0008_0000;
        /// The service may accept this ticket as a delegate.
        const OK_AS_DELEGATE = 0x0004_0000;
        /// The KDC signed the pre-authentication reply.
        const ENC_PA_REP = 0x0001_0000;
        /// Issued to an anonymous principal.
        const ANONYMOUS = 0x0000_8000;

        // A ticket may carry flags this build does not name.
        const _ = !0;
    }
}

/// A Kerberos timestamp, widened the way the library itself does
/// (`ts2tt`): the wire carries 32 bits, read as unsigned so times past
/// 2038 stay in order.
pub(crate) fn widen_timestamp(raw: i32) -> i64 {
    i64::from(raw as u32)
}

/// The exposed contents of a key: the raw enctype and the key bytes.
///
/// The bytes are secret material; `Debug` prints only their length, and the
/// buffer is overwritten before release.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyInfo {
    /// The raw enctype, which may name a type this build does not.
    pub enctype: i32,
    /// The key itself.
    pub contents: Vec<u8>,
}

impl KeyInfo {
    /// The typed enctype, or `None` when the raw value is not one the
    /// library names.
    pub fn enc_type(&self) -> Option<EncType> {
        EncType::from_raw(self.enctype)
    }

    /// Whether the enctype is withdrawn from the modern default set; an
    /// unnamed enctype is not presumed deprecated.
    pub fn deprecated(&self) -> bool {
        self.enc_type().is_some_and(EncType::deprecated)
    }
}

impl fmt::Debug for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyInfo")
            .field("enctype", &self.enctype)
            .field("contents", &format_args!("<{} bytes>", self.contents.len()))
            .finish()
    }
}

impl Drop for KeyInfo {
    fn drop(&mut self) {
        scrub(&mut self.contents);
    }
}

/// Ticket lifetime info, widened to `i64` seconds since the epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TicketTimes {
    /// When the KDC issued the initial ticket this one derives from.
    pub authtime: i64,
    /// Start of validity; tickets without one use `authtime`.
    pub starttime: i64,
    /// Expiration time.
    pub endtime: i64,
    /// Latest time a renewal can reach; zero when not renewable.
    pub renew_till: i64,
}

/// A network address carried in a ticket, kept raw: the library's own
/// `ADDRTYPE_*` space names the type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address {
    /// The raw `krb5_addrtype`.
    pub addrtype: i32,
    /// The address bytes.
    pub contents: Vec<u8>,
}

/// One authorization-data element, kept raw: interpreting the contents
/// belongs to whoever knows the `ad_type`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthData {
    /// The raw `krb5_authdatatype`.
    pub ad_type: i32,
    /// The element bytes.
    pub contents: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enctype_values_are_the_headers() {
        // The RFC 3962 / RFC 8009 / RFC 4757 assignments, by hand.
        for (ty, raw) in [
            (EncType::ENCTYPE_NULL, 0),
            (EncType::ENCTYPE_DES3_CBC_SHA1, 16),
            (EncType::ENCTYPE_AES128_CTS_HMAC_SHA1_96, 17),
            (EncType::ENCTYPE_AES256_CTS_HMAC_SHA1_96, 18),
            (EncType::ENCTYPE_AES128_CTS_HMAC_SHA256_128, 19),
            (EncType::ENCTYPE_AES256_CTS_HMAC_SHA384_192, 20),
            (EncType::ENCTYPE_ARCFOUR_HMAC, 23),
            (EncType::ENCTYPE_CAMELLIA256_CTS_CMAC, 26),
            (EncType::ENCTYPE_UNKNOWN, 0x1ff),
        ] {
            assert_eq!(ty.raw(), raw);
            assert_eq!(EncType::from_raw(raw), Some(ty));
        }
        assert_eq!(EncType::from_raw(7), None);
        assert_eq!(EncType::from_raw(21), None);
    }

    #[test]
    fn deprecation_covers_des_des3_and_rc4_only() {
        let deprecated: Vec<_> = EncType::ALL
            .iter()
            .copied()
            .filter(|t| t.deprecated())
            .map(EncType::raw)
            .collect();
        assert_eq!(deprecated, [1, 2, 3, 4, 5, 6, 8, 16, 23, 24]);
        assert!(!EncType::ENCTYPE_AES256_CTS_HMAC_SHA1_96.deprecated());
        assert!(!EncType::ENCTYPE_CAMELLIA128_CTS_CMAC.deprecated());
    }

    #[test]
    fn principal_types_include_the_negative_ms_space() {
        assert_eq!(PrincipalType::KRB5_NT_PRINCIPAL.raw(), 1);
        assert_eq!(PrincipalType::KRB5_NT_ENTERPRISE_PRINCIPAL.raw(), 10);
        assert_eq!(
            PrincipalType::from_raw(-128),
            Some(PrincipalType::KRB5_NT_MS_PRINCIPAL)
        );
        assert_eq!(
            PrincipalType::from_raw(-130),
            Some(PrincipalType::KRB5_NT_ENT_PRINCIPAL_AND_ID)
        );
        assert_eq!(PrincipalType::from_raw(8), None);
        assert_eq!(PrincipalType::from_raw(9), None);
    }

    #[test]
    fn ticket_flags_are_the_wire_bits() {
        assert_eq!(TicketFlags::FORWARDABLE.bits(), 0x4000_0000);
        assert_eq!(TicketFlags::ANONYMOUS.bits(), 0x0000_8000);
        // Unknown bits survive a round trip rather than being dropped.
        let raw = 0x4000_0001;
        assert_eq!(TicketFlags::from_bits_retain(raw).bits(), raw);
    }

    #[test]
    fn timestamps_widen_unsigned() {
        assert_eq!(widen_timestamp(0), 0);
        assert_eq!(widen_timestamp(0x7fff_ffff), 0x7fff_ffff);
        // Past 2038 the wire value is negative as i32; the library reads
        // it as unsigned.
        assert_eq!(widen_timestamp(-1), 0xffff_ffff);
        assert_eq!(widen_timestamp(i32::MIN), 0x8000_0000);
    }

    #[test]
    fn keyinfo_redacts_and_classifies() {
        let key = KeyInfo {
            enctype: 18,
            contents: vec![0xa5; 32],
        };
        assert_eq!(
            key.enc_type(),
            Some(EncType::ENCTYPE_AES256_CTS_HMAC_SHA1_96)
        );
        assert!(!key.deprecated());
        let shown = format!("{key:?}");
        assert!(shown.contains("<32 bytes>"), "{shown}");
        assert!(!shown.contains("a5"), "{shown}");

        let unknown = KeyInfo {
            enctype: 4242,
            contents: vec![],
        };
        assert_eq!(unknown.enc_type(), None);
        assert!(!unknown.deprecated());
    }
}
