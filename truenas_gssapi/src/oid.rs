// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Oid`]: an object identifier, owned as its BER arc octets.
//!
//! The well-known constructors carry the assignments this crate speaks —
//! the two mechanisms and the name types — with the octets written out
//! from the RFCs that assign them. A test pins each against the OID the
//! linked library exports for the same identifier.
#![allow(unsafe_code)]

use crate::ffi;
use std::fmt;

/// An object identifier: the BER arc octets, without tag or length.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Oid {
    elements: Box<[u8]>,
}

/// The octet tables, one per assignment this crate names.
mod octets {
    /// Kerberos 5: 1.2.840.113554.1.2.2 (RFC 1964 §1).
    pub const KRB5: &[u8] =
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
    /// SPNEGO: 1.3.6.1.5.5.2 (RFC 4178 §4.1).
    pub const SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    /// GSS_C_NT_HOSTBASED_SERVICE: 1.2.840.113554.1.2.1.4
    /// (RFC 2744 §4.1).
    pub const NT_HOSTBASED_SERVICE: &[u8] =
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];
    /// GSS_C_NT_USER_NAME: 1.2.840.113554.1.2.1.1 (RFC 2744 §4.2).
    pub const NT_USER_NAME: &[u8] =
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01];
    /// GSS_C_NT_EXPORT_NAME: 1.3.6.1.5.6.4 (RFC 2743 §4.7).
    pub const NT_EXPORT_NAME: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x06, 0x04];
    /// GSS_KRB5_NT_PRINCIPAL_NAME: 1.2.840.113554.1.2.2.1 (RFC 1964 §2.1.1).
    pub const NT_KRB5_PRINCIPAL: &[u8] =
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01];
}

impl Oid {
    /// The Kerberos 5 mechanism.
    pub fn krb5() -> Oid {
        Oid {
            elements: octets::KRB5.into(),
        }
    }

    /// The SPNEGO pseudo-mechanism.
    pub fn spnego() -> Oid {
        Oid {
            elements: octets::SPNEGO.into(),
        }
    }

    /// The host-based service name type (`service@host`).
    pub fn nt_hostbased_service() -> Oid {
        Oid {
            elements: octets::NT_HOSTBASED_SERVICE.into(),
        }
    }

    /// The user name type.
    pub fn nt_user_name() -> Oid {
        Oid {
            elements: octets::NT_USER_NAME.into(),
        }
    }

    /// The exported-name name type, for re-importing what
    /// [`Name::export`](crate::Name::export) produced.
    pub fn nt_export_name() -> Oid {
        Oid {
            elements: octets::NT_EXPORT_NAME.into(),
        }
    }

    /// The Kerberos principal name type (`user@REALM`).
    pub fn nt_krb5_principal() -> Oid {
        Oid {
            elements: octets::NT_KRB5_PRINCIPAL.into(),
        }
    }

    /// The BER arc octets.
    pub fn elements(&self) -> &[u8] {
        &self.elements
    }

    /// Copy out of a library-owned descriptor.
    ///
    /// # Safety
    /// `raw` must be null or point at a descriptor whose `elements` are
    /// `length` readable bytes.
    pub(crate) unsafe fn from_raw(raw: ffi::gss_OID) -> Option<Oid> {
        if raw.is_null() {
            return None;
        }
        // SAFETY: caller's contract.
        let elements = unsafe {
            let desc = &*raw;
            std::slice::from_raw_parts(
                desc.elements.cast::<u8>(),
                desc.length as usize,
            )
        };
        Some(Oid {
            elements: elements.into(),
        })
    }

    /// A descriptor pointing at these octets, for the duration of a call.
    pub(crate) fn as_desc(&self) -> ffi::gss_OID_desc {
        ffi::gss_OID_desc {
            length: self.elements.len() as ffi::OM_uint32,
            elements: self.elements.as_ptr().cast_mut().cast(),
        }
    }
}

impl fmt::Display for Oid {
    /// Dotted-decimal form, e.g. `1.2.840.113554.1.2.2`; the raw octets in
    /// hex when the encoding is not well-formed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match decode(&self.elements) {
            Some(arcs) => {
                for (i, arc) in arcs.iter().enumerate() {
                    if i > 0 {
                        f.write_str(".")?;
                    }
                    write!(f, "{arc}")?;
                }
                Ok(())
            }
            None => {
                for byte in &self.elements {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({self})")
    }
}

/// Decode BER arc octets to their dotted-decimal arcs: the first octet is
/// `40 * arc0 + arc1`, the rest are base-128 with a continuation bit.
fn decode(elements: &[u8]) -> Option<Vec<u64>> {
    let mut arcs = Vec::new();
    let mut value: u64 = 0;
    for &byte in elements {
        value = value
            .checked_mul(128)?
            .checked_add(u64::from(byte & 0x7f))?;
        if byte & 0x80 != 0 {
            continue;
        }
        if arcs.is_empty() {
            let first = if value < 40 {
                0
            } else if value < 80 {
                1
            } else {
                2
            };
            arcs.push(first);
            arcs.push(value - first * 40);
        } else {
            arcs.push(value);
        }
        value = 0;
    }
    // A trailing continuation bit means truncation.
    if elements.last().is_some_and(|b| b & 0x80 != 0) || elements.is_empty() {
        return None;
    }
    Some(arcs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_decimal_matches_the_assignments() {
        assert_eq!(Oid::krb5().to_string(), "1.2.840.113554.1.2.2");
        assert_eq!(Oid::spnego().to_string(), "1.3.6.1.5.5.2");
        assert_eq!(
            Oid::nt_hostbased_service().to_string(),
            "1.2.840.113554.1.2.1.4"
        );
        assert_eq!(Oid::nt_user_name().to_string(), "1.2.840.113554.1.2.1.1");
        assert_eq!(Oid::nt_export_name().to_string(), "1.3.6.1.5.6.4");
        assert_eq!(
            Oid::nt_krb5_principal().to_string(),
            "1.2.840.113554.1.2.2.1"
        );
    }

    #[test]
    fn equality_is_by_octets() {
        assert_eq!(Oid::krb5(), Oid::krb5());
        assert_ne!(Oid::krb5(), Oid::spnego());
        assert_ne!(Oid::nt_krb5_principal(), Oid::krb5());
    }

    #[test]
    fn malformed_octets_display_as_hex() {
        let truncated = Oid {
            elements: vec![0x2a, 0x86].into(),
        };
        assert_eq!(truncated.to_string(), "2a86");
        let empty = Oid {
            elements: Vec::new().into(),
        };
        assert_eq!(empty.to_string(), "");
    }

    #[test]
    fn tables_match_the_linked_library() {
        // The octets above are the RFCs'; this catches them drifting from
        // what the library actually exports under the same identifiers.
        // SPNEGO has no exported variable to compare against — the
        // mechglue reaches it by value — so the dotted-decimal assertion
        // above stands alone for it.
        for (ours, theirs) in [
            (Oid::krb5(), "gss_mech_krb5"),
            (Oid::nt_hostbased_service(), "GSS_C_NT_HOSTBASED_SERVICE"),
            (Oid::nt_user_name(), "GSS_C_NT_USER_NAME"),
            (Oid::nt_export_name(), "GSS_C_NT_EXPORT_NAME"),
            (Oid::nt_krb5_principal(), "GSS_KRB5_NT_PRINCIPAL_NAME"),
        ] {
            // SAFETY: the library initializes these exported variables to
            // static descriptors; read-only access.
            let exported = unsafe {
                let raw = match theirs {
                    "gss_mech_krb5" => ffi::gss_mech_krb5,
                    "GSS_C_NT_HOSTBASED_SERVICE" => {
                        ffi::GSS_C_NT_HOSTBASED_SERVICE
                    }
                    "GSS_C_NT_USER_NAME" => ffi::GSS_C_NT_USER_NAME,
                    "GSS_C_NT_EXPORT_NAME" => ffi::GSS_C_NT_EXPORT_NAME,
                    "GSS_KRB5_NT_PRINCIPAL_NAME" => {
                        ffi::GSS_KRB5_NT_PRINCIPAL_NAME
                    }
                    _ => unreachable!(),
                };
                Oid::from_raw(raw).expect(theirs)
            };
            assert_eq!(ours, exported, "{theirs} drifted from the library");
        }
    }
}
