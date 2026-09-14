// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Error`], [`ErrCode`], and this crate's [`Result`].
//!
//! Every libkrb5 call returns one `krb5_error_code`: 0 for success,
//! otherwise a com_err code. The codes this crate classifies are the krb5
//! error table's own — the block starting at `KRB5KDC_ERR_NONE`
//! (-1765328384) — plus whatever else the library passes through (system
//! `errno` values among them), which stay raw.
//!
//! Message text is context-sensitive: `krb5_get_error_message` can carry
//! detail about the specific failing call, and only until the next call on
//! the same context. [`Error`] therefore captures the message at the moment
//! the failure is seen, and owns it from then on.

use std::{error, fmt};

/// This crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// An error from a libkrb5 operation: the raw code, and the message the
/// library gave for it at the failing call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    code: i32,
    message: Box<str>,
}

impl Error {
    /// Assemble from a raw code and the message captured for it.
    pub(crate) fn new(code: i32, message: Box<str>) -> Error {
        Error { code, message }
    }

    /// The raw `krb5_error_code`.
    pub fn code(&self) -> i32 {
        self.code
    }

    /// The krb5 error-table code, or `None` when the raw value is outside
    /// that table (a system `errno` passed through, or another com_err
    /// table's code).
    pub fn kind(&self) -> Option<ErrCode> {
        ErrCode::from_raw(self.code)
    }

    /// The message `krb5_get_error_message` gave at the failing call.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl error::Error for Error {}

/// Declares [`ErrCode`] and its raw-value round trip from one list, so the
/// enum, `from_raw`, and `name` cannot drift apart.
macro_rules! err_table {
    ($($name:ident = $value:literal,)+) => {
        /// A code from the krb5 com_err error table.
        ///
        /// Variant names are the library's own macro names, kept verbatim —
        /// they are the vocabulary error messages, RFC 4120, and every other
        /// Kerberos implementation use — so the workspace's naming lint is
        /// lifted for this enum alone.
        #[allow(non_camel_case_types)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        #[repr(i32)]
        #[non_exhaustive]
        pub enum ErrCode {
            $(
                #[allow(missing_docs)]
                $name = $value,
            )+
        }

        impl ErrCode {
            /// The code for a raw return value, or `None` if it is not in
            /// the krb5 error table.
            pub const fn from_raw(code: i32) -> Option<ErrCode> {
                Some(match code {
                    $($value => ErrCode::$name,)+
                    _ => return None,
                })
            }

            /// The upstream macro name, e.g. `"KRB5_KT_NOTFOUND"`.
            pub const fn name(self) -> &'static str {
                match self {
                    $(ErrCode::$name => stringify!($name),)+
                }
            }

            /// Every variant, in table order. Lets a consumer (or a test)
            /// sweep the vocabulary without listing it again.
            pub const ALL: &[ErrCode] = &[$(ErrCode::$name,)+];
        }
    };
}

// Names and values are ABI, taken from `krb5/krb5.h` in `libkrb5-dev`
// 1.21.3: every live code the header assigns, in order. The value space has
// gaps — the header reserves `KRB5PLACEHOLD_*` slots for future codes, which
// are not listed here — so consecutive variants are not always consecutive
// values. `table_is_exactly_the_linked_library` pins both directions against
// the linked runtime, so a code the library names but the table omits, or a
// placeholder the table wrongly lists, fails the suite.
err_table! {
    KRB5KDC_ERR_NONE = -1765328384,
    KRB5KDC_ERR_NAME_EXP = -1765328383,
    KRB5KDC_ERR_SERVICE_EXP = -1765328382,
    KRB5KDC_ERR_BAD_PVNO = -1765328381,
    KRB5KDC_ERR_C_OLD_MAST_KVNO = -1765328380,
    KRB5KDC_ERR_S_OLD_MAST_KVNO = -1765328379,
    KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN = -1765328378,
    KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN = -1765328377,
    KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE = -1765328376,
    KRB5KDC_ERR_NULL_KEY = -1765328375,
    KRB5KDC_ERR_CANNOT_POSTDATE = -1765328374,
    KRB5KDC_ERR_NEVER_VALID = -1765328373,
    KRB5KDC_ERR_POLICY = -1765328372,
    KRB5KDC_ERR_BADOPTION = -1765328371,
    KRB5KDC_ERR_ETYPE_NOSUPP = -1765328370,
    KRB5KDC_ERR_SUMTYPE_NOSUPP = -1765328369,
    KRB5KDC_ERR_PADATA_TYPE_NOSUPP = -1765328368,
    KRB5KDC_ERR_TRTYPE_NOSUPP = -1765328367,
    KRB5KDC_ERR_CLIENT_REVOKED = -1765328366,
    KRB5KDC_ERR_SERVICE_REVOKED = -1765328365,
    KRB5KDC_ERR_TGT_REVOKED = -1765328364,
    KRB5KDC_ERR_CLIENT_NOTYET = -1765328363,
    KRB5KDC_ERR_SERVICE_NOTYET = -1765328362,
    KRB5KDC_ERR_KEY_EXP = -1765328361,
    KRB5KDC_ERR_PREAUTH_FAILED = -1765328360,
    KRB5KDC_ERR_PREAUTH_REQUIRED = -1765328359,
    KRB5KDC_ERR_SERVER_NOMATCH = -1765328358,
    KRB5KDC_ERR_MUST_USE_USER2USER = -1765328357,
    KRB5KDC_ERR_PATH_NOT_ACCEPTED = -1765328356,
    KRB5KDC_ERR_SVC_UNAVAILABLE = -1765328355,
    KRB5KRB_AP_ERR_BAD_INTEGRITY = -1765328353,
    KRB5KRB_AP_ERR_TKT_EXPIRED = -1765328352,
    KRB5KRB_AP_ERR_TKT_NYV = -1765328351,
    KRB5KRB_AP_ERR_REPEAT = -1765328350,
    KRB5KRB_AP_ERR_NOT_US = -1765328349,
    KRB5KRB_AP_ERR_BADMATCH = -1765328348,
    KRB5KRB_AP_ERR_SKEW = -1765328347,
    KRB5KRB_AP_ERR_BADADDR = -1765328346,
    KRB5KRB_AP_ERR_BADVERSION = -1765328345,
    KRB5KRB_AP_ERR_MSG_TYPE = -1765328344,
    KRB5KRB_AP_ERR_MODIFIED = -1765328343,
    KRB5KRB_AP_ERR_BADORDER = -1765328342,
    KRB5KRB_AP_ERR_ILL_CR_TKT = -1765328341,
    KRB5KRB_AP_ERR_BADKEYVER = -1765328340,
    KRB5KRB_AP_ERR_NOKEY = -1765328339,
    KRB5KRB_AP_ERR_MUT_FAIL = -1765328338,
    KRB5KRB_AP_ERR_BADDIRECTION = -1765328337,
    KRB5KRB_AP_ERR_METHOD = -1765328336,
    KRB5KRB_AP_ERR_BADSEQ = -1765328335,
    KRB5KRB_AP_ERR_INAPP_CKSUM = -1765328334,
    KRB5KRB_AP_PATH_NOT_ACCEPTED = -1765328333,
    KRB5KRB_ERR_RESPONSE_TOO_BIG = -1765328332,
    KRB5KRB_ERR_GENERIC = -1765328324,
    KRB5KRB_ERR_FIELD_TOOLONG = -1765328323,
    KRB5KDC_ERR_CLIENT_NOT_TRUSTED = -1765328322,
    KRB5KDC_ERR_KDC_NOT_TRUSTED = -1765328321,
    KRB5KDC_ERR_INVALID_SIG = -1765328320,
    KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED = -1765328319,
    KRB5KDC_ERR_CERTIFICATE_MISMATCH = -1765328318,
    KRB5KRB_AP_ERR_NO_TGT = -1765328317,
    KRB5KDC_ERR_WRONG_REALM = -1765328316,
    KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED = -1765328315,
    KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE = -1765328314,
    KRB5KDC_ERR_INVALID_CERTIFICATE = -1765328313,
    KRB5KDC_ERR_REVOKED_CERTIFICATE = -1765328312,
    KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN = -1765328311,
    KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = -1765328310,
    KRB5KDC_ERR_CLIENT_NAME_MISMATCH = -1765328309,
    KRB5KDC_ERR_KDC_NAME_MISMATCH = -1765328308,
    KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE = -1765328307,
    KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED = -1765328306,
    KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED = -1765328305,
    KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED = -1765328304,
    KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED = -1765328303,
    KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND = -1765328299,
    KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE = -1765328298,
    KRB5KDC_ERR_PREAUTH_EXPIRED = -1765328294,
    KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED = -1765328293,
    KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION = -1765328291,
    KRB5KDC_ERR_NO_ACCEPTABLE_KDF = -1765328284,
    KRB5_ERR_RCSID = -1765328256,
    KRB5_LIBOS_BADLOCKFLAG = -1765328255,
    KRB5_LIBOS_CANTREADPWD = -1765328254,
    KRB5_LIBOS_BADPWDMATCH = -1765328253,
    KRB5_LIBOS_PWDINTR = -1765328252,
    KRB5_PARSE_ILLCHAR = -1765328251,
    KRB5_PARSE_MALFORMED = -1765328250,
    KRB5_CONFIG_CANTOPEN = -1765328249,
    KRB5_CONFIG_BADFORMAT = -1765328248,
    KRB5_CONFIG_NOTENUFSPACE = -1765328247,
    KRB5_BADMSGTYPE = -1765328246,
    KRB5_CC_BADNAME = -1765328245,
    KRB5_CC_UNKNOWN_TYPE = -1765328244,
    KRB5_CC_NOTFOUND = -1765328243,
    KRB5_CC_END = -1765328242,
    KRB5_NO_TKT_SUPPLIED = -1765328241,
    KRB5KRB_AP_WRONG_PRINC = -1765328240,
    KRB5KRB_AP_ERR_TKT_INVALID = -1765328239,
    KRB5_PRINC_NOMATCH = -1765328238,
    KRB5_KDCREP_MODIFIED = -1765328237,
    KRB5_KDCREP_SKEW = -1765328236,
    KRB5_IN_TKT_REALM_MISMATCH = -1765328235,
    KRB5_PROG_ETYPE_NOSUPP = -1765328234,
    KRB5_PROG_KEYTYPE_NOSUPP = -1765328233,
    KRB5_WRONG_ETYPE = -1765328232,
    KRB5_PROG_SUMTYPE_NOSUPP = -1765328231,
    KRB5_REALM_UNKNOWN = -1765328230,
    KRB5_SERVICE_UNKNOWN = -1765328229,
    KRB5_KDC_UNREACH = -1765328228,
    KRB5_NO_LOCALNAME = -1765328227,
    KRB5_MUTUAL_FAILED = -1765328226,
    KRB5_RC_TYPE_EXISTS = -1765328225,
    KRB5_RC_MALLOC = -1765328224,
    KRB5_RC_TYPE_NOTFOUND = -1765328223,
    KRB5_RC_UNKNOWN = -1765328222,
    KRB5_RC_REPLAY = -1765328221,
    KRB5_RC_IO = -1765328220,
    KRB5_RC_NOIO = -1765328219,
    KRB5_RC_PARSE = -1765328218,
    KRB5_RC_IO_EOF = -1765328217,
    KRB5_RC_IO_MALLOC = -1765328216,
    KRB5_RC_IO_PERM = -1765328215,
    KRB5_RC_IO_IO = -1765328214,
    KRB5_RC_IO_UNKNOWN = -1765328213,
    KRB5_RC_IO_SPACE = -1765328212,
    KRB5_TRANS_CANTOPEN = -1765328211,
    KRB5_TRANS_BADFORMAT = -1765328210,
    KRB5_LNAME_CANTOPEN = -1765328209,
    KRB5_LNAME_NOTRANS = -1765328208,
    KRB5_LNAME_BADFORMAT = -1765328207,
    KRB5_CRYPTO_INTERNAL = -1765328206,
    KRB5_KT_BADNAME = -1765328205,
    KRB5_KT_UNKNOWN_TYPE = -1765328204,
    KRB5_KT_NOTFOUND = -1765328203,
    KRB5_KT_END = -1765328202,
    KRB5_KT_NOWRITE = -1765328201,
    KRB5_KT_IOERR = -1765328200,
    KRB5_NO_TKT_IN_RLM = -1765328199,
    KRB5DES_BAD_KEYPAR = -1765328198,
    KRB5DES_WEAK_KEY = -1765328197,
    KRB5_BAD_ENCTYPE = -1765328196,
    KRB5_BAD_KEYSIZE = -1765328195,
    KRB5_BAD_MSIZE = -1765328194,
    KRB5_CC_TYPE_EXISTS = -1765328193,
    KRB5_KT_TYPE_EXISTS = -1765328192,
    KRB5_CC_IO = -1765328191,
    KRB5_FCC_PERM = -1765328190,
    KRB5_FCC_NOFILE = -1765328189,
    KRB5_FCC_INTERNAL = -1765328188,
    KRB5_CC_WRITE = -1765328187,
    KRB5_CC_NOMEM = -1765328186,
    KRB5_CC_FORMAT = -1765328185,
    KRB5_CC_NOT_KTYPE = -1765328184,
    KRB5_INVALID_FLAGS = -1765328183,
    KRB5_NO_2ND_TKT = -1765328182,
    KRB5_NOCREDS_SUPPLIED = -1765328181,
    KRB5_SENDAUTH_BADAUTHVERS = -1765328180,
    KRB5_SENDAUTH_BADAPPLVERS = -1765328179,
    KRB5_SENDAUTH_BADRESPONSE = -1765328178,
    KRB5_SENDAUTH_REJECTED = -1765328177,
    KRB5_PREAUTH_BAD_TYPE = -1765328176,
    KRB5_PREAUTH_NO_KEY = -1765328175,
    KRB5_PREAUTH_FAILED = -1765328174,
    KRB5_RCACHE_BADVNO = -1765328173,
    KRB5_CCACHE_BADVNO = -1765328172,
    KRB5_KEYTAB_BADVNO = -1765328171,
    KRB5_PROG_ATYPE_NOSUPP = -1765328170,
    KRB5_RC_REQUIRED = -1765328169,
    KRB5_ERR_BAD_HOSTNAME = -1765328168,
    KRB5_ERR_HOST_REALM_UNKNOWN = -1765328167,
    KRB5_SNAME_UNSUPP_NAMETYPE = -1765328166,
    KRB5KRB_AP_ERR_V4_REPLY = -1765328165,
    KRB5_REALM_CANT_RESOLVE = -1765328164,
    KRB5_TKT_NOT_FORWARDABLE = -1765328163,
    KRB5_FWD_BAD_PRINCIPAL = -1765328162,
    KRB5_GET_IN_TKT_LOOP = -1765328161,
    KRB5_CONFIG_NODEFREALM = -1765328160,
    KRB5_SAM_UNSUPPORTED = -1765328159,
    KRB5_SAM_INVALID_ETYPE = -1765328158,
    KRB5_SAM_NO_CHECKSUM = -1765328157,
    KRB5_SAM_BAD_CHECKSUM = -1765328156,
    KRB5_KT_NAME_TOOLONG = -1765328155,
    KRB5_KT_KVNONOTFOUND = -1765328154,
    KRB5_APPL_EXPIRED = -1765328153,
    KRB5_LIB_EXPIRED = -1765328152,
    KRB5_CHPW_PWDNULL = -1765328151,
    KRB5_CHPW_FAIL = -1765328150,
    KRB5_KT_FORMAT = -1765328149,
    KRB5_NOPERM_ETYPE = -1765328148,
    KRB5_CONFIG_ETYPE_NOSUPP = -1765328147,
    KRB5_OBSOLETE_FN = -1765328146,
    KRB5_EAI_FAIL = -1765328145,
    KRB5_EAI_NODATA = -1765328144,
    KRB5_EAI_NONAME = -1765328143,
    KRB5_EAI_SERVICE = -1765328142,
    KRB5_ERR_NUMERIC_REALM = -1765328141,
    KRB5_ERR_BAD_S2K_PARAMS = -1765328140,
    KRB5_ERR_NO_SERVICE = -1765328139,
    KRB5_CC_READONLY = -1765328138,
    KRB5_CC_NOSUPP = -1765328137,
    KRB5_DELTAT_BADFORMAT = -1765328136,
    KRB5_PLUGIN_NO_HANDLE = -1765328135,
    KRB5_PLUGIN_OP_NOTSUPP = -1765328134,
    KRB5_ERR_INVALID_UTF8 = -1765328133,
    KRB5_ERR_FAST_REQUIRED = -1765328132,
    KRB5_LOCAL_ADDR_REQUIRED = -1765328131,
    KRB5_REMOTE_ADDR_REQUIRED = -1765328130,
    KRB5_TRACE_NOSUPP = -1765328129,
}

impl ErrCode {
    /// The raw value the library uses for this code.
    pub const fn raw(self) -> i32 {
        self as i32
    }
}

impl fmt::Display for ErrCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_values_round_trip() {
        for code in ErrCode::ALL {
            assert_eq!(ErrCode::from_raw(code.raw()), Some(*code));
        }
        assert_eq!(ErrCode::ALL.len(), 208);
    }

    #[test]
    fn table_bounds_and_gaps() {
        // The table starts at KRB5KDC_ERR_NONE and ends at
        // KRB5_TRACE_NOSUPP.
        assert_eq!(ErrCode::KRB5KDC_ERR_NONE.raw(), -1765328384);
        assert_eq!(ErrCode::KRB5_TRACE_NOSUPP.raw(), -1765328129);
        // One past each end is not the table's.
        assert_eq!(ErrCode::from_raw(-1765328385), None);
        assert_eq!(ErrCode::from_raw(-1765328128), None);
        // Codes inside the range are live and classified, including the
        // ones a stale table dropped.
        assert_eq!(
            ErrCode::from_raw(-1765328357),
            Some(ErrCode::KRB5KDC_ERR_MUST_USE_USER2USER)
        );
        assert_eq!(
            ErrCode::from_raw(-1765328140),
            Some(ErrCode::KRB5_ERR_BAD_S2K_PARAMS)
        );
        assert_eq!(
            ErrCode::from_raw(-1765328132),
            Some(ErrCode::KRB5_ERR_FAST_REQUIRED)
        );
        // A KRB5PLACEHOLD_ slot the header reserves but does not name is a
        // real gap: KRB5PLACEHOLD_30 sits between SVC_UNAVAILABLE (-355) and
        // WRONG_REALM's block.
        assert_eq!(ErrCode::from_raw(-1765328354), None);
        // errno values are not the table's.
        assert_eq!(ErrCode::from_raw(libc::ENOENT), None);
        assert_eq!(ErrCode::from_raw(0), None);
    }

    /// The strong pin: the table is exactly the set of live codes the linked
    /// libkrb5 names across the com_err range. Walks every value from one
    /// past the low end to one past the high end and asserts that `from_raw`
    /// classifies a value iff the library gives it a real (non-placeholder)
    /// message — so a code the library added but the table missed, or a
    /// `KRB5PLACEHOLD_` slot wrongly listed, fails here.
    #[test]
    fn table_is_exactly_the_linked_library() {
        // Uses libkrb5 to render each code; needs a context but no config or
        // KDC (com_err messages are compiled into the library).
        #[allow(unsafe_code)]
        fn message(ctx: &crate::context::Context, code: i32) -> String {
            // SAFETY: valid context; the returned string is the library's,
            // copied then released with the paired free on the same context.
            unsafe {
                let ptr = crate::ffi::krb5_get_error_message(ctx.raw(), code);
                let text = std::ffi::CStr::from_ptr(ptr)
                    .to_string_lossy()
                    .into_owned();
                crate::ffi::krb5_free_error_message(ctx.raw(), ptr);
                text
            }
        }
        // A placeholder or out-of-table code renders as "Unknown code …" or
        // "KRB5 error code N"; a live code renders descriptive text.
        fn is_placeholder(msg: &str) -> bool {
            msg.starts_with("Unknown code")
                || msg.starts_with("KRB5 error code")
        }

        let ctx = crate::context::Context::new().expect("krb5 context");
        let lo = ErrCode::KRB5KDC_ERR_NONE.raw();
        let hi = ErrCode::KRB5_TRACE_NOSUPP.raw();
        let mut listed = 0usize;
        for code in (lo - 1)..=(hi + 1) {
            let named = ErrCode::from_raw(code).is_some();
            let real = !is_placeholder(&message(&ctx, code));
            assert_eq!(
                named,
                real,
                "code {code}: table names it = {named}, library has a real \
                 message = {real} ({:?})",
                message(&ctx, code)
            );
            if named {
                listed += 1;
            }
        }
        assert_eq!(listed, ErrCode::ALL.len());
    }

    #[test]
    fn names_are_the_upstream_macros() {
        assert_eq!(ErrCode::KRB5_KT_NOTFOUND.name(), "KRB5_KT_NOTFOUND");
        assert_eq!(
            ErrCode::KRB5KDC_ERR_PREAUTH_FAILED.to_string(),
            "KRB5KDC_ERR_PREAUTH_FAILED"
        );
        for code in ErrCode::ALL {
            assert!(code.name().starts_with("KRB5"), "{}", code.name());
        }
    }

    #[test]
    fn error_carries_code_and_message() {
        let err = Error::new(
            ErrCode::KRB5_KT_NOTFOUND.raw(),
            "No such entry in the key table".into(),
        );
        assert_eq!(err.code(), -1765328203);
        assert_eq!(err.kind(), Some(ErrCode::KRB5_KT_NOTFOUND));
        assert_eq!(err.to_string(), "No such entry in the key table");

        let os = Error::new(libc::ENOENT, "file not found".into());
        assert_eq!(os.kind(), None);
        assert_eq!(os.code(), libc::ENOENT);
    }

    #[test]
    fn errors_expose_a_source_chain_entry_point() {
        fn boxed(e: Error) -> Box<dyn std::error::Error> {
            Box::new(e)
        }
        assert!(
            boxed(Error::new(5, "input/output error".into()))
                .to_string()
                .contains("input/output")
        );
    }
}
