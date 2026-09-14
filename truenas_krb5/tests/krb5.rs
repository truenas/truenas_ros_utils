// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Behavioral suite: principals, key tables, caches, and error
//! classification, hermetic against files of its own.
//!
//! Each case re-executes the test binary with `KRB5_CONFIG` pointing at a
//! generated minimal configuration, so the host's Kerberos setup — or its
//! absence — cannot reach an assertion. The library reads configuration
//! only through the environment, and the test harness is threaded, so the
//! environment is fixed in a child process rather than mutated in place.
//!
//! The string-to-key case reproduces RFC 3961 Appendix A.4 byte for byte —
//! the DES3 derivation takes no iteration parameter, so its published
//! vectors are reachable through the default-parameter path this crate
//! exposes; the AES vectors of RFC 3962/8009 are not (each is printed for
//! an explicit iteration count or a binary salt). AES derivation is pinned
//! two ways instead: self-consistency here, and end to end in the KDC
//! suite, where a key table this crate derives must satisfy a real AS
//! exchange.

use std::process::Command;
use truenas_krb5::{
    Ccache, EncType, ErrCode, KeySpec, Keytab, Principal, PrincipalType,
};

const MARKER: &str = "TRUENAS_KRB5_HERMETIC";

/// Run `body` in a re-executed child whose Kerberos environment is this
/// suite's own: a generated `krb5.conf` with realm `EXAMPLE.TEST` and DNS
/// lookups off, and a scratch default ccache.
fn hermetic(test: &str, body: fn()) {
    if std::env::var_os(MARKER).is_some() {
        body();
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("krb5.conf");
    std::fs::write(
        &conf,
        "[libdefaults]\n\
         \x20   default_realm = EXAMPLE.TEST\n\
         \x20   dns_lookup_realm = false\n\
         \x20   dns_lookup_kdc = false\n",
    )
    .unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--test-threads=1", "--nocapture", "--exact", test])
        .env(MARKER, "1")
        .env("KRB5_CONFIG", &conf)
        .env(
            "KRB5CCNAME",
            format!("FILE:{}", dir.path().join("cc").display()),
        )
        .env_remove("KRB5_KTNAME")
        .status()
        .unwrap();
    assert!(status.success(), "hermetic child for `{test}` failed");
}

#[test]
fn parse_splits_realm_components_and_type() {
    hermetic("parse_splits_realm_components_and_type", || {
        let p = Principal::parse("HTTP/nas.example.test@EXAMPLE.TEST").unwrap();
        assert_eq!(p.realm, "EXAMPLE.TEST");
        assert_eq!(p.components, ["HTTP", "nas.example.test"]);
        // Parsing yields the library's default name type.
        assert_eq!(p.principal_type(), Some(PrincipalType::KRB5_NT_PRINCIPAL));
        assert_eq!(p.unparse().unwrap(), "HTTP/nas.example.test@EXAMPLE.TEST");
    });
}

#[test]
fn parse_applies_the_default_realm() {
    hermetic("parse_applies_the_default_realm", || {
        let p = Principal::parse("user").unwrap();
        assert_eq!(p.realm, "EXAMPLE.TEST");
        assert_eq!(p.components, ["user"]);
    });
}

#[test]
fn parse_refuses_a_malformed_name() {
    hermetic("parse_refuses_a_malformed_name", || {
        let err = Principal::parse("a@b@c").unwrap_err();
        assert_eq!(err.kind(), Some(ErrCode::KRB5_PARSE_MALFORMED));
    });
}

#[test]
fn interior_nul_is_refused_as_einval() {
    hermetic("interior_nul_is_refused_as_einval", || {
        let err = Principal::parse("us\0er@EXAMPLE.TEST").unwrap_err();
        assert_eq!(err.code(), libc::EINVAL);
        assert_eq!(err.kind(), None);
        assert!(err.to_string().contains("interior NUL"));
    });
}

#[test]
fn quoting_round_trips() {
    hermetic("quoting_round_trips", || {
        // The separators and the escape are legal inside a component when
        // quoted; the library's grammar is authoritative in both
        // directions.
        let odd = Principal {
            realm: "EXAMPLE.TEST".into(),
            components: vec!["we/ird@name\\x".into()],
            name_type: PrincipalType::KRB5_NT_PRINCIPAL.raw(),
        };
        let text = odd.unparse().unwrap();
        assert_eq!(Principal::parse(&text).unwrap(), odd);

        // And the other direction: a quoted wire form parses to the
        // literal component.
        let p = Principal::parse("a\\/b@EXAMPLE.TEST").unwrap();
        assert_eq!(p.components, ["a/b"]);
    });
}

#[test]
fn string_to_key_matches_rfc3961() {
    hermetic("string_to_key_matches_rfc3961", || {
        // RFC 3961 Appendix A.4, written out by hand: passphrase
        // "password", salt "ATHENA.MIT.EDUraeburn" — which is exactly the
        // default salt for raeburn@ATHENA.MIT.EDU, realm then components.
        const DES3: [u8; 24] = [
            0x85, 0x0b, 0xb5, 0x13, 0x58, 0x54, 0x8c, 0xd0, 0x5e, 0x86, 0x76,
            0x8c, 0x31, 0x3e, 0x3b, 0xfe, 0xf7, 0x51, 0x19, 0x37, 0xdc, 0xf7,
            0x2c, 0x3e,
        ];

        let kt = Keytab::from_bytes(&[]).unwrap();
        kt.add_entry(
            "raeburn@ATHENA.MIT.EDU",
            EncType::ENCTYPE_DES3_CBC_SHA1,
            1,
            KeySpec::Password("password"),
        )
        .unwrap();
        let entry = kt.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(entry.key.contents, DES3);
        assert!(entry.key.deprecated());
    });
}

#[test]
fn aes_string_to_key_is_salted_and_deterministic() {
    hermetic("aes_string_to_key_is_salted_and_deterministic", || {
        // The printed AES vectors are not reachable through the default
        // parameters (see the module docs); what must hold regardless:
        // the derivation is a function of passphrase and principal, the
        // principal reaches it through the salt, and the key is the
        // enctype's size. The KDC suite proves the derivation agrees with
        // a real KDC's.
        let derive = |principal: &str, password: &str| {
            let kt = Keytab::from_bytes(&[]).unwrap();
            kt.add_entry(
                principal,
                EncType::ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                1,
                KeySpec::Password(password),
            )
            .unwrap();
            kt.entries()
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .key
                .contents
                .clone()
        };
        let a = derive("user@EXAMPLE.TEST", "hunter2");
        assert_eq!(a.len(), 32);
        assert_eq!(a, derive("user@EXAMPLE.TEST", "hunter2"));
        assert_ne!(a, derive("other@EXAMPLE.TEST", "hunter2"));
        assert_ne!(a, derive("user@EXAMPLE.TEST", "hunter3"));
    });
}

#[test]
fn keytab_round_trips_through_bytes() {
    hermetic("keytab_round_trips_through_bytes", || {
        let kt = Keytab::from_bytes(&[]).unwrap();
        assert_eq!(kt.as_bytes().unwrap(), [0x05, 0x02]);

        kt.add_entry(
            "HTTP/nas.example.test@EXAMPLE.TEST",
            EncType::ENCTYPE_AES256_CTS_HMAC_SHA1_96,
            3,
            KeySpec::Key(&[0xa5; 32]),
        )
        .unwrap();
        kt.add_entry(
            "user@EXAMPLE.TEST",
            EncType::ENCTYPE_AES128_CTS_HMAC_SHA1_96,
            7,
            KeySpec::Password("hunter2"),
        )
        .unwrap();

        let bytes = kt.as_bytes().unwrap();
        assert_eq!(&bytes[..2], [0x05, 0x02]);

        let copy = Keytab::from_bytes(&bytes).unwrap();
        let a: Vec<_> =
            kt.entries().unwrap().collect::<Result<_, _>>().unwrap();
        let b: Vec<_> =
            copy.entries().unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);
        for (x, y) in a.iter().zip(&b) {
            // Timestamps are the write's own (module contract), so they
            // are not part of the round trip.
            assert_eq!(x.principal, y.principal);
            assert_eq!(x.vno, y.vno);
            assert_eq!(x.key, y.key);
            assert!(y.timestamp > 0);
        }
        assert_eq!(a[0].vno, 3);
        assert_eq!(a[0].key.contents, [0xa5; 32]);
        assert!(!a[0].key.deprecated());
    });
}

#[test]
fn remove_entry_honors_filters() {
    hermetic("remove_entry_honors_filters", || {
        let kt = Keytab::from_bytes(&[]).unwrap();
        let p1 = "svc/one@EXAMPLE.TEST";
        let p2 = "svc/two@EXAMPLE.TEST";
        let aes256 = EncType::ENCTYPE_AES256_CTS_HMAC_SHA1_96;
        let aes128 = EncType::ENCTYPE_AES128_CTS_HMAC_SHA1_96;
        kt.add_entry(p1, aes256, 1, KeySpec::Key(&[1; 32])).unwrap();
        kt.add_entry(p1, aes256, 2, KeySpec::Key(&[2; 32])).unwrap();
        kt.add_entry(p2, aes128, 1, KeySpec::Key(&[3; 16])).unwrap();

        assert_eq!(kt.remove_entry(p1, None, Some(2)).unwrap(), 1);
        assert_eq!(kt.remove_entry(p1, Some(aes128), None).unwrap(), 0);
        assert_eq!(
            kt.remove_entry("ghost@EXAMPLE.TEST", None, None).unwrap(),
            0
        );
        assert_eq!(kt.remove_entry(p1, None, None).unwrap(), 1);

        let left: Vec<_> =
            kt.entries().unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].principal.components, ["svc", "two"]);
    });
}

#[test]
fn missing_keytab_file_is_an_error_naming_the_path() {
    hermetic("missing_keytab_file_is_an_error_naming_the_path", || {
        let kt = Keytab::open("FILE:/nonexistent/truenas_krb5.keytab").unwrap();
        let err = kt.entries().unwrap_err();
        assert!(
            err.to_string().contains("/nonexistent/truenas_krb5.keytab"),
            "{err}"
        );
    });
}

#[test]
fn missing_ccache_reports_fcc_nofile() {
    hermetic("missing_ccache_reports_fcc_nofile", || {
        let cc = Ccache::open("FILE:/nonexistent/truenas_krb5.cc").unwrap();
        assert_eq!(cc.cc_type(), "FILE");
        let err = cc.credentials().unwrap_err();
        assert_eq!(err.kind(), Some(ErrCode::KRB5_FCC_NOFILE));
        // The value pin against the linked library: the com_err table this
        // build classifies is the one the library actually raises from.
        assert_eq!(err.code(), -1765328189);
    });
}

#[test]
fn keytab_name_and_type() {
    hermetic("keytab_name_and_type", || {
        let kt = Keytab::from_bytes(&[0x05, 0x02]).unwrap();
        assert_eq!(kt.kt_type(), "FILE");
        assert!(
            kt.name().unwrap().starts_with("FILE:/proc/self/fd/"),
            "{:?}",
            kt.name()
        );
    });
}

#[test]
fn entries_iterator_is_fused_after_end() {
    hermetic("entries_iterator_is_fused_after_end", || {
        let kt = Keytab::from_bytes(&[]).unwrap();
        let mut entries = kt.entries().unwrap();
        assert!(entries.next().is_none());
        assert!(entries.next().is_none());
    });
}

#[test]
fn keyspec_debug_redacts() {
    // No Kerberos state involved; runs as-is.
    let shown = format!("{:?}", KeySpec::Password("hunter2"));
    assert!(!shown.contains("hunter2"), "{shown}");
    let shown = format!("{:?}", KeySpec::Key(&[0xa5; 32]));
    assert!(!shown.contains("a5"), "{shown}");
    assert!(shown.contains("32 bytes"), "{shown}");
}

#[test]
fn ccache_iteration_skips_config_entries() {
    hermetic("ccache_iteration_skips_config_entries", || {
        // Build a cache holding one config pseudo-credential (the
        // `X-CACHECONF:` metadata a modern kinit writes) and no real
        // ticket. Without the filter the iterator would surface the config
        // entry; with it, the cache reads as empty.
        let dir = tempfile::tempdir().unwrap();
        let name = format!("FILE:{}", dir.path().join("cc").display());
        raw::write_config_only(&name, "user@EXAMPLE.TEST");

        let cc = Ccache::open(&name).unwrap();
        let creds: Vec<_> =
            cc.credentials().unwrap().collect::<Result<_, _>>().unwrap();
        assert!(creds.is_empty(), "config entry leaked as a credential");
    });
}

#[test]
fn handles_are_send() {
    fn is_send<T: Send>() {}
    is_send::<Keytab>();
    is_send::<Ccache>();
    is_send::<Principal>();
}

/// A minimal raw binding, local to the config-entry test: the crate exposes
/// no way to *write* a config entry (it only reads caches), so the test
/// stages one directly through libkrb5.
mod raw {
    #![allow(unsafe_code)]
    use std::ffi::{CString, c_char, c_int, c_uint, c_void};

    #[repr(C)]
    struct KData {
        magic: c_int,
        length: c_uint,
        data: *mut c_char,
    }

    unsafe extern "C" {
        fn krb5_init_context(ctx: *mut *mut c_void) -> c_int;
        fn krb5_free_context(ctx: *mut c_void);
        fn krb5_parse_name(
            ctx: *mut c_void,
            name: *const c_char,
            princ: *mut *mut c_void,
        ) -> c_int;
        fn krb5_free_principal(ctx: *mut c_void, princ: *mut c_void);
        fn krb5_cc_resolve(
            ctx: *mut c_void,
            name: *const c_char,
            cache: *mut *mut c_void,
        ) -> c_int;
        fn krb5_cc_initialize(
            ctx: *mut c_void,
            cache: *mut c_void,
            princ: *mut c_void,
        ) -> c_int;
        fn krb5_cc_set_config(
            ctx: *mut c_void,
            cache: *mut c_void,
            princ: *mut c_void,
            key: *const c_char,
            data: *mut KData,
        ) -> c_int;
        fn krb5_cc_close(ctx: *mut c_void, cache: *mut c_void) -> c_int;
    }

    /// Initialize a cache for `client` and store one config entry, nothing
    /// else.
    pub fn write_config_only(ccname: &str, client: &str) {
        let cname = CString::new(client).unwrap();
        let ccn = CString::new(ccname).unwrap();
        let key = CString::new("pa_type").unwrap();
        let mut value = *b"2";
        // SAFETY: standard libkrb5 handshake; every handle is created and
        // freed on the one context, and the config value outlives the call.
        unsafe {
            let mut ctx: *mut c_void = std::ptr::null_mut();
            assert_eq!(krb5_init_context(&mut ctx), 0);
            let mut princ: *mut c_void = std::ptr::null_mut();
            assert_eq!(krb5_parse_name(ctx, cname.as_ptr(), &mut princ), 0);
            let mut cc: *mut c_void = std::ptr::null_mut();
            assert_eq!(krb5_cc_resolve(ctx, ccn.as_ptr(), &mut cc), 0);
            assert_eq!(krb5_cc_initialize(ctx, cc, princ), 0);
            let mut data = KData {
                magic: 0,
                length: value.len() as c_uint,
                data: value.as_mut_ptr().cast(),
            };
            assert_eq!(
                krb5_cc_set_config(ctx, cc, princ, key.as_ptr(), &mut data),
                0
            );
            krb5_cc_close(ctx, cc);
            krb5_free_principal(ctx, princ);
            krb5_free_context(ctx);
        }
    }
}
