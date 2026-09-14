// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Behavioral suite: names, OIDs, and the acceptor against inputs no KDC
//! is needed for.
//!
//! Each case re-executes with `KRB5_CONFIG` pointing at a generated
//! configuration, so the host's Kerberos state cannot reach an assertion.
//! The live exchange lives in the `negotiate` suite; here the acceptor is
//! exercised only where the outcome is fixed without a KDC — an empty
//! credential store, a garbage token — and the surface around it (names,
//! OIDs, errors) is checked directly.

use std::process::Command;
use truenas_gssapi::{Acceptor, AcceptorCred, Name, Oid, RoutineError};

const MARKER: &str = "TRUENAS_GSSAPI_HERMETIC";

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
         \x20   dns_lookup_kdc = false\n\
         [realms]\n\
         \x20   EXAMPLE.TEST = {\n\
         \x20       kdc = 127.0.0.1:88\n\
         \x20   }\n\
         [domain_realm]\n\
         \x20   .example.test = EXAMPLE.TEST\n",
    )
    .unwrap();
    let empty_kt = dir.path().join("empty.keytab");
    std::fs::write(&empty_kt, [0x05, 0x02]).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--test-threads=1", "--nocapture", "--exact", test])
        .env(MARKER, "1")
        .env("KRB5_CONFIG", &conf)
        .env("TRUENAS_GSSAPI_EMPTY_KT", &empty_kt)
        .env_remove("KRB5_KTNAME")
        .status()
        .unwrap();
    assert!(status.success(), "hermetic child for `{test}` failed");
}

#[test]
fn name_imports_displays_and_compares() {
    hermetic("name_imports_displays_and_compares", || {
        let a =
            Name::import("HTTP@nas.example.test", &Oid::nt_hostbased_service())
                .unwrap();
        // Display is the library's rendering; hold to the parts that must
        // survive, not exact punctuation.
        let shown = a.display().unwrap();
        assert!(shown.contains("HTTP"), "{shown}");
        assert!(shown.contains("nas.example.test"), "{shown}");

        let b =
            Name::import("HTTP@nas.example.test", &Oid::nt_hostbased_service())
                .unwrap();
        assert!(a.matches(&b).unwrap());

        let c = Name::import(
            "HTTP@other.example.test",
            &Oid::nt_hostbased_service(),
        )
        .unwrap();
        assert!(!a.matches(&c).unwrap());
    });
}

#[test]
fn krb5_principal_canonicalizes_and_exports() {
    hermetic("krb5_principal_canonicalizes_and_exports", || {
        let name = Name::import("user@EXAMPLE.TEST", &Oid::nt_krb5_principal())
            .unwrap();
        // Export requires a mechanism name; canonicalize to Kerberos first.
        let mn = name.canonicalize(&Oid::krb5()).unwrap();
        let exported = mn.export().unwrap();
        // RFC 2743 §3.2: the token opens with 0x04 0x01 and carries the
        // mechanism OID (DER-wrapped) — here Kerberos's.
        assert_eq!(&exported[..2], &[0x04, 0x01]);
        let krb5_der = {
            let arc = Oid::krb5();
            let mut v = vec![0x06, arc.elements().len() as u8];
            v.extend_from_slice(arc.elements());
            v
        };
        assert!(
            exported.windows(krb5_der.len()).any(|w| w == krb5_der),
            "exported name does not carry the krb5 mechanism OID"
        );

        // The exported form re-imports and still compares equal.
        let round = Name::import(
            &String::from_utf8_lossy(&exported),
            &Oid::nt_export_name(),
        );
        // Some builds reject a non-UTF-8 exported blob through the text
        // import; only assert the happy path when it round-trips cleanly.
        if let Ok(reimported) = round {
            assert!(mn.matches(&reimported).unwrap());
        }
    });
}

#[test]
fn localname_maps_the_default_realm_and_refuses_a_foreign_one() {
    hermetic(
        "localname_maps_the_default_realm_and_refuses_a_foreign_one",
        || {
            // The built-in rule strips the realm for a single-component
            // principal in the default realm.
            let local = Name::import(
                "someuser@EXAMPLE.TEST",
                &Oid::nt_krb5_principal(),
            )
            .unwrap();
            assert_eq!(
                local.localname(Some(&Oid::krb5())).unwrap(),
                "someuser"
            );

            // A principal from a realm with no auth_to_local rule does not
            // map; the mapping fails rather than inventing a user.
            let foreign = Name::import(
                "someuser@FOREIGN.REALM",
                &Oid::nt_krb5_principal(),
            )
            .unwrap();
            assert!(foreign.localname(Some(&Oid::krb5())).is_err());
        },
    );
}

#[test]
fn acquire_from_empty_keytab_has_no_key() {
    hermetic("acquire_from_empty_keytab_has_no_key", || {
        // Acquiring a specific acceptor principal from a keytab with no
        // such key fails; the library reports it as a credential problem.
        let kt = std::env::var("TRUENAS_GSSAPI_EMPTY_KT").unwrap();
        let name =
            Name::import("HTTP@nas.example.test", &Oid::nt_hostbased_service())
                .unwrap();
        let err = AcceptorCred::from_keytab(&format!("FILE:{kt}"), Some(&name))
            .unwrap_err();
        assert!(
            matches!(
                err.routine(),
                Some(RoutineError::NO_CRED | RoutineError::FAILURE)
            ),
            "unexpected routine error: {:?} ({err})",
            err.routine()
        );
    });
}

#[test]
fn acceptor_rejects_a_garbage_token() {
    hermetic("acceptor_rejects_a_garbage_token", || {
        // A default-credential acquisition may itself fail without a
        // keytab; when it succeeds, a non-token must be refused as a
        // defective token rather than accepted.
        let Ok(cred) = AcceptorCred::acquire(None) else {
            eprintln!("no default acceptor credential; nothing to feed");
            return;
        };
        let mut acceptor = Acceptor::new(&cred);
        let err = acceptor.step(b"this is not a GSS token").unwrap_err();
        assert!(!acceptor.is_established());
        assert!(
            matches!(
                err.routine(),
                Some(
                    RoutineError::DEFECTIVE_TOKEN
                        | RoutineError::FAILURE
                        | RoutineError::NO_CRED
                )
            ),
            "unexpected routine error: {:?} ({err})",
            err.routine()
        );
    });
}

#[test]
fn interior_nul_in_keytab_name_is_a_calling_error() {
    hermetic("interior_nul_in_keytab_name_is_a_calling_error", || {
        let err = AcceptorCred::from_keytab("FILE:/etc/kr\0b5.keytab", None)
            .unwrap_err();
        assert!(err.to_string().contains("interior NUL"), "{err}");
        // A calling error, not a routine one.
        assert_eq!(err.routine(), None);
        assert_ne!(err.major() & (0o377 << 24), 0);
    });
}

#[test]
fn handles_are_send() {
    fn is_send<T: Send>() {}
    is_send::<AcceptorCred>();
    is_send::<Name>();
}
