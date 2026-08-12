// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Fixtures shared by the suite: certificate material generated
//! in-process, the userspace client the crate's accepts are driven
//! against, and the engagement gate with its skip-or-fail switch.

// Not every case uses every helper.
#![allow(dead_code)]

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use openssl::x509::{X509, X509NameBuilder};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use truenas_ktls::{Acceptor, Error};

/// A fresh self-signed certificate and key, written as PEM files named
/// for `cn`, which is also the subject's common name — what a client
/// reads back to tell one acceptor's certificate from another's.
pub fn cert_pair(dir: &Path, cn: &str) -> (PathBuf, PathBuf) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    let cert_path = dir.join(format!("{cn}.crt.pem"));
    let key_path = dir.join(format!("{cn}.key.pem"));
    std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
    std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (cert_path, key_path)
}

/// A userspace TLS client over `stream`, deliberately not kernel TLS:
/// the peer that proves the crate's side of the wire is real TLS.
/// Verification is off — the certificates are self-signed, and a case
/// asserting about them reads the peer certificate directly.
pub fn connect(stream: TcpStream, sni: Option<&str>) -> SslStream<TcpStream> {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let mut config = connector.configure().unwrap();
    config.set_verify_hostname(false);
    if sni.is_none() {
        config.set_use_server_name_indication(false);
    }
    config.connect(sni.unwrap_or("unnamed"), stream).unwrap()
}

/// The subject common name of the certificate the server presented.
pub fn peer_cn(stream: &SslStream<TcpStream>) -> String {
    let cert = stream.ssl().peer_certificate().unwrap();
    let entry = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap();
    entry.data().to_string().unwrap()
}

fn system_required() -> bool {
    std::env::var_os("TRUENAS_KTLS_REQUIRE_SYSTEM").is_some_and(|v| v == "1")
}

/// `Some(())` when this host can engage kernel TLS — probed once with a
/// real loopback handshake — or a skip. `TRUENAS_KTLS_REQUIRE_SYSTEM=1`
/// (set by CI where the stack supports it) turns the skip into a
/// failure, so an environment that cannot engage can never read as a
/// pass. Only [`Error::NotEngaged`] skips: it is the one failure that
/// states the environment's answer, and any other means the crate broke.
pub fn engaged() -> Option<()> {
    static PROBE: OnceLock<Result<(), Error>> = OnceLock::new();
    let outcome = PROBE.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = cert_pair(dir.path(), "probe");
        let acceptor = Acceptor::from_pem_files(&cert, &key).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            connect(TcpStream::connect(addr).unwrap(), None);
        });
        let (conn, _) = listener.accept().unwrap();
        let result = {
            use std::os::fd::AsFd;
            acceptor.accept(conn.as_fd()).map(drop)
        };
        client.join().unwrap();
        result
    });
    match outcome {
        Ok(()) => Some(()),
        Err(Error::NotEngaged { .. }) => {
            assert!(
                !system_required(),
                "TRUENAS_KTLS_REQUIRE_SYSTEM=1 but kernel TLS did not \
                 engage: {}",
                outcome.as_ref().unwrap_err()
            );
            None
        }
        Err(other) => panic!("the engagement probe broke: {other}"),
    }
}
