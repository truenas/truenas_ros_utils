// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Initial credentials against a throwaway KDC.
//!
//! The suite builds realm `EXAMPLE.TEST` in a temporary directory with the
//! MIT KDC tools, starts `krb5kdc` on a loopback port, and drives the
//! library in a re-executed child whose `KRB5_CONFIG` names that realm —
//! nothing on the host is read or written. One case acquires credentials
//! through a key table this crate *derived from a password*, which holds
//! the AES string-to-key path to agreement with a real KDC's own
//! derivation.
//!
//! Skips when the KDC tools are not installed; TRUENAS_KRB5_REQUIRE_KDC=1
//! (as CI sets on hosts that carry them) makes that a failure instead.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use truenas_krb5::{
    EncType, ErrCode, KeySpec, Keytab, TicketFlags, kinit_keytab,
    kinit_password,
};

const CHILD: &str = "TRUENAS_KRB5_KDC_CHILD";
const REQUIRE: &str = "TRUENAS_KRB5_REQUIRE_KDC";
const REALM: &str = "EXAMPLE.TEST";
const USER_PW: &str = "the user password";
const DERIVED_PW: &str = "the derived password";

#[test]
fn kdc_initial_credentials() {
    if std::env::var_os(CHILD).is_some() {
        child();
        return;
    }
    let Some(tools) = Tools::find() else {
        if std::env::var_os(REQUIRE).is_some() {
            panic!("{REQUIRE} is set but the MIT KDC tools are not installed");
        }
        eprintln!(
            "skipped: MIT KDC tools (kdb5_util, kadmin.local, krb5kdc, \
             kinit) not installed"
        );
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let realm = Realm::build(&tools, dir.path());
    let _kdc = realm.start_kdc(&tools);
    realm.await_ready(&tools);

    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--test-threads=1",
            "--nocapture",
            "--exact",
            "kdc_initial_credentials",
        ])
        .env(CHILD, "1")
        .env("KRB5_CONFIG", &realm.krb5_conf)
        .env(
            "KRB5CCNAME",
            format!("FILE:{}", realm.dir.join("cc").display()),
        )
        .env("TRUENAS_KRB5_TEST_SVC_KT", &realm.svc_keytab)
        .env("TRUENAS_KRB5_TEST_DIR", &realm.dir)
        .env_remove("KRB5_KTNAME")
        .status()
        .unwrap();
    assert!(
        status.success(),
        "KDC child failed; log:\n{}",
        realm.kdc_log()
    );
}

/// The assertions, run with `KRB5_CONFIG` pointing at the throwaway realm.
fn child() {
    let svc_kt = std::env::var("TRUENAS_KRB5_TEST_SVC_KT").unwrap();
    let dir = PathBuf::from(std::env::var("TRUENAS_KRB5_TEST_DIR").unwrap());

    // A password acquires a TGT into the named cache.
    let cc_name = format!("FILE:{}", dir.join("cc-password").display());
    let cc = kinit_password("user", USER_PW, Some(&cc_name)).unwrap();
    assert_eq!(cc.cc_type(), "FILE");
    let creds: Vec<_> =
        cc.credentials().unwrap().collect::<Result<_, _>>().unwrap();
    let tgt = creds
        .iter()
        .find(|c| c.server.components.first().is_some_and(|c| c == "krbtgt"))
        .expect("no TGT in the cache");
    assert_eq!(tgt.client.realm, REALM);
    assert_eq!(tgt.client.components, ["user"]);
    assert_eq!(tgt.server.components, ["krbtgt", REALM]);
    assert!(tgt.ticket_flags.contains(TicketFlags::INITIAL));
    // The principal requires preauth, so the TGT records it.
    assert!(tgt.ticket_flags.contains(TicketFlags::PRE_AUTH));
    assert!(tgt.times.endtime > tgt.times.starttime);
    assert!(!tgt.keyblock.contents.is_empty());
    assert!(tgt.keyblock.enc_type().is_some());

    // A wrong password fails preauthentication, classified.
    let err = kinit_password("user", "wrong", None).unwrap_err();
    assert_eq!(err.kind(), Some(ErrCode::KRB5KDC_ERR_PREAUTH_FAILED));

    // An unknown principal is the KDC's refusal, classified.
    let err = kinit_password("ghost", USER_PW, None).unwrap_err();
    assert_eq!(err.kind(), Some(ErrCode::KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN));

    // The KDC-exported service keytab acquires credentials.
    let cc_name = format!("FILE:{}", dir.join("cc-keytab").display());
    let cc2 =
        kinit_keytab("svc/nas.example.test", Some(&svc_kt), Some(&cc_name))
            .unwrap();
    let creds: Vec<_> = cc2
        .credentials()
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!creds.is_empty());

    // A key table missing the principal's key is a keytab error, not a
    // KDC exchange.
    let err = kinit_keytab("user", Some(&svc_kt), None).unwrap_err();
    assert_eq!(err.kind(), Some(ErrCode::KRB5_KT_NOTFOUND));

    // The decisive derivation case: a key table built by this crate from
    // the principal's password — never seen by the KDC tools — must
    // satisfy the AS exchange. This holds string-to-key (salt included) to
    // agreement with the KDC's own derivation.
    let derived = Keytab::from_bytes(&[]).unwrap();
    for enctype in [
        EncType::ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        EncType::ENCTYPE_AES128_CTS_HMAC_SHA1_96,
    ] {
        derived
            .add_entry(
                &format!("derived@{REALM}"),
                enctype,
                1,
                KeySpec::Password(DERIVED_PW),
            )
            .unwrap();
    }
    let cc_name = format!("FILE:{}", dir.join("cc-derived").display());
    let cc3 =
        kinit_keytab("derived", Some(&derived.name().unwrap()), Some(&cc_name))
            .unwrap();
    assert!(cc3.credentials().unwrap().next().is_some());

    // kdestroy removes the backing file.
    let path = dir.join("cc-password");
    assert!(path.exists());
    cc.destroy().unwrap();
    assert!(!path.exists());
}

struct Tools {
    kdb5_util: PathBuf,
    kadmin_local: PathBuf,
    krb5kdc: PathBuf,
    kinit: PathBuf,
}

impl Tools {
    fn find() -> Option<Tools> {
        // The daemons live in sbin, which a test environment's PATH often
        // lacks.
        fn locate(name: &str) -> Option<PathBuf> {
            let dirs = std::env::var("PATH").unwrap_or_default();
            for dir in dirs
                .split(':')
                .chain(["/usr/sbin", "/sbin"])
                .filter(|d| !d.is_empty())
            {
                let candidate = Path::new(dir).join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
            None
        }
        Some(Tools {
            kdb5_util: locate("kdb5_util")?,
            kadmin_local: locate("kadmin.local")?,
            krb5kdc: locate("krb5kdc")?,
            kinit: locate("kinit")?,
        })
    }
}

struct Realm {
    dir: PathBuf,
    krb5_conf: PathBuf,
    kdc_conf: PathBuf,
    svc_keytab: PathBuf,
}

impl Realm {
    /// Write the configuration, create the database, and add the
    /// principals the child expects.
    fn build(tools: &Tools, dir: &Path) -> Realm {
        // Bound and released before the KDC starts; the race with another
        // process is accepted, as the port was free a moment ago.
        let port = {
            let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            sock.local_addr().unwrap().port()
        };

        let krb5_conf = dir.join("krb5.conf");
        std::fs::write(
            &krb5_conf,
            format!(
                "[libdefaults]\n\
                 \x20   default_realm = {REALM}\n\
                 \x20   dns_lookup_realm = false\n\
                 \x20   dns_lookup_kdc = false\n\
                 \x20   rdns = false\n\
                 \x20   udp_preference_limit = 1\n\
                 [realms]\n\
                 \x20   {REALM} = {{\n\
                 \x20       kdc = 127.0.0.1:{port}\n\
                 \x20   }}\n"
            ),
        )
        .unwrap();

        let kdc_conf = dir.join("kdc.conf");
        std::fs::write(
            &kdc_conf,
            format!(
                "[realms]\n\
                 \x20   {REALM} = {{\n\
                 \x20       database_name = {dir}/principal\n\
                 \x20       key_stash_file = {dir}/stash\n\
                 \x20       acl_file = {dir}/kadm5.acl\n\
                 \x20       kdc_ports = {port}\n\
                 \x20       kdc_tcp_ports = {port}\n\
                 \x20       supported_enctypes = \
                 aes256-cts-hmac-sha1-96:normal \
                 aes128-cts-hmac-sha1-96:normal\n\
                 \x20   }}\n\
                 [logging]\n\
                 \x20   kdc = FILE:{dir}/kdc.log\n",
                dir = dir.display()
            ),
        )
        .unwrap();
        std::fs::write(dir.join("kadm5.acl"), "*/admin@EXAMPLE.TEST *\n")
            .unwrap();

        let realm = Realm {
            dir: dir.to_path_buf(),
            krb5_conf,
            kdc_conf,
            svc_keytab: dir.join("svc.keytab"),
        };

        realm.run(
            &tools.kdb5_util,
            &["-r", REALM, "create", "-s", "-P", "master key password"],
        );
        // `+requires_preauth` pins the wrong-password classification to
        // KRB5KDC_ERR_PREAUTH_FAILED.
        for query in [
            format!("addprinc -pw \"{USER_PW}\" +requires_preauth user"),
            format!("addprinc -pw \"{DERIVED_PW}\" derived"),
            "addprinc -randkey svc/nas.example.test".to_string(),
            format!(
                "ktadd -k {} svc/nas.example.test",
                realm.svc_keytab.display()
            ),
        ] {
            realm.run(&tools.kadmin_local, &["-r", REALM, "-q", &query]);
        }
        realm
    }

    fn run(&self, tool: &Path, args: &[&str]) {
        let output = Command::new(tool)
            .args(args)
            .env("KRB5_CONFIG", &self.krb5_conf)
            .env("KRB5_KDC_PROFILE", &self.kdc_conf)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {:?} failed:\n{}{}",
            tool.display(),
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn start_kdc(&self, tools: &Tools) -> KdcGuard {
        let child = Command::new(&tools.krb5kdc)
            .args(["-r", REALM, "-n"])
            .env("KRB5_CONFIG", &self.krb5_conf)
            .env("KRB5_KDC_PROFILE", &self.kdc_conf)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        KdcGuard { child }
    }

    /// Wait until the KDC answers: `kinit` with the known password into a
    /// scratch cache, retried while the daemon comes up.
    fn await_ready(&self, tools: &Tools) {
        let scratch = self.dir.join("cc-ready");
        for attempt in 0.. {
            let mut child = Command::new(&tools.kinit)
                .args(["-c", &format!("FILE:{}", scratch.display()), "user"])
                .env("KRB5_CONFIG", &self.krb5_conf)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(USER_PW.as_bytes())
                .unwrap();
            if child.wait().unwrap().success() {
                return;
            }
            assert!(
                attempt < 100,
                "KDC never became ready; log:\n{}",
                self.kdc_log()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn kdc_log(&self) -> String {
        std::fs::read_to_string(self.dir.join("kdc.log")).unwrap_or_default()
    }
}

struct KdcGuard {
    child: Child,
}

impl Drop for KdcGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
