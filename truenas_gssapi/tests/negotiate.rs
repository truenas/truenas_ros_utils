// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The real exchange: a throwaway KDC, a client ticket, and an initiator
//! driving this crate's [`Acceptor`] to completion over both Kerberos and
//! SPNEGO.
//!
//! `truenas_krb5` builds realm `EXAMPLE.TEST`, adds an `HTTP/<host>`
//! service principal, exports its key table, and acquires a client TGT.
//! The initiator side the acceptor is driven against is a small raw
//! binding to `gss_init_sec_context` local to this test — the crate itself
//! ships no initiator. Completion proves the whole path: acquire from a
//! key table, step the accept loop, read the authenticated name, and map
//! it to a local account.
//!
//! Skips when the MIT KDC tools are not installed; TRUENAS_GSSAPI_REQUIRE_KDC=1
//! (as CI sets on hosts that carry them) makes that a failure instead.
#![allow(unsafe_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use truenas_gssapi::{Acceptor, AcceptorCred, Name, Oid, Step};

const CHILD: &str = "TRUENAS_GSSAPI_KDC_CHILD";
const REQUIRE: &str = "TRUENAS_GSSAPI_REQUIRE_KDC";
const REALM: &str = "EXAMPLE.TEST";
const HOST: &str = "nas.example.test";
const USER_PW: &str = "the user password";

#[test]
fn negotiate_end_to_end() {
    if std::env::var_os(CHILD).is_some() {
        child();
        return;
    }
    let Some(tools) = Tools::find() else {
        if std::env::var_os(REQUIRE).is_some() {
            panic!("{REQUIRE} is set but the MIT KDC tools are not installed");
        }
        eprintln!("skipped: MIT KDC tools not installed");
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
            "negotiate_end_to_end",
        ])
        .env(CHILD, "1")
        .env("KRB5_CONFIG", &realm.krb5_conf)
        .env(
            "KRB5CCNAME",
            format!("FILE:{}", realm.dir.join("cc").display()),
        )
        .env("TRUENAS_GSSAPI_TEST_KT", &realm.svc_keytab)
        .env_remove("KRB5_KTNAME")
        .status()
        .unwrap();
    assert!(
        status.success(),
        "child failed; kdc log:\n{}",
        realm.kdc_log()
    );
}

fn child() {
    let kt = std::env::var("TRUENAS_GSSAPI_TEST_KT").unwrap();

    // A client TGT for `user`, acquired with the password into the default
    // cache the environment names.
    truenas_krb5::kinit_password("user", USER_PW, None).expect("client kinit");

    // Kerberos and SPNEGO both authenticate the initiator and complete
    // mutual auth. MIT settles optimistic SPNEGO in one acceptor leg, so
    // these do not exercise the acceptor's continue path — the dedicated
    // multi-leg case below does.
    run_exchange(&kt, Initiator::new(&Oid::krb5()));
    run_exchange(&kt, Initiator::new(&Oid::spnego()));

    // A SPNEGO negotiation advertising two mechanisms with krb5 not first,
    // driven through the same loop. Its purpose is the acceptor's
    // continue-leg path: the `Step::Continue` arm of `run_exchange` carries
    // the invariant assertions (mid-handshake, no identity yet, non-empty
    // challenge) and fires on any build where the negotiated mech requires a
    // mechListMIC round. This MIT build settles it optimistically in a
    // single acceptor leg, so `legs` is 0 here; the exchange must still
    // authenticate and complete mutual auth like the others, which asserts
    // the two-mech NegTokenInit path end to end.
    // IAKERB is 1.3.6.1.5.2.5; krb5 is 1.2.840.113554.1.2.2.
    const IAKERB: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x05];
    const KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
    let _legs = run_exchange(&kt, Initiator::with_neg_mechs(&[IAKERB, KRB5]));

    // A key table without the acceptor's key cannot complete: acquiring
    // for a principal it lacks fails up front.
    let missing =
        Name::import("HTTP@absent.example.test", &Oid::nt_hostbased_service())
            .unwrap();
    assert!(
        AcceptorCred::from_keytab(&format!("FILE:{kt}"), Some(&missing))
            .is_err()
    );
}

/// Drive an initiator/acceptor handshake to completion on both sides.
/// Returns the number of acceptor continue-legs seen. Verifies the acceptor
/// authenticates and maps the initiator, AND that the initiator reaches
/// mutual-auth completion by consuming the acceptor's final token.
fn run_exchange(keytab: &str, mut initiator: Initiator) -> usize {
    let cred = AcceptorCred::from_keytab(&format!("FILE:{keytab}"), None)
        .expect("acquire acceptor cred");
    let mut acceptor = Acceptor::new(&cred);

    let mut token = initiator.start();
    let mut acceptor_continues = 0usize;
    loop {
        match acceptor.step(&token).expect("accept step") {
            Step::Continue { token: challenge } => {
                acceptor_continues += 1;
                // A continue is mid-handshake and must carry a token, and on
                // an intermediate krb5/SPNEGO leg no source name is settled
                // yet.
                assert!(!acceptor.is_established());
                assert!(!challenge.is_empty());
                token = initiator.step(&challenge);
            }
            Step::Complete { token: final_token } => {
                // Deliver the acceptor's final leg (the AP-REP) so the
                // initiator can verify mutual authentication; it must then
                // complete without owing a further token.
                if !initiator.is_complete() {
                    assert!(
                        !final_token.is_empty(),
                        "mutual auth requested but no final token to \
                         complete the initiator"
                    );
                    let leftover = initiator.step(&final_token);
                    assert!(
                        leftover.is_empty(),
                        "initiator still owed a token after completion"
                    );
                }
                break;
            }
        }
    }

    assert!(acceptor.is_established());
    assert!(
        initiator.is_complete(),
        "initiator never reached mutual-auth completion"
    );
    // SPNEGO settles on Kerberos underneath.
    assert_eq!(acceptor.mechanism(), Some(&Oid::krb5()));

    let who = acceptor.source_name().expect("source name");
    let display = who.display().unwrap();
    assert!(display.contains("user@EXAMPLE.TEST"), "{display}");

    // The whole point of the exercise: the authenticated principal maps to
    // the local account under the default realm's built-in rule.
    let local = who.localname(Some(&Oid::krb5())).expect("localname");
    assert_eq!(local, "user");

    initiator.release();
    acceptor_continues
}

// --- a minimal initiator, local to this test --------------------------------
//
// The crate ships no initiator; the acceptor needs one to be driven
// against, so this binds just `gss_init_sec_context` and the buffer/name
// plumbing it needs. Kept deliberately small and separate from the crate's
// own FFI.

mod gss {
    #![allow(non_camel_case_types)]
    use std::os::raw::c_void;
    pub type OM_uint32 = u32;
    pub enum name {}
    pub enum cred {}
    pub enum ctx {}
    #[repr(C)]
    pub struct buffer {
        pub length: usize,
        pub value: *mut c_void,
    }
    #[repr(C)]
    pub struct oid {
        pub length: OM_uint32,
        pub elements: *mut c_void,
    }
    #[repr(C)]
    pub struct oid_set {
        pub count: usize,
        pub elements: *mut oid,
    }
    pub const GSS_C_MUTUAL_FLAG: OM_uint32 = 2;
    pub const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;
    pub const GSS_C_INITIATE: c_int = 1;
    use std::os::raw::c_int;
    unsafe extern "C" {
        pub fn gss_import_name(
            minor: *mut OM_uint32,
            input: *mut buffer,
            name_type: *mut oid,
            output: *mut *mut name,
        ) -> OM_uint32;
        pub fn gss_init_sec_context(
            minor: *mut OM_uint32,
            claimant_cred: *mut cred,
            context: *mut *mut ctx,
            target_name: *mut name,
            mech_type: *mut oid,
            req_flags: OM_uint32,
            time_req: OM_uint32,
            input_chan_bindings: *mut c_void,
            input_token: *mut buffer,
            actual_mech: *mut *mut oid,
            output_token: *mut buffer,
            ret_flags: *mut OM_uint32,
            time_rec: *mut OM_uint32,
        ) -> OM_uint32;
        pub fn gss_release_buffer(
            minor: *mut OM_uint32,
            buffer: *mut buffer,
        ) -> OM_uint32;
        pub fn gss_release_name(
            minor: *mut OM_uint32,
            name: *mut *mut name,
        ) -> OM_uint32;
        pub fn gss_delete_sec_context(
            minor: *mut OM_uint32,
            context: *mut *mut ctx,
            output: *mut buffer,
        ) -> OM_uint32;
        pub fn gss_acquire_cred(
            minor: *mut OM_uint32,
            desired_name: *mut name,
            time_req: OM_uint32,
            desired_mechs: *mut oid_set,
            cred_usage: c_int,
            output_cred: *mut *mut cred,
            actual_mechs: *mut *mut oid_set,
            time_rec: *mut OM_uint32,
        ) -> OM_uint32;
        pub fn gss_release_cred(
            minor: *mut OM_uint32,
            cred: *mut *mut cred,
        ) -> OM_uint32;
        pub fn gss_create_empty_oid_set(
            minor: *mut OM_uint32,
            set: *mut *mut oid_set,
        ) -> OM_uint32;
        pub fn gss_add_oid_set_member(
            minor: *mut OM_uint32,
            member: *mut oid,
            set: *mut *mut oid_set,
        ) -> OM_uint32;
        pub fn gss_release_oid_set(
            minor: *mut OM_uint32,
            set: *mut *mut oid_set,
        ) -> OM_uint32;
        pub fn gss_set_neg_mechs(
            minor: *mut OM_uint32,
            cred: *mut cred,
            mech_set: *mut oid_set,
        ) -> OM_uint32;
    }
}

struct Initiator {
    context: *mut gss::ctx,
    target: *mut gss::name,
    mech: gss::oid,
    mech_elements: Vec<u8>,
    cred: *mut gss::cred,
    complete: bool,
}

impl Initiator {
    /// An initiator advertising a SPNEGO mechanism list, `neg_mechs` (raw
    /// OID octets) in order. Listing more than one mechanism with krb5 not
    /// first forces a `mechListMIC` round trip, so the acceptor takes an
    /// extra leg.
    fn with_neg_mechs(neg_mechs: &[&[u8]]) -> Initiator {
        let mut initiator = Initiator::new(&Oid::spnego());
        // SAFETY: acquire the default initiator credential (null name), then
        // constrain its SPNEGO negotiation order; every out handle is owned
        // and released in `release`. The oid descriptors borrow the caller's
        // octet tables for the duration of the set-building calls.
        unsafe {
            let mut minor = 0;
            let major = gss::gss_acquire_cred(
                &mut minor,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                gss::GSS_C_INITIATE,
                &mut initiator.cred,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            assert_eq!(major, 0, "acquire initiator cred failed: {major:#x}");

            let mut set: *mut gss::oid_set = std::ptr::null_mut();
            assert_eq!(gss::gss_create_empty_oid_set(&mut minor, &mut set), 0);
            for octets in neg_mechs {
                let mut desc = gss::oid {
                    length: octets.len() as u32,
                    elements: octets.as_ptr().cast_mut().cast(),
                };
                assert_eq!(
                    gss::gss_add_oid_set_member(
                        &mut minor, &mut desc, &mut set
                    ),
                    0
                );
            }
            let major = gss::gss_set_neg_mechs(&mut minor, initiator.cred, set);
            assert_eq!(major, 0, "set_neg_mechs failed: {major:#x}");
            gss::gss_release_oid_set(&mut minor, &mut set);
        }
        initiator
    }

    fn new(mech: &Oid) -> Initiator {
        // Target the acceptor by host-based service name.
        let hostbased = Oid::nt_hostbased_service();
        let mut nt = gss::oid {
            length: hostbased.elements().len() as u32,
            elements: hostbased.elements().as_ptr().cast_mut().cast(),
        };
        let text = format!("HTTP@{HOST}");
        let mut buf = gss::buffer {
            length: text.len(),
            value: text.as_ptr().cast_mut().cast(),
        };
        let mut target: *mut gss::name = std::ptr::null_mut();
        let mut minor = 0;
        // SAFETY: descriptors borrow `text` and the OID octets for the
        // call; the out name is released in `release`.
        let major = unsafe {
            gss::gss_import_name(&mut minor, &mut buf, &mut nt, &mut target)
        };
        assert_eq!(major, 0, "initiator import_name failed");
        Initiator {
            context: std::ptr::null_mut(),
            target,
            mech: gss::oid {
                length: 0,
                elements: std::ptr::null_mut(),
            },
            mech_elements: mech.elements().to_vec(),
            cred: std::ptr::null_mut(),
            complete: false,
        }
    }

    fn start(&mut self) -> Vec<u8> {
        self.advance(&[])
    }

    fn step(&mut self, token: &[u8]) -> Vec<u8> {
        self.advance(token)
    }

    /// Whether the initiator's context is established — for a mutual-auth
    /// exchange, true only after it has verified the acceptor's reply.
    fn is_complete(&self) -> bool {
        self.complete
    }

    fn advance(&mut self, input: &[u8]) -> Vec<u8> {
        self.mech = gss::oid {
            length: self.mech_elements.len() as u32,
            elements: self.mech_elements.as_ptr().cast_mut().cast(),
        };
        let mut in_buf = gss::buffer {
            length: input.len(),
            value: input.as_ptr().cast_mut().cast(),
        };
        let mut out = gss::buffer {
            length: 0,
            value: std::ptr::null_mut(),
        };
        let mut minor = 0;
        // SAFETY: default initiator credential (null); the context is null
        // on the first call and owned afterwards; the input borrows the
        // caller's token and the output is released below after copying.
        let major = unsafe {
            gss::gss_init_sec_context(
                &mut minor,
                self.cred,
                &mut self.context,
                self.target,
                &mut self.mech,
                gss::GSS_C_MUTUAL_FLAG,
                0,
                std::ptr::null_mut(),
                &mut in_buf,
                std::ptr::null_mut(),
                &mut out,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert!(
            major == 0 || major & gss::GSS_S_CONTINUE_NEEDED != 0,
            "initiator init_sec_context failed: {major:#x}/{minor}"
        );
        self.complete = major & gss::GSS_S_CONTINUE_NEEDED == 0;
        let token = if out.value.is_null() {
            Vec::new()
        } else {
            // SAFETY: filled by the call above with `length` bytes.
            unsafe {
                std::slice::from_raw_parts(out.value.cast::<u8>(), out.length)
            }
            .to_vec()
        };
        // SAFETY: releasing the output the call allocated.
        unsafe {
            let mut m = 0;
            gss::gss_release_buffer(&mut m, &mut out);
        }
        token
    }

    fn release(&mut self) {
        // SAFETY: owned name and context, each released exactly once.
        unsafe {
            let mut minor = 0;
            if !self.target.is_null() {
                gss::gss_release_name(&mut minor, &mut self.target);
            }
            if !self.context.is_null() {
                gss::gss_delete_sec_context(
                    &mut minor,
                    &mut self.context,
                    std::ptr::null_mut(),
                );
            }
            if !self.cred.is_null() {
                gss::gss_release_cred(&mut minor, &mut self.cred);
            }
        }
    }
}

// --- throwaway realm (shared shape with truenas_krb5's kdc suite) -----------

struct Tools {
    kdb5_util: PathBuf,
    kadmin_local: PathBuf,
    krb5kdc: PathBuf,
    kinit: PathBuf,
}

impl Tools {
    fn find() -> Option<Tools> {
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
    fn build(tools: &Tools, dir: &Path) -> Realm {
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
                 \x20   }}\n\
                 [domain_realm]\n\
                 \x20   .example.test = {REALM}\n\
                 \x20   {HOST} = {REALM}\n"
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
        for query in [
            format!("addprinc -pw \"{USER_PW}\" user"),
            format!("addprinc -randkey HTTP/{HOST}"),
            format!("ktadd -k {} HTTP/{HOST}", realm.svc_keytab.display()),
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
