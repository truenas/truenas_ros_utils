# CLAUDE.md

## Workspace

Virtual workspace, no umbrella crate. Members are independent of each other; a
consumer depends on the one it wants. Crate names use underscores.

Edition 2024 and `rust-version = "1.98.1"` are set once in
`[workspace.package]`; members inherit both. Lints come from
`[workspace.lints.rust]`, with `lints.workspace = true` in each member.
`Cargo.lock` is committed. rustfmt uses `max_width = 80`.

`unsafe_code` is `deny`, not `forbid`, so an FFI crate can lift it per module
with `#![allow(unsafe_code)]`. Every `unsafe` block carries a `// SAFETY:` note
naming the invariant it relies on. A crate with no FFI sets
`#![forbid(unsafe_code)]` at its own root instead.

## Licensing

MIT throughout. [`LICENSE`](LICENSE) holds the text and every member inherits
`license.workspace = true`.

Each source file, manifest, and workflow opens with a two-line SPDX header, so
the license and its holder travel with the file rather than only with the
repository:

```rust
// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
```

`#` replaces `//` in TOML and YAML. The copyright line matches `LICENSE`
verbatim; keep the two in step. A new file gets the header when it is created.
Prose files (`README.md`, `CLAUDE.md`) and `LICENSE` itself do not carry one.

## Documentation and comments

Terse and factual. No marketing, no persuasion, no weighing the design against
alternatives that were not chosen.

- State a constraint as a requirement, not as the consequence of violating it.
- Do not reference other repositories, earlier implementations, or defects in
  them. This is green-field code and reads as such.
- A comment says what invariant holds, or why something non-obvious is the way
  it is. It does not argue for the design.
- A test comment says what the test would catch.

## Testing

Cover the public API surface as closely as is reasonable. Test this
workspace's own decisions — copying, lifetimes, locking, error classification,
wire layout — and take the correctness of what it binds to or depends on as
given.

Expected values come from the specification, written out by hand. Do not
capture them from a run of the implementation: a test built that way only
proves the code still does what it did, not that it does the right thing.

A suite that can skip must be able to fail instead, under an environment
variable CI sets. A skip must never be able to read as a pass.

## Memory safety

A crate with an FFI boundary runs its whole suite under valgrind memcheck in
CI, through `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER`. Only `definite`
leak kinds count as errors: a process-lifetime static is reported as possibly
lost and is not one. `--trace-children=yes` follows a suite's re-executed
children — the NSS fan-out suite drives the module registry only there —
while `cc` and `python3` are skipped: they are not under test and are not
memcheck-clean.

## Implementing a published standard

When a crate implements a specification:

- Fetch the specification and test against it clause by clause, with each test
  naming the section it comes from.
- Reproduce any worked example the document gives, byte for byte.
- Read the reference implementations for behaviour the document leaves open and
  for the error conventions they use. Record what they establish in the crate's
  documentation, not what they are called or where they live.

## `truenas_krb5`

Links the system MIT `libkrb5` (and `libk5crypto`, where
`krb5_c_string_to_key` lives). Kerberos state is host state — `krb5.conf`,
key tables, credential caches — shared with every other consumer, and one
implementation must interpret it, so there is nothing to vendor.

Every handle owns its `krb5_context`. libkrb5 binds a handle to the context
that produced it and forbids concurrent use, so [`src/context.rs`](truenas_krb5/src/context.rs)
gives each `Keytab` and `Ccache` a context of its own: the types are `Send`
and not `Sync`, handles never mix across values, and there is no context
type in the API. The cost is one configuration read per value, which is why
`kinit_keytab` takes names and resolves the handles itself rather than
accepting them.

Error messages are captured, not deferred. `krb5_get_error_message` can
carry detail about the specific failing call and only until the next call on
the context, so [`Error`](truenas_krb5/src/error.rs) records the message the
moment a non-zero code is seen and owns it thereafter. `ErrCode` is the krb5
com_err table — variant names verbatim from `krb5.h`, values pinned to the
linked library — and the table has retired slots, so it is `from_raw` over a
match, not a range. System `errno` values pass through raw, and this crate's
own refusals (interior NUL, non-UTF-8 identity) are `EINVAL`.

Key tables go through the library in every direction. [`Keytab::from_bytes`](truenas_krb5/src/keytab.rs)
backs a `FILE` table with an anonymous `memfd` reached through
`/proc/self/fd`, and `as_bytes` serializes by writing entries into a fresh
one and reading the file back, so the on-disk format is always libkrb5's
own — key material from a database column never touches a filesystem path.
The `FILE` writer stamps its own write time, so a serialize round trip
preserves principals, keys, versions, and enctypes but not timestamps, which
[`tests/krb5.rs`](truenas_krb5/tests/krb5.rs) states. Key bytes are scrubbed
before release and redacted in `Debug`.

Principals parse and unparse through the library, whose quoting rules are the
wire contract; realm and components must be UTF-8, because they are identity.
[`tests/krb5.rs`](truenas_krb5/tests/krb5.rs) is hermetic — each case
re-executes with a generated `KRB5_CONFIG` — and reproduces RFC 3961
Appendix A.4's DES3 string-to-key vector byte for byte; the AES vectors are
not reachable through the default-parameter path, so they are pinned instead
by [`tests/kdc.rs`](truenas_krb5/tests/kdc.rs), where a key table this crate
derives from a password must satisfy a real AS exchange against a throwaway
KDC. That suite skips without the MIT KDC tools;
`TRUENAS_KRB5_REQUIRE_KDC=1` makes the skip a failure.

The crate knows MIT Kerberos and nothing above it. What a principal is
allowed to do, and which key table or cache a deployment uses, are the
consumer's.

## `truenas_gssapi`

Links the system `libgssapi_krb5`. A GSSAPI exchange is only meaningful
against the host's Kerberos state and the mechanisms the mechglue carries, so
there is nothing to vendor.

Acceptor only. Everything on TrueNAS that initiates does so through other
stacks, and an acceptor that cannot initiate has less to review, so the crate
binds `gss_accept_sec_context` and the names, credentials, and OIDs around
it, and not `gss_init_sec_context`. [`AcceptorCred`](truenas_gssapi/src/cred.rs)
acquires from a key table through the `gssapi_ext.h` credential store
(`gss_acquire_cred_from` with a `keytab` element) for every mechanism the
glue offers, so one credential serves a `Negotiate` endpoint whichever way a
peer arrives. [`Acceptor`](truenas_gssapi/src/accept.rs) is the accept-side
context as a step loop: feed the initiator's token, send back any token the
step yields, stop when it completes — Kerberos in one step, SPNEGO across an
extra leg, the same loop either way.

Identity comes from the mechanism, never a claim. The authenticated name is
whatever the ticket proves; [`Name::localname`](truenas_gssapi/src/name.rs)
maps it to a Unix account through the mechanism's own rules (`gss_localname`,
which for Kerberos honours `auth_to_local`), and an unmappable name is an
error, not a guess. `Name` also imports, displays, canonicalizes, exports
(RFC 2743 §3.2), and compares — comparison and mapping are the library's, so
name equivalence is never reimplemented here.

[`Error`](truenas_gssapi/src/error.rs) carries the raw major and minor status
and renders both with `gss_display_status`, captured under the mechanism that
produced the minor status; the routine field classifies as `RoutineError`
with the C bindings' `GSS_S_` names. [`Oid`](truenas_gssapi/src/oid.rs) holds
the BER arc octets, written out from the RFCs that assign them, and a test
pins each against the OID the linked library exports for the same identifier.

[`tests/gssapi.rs`](truenas_gssapi/tests/gssapi.rs) is hermetic and exercises
the surface where the outcome is fixed without a KDC — names, OIDs, errors,
an empty credential store, a garbage token. [`tests/negotiate.rs`](truenas_gssapi/tests/negotiate.rs)
runs the real exchange: `truenas_krb5` stands up a throwaway KDC and a
service key table, and a minimal initiator local to the test — the one place
`gss_init_sec_context` is bound — drives this crate's acceptor to completion
over both Kerberos and SPNEGO, then maps the result to a local account. It
skips without the MIT KDC tools; `TRUENAS_GSSAPI_REQUIRE_KDC=1` makes the
skip a failure.

The crate knows the GSSAPI accept side and nothing above it. The HTTP
`Negotiate` framing, the account lookup, and what a mapped identity is
allowed to do belong to the consumer.

## `truenas_jsonrpc`

Conforms to JSON-RPC 2.0, with no dialect and nothing configurable: what §4
admits is accepted and what §5 requires is emitted.
[`tests/jsonrpc20.rs`](truenas_jsonrpc/tests/jsonrpc20.rs) follows the
specification clause by clause and reproduces every worked example from its
§7; [`tests/batch.rs`](truenas_jsonrpc/tests/batch.rs) does the same for §6,
and [`tests/client.rs`](truenas_jsonrpc/tests/client.rs) for §4's request
and §5's response as a client sees them. Any change to what is accepted or
emitted is checked against the document first.

Sans-io, and both roles. `frame` finds where one message ends in a stream,
`parse` reads an inbound call, `Response` and `batch_frame` build the answer
to one, and `Caller` with `parse_answer` make a call and read what came
back. Nothing reads a socket, owns a runtime, spawns anything, or holds a
connection.

The crate never buffers, so it applies no ceiling to a message: a peer can
hold `Frame::Incomplete` open indefinitely and the transport's own limit on
a buffered message is what bounds that.

`frame`'s three verdicts are what a stream transport's framer has to answer,
and map onto `truenas_ros`'s contract one for one — `Complete(n)` to
`Framing::Complete { header_len: 0, body_len: n }`, `Incomplete` to
`Framing::More` or `MoreInMessage`, `Invalid` to `Framing::Invalid`. Once
bytes of a message have been seen the answer must be `MoreInMessage`: the
two read identically, but `More` returns the connection to the idle clock
and disarms its receipt budget, so a peer that sends half a message and
stops is held by nothing. A transport carrying a length prefix does not need
`frame` at all, its own prefix framer having delimited the message already.

Only an Object or an Array can be framed. §4 makes a request an Object and
§6 makes a batch an Array, and those are also the only shapes whose end is
knowable without the next byte — a bare Number has no end until a non-digit
arrives. Framing finds the boundary and does not validate: a mismatched
pair is delimited here and refused by `parse`, which reads the bytes anyway,
so the check is not paid for twice.

No method registry and no dispatch. Which methods exist, what one does, and
how long it may run need the application, and anything long-running needs to
own concurrency. Correlating an answer to its call is a map from `Id` to
whatever the caller wants resumed, which only the caller knows — `Caller`
hands back the id it minted and stops there.

`params` and `result` cross the boundary as
[`RawValue`](https://docs.rs/serde_json/latest/serde_json/value/struct.RawValue.html),
so an inbound payload is decoded once by whoever knows its type and an
outbound one encoded once by whoever built it. Neither is ever materialized
as a `Value`.

The three shapes §6 distinguishes are the three arms of `Incoming`. A frame
that is neither an Object nor a non-empty Array is answered with one
Response object. A non-empty Array is a batch whose elements are judged
separately, so one bad element does not condemn its neighbours. A batch that
produces no responses — every element a notification — is answered with
nothing at all, which `batch_frame` reports as `None` rather than as an
empty Array, and a batch answer that arrives as an empty Array is refused
for the same reason.

A refusal carries §5.1's code and message and no `data`. Why it was refused
travels beside the error as `Reason`: §5.1 leaves `data` to the server, and
detail naming the validation step that refused a frame describes the
validator to whoever sent it. `ErrorObject::with_reason` attaches it, and
doing so is a decision.

An id is echoed as it arrived. §5 requires the response to carry the same
value, so a Number keeps the `serde_json::Number` it was written as rather
than being narrowed to an integer — narrowing would answer `1` to a request
that asked as `1.0`. A refusal is answered against the request's own id
wherever it could be read, and against Null only where it could not. On the
calling side the id member is required in a response, unlike in a request
where its absence means a notification.

Outbound, §4.2 is enforced before the wire: `params` that encode to
anything but an Array or an Object are `BuildError::ParamsNotStructured`
rather than a frame the peer will refuse. A build that fails consumes no id,
so a gap in the sequence cannot be mistaken for a lost call.

The crate knows JSON-RPC 2.0 and nothing above it. No transport, no
framing policy, no authentication, and no method vocabulary belongs in it.

## `truenas_ktls`

Links the system libssl. Nothing in it implements TLS: the crate drives
the library's handshake over a caller's connected socket with kernel TLS
enabled, reads the kernel's crypto state back for both directions, and
refuses the connection unless it is there. The option is a request and the
readback is the fact; plaintext must never pass for TLS. The handshake
runs over a socket BIO on the real descriptor — which is what lets libssl
install kernel TLS — and the BIO never owns the descriptor. Once `accept`
returns, nothing of the call remains: plain reads and writes on the
socket carry the connection.

`accept` blocks; the caller bounds it with the socket's own timeouts, and
an elapsed timeout is `Error::Stalled`. An `Acceptor` is `Clone` over a
reference-counted context, so certificate rotation is building a new one
and swapping which the caller uses — an in-flight handshake keeps its own
context alive. Resumption is refused on every path the negotiated version
can offer, so nothing retains the state it would need.

[`tests/ktls.rs`](truenas_ktls/tests/ktls.rs) generates certificate
material in-process and drives accepts against a userspace TLS client
over loopback TCP. The engagement cases probe once with a real loopback
handshake and skip where the kernel or libssl cannot install TLS on a
socket; `TRUENAS_KTLS_REQUIRE_SYSTEM=1` turns the skip into a failure.
Only a refused engagement skips — any other probe failure is the crate's
own and fails loudly.

## `truenas_mdb`

Links the system `liblmdb`. It is never vendored: exactly one copy of LMDB may
mediate an environment within a process, and these databases are shared with
other processes that link `liblmdb0`.

`MDB_NOTLS` is neither set nor offered, so LMDB's default applies — one
transaction per thread per environment. [`src/txn.rs`](truenas_mdb/src/txn.rs)
enforces that with `EDEADLK` rather than leaving a second transaction to
deadlock on the writer mutex or fail with `MDB_BAD_RSLOT`.

One environment per path per process, reference counted through the pool in
[`src/env.rs`](truenas_mdb/src/env.rs).

An environment directory is trusted like the process's own memory: LMDB
dereferences the mapped pages and a value's length is data on them, so only an
environment this process controls may be opened.

Values are stored byte for byte. No header, envelope, or encoding is added, so
another reader of the database sees what was written. `EnvFlags` exposes
durability and readahead only; `MDB_WRITEMAP`, `MDB_MAPASYNC`, `MDB_NOSUBDIR`,
and `MDB_NOLOCK` stay out, each omission documented where the type is defined.

Interoperability is held to account against `python3-lmdb` over one shared
environment ([`tests/python_interop.rs`](truenas_mdb/tests/python_interop.rs)).
It must be the distro package, which links `liblmdb0`; `pip install lmdb`
bundles its own copy and would test nothing.

## `truenas_nss`

Consumes the system NSS service modules directly: `libnss_files.so.2`,
`libnss_sss.so.2`, and `libnss_winbind.so.2` are dlopened by bare soname on
first use and their `_nss_<module>_*` service functions called, so
`nsswitch.conf` and the libc frontends never mediate a lookup. Nothing is
linked at build time. It needs glibc 2.34: from there `dlopen` lives in
`libc.so.6`, and `libnss_files.so.2` is a stub whose `_nss_files_*` functions
are reached through the handle's dependency scope — `dlsym` therefore always
goes through the handle, never `RTLD_DEFAULT`.

A loaded module is never dlclosed: NSS modules keep global and thread-local
state and are not built to be unloaded, so every handle and `Service` lives
for the process. Every dlopen/dlsym/dlerror sequence runs under one lock,
because `dlerror` reports through shared state.

Entries name the module that produced them. Identity fields — names and
members — must be present and UTF-8: they round-trip into lookups and
stand in authorization decisions. Descriptive fields (GECOS, directory,
shell) decode lossily, so a stray byte in one cannot deny the identity.
The password fields (`pw_passwd`, `gr_passwd`) are omitted: the hash lives
in the shadow database, and the placeholder invites misuse. The fan-out lookups skip a
module that reports UNAVAIL and propagate every other failure, a module that
cannot be loaded included. The scratch buffer grows only on TRYAGAIN with
ERANGE — the pairing glibc's frontends require — because ERANGE under any
other status is not a request for a larger buffer.

`getgrouplist` drives `_nss_<module>_initgroups_dyn`, the only path to a
directory user's full membership: sssd and winbind compute the closure
server-side and do not enumerate. Membership is additive, so its fan-out is
a union of all three modules under the lookup fan-out's skip rule: a
skipped module is indistinguishable from one with no memberships to add,
so the union covers whichever modules could answer. The gid array is
`malloc`-owned because the module grows it with `realloc`, and the limit is
passed unbounded: a module at a positive limit truncates the list and still
reports success, so a ceiling belongs to the caller, where exceeding it is
visible. NOTFOUND is "no memberships known here", indistinguishable from an
unknown user; existence is `getpwnam`'s question.

Enumeration is per module — no all-modules iterator, which would invent an
ordering NSS does not define. `FILES` keeps one cursor per process, so its
iterator holds a per-service lock for its whole life and another thread's
enumeration waits; `SSS` and `WINBIND` cursors are per thread, so iterators
are `!Send`. A same-thread iterator that would share a cursor (or the lock)
is refused with `Error::Busy` in [`src/service.rs`](truenas_nss/src/service.rs)
rather than left to deadlock. A cursor fault ends the enumeration — the
cursor did not move, so a retry could only repeat it — while an entry that
will not convert is yielded as an error and the walk goes on. The exclusion
reaches this crate's iterators only: libc's own `set`/`get`/`endpwent`
drive the same process-global `FILES` stream, so a consumer must not mix
them with a live enumeration.

`Service::open` points the crate at a module by explicit path, one
`Service` per module: a second over the same module would put a second
lock over its one cursor.
[`tests/`](truenas_nss/tests/) compile deterministic fixture modules from
[`tests/fixture/nss_fixture.c`](truenas_nss/tests/fixture/nss_fixture.c) and
load them that way — built without a soname, so a fixture can never satisfy
the registry's bare-soname lookups. [`tests/fanout.rs`](truenas_nss/tests/fanout.rs)
re-executes itself with `LD_LIBRARY_PATH` pointing at fixtures named as the
three modules, so a child process drives the real registry end to end.

## `truenas_pam`

Links the system `libpam`. A PAM transaction is only meaningful against the
modules and configuration the host has installed, so there is nothing to
vendor.

`pam_start_confdir` is the entry point rather than `pam_start`, so a
transaction may be pointed at service files of its own.
[`tests/`](truenas_pam/tests/) run their own stacks out of the source tree that
way, without privilege and without touching `/etc/pam.d`. It needs libpam 1.4.

`libpam_misc` is not linked, so `pam_misc_setenv`'s read-only variables are not
offered; `pam_putenv` covers set, replace, and delete.

Items are a partial set. `PAM_AUTHTOK` and `PAM_OLDAUTHTOK` are omitted because
a password reaches a module through the conversation, and writing one into the
handle leaves it there for every later module to read; `PAM_CONV` because the
crate owns it; the `PAM_FAIL_DELAY` function pointer in favour of
`pam_fail_delay()`; and the X and prompt-text items as having no bearing on a
network service. Each omission is documented where the accessors are defined.

The conversation is the crate's only C callback, and
[`src/conv.rs`](truenas_pam/src/conv.rs) is where the conventions for one live:
responses are allocated with `malloc` because the module stack frees them with
`free`; every array the stack will not see is scrubbed before release; and the
body runs under `catch_unwind`, since unwinding into C is undefined and
aborting would skip `pam_end`. A panic is held until libpam has unwound its own
frames, then resumed on the thread that drove the call.

One thread at a time per handle, stated in the types: every operation takes
`&mut self`, and [`src/step.rs`](truenas_pam/src/step.rs) moves the whole
transaction onto its worker, so the caller cannot reach it mid-exchange.
Cancellation is cooperative — a module cannot be stopped mid-call — so a step
timeout bounds the round trip and teardown still waits for the module.

The crate knows PAM and nothing above it. Which service to run, what a prompt
means, and what to make of a refusal are policy and belong to the consumer.

## `truenas_xdr`

Conforms to RFC 4506 (STD 67).
[`tests/rfc4506.rs`](truenas_xdr/tests/rfc4506.rs) follows the document section
by section and ends with the §7 worked example taken from its hex dump. Any
change to encoding or decoding is checked against the standard first.

`serde` is a traits-only dependency: the crate implements `Serializer` and
`Deserializer` and hand-writes its wrapper impls, so it pulls no
`serde_derive`. The `derive` feature is the separate `truenas_xdr_derive`
crate, and the codec builds and passes without it.

Decoding entry points are explicit about the input they expect: `from_bytes`
consumes it exactly and reports what is left over, `from_prefix` returns the
unread tail. Silently ignoring trailing input is not an option — it hides
truncation and framing errors.

`Strictness` is a decode-time choice because encoding is identical either way.
`Strict` holds input to what the standard permits an encoder to emit; `Lenient`
accepts what real encoders send.

Decoding bounds its own nesting (`Deserializer::DEFAULT_MAX_DEPTH`, raised
with `with_max_depth`), so a hostile chain of §4.19 optionals is
`Error::RecursionLimit`, not a stack overflow. A sequence count is held to
the remaining input before the element loop — an element is at least one
4-byte unit — so a count the input cannot meet is `Error::Eof`, not a spin
over a zero-size element type.
[`tests/robustness.rs`](truenas_xdr/tests/robustness.rs) holds every decode
path to Ok-or-Err over a hostile corpus.

Strings and opaque data decode as borrows of the input. A wire format has to
round-trip through itself, which `&[u8]` does not — serde encodes it as a
sequence and decodes it as opaque — so `VarOpaqueRef` exists for that.

The codec knows about RFC 4506 and nothing above it. No framing, no envelopes,
no transport or protocol vocabulary belongs in this crate.

## Verification

Everything below must pass before a change lands. CI runs all of it.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
TRUENAS_MDB_REQUIRE_PYTHON=1 TRUENAS_PAM_REQUIRE_MODULES=1 \
    TRUENAS_NSS_REQUIRE_CC=1 TRUENAS_NSS_REQUIRE_SYSTEM=1 \
    TRUENAS_KTLS_REQUIRE_SYSTEM=1 \
    TRUENAS_KRB5_REQUIRE_KDC=1 TRUENAS_GSSAPI_REQUIRE_KDC=1 \
    cargo test --workspace
cargo test -p truenas_xdr --no-default-features
cargo doc --workspace --no-deps          # must be warning-free
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=99 \
    --leak-check=full --errors-for-leak-kinds=definite \
    --keep-debuginfo=yes --quiet \
    --suppressions=$PWD/valgrind.supp \
    --trace-children=yes \
    --trace-children-skip=*/cc,*/python3*,*/krb5kdc,*/kadmin.local,*/kdb5_util,*/kinit" \
    TRUENAS_MDB_REQUIRE_PYTHON=1 TRUENAS_PAM_REQUIRE_MODULES=1 \
    TRUENAS_NSS_REQUIRE_CC=1 TRUENAS_NSS_REQUIRE_SYSTEM=1 \
    TRUENAS_KTLS_REQUIRE_SYSTEM=1 \
    TRUENAS_KRB5_REQUIRE_KDC=1 TRUENAS_GSSAPI_REQUIRE_KDC=1 \
    cargo test --workspace
```

[`valgrind.supp`](valgrind.supp) suppresses leaks *inside* a bound system
library on a path the binding cannot release — currently one: MIT
libgssapi_krb5 abandons the principal it builds while acquiring a credential
that then fails. Each entry is scoped to the allocating library frame, so a
leak in this workspace's own code cannot match one. A leak in a bound
library on a path the crate *can* release is the crate's to fix, not to
suppress.

Build needs `libkrb5-dev`, `liblmdb-dev`, `libpam0g-dev`, and `libssl-dev`;
the interop suite needs `python3-lmdb`, the PAM suites need `libpam-modules`,
the NSS fixture suites need a C compiler (`cc`), and the Kerberos KDC-backed
suites need the MIT KDC tools (`krb5-kdc`, `krb5-admin-server`, `krb5-user`);
the memcheck run needs `valgrind`, and `--keep-debuginfo=yes` because libpam
unloads each module before the process ends. The re-executed KDC tools are
skipped under memcheck alongside `cc` and `python3`: they are not under test
and are not memcheck-clean, and the crate under test drives them only as
child processes.

The Kerberos suites re-execute the test binary as a child (like the NSS
fan-out suite), so `--trace-children=yes` already covers the in-crate code
that runs there; only the KDC daemon and its admin tools are excluded.

`TRUENAS_KTLS_REQUIRE_SYSTEM` is the one gate CI cannot set: the stock
runners' OpenSSL is built without kTLS, so engagement cannot happen there
and those cases skip. The battery above runs on hosts whose kernel and
libssl can engage, and there the gate is required.
