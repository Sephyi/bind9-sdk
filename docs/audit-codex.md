<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
-->

# Codex Codebase Audit

**Date:** 2026-06-15
**Scope:** Static source review of the full workspace against `PRD.md`, `README.md`, `.github/workflows`, `docs/plans`, Rust crates, CLI code, JS bindings, and integration-test infrastructure.
**Important limitation:** I did not run `cargo test`, `cargo check`, builds, npm builds, containers, or integration tests. The request was to avoid code changes; those commands would create or update build artifacts. Findings below are from source inspection only.

## Compact State Summary

The repository has a substantial Rust implementation: a no-std-capable core crate, a tokio network crate, a re-export crate, a CLI crate, napi-rs bindings, BIND9 integration fixtures, and GitHub Actions for fmt, clippy, tests, docs, WASM core checks, bindings checks, dependency review, RustSec audit, and REUSE lint.

Production readiness is **not there yet** for remote or adversarial environments. The core data model is broad, and many security primitives are present, but several PRD-critical surfaces are either incomplete, misleadingly advertised, or fail open/lose data in edge cases. The highest-risk gaps are TSIG response verification for zone transfers, plaintext remote rndc/stats behavior, IXFR semantics, data-losing zone serialization for supported record variants, and incomplete npm/WASM/CLI surfaces.

The project is closer to an **advanced prototype / pre-release SDK** than a production-grade v0.1.0. It may be usable for local experimentation with simple zones, local rndc, basic RFC 2136 updates, and basic parsing/diffing after local verification. It should not yet be positioned as production-grade, compliance-ready, or full BIND9 9.20 coverage.

## PRD And Plan Reality Check

- `PRD.md:10-13` says v1.2 is "In Progress" with Phases 1-5 complete and Phase 6 hardening next.
- `PRD.md:22` says Phase 5 completed with 574 tests passing. `README.md:36` says 576 tests. I did not verify either count.
- Many `docs/plans/*.md` files are implementation plans with unchecked checklist items. They are not reliable completion markers.
- `docs/plans/2026-03-19-compliance-audit-findings.md` remains useful, but part of it is stale. For example, the prior TLS 1.2/TLS 1.3 contradiction appears fixed in current source, while the transfer TSIG, rndc plaintext, stats plaintext, rndc HMAC input, and rndc constant-time comparison findings remain live.
- `README.md:15-18` correctly warns the project is early-stage, but the same README also claims production-like breadth: full rndc wire protocol, IXFR/AXFR, stats API, native addon plus WASM fallback, connection pooling, and 576 tests (`README.md:18-36`). Those claims overstate the current implementation.

## Severity Summary

| Severity | Count | Theme |
| --- | ---: | --- |
| Critical | 3 | Transfer authentication/integrity, IXFR correctness, data loss in zone text serialization |
| High | 8 | Plaintext management channels, HMAC verification hardening, update wire corruption, incomplete JS/WASM/CLI release surfaces |
| Medium | 11 | BIND master-file compatibility, TSIG parser checks, no-std/safety mismatches, partial stats and rndc coverage, CI/fuzz/release gaps |
| Low | 7 | Documentation drift, local workspace hygiene, smaller API/documentation inconsistencies |

## Critical Findings

### C-01: TSIG-signed AXFR/IXFR does not verify transfer responses

**Files:** `crates/bind9-sdk-net/src/transfer/mod.rs:112-129`, `crates/bind9-sdk-net/src/transfer/mod.rs:137-155`, `crates/bind9-sdk-net/src/transfer/mod.rs:194-197`

`TransferClient::axfr()` and `TransferClient::ixfr()` accept an optional `TsigKey` and sign the outgoing query. The response stream then parses records without verifying any response TSIG. The source explicitly says a MITM could inject unsigned records into a TSIG-authenticated transfer stream.

This is the largest security gap because callers can pass a TSIG key and reasonably infer transfer integrity. The CLI does exactly that for `zone export` (`crates/bind9-sdk-cli/src/commands/zone.rs:175-178`), but the received records are still not authenticated.

**Impact:** Authenticated zone transfers are not actually authenticated end-to-end. A remote or on-path attacker could potentially alter transferred records if network and server topology make interception possible.

**Recommendation:** Implement RFC 8945 transfer response verification before yielding records. Until then, reject `tsig_key` for transfers or make the API name/return error explicit enough that no caller can believe it provides verified transfer integrity.

### C-02: IXFR is advertised but implemented as an AXFR-style stream

**Files:** `crates/bind9-sdk-net/src/transfer/mod.rs:132-155`, `crates/bind9-sdk-net/src/transfer/mod.rs:221-238`

`ixfr()` sends an IXFR query and then delegates to the same `transfer_record_stream()` used by AXFR. That stream terminates on the second apex SOA. Real IXFR responses can contain multiple SOA-delimited delete/add sections and need delta semantics. The current stream does not model delete/add groups, does not apply a diff to an existing zone, and can stop early on valid IXFR data.

This conflicts with PRD FR-011, which describes incremental diffs and fallback handling.

**Impact:** IXFR can return incorrect or truncated data while appearing successful. This is especially risky because an IXFR result is naturally used to update local state.

**Recommendation:** Either remove/disable IXFR from public claims until it has RFC 1995 semantics, or implement typed IXFR events/delta groups plus tests against live BIND9 and `dig IXFR`.

### C-03: Zone serializer can silently lose record data for modeled record variants

**Files:** `crates/bind9-sdk-core/src/rdata/mod.rs:188-252`, `crates/bind9-sdk-core/src/zone/rdata_text.rs:25-46`, `crates/bind9-sdk-core/src/zone/rdata_text.rs:148-157`, `crates/bind9-sdk-core/src/zone/rdata_text.rs:529-532`

`RecordData` models TLSA, SSHFP, CSYNC, RP, and other variants, but text parsing only handles a subset of record types. The zone assembler recognizes `TLSA`, `SSHFP`, `CSYNC`, and `RP` as record types (`crates/bind9-sdk-core/src/zone/parser/record.rs:27-50`), but `parse_rdata()` does not parse them and falls through to generic parsing. Serialization is worse: unsupported variants fall through to `serialize_as_generic()`, which returns `\# 0`.

That means constructing a `RecordData::Tlsa`, `RecordData::Sshfp`, `RecordData::Csync`, or `RecordData::Rp` and serializing it to a zone file can emit an empty generic RDATA, losing the record contents.

**Impact:** Zone round-trips are not lossless for supported Rust enum variants. This can corrupt zone exports or CLI output without an error.

**Recommendation:** Implement text parse/serialize for every public `RecordData` variant or make serialization return `Result<String, CoreError>` and fail closed for unsupported variants.

## High Findings

### H-01: rndc connects over plaintext TCP with no remote locality restriction

**Files:** `crates/bind9-sdk-net/src/rndc/mod.rs:123-133`, `crates/bind9-sdk-net/src/config.rs:119-124`, `crates/bind9-sdk-net/src/config.rs:141-146`

`RndcConnection::connect()` accepts any `SocketAddr` and opens raw `TcpStream`. `ClientConfig.tls` exists, but `Bind9Client::new()` only warns that TLS transports are not implemented. `Bind9Client::rndc_command()` then opens plaintext rndc connections through that path.

**Impact:** Remote rndc commands expose management operation names, zone names, timing, and control-plane metadata to the network. HMAC authenticates messages but does not provide confidentiality.

**Recommendation:** Require localhost for plaintext rndc, or implement TLS and reject non-localhost connections without it. The transfer client already has a locality/TLS posture; rndc needs the same policy.

### H-02: rndc HMAC input extraction fails open to empty input

**File:** `crates/bind9-sdk-net/src/rndc/mod.rs:677-681`

`read_isc_message()` extracts the raw bytes used for HMAC verification, but if extraction fails it uses `unwrap_or_default()`. That silently turns a parser invariant failure into verification over an empty byte slice.

**Impact:** Authentication verification becomes dependent on a fallback value instead of rejecting malformed wire order or missing auth input. Even if exploitation still requires a valid key, this is the wrong failure mode for authentication code.

**Recommendation:** Return `NetError::AuthFailed` or `NetError::Protocol` immediately when `extract_hmac_input()` returns `None`.

### H-03: rndc HMAC comparison uses ordinary byte equality

**File:** `crates/bind9-sdk-net/src/rndc/mod.rs:479-496`

The expected rndc HMAC buffer is compared with `expected_hmac.as_slice() != received_hmac.as_slice()`. The TSIG key path uses cryptographic verification, but rndc response verification does not use a constant-time comparison.

**Impact:** This is a cryptographic hardening gap on an authentication boundary.

**Recommendation:** Use the HMAC crate verifier or `subtle::ConstantTimeEq` for the final comparison.

### H-04: Statistics HTTP client permits remote plaintext HTTP and optional auth

**Files:** `crates/bind9-sdk-net/src/stats.rs:97-130`

`StatsHttpClient::new()` accepts any URL string and builds a reqwest client. `with_auth()` is optional. There is no check that remote plaintext `http://` is limited to localhost, and no requirement for HTTPS or auth on remote endpoints.

**Impact:** BIND stats can disclose server version, zone names, serials, counters, and operational behavior over plaintext.

**Recommendation:** Enforce localhost-only for HTTP, require HTTPS for remote URLs, and document auth expectations clearly.

### H-05: RFC 2136 update wire encoder silently truncates or corrupts oversized data

**Files:** `crates/bind9-sdk-core/src/update/message.rs:61-66`, `crates/bind9-sdk-core/src/update/message.rs:145-168`, `crates/bind9-sdk-core/src/update/message.rs:184-188`, `crates/bind9-sdk-core/src/update/message.rs:269-292`, `crates/bind9-sdk-core/src/update/message.rs:361-367`, `crates/bind9-sdk-core/src/update/message.rs:420-424`

`encode_update_message()` is infallible and performs unchecked integer narrowing:

- prerequisite and update section counts cast from `usize` to `u16`;
- RDLENGTH values cast to `u16`;
- TXT strings longer than 255 bytes are silently truncated;
- CAA tag length is cast to `u8` while full tag bytes are still written;
- NSEC3 salt and hash lengths are cast to `u8`.

**Impact:** Invalid or oversized inputs can produce malformed DNS update messages without error. For TXT, the caller's data is silently changed.

**Recommendation:** Make message construction return `Result<UpdateMessage, CoreError>` or validate at builder insertion time. Reject oversized section counts, RDATA lengths, TXT strings, CAA tags, NSEC3 fields, and any other length-prefixed data before encoding.

### H-06: CLI zone and DNSSEC commands are partly stubs or misleading

**Files:** `crates/bind9-sdk-cli/src/commands/zone.rs:86-129`, `crates/bind9-sdk-cli/src/commands/zone.rs:151-203`, `crates/bind9-sdk-cli/src/commands/dnssec.rs:43-82`

`zone list` calls `status()` and prints server zone count rather than listing zones. `zone status` also calls server `status()` and prints the zone name, not `rndc zonestatus`. `dnssec status` and `dnssec checkds` only print messages saying a live BIND9 server is required; they do not execute `RndcCommand::DnssecStatus` or `RndcCommand::DnssecCheckDs`.

`zone export` signs AXFR with `config.rndc_key`, but response TSIG verification is missing as described in C-01.

**Impact:** CLI output can look successful while not performing the requested operation. This blocks production readiness for the CLI artifact described in the PRD.

**Recommendation:** Wire these commands to actual rndc operations and typed parsers, or mark them explicitly unsupported in CLI help and exit non-zero.

### H-07: npm/WASM package is not ready for the PRD's advertised distribution model

**Files:** `crates/bind9-sdk-bindings/package.json:1-17`, `crates/bind9-sdk-bindings/src/lib.rs:15-39`, `crates/bind9-sdk-bindings/src/transfer.rs:43-56`

The npm package is `"private": true`, version `0.0.0`, only lists `aarch64-apple-darwin` as a napi target, and has no exports map for node/browser/default. The WASM build script does not enable the `nodejs` feature, while all exported modules in `src/lib.rs` are gated behind `#[cfg(feature = "nodejs")]`; network modules are also excluded from `wasm32`.

`JsTransferClient` only exposes unsigned AXFR (`.axfr(domain, None)`) and no IXFR, despite docs saying AXFR/IXFR bindings.

**Impact:** The package cannot meet PRD FR-030, FR-040, or FR-041 as written. Browser WASM fallback likely exports little or nothing from the current binding layer.

**Recommendation:** Decide whether bindings are currently native-only or truly native plus WASM. Then add an exports map, platform matrix, generated type checks, WASM core surface exports, and binding-level tests for every advertised API.

### H-08: Transfer response validation is too thin

**File:** `crates/bind9-sdk-net/src/transfer/mod.rs:175-204`

Transfer response parsing checks only that the DNS message has `QR=1` and `RCODE=0`. It does not check response ID against the generated query ID, opcode, question count/content, QTYPE, authority/additional sections, or unexpected framing.

**Impact:** TCP reduces blind spoofing risk, but the client accepts a broad set of protocol-invalid responses. This compounds the TSIG gap.

**Recommendation:** Carry expected query metadata into `transfer_record_stream()` and validate ID, opcode, question, qtype/qclass, and section handling before yielding answers.

## Medium Findings

### M-01: BIND zone parser compatibility is narrower than PRD claims

**Files:** `crates/bind9-sdk-core/src/domain.rs:12-45`, `crates/bind9-sdk-core/src/zone/parser/record.rs:58-67`, `crates/bind9-sdk-core/src/zone/parser/record.rs:168-218`

The parser has useful basics, but several common BIND master-file behaviors are missing or too strict:

- `Label::new()` rejects `*`, so wildcard owner names such as `*.example.com.` fail.
- DNS owner names are validated like hostnames. DNS labels are more general than RFC 1035 host labels in zone files.
- `$ORIGIN` is parsed as an absolute `DomainName::new()` argument and does not resolve relative origins against the previous origin.
- `$INCLUDE` ignores the optional origin argument, parses included content as its own zone, and then only extends records.
- `$INCLUDE` recursion is unbounded.

**Impact:** "Zone files from BIND9 9.18/9.20 without error" is not currently credible for real-world zones.

**Recommendation:** Add a zone-owner name type or parser mode that supports wildcard and master-file owner syntax. Implement relative `$ORIGIN`, `$INCLUDE path [origin]`, include depth limits, and fixtures from real BIND zones.

### M-02: TXT data model cannot fully meet the embedded-NUL requirement

**Files:** `PRD.md:301-304`, `crates/bind9-sdk-core/src/rdata/mod.rs:67-70`, `crates/bind9-sdk-core/src/update/message.rs:269-274`

The PRD requires TXT records with embedded NUL bytes to be stored and serialized correctly. The current model is `Txt(Vec<String>)`, and update encoding uses UTF-8 string bytes with silent 255-byte truncation.

**Impact:** Arbitrary DNS character-string bytes are not represented safely. Embedded NULs and non-UTF-8 octets need byte-oriented handling.

**Recommendation:** Introduce a `TxtString`/character-string type backed by bytes with strict 255-byte validation and text escaping rules.

### M-03: TSIG parser and verifier lack some boundary/cross-field checks

**Files:** `crates/bind9-sdk-core/src/tsig/record.rs:237-318`, `crates/bind9-sdk-core/src/tsig/record.rs:355-405`

`parse_from_wire()` reads RDLENGTH and checks that the RDATA starts within bounds, but subsequent field reads are checked against `wire.len()` rather than an RDATA end boundary, and the function does not verify exact consumption of the declared RDATA. `verify_response()` uses `key.name` and `key.algorithm` to reconstruct variables but does not explicitly reject mismatched `response_tsig.key_name` or `response_tsig.algorithm`, and does not check `response_tsig.original_id` against the DNS message ID.

**Impact:** The HMAC check should fail for many mismatches, but explicit parser and semantic checks would make TSIG validation easier to reason about and easier to test.

**Recommendation:** Parse within `rdata_end`, require `pos == rdata_end`, and explicitly validate key name, algorithm, and original ID before MAC verification.

### M-04: `UpdateBuilder::sign_now()` panics on pre-epoch system time

**File:** `crates/bind9-sdk-core/src/update/builder.rs:158-168`

The PRD's core principles include "Zero panics" (`PRD.md:53`). `sign_now()` uses `.expect("system clock is before Unix epoch")`.

**Impact:** A clock anomaly can panic library callers.

**Recommendation:** Add a fallible `try_sign_now()` or change `sign_now()` to return `Result`. Avoid panic paths in public API.

### M-05: Stats parser is far from full typed BIND9 statistics

**Files:** `crates/bind9-sdk-net/src/stats.rs:18-43`, `crates/bind9-sdk-net/src/stats.rs:59-83`

PRD FR-006 requires deserializing full BIND9 stats JSON into typed Rust structs without `serde_json::Value` fallback, including query rates, SERVFAIL, recursion, socket, DNSSEC, and zone-level transfer counters. Current parsing includes a small subset: boot/config/current time, version, name/class/serial/type, and an ignored `serde_json::Value` `rcodes` field. `record_count` is always `None`.

**Impact:** The stats API is currently a basic subset, not the typed production stats client described in the PRD.

**Recommendation:** Add fixture-driven deserialization for the full BIND9 9.18/9.20 JSON shapes and expose typed counters.

### M-06: RndcCommand enum does not cover all PRD-command shapes

**Files:** `PRD.md:324-359`, `crates/bind9-sdk-net/src/rndc/command.rs:31-98`

The enum says it covers all rndc commands available in BIND9 9.20, but compared with the PRD it is missing named variants such as `Loadkeys`, `DnssecRollover`, `Stop`, `Halt`, `Querylog`, `Recursing`, and `SecRoots`. Many variants use raw `String` instead of `DomainName` or option structs.

**Impact:** The API is less type-safe than the product requirement and depends on `Raw(String)` for some advertised commands.

**Recommendation:** Either narrow the claim or add the missing typed variants and option structs.

### M-07: RndcPool is a concurrency limiter, not a connection pool

**File:** `crates/bind9-sdk-net/src/pool.rs:5-99`

The implementation is explicit that rndc connections are not persistent and that the pool limits concurrent connect/auth/command/close cycles. This is a useful limiter, but it does not match the "connection reuse" and "connection pooling" claims in `README.md:35` and PRD acceptance language.

**Impact:** Users expecting idle connection reuse, recycling, or amortized auth will not get it.

**Recommendation:** Rename it to a limiter, or implement persistent connection pooling with health checks, idle expiry, and transparent reconnect.

### M-08: Re-export crate is not actually no-std-capable and lacks `forbid(unsafe_code)`

**Files:** `bind9-sdk/Cargo.toml:17-27`, `bind9-sdk/src/lib.rs:1-50`, `PRD.md:711-715`

The re-export crate always depends on `bind9-sdk-core` with `features = ["std"]`, even when `default-features = false`. The crate also lacks `#![no_std]` gating and `#![forbid(unsafe_code)]`, despite PRD SR-004 requiring `forbid(unsafe_code)` in the re-export crate.

**Impact:** The top-level crate's "disable network features and use only no_std core" guidance (`README.md:163-168`) does not appear true for the re-export crate.

**Recommendation:** Gate `std` appropriately, add crate-level `forbid(unsafe_code)`, and add CI for `cargo check -p bind9-sdk --no-default-features --target wasm32-unknown-unknown`.

### M-09: CLI JSON mode can emit multiple independent JSON documents

**Files:** `crates/bind9-sdk-cli/src/output.rs:29-50`, `crates/bind9-sdk-cli/src/commands/zone.rs:184-202`

`print_message()` emits a standalone JSON object for every message. Commands such as `zone export` call it for every record and for the completion line. That produces a stream of separate JSON objects, not one valid JSON document.

**Impact:** `--json` output is not reliably machine-consumable.

**Recommendation:** For each command, build a structured response and call `print_output()` once. If streaming JSON is desired, document and implement JSON Lines explicitly.

### M-10: CI exists, but hardening coverage is below PRD Phase 6 goals

**Files:** `.github/workflows/ci.yml:25-131`, `docs/plans/2026-03-19-ngi-grant-milestones.md:94-99`

CI runs fmt, clippy, tests, docs, core WASM check, bindings check, dependency review, RustSec audit, and REUSE lint. That is a good baseline. Gaps remain relative to hardening and compliance claims:

- no checked-in `deny.toml`;
- no SBOM generation;
- no cargo-fuzz targets found;
- no live BIND9 integration job in CI;
- no JS/TypeScript consumer matrix for Node 20/22/Bun;
- no npm pack/install smoke in CI.

**Impact:** The current automation does not prove the release claims around compliance, fuzzing, full BIND9 compatibility, or JS package usability.

**Recommendation:** Add `cargo deny`, SBOM generation, fuzz targets, live BIND9 integration gates, and JS package install/type smoke tests before release.

### M-11: Binding smoke coverage is too shallow

**File:** `crates/bind9-sdk-bindings/tests/smoke.mjs:1-17`

The only JS smoke test constructs a domain and parses a minimal A-record zone. It does not cover update builder, TSIG key handling, record variants, rndc, stats, transfer, generated TypeScript definitions, or WASM import behavior.

**Impact:** Binding regressions in most advertised features can pass unnoticed.

**Recommendation:** Add native and WASM binding tests for each exported module and run them in CI across supported runtimes.

## Low Findings

### L-01: Documentation and implementation drift is significant

Examples:

- `README.md:18-36` claims full protocol breadth and 576 tests.
- `PRD.md:22` claims 574 tests.
- `tests/README.md:70-76` lists only `example.com`, while the BIND fixture tree contains additional zones/plans.
- `docs/plans` checklist state is mostly unchecked even for implemented work.

**Recommendation:** Add a short `STATUS.md` or update README/PRD with a conservative, source-backed feature matrix.

### L-02: Existing untracked plan files look like important project context

At audit start, `git status --short` showed four untracked `docs/plans/2026-03-19-*.md` files. They include compliance, DNS infrastructure security, and grant milestone context. They should be intentionally committed or moved out of the repository.

**Recommendation:** Decide whether these are project docs or local notes. If project docs, commit them after review.

### L-03: `.DS_Store` exists under `.github`

`find .github -maxdepth 3 -type f` shows `.github/.DS_Store`. It is ignored by `.gitignore`, but it is still local workspace noise.

**Recommendation:** Remove local ignored metadata when preparing release artifacts.

### L-04: README install examples imply crates.io/npm publication before package metadata is ready

`README.md:200-207` shows `bind9-sdk = "0.1"` "Once published", while npm metadata is still private and version `0.0.0`.

**Recommendation:** Keep install docs clearly marked as future until release packaging is complete.

### L-05: Some prior compliance findings are resolved but remain in old reports

`docs/plans/2026-03-19-compliance-audit-findings.md` still lists TLS 1.2 support as a high finding, but current TLS code/dependency posture appears changed from that older audit. It also lists SOA GDPR docs as missing, but current `RecordData::Soa.rname` has a GDPR note (`crates/bind9-sdk-core/src/rdata/mod.rs:40-46`).

**Recommendation:** Mark old audit findings as resolved/stale where appropriate, or supersede them with this report.

### L-06: README "connection pooling" wording is misleading

`README.md:35` says connection pooling. Current `RndcPool` is a semaphore concurrency limiter. This is not necessarily bad, but the wording should be precise.

**Recommendation:** Rename the feature description to "concurrency limiter" unless real persistent pooling is added.

### L-07: `git status` reports fsmonitor errors

`git status --short` prints `error: fsmonitor_ipc__send_query: unspecified error on '.git/fsmonitor--daemon.ipc'`.

**Recommendation:** This is local tooling state, not a code issue. Consider restarting or disabling Git fsmonitor locally before release work to avoid noisy status output.

## Notable Strengths

- Core, net, CLI, bindings, tests, and docs are split into coherent workspace crates.
- `bind9-sdk-core` has `#![no_std]` and `#![forbid(unsafe_code)]`.
- TSIG key material handling has several good protections: zeroization, redacted `Debug`/`Display`, and HMAC verification primitives.
- rndc uses a typestate-like unauthenticated/authenticated connection flow.
- There is a real BIND9 fixture directory and integration-test documentation.
- CI is present and covers a useful baseline: fmt, clippy, tests, docs, WASM core, bindings check, dependency review, RustSec audit, and REUSE lint.
- The PRD and plan files preserve a lot of design intent, which makes remaining work easier to prioritize.

## Suggested Remediation Order

1. Fix transfer TSIG response verification and response metadata validation, or disable signed transfers until fixed.
2. Decide whether IXFR is in scope for the next release. If not, remove public IXFR claims and gate the API.
3. Make zone text serialization non-lossy: implement missing record text support or return errors for unsupported variants.
4. Enforce localhost/TLS policy for rndc and stats.
5. Harden rndc HMAC input failure and constant-time comparison.
6. Make update encoding fallible or validate all length/count constraints before construction.
7. Replace CLI stubs with real operations or fail clearly.
8. Clarify package targets: Rust-only first, native Node first, or native plus WASM. Then make metadata, exports, type checks, and CI match that choice.
9. Add Phase 6 quality gates: cargo-deny, SBOM, fuzz targets, live BIND9 integration CI, JS/WASM smoke matrix.
10. Refresh README/PRD/docs into a current feature matrix so users know what is complete, partial, planned, or unsafe for production.

## Production Readiness Matrix

| Area | Current readiness | Notes |
| --- | --- | --- |
| Core DNS types | Medium | Broad enum coverage, but text parse/serialize has data-loss gaps and TXT byte model issues. |
| Zone parser/serializer | Low-Medium | Works for basic zones; not ready for arbitrary BIND master files. |
| RFC 2136 update builder | Medium | Useful typestate API, but encoder needs fallible validation. |
| TSIG core | Medium | Good foundation; parser/verifier should tighten boundary and semantic checks. |
| rndc client | Low-Medium | Auth flow exists, but plaintext remote policy and HMAC hardening gaps remain. |
| Stats client | Low | Basic subset parser; remote HTTP policy weak. |
| AXFR | Low | Streaming exists, but TSIG response verification and metadata validation are missing. |
| IXFR | Low | Query path exists; incremental semantics are not implemented. |
| CLI | Low | Some commands work, but important commands are stubs or misleading. |
| Node bindings | Low | Native-only local shape exists, but package release matrix is not ready. |
| Browser/WASM package | Low | PRD claims are not met by current cfg/package setup. |
| CI/release | Medium | Good baseline; missing live integration, deny/SBOM/fuzz, and npm/WASM release gates. |
| Compliance posture | Low | Several security controls exist, but remote transport, transfer integrity, fuzzing, SBOM, and docs need work before credible claims. |

## Final Assessment

The codebase has strong momentum and a good architecture for a BIND9 SDK, but the current state should be treated as pre-production. The most important correction is not just adding more features; it is aligning public claims with what is actually verified. Once transfer TSIG verification, non-lossy zone serialization, remote transport policy, update validation, and release/package gates are fixed, the project can move from "promising prototype" toward a credible v0.1.0.
