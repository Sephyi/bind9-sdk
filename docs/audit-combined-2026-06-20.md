<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
-->

# Combined Production-Readiness Audit

**Date:** 2026-06-20  
**Baseline:** `a156099` on `development`  
**Inputs:** fresh Codex source review, `docs/audit-codex.md`, and
`.local/audit-claude-2026-06-20.md`

## Executive Summary

The Rust SDK has a strong implemented core and the earlier critical audit
findings around transfer TSIG verification, IXFR semantics, remote plaintext
defaults, typed statistics, serialization loss, and connection pooling are
closed. The audited baseline was green at 664 tests. The current remediation
worktree is green at 689 deterministic tests and all 28 live BIND 9.20 tests.

The project is not yet v1.0 production-ready. Phase 6 release gates are absent,
Phase 7 requirements are unimplemented, several security/operational
requirements exist only in the PRD, and live BIND tests do not gate CI. The
current state is suitable for controlled staging and continued development.

## Findings

### High

| ID | Finding | Status |
| --- | --- | --- |
| CX-01 | AXFR accepted a closing SOA with a different serial from the opening SOA. | Fixed in current worktree; regression test added. |
| CX-02 | Transfer query ID generation and rndc nonce generation could panic on OS entropy failure. Signed transfers and updates could substitute timestamp `0` after a clock failure. | Fixed in current worktree; construction now fails closed. |
| CX-03 | DNS UPDATE response parsing accepted query packets, wrong opcodes, and non-zero reserved bits. A signed `UpdateMessage` could be sent without supplying the response-verification key. | Fixed in current worktree; regression tests added. |
| CX-04 | The ignored live-BIND tests never run in GitHub CI. Protocol compatibility can regress while all required checks remain green. | Fixed in current worktree; a Docker-backed BIND 9.20 job runs all 28 live tests and always tears down the fixture. |
| CX-05 | FR-061 fuzzing is absent. There is no `fuzz/` workspace and no zone, rndc, or stats fuzz target. The required 24-hour clean run has not occurred. | Open. |
| CX-06 | `FrozenZone` is a data marker, not the PRD-required RAII guard. Dropping it does not issue `thaw`, and `NamedControl` has no thaw operation. | Fixed in current worktree with `NamedControl::thaw` and net-level `FrozenZoneGuard`; explicit thaw reports errors and drop schedules best-effort cleanup. |
| CX-07 | High-level rndc clients and `RndcPool` enforce loopback-only plaintext but expose no explicit protected-network mode. They cannot manage a WireGuard-addressed hidden primary without dropping to low-level `connect_insecure`. | Fixed in current worktree; protected-network access requires an explicit policy or CLI/config opt-in. |
| CX-08 | AXFR/IXFR stop when completion is detected but do not reject additional answer records in that same DNS message. Malformed trailing data can be silently ignored. | Fixed in current worktree; both transfer modes reject trailing answers. |

### Medium

| ID | Finding | Status |
| --- | --- | --- |
| CX-09 | The RFC 1982 half-space comparison is undefined. IXFR previously treated it as an ordinary ordering result. | Fixed in current worktree; regression test added. |
| CX-10 | `UpdateBuilder::new` silently used ID zero when entropy was unavailable or in `no_std`. | Fixed in current worktree; it is fallible and `no_std` requires `with_id`. |
| CX-11 | DNS wire-name transfer parsing requires UTF-8 labels. Valid DNS labels containing arbitrary octets cannot be transferred even though the core master-file model supports decimal escapes. | Fixed in current worktree; arbitrary label octets are represented losslessly with master-file escapes. |
| CX-12 | Production panic sites remain in CLI runtime/output/fallback paths and invariant-based core helpers (`Label`, `Zone::serial`, HMAC constructor expectations). | Fixed in current worktree. Production-target clippy with panic, unwrap, expect, and unreachable lints is clean. |
| CX-13 | FR-060 `named.conf` parsing is absent. The PRD already defines a bounded subset, so OQ-003 should be resolved to that explicit scope rather than blocking implementation. | Fixed in current worktree; typed bounded parser is no-std compatible and accepts the live BIND fixture. |
| CX-14 | FR-070 multi-view management, FR-071 rollover workflows, and FR-072 Prometheus output are not implemented. Existing view support is limited to typed command targets and stats selection. | Open. |
| CX-15 | Required operational security helpers are absent: configurable `SecurityWarning` policy, RRSIG-expiry monitoring, weak-algorithm warnings beyond tracing, and optional post-update SOA verification. | Open. |
| CX-16 | `ClientConfig::tls` is documented and stored but unused by `Bind9Client`; stale warnings and transfer docs still say TLS is unimplemented despite working XoT through `TransferClient::connect_tls`. | Open. |
| CX-17 | No `deny.toml`, SBOM generation, release workflow, release profile, or stable/MSRV CI matrix exists. | Open. |
| CX-18 | `SECURITY.md` promises acknowledgment within seven days, while REQ-SC-2 requires 72 hours. The 14-day advisory-remediation SLA is not documented. | Fixed in current worktree; 72-hour acknowledgment, 14-day remediation/mitigation target, GitHub advisory, and RustSec pathway are documented. |
| CX-19 | CI does not enforce all-feature clippy, `missing_docs`, native package smoke tests, WASM runtime tests, browser tests, or the Node 20/22/Bun matrix required by the PRD. | Partially fixed; all-feature and production-panic clippy are mandatory. Documentation and npm/runtime matrix gaps remain. |

### Low / Documentation

| ID | Finding | Status |
| --- | --- | --- |
| CX-20 | PRD roadmap and historical sections still claim 574 tests, old `JsRndcPool` behavior, and completed Phase 4 runtime support that CI does not prove. | Open. |
| CX-21 | README transport text says XoT is planned although certificate-validated XoT is implemented. | Fixed in current worktree. |
| CX-22 | Two rndc response-format TODOs remain despite live BIND 9.20 evidence. | Fixed in current worktree; comments now describe the verified compatibility contract. |
| CX-23 | OQ-005 license selection remains a release-policy decision and cannot be resolved technically. | Owner decision required before publication. |

## Consolidated Delivery Order

1. Close remaining protocol and panic findings in Rust.
2. Add bounded typed `named.conf` parsing.
3. Add fuzz targets and regression corpus.
4. Make live BIND 9.20 tests mandatory in CI and expand RFC fixtures.
5. Add `cargo-deny`, SBOM, release profile/workflow, MSRV/docs gates, and security-policy alignment.
6. Implement views, DNSSEC rollover, Prometheus, warnings, serial verification, and a real freeze guard.
7. Reconcile PRD/README claims and then finalize npm/WASM packaging.

## Current Readiness

| Area | Rating |
| --- | --- |
| Core zone/update/TSIG model | Production-ready with remaining fuzz evidence |
| rndc protocol and pooling | Production-ready with conditions |
| AXFR/IXFR/XoT | Production-ready with conditions |
| Statistics client | Production-ready with upstream schema limitations documented |
| CLI | Staging-ready |
| CI and release supply chain | Not production-ready |
| Full PRD v1.0 scope | Incomplete |
