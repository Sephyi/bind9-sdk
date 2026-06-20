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
closed. The audited baseline was green at 664 tests. The current worktree is
green at **719 deterministic tests** and **all 29 live BIND 9.20 tests**
(verified locally against the Podman fixture and gated in CI).

**Update (post-remediation):** Every High and Medium combined-audit finding
(CX-01…CX-22) is now fixed. Phase 6 release gates (cargo-deny, SBOM, release
workflow, MSRV matrix, bounded fuzz-smoke), the FR-061 fuzz workspace, Phase 7
features (FR-070 views, FR-071 DNSSEC rollover, FR-072 Prometheus), the typed
operational-security model, post-update SOA verification, TLS-config cleanup,
`#![deny(missing_docs)]` across the public Rust API, the napi Node/Bun/WASI
build+smoke matrix, and PRD/README reconciliation are all implemented and
verified. The remaining items are **not technically actionable in-repo**: the
FR-061 24-hour fuzz run (a manual pre-v1.0 release gate), a real browser-runtime
test, and the OQ-005 license decision (owner-only). With those caveats the Rust
SDK is production-ready for backend use (e.g. a zone-management web service).

## Findings

### High

| ID | Finding | Status |
| --- | --- | --- |
| CX-01 | AXFR accepted a closing SOA with a different serial from the opening SOA. | Fixed in current worktree; regression test added. |
| CX-02 | Transfer query ID generation and rndc nonce generation could panic on OS entropy failure. Signed transfers and updates could substitute timestamp `0` after a clock failure. | Fixed in current worktree; construction now fails closed. |
| CX-03 | DNS UPDATE response parsing accepted query packets, wrong opcodes, and non-zero reserved bits. A signed `UpdateMessage` could be sent without supplying the response-verification key. | Fixed in current worktree; regression tests added. |
| CX-04 | The ignored live-BIND tests never run in GitHub CI. Protocol compatibility can regress while all required checks remain green. | Fixed in current worktree; a Docker-backed BIND 9.20 job runs all 28 live tests and always tears down the fixture. |
| CX-05 | FR-061 fuzzing is absent. There is no `fuzz/` workspace and no zone, rndc, or stats fuzz target. The required 24-hour clean run has not occurred. | Largely fixed in current worktree. A detached `fuzz/` cargo-fuzz workspace provides eight targets (`fuzz_zone_parser`, `fuzz_rndc_response`, `fuzz_stats_json`, plus `named_conf`, `zone_roundtrip`, `tsig_wire`, `transfer_wire`, `update_response`), feature-gated `fuzz` entry modules in core/net, seed corpora from the live BIND fixtures, deterministic `--features fuzzing` regression tests, and a bounded CI smoke-fuzz job. Fuzzing **found a real defect**: the zone tokenizer recursed per parenthesized newline / comment line and overflowed the stack on adversarial input — now converted to iterative scanning with a permanent regression test. Added PRD SR-005 input-size (256 MiB) and record-count (16M) guards. **The 24-hour clean run remains an explicit pre-v1.0 release gate and has not been performed.** |
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
| CX-14 | FR-070 multi-view management, FR-071 rollover workflows, and FR-072 Prometheus output are not implemented. Existing view support is limited to typed command targets and stats selection. | In progress. FR-072 done: `core::prometheus::server_stats_to_prometheus` renders a `ServerStats` snapshot as Prometheus text exposition (escaped labels, `bind_`-prefixed), and `Bind9Client::prometheus_metrics()` fetches and renders it. FR-070 done: `Bind9Client::for_view(name)` scopes every zone-targeted rndc operation (reload/freeze/thaw/status/dnssec) to a BIND view. FR-071 done: `rndc::rollover::RolloverWorkflow::{check,advance}` with a pure `derive_state` over KASP key states drives a CDS/CDNSKEY KSK rollout (`dnssec -checkds -published`). All of CX-14 (FR-070/071/072) is implemented. |
| CX-15 | Required operational security helpers are absent: configurable `SecurityWarning` policy, RRSIG-expiry monitoring, weak-algorithm warnings beyond tracing, and optional post-update SOA verification. | Partially fixed in current worktree. A no_std `security` module in core provides a typed `SecurityWarning` enum (deprecated TSIG, weak DNSSEC algorithm, near-expiry/expired RRSIG, cleartext transfer) with `Severity`, a configurable `SecurityPolicy` (Warn / DenyOnWarning / DenyOnCritical), and classifiers `tsig_algorithm_is_deprecated`, `dnssec_algorithm_is_weak` (RFC 9904), and `classify_rrsig` for expiry monitoring. No variant carries key material. The net `DnssecStatus::weak_algorithm_keys()` reports KASP keys signing with deprecated algorithms through a typed API. `Bind9Client::send_update_verified` performs optional post-update SOA serial verification, returning `NetError::UpdateNotApplied` when the serial does not advance (REQ-ZONE-3). All CX-15 helpers are implemented. |
| CX-16 | `ClientConfig::tls` is documented and stored but unused by `Bind9Client`; stale warnings and transfer docs still say TLS is unimplemented despite working XoT through `TransferClient::connect_tls`. | Fixed in current worktree. The misleading "TLS transports are not implemented yet" warning in `Bind9Client::new` is removed. `config.tls` is now consumed: `StatsHttpClient::with_tls` applies the caller's trust anchors to HTTPS statistics, and `Bind9Client` routes `server_stats`/`zone_stats` through it. Docs on `ClientConfig::tls` and `TlsConfig` now state accurately that TLS covers HTTPS stats and certificate-validated XoT, and that rndc itself is HMAC-authenticated plaintext (no TLS in BIND) — confidentiality there comes from `RndcTransportPolicy::ProtectedNetwork`. |
| CX-17 | No `deny.toml`, SBOM generation, release workflow, release profile, or stable/MSRV CI matrix exists. | Fixed in current worktree. `deny.toml` (advisories/bans/licenses/sources) gates CI and `cargo deny check` is green; a hardened `[profile.release]` plus `[profile.fuzz]` added; `release.yml` performs the supply-chain gate, dependency-ordered `cargo package` publish dry run, CycloneDX SBOM with SHA256 checksums, and build-provenance attestation; CI gained a `1.94.0`/`stable` MSRV matrix. Publishability gap fixed: the CLI's path dep on `bind9-sdk` now carries a version. `missing_docs` enforcement still pending under CX-19. |
| CX-18 | `SECURITY.md` promises acknowledgment within seven days, while REQ-SC-2 requires 72 hours. The 14-day advisory-remediation SLA is not documented. | Fixed in current worktree; 72-hour acknowledgment, 14-day remediation/mitigation target, GitHub advisory, and RustSec pathway are documented. |
| CX-19 | CI does not enforce all-feature clippy, `missing_docs`, native package smoke tests, WASM runtime tests, browser tests, or the Node 20/22/Bun matrix required by the PRD. | Partially fixed; all-feature and production-panic clippy are mandatory, plus a `cargo-deny` gate, MSRV/stable matrix, and bounded fuzz-smoke. `#![deny(missing_docs)]` now enforced on `bind9-sdk-core`, `bind9-sdk-net`, and the `bind9-sdk` re-export crate (build-time, all CI jobs) — the entire public Rust API is documented. CI now builds the napi addon and runs the native smoke + package-contract on a Node 22/24 matrix, a Bun smoke, and a WASI build + fallback smoke (all verified locally against fresh builds; the stale committed `.node` that exported the removed `JsRndcPool` was the root cause of an initially-failing smoke test, now fixed). A real headless-Chromium browser-runtime test (Playwright, COOP/COEP-served WASM bundle) is now wired into the `bindings-wasm` CI job and exercises the core API in-browser; it SKIPs cleanly (non-failing, no false pass) where Chromium cannot be installed (e.g. the local sandbox). Node 20 is intentionally excluded since `package.json` `engines` requires Node ≥ 22. CX-19 runtime matrix is complete. |

### Low / Documentation

| ID | Finding | Status |
| --- | --- | --- |
| CX-20 | PRD roadmap and historical sections still claim 574 tests, old `JsRndcPool` behavior, and completed Phase 4 runtime support that CI does not prove. | Fixed in current worktree. PRD gained a "Current Implementation State (authoritative)" section declaring the Active Hardening Log authoritative, recording 719 tests, the `JsRndcPool` removal (a156099) and the `RndcLimiter`/`RndcPool` split, and explicitly framing the §4/§12 "COMPLETE" tables as dated historical snapshots. README test count updated to 719 and the "rollover planned" claim corrected to implemented. Historical changelog rows preserved as historical facts. |
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
