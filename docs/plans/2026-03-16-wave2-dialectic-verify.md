<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

# Dialectic Verify: Wave 2 Post-Merge (WT-3 + WT-4)

**Date**: 2026-03-16
**Mode**: code
**Target**: Post-merge development branch (commit `9cd904d`)
**Reviewers**: GLM5 (20 findings), Codex gpt-5.4 (9 findings), Gemini 2.5 Pro (8 findings, added post-initial synthesis)

## Scope Lock

Target: Post-merge WT-3 + WT-4 implementation on development branch

- `crates/bind9-sdk-net/src/rndc/protocol.rs` (ISC binary message encoding)
- `crates/bind9-sdk-net/src/rndc/command.rs` (RndcCommand enum, RndcResponse, parsers)
- `crates/bind9-sdk-net/src/rndc/mod.rs` (RndcConnection typestate, TCP framing)
- `crates/bind9-sdk-net/src/stats.rs` (StatsHttpClient, JSON deserialization, fetch methods)
- `crates/bind9-sdk-net/src/nsupdate.rs` (NsUpdateSender, DNS response parsing, UDP+TCP)
- `crates/bind9-sdk-net/src/config.rs` (NamedControl, StatsClient, DynamicUpdater trait impls)
- `crates/bind9-sdk-core/src/traits.rs` (constructor additions for `#[non_exhaustive]` structs)

Constraints: must maintain `no_std` core crate, `#[non_exhaustive]` on all public structs/enums, secret-bearing types redacted in Debug, rndc uses 4-byte BE framing NOT 2-byte DNS TCP, trait impls use associated error type `NetError`

Out of scope: performance optimizations, napi-rs bindings, zone parser, TSIG internals (already reviewed in Wave 1), pre-existing code in `error.rs`/`tls.rs` (unchanged)

## GLM5 Findings

| ID | Severity | Description | Location | Confidence |
| --- | --- | --- | --- | --- |
| S-001 | CRITICAL | Auth bypass risk: `_ctrl: "null"` check accepts any response without HMAC validation | `rndc/mod.rs:139-142` | high |
| S-002 | CRITICAL | Replay attack: no nonce/timestamp verification in auth | `rndc/mod.rs:105-122` | high |
| S-003 | CRITICAL | Stack overflow via recursive `decode_map()` with no depth limit | `rndc/protocol.rs:143-177` | high |
| S-004 | CRITICAL | Command injection via `RndcCommand::Raw` | `rndc/command.rs:47` | high |
| S-005 | WARN | Panic on key >255 bytes (`expect` instead of `Result`) | `rndc/protocol.rs:95` | high |
| S-006 | WARN | Allocation before size validation in `read_isc_message()` | `rndc/mod.rs:259-266` | high |
| S-007 | WARN | Missing TSIG in nsupdate (sends unsigned updates) | `nsupdate.rs:63-78` | med |
| S-008 | WARN | HTTP client TLS behavior undocumented | `stats.rs:88-92` | med |
| S-009 | WARN | Response parsing heuristic misparses "error" in zone names | `rndc/command.rs:156-169` | high |
| S-010 | WARN | `extract_field` returns None for empty values | `rndc/command.rs:209-219` | med |
| S-011 | WARN | Zone name not validated before command | `rndc/command.rs:56-95` | med |
| S-012 | WARN | Connection churn (fresh TCP per trait method call) | `config.rs:89-101` | high |
| S-013 | WARN | No EDNS0 support in nsupdate | `nsupdate.rs:83-84` | med |
| S-014 | INFO | Unused version constant | `rndc/protocol.rs:21` | low |
| S-015 | INFO | Type tags unverified | `rndc/protocol.rs:76-81` | med |
| S-016 | INFO | Duplicate `test_key` function | `config.rs:202,220` | high |
| S-017 | INFO | Inconsistent URL trailing slash handling | `stats.rs:107-111` | med |
| S-018 | INFO | No TCP write timeout | `nsupdate.rs:115-119` | med |
| S-019 | INFO | O(n) zone search | `stats.rs:145-162` | med |
| S-020 | INFO | No connection reuse in RndcConnection | `rndc/mod.rs:99-147` | low |

## Codex Findings

| ID | Severity | Description | Location | Confidence |
| --- | --- | --- | --- | --- |
| C-001 | CRITICAL | rndc wire protocol internally inconsistent and unverified; doc says `_data.type` but code sends top-level `type` | `protocol.rs`, `command.rs`, `mod.rs` (multiple) | high |
| C-002 | WARN | `reload_count` populated from `number of zones:` — semantically wrong | `command.rs:757,764`; `traits.rs` | high |
| C-003 | WARN | `ZoneStats.record_count` always 0 — hardcoded in `zone_stats_from_raw()` | `stats.rs:82`; `traits.rs` | high |
| C-004 | WARN | Stats URL contract contradictory (expects `/json/v1` base vs doc shows port-only) | `stats.rs`, `config.rs` | high |
| C-005 | WARN | `ClientConfig.timeout` not applied to rndc/stats; stats hardcodes 10s | `config.rs`, `stats.rs` | high |
| C-006 | WARN | `ClientConfig.tls` is dead config — no transport reads it | `config.rs` | high |
| C-007 | WARN | IPv4-only UDP bind (`0.0.0.0:0`) in nsupdate; IPv6 targets fail | `nsupdate.rs:111` | high |
| C-008 | WARN | Missing `#[non_exhaustive]` on `ClientConfig`, `RndcResponse`, `RndcResult` | `config.rs`, `command.rs` | high |
| C-009 | WARN | `from_text()` heuristic: `contains("error")` false-positives on zone names | `command.rs:191`; `config.rs` | high |

## Gemini Findings

Gemini 3 Pro failed (429 rate limit). Retried with Gemini 2.5 Pro reading actual project files (CLAUDE.md, PRD, plans, source).

| ID | Severity | Description | Location | Confidence |
| --- | --- | --- | --- | --- |
| G-001 | WARN | `RndcCommand` missing `#[non_exhaustive]` | `command.rs:21` | high |
| G-002 | INFO | rndc response extraction only handles strings, not nested maps | `rndc/mod.rs:188` | med |
| G-003 | WARN | `RndcResponse` and `RndcResult` missing `#[non_exhaustive]` | `command.rs:211` | high |
| G-004 | WARN | `from_text()` heuristic `contains("error")` causes false positives | `command.rs:232` | high |
| G-005 | CRITICAL | Auth handshake has no nonce/timestamp — replay attack (cites PRD SR-002) | `rndc/mod.rs:118` | high |
| G-006 | WARN | Auth failure discards server error message, returns generic `NetError::AuthFailed` | `rndc/mod.rs:151` | high |
| G-007 | WARN | `ServerStats` uses empty `String` defaults instead of `Option<String>` for missing JSON fields | `stats.rs:43` | high |
| G-008 | HIGH | TSIG response verification (TSIG-002) was scheduled for WT-4 in remediation plan but not implemented in `NsUpdateSender` | `nsupdate.rs:113` | high |

## Unified Findings (Deduplicated)

28 findings merged from GLM5 (20) + Codex (9), plus 8 from Gemini (added post-initial synthesis). Overlaps on response parsing heuristic (S-009/C-009/G-004), `#[non_exhaustive]` (C-008/G-001/G-003), replay attack (S-002/G-005).

## Decision Record

| F-ID | Decision | Reasoning |
| --- | --- | --- |
| F-001 (S-001) | **MODIFY → WARN** | Valid but explicitly documented with 5+ TODO markers. Pre-release skeleton, not production. |
| F-002 (S-002) | **MODIFY → WARN** | Same — nonce/timestamp gap explicitly called out in TODO (mod.rs:119-124). |
| F-003 (S-003) | **ACCEPT WARN** | Valid. `decode_map()` recurses without depth limit. Mitigated by localhost-only usage. Fix before v0.1.0. |
| F-004 (S-004) | **REJECT** | `Raw` is documented escape hatch. String goes into ISC message, not shell. No injection vector. |
| F-005 (C-001) | **MODIFY → WARN** | Doc inconsistency is real (`_data.type` vs `type`). But protocol is intentionally marked unverified. Accept doc bug, reject CRITICAL severity. |
| F-006 (S-005) | **ACCEPT** | `expect()` at protocol.rs:135 panics. Should return `Result`. |
| F-007 (S-006) | **REJECT** | **Factually wrong.** Size check (line 238) IS before allocation (line 245). |
| F-008 (C-002) | **ACCEPT** | `reload_count` populated from `number of zones:`. Semantically wrong. |
| F-009 (C-003) | **ACCEPT** | `record_count` hardcoded to 0. BIND9 JSON doesn't expose this; document or make `Option<u32>`. |
| F-010 (C-004) | **ACCEPT** | Stats URL docs misaligned between `StatsHttpClient` and `ClientConfig`. |
| F-011 (C-005) | **ACCEPT** | Timeout applied to nsupdate only; rndc and stats ignore `ClientConfig.timeout`. |
| F-012 (C-006) | **ACCEPT** | `tls` field never read by any transport. Dead config. |
| F-013 (C-007) | **ACCEPT** | IPv4-only bind. Should detect IPv6 target. |
| F-014 (C-008) | **ACCEPT** | `ClientConfig`, `RndcResponse`, `RndcResult` missing `#[non_exhaustive]`. Project requires it. |
| F-015 (S-009/C-009) | **ACCEPT** | Both models flagged. `contains("error")` false-positives. Real bug. |
| F-016 (S-007) | **REJECT** | Transport layer. TSIG is caller's responsibility via `UpdateBuilder`. By design. |
| F-017 (S-008) | **MODIFY → INFO** | reqwest verifies system certs by default. Doc note helpful but not a bug. |
| F-018 (S-010) | **MODIFY → INFO** | Empty-value behavior is reasonable. Minor doc improvement. |
| F-019 (S-011) | **REJECT** | Validated at trait boundary (`&DomainName`). RndcCommand is lower-level. |
| F-020 (S-012) | **MODIFY → INFO** | Documented behavior matching rndc CLI. By design. |
| F-021 (S-013) | **REJECT** | 4096 is standard EDNS0 size. TCP fallback handles rest. |
| F-022 (S-015) | **ACCEPT INFO** | Tracked by existing TODO. |
| F-023 (S-016) | **REJECT** | **Factually wrong.** Single `test_key()` at config.rs:337, imported by submodules. |
| F-024 (S-017) | **ACCEPT INFO** | Minor defensive programming. |
| F-025 (S-018) | **ACCEPT INFO** | Valid but low risk for small DNS messages. |
| F-026 (S-019) | **ACCEPT INFO** | Acceptable for v0.1.0. |
| F-027 (S-020) | **REJECT** | By design. Doc suggests `RndcConnection` directly for reuse. |
| F-028 (S-014) | **REJECT** | **Factually wrong.** `ISC_MSG_VERSION` IS used in encode() and decode(). |
| F-029 (G-001) | **REJECT** | **Factually wrong.** `RndcCommand` at command.rs:32 DOES have `#[non_exhaustive]`. Gemini cited wrong line. |
| F-030 (G-002) | **ACCEPT INFO** | Valid. Response extraction only handles string fields. Nested map responses would be lost. |
| F-031 (G-003) | **ACCEPT** | Same as F-014. `RndcResponse`/`RndcResult` missing `#[non_exhaustive]`. Third model confirms. |
| F-032 (G-004) | **ACCEPT** | Same as F-015. `contains("error")` heuristic. All three models flagged — highest confidence. |
| F-033 (G-005) | **ACCEPT WARN** | Same as F-002. Replay attack via missing nonce. Gemini cites PRD SR-002 requirement. |
| F-034 (G-006) | **ACCEPT WARN** | **New.** Auth failure at mod.rs:156 returns `NetError::AuthFailed` discarding server error text. Reduces debuggability. |
| F-035 (G-007) | **ACCEPT WARN** | **New angle on F-009.** `ServerStats` uses `String` defaults for missing JSON fields instead of `Option<String>`. Conflates absent data with empty string. |
| F-036 (G-008) | **ACCEPT WARN** | **New, significant.** TSIG-002 (response verification) was explicitly scheduled for WT-4 in remediation plan but not implemented. PRD changelog incorrectly claims delivery. Must be addressed in WT-5 or PRD corrected. |

**Status**: RESOLVED — All accepted findings remediated in WT-5 + post-WT-5 hardening + audit-remediation commit

## Final Verdict

**PASS** — No accepted CRITICAL blockers.

- 15 accepted WARNs (none blocking merge individually; F-036 TSIG-002 gap is highest priority)
- 8 accepted INFOs
- 10 findings rejected (5 factually wrong, 5 by design)
- 3 models confirmed `contains("error")` heuristic (F-015/F-032) and `#[non_exhaustive]` gaps (F-014/F-031)

## Priority Items for WT-5 / Pre-Release

1. **F-036**: TSIG response verification (TSIG-002) — scheduled for WT-4 but not implemented. Must deliver in WT-5 and correct PRD changelog.
2. **F-003**: Add depth limit to `decode_map()` recursion (`const MAX_DEPTH: usize = 32`)
3. **F-006**: Return `Result` from `encode_map()` instead of panicking on key >255 bytes
4. **F-008**: Fix `reload_count` — either rename field or parse correct line
5. **F-013**: Detect IPv4/IPv6 for UDP bind address in nsupdate
6. **F-014**: Add `#[non_exhaustive]` to `ClientConfig`, `RndcResponse`, `RndcResult`
7. **F-015**: Replace `contains("error")` heuristic with structured response parsing (all 3 models flagged)
8. **F-034**: Include server error text in `NetError::AuthFailed` for debuggability
9. **F-035**: Consider `Option<String>` for `ServerStats` fields to distinguish absent from empty
10. **F-010/F-011/F-012**: Align timeout/TLS/URL contracts between `ClientConfig` and implementations
11. **F-009**: Document `record_count` as always 0 or change to `Option<u32>`
