<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Unified Audit Findings — bind9-sdk Phase 1b

**Date**: 2026-03-16
**Status**: ACTIVE — immediate fixes applied, Phase 2 items tracked
**Codebase**: `development` branch, post-Wave-2 + hardening (417 tests)
**Sources**:

- Dialectic verify (GLM5 + Codex gpt-5.4 + Gemini 2.5 Pro) — `2026-03-16-wave2-dialectic-verify.md`
- Review remediation plan — `2026-03-16-wave2-review-remediation.md`
- WT-5 hardening plan — `2026-03-16-wt5-hardening-remediation.md`
- Post-WT-5 hardening plan — `2026-03-16-post-wt5-hardening-e2e.md`
- External audit: Gemini 2.5 Pro (manual run, 2026-03-16)
- External audit: GPT 5.4 (manual run, 2026-03-16)

## Finding Status Summary

| Status | Count |
| --- | --- |
| FIXED | 30 |
| PHASE-2 | 12 |
| REJECTED | 14 |
| DEFERRED | 3 |

## Immediate Fixes Applied (This Commit)

These 4 findings were validated from the Gemini 2.5 Pro / GPT 5.4 external audits and applied directly:

| ID | Fix | File | Description |
| --- | --- | --- | --- |
| EXT-001 | `#![forbid(unsafe_code)]` | `bind9-sdk-net/src/lib.rs` | Missing safety guardrail in net crate (core had it) |
| EXT-002 | `rdata_type_string()` | `bind9-sdk-core/src/zone/serializer.rs` | `Unknown` variant emitted bare `"TYPE"` instead of RFC 3597 `"TYPE{n}"` |
| EXT-003 | `Result` return | `bind9-sdk-core/src/update.rs:155` | `assert!` panic in `require_rrset_exists_with_data` → `Result<Self, CoreError>` |
| EXT-004 | `#[non_exhaustive]` | `record.rs`, `update.rs` | Missing on `RecordClass`, `Prerequisite`, `UpdateEntry` |

## Previously Fixed (WT-5 + Post-WT-5 Hardening)

All findings from the dialectic verify and review remediation that were resolved in prior commits:

| Original ID | Description | Fixed In |
| --- | --- | --- |
| F-003 (S-003) | `decode_map()` recursion depth limit | WT-5 (`637913f`) |
| F-006 (S-005) | `encode_map()` returns `Result` instead of panicking | WT-5 |
| F-008 (C-002) | `reload_count` parsed from correct field | WT-5 |
| F-009 (C-003) | `record_count` → `Option<u32>` | WT-5 |
| F-010 (C-004) | Stats URL contract alignment | WT-5 |
| F-011 (C-005) | Timeout passed through to stats/rndc | Post-WT-5 (`5b9001b`) |
| F-013 (C-007) | IPv4/IPv6-aware UDP bind in nsupdate | WT-5 |
| F-014 (C-008) | `#[non_exhaustive]` on `ClientConfig`, `RndcResponse`, `RndcResult` | WT-5 |
| F-015 (S-009/C-009/G-004) | Replace `contains("error")` heuristic | WT-5 |
| F-034 (G-006) | Auth error includes server message text | WT-5 |
| F-035 (G-007) | `ServerStats` fields → `Option<String>` | WT-5 |
| F-036 (G-008) | TSIG response verification in nsupdate | WT-5 |
| SEC-001 | Zeroize TsigRecord mac/wire_bytes | WT-5 |
| SEC-002 | TsigRecord Debug redaction | WT-5 |
| SEC-003 | Short TSIG key warning | WT-5 |
| RFC2136-001 | RrsetExistsWithData prerequisite | WT-5 |
| TSIG-002 | TSIG response MAC verification | WT-5 |
| TSIG-004 | Fudge window validation | WT-5 |
| TSIG-005 | `request_mac` for multi-message TSIG | WT-5 |
| TEST-002 | TSIG wire parsing (`parse_from_wire`) | WT-5 |
| TEST-003 | Exhaustive algorithm tests (SHA256/SHA512/SHA1) | WT-5 |
| TEST-004 | Update wire roundtrip + section count tests | WT-5 |
| F-006 (post) | Zeroize `request_mac` in `UpdateMessage` | Post-WT-5 |
| F-007/F-008 (post) | TsigRecord error/other_data parsing | Post-WT-5 |
| F-009 (post) | Reject empty `RrsetExistsWithData` | Post-WT-5 |
| F-012/F-020 (post) | TSIG error RCODE check + response ID matching | Post-WT-5 |
| F-019 (post) | TTL=0 validation in `parse_from_wire` | Post-WT-5 |

## Phase 2 Items (Tracked)

These are real findings that are correctly scoped to Phase 2 or pre-release hardening:

| ID | Severity | Description | Phase |
| --- | --- | --- | --- |
| F-001 (S-001) | WARN | rndc inbound response HMAC verification not performed | Phase 2 (rndc auth hardening) |
| F-002 (S-002/G-005) | WARN | rndc auth has no nonce/timestamp — replay attack vector | Phase 2 (rndc auth hardening) |
| F-005 (C-001) | WARN | rndc wire protocol doc inconsistency (`_data.type` vs `type`) | Phase 2 (doc alignment) |
| F-012 (C-006) | INFO | `ClientConfig.tls` field is dead config (no transport reads it) | Phase 2 (XoT) |
| F-030 (G-002) | INFO | rndc response extraction only handles strings, not nested maps | Phase 2 (rndc enhancements) |
| GPT-SPLIT | INFO | Large files (tsig.rs 1518L, update.rs 1336L, parser.rs 1189L) should be split | Phase 2 (code organization) |
| GPT-SNAP | INFO | No snapshot tests (insta) despite spec mentioning them | Phase 2 (test infra) |


| GPT-PROP | INFO | No proptest usage despite spec mentioning it | Phase 2 (test infra) |
| GPT-RNDC-AUTH | WARN | rndc response not authenticated (same as F-001) | Phase 2 |
| GPT-ERR-TYPED | INFO | `NetError` missing typed variants for `TsigRejected`, `PrerequisiteFailed` | Phase 2 (error refinement) |
| GPT-ZONE-COL | INFO | `ZoneParse` error has `line: u32` but no column | Phase 2 (diagnostics) |
| GPT-DNSSEC | INFO | DNSSEC RR types use generic serialization, not type-specific | Phase 2+ (DNSSEC) |

## Rejected Findings

These were assessed against the codebase and determined to be incorrect, by-design, or not applicable:

| Original ID | Source | Reason for Rejection |
| --- | --- | --- |
| F-004 (S-004) | GLM5 | `RndcCommand::Raw` is documented escape hatch, not shell injection |
| F-007 (S-006) | GLM5 | **Factually wrong** — size check IS before allocation |
| F-016 (S-007) | GLM5 | TSIG signing is caller's responsibility via `UpdateBuilder`, not transport layer |
| F-019 (S-011) | GLM5 | Zone name validated at trait boundary (`&DomainName`), not at lower level |
| F-021 (S-013) | GLM5 | 4096 is standard EDNS0 size; TCP fallback handles rest |
| F-023 (S-016) | GLM5 | **Factually wrong** — single `test_key()` function, not duplicate |
| F-027 (S-020) | GLM5 | Connection reuse is by-design; `RndcConnection` available for direct use |
| F-028 (S-014) | GLM5 | **Factually wrong** — `ISC_MSG_VERSION` IS used in encode/decode |
| F-029 (G-001) | Gemini | **Factually wrong** — `RndcCommand` DOES have `#[non_exhaustive]` at line 32 |
| GPT-BUILD-UNSIGN | GPT 5.4 | `build_unsigned()` typestate is by-design, not a weakness |
| GPT-SR-IDS | GPT 5.4 | GPT used `SR-*` IDs that don't exist in PRD (PRD uses `REQ-*`) |
| GPT-FR005 | GPT 5.4 | `RndcCommand` coverage is adequate for Phase 1 with `Raw` escape hatch |
| GPT-SCORE | GPT 5.4 | 6/10 score too harsh given Phase 1 quality; 7/10 more appropriate |
| GPT-TLS12 | GPT 5.4 | TLS 1.2 enabled in rustls config but TLS is Phase 2 (XoT) — not a current issue |

## Downgraded Findings

| Original ID | Original Severity | Downgraded To | Reason |
| --- | --- | --- | --- |
| F-017 (S-008) | WARN | INFO | reqwest verifies system certs by default |
| F-018 (S-010) | WARN | INFO | Empty-value behavior is reasonable |
| F-020 (S-012) | WARN | INFO | Connection-per-call documented, matches rndc CLI |
| F-022 (S-015) | INFO | INFO (accepted) | Type tags unverified, tracked by existing TODO |
| F-024 (S-017) | INFO | INFO (accepted) | Trailing slash handling — minor defensive fix |
| F-025 (S-018) | INFO | INFO (accepted) | No TCP write timeout — low risk for DNS messages |
| F-026 (S-019) | INFO | INFO (accepted) | O(n) zone search — acceptable for v0.1.0 |

## Deferred

| ID | Severity | Item | Rationale |
| --- | --- | --- | --- |
| RFC2136-002 | LOW | Retry ID documentation | Documentation-only; add when retry API exists |
| TEST-005 | LOW | TLS integration test | Requires live BIND9 with DoT; deferred to integration test phase |
| TEST-001 | HIGH | RFC 8945 known-answer vectors from real BIND9 | Requires captured exchange; deferred to e2e test phase |

## Historical Audit Documents

These documents remain in `docs/plans/` as historical records:

| Document | Status | Notes |
| --- | --- | --- |
| `2026-03-16-wave2-dialectic-verify.md` | RESOLVED | F-001 through F-036, all accepted items remediated |
| `2026-03-16-wave2-review-remediation.md` | COMPLETE | SEC/TSIG/RFC2136/TEST items, all delivered |
| `2026-03-16-wt5-hardening-remediation.md` | COMPLETE | Merged at `637913f` |
| `2026-03-16-post-wt5-hardening-e2e.md` | COMPLETE | Merged at `5b9001b` |

## Follow-up Remediation Branch

Additional Phase 2 remediation was implemented on branch `audit/remediation` after this document was created. These changes are intentionally recorded here as a follow-up rather than rewriting the original snapshot above.

### Branch Status

- **Branch**: `audit/remediation`
- **Base**: `development` at `7481bd6`
- **State**: unmerged, ready for review
- **Verification**: `cargo test --workspace` passed after both commits

### Commits

| Commit | Message | Findings Impact |
| --- | --- | --- |
| `bad8d3a` | `fix(net): verify rndc response auth and nested payloads` | Closes `F-001` / `GPT-RNDC-AUTH`, closes `F-030`, and materially closes the client-side replay gap tracked as `F-002` / `F-033` by validating signed reply `_ser`, `_tim`, `_exp`, `_rpl`, and `_nonce` fields. |
| `87d64ad` | `fix(net): classify update failures and flag dead TLS config` | Closes `GPT-ERR-TYPED`; partially mitigates `F-012` by emitting an explicit warning when `ClientConfig.tls` is set but no transport consumes it yet. |

### What Changed

#### `bad8d3a` — rndc auth hardening

- Verifies server `_auth.hsha` on rndc handshake and command replies before trusting `_data`.
- Validates replay-relevant `_ctrl` fields on signed replies: `_ser`, `_tim`, `_exp`, `_rpl`, and `_nonce`.
- Requires a nonce-bearing authenticated handshake response before transitioning to `Authenticated`.
- Verifies expected `_data.type` on replies to avoid accepting mismatched signed responses.
- Improves response extraction so nested `_data` maps are rendered into usable text instead of being silently dropped.

#### `87d64ad` — typed update failures + TLS dead-config surfacing

- Adds typed `NetError::PrerequisiteFailed` for RFC 2136 prerequisite rcodes (`NXDOMAIN`, `YXDOMAIN`, `NXRRSET`, `YXRRSET`).
- Adds typed `NetError::TsigRejected` for TSIG-authenticated update failures (`BADSIG`, `BADKEY`, `BADTIME`, `BADTRUNC`).
- Classifies update results at the `Bind9Client` boundary instead of returning only generic string errors.
- Emits a runtime warning when `ClientConfig.tls` is configured even though Phase 1 transports still do not consume it.

### Remaining Open Items After `audit/remediation`

These findings still remain open after the branch work above:

| ID | Status After Branch | Note |
| --- | --- | --- |
| `F-012` | PARTIAL | Warning added; full fix still requires actual TLS/XoT transport support or API reshaping. |
| `F-005` | OPEN | Documentation alignment item only; no protocol behavior change required. |
| `GPT-ZONE-COL` | OPEN | Would require public error-shape changes (`ZoneParse` currently exposes line but not column). |
| `GPT-DNSSEC` | OPEN | Phase 2+ type-specific DNSSEC serialization work, not a safe narrow patch for this branch. |
| `GPT-SPLIT` / `GPT-SNAP` / `GPT-PROP` | OPEN | Code organization and test-infra improvements, not correctness blockers for this remediation pass. |
