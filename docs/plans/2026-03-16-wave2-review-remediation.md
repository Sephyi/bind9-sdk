<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Wave 2: Review Remediation Plan

**Source**: Dialectic verification (Codex gpt-5.4 + GLM5) of Wave 1 TSIG/update/net code
**Date**: 2026-03-16
**Status**: PLANNED

Two CRITICAL findings (canonicalization + timestamp) were fixed immediately in `1dde207`.
This plan covers the remaining HIGH/MEDIUM/LOW items to fold into Wave 2 worktrees.

## Assignment to Wave 2 Worktrees

### WT-3 (rndc wire protocol) — no review items

No review findings affect rndc. WT-3 proceeds as originally planned.

### WT-4 (stats HTTP + nsupdate sender) — absorbs nsupdate-adjacent items

| ID | Severity | Item | Notes |
| --- | --- | --- | --- |
| TSIG-002 | HIGH | TSIG response verification | Needed by nsupdate sender to validate server RCODE+TSIG |
| TSIG-004 | MEDIUM | Fudge window validation | Part of response verification |
| TEST-001 | HIGH | RFC 8945 known-answer vectors | Capture a real BIND9 exchange as test fixture |
| TEST-002 | MEDIUM | TSIG wire parsing | Required for response verification |

### WT-5 (new — TSIG/update hardening)

Items that don't belong in WT-3 or WT-4 but should ship before Phase 2.

| ID | Severity | Item | Notes |
| --- | --- | --- | --- |
| SEC-001 | MEDIUM | Zeroize MAC/wire_bytes in TsigRecord | Wrap `mac` and `wire_bytes` in `Zeroizing<Vec<u8>>` |
| SEC-002 | LOW | TsigRecord Debug redacts MAC | Add explicit Debug impl, redact `mac` and `wire_bytes` |
| SEC-003 | LOW | Key length validation warning | Warn (tracing) when key < algorithm's recommended length |
| RFC2136-001 | MEDIUM | RRsetExistsWithData prerequisite | Add value-dependent prerequisite variant per RFC 2136 §2.4.3 |
| TSIG-005 | MEDIUM | request_mac for multi-message | Add `Option<&[u8]>` param to TsigRecord::new for AXFR/IXFR |
| TEST-003 | MEDIUM | Exhaustive algorithm tests | Ensure all TsigAlgorithm variants exercised |
| TEST-004 | MEDIUM | Update wire roundtrip tests | Verify section counts, prerequisite encoding, RDATA encoding |

### Deferred (not Wave 2)

| ID | Severity | Item | Rationale |
| --- | --- | --- | --- |
| RFC2136-002 | LOW | Retry ID documentation | Documentation-only; add when retry API exists |
| TEST-005 | LOW | TLS integration test | Requires live BIND9 with DoT; deferred to integration test phase |

## Execution Order

1. **WT-3** (rndc wire protocol) — independent, start immediately
2. **WT-4** (stats + nsupdate sender) — includes TSIG response verification
3. **WT-5** (hardening) — can run parallel with WT-3/WT-4, no deps
