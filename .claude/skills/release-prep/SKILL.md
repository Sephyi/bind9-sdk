<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

---
name: release-prep
description: Pre-publish readiness check for bind9-sdk — runs audit agents in parallel, cargo audit/deny, missing_docs, reuse lint, PRD blocker check, and outputs a go/no-go verdict
disable-model-invocation: true
allowed-tools: Bash, Agent, Read, Grep
---

Run the full bind9-sdk release readiness gate before crates.io publish. Run each Bash command as a separate call (not chained with `&&`) so all results are captured even if an earlier check fails.

## Phase 1 — Fast checks (Bash, sequential)

### 1. Security audit

```bash
cargo audit
```

Required result: 0 vulnerabilities. Any advisory is a blocker.

### 2. Dependency policy

```bash
cargo deny check
```

`licenses FAILED` for `AGPL-3.0-only OR LicenseRef-Commercial` is expected — OQ-005 is tracking this and it is not a blocker until the license question is resolved. Any other `deny` failure (banned crate, yanked version) IS a blocker.

### 3. Documentation coverage

```bash
RUSTDOCFLAGS="-D missing_docs" cargo doc --no-deps -p bind9-sdk-core 2>&1 | grep "^error" | wc -l
```

Target: 0 errors. Note: `bind9-sdk-net` and `bind9-sdk-bindings` are not required to be 100% at v0.1.0.

### 4. REUSE compliance

```bash
reuse lint 2>/dev/null || echo "REUSE_NOT_INSTALLED"
```

If `REUSE_NOT_INSTALLED`: skip with a note. Otherwise required: 0 violations.

### 5. Packaging smoke test

```bash
cargo publish --dry-run -p bind9-sdk-core 2>&1 | tail -5
```

This should succeed for `bind9-sdk-core` (no local deps). `bind9-sdk` dry-run will fail (deps not published) — skip it or note it as expected.

## Phase 2 — Agent audits (invoke all three in parallel via Agent tool)

Launch simultaneously:

- **`cargo-dep-auditor`** agent — outdated/yanked crate check
- **`rust-security-reviewer`** agent — TSIG/crypto key exposure, zeroization, rndc input validation, NIS2 logging compliance
- **`api-compat-reviewer`** agent — pub API surface, `#[non_exhaustive]` enums, Send+Sync bounds, re-export coverage, semver compatibility

Collect each agent's summary and note any CRITICAL or HIGH findings.

## Phase 3 — PRD blocker check

Read `PRD.md`. Find the Open Questions table. Report the status of these known publish blockers:

- **OQ-005**: AGPL-3.0-only OR LicenseRef-Commercial not in SPDX allow list — `cargo deny check licenses` fails
- **OQ-007**: rndc `_tim`/`_exp` tolerance — do we accept slightly stale timestamps from BIND9?

Also list any other OQs that are NOT marked RESOLVED.

## Output: go/no-go verdict

```
## Release Readiness Report — bind9-sdk v0.1.0

| Check | Result | Notes |
| --- | --- | --- |
| cargo audit | PASS/FAIL | N advisories |
| cargo deny | PASS/WARN | licenses FAILED expected (OQ-005); other: N/A |
| missing_docs (core) | PASS/FAIL | N errors |
| reuse lint | PASS/FAIL/SKIP | N violations |
| publish dry-run | PASS/FAIL | |
| Dep audit | PASS/FAIL | Critical findings: ... |
| Security review | PASS/FAIL | Critical findings: ... |
| API compat | PASS/FAIL | Critical findings: ... |
| OQ-005 (license) | OPEN/RESOLVED | Blocker for publish |
| OQ-007 (rndc tolerance) | OPEN/RESOLVED | Blocker for publish |

### Verdict: GO / NO-GO

**GO** — all required checks pass and all publish blockers are resolved.

**NO-GO** — list specific blockers:
- <item>: <why it blocks>
```

## Guidance

- If `cargo audit` finds advisories: check if they affect our transitive dependency graph specifically. `cargo audit --ignore <id>` only if you have a documented reason.
- If `rust-security-reviewer` raises CRITICAL findings: fix before publish — do not ship known security issues.
- If `api-compat-reviewer` finds missing `#[non_exhaustive]`: these are semver concerns — add before v1.0 but assess for v0.1.0 breakage risk.
- If OQ-005 or OQ-007 are OPEN: coordinate with user on resolution before running `cargo publish`.
