<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# bind9-sdk Preparation & Tooling Design Spec

**Date**: 2026-03-14
**Status**: Draft
**Scope**: Toolchain update, dependency refresh, PRD revision, CLAUDE.md updates, guardrail hooks, specialized agents, compliance integration, skill workflow

## 1. Design Principles

### 1.1 Exceed, Don't Meet

This SDK starts clean in 2026 with zero legacy compatibility obligations. Every default targets best current practice, not minimum compliance:

- **TLS 1.3 only** — no TLS 1.2 support. All modern platforms and BIND9 9.20 support 1.3.
- **HMAC-SHA512 default** — SHA-256 accepted, SHA-1 and MD5 rejected at the type level.
- **Ed25519 recommended** — for DNSSEC. Algorithms below 13 trigger warnings. This intentionally overrides PRD DEC-004 (which chose Algorithm 13/ECDSAP256SHA256 citing incomplete resolver support). As of 2026, Ed25519 resolver support is widespread and RFC 9904 supersedes the RFC 8624 guidance that DEC-004 relied on. DEC-004 must be updated in the PRD revision.
- **AES-256-GCM + ChaCha20-Poly1305 only** — no AES-128, no CBC.
- **XoT required for non-localhost** — cleartext zone transfers only for loopback.
- **Strict certificate validation by default** — no "opportunistic" TLS mode.
- **Forward-integrity log ratchet** — not just basic hash chains. Concrete algorithm selection (KDF, ratchet step construction) is deferred to Phase 1 implementation design.

Compliance standards (GDPR, NIS2, NIST, ISO 27001, SOC 2) define the floor. The SDK operates above it.

### 1.2 Rust-First, npm Secondary

The Rust crate (`bind9-sdk` on crates.io) is the primary artifact. The npm package (via napi-rs v3) is secondary — valuable for ecosystem reach but not a design driver. The `no_std` constraint on `bind9-sdk-core` is retained for architectural separation, not primarily for WASM.

### 1.3 Control Plane, Not Data Plane

The SDK manages BIND9 servers. It does not resolve DNS queries, hold DNSSEC private keys, or serve zones. Key operations are expressed as policy instructions to BIND9, not as direct crypto operations.

## 2. Toolchain & Dependencies

### 2.1 Rust Toolchain

Update `rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.94.0"
components = ["rustfmt", "clippy"]
targets = ["wasm32-unknown-unknown"]
```

Update workspace `Cargo.toml` (remove explicit `resolver = "2"` — edition 2024 defaults to resolver 3 for workspaces):

```toml
[workspace.package]
edition = "2024"
rust-version = "1.94"
```

### 2.2 Available Language Features (Rust 1.85 → 1.94)

These are stable and should be used throughout the codebase:

| Feature | Since | Use case in bind9-sdk |
| --- | --- | --- |
| Async closures (`async \|\| {}`) | 1.85 | Callback-based APIs in net layer |
| Let chains in `if`/`while` | 1.88 | Complex DNS parsing conditions, pattern matching |
| Trait upcasting | 1.86 | Trait object flexibility for `ZoneManager` et al. |
| Safe `#[target_feature]` | 1.86 | SIMD-accelerated parsing without `unsafe` |
| Const generic `_` inference | 1.89 | Generic buffer sizes in wire protocol code |
| AVX-512 / SHA-512 target features | 1.89 | Hardware-accelerated HMAC-SHA512 |

**Not stable — do not use**: never type (`!`), generators/coroutines, portable SIMD (`std::simd`).

### 2.3 Dependency Updates

All pinned to latest stable as of 2026-03-14:

```toml
[workspace.dependencies]
# Internal crates
bind9-sdk-core = { path = "crates/bind9-sdk-core", version = "0.1.0" }
bind9-sdk-net = { path = "crates/bind9-sdk-net", version = "0.1.0" }

# Async runtime (net layer only)
tokio = { version = "1.50", features = ["full"] }

# Data parallelism (optional, std only — not available in WASM)
rayon = { version = "1.11", optional = true }

# Crypto — RustCrypto, no_std compatible
hmac = { version = "0.12", default-features = false }
sha2 = { version = "0.10", default-features = false }
digest = { version = "0.10", default-features = false }

# Serialization
serde = { version = "1", default-features = false, features = ["derive", "alloc"] }
serde_json = { version = "1" }

# HTTP client for statistics-channel (net layer)
reqwest = { version = "0.13", default-features = false, features = ["json", "rustls-tls"] }

# Error handling — v2 auto-detects std vs no_std
thiserror = { version = "2", default-features = false }

# Logging
tracing = { version = "0.1" }

# Secret zeroization — no_std compatible (consumed by bind9-sdk-core for TsigKey and key material types)
zeroize = { version = "1", default-features = false, features = ["derive"] }

# Testing (consumed via [dev-dependencies] in each crate)
proptest = { version = "1.10" }
insta = { version = "1.46" }
```

**Version verification**: All versions above were verified against crates.io as of 2026-03-14 via web search. If any version fails to resolve during implementation, pin to the actual latest stable at that time and update this spec.

**Notes**:
- `reqwest` 0.13 is a breaking change from 0.12 (migrated to hyper 1.0). Existing code referencing reqwest will need updates.
- `thiserror` 2.x auto-detects `std` vs `no_std` — no manual feature-flag dance needed in `bind9-sdk-core`.
- RustCrypto stays at stable (hmac 0.12, sha2 0.10, digest 0.10). The 0.13/0.11 series is release-candidate only — not ready for production.
- `rayon` is optional, gated behind a `parallel` feature flag. It requires `std` and cannot be used in WASM or `no_std` targets.

### 2.4 Feature Flags (Updated)

```toml
# bind9-sdk (re-export crate)
[features]
default = ["net"]
net = ["dep:bind9-sdk-net"]
parallel = ["bind9-sdk-core/parallel", "dep:rayon"]

# bind9-sdk-core
[features]
default = []
std = []                    # Enables std::error::Error impls
serde = ["dep:serde"]       # Enables Serialize/Deserialize on DNS types
parallel = ["std", "dep:rayon"]  # Enables Rayon-based parallel zone parsing (implies std; incompatible with WASM)

# bind9-sdk-bindings (napi-rs v3 unified)
# REMOVED: browser = ["dep:wasm-bindgen"] — replaced by napi-rs v3 WASM output (see §2.5)
[features]
nodejs = ["dep:napi", "dep:napi-derive"]  # Native .node + WASM fallback via napi-rs v3
```

### 2.5 Bindings Architecture: napi-rs v3 Unification

napi-rs v3 (released July 2025, current: 3.8.3, MSRV 1.88) can compile to both native `.node` files AND `wasm32-wasip1-threads` WASM from the same binding code. This eliminates the need for separate `wasm-bindgen` bindings.

**Before** (PRD v0.1 design):
- `browser` feature → wasm-bindgen exports (core subset)
- `nodejs` feature → napi-rs exports (full surface)
- Two separate binding layers, two codegen paths, two test suites

**After** (this spec):
- `nodejs` feature → napi-rs v3 exports (full surface)
- Native `.node` for Node.js/Bun (primary)
- `wasm32-wasip1-threads` WASM fallback (automatic via napi-rs v3 CLI)
- One binding layer, one codegen path, one test suite

**Bun compatibility**: Bun implements ~95% of the Node-API surface. napi-rs v3 `.node` files work with Bun. The napi-rs authors explicitly confirm Bun support. Testing against Bun should be added to CI alongside Node.js.

**Drop `wasm-bindgen` as a direct dependency** of `bind9-sdk-bindings`. The `browser` feature flag is removed. WASM output is a build artifact of the napi-rs v3 compilation, not a separate feature.

**napi v2 → v3 migration**: The existing `bind9-sdk-bindings/Cargo.toml` pins napi at v2. Upgrading to napi v3 is a major version bump with API changes (redesigned `ThreadsafeFunction`, `Function` API, lifetime annotations). Source code changes will be required in `crates/bind9-sdk-bindings/src/node.rs` and `lib.rs` during Phase 4 implementation.

**WASM target clarification**: `rust-toolchain.toml` retains `wasm32-unknown-unknown` for the `no_std` core crate architectural check (the WASM check hook). The `wasm32-wasip1-threads` target needed for napi-rs v3 WASM output is handled by the napi CLI at build time, not by the Rust toolchain file. The two targets serve different purposes: `wasm32-unknown-unknown` validates `no_std` correctness; `wasm32-wasip1-threads` produces the WASM fallback artifact.

`bind9-sdk-core` remains `no_std` + `alloc` — this constraint is architecturally valuable for separation regardless of the WASM story.

## 3. PRD Revision

### 3.1 Stale Reference Fixes

| Current | Correction | Reason |
| --- | --- | --- |
| RFC 8499 | RFC 9499 (March 2024) | Superseded — DNS Terminology BCP 219 |
| RFC 8624 | RFC 9904 (November 2025) | Superseded — DNSSEC algorithm recommendation process. **DEC-004 must be revisited**: its rationale cited RFC 8624 guidance for choosing Algorithm 13. RFC 9904 changes the process and defers to the IANA DNSSEC Algorithm Numbers registry. |
| RFC 2136 status "Internet Standard" | "Proposed Standard" | Never promoted beyond PS |
| RFC 1995 status "Internet Standard" | "Proposed Standard" | Never promoted beyond PS |
| RFC 5936 status "Internet Standard" | "Proposed Standard" | Never promoted beyond PS |
| RFC 4635 not mentioned | Add historical note | HMAC-SHA256/SHA512 algorithm names originated here, absorbed by RFC 8945 |

### 3.2 Missing RFCs (Add to Appendix C)

**Operationally critical** (12 RFCs):

| RFC | Title | Crate | Why |
| --- | --- | --- | --- |
| 1996 | DNS NOTIFY | `net` | Zone transfer trigger logic |
| 7766 | DNS Transport over TCP | `net` | Normative TCP behavior for rndc, nsupdate, IXFR/AXFR |
| 9103 | Zone Transfer over TLS (XoT) | `net` | Default transport for non-localhost transfers |
| 4033 | DNSSEC Introduction | `core` | Context for 4034/4035 |
| 4035 | DNSSEC Protocol Modifications | `core` | DO/AD/CD bits, NSEC chain validation |
| 6840 | DNSSEC Clarifications | `core` | Updates to 4033/4034/4035/5155 |
| 7477 | CSYNC Record | `core` | Missing `RecordData` variant |
| 9615 | DNSSEC Bootstrapping (July 2024) | `core`/`net` | Updates CDS/CDNSKEY chain |
| 9859 | Generalized DNS Notifications (Sep 2025) | `net` | BIND9 9.21 support shipped. Note: SDK targets BIND9 9.20 initially; track as future/informational until 9.21 is baseline. |
| 9904 | DNSSEC Algorithm Process (Nov 2025) | reference | Replaces RFC 8624 |
| 9077 | NSEC/NSEC3 TTL Rules | `core` | NSEC TTL capped at SOA minimum |
| 4343 | DNS Case Insensitivity | `core` | `DomainName` comparison |

**Informational** (6 RFCs):

| RFC | Title | Why |
| --- | --- | --- |
| 2308 | Negative Caching | SOA minimum TTL semantics |
| 7583 | Key Rollover Timing | Required for FR-071 automated rollover |
| 8901 | Multi-Signer DNSSEC | Maps to hidden-primary architecture |
| 9210 | DNS TCP Operational Requirements | BCP 235 for `bind9-sdk-net` |
| 4509 | SHA-256 in DS Records | DS record construction |
| 5702 | RSA with SHA-2 in DNSSEC | DNSKEY/RRSIG algorithm support |

### 3.3 New Section: Compliance Requirements

Add a new top-level section to the PRD documenting the SDK's compliance posture. 33 requirements across 8 categories, each traceable to a regulatory source.

#### 3.3.1 Authentication & Authorization (REQ-AUTH-1 through REQ-AUTH-4)

- No anonymous rndc connections — type-system or construction-time enforcement.
- TSIG key material never in logs, errors, or serialized output. Zeroized on drop.
- TSIG key rotation support (RFC 8945 §5 dual-key transition).
- Structured log entries for all TSIG authentication failures.

Sources: NIST 800-53 IA-3/SC-8, NIS2 Art. 21(2)(h), ISO 27002 A.8.24.

#### 3.3.2 Transport Security (REQ-TLS-1 through REQ-TLS-3)

- XoT required for non-localhost zone transfers. Cleartext only for 127.0.0.1/::1.
- TLS 1.3 only. AES-256-GCM + ChaCha20-Poly1305 cipher suites.
- Strict certificate validation default. TOFU/SPKI pinning as CA alternative. No "opportunistic" mode.

Sources: NIS2 Art. 21(2)(h), BSI TR-02102-2, RFC 9103.

#### 3.3.3 DNSSEC Key Management (REQ-DNSSEC-1 through REQ-DNSSEC-5)

- All IANA-registered DNSSEC algorithms supported (8, 10, 13, 14, 15, 16). Ed25519 recommended default.
- Key lifecycle states per RFC 7583: generated → published → active → retire-scheduled → revoked → removed.
- KSK rollover safety gate: verify DS propagation before retiring old KSK.
- No private key material in SDK — control-plane instructions to BIND9 only.
- Algorithm agility: `DnssecAlgorithm` enum mapped to IANA registry. Extensible for post-quantum (ML-DSA/Dilithium, SLH-DSA expected ~2027-2028).

Sources: NIST SP 800-57/800-81, RFC 7583, BSI TR-02102-1.

#### 3.3.4 Tamper-Evident Logging (REQ-LOG-1 through REQ-LOG-6)

- Every rndc command, RFC 2136 update, TSIG failure, zone transfer, and key event logged.
- Structured JSON: RFC 3339 timestamps (microsecond, UTC), monotonic sequence numbers, session UUIDs, event types.
- Forward-integrity ratchet: per-entry MAC key derived via one-way ratchet. Previous keys destroyed. Attacker at time T cannot forge entries from before T.
- Data minimization: no TSIG secrets, no private keys, no client IPs from stats-channel unless explicitly requested.
- SecurityWarning events: cleartext transfer, deprecated TSIG algorithm, weak DNSSEC algorithm, near-expiry RRSIG. Configurable deny policy (operators can promote to hard errors).
- 12-month retention compatibility: structured format supports SIEM ingestion.

Sources: NIST SP 800-92r1, NIS2 Art. 23, GDPR Art. 5(1)(c), SOC 2 CC7/CC8.

#### 3.3.5 Zone Data Integrity (REQ-ZONE-1 through REQ-ZONE-5)

- Batched atomic updates: `UpdateBuilder` produces single RFC 2136 PDU for multiple operations.
- RAII zone-freeze guard: `FrozenZone` implements `Drop` → calls `thaw` even on panic.
- Optional SOA serial verification after update (detects silent BIND9 rejections).
- IXFR strict serial ordering: reject non-monotonic sequences, discard partial + fall back to AXFR.
- SOA RNAME preserved exactly — documented as potentially personal data.

Sources: RFC 2136 §3.7, ACID properties, SOC 2 PI1.4, GDPR Art. 4(1).

#### 3.3.6 GDPR Compliance Aids (REQ-GDPR-1 through REQ-GDPR-3)

- Stats-channel client does not log raw IP-attributable data by default.
- SOA RNAME, RP records, stats IP data documented with GDPR notes in API docs.
- No cross-session caching of zone data without explicit caller control.

Sources: GDPR Art. 5(1)(c)/(e), Art. 6, Art. 17.

#### 3.3.7 Supply Chain & Release Hygiene (REQ-SC-1 through REQ-SC-4)

- SBOM per release: CycloneDX 1.6 or SPDX 2.3 format.
- `SECURITY.md`: vulnerability disclosure process, 72h acknowledgment SLA, CVE pathway via RustSec.
- `cargo audit` in CI: zero unresolved advisories. 14-day SLA for advisory fixes.
- Pinned toolchain: exact version in `rust-toolchain.toml`, `Cargo.lock` committed.

Sources: NIS2 Art. 21(2)(d)/(e), EU Cyber Resilience Act, ISO 27002 A.5.21.

#### 3.3.8 Operational Security Defaults (REQ-SEC-DEFAULT-1 through REQ-SEC-DEFAULT-3)

- All connection methods require explicit auth config. No default anonymous mode. Type-system enforcement preferred.
- HMAC-MD5 rejected. HMAC-SHA1 accepted with `SecurityWarning`. HMAC-SHA512 default for new configurations.
- `SecurityWarning` system with configurable deny policy.

Sources: NIS2 Art. 21(2)(g), BSI TR-02102-1, RFC 8945.

### 3.4 New Section: Security Architecture

Document the hidden-primary / distributed-secondary architecture:

- Primary server: high-security host with RAM encryption, holds DNSSEC signing keys, KASP-managed.
- Secondary servers: cheap VPS, serve pre-signed zones via authenticated AXFR/IXFR over XoT.
- Per-zone keys: each zone has its own ZSK, KSK can be shared or per-zone depending on operator policy.
- Key isolation: even if primary is compromised, per-zone key scope limits blast radius. RFC 8901 Model 1 (single signer, hidden primary).
- Monitoring: SDK provides RRSIG expiry monitoring, SOA serial consistency checks across primary/secondaries, DNSSEC chain validation status via rndc `dnssec-status`.

### 3.5 Priority Rebalancing

Update the PRD's distribution and compatibility priorities:

| Priority | Artifact | Notes |
| --- | --- | --- |
| P0 | Rust crate (crates.io) | Primary artifact. API ergonomics for Rust consumers. |
| P1 | npm package (napi-rs v3 native) | Node.js + Bun. Secondary but low-cost via napi-rs v3 unification. |
| P2 | WASM (napi-rs v3 fallback) | Comes essentially free from napi-rs v3 compilation. Not a design driver. |

### 3.6 Parallelism Architecture

Add to PRD architecture section:

- `tokio` for async I/O (rndc TCP, zone transfers, nsupdate UDP/TCP, stats HTTP).
- `rayon` for CPU-bound parallelism (large zone parsing, parallel record processing). Feature-gated behind `parallel`.
- Bridge pattern: `tokio::sync::oneshot` channel + `rayon::spawn` for async-to-parallel handoff. Never block tokio threads with rayon's `join`/`install`.
- Rayon requires `std` — not available in `no_std` core or WASM. Sequential fallback used when `parallel` feature is disabled.

### 3.7 New RecordData Variants

Add to the `RecordData` enum:

- `Csync` — RFC 7477 (Child-to-Parent Synchronization)
- `Rp` — RFC 1183 (Responsible Person) — flagged with GDPR note

### 3.8 PRD Sections Affected by napi-rs v3 Transition

The wasm-pack → napi-rs v3 unification (§2.5) requires updates to the following PRD sections:

- **FR-030** (WASM browser bundle): Redefine as napi-rs v3 WASM output, not wasm-pack. Update acceptance criteria.
- **FR-031** (Node.js native addon): Update to reference napi-rs v3, add Bun support requirement.
- **Phase 3** (JavaScript Bindings): Consolidate browser + Node.js binding tasks into single napi-rs v3 implementation. Remove wasm-bindgen references.
- **DR-003** (Distribution architecture): Update to reflect single binding layer.
- **TR-004** (WASM technical requirements): Update target from `wasm32-unknown-unknown` to `wasm32-wasip1-threads` for binding output.
- **TR-006** (Build commands): Replace `wasm-pack build` with napi-rs v3 CLI commands.

### 3.9 Rust Version Updates

- `rust-version = "1.94"` throughout.
- Document available language features in a "Rust Language Features" subsection.
- Update dep versions table with latest stable versions.

## 4. CLAUDE.md Updates

### 4.1 Version & Commands

```markdown
## Commands

- Rust toolchain: 1.94.0 (edition 2024)
- `cargo check --workspace` + `cargo check --workspace --target wasm32-unknown-unknown`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --check`
- `cargo test --workspace`
- `cargo audit` (zero unresolved advisories required)
- `cargo deny check` (license + advisory + ban policy enforcement)
```

### 4.2 Updated Agents Table

```markdown
## Agents

| Agent | Purpose |
| --- | --- |
| `cargo-dep-auditor` | Audit Cargo deps for outdated versions, yanked crates, security advisories |
| `rust-security-reviewer` | Security audit: TSIG/crypto key exposure, DNS parsing safety, rndc input validation, RFC 2136 injection, WASM boundary, napi-rs FFI, zeroization, NIS2 logging compliance |
| `api-compat-reviewer` | Verify pub API surface, #[non_exhaustive] enums, Send+Sync bounds, re-export coverage, semver compatibility |
| `rfc-compliance-checker` | Verify implementation matches referenced RFC requirements, check edge cases, report deviations with section references |
| `dnssec-security-auditor` | DNSSEC key management security: key material exposure, zeroization, per-zone isolation, KASP timing, CDS/CDNSKEY bootstrapping |
```

### 4.3 Updated Hooks Table

```markdown
## Claude Code Hooks

| Hook | Trigger | Action |
| --- | --- | --- |
| `superpowers-check.sh` | SessionStart | Verifies superpowers plugin is active |
| `block-generated-files.sh` | PreToolUse (Edit/Write) | Blocks manual edits to `Cargo.lock` |
| `rust-fmt.sh` | PostToolUse (Edit/Write) | Auto-formats any edited `.rs` file with `rustfmt` |
| `wasm-check.sh` | PostToolUse (Edit/Write) | Runs `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown` on core crate edits |
| `clippy-gate.sh` | PostToolUse (Edit/Write) | Runs `cargo clippy -p <crate> -- -D warnings` on `.rs` edits |
| `spdx-header-check.sh` | PreToolUse (Write) | Blocks new file creation without SPDX header |
| `edition-check.sh` | PreToolUse (Write) | Verifies `edition = "2024"` in new `Cargo.toml` files |
| `dep-freshness.sh` | PostToolUse (Edit) | Warns if `Cargo.toml` dep versions are below known minimums |
```

### 4.4 Remove Stale Notes

Remove from CLAUDE.md agents table:
- "Needs rewrite for bind9-sdk — currently contains commitbee-specific checks"
- "Verify before use — may contain commitbee-specific content"
- "Commitbee artifact — not relevant to bind9-sdk, remove or replace"

### 4.5 Add Compliance Reference

```markdown
## Compliance

SDK targets compliance with GDPR, NIS2 (EU 2022/2555), NIST SP 800-53/800-81/800-57, ISO 27001:2022, and SOC 2 Type II requirements relevant to DNS infrastructure. All defaults exceed minimum compliance thresholds. See PRD §[TBD] (Compliance Requirements) for full requirement set — section number assigned during PRD revision (implementation step 6).
```

### 4.6 Add Workflow Section

```markdown
## Verification Workflow

- **Every change**: `rustfmt` + `clippy` (hooks, automatic)
- **Core crate edits**: WASM target check (hook, automatic)
- **Before commit**: `/verify` — single GLM5 pass
- **Security-sensitive code**: `/dialectic-verify` — parallel multi-model critique
- **Before release**: `cargo-dep-auditor` + `rust-security-reviewer` + `api-compat-reviewer` (all three)
- **Architectural decisions**: `/dialectic-verify` mandatory
```

## 5. Guardrail Hooks

### 5.1 `wasm-check.sh` (PostToolUse — Edit/Write)

Triggers on `.rs` file edits in `crates/bind9-sdk-core/`. Runs:

```bash
cargo check -p bind9-sdk-core --target wasm32-unknown-unknown
```

Fails the hook if `no_std` violations are introduced. This catches `std` imports, `std`-only trait impls, and accidental `net`/`tokio` dependencies in core.

### 5.2 `clippy-gate.sh` (PostToolUse — Edit/Write)

Triggers on any `.rs` file edit. Determines the affected crate from the file path and runs:

```bash
cargo clippy -p <crate-name> -- -D warnings
```

Catches correctness issues, unused imports, and idiom violations immediately.

**Performance note**: Running clippy per-crate on every `.rs` edit adds ~2-5s latency. This is an acceptable tradeoff for catching issues at edit time rather than at commit time. If the project grows significantly and the latency becomes disruptive, consider switching to a debounced or pre-commit-only mode.

### 5.3 `spdx-header-check.sh` (PreToolUse — Write)

Triggers on new file creation. Checks that the file starts with the appropriate SPDX header based on file extension:
- `.rs`: `// SPDX-FileCopyrightText:` + `// SPDX-License-Identifier:`
- `.toml`: `# SPDX-FileCopyrightText:` + `# SPDX-License-Identifier:`
- `.md`: `<!-- SPDX-FileCopyrightText:` + `<!-- SPDX-License-Identifier:`

Blocks the write if missing.

### 5.4 `edition-check.sh` (PreToolUse — Write on `Cargo.toml`)

Triggers when creating new `Cargo.toml` files. Verifies `edition = "2024"` is present. Warns (does not block) if absent.

### 5.5 `dep-freshness.sh` (PostToolUse — Edit on `Cargo.toml`)

Triggers on `Cargo.toml` edits. Runs a lightweight version check against known latest versions. Warns (does not block) if a dependency is pinned to an outdated major/minor version.

Implementation: maintain a `known-dep-versions.toml` file in `.claude/` with expected minimum versions, compare against edited `Cargo.toml`.

## 6. Specialized Agents

### 6.1 `rust-security-reviewer` (Rewrite)

**Scope**: Security audit for bind9-sdk Rust code.

**Checks**:
1. TSIG/crypto key material exposure — key secrets must not appear in `Debug`, `Display`, `tracing` output, or error messages at any level.
2. Zeroization — all key material types must derive `Zeroize` + `ZeroizeOnDrop` from the `zeroize` crate.
3. DNS name parsing safety — `DomainName` must validate label length (≤63 octets), total wire-format length (≤255 octets including length bytes and root label), text-form length (≤253 characters excluding trailing dot), character set (RFC 1035 §2.3.1), and case-insensitive comparison (RFC 4343).
4. rndc wire protocol input validation — length prefix ≤ configurable max (default 1MB), message structure validation before deserialization.
5. RFC 2136 update injection — prerequisite section must be validated, unauthorized record types rejected.
6. WASM boundary safety — no `std` imports in `bind9-sdk-core`, no `tokio`/`net` leakage.
7. napi-rs FFI safety — `unsafe` blocks only in `bind9-sdk-bindings`, each with a `// SAFETY:` comment.
8. NIS2 logging compliance — all security-relevant events produce structured log entries per REQ-LOG-*.
9. TLS configuration — verify TLS 1.3 only, no fallback to 1.2, correct cipher suites.
10. Secret handling — TSIG keys, rndc keys never written to disk, cached, or memoized.

### 6.2 `api-compat-reviewer` (Rewrite)

**Scope**: Public API compatibility verification for bind9-sdk.

**Checks**:
1. All `pub` types in `bind9-sdk-core` and `bind9-sdk-net` are re-exported through `bind9-sdk`.
2. Enums that will grow (e.g., `RecordData`, `RndcCommand`, `DnssecAlgorithm`) use `#[non_exhaustive]`.
3. Traits intended for external implementation carry `Send + Sync` bounds.
4. Breaking changes between workspace crate versions flagged.
5. New public API items have doc comments with `# Examples`.
6. `RecordData` variants match the IANA registry subset documented in the PRD.

### 6.3 `rfc-compliance-checker` (New)

**Scope**: Verify implementation matches referenced RFC requirements.

**Input**: RFC number + module path (e.g., `8945 crates/bind9-sdk-core/src/tsig.rs`).

**Process**:
1. Fetch the RFC text via web search or local cache.
2. Read the implementation module.
3. Cross-reference RFC "MUST", "SHOULD", "MAY" requirements against code.
4. Check edge cases documented in the RFC (e.g., RFC 8945 §5 BADTIME handling).
5. Report deviations with RFC section references.

**Output**: Structured report: `COMPLIANT | DEVIATION | NOT_IMPLEMENTED` per RFC requirement.

### 6.4 `dnssec-security-auditor` (New)

**Scope**: DNSSEC key management security audit.

**Checks**:
1. Key material never in logs, Debug output, Display output, or error messages.
2. Zeroization on drop for all key types (`TsigKey`, `DnssecKeyMetadata`).
3. Per-zone key isolation — verify key types are scoped to zone, not global.
4. KASP policy validation — rollover timing constraints match RFC 7583.
5. CDS/CDNSKEY bootstrapping security — RFC 9615 signal verification.
6. Algorithm agility — no hardcoded algorithm IDs in match arms without a wildcard.
7. DS propagation check — KSK retirement gated on parent zone DS verification.

## 7. Proactive Skill Usage

### 7.1 Mandatory Skills for This Project

| Skill | When | Why |
| --- | --- | --- |
| `dialectic-verify` | Architectural decisions, security-sensitive code, PRD changes | Multi-model independent critique prevents blind spots |
| `verification-before-completion` | Before claiming any task done | Gate every change — evidence before assertions |
| `prd-manager:prd-maintain` | Any PRD update | Safe edit-only, never overwrite |
| `hookify:writing-rules` | Creating new guardrail hooks | Correct hook syntax and patterns |
| `test-driven-development` | All RFC implementations | Tests define RFC compliance before code |
| `requesting-code-review` + `code-reviewer` | Before merging to main | Full review against plan and standards |

### 7.2 Agent Dispatch Patterns

| Situation | Agent(s) | Mode |
| --- | --- | --- |
| Monthly audit | `cargo-dep-auditor` + `rust-security-reviewer` | Parallel background |
| Before release | `cargo-dep-auditor` + `rust-security-reviewer` + `api-compat-reviewer` | All three, parallel |
| After crypto/auth code change | `rust-security-reviewer` | Foreground, blocking |
| After RFC implementation | `rfc-compliance-checker` | Foreground, blocking |
| After DNSSEC code change | `dnssec-security-auditor` | Foreground, blocking |

### 7.3 Multi-Model Verification

For architectural decisions and security-critical code, use `dialectic-verify` which runs:
- Independent parallel critiques from GLM5 + Codex + optionally Gemini (no anchoring bias)
- Dedup normalization
- Opus synthesis with explicit ACCEPT/REJECT/MODIFY per finding

## 8. Implementation Order

This spec's changes should be applied in this order:

1. **`rust-toolchain.toml`** — update to 1.94.0 (unblocks everything else)
2. **`Cargo.toml` workspace** — update all dep versions, add `rayon`, update `rust-version`
3. **Individual crate `Cargo.toml` files** — update feature flags, add new deps
4. **Guardrail hooks** — create and configure all 5 new hooks, update `.claude/settings.json` with hook trigger patterns
5. **Agent definitions** — rewrite `rust-security-reviewer` and `api-compat-reviewer`, create `rfc-compliance-checker` and `dnssec-security-auditor`
6. **PRD.md** — apply all fixes, additions, and new sections (via `prd-manager:prd-maintain`)
7. **CLAUDE.md** — update with new agents, hooks, commands, compliance reference
8. **Verify** — run `cargo update` (resolve new dep versions), then `cargo check --workspace` + `cargo check --workspace --target wasm32-unknown-unknown` to confirm toolchain update works

## 9. Out of Scope

- Phase 1 implementation code (separate planning session)
- Web interface design (separate project)
- CI/CD pipeline setup (after Phase 1 has tests to run)
- npm package publishing workflow (after bindings crate is implemented)
- SECURITY.md creation (Phase 1 deliverable — the file itself is in-scope for Phase 1 implementation, but the detailed vulnerability disclosure process and CVE pathway documented in REQ-SC-2 are refined as the project approaches initial release)
- SBOM generation tooling (after CI is in place)
