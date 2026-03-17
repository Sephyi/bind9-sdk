<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Phases 2–5 Parallel Execution Design

**Date:** 2026-03-17
**Status:** APPROVED
**Scope:** Phase 2 (v0.2.0), Phase 3 (v0.3.0), Phase 4 (v0.4.0), Phase 5 (v0.5.0)
**Predecessor:** Phase 1 complete at `4640403` on `development` (441 tests)

## 1. Goal

Plan and execute Phases 2–5 of bind9-sdk with maximum parallelism, delivering:

- Phase 2: IXFR/AXFR zone transfer client, DNSSEC record types, KASP introspection, CDS/CDNSKEY generation, XoT transport, SOA serial strategies
- Phase 3: napi-rs v3 migration, core surface JS/WASM bindings (auto-generated from Rust)
- Phase 4: Full SDK surface bindings, npm package assembly (local testing only)
- Phase 5: CLI tool, zone diff engine, connection pooling

**No-publish constraint:** Nothing is published to crates.io or npm. All packages prepared for local testing only. `package.json` carries `"private": true`. License decision (OQ-005) deferred.

## 2. Execution Architecture

### Two-Track Pipeline

After Phase 2 completes, work splits into two fully independent tracks:

| Track | Crates | Delivers |
| --- | --- | --- |
| **Rust track** (Phase 5) | `bind9-sdk-core`, `bind9-sdk-net`, new `bind9-sdk-cli` | Zone diff, connection pooling, CLI tool |
| **JS track** (Phases 3→4) | `bind9-sdk-bindings`, `package.json`, auto-generated `.d.ts` | napi-rs v3 native + WASM, npm package (local) |

Zero file overlap between tracks. Parallel worktrees with independent merge cadence.

### Worktree Strategy

- 2–3 concurrent worktrees per wave (proven in Phase 1)
- Feature branches off `development`
- Merge back at wave boundaries after quality gates
- Cross-track merges are independent

### Agent Team Strategy

- Each worktree gets its own implementation agent
- `rfc-compliance-checker` agent for IXFR/AXFR and DNSSEC work
- `wire-format-validator` agent for IXFR/AXFR protocol implementation
- `rust-security-reviewer` agent for napi-rs FFI boundary (Phase 3)
- Dialectic verification at phase boundaries (not per-worktree)

### Quality Gates (per wave)

- `cargo fmt --check` + `clippy -D warnings`
- WASM target check on core edits
- `cargo test --workspace` (unit tests)
- Integration tests against Podman BIND9 (for wire-level features)
- `cargo audit` + `cargo deny check` after adding new dependencies
- Dialectic verify at phase boundaries

### Compliance & Observability

Each worktree MUST include `tracing` instrumentation per coding architecture spec §6. Security-sensitive operations (zone transfers, DNSSEC key events, TSIG auth) require structured log fields per REQ-LOG-1.

Deferred to Phase 6:
- REQ-LOG-3: Forward-integrity log ratchet (complex crypto design)
- REQ-SEC-DEFAULT-3: `SecurityWarning` deny policy system

## 3. Phase 2 — Zone Transfers + DNSSEC

### P2-W0: E2E Infrastructure

**Branch:** `feat/e2e-infra`
**Parallel:** None (prerequisite for W1)
**Size:** Small (~1 session)

Deliverables:

- Harden existing `tests/bind9/` Podman container (named.conf, zone files, rndc key)
- Add `make test-integration` script: start container → wait for health → `cargo test -- --ignored` → teardown
- Add DNSSEC-signed test zone (for DNSSEC type validation and KASP querying)
- Configure AXFR-enabled zone with TSIG key (for IXFR/AXFR worktree)
- Verify existing `#[ignore]` integration tests pass against container (rndc, nsupdate, stats — validates FR-010 acceptance criteria)

### P2-W1: Core Protocol Work (3 parallel worktrees)

#### WT-A: DNSSEC Record Types

**Branch:** `feat/dnssec-types`
**Touches:** `core/rdata.rs` → MUST split to `core/rdata/` submodule (9 new DNSSEC variants push well past 400-line policy), new `core/dnssec.rs`
**FR:** FR-020
**Testing:** Proptest roundtrip per type, insta snapshots for zone serializer output, `dig +dnssec` test vectors

- Wire-format encode/decode: DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, DS, CDS, CDNSKEY, DLV
- Add variants to `RecordData` enum; new `RecordType` variants go in `protocol.rs` (not `record.rs`)
- Zone parser text format for all DNSSEC types
- Zone serializer output (covers GPT-DNSSEC audit item)
- Test vectors from `dig +dnssec` captures
- Proptest roundtrip for each new type

#### WT-B: IXFR/AXFR Zone Transfer Client

**Branch:** `feat/ixfr-axfr`
**Touches:** new `core/transfer.rs`, new `net/transfer/`
**FR:** FR-011
**Testing:** Mock-based unit tests for protocol state machine, proptest for wire roundtrip, integration test against Podman BIND9

- `TransferSession<Pending/Active>` typestate in core (per coding architecture spec)
- `XfrRecord` / `XfrStream` types
- `TransferClient` in net: `async fn transfer() -> impl Stream<Item = Result<ResourceRecord>>`
- TSIG authentication on transfer requests
- IXFR→AXFR automatic fallback (server responds with full zone instead of diff)
- New `NetError` variants: `TransferFailed`, `SerialMismatch`, `IncompleteTransfer`, `XfrProtocolError`
- `tracing` instrumentation on all transfer operations (REQ-LOG-1: log every zone transfer)
- Integration test: AXFR a test zone from Podman container

#### WT-C: SOA Serial Strategies + Audit Carryover

**Branch:** `feat/soa-serial-audit`
**Touches:** `core/record.rs`, `net/rndc/`, docs
**FR:** FR-012 + audit items

- `SerialStrategy` enum: `DateCounter`, `UnixTimestamp`, `Monotonic` (defer `Custom` variant per YAGNI — no concrete consumer exists)
- RFC 1982 serial arithmetic integration with `Serial` type
- `DateCounter` monotonic across day boundaries
- Audit carryover: F-002 (rndc nonce hardening), F-005 (doc alignment), GPT-ZONE-COL (column numbers in zone parse errors)
- Note: GPT-SPLIT/GPT-SNAP/GPT-PROP were resolved in Phase 1 completion; GPT-DNSSEC covered by WT-A

**Merge conflicts:** Minimal. WT-A splits `rdata.rs` to submodule, WT-B creates new files, WT-C touches `record.rs` and `rndc/`. Expected trivial conflict: both WT-A and WT-B add `pub mod` declarations to `core/lib.rs` — resolve at merge.

### P2-W2: Dependent Features + Research (2 parallel worktrees + 1 spike)

#### WT-D: CDS/CDNSKEY Generation + KASP State Querying

**Branch:** `feat/cds-kasp`
**Touches:** `core/dnssec.rs`, `net/rndc/command.rs`
**FR:** FR-022 + FR-021
**Depends on:** WT-A (DNSSEC types merged); soft dependency on WT-C (both touch `net/rndc/` — rebase on merged W1 before starting)
**Testing:** Unit tests for CDS generation, insta snapshots for KASP response parsing, integration test against Podman

- `CdsRecord::from_dnskey(dnskey, digest_type)` — SHA-256 (mandatory), SHA-384
- DELETE sentinel record per RFC 8078 §4
- Parse `rndc dnssec -status` and `rndc dnssec -checkds` responses into typed `DnssecStatus`, `DsCheckResult` structs
- Integration test: query KASP status from Podman container

#### WT-E: XoT Transport (DNS-over-TLS)

**Branch:** `feat/xot-transport`
**Touches:** `net/tls.rs`, `net/transfer/`
**Depends on:** WT-B (IXFR/AXFR merged)

- Wire existing `TlsConfig` into `TransferClient`
- REQ-TLS-1: XoT required for non-localhost transfers
- TLS 1.3 only, strict cert validation, localhost exemption
- Integration test: AXFR over TLS against Podman container (self-signed cert)

#### napi-rs v3 Research Spike (no worktree)

- Evaluate napi-rs v3 current state (stable/beta)
- Build minimal hello-world binding with `wasm32-wasip1-threads` output
- Document: what works, what doesn't, migration path from v2 stub
- Output: research doc in `docs/specs/` consumed by Phase 3 planning

### P2-W3: Integration + Hardening

**Branch:** `feat/p2-hardening`
**Parallel:** None (phase gate)

- Full integration test suite for all Phase 2 features against Podman BIND9
- Dialectic verification of Phase 2 codebase
- Remediation of findings
- Update `audit-findings.md` with Phase 2 entries
- Update PRD with Phase 2 completion status

## 4. Phase 5 — CLI + Ergonomics (Rust Track)

Phase 5 is presented before Phases 3–4 because the Rust track executes independently and typically completes first. No dependencies exist between the Rust track and JS track after Phase 2.

Starts immediately after P2-W3 merges. Runs in parallel with JS track.

### P5-W1: Two parallel worktrees

#### WT-F: Zone Diff Engine

**Branch:** `feat/zone-diff`
**Touches:** `core/zone/` (new `diff.rs`)
**FR:** FR-051

- `Zone::diff(&self, other: &Zone) -> ZoneDiff`
- `ZoneDiff` contains `Vec<DiffEntry>` — `Added`, `Removed`, `Modified` variants
- `ZoneDiff::to_updates() -> Vec<UpdateEntry>` — applying diff produces target zone
- SOA excluded by default (configurable)
- Human-readable text output for CLI consumption
- Proptest: `diff(a, b).apply(a) == b` invariant

#### WT-G: Connection Pooling

**Branch:** `feat/conn-pool`
**Touches:** `net/` (new `pool.rs`)
**FR:** FR-052

- `RndcPool` wrapping `RndcConnection`: configurable size (default 4), idle timeout (default 30s)
- Transparent reconnection on connection drop
- `Bind9Client` gains optional pool mode via `ClientConfig`
- `tokio::sync::Semaphore` for pool slots, background keepalive task
- Integration test: burst 10 rndc commands through pool of 2

### P5-W2: CLI Tool

**Branch:** `feat/cli`
**Depends on:** WT-F + WT-G merged
**FR:** FR-050

- New crate: `bind9-sdk-cli` (binary, workspace member) with `CliError` error enum (wraps `NetError`, config parse errors, IO — per one-enum-per-crate pattern)
- `clap` for argument parsing
- Command groups:
  - `zone list|status|reload|export|diff`
  - `record add|delete`
  - `dnssec status|checkds`
  - `stats`
- Config file at XDG/macOS paths
- `--server`/`--port`/`--key-name`/`--key-secret` flags override config
- `--output json` for all commands
- Exit codes: 0 success, 1 operational error, 2 usage error
- PR-006: binary < 10MB stripped
- Integration tests against Podman container

### P5-W3: Hardening

**Branch:** `feat/p5-hardening`

- Full integration test suite for CLI against Podman BIND9
- Dialectic verification of Phase 5 codebase
- Shell completion generation (bash, zsh, fish via `clap_complete`)
- Remediation

## 5. Phase 3 — JS Bindings, Core Surface (JS Track)

Starts after P2-W3 merges. Runs in parallel with Rust track. All "JS" code is Rust with `#[napi]` macros — napi-rs auto-generates `.node`, WASM, `.d.ts`, and JS loader.

### P3-W1: napi-rs v3 Foundation

**Branch:** `feat/napi-v3-setup`
**Depends on:** napi-rs research spike (P2-W2)

- Migrate `bind9-sdk-bindings/Cargo.toml` from napi-rs v2 to v3
- Add `package.json` (`"private": true`), napi CLI config
- First binding: `DomainName` as JS class (`new()`, `toString()`, `isAbsolute()`)
- Verify dual output: native `.node` + `wasm32-wasip1-threads` WASM
- Auto-generated `.d.ts` from doc comments
- Smoke test: `node -e "..."` for both native and WASM
- Bundle size baseline measurement

### P3-W2: Core Surface Bindings

**Branch:** `feat/napi-core-bindings`
**Depends on:** WT-I merged
**FR:** FR-030 + FR-031

- Zone parsing: `ZoneFile.parse(text)` → JS object graph
- Zone serialization: `ZoneFile.serialize()` → string
- Record types: `ResourceRecord`, `RecordData` variants as JS-friendly objects
- TSIG: `TsigKey` construction, `UpdateBuilder` chain API
- `BindSdkError` with `.message` and `.line` fields
- WASM boundary: core surface only (no networking)
- PR-003: WASM bundle < 500KB gzipped
- `tsc --noEmit` clean on generated types
- Test on Node.js 20 LTS, 22 LTS, and Bun

### P3-W3: Hardening

**Branch:** `feat/p3-hardening`

- Dialectic verification of bindings code
- FFI safety review (`rust-security-reviewer` agent)
- WASM bundle size optimization
- TypeScript type completeness check against core public API
- Remediation

## 6. Phase 4 — Full SDK Surface + npm Package (JS Track)

### P4-W1: Full Surface Bindings

**Branch:** `feat/napi-full-surface`
**Depends on:** Phase 3 complete + Phase 5 merged (for connection pooling). Mitigation if P5 delays: proceed with core net bindings (rndc, nsupdate, stats, transfer) and defer `RndcPool` binding to a follow-up
**FR:** FR-040 + FR-042

- `RndcClient` — all rndc commands, async methods as `Promise<T>`
- `NsUpdateSender` — async send with TSIG
- `StatsClient` — fetch server/zone stats
- `TransferClient` — AXFR/IXFR as async iterator
- `RndcPool` — connection pooling
- Full `.d.ts` with generics, `tsc --strict --noEmit` clean
- Platform build: macOS ARM64 (dev machine). Full platform matrix (FR-040: Linux x86_64/ARM64, macOS x86_64/ARM64, Windows x86_64) deferred to publish phase

### P4-W2: npm Package Assembly

**Branch:** `feat/npm-package`
**Depends on:** WT-K merged
**FR:** FR-041

- `package.json` exports map: `"node"` → native, `"browser"` → WASM, `"default"` → WASM
- CommonJS + ESM dual output
- Auto WASM fallback (napi-rs v3 built-in)
- TypeScript types bundled
- Local testing: `npm pack` → `npm install ./bind9-sdk-*.tgz` in test project
- Bun compatibility verification
- No `npm publish`
- Dialectic verification of complete JS track

## 7. Timeline & Parallelism Map

```txt
TIME →  W0      W1              W2                    W3
        ┃       ┃               ┃                     ┃
P2-W0:  [E2E ]  ┃               ┃                     ┃
        infra   ┃               ┃                     ┃
                ┃               ┃                     ┃
P2-W1:          [WT-A DNSSEC ]  ┃                     ┃
                [WT-B IXFR/AX]  ┃                     ┃
                [WT-C SOA+aud]  ┃                     ┃
                                ┃                     ┃
P2-W2:                          [WT-D CDS+KASP  ]    ┃
                                [WT-E XoT       ]    ┃
                                [napi-rs research]    ┃
                                                      ┃
P2-W3:                                                [P2 hardening]
                                                      ┃
════════════════════════════════════════════════════════╋═══════════
        PHASE 2 COMPLETE — tracks split               ┃
                                                      ┃
        Rust track (Phase 5)          JS track (Phases 3→4)
        ┃                             ┃
P5-W1:  [WT-F zone diff ]    P3-W1:  [WT-I napi-v3 setup ]
        [WT-G conn pool  ]            ┃
        ┃                     P3-W2:  [WT-J core bindings ]
P5-W2:  [WT-H CLI tool  ]            ┃
        ┃                     P3-W3:  [P3 hardening       ]
P5-W3:  [P5 hardening   ]            ┃
                              P4-W1:  [WT-K full surface  ]
                                      ┃
                              P4-W2:  [WT-L npm package   ]
```

## 8. Worktree Reference

| ID | Branch | Phase | Wave | Parallel with | Key dependency |
| --- | --- | --- | --- | --- | --- |
| WT-A | `feat/dnssec-types` | 2 | W1 | WT-B, WT-C | None |
| WT-B | `feat/ixfr-axfr` | 2 | W1 | WT-A, WT-C | E2E infra (P2-W0) |
| WT-C | `feat/soa-serial-audit` | 2 | W1 | WT-A, WT-B | None |
| WT-D | `feat/cds-kasp` | 2 | W2 | WT-E | WT-A (DNSSEC types) |
| WT-E | `feat/xot-transport` | 2 | W2 | WT-D | WT-B (IXFR/AXFR) |
| WT-F | `feat/zone-diff` | 5 | W1 | WT-G, WT-I | Phase 2 complete |
| WT-G | `feat/conn-pool` | 5 | W1 | WT-F, WT-I | Phase 2 complete |
| WT-H | `feat/cli` | 5 | W2 | WT-J | WT-F, WT-G |
| WT-I | `feat/napi-v3-setup` | 3 | W1 | WT-F, WT-G | Phase 2 + research spike |
| WT-J | `feat/napi-core-bindings` | 3 | W2 | WT-H | WT-I |
| WT-K | `feat/napi-full-surface` | 4 | W1 | — | P3 + P5 complete |
| WT-L | `feat/npm-package` | 4 | W2 | — | WT-K |

## 9. Critical Path

Longest dependency chain (determines minimum total time):

```txt
P2-W0 → P2-W1(WT-B) → P2-W2(WT-E) → P2-W3 → P3-W1(WT-I) → P3-W2(WT-J) → P3-W3 → P4-W1(WT-K) → P4-W2(WT-L)
```

The Rust track (Phase 5) is shorter and finishes first. Phase 4 is the true tail because WT-K depends on both tracks completing.

## 10. Verification Schedule

| When | What | Method |
| --- | --- | --- |
| Each worktree merge | fmt + clippy + WASM check + unit + integration | Hooks (automatic) |
| P2-W3 | Full Phase 2 dialectic verify | `/dialectic-verify` |
| P5-W3 | Phase 5 dialectic verify | `/dialectic-verify` |
| P3-W3 | Phase 3 dialectic verify + FFI safety | `/dialectic-verify` + `rust-security-reviewer` |
| P4-W2 | Final dialectic verify of complete SDK | `/dialectic-verify` + all review agents |

## 11. Open Questions Affecting Execution

| ID | Impact | Resolution path |
| --- | --- | --- |
| OQ-005 | No-publish constraint (already handled) | Resolve before any crates.io/npm publish |
| OQ-006 | npm package name | Resolve during P4-W2; no impact until publish |
| OQ-007 | rndc `_tim`/`_exp` fudge window | Validate in P2 integration tests |
| OQ-008 | napi-rs v3 readiness | Research spike in P2-W2; gate P3-W1 on findings |

## 12. New Crates

| Crate | Phase | Type | `no_std` | Workspace member |
| --- | --- | --- | --- | --- |
| `bind9-sdk-cli` | 5 (P5-W2) | Binary | No | Yes |

## 13. New Dependencies (Expected)

| Crate | Phase | Purpose |
| --- | --- | --- |
| `clap` | 5 | CLI argument parsing |
| `clap_complete` | 5 | Shell completion generation |
| `tokio-stream` | 2 | `Stream` trait for IXFR/AXFR |
| `napi` (v3) | 3 | napi-rs v3 core |
| `napi-derive` (v3) | 3 | napi-rs v3 proc macros |
