<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# bind9-sdk — Product Requirements Document

**Version**: v0.6
**Date**: 2026-03-16
**Status**: In Progress — Phase 1a complete, Phase 1b Wave 1 complete, Wave 2 in progress (WT-3 + WT-4 parallel)
**Author**: [Sephyi](https://github.com/Sephyi) + [Claude Opus 4.6](https://www.anthropic.com/news/claude-opus-4-6)

## Changelog

<details>
<summary>Revision history</summary>

| Version | Date | Summary |
| --- | --- | --- |
| 0.6 | 2026-03-16 | Wave 2 started: pre-fix populated 4 placeholder structs with real fields, WT-3 (rndc protocol) + WT-4 (stats/nsupdate) worktrees created and implementation in progress. |
| 0.5 | 2026-03-16 | Post-merge corrections: test count 242→245 (225 core + 19 net + 1 doc after post-merge fixes). Two CRITICAL review findings fixed (TSIG canonicalization via `write_wire_canonical`, explicit timestamp in `sign()`). Wave 2 plan updated with WT-5 (TSIG/update hardening). |
| 0.4 | 2026-03-16 | Phase 1b Wave 1 completed — zone parser (165 tests), TSIG RFC 8945 (TsigKey with zeroization), UpdateBuilder RFC 2136 (typestate Unsigned→Signed), net foundation (NetError, TlsConfig, ClientConfig). 309 new tests, 245 total after merge + post-merge fixes. |
| 0.3 | 2026-03-14 | Phase 1a (Core Foundation) completed — 9 tasks, 11 commits, 57 tests. Added implementation progress tracker (§12.1). Resolved OQ-001 (`no_std` confirmed). New decisions: DEC-005 through DEC-008 (async traits, core::error::Error, thiserror no_std, RRSIG original_ttl). |
| 0.2 | 2026-03-14 | RFC reference fixes (8499→9499, 8624→9904, status corrections), 18 new RFC entries, compliance requirements (33 REQs across 8 categories), security architecture, napi-rs v3 transition, parallelism architecture, Rust 1.94 update, DEC-004 Ed25519 note |
| 0.1 | 2026-03-14 | Initial draft — architecture, phased roadmap v0.1.0 → v1.0.0, full FR set |

</details>

## 1. Vision

> **"The BIND9 management SDK that should have existed a decade ago."**

`bind9-sdk` is a Rust-native library for programmatic BIND9 DNS server manage

ment. It implements the full rndc wire protocol, RFC 1035 zone file parsing and serialization, RFC 2136 dynamic updates (nsupdate), IXFR/AXFR zone transfer, and the BIND9 statistics-channel JSON API — all in one cohesive, type-safe Rust crate with zero shell subprocess dependencies.

It ships as three coordinated artifacts from a single codebase: a Rust crate on crates.io, a native Node.js/Bun addon via napi-rs v3, and a WASM fallback bundle (also via napi-rs v3) for browser environments. The npm package fills a gap that is structurally empty: as of 2026 there is not a single maintained TypeScript or JavaScript library for BIND9 management on npm.

### Core Principles

1. **Protocol-native** — rndc wire protocol, RFC 2136, IXFR/AXFR implemented at the byte level; no shell subprocess calls, ever
2. **Type-safe across the boundary** — DNS record types, zone names, and rndc commands are modelled as Rust enums, not strings
3. **`no_std` core** — the parsing and serialization layer compiles to WASM without modification
4. **Async-first** — tokio throughout the network layer; sync wrappers for embedding contexts that need them
5. **Zero panics** — proptest + fuzzing guarantees on all parsers; `#![forbid(unsafe_code)]` in core
6. **Multi-runtime** — one Rust codebase produces Rust (crates.io), Node.js/Bun (napi-rs v3 native addon), and browser (napi-rs v3 WASM fallback) artifacts
7. **Correct first** — RFC compliance tested against real BIND9 9.20 instances in CI

### Compatibility Policy

| Release | Scope | Breaking Changes |
| --- | --- | --- |
| v0.1.0 | Core Rust SDK — zone parsing, record types, rndc, stats-channel, nsupdate | Initial release |
| v0.2.0 | Zone transfers + DNSSEC utilities | None — additive only |
| v0.3.0 | WASM browser build | None |
| v0.4.0 | napi-rs Node.js native + npm publish | None |
| v0.5.0 | CLI tool + zone diff + ergonomics | None |
| v0.6.0 | Multi-language bindings + hardening + fuzzing | None |
| v1.0.0 | Stable, complete, production-grade | SemVer guarantees begin here |

## 2. Competitive Landscape

### 2.1 Market Position

| Category | Key Players | bind9-sdk Advantage |
| --- | --- | --- |
| BIND9 Python libraries | `octodns-bind` (zone sync only), `apititan/isc-bind-api` (stale 2022), `dnspython` (general DNS) | First Rust-native BIND9 management SDK; no shell deps |
| DNS Rust crates | `hickory-dns` (resolver + server, not management), `trust-dns` (archived) | First dedicated BIND9 *management* crate — rndc, nsupdate, stats |
| TypeScript/npm | Zero maintained packages for BIND9 management | First and only npm package; WASM for browser |
| PowerDNS ecosystem | Official Go + Python API clients | BIND9 has no official client SDK in any language |

### 2.2 Unique Differentiators

1. **rndc TCP wire protocol** — implemented in pure Rust; no competitor does this outside BIND itself
2. **Dual runtime** — one codebase, three artifacts: Rust crate + Node.js/Bun native addon (napi-rs v3) + browser WASM (napi-rs v3 fallback)
3. **Zero shell dependencies** — no `rndc` binary required; no `nsupdate` CLI; no `named-checkzone`
4. **no_std core** — WASM-compatible parsing layer without tricks or feature hacks
5. **Type-safe DNS record model** — every record type is a Rust enum variant, not a stringly-typed map

### 2.3 Market Gap

The Python ecosystem has `octodns-bind` for zone synchronization and `dnspython` for general DNS. Neither implements rndc. The TypeScript/npm ecosystem has zero BIND9 management packages. The Rust ecosystem has no dedicated BIND9 management crate — `hickory-dns` is a resolver and server, not a management client. This gap exists because rndc's wire protocol is custom (not HTTP, not gRPC) and requires reading BIND source to implement. `bind9-sdk` closes it once, in a form that compiles to three runtimes.

## 3. Architecture

### 3.1 Workspace Structure

```
bind9-sdk/
├── Cargo.toml                  # workspace root
├── crates/
│   ├── bind9-sdk-core/          # no_std + alloc; zone parsing, record types,
│   │   ├── Cargo.toml          # TSIG construction, nsupdate message format,
│   │   └── src/               # stats-channel JSON deserialization
│   │       ├── lib.rs          # #![no_std] #![forbid(unsafe_code)]
│   │       ├── zone/           # zone file parser + serializer
│   │       ├── record/         # all RFC record types as enums
│   │       ├── name.rs         # DomainName — validated, wire-format capable
│   │       ├── tsig.rs         # TSIG construction (HMAC-SHA256/SHA512)
│   │       ├── nsupdate.rs     # RFC 2136 message construction (no I/O)
│   │       └── stats.rs        # stats-channel JSON schema (serde Deserialize)
│   ├── bind9-sdk-net/           # tokio; rndc TCP, IXFR/AXFR, nsupdate sender,
│   │   ├── Cargo.toml          # stats-channel HTTP client
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── rndc/           # rndc wire protocol client
│   │       │   ├── client.rs   # RndcClient — connect, authenticate, command
│   │       │   ├── protocol.rs # wire format encode/decode
│   │       │   └── command.rs  # RndcCommand enum (all named commands)
│   │       ├── transfer/       # IXFR + AXFR zone transfer client
│   │       ├── update.rs       # nsupdate sender (UDP + TCP fallback)
│   │       └── stats.rs        # HTTP stats-channel client (reqwest)
│   └── bind9-sdk-bindings/      # napi-rs v3 (native + WASM from single layer)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           └── node.rs         # #[napi] exports — core + net (WASM via napi-rs v3 fallback)
├── bind9-sdk/                   # re-export crate (the public API on crates.io)
│   ├── Cargo.toml
│   └── src/lib.rs              # re-exports from core + net behind feature flags
├── bind9-sdk-cli/               # optional binary crate (Phase 5)
│   ├── Cargo.toml
│   └── src/main.rs
├── tests/
│   ├── integration/            # tests against real BIND9 9.20 (testcontainers)
│   ├── fixtures/               # zone files, rndc captures, stats-channel samples
│   └── fuzz/                   # cargo-fuzz targets
└── npm/
    ├── package.json
    ├── index.js                # auto-generated by napi-rs build
    └── index.d.ts              # TypeScript types (auto-generated)
```

### 3.2 Core Trait Design

```rust
// Zone management — implemented by RndcClient for live servers,
// by ZoneFile for local file editing, mockable in tests
pub trait ZoneManager: Send + Sync {
    async fn list_zones(&self) -> Result<Vec<ZoneSummary>>;
    async fn get_zone(&self, name: &DomainName) -> Result<Zone>;
    async fn reload_zone(&self, name: &DomainName) -> Result<()>;
    async fn freeze_zone(&self, name: &DomainName) -> Result<()>;
    async fn thaw_zone(&self, name: &DomainName) -> Result<()>;
    async fn zone_status(&self, name: &DomainName) -> Result<ZoneStatus>;
}

// rndc command execution — wire protocol over TCP with HMAC auth
pub trait NamedControl: Send + Sync {
    async fn command(&self, cmd: RndcCommand) -> Result<RndcResponse>;
    async fn dnssec_status(&self, zone: &DomainName) -> Result<DnssecStatus>;
    async fn dnssec_checkds(&self, zone: &DomainName) -> Result<DsCheckResult>;
}

// Dynamic DNS updates — RFC 2136
pub trait DynamicUpdater: Send + Sync {
    async fn add_record(&self, zone: &DomainName, record: ResourceRecord) -> Result<()>;
    async fn delete_record(&self, zone: &DomainName, record: &ResourceRecord) -> Result<()>;
    async fn replace_record(&self, zone: &DomainName, record: ResourceRecord) -> Result<()>;
}

// Statistics channel — BIND9 9.20 JSON endpoint
pub trait StatsClient: Send + Sync {
    async fn fetch(&self) -> Result<NamedStats>;
    async fn zone_stats(&self, name: &DomainName) -> Result<ZoneStats>;
}
```

### 3.3 Record Type Model

```rust
// Every DNS record type is a strongly-typed enum variant — no stringly-typed maps
#[non_exhaustive]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Mx { priority: u16, exchange: DomainName },
    Txt(Vec<TxtString>),
    Cname(DomainName),
    Ns(DomainName),
    Soa { mname: DomainName, rname: DomainName, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32 },
    Srv { priority: u16, weight: u16, port: u16, target: DomainName },
    Caa { flags: u8, tag: CaaTag, value: String },
    Ptr(DomainName),
    Dnskey { flags: u16, protocol: u8, algorithm: DnsKeyAlgorithm, public_key: Vec<u8> },
    Rrsig { /* RFC 4034 fields */ },
    Nsec { next_domain: DomainName, type_bitmaps: TypeBitmaps },
    Nsec3 { /* RFC 5155 fields */ },
    Ds { key_tag: u16, algorithm: DnsKeyAlgorithm, digest_type: DigestType, digest: Vec<u8> },
    Cds { /* same as Ds — for automated DS rollover */ },
    Cdnskey { /* same as Dnskey — for automated DS rollover */ },
    Tlsa { /* RFC 6698 */ },
    Sshfp { algorithm: u8, fp_type: u8, fingerprint: Vec<u8> },
    Csync { soa_serial: u32, flags: u16, type_bitmaps: TypeBitmaps },  // RFC 7477 — Child-to-Parent Synchronization
    Rp { mbox: DomainName, txt: DomainName },  // RFC 1183 — Responsible Person. GDPR note: contains personal data (mailbox URI). Subject to GDPR Art. 4(1). API docs must note this.
    Unknown { rtype: u16, data: Vec<u8> },
}
```

### 3.4 WASM Boundary Split

| Layer | WASM (browser) | Node.js (napi-rs native) |
| --- | --- | --- |
| Zone file parsing | Yes | Yes |
| Zone file serialization | Yes | Yes |
| DNS record type construction | Yes | Yes |
| TSIG message construction | Yes | Yes |
| nsupdate message format | Yes (construct only) | Yes (construct + send) |
| rndc TCP client | No (no raw TCP in browser) | Yes |
| IXFR/AXFR client | No | Yes |
| Statistics channel HTTP client | No (CORS) | Yes |

### 3.5 Parallelism Architecture

- **tokio** for async I/O: rndc TCP, zone transfers, nsupdate UDP/TCP, stats HTTP
- **rayon** for CPU-bound parallelism: large zone parsing, parallel record processing. Feature-gated behind `parallel`
- **Bridge pattern**: `tokio::sync::oneshot` channel + `rayon::spawn` for async-to-parallel handoff. Never block tokio threads with rayon's `join`/`install`
- **Sequential fallback**: rayon requires `std` — not available in `no_std` core or WASM. Sequential processing used when `parallel` feature is disabled

### 3.6 Rust Language Features

`rust-version = "1.94"` (edition 2024). Features available since the 1.85 baseline that the SDK uses:

| Feature | Stable Since | Usage |
| --- | --- | --- |
| Async closures (`async &#124;&#124; {}`) | 1.85 | Async callbacks in builder patterns |
| Trait upcasting | 1.86 | Trait object hierarchy for `ZoneManager` / `NamedControl` |
| Safe `#[target_feature]` | 1.86 | Optional SIMD-accelerated parsing paths |
| Let chains in `if`/`while` | 1.88 | Ergonomic pattern matching in parsers |
| Const generic `_` inference | 1.89 | Generic buffer sizes in wire protocol encoding |

### 3.7 Resolved Design Decisions

See Decisions Log (§16).

## 4. Feature Requirements

### 4.1 Phase 1 — v0.1.0: Core Rust SDK

#### FR-001: Zone File Parser

**Priority**: P0 | **Phase**: 1

Full RFC 1035 compliant zone file parser. Handles `$ORIGIN`, `$TTL`, `$INCLUDE` directives. Relative and absolute domain names. All standard record types (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR, CAA). Unknown record types stored as raw bytes.

**Acceptance Criteria**:
- ✓ Parses all zone files produced by BIND9 9.18 and 9.20 without error
- ✓ Round-trips losslessly: `parse(serialize(parse(input))) == parse(input)`
- ✓ Returns structured `ParseError` with line number and column for syntax errors
- ✓ Handles zones with > 100,000 records within 500ms on reference hardware
- ✓ `no_std` + `alloc` — compiles to WASM without feature gates

**Edge Cases**:
- `$INCLUDE` without `--allow-include` flag → `ParseError::IncludeNotAllowed`
- Multi-string TXT records (split across multiple quoted strings) → concatenated correctly
- TTL values exceeding 2^31-1 → `ParseError::TtlOverflow`
- Zone file with only SOA record → valid minimal zone, no error

#### FR-002: Zone File Serializer

**Priority**: P0 | **Phase**: 1

Serializes a `Zone` struct back to canonical BIND9 zone file format. Deterministic output (same input → same bytes). Configurable: column alignment, `$ORIGIN` compression, TTL optimization.

**Acceptance Criteria**:
- ✓ Output accepted by `named-checkzone` without warnings
- ✓ Deterministic: identical `Zone` struct always produces identical bytes
- ✓ `$ORIGIN` compression reduces file size for zones with repeated base domain
- ✓ Configurable indent width (default: tab-aligned to BIND9 convention)

#### FR-003: DNS Record Type Library

**Priority**: P0 | **Phase**: 1

Complete `RecordData` enum covering all IANA-registered record types present in BIND9 9.20. Each variant implements `Display` (zone file text form) and wire-format encode/decode.

**Acceptance Criteria**:
- ✓ All 20+ record types listed in §3.3 implemented
- ✓ Wire-format encode/decode verified against `dig +nocmd +noall +answer` output for each type
- ✓ `RecordData::Unknown` preserves raw bytes for unknown types — no data loss
- ✓ `DomainName` validates label length (max 63 bytes), total length (max 253), and character set

**Edge Cases**:
- SOA with negative serial wrap (u32 arithmetic) → handled per RFC 1982
- TXT record with embedded NUL bytes → stored and serialized correctly
- DNSKEY with algorithm 0 (reserved) → parsed as `Unknown` without error

#### FR-004: rndc Wire Protocol Client

**Priority**: P0 | **Phase**: 1

Full implementation of the rndc TCP wire protocol with HMAC-SHA256 authentication. Connects to BIND9's control channel, authenticates with a TSIG-style key, sends commands, receives structured responses.

**Acceptance Criteria**:
- ✓ Connects to BIND9 9.20 `controls { inet 127.0.0.1 port 953 allow { ... } keys { ... }; }` without the `rndc` binary
- ✓ HMAC-SHA256 authentication verified against BIND9's key validation
- ✓ All `RndcCommand` variants produce correct wire bytes (verified against Wireshark captures)
- ✓ Async: connect + command in < 100ms on loopback
- ✓ Connection reuse: single `RndcClient` can execute multiple sequential commands without reconnecting

**Edge Cases**:
- BIND9 closes connection mid-response → `RndcError::ConnectionReset` with partial data dropped
- Wrong key → `RndcError::AuthenticationFailed` (not silently ignored)
- Command not permitted by BIND9 ACL → `RndcError::PermissionDenied` with BIND's error text

#### FR-005: RndcCommand Enum

**Priority**: P0 | **Phase**: 1

Typed enum covering all rndc commands available in BIND9 9.20.

```rust
pub enum RndcCommand {
    Reload { zone: Option<DomainName> },
    Freeze { zone: Option<DomainName> },
    Thaw { zone: Option<DomainName> },
    Flush { cache: Option<String> },
    FlushName { name: DomainName },
    Zonestatus { zone: DomainName },
    Retransfer { zone: DomainName },
    Notify { zone: DomainName },
    Sign { zone: DomainName },
    Loadkeys { zone: DomainName },
    DnssecStatus { zone: DomainName },
    DnssecCheckds { zone: DomainName },
    DnssecRollover { zone: DomainName, key_tag: u16 },
    Validation { enable: bool },
    Stats,
    Status,
    Stop { save: bool },
    Halt { save: bool },
    Querylog { enable: bool },
    Recursing,
    Dumpdb { options: DumpDbOptions },
    SecRoots,
    NtaAdd { name: DomainName, lifetime: Duration },
    NtaRemove { name: DomainName },
    NtaList,
    Raw(String),  // escape hatch for commands not yet in enum
}
```

**Acceptance Criteria**:
- ✓ Each variant serializes to the correct rndc wire command string
- ✓ `Raw(String)` accepts arbitrary strings for forward compatibility
- ✓ All variants round-trip: serialize → send → parse response without data loss

#### FR-006: Statistics-Channel JSON Client

**Priority**: P0 | **Phase**: 1

HTTP client for BIND9 9.20 statistics-channel (JSON format). Parses the full response into typed Rust structs. Targets `statistics-channels { inet * port 8053 allow { localhost; }; };`.

**Acceptance Criteria**:
- ✓ Deserializes full BIND9 9.20 stats JSON into `NamedStats` struct without `serde_json::Value` fallback
- ✓ Zone-level stats accessible via `ZoneStats { queries_in, queries_out, transfers_in, transfers_out, ... }`
- ✓ Server-level stats: query rate, SERVFAIL rate, recursion stats, socket stats
- ✓ DNSSEC stats: signing operations, key events

**Edge Cases**:
- BIND9 9.18 stats format differences → detected by version field, degraded gracefully to partial parse
- Stats endpoint behind HTTP auth → configurable `Authorization` header support

#### FR-007: TSIG Key Utilities

**Priority**: P0 | **Phase**: 1

Generate, parse, and serialize TSIG keys for zone transfer authentication and nsupdate signing. No I/O — pure cryptographic construction.

**Acceptance Criteria**:
- ✓ `TsigKey::generate(algorithm, name)` produces a valid key struct and base64-encoded key material
- ✓ TSIG MAC computation matches BIND9's reference implementation for HMAC-SHA256 and HMAC-SHA512
- ✓ Key material never included in `Debug` output (redacted as `[REDACTED]`)
- ✓ Named TSIG keys can be serialized to `named.conf` `key { ... }` fragment format

#### FR-008: nsupdate Message Construction

**Priority**: P0 | **Phase**: 1

RFC 2136 dynamic update message construction. Pure construction — no I/O in `bind9-sdk-core`. Sending is in `bind9-sdk-net` (FR-011).

**Acceptance Criteria**:
- ✓ Builds valid RFC 2136 UPDATE messages for add, delete (RRset, specific RR, name), and no-op prerequisite checks
- ✓ TSIG signing applied to message bytes using `TsigKey`
- ✓ Wire-format output verified against `nsupdate -d` packet dumps

### 4.2 Phase 2 — v0.2.0: Zone Transfers + DNSSEC Utilities

#### FR-010: nsupdate Sender

**Priority**: P0 | **Phase**: 2

Sends RFC 2136 UPDATE messages over UDP (with TCP fallback for responses > 512 bytes or when UPDATE message > 512 bytes). TSIG-signed.

**Acceptance Criteria**:
- ✓ Sends to BIND9 9.20 primary and receives NOERROR or RCODE error
- ✓ TCP fallback triggered automatically on TRUNCATED response
- ✓ TSIG error (BADSIG, BADKEY, BADTIME) returned as `UpdateError::TsigRejected`
- ✓ Prerequisite check failures (NXDOMAIN, YXDOMAIN, NXRRSET, YXRRSET) typed as `UpdateError::PrerequisiteFailed`

#### FR-011: IXFR/AXFR Zone Transfer Client

**Priority**: P0 | **Phase**: 2

Client-side zone transfer over TCP. Receives full AXFR or incremental IXFR from a primary nameserver.

**Acceptance Criteria**:
- ✓ AXFR: receives complete zone as a stream of `ResourceRecord` items; assembles into `Zone`
- ✓ IXFR: receives incremental diff; applies to existing `Zone` producing updated `Zone`
- ✓ TSIG authentication on zone transfer channel
- ✓ Transfer from BIND9 9.20 hidden primary using WireGuard IP and TSIG key matches zone contents verified by `named-checkzone`
- ✓ Streaming API: `async fn transfer(&self) -> impl Stream<Item = Result<XfrRecord>>`

**Edge Cases**:
- AXFR response split across TCP segments → reassembled transparently
- IXFR fallback to AXFR (server responds with AXFR when IXFR serial too old) → handled automatically

#### FR-012: SOA Serial Strategies

**Priority**: P1 | **Phase**: 2

Pluggable SOA serial number generation strategies.

```rust
pub enum SerialStrategy {
    DateCounter,     // YYYYMMDDNN — increment NN, rollover on new day
    UnixTimestamp,   // seconds since epoch (u32, wraps in 2106)
    Monotonic,       // simple +1 increment from current value
    Custom(Box<dyn Fn(u32) -> u32 + Send + Sync>),
}
```

**Acceptance Criteria**:
- ✓ `DateCounter` never goes backwards even when called multiple times per second
- ✓ `DateCounter` rolls NN correctly across day boundary (00 on new day)
- ✓ All strategies respect RFC 1982 serial arithmetic for ordering comparison

#### FR-020: DNSSEC Record Types

**Priority**: P0 | **Phase**: 2

Complete implementation of DNSSEC record types in `RecordData`: DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, DS, CDS, CDNSKEY, DLV.

**Acceptance Criteria**:
- ✓ Wire-format encode/decode verified against `dig +dnssec` output for signed zones
- ✓ DNSKEY flags field: Zone Key (bit 8), SEP (bit 15), REVOKE (bit 8) exposed as `DnskeyFlags` bitflags
- ✓ RRSIG expiration comparison uses `DomainName::labels()` for correct relativization

#### FR-021: KASP State Querying

**Priority**: P1 | **Phase**: 2

Query BIND9 KASP (Key and Signing Policy) state via rndc.

**Acceptance Criteria**:
- ✓ `RndcCommand::DnssecStatus { zone }` response parsed into `DnssecStatus` struct with: key states (omnipresent/rumoured/hidden/unretentive), next rollover timestamp, active KSK/ZSK key tags
- ✓ `RndcCommand::DnssecCheckds { zone }` response parsed into `DsCheckResult` (DS present/absent at parent)

#### FR-022: CDS/CDNSKEY Generation

**Priority**: P1 | **Phase**: 2

Generate CDS and CDNSKEY records from an existing DNSKEY record, for automated DS record rollover at registrars that support RFC 8078.

**Acceptance Criteria**:
- ✓ `CdsRecord::from_dnskey(dnskey, digest_type)` produces correct DS digest
- ✓ Supported digest types: SHA-256 (type 2, mandatory), SHA-384 (type 4)
- ✓ DELETE sentinel record (`0 3 0 AA==`) generation for DS removal (RFC 8078 §4)

### 4.3 Phase 3 — v0.3.0: JavaScript Bindings (napi-rs v3)

#### FR-030: WASM Build (napi-rs v3)

**Priority**: P2 | **Phase**: 3

WASM output produced as a byproduct of napi-rs v3 compilation targeting `wasm32-wasip1-threads`. Exports the `bind9-sdk-core` surface (zone parsing/serialization, record types, TSIG construction, nsupdate message building). This is no longer a separate wasm-pack build step — napi-rs v3 handles both native and WASM from a single binding layer.

**Acceptance Criteria**:
- ✓ `import { parseZone, Zone, DomainName } from 'bind9-sdk'` works in Vite, webpack 5, and Rollup without configuration
- ✓ `import('bind9-sdk')` works as a dynamic import in browser (lazy WASM load)
- ✓ WASM bundle size < 500KB gzipped
- ✓ Zero runtime panics on zone files from BIND9 9.20
- ✓ `parseZone(str)` returns either `Zone` or throws `BindSdkError` with `.message` and `.line` fields
- ✓ napi-rs v3 WASM target: `wasm32-wasip1-threads`

**Edge Cases**:
- WASM module instantiation fails (out of memory) → throws `BindSdkError` with `.code = 'WASM_INIT_FAILED'`
- Called with non-string input → TypeError before WASM boundary (validated in JS wrapper)

#### FR-031: TypeScript Type Definitions (napi-rs v3)

**Priority**: P0 | **Phase**: 3

napi-rs v3 generates `.d.ts` for all exported functions and types (both native and WASM surfaces). Additional hand-written overloads where auto-generated output is imprecise. Bun runtime support required alongside Node.js.

**Acceptance Criteria**:
- ✓ `tsc --noEmit` passes with zero errors on TypeScript consumer using both native and WASM packages
- ✓ All exported functions have JSDoc comments (generated from Rust `///` doc comments)
- ✓ Types verified in Node.js 20 LTS, Node.js 22 LTS, and Bun

### 4.4 Phase 4 — v0.4.0: npm Publish + Full SDK Surface

#### FR-040: napi-rs v3 Node.js + Bun Native Addon

**Priority**: P0 | **Phase**: 4

Compile `bind9-sdk-bindings` as a native addon via napi-rs v3. Exposes the full SDK surface — both `bind9-sdk-core` and `bind9-sdk-net` — including rndc, nsupdate sender, IXFR/AXFR, and stats-channel client. Single binding layer produces both native and WASM outputs.

**Acceptance Criteria**:
- ✓ `const { RndcClient, parseZone } = require('bind9-sdk')` works in Node.js 20 LTS, Node.js 22 LTS, and Bun
- ✓ `await client.command(RndcCommand.reload())` reaches real BIND9 9.20 and returns `RndcResponse`
- ✓ Platform matrix: Linux x86_64, Linux ARM64, macOS ARM64, macOS x86_64, Windows x86_64
- ✓ Pre-built native binaries published to npm — no local Rust toolchain required for consumers
- ✓ napi-rs v3 WASM fallback (`wasm32-wasip1-threads`) automatically used when native binary unavailable for consumer's platform

#### FR-041: npm Package (`bind9-sdk`)

**Priority**: P0 | **Phase**: 4

Single npm package that bundles both the napi-rs native addon and the WASM bundle. Runtime detection selects native when available.

**Acceptance Criteria**:
- ✓ `npm install bind9-sdk` installs without any build step on supported platforms
- ✓ `import { parseZone } from 'bind9-sdk'` works in both CommonJS and ESM consumers
- ✓ `package.json` exports map: `"node"` → native addon, `"browser"` → WASM bundle, `"default"` → WASM
- ✓ TypeScript types bundled: `index.d.ts` covers both native and WASM surface

#### FR-042: TypeScript Types (Full SDK)

**Priority**: P0 | **Phase**: 4

Complete TypeScript type definitions for the full Node.js SDK surface, auto-generated by napi-rs with hand-written overrides for complex types.

**Acceptance Criteria**:
- ✓ `tsc --strict --noEmit` passes on TypeScript consumer using native Node.js package
- ✓ `RndcClient`, `ZoneManager`, `DynamicUpdater`, `StatsClient` all exported with full generic types
- ✓ All async methods typed as `Promise<T>` with documented rejection reasons in JSDoc

### 4.5 Phase 5 — v0.5.0: CLI + Ergonomics

#### FR-050: `bind9-sdk` CLI Tool

**Priority**: P1 | **Phase**: 5

Command-line interface for quick BIND9 management operations without writing code. Uses `bind9-sdk-net` directly.

```
bind9-sdk zone list                          # list zones from rndc
bind9-sdk zone status <name>                 # rndc zonestatus
bind9-sdk zone reload <name>                 # rndc reload zone
bind9-sdk record add <zone> <rr>             # nsupdate add record
bind9-sdk record delete <zone> <rr>          # nsupdate delete record
bind9-sdk dnssec status <zone>               # rndc dnssec -status
bind9-sdk dnssec checkds <zone>              # rndc dnssec -checkds
bind9-sdk stats                              # dump stats-channel summary
bind9-sdk zone export <name>                 # AXFR and print zone file
bind9-sdk zone diff <file> <name>            # diff local file vs live zone
```

**Acceptance Criteria**:
- ✓ Config file at `~/.config/bind9-sdk/config.toml` (Linux XDG) / `~/Library/Application Support/bind9-sdk/config.toml` (macOS)
- ✓ `--server`, `--port`, `--key-name`, `--key-secret` CLI flags override config
- ✓ Exit codes: 0 success, 1 error, 2 usage error
- ✓ Machine-readable `--output json` for scripting

#### FR-051: Zone Diff

**Priority**: P1 | **Phase**: 5

Compute the diff between two `Zone` values (or a local file and a live zone) as a set of RFC 2136 UPDATE operations.

**Acceptance Criteria**:
- ✓ `Zone::diff(&self, other: &Zone) -> ZoneDiff` returns `Vec<UpdateOperation>` (add/delete)
- ✓ Applying `ZoneDiff` as nsupdate operations transforms the source zone into the target zone exactly
- ✓ SOA record excluded from diff by default (configurable)
- ✓ Human-readable diff output in CLI (`+  A 300 1.2.3.4`, `-  A 300 1.2.3.5`)

#### FR-052: Connection Pooling

**Priority**: P1 | **Phase**: 5

`RndcPool` — shared pool of `RndcClient` connections for high-frequency command scenarios.

**Acceptance Criteria**:
- ✓ Configurable pool size (default 4 connections)
- ✓ Idle connections recycled after configurable timeout (default 30s)
- ✓ On connection drop from pool, re-established transparently on next command

### 4.6 Phase 6 — v0.6.0: Hardening

#### FR-060: named.conf Configuration Parser

**Priority**: P2 | **Phase**: 6

Parser for BIND9 `named.conf` files. Reads zone declarations, TSIG key stanzas, ACL blocks, and option fields relevant to SDK usage. Enables auto-discovery of configured zones and key material without manual configuration duplication.

**Acceptance Criteria**:
- ✓ Parses `zone` blocks: name, type (`primary`/`secondary`/`stub`/`forward`), file path, `allow-transfer` ACL
- ✓ Parses `key` blocks: algorithm, base64 secret — returns `TsigKey` struct directly usable by `RndcClient`
- ✓ Parses `options` subset: `directory`, `statistics-channels` (address + port), `allow-recursion`
- ✓ Parses `controls` block: rndc listen address and port
- ✓ Returns typed structs — no raw string values for structured fields
- ✓ Errors identify file path + line number for diagnostics
- ✓ Does NOT attempt to replicate the full `named.conf` grammar (that is a non-goal)

#### FR-061: Fuzzing

**Priority**: P0 | **Phase**: 6

`cargo-fuzz` targets for all parsers.

**Acceptance Criteria**:
- ✓ Three fuzz targets: `fuzz_zone_parser`, `fuzz_rndc_response`, `fuzz_stats_json`
- ✓ 24-hour fuzz run with no panics before v1.0.0 tag
- ✓ All fuzz-discovered crashes fixed and regression tests added

#### FR-062: RFC Compliance Suite

**Priority**: P0 | **Phase**: 6

Integration test suite verifying correct behavior against real BIND9 9.20 instances (via testcontainers or pre-configured CI container).

**Acceptance Criteria**:
- ✓ Zone parse → serialize → load into BIND9 → query = correct answers for 20+ zone file fixtures
- ✓ rndc all commands verified against real BIND9 responses (not mocks)
- ✓ nsupdate add/delete/replace verified against BIND9 query responses post-update
- ✓ AXFR/IXFR verified: transferred zone equals authoritative zone per `dig AXFR`

### 4.7 Phase 7 — v1.0.0: Complete SDK

#### FR-070: Multi-View Support

**Priority**: P1 | **Phase**: 7

BIND9 named.conf `view` awareness. `RndcClient::for_view(name)` scopes all zone operations to a specific view.

#### FR-071: DNSSEC Key Rollover Helpers

**Priority**: P1 | **Phase**: 7

High-level helpers for DNSSEC key rollover workflows, built on top of FR-021 and FR-022.

```rust
pub struct RolloverWorkflow {
    pub zone: DomainName,
    pub state: RolloverState,  // WaitingForDs | DsPublished | OldKeyRetired
    pub next_action: RolloverAction,
    pub deadline: Option<DateTime<Utc>>,
}
```

**Acceptance Criteria**:
- ✓ `RolloverWorkflow::check(&rndc_client, &zone)` returns current rollover state without side effects
- ✓ `RolloverWorkflow::advance(&rndc_client, &zone)` executes the next rndc command when state allows
- ✓ KSK rollover via CDS/CDNSKEY: detects when registrar has published new DS and advances state

#### FR-072: Prometheus Metrics Integration

**Priority**: P2 | **Phase**: 7

Parse `bind_exporter`-format Prometheus text output, or directly query the stats-channel and produce Prometheus-formatted metrics.

## 5. Security Requirements

### SR-001: Key Material Handling

- TSIG key secret material never included in `Debug` or `Display` output — redacted as `[REDACTED]`
- Key secrets zeroized from memory on drop via `zeroize` crate
- Key material never written to log output at any `tracing` level

### SR-002: rndc Authentication

- HMAC-SHA256 authentication is mandatory — no unauthenticated rndc mode
- `RndcClient::connect()` fails fast on authentication error rather than silently degrading
- Nonce uniqueness enforced: each connection generates a fresh random nonce via `OsRng`

### SR-003: WASM Sandbox Compliance

- WASM build has no access to filesystem, network, or system entropy
- TSIG construction in WASM uses caller-provided nonce (no `OsRng` in WASM)
- All cryptographic operations in WASM use pure-Rust implementations (no native bindings)

### SR-004: Code Safety

- `#![forbid(unsafe_code)]` in `bind9-sdk-core` and the re-export crate
- `unsafe` permitted only in `bind9-sdk-bindings` (napi-rs FFI boundary) and only in explicitly reviewed blocks
- `cargo deny` for license compliance; `cargo audit` in CI for CVE tracking

### SR-005: Input Validation

- All `DomainName` construction validates label length (≤ 63 bytes), total length (≤ 253 octets), and label character set (RFC 1035 §2.3.1)
- Zone file parser enforces RFC 1035 record count limits before allocating
- rndc response parser rejects messages exceeding configurable max size (default 1 MB)

## 6. Performance Requirements

### PR-001: Zone File Parsing

- Parse a 10,000-record zone file in < 200ms on a single core (reference: Apple M-series or AMD Zen 4)
- Parser allocates once per record, not per byte — no per-character heap allocation

### PR-002: rndc Round-Trip

- Command + response on loopback TCP: < 50ms (p99)
- Connection establishment (TCP + HMAC handshake): < 100ms on LAN

### PR-003: WASM Bundle Size

- Browser bundle: < 500KB gzipped
- Tree-shaking: consumers importing only `parseZone` should not include rndc or stats-channel code

### PR-004: nsupdate Throughput

- 1,000 single-record UPDATE messages per second on loopback UDP without connection pooling

### PR-005: Memory

- Zone with 100,000 records: < 200MB RSS
- No memory growth across repeated parse/serialize cycles (no leaks verified with valgrind in CI)

### PR-006: Binary Size (CLI)

- `bind9-sdk-cli` release binary: < 10MB stripped

## 7. UX Requirements

### UX-001: Error Messages

Every error includes what went wrong, the BIND9 or RFC context, and how to fix it:

```
error[RNDC_AUTH]: Authentication failed connecting to 127.0.0.1:953

  context: HMAC-SHA256 verification rejected by named
  help: Verify the key name and secret in your config match
        the `key { ... }` block in named.conf
        Key used: "rndc-key"
```

### UX-002: API Ergonomics

- Builder pattern for complex types: `UpdateMessage::builder().add(record).prerequisite(pre).build()`
- `FromStr` on `DomainName`, `ResourceRecord`, `TsigKey` (parses zone-file text format)
- `Display` on all public types produces zone-file text form

### UX-003: Documentation

- 100% public API documented on docs.rs
- Each module has a module-level doc comment with example
- `# Examples` in all `impl` blocks for frequently-used types
- BIND9 RFC reference links in doc comments for wire-format types

### UX-004: Tracing Integration

- `tracing` spans on all async operations at `DEBUG` level
- TSIG nonce and key name logged at `TRACE` level; key secret never logged
- rndc command and response type logged at `DEBUG`; response body at `TRACE`

## 8. Compliance Requirements

SDK targets compliance with GDPR, NIS2 (EU 2022/2555), NIST SP 800-53/800-81/800-57, ISO 27001:2022, and SOC 2 Type II requirements relevant to DNS infrastructure. All defaults exceed minimum compliance thresholds.

### 8.1 Authentication & Authorization

| ID | Requirement | Source |
| --- | --- | --- |
| REQ-AUTH-1 | No anonymous rndc connections — type-system or construction-time enforcement | NIST 800-53 IA-3/SC-8, NIS2 Art. 21(2)(h) |
| REQ-AUTH-2 | TSIG key material never in logs, errors, or serialized output. Zeroized on drop | ISO 27002 A.8.24 |
| REQ-AUTH-3 | TSIG key rotation support (RFC 8945 S5 dual-key transition) | NIST 800-53 SC-12 |
| REQ-AUTH-4 | Structured log entries for all TSIG authentication failures | NIS2 Art. 23 |

### 8.2 Transport Security

| ID | Requirement | Source |
| --- | --- | --- |
| REQ-TLS-1 | XoT required for non-localhost zone transfers. Cleartext only for 127.0.0.1/::1 | NIS2 Art. 21(2)(h), RFC 9103 |
| REQ-TLS-2 | TLS 1.3 only. AES-256-GCM + ChaCha20-Poly1305 cipher suites | BSI TR-02102-2 |
| REQ-TLS-3 | Strict certificate validation default. TOFU/SPKI pinning as CA alternative | NIS2 Art. 21(2)(h) |

### 8.3 DNSSEC Key Management

| ID | Requirement | Source |
| --- | --- | --- |
| REQ-DNSSEC-1 | All IANA-registered DNSSEC algorithms supported (8, 10, 13, 14, 15, 16). Ed25519 recommended default | NIST SP 800-57/800-81 |
| REQ-DNSSEC-2 | Key lifecycle states per RFC 7583: generated -> published -> active -> retire-scheduled -> revoked -> removed | RFC 7583 |
| REQ-DNSSEC-3 | KSK rollover safety gate: verify DS propagation before retiring old KSK | NIST SP 800-81 |
| REQ-DNSSEC-4 | No private key material in SDK — control-plane instructions to BIND9 only | BSI TR-02102-1 |
| REQ-DNSSEC-5 | Algorithm agility: `DnssecAlgorithm` enum mapped to IANA registry. Extensible for post-quantum | RFC 9904 |

### 8.4 Tamper-Evident Logging

| ID | Requirement | Source |
| --- | --- | --- |
| REQ-LOG-1 | Every rndc command, RFC 2136 update, TSIG failure, zone transfer, and key event logged | NIST SP 800-92r1 |
| REQ-LOG-2 | Structured JSON: RFC 3339 timestamps (microsecond, UTC), monotonic sequence numbers, session UUIDs | SOC 2 CC7/CC8 |
| REQ-LOG-3 | Forward-integrity ratchet: per-entry MAC key derived via one-way ratchet | NIS2 Art. 23 |
| REQ-LOG-4 | Data minimization: no TSIG secrets, no private keys, no client IPs unless explicitly requested | GDPR Art. 5(1)(c) |
| REQ-LOG-5 | SecurityWarning events: cleartext transfer, deprecated TSIG algorithm, weak DNSSEC algorithm, near-expiry RRSIG | NIS2 Art. 21(2)(g) |
| REQ-LOG-6 | 12-month retention compatibility: structured format supports SIEM ingestion | SOC 2 CC7 |

### 8.5 Zone Data Integrity

| ID | Requirement | Source |
| --- | --- | --- |
| REQ-ZONE-1 | Batched atomic updates: `UpdateBuilder` produces single RFC 2136 PDU for multiple operations | RFC 2136 S3.7 |
| REQ-ZONE-2 | RAII zone-freeze guard: `FrozenZone` implements `Drop` -> calls `thaw` even on panic | SOC 2 PI1.4 |
| REQ-ZONE-3 | Optional SOA serial verification after update (detects silent BIND9 rejections) | ACID properties |
| REQ-ZONE-4 | IXFR strict serial ordering: reject non-monotonic sequences, discard partial + fall back to AXFR | RFC 1995 |
| REQ-ZONE-5 | SOA RNAME preserved exactly — documented as potentially personal data | GDPR Art. 4(1) |

### 8.6 GDPR Compliance Aids

| ID | Requirement | Source |
| --- | --- | --- |
| REQ-GDPR-1 | Stats-channel client does not log raw IP-attributable data by default | GDPR Art. 5(1)(c)/(e) |
| REQ-GDPR-2 | SOA RNAME, RP records, stats IP data documented with GDPR notes in API docs | GDPR Art. 6 |
| REQ-GDPR-3 | No cross-session caching of zone data without explicit caller control | GDPR Art. 17 |

### 8.7 Supply Chain & Release Hygiene

| ID | Requirement | Source |
| --- | --- | --- |
| REQ-SC-1 | SBOM per release: CycloneDX 1.6 or SPDX 2.3 format | NIS2 Art. 21(2)(d)/(e) |
| REQ-SC-2 | `SECURITY.md`: vulnerability disclosure process, 72h acknowledgment SLA, CVE pathway via RustSec | EU Cyber Resilience Act |
| REQ-SC-3 | `cargo audit` in CI: zero unresolved advisories. 14-day SLA for advisory fixes | ISO 27002 A.5.21 |
| REQ-SC-4 | Pinned toolchain: exact version in `rust-toolchain.toml`, `Cargo.lock` committed | NIS2 Art. 21(2)(e) |

### 8.8 Operational Security Defaults

| ID | Requirement | Source |
| --- | --- | --- |
| REQ-SEC-DEFAULT-1 | All connection methods require explicit auth config. No default anonymous mode | NIS2 Art. 21(2)(g) |
| REQ-SEC-DEFAULT-2 | HMAC-MD5 rejected. HMAC-SHA1 accepted with `SecurityWarning`. HMAC-SHA512 default | BSI TR-02102-1, RFC 8945 |
| REQ-SEC-DEFAULT-3 | `SecurityWarning` system with configurable deny policy | NIS2 Art. 21(2)(g) |

## 9. Security Architecture

### 9.1 Hidden-Primary / Distributed-Secondary

- **Primary server**: high-security host with RAM encryption, holds DNSSEC signing keys, KASP-managed
- **Secondary servers**: low-cost VPS, serve pre-signed zones via authenticated AXFR/IXFR over XoT
- **Per-zone keys**: each zone has its own ZSK; KSK can be shared or per-zone depending on operator policy
- **Key isolation**: even if primary is compromised, per-zone key scope limits blast radius. RFC 8901 Model 1 (single signer, hidden primary)

### 9.2 Monitoring

- RRSIG expiry monitoring with configurable warning threshold
- SOA serial consistency checks across primary/secondaries
- DNSSEC chain validation status via rndc `dnssec-status`
- SecurityWarning events for near-expiry signatures, algorithm deprecation, cleartext transfers

## 10. Testing Requirements

### TR-001: Unit Tests

| Module | Technique | Coverage Target |
| --- | --- | --- |
| Zone file parser | Snapshot (insta) + proptest | All record types, directives, error paths |
| Zone file serializer | Roundtrip property | `parse(serialize(zone)) == zone` for all inputs |
| `RecordData` wire format | Unit per variant | RFC-verified byte sequences |
| `DomainName` | Unit + proptest | Never panics; validates all constraints |
| TSIG construction | Unit | MAC verified against BIND9 reference |
| nsupdate message | Unit | Wire bytes verified against `nsupdate -d` |
| `RndcCommand` serialization | Unit | All variants produce correct command strings |
| SOA serial strategies | Unit | `DateCounter` monotonicity across day boundary |

### TR-002: Integration Tests (BIND9 9.20)

Real BIND9 9.20 container via `testcontainers-rs` in CI:

| Scenario | What is Verified |
| --- | --- |
| rndc reload zone | Zone reloads; subsequent query returns updated record |
| rndc zonestatus | Response parses into `ZoneStatus` with correct serial |
| nsupdate add record | `dig A example.com` returns added address |
| nsupdate delete record | Record absent after delete |
| AXFR zone transfer | Transferred zone == authoritative zone |
| IXFR incremental transfer | Updated zone == full zone after applying diff |
| Stats-channel JSON | Full response deserializes without `Value` fallback |
| TSIG wrong key | Returns `AuthenticationFailed`, not silent error |
| DNSSEC status | Parses KSK/ZSK state for signed zone |

### TR-003: Property-Based Tests

```rust
proptest! {
    #[test]
    fn zone_parser_never_panics(input in "\\PC*") {
        let _ = Zone::parse(&input, ParseOptions::default());
    }

    #[test]
    fn domain_name_never_panics(input in "\\PC*") {
        let _ = DomainName::from_str(&input);
    }

    #[test]
    fn serialize_parse_roundtrip(zone in zone_strategy()) {
        let serialized = zone.serialize(SerializeOptions::default());
        let reparsed = Zone::parse(&serialized, ParseOptions::default()).unwrap();
        assert_eq!(zone, reparsed);
    }
}
```

### TR-004: WASM Tests

- napi-rs v3 WASM output (`wasm32-wasip1-threads`) tested via Node.js WASI runtime
- Browser bundle smoke test via Playwright: `parseZone` with a 1,000-record zone in Chromium and Firefox

### TR-005: napi-rs / npm Tests

- Jest test suite covering all exported Node.js API surface
- Run against Node.js 20 LTS and 22 LTS in CI matrix

### TR-006: CI Pipeline

- `cargo check` → `cargo clippy -- -D warnings` → `cargo test` → `cargo audit` → `cargo deny check`
- WASM build: `napi build --target wasm32-wasip1-threads --release`
- Integration tests: BIND9 9.20 container via testcontainers
- Fuzzing: scheduled 1-hour run on `main`, full 24-hour run before `v1.0.0`
- Matrix: stable Rust + MSRV (`rust-version = "1.94"`, edition 2024)

### TR-007: Fuzzing

Three `cargo-fuzz` targets:
- `fuzz_zone_parser` — arbitrary bytes as zone file input
- `fuzz_rndc_response` — arbitrary bytes as rndc response packet
- `fuzz_stats_json` — arbitrary bytes as stats-channel JSON

## 11. Distribution Requirements

### DR-001: crates.io (P0 — Primary Artifact)

`cargo add bind9-sdk` — published on crates.io. Feature flags:
- `net` (default) — enables `bind9-sdk-net` (tokio, rndc, IXFR, nsupdate sender, stats HTTP)
- `core-only` — `no_std` + `alloc` only; for embedding in WASM or constrained environments
- `cli` — enables `bind9-sdk-cli` binary

### DR-002: npm (P1 — Node.js + Bun via napi-rs v3 Native)

`npm install bind9-sdk` — single package on npm registry. Pre-built native binaries for all supported platforms via napi-rs v3; WASM fallback auto-selected when native unavailable.

Supported platforms for pre-built native binaries:
- Linux x86_64 (glibc >= 2.17), Linux ARM64
- macOS ARM64, macOS x86_64
- Windows x86_64

Supported runtimes: Node.js 20 LTS, Node.js 22 LTS, Bun.

### DR-003: WASM (P2 — napi-rs v3 Fallback)

WASM output comes free from napi-rs v3 compilation (`wasm32-wasip1-threads` target). Not a separate design driver. Exposes the `bind9-sdk-core` subset only (zone parsing, record construction, RFC 2136 message building). No TCP in browser. Bundle size target: < 500 KB gzipped.

### DR-004: Docs

- docs.rs for Rust API (auto-published on crates.io publish)
- Dedicated docs site (mdBook or similar) with guides: getting started, zone management, rndc automation, DNSSEC lifecycle, WASM integration, Node.js integration

### DR-005: Release Profile

```toml
[profile.release]
lto = true
strip = true
codegen-units = 1
opt-level = "z"
```

## 12. Roadmap Summary

| Phase | Version | Focus |
| --- | --- | --- |
| 1 | v0.1.0 | Core Rust SDK: zone parser/serializer, all record types, rndc client, stats-channel, TSIG, nsupdate construction |
| 2 | v0.2.0 | Zone transfers: nsupdate sender, IXFR/AXFR client, DNSSEC record types, KASP introspection, CDS/CDNSKEY |
| 3 | v0.3.0 | JavaScript bindings: napi-rs v3 (native + WASM from single layer), TypeScript types, Bun support |
| 4 | v0.4.0 | npm publish: full SDK surface in JS ecosystem, pre-built native binaries, WASM fallback |
| 5 | v0.5.0 | CLI tool, zone diff, connection pooling |
| 6 | v0.6.0 | named.conf parser (FR-060), fuzzing (FR-061), RFC compliance integration suite (FR-062) |
| 7 | v1.0.0 | Multi-view support, DNSSEC rollover helpers, Prometheus integration, SemVer stability |

### 12.1 Implementation Progress

#### Phase 1a: Core Foundation — COMPLETED (2026-03-14)

**Branch**: `development` | **Commits**: 11 | **Tests**: 57 passing | **Status**: clippy clean, WASM clean

Modules delivered in `crates/bind9-sdk-core/src/`:

| Module | What it provides |
| --- | --- |
| `error.rs` | `CoreError` enum with 6 `#[non_exhaustive]` variants (InvalidName, InvalidLabel, InvalidRecord, ZoneParse, WireFormat, Tsig) |
| `domain.rs` | `Label` newtype (63-byte max, RFC 1035) + `DomainName` newtype (253-char text / 255-octet wire max, case-insensitive `PartialEq`, label-boundary-aware `Hash`) |
| `record.rs` | `Ttl` (u32, RFC 8767 max), `Serial` (u32, RFC 1982 `PartialOrd` with wrapping), `RecordClass` (IN/CH/HS/ANY/Unknown), `ResourceRecord` struct |
| `rdata.rs` | `RecordData` enum with 21 DNS record type variants + Unknown, `#[non_exhaustive]` |
| `traits.rs` | 4 management traits with associated error types: `NamedControl`, `DynamicUpdater`, `ZoneManager`, `StatsClient` |
| `lib.rs` | Curated re-exports, `#![no_std]`, `#![forbid(unsafe_code)]` |

Re-export crate (`bind9-sdk/src/lib.rs`):

- `pub use bind9_sdk_core as core` + curated top-level re-exports
- Doc example in crate-level docs

Testing:

- Property-based testing established with proptest (label roundtrip, domain name display roundtrip, serial RFC 1982 arithmetic)
- All 57 tests passing across workspace

Key implementation decisions recorded as DEC-005 through DEC-008 (see §16).

**Deferred to Phase 1b**: `RdataLength` newtype (wire encoding context needed).

#### Phase 1b Wave 1: Zone Parser + TSIG + UpdateBuilder + Net Foundation — COMPLETED (2026-03-16)

**Branches**: `feat/zone-parser` (5 commits, 165 tests) + `feat/tsig-update-net` (3 commits, 144 tests) | **Status**: merged to `development`, clippy clean, WASM clean

Modules delivered in `crates/bind9-sdk-core/src/`:

| Module | What it provides |
| --- | --- |
| `zone/parser.rs` | Zone file tokenizer (comments, directives, parens, escapes) + record assembler (`$ORIGIN`, `$TTL`, `$INCLUDE`, owner name inheritance, relative→absolute resolution) |
| `zone/rdata_text.rs` | Text-format rdata parser/serializer for 10 record types (A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA) + RFC 3597 unknown type generic format |
| `zone/serializer.rs` | Zone file serializer (`ZoneFile` → text) with roundtrip property tests |
| `zone/mod.rs` | `ZoneFile` type, `IncludeResolver` trait, `ZoneManager` impl for `ZoneFile` |
| `tsig.rs` | `TsigAlgorithm` (SHA-1 deprecated, SHA-256, SHA-512), `TsigKey` (Zeroizing material, base64 decode, key generation), `TsigRecord` (RFC 8945 wire format), HMAC sign/verify |
| `update.rs` | `UpdateBuilder<Unsigned/Signed>` typestate, `Prerequisite` (RFC 2136 §2.4), `UpdateEntry` (add/delete), wire encoding for all 22 rdata variants |
| `domain.rs` | Added `DomainName::write_wire()` for DNS wire format encoding |

Modules delivered in `crates/bind9-sdk-net/src/`:

| Module | What it provides |
| --- | --- |
| `error.rs` | `NetError` enum with 7 `#[non_exhaustive]` variants (Connection, Protocol, Timeout, Auth, Tls, Http, UpdateRejected) |
| `tls.rs` | `TlsConfig` wrapping `rustls::ClientConfig` with explicit ring CryptoProvider |
| `config.rs` | `ClientConfig` (host, port, TLS, TSIG) + `Bind9Client` skeleton implementing all 4 management traits |

Testing: 225 core + 19 net + 1 doc = **245 tests passing** across workspace. Property tests include proptest fuzz for zone parser, TSIG sign/verify roundtrip.

Post-merge fixes (commit `1dde207`): Two CRITICAL findings from dialectic verification (Codex gpt-5.4 + GLM5) fixed immediately — (1) TSIG canonicalization: added `DomainName::write_wire_canonical()` for case-insensitive wire encoding per RFC 8945, (2) explicit timestamp parameter in `TsigRecord::sign()` instead of implicit `SystemTime::now()` (enables deterministic testing and `no_std` compatibility).

#### Phase 1b Wave 2: rndc Wire Protocol + Stats/nsupdate + Hardening — IN PROGRESS

Pre-fix (commit `fb83f0f`): Populated 4 placeholder structs with real fields on `development` — `ServerStatus` (version, running_since, reload_count, server_up, raw_text), `FrozenZone` (name, class), `ServerStats` (boot_time, config_time, current_time, version), `ZoneStats` (name, class, serial, record_count, zone_type). All `#[non_exhaustive]` for future extension. Re-exported from `bind9-sdk-core`.

Active worktrees (see `docs/plans/2026-03-16-wave2-review-remediation.md` for full breakdown):
- **WT-3** (`feat/rndc-protocol`): rndc wire protocol client (custom TCP framing, ISC message encoding) — IN PROGRESS, 4 chunks / 12 tasks
- **WT-4** (`feat/stats-nsupdate`): statistics-channel HTTP client + nsupdate sender — IN PROGRESS, 4 chunks / 15 tasks. Absorbs TSIG response verification (TSIG-002 HIGH), fudge window validation (TSIG-004), RFC 8945 known-answer vectors (TEST-001), TSIG wire parsing (TEST-002)
- **WT-5**: TSIG/update hardening — PLANNED (after WT-3 + WT-4 merge). Review findings: zeroize MAC/wire_bytes in TsigRecord (SEC-001), TsigRecord Debug redaction (SEC-002), key length validation warning (SEC-003), RRsetExistsWithData prerequisite (RFC2136-001), request_mac for multi-message TSIG (TSIG-005), exhaustive algorithm tests (TEST-003), update wire roundtrip tests (TEST-004)

## 13. Success Metrics

| Metric | Target | Measurement |
| --- | --- | --- |
| Runtime panics | 0 | proptest + 24h fuzz run before v1.0.0 |
| Zone parser roundtrip | 100% lossless | Property test `parse(serialize(zone)) == zone` |
| rndc RFC compliance | 100% commands verified | Integration tests against real BIND9 9.20 |
| WASM bundle size | < 500KB gzipped | CI artifact size check |
| docs.rs coverage | 100% public API | `cargo doc --no-deps -D missing_docs` |
| crates.io downloads | > 1K/month at v1.0.0 | crates.io stats |
| npm weekly downloads | > 500 at v1.0.0 | npm stats |
| MSRV | Rust 1.94 (edition 2024) | CI matrix |
| CLI startup | < 100ms | hyperfine in CI |

## 14. Non-Goals

- **DNS resolver** — `bind9-sdk` manages BIND9 servers; it does not resolve DNS queries for clients. Use `hickory-dns` for resolution.
- **BIND9 configuration file generation** — `named.conf` generation is out of scope. Zone files only.
- **Other authoritative servers** — PowerDNS, Knot DNS, NSD: not in scope. BIND9 only.
- **DNSSEC signing** — `bind9-sdk` reads and introspects DNSSEC state; it does not perform signing itself (BIND9 does that via KASP).
- **Recursive resolver management** — `allow-recursion`, views for caching: management is limited to authoritative server operations.
- **GUI / web UI** — library and CLI only.
- **Windows DNS Server** — Microsoft DNS is a different product with a different protocol.

## 15. Open Questions

| ID | Question | Owner | Deadline | Status |
| --- | --- | --- | --- | --- |
| OQ-001 | Can `bind9-sdk-core` be fully `no_std` + `alloc`? Zone parsing needs complex allocation — confirm no `std` leakage before v0.1.0 | Sephyi | 2026-04-01 | RESOLVED — confirmed in Phase 1a. `#![no_std]` + `extern crate alloc` works. `cargo check --target wasm32-unknown-unknown` passes. `core::error::Error` (stable since 1.81) used instead of `std::error::Error`. `thiserror` 2.x with `default-features = false` for no_std. |
| OQ-002 | napi-rs v3 produces both native and WASM from single binding layer. wasm-bindgen removed from architecture. | Sephyi | 2026-04-15 | RESOLVED — napi-rs v3 |
| OQ-003 | named.conf parser (FR-060): scope creep risk — how much of the named.conf grammar to support? Define explicit in-scope/out-of-scope boundary before v0.6.0 start. | Sephyi | Before v0.6.0 start | PENDING |
| OQ-004 | MSRV: edition 2024 + language features through 1.94. Acceptable? `rust-version = "1.94"` set. | Sephyi | 2026-04-01 | RESOLVED — 1.94 |
| OQ-005 | License: PolyForm-Noncommercial-1.0.0 is a placeholder. Open-source SDK (MIT/Apache 2.0) likely better for ecosystem adoption. Decide before first crates.io publish. | Sephyi | Before v0.1.0 publish | PENDING |
| OQ-006 | `bind9-sdk` npm package name: is `bind9-sdk` available on npm? Alternative: `@bind9-sdk/core`? | Sephyi | 2026-04-01 | PENDING |

## 16. Decisions Log

### DEC-001: BIND9 over Knot DNS

**Date**: 2026-03-14
**Context**: Choosing the target DNS server for the SDK
**Decision Drivers**: rndc protocol documentation quality, official OCI image availability, SDK ecosystem gap
**Options**:
1. BIND9 9.20
2. Knot DNS 3.x
**Chosen**: Option 1 — BIND9 9.20
**Outcome**: BIND9's rndc wire protocol is stable, documented in source, and has third-party implementation precedent. BIND9 has an official OCI image (`internetsystemsconsortium/bind9:9.20`). Knot DNS uses `knotc` over a Unix socket with no documented wire protocol for third-party clients. BIND9's statistics-channel is JSON and HTTP — directly consumable without custom protocol work.
**Consequences**: ✓ Stable, documented target / ✗ rndc is a custom TCP protocol (not HTTP/gRPC) — requires careful implementation
**Status**: ACCEPTED

### DEC-002: Rust as primary language; no Python

**Date**: 2026-03-14
**Context**: Language selection for SDK implementation
**Decision Drivers**: Performance, type safety, WASM compatibility, developer preference
**Chosen**: Rust — exclusively for implementation. Distribution targets: Rust crate (crates.io), Node.js/Bun native addon + browser WASM (napi-rs v3). No Python bindings.
**Consequences**: ✓ Single codebase for three runtimes / ✗ LiveKit voice agent must be built manually (no Python LiveKit Agents framework equivalent in Rust)
**Status**: ACCEPTED

### DEC-003: `bind9-sdk` as crate name (no `-rs` suffix)

**Date**: 2026-03-14
**Context**: Naming convention for crates.io + npm
**Chosen**: `bind9-sdk` — descriptive, no `-rs` suffix (language-decorating suffixes are redundant on crates.io and confusing on npm)
**Consequences**: ✓ Clean, ecosystem-consistent name / ✗ Must verify crates.io + npm availability before publish
**Status**: ACCEPTED

### DEC-004: Algorithm 13 (ECDSAP256SHA256) as default DNSSEC algorithm

**Date**: 2026-03-14
**Context**: Default DNSSEC signing algorithm for KASP introspection and CDS/CDNSKEY helpers
**Decision Drivers**: RFC 8624 recommendation, BIND9 9.20 default, resolver support matrix
**Chosen**: ECDSAP256SHA256 (Algorithm 13). Ed25519 (Algorithm 15) available but not default — incomplete resolver support as of 2026.
**Status**: ACCEPTED

> **Update (v0.2)**: This decision will be revisited. RFC 9904 (November 2025) supersedes the RFC 8624 guidance that DEC-004 relied on. Ed25519 (Algorithm 15) resolver support is now widespread. The preparation spec recommends defaulting to Ed25519 over Algorithm 13. See Compliance Requirements REQ-DNSSEC-1.

### DEC-005: `async fn` in traits (not desugared)

**Date**: 2026-03-14 (Phase 1a)
**Context**: The four management traits (`NamedControl`, `DynamicUpdater`, `ZoneManager`, `StatsClient`) use async methods. Two options: native `async fn` in traits (stable since Rust 1.75) or manual desugaring with `Pin<Box<dyn Future>>`.
**Chosen**: Native `async fn` in traits with `#![allow(async_fn_in_trait)]` — static dispatch only. No `dyn Trait` usage planned for these traits; consumers use generics or concrete types.
**Consequences**: Simpler trait definitions, no boxing overhead. If dynamic dispatch is ever needed, a separate `DynZoneManager` wrapper with boxed futures can be added without breaking the static-dispatch API.
**Status**: ACCEPTED

### DEC-006: `core::error::Error` over `std::error::Error`

**Date**: 2026-03-14 (Phase 1a)
**Context**: `bind9-sdk-core` is `#![no_std]`. Error types need `Error` trait impl. `core::error::Error` was stabilized in Rust 1.81, well below the project MSRV of 1.85/1.94.
**Chosen**: Use `core::error::Error` unconditionally in `bind9-sdk-core`. The `std` feature flag on the crate opts back in to `std::error::Error` for consumers who want it.
**Consequences**: No feature-gating gymnastics for error impls. All error types work in `no_std` by default.
**Status**: ACCEPTED

### DEC-007: `thiserror` 2.x with `default-features = false`

**Date**: 2026-03-14 (Phase 1a)
**Context**: `thiserror` 1.x required `std`. `thiserror` 2.x supports `no_std` via `default-features = false`. Alternative: hand-write `Display` + `Error` impls.
**Chosen**: `thiserror` 2.x with `default-features = false` in `bind9-sdk-core`. Reduces boilerplate while maintaining `no_std` compatibility.
**Consequences**: One additional dependency in core, but `thiserror` is widely trusted and the `no_std` support is clean.
**Status**: ACCEPTED

### DEC-008: RRSIG `original_ttl` as raw `u32` (not `Ttl` newtype)

**Date**: 2026-03-14 (Phase 1a)
**Context**: `RecordData::Rrsig` contains an `original_ttl` field. Two options: wrap it in the `Ttl` newtype (which enforces RFC 8767 max) or use raw `u32` for wire fidelity.
**Chosen**: Raw `u32`. The RRSIG `original_ttl` is a wire-format field that records the TTL at signing time. It must round-trip exactly as received, even if the value exceeds the SDK's recommended TTL range. Applying `Ttl` validation would reject valid signed records from other implementations.
**Consequences**: Wire fidelity preserved. The `Ttl` newtype is used for user-facing TTL values (e.g., in `ResourceRecord`), while RRSIG's `original_ttl` stays as the raw wire value.
**Status**: ACCEPTED

## 17. Assumptions & Dependencies

| ID | Type | Assumption | Consequence if Wrong |
| --- | --- | --- | --- |
| ASSM-001 | Technical | BIND9 9.20 rndc wire protocol is stable and will not change in 9.20.x patch releases | Patch releases break rndc client — requires version-gated protocol handling |
| ASSM-002 | Technical | **CONFIRMED (Phase 1a)**: `bind9-sdk-core` compiles as `no_std + alloc` without losing functionality. `core::error::Error`, `thiserror` 2.x no_std, WASM target all clean. | Zone parser or record types require std — must move affected code to `bind9-sdk-net` or add `std` feature gate |
| ASSM-003 | Technical | napi-rs pre-built binary distribution covers > 95% of Node.js consumer platforms | Consumers on unsupported platforms must build from source — degrades DX |
| ASSM-004 | Business | Zero maintained npm packages for BIND9 management remain as of v0.1.0 publish | Competition exists — differentiate on Rust-native quality, not gap alone |
| ASSM-005 | Dependency | BIND9 9.20 statistics-channel JSON schema does not change between 9.20.x releases | Stats client deserialization breaks on schema change — version detection needed |
| ASSM-006 | User | Primary consumers are self-hosters and infrastructure automation engineers, not browser app developers | Browser WASM investment (Phase 3) under-utilized — deprioritize Phase 3 and shift resources to CLI (Phase 5) |

## Appendix A: Competitive Feature Matrix

| Feature | bind9-sdk | octodns-bind | dnspython | isc-bind-api | hickory-dns |
| --- | --- | --- | --- | --- | --- |
| **Language** | Rust + WASM + Node | Python | Python | Python | Rust |
| **rndc wire protocol** | Yes (FR-004) | No | No | No | No |
| **Zone file parser** | Yes (FR-001) | Via dnspython | Yes | No | No |
| **nsupdate (RFC 2136)** | Yes (FR-010) | Via dnspython | Yes | Partial | No |
| **IXFR/AXFR client** | Yes (FR-011) | AXFR only | Yes | No | Partial |
| **Statistics-channel** | Yes (FR-006) | No | No | No | No |
| **DNSSEC utilities** | Yes (FR-020–022) | No | Partial | No | Partial |
| **WASM / browser** | Yes (FR-030) | No | No | No | No |
| **npm package** | Yes (FR-041) | No | No | No | No |
| **named.conf parser** | Yes (FR-060) | No | No | No | No |
| **CLI tool** | Yes (FR-050) | No | No | No | No |
| **Maintained 2026** | New | Yes | Yes | No (last: 2022) | Yes |
| **Zero shell deps** | Yes | No | No | No | N/A |

## Appendix B: Research Sources

1. `bind9-dns-management-2026.md` — BIND9 9.20 research including rndc protocol, KASP, statistics-channel JSON schema, Podman rootless deployment, NSEC3 RFC 9276 best practices
2. ISC BIND 9.20 source — rndc wire protocol specification, statistics-channel JSON schema
3. npm registry survey — confirmed zero maintained BIND9 management packages as of March 2026
4. See **Appendix C** for the full RFC reference table with per-FR traceability.

## Appendix C: RFC Reference

RFCs implemented or referenced by bind9-sdk, with traceability to feature requirements.

### Standard Protocol RFCs

| RFC | Title | Status | Module | FRs |
| --- | --- | --- | --- | --- |
| RFC 1034 | Domain Names: Concepts and Facilities | Internet Standard | `bind9-sdk-core::domain` | FR-001, FR-003 |
| RFC 1035 | Domain Names: Implementation and Specification | Internet Standard | Zone parser/serializer, wire encoder/decoder | FR-001, FR-002, FR-003, FR-061 |
| RFC 1982 | Serial Number Arithmetic | Internet Standard | SOA serial strategies | FR-012 |
| RFC 1995 | Incremental Zone Transfer in DNS (IXFR) | Proposed Standard | `bind9-sdk-net::transfer` | FR-011 |
| RFC 2136 | Dynamic Updates in the Domain Name System (DNS UPDATE) | Proposed Standard | `bind9-sdk-core::update`, `bind9-sdk-net::nsupdate` | FR-008, FR-010, FR-051 |
| RFC 2181 | Clarifications to the DNS Specification | Internet Standard | Zone parser, `DomainName` validation | FR-001, FR-003 |
| RFC 2782 | DNS RR for Specifying the Location of Services (SRV) | Internet Standard | `RecordData::Srv` | FR-003 |
| RFC 3007 | Secure Dynamic Update | Internet Standard | `bind9-sdk-net::nsupdate` (TSIG-signed updates) | FR-010 |
| RFC 3596 | DNS Extensions to Support IP Version 6 (AAAA) | Internet Standard | `RecordData::Aaaa` | FR-001, FR-003 |
| RFC 5936 | DNS Zone Transfer Protocol (AXFR) | Proposed Standard | `bind9-sdk-net::transfer` | FR-011 |
| RFC 6891 | Extension Mechanisms for DNS — EDNS(0) | Internet Standard | OPT record in TSIG messages | FR-008, FR-010 |
| RFC 9499 | DNS Terminology (March 2024) | BCP 219 | Terminology reference throughout. Supersedes RFC 8499 | — |
| RFC 1996 | DNS NOTIFY | Proposed Standard | Zone transfer trigger logic | FR-011 |
| RFC 7766 | DNS Transport over TCP | Proposed Standard | Normative TCP behavior for rndc, nsupdate, IXFR/AXFR | FR-004, FR-010, FR-011 |
| RFC 9103 | Zone Transfer over TLS (XoT) | Proposed Standard | Default transport for non-localhost transfers | FR-011 |
| RFC 9210 | DNS Transport over TCP — Operational Requirements | BCP 235 | TCP operational requirements for `bind9-sdk-net` | FR-004, FR-010, FR-011 |
| RFC 4343 | Domain Name System Case Insensitivity Clarification | Proposed Standard | `DomainName` comparison semantics | FR-003 |

### DNSSEC RFCs

| RFC | Title | Status | Module | FRs |
| --- | --- | --- | --- | --- |
| RFC 4034 | Resource Records for the DNS Security Extensions (DNSKEY, RRSIG, NSEC, DS) | Internet Standard | `bind9-sdk-core::record::dnssec` | FR-003, FR-020, FR-021 |
| RFC 5011 | Automated Updates of DNS Security Trust Anchors | Internet Standard | `bind9-sdk-net::rndc` (DNSSEC state introspection) | FR-071 |
| RFC 5155 | DNS Security Hashed Authenticated Denial (NSEC3, NSEC3PARAM) | Internet Standard | `bind9-sdk-core::record::dnssec` | FR-003, FR-020 |
| RFC 6605 | Elliptic Curve DSA for DNSSEC (ECDSAP256SHA256, ECDSAP384SHA384) | Internet Standard | `RecordData::Dnskey` algorithm field | FR-003, FR-020 |
| RFC 6781 | DNSSEC Operational Practices | Informational | Key rollover design reference | FR-071 |
| RFC 7344 | Automating DNSSEC Delegation Trust Maintenance (CDS, CDNSKEY) | Internet Standard | `RecordData::Cds`, `RecordData::Cdnskey` | FR-003, FR-020, FR-022 |
| RFC 8078 | Managing DS Records from the Parent via CDS/CDNSKEY | Internet Standard | `bind9-sdk-core::dnssec::cds` | FR-022 |
| RFC 8080 | Edwards-Curve Digital Security Algorithm for DNSSEC (ED25519, ED448) | Internet Standard | `RecordData::Dnskey` algorithm field | FR-003, FR-020 |
| RFC 9904 | DNSSEC Algorithm Implementation Requirements (November 2025) | BCP | Algorithm ordering and default selection. Supersedes RFC 8624 — DNSSEC algorithm recommendation process | FR-020, FR-071 |
| RFC 9276 | Guidance for NSEC3 Parameter Settings | BCP | iterations=0, no-salt defaults | FR-020 |
| RFC 4033 | DNS Security Introduction and Requirements | Proposed Standard | Context for DNSSEC (RFC 4034/4035) | FR-020 |
| RFC 4035 | Protocol Modifications for the DNS Security Extensions | Proposed Standard | DO/AD/CD bits, NSEC chain validation | FR-020 |
| RFC 6840 | Clarifications and Implementation Notes for DNS Security (DNSSEC) | Proposed Standard | Updates to RFC 4033/4034/4035/5155 | FR-020 |
| RFC 7477 | Child-to-Parent Synchronization in DNS (CSYNC) | Proposed Standard | `RecordData::Csync` variant | FR-003 |
| RFC 9615 | Automatic DNSSEC Bootstrapping using Authenticated Signals from the Zone's Operator (July 2024) | Proposed Standard | Updates CDS/CDNSKEY chain | FR-022 |
| RFC 9859 | Generalized DNS Notifications (September 2025) | Proposed Standard | BIND9 9.21 support shipped. SDK targets BIND9 9.20 initially; track as future/informational until 9.21 is baseline | — |
| RFC 9077 | NSEC and NSEC3: TTLs and Aggressive Use | Proposed Standard | NSEC TTL capped at SOA minimum | FR-020 |
| RFC 4509 | Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records | Proposed Standard | DS record construction | FR-020, FR-022 |
| RFC 5702 | Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC | Proposed Standard | DNSKEY/RRSIG algorithm support | FR-020 |

### TSIG Authentication RFCs

| RFC | Title | Status | Module | FRs |
| --- | --- | --- | --- | --- |
| RFC 2845 | Secret Key Transaction Authentication for DNS (TSIG) | **Obsoleted by RFC 8945** | — | — |
| RFC 8945 | Secret Key Transaction Authentication for DNS (TSIG) | Internet Standard | `bind9-sdk-core::tsig` | FR-007, FR-008, FR-010 |

> **Historical note**: RFC 4635 (HMAC SHA TSIG Algorithm Identifiers) defined the HMAC-SHA256 and HMAC-SHA512 algorithm names for TSIG. Its content has been absorbed by RFC 8945, which is now the sole normative reference for TSIG authentication in this SDK.

### Informational & Operational RFCs

| RFC | Title | Status | Why |
| --- | --- | --- | --- |
| RFC 2308 | Negative Caching of DNS Queries | Proposed Standard | SOA minimum TTL semantics |
| RFC 7583 | DNSSEC Key Rollover Timing Considerations | Informational | Required for FR-071 automated rollover |
| RFC 8901 | Multi-Signer DNSSEC Models | Informational | Maps to hidden-primary architecture |

### Application Record RFCs

| RFC | Title | Status | Module | FRs |
| --- | --- | --- | --- | --- |
| RFC 4255 | Using DNS to Securely Publish SSH Key Fingerprints (SSHFP) | Internet Standard | `RecordData::Sshfp` | FR-003 |
| RFC 6698 | The DNS-Based Authentication of Named Entities (DANE) — TLSA | Internet Standard | `RecordData::Tlsa` | FR-003 |
| RFC 8659 | DNS Certification Authority Authorization (CAA) | Internet Standard | `RecordData::Caa` | FR-003 |

### ISC BIND Proprietary Protocols (no RFC)

| Protocol | Specification | FRs |
| --- | --- | --- |
| rndc wire protocol | BIND9 source (`lib/isc/netmgr/`) — 4-byte BE length prefix + ISC internal message encoding + HMAC-SHA256 authentication | FR-004, FR-005 |
| BIND9 statistics-channel | ISC-defined JSON schema served over HTTP — documented in BIND 9 ARM (Administrator Reference Manual) | FR-006 |
| BIND9 named.conf grammar | ISC-defined configuration language — partially parsed for SDK auto-discovery (FR-060 scope only) | FR-060 |
| BIND9 views | ISC extension — multiple logical DNS views per `named` instance, not standardized by any RFC | FR-070 |
