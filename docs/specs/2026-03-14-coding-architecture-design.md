<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# bind9-sdk Coding Architecture Design

**Date**: 2026-03-14  
**Status**: Draft  
**Scope**: Core design principles, type patterns, error strategy, module organization, trait design, observability, testing patterns  

## 1. Core Design Principles

Three principles govern all implementation decisions. They are ordered by priority — when in conflict, earlier principles take precedence.

### 1.1 Make Invalid States Unrepresentable

The type system is the first line of defense. If invalid data cannot be constructed, it cannot propagate.

- Newtypes wrap primitives to enforce domain invariants at compile time
- Typestate generics restrict method availability to valid lifecycle phases
- Enums with data-carrying variants replace stringly-typed fields

### 1.2 Parse, Don't Validate

External input crosses a trust boundary exactly once: at construction. After parsing into a typed value, no re-validation is needed.

- Constructors return `Result<T, CoreError>` — never infallible for external input
- Once a value exists as a typed struct, all consumers trust it unconditionally
- Wire bytes, zone file text, rndc responses, and napi-rs inputs are all untrusted until parsed

### 1.3 Compose, Don't Inherit

Rust has no inheritance. Composition via traits and generics replaces class hierarchies. This principle also means:

- No trait hierarchies deeper than one level of supertraits
- No God objects — small, focused types composed via struct fields
- No premature abstraction — three concrete uses before extracting a trait

## 2. Type Design Patterns

### 2.1 Newtypes

Wrap primitives in domain types to prevent misuse at compile time. Each newtype validates on construction and is trusted thereafter (§1.2).

| Newtype | Wraps | Invariants |
| --- | --- | --- |
| `DomainName` | `String` | RFC 1035 §2.3.1 syntax, ≤255 octets, labels ≤63 bytes |
| `Label` | `String` | Single DNS label, ≤63 bytes, valid characters |
| `Ttl` | `u32` | 0–2147483647 (RFC 8767) |
| `Serial` | `u32` | RFC 1982 wrap-around arithmetic (`Add`, `PartialOrd`) |
| `RecordClass` | `u16` | Valid IANA class (IN, CH, HS, ANY) |
| `RdataLength` | `u16` | Wire format RDLENGTH bound |

### 2.2 Typestate Pattern

Use generic type parameters to encode lifecycle state at compile time. Methods are available only in the correct state — misuse is a compile error, not a runtime error.

**Apply typestate to:**

- `UpdateBuilder<Unsigned>` / `UpdateBuilder<Signed>` — RFC 2136 message construction. `.sign(key)` transitions `Unsigned` → `Signed`. Only `Signed` exposes `.build()`.
- `RndcConnection<Unauthenticated>` / `RndcConnection<Authenticated>` — rndc TCP session. `.authenticate(key)` transitions state. Only `Authenticated` exposes `.command()`.
- `TransferSession<Pending>` / `TransferSession<Active>` — AXFR/IXFR. `.start()` transitions state. Only `Active` exposes `.next_record()`.

**Do NOT apply typestate to:**

- `TsigKey` — a value object, no lifecycle
- `ResourceRecord` — a data container, no state machine
- Config structs — builder pattern is sufficient

### 2.3 Secret-Bearing Types

Types that hold cryptographic key material require special treatment:

- **Manual `Debug` impl** with redaction (`"[REDACTED]"`) — never `#[derive(Debug)]` on key types
- **Manual `Display` impl** — same redaction rule
- **`ZeroizeOnDrop`** derive from the `zeroize` crate — key bytes are zeroed when the value is dropped
- **No `Clone`** — cloning defeats zeroization tracking; use `&self` references instead
- **Never in logs** — `tracing` fields must not include key material

Applies to: `TsigKey`, `RndcKey`, any struct with `key_material`, `secret`, or `hmac_key` fields.

**Interaction with mocks (§7.4):** Secret-bearing types are inputs to operations (signing, authentication), never return values from trait methods. Mock testing (§7.4) uses `.clone()` on result types like `ServerStatus` — these are plain data, not secrets. No conflict with the `No Clone` rule.

## 3. Error Design

One `#[non_exhaustive]` error enum per crate, using `thiserror`. Variants are split by actionability — callers can match on what they can handle and wildcard the rest.

**`no_std` note:** `bind9-sdk-core` uses `thiserror` 2.x with `default-features = false` to avoid pulling in `std`. This is required for WASM target compilation.

### 3.1 `CoreError` (bind9-sdk-core)

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    #[error("invalid domain name: {reason}")]
    InvalidName { name: String, reason: String },

    #[error("invalid record data: {0}")]
    InvalidRecord(String),

    #[error("zone parse error at line {line}: {reason}")]
    ZoneParse { line: u32, reason: String },

    #[error("wire format error: {0}")]
    WireFormat(String),

    #[error("TSIG error: {0}")]
    Tsig(String),
}
```

### 3.2 `NetError` (bind9-sdk-net)

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    #[error("connection failed: {0}")]
    Connection(String),

    #[error("request timed out after {0:?}")]
    Timeout(core::time::Duration),

    #[error("rndc authentication failed")]
    AuthFailed,

    #[error("rndc protocol error: {0}")]
    Protocol(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error(transparent)]
    Core(#[from] CoreError),
}
```

### 3.3 Error Principles

- **No `anyhow`** in library code — `anyhow` is for applications, not libraries
- **No `Box<dyn Error>`** — callers lose the ability to match on variants
- **Error messages never contain key material** — enforced by §2.3 redaction rules
- **`#[non_exhaustive]`** on both enums — adding variants is a non-breaking change

### 3.4 Bindings Error Mapping

`bind9-sdk-bindings` does not define its own error enum. Instead, it maps `CoreError` and `NetError` into JavaScript exceptions at the napi-rs boundary using `napi::Error::from_reason()`. WASM builds map `CoreError` into a `BindSdkError` JS class with `.message` and `.code` fields. The conversion is a one-way mapping at the FFI edge — no Rust-side `BindingsError` type is needed.

## 4. Module Organization

### 4.1 bind9-sdk-core

```txt
crates/bind9-sdk-core/src/
├── lib.rs          ← pub mod declarations, #![no_std], extern crate alloc
├── error.rs        ← CoreError enum
├── domain.rs       ← DomainName, Label newtypes
├── record.rs       ← ResourceRecord, RecordClass, Ttl, Serial
├── rdata.rs        ← RecordData enum (20+ variants, #[non_exhaustive])
├── zone.rs         ← ZoneFile struct, zone parser, zone emitter
├── update.rs       ← UpdateBuilder<State>, UpdateMessage (RFC 2136)
├── tsig.rs         ← TsigKey, HMAC signing, TSIG record construction
└── traits.rs       ← NamedControl, DynamicUpdater, ZoneManager, StatsClient trait definitions
```

### 4.2 bind9-sdk-net

```txt
crates/bind9-sdk-net/src/
├── lib.rs          ← pub mod declarations
├── error.rs        ← NetError enum
├── rndc.rs         ← RndcConnection<State>, rndc wire protocol client
├── nsupdate.rs     ← NsUpdateSender, RFC 2136 send over UDP/TCP
├── transfer.rs     ← TransferSession<State>, AXFR/IXFR client
├── stats.rs        ← StatsHttpClient, statistics-channel JSON API
├── tls.rs          ← TLS configuration (see §4.3)
└── config.rs       ← Bind9Client, connection pool, shared config
```

### 4.3 TLS Module (`tls.rs`)

Handles all secure transport concerns per PRD REQ-TLS-1 through REQ-TLS-3:

- **`rustls`** as the TLS backend — `reqwest` uses `rustls-tls` feature, never `native-tls`
- **TLS 1.3 only** — no TLS 1.2 fallback. Configured via `rustls::ClientConfig` with `protocol_versions: &[&rustls::version::TLS13]`
- **Cipher suites** — AES-256-GCM and ChaCha20-Poly1305 only
- **Certificate validation** — strict by default via `webpki` roots. No `danger_accept_invalid_certs` in any code path
- **TOFU/SPKI pinning** — optional, for environments without a CA. Pin comparison must be constant-time
- **Localhost exemption** — non-TLS connections permitted only when the peer resolves to a loopback address (`127.0.0.0/8`, `::1`). Enforced by checking the resolved address, not the hostname string
- **XoT (DNS over TLS, RFC 9103)** — used for AXFR/IXFR zone transfers to non-localhost peers. The `TransferSession` typestate enforces that non-localhost transfers start in a TLS-wrapped state

### 4.4 File Size Policy

- **Target**: 200–300 lines per file
- **Hard split at**: ~400 lines — extract a submodule
- **Rationale**: Smaller files are easier to reason about, review, and hold in context. This is a guideline, not a linter rule — a 410-line file with cohesive content is fine.
- **Expected early splits**: `rdata.rs` (20+ enum variants) will likely need a `rdata/` submodule directory during implementation. This is expected, not a design failure.

## 5. Trait Design & Composition

### 5.1 Management Traits

Four async traits define the SDK's management API. They live in `core` (for mock testability) but use associated error types to avoid circular dependencies with `net`.

**Note on PRD divergence:** The PRD §3.2 sketches broader trait signatures (e.g., `DynamicUpdater` with `add_record`/`delete_record`/`replace_record`). This spec deliberately consolidates those into `send_update(&UpdateMessage)` — the builder pattern (§2.2) handles add/delete/replace semantics via `UpdateBuilder`, and the trait receives the fully constructed message. Similarly, `NamedControl` consolidates PRD's `command` into typed methods (`status`, `reload`, `freeze`) to prevent stringly-typed dispatch. These are intentional refinements, not omissions.

```rust
// crates/bind9-sdk-core/src/traits.rs

pub trait NamedControl: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn status(&self) -> Result<ServerStatus, Self::Error>;
    async fn reload(&self) -> Result<(), Self::Error>;
    async fn reload_zone(&self, zone: &DomainName) -> Result<(), Self::Error>;
    async fn freeze(&self, zone: &DomainName) -> Result<FrozenZone, Self::Error>;
}

pub trait DynamicUpdater: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn send_update(&self, update: &UpdateMessage) -> Result<UpdateResult, Self::Error>;
}

pub trait ZoneManager: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn list_zones(&self) -> Result<Vec<ZoneSummary>, Self::Error>;
    async fn get_zone(&self, name: &DomainName) -> Result<Zone, Self::Error>;
}

pub trait StatsClient: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn server_stats(&self) -> Result<ServerStats, Self::Error>;
    async fn zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, Self::Error>;
}
```

### 5.2 Associated Error Types

The associated `type Error` avoids a circular dependency:

- `core` defines trait shapes without referencing `NetError`
- `net::Bind9Client` implements all four traits with `type Error = NetError`
- Test mocks implement with `type Error = CoreError` or a custom test error
- `core::ZoneFile` implements `ZoneManager` with `type Error = CoreError` for local file operations

**Async in `no_std`:** The traits use `async fn`, which compiles in `no_std` (it desugars to `core::future::Future`). The `ZoneFile` implementation returns immediately-ready futures — no executor needed for local operations. WASM callers can `.await` these through any minimal executor or poll them directly.

### 5.3 Concrete Implementations

**`Bind9Client`** (in `net`) — one struct implements all four network-backed traits:

```rust
// crates/bind9-sdk-net/src/config.rs

pub struct Bind9Client {
    // Connection pool, TLS config, rndc key, timeouts
    // Internal synchronization via tokio primitives
}

impl NamedControl for Bind9Client {
    type Error = NetError;
    // ...
}

impl DynamicUpdater for Bind9Client {
    type Error = NetError;
    // ...
}
// etc.
```

**`ZoneFile`** (in `core`) — local zone file operations without network:

```rust
// crates/bind9-sdk-core/src/zone.rs

pub struct ZoneFile {
    // Parsed zone data, file path or in-memory content
}

impl ZoneManager for ZoneFile {
    type Error = CoreError;

    async fn list_zones(&self) -> Result<Vec<ZoneSummary>, CoreError> { /* ... */ }
    async fn get_zone(&self, name: &DomainName) -> Result<Zone, CoreError> { /* ... */ }
}
```

This enables the WASM/browser use case: zone file parsing and editing works without `net`.

### 5.4 Method Signatures

- **`&self`**, not `&mut self` — internal synchronization via tokio mutex / connection pool. Callers can share a `Bind9Client` across tasks without external locking.
- **`Send + Sync` bounds** on all traits — required for `dyn Trait` in async contexts and for implementations to be shared across tokio tasks.

## 6. Observability

### 6.1 `tracing` Integration

The SDK instruments all operations with the `tracing` crate. The library emits events and spans — consumers configure subscribers (formatting, filtering, export).

- **Async operations**: wrapped in `tracing::instrument` spans with relevant context (zone name, command, peer address)
- **Request/response pairs**: `DEBUG` level spans with timing
- **Authentication events**: `INFO` level (success) / `WARN` level (failure), never including key material
- **Wire protocol details**: `TRACE` level for message hex dumps (excluding TSIG key bytes)

### 6.2 Log Levels

| Level | What |
| --- | --- |
| `ERROR` | Unrecoverable failures (connection lost, auth rejected) |
| `WARN` | Recoverable issues, weak algorithm warnings, deprecated features |
| `INFO` | Lifecycle events (connected, authenticated, transfer complete) |
| `DEBUG` | Request/response details, timing, retry attempts |
| `TRACE` | Wire bytes, parser internals, state machine transitions |

### 6.3 Structured Fields

All `tracing` events use structured fields, not interpolated strings. This enables machine-parseable output for SIEM integration (PRD §8.4).

```rust
tracing::info!(
    zone = %zone_name,
    command = "reload",
    result = "success",
    "rndc command completed"
);
```

### 6.4 Security Logging Constraints

- TSIG key material, private key bytes: **never** in any log field at any level
- Client IP addresses from stats-channel: **not logged by default** (GDPR, PRD §8.6)
- Authentication failures: log peer address, algorithm, failure reason — never the key

## 7. Testing Patterns

### 7.1 Unit Tests

Co-located in source files under `#[cfg(test)] mod tests`. One test module per source file.

### 7.2 Property-Based Testing (proptest)

For invariants that must hold across all inputs:

- **Wire format roundtrip**: `encode(decode(bytes)) == bytes` for all valid DNS messages
- **Text format roundtrip**: `parse(display(name)) == name` for DomainName
- **Serial arithmetic**: RFC 1982 comparison properties across wrap boundary
- **RDATA length consistency**: encoded RDATA length matches RDLENGTH field

### 7.3 Snapshot Testing (insta)

For serialization stability:

- Zone file output format
- JSON stats response parsing
- Error message formatting (prevents accidental key material leaks in error strings)

### 7.4 Mock Testing

Hand-written mock structs implementing the management traits (§5). No `mockall` dependency — the associated error types make manual mocks straightforward:

```rust
#[cfg(test)]
struct MockNamedControl {
    status_result: Result<ServerStatus, CoreError>,
}

impl NamedControl for MockNamedControl {
    type Error = CoreError;

    async fn status(&self) -> Result<ServerStatus, CoreError> {
        self.status_result.clone()
    }
    // ...
}
```

### 7.5 Integration Tests

Live BIND9 instance tests, gated behind `#[ignore]`:

- `tests/` directory at workspace root
- Require BIND9 on localhost:953 with test rndc key
- CI runs these against a Podman container

### 7.6 Testing Distribution

| Layer | Technique | Why |
| --- | --- | --- |
| Newtypes (§2.1) | Proptest | Validate invariants across input space |
| Wire format | Proptest + insta | Roundtrip correctness + format stability |
| Zone parser | Proptest + insta | Roundtrip + output stability |
| Trait impls | Hand-written mocks | Test business logic without network |
| rndc protocol | Integration tests | Wire compatibility with real BIND9 |
| Error formatting | Insta snapshots | Prevent key material leaks in messages |
| `#![forbid(unsafe_code)]` | CI / compile-time | Enforced in `core` and `net` crate roots |

## 8. Guiding Principles Summary

### Apply

| Principle | Meaning in This Codebase |
| --- | --- |
| KISS | Start with the simplest correct implementation. Escalate complexity only when a test or requirement demands it. |
| YAGNI | No abstractions for hypothetical future requirements. Three concrete uses before extracting a shared pattern. |
| Parse, don't validate | External input crosses a trust boundary once at construction. After that, types are trusted. |
| Make invalid states unrepresentable | If the type system can prevent a bug, it must. Runtime checks are a fallback, not a first choice. |
| Composition over inheritance | Small, focused types composed via struct fields and trait implementations. No deep hierarchies. |
| `no_std` discipline | `bind9-sdk-core` compiles without `std`. Enforced by WASM target check hook. |
| Minimum viable API surface | Start with the smallest useful public API. Expanding is non-breaking; shrinking is breaking. |

### Defer

| Item | Reason |
| --- | --- |
| Parallelism architecture (PRD §3.5) | Implementation detail for zone parsing. Decide during Phase 1 when profiling data exists. |
| Zero-copy parsing (`bytes` crate) | Performance optimization. Start with owned types, profile, optimize if needed. |
| Custom proc macros | Complexity not justified until the pattern appears 5+ times. |
| Forward-integrity log ratchet (PRD §8.4, REQ-LOG-3) | Complex cryptographic design (per-entry MAC key derivation). Deferred to a dedicated logging spec when the `tracing` integration (§6) is implemented. |
| `unsafe` code | Forbidden in `core` and `net` (`#![forbid(unsafe_code)]`). Permitted only in `bindings` crate for FFI, with safety comments. |
| `SecurityWarning` system (PRD REQ-SEC-DEFAULT-3) | Cross-cutting concern affecting errors, traits, and observability. Will be designed when the first algorithm-negotiation code is written (TSIG key construction). |

## 9. Re-Export Strategy

`bind9-sdk` is the only user-facing crate. It re-exports through two layers:

1. **Curated top-level re-exports** for the most common types (DomainName, ResourceRecord, Bind9Client, error types, traits)
2. **Module-level re-exports** for full access: `pub use bind9_sdk_core as core` and `pub use bind9_sdk_net as net`

Users write `use bind9_sdk::DomainName` for common types, or `use bind9_sdk::core::rdata::RecordData` for deep access.

**Stability:** The curated top-level re-exports are covered by semver. The `core` and `net` module re-exports are documented as **unstable escape hatches** — internal crate paths may change between minor versions. Module-level docs will carry a warning: "Paths under `bind9_sdk::core` and `bind9_sdk::net` are not covered by semver guarantees. Prefer top-level imports."
