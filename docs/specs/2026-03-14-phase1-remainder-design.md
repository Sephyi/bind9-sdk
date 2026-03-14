<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Phase 1 Remainder — Parallel Execution Design

**Date**: 2026-03-14
**Status**: Draft
**Scope**: Complete Phase 1 (v0.1.0) — zone parser/serializer, TSIG crypto, RFC 2136 builder, rndc wire protocol, stats-channel HTTP, nsupdate sender
**Depends on**: Phase 1a Core Foundation (completed), Coding Architecture Spec

## 1. Executive Summary

Phase 1a delivered the core type system (DomainName, Label, ResourceRecord, RecordData, Ttl, Serial, RecordClass), error types, and management traits. This spec covers everything remaining for v0.1.0: zone file parsing/serialization, TSIG cryptographic signing, RFC 2136 dynamic update construction, the rndc wire protocol client, statistics-channel HTTP client, and nsupdate sender.

The work is organized into two waves of two parallel git worktrees each. Each worktree gets its own feature branch and implementation plan, executed via subagent-driven-development. After both worktrees in a wave complete, they merge sequentially into `development`.

**PRD adjustment**: nsupdate sender (FR-010) is moved from Phase 2 to Phase 1. IXFR/AXFR transfer client (FR-011) remains Phase 2. This gives v0.1.0 a complete control + update workflow without the complexity of zone transfers.

**Review-driven changes** (from dialectic verification — Claude spec reviewer + Gemini 3 Pro):
- `getrandom` replaced with feature-gated randomness: `TsigKey::generate()` requires `std`, WASM gets deterministic `with_id()` constructors
- Placeholder types from Phase 1a explicitly migrated in pre-worktree setup
- `ZoneFile` changed from `Vec<Zone>` to single `Zone` (RFC 1035 = one zone per file)
- `RndcConnection::command()` uses `&mut self` (TCP is mutable state)
- `RecordType` enum added to core for type-safe prerequisites
- `Rcode` enum moved to core (`protocol.rs`)
- `TsigKey::key_material` uses `Zeroizing<Vec<u8>>` (not raw `Vec<u8>`)
- `HmacSha1` added as `#[deprecated]` for legacy BIND9 compatibility
- `IncludeResolver` trait added for pluggable `$INCLUDE` handling
- rdata text parsing prioritized: common types first (A/AAAA/NS/SOA/MX/CNAME/TXT/SRV/PTR/CAA), remaining types follow

## 2. Wave Structure

```
Wave 1 (parallel)
├── WT-1: Zone parser + serializer     (core/zone/)
│   Branch: feat/zone-parser
│   Scope: RFC 1035 master file parsing, zone serialization,
│          ZoneFile/Zone/ZoneSummary types, RecordData text parsing
│
└── WT-2: TSIG + UpdateBuilder + Net foundation
    Branch: feat/tsig-update-net
    Scope: TsigKey + HMAC signing, UpdateBuilder<State> typestate,
           NetError, TLS config, Bind9Client skeleton

    ─── merge both into development ───

Wave 2 (parallel, depends on Wave 1)
├── WT-3: rndc wire protocol           (net/rndc/)
│   Branch: feat/rndc-protocol
│   Scope: 4-byte framing, ISC message encoding, RndcCommand enum,
│          RndcConnection<State> typestate, HMAC authentication
│
└── WT-4: Stats HTTP + nsupdate sender (net/stats.rs, net/nsupdate.rs)
    Branch: feat/stats-nsupdate
    Scope: reqwest-based stats-channel JSON client, UDP/TCP update sender

    ─── merge both into development ───
```

## 3. Stream A — Zone Parser + Serializer (WT-1)

### 3.1 Scope

Build a complete RFC 1035 master file format parser and serializer in `bind9-sdk-core`. This is the largest single piece in Phase 1.

### 3.2 File Structure

```
crates/bind9-sdk-core/src/
├── zone/
│   ├── mod.rs          — ZoneFile, Zone, ZoneSummary public types
│   ├── parser.rs       — tokenizer + parser state machine
│   ├── serializer.rs   — zone file text emitter
│   └── rdata_text.rs   — RecordData ↔ zone file text conversion
├── protocol.rs         — RecordType enum, Rcode enum (shared DNS protocol types)
└── lib.rs              — update: pub mod zone; pub mod protocol;
```

The `zone/` submodule split follows the architecture spec's file size policy (§4.4: split at ~400 lines). The parser and serializer alone will each exceed 300 lines.

### 3.3 Types

**ZoneSummary** — replaces the placeholder unit struct from Phase 1a:

```rust
pub struct ZoneSummary {
    pub name: DomainName,
    pub class: RecordClass,
    pub serial: Serial,
}
```

**Zone** — replaces the placeholder unit struct:

```rust
pub struct Zone {
    pub name: DomainName,
    pub class: RecordClass,
    pub records: Vec<ResourceRecord>,
}

impl Zone {
    pub fn serial(&self) -> Option<Serial> { /* find SOA record */ }
    pub fn soa(&self) -> Option<&ResourceRecord> { /* find SOA */ }
    pub fn summary(&self) -> ZoneSummary { /* extract */ }
}
```

**ZoneFile** — parsed zone file with metadata. One `ZoneFile` = one `Zone` (RFC 1035 master file format defines a single zone per file):

```rust
pub struct ZoneFile {
    pub origin: DomainName,
    pub default_ttl: Option<Ttl>,
    pub zone: Zone,
}

impl ZoneFile {
    pub fn parse(input: &str) -> Result<Self, CoreError> { /* ... */ }
    pub fn parse_with_includes(
        input: &str,
        resolver: &dyn IncludeResolver,
    ) -> Result<Self, CoreError> { /* ... */ }
    pub fn serialize(&self) -> String { /* ... */ }
}
```

**IncludeResolver** — pluggable `$INCLUDE` handler (allows filesystem I/O in `std` contexts while keeping core `no_std`):

```rust
pub trait IncludeResolver {
    fn resolve(&self, path: &str) -> Result<String, CoreError>;
}
```

The default `parse()` method returns `CoreError::ZoneParse` on `$INCLUDE` directives. Callers with filesystem access use `parse_with_includes()` with a resolver that reads files.

**ZoneFile implements ZoneManager:**

```rust
impl ZoneManager for ZoneFile {
    type Error = CoreError;

    async fn list_zones(&self) -> Result<Vec<ZoneSummary>, CoreError> {
        Ok(alloc::vec![self.zone.summary()])
    }

    async fn get_zone(&self, name: &DomainName) -> Result<Zone, CoreError> {
        if self.zone.name == *name {
            Ok(self.zone.clone())
        } else {
            Err(CoreError::InvalidName {
                name: name.to_string(),
                reason: "zone not found".into(),
            })
        }
    }
}
```

### 3.4 Parser Design

The zone file parser handles:

- **Directives**: `$ORIGIN`, `$TTL`. `$INCLUDE` is handled by the `IncludeResolver` trait — `parse()` returns `CoreError::ZoneParse` on `$INCLUDE`, `parse_with_includes()` delegates to the resolver.
- **Comments**: `;` to end of line.
- **Continuation**: Parenthesized `(...)` multi-line records.
- **Owner name inheritance**: blank owner field inherits from the previous record.
- **`@` shorthand**: resolves to current `$ORIGIN`.
- **Relative names**: names not ending in `.` are appended to `$ORIGIN`.
- **Class and TTL field ordering**: both `IN 300 A 1.2.3.4` and `300 IN A 1.2.3.4` are valid.
- **Escape sequences**: `\DDD` (decimal byte), `\.` (literal dot in labels).

The parser is a two-phase design:
1. **Tokenizer** — splits input into tokens (name, string, number, directive, comment, paren-open, paren-close, newline).
2. **Record assembler** — consumes tokens, tracks `$ORIGIN` and `$TTL` state, resolves relative names, produces `ResourceRecord` values.

No streaming/incremental parsing in v0.1.0. The entire input is parsed into a `Vec<ResourceRecord>`. This is YAGNI — optimize later if profiling shows memory issues on very large zones.

### 3.5 RecordData Text Parsing (`rdata_text.rs`)

Each RecordData variant needs two functions:
- `parse_rdata(rtype: &str, tokens: &mut TokenStream, origin: &DomainName) -> Result<RecordData, CoreError>`
- `serialize_rdata(rdata: &RecordData) -> String`

Text format support is prioritized by usage frequency. v0.1.0 must support: A, AAAA, NS, SOA, MX, CNAME, TXT, SRV, PTR, CAA (the 10 most common types). Remaining variants (DNSSEC types, SSHFP, TLSA, RP, CSYNC) are added in follow-up commits within the same worktree if time permits, otherwise deferred. The `Unknown` variant uses RFC 3597 generic format: `\# <length> <hex>`.

### 3.6 Testing Strategy

- **Proptest roundtrip**: `parse(serialize(zone)) == zone` for generated zones
- **Proptest fuzz**: `ZoneFile::parse(arbitrary_string)` never panics
- **Snapshot tests** (insta): known zone files produce stable output
- **Unit tests**: each directive, edge case, error condition
- **Real-world zones**: parse BIND9's own example zone files (embedded as test fixtures)

### 3.7 Dependencies

- Phase 1a types only (DomainName, Label, ResourceRecord, RecordData, etc.)
- No new crate dependencies — text parsing uses `core`/`alloc` only
- Must remain `no_std` compatible

## 4. Stream B — TSIG + UpdateBuilder + Net Foundation (WT-2)

This stream spans both crates. The core pieces (TSIG, UpdateBuilder) are `no_std`. The net foundation (NetError, TLS config, Bind9Client skeleton) requires `std`/`tokio`.

### 4.1 File Structure

```
crates/bind9-sdk-core/src/
├── tsig.rs             — TsigKey, HMAC computation, TSIG record construction
├── update.rs           — UpdateBuilder<State>, UpdateMessage
└── lib.rs              — update: pub mod tsig; pub mod update;

crates/bind9-sdk-net/src/
├── error.rs            — NetError enum
├── tls.rs              — TLS 1.3 configuration (rustls)
├── config.rs           — Bind9Client struct skeleton, ClientConfig
└── lib.rs              — update: pub mod error; pub mod tls; pub mod config;
```

### 4.2 TSIG (`core/tsig.rs`)

Per architecture spec §2.3 (secret-bearing types):

```rust
pub struct TsigKey {
    name: DomainName,
    algorithm: TsigAlgorithm,
    key_material: zeroize::Zeroizing<Vec<u8>>,
}
```

Uses `zeroize::Zeroizing<Vec<u8>>` — key bytes are zeroed on drop automatically. Manual `Debug` impl redacts as `TsigKey { name: "...", algorithm: HmacSha256, key: [REDACTED] }`. No `Clone` — per architecture spec §2.3.

**TsigAlgorithm** enum:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TsigAlgorithm {
    HmacSha256,
    HmacSha512,
    #[deprecated(note = "HMAC-SHA1 is weak; use HmacSha256 or HmacSha512 for new deployments")]
    HmacSha1,
}
```

HMAC-SHA1 is included for legacy BIND9 compatibility but marked deprecated. No HMAC-MD5 support — too weak per RFC 8945 §5.3.

**Key behaviors:**
- `TsigKey::new(name, algorithm, key_material)` — construct from raw bytes
- `TsigKey::from_base64(name, algorithm, base64_key)` — parse from `rndc.conf` / `named.conf` key format
- `TsigKey::generate(name, algorithm)` — generate random key. **Requires `std` feature** (uses `getrandom`). Not available in `no_std`/WASM builds.
- `TsigKey::sign(&self, message_bytes) -> Vec<u8>` — compute HMAC over message
- `TsigKey::verify(&self, message_bytes, mac) -> Result<(), CoreError>` — verify HMAC

**TSIG record construction** (RFC 8945 §4.3):
- `TsigRecord::new(key, message, timestamp)` — constructs the TSIG pseudo-record
- Time fudge defaults to 300 seconds (RFC 8945 recommendation)
- MAC computed over: request MAC (if response) + DNS message (sans TSIG) + TSIG variables

**Dependencies**: `hmac`, `sha2`, `digest` (all workspace deps, `no_std`), `zeroize` (workspace dep), `base64` (new, `no_std` with `alloc`), `getrandom` (new, behind `std` feature only — not compiled for WASM).

### 4.3 UpdateBuilder (`core/update.rs`)

Typestate pattern per architecture spec §2.2:

```rust
pub struct Unsigned;
pub struct Signed;

pub struct UpdateBuilder<State = Unsigned> {
    zone: DomainName,
    class: RecordClass,
    prerequisites: Vec<Prerequisite>,
    updates: Vec<UpdateEntry>,
    _state: core::marker::PhantomData<State>,
}
```

**Builder API:**

```rust
impl UpdateBuilder<Unsigned> {
    pub fn new(zone: DomainName, class: RecordClass) -> Self;

    // Prerequisites (RFC 2136 §2.4)
    pub fn require_rrset_exists(self, name: &DomainName, rtype: RecordType) -> Self;
    pub fn require_rrset_not_exists(self, name: &DomainName, rtype: RecordType) -> Self;
    pub fn require_name_exists(self, name: &DomainName) -> Self;
    pub fn require_name_not_exists(self, name: &DomainName) -> Self;

    // Updates (RFC 2136 §2.5)
    pub fn add_record(self, record: ResourceRecord) -> Self;
    pub fn delete_rrset(self, name: &DomainName, rtype: RecordType) -> Self;
    pub fn delete_record(self, record: ResourceRecord) -> Self;
    pub fn delete_name(self, name: &DomainName) -> Self;

    // State transition
    pub fn sign(self, key: &TsigKey) -> UpdateBuilder<Signed>;

    // Build without signing (for testing / trusted networks)
    pub fn build_unsigned(self) -> UpdateMessage;
}

impl UpdateBuilder<Signed> {
    pub fn build(self) -> UpdateMessage;
}
```

**UpdateMessage** — replaces placeholder from Phase 1a:

```rust
pub struct UpdateMessage {
    pub(crate) wire_bytes: Vec<u8>,
    pub(crate) id: u16,
}

impl UpdateMessage {
    pub fn as_bytes(&self) -> &[u8];
    pub fn id(&self) -> u16;
}
```

The wire encoding follows RFC 2136 §2: DNS message with opcode UPDATE (5), zone section, prerequisite section, update section, additional section (TSIG if signed).

**Dependencies**: Phase 1a types, TSIG from §4.2, `RecordType` from `protocol.rs`. Message ID generation: `UpdateBuilder::new()` uses random ID when `std` feature is enabled (via `getrandom`). For `no_std`/WASM, use `UpdateBuilder::with_id(id: u16)` to supply a deterministic ID.

### 4.4 NetError (`net/error.rs`)

Per architecture spec §3.2:

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

    #[error("HTTP error: {status}")]
    Http { status: u16, body: String },

    #[error("DNS update rejected: {rcode}")]
    UpdateRejected { rcode: String },

    #[error(transparent)]
    Core(#[from] bind9_sdk_core::CoreError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
```

### 4.5 TLS Configuration (`net/tls.rs`)

Per architecture spec §4.3:

```rust
pub struct TlsConfig {
    // Internal: rustls::ClientConfig
}

impl TlsConfig {
    pub fn new() -> Result<Self, NetError>;           // TLS 1.3, webpki roots
    pub fn with_spki_pin(pin: &[u8]) -> Result<Self, NetError>;  // TOFU pinning
}
```

- TLS 1.3 only — no TLS 1.2 fallback
- Cipher suites: AES-256-GCM and ChaCha20-Poly1305 only
- Certificate validation via `webpki` roots (strict by default)
- Localhost exemption: non-TLS permitted only for loopback addresses

**Dependencies**: `rustls`, `webpki-roots` (new workspace deps needed). `tokio-rustls` is deferred to Phase 2 (XoT for zone transfers). Phase 1 rndc uses plaintext TCP on localhost with HMAC auth — no TLS needed.

### 4.6 Bind9Client Skeleton (`net/config.rs`)

```rust
pub struct ClientConfig {
    pub rndc_addr: std::net::SocketAddr,
    pub rndc_key: bind9_sdk_core::tsig::TsigKey,
    pub stats_url: Option<String>,
    pub dns_addr: Option<std::net::SocketAddr>,
    pub tls: Option<TlsConfig>,
    pub timeout: std::time::Duration,
}

pub struct Bind9Client {
    config: ClientConfig,
    // Connection state — filled in by Wave 2
}

impl Bind9Client {
    pub fn new(config: ClientConfig) -> Self;
}
```

The trait implementations (`NamedControl`, `DynamicUpdater`, `StatsClient`) are added by Wave 2 streams as each protocol is implemented. In Wave 1, this is just the struct + constructor.

### 4.7 Testing Strategy

**TSIG:**
- Known-answer tests: HMAC-SHA256/SHA512 against RFC 2202 test vectors
- Key generation produces valid length keys
- `Debug` output contains `[REDACTED]`, never key bytes
- `ZeroizeOnDrop` confirmed via `zeroize` crate tests
- proptest: `sign(msg) |> verify(msg)` always succeeds for any message

**UpdateBuilder:**
- Typestate enforcement: `build()` only available on `Signed`, `build_unsigned()` only on `Unsigned` (compile-fail tests or `trybuild`)
- Wire format matches `nsupdate -d` packet dumps (captured test fixtures)
- Prerequisites encode correctly per RFC 2136 §2.4
- proptest: build → parse roundtrip for wire bytes

**NetError:**
- Format strings are correct
- `From<CoreError>` conversion works
- `From<std::io::Error>` conversion works

**TLS:**
- Config creation succeeds (unit test)
- TLS 1.3 enforced (integration test — deferred to Phase 3)

## 5. Stream C — rndc Wire Protocol (WT-3)

### 5.1 Scope

The rndc wire protocol is BIND9's custom control channel. It is NOT DNS — it uses a completely different framing and encoding. This is the most protocol-intensive piece in Phase 1.

### 5.2 File Structure

```
crates/bind9-sdk-net/src/
├── rndc/
│   ├── mod.rs          — RndcConnection<State> typestate, public API
│   ├── protocol.rs     — wire format: 4-byte length prefix, ISC message encode/decode
│   └── command.rs      — RndcCommand enum, response parsing
└── lib.rs              — update: pub mod rndc;
```

### 5.3 Wire Protocol

**Framing**: 4-byte big-endian length prefix + payload. NOT the 2-byte DNS TCP prefix.

**Authentication**: HMAC-based mutual authentication. The exact sequence must be verified against BIND9 source (`lib/isccfg/`, `lib/isc/netmgr/`) before implementation — the description below is approximate:
1. Client connects to TCP port 953
2. Client sends a `_ctrl` message containing a nonce, HMAC-signed with the shared key
3. Server validates the HMAC, responds with success/failure
4. Subsequent commands include HMAC signatures

**Note**: This flow may differ from the actual BIND9 9.20 implementation. The rndc protocol is not formally documented outside the BIND9 source. Implementation must reference the source code and/or captured wire dumps, not this description alone.

**ISC message encoding**: Key-value pairs in a binary format. Keys and values are length-prefixed strings. The format is stable across BIND9 minor versions.

### 5.4 Types

**RndcConnection typestate:**

```rust
pub struct Unauthenticated;
pub struct Authenticated;

pub struct RndcConnection<State = Unauthenticated> {
    stream: tokio::net::TcpStream,
    _state: core::marker::PhantomData<State>,
}

impl RndcConnection<Unauthenticated> {
    pub async fn connect(addr: std::net::SocketAddr) -> Result<Self, NetError>;
    pub async fn authenticate(self, key: &TsigKey) -> Result<RndcConnection<Authenticated>, NetError>;
}

impl RndcConnection<Authenticated> {
    pub async fn command(&mut self, cmd: RndcCommand) -> Result<RndcResponse, NetError>;
    pub async fn close(self) -> Result<(), NetError>;
}
```

The `Bind9Client` wraps `RndcConnection` behind a `tokio::sync::Mutex` internally, exposing `&self` at the `NamedControl` trait level per architecture spec §5.4.

**RndcCommand**: The full enum from PRD FR-005 (§4.1). Each variant serializes to the correct rndc command string.

**RndcResponse:**

```rust
pub struct RndcResponse {
    pub text: String,
    pub result: RndcResult,
}

pub enum RndcResult {
    Success,
    Error { code: u32, message: String },
}
```

**Bind9Client implements NamedControl:**

```rust
impl NamedControl for Bind9Client {
    type Error = NetError;

    async fn status(&self) -> Result<ServerStatus, NetError> {
        let conn = RndcConnection::connect(self.config.rndc_addr).await?;
        let conn = conn.authenticate(&self.config.rndc_key).await?;
        let resp = conn.command(RndcCommand::Status).await?;
        // Parse response text into ServerStatus
    }
    // ... reload, reload_zone, freeze
}
```

### 5.5 ServerStatus

Flesh out the placeholder from Phase 1a. **This type stays in `bind9-sdk-core/src/traits.rs`** (where the trait that returns it is defined). The rndc stream constructs and populates these structs but does not define them. Same applies to `FrozenZone`.

```rust
// In bind9-sdk-core/src/traits.rs (replacing the unit struct placeholder)
pub struct ServerStatus {
    pub version: String,
    pub running_since: Option<String>,  // ISO 8601 timestamp string
    pub reload_count: u32,
    pub server_up: bool,
    pub raw_text: String,  // full rndc status output for fields we don't parse
}
```

### 5.6 Testing Strategy

- **Protocol unit tests**: encode/decode roundtrip for ISC message format
- **Command serialization**: each RndcCommand variant produces correct command string
- **Response parsing**: known rndc output strings parse correctly
- **Typestate**: compile-fail test — `command()` unavailable on `Unauthenticated`
- **Integration** (deferred, `#[ignore]`): real BIND9 on localhost:953

## 6. Stream D — Stats HTTP + nsupdate Sender (WT-4)

### 6.1 Stats HTTP Client (`net/stats.rs`)

HTTP client for BIND9's statistics-channel JSON API (typically port 8053).

**Types:**

```rust
pub struct StatsHttpClient {
    url: String,
    http: reqwest::Client,
}

impl StatsHttpClient {
    pub fn new(url: &str) -> Result<Self, NetError>;
    pub fn with_auth(url: &str, auth_header: &str) -> Result<Self, NetError>;
}
```

**ServerStats** — flesh out placeholder. **This type stays in `bind9-sdk-core/src/traits.rs`** (where the `StatsClient` trait that returns it is defined). The HTTP client constructs and populates these structs but does not define them. Same applies to `ZoneStats`.

```rust
// In bind9-sdk-core/src/traits.rs (replacing the unit struct placeholder)
pub struct ServerStats {
    pub boot_time: String,
    pub config_time: String,
    pub current_time: String,
    pub version: String,
    pub queries: QueryCounters,
    pub opcodes: OpcodeCounters,
    pub rcodes: RcodeCounters,
}
```

**ZoneStats** — flesh out placeholder:

```rust
// In bind9-sdk-core/src/traits.rs (replacing the unit struct placeholder)
pub struct ZoneStats {
    pub name: DomainName,
    pub class: RecordClass,
    pub serial: Serial,
    pub record_count: u32,
    pub zone_type: String,
}
```

The full stats JSON structure is large. For v0.1.0, we parse the top-level server stats and per-zone summary. Detailed counters (`QueryCounters`, `OpcodeCounters`, `RcodeCounters`) are simple structs with `u64` fields, deserialized with serde.

**Bind9Client implements StatsClient:**

```rust
impl StatsClient for Bind9Client {
    type Error = NetError;

    async fn server_stats(&self) -> Result<ServerStats, NetError> {
        let url = self.config.stats_url.as_ref()
            .ok_or(NetError::Connection("stats URL not configured".into()))?;
        let client = StatsHttpClient::new(url)?;
        client.fetch_server_stats().await
    }

    async fn zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, NetError> {
        // similar
    }
}
```

### 6.2 nsupdate Sender (`net/nsupdate.rs`)

Sends `UpdateMessage` (from core) over the network.

```rust
pub struct NsUpdateSender {
    server: std::net::SocketAddr,
    timeout: std::time::Duration,
}

impl NsUpdateSender {
    pub fn new(server: std::net::SocketAddr) -> Self;
    pub fn with_timeout(server: std::net::SocketAddr, timeout: std::time::Duration) -> Self;
}
```

**UpdateResult** — flesh out placeholder. **Stays in `bind9-sdk-core/src/traits.rs`** (returned by `DynamicUpdater` trait):

```rust
// In bind9-sdk-core/src/traits.rs
pub struct UpdateResult {
    pub rcode: Rcode,
    pub id: u16,
}
```

**Rcode** — defined in `bind9-sdk-core/src/protocol.rs` (fundamental DNS concept, reused by multiple subsystems):

```rust
// In bind9-sdk-core/src/protocol.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rcode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    YxDomain,
    YxRrset,
    NxRrset,
    NotAuth,
    NotZone,
    Other(u16),
}

impl Rcode {
    pub fn from_value(value: u16) -> Self;
    pub fn value(&self) -> u16;
}
```

**RecordType** — also in `protocol.rs` (used by UpdateBuilder prerequisites):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordType {
    A, Aaaa, Cname, Ns, Ptr, Soa, Mx, Txt, Srv, Caa,
    Dnskey, Rrsig, Nsec, Nsec3, Ds, Cds, Cdnskey,
    Tlsa, Sshfp, Csync, Rp,
    Other(u16),
}

impl RecordType {
    pub fn from_value(value: u16) -> Self;
    pub fn value(&self) -> u16;
}
```

**Send logic:**
1. Send UpdateMessage bytes over UDP to server:53
2. Wait for response (with timeout)
3. If response has TC (truncated) bit set, retry over TCP (2-byte length prefix + message)
4. Parse response header: extract RCODE
5. Return `UpdateResult`

**Bind9Client implements DynamicUpdater:**

```rust
impl DynamicUpdater for Bind9Client {
    type Error = NetError;

    async fn send_update(&self, update: &UpdateMessage) -> Result<UpdateResult, NetError> {
        let addr = self.config.dns_addr
            .ok_or(NetError::Connection("DNS address not configured".into()))?;
        let sender = NsUpdateSender::new(addr);
        sender.send(update).await
    }
}
```

### 6.3 Testing Strategy

**Stats:**
- Snapshot tests: known BIND9 JSON responses deserialize correctly (embedded fixtures)
- Missing fields handled gracefully (BIND9 version differences)
- HTTP error codes map to `NetError::Http`

**nsupdate sender:**
- Wire format: response parsing extracts correct RCODE
- UDP → TCP fallback triggered by TC bit
- Timeout produces `NetError::Timeout`
- Integration (deferred, `#[ignore]`): send to real BIND9

## 7. Merge Strategy

### 7.1 Wave 1 Merge Order

1. Merge `feat/zone-parser` into `development` first (only touches core, no conflicts)
2. Merge `feat/tsig-update-net` into `development` second (touches both core and net)
3. Potential conflict point: `core/lib.rs` module declarations. Mitigation: pre-add `pub mod zone;`, `pub mod tsig;`, `pub mod update;` stubs to `lib.rs` on `development` BEFORE creating worktrees.

### 7.2 Wave 2 Merge Order

1. Merge `feat/rndc-protocol` first (adds `net/rndc/`)
2. Merge `feat/stats-nsupdate` second (adds `net/stats.rs`, `net/nsupdate.rs`)
3. Same `lib.rs` mitigation: pre-add module declarations.

### 7.3 Pre-Worktree Setup

Before creating any worktrees, on `development`:

1. **Migrate placeholder types** from `core/traits.rs`:
   - `Zone`, `ZoneSummary` → `core/zone/mod.rs` (created as stubs with real fields)
   - `UpdateMessage`, `UpdateResult` → `core/update.rs` (created as stubs)
   - `ServerStatus`, `FrozenZone`, `ServerStats`, `ZoneStats` → remain in `core/traits.rs` but get real fields
   - Update mock tests in `traits.rs` to construct with real fields
   - Update imports throughout

2. **Add module declarations** to `core/lib.rs`:
   - `pub mod zone; pub mod tsig; pub mod update; pub mod protocol;`
   - Create empty stub files/directories for each

3. **Add module declarations** to `net/lib.rs`:
   - `pub mod error; pub mod tls; pub mod config; pub mod rndc; pub mod stats; pub mod nsupdate;`
   - Create empty stub files

4. **Add workspace dependencies** to root `Cargo.toml` `[workspace.dependencies]`:
   - `getrandom = { version = "0.3", default-features = false }`
   - `base64 = { version = "0.22", default-features = false, features = ["alloc"] }`
   - `rustls = { version = "0.23" }`
   - `webpki-roots = { version = "1" }`
   - `sha1 = { version = "0.10", default-features = false }` (for `HmacSha1`)

5. **Add crate-level dependencies**:
   - `bind9-sdk-core/Cargo.toml`: add `base64`, `getrandom` (behind `std` feature), `sha1`
   - `bind9-sdk-net/Cargo.toml`: add `rustls`, `webpki-roots`

6. **Update PRD**: FR-010 phase change, stats-channel comment fix, Phase 2 scope update

7. **Commit** this scaffolding

This ensures worktrees branch from a common base with all module paths declared and dependencies resolved, eliminating merge conflicts.

## 8. New Dependencies

| Crate | Version | Purpose | Used by | `no_std`? |
| --- | --- | --- | --- | --- |
| `getrandom` | 0.3 | Random bytes for key gen + message IDs | core (behind `std` feature only) | No — `std` gated |
| `base64` | 0.22 | TSIG key base64 encoding/decoding | core (tsig) | Yes (`default-features = false`, `alloc`) |
| `sha1` | 0.10 | HMAC-SHA1 for legacy BIND9 compat | core (tsig) | Yes (`default-features = false`) |
| `rustls` | 0.23 | TLS 1.3 client configuration | net (tls) | No |
| `webpki-roots` | 1 | Mozilla CA root certificates | net (tls) | No |
| `tokio` | 1 | Already in workspace | net | No |
| `reqwest` | 0.12 | Already in workspace | net (stats) | No |

## 9. PRD Adjustments

The following PRD changes are needed to reflect this plan:

1. **FR-010 (nsupdate sender)**: Move from Phase 2 to Phase 1. Rationale: the sender is simple (~150 lines) once UpdateMessage exists; shipping v0.1.0 without the ability to actually send updates is incomplete.
2. **Stats-channel (FR-006)**: Move from "Phase 2" comment in `net/lib.rs` to Phase 1 (it was already Phase 1 in the PRD, the lib.rs comment was wrong).
3. **Phase 2 scope update**: Phase 2 becomes IXFR/AXFR + DNSSEC/KASP + CDS/CDNSKEY. Clean thematic split: "Phase 2 = zone transfer + DNSSEC operations."

## 10. Success Criteria

Phase 1 is complete when:

- `cargo test --workspace` passes with all new tests (target: 150+ total)
- `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown` passes (core remains no_std)
- `cargo clippy --workspace --all-targets -- -D warnings` clean
- `cargo fmt --check` clean
- The following end-to-end workflow compiles (doc test in `bind9-sdk`):
  ```rust
  // Parse a zone file
  let zone = ZoneFile::parse(zone_text)?;
  // Build an update
  let update = UpdateBuilder::new(zone_name, RecordClass::IN)
      .add_record(record)
      .sign(&tsig_key)
      .build();
  // (sending, rndc, stats require a live server — integration tests)
  ```
- All placeholder types from Phase 1a are fleshed out with real fields

## 11. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Zone parser complexity exceeds estimate | Medium | Delays Wave 1 | Start with common record types (A, AAAA, MX, CNAME, NS, SOA, TXT, SRV), add remaining in follow-up commits |
| rndc wire protocol underdocumented | Medium | Delays Wave 2 | Reference BIND9 source code (`lib/isc/netmgr/`), capture wire dumps from real rndc sessions |
| `getrandom` in no_std context | Low (mitigated) | Blocks TSIG key generation | Resolved: `generate()` is `std`-gated. WASM gets `with_id()` constructors. |
| Merge conflicts between worktrees | Low | Delays merge | Pre-add all module declarations (§7.3) |
| TSIG implementation doesn't match BIND9 | Medium | Integration test failures | Use RFC 2202 test vectors + captured BIND9 TSIG packets as fixtures |
