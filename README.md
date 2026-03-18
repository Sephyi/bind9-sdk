<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# 🌐 bind9-sdk &emsp; ![MSRV] ![License]

[MSRV]: https://img.shields.io/badge/MSRV-1.94-orange.svg
[License]: https://img.shields.io/badge/license-TBD-yellow.svg

**The BIND9 management SDK that should have existed a decade ago.**

> [!CAUTION]
> This project is in its very early stages. I decided to share it from the beginning anyway. If you're interested in contributing, feel free to reach out — contact info is on [my profile](https://github.com/Sephyi).

A Rust-native library for programmatic BIND9 DNS server management. Implements the full rndc wire protocol, RFC 1035 zone file parsing, RFC 2136 dynamic updates (nsupdate), IXFR/AXFR zone transfers, and the BIND9 statistics-channel JSON API — all with zero shell subprocess dependencies.

Ships as three coordinated artifacts from one codebase:

- 🦀 **Rust crate** (`bind9-sdk`) — the primary library, published to crates.io
- 📦 **Node.js/Bun native addon** (`bind9-sdk-bindings`) — napi-rs v3, native `.node` + WASM fallback
- 🐚 **CLI tool** (`bind9`) — zone, record, DNSSEC, and stats management from the terminal

## ✨ Highlights

- 🔌 **Full rndc wire protocol** — 25+ commands over TCP, no shell subprocesses, no `rndc` binary needed
- 📝 **RFC 2136 dynamic updates** — add, delete, and replace DNS records with TSIG signing
- 🔄 **AXFR/IXFR zone transfers** — async streaming client with compression pointer rejection and per-message timeouts
- 📄 **Zone file parser** — RFC 1035 compliant parser/serializer with zone diffing
- 📊 **Statistics API** — BIND9 statistics-channel JSON API client
- 🔐 **TSIG authentication** — HMAC-SHA256/SHA512, secrets zeroized on drop, never in logs
- 🧱 **`no_std` core** — core crate compiles without std, works in WASM and embedded contexts
- 🔗 **Connection pooling** — `RndcPool` for high-throughput rndc operations
- 🧪 **574 tests** — unit, property (proptest), snapshot (insta), and integration tests
- 🦀 **Single workspace** — one repo, one `cargo build`, all three artifacts

## 📋 Prerequisites

- **Rust 1.94+** — `rust-toolchain.toml` pins the channel
- **BIND9 9.20** — for integration tests (Podman rootless or native `named`)
- **Node.js 18+** — for the napi-rs native addon (optional)

## 🔨 Building from source

```bash
git clone https://github.com/Sephyi/bind9-sdk.git
cd bind9-sdk
```

### 🦀 Rust library

```bash
# Build all crates
cargo build --workspace

# Run tests (unit only — integration tests require a live BIND9)
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --check
```

### 🐚 CLI tool

```bash
# Build the CLI binary
cargo build -p bind9-sdk-cli --release

# The binary is at target/release/bind9
./target/release/bind9 --help

# Or install to ~/.cargo/bin/
cargo install --path crates/bind9-sdk-cli
```

### 📦 Node.js native addon

```bash
cd crates/bind9-sdk-bindings

# Install napi-rs CLI
npm install

# Build the native .node file + JS/TS bindings
npm run build

# Verify it works
node tests/smoke.mjs
```

This produces three files:

| File | Description |
| --- | --- |
| `bind9-sdk.node` | Native binary (~6 MB on arm64) |
| `index.js` | Platform loader (auto-detects OS/arch) |
| `index.d.ts` | TypeScript type definitions |

## 📥 Using before publication

The SDK is not yet published to crates.io or npm. You can use it directly from git or a local checkout.

### 🦀 Rust — git dependency

Point your `Cargo.toml` at the repository:

```toml
[dependencies]
# From GitHub (latest development branch)
bind9-sdk = { git = "https://github.com/Sephyi/bind9-sdk", branch = "development" }

# Or pin to a specific commit
bind9-sdk = { git = "https://github.com/Sephyi/bind9-sdk", rev = "303f445" }

# Or from a local checkout
bind9-sdk = { path = "../bind9-sdk/bind9-sdk" }
```

> [!NOTE]
> The path must point to the `bind9-sdk/` subdirectory (the re-export crate), not the repository root.

To disable the network features (rndc, nsupdate, transfers) and use only the `no_std` core:

```toml
[dependencies]
bind9-sdk = { git = "https://github.com/Sephyi/bind9-sdk", default-features = false }
```

### 📦 Node.js / Bun — local build

```bash
# 1. Clone and build
git clone https://github.com/Sephyi/bind9-sdk.git
cd bind9-sdk/crates/bind9-sdk-bindings
npm install
npm run build

# 2. From your project, link to the built package
cd /path/to/your-project
npm link /path/to/bind9-sdk/crates/bind9-sdk-bindings

# Or add it as a file dependency in your package.json
```

```json
{
  "dependencies": {
    "bind9-sdk": "file:../bind9-sdk/crates/bind9-sdk-bindings"
  }
}
```

Then import as usual:

```javascript
import { JsDomainName, JsZoneFile } from 'bind9-sdk';
```

## 🦀 Rust API

Once published, add to your `Cargo.toml`:

```toml
[dependencies]
bind9-sdk = "0.1"
```

### 📄 Parse a zone file

```rust
use bind9_sdk::{ZoneFile, DomainName};

let zone = ZoneFile::parse("$ORIGIN example.com.\nexample.com. 3600 IN A 192.0.2.1\n")?;
for record in &zone.zone.records {
    println!("{} {} IN {:?}", record.name, record.ttl, record.data);
}
```

### 🔀 Zone diff

```rust
use bind9_sdk::ZoneFile;

let old = ZoneFile::parse(&std::fs::read_to_string("old.zone")?)?;
let new = ZoneFile::parse(&std::fs::read_to_string("new.zone")?)?;
let diff = old.zone.diff(&new.zone);

println!("{diff}"); // Shows added/removed/changed records
```

### 📝 Dynamic update (RFC 2136)

```rust
use bind9_sdk::{
    DomainName, RecordClass, RecordData, ResourceRecord, Ttl,
    UpdateBuilder, TsigKey, TsigAlgorithm, NsUpdateSender,
};

let zone = DomainName::new("example.com.")?;
let key = TsigKey::new(
    DomainName::new("update-key.")?,
    TsigAlgorithm::HmacSha256,
    &base64_decode("your-key-secret-here")?,
)?;

let record = ResourceRecord::new(
    DomainName::new("www.example.com.")?,
    RecordData::A("192.0.2.1".parse()?),
    Ttl::new(3600),
);

let update = UpdateBuilder::new(zone, RecordClass::IN)
    .add_record(record)
    .sign_now(&key)
    .build();

let sender = NsUpdateSender::new("127.0.0.1:53".parse()?);
let response = sender.send(&update, Some(&key)).await?;
```

### 🔌 rndc control

```rust
use bind9_sdk::{Bind9Client, ClientConfig, DomainName, NamedControl};

let key = /* TsigKey as above */;
let config = ClientConfig::new("127.0.0.1:953".parse()?, key);
let client = Bind9Client::new(config);

let status = client.status().await?;
println!("BIND {} — {} zones", status.version, status.zone_count);

client.reload_zone(&DomainName::new("example.com.")?).await?;
```

### 🔄 AXFR zone transfer

```rust
use bind9_sdk::{TransferClient, DomainName, TransferRecord};
use tokio_stream::StreamExt;

let client = TransferClient::connect("127.0.0.1:53".parse()?, None).await?;
let stream = client.axfr(DomainName::new("example.com.")?, None).await?;
tokio::pin!(stream);

while let Some(result) = stream.next().await {
    let record = result?;
    match record {
        TransferRecord::Record(rr) => println!("{} {}", rr.name, rr.ttl),
        _ => {}
    }
}
```

## 🐚 CLI Usage

The `bind9` CLI provides zone, record, DNSSEC, and stats management.

### ⚙️ Global options

All commands accept these flags (CLI flags override config file values):

```txt
--server <HOST>       Server hostname or IP address
--port <PORT>         rndc control port (default: 953)
--dns-port <PORT>     DNS port for updates and transfers (default: 53)
--key-name <NAME>     TSIG key name
--key-secret <SECRET> Base64-encoded TSIG key secret
--output <FORMAT>     Output format: text (default) or json
```

### 📁 Configuration file

Instead of passing flags every time, create a config file:

- 🍎 **macOS:** `~/Library/Application Support/bind9-sdk/config.toml`
- 🐧 **Linux:** `~/.config/bind9-sdk/config.toml`

```toml
[server]
host = "127.0.0.1"
port = 953
dns_port = 53
stats_url = "http://127.0.0.1:8053"

[auth]
key_name = "rndc-key"
key_secret = "base64-encoded-secret-here"
algorithm = "hmac-sha256"  # or hmac-sha512
```

### 🗂️ Zone commands

```bash
# List zones (shows server status and zone count)
bind9 zone list

# Show zone status
bind9 zone status example.com.

# Reload a zone
bind9 zone reload example.com.

# Export a zone via AXFR (requires --dns-port for the DNS server port)
bind9 zone export example.com. --dns-port 53

# Diff two local zone files (no server needed)
bind9 zone diff old.zone new.zone
```

### 📝 Record commands

Record commands use RFC 2136 dynamic updates and require `--dns-port`.

```bash
# Add an A record
bind9 record add example.com. www.example.com. A 192.0.2.1 --ttl 300 --dns-port 53

# Add an AAAA record
bind9 record add example.com. www.example.com. AAAA 2001:db8::1 --dns-port 53

# Add an MX record
bind9 record add example.com. example.com. MX "10 mail.example.com." --dns-port 53

# Delete a specific record
bind9 record delete example.com. www.example.com. A 192.0.2.1 --dns-port 53

# Delete all records of a type (omit data)
bind9 record delete example.com. www.example.com. A --dns-port 53
```

Supported record types: `A`, `AAAA`, `CNAME`, `NS`, `PTR`, `SOA`, `MX`, `TXT`, `SRV`, `CAA`, `DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `DS`, `CDS`, `CDNSKEY`, `TLSA`, `SSHFP`, `CSYNC`, `RP`, `DLV`, plus RFC 3597 `TYPEn` syntax for any type by number.

### 🔐 DNSSEC commands

```bash
# Show DNSSEC status for a zone
bind9 dnssec status example.com.

# Check DS record publication
bind9 dnssec checkds example.com.
```

### 📊 Stats

```bash
# Fetch server statistics (requires stats_url in config or BIND9 statistics-channel)
bind9 stats
bind9 stats --output json
```

### 🐚 Shell completions

```bash
# Generate completions for your shell
bind9 completions bash >> ~/.bashrc
bind9 completions zsh >> ~/.zshrc
bind9 completions fish > ~/.config/fish/completions/bind9.fish
```

## 📦 Node.js / Bun API

```javascript
import { JsDomainName, JsZoneFile, JsRndcClient } from 'bind9-sdk';

// Parse a domain name
const name = new JsDomainName('example.com.');
console.log(name.toString());     // "example.com."
console.log(name.labelCount());   // 2

// Parse a zone file
const zone = JsZoneFile.parse('$ORIGIN example.com.\nexample.com. 3600 IN A 192.0.2.1\n');
console.log(zone.recordCount());  // 1

// rndc client (async)
const client = new JsRndcClient('127.0.0.1', 953, 'rndc-key', 'base64-secret');
const status = await client.status();
console.log(status);
```

Available binding modules: `domain`, `zone`, `record`, `tsig`, `update`, `rndc`, `nsupdate`, `stats`, `transfer`, `pool`.

## 🏗️ Architecture

```txt
bind9-sdk/
├── bind9-sdk/                 ← re-export crate (crates.io entry point)
├── crates/
│   ├── bind9-sdk-core/        ← no_std + alloc; DNS types, zone parsing, TSIG, RFC 2136
│   ├── bind9-sdk-net/         ← tokio; rndc, nsupdate, AXFR/IXFR, stats HTTP, connection pool
│   ├── bind9-sdk-bindings/    ← napi-rs v3; native .node + WASM fallback
│   └── bind9-sdk-cli/         ← clap CLI binary
└── Cargo.toml                 ← workspace root
```

| Crate | `no_std` | What it provides |
| --- | --- | --- |
| `bind9-sdk-core` | ✅ | DNS types, zone parser/serializer, zone diff, RFC 2136 UpdateBuilder, TSIG (HMAC-SHA256/SHA512) |
| `bind9-sdk-net` | ❌ | rndc wire protocol (25+ commands), NsUpdateSender, AXFR/IXFR client, stats HTTP, connection pool |
| `bind9-sdk-bindings` | — | Node.js/Bun native addon via napi-rs v3 (11 binding modules) |
| `bind9-sdk-cli` | — | `bind9` binary with zone/record/dnssec/stats subcommands |
| `bind9-sdk` | — | Re-export crate — the single dependency users add |

## 🛡️ Compliance and Security

Designed to meet GDPR, NIS2, NIST SP 800-53/800-81/800-57, ISO 27001:2022, and SOC 2 Type II requirements for DNS infrastructure. Secure defaults out of the box.

- 🔒 **Authentication** — No anonymous rndc. TSIG secrets zeroized on drop, never in logs or errors.
- 🔐 **Transport** — XoT for non-localhost transfers. TLS 1.3 only. Strict cert validation default.
- 🛡️ **DNSSEC** — All IANA algorithms (8–16). Ed25519 default. KSK rollover safety gates.
- 📦 **Supply Chain** — SBOM per release. `cargo audit` in CI. `#![forbid(unsafe_code)]` in core.
- ⚙️ **Defaults** — HMAC-MD5 rejected. HMAC-SHA1 warns. HMAC-SHA256/SHA512 default.

## 💛 Sponsor

If you find bind9-sdk useful, consider [**sponsoring my work**](https://github.com/sponsors/Sephyi).

## 📄 License

License not yet decided. The codebase currently carries PolyForm-Noncommercial-1.0.0 headers as a placeholder.

Copyright 2026 [Sephyi](https://sephy.io)
