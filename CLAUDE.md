<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# bind9-sdk

Rust SDK for programmatic BIND9 DNS server management. Implements the rndc wire protocol, RFC 1035 zone file parsing, RFC 2136 dynamic updates (nsupdate), IXFR/AXFR zone transfer, and the BIND9 statistics-channel JSON API — all with zero shell subprocess dependencies.

Distributes as three coordinated artifacts from one codebase: a Rust crate (`bind9-sdk` on crates.io), a browser WASM bundle (wasm-pack from `bind9-sdk-bindings`), and a Node.js native addon (napi-rs from `bind9-sdk-bindings`).

## Prerequisites

- Rust stable ≥ 1.85 — `rust-toolchain.toml` pins channel and installs `wasm32-unknown-unknown`
- `wasm-pack` — for browser WASM builds (`cargo install wasm-pack`)
- BIND9 9.20 — for integration tests (Podman rootless or native `named`)

## Commands

```bash
# Type-check all crates (both native and WASM targets)
cargo check --workspace
cargo check --workspace --target wasm32-unknown-unknown

# Build
cargo build --workspace

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Format
cargo fmt --check

# Tests (unit only — integration tests require a live BIND9 instance)
cargo test --workspace

# Integration tests (requires BIND9 on localhost:953 with test rndc key — see tests/README.md)
cargo test --workspace -- --ignored

# Browser WASM build (bind9-sdk-core subset)
wasm-pack build crates/bind9-sdk-bindings --target web --features browser

# Node.js native addon build (full surface)
cargo build --release --manifest-path crates/bind9-sdk-bindings/Cargo.toml --features nodejs
```

## Workspace Architecture

```txt
bind9-sdk/                     ← git repo root (this directory)
├── bind9-sdk/                 ← re-export crate (public crates.io API)
│   └── src/lib.rs
├── crates/
│   ├── bind9-sdk-core/        ← no_std + alloc; DNS types, zone parsing, RFC 2136, TSIG
│   ├── bind9-sdk-net/         ← tokio; rndc TCP, nsupdate sender, IXFR/AXFR, stats HTTP
│   └── bind9-sdk-bindings/    ← wasm-bindgen (browser) + napi-rs (Node.js native addon)
├── npm/                       ← npm package output (wasm-pack + napi-rs artifacts)
├── tests/                     ← integration test suite (live BIND9 required)
├── Cargo.toml                 ← workspace root
├── rust-toolchain.toml
└── REUSE.toml
```

### Crate Responsibilities

| Crate | `no_std` | Feature gate | What it provides |
| --- | --- | --- | --- |
| `bind9-sdk-core` | Yes | — | `DomainName`, `ResourceRecord`, `RecordData` (20+ variants), zone file parser/emitter, RFC 2136 message construction, TSIG signing (HMAC-SHA256/SHA512) |
| `bind9-sdk-net` | No | `net` (default) | `rndc` TCP wire protocol client, nsupdate sender, IXFR/AXFR client, statistics-channel HTTP client |
| `bind9-sdk-bindings` | — | `browser` / `nodejs` | wasm-bindgen exports of core types; napi-rs exports of full SDK surface |
| `bind9-sdk` | — | — | Re-exports `core` and optionally `net`; the single crates.io entry point |

## Feature Flags

| Flag | Crate | Effect |
| --- | --- | --- |
| `std` | `bind9-sdk-core` | Enables `std::error::Error` impls; disables `no_std` |
| `serde` | `bind9-sdk-core` | Enables `Serialize`/`Deserialize` on DNS types |
| `net` *(default)* | `bind9-sdk` | Includes `bind9-sdk-net` (rndc, nsupdate, IXFR/AXFR, stats) |
| `browser` | `bind9-sdk-bindings` | Enables wasm-bindgen exports (core subset only) |
| `nodejs` | `bind9-sdk-bindings` | Enables napi-rs exports (full surface including net) |

## Key Design Decisions

1. **`no_std` core** — `bind9-sdk-core` compiles without std via `#![no_std]` + `extern crate alloc;`. This is the constraint that makes browser WASM work without feature hacks. All crypto (HMAC-SHA256/SHA512) uses RustCrypto crates which are `no_std` compatible.

2. **Trait-first** — Management operations are defined as traits (`ZoneManager`, `NamedControl`, `DynamicUpdater`, `StatsClient`) in `bind9-sdk-core`. The net layer provides concrete implementations. Tests use mock implementations against the traits.

3. **TSIG in core, send in net** — TSIG key material, HMAC computation, and message authentication code construction live in `bind9-sdk-core` (no_std). The net layer consumes the signed bytes and handles the TCP/UDP transport. This separation makes TSIG testable without a network.

4. **rndc wire protocol is NOT DNS** — BIND9's rndc uses a custom TCP framing format: 4-byte big-endian length prefix + ISC internal message encoding. Do not confuse with DNS-over-TCP (2-byte prefix). The protocol is documented in the BIND source (`lib/isc/netmgr/`, ISC KB). It is stable across BIND9 minor versions.

5. **WASM boundary split** — Browser WASM (`feature = "browser"`) exposes only `bind9-sdk-core` types: zone parsing, record construction, RFC 2136 message building. TCP connections (rndc, IXFR, nsupdate send) are unavailable in browser WASM — those require the Node.js native addon (`feature = "nodejs"`) via napi-rs.

6. **`bind9-sdk` is the only published user-facing crate** — Users add `bind9-sdk` to their `Cargo.toml`, never internal crates directly. Internal crates are published to satisfy crates.io dependency resolution but carry no stability guarantees of their own.

## Gotchas

- **`no_std` means `core::error::Error`** — `std::error::Error` is not available in `bind9-sdk-core`. Use `core::error::Error` (stable since Rust 1.81, which is below our rust-version of 1.85). The `std` feature flag on `bind9-sdk-core` opts back in to `std::error::Error`.
- **`wasm32-unknown-unknown` has no TCP** — any `bind9-sdk-net` code compiled for WASM will fail to link. Keep all net types behind the `nodejs` feature in `bind9-sdk-bindings`, never the `browser` feature.
- **napi-rs requires a native build step** — `cargo build --features nodejs` alone is not enough; napi-rs needs `npm run build` (or `napi build --release`) to generate the `.node` file and JS bindings. napi-rs auto-falls back to WASM when the native binary is unavailable on a given platform.
- **TSIG key format in `rndc.conf`** — base64-encoded raw HMAC-SHA256 key material, not PEM. The `algorithm hmac-sha256;` line is not a hint about encoding — it specifies the MAC algorithm directly.
- **BIND9 rndc framing** — message length is encoded as a big-endian u32 (4 bytes), not the 2-byte DNS TCP length. Misreading this is the most common rndc client implementation bug.
- **`cargo check --workspace` does not check WASM target** — always also run `cargo check --workspace --target wasm32-unknown-unknown` before PR to catch no_std violations in core.

## Code Style

- Rust 2024 edition, stable toolchain
- `cargo fmt` + `clippy --workspace -D warnings` enforced by PostToolUse hook
- `#![no_std]` in `bind9-sdk-core` — verified by WASM target check
- SPDX headers on all source files (`// SPDX-...` for Rust, `# SPDX-...` for TOML, `<!-- SPDX-... -->` for Markdown)
- License: PolyForm-Noncommercial-1.0.0 (REUSE compliant via `REUSE.toml`)

## Claude Code Hooks

| Hook | Trigger | Action |
| --- | --- | --- |
| `superpowers-check.sh` | SessionStart | Verifies superpowers plugin is active |
| `block-generated-files.sh` | PreToolUse (Edit/Write) | Blocks manual edits to `Cargo.lock` |
| `rust-fmt.sh` | PostToolUse (Edit/Write) | Auto-formats any edited `.rs` file with `rustfmt` |

## Agents

| Agent | Purpose |
| --- | --- |
| `cargo-dep-auditor` | Audit Cargo deps for outdated versions, yanked crates, security advisories |
| `rust-security-reviewer` | *Needs rewrite for bind9-sdk — currently contains commitbee-specific checks* |
| `api-compat-reviewer` | *Verify before use — may contain commitbee-specific content* |
| `llm-prompt-quality-reviewer` | *Commitbee artifact — not relevant to bind9-sdk, remove or replace* |

## References

- **PRD**: `PRD.md`
- **Research doc**: `/Users/sephyi/Documents/Markdown/huhn/bind9-dns-management-2026.md`
- **hu.hn infra plans**: `/Users/sephyi/Documents/Markdown/huhn/dev-concerns.md`
- **rndc wire protocol**: BIND9 source `lib/isc/netmgr/`, ISC Knowledge Base
- **RFC 1035**: Domain Names — Implementation and Specification
- **RFC 2136**: Dynamic Updates in the Domain Name System
- **RFC 8945**: Secret Key Transaction Authentication for DNS (TSIG)
- **RustCrypto hmac/sha2**: `docs.rs/hmac`, `docs.rs/sha2`
- **napi-rs**: `napi.rs`
- **wasm-pack**: `rustwasm.github.io/wasm-pack`
