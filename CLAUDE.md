<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
-->

# bind9-sdk

Rust SDK for programmatic BIND9 DNS server management. Implements the rndc wire protocol, RFC 1035 zone file parsing, RFC 2136 dynamic updates (nsupdate), IXFR/AXFR zone transfer, and the BIND9 statistics-channel JSON API — all with zero shell subprocess dependencies.

Distributes as three coordinated artifacts from one codebase: a Rust crate (`bind9-sdk` on crates.io), a Node.js/Bun native addon (napi-rs v3 from `bind9-sdk-bindings`; native `.node` + WASM fallback), and a CLI tool (`bind9` binary from `bind9-sdk-cli`).

## Prerequisites

- Rust 1.94.0 — `rust-toolchain.toml` pins channel and installs `wasm32-unknown-unknown`
- BIND9 9.20 — for integration tests (Podman rootless or native `named`)

## Commands

```bash
# Type-check all crates (both native and WASM targets)
cargo check --workspace
cargo check -p bind9-sdk-core --target wasm32-unknown-unknown

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

# CLI binary
cargo build -p bind9-sdk-cli
cargo run -p bind9-sdk-cli -- --help

# Node.js/Bun native addon build (full surface via napi-rs v3)
cargo build --release --manifest-path crates/bind9-sdk-bindings/Cargo.toml --features nodejs

# Audit
cargo audit
cargo deny check
```

## Workspace Architecture

```txt
bind9-sdk/                     ← git repo root (this directory)
├── bind9-sdk/                 ← re-export crate (public crates.io API)
│   └── src/lib.rs
├── crates/
│   ├── bind9-sdk-core/        ← no_std + alloc; DNS types, zone parsing, RFC 2136, TSIG
│   │   └── src/
│   │       ├── tsig/          ← TSIG: key, record, wire, tests
│   │       ├── update/        ← RFC 2136: builder, message, tests
│   │       └── zone/          ← zone parser/serializer, diff; parser/ is itself a submodule
│   ├── bind9-sdk-net/         ← tokio; rndc TCP, nsupdate sender, IXFR/AXFR, stats HTTP
│   │   └── src/
│   │       ├── rndc/          ← rndc wire protocol + DNSSEC commands
│   │       ├── transfer/      ← IXFR/AXFR zone transfer client
│   │       ├── pool.rs        ← persistent authenticated connections (RndcPool)
│   │       └── limiter.rs     ← fresh-cycle concurrency limiting (RndcLimiter)
│   ├── bind9-sdk-bindings/    ← napi-rs v3 (Node.js/Bun native addon + WASM fallback)
│   └── bind9-sdk-cli/         ← clap CLI binary (`bind9`); zone/record/dnssec/stats subcommands
├── docs/
│   ├── plans/                 ← implementation plans
│   └── specs/                 ← design specs
├── Cargo.toml                 ← workspace root
├── rust-toolchain.toml
└── REUSE.toml
```

### Crate Responsibilities

| Crate | `no_std` | Feature gate | What it provides |
| --- | --- | --- | --- |
| `bind9-sdk-core` | Yes | — | `DomainName`, `ResourceRecord`, `RecordData` (20+ variants), `Rcode`, `RecordType`, zone file parser/emitter (`ZoneFile`, `Zone`), zone diffing (`ZoneDiff`, `DiffEntry`, `Zone::diff()`/`apply_diff()`), RFC 2136 `UpdateBuilder` (typestate `Unsigned`/`Signed`, `UpdateMessage` with `request_mac()`), TSIG (`TsigKey`, `TsigRecord` with wire parsing + response verification, HMAC-SHA256/SHA512/SHA1), management traits (`NamedControl`, `DynamicUpdater`, `ZoneManager`, `StatsClient`) |
| `bind9-sdk-net` | No | `net` (default) | `Bind9Client`, `ClientConfig`, `NetError`, `TlsConfig`; full typed BIND 9.20 rndc grammar, persistent `RndcPool`, fresh-cycle `RndcLimiter`, `NsUpdateSender`, typed `StatsHttpClient`, and verified IXFR/AXFR/XoT |
| `bind9-sdk-bindings` | — | `nodejs` | napi-rs v3: native `.node` + WASM fallback. Modules: domain, zone, record, tsig, update, rndc, nsupdate, stats, transfer, limiter. Net modules gated behind `#[cfg(not(target_arch = "wasm32"))]` |
| `bind9-sdk-cli` | — | — | `bind9` binary (clap). Subcommands: zone, record, dnssec, stats, completions. TOML config from XDG/macOS paths. Depends on `bind9-sdk` (re-export crate) |
| `bind9-sdk` | — | — | Re-exports `core` and optionally `net`; the single crates.io entry point |

## Feature Flags

| Flag | Crate | Effect |
| --- | --- | --- |
| `std` | `bind9-sdk-core` | Enables `std::error::Error` impls; disables `no_std` |
| `serde` | `bind9-sdk-core` | Enables `Serialize`/`Deserialize` on DNS types |
| `net` *(default)* | `bind9-sdk` | Includes `bind9-sdk-net` (rndc, nsupdate, IXFR/AXFR, stats) |
| `parallel` | `bind9-sdk-core` | Enables Rayon-based parallel zone parsing (implies `std`, incompatible with WASM) |
| `nodejs` | `bind9-sdk-bindings` | Enables napi-rs v3 exports: native `.node` + WASM fallback |

## Key Design Decisions

1. **`no_std` core** — `bind9-sdk-core` compiles without std via `#![no_std]` + `extern crate alloc;`. This is the constraint that makes browser WASM work without feature hacks. All crypto (HMAC-SHA256/SHA512) uses RustCrypto crates which are `no_std` compatible.

2. **Trait-first** — Management operations are defined as traits (`ZoneManager`, `NamedControl`, `DynamicUpdater`, `StatsClient`) in `bind9-sdk-core`. The net layer provides concrete implementations. Tests use mock implementations against the traits.

3. **TSIG in core, send in net** — TSIG key material, HMAC computation, message authentication code construction, wire parsing (`TsigRecord::parse_from_wire`), and response verification (`TsigRecord::verify_response` per RFC 8945 §4.5) live in `bind9-sdk-core` (no_std). The net layer calls `verify_response` with the request MAC for TSIG chaining. This separation makes TSIG testable without a network.

4. **rndc wire protocol is NOT DNS** — BIND9's rndc uses a custom TCP framing format: 4-byte big-endian length prefix + ISC internal message encoding. Do not confuse with DNS-over-TCP (2-byte prefix). The protocol is documented in the BIND source (`lib/isc/netmgr/`, ISC KB). It is stable across BIND9 minor versions.

5. **napi-rs v3 unified bindings** — napi-rs v3 (napi-build = "2") compiles to both native `.node` files and `wasm32-wasip1-threads` WASM from the same binding code. Net-dependent modules are gated behind `#[cfg(not(target_arch = "wasm32"))]` so core-only bindings (domain, zone, record, tsig, update) work in WASM. `wasm32-unknown-unknown` is retained in `rust-toolchain.toml` solely for the `no_std` validation hook on `bind9-sdk-core`.

6. **`bind9-sdk` is the only published user-facing crate** — Users add `bind9-sdk` to their `Cargo.toml`, never internal crates directly. Internal crates are published to satisfy crates.io dependency resolution but carry no stability guarantees of their own.

## Coding Architecture

Full spec: `docs/specs/2026-03-14-coding-architecture-design.md`

Key patterns enforced across all implementation:

- **Make invalid states unrepresentable** — newtypes (`DomainName`, `Ttl`, `Serial`), typestate (`UpdateBuilder<Unsigned/Signed>`, `RndcConnection<Unauth/Auth>`), `#[non_exhaustive]` enums
- **Parse, don't validate** — external input validated once at construction, trusted thereafter
- **Error strategy** — one `#[non_exhaustive]` `thiserror` enum per crate (`CoreError`, `NetError`). No `anyhow`, no `Box<dyn Error>`. `thiserror` 2.x with `default-features = false` in core (no_std)
- **Trait design** — management traits in `core` with associated error types (`type Error: core::error::Error + Send + Sync + 'static`) to avoid circular deps. `net::Bind9Client` implements with `type Error = NetError`
- **Secret-bearing types** — manual `Debug`/`Display` with `[REDACTED]`, `ZeroizeOnDrop`, no `Clone`. Applies to `TsigKey`, `RndcKey`, any key material
- **Observability** — `tracing` crate for all instrumentation. Structured fields, never interpolated strings. Key material never in any log field
- **File size** — target 200–300 lines, split at ~400. `rdata.rs` expected to become `rdata/` submodule early
- **Testing** — proptest for roundtrip/invariant properties, insta for serialization snapshots, hand-written mocks for trait testing. `#![forbid(unsafe_code)]` in `core` and `net`

## Gotchas

- **`no_std` means `core::error::Error`** — `std::error::Error` is not available in `bind9-sdk-core`. Use `core::error::Error` (stable since Rust 1.81, which is below our rust-version of 1.94). The `std` feature flag on `bind9-sdk-core` opts back in to `std::error::Error`.
- **`wasm32-unknown-unknown` is for `no_std` validation only** — retained in `rust-toolchain.toml` for the WASM check hook on `bind9-sdk-core`. The napi-rs v3 WASM output uses `wasm32-wasip1-threads` (handled by the napi CLI, not the toolchain file).
- **napi-rs requires a native build step** — `cargo build --features nodejs` alone is not enough; napi-rs needs `napi build --release` to generate the `.node` file and JS bindings. Uses napi-rs v3 with napi-build = "2".
- **CLI config resolution** — `bind9-sdk-cli` reads TOML config from XDG (`$XDG_CONFIG_HOME/bind9/config.toml`) or macOS (`~/Library/Application Support/bind9/config.toml`) via the `dirs` crate. Missing config is not an error.
- **TSIG key format in `rndc.conf`** — base64-encoded raw HMAC-SHA256 key material, not PEM. The `algorithm hmac-sha256;` line is not a hint about encoding — it specifies the MAC algorithm directly.
- **BIND9 rndc framing** — message length is encoded as a big-endian u32 (4 bytes), not the 2-byte DNS TCP length. Misreading this is the most common rndc client implementation bug.
- **`cargo check --workspace` does not check WASM target** — always also run `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown` before PR to catch `no_std` violations in core. The `--workspace` variant fails because non-core crates depend on `getrandom` which doesn't compile on `wasm32-unknown-unknown`.

## Code Style

- Rust 2024 edition, stable toolchain
- `cargo fmt` + `clippy --workspace -D warnings` enforced by PostToolUse hook
- `#![no_std]` in `bind9-sdk-core` — verified by WASM target check
- SPDX headers on all source files (`// SPDX-...` for Rust, `# SPDX-...` for TOML, `<!-- SPDX-... -->` for Markdown)
- License: AGPL-3.0-only OR LicenseRef-Commercial (REUSE compliant via `REUSE.toml`)

## Claude Code Hooks

| Hook | Trigger | Action |
| --- | --- | --- |
| `superpowers-check.sh` | SessionStart | Verifies superpowers plugin is active |
| `block-generated-files.sh` | PreToolUse (Edit/Write) | Blocks manual edits to `Cargo.lock` |
| `spdx-header-check.sh` | PreToolUse (Write) | Blocks new file creation without SPDX header |
| `edition-check.sh` | PreToolUse (Write) | Verifies `edition = "2024"` in new `Cargo.toml` files |
| `rust-fmt.sh` | PostToolUse (Edit/Write) | Auto-formats any edited `.rs` file with `rustfmt` |
| `wasm-check.sh` | PostToolUse (Edit/Write) | Runs `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown` on core crate edits |
| `clippy-gate.sh` | PostToolUse (Edit/Write) | Runs `cargo clippy -p <crate> -- -D warnings` on `.rs` edits |
| `dep-freshness.sh` | PostToolUse (Edit) | Warns if `Cargo.toml` dep versions are below known minimums |
| `cargo-test-gate.sh` | PostToolUse (Edit/Write) | Runs `cargo test -p <crate> --lib` on `.rs` edits (non-blocking); covers all submodule paths |
| `fmt-drift-guard.sh` | Stop | Runs `cargo fmt --all --check` at end of session; warns on cross-file drift (non-blocking) |
| `no-std-import-guard.sh` | PreToolUse (Edit/Write) | Blocks bare `use std::` in `bind9-sdk-core` without `cfg` guard |

## Agents

| Agent | Purpose |
| --- | --- |
| `cargo-dep-auditor` | Audit Cargo deps for outdated versions, yanked crates, security advisories |
| `rust-security-reviewer` | Security audit: TSIG/crypto key exposure, DNS parsing safety, rndc input validation, RFC 2136 injection, WASM boundary, napi-rs FFI, zeroization, NIS2 logging compliance |
| `api-compat-reviewer` | Verify pub API surface, `#[non_exhaustive]` enums, Send+Sync bounds, re-export coverage, semver compatibility |
| `rfc-compliance-checker` | Verify implementation matches referenced RFC requirements, check edge cases, report deviations with section references |
| `dnssec-security-auditor` | DNSSEC key management security: key material exposure, zeroization, per-zone isolation, KASP timing, CDS/CDNSKEY bootstrapping |
| `wire-format-validator` | Validate DNS/rndc wire format output byte-by-byte against RFC specifications and test vectors |
| `rndc-packet-tracer` | Annotate rndc wire packets byte-by-byte, decode ISC binary association lists, verify HMAC-SHA256, generate test vectors |

## Skills

Invoke with `/skill-name` or via the Skill tool.

| Skill | Invocation | Purpose |
| --- | --- | --- |
| `ci-check [fast\|full\|test <name>]` | User | Run full CI gate: fmt, clippy, WASM, tests, audit, REUSE |
| `reuse-annotate <file(s)>` | User | Add SPDX/REUSE headers to new files |
| `wave-setup <wt-id>` | User | Create a single git worktree for a named wave plan |
| `parallel-wave-setup <wt-ids...>` | User | Create multiple worktrees at once, resolve dependencies, output launch table |
| `wave-status [merge <branch>]` | User | Show status of all active worktrees; merge + cleanup a completed branch |
| `release-prep` | User | Full pre-publish readiness gate: audit agents + cargo checks + PRD blockers → go/no-go |
| `new-crate <name> [--no-std] [--net]` | User | Scaffold a new workspace crate with correct boilerplate |

## Compliance

SDK targets compliance with GDPR, NIS2 (EU 2022/2555), NIST SP 800-53/800-81/800-57, ISO 27001:2022, and SOC 2 Type II requirements relevant to DNS infrastructure. All defaults exceed minimum compliance thresholds. See PRD §8 (Compliance Requirements) for full requirement set.

## Verification Workflow

- **Every change**: `rustfmt` + `clippy` (hooks, automatic)
- **Core crate edits**: WASM target check (hook, automatic)
- **Before commit**: `/verify` — single GLM5 pass
- **Security-sensitive code**: `/dialectic-verify` — parallel multi-model critique
- **Before release**: `cargo-dep-auditor` + `rust-security-reviewer` + `api-compat-reviewer` (all three)
- **Architectural decisions**: `/dialectic-verify` mandatory

## References

- **Coding architecture**: `docs/specs/2026-03-14-coding-architecture-design.md` — type patterns, error strategy, trait design, observability, testing
- **Design specs**: `docs/specs/` (brainstorming skill writes specs here, not the default `docs/superpowers/specs/`)
- **Implementation plans**: `docs/plans/` (writing-plans skill writes plans here, not the default `docs/superpowers/plans/`)
- **PRD**: `PRD.md`
- **Research doc**: `/Users/sephyi/Documents/Markdown/huhn/bind9-dns-management-2026.md`
- **hu.hn infra plans**: `/Users/sephyi/Documents/Markdown/huhn/dev-concerns.md`
- **rndc wire protocol**: BIND9 source `lib/isc/netmgr/`, ISC Knowledge Base
- **RFC 1035**: Domain Names — Implementation and Specification
- **RFC 2136**: Dynamic Updates in the Domain Name System
- **RFC 8945**: Secret Key Transaction Authentication for DNS (TSIG)
- **RustCrypto hmac/sha2**: `docs.rs/hmac`, `docs.rs/sha2`
- **napi-rs**: `napi.rs`
