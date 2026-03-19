<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

# Phase 5 Implementation Plan — CLI + Ergonomics (Rust Track)

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver zone diff engine, rndc connection pooling, and a CLI tool for bind9-sdk — completing Phase 5 (v0.5.0), the Rust track of post-Phase 2 work.

**Architecture:** Three waves: W1 runs 2 parallel worktrees (zone diff in core, connection pooling in net); W2 builds the CLI tool (depends on W1); W3 is hardening + shell completions. Runs in parallel with JS track (Phases 3-4) — zero file overlap between tracks.

**Tech Stack:** Rust 2024, tokio, clap, clap_complete, proptest, Podman BIND9

**Spec:** `docs/specs/2026-03-17-phases2-5-parallel-execution-design.md` §4
**Depends on:** Phase 2 complete (P2-W3 merged to `development`)

## File Structure

### New files

| File | Crate | Purpose |
| --- | --- | --- |
| `crates/bind9-sdk-core/src/zone/diff.rs` | core | Zone diff engine — `Zone::diff()`, `ZoneDiff`, `DiffEntry` |
| `crates/bind9-sdk-net/src/pool.rs` | net | `RndcPool` — semaphore-based concurrency limiter |
| `crates/bind9-sdk-cli/Cargo.toml` | cli | New binary crate |
| `crates/bind9-sdk-cli/src/main.rs` | cli | Entry point |
| `crates/bind9-sdk-cli/src/error.rs` | cli | `CliError` enum |
| `crates/bind9-sdk-cli/src/config.rs` | cli | Config file loading (TOML) |
| `crates/bind9-sdk-cli/src/commands/mod.rs` | cli | Command dispatch |
| `crates/bind9-sdk-cli/src/commands/zone.rs` | cli | `zone list|status|reload|export|diff` |
| `crates/bind9-sdk-cli/src/commands/record.rs` | cli | `record add|delete` |
| `crates/bind9-sdk-cli/src/commands/dnssec.rs` | cli | `dnssec status|checkds` |
| `crates/bind9-sdk-cli/src/commands/stats.rs` | cli | `stats` |

### Modified files

| File | Changes |
| --- | --- |
| `crates/bind9-sdk-core/src/zone/mod.rs` | Add `pub mod diff;`, add `Zone::diff()` method |
| `crates/bind9-sdk-net/src/lib.rs` | Add `pub mod pool;` |
| `crates/bind9-sdk-net/src/config.rs` | Add pool config fields to `ClientConfig` |
| `Cargo.toml` (workspace) | Add `bind9-sdk-cli` member, `clap`, `clap_complete`, `toml` to workspace deps |

## P5-W1: Two Parallel Worktrees

### WT-F: Zone Diff Engine

**Branch:** `feat/zone-diff`
**Worktree:** `.worktrees/wt-f`

#### Task 1: DiffEntry and ZoneDiff Types

**Files:**
- Create: `crates/bind9-sdk-core/src/zone/diff.rs`
- Modify: `crates/bind9-sdk-core/src/zone/mod.rs`

- [ ] **Step 1.1: Write failing test**

  ```rust
  #[test]
  fn diff_identical_zones_is_empty() {
      let zone = make_test_zone();
      let diff = zone.diff(&zone);
      assert!(diff.entries().is_empty());
  }
  ```

- [ ] **Step 1.2: Run to verify fail**

  Run: `cargo test -p bind9-sdk-core --lib diff_identical_zones`
  Expected: FAIL — module not found

- [ ] **Step 1.3: Implement core diff types**

  ```rust
  use alloc::vec::Vec;
  use crate::record::ResourceRecord;

  /// A single difference between two zones.
  #[derive(Debug, Clone, PartialEq, Eq)]
  #[non_exhaustive]
  pub enum DiffEntry {
      /// Record exists in target but not in source.
      Added(ResourceRecord),
      /// Record exists in source but not in target.
      Removed(ResourceRecord),
      /// Record exists in both but with different TTL.
      /// (Spec §4 calls this "Modified" — `TtlChanged` is more precise since
      /// the diff algorithm compares by name+class+rtype+rdata identity, and
      /// TTL is the only remaining field that can differ.)
      TtlChanged {
          record: ResourceRecord,
          old_ttl: crate::record::Ttl,
          new_ttl: crate::record::Ttl,
      },
  }

  /// The result of comparing two zones.
  #[derive(Debug, Clone)]
  pub struct ZoneDiff {
      entries: Vec<DiffEntry>,
  }

  impl ZoneDiff {
      /// The list of differences.
      pub fn entries(&self) -> &[DiffEntry] {
          &self.entries
      }

      /// Whether the zones are identical.
      pub fn is_empty(&self) -> bool {
          self.entries.is_empty()
      }

      /// Number of differences.
      pub fn len(&self) -> usize {
          self.entries.len()
      }
  }
  ```

- [ ] **Step 1.4: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 1.5: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/zone/diff.rs crates/bind9-sdk-core/src/zone/mod.rs
  git commit -m "feat(core): zone diff types — DiffEntry, ZoneDiff"
  ```

#### Task 2: Zone::diff() Implementation

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/diff.rs`

- [ ] **Step 2.1: Write failing test — added record**

  ```rust
  #[test]
  fn diff_detects_added_record() {
      let zone_a = make_test_zone();
      let mut zone_b = make_test_zone();
      zone_b.records.push(ResourceRecord {
          name: DomainName::new("new.example.com.").unwrap(),
          class: RecordClass::IN,
          ttl: Ttl::new(3600).unwrap(),
          rdata: RecordData::A(core::net::Ipv4Addr::new(192, 0, 2, 99)),
      });
      let diff = zone_a.diff(&zone_b);
      assert_eq!(diff.len(), 1);
      assert!(matches!(&diff.entries()[0], DiffEntry::Added(_)));
  }
  ```

- [ ] **Step 2.2: Implement diff algorithm**

  Merge-join algorithm:
  1. Sort both zones' records by (name, class, rtype, rdata) — canonical order
  2. Walk both sorted lists with two pointers
  3. If left < right: record was removed
  4. If left > right: record was added
  5. If equal name+class+rtype+rdata but different TTL: `TtlChanged`
  6. SOA records excluded by default (configurable via `DiffOptions`)

  ```rust
  impl Zone {
      /// Compare this zone with another, producing a diff.
      ///
      /// SOA records are excluded by default. Use `diff_with_options()` to include them.
      pub fn diff(&self, other: &Zone) -> ZoneDiff { ... }
  }
  ```

- [ ] **Step 2.3: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 2.4: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/zone/diff.rs
  git commit -m "feat(core): Zone::diff() merge-join implementation"
  ```

#### Task 3: ZoneDiff::to_updates()

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/diff.rs`

- [ ] **Step 3.1: Write failing test**

  ```rust
  #[test]
  fn diff_to_updates_produces_valid_entries() {
      let zone_a = make_test_zone();
      let zone_b = make_modified_zone(); // has additions and removals
      let diff = zone_a.diff(&zone_b);
      let updates = diff.to_updates();
      assert!(!updates.is_empty());
      // Added records become AddRecord entries, removed become DeleteRecord
  }
  ```

- [ ] **Step 3.2: Implement to_updates()**

  ```rust
  impl ZoneDiff {
      /// Convert diff entries to RFC 2136 update entries.
      ///
      /// - `Added` → `UpdateEntry::AddRecord(record)`
      /// - `Removed` → `UpdateEntry::DeleteRecord(record)`
      /// - `TtlChanged` → `UpdateEntry::DeleteRecord(old)` + `UpdateEntry::AddRecord(new_ttl)` (with new TTL)
      pub fn to_updates(&self) -> Vec<UpdateEntry> { ... }
  }
  ```

- [ ] **Step 3.3: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 3.4: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/zone/diff.rs
  git commit -m "feat(core): ZoneDiff::to_updates() — diff to RFC 2136 entries"
  ```

#### Task 4: Human-Readable Diff Output

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/diff.rs`

- [ ] **Step 4.1: Write failing test**

  ```rust
  #[test]
  fn diff_display_format() {
      let diff = make_sample_diff();
      let text = diff.to_string();
      assert!(text.contains("+ new.example.com."));
      assert!(text.contains("- old.example.com."));
  }
  ```

- [ ] **Step 4.2: Implement Display for ZoneDiff**

  Format: `+` prefix for added, `-` for removed, `~ TTL: old → new` for TTL changes. Similar to unified diff but for DNS records.

- [ ] **Step 4.3: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 4.4: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/zone/diff.rs
  git commit -m "feat(core): human-readable ZoneDiff display output"
  ```

#### Task 5: Proptest — diff(a,b).apply(a) == b

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/diff.rs`

- [ ] **Step 5.1: Write proptest**

  ```rust
  proptest! {
      #[test]
      fn diff_apply_roundtrip(
          records_a in prop::collection::vec(arb_resource_record(), 0..20),
          records_b in prop::collection::vec(arb_resource_record(), 0..20),
      ) {
          let zone_a = Zone {
              name: DomainName::new("example.com.").unwrap(),
              class: RecordClass::IN,
              records: records_a,
          };
          let zone_b = Zone {
              name: DomainName::new("example.com.").unwrap(),
              class: RecordClass::IN,
              records: records_b,
          };
          let diff = zone_a.diff(&zone_b);
          let applied = zone_a.apply_diff(&diff);
          // After applying diff, the resulting zone should match zone_b
          // (ignoring SOA which is excluded from diff)
          let re_diff = applied.diff(&zone_b);
          prop_assert!(re_diff.is_empty(), "diff(a,b).apply(a) should equal b");
      }
  }
  ```

  This requires an `arb_resource_record()` proptest strategy and `Zone::apply_diff()` method.

- [ ] **Step 5.2: Implement Zone::apply_diff()**

  ```rust
  impl Zone {
      /// Apply a diff to this zone, producing a new zone.
      pub fn apply_diff(&self, diff: &ZoneDiff) -> Zone { ... }
  }
  ```

- [ ] **Step 5.3: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib diff_apply_roundtrip`
  Expected: PASS

- [ ] **Step 5.4: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/zone/diff.rs
  git commit -m "test(core): proptest diff(a,b).apply(a)==b invariant"
  ```

### WT-G: Connection Pooling

**Branch:** `feat/conn-pool`
**Worktree:** `.worktrees/wt-g`

#### Task 6: RndcPool Type

**Files:**
- Create: `crates/bind9-sdk-net/src/pool.rs`
- Modify: `crates/bind9-sdk-net/src/lib.rs`

- [ ] **Step 6.1: Write failing test**

  ```rust
  /// Helper — constructs a test ClientConfig via struct literal (same-crate access).
  /// Mirrors the existing test_key() pattern in config.rs.
  fn pool_config() -> ClientConfig {
      ClientConfig {
          rndc_addr: "127.0.0.1:9953".parse().unwrap(),
          rndc_key: test_key(),
          stats_url: None,
          dns_addr: None,
          tls: None,
          timeout: Duration::from_secs(10),
          pool_size: None,
      }
  }

  #[tokio::test]
  async fn pool_limits_concurrency() {
      let pool = RndcPool::new(pool_config(), 2);
      // Acquire 2 permits — both succeed
      let _p1 = pool.acquire().await.unwrap();
      let _p2 = pool.acquire().await.unwrap();
      // Third acquire should block (we test with timeout)
      let result = tokio::time::timeout(
          Duration::from_millis(50),
          pool.acquire(),
      ).await;
      assert!(result.is_err(), "should timeout — pool exhausted");
  }
  ```

- [ ] **Step 6.2: Run to verify fail**

  Expected: FAIL — module not found

- [ ] **Step 6.3: Implement RndcPool**

  ```rust
  use std::sync::Arc;
  use std::time::Duration;
  use tokio::sync::Semaphore;

  use crate::config::ClientConfig;
  use crate::error::NetError;

  /// Semaphore-based concurrency limiter for rndc connections.
  ///
  /// Each `acquire()` creates a fresh `RndcConnection` (rndc connections
  /// are not persistent — each command is a full connect→auth→command→close
  /// cycle). The pool limits how many concurrent connections exist.
  ///
  /// `ClientConfig` is NOT Clone (it contains `TsigKey` which intentionally
  /// doesn't impl Clone to prevent key material duplication). The pool wraps
  /// config in `Arc` so multiple guards can reference it without cloning.
  pub struct RndcPool {
      config: Arc<ClientConfig>,
      semaphore: Arc<Semaphore>,
  }

  /// An acquired pool slot. Releases the semaphore permit on drop.
  /// Holds an Arc reference to the shared config.
  pub struct PoolGuard {
      _permit: tokio::sync::OwnedSemaphorePermit,
      config: Arc<ClientConfig>,
  }

  impl PoolGuard {
      /// Access the connection config.
      pub fn config(&self) -> &ClientConfig {
          &self.config
      }
  }

  impl RndcPool {
      /// Create a new pool with the given concurrency limit.
      ///
      /// Takes ownership of the `ClientConfig` and wraps it in `Arc`.
      /// `max_concurrent` defaults to 4 if 0 is passed.
      pub fn new(config: ClientConfig, max_concurrent: usize) -> Self {
          let max = if max_concurrent == 0 { 4 } else { max_concurrent };
          Self {
              config: Arc::new(config),
              semaphore: Arc::new(Semaphore::new(max)),
          }
      }

      /// Acquire a pool slot. Blocks if all slots are in use.
      pub async fn acquire(&self) -> Result<PoolGuard, NetError> {
          let permit = self.semaphore.clone().acquire_owned().await
              .map_err(|_| NetError::Connection("pool closed".into()))?;
          Ok(PoolGuard {
              _permit: permit,
              config: Arc::clone(&self.config),
          })
      }

      /// Number of available slots.
      pub fn available(&self) -> usize {
          self.semaphore.available_permits()
      }
  }
  ```

  Note: This is a semaphore-based concurrency limiter, NOT a persistent connection pool. Each rndc command creates a fresh connection because the `RndcConnection<Authenticated<'k>>` lifetime makes pooling persistent connections impractical. The semaphore prevents overwhelming the BIND9 server. `ClientConfig` is wrapped in `Arc` (not cloned) because `TsigKey` intentionally doesn't implement `Clone`.

- [ ] **Step 6.4: Run tests**

  Run: `cargo test -p bind9-sdk-net --lib`
  Expected: PASS

- [ ] **Step 6.5: Commit**

  ```bash
  git add crates/bind9-sdk-net/src/pool.rs crates/bind9-sdk-net/src/lib.rs
  git commit -m "feat(net): RndcPool — semaphore-based rndc concurrency limiter"
  ```

#### Task 7: Wire Pool into ClientConfig

**Files:**
- Modify: `crates/bind9-sdk-net/src/config.rs`

- [ ] **Step 7.1: Write failing test**

  ```rust
  #[test]
  fn client_config_pool_defaults() {
      let config = test_config(); // uses struct literal construction (see net/src/config.rs)
      assert_eq!(config.pool_size, None); // Pool disabled by default
  }

  #[test]
  fn client_config_with_pool() {
      let mut config = test_config();
      config.pool_size = Some(4);
      assert_eq!(config.pool_size, Some(4));
  }

  // Helper matching existing net crate test pattern:
  // fn test_config() -> ClientConfig { ClientConfig { rndc_addr: ..., rndc_key: test_key(), ... } }
  ```

- [ ] **Step 7.2: Add pool config to ClientConfig**

  Add `pool_size: Option<usize>` field with builder method `with_pool(size)`.

  **Important:** `ClientConfig` is `#[non_exhaustive]` and constructed via struct literal. Adding a new field is a breaking change for any external struct literal construction (which is already impossible thanks to `#[non_exhaustive]`). However, all *internal* construction sites in tests and the net crate must be updated to include `pool_size: None`. Search for `ClientConfig {` across the workspace and update every occurrence.

- [ ] **Step 7.3: Run tests**

  Run: `cargo test -p bind9-sdk-net --lib`
  Expected: PASS

- [ ] **Step 7.4: Commit**

  ```bash
  git add crates/bind9-sdk-net/src/config.rs
  git commit -m "feat(net): pool_size config in ClientConfig"
  ```

#### Task 8: Integration Test — Burst Through Pool

**Files:**
- Create: `crates/bind9-sdk-net/tests/pool_integration.rs`

- [ ] **Step 8.1: Write integration test**

  **Note:** The `test_key()` helper in `net/src/config.rs` is `#[cfg(test)]` and not accessible from integration test files (they compile as separate crates). Either: (a) create a shared `tests/common/mod.rs` test helper, or (b) construct the `TsigKey` directly in the integration test using `TsigKey::from_base64()`.

  ```rust
  #[tokio::test]
  #[ignore = "requires live BIND9 on localhost:9953"]
  async fn pool_burst_10_through_2() {
      // Construct config directly — test_key() is #[cfg(test)] and
      // inaccessible from integration test crates. Use TsigKey::from_base64().
      let config = make_test_config(); // local helper in this file
      let pool = Arc::new(RndcPool::new(config, 2));

      let mut handles = Vec::new();
      for _ in 0..10 {
          let pool = Arc::clone(&pool);
          handles.push(tokio::spawn(async move {
              let guard = pool.acquire().await.unwrap();
              // Execute rndc status through this guard
              // guard.execute(RndcCommand::Status).await.unwrap();
          }));
      }

      for h in handles {
          h.await.unwrap();
      }
  }
  ```

- [ ] **Step 8.2: Commit**

  ```bash
  git add crates/bind9-sdk-net/tests/pool_integration.rs
  git commit -m "test(net): pool burst integration test — 10 commands through 2 slots"
  ```

### P5-W1 Merge

- [ ] **Step 9.1: Merge WT-F (zone diff)**

  ```bash
  git checkout development
  git merge feat/zone-diff --no-ff -m "feat: P5-W1 zone diff engine (WT-F)"
  ```

- [ ] **Step 9.2: Merge WT-G (connection pool)**

  ```bash
  git merge feat/conn-pool --no-ff -m "feat: P5-W1 rndc connection pooling (WT-G)"
  ```

- [ ] **Step 9.3: Run full quality gate**

  ```bash
  cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo check -p bind9-sdk-core --target wasm32-unknown-unknown && cargo test --workspace
  ```

## P5-W2: CLI Tool

**Branch:** `feat/cli`
**Depends on:** WT-F + WT-G merged

#### Task 10: Scaffold bind9-sdk-cli Crate

**Files:**
- Create: `crates/bind9-sdk-cli/Cargo.toml`
- Create: `crates/bind9-sdk-cli/src/main.rs`
- Create: `crates/bind9-sdk-cli/src/error.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 10.1: Add workspace deps**

  In workspace `Cargo.toml`:

  ```toml
  clap = { version = "4", features = ["derive"] }
  clap_complete = "4"
  toml = "0.8"
  ```

  Add to members: `"crates/bind9-sdk-cli"`

- [ ] **Step 10.2: Create Cargo.toml**

  ```toml
  # SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
  # SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

  [package]
  name = "bind9-sdk-cli"
  version.workspace = true
  edition.workspace = true
  rust-version.workspace = true
  license.workspace = true
  description = "CLI tool for BIND9 DNS server management"
  keywords.workspace = true
  categories.workspace = true

  [[bin]]
  name = "bind9"
  path = "src/main.rs"

  [dependencies]
  bind9-sdk = { path = "../../bind9-sdk" }
  clap = { workspace = true }
  clap_complete = { workspace = true }
  tokio = { workspace = true }
  toml = { workspace = true }
  serde = { workspace = true, features = ["std"] }  # workspace serde is no_std; CLI needs std
  tracing = { workspace = true }
  tracing-subscriber = { version = "0.3", features = ["env-filter"] }
  ```

- [ ] **Step 10.3: Create error.rs**

  ```rust
  // SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
  //
  // SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

  /// CLI errors — one enum per crate.
  #[derive(Debug, thiserror::Error)]
  #[non_exhaustive]
  pub enum CliError {
      /// Network operation failed.
      #[error(transparent)]
      Net(#[from] bind9_sdk::net::NetError),

      /// Core operation failed.
      #[error(transparent)]
      Core(#[from] bind9_sdk::CoreError),

      /// Config file parse error.
      #[error("config error: {0}")]
      Config(String),

      /// I/O error.
      #[error("I/O error: {0}")]
      Io(#[from] std::io::Error),
  }
  ```

- [ ] **Step 10.4: Create minimal main.rs**

  ```rust
  // SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
  //
  // SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

  mod error;

  fn main() {
      eprintln!("bind9-sdk CLI — not yet implemented");
      std::process::exit(2);
  }
  ```

- [ ] **Step 10.5: Verify it compiles**

  Run: `cargo build -p bind9-sdk-cli`
  Expected: compiles successfully

- [ ] **Step 10.6: Commit**

  ```bash
  git add crates/bind9-sdk-cli/ Cargo.toml
  git commit -m "feat(cli): scaffold bind9-sdk-cli crate"
  ```

#### Task 11: Config File Loading

**Files:**
- Create: `crates/bind9-sdk-cli/src/config.rs`

- [ ] **Step 11.1: Write failing test**

  ```rust
  #[test]
  fn parse_config_minimal() {
      let toml = r#"
      [server]
      host = "127.0.0.1"
      port = 953

      [auth]
      key_name = "rndc-key"
      key_secret = "dGVzdA=="
      "#;
      let config = CliConfig::from_str(toml).unwrap();
      assert_eq!(config.server.host, "127.0.0.1");
      assert_eq!(config.server.port, 953);
  }
  ```

- [ ] **Step 11.2: Implement CliConfig**

  ```rust
  use serde::Deserialize;

  #[derive(Debug, Deserialize)]
  pub struct CliConfig {
      pub server: ServerConfig,
      pub auth: Option<AuthConfig>,
  }

  #[derive(Debug, Deserialize)]
  pub struct ServerConfig {
      pub host: String,
      #[serde(default = "default_port")]
      pub port: u16,
  }

  fn default_port() -> u16 { 953 }

  #[derive(Debug, Deserialize)]
  pub struct AuthConfig {
      pub key_name: String,
      pub key_secret: String,
      #[serde(default = "default_algorithm")]
      pub algorithm: String,
  }

  fn default_algorithm() -> String { "hmac-sha256".into() }
  ```

  Config file path: `$XDG_CONFIG_HOME/bind9-sdk/config.toml` on Linux, `~/Library/Application Support/bind9-sdk/config.toml` on macOS.

- [ ] **Step 11.3: Run tests**

  Run: `cargo test -p bind9-sdk-cli`
  Expected: PASS

- [ ] **Step 11.4: Commit**

  ```bash
  git add crates/bind9-sdk-cli/src/config.rs
  git commit -m "feat(cli): TOML config file loading with XDG/macOS paths"
  ```

#### Task 12: Clap Command Structure

**Files:**
- Create: `crates/bind9-sdk-cli/src/commands/mod.rs`
- Create: `crates/bind9-sdk-cli/src/commands/zone.rs`
- Create: `crates/bind9-sdk-cli/src/commands/record.rs`
- Create: `crates/bind9-sdk-cli/src/commands/dnssec.rs`
- Create: `crates/bind9-sdk-cli/src/commands/stats.rs`
- Modify: `crates/bind9-sdk-cli/src/main.rs`

  **TDD note:** Clap command structure is scaffolding — the "test" is `cargo run -- --help` at Step 12.4 which verifies the structure parses and renders. Full TDD with `assert_cmd` is deferred to integration tests (Task 18).

- [ ] **Step 12.1: Define clap CLI structure**

  ```rust
  use clap::{Parser, Subcommand};

  #[derive(Parser)]
  #[command(name = "bind9", about = "BIND9 DNS server management CLI")]
  pub struct Cli {
      /// Server hostname
      #[arg(long, global = true)]
      pub server: Option<String>,

      /// Server port
      #[arg(long, global = true)]
      pub port: Option<u16>,

      /// TSIG key name
      #[arg(long, global = true)]
      pub key_name: Option<String>,

      /// TSIG key secret (base64)
      #[arg(long, global = true)]
      pub key_secret: Option<String>,

      /// Output format
      #[arg(long, global = true, default_value = "text")]
      pub output: OutputFormat,

      #[command(subcommand)]
      pub command: Command,
  }

  #[derive(Subcommand)]
  pub enum Command {
      /// Zone management
      Zone(ZoneArgs),
      /// Record management
      Record(RecordArgs),
      /// DNSSEC operations
      Dnssec(DnssecArgs),
      /// Server statistics
      Stats,
  }

  #[derive(Clone, clap::ValueEnum)]
  pub enum OutputFormat {
      Text,
      Json,
  }
  ```

- [ ] **Step 12.2: Implement zone subcommands**

  ```rust
  #[derive(clap::Args)]
  pub struct ZoneArgs {
      #[command(subcommand)]
      pub action: ZoneAction,
  }

  #[derive(Subcommand)]
  pub enum ZoneAction {
      /// List all zones
      List,
      /// Show zone status
      Status { zone: String },
      /// Reload a zone
      Reload { zone: String },
      /// Export zone file
      Export { zone: String },
      /// Diff two zone files
      Diff { file_a: String, file_b: String },
  }
  ```

- [ ] **Step 12.3: Wire main.rs to clap**

  ```rust
  #[tokio::main]
  async fn main() -> std::process::ExitCode {
      let cli = Cli::parse();
      // Initialize tracing
      tracing_subscriber::fmt()
          .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
          .init();

      match run(cli).await {
          Ok(()) => std::process::ExitCode::from(0),
          Err(CliError::Config(_)) => {
              eprintln!("Usage error");
              std::process::ExitCode::from(2)
          }
          Err(e) => {
              eprintln!("Error: {e}");
              std::process::ExitCode::from(1)
          }
      }
  }
  ```

- [ ] **Step 12.4: Verify help output**

  Run: `cargo run -p bind9-sdk-cli -- --help`
  Expected: shows help with zone/record/dnssec/stats subcommands

- [ ] **Step 12.5: Commit**

  ```bash
  git add crates/bind9-sdk-cli/src/
  git commit -m "feat(cli): clap command structure — zone, record, dnssec, stats"
  ```

#### Task 13: Implement Zone Commands

**Files:**
- Modify: `crates/bind9-sdk-cli/src/commands/zone.rs`

- [ ] **Step 13.1: Implement zone list**

  Calls `rndc zonestatus` for all zones. Outputs as table (text) or JSON array.

- [ ] **Step 13.2: Implement zone diff**

  Reads two zone files from disk, parses with `ZoneFile::parse()`, calls `Zone::diff()`, prints result.

- [ ] **Step 13.3: Implement zone export**

  Calls AXFR transfer for the zone, serializes to zone file format.

- [ ] **Step 13.4: Run tests**

  Run: `cargo test -p bind9-sdk-cli`
  Expected: PASS

- [ ] **Step 13.5: Commit**

  ```bash
  git add crates/bind9-sdk-cli/src/commands/zone.rs
  git commit -m "feat(cli): zone list, diff, export commands"
  ```

#### Task 14: Implement Record, DNSSEC, Stats Commands

**Files:**
- Modify: `crates/bind9-sdk-cli/src/commands/record.rs`
- Modify: `crates/bind9-sdk-cli/src/commands/dnssec.rs`
- Modify: `crates/bind9-sdk-cli/src/commands/stats.rs`

  **TDD note:** These commands are thin wrappers around SDK methods (already tested in core/net). Unit tests validate command output formatting; integration tests against live BIND9 in Task 18 validate end-to-end behavior.

- [ ] **Step 14.1: Implement record add/delete**

  `record add` builds an `UpdateBuilder`, signs with TSIG, sends via `NsUpdateSender`.
  `record delete` does the same with delete prerequisites.

- [ ] **Step 14.2: Implement dnssec status/checkds**

  Wraps `rndc dnssec -status` and `rndc dnssec -checkds` commands.

- [ ] **Step 14.3: Implement stats**

  Calls `StatsHttpClient` to fetch server statistics, formats as table or JSON.

- [ ] **Step 14.4: Run tests**

  Run: `cargo test -p bind9-sdk-cli`
  Expected: PASS

- [ ] **Step 14.5: Commit**

  ```bash
  git add crates/bind9-sdk-cli/src/commands/
  git commit -m "feat(cli): record add/delete, dnssec status/checkds, stats commands"
  ```

#### Task 15: JSON Output + Exit Codes

**Files:**
- Modify: `crates/bind9-sdk-cli/src/main.rs`
- Modify: `crates/bind9-sdk-cli/src/commands/mod.rs`

- [ ] **Step 15.1: Write test for JSON output**

  ```rust
  #[test]
  fn json_output_is_valid() {
      // Test that --output json produces valid JSON for each command
  }
  ```

- [ ] **Step 15.2: Implement serde serialization for all command outputs**

  Each command result type gets `#[derive(Serialize)]` and a `to_json()` method.

- [ ] **Step 15.3: Verify exit codes**

  - 0: success
  - 1: operational error (connection failed, command rejected)
  - 2: usage error (bad args, config parse failure)

- [ ] **Step 15.4: Run tests**

  Run: `cargo test -p bind9-sdk-cli`
  Expected: PASS

- [ ] **Step 15.5: Commit**

  ```bash
  git add crates/bind9-sdk-cli/src/
  git commit -m "feat(cli): JSON output + exit code conventions"
  ```

#### Task 16: Binary Size Check (PR-006)

- [ ] **Step 16.1: Build release binary**

  ```bash
  cargo build --release -p bind9-sdk-cli
  strip target/release/bind9
  ls -lh target/release/bind9
  ```

  Expected: < 10MB stripped (PR-006 requirement)

- [ ] **Step 16.2: If oversized, investigate with cargo-bloat**

  ```bash
  cargo install cargo-bloat
  cargo bloat --release -p bind9-sdk-cli -n 20
  ```

- [ ] **Step 16.3: Commit any size optimizations**

## P5-W3: Hardening

**Branch:** `feat/p5-hardening`

#### Task 17: Shell Completions

**Files:**
- Modify: `crates/bind9-sdk-cli/src/main.rs`

- [ ] **Step 17.1: Add completion generation command**

  ```rust
  #[derive(Subcommand)]
  pub enum Command {
      // ... existing commands ...
      /// Generate shell completions
      Completions {
          /// Shell to generate completions for
          #[arg(value_enum)]
          shell: clap_complete::Shell,
      },
  }
  ```

- [ ] **Step 17.2: Implement completion generation**

  ```rust
  Command::Completions { shell } => {
      clap_complete::generate(
          shell,
          &mut Cli::command(),
          "bind9",
          &mut std::io::stdout(),
      );
  }
  ```

- [ ] **Step 17.3: Test each shell**

  ```bash
  cargo run -p bind9-sdk-cli -- completions bash > /dev/null
  cargo run -p bind9-sdk-cli -- completions zsh > /dev/null
  cargo run -p bind9-sdk-cli -- completions fish > /dev/null
  ```

- [ ] **Step 17.4: Commit**

  ```bash
  git add crates/bind9-sdk-cli/src/main.rs
  git commit -m "feat(cli): shell completion generation — bash, zsh, fish"
  ```

#### Task 18: Integration Tests Against Podman

- [ ] **Step 18.1: Write CLI integration tests**

  ```rust
  #[tokio::test]
  #[ignore = "requires live BIND9 on localhost:9953"]
  async fn cli_zone_list() {
      let output = Command::new("cargo")
          .args(["run", "-p", "bind9-sdk-cli", "--", "zone", "list",
                 "--server", "127.0.0.1", "--port", "9953",
                 "--key-name", "rndc-key", "--key-secret", "..."])
          .output()
          .await
          .unwrap();
      assert!(output.status.success());
  }
  ```

- [ ] **Step 18.2: Run integration tests**

  ```bash
  make test-integration
  ```

- [ ] **Step 18.3: Commit**

  ```bash
  git add crates/bind9-sdk-cli/tests/
  git commit -m "test(cli): integration tests against Podman BIND9"
  ```

#### Task 19: Dialectic Verification

- [ ] **Step 19.1: Run `/dialectic-verify` on Phase 5 codebase**
- [ ] **Step 19.2: Remediate findings**
- [ ] **Step 19.3: Update audit-findings.md**

#### Task 20: Phase 5 Completion

- [ ] **Step 20.1: Merge to development**

  ```bash
  git checkout development
  git merge feat/p5-hardening --no-ff -m "feat: Phase 5 complete — zone diff, connection pool, CLI tool"
  ```

- [ ] **Step 20.2: Update PRD with Phase 5 status**
- [ ] **Step 20.3: Push**

  ```bash
  git push origin development
  ```
