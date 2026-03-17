<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Phases 3-4 Implementation Plan — napi-rs Bindings + npm Package (JS Track)

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate bind9-sdk-bindings from napi-rs v2 to v3, expose the full SDK surface as JS/WASM bindings, and assemble a local-testable npm package — completing Phases 3 (v0.3.0) and 4 (v0.4.0), the JS track of post-Phase 2 work.

**Architecture:** Phase 3 has 3 waves: W1 sets up napi-rs v3 foundation; W2 binds the core surface (zone parsing, records, TSIG, UpdateBuilder); W3 hardens. Phase 4 has 2 waves: W1 binds the full SDK surface (rndc, nsupdate, stats, transfer); W2 assembles the npm package for local testing. All "JS" code is Rust with `#[napi]` macros — napi-rs auto-generates native `.node`, WASM binary, `.d.ts` types, and JS loader. Zero hand-written TypeScript.

**Tech Stack:** Rust 2024, napi-rs v3 (or v2 if v3 gate fails), `wasm32-wasip1-threads`, Node.js 20/22 LTS, Bun

**Spec:** `docs/specs/2026-03-17-phases2-5-parallel-execution-design.md` §5-6
**Depends on:** Phase 2 complete + napi-rs v3 research spike (P2-W2)

**No-publish constraint:** `package.json` has `"private": true`. Local `npm pack` testing only. No `npm publish`.

## File Structure

### New files

| File | Crate | Purpose |
| --- | --- | --- |
| `crates/bind9-sdk-bindings/src/error.rs` | bindings | `BindSdkError` — maps Core/Net errors to JS |
| `crates/bind9-sdk-bindings/src/domain.rs` | bindings | `JsDomainName` class |
| `crates/bind9-sdk-bindings/src/zone.rs` | bindings | `JsZoneFile` — parse/serialize |
| `crates/bind9-sdk-bindings/src/record.rs` | bindings | `JsResourceRecord`, `JsRecordData` |
| `crates/bind9-sdk-bindings/src/tsig.rs` | bindings | `JsTsigKey` (Arc wrapper — no key material crosses FFI) |
| `crates/bind9-sdk-bindings/src/update.rs` | bindings | `JsUpdateBuilder` chain API |
| `crates/bind9-sdk-bindings/src/rndc.rs` | bindings | `JsRndcClient` — async rndc commands (native only) |
| `crates/bind9-sdk-bindings/src/nsupdate.rs` | bindings | `JsNsUpdateSender` — async send (native only) |
| `crates/bind9-sdk-bindings/src/stats.rs` | bindings | `JsStatsClient` — async stats (native only) |
| `crates/bind9-sdk-bindings/src/transfer.rs` | bindings | `JsTransferClient` — async iterator (native only) |
| `crates/bind9-sdk-bindings/src/pool.rs` | bindings | `JsRndcPool` — pool wrapper (native only) |
| `crates/bind9-sdk-bindings/package.json` | bindings | npm package manifest (`"private": true`) |
| `crates/bind9-sdk-bindings/build.rs` | bindings | napi-rs v3 build script |
| `crates/bind9-sdk-bindings/tests/smoke.mjs` | bindings | Node.js smoke test |
| `crates/bind9-sdk-bindings/tests/smoke.bun.ts` | bindings | Bun smoke test |

### Modified files

| File | Changes |
| --- | --- |
| `crates/bind9-sdk-bindings/Cargo.toml` | napi-rs v2 → v3 deps, feature flags |
| `crates/bind9-sdk-bindings/src/lib.rs` | Replace placeholder comments with module declarations |
| `Cargo.toml` (workspace) | Add napi v3, napi-derive v3 to workspace deps |

## Gate Check: napi-rs v3 Readiness

Before starting Phase 3 implementation, verify the research spike findings:

- [ ] **Gate 1: napi-rs v3 is stable or late beta**

  If napi-rs v3 is not ready:
  - Fall back to napi-rs v2 (currently in Cargo.toml)
  - Skip `wasm32-wasip1-threads` output — native `.node` only
  - Defer WASM browser support to a future phase
  - Adjust plan: remove all WASM-specific steps, keep native binding work

- [ ] **Gate 2: `wasm32-wasip1-threads` target builds hello-world**

  ```bash
  # Test from research spike
  napi build --target wasm32-wasip1-threads
  ```

  If this fails, proceed with native-only and defer WASM.

## Phase 3: JS Bindings, Core Surface

### P3-W1: napi-rs v3 Foundation (WT-I)

**Branch:** `feat/napi-v3-setup`
**Worktree:** `.worktrees/wt-i`

#### Task 1: Migrate Cargo.toml to napi-rs v3

**Files:**
- Modify: `crates/bind9-sdk-bindings/Cargo.toml`
- Modify: `Cargo.toml` (workspace)

- [ ] **Step 1.1: Update workspace dependencies**

  In workspace `Cargo.toml`, add:

  ```toml
  # Feature names are from v2 — confirm exact v3 feature names from research spike
  napi = { version = "3", features = ["async", "serde-json"] }
  napi-derive = "3"
  ```

  (Exact version depends on research spike findings — use whatever v3 release is stable.)

- [ ] **Step 1.2: Update bindings Cargo.toml**

  Replace existing v2 stubs:

  ```toml
  [package]
  name = "bind9-sdk-bindings"
  version.workspace = true
  edition.workspace = true
  rust-version.workspace = true
  license.workspace = true
  description = "Node.js/Bun native addon + WASM bindings for bind9-sdk"

  [lib]
  # Both crate-types are required:
  # - "cdylib" for napi-rs to produce the native .node addon
  # - "rlib" so that `cargo test` can link unit tests (cdylib-only breaks cargo test)
  crate-type = ["cdylib", "rlib"]

  [dependencies]
  bind9-sdk-core = { path = "../bind9-sdk-core", features = ["serde"] }  # serde needed for RecordData → JSON
  bind9-sdk-net = { path = "../bind9-sdk-net", optional = true }
  napi = { workspace = true }
  napi-derive = { workspace = true }
  # Note: No data-encoding needed — TSIG key creation uses TsigKey::from_base64()
  # which handles base64 decoding internally via the `base64` crate already in workspace.
  serde_json = { workspace = true }      # tagged union rdata serialization

  [features]
  default = ["nodejs"]
  nodejs = ["dep:bind9-sdk-net"]

  [build-dependencies]
  napi-build = "3"
  ```

- [ ] **Step 1.3: Verify it compiles**

  ```bash
  cargo build -p bind9-sdk-bindings
  ```

- [ ] **Step 1.4: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/Cargo.toml Cargo.toml
  git commit -m "feat(bindings): migrate to napi-rs v3 dependencies"
  ```

#### Task 2: First Binding — DomainName

**Files:**
- Create: `crates/bind9-sdk-bindings/src/domain.rs`
- Create: `crates/bind9-sdk-bindings/src/error.rs`
- Modify: `crates/bind9-sdk-bindings/src/lib.rs`

- [ ] **Step 2.1: Implement BindSdkError**

  ```rust
  // SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
  //
  // SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

  use napi::bindgen_prelude::*;
  use napi_derive::napi;

  /// Error type exposed to JavaScript.
  ///
  /// Maps CoreError and NetError to napi::Error with structured fields.
  pub struct BindSdkError;

  impl BindSdkError {
      pub fn from_core(err: bind9_sdk_core::CoreError) -> napi::Error {
          napi::Error::from_reason(err.to_string())
      }

      #[cfg(feature = "nodejs")]
      pub fn from_net(err: bind9_sdk_net::NetError) -> napi::Error {
          napi::Error::from_reason(err.to_string())
      }
  }
  ```

- [ ] **Step 2.2: Implement JsDomainName**

  ```rust
  // SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
  //
  // SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

  use napi_derive::napi;
  use bind9_sdk_core::DomainName;
  use crate::error::BindSdkError;

  /// A fully-qualified domain name.
  #[napi]
  pub struct JsDomainName {
      inner: DomainName,
  }

  #[napi]
  impl JsDomainName {
      /// Create a new domain name from a string.
      ///
      /// The name must be absolute (ending with `.`) or will be made absolute.
      #[napi(constructor)]
      pub fn new(name: String) -> napi::Result<Self> {
          let inner = DomainName::new(&name).map_err(BindSdkError::from_core)?;
          Ok(Self { inner })
      }

      /// Returns the string representation of this domain name.
      #[napi]
      pub fn to_string(&self) -> String {
          self.inner.to_string()
      }

      /// Whether this domain name is absolute (ends with root `.`).
      #[napi]
      pub fn is_absolute(&self) -> bool {
          // DomainName always stores absolute form
          true
      }

      /// Number of labels in this domain name.
      #[napi]
      pub fn label_count(&self) -> u32 {
          self.inner.labels().len() as u32
      }
  }
  ```

- [ ] **Step 2.3: Update lib.rs**

  ```rust
  // SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
  //
  // SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

  mod domain;
  mod error;

  // Net-dependent modules (rndc, nsupdate, stats, transfer, pool) are added
  // in Phase 4 behind #[cfg(feature = "nodejs")] since they depend on
  // bind9-sdk-net which is gated behind the `nodejs` feature.
  ```

- [ ] **Step 2.4: Build and verify**

  ```bash
  cargo build -p bind9-sdk-bindings
  ```

- [ ] **Step 2.5: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/src/
  git commit -m "feat(bindings): first napi-rs v3 binding — JsDomainName"
  ```

#### Task 3: package.json + napi CLI Config

**Files:**
- Create: `crates/bind9-sdk-bindings/package.json`
- Create: `crates/bind9-sdk-bindings/build.rs`

- [ ] **Step 3.1: Create package.json**

  ```json
  {
    "name": "bind9-sdk",
    "version": "0.0.0",
    "private": true,
    "description": "BIND9 DNS server management SDK — native + WASM",
    "main": "index.js",
    "types": "index.d.ts",
    "napi": {
      "binaryName": "bind9-sdk",
      "targets": [
        "aarch64-apple-darwin"
      ]
    },
    "scripts": {
      "build": "napi build --release",
      "build:wasm": "napi build --release --target wasm32-wasip1-threads"
    },
    "devDependencies": {
      "@napi-rs/cli": "^3.0.0"
    }
  }
  ```

  Note: `"private": true` prevents accidental publish. Platform targets limited to dev machine (macOS ARM64). Full matrix deferred to publish phase.

- [ ] **Step 3.2: Create build.rs**

  ```rust
  // SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
  //
  // SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

  fn main() {
      napi_build::setup();
  }
  ```

- [ ] **Step 3.3: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/package.json crates/bind9-sdk-bindings/build.rs
  git commit -m "feat(bindings): package.json + napi CLI config"
  ```

#### Task 4: Verify Dual Output

- [ ] **Step 4.1: Build native**

  ```bash
  cd crates/bind9-sdk-bindings
  npm install
  npm run build
  ```

  Expected: generates `bind9-sdk.darwin-arm64.node` and `index.js` + `index.d.ts`

- [ ] **Step 4.2: Smoke test native**

  ```bash
  node -e "const { JsDomainName } = require('./index.js'); const d = new JsDomainName('example.com.'); console.log(d.toString());"
  ```

  Expected: prints `example.com.`

- [ ] **Step 4.3: Build WASM (if gate passed)**

  ```bash
  npm run build:wasm
  ```

  Expected: generates WASM binary

- [ ] **Step 4.4: Record bundle size baseline**

  ```bash
  ls -lh *.node *.wasm 2>/dev/null
  ```

- [ ] **Step 4.5: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/
  git commit -m "feat(bindings): verified dual output — native + WASM"
  ```

### P3-W2: Core Surface Bindings (WT-J)

**Branch:** `feat/napi-core-bindings`
**Worktree:** `.worktrees/wt-j`
**Depends on:** WT-I merged

**TDD approach for bindings:** Unlike pure Rust modules where we write a failing `#[test]` first, napi-rs bindings are tested via the Node.js/Bun smoke tests (Task 11). The TDD cycle for each binding task is: (1) write binding code, (2) `cargo build -p bind9-sdk-bindings` to verify Rust compiles, (3) `npm run build` to produce `.node`, (4) run `node -e "..."` inline smoke test to verify JS interop, (5) commit. Full smoke tests in Task 11 provide the regression suite.

#### Task 5: Zone Parsing Bindings

**Files:**
- Create: `crates/bind9-sdk-bindings/src/zone.rs`

- [ ] **Step 5.1: Implement JsZoneFile**

  ```rust
  use napi_derive::napi;
  use bind9_sdk_core::zone::ZoneFile;
  use bind9_sdk_core::DomainName;
  use crate::error::BindSdkError;

  /// A parsed DNS zone file.
  #[napi]
  pub struct JsZoneFile {
      inner: ZoneFile,
  }

  #[napi]
  impl JsZoneFile {
      /// Parse a zone file from text.
      ///
      /// `ZoneFile::parse()` takes a single `&str` argument.
      /// The origin is inferred from the `$ORIGIN` directive or SOA record.
      #[napi(factory)]
      pub fn parse(text: String) -> napi::Result<Self> {
          let inner = ZoneFile::parse(&text).map_err(BindSdkError::from_core)?;
          Ok(Self { inner })
      }

      /// Serialize the zone file back to text.
      #[napi]
      pub fn serialize(&self) -> String {
          self.inner.serialize()
      }

      /// Number of records in the zone.
      /// `ZoneFile.zone.records` is a pub `Vec<ResourceRecord>` field.
      #[napi]
      pub fn record_count(&self) -> u32 {
          self.inner.zone.records.len() as u32
      }
  }
  ```

- [ ] **Step 5.2: Add to lib.rs**

  ```rust
  mod zone;
  ```

- [ ] **Step 5.3: Build and test**

  ```bash
  npm run build
  node -e "const { JsZoneFile } = require('./index.js'); const z = JsZoneFile.parse('\$ORIGIN example.com.\nexample.com. 3600 IN A 192.0.2.1'); console.log(z.recordCount());"
  ```

- [ ] **Step 5.4: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/src/zone.rs crates/bind9-sdk-bindings/src/lib.rs
  git commit -m "feat(bindings): zone parsing — JsZoneFile.parse() + serialize()"
  ```

#### Task 6: Record Type Bindings

**Files:**
- Create: `crates/bind9-sdk-bindings/src/record.rs`

- [ ] **Step 6.1: Implement JsResourceRecord and JsRecordData**

  `RecordData` is mapped to JS as tagged union objects:

  ```rust
  use napi_derive::napi;
  use napi::bindgen_prelude::*;

  /// A DNS resource record.
  #[napi(object)]
  pub struct JsResourceRecord {
      pub name: String,
      pub class: String,
      pub ttl: u32,
      pub rtype: String,
      pub rdata: serde_json::Value,
  }
  ```

  Each `RecordData` variant maps to a JSON object with a `type` discriminator:
  - `{ type: "A", address: "192.0.2.1" }`
  - `{ type: "MX", preference: 10, exchange: "mail.example.com." }`
  - `{ type: "SOA", mname: "...", rname: "...", serial: 123, ... }`

- [ ] **Step 6.2: Build and test**

- [ ] **Step 6.3: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/src/record.rs crates/bind9-sdk-bindings/src/lib.rs
  git commit -m "feat(bindings): record type bindings — JsResourceRecord + tagged union rdata"
  ```

#### Task 7: TSIG Bindings

**Files:**
- Create: `crates/bind9-sdk-bindings/src/tsig.rs`

- [ ] **Step 7.1: Implement JsTsigKey**

  ```rust
  use std::sync::Arc;
  use napi_derive::napi;
  use bind9_sdk_core::DomainName;
  use bind9_sdk_core::tsig::{TsigKey, TsigAlgorithm};
  use crate::error::BindSdkError;

  /// A TSIG key for DNS authentication.
  ///
  /// Key material is held inside an Arc and never crosses the FFI boundary.
  /// JavaScript code can use the key for signing but cannot read the secret.
  #[napi]
  pub struct JsTsigKey {
      inner: Arc<TsigKey>,
  }

  #[napi]
  impl JsTsigKey {
      /// Create a TSIG key from a name, algorithm, and base64-encoded secret.
      #[napi(constructor)]
      pub fn new(name: String, algorithm: String, secret_base64: String) -> napi::Result<Self> {
          let algo = match algorithm.as_str() {
              "hmac-sha256" => TsigAlgorithm::HmacSha256,
              "hmac-sha512" => TsigAlgorithm::HmacSha512,
              "hmac-sha1" => {
                  #[allow(deprecated)]
                  TsigAlgorithm::HmacSha1
              }
              other => return Err(napi::Error::from_reason(
                  format!("unsupported algorithm: {other}")
              )),
          };
              // TsigKey::from_base64() handles base64 decoding internally,
          // including whitespace stripping. No need for data-encoding crate.
          let domain = DomainName::new(&name).map_err(BindSdkError::from_core)?;
          let key = TsigKey::from_base64(domain, algo, &secret_base64)
              .map_err(BindSdkError::from_core)?;
          Ok(Self { inner: Arc::new(key) })
      }

      /// The key name.
      #[napi]
      pub fn name(&self) -> String {
          self.inner.name().to_string()
      }

      /// The algorithm name.
      #[napi]
      pub fn algorithm(&self) -> String {
          format!("{}", self.inner.algorithm())
      }
  }
  ```

  Note: `Arc<TsigKey>` prevents key material from being accessible to JS. The key is used internally for signing operations but its secret bytes are never exposed.

- [ ] **Step 7.2: Build and test**

- [ ] **Step 7.3: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/src/tsig.rs crates/bind9-sdk-bindings/src/lib.rs
  git commit -m "feat(bindings): TSIG key binding — Arc-wrapped, no secret exposure"
  ```

#### Task 8: UpdateBuilder Bindings

**Files:**
- Create: `crates/bind9-sdk-bindings/src/update.rs`

- [ ] **Step 8.1: Implement JsUpdateBuilder**

  **Design note:** The Rust `UpdateBuilder` uses a consuming-self typestate pattern:
  `add_record(mut self, record) -> Self` and `sign(self, key, timestamp) -> UpdateBuilder<Signed>`.
  napi-rs methods use `&mut self`, so we wrap the builder in `Option` and use the take-and-replace pattern.

  ```rust
  use napi_derive::napi;
  use bind9_sdk_core::DomainName;
  use bind9_sdk_core::record::{RecordClass, RecordData, ResourceRecord, Ttl};
  use bind9_sdk_core::update::{UpdateBuilder, Unsigned};
  use crate::error::BindSdkError;
  use crate::tsig::JsTsigKey;

  /// Builder for RFC 2136 dynamic DNS update messages.
  ///
  /// Wraps `UpdateBuilder<Unsigned>` in an `Option` to work around the
  /// consuming-self typestate pattern. Each method takes the inner builder,
  /// calls the consuming method, and puts the result back.
  #[napi]
  pub struct JsUpdateBuilder {
      inner: Option<UpdateBuilder<Unsigned>>,
  }

  impl JsUpdateBuilder {
      /// Take the inner builder, returning an error if already consumed (signed).
      fn take(&mut self) -> napi::Result<UpdateBuilder<Unsigned>> {
          self.inner.take().ok_or_else(|| {
              napi::Error::from_reason("UpdateBuilder already consumed (signed)")
          })
      }
  }

  #[napi]
  impl JsUpdateBuilder {
      /// Create a new update builder for the given zone.
      ///
      /// `UpdateBuilder::new()` takes `(DomainName, RecordClass)`.
      #[napi(constructor)]
      pub fn new(zone: String) -> napi::Result<Self> {
          let domain = DomainName::new(&zone).map_err(BindSdkError::from_core)?;
          let builder = UpdateBuilder::new(domain, RecordClass::IN);
          Ok(Self { inner: Some(builder) })
      }

      /// Add a record to the update.
      ///
      /// Parameters are strings — the binding constructs a `ResourceRecord`
      /// from them. `rdata` format matches zone file text format (e.g. "192.0.2.1"
      /// for A records, "10 mail.example.com." for MX).
      #[napi]
      pub fn add_record(
          &mut self,
          name: String,
          ttl: u32,
          rtype: String,
          rdata: String,
      ) -> napi::Result<&Self> {
          let builder = self.take()?;
          let record = parse_record_from_strings(&name, ttl, &rtype, &rdata)?;
          self.inner = Some(builder.add_record(record));
          Ok(self)
      }

      /// Delete a specific record from the zone.
      #[napi]
      pub fn delete_record(
          &mut self,
          name: String,
          ttl: u32,
          rtype: String,
          rdata: String,
      ) -> napi::Result<&Self> {
          let builder = self.take()?;
          let record = parse_record_from_strings(&name, ttl, &rtype, &rdata)?;
          self.inner = Some(builder.delete_record(record));
          Ok(self)
      }

      /// Sign the update with a TSIG key and return wire-format bytes.
      ///
      /// This consumes the builder — further calls will error.
      /// Internally calls `builder.sign(key, timestamp)` → `UpdateBuilder<Signed>`,
      /// then `.build()` → `UpdateMessage`, then extracts `.wire_bytes`.
      #[napi]
      pub fn sign(&mut self, key: &JsTsigKey) -> napi::Result<napi::bindgen_prelude::Buffer> {
          let builder = self.take()?;
          // sign_now() handles timestamping automatically (requires `std` feature,
          // which bindings have since they depend on bind9-sdk-net)
          let signed = builder.sign_now(key.inner_ref());
          let message = signed.build();
          // wire_bytes is pub(crate); use public accessor as_bytes()
          Ok(message.as_bytes().to_vec().into())
      }
  }

  /// Parse a ResourceRecord from string parameters.
  /// This is a helper that constructs the record from zone-file-style text.
  fn parse_record_from_strings(
      name: &str,
      ttl: u32,
      rtype: &str,
      rdata: &str,
  ) -> napi::Result<ResourceRecord> {
      let domain = DomainName::new(name).map_err(BindSdkError::from_core)?;
      let ttl_val = Ttl::new(ttl).map_err(BindSdkError::from_core)?;
      // Construct a minimal zone-file line and parse it via ZoneFile::parse().
      // rdata_text::parse_rdata() is pub(crate) and not accessible from bindings.
      // Approach: build a zone file snippet and extract the first record.
      let snippet = format!(
          "$ORIGIN {name}\n{name} {ttl} IN {rtype} {rdata}\n"
      );
      let zone_file = bind9_sdk_core::zone::ZoneFile::parse(&snippet)
          .map_err(BindSdkError::from_core)?;
      zone_file.zone.records.into_iter().next().ok_or_else(|| {
          napi::Error::from_reason("failed to parse record from string params")
      })
  }
  ```

  **Note:** `JsTsigKey` needs an `inner_ref()` method that returns `&TsigKey` (add to `tsig.rs`):
  ```rust
  impl JsTsigKey {
      pub(crate) fn inner_ref(&self) -> &TsigKey {
          &self.inner
      }
  }
  ```
  ```

- [ ] **Step 8.2: Build and test**

- [ ] **Step 8.3: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/src/update.rs crates/bind9-sdk-bindings/src/lib.rs
  git commit -m "feat(bindings): UpdateBuilder chain API binding"
  ```

#### Task 9: WASM Bundle Size Check (PR-003)

- [ ] **Step 9.1: Build WASM and measure**

  ```bash
  npm run build:wasm
  gzip -c *.wasm | wc -c
  ```

  Expected: < 500KB gzipped (PR-003 requirement)

- [ ] **Step 9.2: If oversized, optimize**

  - Enable LTO in release profile
  - `opt-level = "z"` for size
  - Strip unused features

- [ ] **Step 9.3: Commit optimizations if needed**

#### Task 10: TypeScript Type Check

- [ ] **Step 10.1: Run tsc on generated types**

  ```bash
  npx tsc --noEmit --strict index.d.ts
  ```

  Expected: no errors

- [ ] **Step 10.2: Fix any type issues**

- [ ] **Step 10.3: Commit**

#### Task 11: Smoke Tests

**Files:**
- Create: `crates/bind9-sdk-bindings/tests/smoke.mjs`
- Create: `crates/bind9-sdk-bindings/tests/smoke.bun.ts`

- [ ] **Step 11.1: Node.js smoke test**

  ```javascript
  import { JsDomainName, JsZoneFile, JsTsigKey, JsUpdateBuilder } from '../index.js';

  // DomainName
  const d = new JsDomainName('example.com.');
  console.assert(d.toString() === 'example.com.');
  console.assert(d.isAbsolute() === true);

  // ZoneFile — parse() takes a single string argument
  const zone = JsZoneFile.parse('$ORIGIN example.com.\nexample.com. 3600 IN A 192.0.2.1');
  console.assert(zone.recordCount() === 1);
  console.assert(zone.serialize().includes('192.0.2.1'));

  // TSIG (constructor only — can't sign without network)
  const key = new JsTsigKey('test.', 'hmac-sha256', 'dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGs=');
  console.assert(key.name() === 'test.'); // DomainName always stores absolute form

  console.log('Node.js smoke test passed');
  ```

- [ ] **Step 11.2: Bun smoke test**

  Same tests but using Bun runtime:

  ```bash
  bun run tests/smoke.bun.ts
  ```

- [ ] **Step 11.3: Run on Node.js 20 and 22**

  ```bash
  node tests/smoke.mjs
  ```

- [ ] **Step 11.4: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/tests/
  git commit -m "test(bindings): smoke tests — Node.js 20/22 + Bun"
  ```

### P3-W3: Hardening

**Branch:** `feat/p3-hardening`

#### Task 12: FFI Safety Review

- [ ] **Step 12.1: Run `rust-security-reviewer` agent on bindings crate**

  Focus areas:
  - No key material crossing FFI boundary (TSIG key via Arc)
  - No unbounded allocations from JS input
  - Error handling: all Rust panics caught by napi-rs
  - Buffer ownership: no use-after-free on returned buffers

- [ ] **Step 12.2: Remediate findings**

- [ ] **Step 12.3: Commit**

  ```bash
  git add -u
  git commit -m "fix(bindings): FFI safety review remediation"
  ```

#### Task 13: Dialectic Verification

- [ ] **Step 13.1: Run `/dialectic-verify` on Phase 3 bindings**
- [ ] **Step 13.2: Remediate findings**

#### Task 14: Type Completeness Check

- [ ] **Step 14.1: Compare generated .d.ts against core public API**

  Verify that every public type in `bind9-sdk-core` that's relevant to JS has a corresponding binding:
  - DomainName ✓
  - ZoneFile ✓
  - ResourceRecord ✓
  - RecordData variants ✓
  - TsigKey ✓
  - UpdateBuilder ✓

- [ ] **Step 14.2: Document any intentionally omitted types**

- [ ] **Step 14.3: Merge to development**

  ```bash
  git checkout development
  git merge feat/p3-hardening --no-ff -m "feat: Phase 3 complete — napi-rs v3 core surface bindings"
  ```

## Phase 4: Full SDK Surface + npm Package

### P4-W1: Full Surface Bindings (WT-K)

**Branch:** `feat/napi-full-surface`
**Worktree:** `.worktrees/wt-k`
**Depends on:** Phase 3 complete + Phase 5 merged (for connection pooling)

**Mitigation if Phase 5 delays:** Proceed with core net bindings (rndc, nsupdate, stats, transfer) and defer `RndcPool` binding to follow-up.

#### Task 15: RndcClient Binding

**Files:**
- Create: `crates/bind9-sdk-bindings/src/rndc.rs`

- [ ] **Step 15.1: Implement JsRndcClient**

  ```rust
  #[cfg(not(target_arch = "wasm32"))]
  mod rndc_impl {
      use napi_derive::napi;
      use bind9_sdk_net::rndc::{RndcConnection, RndcCommand};

      /// BIND9 rndc client — native only (not available in WASM).
      #[napi]
      pub struct JsRndcClient {
          // Configuration for creating connections
      }

      #[napi]
      impl JsRndcClient {
          #[napi(constructor)]
          pub fn new(host: String, port: u16, key_name: String, key_secret: String) -> napi::Result<Self> { ... }

          /// Get server status.
          #[napi]
          pub async fn status(&self) -> napi::Result<String> { ... }

          /// Reload a zone.
          #[napi]
          pub async fn reload(&self, zone: String) -> napi::Result<String> { ... }

          /// Get zone status.
          #[napi]
          pub async fn zone_status(&self, zone: String) -> napi::Result<String> { ... }

          // ... all 25+ RndcCommand variants as async methods
      }
  }
  ```

  Note: `#[cfg(not(target_arch = "wasm32"))]` ensures this module is excluded from WASM builds (networking not available in browser WASM).

- [ ] **Step 15.2: Build and test**

- [ ] **Step 15.3: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/src/rndc.rs crates/bind9-sdk-bindings/src/lib.rs
  git commit -m "feat(bindings): JsRndcClient — all rndc commands as async methods"
  ```

#### Task 16: NsUpdateSender + StatsClient Bindings

**Files:**
- Create: `crates/bind9-sdk-bindings/src/nsupdate.rs`
- Create: `crates/bind9-sdk-bindings/src/stats.rs`

- [ ] **Step 16.1: Implement JsNsUpdateSender**

  ```rust
  #[cfg(not(target_arch = "wasm32"))]
  #[napi]
  pub struct JsNsUpdateSender { ... }

  #[cfg(not(target_arch = "wasm32"))]
  #[napi]
  impl JsNsUpdateSender {
      #[napi]
      pub async fn send(&self, message: Buffer, server: String, port: u16) -> napi::Result<()> { ... }
  }
  ```

- [ ] **Step 16.2: Implement JsStatsClient**

  ```rust
  #[cfg(not(target_arch = "wasm32"))]
  #[napi]
  pub struct JsStatsClient { ... }

  #[cfg(not(target_arch = "wasm32"))]
  #[napi]
  impl JsStatsClient {
      #[napi]
      pub async fn server_stats(&self) -> napi::Result<serde_json::Value> { ... }

      #[napi]
      pub async fn zone_stats(&self, zone: String) -> napi::Result<serde_json::Value> { ... }
  }
  ```

- [ ] **Step 16.3: Build and test**

- [ ] **Step 16.4: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/src/nsupdate.rs crates/bind9-sdk-bindings/src/stats.rs crates/bind9-sdk-bindings/src/lib.rs
  git commit -m "feat(bindings): NsUpdateSender + StatsClient bindings"
  ```

#### Task 17: TransferClient Binding

**Files:**
- Create: `crates/bind9-sdk-bindings/src/transfer.rs`

- [ ] **Step 17.1: Implement JsTransferClient with async iterator**

  ```rust
  #[cfg(not(target_arch = "wasm32"))]
  #[napi]
  pub struct JsTransferClient { ... }

  #[cfg(not(target_arch = "wasm32"))]
  #[napi]
  impl JsTransferClient {
      /// Perform AXFR and return all records as an array.
      #[napi]
      pub async fn axfr(&self, zone: String) -> napi::Result<Vec<JsResourceRecord>> { ... }

      /// Perform IXFR and return diff records.
      #[napi]
      pub async fn ixfr(&self, zone: String, current_serial: u32) -> napi::Result<Vec<JsResourceRecord>> { ... }
  }
  ```

- [ ] **Step 17.2: Build and test**

- [ ] **Step 17.3: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/src/transfer.rs crates/bind9-sdk-bindings/src/lib.rs
  git commit -m "feat(bindings): TransferClient binding — AXFR/IXFR"
  ```

#### Task 18: RndcPool Binding (if Phase 5 available)

**Files:**
- Create: `crates/bind9-sdk-bindings/src/pool.rs`

- [ ] **Step 18.1: Implement JsRndcPool**

  ```rust
  #[cfg(not(target_arch = "wasm32"))]
  #[napi]
  pub struct JsRndcPool { ... }

  #[cfg(not(target_arch = "wasm32"))]
  #[napi]
  impl JsRndcPool {
      #[napi(constructor)]
      pub fn new(host: String, port: u16, key_name: String, key_secret: String, pool_size: u32) -> napi::Result<Self> { ... }

      #[napi]
      pub fn available(&self) -> u32 { ... }
  }
  ```

- [ ] **Step 18.2: Build and test**

- [ ] **Step 18.3: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/src/pool.rs crates/bind9-sdk-bindings/src/lib.rs
  git commit -m "feat(bindings): RndcPool binding"
  ```

#### Task 19: Full .d.ts Type Check

- [ ] **Step 19.1: Rebuild and check types**

  ```bash
  npm run build
  npx tsc --noEmit --strict index.d.ts
  ```

  Expected: no errors

- [ ] **Step 19.2: Commit**

### P4-W2: npm Package Assembly (WT-L)

**Branch:** `feat/npm-package`
**Worktree:** `.worktrees/wt-l`
**Depends on:** WT-K merged

#### Task 20: Package.json Exports Map

**Files:**
- Modify: `crates/bind9-sdk-bindings/package.json`

- [ ] **Step 20.1: Configure exports map**

  ```json
  {
    "exports": {
      ".": {
        "node": {
          "import": "./index.mjs",
          "require": "./index.js"
        },
        "browser": "./browser.js",
        "default": "./browser.js"
      }
    },
    "files": [
      "index.js",
      "index.mjs",
      "index.d.ts",
      "browser.js",
      "*.node",
      "*.wasm"
    ]
  }
  ```

  `node` → native `.node` binary, `browser` → WASM fallback, `default` → WASM.

- [ ] **Step 20.2: Commit**

  ```bash
  git add crates/bind9-sdk-bindings/package.json
  git commit -m "feat(bindings): package.json exports map — node/browser/default"
  ```

#### Task 21: Local npm pack Test

- [ ] **Step 21.1: Build and pack**

  ```bash
  cd crates/bind9-sdk-bindings
  npm run build
  npm pack
  ```

  Expected: produces `bind9-sdk-0.0.0.tgz`

- [ ] **Step 21.2: Install in test project**

  ```bash
  mkdir -p /tmp/bind9-sdk-test
  cd /tmp/bind9-sdk-test
  npm init -y
  npm install /path/to/bind9-sdk-0.0.0.tgz
  ```

- [ ] **Step 21.3: Test require and import**

  ```javascript
  // CommonJS
  const { JsDomainName, JsZoneFile } = require('bind9-sdk');
  console.log(new JsDomainName('example.com.').toString());

  // ESM
  import { JsDomainName } from 'bind9-sdk';
  ```

- [ ] **Step 21.4: Test Bun compatibility**

  ```bash
  bun -e "const { JsDomainName } = require('bind9-sdk'); console.log(new JsDomainName('example.com.').toString());"
  ```

- [ ] **Step 21.5: Commit test artifacts**

  ```bash
  git add -u
  git commit -m "test(bindings): local npm pack verification — CJS + ESM + Bun"
  ```

#### Task 22: Dialectic Verification — Complete JS Track

- [ ] **Step 22.1: Run `/dialectic-verify` on complete bindings crate**
- [ ] **Step 22.2: Run all review agents**

  - `rust-security-reviewer` — FFI boundary, key material
  - `api-compat-reviewer` — public API surface completeness

- [ ] **Step 22.3: Remediate findings**

#### Task 23: Phase 4 Completion

- [ ] **Step 23.1: Merge to development**

  ```bash
  git checkout development
  git merge feat/npm-package --no-ff -m "feat: Phase 4 complete — full SDK bindings + npm package (local)"
  ```

- [ ] **Step 23.2: Update PRD with Phase 4 status**

- [ ] **Step 23.3: Push**

  ```bash
  git push origin development
  ```
