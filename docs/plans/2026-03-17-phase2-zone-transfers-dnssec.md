<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Phase 2 Implementation Plan — Zone Transfers + DNSSEC

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver IXFR/AXFR zone transfer client, DNSSEC record type text parsing/serialization, CDS/CDNSKEY generation, KASP state querying, XoT transport, and SOA serial strategies — completing Phase 2 (v0.2.0) of bind9-sdk.

**Architecture:** Four waves: W0 hardens E2E Podman infrastructure; W1 runs 3 parallel worktrees (DNSSEC types, IXFR/AXFR, SOA serial + audit carryover); W2 runs 2 parallel worktrees + a research spike (CDS/KASP, XoT, napi-rs v3 research); W3 is integration hardening + dialectic verification. All new code follows `no_std` core / `std` net split. DNSSEC types in core, transfer protocol in net.

**Tech Stack:** Rust 2024, tokio, tokio-stream, proptest, insta, data-encoding (base32hex for NSEC3), Podman rootless, BIND9 9.20

**Spec:** `docs/specs/2026-03-17-phases2-5-parallel-execution-design.md`
**Branch prefix:** `feat/` per worktree (see worktree table)

## File Structure

### New files

| File | Crate | Purpose |
| --- | --- | --- |
| `core/src/rdata/mod.rs` | core | `RecordData` enum (moved from `core/src/rdata.rs`) |
| `core/src/rdata/tests.rs` | core | Unit tests for RecordData (moved from inline) |
| `core/src/zone/rdata_dnssec.rs` | core | DNSSEC text parse + serialize (DNSKEY, RRSIG, NSEC, NSEC3, DS, CDS, CDNSKEY, NSEC3PARAM, DLV) |
| `core/src/dnssec.rs` | core | CDS generation, DS digest, key tag computation, DELETE sentinels |
| `core/src/transfer.rs` | core | `TransferSession` typestate, `XfrRecord`, `XfrStream` types |
| `net/src/transfer/mod.rs` | net | `TransferClient` — AXFR/IXFR streaming client |
| `net/src/transfer/wire.rs` | net | DNS wire format parsing for zone transfer responses |
| `net/src/transfer/tests.rs` | net | Unit tests with mock TCP streams |
| `net/src/rndc/dnssec.rs` | net | KASP response parsing (`DnssecStatus`, `DsCheckResult`) |
| `net/tests/transfer_integration.rs` | net | Integration test: AXFR from Podman container |
| `tests/bind9/zones/dnssec.example.com.zone` | infra | DNSSEC-signed test zone |
| `tests/bind9/zones/transfer.example.com.zone` | infra | AXFR-enabled test zone |
| `Makefile` | root | `make test-integration` target |

### Modified files

| File | Changes |
| --- | --- |
| `core/src/rdata.rs` | Split to `core/src/rdata/mod.rs` (move enum + tests to submodule) |
| `core/src/zone/rdata_text.rs` | Add DNSSEC type arms to `parse_rdata()` and `serialize_rdata()` — delegate to new `rdata_dnssec.rs` |
| `core/src/protocol.rs` | Add `Nsec3param` and `Dlv` variants to `RecordType` |
| `core/src/record.rs` | Add `SerialStrategy` enum, `Serial::next()` method |
| `core/src/error.rs` | Add `column` field to `CoreError::ZoneParse` (GPT-ZONE-COL audit item). Note: `line` is `u32`, not `usize` |
| `core/src/lib.rs` | Add `pub mod dnssec;`, `pub mod transfer;` |
| `net/src/error.rs` | Add `TransferFailed`, `SerialMismatch`, `IncompleteTransfer`, `XfrProtocolError`, `TlsRequired` variants |
| `net/src/tls.rs` | Add localhost exemption logic, self-signed cert support for integration tests |
| `net/src/rndc/command.rs` | Add `DnssecStatus`, `DnssecCheckDs` command variants |
| `net/src/rndc/mod.rs` | F-002: rndc nonce hardening |
| `net/src/lib.rs` | Add `pub mod transfer;` |
| `tests/bind9/named.conf` | Add DNSSEC-signed zone, AXFR-enabled zone with TSIG |
| `tests/bind9/podman-compose.yml` | Health check improvements |
| `Cargo.toml` (workspace) | Add `tokio-stream`, `data-encoding` to workspace deps |
| `core/Cargo.toml` | Add `data-encoding` dependency (no_std compatible) |
| `net/Cargo.toml` | Add `tokio-stream` dependency |

## P2-W0: E2E Infrastructure

**Branch:** `feat/e2e-infra`
**Worktree:** None (small, runs in main checkout)

### Task 1: Makefile + Container Health

**Files:**
- Create: `Makefile`
- Modify: `tests/bind9/podman-compose.yml`

- [ ] **Step 1.1: Write failing test — verify Makefile target exists**

  ```bash
  make test-integration 2>&1 || true
  ```

  Expected: `make: *** No rule to make target 'test-integration'. Stop.`

- [ ] **Step 1.2: Create Makefile with test-integration target**

  ```makefile
  .PHONY: test-integration test-integration-up test-integration-down

  COMPOSE := podman-compose -f tests/bind9/podman-compose.yml

  test-integration-up:
  	$(COMPOSE) up -d
  	@echo "Waiting for BIND9 health..."
  	@for i in $$(seq 1 30); do \
  		if $(COMPOSE) exec bind9 rndc status >/dev/null 2>&1; then \
  			echo "BIND9 healthy after $$i seconds"; \
  			break; \
  		fi; \
  		sleep 1; \
  	done

  test-integration-down:
  	$(COMPOSE) down -v

  test-integration: test-integration-up
  	cargo test --workspace -- --ignored; \
  	status=$$?; \
  	$(MAKE) test-integration-down; \
  	exit $$status
  ```

- [ ] **Step 1.3: Add healthcheck to podman-compose.yml**

  Add to the bind9 service:

  ```yaml
  healthcheck:
    test: ["CMD", "rndc", "status"]
    interval: 2s
    timeout: 5s
    retries: 15
  ```

- [ ] **Step 1.4: Verify Makefile parses**

  Run: `make -n test-integration`
  Expected: prints the commands without executing

- [ ] **Step 1.5: Commit**

  ```bash
  git add Makefile tests/bind9/podman-compose.yml
  git commit -m "feat(infra): add make test-integration with Podman healthcheck"
  ```

### Task 2: DNSSEC-Signed Test Zone

**Files:**
- Create: `tests/bind9/zones/dnssec.example.com.zone`
- Modify: `tests/bind9/named.conf`

- [ ] **Step 2.1: Create DNSSEC zone file with inline-signing**

  Create `tests/bind9/zones/dnssec.example.com.zone`:

  ```zone
  $ORIGIN dnssec.example.com.
  $TTL 3600
  @   IN  SOA  ns1.dnssec.example.com. admin.dnssec.example.com. (
              2026031701 ; serial
              3600       ; refresh
              900        ; retry
              604800     ; expire
              86400      ; minimum
          )
  @       IN  NS   ns1.dnssec.example.com.
  ns1     IN  A    127.0.0.1
  www     IN  A    192.0.2.10
  mail    IN  MX   10 mail.dnssec.example.com.
  mail    IN  A    192.0.2.20
  ```

- [ ] **Step 2.2: Add DNSSEC zone to named.conf with inline-signing**

  Add zone block:

  ```named
  zone "dnssec.example.com" {
      type primary;
      file "/var/named/dnssec.example.com.zone";
      dnssec-policy default;
      inline-signing yes;
  };
  ```

- [ ] **Step 2.3: Commit**

  ```bash
  git add tests/bind9/zones/dnssec.example.com.zone tests/bind9/named.conf
  git commit -m "feat(infra): add DNSSEC-signed test zone with inline-signing"
  ```

### Task 3: AXFR-Enabled Test Zone

**Files:**
- Create: `tests/bind9/zones/transfer.example.com.zone`
- Modify: `tests/bind9/named.conf`

- [ ] **Step 3.1: Create transfer test zone**

  Create `tests/bind9/zones/transfer.example.com.zone`:

  ```zone
  $ORIGIN transfer.example.com.
  $TTL 3600
  @   IN  SOA  ns1.transfer.example.com. admin.transfer.example.com. (
              2026031701 ; serial
              3600       ; refresh
              900        ; retry
              604800     ; expire
              86400      ; minimum
          )
  @       IN  NS   ns1.transfer.example.com.
  ns1     IN  A    127.0.0.1
  www     IN  A    192.0.2.30
  sub     IN  A    192.0.2.31
  txt     IN  TXT  "transfer-test-record"
  ```

- [ ] **Step 3.2: Add AXFR-enabled zone to named.conf**

  Add zone block with TSIG-authenticated AXFR:

  ```named
  zone "transfer.example.com" {
      type primary;
      file "/var/named/transfer.example.com.zone";
      allow-transfer { key "rndc-key"; };
  };
  ```

- [ ] **Step 3.3: Commit**

  ```bash
  git add tests/bind9/zones/transfer.example.com.zone tests/bind9/named.conf
  git commit -m "feat(infra): add AXFR-enabled test zone with TSIG auth"
  ```

### Task 4: Verify Existing Integration Tests

- [ ] **Step 4.1: Start container and run ignored tests**

  ```bash
  make test-integration
  ```

  Expected: existing rndc, nsupdate, stats `#[ignore]` tests execute against container. Some may still fail — document which ones.

- [ ] **Step 4.2: Fix any broken integration tests**

  Address failures discovered in step 4.1. Common issues: wrong port, wrong key name, wrong zone name.

- [ ] **Step 4.3: Commit fixes if any**

  ```bash
  git add -u
  git commit -m "fix(infra): resolve integration test configuration issues"
  ```

- [ ] **Step 4.4: Merge to development**

  ```bash
  git checkout development
  git merge feat/e2e-infra --no-ff -m "feat(infra): P2-W0 E2E Podman infrastructure"
  ```

## P2-W1: Core Protocol Work (3 Parallel Worktrees)

All three worktrees branch from `development` after P2-W0 merges. They run in parallel and merge back at wave boundary.

### WT-A: DNSSEC Record Types

**Branch:** `feat/dnssec-types`
**Worktree:** `.worktrees/wt-a`

#### Task 5: Split rdata.rs to Submodule

**Files:**
- Create: `crates/bind9-sdk-core/src/rdata/mod.rs`
- Create: `crates/bind9-sdk-core/src/rdata/tests.rs`
- Delete: `crates/bind9-sdk-core/src/rdata.rs`

- [ ] **Step 5.1: Create rdata directory**

  ```bash
  mkdir -p crates/bind9-sdk-core/src/rdata
  ```

- [ ] **Step 5.2: Move RecordData enum to rdata/mod.rs**

  Move contents of `rdata.rs` to `rdata/mod.rs`. Extract the `#[cfg(test)] mod tests` block to `rdata/tests.rs`. Add `#[cfg(test)] mod tests;` at the bottom of `mod.rs`. Add SPDX headers to both new files.

- [ ] **Step 5.3: Run tests to verify no breakage**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: all 265+ tests pass

- [ ] **Step 5.4: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/rdata/ && git rm crates/bind9-sdk-core/src/rdata.rs
  git commit -m "refactor(core): split rdata.rs to rdata/ submodule"
  ```

#### Task 6: Add Missing RecordType Variants

**Files:**
- Modify: `crates/bind9-sdk-core/src/protocol.rs`

- [ ] **Step 6.1: Write failing test for Nsec3param**

  ```rust
  #[test]
  fn record_type_nsec3param() {
      let rt = RecordType::from_value(51);
      assert_eq!(rt, RecordType::Nsec3param);
      assert_eq!(rt.value(), 51);
      assert_eq!(alloc::format!("{rt}"), "NSEC3PARAM");
  }
  ```

- [ ] **Step 6.2: Run test to verify it fails**

  Run: `cargo test -p bind9-sdk-core --lib record_type_nsec3param`
  Expected: FAIL — no variant `Nsec3param`

- [ ] **Step 6.3: Add Nsec3param and Dlv variants**

  Add to `RecordType` enum:

  ```rust
  /// NSEC3 parameters (type 51).
  Nsec3param,
  /// DNSSEC lookaside validation (type 32769, historic).
  Dlv,
  ```

  Add to `from_value`: `51 => Self::Nsec3param, 32769 => Self::Dlv,`
  Add to `value`: `Self::Nsec3param => 51, Self::Dlv => 32769,`
  Add to `Display`: `Self::Nsec3param => f.write_str("NSEC3PARAM"), Self::Dlv => f.write_str("DLV"),`

- [ ] **Step 6.4: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 6.5: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/protocol.rs
  git commit -m "feat(core): add Nsec3param and Dlv RecordType variants"
  ```

#### Task 7: Add NSEC3PARAM and DLV RecordData Variants

**Files:**
- Modify: `crates/bind9-sdk-core/src/rdata/mod.rs`

- [ ] **Step 7.1: Write failing test**

  ```rust
  #[test]
  fn record_data_nsec3param() {
      let rd = RecordData::Nsec3param {
          hash_algorithm: 1,
          flags: 0,
          iterations: 10,
          salt: alloc::vec![0xab, 0xcd],
      };
      assert!(matches!(rd, RecordData::Nsec3param { iterations: 10, .. }));
  }
  ```

- [ ] **Step 7.2: Run to verify fail**

  Run: `cargo test -p bind9-sdk-core --lib record_data_nsec3param`
  Expected: FAIL

- [ ] **Step 7.3: Add variants to RecordData**

  ```rust
  /// NSEC3PARAM record — NSEC3 parameters (RFC 5155)
  Nsec3param {
      /// Hash algorithm identifier (1 = SHA-1).
      hash_algorithm: u8,
      /// Flags byte.
      flags: u8,
      /// Number of additional hash iterations.
      iterations: u16,
      /// Random salt appended before hashing.
      salt: Vec<u8>,
  },

  /// DLV record — DNSSEC lookaside validation (historic, RFC 4431)
  Dlv {
      /// Key tag of the referenced DNSKEY.
      key_tag: u16,
      /// Algorithm of the referenced DNSKEY.
      algorithm: u8,
      /// Digest algorithm used.
      digest_type: u8,
      /// Cryptographic digest of the DNSKEY record.
      digest: Vec<u8>,
  },
  ```

- [ ] **Step 7.4: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 7.5: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/rdata/mod.rs
  git commit -m "feat(core): add Nsec3param and Dlv RecordData variants"
  ```

#### Task 8: DNSSEC Text Parse/Serialize — DNSKEY, DS, CDS, CDNSKEY, DLV

Note: `RecordData` already has DNSKEY, RRSIG, NSEC, NSEC3, DS, CDS, CDNSKEY, TLSA, SSHFP, CSYNC variants. This task adds **text format** parse/serialize for them (currently they fall through to `serialize_as_generic()` which emits `\# 0`). Only NSEC3PARAM and DLV are new enum variants (added in Task 7).

**Files:**
- Create: `crates/bind9-sdk-core/src/zone/rdata_dnssec.rs`
- Modify: `crates/bind9-sdk-core/src/zone/rdata_text.rs`
- Modify: `crates/bind9-sdk-core/src/zone/mod.rs`

- [ ] **Step 8.1: Write failing test — parse DNSKEY**

  In `rdata_dnssec.rs`:

  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;
      use crate::domain::DomainName;

      fn origin() -> DomainName {
          DomainName::new("example.com.").unwrap()
      }

      #[test]
      fn parse_dnskey_valid() {
          // flags=257 (KSK), protocol=3, algorithm=13 (ECDSAP256SHA256), base64 key
          let tokens = &["257", "3", "13", "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="];
          let rdata = parse_dnskey(tokens).unwrap();
          match rdata {
              RecordData::Dnskey { flags, protocol, algorithm, .. } => {
                  assert_eq!(flags, 257);
                  assert_eq!(protocol, 3);
                  assert_eq!(algorithm, 13);
              }
              other => panic!("expected DNSKEY, got {other:?}"),
          }
      }
  }
  ```

- [ ] **Step 8.2: Run to verify fail**

  Run: `cargo test -p bind9-sdk-core --lib parse_dnskey_valid`
  Expected: FAIL — function not found

- [ ] **Step 8.3: Implement DNSSEC text parsers**

  Create `rdata_dnssec.rs` with functions:
  - `parse_dnskey(tokens) -> Result<RecordData>` — `flags protocol algorithm base64_key`
  - `parse_ds(tokens) -> Result<RecordData>` — `key_tag algorithm digest_type hex_digest`
  - `parse_cds(tokens) -> Result<RecordData>` — same format as DS
  - `parse_cdnskey(tokens) -> Result<RecordData>` — same format as DNSKEY
  - `parse_dlv(tokens) -> Result<RecordData>` — same format as DS
  - `serialize_dnskey(flags, protocol, algorithm, public_key) -> String`
  - `serialize_ds(key_tag, algorithm, digest_type, digest) -> String`
  - `serialize_cds(...)` — delegate to `serialize_ds`
  - `serialize_cdnskey(...)` — delegate to `serialize_dnskey`
  - `serialize_dlv(...)` — delegate to `serialize_ds`

  Base64 encoding/decoding: use `data-encoding` crate (no_std compatible). Add to `core/Cargo.toml`:

  ```toml
  [dependencies]
  data-encoding = { version = "2", default-features = false, features = ["alloc"] }
  ```

  And workspace `Cargo.toml`:

  ```toml
  data-encoding = { version = "2", default-features = false, features = ["alloc"] }
  ```

- [ ] **Step 8.4: Wire into rdata_text.rs**

  In `parse_rdata()`, add arms:

  ```rust
  "DNSKEY" => rdata_dnssec::parse_dnskey(tokens),
  "DS" => rdata_dnssec::parse_ds(tokens),
  "CDS" => rdata_dnssec::parse_cds(tokens),
  "CDNSKEY" => rdata_dnssec::parse_cdnskey(tokens),
  "DLV" => rdata_dnssec::parse_dlv(tokens),
  ```

  In `serialize_rdata()`, replace the catch-all `other => serialize_as_generic(other)` with explicit arms:

  ```rust
  RecordData::Dnskey { flags, protocol, algorithm, ref public_key } =>
      rdata_dnssec::serialize_dnskey(*flags, *protocol, *algorithm, public_key),
  RecordData::Ds { key_tag, algorithm, digest_type, ref digest } =>
      rdata_dnssec::serialize_ds(*key_tag, *algorithm, *digest_type, digest),
  // ... similar for CDS, CDNSKEY, DLV
  ```

  Add `mod rdata_dnssec;` to `zone/mod.rs`.

- [ ] **Step 8.5: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 8.6: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/zone/rdata_dnssec.rs crates/bind9-sdk-core/src/zone/rdata_text.rs crates/bind9-sdk-core/src/zone/mod.rs crates/bind9-sdk-core/Cargo.toml Cargo.toml
  git commit -m "feat(core): DNSSEC text parse/serialize — DNSKEY, DS, CDS, CDNSKEY, DLV"
  ```

#### Task 9: DNSSEC Text Parse/Serialize — RRSIG, NSEC, NSEC3, NSEC3PARAM

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/rdata_dnssec.rs`
- Modify: `crates/bind9-sdk-core/src/zone/rdata_text.rs`

- [ ] **Step 9.1: Write failing test — parse RRSIG**

  ```rust
  #[test]
  fn parse_rrsig_valid() {
      // type_covered=A algorithm=13 labels=3 original_ttl=3600
      // sig_expiration=20260401000000 sig_inception=20260301000000
      // key_tag=12345 signer=example.com. signature=base64
      let tokens = &[
          "A", "13", "3", "3600",
          "20260401000000", "20260301000000",
          "12345", "example.com.",
          "dGVzdHNpZw==",
      ];
      let rdata = parse_rrsig(tokens, &origin()).unwrap();
      assert!(matches!(rdata, RecordData::Rrsig { type_covered: 1, algorithm: 13, .. }));
  }
  ```

- [ ] **Step 9.2: Run to verify fail**

  Expected: FAIL

- [ ] **Step 9.3: Implement RRSIG, NSEC, NSEC3, NSEC3PARAM parsers and serializers**

  - `parse_rrsig(tokens, origin)` — type_covered (string→u16 via RecordType), algorithm, labels, original_ttl, expiration (YYYYMMDDHHMMSS→u32 timestamp), inception, key_tag, signer_name, base64 signature
  - `parse_nsec(tokens, origin)` — next_domain, type list (space-separated type names → bitmap)
  - `parse_nsec3(tokens)` — hash_alg, flags, iterations, salt (hex or `-`), next_hashed_owner (base32hex), type list → bitmap
  - `parse_nsec3param(tokens)` — hash_alg, flags, iterations, salt (hex or `-`)
  - Corresponding `serialize_*` functions
  - Type bitmap encode/decode helpers: `encode_type_bitmap(types: &[RecordType]) -> Vec<u8>` and `decode_type_bitmap(bytes: &[u8]) -> Vec<RecordType>`
  - NSEC3 base32hex: use `data-encoding::BASE32HEX_NOPAD`

- [ ] **Step 9.4: Wire into rdata_text.rs**

  Add parse arms for "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM" and serialize arms for the corresponding `RecordData` variants.

- [ ] **Step 9.5: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 9.6: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/zone/rdata_dnssec.rs crates/bind9-sdk-core/src/zone/rdata_text.rs
  git commit -m "feat(core): DNSSEC text parse/serialize — RRSIG, NSEC, NSEC3, NSEC3PARAM"
  ```

#### Task 10: Proptest Roundtrip + Insta Snapshots for DNSSEC Types

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/rdata_dnssec.rs` (add proptest + insta in tests module)

- [ ] **Step 10.1: Write proptest roundtrip for DNSKEY**

  ```rust
  proptest! {
      #[test]
      fn dnskey_roundtrip(
          flags in 0u16..=65535,
          protocol in proptest::num::u8::ANY,
          algorithm in 1u8..=16,
          key_len in 16usize..=128,
      ) {
          let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
          let rdata = RecordData::Dnskey { flags, protocol, algorithm, public_key: key };
          let text = serialize_rdata(&rdata);
          let tokens: Vec<&str> = text.split_whitespace().collect();
          let parsed = parse_dnskey(&tokens).unwrap();
          prop_assert_eq!(rdata, parsed);
      }
  }
  ```

- [ ] **Step 10.2: Add roundtrip proptests for DS, NSEC3, RRSIG**

  Similar pattern: generate valid field values, serialize, split, parse, assert equality.

- [ ] **Step 10.3: Add insta snapshot tests for DNSSEC zone serialization**

  ```rust
  #[test]
  fn snapshot_dnssec_zone() {
      let zone = ZoneFile { /* zone with DNSKEY, RRSIG, DS records */ };
      let output = zone.serialize();
      insta::assert_snapshot!(output);
  }
  ```

- [ ] **Step 10.4: Run tests and review snapshots**

  Run: `cargo test -p bind9-sdk-core --lib`
  Then: `cargo insta review`
  Expected: PASS, snapshots look correct

- [ ] **Step 10.5: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/zone/rdata_dnssec.rs crates/bind9-sdk-core/src/snapshots/
  git commit -m "test(core): proptest roundtrip + insta snapshots for DNSSEC types"
  ```

#### Task 11: DNSSEC Test Vectors from dig

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/rdata_dnssec.rs` (tests module)

- [ ] **Step 11.1: Add dig +dnssec test vectors**

  Parse real DNSSEC output captured from `dig +dnssec example.com DNSKEY` against a real DNSSEC-signed zone. These are golden-file tests — hardcoded expected output.

  ```rust
  #[test]
  fn parse_real_dnskey_from_dig() {
      // Captured from: dig +dnssec example.com DNSKEY
      let tokens = &["257", "3", "13",
          "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="];
      let rdata = parse_dnskey(tokens).unwrap();
      // Verify specific field values
      match rdata {
          RecordData::Dnskey { flags: 257, protocol: 3, algorithm: 13, ref public_key } => {
              assert_eq!(public_key.len(), 64); // P-256 key is 64 bytes
          }
          other => panic!("unexpected: {other:?}"),
      }
  }
  ```

- [ ] **Step 11.2: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 11.3: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/zone/rdata_dnssec.rs
  git commit -m "test(core): DNSSEC test vectors from dig captures"
  ```

### WT-B: IXFR/AXFR Zone Transfer Client

**Branch:** `feat/ixfr-axfr`
**Worktree:** `.worktrees/wt-b`

#### Task 12: Core Transfer Types

**Files:**
- Create: `crates/bind9-sdk-core/src/transfer.rs`
- Modify: `crates/bind9-sdk-core/src/lib.rs`

- [ ] **Step 12.1: Write failing test**

  ```rust
  #[test]
  fn transfer_request_axfr() {
      let zone = DomainName::new("example.com.").unwrap();
      let req = TransferRequest::axfr(zone.clone());
      assert_eq!(req.zone(), &zone);
      assert!(req.is_axfr());
  }
  ```

- [ ] **Step 12.2: Run to verify fail**

  Expected: FAIL

- [ ] **Step 12.3: Implement core transfer types**

  Per spec: `TransferSession<Pending/Active>` typestate in core.

  ```rust
  /// Typestate marker: transfer session created but not started.
  pub struct Pending;
  /// Typestate marker: transfer is actively streaming records.
  pub struct Active;

  /// A zone transfer session with typestate tracking.
  ///
  /// `TransferSession<Pending>` → call `start()` → `TransferSession<Active>`
  pub struct TransferSession<State> {
      zone: DomainName,
      kind: TransferKind,
      current_serial: Option<Serial>,
      _state: core::marker::PhantomData<State>,
  }

  impl TransferSession<Pending> {
      /// Create a new AXFR transfer session.
      pub fn axfr(zone: DomainName) -> Self { ... }
      /// Create a new IXFR transfer session.
      pub fn ixfr(zone: DomainName, current_serial: Serial) -> Self { ... }
      /// Zone being transferred.
      pub fn zone(&self) -> &DomainName { &self.zone }
      /// Whether this is a full transfer.
      pub fn is_axfr(&self) -> bool { matches!(self.kind, TransferKind::Axfr) }
  }

  /// Whether this is a full (AXFR) or incremental (IXFR) transfer.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum TransferKind {
      Axfr,
      Ixfr,
  }

  /// A single record from a zone transfer response.
  #[derive(Debug, Clone, PartialEq, Eq)]
  #[non_exhaustive]
  pub enum TransferRecord {
      /// Begin of transfer (first SOA).
      BeginSoa(ResourceRecord),
      /// A regular record in the transfer.
      Record(ResourceRecord),
      /// End of transfer (final SOA — serial matches begin).
      EndSoa(ResourceRecord),
  }
  ```

- [ ] **Step 12.4: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 12.5: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/transfer.rs crates/bind9-sdk-core/src/lib.rs
  git commit -m "feat(core): transfer types — TransferRequest, TransferKind, TransferRecord"
  ```

#### Task 13: DNS Wire Format Parsing

**Files:**
- Create: `crates/bind9-sdk-net/src/transfer/mod.rs`
- Create: `crates/bind9-sdk-net/src/transfer/wire.rs`
- Modify: `crates/bind9-sdk-net/src/lib.rs`

- [ ] **Step 13.1: Write failing test — parse DNS header**

  ```rust
  #[test]
  fn parse_dns_header() {
      // Minimal DNS response header: ID=0x1234, QR=1, OPCODE=0, RCODE=0
      let bytes = [0x12, 0x34, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
      let header = DnsHeader::parse(&bytes).unwrap();
      assert_eq!(header.id, 0x1234);
      assert!(header.is_response);
      assert_eq!(header.answer_count, 1);
  }
  ```

- [ ] **Step 13.2: Run to verify fail**

  Expected: FAIL

- [ ] **Step 13.3: Implement DNS wire format parser**

  In `transfer/wire.rs`:
  - `DnsHeader` — 12-byte DNS header parser
  - `parse_name(buf, offset) -> (DomainName, new_offset)` — DNS name compression (RFC 1035 §4.1.4)
  - `parse_resource_record(buf, offset) -> (ResourceRecord, new_offset)` — name + type + class + TTL + rdlength + rdata
  - `parse_rdata_wire(rtype, buf) -> RecordData` — wire format → RecordData for all supported types
  - `encode_axfr_query(zone, tsig_key) -> Vec<u8>` — build AXFR query message
  - `encode_ixfr_query(zone, serial, tsig_key) -> Vec<u8>` — build IXFR query message

  DNS TCP framing: 2-byte big-endian length prefix (NOT 4-byte like rndc).

- [ ] **Step 13.4: Run tests**

  Run: `cargo test -p bind9-sdk-net --lib`
  Expected: PASS

- [ ] **Step 13.5: Commit**

  ```bash
  git add crates/bind9-sdk-net/src/transfer/ crates/bind9-sdk-net/src/lib.rs
  git commit -m "feat(net): DNS wire format parser for zone transfers"
  ```

#### Task 14: TransferClient Streaming API

**Files:**
- Modify: `crates/bind9-sdk-net/src/transfer/mod.rs`
- Create: `crates/bind9-sdk-net/src/transfer/tests.rs`
- Modify: `crates/bind9-sdk-net/Cargo.toml`

- [ ] **Step 14.1: Add tokio-stream dependency**

  In workspace `Cargo.toml`:

  ```toml
  tokio-stream = "0.1"
  ```

  In `net/Cargo.toml`:

  ```toml
  tokio-stream = { workspace = true }
  ```

- [ ] **Step 14.2: Write failing test — transfer client connects**

  ```rust
  #[tokio::test]
  async fn transfer_client_mock_axfr() {
      let mock = MockTcpStream::new(/* AXFR response bytes */);
      let client = TransferClient::new(mock);
      let zone = DomainName::new("example.com.").unwrap();
      let mut stream = client.axfr(zone).await.unwrap();
      let first = stream.next().await.unwrap().unwrap();
      assert!(matches!(first, TransferRecord::BeginSoa(_)));
  }
  ```

- [ ] **Step 14.3: Implement TransferClient**

  ```rust
  /// Client for DNS zone transfers (AXFR/IXFR).
  pub struct TransferClient<S: AsyncRead + AsyncWrite + Unpin> {
      stream: S,
      tsig_key: Option<TsigKey>,
  }

  impl<S: AsyncRead + AsyncWrite + Unpin> TransferClient<S> {
      /// Perform a full zone transfer (AXFR).
      pub async fn axfr(
          &mut self,
          zone: DomainName,
      ) -> Result<impl Stream<Item = Result<TransferRecord, NetError>>, NetError> { ... }

      /// Perform an incremental zone transfer (IXFR).
      /// Falls back to AXFR if the server responds with a full zone.
      pub async fn ixfr(
          &mut self,
          zone: DomainName,
          current_serial: Serial,
      ) -> Result<impl Stream<Item = Result<TransferRecord, NetError>>, NetError> { ... }
  }
  ```

  Add `tracing` instrumentation: `#[instrument(skip(self), fields(zone = %zone))]` on `axfr()` and `ixfr()`.

- [ ] **Step 14.4: Run tests**

  Run: `cargo test -p bind9-sdk-net --lib`
  Expected: PASS

- [ ] **Step 14.5: Commit**

  ```bash
  git add crates/bind9-sdk-net/src/transfer/ crates/bind9-sdk-net/Cargo.toml Cargo.toml
  git commit -m "feat(net): TransferClient with AXFR/IXFR streaming API"
  ```

#### Task 15: TSIG Authentication for Transfers

**Files:**
- Modify: `crates/bind9-sdk-net/src/transfer/mod.rs`
- Modify: `crates/bind9-sdk-net/src/transfer/wire.rs`

- [ ] **Step 15.1: Write failing test — TSIG-signed AXFR query**

  ```rust
  #[test]
  fn axfr_query_includes_tsig() {
      let key = TsigKey::new(
          DomainName::new("test-key.").unwrap(),
          TsigAlgorithm::HmacSha256,
          vec![0u8; 32],
      ).unwrap();
      let query = encode_axfr_query(
          &DomainName::new("example.com.").unwrap(),
          Some(&key),
      );
      // TSIG record should be appended as additional record
      // AR count in header should be 1
      assert_eq!(query[10], 0); // ARCOUNT high byte
      assert_eq!(query[11], 1); // ARCOUNT low byte
  }
  ```

- [ ] **Step 15.2: Implement TSIG signing for transfer queries**

  Wire `TsigKey::sign()` into the AXFR/IXFR query encoding. Append TSIG as additional record per RFC 8945.

- [ ] **Step 15.3: Implement TSIG verification on transfer responses**

  Call `TsigRecord::verify_response()` with request MAC for TSIG chaining across multi-message transfers.

- [ ] **Step 15.4: Run tests**

  Run: `cargo test -p bind9-sdk-net --lib`
  Expected: PASS

- [ ] **Step 15.5: Commit**

  ```bash
  git add crates/bind9-sdk-net/src/transfer/
  git commit -m "feat(net): TSIG authentication for zone transfers"
  ```

#### Task 16: NetError Transfer Variants

**Files:**
- Modify: `crates/bind9-sdk-net/src/error.rs`

- [ ] **Step 16.1: Write failing test**

  ```rust
  #[test]
  fn transfer_failed_display() {
      let err = NetError::TransferFailed { reason: "connection reset".into() };
      assert_eq!(err.to_string(), "zone transfer failed: connection reset");
  }
  ```

- [ ] **Step 16.2: Run to verify fail**

  Expected: FAIL

- [ ] **Step 16.3: Add transfer error variants**

  ```rust
  /// Zone transfer failed.
  #[error("zone transfer failed: {reason}")]
  TransferFailed { reason: String },

  /// IXFR serial mismatch — server's base serial doesn't match requested.
  #[error("serial mismatch: expected {expected}, got {actual}")]
  SerialMismatch { expected: u32, actual: u32 },

  /// Zone transfer ended prematurely (no closing SOA).
  #[error("incomplete zone transfer: {reason}")]
  IncompleteTransfer { reason: String },

  /// XFR protocol error (bad message format, unexpected record sequence).
  #[error("XFR protocol error: {0}")]
  XfrProtocolError(String),
  ```

- [ ] **Step 16.4: Run tests**

  Run: `cargo test -p bind9-sdk-net --lib`
  Expected: PASS

- [ ] **Step 16.5: Commit**

  ```bash
  git add crates/bind9-sdk-net/src/error.rs
  git commit -m "feat(net): add zone transfer NetError variants"
  ```

#### Task 17: Integration Test — AXFR from Podman

**Files:**
- Create: `crates/bind9-sdk-net/tests/transfer_integration.rs`

- [ ] **Step 17.1: Write integration test**

  ```rust
  #[tokio::test]
  #[ignore = "requires live BIND9 on localhost:8053"]
  async fn axfr_transfer_example_com() {
      let stream = TcpStream::connect("127.0.0.1:8053").await.unwrap();
      let key = TsigKey::new(
          DomainName::new("rndc-key.").unwrap(),
          TsigAlgorithm::HmacSha256,
          base64_decode("/* key from tests/bind9/rndc.conf */"),
      ).unwrap();
      let mut client = TransferClient::new(stream);
      let zone = DomainName::new("transfer.example.com.").unwrap();
      let records: Vec<_> = client
          .axfr(zone)
          .await
          .unwrap()
          .collect()
          .await;
      assert!(records.len() >= 5, "expected at least SOA + NS + A records");
  }
  ```

- [ ] **Step 17.2: Commit**

  ```bash
  git add crates/bind9-sdk-net/tests/transfer_integration.rs
  git commit -m "test(net): AXFR integration test against Podman BIND9"
  ```

### WT-C: SOA Serial Strategies + Audit Carryover

**Branch:** `feat/soa-serial-audit`
**Worktree:** `.worktrees/wt-c`

#### Task 18: SerialStrategy Enum

**Files:**
- Modify: `crates/bind9-sdk-core/src/record.rs`

- [ ] **Step 18.1: Write failing test**

  ```rust
  #[test]
  fn serial_strategy_date_counter() {
      let strategy = SerialStrategy::DateCounter;
      let current = Serial::new(2026031700);
      let next = strategy.next(current);
      assert_eq!(next.value(), 2026031701);
  }
  ```

- [ ] **Step 18.2: Run to verify fail**

  Expected: FAIL

- [ ] **Step 18.3: Implement SerialStrategy**

  ```rust
  /// Strategy for computing the next SOA serial number.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  #[non_exhaustive]
  pub enum SerialStrategy {
      /// YYYYMMDDNN format — increment NN within same day, roll to next day's 00.
      DateCounter,
      /// Unix timestamp (seconds since epoch).
      UnixTimestamp,
      /// Simple increment by 1 (wraps at u32::MAX per RFC 1982).
      Monotonic,
  }

  impl SerialStrategy {
      /// Compute the next serial given the current value.
      ///
      /// For `DateCounter`, uses the current date. If the current serial
      /// already has today's date prefix, increments the counter. Otherwise,
      /// starts at `YYYYMMDD00`.
      ///
      /// For `UnixTimestamp`, returns current Unix time. If that would not
      /// be greater than `current` (clock skew), returns `current + 1`.
      ///
      /// For `Monotonic`, returns `current + 1`.
      pub fn next(&self, current: Serial) -> Serial {
          match self {
              Self::Monotonic => current + 1,
              Self::UnixTimestamp => {
                  // Requires std — feature-gated
                  #[cfg(feature = "std")]
                  {
                      let now = std::time::SystemTime::now()
                          .duration_since(std::time::UNIX_EPOCH)
                          .unwrap_or_default()
                          .as_secs() as u32;
                      if Serial::new(now) > current {
                          Serial::new(now)
                      } else {
                          current + 1
                      }
                  }
                  #[cfg(not(feature = "std"))]
                  {
                      current + 1 // Fallback without clock
                  }
              }
              Self::DateCounter => {
                  // Date-based: YYYYMMDDNN
                  #[cfg(feature = "std")]
                  {
                      // Implementation uses current date
                      compute_date_counter_serial(current)
                  }
                  #[cfg(not(feature = "std"))]
                  {
                      current + 1 // Fallback without clock
                  }
              }
          }
      }
  }
  ```

- [ ] **Step 18.4: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 18.5: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/record.rs
  git commit -m "feat(core): SerialStrategy — DateCounter, UnixTimestamp, Monotonic"
  ```

#### Task 19: Column Numbers in ZoneParse Errors (GPT-ZONE-COL)

**Files:**
- Modify: `crates/bind9-sdk-core/src/error.rs`
- Modify: `crates/bind9-sdk-core/src/zone/parser/mod.rs`
- Modify: `crates/bind9-sdk-core/src/zone/parser/tokenizer.rs`
- Modify: `crates/bind9-sdk-core/src/zone/rdata_text.rs`

- [ ] **Step 19.1: Write failing test**

  ```rust
  #[test]
  fn zone_parse_error_has_column() {
      let input = "example.com. 3600 IN A not-an-ip";
      let result = ZoneFile::parse(input);
      let err = result.unwrap_err();
      match err {
          CoreError::ZoneParse { line, column, .. } => {
              assert!(column.is_some(), "error should include column number");
          }
          other => panic!("expected ZoneParse, got {other:?}"),
      }
  }
  ```

- [ ] **Step 19.2: Add column field to ZoneParse**

  In `error.rs`, change:

  ```rust
  ZoneParse { line: u32, reason: String }
  ```

  to:

  ```rust
  ZoneParse { line: u32, column: Option<u32>, reason: String }
  ```

  Update all existing `CoreError::ZoneParse { line, reason }` construction sites to include `column: None` initially, then propagate column info from the tokenizer where available.

- [ ] **Step 19.3: Run tests — fix compilation errors**

  Update all pattern matches and constructors across the codebase.

  Run: `cargo test --workspace`
  Expected: PASS

- [ ] **Step 19.4: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/error.rs crates/bind9-sdk-core/src/zone/
  git commit -m "feat(core): add column to ZoneParse error (GPT-ZONE-COL)"
  ```

#### Task 20: F-002 rndc Nonce Hardening

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/mod.rs`

- [ ] **Step 20.1: Write failing test**

  ```rust
  #[test]
  fn rndc_nonce_is_random() {
      let nonce1 = generate_nonce();
      let nonce2 = generate_nonce();
      assert_ne!(nonce1, nonce2, "nonces should not be identical");
      assert_eq!(nonce1.len(), 16, "nonce should be 16 bytes");
  }
  ```

- [ ] **Step 20.2: Implement random nonce generation**

  Replace any static/sequential nonce with `rand::thread_rng().fill_bytes()` (or `getrandom` if `rand` not available). Generate 16 random bytes per rndc session.

- [ ] **Step 20.3: Run tests**

  Run: `cargo test -p bind9-sdk-net --lib`
  Expected: PASS

- [ ] **Step 20.4: Commit**

  ```bash
  git add crates/bind9-sdk-net/src/rndc/mod.rs
  git commit -m "fix(net): F-002 rndc nonce hardening — use random bytes"
  ```

#### Task 21: F-005 Doc Alignment

**Files:**
- Various doc updates across crate

- [ ] **Step 21.1: Review and fix doc alignment issues from audit**

  Check all public API doc comments match actual behavior. Fix any discrepancies found in F-005.

- [ ] **Step 21.2: Run doc tests**

  Run: `cargo test --workspace --doc`
  Expected: PASS

- [ ] **Step 21.3: Commit**

  ```bash
  git add -u
  git commit -m "docs(sdk): F-005 doc alignment — fix public API doc accuracy"
  ```

### P2-W1 Merge

After all three worktrees complete:

- [ ] **Step 22.1: Merge WT-C first (smallest diff, least conflict risk)**

  ```bash
  git checkout development
  git merge feat/soa-serial-audit --no-ff -m "feat: P2-W1 SOA serial strategies + audit carryover (WT-C)"
  ```

- [ ] **Step 22.2: Merge WT-B (transfer client)**

  ```bash
  git merge feat/ixfr-axfr --no-ff -m "feat: P2-W1 IXFR/AXFR zone transfer client (WT-B)"
  ```

- [ ] **Step 22.3: Merge WT-A (DNSSEC types — may conflict on core/lib.rs pub mod)**

  ```bash
  git merge feat/dnssec-types --no-ff -m "feat: P2-W1 DNSSEC record types (WT-A)"
  ```

  Expected trivial conflict: both WT-A and WT-B add `pub mod` declarations to `core/lib.rs`. Resolve by keeping both.

- [ ] **Step 22.4: Run full quality gate**

  ```bash
  cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo check -p bind9-sdk-core --target wasm32-unknown-unknown && cargo test --workspace
  ```

  Expected: PASS

- [ ] **Step 22.5: Commit merge resolution if needed**

## P2-W2: Dependent Features + Research

### WT-D: CDS/CDNSKEY Generation + KASP State Querying

**Branch:** `feat/cds-kasp`
**Worktree:** `.worktrees/wt-d`
**Depends on:** WT-A merged (DNSSEC types available)

#### Task 23: CDS Generation from DNSKEY

**Files:**
- Create: `crates/bind9-sdk-core/src/dnssec.rs`
- Modify: `crates/bind9-sdk-core/src/lib.rs`

- [ ] **Step 23.1: Write failing test**

  ```rust
  #[test]
  fn cds_from_dnskey_sha256() {
      let dnskey = RecordData::Dnskey {
          flags: 257,
          protocol: 3,
          algorithm: 13,
          public_key: vec![/* 64 bytes of test key */],
      };
      let cds = CdsRecord::from_dnskey(&dnskey, DigestType::Sha256).unwrap();
      assert_eq!(cds.algorithm, 13);
      assert_eq!(cds.digest_type, 2); // SHA-256 = 2
      assert_eq!(cds.digest.len(), 32);
  }
  ```

- [ ] **Step 23.2: Implement CDS generation**

  ```rust
  /// Digest algorithm for DS/CDS record generation.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum DigestType {
      /// SHA-256 (mandatory per RFC 4509).
      Sha256,
      /// SHA-384.
      Sha384,
  }

  /// Helper for generating CDS records from DNSKEY.
  pub struct CdsRecord;

  impl CdsRecord {
      /// Generate a CDS record from a DNSKEY record.
      ///
      /// Computes the DS digest per RFC 4034 §5.1.4:
      /// digest = hash(owner_name_wire || dnskey_rdata_wire)
      pub fn from_dnskey(
          owner: &DomainName,
          dnskey: &RecordData,
          digest_type: DigestType,
      ) -> Result<RecordData, CoreError> { ... }

      /// Generate the RFC 8078 §4 DELETE sentinel CDS record.
      ///
      /// key_tag=0, algorithm=0, digest_type=0, digest=0x00
      pub fn delete_sentinel() -> RecordData { ... }
  }

  /// Compute the key tag for a DNSKEY record per RFC 4034 Appendix B.
  pub fn compute_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 { ... }
  ```

  Uses `sha2` crate (already in workspace via TSIG dependencies, `no_std` compatible).

- [ ] **Step 23.3: Run tests**

  Run: `cargo test -p bind9-sdk-core --lib`
  Expected: PASS

- [ ] **Step 23.4: Commit**

  ```bash
  git add crates/bind9-sdk-core/src/dnssec.rs crates/bind9-sdk-core/src/lib.rs
  git commit -m "feat(core): CDS generation from DNSKEY — SHA-256/SHA-384 + DELETE sentinel"
  ```

#### Task 24: KASP Response Parsing

**Files:**
- Create: `crates/bind9-sdk-net/src/rndc/dnssec.rs`
- Modify: `crates/bind9-sdk-net/src/rndc/mod.rs`
- Modify: `crates/bind9-sdk-net/src/rndc/command.rs`

- [ ] **Step 24.1: Write failing test**

  ```rust
  #[test]
  fn parse_dnssec_status_response() {
      let raw = "dnssec-policy: default\nkey: 12345 (KSK), state: OMNIPRESENT\n";
      let status = DnssecStatus::parse(raw).unwrap();
      assert_eq!(status.policy, "default");
      assert_eq!(status.keys.len(), 1);
      assert_eq!(status.keys[0].tag, 12345);
  }
  ```

- [ ] **Step 24.2: Implement KASP response types**

  ```rust
  /// Parsed output of `rndc dnssec -status <zone>`.
  #[derive(Debug, Clone)]
  pub struct DnssecStatus {
      pub policy: String,
      pub keys: Vec<DnssecKeyInfo>,
  }

  #[derive(Debug, Clone)]
  pub struct DnssecKeyInfo {
      pub tag: u16,
      pub role: KeyRole,
      pub state: String,
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum KeyRole { Ksk, Zsk, Csk }

  /// Parsed output of `rndc dnssec -checkds <zone>`.
  #[derive(Debug, Clone)]
  pub struct DsCheckResult {
      pub published: bool,
      pub withdrawn: bool,
  }
  ```

- [ ] **Step 24.3: Add rndc command variants**

  In `command.rs`, add `DnssecStatus(DomainName)` and `DnssecCheckDs(DomainName)` to `RndcCommand`.

- [ ] **Step 24.4: Run tests**

  Run: `cargo test -p bind9-sdk-net --lib`
  Expected: PASS

- [ ] **Step 24.5: Commit**

  ```bash
  git add crates/bind9-sdk-net/src/rndc/dnssec.rs crates/bind9-sdk-net/src/rndc/mod.rs crates/bind9-sdk-net/src/rndc/command.rs
  git commit -m "feat(net): KASP response parsing — DnssecStatus, DsCheckResult"
  ```

### WT-E: XoT Transport (DNS-over-TLS)

**Branch:** `feat/xot-transport`
**Worktree:** `.worktrees/wt-e`
**Depends on:** WT-B merged (TransferClient available)

#### Task 25: TLS Required Error + Localhost Exemption

**Files:**
- Modify: `crates/bind9-sdk-net/src/error.rs`
- Modify: `crates/bind9-sdk-net/src/tls.rs`

- [ ] **Step 25.1: Write failing test**

  ```rust
  #[test]
  fn tls_required_error() {
      let err = NetError::TlsRequired { remote: "10.0.0.1:853".into() };
      assert_eq!(err.to_string(), "TLS required for non-localhost connection to 10.0.0.1:853");
  }
  ```

- [ ] **Step 25.2: Add TlsRequired variant**

  ```rust
  /// TLS is required for non-localhost connections (REQ-TLS-1).
  #[error("TLS required for non-localhost connection to {remote}")]
  TlsRequired { remote: String },
  ```

- [ ] **Step 25.3: Implement localhost exemption**

  In `tls.rs`, add:

  ```rust
  /// Check if a socket address is localhost (127.0.0.0/8 or ::1).
  pub fn is_localhost(addr: &std::net::SocketAddr) -> bool {
      match addr.ip() {
          std::net::IpAddr::V4(v4) => v4.is_loopback(),
          std::net::IpAddr::V6(v6) => v6.is_loopback(),
      }
  }
  ```

- [ ] **Step 25.4: Run tests**

  Run: `cargo test -p bind9-sdk-net --lib`
  Expected: PASS

- [ ] **Step 25.5: Commit**

  ```bash
  git add crates/bind9-sdk-net/src/error.rs crates/bind9-sdk-net/src/tls.rs
  git commit -m "feat(net): TlsRequired error + localhost exemption for XoT"
  ```

#### Task 26: Wire TLS into TransferClient

**Files:**
- Modify: `crates/bind9-sdk-net/src/transfer/mod.rs`

- [ ] **Step 26.1: Write failing test**

  ```rust
  #[tokio::test]
  async fn transfer_rejects_non_localhost_without_tls() {
      let addr: SocketAddr = "10.0.0.1:53".parse().unwrap();
      let result = TransferClient::connect(addr, None).await;
      assert!(matches!(result, Err(NetError::TlsRequired { .. })));
  }

  #[tokio::test]
  async fn transfer_allows_localhost_without_tls() {
      // This will fail to connect (no server), but should NOT get TlsRequired error
      let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
      let result = TransferClient::connect(addr, None).await;
      assert!(matches!(result, Err(NetError::Connection(_))));
  }
  ```

- [ ] **Step 26.2: Implement TLS enforcement in TransferClient::connect**

  Add `connect(addr, tls_config)` constructor that checks `is_localhost()` and requires TLS for remote addresses. When TLS is provided, use `tokio-rustls` to wrap the TCP stream.

- [ ] **Step 26.3: Run tests**

  Run: `cargo test -p bind9-sdk-net --lib`
  Expected: PASS

- [ ] **Step 26.4: Commit**

  ```bash
  git add crates/bind9-sdk-net/src/transfer/mod.rs
  git commit -m "feat(net): XoT — TLS enforcement for non-localhost zone transfers"
  ```

### napi-rs v3 Research Spike

No worktree — this is a research task that produces a document.

#### Task 27: Research Spike

- [ ] **Step 27.1: Evaluate napi-rs v3 state**

  - Check napi-rs v3 release status (stable/beta/alpha)
  - Build minimal hello-world binding with v3
  - Test `wasm32-wasip1-threads` output
  - Document: what works, what doesn't, migration path from v2 stub

- [ ] **Step 27.2: Write research doc**

  Create `docs/specs/2026-XX-XX-napi-v3-research.md` with findings.

- [ ] **Step 27.3: Commit**

  ```bash
  git add docs/specs/
  git commit -m "docs(specs): napi-rs v3 research spike findings"
  ```

### P2-W2 Merge

- [ ] **Step 28.1: Merge WT-D**

  ```bash
  git checkout development
  git merge feat/cds-kasp --no-ff -m "feat: P2-W2 CDS/CDNSKEY generation + KASP querying (WT-D)"
  ```

- [ ] **Step 28.2: Merge WT-E**

  ```bash
  git merge feat/xot-transport --no-ff -m "feat: P2-W2 XoT transport (WT-E)"
  ```

- [ ] **Step 28.3: Run full quality gate**

  ```bash
  cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo check -p bind9-sdk-core --target wasm32-unknown-unknown && cargo test --workspace
  ```

## P2-W3: Integration + Hardening

**Branch:** `feat/p2-hardening`

#### Task 29: Full Integration Test Suite

- [ ] **Step 29.1: Run all integration tests against Podman**

  ```bash
  make test-integration
  ```

- [ ] **Step 29.2: Fix any failures**

- [ ] **Step 29.3: Commit**

  ```bash
  git add -u
  git commit -m "fix(net): P2-W3 integration test fixes"
  ```

#### Task 30: Dialectic Verification

- [ ] **Step 30.1: Run `/dialectic-verify` on Phase 2 codebase**

- [ ] **Step 30.2: Remediate findings**

- [ ] **Step 30.3: Update audit-findings.md**

  ```bash
  git add docs/plans/2026-03-16-audit-findings.md
  git commit -m "docs(audit): Phase 2 dialectic verification findings"
  ```

#### Task 31: Phase 2 Completion

- [ ] **Step 31.1: Update PRD with Phase 2 status**

- [ ] **Step 31.2: Merge to development**

  ```bash
  git checkout development
  git merge feat/p2-hardening --no-ff -m "feat: Phase 2 complete — zone transfers, DNSSEC, CDS/KASP, XoT"
  ```

- [ ] **Step 31.3: Push**

  ```bash
  git push origin development
  ```
