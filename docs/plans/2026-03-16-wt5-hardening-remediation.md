<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
-->

# WT-5: TSIG/Update Hardening + Dialectic Verify Remediation

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden TSIG, fix all accepted dialectic verify findings, and add TSIG response verification that was deferred from WT-4.

**Architecture:** Two crates affected: `bind9-sdk-core` (TSIG hardening, RFC 2136 prerequisite, TSIG wire parsing) and `bind9-sdk-net` (rndc protocol fixes, config contract alignment, nsupdate TSIG verification). All changes are backward-compatible except `ServerStats`/`ZoneStats` field type changes and `NetError::AuthFailed` gaining a field — all guarded by existing `#[non_exhaustive]`.

**Tech Stack:** Rust 2024, tokio, bind9-sdk-core (TsigKey, TsigRecord), bind9-sdk-net (rndc, stats, nsupdate), zeroize, tracing

**Branch:** `feat/wt5-hardening`
**Sources:**
- Remediation plan: `docs/plans/2026-03-16-wave2-review-remediation.md` (SEC-001/002/003, RFC2136-001, TSIG-005, TEST-003/004)
- Dialectic verify: `docs/plans/2026-03-16-wave2-dialectic-verify.md` (F-003/006/008/009/013/014/015/034/035/036)
**Depends on:** WT-3 + WT-4 merged to `development` (commit `7a2a0f1`)

## Pre-conditions

Before starting, the following must exist on `development`:

- `bind9-sdk-core` has: `TsigKey`, `TsigRecord`, `TsigAlgorithm` in `tsig.rs`; `Prerequisite` enum and `UpdateBuilder` in `update.rs`; `ServerStatus`, `ServerStats`, `ZoneStats` in `traits.rs`
- `bind9-sdk-net` has: `RndcConnection` typestate in `rndc/mod.rs`; `IscMessage` encode/decode in `rndc/protocol.rs`; `RndcCommand`, `RndcResponse`, `RndcResult`, `parse_server_status` in `rndc/command.rs`; `StatsHttpClient` in `stats.rs`; `NsUpdateSender` in `nsupdate.rs`; `ClientConfig`, `Bind9Client` in `config.rs`; `NetError` in `error.rs`

## Chunk 1: Core Crate — TsigRecord Hardening (SEC-001, SEC-002, TSIG-005)

Harden TsigRecord: zeroize secret fields, redact in Debug, add request_mac parameter.

### Task 1.1: Zeroize TsigRecord MAC and Wire Bytes (SEC-001)

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs:233-248` (TsigRecord struct)
- Modify: `crates/bind9-sdk-core/src/tsig.rs:250-365` (TsigRecord::new)

- [ ] **Step 1: Write failing test for zeroize on TsigRecord**

Add to `tsig.rs` tests:

```rust
#[test]
fn tsig_record_mac_is_zeroizing() {
    let key = TsigKey::new(
        DomainName::new("zr-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let record = TsigRecord::new(&key, &alloc::vec![0u8; 12], 1710000000);
    // Verify mac field type is Zeroizing<Vec<u8>> by checking it derefs
    let mac_bytes: &[u8] = &record.mac;
    assert_eq!(mac_bytes.len(), 32);
}
```

- [ ] **Step 2: Run test — expect compile error (mac is Vec, not Zeroizing)**

Run: `cargo test -p bind9-sdk-core tsig_record_mac_is_zeroizing`

- [ ] **Step 3: Change TsigRecord fields to use Zeroizing**

In `tsig.rs`, change TsigRecord:

```rust
pub struct TsigRecord {
    pub key_name: DomainName,
    pub algorithm: TsigAlgorithm,
    pub time_signed: u64,
    pub fudge: u16,
    /// The computed HMAC. Wrapped in `Zeroizing` to clear on drop.
    pub mac: Zeroizing<Vec<u8>>,
    pub original_id: u16,
    /// Complete TSIG record in wire format. Wrapped in `Zeroizing` to clear on drop.
    pub wire_bytes: Zeroizing<Vec<u8>>,
}
```

Update `TsigRecord::new()` return to wrap in `Zeroizing::new()`:

```rust
TsigRecord {
    key_name: key.name.clone(),
    algorithm: key.algorithm,
    time_signed: timestamp,
    fudge,
    mac: Zeroizing::new(mac),
    original_id,
    wire_bytes: Zeroizing::new(wire),
}
```

- [ ] **Step 4: Fix all compilation errors from the type change**

Update any code that accesses `record.mac` or `record.wire_bytes` — `Zeroizing<Vec<u8>>` derefs to `Vec<u8>`, so most usages work unchanged. Fix test assertions that compare `Vec` directly (use `.as_slice()` or `&*record.mac`).

- [ ] **Step 5: Run tests**

Run: `cargo test -p bind9-sdk-core`
Expected: All existing + new test pass.

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): zeroize TsigRecord mac and wire_bytes (SEC-001)"
```

### Task 1.2: TsigRecord Debug Redaction (SEC-002)

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs` (add Debug impl for TsigRecord)

- [ ] **Step 1: Write failing test for Debug redaction**

```rust
#[test]
fn tsig_record_debug_redacts_mac() {
    let key = TsigKey::new(
        DomainName::new("dbg-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xEE; 32],
    )
    .unwrap();
    let record = TsigRecord::new(&key, &alloc::vec![0u8; 12], 1710000000);
    let debug = format!("{:?}", record);
    assert!(debug.contains("[REDACTED]"), "Debug must redact mac: {debug}");
    assert!(!debug.contains("238"), "Debug must not leak mac bytes: {debug}");
}
```

- [ ] **Step 2: Run test — expect failure (derive Debug shows raw bytes)**

Run: `cargo test -p bind9-sdk-core tsig_record_debug_redacts_mac`

- [ ] **Step 3: Remove derive(Debug) from TsigRecord, add manual impl**

Remove `Debug` from any derive on `TsigRecord` (it currently has none — it's a plain struct without derive). Add:

```rust
impl fmt::Debug for TsigRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigRecord")
            .field("key_name", &self.key_name)
            .field("algorithm", &self.algorithm)
            .field("time_signed", &self.time_signed)
            .field("fudge", &self.fudge)
            .field("mac", &"[REDACTED]")
            .field("original_id", &self.original_id)
            .field("wire_bytes", &"[REDACTED]")
            .finish()
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-core`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): redact TsigRecord mac/wire_bytes in Debug (SEC-002)"
```

### Task 1.3: Key Length Validation Warning (SEC-003)

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs:85-101` (TsigKey::new)

- [ ] **Step 1: Add tracing warning when key is shorter than recommended**

In `TsigKey::new()`, after the empty check, add:

```rust
#[cfg(feature = "std")]
if key_material.len() < algorithm.key_length() {
    tracing::warn!(
        key_name = %name,
        algorithm = %algorithm,
        actual_len = key_material.len(),
        recommended_len = algorithm.key_length(),
        "TSIG key shorter than algorithm's recommended length"
    );
}
```

This is `std`-gated because `tracing` requires `std` in practice and `no_std` core shouldn't log.

- [ ] **Step 2: Add tracing dev-dependency to bind9-sdk-core**

In `crates/bind9-sdk-core/Cargo.toml`, add under `[dependencies]`:

```toml
tracing = { version = "0.1", optional = true }
```

And add to `[features]`:

```toml
std = ["tracing"]
```

Note: If `tracing` is already a dependency, just ensure it's behind `std`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p bind9-sdk-core`
Expected: PASS (warning only emitted, not tested — runtime behavior)

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: PASS (tracing gated behind `std`)

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-core/
git commit -m "feat(core): warn on short TSIG key material (SEC-003)"
```

### Task 1.4: request_mac for Multi-Message TSIG (TSIG-005)

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs:259` (TsigRecord::new signature)

- [ ] **Step 1: Write failing test for request_mac chaining**

```rust
#[test]
fn tsig_record_with_request_mac_differs() {
    let key = TsigKey::new(
        DomainName::new("chain-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xBB; 32],
    )
    .unwrap();
    let msg = alloc::vec![0u8; 12];
    let ts = 1710000000u64;

    let r1 = TsigRecord::new(&key, &msg, ts, None);
    let prior_mac = alloc::vec![0xCC; 32];
    let r2 = TsigRecord::new(&key, &msg, ts, Some(&prior_mac));

    assert_ne!(
        &*r1.mac, &*r2.mac,
        "Including request_mac must change the output MAC"
    );
}
```

- [ ] **Step 2: Run test — expect compile error (wrong arg count)**

Run: `cargo test -p bind9-sdk-core tsig_record_with_request_mac_differs`

- [ ] **Step 3: Add request_mac parameter to TsigRecord::new**

Change signature from:

```rust
pub fn new(key: &TsigKey, message: &[u8], timestamp: u64) -> Self {
```

To:

```rust
pub fn new(key: &TsigKey, message: &[u8], timestamp: u64, request_mac: Option<&[u8]>) -> Self {
```

Per RFC 8945 §4.5.3, for response MAC computation, prepend the request MAC (length-prefixed) before the DNS message in the MAC input:

```rust
let mut mac_input = Vec::with_capacity(message.len() + tsig_vars.len());
// If chaining (response or multi-message), prepend prior MAC
if let Some(prior) = request_mac {
    mac_input.extend_from_slice(&(prior.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(prior);
}
mac_input.extend_from_slice(message);
mac_input.extend_from_slice(&tsig_vars);
```

- [ ] **Step 4: Update all existing callers to pass `None`**

All existing calls to `TsigRecord::new(key, msg, ts)` become `TsigRecord::new(key, msg, ts, None)`. Search across crates:

- `crates/bind9-sdk-core/src/tsig.rs` (tests)
- `crates/bind9-sdk-core/src/update.rs` (UpdateBuilder::sign)
- Any net crate callers

- [ ] **Step 5: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/ crates/bind9-sdk-net/
git commit -m "feat(core): add request_mac param to TsigRecord::new (TSIG-005)"
```

## Chunk 2: Core Crate — TSIG Wire Parsing + Response Verification (TEST-002, TSIG-002, TSIG-004)

Add ability to parse TSIG records from DNS response wire format and verify them. This is the highest-priority item from dialectic verify (F-036).

### Task 2.1: TSIG Wire Parsing (TEST-002)

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs` (add `TsigRecord::parse_from_wire`)

- [ ] **Step 1: Write failing test for TSIG wire roundtrip**

```rust
#[test]
fn tsig_record_wire_roundtrip() {
    let key = TsigKey::new(
        DomainName::new("rt-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xDD; 32],
    )
    .unwrap();
    let message = alloc::vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let ts = 1710000000u64;
    let original = TsigRecord::new(&key, &message, ts, None);

    let parsed = TsigRecord::parse_from_wire(&original.wire_bytes).unwrap();
    assert_eq!(parsed.key_name, original.key_name);
    assert_eq!(parsed.algorithm, original.algorithm);
    assert_eq!(parsed.time_signed, original.time_signed);
    assert_eq!(parsed.fudge, original.fudge);
    assert_eq!(&*parsed.mac, &*original.mac);
    assert_eq!(parsed.original_id, original.original_id);
}
```

- [ ] **Step 2: Run test — expect compile error (method doesn't exist)**

Run: `cargo test -p bind9-sdk-core tsig_record_wire_roundtrip`

- [ ] **Step 3: Implement `TsigRecord::parse_from_wire`**

Parse the wire format produced by `TsigRecord::new`. Wire layout:
1. Owner name (wire format labels)
2. TYPE: u16 (must be 250 = TSIG)
3. CLASS: u16 (must be 255 = ANY)
4. TTL: u32 (must be 0)
5. RDLENGTH: u16
6. RDATA:
   - Algorithm name (wire format labels)
   - Time signed: 6 bytes (48-bit big-endian)
   - Fudge: u16
   - MAC size: u16
   - MAC: [u8; mac_size]
   - Original ID: u16
   - Error: u16
   - Other length: u16
   - Other data: [u8; other_length]

```rust
impl TsigRecord {
    /// Parse a TSIG pseudo-record from wire format bytes.
    ///
    /// The input should be the complete TSIG record starting from the owner name.
    /// Returns `Err` if the wire format is invalid or truncated.
    pub fn parse_from_wire(wire: &[u8]) -> Result<Self, CoreError> {
        // Implementation: parse each field sequentially
        // Use helper to read wire-format domain name
        // Map algorithm DNS name back to TsigAlgorithm
        // ...
    }
}
```

The implementation needs a wire-format domain name reader. Add a helper:

```rust
/// Read a wire-format domain name (uncompressed) from `data` at `pos`.
/// Returns the parsed name string and advances `pos`.
fn read_wire_name(data: &[u8], pos: &mut usize) -> Result<String, CoreError> {
    let mut labels = Vec::new();
    loop {
        if *pos >= data.len() {
            return Err(CoreError::Tsig("truncated wire name".into()));
        }
        let len = data[*pos] as usize;
        *pos += 1;
        if len == 0 {
            break;
        }
        if *pos + len > data.len() {
            return Err(CoreError::Tsig("truncated wire name label".into()));
        }
        let label = core::str::from_utf8(&data[*pos..*pos + len])
            .map_err(|_| CoreError::Tsig("invalid UTF-8 in wire name".into()))?;
        labels.push(label.to_string());
        *pos += len;
    }
    let mut name = labels.join(".");
    name.push('.');
    Ok(name)
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-core`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): add TsigRecord::parse_from_wire (TEST-002)"
```

### Task 2.2: Fudge Window Validation (TSIG-004)

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs`

- [ ] **Step 1: Write failing test for fudge window check**

```rust
#[test]
fn tsig_verify_response_rejects_expired_fudge() {
    let key = TsigKey::new(
        DomainName::new("fudge-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let msg = alloc::vec![0u8; 12];
    let request_ts = 1710000000u64;
    let record = TsigRecord::new(&key, &msg, request_ts, None);

    // Verify with a current time far outside fudge window (300s default)
    let now = request_ts + 600; // 10 minutes later
    let result = record.verify_time(now);
    assert!(result.is_err(), "Should reject response outside fudge window");
}

#[test]
fn tsig_verify_response_accepts_within_fudge() {
    let key = TsigKey::new(
        DomainName::new("fudge-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let msg = alloc::vec![0u8; 12];
    let request_ts = 1710000000u64;
    let record = TsigRecord::new(&key, &msg, request_ts, None);

    let now = request_ts + 100; // within 300s fudge
    let result = record.verify_time(now);
    assert!(result.is_ok());
}
```

- [ ] **Step 2: Run test — expect compile error**

- [ ] **Step 3: Implement `verify_time` on TsigRecord**

```rust
impl TsigRecord {
    /// Verify that the TSIG timestamp is within the fudge window of `now`.
    ///
    /// Per RFC 8945 §5.2.3, if |time_signed - now| > fudge, reject with BADTIME.
    pub fn verify_time(&self, now: u64) -> Result<(), CoreError> {
        let diff = if now > self.time_signed {
            now - self.time_signed
        } else {
            self.time_signed - now
        };
        if diff > self.fudge as u64 {
            return Err(CoreError::Tsig(alloc::format!(
                "TSIG time outside fudge window: signed={}, now={}, fudge={}",
                self.time_signed, now, self.fudge
            )));
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-core`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): add TsigRecord fudge window validation (TSIG-004)"
```

### Task 2.3: TSIG Response MAC Verification Helper

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs`

- [ ] **Step 1: Write failing test for response verification**

```rust
#[test]
fn tsig_verify_response_mac_valid() {
    let key = TsigKey::new(
        DomainName::new("resp-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let request_msg = alloc::vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let ts = 1710000000u64;
    let request_tsig = TsigRecord::new(&key, &request_msg, ts, None);

    // Simulate a response: same structure, different ID
    let response_msg = alloc::vec![0x00, 0x01, 0x80, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let response_tsig = TsigRecord::new(&key, &response_msg, ts, Some(&request_tsig.mac));

    // Verify the response TSIG
    let result = TsigRecord::verify_response(
        &key,
        &response_msg,
        &response_tsig,
        &request_tsig.mac,
        ts + 1, // current time
    );
    assert!(result.is_ok());
}
```

- [ ] **Step 2: Implement `TsigRecord::verify_response`**

```rust
impl TsigRecord {
    /// Verify a TSIG-signed DNS response.
    ///
    /// Per RFC 8945 §4.5: reconstruct MAC input from request MAC + response message +
    /// TSIG variables, then verify. Also checks fudge window.
    pub fn verify_response(
        key: &TsigKey,
        response_message: &[u8],
        response_tsig: &TsigRecord,
        request_mac: &[u8],
        now: u64,
    ) -> Result<(), CoreError> {
        // 1. Check fudge window
        response_tsig.verify_time(now)?;

        // 2. Reconstruct TSIG variables (same as in new(), without MAC)
        // 3. Build MAC input: request_mac (length-prefixed) + response + tsig_vars
        // 4. key.verify(mac_input, &response_tsig.mac)
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p bind9-sdk-core`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): add TsigRecord::verify_response (TSIG-002 foundation)"
```

## Chunk 3: Core Crate — RFC 2136 + Test Coverage (RFC2136-001, TEST-003, TEST-004)

### Task 3.1: RRsetExistsWithData Prerequisite (RFC2136-001)

**Files:**
- Modify: `crates/bind9-sdk-core/src/update.rs:11-25` (Prerequisite enum)

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn prerequisite_rrset_exists_with_data() {
    let name = DomainName::new("example.com.").unwrap();
    let rr = ResourceRecord { /* A record with 192.0.2.1 */ };
    let prereq = Prerequisite::RrsetExistsWithData {
        name: name.clone(),
        rtype: RecordType::A,
        records: alloc::vec![rr],
    };
    // Verify it compiles and has the expected fields
    match &prereq {
        Prerequisite::RrsetExistsWithData { name: n, rtype, records } => {
            assert_eq!(n, &name);
            assert_eq!(*rtype, RecordType::A);
            assert_eq!(records.len(), 1);
        }
        _ => panic!("wrong variant"),
    }
}
```

- [ ] **Step 2: Add variant to Prerequisite enum**

```rust
/// An RRset with this name, type, and specific data must exist (§2.4.2).
RrsetExistsWithData {
    name: DomainName,
    rtype: RecordType,
    records: Vec<ResourceRecord>,
},
```

- [ ] **Step 3: Update wire encoding in UpdateBuilder to handle new variant**

The prerequisite wire encoding in `UpdateBuilder::build_wire()` needs to encode `RrsetExistsWithData` per RFC 2136 §2.4.2: CLASS=zone class, TYPE=rtype, RDATA=actual record data.

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-core`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/update.rs
git commit -m "feat(core): add RRsetExistsWithData prerequisite (RFC2136-001)"
```

### Task 3.2: Exhaustive Algorithm Tests (TEST-003)

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs` (test section)

- [ ] **Step 1: Add sign/verify tests for all algorithm variants**

Ensure all three algorithms (HmacSha256, HmacSha512, HmacSha1) have:
- Sign produces correct length
- Verify roundtrip
- Verify wrong MAC fails
- RFC test vectors (4231 for SHA256 already exists; add SHA512)

```rust
#[test]
fn verify_roundtrip_sha512() {
    let key = TsigKey::new(
        DomainName::new("v-key.").unwrap(),
        TsigAlgorithm::HmacSha512,
        alloc::vec![0x42; 64],
    )
    .unwrap();
    let mac = key.sign(b"test message");
    assert!(key.verify(b"test message", &mac).is_ok());
    assert!(key.verify(b"wrong message", &mac).is_err());
}

#[test]
#[allow(deprecated)]
fn verify_roundtrip_sha1() {
    let key = TsigKey::new(
        DomainName::new("v-key.").unwrap(),
        TsigAlgorithm::HmacSha1,
        alloc::vec![0x42; 20],
    )
    .unwrap();
    let mac = key.sign(b"test message");
    assert!(key.verify(b"test message", &mac).is_ok());
    assert!(key.verify(b"wrong message", &mac).is_err());
}

/// RFC 4231 Test Case 1 for HMAC-SHA512
#[test]
fn sign_rfc_test_vector_sha512() {
    let key = TsigKey::new(
        DomainName::new("test.").unwrap(),
        TsigAlgorithm::HmacSha512,
        alloc::vec![0x0b; 20],
    )
    .unwrap();
    let mac = key.sign(b"Hi There");
    let expected: [u8; 64] = [
        0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d,
        0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0,
        0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78,
        0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
        0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02,
        0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
        0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
        0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
    ];
    assert_eq!(mac.as_slice(), &expected);
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p bind9-sdk-core`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "test(core): exhaustive algorithm sign/verify tests (TEST-003)"
```

### Task 3.3: Update Wire Roundtrip Tests (TEST-004)

**Files:**
- Modify: `crates/bind9-sdk-core/src/update.rs` (test section)

- [ ] **Step 1: Add wire roundtrip and section count tests**

```rust
#[test]
fn update_wire_section_counts() {
    let zone = DomainName::new("example.com.").unwrap();
    let builder = UpdateBuilder::with_id(0x1234, zone, RecordClass::IN)
        .require_name_exists(&DomainName::new("host.example.com.").unwrap())
        .add_record(/* A record */);
    let msg = builder.build();
    let wire = &msg.wire;

    // Header: ID(2) + FLAGS(2) + ZOCOUNT(2) + PRCOUNT(2) + UPCOUNT(2) + ADCOUNT(2)
    assert!(wire.len() >= 12);
    let zocount = u16::from_be_bytes([wire[4], wire[5]]);
    let prcount = u16::from_be_bytes([wire[6], wire[7]]);
    let upcount = u16::from_be_bytes([wire[8], wire[9]]);
    assert_eq!(zocount, 1, "zone section count");
    assert_eq!(prcount, 1, "prerequisite count");
    assert_eq!(upcount, 1, "update count");
}
```

Add tests for:
- Empty update (no prereqs, no updates)
- Multiple prerequisites
- Multiple update entries (add + delete)
- RDATA encoding for common types (A, AAAA, CNAME, MX)

- [ ] **Step 2: Run tests**

Run: `cargo test -p bind9-sdk-core`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-core/src/update.rs
git commit -m "test(core): update wire section counts and roundtrip (TEST-004)"
```

## Chunk 4: Net Crate — rndc Protocol Hardening (F-003, F-006, F-008, F-015, F-034, F-014)

Fix all rndc-related dialectic verify findings.

### Task 4.1: decode_map Depth Limit (F-003)

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/protocol.rs:167` (decode_map)

- [ ] **Step 1: Write failing test for recursive depth limit**

```rust
#[test]
fn decode_map_rejects_deep_nesting() {
    // Build a pathologically nested ISC message: 50 levels deep
    let mut wire = Vec::new();
    // Version header
    wire.extend_from_slice(&1u32.to_be_bytes());
    for _ in 0..50 {
        wire.push(1); // key length = 1
        wire.push(b'x'); // key = "x"
        wire.push(0x01); // type = map
        // We'll build a minimal nested structure
    }
    // This is simplified — actual test needs valid nested wire bytes
    let result = IscMessage::decode(&wire);
    assert!(result.is_err(), "Should reject deeply nested messages");
}
```

- [ ] **Step 2: Add depth parameter to decode_map**

Change `decode_map` signature to include a depth counter:

```rust
const MAX_DECODE_DEPTH: usize = 32;

fn decode_map(data: &[u8], pos: &mut usize, depth: usize) -> Result<BTreeMap<String, IscValue>, NetError> {
    if depth > MAX_DECODE_DEPTH {
        return Err(NetError::Protocol(
            "ISC message exceeds maximum nesting depth".into(),
        ));
    }
    // ... existing code ...
    // Recursive call passes depth + 1:
    IscValue::Map(Self::decode_map(data, &mut map_pos, depth + 1)?)
```

Update the call site in `decode()` to pass `0`:

```rust
let map = Self::decode_map(data, &mut pos, 0)?;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p bind9-sdk-net`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-net/src/rndc/protocol.rs
git commit -m "fix(net): add depth limit to ISC decode_map (F-003)"
```

### Task 4.2: encode_map Returns Result (F-006)

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/protocol.rs:130` (encode_map)

- [ ] **Step 1: Write failing test for long key**

```rust
#[test]
fn encode_map_rejects_long_key() {
    let mut msg = IscMessage::new();
    let long_key = "x".repeat(256);
    msg.insert_string(&long_key, "value");
    let result = msg.encode();
    assert!(result.is_err(), "Keys > 255 bytes should return Err");
}
```

- [ ] **Step 2: Change encode_map and encode to return Result**

Change `fn encode_map(...)` to `fn encode_map(...) -> Result<(), NetError>`.
Replace `expect()` calls with `?` returns.
Change `pub fn encode(&self) -> Vec<u8>` to `pub fn encode(&self) -> Result<Vec<u8>, NetError>`.

```rust
fn encode_map(map: &BTreeMap<String, IscValue>, buf: &mut Vec<u8>) -> Result<(), NetError> {
    for (key, value) in map {
        let key_bytes = key.as_bytes();
        let key_len = u8::try_from(key_bytes.len()).map_err(|_| {
            NetError::Protocol(format!("ISC message key too long: {} bytes", key_bytes.len()))
        })?;
        buf.push(key_len);
        buf.extend_from_slice(key_bytes);
        // ... rest with ? instead of expect ...
    }
    Ok(())
}
```

- [ ] **Step 3: Update all callers of encode()**

Search for `.encode()` calls — they now return `Result`. Add `?` at each call site.

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-net`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/rndc/
git commit -m "fix(net): encode_map returns Result instead of panicking (F-006)"
```

### Task 4.3: Fix reload_count Semantic Error (F-008)

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/command.rs:227-239` (parse_server_status)

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn parse_server_status_reload_count_not_zone_count() {
    let text = "version: BIND 9.20.0\n\
                boot time: Mon, 01 Jan 2026 00:00:00 GMT\n\
                number of zones: 42 (0 automatic)\n\
                server is up and running";
    let status = parse_server_status(text);
    // reload_count should NOT be 42 (that's zone count)
    assert_eq!(status.reload_count, 0, "reload_count should not come from zone count");
}
```

- [ ] **Step 2: Fix the parser — use the correct field**

BIND9 `rndc status` does not output a reload count directly. The field should parse from `"reloads since start:"` if present, or default to 0.

```rust
let reload_count = extract_field(text, "reloads since start:")
    .and_then(|s| s.trim().parse::<u32>().ok())
    .unwrap_or(0);
```

- [ ] **Step 3: Update any tests that relied on the old (wrong) behavior**

Search for tests that assert `reload_count` equals a zone count value and fix them.

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-net`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/rndc/command.rs
git commit -m "fix(net): parse reload_count from correct field (F-008)"
```

### Task 4.4: Replace contains("error") Heuristic (F-015)

**Files:**
- Modify: `crates/bind9-sdk-net/src/rndc/command.rs:188-205` (RndcResponse::from_text)

- [ ] **Step 1: Write failing test for false positive**

```rust
#[test]
fn from_text_zone_name_with_error_is_success() {
    // Zone name containing "error" should not be classified as error
    let response = RndcResponse::from_text("zone error-reporting.example.com/IN: loaded");
    assert!(response.is_success(), "Zone name containing 'error' should not be an error");
}
```

- [ ] **Step 2: Replace heuristic with structured parsing**

BIND9 rndc error responses follow specific patterns:
- Start with `"rndc: "` prefix
- ISC message contains `_result` field with non-zero value

Replace the broad `contains("error")` with specific checks:

```rust
pub(crate) fn from_text(text: &str) -> Self {
    let is_error = text.starts_with("rndc: ")
        || text.starts_with("error: ");

    if is_error {
        RndcResponse {
            text: text.to_string(),
            result: RndcResult::Error {
                code: 1,
                message: text.to_string(),
            },
        }
    } else {
        RndcResponse {
            text: text.to_string(),
            result: RndcResult::Success,
        }
    }
}
```

- [ ] **Step 3: Update existing tests for the new behavior**

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-net`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/rndc/command.rs
git commit -m "fix(net): replace contains(\"error\") heuristic with prefix check (F-015)"
```

### Task 4.5: Include Server Error Text in AuthFailed (F-034)

**Files:**
- Modify: `crates/bind9-sdk-net/src/error.rs:24-25` (NetError::AuthFailed)
- Modify: `crates/bind9-sdk-net/src/rndc/mod.rs:148-156` (authenticate)

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn auth_failed_includes_server_message() {
    let err = NetError::AuthFailed {
        server_message: Some("bad key name".into()),
    };
    assert!(err.to_string().contains("bad key name"));
}
```

- [ ] **Step 2: Change AuthFailed from unit variant to struct variant**

```rust
/// rndc HMAC authentication was rejected by the server.
#[error("rndc authentication failed{}", server_message.as_ref().map(|m| format!(": {m}")).unwrap_or_default())]
AuthFailed {
    /// Error text from the server, if available.
    server_message: Option<String>,
},
```

- [ ] **Step 3: Update authenticate() to include server error**

In `rndc/mod.rs`, change the auth failure path:

```rust
let err_text = response
    .get_string("_err")
    .or(response.get_string("result"))
    .map(String::from);
return Err(NetError::AuthFailed {
    server_message: err_text,
});
```

- [ ] **Step 4: Update all existing `NetError::AuthFailed` patterns**

Search for `NetError::AuthFailed` in tests and match arms — update to struct pattern:
- `NetError::AuthFailed` → `NetError::AuthFailed { .. }`
- Constructor: `NetError::AuthFailed` → `NetError::AuthFailed { server_message: None }`

- [ ] **Step 5: Run tests**

Run: `cargo test -p bind9-sdk-net`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-net/src/error.rs crates/bind9-sdk-net/src/rndc/mod.rs
git commit -m "fix(net): include server error text in AuthFailed (F-034)"
```

### Task 4.6: Add #[non_exhaustive] to Missing Types (F-014)

**Files:**
- Modify: `crates/bind9-sdk-net/src/config.rs:26` (ClientConfig)
- Modify: `crates/bind9-sdk-net/src/rndc/command.rs:155` (RndcResponse)
- Modify: `crates/bind9-sdk-net/src/rndc/command.rs:163` (RndcResult)

- [ ] **Step 1: Add the attribute to all three types**

```rust
// config.rs
#[non_exhaustive]
pub struct ClientConfig {

// command.rs
#[non_exhaustive]
pub struct RndcResponse {

// command.rs
#[non_exhaustive]
pub enum RndcResult {
```

- [ ] **Step 2: Add constructors where needed**

`ClientConfig` needs a `new()` constructor since external code can no longer use struct literal syntax. `RndcResponse` is `pub(crate)` constructed — verify no external struct literals exist.

- [ ] **Step 3: Run workspace tests**

Run: `cargo test --workspace`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-net/src/config.rs crates/bind9-sdk-net/src/rndc/command.rs
git commit -m "fix(net): add #[non_exhaustive] to ClientConfig, RndcResponse, RndcResult (F-014)"
```

## Chunk 5: Net Crate — Config & Transport Fixes (F-013, F-035, F-009, F-010/F-011/F-012)

### Task 5.1: IPv6-Aware UDP Bind in NsUpdateSender (F-013)

**Files:**
- Modify: `crates/bind9-sdk-net/src/nsupdate.rs:111`

- [ ] **Step 1: Write test documenting the fix**

```rust
#[tokio::test]
async fn send_udp_uses_matching_bind_address() {
    // Verify that IPv6 targets use [::]:0, not 0.0.0.0:0
    let ipv6_addr: SocketAddr = "[::1]:53".parse().unwrap();
    let sender = NsUpdateSender::new(ipv6_addr, Duration::from_secs(5));
    // The bind address selection is internal, so test indirectly
    // by verifying the sender can be created with IPv6 target
    assert!(sender.server.is_ipv6());
}
```

- [ ] **Step 2: Fix bind address to match target IP version**

```rust
async fn send_udp(&self, wire: &[u8]) -> Result<Vec<u8>, NetError> {
    let bind_addr = if self.server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| NetError::Connection(format!("failed to bind UDP socket: {e}")))?;
    // ... rest unchanged
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p bind9-sdk-net`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-net/src/nsupdate.rs
git commit -m "fix(net): detect IPv4/IPv6 for UDP bind in nsupdate (F-013)"
```

### Task 5.2: ServerStats Option Fields (F-035)

**Files:**
- Modify: `crates/bind9-sdk-core/src/traits.rs:82-91` (ServerStats)
- Modify: `crates/bind9-sdk-net/src/stats.rs:44-53` (From impl)

- [ ] **Step 1: Change ServerStats fields to Option<String>**

```rust
pub struct ServerStats {
    pub boot_time: Option<String>,
    pub config_time: Option<String>,
    pub current_time: Option<String>,
    pub version: Option<String>,
}
```

Update `ServerStats::new()` to take `Option<String>` params.

- [ ] **Step 2: Update From<RawServerStats> to pass through Options**

```rust
impl From<RawServerStats> for ServerStats {
    fn from(raw: RawServerStats) -> Self {
        ServerStats::new(raw.boot_time, raw.config_time, raw.current_time, raw.version)
    }
}
```

- [ ] **Step 3: Fix all compile errors across workspace**

Update mock implementations in `traits.rs` tests and any other references.

- [ ] **Step 4: Run tests**

Run: `cargo test --workspace`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/traits.rs crates/bind9-sdk-net/src/stats.rs
git commit -m "fix(core): ServerStats uses Option<String> for missing fields (F-035)"
```

### Task 5.3: ZoneStats record_count → Option<u32> (F-009)

**Files:**
- Modify: `crates/bind9-sdk-core/src/traits.rs:106` (ZoneStats)
- Modify: `crates/bind9-sdk-net/src/stats.rs:82` (zone_stats_from_raw)

- [ ] **Step 1: Change field type**

```rust
pub struct ZoneStats {
    // ...
    /// Number of resource records in the zone, if available from the API.
    /// BIND9 statistics JSON does not expose this; will be `None` for stats-channel data.
    pub record_count: Option<u32>,
    // ...
}
```

- [ ] **Step 2: Update zone_stats_from_raw to pass None**

```rust
Ok(ZoneStats::new(name, class, serial, None, zone_type))
```

- [ ] **Step 3: Fix all compile errors**

Update `ZoneStats::new()` signature and mock tests.

- [ ] **Step 4: Run tests**

Run: `cargo test --workspace`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/traits.rs crates/bind9-sdk-net/src/stats.rs
git commit -m "fix(core): ZoneStats record_count is Option<u32> (F-009)"
```

### Task 5.4: Config Contract Alignment (F-010/F-011/F-012)

**Files:**
- Modify: `crates/bind9-sdk-net/src/stats.rs:88-95` (StatsHttpClient::new)
- Modify: `crates/bind9-sdk-net/src/config.rs` (Bind9Client trait impls)

- [ ] **Step 1: Pass timeout from ClientConfig to StatsHttpClient**

In `StatsHttpClient::new()`, accept a timeout parameter instead of hardcoding 10s:

```rust
pub fn new(base_url: &str, timeout: Duration) -> Result<Self, NetError> {
    let http = reqwest::Client::builder()
        .timeout(timeout)
        // ...
```

Update the constructor call in `config.rs` to pass `self.config.timeout`.

- [ ] **Step 2: Document that `tls` field is reserved for future use**

Add doc comment to `ClientConfig.tls`:

```rust
/// Optional TLS configuration for encrypted connections.
///
/// **Note:** Currently unused. Reserved for future TLS-encrypted rndc
/// and statistics-channel connections. See roadmap for TLS support timeline.
pub tls: Option<TlsConfig>,
```

- [ ] **Step 3: Normalize stats URL handling**

Ensure `StatsHttpClient` strips trailing slashes from the base URL:

```rust
pub fn new(base_url: &str, timeout: Duration) -> Result<Self, NetError> {
    let url = base_url.trim_end_matches('/').to_string();
    // ...
```

- [ ] **Step 4: Run tests**

Run: `cargo test --workspace`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/stats.rs crates/bind9-sdk-net/src/config.rs
git commit -m "fix(net): align timeout/TLS/URL config contracts (F-010/F-011/F-012)"
```

## Chunk 6: Net Crate — NsUpdate TSIG Response Verification (F-036/TSIG-002)

Wire the TSIG response verification from Chunk 2 into the nsupdate sender.

### Task 6.1: Add TSIG Verification to NsUpdateSender

**Files:**
- Modify: `crates/bind9-sdk-net/src/nsupdate.rs`

- [ ] **Step 1: Write test for TSIG response verification path**

This is best tested as an integration test since it requires DNS wire format manipulation. Add a unit test that verifies the verification logic is called:

```rust
#[test]
fn parse_dns_response_extracts_tsig() {
    // Build a minimal DNS response with a TSIG record in additional section
    // Verify that parse_dns_response returns the TSIG for verification
}
```

- [ ] **Step 2: Modify parse_dns_response to extract TSIG**

The current `parse_dns_response` only checks RCODE. Extend it to:
1. Check ARCOUNT for a TSIG record (TYPE 250) in the additional section
2. If present, parse it with `TsigRecord::parse_from_wire`
3. Return it alongside the UpdateResult

- [ ] **Step 3: Add TSIG verification in send() method**

After receiving and parsing the DNS response, if the request was signed and the response contains a TSIG:

```rust
// If we sent a signed update, verify the response TSIG
if let (Some(request_tsig), Some(response_tsig)) = (&request_tsig_mac, &parsed_response_tsig) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    TsigRecord::verify_response(
        key,
        &response_wire_sans_tsig,
        response_tsig,
        request_tsig,
        now,
    )
    .map_err(|e| NetError::Core(e))?;
}
```

- [ ] **Step 4: Update DynamicUpdater trait impl to pass TSIG context**

The `Bind9Client::send_update()` in `config.rs` needs to pass the TsigKey to `NsUpdateSender` so it can verify the response.

- [ ] **Step 5: Run tests**

Run: `cargo test --workspace`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-net/src/nsupdate.rs crates/bind9-sdk-net/src/config.rs
git commit -m "feat(net): verify TSIG on DNS update responses (F-036/TSIG-002)"
```

### Task 6.2: Final Workspace Validation

- [ ] **Step 1: Run full test suite**

```bash
cargo test --workspace
```

- [ ] **Step 2: Run clippy**

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 3: Run WASM check on core**

```bash
cargo check -p bind9-sdk-core --target wasm32-unknown-unknown
```

- [ ] **Step 4: Run format check**

```bash
cargo fmt --check
```

- [ ] **Step 5: Commit any final fixes and tag**

```bash
git add -A
git commit -m "chore: final WT-5 cleanup and validation"
```
