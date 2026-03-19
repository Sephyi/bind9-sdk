<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

# Post-WT-5 Hardening + E2E Infrastructure Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix dialectic verify WARNs, clean up stale TODOs, wire up integration tests, and provision BIND9 e2e test infrastructure — all parallelized where dependencies allow.

**Architecture:** Four parallel work streams converge into a single branch. Stream A (core TSIG hardening) and Stream B (core update hardening) touch independent files in `bind9-sdk-core`. Stream C (net layer fixes) depends on A completing first (needs new `TsigRecord` fields). Stream D (e2e infrastructure) is fully independent. All streams merge to `development` at the end.

**Tech Stack:** Rust 1.94, tokio, zeroize, Podman (for BIND9 9.20 container)

**Branch:** `feat/post-wt5-hardening`

**Pre-conditions:**
- `development` at `6e58f75` with 398 tests passing
- WT-5 merged, F-004 CRITICAL fixed
- `TsigKey::from_base64()` already exists in `tsig.rs:120-136`

## Parallelization Map

```txt
               ┌─────────────────┐
               │  Create worktree │
               └────────┬────────┘
        ┌───────────────┼───────────────┬──────────────────┐
        ▼               ▼               ▼                  ▼
   ┌─────────┐    ┌─────────┐    ┌─────────────┐    ┌───────────┐
   │ Stream A │    │ Stream B │    │  Stream D   │    │  Task 1   │
   │ TSIG     │    │ Update   │    │  E2E Infra  │    │  Cleanup  │
   │ Harden   │    │ Harden   │    │  (Podman)   │    │  (TODOs)  │
   └────┬─────┘    └────┬─────┘    └──────┬──────┘    └─────┬─────┘
        │               │                │                  │
        ▼               │                │                  │
   ┌─────────┐          │                │                  │
   │ Stream C │◀─────────┘                │                  │
   │ Net fixes│                           │                  │
   └────┬─────┘                           │                  │
        │               ┌────────────────┘                  │
        ▼               ▼                                   │
   ┌─────────────────────────┐                              │
   │  Integration test wiring │◀────────────────────────────┘
   └────────────┬────────────┘
                ▼
        ┌──────────────┐
        │  Final verify │
        └──────────────┘
```

**Parallel batches:**
- **Batch 1** (fully parallel): Task 1 + Stream A + Stream B + Stream D
- **Batch 2** (after A+B): Stream C
- **Batch 3** (after all): Integration test wiring + final verify

## Chunk 1: Cleanup + TSIG Hardening (Batch 1, parallel)

### Task 1: Stale TODO cleanup

**Files:**
- Modify: `crates/bind9-sdk-net/src/nsupdate.rs:688-697`
- Modify: `crates/bind9-sdk-net/tests/rndc_integration.rs:29-33,79-84`

This task removes 3 `todo!()` macros that reference "WT-2" (completed in Wave 1) and wires up the now-available `TsigKey::from_base64()`.

- [ ] **Step 1: Fix `test_key()` in rndc_integration.rs**

Replace the `todo!()` with a real `TsigKey::from_base64()` call:

```rust
fn test_key() -> bind9_sdk_core::tsig::TsigKey {
    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::tsig::TsigAlgorithm;

    bind9_sdk_core::tsig::TsigKey::from_base64(
        DomainName::new("rndc-test-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        "dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==",
    )
    .expect("test key must be valid")
}
```

- [ ] **Step 2: Wire up `rndc_wrong_key_fails_auth` test body**

Replace the commented-out body at lines 78-85:

```rust
#[tokio::test]
#[ignore = "requires live BIND9 on localhost:953"]
async fn rndc_wrong_key_fails_auth() {
    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::tsig::TsigAlgorithm;

    let addr: std::net::SocketAddr = "127.0.0.1:953".parse().unwrap();
    let wrong_key = bind9_sdk_core::tsig::TsigKey::new(
        DomainName::new("wrong-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        vec![0xBA; 32],
    )
    .unwrap();
    let conn = bind9_sdk_net::rndc::RndcConnection::connect(addr)
        .await
        .unwrap();
    let result = conn.authenticate(&wrong_key).await;
    assert!(result.is_err(), "wrong key should fail authentication");
}
```

- [ ] **Step 3: Fix nsupdate integration test stubs**

Replace `todo!()` at lines 688-697 with real test bodies using `UpdateBuilder`:

```rust
#[tokio::test]
#[ignore = "requires live BIND9 accepting dynamic updates on localhost:53"]
async fn integration_send_update_to_live_bind9() {
    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::protocol::RecordType;
    use bind9_sdk_core::record::{RecordClass, RecordData, ResourceRecord, Ttl};
    use bind9_sdk_core::tsig::TsigAlgorithm;
    use bind9_sdk_core::update::UpdateBuilder;

    let zone = DomainName::new("example.com.").unwrap();
    let key = bind9_sdk_core::tsig::TsigKey::from_base64(
        DomainName::new("rndc-test-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        "dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==",
    )
    .unwrap();

    let rr = ResourceRecord::new(
        DomainName::new("test.example.com.").unwrap(),
        RecordType::A,
        RecordClass::IN,
        Ttl::new(300),
        RecordData::A([192, 0, 2, 1].into()),
    );

    let builder = UpdateBuilder::new(zone)
        .add(rr)
        .sign(&key);
    let msg = builder.build();

    let sender = NsUpdateSender::new("127.0.0.1:53".parse().unwrap());
    let result = sender.send(&msg, Some(&key)).await;
    assert!(result.is_ok(), "dynamic update should succeed: {:?}", result.err());
}

#[tokio::test]
#[ignore = "requires live BIND9 — tests TCP fallback with large update"]
async fn integration_tcp_fallback_with_large_update() {
    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::protocol::RecordType;
    use bind9_sdk_core::record::{RecordClass, RecordData, ResourceRecord, Ttl};
    use bind9_sdk_core::tsig::TsigAlgorithm;
    use bind9_sdk_core::update::UpdateBuilder;

    let zone = DomainName::new("example.com.").unwrap();
    let key = bind9_sdk_core::tsig::TsigKey::from_base64(
        DomainName::new("rndc-test-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        "dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==",
    )
    .unwrap();

    // Add enough records to exceed UDP 512-byte limit
    let mut builder = UpdateBuilder::new(zone);
    for i in 0..50 {
        let name = DomainName::new(&format!("host{i}.example.com.")).unwrap();
        let rr = ResourceRecord::new(
            name,
            RecordType::A,
            RecordClass::IN,
            Ttl::new(300),
            RecordData::A([192, 0, 2, (i as u8) + 1].into()),
        );
        builder = builder.add(rr);
    }
    let msg = builder.sign(&key).build();

    let sender = NsUpdateSender::new("127.0.0.1:53".parse().unwrap());
    let result = sender.send(&msg, Some(&key)).await;
    assert!(result.is_ok(), "TCP fallback should succeed: {:?}", result.err());
}
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p bind9-sdk-net --tests`
Expected: compiles with no errors (tests are `#[ignore]` so they won't execute)

- [ ] **Step 5: Run unit tests**

Run: `cargo test -p bind9-sdk-net --lib`
Expected: 145 passed, 4 ignored

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-net/src/nsupdate.rs crates/bind9-sdk-net/tests/rndc_integration.rs
git commit -m "chore(net): replace stale WT-2 todo!() stubs with real test bodies"
```

### Task 2: TsigRecord — parse error/other_len/other_data fields (Stream A, F-007)

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs:245-262,500-517`

The TSIG parser currently stops after `original_id` (line 505). Per RFC 8945, the RDATA also contains `error` (u16), `other_len` (u16), and `other_data` (variable). These are needed for BADTIME response handling (F-008).

- [ ] **Step 1: Write failing test for error/other_len parsing**

Add to the existing TSIG tests in `tsig.rs`:

```rust
#[test]
fn parse_from_wire_extracts_error_and_other_fields() {
    let key = test_key();
    let msg = b"test message";
    let timestamp = 1710000000u64;
    let tsig = TsigRecord::new(&key, msg, timestamp, None);

    // Round-trip through wire format
    let parsed = TsigRecord::parse_from_wire(&tsig.wire_bytes).unwrap();
    assert_eq!(parsed.error, 0);
    assert_eq!(parsed.other_data.len(), 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p bind9-sdk-core parse_from_wire_extracts_error`
Expected: FAIL — `TsigRecord` has no field `error`

- [ ] **Step 3: Add `error` and `other_data` fields to `TsigRecord`**

Modify the struct at line 245:

```rust
pub struct TsigRecord {
    /// The TSIG key name.
    pub key_name: DomainName,
    /// The algorithm used.
    pub algorithm: TsigAlgorithm,
    /// The time the message was signed (seconds since Unix epoch).
    pub time_signed: u64,
    /// Clock skew tolerance in seconds (default: 300).
    pub fudge: u16,
    /// The computed HMAC (message authentication code).
    /// Wrapped in `Zeroizing` to clear on drop.
    pub mac: Zeroizing<Vec<u8>>,
    /// The original DNS message ID.
    pub original_id: u16,
    /// TSIG error code (0 = NOERROR, 18 = BADTIME).
    pub error: u16,
    /// Additional data (used for BADTIME: server's current time as 48-bit).
    pub other_data: Vec<u8>,
    /// The complete TSIG record in wire format, ready to append to a DNS message.
    /// Wrapped in `Zeroizing` to clear on drop.
    pub wire_bytes: Zeroizing<Vec<u8>>,
}
```

- [ ] **Step 4: Update `TsigRecord::new()` to set error/other_data**

In `new()` (around line 393), add the new fields:

```rust
TsigRecord {
    key_name: key.name.clone(),
    algorithm: key.algorithm,
    time_signed: timestamp,
    fudge,
    mac: Zeroizing::new(mac),
    original_id,
    error,
    other_data: Vec::new(),
    wire_bytes: Zeroizing::new(wire),
}
```

- [ ] **Step 5: Update Debug impl to include error field**

At line 264, add `error` and `other_data` (not redacted — these are not secrets):

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
            .field("error", &self.error)
            .field("other_data_len", &self.other_data.len())
            .field("wire_bytes", &"[REDACTED]")
            .finish()
    }
}
```

- [ ] **Step 6: Update `parse_from_wire()` to parse remaining fields**

Replace lines 505-517:

```rust
let original_id = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
pos += 2;

// RDATA: Error (16-bit)
if pos + 2 > wire.len() {
    return Err(CoreError::Tsig("truncated TSIG error".into()));
}
let error = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
pos += 2;

// RDATA: Other length (16-bit)
if pos + 2 > wire.len() {
    return Err(CoreError::Tsig("truncated TSIG other_len".into()));
}
let other_len = u16::from_be_bytes([wire[pos], wire[pos + 1]]) as usize;
pos += 2;

// RDATA: Other data
if pos + other_len > wire.len() {
    return Err(CoreError::Tsig("truncated TSIG other_data".into()));
}
let other_data = wire[pos..pos + other_len].to_vec();

Ok(TsigRecord {
    key_name,
    algorithm,
    time_signed,
    fudge,
    mac: Zeroizing::new(mac),
    original_id,
    error,
    other_data,
    wire_bytes: Zeroizing::new(wire.to_vec()),
})
```

- [ ] **Step 7: Update `verify_response()` to use parsed error/other_data (F-008)**

Replace the hardcoded zeros at lines 576-580:

```rust
// Error: 16-bit (from parsed response TSIG)
tsig_vars.extend_from_slice(&response_tsig.error.to_be_bytes());

// Other length + other data (from parsed response TSIG)
tsig_vars.extend_from_slice(&(response_tsig.other_data.len() as u16).to_be_bytes());
tsig_vars.extend_from_slice(&response_tsig.other_data);
```

- [ ] **Step 8: Add TTL validation in parser (F-019)**

After line 444 (`pos += 4; // skip TTL`), add validation:

```rust
// TTL (must be 0 per RFC 8945)
if pos + 4 > wire.len() {
    return Err(CoreError::Tsig("truncated TSIG TTL".into()));
}
let ttl = u32::from_be_bytes([wire[pos], wire[pos + 1], wire[pos + 2], wire[pos + 3]]);
if ttl != 0 {
    return Err(CoreError::Tsig(alloc::format!(
        "TSIG TTL must be 0, got {ttl}"
    )));
}
pos += 4;
```

- [ ] **Step 9: Write test for TTL validation**

```rust
#[test]
fn parse_from_wire_rejects_nonzero_ttl() {
    let key = test_key();
    let tsig = TsigRecord::new(&key, b"msg", 1710000000, None);
    let mut bad_wire = tsig.wire_bytes.to_vec();
    // Find TTL field (after name + TYPE(2) + CLASS(2)) and set non-zero
    // The TTL is 4 bytes starting after TYPE+CLASS
    let mut pos = 0;
    // Skip name
    loop {
        let len = bad_wire[pos] as usize;
        if len == 0 { pos += 1; break; }
        pos += 1 + len;
    }
    pos += 4; // TYPE + CLASS
    // Set TTL to 1
    bad_wire[pos..pos + 4].copy_from_slice(&1u32.to_be_bytes());
    assert!(TsigRecord::parse_from_wire(&bad_wire).is_err());
}
```

- [ ] **Step 10: Run tests**

Run: `cargo test -p bind9-sdk-core`
Expected: all tests pass (including the 2 new ones)

- [ ] **Step 11: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): parse TSIG error/other_data fields, validate TTL=0 (F-007/F-008/F-019)"
```

### Task 3: Zeroize request_mac + validate non-empty RrsetExistsWithData (Stream B, F-006/F-009)

**Files:**
- Modify: `crates/bind9-sdk-core/src/update.rs:5,288,245,266,309-310,379,713`

- [ ] **Step 1: Write failing test for empty RrsetExistsWithData**

Add to the existing update tests:

```rust
#[test]
fn rrset_exists_with_data_rejects_empty_records() {
    use crate::update::Prerequisite;
    let name = DomainName::new("example.com.").unwrap();
    let prereq = Prerequisite::RrsetExistsWithData {
        name,
        rtype: RecordType::A,
        records: vec![],
    };
    // wire_rr_count should never be 0 for this variant
    assert!(prereq.wire_rr_count() > 0 || true); // placeholder — actual fix is in UpdateBuilder
}
```

Actually, the validation belongs in `UpdateBuilder::prerequisite()`. Write the test there:

```rust
#[test]
#[should_panic(expected = "empty")]
fn prerequisite_rejects_empty_rrset_exists_with_data() {
    let zone = DomainName::new("example.com.").unwrap();
    let prereq = Prerequisite::RrsetExistsWithData {
        name: DomainName::new("test.example.com.").unwrap(),
        rtype: RecordType::A,
        records: vec![],
    };
    // This should fail — an empty RrsetExistsWithData is nonsensical
    let _builder = UpdateBuilder::new(zone).prerequisite(prereq);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p bind9-sdk-core prerequisite_rejects_empty`
Expected: FAIL — no panic occurs, test fails

- [ ] **Step 3: Add validation in UpdateBuilder::prerequisite()**

Find the `prerequisite()` method and add:

```rust
pub fn prerequisite(mut self, prereq: Prerequisite) -> Self {
    if let Prerequisite::RrsetExistsWithData { records, .. } = &prereq {
        assert!(!records.is_empty(), "RrsetExistsWithData must have non-empty records");
    }
    self.prerequisites.push(prereq);
    self
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p bind9-sdk-core prerequisite_rejects_empty`
Expected: PASS

- [ ] **Step 5: Change `request_mac` from `Vec<u8>` to `Zeroizing<Vec<u8>>`**

In `update.rs`, add `use zeroize::Zeroizing;` to imports (line 5 area), then change line 288:

```rust
pub(crate) request_mac: Option<Zeroizing<Vec<u8>>>,
```

Update the accessor at line 309:

```rust
pub fn request_mac(&self) -> Option<&[u8]> {
    self.request_mac.as_deref()
}
```

Update `sign_inner()` where `request_mac` is set (line 245 area):

```rust
request_mac: Some(Zeroizing::new(request_mac)),
```

Update `encode_update_message()` where `request_mac` is `None` (line 379 area):

```rust
request_mac: None,
```

Update any test that constructs `UpdateMessage` directly with `request_mac: None` (line 713 area):

```rust
request_mac: None,
```

- [ ] **Step 6: Run all core tests**

Run: `cargo test -p bind9-sdk-core`
Expected: all pass

- [ ] **Step 7: Run net tests (they use `request_mac()` accessor)**

Run: `cargo test -p bind9-sdk-net --lib`
Expected: all pass — the accessor signature is unchanged

- [ ] **Step 8: Commit**

```bash
git add crates/bind9-sdk-core/src/update.rs
git commit -m "fix(core): zeroize request_mac, reject empty RrsetExistsWithData (F-006/F-009)"
```

## Chunk 2: Net Layer Fixes + E2E Infrastructure (Batch 1-2)

### Task 4: Wrap rndc operations with timeout (Stream C, F-010)

**Files:**
- Modify: `crates/bind9-sdk-net/src/config.rs:90-99`

**Depends on:** None (independent of core changes)

- [ ] **Step 1: Write test for rndc timeout**

Add to the config tests in `config.rs`:

```rust
#[tokio::test]
async fn rndc_command_times_out_with_unreachable_host() {
    let config = ClientConfig {
        rndc_addr: "192.0.2.1:953".parse().unwrap(), // RFC 5737 TEST-NET — unreachable
        rndc_key: test_key(),
        stats_url: None,
        dns_addr: None,
        tls: None,
        timeout: Duration::from_millis(100), // Very short timeout
    };
    let client = Bind9Client::new(config);

    let start = std::time::Instant::now();
    let result = client.status().await;
    let elapsed = start.elapsed();

    assert!(result.is_err(), "should fail with unreachable host");
    // Should complete within ~200ms (100ms timeout + overhead), not hang
    assert!(
        elapsed < Duration::from_secs(2),
        "should have timed out quickly, took {:?}",
        elapsed
    );
}
```

- [ ] **Step 2: Run test**

Run: `cargo test -p bind9-sdk-net rndc_command_times_out`
Expected: FAIL — test hangs or takes much longer than 2 seconds

- [ ] **Step 3: Add timeout wrapper to rndc_command()**

Modify `rndc_command()` in `config.rs:90-99`:

```rust
async fn rndc_command(
    &self,
    cmd: RndcCommand,
) -> Result<crate::rndc::command::RndcResponse, NetError> {
    let timeout = self.config.timeout;
    let fut = async {
        let conn = RndcConnection::connect(self.config.rndc_addr).await?;
        let mut conn = conn.authenticate(&self.config.rndc_key).await?;
        let resp = conn.command(cmd).await?;
        conn.close().await?;
        Ok(resp)
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| NetError::Timeout(timeout))?
}
```

- [ ] **Step 4: Run test**

Run: `cargo test -p bind9-sdk-net rndc_command_times_out`
Expected: PASS — completes within ~200ms

- [ ] **Step 5: Run all net tests**

Run: `cargo test -p bind9-sdk-net --lib`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-net/src/config.rs
git commit -m "fix(net): wrap rndc operations with ClientConfig.timeout (F-010)"
```

### Task 5: TSIG error RCODE check + response ID matching (Stream C, F-012/F-020)

**Files:**
- Modify: `crates/bind9-sdk-net/src/nsupdate.rs:213-251`

**Depends on:** Task 2 (needs `error` field on `TsigRecord`)

- [ ] **Step 1: Write test for response ID mismatch detection**

```rust
#[test]
fn parse_dns_response_returns_id() {
    let response = [
        0x12, 0x34, // ID = 0x1234
        0x85, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let result = parse_dns_response(&response).unwrap();
    assert_eq!(result.id, 0x1234);
}
```

This test already exists. The actual fix is adding ID matching in `send()`.

- [ ] **Step 2: Add response ID validation in `send()`**

After `let result = parse_dns_response(&response)?;` at line 211, add:

```rust
// Verify response ID matches request (RFC 1035 §4.1.1)
if result.id != update.id() {
    return Err(NetError::Protocol(format!(
        "response ID {} does not match request ID {}",
        result.id,
        update.id()
    )));
}
```

- [ ] **Step 3: Add TSIG error RCODE check before MAC chaining (F-012)**

In the TSIG verification block (after parsing response_tsig, before verify_response), add:

```rust
// Per RFC 8945 §5.2: check TSIG error before using MAC for chaining
if response_tsig.error != 0 {
    return Err(NetError::Protocol(format!(
        "response TSIG error: {}",
        response_tsig.error
    )));
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-net --lib`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/nsupdate.rs
git commit -m "fix(net): validate response ID, check TSIG error RCODE (F-012/F-020)"
```

### Task 6: E2E test infrastructure — Podman + BIND9 9.20 (Stream D)

**Files:**
- Create: `tests/bind9/docker-compose.yml`
- Create: `tests/bind9/named.conf`
- Create: `tests/bind9/zones/example.com.zone`
- Create: `tests/bind9/Dockerfile`
- Create: `tests/README.md`

**Depends on:** Nothing — fully independent, can run in parallel with all other tasks.

- [ ] **Step 1: Create tests directory structure**

```bash
mkdir -p tests/bind9/zones
```

- [ ] **Step 2: Create the BIND9 Dockerfile**

`tests/bind9/Dockerfile`:

```dockerfile
# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y bind9 bind9-utils && rm -rf /var/lib/apt/lists/*
COPY named.conf /etc/bind/named.conf
COPY zones/ /var/lib/bind/
RUN chown -R bind:bind /var/lib/bind
EXPOSE 53/udp 53/tcp 953/tcp 8053/tcp
CMD ["/usr/sbin/named", "-g", "-c", "/etc/bind/named.conf", "-u", "bind"]
```

- [ ] **Step 3: Create named.conf**

`tests/bind9/named.conf`:

```conf
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// Test BIND9 configuration for bind9-sdk integration tests.

key "rndc-test-key" {
    algorithm hmac-sha256;
    secret "dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==";
};

controls {
    inet 0.0.0.0 port 953 allow { any; } keys { "rndc-test-key"; };
};

statistics-channels {
    inet 0.0.0.0 port 8053 allow { any; };
};

options {
    directory "/var/lib/bind";
    listen-on { any; };
    listen-on-v6 { any; };
    allow-query { any; };
    dnssec-validation no;
};

zone "example.com" {
    type primary;
    file "example.com.zone";
    allow-update { key "rndc-test-key"; };
};
```

- [ ] **Step 4: Create zone file**

`tests/bind9/zones/example.com.zone`:

```zone
; SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
; SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

$TTL 3600
@   IN  SOA ns1.example.com. admin.example.com. (
        2026031601  ; serial
        3600        ; refresh
        900         ; retry
        604800      ; expire
        86400       ; minimum
    )
    IN  NS  ns1.example.com.
ns1 IN  A   127.0.0.1
```

- [ ] **Step 5: Create docker-compose.yml**

`tests/bind9/docker-compose.yml`:

```yaml
# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

services:
  bind9:
    build: .
    ports:
      - "127.0.0.1:53:53/udp"
      - "127.0.0.1:53:53/tcp"
      - "127.0.0.1:953:953/tcp"
      - "127.0.0.1:8053:8053/tcp"
    healthcheck:
      test: ["CMD", "rndc", "-s", "127.0.0.1", "-p", "953", "-k", "/etc/bind/rndc.key", "status"]
      interval: 2s
      timeout: 5s
      retries: 10
```

- [ ] **Step 6: Create tests/README.md**

`tests/README.md`:

```markdown
<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

# Integration Tests

## Prerequisites

- Podman or Docker with compose support

## Quick Start

```bash
# Start BIND9 test instance
cd tests/bind9
podman-compose up -d
# or: docker compose up -d

# Wait for BIND9 to be ready
sleep 3

# Run integration tests
cargo test --workspace -- --ignored

# Stop BIND9
podman-compose down
```

## Test Key

The test BIND9 instance uses this rndc key:

- **Name**: `rndc-test-key`
- **Algorithm**: hmac-sha256
- **Secret** (base64): `dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==`

This key is hardcoded in tests and in `tests/bind9/named.conf`.

## Ports

| Port | Protocol | Service |
| --- | --- | --- |
| 53 | UDP/TCP | DNS (accepts dynamic updates for example.com) |
| 953 | TCP | rndc control channel |
| 8053 | TCP | statistics-channel (JSON API at /json/v1/) |

## CI

The GitHub Actions workflow starts this container automatically before
running `cargo test --workspace -- --ignored`.
```

- [ ] **Step 7: Test the container builds**

Run: `cd tests/bind9 && podman build -t bind9-sdk-test .`
Expected: builds successfully

- [ ] **Step 8: Commit**

```bash
git add tests/
git commit -m "feat(test): add BIND9 9.20 Podman container for e2e tests"
```

## Chunk 3: Final Verification + PRD Fix

### Task 7: Fix stale PRD status line

**Files:**
- Modify: `PRD.md:12`

- [ ] **Step 1: Fix the status line**

Line 12 currently says "WT-3 + WT-4 in progress" but all worktrees are complete. Change to:

```markdown
**Status**: In Progress — Phase 1a complete, Phase 1b Wave 2 complete (WT-3 + WT-4 + WT-5 merged), preparing Phase 2
```

- [ ] **Step 2: Commit**

```bash
git add PRD.md
git commit -m "docs(prd): fix status line — Wave 2 fully complete"
```

### Task 8: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test --workspace`
Expected: 398+ tests pass (new tests from Tasks 1-5 add to the count)

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings

- [ ] **Step 3: Run WASM check**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: passes (zeroize is no_std compatible)

- [ ] **Step 4: Run format check**

Run: `cargo fmt --check`
Expected: no formatting issues

- [ ] **Step 5: Verify integration test compilation**

Run: `cargo test -p bind9-sdk-net -- --ignored --list`
Expected: lists all 9+ ignored integration tests without compilation errors

- [ ] **Step 6: Commit any final fixes, then use `finishing-a-development-branch` skill**
