<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
-->

# Phase 1 Pre-Worktree Scaffolding Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Set up module stubs, dependencies, and migrate placeholder types on `development` so that all 4 worktree branches start from a clean, conflict-free base.

**Architecture:** This plan modifies the `development` branch directly (no worktree). It adds workspace dependencies, creates empty module files, migrates placeholder unit structs from `traits.rs` to their target modules with real fields, and adds `protocol.rs` with shared DNS enums. All worktree plans depend on this completing first.

**Tech Stack:** Rust 2024, `no_std` + `alloc` for core, workspace dependency management

**Spec:** `docs/specs/2026-03-14-phase1-remainder-design.md` §7.3

## Chunk 1: Dependencies and Module Structure

### Task 1: Add Workspace Dependencies

**Files:**
- Modify: `Cargo.toml` (workspace root, lines 22-56)

- [ ] **Step 1: Add new workspace dependencies**

Add these entries to the `[workspace.dependencies]` section in `Cargo.toml`:

```toml
# Base64 encoding for TSIG keys — no_std compatible
base64 = { version = "0.22", default-features = false, features = ["alloc"] }

# Random bytes for key generation — std only (not compiled for WASM)
getrandom = { version = "0.3", default-features = false }

# HMAC-SHA1 for legacy BIND9 compatibility — no_std compatible
sha1 = { version = "0.10", default-features = false }

# TLS 1.3 client
rustls = { version = "0.23", default-features = false, features = ["ring", "tls12"] }

# Mozilla CA root certificates
webpki-roots = { version = "1" }

# Tokio rustls integration
tokio-rustls = { version = "0.26" }
```

- [ ] **Step 2: Run cargo check to verify workspace deps resolve**

Run: `cargo check --workspace 2>&1 | head -20`
Expected: Compiles successfully (new deps are declared but not yet used)

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build: add workspace deps for Phase 1 remainder (base64, getrandom, sha1, rustls, webpki-roots)"
```

### Task 2: Add Crate-Level Dependencies

**Files:**
- Modify: `crates/bind9-sdk-core/Cargo.toml`
- Modify: `crates/bind9-sdk-net/Cargo.toml`

- [ ] **Step 1: Add dependencies to bind9-sdk-core**

Add to `[dependencies]` in `crates/bind9-sdk-core/Cargo.toml`:

```toml
base64 = { workspace = true }
sha1 = { workspace = true }
getrandom = { workspace = true, features = ["std"], optional = true }
```

Update the `std` feature to include getrandom:

```toml
[features]
default = []
std = ["thiserror/std", "serde?/std", "dep:getrandom"]
serde = ["dep:serde"]
parallel = ["std", "dep:rayon"]
```

- [ ] **Step 2: Add dependencies to bind9-sdk-net**

Add to `[dependencies]` in `crates/bind9-sdk-net/Cargo.toml`:

```toml
rustls = { workspace = true }
webpki-roots = { workspace = true }
tokio-rustls = { workspace = true }
serde = { workspace = true }
```

- [ ] **Step 3: Run cargo check for both targets**

Run: `cargo check --workspace && cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Both pass

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-core/Cargo.toml crates/bind9-sdk-net/Cargo.toml Cargo.lock
git commit -m "build: add crate-level deps for TSIG, TLS, base64"
```

### Task 3: Create protocol.rs (RecordType + Rcode)

**Files:**
- Create: `crates/bind9-sdk-core/src/protocol.rs`

- [ ] **Step 1: Write tests for RecordType**

Create `crates/bind9-sdk-core/src/protocol.rs` with tests first (the implementations will follow):

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use core::fmt;

/// DNS record type codes (RFC 1035 §3.2.2 and IANA registry).
///
/// Used by `UpdateBuilder` prerequisites and throughout the SDK
/// for type-safe record type references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Ns,
    Ptr,
    Soa,
    Mx,
    Txt,
    Srv,
    Caa,
    Dnskey,
    Rrsig,
    Nsec,
    Nsec3,
    Ds,
    Cds,
    Cdnskey,
    Tlsa,
    Sshfp,
    Csync,
    Rp,
    /// Any record type not covered by a named variant.
    Other(u16),
}

impl RecordType {
    /// Convert from wire format value.
    pub fn from_value(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::Aaaa,
            5 => Self::Cname,
            2 => Self::Ns,
            12 => Self::Ptr,
            6 => Self::Soa,
            15 => Self::Mx,
            16 => Self::Txt,
            33 => Self::Srv,
            257 => Self::Caa,
            48 => Self::Dnskey,
            46 => Self::Rrsig,
            47 => Self::Nsec,
            50 => Self::Nsec3,
            43 => Self::Ds,
            59 => Self::Cds,
            60 => Self::Cdnskey,
            52 => Self::Tlsa,
            44 => Self::Sshfp,
            62 => Self::Csync,
            17 => Self::Rp,
            other => Self::Other(other),
        }
    }

    /// Convert to wire format value.
    pub fn value(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Cname => 5,
            Self::Ns => 2,
            Self::Ptr => 12,
            Self::Soa => 6,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Srv => 33,
            Self::Caa => 257,
            Self::Dnskey => 48,
            Self::Rrsig => 46,
            Self::Nsec => 47,
            Self::Nsec3 => 50,
            Self::Ds => 43,
            Self::Cds => 59,
            Self::Cdnskey => 60,
            Self::Tlsa => 52,
            Self::Sshfp => 44,
            Self::Csync => 62,
            Self::Rp => 17,
            Self::Other(v) => *v,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => f.write_str("A"),
            Self::Aaaa => f.write_str("AAAA"),
            Self::Cname => f.write_str("CNAME"),
            Self::Ns => f.write_str("NS"),
            Self::Ptr => f.write_str("PTR"),
            Self::Soa => f.write_str("SOA"),
            Self::Mx => f.write_str("MX"),
            Self::Txt => f.write_str("TXT"),
            Self::Srv => f.write_str("SRV"),
            Self::Caa => f.write_str("CAA"),
            Self::Dnskey => f.write_str("DNSKEY"),
            Self::Rrsig => f.write_str("RRSIG"),
            Self::Nsec => f.write_str("NSEC"),
            Self::Nsec3 => f.write_str("NSEC3"),
            Self::Ds => f.write_str("DS"),
            Self::Cds => f.write_str("CDS"),
            Self::Cdnskey => f.write_str("CDNSKEY"),
            Self::Tlsa => f.write_str("TLSA"),
            Self::Sshfp => f.write_str("SSHFP"),
            Self::Csync => f.write_str("CSYNC"),
            Self::Rp => f.write_str("RP"),
            Self::Other(v) => write!(f, "TYPE{v}"),
        }
    }
}

/// DNS response codes (RFC 1035 §4.1.1 + RFC 2136 §2.2).
///
/// Used by `UpdateResult` and response parsing throughout the SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Any RCODE not covered by a named variant.
    Other(u16),
}

impl Rcode {
    /// Convert from wire format value.
    pub fn from_value(value: u16) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YxDomain,
            7 => Self::YxRrset,
            8 => Self::NxRrset,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            other => Self::Other(other),
        }
    }

    /// Convert to wire format value.
    pub fn value(&self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::YxDomain => 6,
            Self::YxRrset => 7,
            Self::NxRrset => 8,
            Self::NotAuth => 9,
            Self::NotZone => 10,
            Self::Other(v) => *v,
        }
    }

    /// Whether this RCODE indicates success.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::NoError)
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => f.write_str("NOERROR"),
            Self::FormErr => f.write_str("FORMERR"),
            Self::ServFail => f.write_str("SERVFAIL"),
            Self::NxDomain => f.write_str("NXDOMAIN"),
            Self::NotImp => f.write_str("NOTIMP"),
            Self::Refused => f.write_str("REFUSED"),
            Self::YxDomain => f.write_str("YXDOMAIN"),
            Self::YxRrset => f.write_str("YXRRSET"),
            Self::NxRrset => f.write_str("NXRRSET"),
            Self::NotAuth => f.write_str("NOTAUTH"),
            Self::NotZone => f.write_str("NOTZONE"),
            Self::Other(v) => write!(f, "RCODE{v}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_type_roundtrip_named() {
        let types = [
            (RecordType::A, 1, "A"),
            (RecordType::Aaaa, 28, "AAAA"),
            (RecordType::Cname, 5, "CNAME"),
            (RecordType::Ns, 2, "NS"),
            (RecordType::Soa, 6, "SOA"),
            (RecordType::Mx, 15, "MX"),
            (RecordType::Txt, 16, "TXT"),
            (RecordType::Srv, 33, "SRV"),
            (RecordType::Caa, 257, "CAA"),
            (RecordType::Ptr, 12, "PTR"),
        ];
        for (rtype, value, name) in types {
            assert_eq!(rtype.value(), value, "value mismatch for {name}");
            assert_eq!(RecordType::from_value(value), rtype, "from_value mismatch for {name}");
            assert_eq!(alloc::format!("{rtype}"), name, "display mismatch for {name}");
        }
    }

    #[test]
    fn record_type_unknown_roundtrip() {
        let rtype = RecordType::from_value(65534);
        assert_eq!(rtype, RecordType::Other(65534));
        assert_eq!(rtype.value(), 65534);
        assert_eq!(alloc::format!("{rtype}"), "TYPE65534");
    }

    #[test]
    fn rcode_roundtrip_named() {
        let codes = [
            (Rcode::NoError, 0, "NOERROR"),
            (Rcode::NxDomain, 3, "NXDOMAIN"),
            (Rcode::Refused, 5, "REFUSED"),
            (Rcode::NotAuth, 9, "NOTAUTH"),
        ];
        for (rcode, value, name) in codes {
            assert_eq!(rcode.value(), value, "value mismatch for {name}");
            assert_eq!(Rcode::from_value(value), rcode, "from_value mismatch for {name}");
            assert_eq!(alloc::format!("{rcode}"), name, "display mismatch for {name}");
        }
    }

    #[test]
    fn rcode_is_success() {
        assert!(Rcode::NoError.is_success());
        assert!(!Rcode::NxDomain.is_success());
        assert!(!Rcode::Refused.is_success());
        assert!(!Rcode::Other(99).is_success());
    }

    #[test]
    fn rcode_unknown_roundtrip() {
        let rcode = Rcode::from_value(999);
        assert_eq!(rcode, Rcode::Other(999));
        assert_eq!(rcode.value(), 999);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p bind9-sdk-core -- protocol`
Expected: All tests pass

- [ ] **Step 3: Verify WASM target**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Passes (protocol.rs is pure no_std)

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-core/src/protocol.rs
git commit -m "feat(core): add RecordType and Rcode enums in protocol.rs"
```

### Task 4: Create Zone Module Stubs

**Files:**
- Create: `crates/bind9-sdk-core/src/zone/mod.rs`

- [ ] **Step 1: Create zone directory and mod.rs with real types**

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::vec::Vec;

use crate::domain::DomainName;
use crate::error::CoreError;
use crate::record::{RecordClass, ResourceRecord, Serial};

/// Summary of a zone (name, class, serial).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSummary {
    pub name: DomainName,
    pub class: RecordClass,
    pub serial: Serial,
}

/// Full zone data — a collection of resource records sharing a common origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    pub name: DomainName,
    pub class: RecordClass,
    pub records: Vec<ResourceRecord>,
}

impl Zone {
    /// Extract the SOA serial number, if the zone contains a SOA record.
    pub fn serial(&self) -> Option<Serial> {
        self.soa().map(|rr| match &rr.rdata {
            crate::rdata::RecordData::Soa { serial, .. } => *serial,
            _ => unreachable!("soa() only returns SOA records"),
        })
    }

    /// Find the SOA record in this zone.
    pub fn soa(&self) -> Option<&ResourceRecord> {
        self.records.iter().find(|rr| {
            matches!(rr.rdata, crate::rdata::RecordData::Soa { .. })
        })
    }

    /// Create a zone summary.
    pub fn summary(&self) -> ZoneSummary {
        ZoneSummary {
            name: self.name.clone(),
            class: self.class,
            serial: self.serial().unwrap_or(Serial::new(0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::RecordData;
    use crate::record::{RecordClass, Ttl};

    fn example_zone() -> Zone {
        let name = DomainName::new("example.com.").unwrap();
        Zone {
            name: name.clone(),
            class: RecordClass::IN,
            records: alloc::vec![
                ResourceRecord {
                    name: name.clone(),
                    class: RecordClass::IN,
                    ttl: Ttl::new(3600).unwrap(),
                    rdata: RecordData::Soa {
                        mname: DomainName::new("ns1.example.com.").unwrap(),
                        rname: DomainName::new("admin.example.com.").unwrap(),
                        serial: Serial::new(2026031401),
                        refresh: Ttl::new(3600).unwrap(),
                        retry: Ttl::new(900).unwrap(),
                        expire: Ttl::new(604800).unwrap(),
                        minimum: Ttl::new(86400).unwrap(),
                    },
                },
                ResourceRecord {
                    name: name.clone(),
                    class: RecordClass::IN,
                    ttl: Ttl::new(3600).unwrap(),
                    rdata: RecordData::A(core::net::Ipv4Addr::new(192, 0, 2, 1)),
                },
            ],
        }
    }

    #[test]
    fn zone_serial_from_soa() {
        let zone = example_zone();
        assert_eq!(zone.serial(), Some(Serial::new(2026031401)));
    }

    #[test]
    fn zone_soa_found() {
        let zone = example_zone();
        assert!(zone.soa().is_some());
    }

    #[test]
    fn zone_summary() {
        let zone = example_zone();
        let summary = zone.summary();
        assert_eq!(summary.name, DomainName::new("example.com.").unwrap());
        assert_eq!(summary.class, RecordClass::IN);
        assert_eq!(summary.serial, Serial::new(2026031401));
    }

    #[test]
    fn zone_no_soa_serial_is_none() {
        let zone = Zone {
            name: DomainName::new("empty.example.com.").unwrap(),
            class: RecordClass::IN,
            records: alloc::vec![],
        };
        assert_eq!(zone.serial(), None);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p bind9-sdk-core -- zone`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/
git commit -m "feat(core): add Zone and ZoneSummary types in zone/mod.rs"
```

### Task 5: Create TSIG and Update Module Stubs

**Files:**
- Create: `crates/bind9-sdk-core/src/tsig.rs`
- Create: `crates/bind9-sdk-core/src/update.rs`

- [ ] **Step 1: Create tsig.rs stub**

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// TSIG key material and HMAC signing — fleshed out in WT-2 plan.
// This stub exists so the module declaration compiles.
```

- [ ] **Step 2: Create update.rs with real UpdateMessage and UpdateResult types**

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::vec::Vec;

use crate::protocol::Rcode;

/// A constructed RFC 2136 dynamic update message, ready to send on the wire.
///
/// Created by `UpdateBuilder::build()` or `UpdateBuilder::build_unsigned()`.
/// The wire bytes are the complete DNS message including headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage {
    pub(crate) wire_bytes: Vec<u8>,
    pub(crate) id: u16,
}

impl UpdateMessage {
    /// The raw wire bytes of the DNS update message.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire_bytes
    }

    /// The DNS message ID.
    pub fn id(&self) -> u16 {
        self.id
    }
}

/// Result of sending an RFC 2136 update to a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateResult {
    pub rcode: Rcode,
    pub id: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_message_accessors() {
        let msg = UpdateMessage {
            wire_bytes: alloc::vec![0x00, 0x01, 0x28, 0x00],
            id: 0x0001,
        };
        assert_eq!(msg.as_bytes(), &[0x00, 0x01, 0x28, 0x00]);
        assert_eq!(msg.id(), 0x0001);
    }

    #[test]
    fn update_result_success() {
        let result = UpdateResult {
            rcode: Rcode::NoError,
            id: 42,
        };
        assert!(result.rcode.is_success());
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p bind9-sdk-core -- update`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs crates/bind9-sdk-core/src/update.rs
git commit -m "feat(core): add tsig.rs stub and update.rs with UpdateMessage/UpdateResult"
```

### Task 6: Migrate Placeholders from traits.rs

**Files:**
- Modify: `crates/bind9-sdk-core/src/traits.rs`

The placeholder unit structs `Zone`, `ZoneSummary`, `UpdateMessage`, `UpdateResult` now live in their target modules. Remove them from `traits.rs` and update imports. Keep `ServerStatus`, `FrozenZone`, `ServerStats`, `ZoneStats` in `traits.rs` but flesh out with real fields.

- [ ] **Step 1: Replace placeholder types with real fields and update imports**

Replace the entire placeholder block and trait definitions. The key changes:

1. Remove: `pub struct Zone;`, `pub struct ZoneSummary;`, `pub struct UpdateMessage;`, `pub struct UpdateResult;`
2. Add imports: `use crate::zone::{Zone, ZoneSummary};`, `use crate::update::{UpdateMessage, UpdateResult};`
3. Flesh out: `ServerStatus`, `FrozenZone`, `ServerStats`, `ZoneStats` with real fields

New `traits.rs` content (replace everything after the `#![allow(...)]` attribute):

```rust
use alloc::string::String;
use alloc::vec::Vec;

use crate::domain::DomainName;
use crate::record::{RecordClass, Serial};
use crate::update::{UpdateMessage, UpdateResult};
use crate::zone::{Zone, ZoneSummary};

/// Server status information from `rndc status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStatus {
    pub version: String,
    pub running_since: Option<String>,
    pub reload_count: u32,
    pub server_up: bool,
    pub raw_text: String,
}

/// A zone that has been frozen via `rndc freeze`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenZone {
    pub name: DomainName,
    pub class: RecordClass,
}

/// Server-level statistics from the BIND9 statistics-channel.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerStats {
    pub boot_time: String,
    pub config_time: String,
    pub current_time: String,
    pub version: String,
}

/// Zone-level statistics from the BIND9 statistics-channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneStats {
    pub name: DomainName,
    pub class: RecordClass,
    pub serial: Serial,
    pub record_count: u32,
    pub zone_type: String,
}
```

Keep all 4 trait definitions (`NamedControl`, `DynamicUpdater`, `ZoneManager`, `StatsClient`) unchanged — they already use the correct type names.

- [ ] **Step 2: Update mock tests in traits.rs**

The mocks need to construct real types now instead of unit structs:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CoreError;

    struct MockNamedControl;

    impl NamedControl for MockNamedControl {
        type Error = CoreError;

        async fn status(&self) -> Result<ServerStatus, CoreError> {
            Ok(ServerStatus {
                version: "BIND 9.20.0".into(),
                running_since: None,
                reload_count: 0,
                server_up: true,
                raw_text: "mock".into(),
            })
        }

        async fn reload(&self) -> Result<(), CoreError> {
            Ok(())
        }

        async fn reload_zone(&self, _zone: &DomainName) -> Result<(), CoreError> {
            Ok(())
        }

        async fn freeze(&self, zone: &DomainName) -> Result<FrozenZone, CoreError> {
            Ok(FrozenZone {
                name: zone.clone(),
                class: crate::record::RecordClass::IN,
            })
        }
    }

    #[test]
    fn mock_named_control_compiles() {
        let _mock = MockNamedControl;
    }

    struct MockZoneManager;

    impl ZoneManager for MockZoneManager {
        type Error = CoreError;

        async fn list_zones(&self) -> Result<Vec<ZoneSummary>, CoreError> {
            Ok(alloc::vec![])
        }

        async fn get_zone(&self, _name: &DomainName) -> Result<Zone, CoreError> {
            Ok(Zone {
                name: DomainName::new("example.com.").unwrap(),
                class: crate::record::RecordClass::IN,
                records: alloc::vec![],
            })
        }
    }

    #[test]
    fn mock_zone_manager_compiles() {
        let _mock = MockZoneManager;
    }

    struct MockDynamicUpdater;

    impl DynamicUpdater for MockDynamicUpdater {
        type Error = CoreError;

        async fn send_update(&self, _update: &UpdateMessage) -> Result<UpdateResult, CoreError> {
            Ok(UpdateResult {
                rcode: crate::protocol::Rcode::NoError,
                id: 0,
            })
        }
    }

    #[test]
    fn mock_dynamic_updater_compiles() {
        let _mock = MockDynamicUpdater;
    }

    struct MockStatsClient;

    impl StatsClient for MockStatsClient {
        type Error = CoreError;

        async fn server_stats(&self) -> Result<ServerStats, CoreError> {
            Ok(ServerStats {
                boot_time: "2026-01-01T00:00:00Z".into(),
                config_time: "2026-01-01T00:00:00Z".into(),
                current_time: "2026-03-14T12:00:00Z".into(),
                version: "BIND 9.20.0".into(),
            })
        }

        async fn zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, CoreError> {
            Ok(ZoneStats {
                name: zone.clone(),
                class: crate::record::RecordClass::IN,
                serial: crate::record::Serial::new(1),
                record_count: 0,
                zone_type: "primary".into(),
            })
        }
    }

    #[test]
    fn mock_stats_client_compiles() {
        let _mock = MockStatsClient;
    }
}
```

- [ ] **Step 3: Run all tests**

Run: `cargo test -p bind9-sdk-core`
Expected: All tests pass (including mock tests with real constructors)

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-core/src/traits.rs
git commit -m "refactor(core): migrate placeholders to target modules, flesh out ServerStatus/ServerStats/ZoneStats"
```

### Task 7: Update core lib.rs with New Module Declarations

**Files:**
- Modify: `crates/bind9-sdk-core/src/lib.rs`

- [ ] **Step 1: Add module declarations and re-exports**

Update `lib.rs` to declare all new modules and add curated re-exports:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod domain;
pub mod error;
pub mod protocol;
pub mod rdata;
pub mod record;
pub mod traits;
pub mod tsig;
pub mod update;
pub mod zone;

// Curated re-exports for common access
pub use domain::{DomainName, Label};
pub use error::CoreError;
pub use protocol::{Rcode, RecordType};
pub use rdata::RecordData;
pub use record::{RecordClass, ResourceRecord, Serial, Ttl};
pub use traits::{DynamicUpdater, NamedControl, StatsClient, ZoneManager};
pub use update::{UpdateMessage, UpdateResult};
pub use zone::{Zone, ZoneSummary};
```

- [ ] **Step 2: Run tests and WASM check**

Run: `cargo test -p bind9-sdk-core && cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Both pass

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-core/src/lib.rs
git commit -m "feat(core): declare protocol, tsig, update, zone modules in lib.rs"
```

## Chunk 2: Net Module Stubs and Final Verification

### Task 8: Create Net Module Stubs

**Files:**
- Create: `crates/bind9-sdk-net/src/error.rs`
- Create: `crates/bind9-sdk-net/src/tls.rs`
- Create: `crates/bind9-sdk-net/src/config.rs`
- Create: `crates/bind9-sdk-net/src/rndc/mod.rs` (directory + file)
- Create: `crates/bind9-sdk-net/src/stats.rs`
- Create: `crates/bind9-sdk-net/src/nsupdate.rs`
- Modify: `crates/bind9-sdk-net/src/lib.rs`

- [ ] **Step 1: Create empty stub files for each net module**

Each stub file has the SPDX header and a doc comment explaining what it will contain:

`crates/bind9-sdk-net/src/error.rs`:
```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// NetError enum — fleshed out in WT-2 plan.
```

`crates/bind9-sdk-net/src/tls.rs`:
```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// TLS 1.3 configuration — fleshed out in WT-2 plan.
```

`crates/bind9-sdk-net/src/config.rs`:
```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// Bind9Client skeleton and ClientConfig — fleshed out in WT-2 plan.
```

`crates/bind9-sdk-net/src/rndc/mod.rs`:
```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// rndc wire protocol — fleshed out in WT-3 plan.
```

`crates/bind9-sdk-net/src/stats.rs`:
```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// Statistics-channel HTTP client — fleshed out in WT-4 plan.
```

`crates/bind9-sdk-net/src/nsupdate.rs`:
```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// nsupdate sender (UDP/TCP) — fleshed out in WT-4 plan.
```

- [ ] **Step 2: Update net lib.rs with module declarations**

Replace `crates/bind9-sdk-net/src/lib.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub mod config;
pub mod error;
pub mod nsupdate;
pub mod rndc;
pub mod stats;
pub mod tls;
```

- [ ] **Step 3: Run cargo check**

Run: `cargo check --workspace`
Expected: Passes (all stubs compile, even though they're empty)

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-net/src/
git commit -m "feat(net): add module stubs for error, tls, config, rndc, stats, nsupdate"
```

### Task 9: Final Verification

- [ ] **Step 1: Full workspace test suite**

Run: `cargo test --workspace`
Expected: All existing tests pass, plus new tests from protocol.rs, zone/mod.rs, update.rs

- [ ] **Step 2: WASM target check**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Passes (core remains no_std clean)

- [ ] **Step 3: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean

- [ ] **Step 4: Format check**

Run: `cargo fmt --check`
Expected: Clean

- [ ] **Step 5: Commit any remaining changes**

```bash
git add -A
git commit -m "chore: Phase 1 scaffolding complete — ready for worktree creation"
```

This scaffolding is now the base for all 4 worktree branches. Create worktrees from this commit.
