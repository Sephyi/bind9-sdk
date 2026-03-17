// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # bind9-sdk
//!
//! Rust SDK for programmatic BIND9 DNS server management.
//!
//! ## Quick start
//!
//! ```rust
//! use bind9_sdk::{
//!     DomainName, RecordData, RecordType, ResourceRecord, RecordClass, Ttl,
//!     ZoneFile, TsigAlgorithm, UpdateBuilder,
//! };
//! use core::net::Ipv4Addr;
//!
//! let name = DomainName::new("example.com.").unwrap();
//! ```

/// Core DNS types, zone parsing, and RFC 2136 message construction.
///
/// This module is `no_std` compatible — safe to use in WASM and embedded contexts.
///
/// **Stability:** Paths under `bind9_sdk::core` are not covered by semver guarantees.
/// Prefer top-level imports (e.g., `use bind9_sdk::DomainName`).
pub use bind9_sdk_core as core;

/// Network operations: rndc TCP wire protocol, nsupdate sender, IXFR/AXFR, statistics HTTP.
///
/// Requires `feature = "net"` (enabled by default).
///
/// **Stability:** Paths under `bind9_sdk::net` are not covered by semver guarantees.
/// Prefer top-level imports.
#[cfg(feature = "net")]
pub use bind9_sdk_net as net;

// Curated top-level re-exports (covered by semver)
pub use bind9_sdk_core::{
    CoreError, DiffEntry, DomainName, DynamicUpdater, Label, NamedControl, Rcode, RecordClass,
    RecordData, RecordType, ResourceRecord, Serial, SerialStrategy, StatsClient, TransferRecord,
    TsigAlgorithm, TsigKey, Ttl, UpdateBuilder, UpdateMessage, Zone, ZoneDiff, ZoneFile,
    ZoneManager,
};

#[cfg(feature = "net")]
pub use bind9_sdk_net::{
    Bind9Client, ClientConfig, NetError, NsUpdateSender, RndcPool, StatsHttpClient, TlsConfig,
    TransferClient,
};
