// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

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
    Acl, AclElement, ControlEndpoint, CoreError, CounterSet, DiffEntry, DomainName, DynamicUpdater,
    Label, ListenAddress, MemoryContextStats, MemoryStats, NamedAcl, NamedConf, NamedControl,
    NamedCounter, NamedOptions, NamedZone, NamedZoneType, Rcode, RecordClass, RecordData,
    RecordType, ResourceRecord, Serial, SerialStrategy, ServerStats, ServerStatsRates,
    StatisticsChannel, StatsClient, TrafficHistogram, TransferRecord, TsigAlgorithm, TsigKey, Ttl,
    TxtString, UpdateBuilder, UpdateMessage, ViewStats, Zone, ZoneDiff, ZoneFile, ZoneManager,
    ZoneStats,
};

#[cfg(feature = "net")]
pub use bind9_sdk_net::{
    Bind9Client, ClientConfig, FrozenZoneGuard, NetError, NsUpdateSender, RndcLimiter, RndcPool,
    RndcTransportPolicy, StatsHttpClient, TlsConfig, TransferClient,
};
