// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Core `no_std` types for the BIND9 management SDK.
//!
//! Provides DNS domain names, resource records, zone file parsing and
//! serialization, RFC 2136 dynamic update messages, RFC 8945 TSIG signing,
//! and management traits — all without requiring `std`.
//!
//! Enable the `std` feature to opt in to `std::error::Error` impls.
//! Enable the `serde` feature for `Serialize`/`Deserialize` on DNS types.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// DNSSEC utilities: CDS/CDNSKEY generation, key tag computation.
pub mod dnssec;
/// Validated DNS domain name and label types.
pub mod domain;
/// Error type for all `bind9-sdk-core` operations.
pub mod error;
/// Unstable fuzzing entry points (feature `fuzzing`); not semver-stable.
#[cfg(feature = "fuzzing")]
pub mod fuzz;
/// Bounded typed parser for SDK-relevant `named.conf` statements.
pub mod named_conf;
/// Prometheus text exposition for BIND statistics (FR-072).
pub mod prometheus;
/// DNS protocol primitives: `RecordType` and `Rcode`.
pub mod protocol;
/// DNS record data variants (`RecordData`).
pub mod rdata;
/// DNS resource record and associated types (`ResourceRecord`, `Ttl`, `Serial`, `SerialStrategy`, `RecordClass`).
pub mod record;
/// Typed operational security warnings and policy (REQ-LOG-5, REQ-SEC-DEFAULT).
pub mod security;
/// Management traits (`NamedControl`, `DynamicUpdater`, `ZoneManager`, `StatsClient`).
pub mod traits;
/// Zone transfer types (`TransferSession`, `TransferKind`, `TransferRecord`).
pub mod transfer;
/// TSIG authentication types and signing/verification (RFC 8945).
pub mod tsig;
/// RFC 2136 dynamic update builder and message types.
pub mod update;
/// Zone file parser, serializer, and zone types.
pub mod zone;

// Curated re-exports for common access
pub use dnssec::{CdsRecord, DigestType, compute_key_tag};
pub use domain::{DomainName, Label};
pub use error::CoreError;
pub use named_conf::{
    Acl, AclElement, ControlEndpoint, ListenAddress, NamedAcl, NamedConf, NamedOptions, NamedZone,
    NamedZoneType, StatisticsChannel,
};
pub use prometheus::server_stats_to_prometheus;
pub use protocol::{Rcode, RecordType};
pub use rdata::{RecordData, TxtString};
pub use record::{RecordClass, ResourceRecord, Serial, SerialStrategy, Ttl};
pub use security::{
    SecurityPolicy, SecurityWarning, Severity, classify_rrsig, dnssec_algorithm_is_weak,
    dnssec_algorithm_name_is_weak, tsig_algorithm_is_deprecated,
};
pub use traits::{
    CounterSet, DynamicUpdater, FrozenZone, MemoryContextStats, MemoryStats, NamedControl,
    NamedCounter, ServerStats, ServerStatsRates, ServerStatus, StatsClient, TrafficHistogram,
    ViewStats, ZoneManager, ZoneStats,
};
pub use transfer::{Active, IxfrEvent, Pending, TransferKind, TransferRecord, TransferSession};
pub use tsig::{TsigAlgorithm, TsigKey, TsigRecord};
pub use update::{
    Prerequisite, Signed, Unsigned, UpdateBuilder, UpdateEntry, UpdateMessage, UpdateResult,
};
pub use zone::{DiffEntry, IncludeResolver, Zone, ZoneDiff, ZoneFile, ZoneSummary};
