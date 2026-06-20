// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// We intentionally use `async fn` in traits rather than `-> impl Future + Send`
// desugaring. These traits are not used as trait objects (`dyn Trait`); they exist
// for static dispatch only. See coding architecture spec §5.2.
#![allow(async_fn_in_trait)]

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::domain::DomainName;
use crate::record::{RecordClass, Serial};
use crate::update::{UpdateMessage, UpdateResult};
use crate::zone::{Zone, ZoneSummary};

/// Server status information from `rndc status`.
///
/// Populated by the net crate from an rndc status response.
/// Fields that the parser cannot extract are left as defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerStatus {
    /// BIND version string (e.g., `"BIND 9.20.4"`).
    pub version: String,
    /// ISO 8601 timestamp of when the server started, if available.
    pub running_since: Option<String>,
    /// Number of zones loaded by the server.
    pub zone_count: u32,
    /// Whether the server reports itself as running.
    pub server_up: bool,
    /// Full raw text of the rndc status response for unparsed fields.
    pub raw_text: String,
}

impl ServerStatus {
    /// Create a new `ServerStatus`.
    pub fn new(
        version: String,
        running_since: Option<String>,
        zone_count: u32,
        server_up: bool,
        raw_text: String,
    ) -> Self {
        Self {
            version,
            running_since,
            zone_count,
            server_up,
            raw_text,
        }
    }
}

/// A zone that has been frozen via `rndc freeze`.
///
/// Returned by `NamedControl::freeze()`. Contains the zone identity
/// so callers can confirm which zone was frozen.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FrozenZone {
    /// The domain name of the frozen zone.
    pub name: DomainName,
    /// The DNS class of the frozen zone.
    pub class: RecordClass,
}

impl FrozenZone {
    /// Create a new `FrozenZone`.
    pub fn new(name: DomainName, class: RecordClass) -> Self {
        Self { name, class }
    }
}

/// A cumulative BIND statistics counter.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NamedCounter {
    /// Counter name as emitted by BIND.
    pub name: String,
    /// Cumulative counter value.
    pub value: u64,
}

impl NamedCounter {
    /// Create a named cumulative counter.
    pub fn new(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// A deterministic collection of named BIND counters.
///
/// BIND adds counters over time, so names remain strings while values are
/// strongly typed integers. Entries are sorted by name for stable output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CounterSet {
    counters: Vec<NamedCounter>,
}

impl CounterSet {
    /// Create a counter set and sort it by counter name.
    pub fn new(mut counters: Vec<NamedCounter>) -> Self {
        counters.sort_by(|left, right| left.name.cmp(&right.name));
        Self { counters }
    }

    /// Return a counter value by its exact BIND name.
    pub fn get(&self, name: &str) -> Option<u64> {
        self.counters
            .binary_search_by(|counter| counter.name.as_str().cmp(name))
            .ok()
            .map(|index| self.counters[index].value)
    }

    /// Iterate over counters in stable name order.
    pub fn iter(&self) -> impl Iterator<Item = &NamedCounter> {
        self.counters.iter()
    }

    /// Return the number of counters.
    pub fn len(&self) -> usize {
        self.counters.len()
    }

    /// Return whether this set contains no counters.
    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }
}

/// Resolver and cache counters for one BIND view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ViewStats {
    /// BIND view name.
    pub name: String,
    /// Resolver operation counters.
    pub resolver_stats: CounterSet,
    /// Outgoing resolver query counters by RR type.
    pub query_types: CounterSet,
    /// Cached RRset counters by RR type.
    pub cache: CounterSet,
    /// Cache behavior and memory counters.
    pub cache_stats: CounterSet,
    /// Address database counters.
    pub adb: CounterSet,
}

/// One memory context from the aggregate statistics response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryContextStats {
    /// Internal BIND context identifier.
    pub id: String,
    /// Human-readable context name.
    pub name: String,
    /// Current reference count.
    pub references: u64,
    /// Bytes allocated by this context.
    pub malloced: u64,
    /// Bytes currently in use.
    pub in_use: u64,
    /// Number of memory pools.
    pub pools: u64,
    /// Configured high-water mark.
    pub high_water: u64,
    /// Configured low-water mark.
    pub low_water: u64,
}

/// BIND memory statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryStats {
    /// Total bytes currently in use.
    pub in_use: u64,
    /// Total bytes allocated.
    pub malloced: u64,
    /// Per-context memory statistics.
    pub contexts: Vec<MemoryContextStats>,
}

/// A DNS message-size histogram emitted by BIND.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrafficHistogram {
    /// Histogram name, including transport, direction, and address family.
    pub name: String,
    /// Size-bucket counters.
    pub buckets: CounterSet,
}

/// Rates derived from two cumulative BIND statistics snapshots.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct ServerStatsRates {
    /// Incoming QUERY operations per second.
    pub queries_per_second: Option<f64>,
    /// SERVFAIL responses per second.
    pub servfail_per_second: Option<f64>,
}

/// Server-level statistics from the BIND9 statistics-channel JSON API.
///
/// The values returned by BIND are cumulative counters. Rates require two
/// snapshots and can be derived with [`ServerStats::rates_since`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerStats {
    /// JSON statistics schema version (for example, `"1.8"`).
    pub json_stats_version: Option<String>,
    /// ISO 8601 timestamp of server boot, if present in the JSON response.
    pub boot_time: Option<String>,
    /// ISO 8601 timestamp of last configuration load, if present.
    pub config_time: Option<String>,
    /// ISO 8601 timestamp of the stats snapshot, if present.
    pub current_time: Option<String>,
    /// BIND version string (e.g., `"BIND 9.20.4 (Stable Release)"`), if present.
    pub version: Option<String>,
    /// Incoming requests grouped by DNS opcode.
    pub opcodes: CounterSet,
    /// Responses grouped by DNS RCODE.
    pub rcodes: CounterSet,
    /// Per-view resolver and cache statistics.
    pub views: Vec<ViewStats>,
    /// Socket I/O counters from the aggregate endpoint.
    pub socket: CounterSet,
    /// Memory statistics from the aggregate endpoint.
    pub memory: Option<MemoryStats>,
    /// DNS message-size traffic histograms.
    pub traffic: Vec<TrafficHistogram>,
}

/// Zone-level statistics from the BIND9 statistics-channel JSON API.
///
/// Populated by the net crate from HTTP `/json/v1/zones`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ZoneStats {
    /// BIND view containing the zone.
    pub view: String,
    /// The domain name of the zone.
    pub name: DomainName,
    /// The DNS class of the zone.
    pub class: RecordClass,
    /// The current SOA serial number.
    pub serial: Serial,
    /// Number of resource records in the zone, if available.
    ///
    /// BIND9's statistics-channel JSON API does not always expose this value;
    /// when absent, this is `None`.
    pub record_count: Option<u32>,
    /// Zone type (e.g., `"primary"`, `"secondary"`).
    pub zone_type: String,
    /// ISO 8601 time at which the zone was loaded.
    pub loaded: Option<String>,
}

impl ZoneStats {
    /// Create a new `ZoneStats`.
    pub fn new(
        name: DomainName,
        class: RecordClass,
        serial: Serial,
        record_count: Option<u32>,
        zone_type: String,
    ) -> Self {
        Self {
            view: String::from("_default"),
            name,
            class,
            serial,
            record_count,
            zone_type,
            loaded: None,
        }
    }

    /// Create zone statistics with the containing view and load timestamp.
    pub fn new_in_view(
        view: String,
        name: DomainName,
        class: RecordClass,
        serial: Serial,
        zone_type: String,
        loaded: Option<String>,
    ) -> Self {
        Self {
            view,
            name,
            class,
            serial,
            record_count: None,
            zone_type,
            loaded,
        }
    }
}

impl ServerStats {
    /// Create a new `ServerStats`.
    pub fn new(
        boot_time: Option<String>,
        config_time: Option<String>,
        current_time: Option<String>,
        version: Option<String>,
    ) -> Self {
        Self {
            boot_time,
            config_time,
            current_time,
            version,
            ..Self::default()
        }
    }

    /// Derive selected rates from an older cumulative snapshot.
    ///
    /// A rate is `None` when a counter is absent, the interval is zero, or the
    /// current value is lower than the previous value after a server restart
    /// or statistics reset.
    pub fn rates_since(&self, previous: &Self, elapsed: Duration) -> ServerStatsRates {
        ServerStatsRates {
            queries_per_second: counter_rate(
                self.opcodes.get("QUERY"),
                previous.opcodes.get("QUERY"),
                elapsed,
            ),
            servfail_per_second: counter_rate(
                self.rcodes.get("SERVFAIL"),
                previous.rcodes.get("SERVFAIL"),
                elapsed,
            ),
        }
    }
}

fn counter_rate(current: Option<u64>, previous: Option<u64>, elapsed: Duration) -> Option<f64> {
    let seconds = elapsed.as_secs_f64();
    if seconds == 0.0 {
        return None;
    }
    let delta = current?.checked_sub(previous?)?;
    Some(delta as f64 / seconds)
}

/// rndc server management.
///
/// Implemented by `Bind9Client` (net crate) for live servers.
/// Test mocks implement with `type Error = CoreError`.
pub trait NamedControl: Send + Sync {
    /// Error type returned by all rndc operations.
    type Error: core::error::Error + Send + Sync + 'static;

    /// Fetch the server status from `rndc status`.
    async fn status(&self) -> Result<ServerStatus, Self::Error>;
    /// Reload all zones and configuration.
    async fn reload(&self) -> Result<(), Self::Error>;
    /// Reload a single zone by name.
    async fn reload_zone(&self, zone: &DomainName) -> Result<(), Self::Error>;
    /// Freeze dynamic updates for a zone so the zone file can be edited safely.
    async fn freeze(&self, zone: &DomainName) -> Result<FrozenZone, Self::Error>;
}

/// RFC 2136 dynamic DNS updates.
///
/// Implemented by `Bind9Client` (net crate).
pub trait DynamicUpdater: Send + Sync {
    /// Error type returned by dynamic update operations.
    type Error: core::error::Error + Send + Sync + 'static;

    /// Send a wire-encoded RFC 2136 update message and return the server response.
    async fn send_update(&self, update: &UpdateMessage) -> Result<UpdateResult, Self::Error>;
}

/// Zone listing and retrieval.
///
/// Implemented by `Bind9Client` (net crate) for live servers
/// and by `ZoneFile` (core crate) for local file operations.
pub trait ZoneManager: Send + Sync {
    /// Error type returned by zone management operations.
    type Error: core::error::Error + Send + Sync + 'static;

    /// List all zones known to the server.
    async fn list_zones(&self) -> Result<Vec<ZoneSummary>, Self::Error>;
    /// Retrieve the full record set for a zone.
    async fn get_zone(&self, name: &DomainName) -> Result<Zone, Self::Error>;
}

/// BIND9 statistics-channel JSON API.
///
/// Implemented by `Bind9Client` (net crate).
pub trait StatsClient: Send + Sync {
    /// Error type returned by statistics-channel operations.
    type Error: core::error::Error + Send + Sync + 'static;

    /// Fetch server-level statistics from `/json/v1/server`.
    async fn server_stats(&self) -> Result<ServerStats, Self::Error>;
    /// Fetch zone-level statistics for a named zone from `/json/v1/zones`.
    async fn zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, Self::Error>;
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use core::time::Duration;

    use super::*;
    use crate::error::CoreError;
    use crate::protocol::Rcode;
    use crate::record::RecordClass;

    // Minimal mock to verify trait is implementable
    struct MockNamedControl;

    impl NamedControl for MockNamedControl {
        type Error = CoreError;

        async fn status(&self) -> Result<ServerStatus, CoreError> {
            Ok(ServerStatus {
                version: String::from("BIND 9.20.4"),
                running_since: Some(String::from("2026-01-15T08:30:00Z")),
                zone_count: 0,
                server_up: true,
                raw_text: String::from("server is up and running"),
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
                class: RecordClass::IN,
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
                class: RecordClass::IN,
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
                rcode: Rcode::NoError,
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
                boot_time: Some(String::from("2026-01-15T08:30:00Z")),
                config_time: Some(String::from("2026-01-15T08:30:05Z")),
                current_time: Some(String::from("2026-03-14T12:00:00Z")),
                version: Some(String::from("BIND 9.20.4")),
                ..ServerStats::default()
            })
        }

        async fn zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, CoreError> {
            Ok(ZoneStats {
                view: String::from("_default"),
                name: zone.clone(),
                class: RecordClass::IN,
                serial: Serial::new(2026031401),
                record_count: Some(42),
                zone_type: String::from("primary"),
                loaded: None,
            })
        }
    }

    #[test]
    fn mock_stats_client_compiles() {
        let _mock = MockStatsClient;
    }

    #[test]
    fn server_stats_derives_rates_from_cumulative_snapshots() {
        let previous = ServerStats {
            opcodes: CounterSet::new(alloc::vec![NamedCounter::new("QUERY", 100)]),
            rcodes: CounterSet::new(alloc::vec![NamedCounter::new("SERVFAIL", 2)]),
            ..ServerStats::default()
        };
        let current = ServerStats {
            opcodes: CounterSet::new(alloc::vec![NamedCounter::new("QUERY", 160)]),
            rcodes: CounterSet::new(alloc::vec![NamedCounter::new("SERVFAIL", 5)]),
            ..ServerStats::default()
        };

        let rates = current.rates_since(&previous, Duration::from_secs(30));
        assert_eq!(rates.queries_per_second, Some(2.0));
        assert_eq!(rates.servfail_per_second, Some(0.1));
    }

    #[test]
    fn counter_rate_is_unknown_after_counter_reset() {
        let previous = ServerStats {
            opcodes: CounterSet::new(alloc::vec![NamedCounter::new("QUERY", 100)]),
            ..ServerStats::default()
        };
        let current = ServerStats {
            opcodes: CounterSet::new(alloc::vec![NamedCounter::new("QUERY", 4)]),
            ..ServerStats::default()
        };

        let rates = current.rates_since(&previous, Duration::from_secs(30));
        assert_eq!(rates.queries_per_second, None);
    }
}
