// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

// We intentionally use `async fn` in traits rather than `-> impl Future + Send`
// desugaring. These traits are not used as trait objects (`dyn Trait`); they exist
// for static dispatch only. See coding architecture spec §5.2.
#![allow(async_fn_in_trait)]

use alloc::string::String;
use alloc::vec::Vec;

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

/// Server-level statistics from the BIND9 statistics-channel JSON API.
///
/// Populated by the net crate from HTTP `/json/v1/server`. Counter
/// fields (queries, opcodes, rcodes) are added by WT-4 implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerStats {
    /// ISO 8601 timestamp of server boot, if present in the JSON response.
    pub boot_time: Option<String>,
    /// ISO 8601 timestamp of last configuration load, if present.
    pub config_time: Option<String>,
    /// ISO 8601 timestamp of the stats snapshot, if present.
    pub current_time: Option<String>,
    /// BIND version string (e.g., `"BIND 9.20.4 (Stable Release)"`), if present.
    pub version: Option<String>,
}

/// Zone-level statistics from the BIND9 statistics-channel JSON API.
///
/// Populated by the net crate from HTTP `/json/v1/zones`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ZoneStats {
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
            name,
            class,
            serial,
            record_count,
            zone_type,
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
        }
    }
}

/// rndc server management.
///
/// Implemented by `Bind9Client` (net crate) for live servers.
/// Test mocks implement with `type Error = CoreError`.
pub trait NamedControl: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn status(&self) -> Result<ServerStatus, Self::Error>;
    async fn reload(&self) -> Result<(), Self::Error>;
    async fn reload_zone(&self, zone: &DomainName) -> Result<(), Self::Error>;
    async fn freeze(&self, zone: &DomainName) -> Result<FrozenZone, Self::Error>;
}

/// RFC 2136 dynamic DNS updates.
///
/// Implemented by `Bind9Client` (net crate).
pub trait DynamicUpdater: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn send_update(&self, update: &UpdateMessage) -> Result<UpdateResult, Self::Error>;
}

/// Zone listing and retrieval.
///
/// Implemented by `Bind9Client` (net crate) for live servers
/// and by `ZoneFile` (core crate) for local file operations.
pub trait ZoneManager: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn list_zones(&self) -> Result<Vec<ZoneSummary>, Self::Error>;
    async fn get_zone(&self, name: &DomainName) -> Result<Zone, Self::Error>;
}

/// BIND9 statistics-channel JSON API.
///
/// Implemented by `Bind9Client` (net crate).
pub trait StatsClient: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn server_stats(&self) -> Result<ServerStats, Self::Error>;
    async fn zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, Self::Error>;
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

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
            })
        }

        async fn zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, CoreError> {
            Ok(ZoneStats {
                name: zone.clone(),
                class: RecordClass::IN,
                serial: Serial::new(2026031401),
                record_count: Some(42),
                zone_type: String::from("primary"),
            })
        }
    }

    #[test]
    fn mock_stats_client_compiles() {
        let _mock = MockStatsClient;
    }
}
