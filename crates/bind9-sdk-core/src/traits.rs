// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::vec::Vec;

use crate::domain::DomainName;

// Placeholder types — fleshed out in subsequent plans.
// These exist so the trait signatures compile now.

/// Server status information from `rndc status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStatus;

/// A zone that has been frozen via `rndc freeze`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenZone;

/// A constructed RFC 2136 dynamic update message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage;

/// Result of sending an RFC 2136 update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateResult;

/// Summary of a zone (name, class, serial).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSummary;

/// Full zone data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone;

/// Server-level statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStats;

/// Zone-level statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneStats;

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
    use super::*;
    use crate::error::CoreError;

    // Minimal mock to verify trait is implementable
    struct MockNamedControl;

    impl NamedControl for MockNamedControl {
        type Error = CoreError;

        async fn status(&self) -> Result<ServerStatus, CoreError> {
            Ok(ServerStatus)
        }

        async fn reload(&self) -> Result<(), CoreError> {
            Ok(())
        }

        async fn reload_zone(&self, _zone: &crate::domain::DomainName) -> Result<(), CoreError> {
            Ok(())
        }

        async fn freeze(
            &self,
            _zone: &crate::domain::DomainName,
        ) -> Result<FrozenZone, CoreError> {
            Ok(FrozenZone)
        }
    }

    #[test]
    fn mock_named_control_compiles() {
        let _mock = MockNamedControl;
    }

    struct MockZoneManager;

    impl ZoneManager for MockZoneManager {
        type Error = CoreError;

        async fn list_zones(&self) -> Result<alloc::vec::Vec<ZoneSummary>, CoreError> {
            Ok(alloc::vec![])
        }

        async fn get_zone(
            &self,
            _name: &crate::domain::DomainName,
        ) -> Result<Zone, CoreError> {
            Ok(Zone)
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
            Ok(UpdateResult)
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
            Ok(ServerStats)
        }

        async fn zone_stats(
            &self,
            _zone: &crate::domain::DomainName,
        ) -> Result<ZoneStats, CoreError> {
            Ok(ZoneStats)
        }
    }

    #[test]
    fn mock_stats_client_compiles() {
        let _mock = MockStatsClient;
    }
}
