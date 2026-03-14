// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

// We intentionally use `async fn` in traits rather than `-> impl Future + Send`
// desugaring. These traits are not used as trait objects (`dyn Trait`); they exist
// for static dispatch only. See coding architecture spec §5.2.
#![allow(async_fn_in_trait)]

use alloc::vec::Vec;

use crate::domain::DomainName;
use crate::update::{UpdateMessage, UpdateResult};
use crate::zone::{Zone, ZoneSummary};

// Placeholder types — fleshed out in subsequent worktrees.

/// Server status information from `rndc status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStatus;

/// A zone that has been frozen via `rndc freeze`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenZone;

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
    use crate::protocol::Rcode;
    use crate::record::RecordClass;

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

        async fn reload_zone(&self, _zone: &DomainName) -> Result<(), CoreError> {
            Ok(())
        }

        async fn freeze(&self, _zone: &DomainName) -> Result<FrozenZone, CoreError> {
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
            Ok(ServerStats)
        }

        async fn zone_stats(&self, _zone: &DomainName) -> Result<ZoneStats, CoreError> {
            Ok(ZoneStats)
        }
    }

    #[test]
    fn mock_stats_client_compiles() {
        let _mock = MockStatsClient;
    }
}
