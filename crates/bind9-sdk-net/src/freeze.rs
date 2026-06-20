// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bind9_sdk_core::domain::DomainName;
use bind9_sdk_core::traits::{FrozenZone, NamedControl};
use tokio::runtime::Handle;

use crate::config::Bind9Client;
use crate::error::NetError;

pub(crate) type ThawFuture = Pin<Box<dyn Future<Output = Result<(), NetError>> + Send + 'static>>;

pub(crate) trait ZoneThawer: Send + Sync {
    fn thaw(&self, zone: DomainName) -> ThawFuture;
}

struct Bind9Thawer {
    client: Arc<Bind9Client>,
}

impl ZoneThawer for Bind9Thawer {
    fn thaw(&self, zone: DomainName) -> ThawFuture {
        let client = Arc::clone(&self.client);
        Box::pin(async move { NamedControl::thaw(client.as_ref(), &zone).await })
    }
}

/// RAII guard for a zone frozen through rndc.
///
/// Call [`thaw`](Self::thaw) to await cleanup and receive any error. If the
/// guard is dropped while still armed, including during panic unwinding, it
/// schedules a best-effort thaw operation on the Tokio runtime captured when
/// the guard was created.
pub struct FrozenZoneGuard {
    frozen: Option<FrozenZone>,
    thawer: Arc<dyn ZoneThawer>,
    runtime: Handle,
}

impl FrozenZoneGuard {
    pub(crate) fn for_client(
        frozen: FrozenZone,
        client: Arc<Bind9Client>,
    ) -> Result<Self, NetError> {
        let runtime = Handle::try_current().map_err(|error| {
            NetError::Protocol(format!(
                "a running Tokio runtime is required for a frozen-zone guard: {error}"
            ))
        })?;
        Ok(Self::new(frozen, Arc::new(Bind9Thawer { client }), runtime))
    }

    fn new(frozen: FrozenZone, thawer: Arc<dyn ZoneThawer>, runtime: Handle) -> Self {
        Self {
            frozen: Some(frozen),
            thawer,
            runtime,
        }
    }

    /// Return the frozen zone identity while the guard is armed.
    pub fn frozen_zone(&self) -> Option<&FrozenZone> {
        self.frozen.as_ref()
    }

    /// Thaw the zone, await completion, and disarm drop cleanup.
    pub async fn thaw(mut self) -> Result<(), NetError> {
        let frozen = self.frozen.take().ok_or_else(|| {
            NetError::Protocol("frozen-zone guard is already disarmed".to_string())
        })?;
        self.thawer.thaw(frozen.name).await
    }
}

impl fmt::Debug for FrozenZoneGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrozenZoneGuard")
            .field("frozen", &self.frozen)
            .finish_non_exhaustive()
    }
}

impl Drop for FrozenZoneGuard {
    fn drop(&mut self) {
        let Some(frozen) = self.frozen.take() else {
            return;
        };
        let future = self.thawer.thaw(frozen.name.clone());
        self.runtime.spawn(async move {
            if let Err(error) = future.await {
                tracing::error!(
                    zone = %frozen.name,
                    %error,
                    "best-effort thaw after dropping FrozenZoneGuard failed"
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::record::RecordClass;
    use bind9_sdk_core::traits::FrozenZone;

    use super::{FrozenZoneGuard, ThawFuture, ZoneThawer};
    use crate::NetError;

    struct RecordingThawer {
        zones: Arc<Mutex<Vec<DomainName>>>,
    }

    impl ZoneThawer for RecordingThawer {
        fn thaw(&self, zone: DomainName) -> ThawFuture {
            let zones = Arc::clone(&self.zones);
            Box::pin(async move {
                zones.lock().unwrap().push(zone);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn dropping_guard_schedules_thaw() {
        let zones = Arc::new(Mutex::new(Vec::new()));
        let guard = FrozenZoneGuard::new(
            FrozenZone::new(DomainName::new("example.com.").unwrap(), RecordClass::IN),
            Arc::new(RecordingThawer {
                zones: Arc::clone(&zones),
            }),
            tokio::runtime::Handle::current(),
        );

        drop(guard);
        tokio::task::yield_now().await;

        assert_eq!(
            zones.lock().unwrap().as_slice(),
            &[DomainName::new("example.com.").unwrap()]
        );
    }

    #[tokio::test]
    async fn explicit_thaw_disarms_drop_cleanup() {
        let zones = Arc::new(Mutex::new(Vec::new()));
        let guard = FrozenZoneGuard::new(
            FrozenZone::new(DomainName::new("example.com.").unwrap(), RecordClass::IN),
            Arc::new(RecordingThawer {
                zones: Arc::clone(&zones),
            }),
            tokio::runtime::Handle::current(),
        );

        guard.thaw().await.unwrap();
        tokio::task::yield_now().await;

        assert_eq!(zones.lock().unwrap().len(), 1);
    }

    fn _thaw_future_is_send(
        future: ThawFuture,
    ) -> Pin<Box<dyn Future<Output = Result<(), NetError>> + Send + 'static>> {
        future
    }
}
