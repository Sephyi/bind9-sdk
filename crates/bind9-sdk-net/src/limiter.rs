// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Concurrency limiter for rndc operations.
//!
//! rndc connections are not persistent — each command is a full
//! connect → auth → command → close cycle. The limiter bounds how many
//! of those cycles can run concurrently.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::ClientConfig;
use crate::error::NetError;

/// Default maximum concurrent rndc command cycles when `max_concurrent` is 0.
const DEFAULT_MAX_CONCURRENT: usize = 4;

/// Semaphore-based concurrency limiter for rndc command cycles.
///
/// Each [`acquire`](RndcLimiter::acquire) call returns an [`RndcPermit`] that holds
/// a semaphore permit and a reference to the shared config. The permit is
/// released when the guard is dropped, making the slot available for the next
/// caller.
///
/// `ClientConfig` is wrapped in [`Arc`] (not cloned) because [`TsigKey`]
/// intentionally does not implement `Clone` — key material must never be
/// duplicated.
///
/// [`TsigKey`]: bind9_sdk_core::tsig::TsigKey
pub struct RndcLimiter {
    config: Arc<ClientConfig>,
    semaphore: Arc<Semaphore>,
}

impl RndcLimiter {
    /// Create a new limiter wrapping `config` with a concurrency limit of
    /// `max_concurrent` slots.
    ///
    /// If `max_concurrent` is `0` the limiter defaults to 4 slots.
    pub fn new(config: ClientConfig, max_concurrent: usize) -> Self {
        let limit = if max_concurrent == 0 {
            DEFAULT_MAX_CONCURRENT
        } else {
            max_concurrent
        };
        Self {
            config: Arc::new(config),
            semaphore: Arc::new(Semaphore::new(limit)),
        }
    }

    /// Acquire a connection slot, blocking until one is available.
    ///
    /// Returns an [`RndcPermit`] that holds the slot until dropped.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Connection`] if the semaphore has been closed
    /// (which only happens if the limiter itself is dropped while tasks are
    /// waiting — in practice this should not occur in normal usage).
    pub async fn acquire(&self) -> Result<RndcPermit, NetError> {
        let permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| NetError::Connection("rndc concurrency limiter closed".into()))?;
        Ok(RndcPermit {
            _permit: permit,
            config: Arc::clone(&self.config),
        })
    }

    /// Return the number of currently available (unacquired) slots.
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// A permit holding one slot in an [`RndcLimiter`].
///
/// The slot is released back to the limiter when this permit is dropped.
/// Use [`config`](RndcPermit::config) to access the shared [`ClientConfig`]
/// for building an [`RndcConnection`].
///
/// [`RndcConnection`]: crate::rndc::RndcConnection
pub struct RndcPermit {
    /// Holds the semaphore permit for the duration of this guard's lifetime.
    _permit: OwnedSemaphorePermit,
    /// Shared reference to the limiter's configuration.
    config: Arc<ClientConfig>,
}

impl RndcPermit {
    /// Access the shared client configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};

    use super::*;
    use crate::config::ClientConfig;

    fn make_test_config() -> ClientConfig {
        let key = TsigKey::new(
            DomainName::new("rndc-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            vec![0xAA; 32],
        )
        .unwrap();
        ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: key,
            rndc_transport: crate::config::RndcTransportPolicy::LoopbackOnly,
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: Duration::from_secs(5),
            rndc_max_concurrent: None,
        }
    }

    #[tokio::test]
    async fn limiter_bounds_concurrency() {
        let limiter = RndcLimiter::new(make_test_config(), 2);
        assert_eq!(limiter.available(), 2);

        let _g1 = limiter.acquire().await.unwrap();
        assert_eq!(limiter.available(), 1);

        let _g2 = limiter.acquire().await.unwrap();
        assert_eq!(limiter.available(), 0);

        // Third acquire should timeout because the limiter is exhausted.
        let result = tokio::time::timeout(Duration::from_millis(50), limiter.acquire()).await;
        assert!(
            result.is_err(),
            "should timeout because limiter is exhausted"
        );
    }

    #[tokio::test]
    async fn permit_releases_slot_on_drop() {
        let limiter = RndcLimiter::new(make_test_config(), 1);
        {
            let _g = limiter.acquire().await.unwrap();
            assert_eq!(limiter.available(), 0);
        }
        // Guard dropped — slot should be available again.
        assert_eq!(limiter.available(), 1);
    }

    #[tokio::test]
    async fn zero_max_concurrent_defaults_to_four() {
        let limiter = RndcLimiter::new(make_test_config(), 0);
        assert_eq!(limiter.available(), DEFAULT_MAX_CONCURRENT);
    }

    #[tokio::test]
    async fn permit_exposes_config() {
        let limiter = RndcLimiter::new(make_test_config(), 1);
        let guard = limiter.acquire().await.unwrap();
        assert_eq!(guard.config().rndc_addr.port(), 953);
    }

    #[test]
    fn rndc_limiter_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RndcLimiter>();
        assert_send_sync::<RndcPermit>();
    }
}
