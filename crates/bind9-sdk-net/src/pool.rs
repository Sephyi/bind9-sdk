// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Connection pool for concurrent rndc operations.
//!
//! rndc connections are not persistent — each command is a full
//! connect → auth → command → close cycle. The pool limits how many
//! of those cycles can run concurrently.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::ClientConfig;
use crate::error::NetError;

/// Default maximum concurrent rndc connections when `max_concurrent` is 0.
const DEFAULT_MAX_CONCURRENT: usize = 4;

/// Semaphore-based concurrency limiter for rndc connections.
///
/// Each [`acquire`](RndcPool::acquire) call returns a [`PoolGuard`] that holds
/// a semaphore permit and a reference to the shared config. The permit is
/// released when the guard is dropped, making the slot available for the next
/// caller.
///
/// `ClientConfig` is wrapped in [`Arc`] (not cloned) because [`TsigKey`]
/// intentionally does not implement `Clone` — key material must never be
/// duplicated.
///
/// [`TsigKey`]: bind9_sdk_core::tsig::TsigKey
pub struct RndcPool {
    config: Arc<ClientConfig>,
    semaphore: Arc<Semaphore>,
}

impl RndcPool {
    /// Create a new pool wrapping `config` with a concurrency limit of
    /// `max_concurrent` slots.
    ///
    /// If `max_concurrent` is `0` the pool defaults to
    /// [`DEFAULT_MAX_CONCURRENT`] (4) slots.
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
    /// Returns a [`PoolGuard`] that holds the slot until dropped.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Connection`] if the semaphore has been closed
    /// (which only happens if the pool itself is dropped while tasks are
    /// waiting — in practice this should not occur in normal usage).
    pub async fn acquire(&self) -> Result<PoolGuard, NetError> {
        let permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| NetError::Connection("connection pool closed".into()))?;
        Ok(PoolGuard {
            _permit: permit,
            config: Arc::clone(&self.config),
        })
    }

    /// Return the number of currently available (unacquired) slots.
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// A guard holding one slot in an [`RndcPool`].
///
/// The slot is released back to the pool when this guard is dropped.
/// Use [`config`](PoolGuard::config) to access the shared [`ClientConfig`]
/// for building an [`RndcConnection`].
///
/// [`RndcConnection`]: crate::rndc::RndcConnection
pub struct PoolGuard {
    /// Holds the semaphore permit for the duration of this guard's lifetime.
    _permit: OwnedSemaphorePermit,
    /// Shared reference to the pool's configuration.
    config: Arc<ClientConfig>,
}

impl PoolGuard {
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
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: Duration::from_secs(5),
            pool_size: None,
        }
    }

    #[tokio::test]
    async fn pool_limits_concurrency() {
        let pool = RndcPool::new(make_test_config(), 2);
        assert_eq!(pool.available(), 2);

        let _g1 = pool.acquire().await.unwrap();
        assert_eq!(pool.available(), 1);

        let _g2 = pool.acquire().await.unwrap();
        assert_eq!(pool.available(), 0);

        // Third acquire should timeout — pool exhausted.
        let result = tokio::time::timeout(Duration::from_millis(50), pool.acquire()).await;
        assert!(result.is_err(), "should timeout — pool exhausted");
    }

    #[tokio::test]
    async fn pool_releases_on_drop() {
        let pool = RndcPool::new(make_test_config(), 1);
        {
            let _g = pool.acquire().await.unwrap();
            assert_eq!(pool.available(), 0);
        }
        // Guard dropped — slot should be available again.
        assert_eq!(pool.available(), 1);
    }

    #[tokio::test]
    async fn zero_max_concurrent_defaults_to_four() {
        let pool = RndcPool::new(make_test_config(), 0);
        assert_eq!(pool.available(), DEFAULT_MAX_CONCURRENT);
    }

    #[tokio::test]
    async fn guard_exposes_config() {
        let pool = RndcPool::new(make_test_config(), 1);
        let guard = pool.acquire().await.unwrap();
        assert_eq!(guard.config().rndc_addr.port(), 953);
    }

    #[test]
    fn rndc_pool_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RndcPool>();
        assert_send_sync::<PoolGuard>();
    }
}
