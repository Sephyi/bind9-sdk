// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Persistent authenticated rndc connection pool.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::timeout;

use bind9_sdk_core::tsig::TsigKey;

use crate::config::{ClientConfig, RndcTransportPolicy};
use crate::error::NetError;
use crate::rndc::command::{RndcCommand, RndcResponse};
use crate::rndc::{RndcConnection, SharedAuthenticated};

const DEFAULT_POOL_SIZE: usize = 4;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

struct PoolJob {
    command: RndcCommand,
    response: oneshot::Sender<Result<RndcResponse, NetError>>,
}

struct PoolConnectionConfig {
    address: SocketAddr,
    key: Arc<TsigKey>,
    operation_timeout: Duration,
    transport_policy: RndcTransportPolicy,
}

struct PoolInner {
    workers: Vec<mpsc::Sender<PoolJob>>,
    available_rx: Mutex<mpsc::Receiver<usize>>,
    available_tx: mpsc::Sender<usize>,
    available_count: Arc<AtomicUsize>,
    connections_created: Arc<AtomicU64>,
}

/// Pool of persistent, authenticated rndc connections.
///
/// Each worker owns one reusable rndc connection. Failed connections are
/// discarded and retried once, and idle connections are closed after the
/// configured timeout. Cloning the pool shares the same workers.
#[derive(Clone)]
pub struct RndcPool {
    inner: Arc<PoolInner>,
}

impl RndcPool {
    /// Create a persistent rndc connection pool.
    ///
    /// `size == 0` selects the default of four workers. An `idle_timeout` of
    /// zero selects the default of 30 seconds.
    pub fn new(
        config: ClientConfig,
        size: usize,
        idle_timeout: Duration,
    ) -> Result<Self, NetError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            NetError::Connection(format!(
                "RndcPool must be created inside a Tokio runtime: {error}"
            ))
        })?;
        let configured_size = config
            .rndc_max_concurrent
            .filter(|configured| *configured > 0)
            .unwrap_or(DEFAULT_POOL_SIZE);
        let size = if size == 0 { configured_size } else { size };
        let idle_timeout = if idle_timeout.is_zero() {
            DEFAULT_IDLE_TIMEOUT
        } else {
            idle_timeout
        };
        let connection_config = Arc::new(PoolConnectionConfig {
            address: config.rndc_addr,
            key: Arc::new(config.rndc_key),
            operation_timeout: config.timeout,
            transport_policy: config.rndc_transport,
        });

        let (available_tx, available_rx) = mpsc::channel(size);
        let available_count = Arc::new(AtomicUsize::new(size));
        let connections_created = Arc::new(AtomicU64::new(0));
        let mut workers = Vec::with_capacity(size);

        for index in 0..size {
            let (worker_tx, worker_rx) = mpsc::channel(1);
            workers.push(worker_tx);
            available_tx.try_send(index).map_err(|error| {
                NetError::Connection(format!("failed to initialize rndc pool: {error}"))
            })?;
            runtime.spawn(pool_worker(
                index,
                worker_rx,
                Arc::clone(&connection_config),
                idle_timeout,
                available_tx.clone(),
                Arc::clone(&available_count),
                Arc::clone(&connections_created),
            ));
        }

        Ok(Self {
            inner: Arc::new(PoolInner {
                workers,
                available_rx: Mutex::new(available_rx),
                available_tx,
                available_count,
                connections_created,
            }),
        })
    }

    /// Execute one command on an available persistent connection.
    pub async fn execute(&self, command: RndcCommand) -> Result<RndcResponse, NetError> {
        let worker_index = self
            .inner
            .available_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| NetError::Connection("rndc pool is closed".into()))?;
        self.inner.available_count.fetch_sub(1, Ordering::AcqRel);

        let (response_tx, response_rx) = oneshot::channel();
        let job = PoolJob {
            command,
            response: response_tx,
        };
        if self.inner.workers[worker_index].send(job).await.is_err() {
            self.release_worker(worker_index).await;
            return Err(NetError::Connection("rndc pool worker stopped".into()));
        }

        response_rx
            .await
            .map_err(|_| NetError::Connection("rndc pool worker dropped response".into()))?
    }

    /// Number of workers currently available to execute a command.
    pub fn available(&self) -> usize {
        self.inner.available_count.load(Ordering::Acquire)
    }

    /// Number of TCP connections successfully created by this pool.
    ///
    /// This operational counter is useful for verifying reuse and monitoring
    /// reconnect churn.
    pub fn total_connections_created(&self) -> u64 {
        self.inner.connections_created.load(Ordering::Acquire)
    }

    async fn release_worker(&self, worker_index: usize) {
        if self.inner.available_tx.send(worker_index).await.is_ok() {
            self.inner.available_count.fetch_add(1, Ordering::AcqRel);
        }
    }
}

async fn pool_worker(
    index: usize,
    mut jobs: mpsc::Receiver<PoolJob>,
    config: Arc<PoolConnectionConfig>,
    idle_timeout: Duration,
    available_tx: mpsc::Sender<usize>,
    available_count: Arc<AtomicUsize>,
    connections_created: Arc<AtomicU64>,
) {
    let mut connection: Option<RndcConnection<SharedAuthenticated>> = None;

    loop {
        let job = if connection.is_some() {
            match timeout(idle_timeout, jobs.recv()).await {
                Ok(job) => job,
                Err(_) => {
                    if let Some(connection) = connection.take() {
                        let _ = connection.close_shared().await;
                    }
                    continue;
                }
            }
        } else {
            jobs.recv().await
        };

        let Some(job) = job else {
            if let Some(connection) = connection.take() {
                let _ = connection.close_shared().await;
            }
            return;
        };

        let result =
            execute_with_reconnect(&mut connection, &config, &connections_created, job.command)
                .await;
        if available_tx.send(index).await.is_err() {
            let _ = job.response.send(Err(NetError::Connection(
                "rndc pool availability queue closed".into(),
            )));
            return;
        }
        available_count.fetch_add(1, Ordering::AcqRel);
        let _ = job.response.send(result);
    }
}

async fn execute_with_reconnect(
    connection: &mut Option<RndcConnection<SharedAuthenticated>>,
    config: &PoolConnectionConfig,
    connections_created: &AtomicU64,
    command: RndcCommand,
) -> Result<RndcResponse, NetError> {
    for attempt in 0..=1 {
        if connection.is_none() {
            *connection = Some(connect_authenticated(config, connections_created).await?);
        }
        let Some(active) = connection.as_mut() else {
            return Err(NetError::Connection(
                "rndc pool failed to initialize a connection".into(),
            ));
        };

        let result = timeout(
            config.operation_timeout,
            active.command_shared(command.clone()),
        )
        .await
        .map_err(|_| NetError::Timeout(config.operation_timeout))
        .and_then(|result| result);

        match result {
            Ok(response) => return Ok(response),
            Err(error) if attempt == 0 => {
                tracing::warn!("pooled rndc connection failed; reconnecting once: {error}");
                connection.take();
            }
            Err(error) => return Err(error),
        }
    }

    Err(NetError::Connection(
        "rndc pool retry loop completed unexpectedly".into(),
    ))
}

async fn connect_authenticated(
    config: &PoolConnectionConfig,
    connections_created: &AtomicU64,
) -> Result<RndcConnection<SharedAuthenticated>, NetError> {
    let connection = timeout(config.operation_timeout, async {
        match config.transport_policy {
            RndcTransportPolicy::LoopbackOnly => RndcConnection::connect(config.address).await,
            RndcTransportPolicy::ProtectedNetwork => {
                RndcConnection::connect_insecure(config.address).await
            }
        }
    })
    .await
    .map_err(|_| NetError::Timeout(config.operation_timeout))??;
    let connection = timeout(
        config.operation_timeout,
        connection.authenticate_shared(Arc::clone(&config.key)),
    )
    .await
    .map_err(|_| NetError::Timeout(config.operation_timeout))??;
    connections_created.fetch_add(1, Ordering::AcqRel);
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};

    use super::*;

    fn test_config() -> ClientConfig {
        let key = TsigKey::new(
            DomainName::new("rndc-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            vec![0xAA; 32],
        )
        .unwrap();
        ClientConfig::new("127.0.0.1:953".parse().unwrap(), key)
    }

    #[test]
    fn creation_without_tokio_runtime_is_fallible() {
        let error = match RndcPool::new(test_config(), 1, Duration::from_secs(30)) {
            Ok(_) => panic!("pool creation outside Tokio must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("Tokio runtime"));
    }

    #[tokio::test]
    async fn zero_size_uses_client_config_limit() {
        let mut config = test_config();
        config.rndc_max_concurrent = Some(2);
        let pool = RndcPool::new(config, 0, Duration::from_secs(30)).unwrap();
        assert_eq!(pool.available(), 2);
        assert_eq!(pool.total_connections_created(), 0);
    }

    #[test]
    fn rndc_pool_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RndcPool>();
    }
}
