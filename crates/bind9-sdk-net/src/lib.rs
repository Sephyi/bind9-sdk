// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Network layer for the BIND9 management SDK.
//!
//! Provides the concrete `tokio`-based implementations of the management
//! traits from `bind9-sdk-core`: the rndc TCP control-channel client, the
//! RFC 2136 nsupdate sender, the IXFR/AXFR (and XoT) transfer client, and the
//! statistics-channel HTTP client, plus connection pooling and concurrency
//! limiting. The high-level entry point is [`Bind9Client`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Client configuration and the high-level [`Bind9Client`].
pub mod config;
/// The network-layer error type [`NetError`].
pub mod error;
mod freeze;
/// Unstable fuzzing entry points (feature `fuzzing`); not semver-stable.
#[cfg(feature = "fuzzing")]
pub mod fuzz;
/// Fresh-cycle rndc concurrency limiting ([`RndcLimiter`]).
pub mod limiter;
/// RFC 2136 dynamic-update sender over UDP/TCP ([`NsUpdateSender`]).
pub mod nsupdate;
/// Persistent authenticated rndc connection pool ([`RndcPool`]).
pub mod pool;
/// rndc wire protocol client, typed command grammar, and DNSSEC helpers.
pub mod rndc;
/// BIND9 statistics-channel HTTP client ([`StatsHttpClient`]).
pub mod stats;
/// TLS 1.3 configuration for HTTPS statistics and XoT ([`TlsConfig`]).
pub mod tls;
/// IXFR/AXFR zone-transfer client ([`TransferClient`]).
pub mod transfer;

// Curated re-exports for common access
pub use config::{Bind9Client, ClientConfig, RndcTransportPolicy};
pub use error::NetError;
pub use freeze::FrozenZoneGuard;
pub use limiter::{RndcLimiter, RndcPermit};
pub use nsupdate::NsUpdateSender;
pub use pool::RndcPool;
pub use stats::StatsHttpClient;
pub use tls::TlsConfig;
pub use transfer::TransferClient;
