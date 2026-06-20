// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
mod freeze;
pub mod limiter;
pub mod nsupdate;
pub mod pool;
pub mod rndc;
pub mod stats;
pub mod tls;
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
