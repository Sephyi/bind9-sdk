// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod nsupdate;
pub mod pool;
pub mod rndc;
pub mod stats;
pub mod tls;
pub mod transfer;

// Curated re-exports for common access
pub use config::{Bind9Client, ClientConfig};
pub use error::NetError;
pub use nsupdate::NsUpdateSender;
pub use pool::{PoolGuard, RndcPool};
pub use stats::StatsHttpClient;
pub use tls::TlsConfig;
pub use transfer::TransferClient;
