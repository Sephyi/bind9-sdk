// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

pub mod config;
pub mod error;
pub mod nsupdate;
pub mod rndc;
pub mod stats;
pub mod tls;

// Curated re-exports for common access
pub use config::{Bind9Client, ClientConfig};
pub use error::NetError;
pub use nsupdate::NsUpdateSender;
pub use stats::StatsHttpClient;
pub use tls::TlsConfig;
