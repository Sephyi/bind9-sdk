// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod domain;
pub mod error;
pub mod rdata;
pub mod record;
pub mod traits;

// Curated re-exports for common access
pub use domain::{DomainName, Label};
pub use error::CoreError;
pub use rdata::RecordData;
pub use record::{RecordClass, ResourceRecord, Serial, Ttl};
pub use traits::{DynamicUpdater, NamedControl, StatsClient, ZoneManager};
