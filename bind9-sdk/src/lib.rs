// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # bind9-sdk
//!
//! Rust SDK for programmatic BIND9 DNS server management.
//!
//! Implements the full rndc wire protocol, RFC 1035 zone file parsing and serialization,
//! RFC 2136 dynamic updates (nsupdate), IXFR/AXFR zone transfer, and the BIND9
//! statistics-channel JSON API — with zero shell subprocess dependencies.
//!
//! ## Feature flags
//!
//! - `net` *(default)*: includes `bind9-sdk-net` for rndc, nsupdate, IXFR/AXFR, stats HTTP.
//!   Disable with `default-features = false` if you only need zone file parsing or
//!   RFC 2136 message construction in a `no_std` context.
//!
//! ## Workspace crates
//!
//! | Crate | Role |
//! |---|---|
//! | `bind9-sdk-core` | `no_std + alloc`: DNS types, zone parsing, RFC 2136 construction, TSIG |
//! | `bind9-sdk-net` | tokio: rndc TCP, nsupdate send, IXFR/AXFR, stats HTTP |
//! | `bind9-sdk-bindings` | wasm-bindgen (browser) + napi-rs (Node.js) |

/// Core DNS types, zone parsing, and RFC 2136 message construction.
///
/// This module is `no_std` compatible — safe to use in WASM and embedded contexts.
pub use bind9_sdk_core as core;

/// Network operations: rndc TCP wire protocol, nsupdate sender, IXFR/AXFR, statistics HTTP.
///
/// Requires `feature = "net"` (enabled by default).
#[cfg(feature = "net")]
pub use bind9_sdk_net as net;
