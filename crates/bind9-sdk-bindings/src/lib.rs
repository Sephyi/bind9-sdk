// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! JavaScript/WASM bindings for bind9-sdk.
//!
//! **Browser WASM** (planned `browser` feature):
//! Exposes `bind9-sdk-core` types — zone parsing, record construction,
//! RFC 2136 message building. No network operations.
//!
//! **Node.js/Bun native addon** (`nodejs` feature, napi-rs v3):
//! Full bind9-sdk surface including rndc, nsupdate, IXFR/AXFR, and
//! statistics-channel. Built via `napi build --release`.

#[cfg(feature = "nodejs")]
mod domain;
#[cfg(feature = "nodejs")]
mod error;
#[cfg(feature = "nodejs")]
mod record;
#[cfg(feature = "nodejs")]
mod tsig;
#[cfg(feature = "nodejs")]
mod update;
#[cfg(feature = "nodejs")]
mod zone;

// Net-dependent modules: require `nodejs` feature (which pulls in bind9-sdk-net)
// and are excluded from WASM builds.
#[cfg(all(feature = "nodejs", not(target_arch = "wasm32")))]
mod nsupdate;
#[cfg(all(feature = "nodejs", not(target_arch = "wasm32")))]
mod pool;
#[cfg(all(feature = "nodejs", not(target_arch = "wasm32")))]
mod rndc;
#[cfg(all(feature = "nodejs", not(target_arch = "wasm32")))]
mod stats;
#[cfg(all(feature = "nodejs", not(target_arch = "wasm32")))]
mod transfer;
