// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! JavaScript/WASM bindings for bind9-sdk.
//!
//! **Browser WASM** (`wasm` feature):
//! Exposes `bind9-sdk-core` types — zone parsing, record construction,
//! RFC 2136 message building. No network operations.
//!
//! **Node.js/Bun native addon** (`nodejs` feature, napi-rs v3):
//! Full bind9-sdk surface including rndc, nsupdate, IXFR/AXFR, and
//! statistics-channel. Built via `napi build --release`.

#[cfg(any(feature = "nodejs", feature = "wasm"))]
mod domain;
#[cfg(any(feature = "nodejs", feature = "wasm"))]
mod error;
#[cfg(any(feature = "nodejs", feature = "wasm"))]
mod record;
#[cfg(any(feature = "nodejs", feature = "wasm"))]
mod tsig;
#[cfg(any(feature = "nodejs", feature = "wasm"))]
mod update;
#[cfg(any(feature = "nodejs", feature = "wasm"))]
mod zone;

// Net-dependent modules: require `nodejs` feature (which pulls in bind9-sdk-net)
// and are excluded from WASM builds.
#[cfg(all(feature = "nodejs", not(target_arch = "wasm32")))]
mod limiter;
#[cfg(all(feature = "nodejs", not(target_arch = "wasm32")))]
mod nsupdate;
#[cfg(all(feature = "nodejs", not(target_arch = "wasm32")))]
mod rndc;
#[cfg(all(feature = "nodejs", not(target_arch = "wasm32")))]
mod stats;
#[cfg(all(feature = "nodejs", not(target_arch = "wasm32")))]
mod transfer;
