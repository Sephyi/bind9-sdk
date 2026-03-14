// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

// Browser WASM bindings — feature = "browser" (wasm-pack, target wasm32-unknown-unknown)
//
// Exposes bind9-sdk-core types: zone parsing, record construction, RFC 2136 message building.
// TCP connections are unavailable in browser WASM — rndc, IXFR, and nsupdate-send are
// Node.js native only.
//
// Node.js native addon — feature = "nodejs" (napi-rs, native target)
//
// Exposes the full bind9-sdk surface including all network operations.
// Built via `npm run build` using napi-rs build toolchain.
// napi-rs auto-falls back to WASM when native binary is unavailable.
