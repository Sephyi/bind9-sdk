// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

// Phase 1 — v0.1.0 implementation modules:
//
// pub mod rndc;      // rndc TCP wire protocol client — BIND9 custom framing + HMAC-SHA256 auth
// pub mod nsupdate;  // RFC 2136 dynamic update sender (UDP + TCP fallback with TSIG)
// pub mod error;     // NetError
//
// Phase 2 — v0.2.0:
// pub mod stats;     // BIND9 statistics-channel HTTP client (JSON parsing into typed structs)
//
// Phase 3 — v0.3.0:
// pub mod transfer;  // IXFR/AXFR zone transfer client
