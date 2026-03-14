// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![no_std]

extern crate alloc;

// Phase 1 — v0.1.0 implementation modules:
//
// pub mod domain;   // DomainName, Label — RFC 1035 §2.3 wire encoding and text form
// pub mod record;   // ResourceRecord, RecordData, RecordType (A, AAAA, MX, TXT, CNAME, ...)
// pub mod zone;     // Zone, ZoneSummary, ZoneStatus
// pub mod update;   // RFC 2136 dynamic update message construction
// pub mod tsig;     // TSIG signing — RFC 8945, HMAC-SHA256/SHA512 via RustCrypto
// pub mod error;    // CoreError
