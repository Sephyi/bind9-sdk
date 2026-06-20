// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! FR-061: parse -> serialize -> parse idempotence property fuzz target.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    bind9_sdk_core::fuzz::zone_roundtrip(data);
});
