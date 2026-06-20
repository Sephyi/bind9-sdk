// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Unstable fuzzing entry points (feature `fuzzing`).
//!
//! Thin wrappers that feed arbitrary bytes into the network-layer parsers so
//! the out-of-tree `fuzz/` cargo-fuzz workspace can target them. Each must
//! never panic on any input. **Not** part of the public, semver-stable API.

use crate::rndc::protocol::IscMessage;
use crate::stats::{RawServerStats, RawZonesResponse};
use crate::transfer::wire;

/// Drive the rndc ISC control-message (response) binary decoder.
///
/// This is the `fuzz_rndc_response` target: BIND's rndc replies are ISC
/// association lists framed as `[4-byte version][typed key/value table]`.
pub fn rndc_response(data: &[u8]) {
    let _ = IscMessage::decode(data);
}

/// Drive the statistics-channel JSON deserializers (server + zones endpoints).
pub fn stats_json(data: &[u8]) {
    let _ = serde_json::from_slice::<RawServerStats>(data);
    let _ = serde_json::from_slice::<RawZonesResponse>(data);
}

/// Drive the AXFR/IXFR DNS wire parsers: header, then a resource record read
/// from offset 0 (which itself exercises name decompression and rdata parsing).
pub fn transfer_wire(data: &[u8]) {
    let _ = wire::DnsHeader::parse(data);
    let _ = wire::parse_resource_record(data, 0);
    let _ = wire::parse_name(data, 0);
}

/// Drive the nsupdate DNS UPDATE response header parser.
pub fn update_response(data: &[u8]) {
    let _ = crate::nsupdate::parse_dns_response(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Adversarial byte inputs every wire/JSON parser must survive. New
    /// fuzz-discovered crashes are appended here as permanent regressions.
    fn adversarial_inputs() -> Vec<Vec<u8>> {
        vec![
            Vec::new(),
            vec![0u8],
            vec![0xff; 4096],
            // ISC message version header followed by truncated table entries.
            vec![0x00, 0x00, 0x00, 0x01, 0x05],
            vec![0x00, 0x00, 0x00, 0x01],
            // DNS-shaped headers with maximal section counts to stress loops.
            vec![
                0x12, 0x34, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
            // Compression-pointer loop bait.
            vec![0xc0, 0x00, 0xc0, 0x00],
            b"{}".to_vec(),
            b"[]".to_vec(),
            b"{\"json-stats-version\":".to_vec(),
            b"{\"views\":{\"_default\":{\"zones\":[]}}}".to_vec(),
            vec![b'{'; 10_000],
        ]
    }

    #[test]
    fn entry_points_never_panic() {
        for input in adversarial_inputs() {
            rndc_response(&input);
            stats_json(&input);
            transfer_wire(&input);
            update_response(&input);
        }
    }

    #[test]
    fn valid_stats_json_seed() {
        let server = br#"{"json-stats-version":"1.7","boot-time":"2026-01-01T00:00:00Z"}"#;
        stats_json(server);
        let zones = br#"{"views":{"_default":{"zones":[{"name":"example.com","serial":1}]}}}"#;
        stats_json(zones);
    }
}
