// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Unstable fuzzing entry points (feature `fuzzing`).
//!
//! These thin wrappers feed arbitrary bytes into the crate's parsers so the
//! out-of-tree `fuzz/` cargo-fuzz workspace can target them. Each function must
//! never panic on any input — that is precisely the invariant the fuzzer
//! checks. They are **not** part of the public, semver-stable API.

use crate::{NamedConf, TsigRecord, ZoneFile};
use alloc::string::String;

/// Drive the RFC 1035 master-file (zone) parser with arbitrary bytes.
pub fn zone(data: &[u8]) {
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = ZoneFile::parse(text);
    }
}

/// Drive the bounded `named.conf` parser with arbitrary bytes.
pub fn named_conf(data: &[u8]) {
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = NamedConf::parse("fuzz.conf", text);
    }
}

/// Drive the TSIG resource-record wire parser with arbitrary bytes.
pub fn tsig_wire(data: &[u8]) {
    let _ = TsigRecord::parse_from_wire(data);
}

/// Round-trip property: any zone text that parses must re-serialize and
/// re-parse to an equal zone. Catches serializer/parser asymmetry.
pub fn zone_roundtrip(data: &[u8]) {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = ZoneFile::parse(text) else {
        return;
    };
    let serialized: String = parsed.serialize();
    match ZoneFile::parse(&serialized) {
        Ok(reparsed) => {
            // Re-serialization must be a fixed point.
            assert_eq!(
                serialized,
                reparsed.serialize(),
                "zone serialization is not idempotent"
            );
        }
        Err(e) => panic!("re-parse of serialized zone failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Adversarial byte inputs every parser must survive without panicking.
    /// New fuzz-discovered crashes are appended here as permanent regressions.
    fn adversarial_inputs() -> Vec<Vec<u8>> {
        let mut cases: Vec<Vec<u8>> = alloc::vec![
            Vec::new(),
            alloc::vec![0u8],
            alloc::vec![0xff; 1024],
            alloc::vec![b'$'; 256],
            b"\xc0\xc0\xc0\xc0".to_vec(),
            b"$ORIGIN".to_vec(),
            b"$TTL".to_vec(),
            b"@ IN SOA".to_vec(),
            b"key \"k\" { algorithm; secret; };".to_vec(),
            b"zone \"".to_vec(),
            b"{{{{{{{{{{{{{{{{".to_vec(),
            b";".to_vec(),
            b"\n\n\n\n\r\r\t\t  ".to_vec(),
        ];
        // Deeply nested / repeated structures that stress recursion bounds.
        cases.push(b"a".repeat(100_000));
        cases.push(b"(".repeat(10_000));
        // Regression: many newlines inside an open paren previously recursed
        // per newline and overflowed the stack. Must scan iteratively now.
        let mut parens_newlines = b"@ IN SOA ns admin (\n".to_vec();
        parens_newlines.extend(core::iter::repeat_n(b'\n', 200_000));
        cases.push(parens_newlines);
        // Regression: long comment run previously recursed per comment line.
        cases.push(b";\n".repeat(100_000));
        cases
    }

    #[test]
    fn entry_points_never_panic() {
        for input in adversarial_inputs() {
            zone(&input);
            named_conf(&input);
            tsig_wire(&input);
            zone_roundtrip(&input);
        }
    }

    #[test]
    fn valid_zone_seed_roundtrips() {
        let sample = b"$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 2 3 4 5\n@ IN NS ns1\nns1 IN A 192.0.2.1\n";
        zone(sample);
        zone_roundtrip(sample);
    }

    #[test]
    fn valid_named_conf_seed() {
        let sample = b"options { directory \"/var/named\"; };\nzone \"example.com\" { type primary; file \"e.zone\"; };\n";
        named_conf(sample);
    }
}
