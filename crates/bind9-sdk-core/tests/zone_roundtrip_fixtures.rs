// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! FR-062 representative master-file fixtures.
//!
//! Each fixture is a complete RFC 1035 master file exercising one or more
//! record types. For every fixture we assert the parse → serialize → re-parse
//! pipeline is **idempotent** (the serializer is a fixed point) and
//! **semantically stable** (the re-parsed zone equals the first parse). This is
//! the deterministic half of FR-062; the live "load into BIND9 → query" half is
//! covered by the ignored integration suite. Twenty-plus fixtures cover every
//! `RecordData` variant the serializer handles.

use bind9_sdk_core::ZoneFile;

/// (name, master-file text) — each must parse, then round-trip idempotently.
const FIXTURES: &[(&str, &str)] = &[
    (
        "minimal_soa_a",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN NS ns1\nns1 IN A 192.0.2.1\n",
    ),
    (
        "soa_parenthesized",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1.example.com. admin.example.com. (\n  2026010101 ; serial\n  7200 ; refresh\n  3600 ; retry\n  1209600 ; expire\n  3600 ) ; minimum\n@ IN NS ns1.example.com.\n",
    ),
    (
        "a_records",
        "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\nhost1 IN A 192.0.2.10\nhost2 IN A 192.0.2.11\nhost3 IN A 203.0.113.5\n",
    ),
    (
        "aaaa_records",
        "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\nv6a IN AAAA 2001:db8::1\nv6b IN AAAA 2001:db8:0:0:0:0:0:53\n",
    ),
    (
        "mx_records",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN MX 10 mail1\n@ IN MX 20 mail2.example.net.\n",
    ),
    (
        "cname_and_ns",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN NS ns1.example.net.\nwww IN CNAME web.example.net.\n",
    ),
    (
        "txt_simple_and_multi",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN TXT \"v=spf1 -all\"\nsplit IN TXT \"part-one\" \"part-two\"\n",
    ),
    (
        "txt_with_escapes",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\nesc IN TXT \"quote:\\\" and backslash kept\"\n",
    ),
    (
        "srv_records",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n_sip._tcp IN SRV 10 60 5060 sipserver.example.net.\n",
    ),
    (
        "caa_records",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN CAA 0 issue \"letsencrypt.org\"\n@ IN CAA 0 iodef \"mailto:security@example.com\"\n",
    ),
    (
        "ptr_reverse",
        "$ORIGIN 2.0.192.in-addr.arpa.\n$TTL 3600\n@ IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600\n10 IN PTR host10.example.com.\n",
    ),
    (
        "rp_record",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN RP admin.example.com. contact.example.com.\n",
    ),
    (
        "tlsa_record",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n_443._tcp IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    ),
    (
        "sshfp_record",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\nhost IN SSHFP 1 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    ),
    (
        "dnskey_record",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n",
    ),
    (
        "ds_record",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN DS 12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    ),
    (
        "cds_cdnskey",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN CDS 12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n@ IN CDNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n",
    ),
    (
        "rrsig_record",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN RRSIG A 13 2 3600 20260101000000 20251201000000 12345 example.com. abcdefABCDEF0123456789+/abcdefABCDEF0123456789+/AA==\n",
    ),
    (
        "nsec_record",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN NSEC mail.example.com. A NS SOA MX RRSIG NSEC DNSKEY\n",
    ),
    (
        "nsec3param_record",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN NSEC3PARAM 1 0 10 ABCDEF\n",
    ),
    (
        "csync_record",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN CSYNC 1 3 A NS AAAA\n",
    ),
    (
        "unknown_type_rfc3597",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n@ IN TYPE65280 \\# 4 0a000001\n",
    ),
    (
        "ttl_and_class_orderings",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\na1 300 IN A 192.0.2.20\na2 IN 300 A 192.0.2.21\na3 IN A 192.0.2.22\n",
    ),
    (
        "owner_inheritance",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\nmulti IN A 192.0.2.30\n     IN A 192.0.2.31\n     IN AAAA 2001:db8::30\n",
    ),
    (
        "kitchen_sink",
        "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1.example.com. admin.example.com. 2026010101 7200 3600 1209600 3600\n@ IN NS ns1.example.com.\n@ IN NS ns2.example.com.\n@ IN MX 10 mail.example.com.\n@ IN TXT \"v=spf1 mx -all\"\n@ IN CAA 0 issue \"letsencrypt.org\"\nns1 IN A 192.0.2.1\nns2 IN AAAA 2001:db8::2\nmail IN A 192.0.2.3\nwww IN CNAME @\n_sip._tcp IN SRV 10 20 5060 sip.example.com.\n",
    ),
];

#[test]
fn at_least_twenty_fixtures() {
    assert!(
        FIXTURES.len() >= 20,
        "FR-062 requires 20+ representative fixtures, found {}",
        FIXTURES.len()
    );
}

#[test]
fn every_fixture_parses() {
    for (name, text) in FIXTURES {
        ZoneFile::parse(text).unwrap_or_else(|e| panic!("fixture `{name}` failed to parse: {e}"));
    }
}

#[test]
fn every_fixture_roundtrips_idempotently() {
    for (name, text) in FIXTURES {
        let parsed1 = ZoneFile::parse(text)
            .unwrap_or_else(|e| panic!("fixture `{name}` failed to parse: {e}"));
        let serialized1 = parsed1.serialize();
        let parsed2 = ZoneFile::parse(&serialized1).unwrap_or_else(|e| {
            panic!("fixture `{name}` re-parse of serialized output failed: {e}")
        });
        let serialized2 = parsed2.serialize();

        assert_eq!(
            serialized1, serialized2,
            "fixture `{name}`: serialization is not a fixed point"
        );
        assert_eq!(
            parsed1.zone.records, parsed2.zone.records,
            "fixture `{name}`: re-parsed records differ from first parse"
        );
        assert!(
            !parsed1.zone.records.is_empty(),
            "fixture `{name}`: produced no records"
        );
    }
}
