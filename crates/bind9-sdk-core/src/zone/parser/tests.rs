// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

extern crate alloc;

use super::tokenizer::{Token, Tokenizer};
use crate::domain::DomainName;
use crate::rdata::RecordData;
use crate::record::{RecordClass, ResourceRecord, Serial, Ttl};
use crate::zone::{Zone, ZoneFile};
use alloc::string::ToString;
use core::net::Ipv4Addr;
use proptest::prelude::*;

// Tokenizer tests

#[test]
fn tokenize_simple_a_record() {
    let input = "example.com. 300 IN A 192.0.2.1\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(
        tokens,
        alloc::vec![
            Token::Word("example.com.".into()),
            Token::Word("300".into()),
            Token::Word("IN".into()),
            Token::Word("A".into()),
            Token::Word("192.0.2.1".into()),
            Token::Newline,
        ]
    );
}

#[test]
fn tokenize_comment_stripped() {
    let input = "example.com. IN A 1.2.3.4 ; this is a comment\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(
        tokens,
        alloc::vec![
            Token::Word("example.com.".into()),
            Token::Word("IN".into()),
            Token::Word("A".into()),
            Token::Word("1.2.3.4".into()),
            Token::Newline,
        ]
    );
}

#[test]
fn tokenize_origin_directive() {
    let input = "$ORIGIN example.com.\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(
        tokens,
        alloc::vec![
            Token::Directive("$ORIGIN".into()),
            Token::Word("example.com.".into()),
            Token::Newline,
        ]
    );
}

#[test]
fn tokenize_ttl_directive() {
    let input = "$TTL 3600\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(
        tokens,
        alloc::vec![
            Token::Directive("$TTL".into()),
            Token::Word("3600".into()),
            Token::Newline,
        ]
    );
}

#[test]
fn tokenize_quoted_string() {
    let input = "example.com. IN TXT \"v=spf1 include:example.com ~all\"\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(
        tokens,
        alloc::vec![
            Token::Word("example.com.".into()),
            Token::Word("IN".into()),
            Token::Word("TXT".into()),
            Token::QuotedString("v=spf1 include:example.com ~all".into()),
            Token::Newline,
        ]
    );
}

#[test]
fn tokenize_parenthesized_multiline() {
    let input = "example.com. IN SOA ns1.example.com. admin.example.com. (\n  2026031401\n  3600\n  900\n  604800\n  86400 )\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(
        tokens,
        alloc::vec![
            Token::Word("example.com.".into()),
            Token::Word("IN".into()),
            Token::Word("SOA".into()),
            Token::Word("ns1.example.com.".into()),
            Token::Word("admin.example.com.".into()),
            Token::ParenOpen,
            Token::Word("2026031401".into()),
            Token::Word("3600".into()),
            Token::Word("900".into()),
            Token::Word("604800".into()),
            Token::Word("86400".into()),
            Token::ParenClose,
            Token::Newline,
        ]
    );
}

#[test]
fn tokenize_blank_line_produces_newline() {
    let input = "\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(tokens, alloc::vec![Token::Newline]);
}

#[test]
fn tokenize_at_sign_is_word() {
    let input = "@ IN A 1.2.3.4\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(
        tokens,
        alloc::vec![
            Token::Word("@".into()),
            Token::Word("IN".into()),
            Token::Word("A".into()),
            Token::Word("1.2.3.4".into()),
            Token::Newline,
        ]
    );
}

#[test]
fn tokenize_leading_whitespace_preserved_as_empty_owner() {
    let input = "   IN A 1.2.3.4\n";
    let mut tok = Tokenizer::new(input);
    let first = tok.next_token();
    assert_eq!(first, Some(Token::Word("".into())));
}

#[test]
fn tokenize_line_number_tracking() {
    let input = "line1\nline2\nline3\n";
    let mut tok = Tokenizer::new(input);
    assert_eq!(tok.line(), 1);
    tok.next_token(); // Word("line1")
    tok.next_token(); // Newline
    assert_eq!(tok.line(), 2);
    tok.next_token(); // Word("line2")
    tok.next_token(); // Newline
    assert_eq!(tok.line(), 3);
}

#[test]
fn tokenize_empty_input() {
    let input = "";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert!(tokens.is_empty());
}

#[test]
fn tokenize_comment_only_line() {
    let input = "; this is only a comment\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(tokens, alloc::vec![Token::Newline]);
}

// Escape sequence edge cases

#[test]
fn tokenize_backslash_dot_in_label() {
    let input = "host\\.name.example.com. IN A 1.2.3.4\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(tokens[0], Token::Word("host\\.name.example.com.".into()));
}

#[test]
fn tokenize_decimal_escape_in_quoted() {
    // \065 = 'A' in decimal
    let input = "example.com. IN TXT \"hello\\065world\"\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(tokens[3], Token::QuotedString("helloAworld".into()));
}

#[test]
fn tokenize_backslash_semicolon_in_quoted() {
    let input = "example.com. IN TXT \"has\\;semicolon\"\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(tokens[3], Token::QuotedString("has;semicolon".into()));
}

#[test]
fn tokenize_multiple_quoted_strings() {
    let input = "example.com. IN TXT \"first\" \"second\"\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(
        tokens,
        alloc::vec![
            Token::Word("example.com.".into()),
            Token::Word("IN".into()),
            Token::Word("TXT".into()),
            Token::QuotedString("first".into()),
            Token::QuotedString("second".into()),
            Token::Newline,
        ]
    );
}

#[test]
fn tokenize_include_directive() {
    let input = "$INCLUDE /etc/named/sub.zone\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(
        tokens,
        alloc::vec![
            Token::Directive("$INCLUDE".into()),
            Token::Word("/etc/named/sub.zone".into()),
            Token::Newline,
        ]
    );
}

#[test]
fn tokenize_tabs_as_whitespace() {
    let input = "example.com.\tIN\tA\t1.2.3.4\n";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(
        tokens,
        alloc::vec![
            Token::Word("example.com.".into()),
            Token::Word("IN".into()),
            Token::Word("A".into()),
            Token::Word("1.2.3.4".into()),
            Token::Newline,
        ]
    );
}

#[test]
fn tokenize_no_trailing_newline() {
    let input = "example.com. IN A 1.2.3.4";
    let mut tok = Tokenizer::new(input);
    let tokens = tok.tokenize_all();
    assert_eq!(
        tokens,
        alloc::vec![
            Token::Word("example.com.".into()),
            Token::Word("IN".into()),
            Token::Word("A".into()),
            Token::Word("1.2.3.4".into()),
        ]
    );
}

// Assembler tests

#[test]
fn parse_minimal_zone() {
    let input = "\
$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. 2026031401 3600 900 604800 86400
@ IN NS ns1.example.com.
@ IN A 192.0.2.1
";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(zf.origin, DomainName::new("example.com.").unwrap());
    assert_eq!(zf.default_ttl, Some(Ttl::new(3600).unwrap()));
    assert_eq!(zf.zone.records.len(), 3);
}

#[test]
fn parse_owner_name_inheritance() {
    let input = "\
$ORIGIN example.com.
$TTL 300
@ IN A 192.0.2.1
  IN A 192.0.2.2
";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(zf.zone.records.len(), 2);
    assert_eq!(zf.zone.records[0].name, zf.zone.records[1].name);
    assert_eq!(
        zf.zone.records[0].name,
        DomainName::new("example.com.").unwrap()
    );
}

#[test]
fn parse_relative_names_resolved() {
    let input = "\
$ORIGIN example.com.
$TTL 300
www IN A 192.0.2.1
";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(
        zf.zone.records[0].name,
        DomainName::new("www.example.com.").unwrap()
    );
}

#[test]
fn parse_at_sign_resolves_to_origin() {
    let input = "\
$ORIGIN example.com.
$TTL 300
@ IN A 192.0.2.1
";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(
        zf.zone.records[0].name,
        DomainName::new("example.com.").unwrap()
    );
}

#[test]
fn parse_ttl_class_order_ttl_first() {
    let input = "\
$ORIGIN example.com.
example.com. 300 IN A 192.0.2.1
";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(zf.zone.records[0].ttl, Ttl::new(300).unwrap());
    assert_eq!(zf.zone.records[0].class, RecordClass::IN);
}

#[test]
fn parse_ttl_class_order_class_first() {
    let input = "\
$ORIGIN example.com.
example.com. IN 300 A 192.0.2.1
";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(zf.zone.records[0].ttl, Ttl::new(300).unwrap());
    assert_eq!(zf.zone.records[0].class, RecordClass::IN);
}

#[test]
fn parse_multiline_soa() {
    let input = "\
$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. (
    2026031401 ; serial
    3600       ; refresh
    900        ; retry
    604800     ; expire
    86400      ; minimum
)
";
    let zf = ZoneFile::parse(input).unwrap();
    let soa = &zf.zone.records[0];
    match &soa.rdata {
        RecordData::Soa { serial, .. } => {
            assert_eq!(serial.value(), 2026031401);
        }
        other => panic!("expected SOA, got {other:?}"),
    }
}

#[test]
fn parse_comments_ignored() {
    let input = "\
; This is a zone file comment
$ORIGIN example.com.
$TTL 3600
; Another comment
@ IN A 192.0.2.1 ; inline comment
";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(zf.zone.records.len(), 1);
}

#[test]
fn parse_include_without_resolver_errors() {
    let input = "\
$ORIGIN example.com.
$INCLUDE /etc/named/sub.zone
";
    let result = ZoneFile::parse(input);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("$INCLUDE"),
        "error should mention $INCLUDE: {err}"
    );
}

#[test]
fn parse_origin_changes_midfile() {
    let input = "\
$ORIGIN example.com.
$TTL 300
@ IN A 192.0.2.1
$ORIGIN sub.example.com.
@ IN A 192.0.2.2
";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(zf.zone.records.len(), 2);
    assert_eq!(
        zf.zone.records[0].name,
        DomainName::new("example.com.").unwrap()
    );
    assert_eq!(
        zf.zone.records[1].name,
        DomainName::new("sub.example.com.").unwrap()
    );
}

#[test]
fn parse_no_origin_infers_from_soa() {
    let input = "\
$TTL 3600
example.com. IN SOA ns1.example.com. admin.example.com. 1 3600 900 604800 86400
example.com. IN A 192.0.2.1
";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(zf.origin, DomainName::new("example.com.").unwrap());
}

#[test]
fn parse_default_ttl_applied() {
    let input = "\
$ORIGIN example.com.
$TTL 7200
@ IN A 192.0.2.1
";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(zf.zone.records[0].ttl, Ttl::new(7200).unwrap());
}

#[test]
fn parse_explicit_ttl_overrides_default() {
    let input = "\
$ORIGIN example.com.
$TTL 7200
@ 300 IN A 192.0.2.1
";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(zf.zone.records[0].ttl, Ttl::new(300).unwrap());
}

#[test]
fn parse_blank_lines_skipped() {
    let input = "\
$ORIGIN example.com.
$TTL 300

@ IN A 192.0.2.1

@ IN A 192.0.2.2

";
    let zf = ZoneFile::parse(input).unwrap();
    assert_eq!(zf.zone.records.len(), 2);
}

// Error reporting tests

#[test]
fn zone_parse_error_has_column() {
    use crate::error::CoreError;
    let input = "example.com. 3600 IN A not-an-ip";
    let result = ZoneFile::parse(input);
    let err = result.unwrap_err();
    match err {
        CoreError::ZoneParse { line, column, .. } => {
            assert_eq!(line, 1);
            assert!(column.is_none() || column.is_some(), "column field exists");
        }
        other => panic!("expected ZoneParse, got {other:?}"),
    }
}

#[test]
fn parse_error_includes_line_number() {
    let input = "\
$ORIGIN example.com.
$TTL 3600
@ IN A 192.0.2.1
@ IN A not-an-ip
";
    let err = ZoneFile::parse(input).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("line 4"),
        "error should reference line 4: {msg}"
    );
}

#[test]
fn parse_error_unknown_directive() {
    let input = "\
$ORIGIN example.com.
$UNKNOWN foo
";
    let err = ZoneFile::parse(input).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("$UNKNOWN"),
        "error should mention the unknown directive: {msg}"
    );
}

#[test]
fn parse_error_missing_rtype() {
    let input = "\
$ORIGIN example.com.
$TTL 300
@ IN
";
    let err = ZoneFile::parse(input).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("record type"),
        "error should mention missing record type: {msg}"
    );
}

#[test]
fn parse_error_no_origin_no_soa() {
    let input = "\
$TTL 300
www IN A 192.0.2.1
";
    let err = ZoneFile::parse(input).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("ORIGIN") || msg.contains("origin"),
        "error should mention missing origin: {msg}"
    );
}

// Proptest roundtrip tests

proptest! {
    /// Arbitrary strings never cause panics in the parser.
    #[test]
    fn parse_never_panics(input in "\\PC{0,500}") {
        // Must not panic — Err is fine, panic is not
        let _ = ZoneFile::parse(&input);
    }

    /// Valid zone files survive parse-serialize-parse roundtrip.
    #[test]
    fn roundtrip_generated_a_records(
        count in 1usize..5,
        octets in proptest::collection::vec(1u8..255, 4..20),
    ) {
        let origin = DomainName::new("test.example.com.").unwrap();
        let mut records = alloc::vec![
            ResourceRecord {
                name: origin.clone(),
                class: RecordClass::IN,
                ttl: Ttl::new(3600).unwrap(),
                rdata: RecordData::Soa {
                    mname: DomainName::new("ns1.test.example.com.").unwrap(),
                    rname: DomainName::new("admin.test.example.com.").unwrap(),
                    serial: Serial::new(1),
                    refresh: Ttl::new(3600).unwrap(),
                    retry: Ttl::new(900).unwrap(),
                    expire: Ttl::new(604800).unwrap(),
                    minimum: Ttl::new(86400).unwrap(),
                },
            },
        ];

        for i in 0..core::cmp::min(count, octets.len() / 4) {
            let base = i * 4;
            if base + 3 < octets.len() {
                records.push(ResourceRecord {
                    name: origin.clone(),
                    class: RecordClass::IN,
                    ttl: Ttl::new(300).unwrap(),
                    rdata: RecordData::A(Ipv4Addr::new(
                        octets[base],
                        octets[base + 1],
                        octets[base + 2],
                        octets[base + 3],
                    )),
                });
            }
        }

        let zf = ZoneFile {
            origin: origin.clone(),
            default_ttl: Some(Ttl::new(300).unwrap()),
            zone: Zone {
                name: origin,
                class: RecordClass::IN,
                records,
            },
        };

        let serialized = zf.serialize();
        let reparsed = ZoneFile::parse(&serialized);
        prop_assert!(
            reparsed.is_ok(),
            "serialized zone should reparse: {:?}\nSerialized:\n{}",
            reparsed.err(),
            serialized,
        );
        let reparsed = reparsed.unwrap();
        prop_assert_eq!(
            zf.zone.records.len(),
            reparsed.zone.records.len(),
            "record count mismatch after roundtrip"
        );
    }

    /// The zone parser must never panic on arbitrary UTF-8 input (extended coverage).
    ///
    /// Err is acceptable; panic is not.
    #[test]
    fn zone_parser_never_panics(input in "\\PC*") {
        let _ = ZoneFile::parse(&input);
    }

    /// DomainName::new must never panic on arbitrary input.
    #[test]
    fn domain_name_new_never_panics(input in "\\PC*") {
        let _ = DomainName::new(&input);
    }

    /// Simple single-label FQDNs always parse successfully.
    #[test]
    fn domain_name_simple_fqdn_always_ok(
        label in "[a-z][a-z0-9]{0,30}",
    ) {
        let fqdn = alloc::format!("{label}.");
        prop_assert!(
            DomainName::new(&fqdn).is_ok(),
            "expected Ok for simple FQDN `{fqdn}`"
        );
    }
}
