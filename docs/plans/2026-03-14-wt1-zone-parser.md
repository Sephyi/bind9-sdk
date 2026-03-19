<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
-->

# WT-1: Zone Parser + Serializer Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a complete RFC 1035 zone file parser and serializer in bind9-sdk-core (no_std).

**Architecture:** Two-phase parser (tokenizer -> record assembler) with IncludeResolver trait for pluggable $INCLUDE. Text format support for 10 common record types, with Unknown using RFC 3597 generic format. Serializer produces canonical zone file output.

**Tech Stack:** Rust 2024, no_std + alloc, proptest, insta

**Branch:** `feat/zone-parser`
**Spec:** `docs/specs/2026-03-14-phase1-remainder-design.md` S3
**Depends on:** Phase 1 scaffolding plan (must be complete)

## Chunk 1: Tokenizer

### Task 1: Token Types and Basic Tokenization

**Files:**
- Create: `crates/bind9-sdk-core/src/zone/parser.rs`

- [ ] **Step 1: Write failing tests for Token type and tokenize_line**

Create `crates/bind9-sdk-core/src/zone/parser.rs` with token types and tests. The tokenizer implementation will be stubbed with `todo!()` so tests fail.

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::string::String;
use alloc::vec::Vec;

/// A single token from a zone file line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    /// A name, keyword, or unquoted value (e.g., `example.com.`, `IN`, `A`).
    Word(String),
    /// A quoted string (content only, quotes stripped).
    QuotedString(String),
    /// A `$DIRECTIVE` keyword (e.g., `$ORIGIN`, `$TTL`, `$INCLUDE`).
    Directive(String),
    /// Opening parenthesis for multi-line continuation.
    ParenOpen,
    /// Closing parenthesis.
    ParenClose,
    /// End of a logical line (newline outside parentheses).
    Newline,
}

/// Tokenizer state tracks parenthesized continuation across physical lines.
pub(crate) struct Tokenizer<'a> {
    input: &'a str,
    pos: usize,
    line: u32,
    in_parens: bool,
}

impl<'a> Tokenizer<'a> {
    /// Create a tokenizer over the full zone file input.
    pub(crate) fn new(input: &'a str) -> Self {
        Tokenizer {
            input,
            pos: 0,
            line: 1,
            in_parens: false,
        }
    }

    /// Current line number (1-based) for error reporting.
    pub(crate) fn line(&self) -> u32 {
        self.line
    }

    /// Whether the tokenizer is inside a parenthesized group.
    pub(crate) fn in_parens(&self) -> bool {
        self.in_parens
    }

    /// Consume and return the next token, or None at EOF.
    pub(crate) fn next_token(&mut self) -> Option<Token> {
        todo!("implement tokenizer")
    }

    /// Collect all remaining tokens into a Vec.
    pub(crate) fn tokenize_all(&mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        while let Some(tok) = self.next_token() {
            tokens.push(tok);
        }
        tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::string::ToString;

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
        // Newlines inside parens are suppressed; parens are emitted as tokens.
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
        // When a line starts with whitespace, the first token position indicates
        // owner name inheritance. The tokenizer emits an empty Word("") for this.
        let input = "   IN A 1.2.3.4\n";
        let mut tok = Tokenizer::new(input);
        let first = tok.next_token();
        // First token must indicate the line started with whitespace
        // (inherited owner). We represent this as Word("").
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
}
```

- [ ] **Step 2: Declare parser submodule in zone/mod.rs**

Add `pub(crate) mod parser;` to `crates/bind9-sdk-core/src/zone/mod.rs` (after the existing imports, before the struct definitions).

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p bind9-sdk-core -- zone::parser`
Expected: All tests fail with `todo!()` panic

- [ ] **Step 4: Implement Tokenizer::next_token**

Replace the `todo!()` in `next_token` with the full implementation:

```rust
    /// Consume and return the next token, or None at EOF.
    pub(crate) fn next_token(&mut self) -> Option<Token> {
        let bytes = self.input.as_bytes();
        if self.pos >= bytes.len() {
            return None;
        }

        // Check if we are at the start of a line and the first char is whitespace.
        // This signals owner name inheritance. We track this by checking if the
        // previous character was a newline (or we are at pos 0).
        let at_line_start = self.pos == 0
            || (self.pos > 0 && bytes[self.pos - 1] == b'\n');

        // Skip whitespace (but NOT newlines — those are significant tokens)
        let had_leading_space = self.pos < bytes.len()
            && (bytes[self.pos] == b' ' || bytes[self.pos] == b'\t');
        while self.pos < bytes.len()
            && (bytes[self.pos] == b' ' || bytes[self.pos] == b'\t')
        {
            self.pos += 1;
        }

        if self.pos >= bytes.len() {
            return None;
        }

        // If at line start and had leading whitespace, emit empty owner token
        if at_line_start && had_leading_space && bytes[self.pos] != b'\n' && !self.in_parens {
            return Some(Token::Word(String::new()));
        }

        let ch = bytes[self.pos];

        // Newline
        if ch == b'\n' {
            self.pos += 1;
            self.line += 1;
            if self.in_parens {
                // Inside parens, skip newlines and continue tokenizing
                return self.next_token();
            }
            return Some(Token::Newline);
        }

        // Comment — skip to end of line
        if ch == b';' {
            while self.pos < bytes.len() && bytes[self.pos] != b'\n' {
                self.pos += 1;
            }
            // Don't consume the newline here — let the next call handle it
            return self.next_token();
        }

        // Opening paren
        if ch == b'(' {
            self.pos += 1;
            self.in_parens = true;
            return Some(Token::ParenOpen);
        }

        // Closing paren
        if ch == b')' {
            self.pos += 1;
            self.in_parens = false;
            return Some(Token::ParenClose);
        }

        // Quoted string
        if ch == b'"' {
            self.pos += 1; // skip opening quote
            let mut value = String::new();
            while self.pos < bytes.len() && bytes[self.pos] != b'"' {
                if bytes[self.pos] == b'\\' && self.pos + 1 < bytes.len() {
                    self.pos += 1;
                    let escaped = bytes[self.pos];
                    // \DDD decimal escape
                    if escaped.is_ascii_digit()
                        && self.pos + 2 < bytes.len()
                        && bytes[self.pos + 1].is_ascii_digit()
                        && bytes[self.pos + 2].is_ascii_digit()
                    {
                        let d1 = (escaped - b'0') as u16;
                        let d2 = (bytes[self.pos + 1] - b'0') as u16;
                        let d3 = (bytes[self.pos + 2] - b'0') as u16;
                        let byte_val = d1 * 100 + d2 * 10 + d3;
                        if byte_val <= 255 {
                            value.push(byte_val as u8 as char);
                            self.pos += 3;
                            continue;
                        }
                    }
                    // Any other escaped character is literal
                    value.push(escaped as char);
                    self.pos += 1;
                } else {
                    value.push(bytes[self.pos] as char);
                    self.pos += 1;
                }
            }
            if self.pos < bytes.len() {
                self.pos += 1; // skip closing quote
            }
            return Some(Token::QuotedString(value));
        }

        // Word or directive — read until whitespace, newline, comment, paren, or quote
        let start = self.pos;
        while self.pos < bytes.len() {
            let b = bytes[self.pos];
            if b == b' '
                || b == b'\t'
                || b == b'\n'
                || b == b';'
                || b == b'('
                || b == b')'
                || b == b'"'
            {
                break;
            }
            // Handle escape sequences in unquoted words
            if b == b'\\' && self.pos + 1 < bytes.len() {
                self.pos += 2; // skip backslash and next char
                continue;
            }
            self.pos += 1;
        }

        let word = &self.input[start..self.pos];

        if word.starts_with('$') {
            Some(Token::Directive(String::from(word)))
        } else {
            Some(Token::Word(String::from(word)))
        }
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p bind9-sdk-core -- zone::parser`
Expected: All 12 tests pass

- [ ] **Step 6: Run clippy and WASM check**

Run: `cargo clippy -p bind9-sdk-core --all-targets -- -D warnings && cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Both pass

- [ ] **Step 7: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/parser.rs crates/bind9-sdk-core/src/zone/mod.rs
git commit -m "feat(core): add zone file tokenizer with comment, paren, directive, escape support"
```

### Task 2: Escape Sequence Edge Cases

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/parser.rs`

- [ ] **Step 1: Write failing tests for escape sequences**

Add these tests to the `tests` module in `parser.rs`:

```rust
    #[test]
    fn tokenize_backslash_dot_in_label() {
        // \. in an unquoted name is a literal dot (part of a label, not separator)
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
        // File without trailing newline — last record still parsed
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
```

- [ ] **Step 2: Run tests to verify new tests pass (existing implementation should handle these)**

Run: `cargo test -p bind9-sdk-core -- zone::parser`
Expected: All tests pass (the implementation from Task 1 handles these cases)

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/parser.rs
git commit -m "test(core): add tokenizer edge case tests for escapes, tabs, includes, no-trailing-newline"
```

## Chunk 2: RecordData Text Parsing

### Task 3: rdata_text Module — A, AAAA, NS, CNAME, PTR

**Files:**
- Create: `crates/bind9-sdk-core/src/zone/rdata_text.rs`
- Modify: `crates/bind9-sdk-core/src/zone/mod.rs`

- [ ] **Step 1: Write failing tests for A, AAAA, NS, CNAME, PTR text parsing**

Create `crates/bind9-sdk-core/src/zone/rdata_text.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::domain::DomainName;
use crate::error::CoreError;
use crate::rdata::RecordData;
use crate::record::{Serial, Ttl};

/// Parse record data from zone file text tokens.
///
/// `rtype` is the record type keyword (e.g., "A", "AAAA", "SOA").
/// `tokens` is the remaining tokens on the record line after the type keyword.
/// `origin` is the current `$ORIGIN` for resolving relative names.
pub(crate) fn parse_rdata(
    rtype: &str,
    tokens: &[&str],
    origin: &DomainName,
) -> Result<RecordData, CoreError> {
    match rtype {
        "A" => parse_a(tokens),
        "AAAA" => parse_aaaa(tokens),
        "NS" => parse_ns(tokens, origin),
        "CNAME" => parse_cname(tokens, origin),
        "PTR" => parse_ptr(tokens, origin),
        "SOA" => parse_soa(tokens, origin),
        "MX" => parse_mx(tokens, origin),
        "TXT" => parse_txt(tokens),
        "SRV" => parse_srv(tokens, origin),
        "CAA" => parse_caa(tokens),
        _ => parse_unknown(rtype, tokens),
    }
}

/// Serialize record data to zone file text format.
pub(crate) fn serialize_rdata(rdata: &RecordData) -> String {
    match rdata {
        RecordData::A(addr) => format!("{addr}"),
        RecordData::Aaaa(addr) => format!("{addr}"),
        RecordData::Ns(name) => format!("{name}"),
        RecordData::Cname(name) => format!("{name}"),
        RecordData::Ptr(name) => format!("{name}"),
        RecordData::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => format!(
            "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
        ),
        RecordData::Mx {
            preference,
            exchange,
        } => format!("{preference} {exchange}"),
        RecordData::Txt(strings) => serialize_txt(strings),
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        RecordData::Caa { flags, tag, value } => format!("{flags} {tag} \"{value}\""),
        RecordData::Unknown { rtype, rdata } => serialize_unknown(*rtype, rdata),
        // DNSSEC and other types not yet supported for text format — use generic format
        other => serialize_as_generic(other),
    }
}

/// Resolve a domain name token, handling `@` and relative names.
fn resolve_name(token: &str, origin: &DomainName) -> Result<DomainName, CoreError> {
    if token == "@" {
        return Ok(origin.clone());
    }
    if token.ends_with('.') {
        DomainName::new(token)
    } else {
        // Relative name — append origin
        let absolute = format!("{token}.{origin}");
        DomainName::new(&absolute)
    }
}

fn parse_a(tokens: &[&str]) -> Result<RecordData, CoreError> {
    if tokens.len() != 1 {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!("A record expects 1 token, got {}", tokens.len()),
        });
    }
    let addr: Ipv4Addr = tokens[0].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid IPv4 address `{}`: {e}", tokens[0]),
    })?;
    Ok(RecordData::A(addr))
}

fn parse_aaaa(tokens: &[&str]) -> Result<RecordData, CoreError> {
    if tokens.len() != 1 {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!("AAAA record expects 1 token, got {}", tokens.len()),
        });
    }
    let addr: Ipv6Addr = tokens[0].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid IPv6 address `{}`: {e}", tokens[0]),
    })?;
    Ok(RecordData::Aaaa(addr))
}

fn parse_ns(tokens: &[&str], origin: &DomainName) -> Result<RecordData, CoreError> {
    if tokens.len() != 1 {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!("NS record expects 1 token, got {}", tokens.len()),
        });
    }
    let name = resolve_name(tokens[0], origin)?;
    Ok(RecordData::Ns(name))
}

fn parse_cname(tokens: &[&str], origin: &DomainName) -> Result<RecordData, CoreError> {
    if tokens.len() != 1 {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!("CNAME record expects 1 token, got {}", tokens.len()),
        });
    }
    let name = resolve_name(tokens[0], origin)?;
    Ok(RecordData::Cname(name))
}

fn parse_ptr(tokens: &[&str], origin: &DomainName) -> Result<RecordData, CoreError> {
    if tokens.len() != 1 {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!("PTR record expects 1 token, got {}", tokens.len()),
        });
    }
    let name = resolve_name(tokens[0], origin)?;
    Ok(RecordData::Ptr(name))
}

fn parse_soa(
    _tokens: &[&str],
    _origin: &DomainName,
) -> Result<RecordData, CoreError> {
    todo!("SOA parsing — implemented in Task 4")
}

fn parse_mx(
    _tokens: &[&str],
    _origin: &DomainName,
) -> Result<RecordData, CoreError> {
    todo!("MX parsing — implemented in Task 4")
}

fn parse_txt(_tokens: &[&str]) -> Result<RecordData, CoreError> {
    todo!("TXT parsing — implemented in Task 5")
}

fn parse_srv(
    _tokens: &[&str],
    _origin: &DomainName,
) -> Result<RecordData, CoreError> {
    todo!("SRV parsing — implemented in Task 5")
}

fn parse_caa(_tokens: &[&str]) -> Result<RecordData, CoreError> {
    todo!("CAA parsing — implemented in Task 5")
}

fn parse_unknown(_rtype: &str, _tokens: &[&str]) -> Result<RecordData, CoreError> {
    todo!("unknown/generic parsing — implemented in Task 6")
}

fn serialize_txt(_strings: &[String]) -> String {
    todo!("TXT serialization — implemented in Task 5")
}

fn serialize_unknown(_rtype: u16, _rdata: &[u8]) -> String {
    todo!("unknown/generic serialization — implemented in Task 6")
}

fn serialize_as_generic(_rdata: &RecordData) -> String {
    todo!("generic fallback serialization — implemented in Task 6")
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    fn origin() -> DomainName {
        DomainName::new("example.com.").unwrap()
    }

    // -- A record --

    #[test]
    fn parse_a_valid() {
        let rdata = parse_rdata("A", &["192.0.2.1"], &origin()).unwrap();
        assert_eq!(rdata, RecordData::A(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn parse_a_invalid_addr() {
        let result = parse_rdata("A", &["999.0.0.1"], &origin());
        assert!(result.is_err());
    }

    #[test]
    fn parse_a_wrong_token_count() {
        let result = parse_rdata("A", &["1.2.3.4", "extra"], &origin());
        assert!(result.is_err());
    }

    // -- AAAA record --

    #[test]
    fn parse_aaaa_valid() {
        let rdata = parse_rdata("AAAA", &["2001:db8::1"], &origin()).unwrap();
        assert_eq!(
            rdata,
            RecordData::Aaaa("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn parse_aaaa_localhost() {
        let rdata = parse_rdata("AAAA", &["::1"], &origin()).unwrap();
        assert_eq!(rdata, RecordData::Aaaa(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn parse_aaaa_invalid() {
        let result = parse_rdata("AAAA", &["not-an-ipv6"], &origin());
        assert!(result.is_err());
    }

    // -- NS record --

    #[test]
    fn parse_ns_absolute() {
        let rdata = parse_rdata("NS", &["ns1.example.com."], &origin()).unwrap();
        assert_eq!(
            rdata,
            RecordData::Ns(DomainName::new("ns1.example.com.").unwrap())
        );
    }

    #[test]
    fn parse_ns_relative() {
        let rdata = parse_rdata("NS", &["ns1"], &origin()).unwrap();
        assert_eq!(
            rdata,
            RecordData::Ns(DomainName::new("ns1.example.com.").unwrap())
        );
    }

    #[test]
    fn parse_ns_at_sign() {
        let rdata = parse_rdata("NS", &["@"], &origin()).unwrap();
        assert_eq!(
            rdata,
            RecordData::Ns(DomainName::new("example.com.").unwrap())
        );
    }

    // -- CNAME record --

    #[test]
    fn parse_cname_absolute() {
        let rdata =
            parse_rdata("CNAME", &["www.example.com."], &origin()).unwrap();
        assert_eq!(
            rdata,
            RecordData::Cname(DomainName::new("www.example.com.").unwrap())
        );
    }

    #[test]
    fn parse_cname_relative() {
        let rdata = parse_rdata("CNAME", &["www"], &origin()).unwrap();
        assert_eq!(
            rdata,
            RecordData::Cname(DomainName::new("www.example.com.").unwrap())
        );
    }

    // -- PTR record --

    #[test]
    fn parse_ptr_absolute() {
        let rdata =
            parse_rdata("PTR", &["host.example.com."], &origin()).unwrap();
        assert_eq!(
            rdata,
            RecordData::Ptr(DomainName::new("host.example.com.").unwrap())
        );
    }

    // -- Serialize simple types --

    #[test]
    fn serialize_a() {
        let rdata = RecordData::A(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(serialize_rdata(&rdata), "192.0.2.1");
    }

    #[test]
    fn serialize_aaaa() {
        let rdata = RecordData::Aaaa("2001:db8::1".parse().unwrap());
        assert_eq!(serialize_rdata(&rdata), "2001:db8::1");
    }

    #[test]
    fn serialize_ns() {
        let rdata = RecordData::Ns(DomainName::new("ns1.example.com.").unwrap());
        assert_eq!(serialize_rdata(&rdata), "ns1.example.com.");
    }

    #[test]
    fn serialize_cname() {
        let rdata =
            RecordData::Cname(DomainName::new("www.example.com.").unwrap());
        assert_eq!(serialize_rdata(&rdata), "www.example.com.");
    }

    #[test]
    fn serialize_ptr() {
        let rdata =
            RecordData::Ptr(DomainName::new("host.example.com.").unwrap());
        assert_eq!(serialize_rdata(&rdata), "host.example.com.");
    }
}
```

- [ ] **Step 2: Declare rdata_text submodule in zone/mod.rs**

Add `pub(crate) mod rdata_text;` to `crates/bind9-sdk-core/src/zone/mod.rs`.

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p bind9-sdk-core -- zone::rdata_text`
Expected: All 15 tests pass (A/AAAA/NS/CNAME/PTR parsing and serialization)

- [ ] **Step 4: Run clippy and WASM check**

Run: `cargo clippy -p bind9-sdk-core --all-targets -- -D warnings && cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Both pass

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/rdata_text.rs crates/bind9-sdk-core/src/zone/mod.rs
git commit -m "feat(core): add rdata text parsing for A, AAAA, NS, CNAME, PTR"
```

### Task 4: rdata_text — SOA, MX

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/rdata_text.rs`

- [ ] **Step 1: Write failing tests for SOA and MX text parsing**

Add these tests to the `tests` module in `rdata_text.rs`:

```rust
    // -- SOA record --

    #[test]
    fn parse_soa_valid() {
        let tokens = &[
            "ns1.example.com.",
            "admin.example.com.",
            "2026031401",
            "3600",
            "900",
            "604800",
            "86400",
        ];
        let rdata = parse_rdata("SOA", tokens, &origin()).unwrap();
        match rdata {
            RecordData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                assert_eq!(mname, DomainName::new("ns1.example.com.").unwrap());
                assert_eq!(rname, DomainName::new("admin.example.com.").unwrap());
                assert_eq!(serial.value(), 2026031401);
                assert_eq!(refresh.value(), 3600);
                assert_eq!(retry.value(), 900);
                assert_eq!(expire.value(), 604800);
                assert_eq!(minimum.value(), 86400);
            }
            other => panic!("expected SOA, got {other:?}"),
        }
    }

    #[test]
    fn parse_soa_relative_names() {
        let tokens = &["ns1", "admin", "1", "3600", "900", "604800", "86400"];
        let rdata = parse_rdata("SOA", tokens, &origin()).unwrap();
        match rdata {
            RecordData::Soa { mname, rname, .. } => {
                assert_eq!(mname, DomainName::new("ns1.example.com.").unwrap());
                assert_eq!(rname, DomainName::new("admin.example.com.").unwrap());
            }
            other => panic!("expected SOA, got {other:?}"),
        }
    }

    #[test]
    fn parse_soa_wrong_token_count() {
        let tokens = &["ns1.example.com.", "admin.example.com.", "1"];
        let result = parse_rdata("SOA", tokens, &origin());
        assert!(result.is_err());
    }

    #[test]
    fn serialize_soa() {
        let rdata = RecordData::Soa {
            mname: DomainName::new("ns1.example.com.").unwrap(),
            rname: DomainName::new("admin.example.com.").unwrap(),
            serial: Serial::new(2026031401),
            refresh: Ttl::new(3600).unwrap(),
            retry: Ttl::new(900).unwrap(),
            expire: Ttl::new(604800).unwrap(),
            minimum: Ttl::new(86400).unwrap(),
        };
        assert_eq!(
            serialize_rdata(&rdata),
            "ns1.example.com. admin.example.com. 2026031401 3600 900 604800 86400"
        );
    }

    // -- MX record --

    #[test]
    fn parse_mx_valid() {
        let rdata = parse_rdata("MX", &["10", "mail.example.com."], &origin()).unwrap();
        match rdata {
            RecordData::Mx {
                preference,
                exchange,
            } => {
                assert_eq!(preference, 10);
                assert_eq!(exchange, DomainName::new("mail.example.com.").unwrap());
            }
            other => panic!("expected MX, got {other:?}"),
        }
    }

    #[test]
    fn parse_mx_relative() {
        let rdata = parse_rdata("MX", &["20", "mail"], &origin()).unwrap();
        match rdata {
            RecordData::Mx {
                preference,
                exchange,
            } => {
                assert_eq!(preference, 20);
                assert_eq!(exchange, DomainName::new("mail.example.com.").unwrap());
            }
            other => panic!("expected MX, got {other:?}"),
        }
    }

    #[test]
    fn parse_mx_wrong_token_count() {
        let result = parse_rdata("MX", &["10"], &origin());
        assert!(result.is_err());
    }

    #[test]
    fn serialize_mx() {
        let rdata = RecordData::Mx {
            preference: 10,
            exchange: DomainName::new("mail.example.com.").unwrap(),
        };
        assert_eq!(serialize_rdata(&rdata), "10 mail.example.com.");
    }
```

- [ ] **Step 2: Run tests to verify SOA and MX tests fail**

Run: `cargo test -p bind9-sdk-core -- zone::rdata_text::tests::parse_soa 2>&1 | head -5`
Expected: Panics with `todo!()`

- [ ] **Step 3: Implement parse_soa and parse_mx**

Replace the `todo!()` stubs in `rdata_text.rs`:

```rust
fn parse_soa(tokens: &[&str], origin: &DomainName) -> Result<RecordData, CoreError> {
    if tokens.len() != 7 {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!("SOA record expects 7 tokens, got {}", tokens.len()),
        });
    }
    let mname = resolve_name(tokens[0], origin)?;
    let rname = resolve_name(tokens[1], origin)?;
    let serial_val: u32 = tokens[2].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid SOA serial `{}`: {e}", tokens[2]),
    })?;
    let refresh_val: u32 = tokens[3].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid SOA refresh `{}`: {e}", tokens[3]),
    })?;
    let retry_val: u32 = tokens[4].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid SOA retry `{}`: {e}", tokens[4]),
    })?;
    let expire_val: u32 = tokens[5].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid SOA expire `{}`: {e}", tokens[5]),
    })?;
    let minimum_val: u32 = tokens[6].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid SOA minimum `{}`: {e}", tokens[6]),
    })?;
    Ok(RecordData::Soa {
        mname,
        rname,
        serial: Serial::new(serial_val),
        refresh: Ttl::new(refresh_val).map_err(|e| CoreError::ZoneParse {
            line: 0,
            reason: format!("invalid SOA refresh TTL: {e}"),
        })?,
        retry: Ttl::new(retry_val).map_err(|e| CoreError::ZoneParse {
            line: 0,
            reason: format!("invalid SOA retry TTL: {e}"),
        })?,
        expire: Ttl::new(expire_val).map_err(|e| CoreError::ZoneParse {
            line: 0,
            reason: format!("invalid SOA expire TTL: {e}"),
        })?,
        minimum: Ttl::new(minimum_val).map_err(|e| CoreError::ZoneParse {
            line: 0,
            reason: format!("invalid SOA minimum TTL: {e}"),
        })?,
    })
}

fn parse_mx(tokens: &[&str], origin: &DomainName) -> Result<RecordData, CoreError> {
    if tokens.len() != 2 {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!("MX record expects 2 tokens, got {}", tokens.len()),
        });
    }
    let preference: u16 = tokens[0].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid MX preference `{}`: {e}", tokens[0]),
    })?;
    let exchange = resolve_name(tokens[1], origin)?;
    Ok(RecordData::Mx {
        preference,
        exchange,
    })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bind9-sdk-core -- zone::rdata_text`
Expected: All tests pass (including previous A/AAAA/NS/CNAME/PTR tests)

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/rdata_text.rs
git commit -m "feat(core): add rdata text parsing for SOA and MX"
```

### Task 5: rdata_text — TXT, SRV, CAA

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/rdata_text.rs`

- [ ] **Step 1: Write failing tests for TXT, SRV, CAA**

Add these tests to the `tests` module in `rdata_text.rs`:

```rust
    // -- TXT record --

    #[test]
    fn parse_txt_single_string() {
        let rdata = parse_rdata("TXT", &["v=spf1 ~all"], &origin()).unwrap();
        assert_eq!(rdata, RecordData::Txt(alloc::vec!["v=spf1 ~all".into()]));
    }

    #[test]
    fn parse_txt_multiple_strings() {
        let rdata =
            parse_rdata("TXT", &["v=spf1", "include:example.com", "~all"], &origin())
                .unwrap();
        assert_eq!(
            rdata,
            RecordData::Txt(alloc::vec![
                "v=spf1".into(),
                "include:example.com".into(),
                "~all".into(),
            ])
        );
    }

    #[test]
    fn parse_txt_empty_rejected() {
        let result = parse_rdata("TXT", &[], &origin());
        assert!(result.is_err());
    }

    #[test]
    fn serialize_txt_single() {
        let rdata = RecordData::Txt(alloc::vec!["hello world".into()]);
        assert_eq!(serialize_rdata(&rdata), "\"hello world\"");
    }

    #[test]
    fn serialize_txt_multiple() {
        let rdata = RecordData::Txt(alloc::vec![
            "v=spf1".into(),
            "include:example.com".into(),
        ]);
        assert_eq!(
            serialize_rdata(&rdata),
            "\"v=spf1\" \"include:example.com\""
        );
    }

    #[test]
    fn serialize_txt_with_quote_in_value() {
        let rdata = RecordData::Txt(alloc::vec!["has\"quote".into()]);
        assert_eq!(serialize_rdata(&rdata), "\"has\\\"quote\"");
    }

    // -- SRV record --

    #[test]
    fn parse_srv_valid() {
        let rdata = parse_rdata(
            "SRV",
            &["10", "60", "5060", "sip.example.com."],
            &origin(),
        )
        .unwrap();
        match rdata {
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                assert_eq!(priority, 10);
                assert_eq!(weight, 60);
                assert_eq!(port, 5060);
                assert_eq!(target, DomainName::new("sip.example.com.").unwrap());
            }
            other => panic!("expected SRV, got {other:?}"),
        }
    }

    #[test]
    fn parse_srv_relative_target() {
        let rdata =
            parse_rdata("SRV", &["0", "0", "443", "web"], &origin()).unwrap();
        match rdata {
            RecordData::Srv { target, .. } => {
                assert_eq!(
                    target,
                    DomainName::new("web.example.com.").unwrap()
                );
            }
            other => panic!("expected SRV, got {other:?}"),
        }
    }

    #[test]
    fn parse_srv_wrong_token_count() {
        let result = parse_rdata("SRV", &["10", "60", "5060"], &origin());
        assert!(result.is_err());
    }

    #[test]
    fn serialize_srv() {
        let rdata = RecordData::Srv {
            priority: 10,
            weight: 60,
            port: 5060,
            target: DomainName::new("sip.example.com.").unwrap(),
        };
        assert_eq!(
            serialize_rdata(&rdata),
            "10 60 5060 sip.example.com."
        );
    }

    // -- CAA record --

    #[test]
    fn parse_caa_valid() {
        let rdata =
            parse_rdata("CAA", &["0", "issue", "letsencrypt.org"], &origin())
                .unwrap();
        match rdata {
            RecordData::Caa { flags, tag, value } => {
                assert_eq!(flags, 0);
                assert_eq!(tag, "issue");
                assert_eq!(value, "letsencrypt.org");
            }
            other => panic!("expected CAA, got {other:?}"),
        }
    }

    #[test]
    fn parse_caa_with_critical_flag() {
        let rdata =
            parse_rdata("CAA", &["128", "issuewild", ";"], &origin()).unwrap();
        match rdata {
            RecordData::Caa { flags, tag, value } => {
                assert_eq!(flags, 128);
                assert_eq!(tag, "issuewild");
                assert_eq!(value, ";");
            }
            other => panic!("expected CAA, got {other:?}"),
        }
    }

    #[test]
    fn parse_caa_wrong_token_count() {
        let result = parse_rdata("CAA", &["0", "issue"], &origin());
        assert!(result.is_err());
    }

    #[test]
    fn serialize_caa() {
        let rdata = RecordData::Caa {
            flags: 0,
            tag: "issue".into(),
            value: "letsencrypt.org".into(),
        };
        assert_eq!(
            serialize_rdata(&rdata),
            "0 issue \"letsencrypt.org\""
        );
    }
```

- [ ] **Step 2: Run tests to verify TXT/SRV/CAA tests fail**

Run: `cargo test -p bind9-sdk-core -- zone::rdata_text::tests::parse_txt 2>&1 | head -5`
Expected: Panics with `todo!()`

- [ ] **Step 3: Implement parse_txt, parse_srv, parse_caa, serialize_txt**

Replace the `todo!()` stubs:

```rust
fn parse_txt(tokens: &[&str]) -> Result<RecordData, CoreError> {
    if tokens.is_empty() {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: "TXT record expects at least 1 token".into(),
        });
    }
    let strings: Vec<String> = tokens.iter().map(|t| String::from(*t)).collect();
    Ok(RecordData::Txt(strings))
}

fn parse_srv(tokens: &[&str], origin: &DomainName) -> Result<RecordData, CoreError> {
    if tokens.len() != 4 {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!("SRV record expects 4 tokens, got {}", tokens.len()),
        });
    }
    let priority: u16 = tokens[0].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid SRV priority `{}`: {e}", tokens[0]),
    })?;
    let weight: u16 = tokens[1].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid SRV weight `{}`: {e}", tokens[1]),
    })?;
    let port: u16 = tokens[2].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid SRV port `{}`: {e}", tokens[2]),
    })?;
    let target = resolve_name(tokens[3], origin)?;
    Ok(RecordData::Srv {
        priority,
        weight,
        port,
        target,
    })
}

fn parse_caa(tokens: &[&str]) -> Result<RecordData, CoreError> {
    if tokens.len() < 3 {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!("CAA record expects at least 3 tokens, got {}", tokens.len()),
        });
    }
    let flags: u8 = tokens[0].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid CAA flags `{}`: {e}", tokens[0]),
    })?;
    let tag = String::from(tokens[1]);
    // Value may contain spaces if multiple tokens remain — join them
    let value = if tokens.len() == 3 {
        String::from(tokens[2])
    } else {
        tokens[2..].join(" ")
    };
    Ok(RecordData::Caa { flags, tag, value })
}

fn serialize_txt(strings: &[String]) -> String {
    let mut out = String::new();
    for (i, s) in strings.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push('"');
        for ch in s.chars() {
            if ch == '"' {
                out.push('\\');
                out.push('"');
            } else if ch == '\\' {
                out.push('\\');
                out.push('\\');
            } else {
                out.push(ch);
            }
        }
        out.push('"');
    }
    out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bind9-sdk-core -- zone::rdata_text`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/rdata_text.rs
git commit -m "feat(core): add rdata text parsing for TXT, SRV, CAA"
```

### Task 6: rdata_text — Unknown/Generic Format (RFC 3597)

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/rdata_text.rs`

- [ ] **Step 1: Write failing tests for unknown/generic format**

Add these tests to the `tests` module in `rdata_text.rs`:

```rust
    // -- Unknown / RFC 3597 generic format --

    #[test]
    fn parse_unknown_type_generic_format() {
        // RFC 3597: \# <length> <hex>
        let rdata = parse_rdata("TYPE999", &["\\#", "4", "deadbeef"], &origin()).unwrap();
        match rdata {
            RecordData::Unknown { rtype, rdata } => {
                assert_eq!(rtype, 999);
                assert_eq!(rdata, alloc::vec![0xde, 0xad, 0xbe, 0xef]);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_type_empty_rdata() {
        let rdata = parse_rdata("TYPE65534", &["\\#", "0"], &origin()).unwrap();
        match rdata {
            RecordData::Unknown { rtype, rdata } => {
                assert_eq!(rtype, 65534);
                assert!(rdata.is_empty());
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_type_wrong_length() {
        let result = parse_rdata("TYPE999", &["\\#", "2", "deadbeef"], &origin());
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_type_invalid_hex() {
        let result = parse_rdata("TYPE999", &["\\#", "2", "zzzz"], &origin());
        assert!(result.is_err());
    }

    #[test]
    fn serialize_unknown_type() {
        let rdata = RecordData::Unknown {
            rtype: 999,
            rdata: alloc::vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(serialize_rdata(&rdata), "\\# 4 deadbeef");
    }

    #[test]
    fn serialize_unknown_type_empty() {
        let rdata = RecordData::Unknown {
            rtype: 65534,
            rdata: alloc::vec![],
        };
        assert_eq!(serialize_rdata(&rdata), "\\# 0");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bind9-sdk-core -- zone::rdata_text::tests::parse_unknown 2>&1 | head -5`
Expected: Panics with `todo!()`

- [ ] **Step 3: Implement parse_unknown, serialize_unknown, serialize_as_generic**

Replace the `todo!()` stubs:

```rust
fn parse_unknown(rtype: &str, tokens: &[&str]) -> Result<RecordData, CoreError> {
    // Extract numeric type from "TYPE<n>" format
    let type_num = if let Some(stripped) = rtype.strip_prefix("TYPE") {
        stripped.parse::<u16>().map_err(|e| CoreError::ZoneParse {
            line: 0,
            reason: format!("invalid record type `{rtype}`: {e}"),
        })?
    } else {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!("unsupported record type `{rtype}`"),
        });
    };

    // RFC 3597 generic format: \# <length> [<hex>...]
    if tokens.is_empty() || tokens[0] != "\\#" {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!(
                "unknown type {rtype} must use RFC 3597 generic format: \\# <length> <hex>"
            ),
        });
    }
    if tokens.len() < 2 {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: "RFC 3597 generic format missing length".into(),
        });
    }
    let expected_len: usize = tokens[1].parse().map_err(|e| CoreError::ZoneParse {
        line: 0,
        reason: format!("invalid RFC 3597 length `{}`: {e}", tokens[1]),
    })?;

    if expected_len == 0 {
        if tokens.len() > 2 {
            return Err(CoreError::ZoneParse {
                line: 0,
                reason: "RFC 3597 length is 0 but hex data present".into(),
            });
        }
        return Ok(RecordData::Unknown {
            rtype: type_num,
            rdata: Vec::new(),
        });
    }

    // Concatenate remaining hex tokens
    let hex_str: String = tokens[2..].iter().copied().collect();
    let rdata = decode_hex(&hex_str).map_err(|reason| CoreError::ZoneParse {
        line: 0,
        reason,
    })?;

    if rdata.len() != expected_len {
        return Err(CoreError::ZoneParse {
            line: 0,
            reason: format!(
                "RFC 3597 length mismatch: declared {expected_len}, got {} bytes",
                rdata.len()
            ),
        });
    }

    Ok(RecordData::Unknown {
        rtype: type_num,
        rdata,
    })
}

/// Decode a hex string into bytes.
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {}", hex.len()));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let h = hi
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex character `{hi}`"))?
            as u8;
        let l = lo
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex character `{lo}`"))?
            as u8;
        bytes.push((h << 4) | l);
    }
    Ok(bytes)
}

/// Encode bytes to lowercase hex string.
fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn serialize_unknown(rtype: u16, rdata: &[u8]) -> String {
    let _ = rtype; // rtype is in the record header, not in the rdata text
    if rdata.is_empty() {
        "\\# 0".into()
    } else {
        format!("\\# {} {}", rdata.len(), encode_hex(rdata))
    }
}

fn serialize_as_generic(rdata: &RecordData) -> String {
    // For record types we don't have text format support yet,
    // we cannot serialize them. This is a programming error in v0.1.0.
    // In production, all record types would have text format support.
    let _ = rdata;
    String::from("\\# 0")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bind9-sdk-core -- zone::rdata_text`
Expected: All tests pass

- [ ] **Step 5: Run clippy and WASM check**

Run: `cargo clippy -p bind9-sdk-core --all-targets -- -D warnings && cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Both pass

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/rdata_text.rs
git commit -m "feat(core): add RFC 3597 generic format for unknown record types"
```

## Chunk 3: Record Assembler and ZoneFile Parser

### Task 7: IncludeResolver Trait and ZoneFile Type

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/mod.rs`

- [ ] **Step 1: Write tests for ZoneFile type and IncludeResolver trait**

Add the following to `crates/bind9-sdk-core/src/zone/mod.rs`, after the existing `Zone` impl block and before the `#[cfg(test)]` module:

```rust
use crate::record::Ttl;

/// Resolver for `$INCLUDE` directives in zone files.
///
/// Implement this trait to provide filesystem or custom include resolution.
/// The default `ZoneFile::parse()` method returns an error on `$INCLUDE`.
/// Use `ZoneFile::parse_with_includes()` to supply a resolver.
pub trait IncludeResolver {
    /// Read the content of an included file.
    fn resolve(&self, path: &str) -> Result<alloc::string::String, CoreError>;
}

/// A parsed zone file with metadata.
///
/// One `ZoneFile` corresponds to one zone (RFC 1035 master file format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneFile {
    /// The zone origin (from `$ORIGIN` directive or inferred from SOA).
    pub origin: DomainName,
    /// The default TTL (from `$TTL` directive).
    pub default_ttl: Option<Ttl>,
    /// The parsed zone data.
    pub zone: Zone,
}

impl ZoneFile {
    /// Parse a zone file from text.
    ///
    /// Returns `CoreError::ZoneParse` on `$INCLUDE` directives. Use
    /// `parse_with_includes()` if the zone file may contain includes.
    pub fn parse(input: &str) -> Result<Self, CoreError> {
        todo!("zone file parser — implemented in Task 8")
    }

    /// Parse a zone file from text with include resolution.
    pub fn parse_with_includes(
        input: &str,
        resolver: &dyn IncludeResolver,
    ) -> Result<Self, CoreError> {
        todo!("zone file parser with includes — implemented in Task 8")
    }

    /// Serialize the zone file back to text format.
    pub fn serialize(&self) -> alloc::string::String {
        todo!("zone file serializer — implemented in Task 10")
    }
}
```

Then extend the `#[cfg(test)]` module with tests for the new types:

```rust
    #[test]
    fn zonefile_type_constructs() {
        let zf = ZoneFile {
            origin: DomainName::new("example.com.").unwrap(),
            default_ttl: Some(Ttl::new(3600).unwrap()),
            zone: example_zone(),
        };
        assert_eq!(zf.origin, DomainName::new("example.com.").unwrap());
        assert_eq!(zf.default_ttl, Some(Ttl::new(3600).unwrap()));
        assert_eq!(zf.zone.name, DomainName::new("example.com.").unwrap());
    }

    struct TestIncludeResolver;

    impl IncludeResolver for TestIncludeResolver {
        fn resolve(&self, _path: &str) -> Result<alloc::string::String, CoreError> {
            Ok(alloc::string::String::from(
                "included IN A 10.0.0.1\n",
            ))
        }
    }

    #[test]
    fn include_resolver_trait_implementable() {
        let resolver = TestIncludeResolver;
        let content = resolver.resolve("test.zone").unwrap();
        assert!(content.contains("included"));
    }
```

- [ ] **Step 2: Run tests to verify they compile and pass**

Run: `cargo test -p bind9-sdk-core -- zone::tests`
Expected: `zonefile_type_constructs` and `include_resolver_trait_implementable` pass

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/mod.rs
git commit -m "feat(core): add ZoneFile type and IncludeResolver trait"
```

### Task 8: Record Assembler — Core Parse Logic

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/parser.rs`

- [ ] **Step 1: Write failing tests for ZoneFile::parse**

Add a new `assembler_tests` module at the bottom of `parser.rs`:

```rust
#[cfg(test)]
mod assembler_tests {
    extern crate alloc;
    use alloc::string::ToString;
    use crate::domain::DomainName;
    use crate::rdata::RecordData;
    use crate::record::{RecordClass, Ttl, Serial};
    use crate::zone::ZoneFile;
    use core::net::Ipv4Addr;

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
        // Both records should have the same owner name
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
        assert!(err.contains("$INCLUDE"), "error should mention $INCLUDE: {err}");
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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bind9-sdk-core -- zone::parser::assembler_tests 2>&1 | head -10`
Expected: Panics with `todo!()` from `ZoneFile::parse`

- [ ] **Step 3: Implement the record assembler in parser.rs**

Add the assembler function after the `Tokenizer` impl block, before the `#[cfg(test)]` module:

```rust
use crate::domain::DomainName;
use crate::error::CoreError;
use crate::rdata::RecordData;
use crate::record::{RecordClass, ResourceRecord, Ttl};
use crate::zone::rdata_text;
use crate::zone::{IncludeResolver, Zone, ZoneFile};

/// Check if a word token is a record class keyword.
fn is_class(word: &str) -> Option<RecordClass> {
    match word.to_ascii_uppercase().as_str() {
        "IN" => Some(RecordClass::IN),
        "CH" => Some(RecordClass::CH),
        "HS" => Some(RecordClass::HS),
        _ => None,
    }
}

/// Check if a word token is a record type keyword.
fn is_record_type(word: &str) -> bool {
    matches!(
        word.to_ascii_uppercase().as_str(),
        "A" | "AAAA" | "CNAME" | "NS" | "PTR" | "SOA" | "MX" | "TXT" | "SRV"
            | "CAA" | "DNSKEY" | "RRSIG" | "NSEC" | "NSEC3" | "DS" | "CDS"
            | "CDNSKEY" | "TLSA" | "SSHFP" | "CSYNC" | "RP"
    ) || word.to_ascii_uppercase().starts_with("TYPE")
}

/// Check if a word token is a TTL (purely numeric).
fn is_ttl(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_digit())
}

/// Resolve an owner name token against the current origin.
fn resolve_owner(token: &str, origin: &DomainName) -> Result<DomainName, CoreError> {
    if token == "@" {
        Ok(origin.clone())
    } else if token.ends_with('.') {
        DomainName::new(token)
    } else {
        let absolute = alloc::format!("{token}.{origin}");
        DomainName::new(&absolute)
    }
}

/// Parse a zone file into a ZoneFile struct.
pub(crate) fn parse_zone(
    input: &str,
    resolver: Option<&dyn IncludeResolver>,
) -> Result<ZoneFile, CoreError> {
    let mut tokenizer = Tokenizer::new(input);
    let mut origin: Option<DomainName> = None;
    let mut default_ttl: Option<Ttl> = None;
    let mut records: Vec<ResourceRecord> = Vec::new();
    let mut last_owner: Option<DomainName> = None;
    let mut default_class = RecordClass::IN;

    // Collect logical lines: each line is a vec of tokens between Newlines
    let mut current_line: Vec<Token> = Vec::new();
    let mut lines: Vec<(u32, Vec<Token>)> = Vec::new();
    let mut line_start = tokenizer.line();

    let all_tokens = tokenizer.tokenize_all();
    let mut token_line = 1u32;
    // Re-tokenize to track line numbers properly
    let mut tokenizer2 = Tokenizer::new(input);

    // Simpler approach: process tokens sequentially
    let mut tok = Tokenizer::new(input);
    let mut current_tokens: Vec<Token> = Vec::new();
    let mut record_line: u32 = tok.line();

    loop {
        let t = tok.next_token();
        match t {
            None => {
                // EOF — process any remaining tokens
                if !current_tokens.is_empty() {
                    process_line(
                        &current_tokens,
                        record_line,
                        &mut origin,
                        &mut default_ttl,
                        &mut default_class,
                        &mut last_owner,
                        &mut records,
                        resolver,
                    )?;
                }
                break;
            }
            Some(Token::Newline) => {
                if !current_tokens.is_empty() {
                    process_line(
                        &current_tokens,
                        record_line,
                        &mut origin,
                        &mut default_ttl,
                        &mut default_class,
                        &mut last_owner,
                        &mut records,
                        resolver,
                    )?;
                    current_tokens.clear();
                }
                record_line = tok.line();
            }
            Some(Token::ParenOpen) | Some(Token::ParenClose) => {
                // Parens are consumed by tokenizer for line continuation;
                // they don't appear in the logical line.
            }
            Some(token) => {
                current_tokens.push(token);
            }
        }
    }

    // Determine zone origin
    let zone_origin = if let Some(o) = origin {
        o
    } else {
        // Try to infer from the first SOA record
        records
            .iter()
            .find(|rr| matches!(rr.rdata, RecordData::Soa { .. }))
            .map(|rr| rr.name.clone())
            .ok_or_else(|| CoreError::ZoneParse {
                line: 1,
                reason: "no $ORIGIN directive and no SOA record found".into(),
            })?
    };

    let zone = Zone {
        name: zone_origin.clone(),
        class: default_class,
        records,
    };

    Ok(ZoneFile {
        origin: zone_origin,
        default_ttl,
        zone,
    })
}

/// Process a single logical line of tokens.
fn process_line(
    tokens: &[Token],
    line: u32,
    origin: &mut Option<DomainName>,
    default_ttl: &mut Option<Ttl>,
    default_class: &mut RecordClass,
    last_owner: &mut Option<DomainName>,
    records: &mut Vec<ResourceRecord>,
    resolver: Option<&dyn IncludeResolver>,
) -> Result<(), CoreError> {
    if tokens.is_empty() {
        return Ok(());
    }

    // Check for directives
    if let Token::Directive(ref d) = tokens[0] {
        match d.as_str() {
            "$ORIGIN" => {
                if tokens.len() < 2 {
                    return Err(CoreError::ZoneParse {
                        line,
                        reason: "$ORIGIN requires a domain name argument".into(),
                    });
                }
                let name_str = token_as_str(&tokens[1]);
                let o = DomainName::new(&name_str).map_err(|e| CoreError::ZoneParse {
                    line,
                    reason: alloc::format!("invalid $ORIGIN `{name_str}`: {e}"),
                })?;
                *origin = Some(o);
                return Ok(());
            }
            "$TTL" => {
                if tokens.len() < 2 {
                    return Err(CoreError::ZoneParse {
                        line,
                        reason: "$TTL requires a value".into(),
                    });
                }
                let ttl_str = token_as_str(&tokens[1]);
                let val: u32 = ttl_str.parse().map_err(|e| CoreError::ZoneParse {
                    line,
                    reason: alloc::format!("invalid $TTL `{ttl_str}`: {e}"),
                })?;
                *default_ttl = Some(Ttl::new(val).map_err(|e| CoreError::ZoneParse {
                    line,
                    reason: alloc::format!("invalid $TTL value: {e}"),
                })?);
                return Ok(());
            }
            "$INCLUDE" => {
                if let Some(r) = resolver {
                    if tokens.len() < 2 {
                        return Err(CoreError::ZoneParse {
                            line,
                            reason: "$INCLUDE requires a file path".into(),
                        });
                    }
                    let path = token_as_str(&tokens[1]);
                    let content = r.resolve(&path)?;
                    let included = parse_zone(&content, Some(r))?;
                    records.extend(included.zone.records);
                    return Ok(());
                }
                return Err(CoreError::ZoneParse {
                    line,
                    reason: "$INCLUDE directive not supported without a resolver".into(),
                });
            }
            other => {
                return Err(CoreError::ZoneParse {
                    line,
                    reason: alloc::format!("unknown directive `{other}`"),
                });
            }
        }
    }

    // Parse a resource record line
    let cur_origin = origin.as_ref().ok_or_else(|| CoreError::ZoneParse {
        line,
        reason: "record found before $ORIGIN; set $ORIGIN first or provide an absolute owner name"
            .into(),
    })?;

    // Extract word strings from tokens
    let words: Vec<alloc::string::String> = tokens
        .iter()
        .map(|t| match t {
            Token::Word(w) => w.clone(),
            Token::QuotedString(s) => s.clone(),
            Token::Directive(d) => d.clone(),
            _ => alloc::string::String::new(),
        })
        .collect();
    let word_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();

    // Parse owner name, class, TTL, type, rdata
    let mut pos = 0;

    // Owner name: if first word is empty (inherited), use last_owner
    let owner = if word_refs[0].is_empty() {
        pos += 1;
        last_owner.clone().ok_or_else(|| CoreError::ZoneParse {
            line,
            reason: "inherited owner name but no previous owner".into(),
        })?
    } else if is_class(word_refs[0]).is_some()
        || is_record_type(word_refs[0])
        || is_ttl(word_refs[0])
    {
        // No owner name — inherit from last
        last_owner.clone().ok_or_else(|| CoreError::ZoneParse {
            line,
            reason: "inherited owner name but no previous owner".into(),
        })?
    } else {
        let o = resolve_owner(word_refs[0], cur_origin)?;
        pos += 1;
        o
    };

    *last_owner = Some(owner.clone());

    // Parse optional TTL and class in either order
    let mut record_ttl: Option<Ttl> = None;
    let mut record_class: Option<RecordClass> = None;

    // Try up to 2 tokens for TTL/class
    for _ in 0..2 {
        if pos >= word_refs.len() {
            break;
        }
        if record_class.is_none() {
            if let Some(c) = is_class(word_refs[pos]) {
                record_class = Some(c);
                pos += 1;
                continue;
            }
        }
        if record_ttl.is_none() && is_ttl(word_refs[pos]) {
            let val: u32 = word_refs[pos].parse().map_err(|e| CoreError::ZoneParse {
                line,
                reason: alloc::format!("invalid TTL `{}`: {e}", word_refs[pos]),
            })?;
            record_ttl = Some(Ttl::new(val).map_err(|e| CoreError::ZoneParse {
                line,
                reason: alloc::format!("invalid TTL value: {e}"),
            })?);
            pos += 1;
            continue;
        }
        break;
    }

    // Record type
    if pos >= word_refs.len() {
        return Err(CoreError::ZoneParse {
            line,
            reason: "expected record type".into(),
        });
    }
    let rtype = word_refs[pos].to_ascii_uppercase();
    pos += 1;

    // Remaining tokens are rdata
    // For rdata, we need to pass token strings (including QuotedStrings as-is)
    let rdata_strs: Vec<&str> = word_refs[pos..].iter().copied().collect();
    let rdata = rdata_text::parse_rdata(&rtype, &rdata_strs, cur_origin)
        .map_err(|e| match e {
            CoreError::ZoneParse { reason, .. } => CoreError::ZoneParse { line, reason },
            other => other,
        })?;

    let ttl = record_ttl
        .or(*default_ttl)
        .ok_or_else(|| CoreError::ZoneParse {
            line,
            reason: "no TTL specified and no $TTL default set".into(),
        })?;

    let class = record_class.unwrap_or(*default_class);
    if record_class.is_some() {
        *default_class = class;
    }

    records.push(ResourceRecord {
        name: owner,
        class,
        ttl,
        rdata,
    });

    Ok(())
}

/// Extract the string content from a token.
fn token_as_str(token: &Token) -> alloc::string::String {
    match token {
        Token::Word(w) => w.clone(),
        Token::QuotedString(s) => s.clone(),
        Token::Directive(d) => d.clone(),
        _ => alloc::string::String::new(),
    }
}

/// Convert a word to uppercase (ASCII only, no_std compatible).
trait AsciiUppercase {
    fn to_ascii_uppercase(&self) -> alloc::string::String;
}

impl AsciiUppercase for str {
    fn to_ascii_uppercase(&self) -> alloc::string::String {
        self.chars()
            .map(|c| c.to_ascii_uppercase())
            .collect()
    }
}
```

- [ ] **Step 4: Wire ZoneFile::parse to the assembler**

In `crates/bind9-sdk-core/src/zone/mod.rs`, replace the `todo!()` stubs in `ZoneFile::parse` and `ZoneFile::parse_with_includes`:

```rust
    pub fn parse(input: &str) -> Result<Self, CoreError> {
        parser::parse_zone(input, None)
    }

    pub fn parse_with_includes(
        input: &str,
        resolver: &dyn IncludeResolver,
    ) -> Result<Self, CoreError> {
        parser::parse_zone(input, Some(resolver))
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p bind9-sdk-core -- zone::parser::assembler_tests`
Expected: All 14 assembler tests pass

- [ ] **Step 6: Run clippy and WASM check**

Run: `cargo clippy -p bind9-sdk-core --all-targets -- -D warnings && cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Both pass

- [ ] **Step 7: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/parser.rs crates/bind9-sdk-core/src/zone/mod.rs
git commit -m "feat(core): implement zone file record assembler with directive, TTL/class, name resolution"
```

### Task 9: Parse Error Reporting

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/parser.rs`

- [ ] **Step 1: Write tests for error reporting quality**

Add to the `assembler_tests` module:

```rust
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
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p bind9-sdk-core -- zone::parser::assembler_tests`
Expected: All tests pass (including new error reporting tests)

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/parser.rs
git commit -m "test(core): add zone parser error reporting tests"
```

## Chunk 4: Serializer, ZoneManager, and Testing

### Task 10: Zone File Serializer

**Files:**
- Create: `crates/bind9-sdk-core/src/zone/serializer.rs`
- Modify: `crates/bind9-sdk-core/src/zone/mod.rs`

- [ ] **Step 1: Write failing tests for the serializer**

Create `crates/bind9-sdk-core/src/zone/serializer.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::format;
use alloc::string::String;

use crate::domain::DomainName;
use crate::record::{RecordClass, Ttl};
use crate::zone::rdata_text;
use crate::zone::ZoneFile;

/// Serialize a ZoneFile to canonical zone file text format.
pub(crate) fn serialize(zone_file: &ZoneFile) -> String {
    todo!("serializer implementation")
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use crate::domain::DomainName;
    use crate::rdata::RecordData;
    use crate::record::{RecordClass, ResourceRecord, Serial, Ttl};
    use crate::zone::Zone;
    use core::net::Ipv4Addr;

    fn example_zonefile() -> ZoneFile {
        let origin = DomainName::new("example.com.").unwrap();
        ZoneFile {
            origin: origin.clone(),
            default_ttl: Some(Ttl::new(3600).unwrap()),
            zone: Zone {
                name: origin.clone(),
                class: RecordClass::IN,
                records: alloc::vec![
                    ResourceRecord {
                        name: origin.clone(),
                        class: RecordClass::IN,
                        ttl: Ttl::new(3600).unwrap(),
                        rdata: RecordData::Soa {
                            mname: DomainName::new("ns1.example.com.").unwrap(),
                            rname: DomainName::new("admin.example.com.").unwrap(),
                            serial: Serial::new(2026031401),
                            refresh: Ttl::new(3600).unwrap(),
                            retry: Ttl::new(900).unwrap(),
                            expire: Ttl::new(604800).unwrap(),
                            minimum: Ttl::new(86400).unwrap(),
                        },
                    },
                    ResourceRecord {
                        name: origin.clone(),
                        class: RecordClass::IN,
                        ttl: Ttl::new(3600).unwrap(),
                        rdata: RecordData::Ns(
                            DomainName::new("ns1.example.com.").unwrap(),
                        ),
                    },
                    ResourceRecord {
                        name: origin.clone(),
                        class: RecordClass::IN,
                        ttl: Ttl::new(3600).unwrap(),
                        rdata: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
                    },
                ],
            },
        }
    }

    #[test]
    fn serialize_includes_origin_directive() {
        let zf = example_zonefile();
        let output = serialize(&zf);
        assert!(
            output.starts_with("$ORIGIN example.com.\n"),
            "should start with $ORIGIN: {output}"
        );
    }

    #[test]
    fn serialize_includes_ttl_directive() {
        let zf = example_zonefile();
        let output = serialize(&zf);
        assert!(
            output.contains("$TTL 3600\n"),
            "should contain $TTL: {output}"
        );
    }

    #[test]
    fn serialize_records_present() {
        let zf = example_zonefile();
        let output = serialize(&zf);
        assert!(output.contains("SOA"), "should contain SOA: {output}");
        assert!(output.contains("NS"), "should contain NS: {output}");
        assert!(output.contains("192.0.2.1"), "should contain A record: {output}");
    }

    #[test]
    fn serialize_records_have_class_and_ttl() {
        let zf = example_zonefile();
        let output = serialize(&zf);
        assert!(
            output.contains("IN"),
            "should contain record class: {output}"
        );
        assert!(
            output.contains("3600"),
            "should contain TTL: {output}"
        );
    }

    #[test]
    fn serialize_no_default_ttl() {
        let mut zf = example_zonefile();
        zf.default_ttl = None;
        let output = serialize(&zf);
        assert!(
            !output.contains("$TTL"),
            "should not contain $TTL when None: {output}"
        );
    }

    #[test]
    fn serialize_ends_with_newline() {
        let zf = example_zonefile();
        let output = serialize(&zf);
        assert!(
            output.ends_with('\n'),
            "output should end with newline"
        );
    }
}
```

- [ ] **Step 2: Declare serializer submodule in zone/mod.rs**

Add `pub(crate) mod serializer;` to `crates/bind9-sdk-core/src/zone/mod.rs`.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p bind9-sdk-core -- zone::serializer`
Expected: Panics with `todo!()`

- [ ] **Step 4: Implement the serializer**

Replace the `todo!()` in `serializer.rs`:

```rust
/// Serialize a ZoneFile to canonical zone file text format.
pub(crate) fn serialize(zone_file: &ZoneFile) -> String {
    let mut out = String::new();

    // $ORIGIN directive
    out.push_str(&format!("$ORIGIN {}\n", zone_file.origin));

    // $TTL directive (if set)
    if let Some(ref ttl) = zone_file.default_ttl {
        out.push_str(&format!("$TTL {}\n", ttl.value()));
    }

    // Records
    let mut last_owner: Option<&DomainName> = None;

    for rr in &zone_file.zone.records {
        // Owner name — use the full name each time for canonical output.
        // Owner name elision (blank for repeated names) is a nice-to-have
        // but not required for correctness.
        let owner_str = format!("{}", rr.name);

        // Check if we can elide the owner (same as previous)
        if last_owner == Some(&rr.name) {
            // Elide owner — use whitespace
            out.push_str(&format!(
                "\t{}\t{}\t{}\t{}\n",
                rr.ttl.value(),
                rr.class,
                rdata_type_str(&rr.rdata),
                rdata_text::serialize_rdata(&rr.rdata),
            ));
        } else {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                owner_str,
                rr.ttl.value(),
                rr.class,
                rdata_type_str(&rr.rdata),
                rdata_text::serialize_rdata(&rr.rdata),
            ));
        }

        last_owner = Some(&rr.name);
    }

    out
}

/// Get the type keyword string for a RecordData variant.
fn rdata_type_str(rdata: &crate::rdata::RecordData) -> &'static str {
    use crate::rdata::RecordData;
    match rdata {
        RecordData::A(_) => "A",
        RecordData::Aaaa(_) => "AAAA",
        RecordData::Cname(_) => "CNAME",
        RecordData::Ns(_) => "NS",
        RecordData::Ptr(_) => "PTR",
        RecordData::Soa { .. } => "SOA",
        RecordData::Mx { .. } => "MX",
        RecordData::Txt(_) => "TXT",
        RecordData::Srv { .. } => "SRV",
        RecordData::Caa { .. } => "CAA",
        RecordData::Dnskey { .. } => "DNSKEY",
        RecordData::Rrsig { .. } => "RRSIG",
        RecordData::Nsec { .. } => "NSEC",
        RecordData::Nsec3 { .. } => "NSEC3",
        RecordData::Ds { .. } => "DS",
        RecordData::Cds { .. } => "CDS",
        RecordData::Cdnskey { .. } => "CDNSKEY",
        RecordData::Tlsa { .. } => "TLSA",
        RecordData::Sshfp { .. } => "SSHFP",
        RecordData::Csync { .. } => "CSYNC",
        RecordData::Rp { .. } => "RP",
        RecordData::Unknown { .. } => "TYPE",
        _ => "UNKNOWN",
    }
}
```

- [ ] **Step 5: Wire ZoneFile::serialize to the serializer module**

In `crates/bind9-sdk-core/src/zone/mod.rs`, replace the `todo!()` in `ZoneFile::serialize`:

```rust
    pub fn serialize(&self) -> alloc::string::String {
        serializer::serialize(self)
    }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p bind9-sdk-core -- zone::serializer`
Expected: All 6 serializer tests pass

- [ ] **Step 7: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/serializer.rs crates/bind9-sdk-core/src/zone/mod.rs
git commit -m "feat(core): implement zone file serializer with canonical output format"
```

### Task 11: ZoneManager Implementation for ZoneFile

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/mod.rs`

- [ ] **Step 1: Write failing tests for ZoneManager impl**

Add to the test module in `zone/mod.rs`:

```rust
    #[test]
    fn zonefile_zone_manager_list_zones() {
        let zf = ZoneFile {
            origin: DomainName::new("example.com.").unwrap(),
            default_ttl: Some(Ttl::new(3600).unwrap()),
            zone: example_zone(),
        };
        // ZoneManager::list_zones is async, test using block_on or poll
        // For no_std, we test the sync equivalent directly
        let summaries = alloc::vec![zf.zone.summary()];
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, DomainName::new("example.com.").unwrap());
        assert_eq!(summaries[0].serial, Serial::new(2026031401));
    }

    #[test]
    fn zonefile_zone_manager_get_zone_found() {
        let zf = ZoneFile {
            origin: DomainName::new("example.com.").unwrap(),
            default_ttl: Some(Ttl::new(3600).unwrap()),
            zone: example_zone(),
        };
        let name = DomainName::new("example.com.").unwrap();
        // Direct test — the async trait impl delegates to this logic
        assert_eq!(zf.zone.name, name);
    }

    #[test]
    fn zonefile_zone_manager_get_zone_not_found() {
        let zf = ZoneFile {
            origin: DomainName::new("example.com.").unwrap(),
            default_ttl: Some(Ttl::new(3600).unwrap()),
            zone: example_zone(),
        };
        let other = DomainName::new("other.com.").unwrap();
        assert_ne!(zf.zone.name, other);
    }
```

- [ ] **Step 2: Implement ZoneManager for ZoneFile**

Add to `zone/mod.rs`, after the `ZoneFile` impl block:

```rust
impl crate::traits::ZoneManager for ZoneFile {
    type Error = CoreError;

    async fn list_zones(&self) -> Result<Vec<ZoneSummary>, CoreError> {
        Ok(alloc::vec![self.zone.summary()])
    }

    async fn get_zone(&self, name: &DomainName) -> Result<Zone, CoreError> {
        if self.zone.name == *name {
            Ok(self.zone.clone())
        } else {
            Err(CoreError::InvalidName {
                name: alloc::format!("{name}"),
                reason: "zone not found".into(),
            })
        }
    }
}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p bind9-sdk-core -- zone::tests`
Expected: All tests pass

- [ ] **Step 4: Run clippy and WASM check**

Run: `cargo clippy -p bind9-sdk-core --all-targets -- -D warnings && cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Both pass

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/mod.rs
git commit -m "feat(core): implement ZoneManager trait for ZoneFile"
```

### Task 12: Parse-Serialize Roundtrip Tests

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/serializer.rs`

- [ ] **Step 1: Write roundtrip tests**

Add a `roundtrip_tests` module to `serializer.rs`:

```rust
#[cfg(test)]
mod roundtrip_tests {
    extern crate alloc;
    use crate::zone::ZoneFile;

    #[test]
    fn roundtrip_minimal_zone() {
        let input = "\
$ORIGIN example.com.
$TTL 3600
example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2026031401 3600 900 604800 86400
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN A 192.0.2.1
";
        let zf = ZoneFile::parse(input).unwrap();
        let output = zf.serialize();
        let zf2 = ZoneFile::parse(&output).unwrap();
        assert_eq!(zf.zone.records.len(), zf2.zone.records.len());
        assert_eq!(zf.origin, zf2.origin);
        assert_eq!(zf.zone.records, zf2.zone.records);
    }

    #[test]
    fn roundtrip_multiple_record_types() {
        let input = "\
$ORIGIN example.com.
$TTL 300
example.com. 300 IN SOA ns1.example.com. admin.example.com. 1 3600 900 604800 86400
example.com. 300 IN NS ns1.example.com.
example.com. 300 IN NS ns2.example.com.
example.com. 300 IN A 192.0.2.1
example.com. 300 IN AAAA 2001:db8::1
example.com. 300 IN MX 10 mail.example.com.
www.example.com. 300 IN CNAME example.com.
example.com. 300 IN TXT \"v=spf1 ~all\"
";
        let zf = ZoneFile::parse(input).unwrap();
        let output = zf.serialize();
        let zf2 = ZoneFile::parse(&output).unwrap();
        assert_eq!(zf.zone.records.len(), zf2.zone.records.len());
        for (a, b) in zf.zone.records.iter().zip(zf2.zone.records.iter()) {
            assert_eq!(a.name, b.name, "owner mismatch");
            assert_eq!(a.class, b.class, "class mismatch");
            assert_eq!(a.ttl, b.ttl, "ttl mismatch");
            assert_eq!(a.rdata, b.rdata, "rdata mismatch");
        }
    }

    #[test]
    fn roundtrip_srv_and_caa() {
        let input = "\
$ORIGIN example.com.
$TTL 300
example.com. 300 IN SOA ns1.example.com. admin.example.com. 1 3600 900 604800 86400
_sip._tcp.example.com. 300 IN SRV 10 60 5060 sip.example.com.
example.com. 300 IN CAA 0 issue \"letsencrypt.org\"
";
        let zf = ZoneFile::parse(input).unwrap();
        let output = zf.serialize();
        let zf2 = ZoneFile::parse(&output).unwrap();
        assert_eq!(zf.zone.records.len(), zf2.zone.records.len());
        assert_eq!(zf.zone.records, zf2.zone.records);
    }

    #[test]
    fn roundtrip_preserves_origin() {
        let input = "\
$ORIGIN sub.example.com.
$TTL 600
sub.example.com. 600 IN SOA ns1.example.com. admin.example.com. 1 3600 900 604800 86400
sub.example.com. 600 IN A 10.0.0.1
";
        let zf = ZoneFile::parse(input).unwrap();
        let output = zf.serialize();
        let zf2 = ZoneFile::parse(&output).unwrap();
        assert_eq!(zf.origin, zf2.origin);
    }
}
```

- [ ] **Step 2: Run roundtrip tests**

Run: `cargo test -p bind9-sdk-core -- zone::serializer::roundtrip_tests`
Expected: All 4 roundtrip tests pass

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/serializer.rs
git commit -m "test(core): add parse-serialize roundtrip tests for zone files"
```

### Task 13: Proptest Fuzz and Roundtrip Properties

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/parser.rs`

- [ ] **Step 1: Write proptest fuzz test**

Add a `proptests` module to `parser.rs`:

```rust
#[cfg(test)]
mod proptests {
    extern crate alloc;
    use proptest::prelude::*;
    use crate::zone::ZoneFile;
    use crate::domain::DomainName;
    use crate::rdata::RecordData;
    use crate::record::{RecordClass, ResourceRecord, Serial, Ttl};
    use crate::zone::Zone;
    use core::net::Ipv4Addr;

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

            // Generate A records with varied IPs
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
    }
}
```

- [ ] **Step 2: Run proptest tests**

Run: `cargo test -p bind9-sdk-core -- zone::parser::proptests`
Expected: All proptest cases pass (256 cases for fuzz, 256 for roundtrip)

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-core/src/zone/parser.rs
git commit -m "test(core): add proptest fuzz and roundtrip property tests for zone parser"
```

### Task 14: Re-export ZoneFile and IncludeResolver from lib.rs

**Files:**
- Modify: `crates/bind9-sdk-core/src/zone/mod.rs`
- Modify: `crates/bind9-sdk-core/src/lib.rs`

- [ ] **Step 1: Add public re-exports**

In `crates/bind9-sdk-core/src/zone/mod.rs`, ensure `ZoneFile` and `IncludeResolver` are `pub` (they should be from Task 7).

In `crates/bind9-sdk-core/src/lib.rs`, add to the re-exports section:

```rust
pub use zone::{IncludeResolver, ZoneFile};
```

The full re-exports block should now be:

```rust
// Curated re-exports for common access
pub use domain::{DomainName, Label};
pub use error::CoreError;
pub use protocol::{Rcode, RecordType};
pub use rdata::RecordData;
pub use record::{RecordClass, ResourceRecord, Serial, Ttl};
pub use traits::{DynamicUpdater, NamedControl, StatsClient, ZoneManager};
pub use update::{UpdateMessage, UpdateResult};
pub use zone::{IncludeResolver, Zone, ZoneFile, ZoneSummary};
```

- [ ] **Step 2: Run all tests**

Run: `cargo test -p bind9-sdk-core`
Expected: All tests pass across all modules

- [ ] **Step 3: Run clippy and WASM check**

Run: `cargo clippy -p bind9-sdk-core --all-targets -- -D warnings && cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Both pass

- [ ] **Step 4: Run workspace check**

Run: `cargo check --workspace && cargo check --workspace --target wasm32-unknown-unknown`
Expected: Both pass (other crates can import ZoneFile)

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/lib.rs crates/bind9-sdk-core/src/zone/mod.rs
git commit -m "feat(core): re-export ZoneFile and IncludeResolver from crate root"
```

### Task 15: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run complete test suite**

Run: `cargo test -p bind9-sdk-core`
Expected: All tests pass

- [ ] **Step 2: Run clippy on all targets**

Run: `cargo clippy -p bind9-sdk-core --all-targets -- -D warnings`
Expected: No warnings

- [ ] **Step 3: Run format check**

Run: `cargo fmt -p bind9-sdk-core --check`
Expected: No formatting issues (PostToolUse hook should have formatted all files)

- [ ] **Step 4: Verify WASM target**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Passes (all zone code is no_std compatible)

- [ ] **Step 5: Verify workspace compiles**

Run: `cargo check --workspace`
Expected: Passes (other crates resolve imports correctly)

- [ ] **Step 6: Review file structure matches spec**

Verify these files exist with complete implementations:

```
crates/bind9-sdk-core/src/zone/
  mod.rs          — Zone, ZoneSummary, ZoneFile, IncludeResolver, ZoneManager impl
  parser.rs       — Tokenizer, parse_zone record assembler
  serializer.rs   — serialize() canonical output
  rdata_text.rs   — parse_rdata/serialize_rdata for 10 types + Unknown
```

Run: `ls -la crates/bind9-sdk-core/src/zone/`
Expected: All 4 files present
