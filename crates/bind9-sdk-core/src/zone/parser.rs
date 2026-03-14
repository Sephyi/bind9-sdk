// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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

    /// Consume and return the next token, or None at EOF.
    pub(crate) fn next_token(&mut self) -> Option<Token> {
        let bytes = self.input.as_bytes();
        if self.pos >= bytes.len() {
            return None;
        }

        // Check if we are at the start of a line and the first char is whitespace.
        // This signals owner name inheritance.
        let at_line_start = self.pos == 0 || (self.pos > 0 && bytes[self.pos - 1] == b'\n');

        // Skip whitespace (but NOT newlines — those are significant tokens)
        let had_leading_space =
            self.pos < bytes.len() && (bytes[self.pos] == b' ' || bytes[self.pos] == b'\t');
        while self.pos < bytes.len() && (bytes[self.pos] == b' ' || bytes[self.pos] == b'\t') {
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

    /// Collect all remaining tokens into a Vec.
    #[cfg(test)]
    pub(crate) fn tokenize_all(&mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        while let Some(tok) = self.next_token() {
            tokens.push(tok);
        }
        tokens
    }
}

use crate::domain::DomainName;
use crate::error::CoreError;
use crate::record::{RecordClass, ResourceRecord, Ttl};
use crate::zone::rdata_text;
use crate::zone::{IncludeResolver, Zone, ZoneFile};

/// Check if a word token is a record class keyword.
fn is_class(word: &str) -> Option<RecordClass> {
    match word {
        "IN" | "in" => Some(RecordClass::IN),
        "CH" | "ch" => Some(RecordClass::CH),
        "HS" | "hs" => Some(RecordClass::HS),
        _ => None,
    }
}

/// Check if a word token is a record type keyword.
fn is_record_type(word: &str) -> bool {
    matches!(
        word,
        "A" | "AAAA"
            | "CNAME"
            | "NS"
            | "PTR"
            | "SOA"
            | "MX"
            | "TXT"
            | "SRV"
            | "CAA"
            | "DNSKEY"
            | "RRSIG"
            | "NSEC"
            | "NSEC3"
            | "DS"
            | "CDS"
            | "CDNSKEY"
            | "TLSA"
            | "SSHFP"
            | "CSYNC"
            | "RP"
    ) || word.starts_with("TYPE")
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
    let mut tok = Tokenizer::new(input);
    let mut state = ParseState {
        origin: None,
        default_ttl: None,
        default_class: RecordClass::IN,
        last_owner: None,
        records: Vec::new(),
    };

    let mut current_tokens: Vec<Token> = Vec::new();
    let mut record_line: u32 = tok.line();

    loop {
        let t = tok.next_token();
        match t {
            None => {
                if !current_tokens.is_empty() {
                    process_line(&current_tokens, record_line, &mut state, resolver)?;
                }
                break;
            }
            Some(Token::Newline) => {
                if !current_tokens.is_empty() {
                    process_line(&current_tokens, record_line, &mut state, resolver)?;
                    current_tokens.clear();
                }
                record_line = tok.line();
            }
            Some(Token::ParenOpen) | Some(Token::ParenClose) => {
                // Parens are consumed by tokenizer for line continuation
            }
            Some(token) => {
                current_tokens.push(token);
            }
        }
    }

    // Determine zone origin
    let zone_origin = if let Some(o) = state.origin {
        o
    } else {
        // Try to infer from the first SOA record
        state
            .records
            .iter()
            .find(|rr| matches!(rr.rdata, crate::rdata::RecordData::Soa { .. }))
            .map(|rr| rr.name.clone())
            .ok_or_else(|| CoreError::ZoneParse {
                line: 1,
                reason: "no $ORIGIN directive and no SOA record found".into(),
            })?
    };

    let zone = Zone {
        name: zone_origin.clone(),
        class: state.default_class,
        records: state.records,
    };

    Ok(ZoneFile {
        origin: zone_origin,
        default_ttl: state.default_ttl,
        zone,
    })
}

/// Mutable parsing state threaded through record assembly.
struct ParseState {
    origin: Option<DomainName>,
    default_ttl: Option<Ttl>,
    default_class: RecordClass,
    last_owner: Option<DomainName>,
    records: Vec<ResourceRecord>,
}

/// Process a single logical line of tokens.
#[allow(clippy::too_many_lines)]
fn process_line(
    tokens: &[Token],
    line: u32,
    state: &mut ParseState,
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
                state.origin = Some(o);
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
                state.default_ttl = Some(Ttl::new(val).map_err(|e| CoreError::ZoneParse {
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
                    state.records.extend(included.zone.records);
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

    // Extract word strings from tokens
    let words: Vec<String> = tokens
        .iter()
        .map(|t| match t {
            Token::Word(w) => w.clone(),
            Token::QuotedString(s) => s.clone(),
            Token::Directive(d) => d.clone(),
            _ => String::new(),
        })
        .collect();
    let word_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();

    // Parse owner name, class, TTL, type, rdata
    let mut pos = 0;

    // Owner name: if first word is empty (inherited), use last_owner
    let owner = if word_refs[0].is_empty() {
        pos += 1;
        state.last_owner.clone().ok_or_else(|| CoreError::ZoneParse {
            line,
            reason: "inherited owner name but no previous owner".into(),
        })?
    } else if is_class(word_refs[0]).is_some()
        || is_record_type(word_refs[0])
        || is_ttl(word_refs[0])
    {
        state.last_owner.clone().ok_or_else(|| CoreError::ZoneParse {
            line,
            reason: "inherited owner name but no previous owner".into(),
        })?
    } else if word_refs[0].ends_with('.') {
        let o = DomainName::new(word_refs[0]).map_err(|e| CoreError::ZoneParse {
            line,
            reason: alloc::format!("invalid owner name `{}`: {e}", word_refs[0]),
        })?;
        pos += 1;
        o
    } else if word_refs[0] == "@" {
        let cur_origin = state.origin.as_ref().ok_or_else(|| CoreError::ZoneParse {
            line,
            reason: "@ used but no $ORIGIN set".into(),
        })?;
        pos += 1;
        cur_origin.clone()
    } else {
        let cur_origin = state.origin.as_ref().ok_or_else(|| CoreError::ZoneParse {
            line,
            reason: "relative name used before $ORIGIN; set $ORIGIN or use absolute owner names"
                .into(),
        })?;
        let o = resolve_owner(word_refs[0], cur_origin)?;
        pos += 1;
        o
    };

    state.last_owner = Some(owner.clone());

    // Parse optional TTL and class in either order
    let mut record_ttl: Option<Ttl> = None;
    let mut record_class: Option<RecordClass> = None;

    for _ in 0..2 {
        if pos >= word_refs.len() {
            break;
        }
        if record_class.is_none()
            && let Some(c) = is_class(word_refs[pos])
        {
            record_class = Some(c);
            pos += 1;
            continue;
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
    let rtype = {
        let w = word_refs[pos];
        let mut upper = String::with_capacity(w.len());
        for c in w.chars() {
            upper.push(c.to_ascii_uppercase());
        }
        upper
    };
    pos += 1;

    // Remaining tokens are rdata — use origin for name resolution (fall back to owner name)
    let rdata_origin = state
        .origin
        .as_ref()
        .cloned()
        .unwrap_or_else(|| owner.clone());
    let rdata_strs: Vec<&str> = word_refs[pos..].to_vec();
    let rdata =
        rdata_text::parse_rdata(&rtype, &rdata_strs, &rdata_origin).map_err(|e| match e {
            CoreError::ZoneParse { reason, .. } => CoreError::ZoneParse { line, reason },
            other => other,
        })?;

    let ttl = record_ttl
        .or(state.default_ttl)
        .ok_or_else(|| CoreError::ZoneParse {
            line,
            reason: "no TTL specified and no $TTL default set".into(),
        })?;

    let class = record_class.unwrap_or(state.default_class);
    if record_class.is_some() {
        state.default_class = class;
    }

    state.records.push(ResourceRecord {
        name: owner,
        class,
        ttl,
        rdata,
    });

    Ok(())
}

/// Extract the string content from a token.
fn token_as_str(token: &Token) -> String {
    match token {
        Token::Word(w) => w.clone(),
        Token::QuotedString(s) => s.clone(),
        Token::Directive(d) => d.clone(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

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

    // Task 2: Escape sequence edge cases

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
}

#[cfg(test)]
mod assembler_tests {
    extern crate alloc;
    use crate::domain::DomainName;
    use crate::rdata::RecordData;
    use crate::record::{RecordClass, Ttl};
    use crate::zone::ZoneFile;
    use alloc::string::ToString;

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

    // Task 9: Error reporting tests

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
}
