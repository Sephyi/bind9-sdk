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

    /// Whether the tokenizer is inside a parenthesized group.
    pub(crate) fn in_parens(&self) -> bool {
        self.in_parens
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
