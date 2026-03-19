// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::string::String;
#[cfg(test)]
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
