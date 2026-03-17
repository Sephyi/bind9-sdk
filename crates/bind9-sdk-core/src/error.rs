// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::string::String;

/// Errors from the `bind9-sdk-core` crate.
///
/// Variants are split by actionability — callers match on what they can handle
/// and use a wildcard for the rest. The enum is `#[non_exhaustive]` so new
/// variants can be added without a semver bump.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// A domain name failed validation (RFC 1035 §2.3.1).
    #[error("invalid domain name `{name}`: {reason}")]
    InvalidName {
        /// The rejected name string.
        name: String,
        /// Human-readable explanation of the validation failure.
        reason: String,
    },

    /// A DNS label failed validation (length, character set).
    #[error("invalid label: {0}")]
    InvalidLabel(String),

    /// Record data failed validation.
    #[error("invalid record data: {0}")]
    InvalidRecord(String),

    /// Zone file parsing failed at a specific line (and optionally column).
    #[error("zone parse error at line {line}{}: {reason}", column.map(|c| alloc::format!(", column {c}")).unwrap_or_default())]
    ZoneParse {
        /// 1-based line number where the parse error occurred.
        line: u32,
        /// 1-based column number where the parse error occurred (if available).
        column: Option<u32>,
        /// Human-readable description of the parse failure.
        reason: String,
    },

    /// DNS wire format encoding or decoding failed.
    #[error("wire format error: {0}")]
    WireFormat(String),

    /// TSIG authentication or signing error.
    #[error("TSIG error: {0}")]
    Tsig(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::string::ToString;

    #[test]
    fn invalid_name_error_formats_correctly() {
        let err = CoreError::InvalidName {
            name: "bad..name".into(),
            reason: "consecutive dots".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid domain name `bad..name`: consecutive dots"
        );
    }

    #[test]
    fn zone_parse_error_includes_line_number() {
        let err = CoreError::ZoneParse {
            line: 42,
            column: None,
            reason: "unexpected token".into(),
        };
        assert_eq!(
            err.to_string(),
            "zone parse error at line 42: unexpected token"
        );
    }

    #[test]
    fn zone_parse_error_includes_column_when_present() {
        let err = CoreError::ZoneParse {
            line: 7,
            column: Some(15),
            reason: "invalid rdata".into(),
        };
        assert_eq!(
            err.to_string(),
            "zone parse error at line 7, column 15: invalid rdata"
        );
    }

    #[test]
    #[allow(unreachable_patterns)] // #[non_exhaustive] only forces wildcard arms on external crates
    fn core_error_is_non_exhaustive() {
        let err = CoreError::WireFormat("test".into());
        match err {
            CoreError::InvalidName { .. } => {}
            CoreError::InvalidLabel(_) => {}
            CoreError::InvalidRecord(_) => {}
            CoreError::ZoneParse { .. } => {}
            CoreError::WireFormat(_) => {}
            CoreError::Tsig(_) => {}
            _ => {} // required by #[non_exhaustive]
        }
    }
}
