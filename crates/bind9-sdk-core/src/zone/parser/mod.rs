// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Zone file parser: tokenizer and record assembler.
//!
//! The parser is split into two submodules:
//! - `tokenizer` — lexes raw zone file text into [`Token`] values
//! - `record` — assembles tokens into [`ResourceRecord`] values with full RFC 1035 semantics

mod record;
pub(crate) mod tokenizer;

#[cfg(test)]
mod tests;

pub(crate) use self::record::parse_zone;
