// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::string::String;
use alloc::vec::Vec;

use crate::domain::DomainName;
use crate::error::CoreError;
use crate::record::{RecordClass, ResourceRecord, Ttl};
use crate::zone::rdata_text;
use crate::zone::{IncludeResolver, Zone, ZoneFile};

use super::tokenizer::Token;

const MAX_INCLUDE_DEPTH: usize = 16;

/// Maximum accepted size of a single zone-file text (or `$INCLUDE` body), in
/// bytes. Enforced before tokenizing so a hostile input cannot drive unbounded
/// work or allocation (PRD SR-005). 256 MiB is far above any zone managed via
/// rndc in practice (~8M minimal records) while keeping worst-case parse time
/// bounded — the parser itself is linear in input length.
const MAX_ZONE_INPUT_BYTES: usize = 256 * 1024 * 1024;

/// Maximum number of resource records produced from one parse. Enforced while
/// records accumulate so a pathological input cannot exhaust memory through
/// record count alone (PRD SR-005).
const MAX_ZONE_RECORDS: usize = 16 * 1024 * 1024;

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
    let mut state = ParseState {
        origin: None,
        zone_origin: None,
        default_ttl: None,
        default_class: RecordClass::IN,
        last_owner: None,
        records: Vec::new(),
    };
    parse_into(input, resolver, &mut state, 0)?;

    // Determine zone origin
    let zone_origin = if let Some(o) = state.zone_origin {
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
                column: None,
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

fn parse_into(
    input: &str,
    resolver: Option<&dyn IncludeResolver>,
    state: &mut ParseState,
    include_depth: usize,
) -> Result<(), CoreError> {
    if include_depth > MAX_INCLUDE_DEPTH {
        return Err(CoreError::ZoneParse {
            line: 1,
            column: None,
            reason: alloc::format!("$INCLUDE include depth exceeds maximum of {MAX_INCLUDE_DEPTH}"),
        });
    }

    // SR-005: reject oversized input before doing any tokenization or allocation.
    if input.len() > MAX_ZONE_INPUT_BYTES {
        return Err(CoreError::ZoneParse {
            line: 1,
            column: None,
            reason: alloc::format!(
                "zone input of {} bytes exceeds the maximum of {MAX_ZONE_INPUT_BYTES} bytes",
                input.len()
            ),
        });
    }

    use super::tokenizer::Tokenizer;

    let mut tok = Tokenizer::new(input);

    let mut current_tokens: Vec<Token> = Vec::new();
    let mut record_line: u32 = tok.line();

    loop {
        let t = tok.next_token();
        match t {
            None => {
                if !current_tokens.is_empty() {
                    process_line(&current_tokens, record_line, state, resolver, include_depth)?;
                }
                break;
            }
            Some(Token::Newline) => {
                if !current_tokens.is_empty() {
                    process_line(&current_tokens, record_line, state, resolver, include_depth)?;
                    current_tokens.clear();
                }
                if state.records.len() > MAX_ZONE_RECORDS {
                    return Err(CoreError::ZoneParse {
                        line: record_line,
                        column: None,
                        reason: alloc::format!(
                            "zone exceeds the maximum of {MAX_ZONE_RECORDS} records"
                        ),
                    });
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

    Ok(())
}

/// Mutable parsing state threaded through record assembly.
struct ParseState {
    origin: Option<DomainName>,
    zone_origin: Option<DomainName>,
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
    include_depth: usize,
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
                        column: None,
                        reason: "$ORIGIN requires a domain name argument".into(),
                    });
                }
                let name_str = token_as_str(&tokens[1]);
                let o = if name_str.ends_with('.') {
                    DomainName::new(&name_str)
                } else {
                    let current = state.origin.as_ref().ok_or_else(|| CoreError::ZoneParse {
                        line,
                        column: None,
                        reason: "relative $ORIGIN requires an existing origin".into(),
                    })?;
                    resolve_owner(&name_str, current)
                }
                .map_err(|e| CoreError::ZoneParse {
                    line,
                    column: None,
                    reason: alloc::format!("invalid $ORIGIN `{name_str}`: {e}"),
                })?;
                if state.zone_origin.is_none() {
                    state.zone_origin = Some(o.clone());
                }
                state.origin = Some(o);
                return Ok(());
            }
            "$TTL" => {
                if tokens.len() < 2 {
                    return Err(CoreError::ZoneParse {
                        line,
                        column: None,
                        reason: "$TTL requires a value".into(),
                    });
                }
                let ttl_str = token_as_str(&tokens[1]);
                let val: u32 = ttl_str.parse().map_err(|e| CoreError::ZoneParse {
                    line,
                    column: None,
                    reason: alloc::format!("invalid $TTL `{ttl_str}`: {e}"),
                })?;
                state.default_ttl = Some(Ttl::new(val).map_err(|e| CoreError::ZoneParse {
                    line,
                    column: None,
                    reason: alloc::format!("invalid $TTL value: {e}"),
                })?);
                return Ok(());
            }
            "$INCLUDE" => {
                if let Some(r) = resolver {
                    if tokens.len() < 2 {
                        return Err(CoreError::ZoneParse {
                            line,
                            column: None,
                            reason: "$INCLUDE requires a file path".into(),
                        });
                    }
                    let path = token_as_str(&tokens[1]);
                    let content = r.resolve(&path)?;
                    let saved_origin = state.origin.clone();
                    let saved_owner = state.last_owner.clone();

                    if tokens.len() >= 3 {
                        let include_origin = token_as_str(&tokens[2]);
                        let origin = if include_origin.ends_with('.') {
                            DomainName::new(&include_origin)
                        } else {
                            let current =
                                state.origin.as_ref().ok_or_else(|| CoreError::ZoneParse {
                                    line,
                                    column: None,
                                    reason: "relative $INCLUDE origin requires an existing origin"
                                        .into(),
                                })?;
                            resolve_owner(&include_origin, current)
                        }
                        .map_err(|e| CoreError::ZoneParse {
                            line,
                            column: None,
                            reason: alloc::format!(
                                "invalid $INCLUDE origin `{include_origin}`: {e}"
                            ),
                        })?;
                        state.origin = Some(origin);
                    }

                    let result = parse_into(&content, Some(r), state, include_depth + 1);
                    state.origin = saved_origin;
                    state.last_owner = saved_owner;
                    result?;
                    return Ok(());
                }
                return Err(CoreError::ZoneParse {
                    line,
                    column: None,
                    reason: "$INCLUDE directive not supported without a resolver".into(),
                });
            }
            other => {
                return Err(CoreError::ZoneParse {
                    line,
                    column: None,
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
        state
            .last_owner
            .clone()
            .ok_or_else(|| CoreError::ZoneParse {
                line,
                column: None,
                reason: "inherited owner name but no previous owner".into(),
            })?
    } else if is_class(word_refs[0]).is_some()
        || is_record_type(word_refs[0])
        || is_ttl(word_refs[0])
    {
        state
            .last_owner
            .clone()
            .ok_or_else(|| CoreError::ZoneParse {
                line,
                column: None,
                reason: "inherited owner name but no previous owner".into(),
            })?
    } else if word_refs[0].ends_with('.') {
        let o = DomainName::new(word_refs[0]).map_err(|e| CoreError::ZoneParse {
            line,
            column: None,
            reason: alloc::format!("invalid owner name `{}`: {e}", word_refs[0]),
        })?;
        pos += 1;
        o
    } else if word_refs[0] == "@" {
        let cur_origin = state.origin.as_ref().ok_or_else(|| CoreError::ZoneParse {
            line,
            column: None,
            reason: "@ used but no $ORIGIN set".into(),
        })?;
        pos += 1;
        cur_origin.clone()
    } else {
        let cur_origin = state.origin.as_ref().ok_or_else(|| CoreError::ZoneParse {
            line,
            column: None,
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
                column: None,
                reason: alloc::format!("invalid TTL `{}`: {e}", word_refs[pos]),
            })?;
            record_ttl = Some(Ttl::new(val).map_err(|e| CoreError::ZoneParse {
                line,
                column: None,
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
            column: None,
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
            CoreError::ZoneParse { reason, .. } => CoreError::ZoneParse {
                line,
                column: None,
                reason,
            },
            other => other,
        })?;

    let ttl = record_ttl
        .or(state.default_ttl)
        .ok_or_else(|| CoreError::ZoneParse {
            line,
            column: None,
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
