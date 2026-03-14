// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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
        } => format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"),
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
    let rdata = decode_hex(&hex_str).map_err(|reason| CoreError::ZoneParse { line: 0, reason })?;

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
            .ok_or_else(|| format!("invalid hex character `{hi}`"))? as u8;
        let l = lo
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex character `{lo}`"))? as u8;
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

fn serialize_unknown(_rtype: u16, rdata: &[u8]) -> String {
    if rdata.is_empty() {
        "\\# 0".into()
    } else {
        format!("\\# {} {}", rdata.len(), encode_hex(rdata))
    }
}

fn serialize_as_generic(_rdata: &RecordData) -> String {
    // For record types we don't have text format support yet,
    // fall back to zero-length generic format.
    String::from("\\# 0")
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
        assert_eq!(rdata, RecordData::Aaaa("2001:db8::1".parse().unwrap()));
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
        let rdata = parse_rdata("CNAME", &["www.example.com."], &origin()).unwrap();
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
        let rdata = parse_rdata("PTR", &["host.example.com."], &origin()).unwrap();
        assert_eq!(
            rdata,
            RecordData::Ptr(DomainName::new("host.example.com.").unwrap())
        );
    }

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

    // -- TXT record --

    #[test]
    fn parse_txt_single_string() {
        let rdata = parse_rdata("TXT", &["v=spf1 ~all"], &origin()).unwrap();
        assert_eq!(rdata, RecordData::Txt(alloc::vec!["v=spf1 ~all".into()]));
    }

    #[test]
    fn parse_txt_multiple_strings() {
        let rdata =
            parse_rdata("TXT", &["v=spf1", "include:example.com", "~all"], &origin()).unwrap();
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
        let rdata = RecordData::Txt(alloc::vec!["v=spf1".into(), "include:example.com".into(),]);
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
        let rdata =
            parse_rdata("SRV", &["10", "60", "5060", "sip.example.com."], &origin()).unwrap();
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
        let rdata = parse_rdata("SRV", &["0", "0", "443", "web"], &origin()).unwrap();
        match rdata {
            RecordData::Srv { target, .. } => {
                assert_eq!(target, DomainName::new("web.example.com.").unwrap());
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
        assert_eq!(serialize_rdata(&rdata), "10 60 5060 sip.example.com.");
    }

    // -- CAA record --

    #[test]
    fn parse_caa_valid() {
        let rdata = parse_rdata("CAA", &["0", "issue", "letsencrypt.org"], &origin()).unwrap();
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
        let rdata = parse_rdata("CAA", &["128", "issuewild", ";"], &origin()).unwrap();
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
        assert_eq!(serialize_rdata(&rdata), "0 issue \"letsencrypt.org\"");
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
        let rdata = RecordData::Cname(DomainName::new("www.example.com.").unwrap());
        assert_eq!(serialize_rdata(&rdata), "www.example.com.");
    }

    #[test]
    fn serialize_ptr() {
        let rdata = RecordData::Ptr(DomainName::new("host.example.com.").unwrap());
        assert_eq!(serialize_rdata(&rdata), "host.example.com.");
    }

    // -- Unknown / RFC 3597 generic format --

    #[test]
    fn parse_unknown_type_generic_format() {
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
}
