// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;
use core::str::FromStr;

use crate::domain::DomainName;
use crate::error::CoreError;
use crate::tsig::{TsigAlgorithm, TsigKey};

/// One element in a BIND address-match list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AclElement {
    /// Match every address.
    Any,
    /// Match no address.
    None,
    /// BIND's built-in `localhost` ACL.
    Localhost,
    /// BIND's built-in `localnets` ACL.
    Localnets,
    /// One IP address.
    Address(IpAddr),
    /// One CIDR network.
    Network { address: IpAddr, prefix: u8 },
    /// A TSIG key identity.
    Key(DomainName),
    /// A reference to a named ACL.
    Named(String),
    /// Negation of another match element.
    Negated(Box<AclElement>),
}

/// A typed BIND address-match list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Acl {
    /// Elements in declaration order.
    pub elements: Vec<AclElement>,
}

/// A named top-level ACL declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NamedAcl {
    /// ACL name.
    pub name: String,
    /// ACL contents.
    pub acl: Acl,
}

/// Supported BIND zone types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamedZoneType {
    /// Writable primary zone.
    Primary,
    /// Transferred secondary zone.
    Secondary,
    /// Stub zone.
    Stub,
    /// Forward-only zone declaration.
    Forward,
}

/// SDK-relevant fields from one `zone` block.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NamedZone {
    /// Absolute zone name.
    pub name: DomainName,
    /// Zone role.
    pub zone_type: NamedZoneType,
    /// Configured master-file path.
    pub file: Option<String>,
    /// Transfer authorization list.
    pub allow_transfer: Option<Acl>,
}

/// Address accepted by a control or statistics listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenAddress {
    /// BIND wildcard (`*` or `any`).
    Any,
    /// Concrete IP address.
    Ip(IpAddr),
}

/// One `controls` listener.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ControlEndpoint {
    /// Listen address.
    pub address: ListenAddress,
    /// Listen port.
    pub port: u16,
    /// Client address authorization.
    pub allow: Option<Acl>,
    /// Accepted TSIG key names.
    pub keys: Vec<DomainName>,
}

/// One statistics-channel listener.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StatisticsChannel {
    /// Listen address.
    pub address: ListenAddress,
    /// Listen port.
    pub port: u16,
    /// Client address authorization.
    pub allow: Option<Acl>,
}

/// SDK-relevant `options` fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NamedOptions {
    /// Base directory for relative paths.
    pub directory: Option<String>,
    /// Recursive-query authorization.
    pub allow_recursion: Option<Acl>,
}

/// Parsed SDK-relevant subset of a BIND `named.conf`.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct NamedConf {
    /// Zone declarations.
    pub zones: Vec<NamedZone>,
    /// TSIG keys. Debug output remains redacted through [`TsigKey`].
    pub keys: Vec<TsigKey>,
    /// Named ACL declarations.
    pub acls: Vec<NamedAcl>,
    /// Global options.
    pub options: NamedOptions,
    /// RNDC control listeners.
    pub controls: Vec<ControlEndpoint>,
    /// Statistics-channel listeners.
    pub statistics_channels: Vec<StatisticsChannel>,
}

impl NamedConf {
    /// Parse the bounded SDK-relevant `named.conf` subset.
    ///
    /// Unknown statements are skipped structurally. Supported statements are
    /// validated and return path-and-line diagnostics when malformed.
    pub fn parse(path: &str, input: &str) -> Result<Self, CoreError> {
        Parser::new(path, tokenize(path, input)?).parse()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Word(String),
    Quoted(String),
    Open,
    Close,
    Semi,
    Bang,
}

#[derive(Debug, Clone)]
struct Token {
    kind: Kind,
    line: u32,
}

fn parse_error(path: &str, line: u32, reason: impl Into<String>) -> CoreError {
    CoreError::NamedConfParse {
        path: path.to_string(),
        line,
        reason: reason.into(),
    }
}

fn tokenize(path: &str, input: &str) -> Result<Vec<Token>, CoreError> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut line = 1u32;
    while index < chars.len() {
        match chars[index] {
            '\n' => {
                line += 1;
                index += 1;
            }
            c if c.is_whitespace() => index += 1,
            '#' => {
                while index < chars.len() && chars[index] != '\n' {
                    index += 1;
                }
            }
            '/' if chars.get(index + 1) == Some(&'/') => {
                index += 2;
                while index < chars.len() && chars[index] != '\n' {
                    index += 1;
                }
            }
            '/' if chars.get(index + 1) == Some(&'*') => {
                let start = line;
                index += 2;
                let mut closed = false;
                while index + 1 < chars.len() {
                    if chars[index] == '\n' {
                        line += 1;
                    }
                    if chars[index] == '*' && chars[index + 1] == '/' {
                        index += 2;
                        closed = true;
                        break;
                    }
                    index += 1;
                }
                if !closed {
                    return Err(parse_error(path, start, "unterminated block comment"));
                }
            }
            '"' => {
                let start = line;
                index += 1;
                let mut value = String::new();
                let mut closed = false;
                while index < chars.len() {
                    match chars[index] {
                        '"' => {
                            index += 1;
                            closed = true;
                            break;
                        }
                        '\\' => {
                            index += 1;
                            let Some(&escaped) = chars.get(index) else {
                                break;
                            };
                            value.push(escaped);
                            index += 1;
                        }
                        '\n' => {
                            line += 1;
                            value.push('\n');
                            index += 1;
                        }
                        c => {
                            value.push(c);
                            index += 1;
                        }
                    }
                }
                if !closed {
                    return Err(parse_error(path, start, "unterminated quoted string"));
                }
                tokens.push(Token {
                    kind: Kind::Quoted(value),
                    line: start,
                });
            }
            '{' | '}' | ';' | '!' => {
                let kind = match chars[index] {
                    '{' => Kind::Open,
                    '}' => Kind::Close,
                    ';' => Kind::Semi,
                    _ => Kind::Bang,
                };
                tokens.push(Token { kind, line });
                index += 1;
            }
            _ => {
                let start = index;
                while index < chars.len() {
                    let current = chars[index];
                    let starts_comment =
                        current == '/' && matches!(chars.get(index + 1), Some('/') | Some('*'));
                    if current.is_whitespace()
                        || matches!(current, '{' | '}' | ';' | '!' | '"')
                        || starts_comment
                    {
                        break;
                    }
                    index += 1;
                }
                tokens.push(Token {
                    kind: Kind::Word(chars[start..index].iter().collect()),
                    line,
                });
            }
        }
    }
    Ok(tokens)
}

struct Parser<'a> {
    path: &'a str,
    tokens: Vec<Token>,
    pos: usize,
    output: NamedConf,
}

impl<'a> Parser<'a> {
    fn new(path: &'a str, tokens: Vec<Token>) -> Self {
        Self {
            path,
            tokens,
            pos: 0,
            output: NamedConf::default(),
        }
    }

    fn parse(mut self) -> Result<NamedConf, CoreError> {
        while self.pos < self.tokens.len() {
            let token = self.next()?;
            let keyword = self.text(&token)?.to_ascii_lowercase();
            match keyword.as_str() {
                "zone" => {
                    let zone = self.parse_zone(token.line)?;
                    self.output.zones.push(zone);
                }
                "key" => {
                    let key = self.parse_key(token.line)?;
                    self.output.keys.push(key);
                }
                "acl" => {
                    let acl = self.parse_named_acl(token.line)?;
                    self.output.acls.push(acl);
                }
                "options" => self.parse_options(token.line)?,
                "controls" => {
                    let endpoints = self.parse_controls(token.line)?;
                    self.output.controls.extend(endpoints);
                }
                "statistics-channels" => {
                    let channels = self.parse_statistics_channels(token.line)?;
                    self.output.statistics_channels.extend(channels);
                }
                _ => self.skip_statement(token.line)?,
            }
        }
        Ok(self.output)
    }

    fn parse_zone(&mut self, line: u32) -> Result<NamedZone, CoreError> {
        let name_text = self.next_text()?;
        let name = DomainName::new(&name_text)
            .map_err(|error| parse_error(self.path, line, error.to_string()))?;
        self.expect(Kind::Open)?;
        let mut zone_type = None;
        let mut file = None;
        let mut allow_transfer = None;
        while !self.consume(&Kind::Close) {
            let directive = self.next()?;
            match self.text(&directive)?.to_ascii_lowercase().as_str() {
                "type" => {
                    let value = self.next_text()?.to_ascii_lowercase();
                    zone_type = Some(match value.as_str() {
                        "primary" | "master" => NamedZoneType::Primary,
                        "secondary" | "slave" => NamedZoneType::Secondary,
                        "stub" => NamedZoneType::Stub,
                        "forward" => NamedZoneType::Forward,
                        _ => {
                            return Err(parse_error(
                                self.path,
                                directive.line,
                                alloc::format!("unsupported zone type `{value}`"),
                            ));
                        }
                    });
                    self.expect(Kind::Semi)?;
                }
                "file" => {
                    file = Some(self.next_text()?);
                    self.expect(Kind::Semi)?;
                }
                "allow-transfer" => {
                    allow_transfer = Some(self.parse_acl()?);
                    self.expect(Kind::Semi)?;
                }
                _ => self.skip_statement(directive.line)?,
            }
        }
        self.expect(Kind::Semi)?;
        Ok(NamedZone {
            name,
            zone_type: zone_type
                .ok_or_else(|| parse_error(self.path, line, "zone block is missing `type`"))?,
            file,
            allow_transfer,
        })
    }

    fn parse_key(&mut self, line: u32) -> Result<TsigKey, CoreError> {
        let name_text = self.next_text()?;
        let name = DomainName::new(&name_text)
            .map_err(|error| parse_error(self.path, line, error.to_string()))?;
        self.expect(Kind::Open)?;
        let mut algorithm = None;
        let mut secret = None;
        while !self.consume(&Kind::Close) {
            let directive = self.next()?;
            match self.text(&directive)?.to_ascii_lowercase().as_str() {
                "algorithm" => {
                    let value = self.next_text()?.to_ascii_lowercase();
                    #[allow(deprecated)]
                    let parsed = match value.trim_end_matches('.') {
                        "hmac-sha256" => TsigAlgorithm::HmacSha256,
                        "hmac-sha512" => TsigAlgorithm::HmacSha512,
                        "hmac-sha1" => TsigAlgorithm::HmacSha1,
                        _ => {
                            return Err(parse_error(
                                self.path,
                                directive.line,
                                alloc::format!("unsupported TSIG algorithm `{value}`"),
                            ));
                        }
                    };
                    algorithm = Some(parsed);
                    self.expect(Kind::Semi)?;
                }
                "secret" => {
                    secret = Some(self.next_text()?);
                    self.expect(Kind::Semi)?;
                }
                _ => self.skip_statement(directive.line)?,
            }
        }
        self.expect(Kind::Semi)?;
        let algorithm = algorithm
            .ok_or_else(|| parse_error(self.path, line, "key block is missing `algorithm`"))?;
        let secret =
            secret.ok_or_else(|| parse_error(self.path, line, "key block is missing `secret`"))?;
        TsigKey::from_base64(name, algorithm, &secret)
            .map_err(|error| parse_error(self.path, line, error.to_string()))
    }

    fn parse_named_acl(&mut self, _line: u32) -> Result<NamedAcl, CoreError> {
        let name = self.next_text()?;
        let acl = self.parse_acl()?;
        self.expect(Kind::Semi)?;
        Ok(NamedAcl { name, acl })
    }

    fn parse_options(&mut self, line: u32) -> Result<(), CoreError> {
        self.expect(Kind::Open)?;
        while !self.consume(&Kind::Close) {
            let directive = self.next()?;
            match self.text(&directive)?.to_ascii_lowercase().as_str() {
                "directory" => {
                    self.output.options.directory = Some(self.next_text()?);
                    self.expect(Kind::Semi)?;
                }
                "allow-recursion" => {
                    self.output.options.allow_recursion = Some(self.parse_acl()?);
                    self.expect(Kind::Semi)?;
                }
                "statistics-channels" => {
                    let channels = self.parse_statistics_channels(directive.line)?;
                    self.output.statistics_channels.extend(channels);
                }
                _ => self.skip_statement(directive.line)?,
            }
        }
        self.expect(Kind::Semi)
            .map_err(|_| parse_error(self.path, line, "unterminated options block"))
    }

    fn parse_controls(&mut self, _line: u32) -> Result<Vec<ControlEndpoint>, CoreError> {
        self.expect(Kind::Open)?;
        let mut endpoints = Vec::new();
        while !self.consume(&Kind::Close) {
            let directive = self.next()?;
            if self.text(&directive)?.eq_ignore_ascii_case("inet") {
                let address = parse_listen(self.path, directive.line, &self.next_text()?)?;
                let mut endpoint = ControlEndpoint {
                    address,
                    port: 953,
                    allow: None,
                    keys: Vec::new(),
                };
                while !self.consume(&Kind::Semi) {
                    let option = self.next()?;
                    match self.text(&option)?.to_ascii_lowercase().as_str() {
                        "port" => endpoint.port = self.parse_port()?,
                        "allow" => endpoint.allow = Some(self.parse_acl()?),
                        "keys" => endpoint.keys = self.parse_key_names()?,
                        _ => self.skip_statement(option.line)?,
                    }
                }
                endpoints.push(endpoint);
            } else {
                self.skip_statement(directive.line)?;
            }
        }
        self.expect(Kind::Semi)?;
        Ok(endpoints)
    }

    fn parse_statistics_channels(
        &mut self,
        _line: u32,
    ) -> Result<Vec<StatisticsChannel>, CoreError> {
        self.expect(Kind::Open)?;
        let mut channels = Vec::new();
        while !self.consume(&Kind::Close) {
            let directive = self.next()?;
            if self.text(&directive)?.eq_ignore_ascii_case("inet") {
                let address = parse_listen(self.path, directive.line, &self.next_text()?)?;
                let mut channel = StatisticsChannel {
                    address,
                    port: 80,
                    allow: None,
                };
                while !self.consume(&Kind::Semi) {
                    let option = self.next()?;
                    match self.text(&option)?.to_ascii_lowercase().as_str() {
                        "port" => channel.port = self.parse_port()?,
                        "allow" => channel.allow = Some(self.parse_acl()?),
                        _ => self.skip_statement(option.line)?,
                    }
                }
                channels.push(channel);
            } else {
                self.skip_statement(directive.line)?;
            }
        }
        self.expect(Kind::Semi)?;
        Ok(channels)
    }

    fn parse_acl(&mut self) -> Result<Acl, CoreError> {
        self.expect(Kind::Open)?;
        let mut elements = Vec::new();
        while !self.consume(&Kind::Close) {
            let negated = self.consume(&Kind::Bang);
            let token = self.next()?;
            let text = self.text(&token)?;
            let element = if text.eq_ignore_ascii_case("key") {
                let name = self.next_text()?;
                AclElement::Key(
                    DomainName::new(&name)
                        .map_err(|error| parse_error(self.path, token.line, error.to_string()))?,
                )
            } else {
                parse_acl_element(self.path, token.line, text)?
            };
            self.expect(Kind::Semi)?;
            elements.push(if negated {
                AclElement::Negated(Box::new(element))
            } else {
                element
            });
        }
        Ok(Acl { elements })
    }

    fn parse_key_names(&mut self) -> Result<Vec<DomainName>, CoreError> {
        self.expect(Kind::Open)?;
        let mut keys = Vec::new();
        while !self.consume(&Kind::Close) {
            let token = self.next()?;
            let name = self.text(&token)?;
            keys.push(
                DomainName::new(name)
                    .map_err(|error| parse_error(self.path, token.line, error.to_string()))?,
            );
            self.expect(Kind::Semi)?;
        }
        Ok(keys)
    }

    fn parse_port(&mut self) -> Result<u16, CoreError> {
        let token = self.next()?;
        self.text(&token)?.parse().map_err(|_| {
            parse_error(
                self.path,
                token.line,
                alloc::format!("invalid port `{}`", self.text(&token).unwrap_or("")),
            )
        })
    }

    fn skip_statement(&mut self, line: u32) -> Result<(), CoreError> {
        let mut depth = 0usize;
        while let Some(token) = self.tokens.get(self.pos) {
            match token.kind {
                Kind::Open => {
                    depth += 1;
                    self.pos += 1;
                }
                Kind::Close if depth > 0 => {
                    depth -= 1;
                    self.pos += 1;
                }
                Kind::Semi if depth == 0 => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => self.pos += 1,
            }
        }
        Err(parse_error(self.path, line, "unterminated statement"))
    }

    fn next(&mut self) -> Result<Token, CoreError> {
        let token = self.tokens.get(self.pos).cloned().ok_or_else(|| {
            parse_error(
                self.path,
                self.tokens.last().map_or(1, |token| token.line),
                "unexpected end of file",
            )
        })?;
        self.pos += 1;
        Ok(token)
    }

    fn next_text(&mut self) -> Result<String, CoreError> {
        let token = self.next()?;
        Ok(self.text(&token)?.to_string())
    }

    fn text<'b>(&self, token: &'b Token) -> Result<&'b str, CoreError> {
        match &token.kind {
            Kind::Word(value) | Kind::Quoted(value) => Ok(value),
            _ => Err(parse_error(self.path, token.line, "expected a value")),
        }
    }

    fn expect(&mut self, expected: Kind) -> Result<(), CoreError> {
        let token = self.next()?;
        if token.kind == expected {
            Ok(())
        } else {
            Err(parse_error(
                self.path,
                token.line,
                alloc::format!("expected {expected:?}, got {:?}", token.kind),
            ))
        }
    }

    fn consume(&mut self, expected: &Kind) -> bool {
        if self
            .tokens
            .get(self.pos)
            .is_some_and(|t| &t.kind == expected)
        {
            self.pos += 1;
            true
        } else {
            false
        }
    }
}

fn parse_listen(path: &str, line: u32, value: &str) -> Result<ListenAddress, CoreError> {
    if value == "*" || value.eq_ignore_ascii_case("any") {
        Ok(ListenAddress::Any)
    } else {
        IpAddr::from_str(value).map(ListenAddress::Ip).map_err(|_| {
            parse_error(
                path,
                line,
                alloc::format!("invalid listen address `{value}`"),
            )
        })
    }
}

fn parse_acl_element(path: &str, line: u32, value: &str) -> Result<AclElement, CoreError> {
    match value.to_ascii_lowercase().as_str() {
        "any" => return Ok(AclElement::Any),
        "none" => return Ok(AclElement::None),
        "localhost" => return Ok(AclElement::Localhost),
        "localnets" => return Ok(AclElement::Localnets),
        _ => {}
    }
    if let Some((address, prefix)) = value.split_once('/') {
        let address = IpAddr::from_str(address)
            .map_err(|_| parse_error(path, line, alloc::format!("invalid network `{value}`")))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| parse_error(path, line, alloc::format!("invalid network `{value}`")))?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err(parse_error(
                path,
                line,
                alloc::format!("invalid network prefix `{value}`"),
            ));
        }
        return Ok(AclElement::Network { address, prefix });
    }
    if let Ok(address) = IpAddr::from_str(value) {
        return Ok(AclElement::Address(address));
    }
    Ok(AclElement::Named(value.to_string()))
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr};

    use super::*;

    const CONFIG: &str = r#"
        acl "secondaries" { 192.0.2.0/24; key "transfer-key"; };

        key "transfer-key" {
            algorithm hmac-sha256;
            secret "dGVzdC1rZXktbWF0ZXJpYWw=";
        };

        controls {
            inet 10.23.0.1 port 953 allow { localhost; 10.23.0.0/24; }
                keys { "transfer-key"; };
        };

        statistics-channels {
            inet 127.0.0.1 port 8053 allow { localhost; };
        };

        options {
            directory "/var/lib/bind";
            allow-recursion { localhost; localnets; };
            listen-on { any; };
        };

        zone "example.com" {
            type primary;
            file "example.com.zone";
            allow-transfer { secondaries; key "transfer-key"; };
            dnssec-policy default;
        };
    "#;

    #[test]
    fn parses_sdk_relevant_named_conf_subset() {
        let config = NamedConf::parse("/etc/bind/named.conf", CONFIG).unwrap();

        assert_eq!(config.zones.len(), 1);
        assert_eq!(config.zones[0].name.to_string(), "example.com.");
        assert_eq!(config.zones[0].zone_type, NamedZoneType::Primary);
        assert_eq!(config.zones[0].file.as_deref(), Some("example.com.zone"));
        assert_eq!(config.keys.len(), 1);
        assert_eq!(config.keys[0].name().to_string(), "transfer-key.");
        assert_eq!(config.acls.len(), 1);
        assert_eq!(config.options.directory.as_deref(), Some("/var/lib/bind"));
        assert_eq!(config.controls[0].port, 953);
        assert_eq!(
            config.controls[0].address,
            ListenAddress::Ip(IpAddr::V4(Ipv4Addr::new(10, 23, 0, 1)))
        );
        assert_eq!(config.statistics_channels[0].port, 8053);
    }

    #[test]
    fn error_contains_path_and_line() {
        let error = NamedConf::parse(
            "/etc/bind/broken.conf",
            "options {\n directory \"/var/lib/bind\"\n};",
        )
        .unwrap_err();
        let text = alloc::format!("{error}");
        assert!(text.contains("/etc/bind/broken.conf"));
        assert!(text.contains("line 3") || text.contains("line 2"));
    }

    #[test]
    fn rejects_key_without_secret() {
        let error = NamedConf::parse("named.conf", r#"key "missing" { algorithm hmac-sha256; };"#)
            .unwrap_err();
        assert!(alloc::format!("{error}").contains("secret"));
    }

    #[test]
    fn parses_all_supported_zone_types() {
        let config = NamedConf::parse(
            "named.conf",
            r#"
            zone "a.example" { type primary; file "a"; };
            zone "b.example" { type secondary; file "b"; };
            zone "c.example" { type stub; };
            zone "d.example" { type forward; };
            "#,
        )
        .unwrap();

        assert_eq!(
            config
                .zones
                .iter()
                .map(|zone| zone.zone_type)
                .collect::<alloc::vec::Vec<_>>(),
            alloc::vec![
                NamedZoneType::Primary,
                NamedZoneType::Secondary,
                NamedZoneType::Stub,
                NamedZoneType::Forward,
            ]
        );
    }

    #[test]
    fn parses_live_bind_fixture() {
        let input = include_str!("../../../tests/bind9/named.conf");
        let config = NamedConf::parse("tests/bind9/named.conf", input).unwrap();

        assert_eq!(config.zones.len(), 3);
        assert_eq!(config.keys.len(), 1);
        assert_eq!(config.controls.len(), 1);
        assert_eq!(config.statistics_channels.len(), 1);
    }
}
