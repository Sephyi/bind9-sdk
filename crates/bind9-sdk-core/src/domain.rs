// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::error::CoreError;

/// A single DNS label (component between dots).
///
/// Maximum 63 bytes. DNS labels are not restricted to hostname syntax:
/// printable ASCII characters other than `.` and `\` are accepted.
///
/// Master-file escape decoding is handled by the zone parser before labels
/// reach this type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Label {
    inner: String,
    wire: Vec<u8>,
}

impl Label {
    /// Create a new label, validating RFC 1035 constraints.
    pub fn new(s: &str) -> Result<Self, CoreError> {
        if s.is_empty() {
            return Err(CoreError::InvalidLabel("label is empty".into()));
        }
        let decoded = decode_label(s)?;
        if decoded.len() > 63 {
            return Err(CoreError::InvalidLabel(format!(
                "label exceeds 63 bytes: {} bytes",
                decoded.len()
            )));
        }
        Ok(Label {
            inner: s.into(),
            wire: decoded,
        })
    }

    /// The label text.
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Byte length of the label.
    pub fn len(&self) -> usize {
        self.wire_bytes().len()
    }

    /// Whether the label is empty (should never be true for a valid Label).
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn wire_bytes(&self) -> &[u8] {
        &self.wire
    }
}

fn decode_label(label: &str) -> Result<Vec<u8>, CoreError> {
    let bytes = label.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut pos = 0;

    while pos < bytes.len() {
        let byte = bytes[pos];
        if byte == b'\\' {
            if pos + 1 >= bytes.len() {
                return Err(CoreError::InvalidLabel(format!(
                    "label ends with incomplete escape: `{label}`"
                )));
            }
            if pos + 3 < bytes.len()
                && bytes[pos + 1].is_ascii_digit()
                && bytes[pos + 2].is_ascii_digit()
                && bytes[pos + 3].is_ascii_digit()
            {
                let value = u16::from(bytes[pos + 1] - b'0') * 100
                    + u16::from(bytes[pos + 2] - b'0') * 10
                    + u16::from(bytes[pos + 3] - b'0');
                if value > 255 {
                    return Err(CoreError::InvalidLabel(format!(
                        "decimal escape exceeds 255 in label: `{label}`"
                    )));
                }
                decoded.push(value as u8);
                pos += 4;
                continue;
            }
            decoded.push(bytes[pos + 1]);
            pos += 2;
            continue;
        }
        if !byte.is_ascii_graphic() || byte == b'.' {
            return Err(CoreError::InvalidLabel(format!(
                "label contains invalid character: `{label}`"
            )));
        }
        decoded.push(byte);
        pos += 1;
    }

    Ok(decoded)
}

fn split_domain_labels(name: &str) -> Result<(Vec<&str>, bool), CoreError> {
    let bytes = name.as_bytes();
    let mut labels = Vec::new();
    let mut start = 0;
    let mut pos = 0;

    while pos < bytes.len() {
        match bytes[pos] {
            b'\\' => {
                if pos + 1 >= bytes.len() {
                    return Err(CoreError::InvalidName {
                        name: name.into(),
                        reason: "name ends with incomplete escape".into(),
                    });
                }
                if pos + 3 < bytes.len()
                    && bytes[pos + 1].is_ascii_digit()
                    && bytes[pos + 2].is_ascii_digit()
                    && bytes[pos + 3].is_ascii_digit()
                {
                    pos += 4;
                } else {
                    pos += 2;
                }
            }
            b'.' => {
                labels.push(&name[start..pos]);
                start = pos + 1;
                pos += 1;
            }
            _ => pos += 1,
        }
    }

    let absolute = start == name.len();
    if !absolute {
        labels.push(&name[start..]);
    }
    Ok((labels, absolute))
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label(\"{}\")", self.inner)
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

/// A validated DNS domain name per RFC 1035 §2.3.1.
///
/// Always stored in absolute form (with trailing dot).
/// Text form max 253 characters (excluding trailing dot).
/// Wire format max 255 octets.
/// Each label max 63 bytes.
///
/// Comparison is case-insensitive per RFC 4343.
#[derive(Clone)]
pub struct DomainName {
    labels: Vec<Label>,
}

impl DomainName {
    /// Parse and validate a domain name string.
    ///
    /// Accepts both relative ("example.com") and absolute ("example.com.") forms.
    /// Internally stores as absolute (trailing dot).
    pub fn new(name: &str) -> Result<Self, CoreError> {
        if name == "." {
            return Ok(Self::root());
        }

        let (parts, _) = split_domain_labels(name)?;
        let mut labels = Vec::new();
        for part in parts {
            if part.is_empty() {
                return Err(CoreError::InvalidName {
                    name: name.into(),
                    reason: "empty label (consecutive dots)".into(),
                });
            }
            labels.push(Label::new(part).map_err(|e| CoreError::InvalidName {
                name: name.into(),
                reason: format!("{e}"),
            })?);
        }

        let dn = DomainName { labels };

        // Check wire format length (max 255 octets)
        if dn.wire_len() > 255 {
            return Err(CoreError::InvalidName {
                name: name.into(),
                reason: format!("wire format exceeds 255 octets: {} octets", dn.wire_len()),
            });
        }

        Ok(dn)
    }

    /// The DNS root (".").
    pub fn root() -> Self {
        DomainName { labels: Vec::new() }
    }

    /// The labels in order (e.g., ["www", "example", "com"]).
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }

    /// Number of labels (excluding root).
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Wire-format length in octets.
    ///
    /// Each label: 1 byte length prefix + label bytes.
    /// Plus 1 byte for the root null label.
    pub fn wire_len(&self) -> usize {
        self.labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1
    }

    /// Whether this is the root domain (".").
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Write this domain name in DNS wire format into the buffer.
    ///
    /// Format: each label as `<length byte><label bytes>`, terminated by
    /// a zero-length root label. No DNS name compression.
    /// Preserves original label casing.
    pub fn write_wire(&self, buf: &mut Vec<u8>) {
        for label in &self.labels {
            let bytes = label.wire_bytes();
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        }
        buf.push(0); // root label
    }

    /// Write this domain name in canonical DNS wire format (RFC 4034 §6.2).
    ///
    /// Same as [`write_wire`](Self::write_wire) but lowercases all ASCII
    /// characters. Required by RFC 8945 for TSIG MAC computation.
    pub fn write_wire_canonical(&self, buf: &mut Vec<u8>) {
        for label in &self.labels {
            let bytes = label.wire_bytes();
            buf.push(bytes.len() as u8);
            for byte in bytes {
                buf.push(byte.to_ascii_lowercase());
            }
        }
        buf.push(0); // root label
    }
}

impl PartialEq for DomainName {
    fn eq(&self, other: &Self) -> bool {
        if self.labels.len() != other.labels.len() {
            return false;
        }
        self.labels.iter().zip(other.labels.iter()).all(|(a, b)| {
            let a = a.wire_bytes();
            let b = b.wire_bytes();
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
    }
}

impl Eq for DomainName {}

impl core::hash::Hash for DomainName {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.labels.len().hash(state);
        for label in &self.labels {
            let bytes = label.wire_bytes();
            bytes.len().hash(state);
            for byte in bytes {
                state.write_u8(byte.to_ascii_lowercase());
            }
        }
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DomainName(\"{}\")", self)
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for (i, label) in self.labels.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            fmt::Display::fmt(label, f)?;
        }
        f.write_str(".")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    // -- Label tests --

    #[test]
    fn label_valid_simple() {
        let label = Label::new("www").unwrap();
        assert_eq!(label.as_str(), "www");
        assert_eq!(label.len(), 3);
    }

    #[test]
    fn label_valid_with_hyphen() {
        let label = Label::new("my-host").unwrap();
        assert_eq!(label.as_str(), "my-host");
    }

    #[test]
    fn label_valid_with_digits() {
        let label = Label::new("ns1").unwrap();
        assert_eq!(label.as_str(), "ns1");
    }

    #[test]
    fn label_accepts_dns_wildcard() {
        let label = Label::new("*").unwrap();
        assert_eq!(label.as_str(), "*");
    }

    #[test]
    fn label_accepts_non_hostname_dns_characters() {
        assert!(Label::new("-service-").is_ok());
        assert!(Label::new("owner!tag").is_ok());
    }

    #[test]
    fn escaped_dot_is_one_label_byte() {
        let label = Label::new(r"host\.name").unwrap();
        assert_eq!(label.len(), 9);
    }

    #[test]
    fn label_empty_rejected() {
        assert!(Label::new("").is_err());
    }

    #[test]
    fn label_too_long_rejected() {
        let long = "a".repeat(64);
        assert!(Label::new(&long).is_err());
    }

    #[test]
    fn label_max_length_accepted() {
        let max = "a".repeat(63);
        assert!(Label::new(&max).is_ok());
    }

    #[test]
    fn label_leading_hyphen_accepted() {
        assert!(Label::new("-start").is_ok());
    }

    #[test]
    fn label_trailing_hyphen_accepted() {
        assert!(Label::new("end-").is_ok());
    }

    #[test]
    fn label_invalid_chars_rejected() {
        assert!(Label::new("has space").is_err());
        assert!(Label::new("has.dot").is_err());
    }

    #[test]
    fn label_underscore_accepted() {
        // Underscores are used in SRV records (_sip._tcp) and DKIM (_dmarc)
        let label = Label::new("_sip").unwrap();
        assert_eq!(label.as_str(), "_sip");
    }

    #[test]
    fn label_display() {
        let label = Label::new("www").unwrap();
        assert_eq!(alloc::format!("{label}"), "www");
    }

    // -- DomainName tests --

    #[test]
    fn domain_name_simple() {
        let name = DomainName::new("example.com.").unwrap();
        assert_eq!(name.label_count(), 2);
        assert_eq!(name.labels()[0].as_str(), "example");
        assert_eq!(name.labels()[1].as_str(), "com");
    }

    #[test]
    fn domain_name_appends_trailing_dot() {
        let name = DomainName::new("example.com").unwrap();
        assert_eq!(alloc::format!("{name}"), "example.com.");
    }

    #[test]
    fn domain_escaped_dot_does_not_split_label() {
        let name = DomainName::new(r"host\.name.example.").unwrap();
        assert_eq!(name.label_count(), 2);
        assert_eq!(name.labels()[0].as_str(), r"host\.name");
        let mut wire = alloc::vec::Vec::new();
        name.write_wire(&mut wire);
        assert_eq!(&wire[..10], b"\thost.name");
        assert_eq!(alloc::format!("{name}"), r"host\.name.example.");
    }

    #[test]
    fn domain_decimal_escape_writes_arbitrary_octet() {
        let name = DomainName::new(r"binary\000label.example.").unwrap();
        let mut wire = alloc::vec::Vec::new();
        name.write_wire(&mut wire);
        assert_eq!(wire[0], 12);
        assert_eq!(wire[7], 0);
    }

    #[test]
    fn domain_name_root() {
        let root = DomainName::root();
        assert!(root.is_root());
        assert_eq!(root.label_count(), 0);
        assert_eq!(alloc::format!("{root}"), ".");
    }

    #[test]
    fn domain_name_wire_len_simple() {
        // "example.com." → 1+7 + 1+3 + 1 = 13 octets
        let name = DomainName::new("example.com.").unwrap();
        assert_eq!(name.wire_len(), 13);
    }

    #[test]
    fn domain_name_wire_len_root() {
        // Root "." → just 1 null byte = 1 octet
        assert_eq!(DomainName::root().wire_len(), 1);
    }

    #[test]
    fn domain_name_max_length_accepted() {
        // 253 characters of text = maximum allowed
        let label = "a".repeat(63);
        let name_str = alloc::format!("{label}.{label}.{label}.{}.", "a".repeat(61));
        assert_eq!(name_str.len(), 254); // 253 chars + trailing dot
        assert!(DomainName::new(&name_str).is_ok());
    }

    #[test]
    fn domain_name_too_long_rejected() {
        // Wire length exceeds 255 octets
        let label = "a".repeat(63);
        let name_str = alloc::format!("{label}.{label}.{label}.{label}.a.");
        assert!(DomainName::new(&name_str).is_err());
    }

    #[test]
    fn domain_name_empty_label_rejected() {
        // Double dot = empty label
        assert!(DomainName::new("example..com.").is_err());
    }

    #[test]
    fn domain_name_case_insensitive_eq() {
        let a = DomainName::new("Example.COM.").unwrap();
        let b = DomainName::new("example.com.").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn domain_name_display() {
        let name = DomainName::new("www.example.com.").unwrap();
        assert_eq!(alloc::format!("{name}"), "www.example.com.");
    }

    #[test]
    fn label_all_numeric_accepted() {
        let label = Label::new("123").unwrap();
        assert_eq!(label.as_str(), "123");
    }

    #[test]
    fn domain_name_all_numeric_labels() {
        let name = DomainName::new("4.3.2.1.in-addr.arpa.").unwrap();
        assert_eq!(name.label_count(), 6);
    }

    #[test]
    fn domain_name_hash_distinguishes_label_boundaries() {
        use core::hash::{Hash, Hasher};
        // "ab.c." and "a.bc." have the same concatenated bytes
        // but different label structure — must hash differently.
        let a = DomainName::new("ab.c.").unwrap();
        let b = DomainName::new("a.bc.").unwrap();
        let hash = |name: &DomainName| {
            let mut hasher = std::hash::DefaultHasher::new();
            name.hash(&mut hasher);
            hasher.finish()
        };
        assert_ne!(hash(&a), hash(&b));
    }

    #[test]
    fn domain_name_write_wire() {
        let name = DomainName::new("example.com.").unwrap();
        let mut buf = Vec::new();
        name.write_wire(&mut buf);
        // Expected: \x07example\x03com\x00
        assert_eq!(
            buf,
            alloc::vec![
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            ]
        );
    }

    #[test]
    fn domain_name_write_wire_root() {
        let name = DomainName::root();
        let mut buf = Vec::new();
        name.write_wire(&mut buf);
        assert_eq!(buf, alloc::vec![0]);
    }

    #[test]
    fn domain_name_write_wire_canonical_lowercases() {
        let name = DomainName::new("Example.COM.").unwrap();
        let mut buf = Vec::new();
        name.write_wire_canonical(&mut buf);
        // All ASCII lowered: \x07example\x03com\x00
        assert_eq!(
            buf,
            alloc::vec![
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            ]
        );
    }

    #[test]
    fn domain_name_write_wire_canonical_matches_lowercase_write_wire() {
        let mixed = DomainName::new("Www.Example.COM.").unwrap();
        let lower = DomainName::new("www.example.com.").unwrap();
        let mut canonical = Vec::new();
        let mut plain = Vec::new();
        mixed.write_wire_canonical(&mut canonical);
        lower.write_wire(&mut plain);
        assert_eq!(canonical, plain);
    }

    #[test]
    fn domain_name_write_wire_length_matches() {
        let name = DomainName::new("www.example.com.").unwrap();
        let mut buf = Vec::new();
        name.write_wire(&mut buf);
        assert_eq!(buf.len(), name.wire_len());
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn label_roundtrip(s in "[a-z][a-z0-9]{0,10}") {
                let label = Label::new(&s).unwrap();
                prop_assert_eq!(label.as_str(), s.as_str());
            }

            #[test]
            fn domain_name_display_roundtrip(
                labels in proptest::collection::vec(
                    "[a-z][a-z0-9]{0,10}",
                    1..4
                )
            ) {
                let name_str = alloc::format!("{}.", labels.join("."));
                let name = DomainName::new(&name_str);
                prop_assume!(name.is_ok(), "generated name must be valid");
                let name = name.unwrap();
                let displayed = alloc::format!("{name}");
                let reparsed = DomainName::new(&displayed).unwrap();
                prop_assert_eq!(name, reparsed);
            }

            #[test]
            fn domain_name_wire_len_positive(
                labels in proptest::collection::vec(
                    "[a-z]{1,10}",
                    1..4
                )
            ) {
                let name_str = alloc::format!("{}.", labels.join("."));
                let name = DomainName::new(&name_str);
                prop_assume!(name.is_ok(), "generated name must be valid");
                let name = name.unwrap();
                prop_assert!(name.wire_len() > 0);
                prop_assert!(name.wire_len() <= 255);
            }
        }
    }
}
