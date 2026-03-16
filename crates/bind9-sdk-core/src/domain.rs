// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::error::CoreError;

/// A single DNS label (component between dots).
///
/// Maximum 63 bytes. ASCII letters, digits, hyphens, and underscores.
/// Must not start or end with a hyphen.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Label {
    inner: String,
}

impl Label {
    /// Create a new label, validating RFC 1035 constraints.
    pub fn new(s: &str) -> Result<Self, CoreError> {
        if s.is_empty() {
            return Err(CoreError::InvalidLabel("label is empty".into()));
        }
        if s.len() > 63 {
            return Err(CoreError::InvalidLabel(format!(
                "label exceeds 63 bytes: {} bytes",
                s.len()
            )));
        }
        if s.starts_with('-') || s.ends_with('-') {
            return Err(CoreError::InvalidLabel(format!(
                "label must not start or end with hyphen: `{s}`"
            )));
        }
        for byte in s.bytes() {
            if !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') {
                return Err(CoreError::InvalidLabel(format!(
                    "label contains invalid character: `{s}`"
                )));
            }
        }
        Ok(Label { inner: s.into() })
    }

    /// The label text.
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Byte length of the label.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the label is empty (should never be true for a valid Label).
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
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

        // Strip trailing dot for splitting; we always store absolute
        let trimmed = name.strip_suffix('.').unwrap_or(name);

        if trimmed.is_empty() {
            return Ok(Self::root());
        }

        // Check text length (max 253 characters excluding trailing dot)
        if trimmed.len() > 253 {
            return Err(CoreError::InvalidName {
                name: name.into(),
                reason: format!("exceeds 253 characters: {} characters", trimmed.len()),
            });
        }

        let mut labels = Vec::new();
        for part in trimmed.split('.') {
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
            let bytes = label.as_str().as_bytes();
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
            let bytes = label.as_str().as_bytes();
            buf.push(bytes.len() as u8);
            for &byte in bytes {
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
        self.labels
            .iter()
            .zip(other.labels.iter())
            .all(|(a, b)| a.as_str().eq_ignore_ascii_case(b.as_str()))
    }
}

impl Eq for DomainName {}

impl core::hash::Hash for DomainName {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.labels.len().hash(state);
        for label in &self.labels {
            label.as_str().len().hash(state);
            for byte in label.as_str().bytes() {
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
    fn label_leading_hyphen_rejected() {
        assert!(Label::new("-start").is_err());
    }

    #[test]
    fn label_trailing_hyphen_rejected() {
        assert!(Label::new("end-").is_err());
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
            alloc::vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,]
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
            alloc::vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,]
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
