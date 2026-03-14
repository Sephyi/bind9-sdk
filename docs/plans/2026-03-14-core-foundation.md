<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Core Foundation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement all foundational types for bind9-sdk-core — error enum, domain name newtypes, record primitives, the full RecordData enum, ResourceRecord struct, and management trait definitions.

**Architecture:** Everything lives in `bind9-sdk-core` under `#![no_std]` + `extern crate alloc`. Types follow the coding architecture spec: newtypes validate on construction (parse, don't validate), errors use `thiserror` 2.x with `default-features = false`, and traits use associated error types to avoid circular dependencies with the net crate.

**Tech Stack:** Rust 2024 edition, `thiserror` 2.x (no_std), `zeroize` 1.x (no_std), `proptest` (dev), `insta` (dev)

**Spec:** `docs/specs/2026-03-14-coding-architecture-design.md`
**PRD scope:** FR-003 (DNS Record Type Library), partial FR-007 (TsigKey type only, no HMAC yet), trait definitions for FR-004/FR-006

**Subsequent plans:**
- Phase 1b: Zone parser + serializer + TSIG crypto + RFC 2136 construction
- Phase 1c: Network layer — rndc, nsupdate sender, stats-channel HTTP

## File Structure

| File | Responsibility | Creates/Modifies |
| --- | --- | --- |
| `crates/bind9-sdk-core/src/lib.rs` | Module declarations, `#![no_std]`, `#![forbid(unsafe_code)]` | Modify |
| `crates/bind9-sdk-core/src/error.rs` | `CoreError` enum | Create |
| `crates/bind9-sdk-core/src/domain.rs` | `DomainName`, `Label` newtypes | Create |
| `crates/bind9-sdk-core/src/record.rs` | `ResourceRecord`, `Ttl`, `Serial`, `RecordClass` | Create |
| `crates/bind9-sdk-core/src/rdata.rs` | `RecordData` enum (all variants) | Create |
| `crates/bind9-sdk-core/src/traits.rs` | `NamedControl`, `DynamicUpdater`, `ZoneManager`, `StatsClient` | Create |
| `bind9-sdk/src/lib.rs` | Curated re-exports | Modify |

## Chunk 1: Scaffolding, Errors, Domain Types, Record Primitives

### Task 1: Project Scaffolding

**Files:**
- Modify: `crates/bind9-sdk-core/src/lib.rs`

- [ ] **Step 1: Update lib.rs with module declarations and safety attributes**

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod domain;
pub mod error;
pub mod rdata;
pub mod record;
pub mod traits;
```

- [ ] **Step 2: Create empty module files so the crate compiles**

Create each file with just the SPDX header:
- `crates/bind9-sdk-core/src/error.rs`
- `crates/bind9-sdk-core/src/domain.rs`
- `crates/bind9-sdk-core/src/record.rs`
- `crates/bind9-sdk-core/src/rdata.rs`
- `crates/bind9-sdk-core/src/traits.rs`

Each file:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
```

- [ ] **Step 3: Verify the crate compiles on both native and WASM targets**

Run: `cargo check -p bind9-sdk-core`
Expected: success (empty modules)

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: success (no_std verified)

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-core/src/
git commit -m "feat(core): scaffold module structure with forbid(unsafe_code)"
```

### Task 2: CoreError

**Files:**
- Create: `crates/bind9-sdk-core/src/error.rs`

**Reference:** Coding architecture spec §3.1

- [ ] **Step 1: Write the test**

Add to `crates/bind9-sdk-core/src/error.rs`:

```rust
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
            reason: "unexpected token".into(),
        };
        assert_eq!(
            err.to_string(),
            "zone parse error at line 42: unexpected token"
        );
    }

    #[test]
    fn core_error_is_non_exhaustive() {
        // This test verifies the enum requires a wildcard arm.
        // If #[non_exhaustive] is removed, this match becomes exhaustive
        // and clippy will warn about the unnecessary wildcard.
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p bind9-sdk-core -- error::tests`
Expected: FAIL — `CoreError` not defined

- [ ] **Step 3: Implement CoreError**

Write the full `crates/bind9-sdk-core/src/error.rs`:

```rust
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
    InvalidName { name: String, reason: String },

    /// A DNS label failed validation (length, character set).
    #[error("invalid label: {0}")]
    InvalidLabel(String),

    /// Record data failed validation.
    #[error("invalid record data: {0}")]
    InvalidRecord(String),

    /// Zone file parsing failed at a specific line.
    #[error("zone parse error at line {line}: {reason}")]
    ZoneParse { line: u32, reason: String },

    /// DNS wire format encoding or decoding failed.
    #[error("wire format error: {0}")]
    WireFormat(String),

    /// TSIG authentication or signing error.
    #[error("TSIG error: {0}")]
    Tsig(String),
}

// Keep the #[cfg(test)] mod tests from Step 1 unchanged below this line.
```

**Important:** When writing this file, place the test module from Step 1 at the bottom. Do not replace it with a placeholder comment.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bind9-sdk-core -- error::tests`
Expected: 3 tests PASS

- [ ] **Step 5: Verify WASM target**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: success (thiserror 2.x with default-features=false is no_std)

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/error.rs
git commit -m "feat(core): add CoreError enum with thiserror no_std"
```

### Task 3: DomainName and Label Newtypes

**Files:**
- Create: `crates/bind9-sdk-core/src/domain.rs`

**Reference:** Coding architecture spec §2.1, PRD FR-003 (DomainName validates label length max 63, total max 253, character set)

**Important:** PRD says max total 253 characters in text form (RFC 1035 §2.3.4: 253 characters excluding trailing dot). Wire format max is 255 octets. Both limits must be checked.

- [ ] **Step 1: Write tests for Label**

Add to `crates/bind9-sdk-core/src/domain.rs`:

```rust
#[cfg(test)]
mod tests {
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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bind9-sdk-core -- domain::tests`
Expected: FAIL — `Label` not defined

- [ ] **Step 3: Implement Label**

```rust
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
```

- [ ] **Step 4: Run Label tests**

Run: `cargo test -p bind9-sdk-core -- domain::tests::label`
Expected: all Label tests PASS

- [ ] **Step 5: Write DomainName tests**

Add to the tests module:

```rust
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
        // Build: 63-char label + "." repeated, fitting within 253 chars
        let label = "a".repeat(63);
        // 63 + 1 (dot) = 64 per segment; 253 / 64 = 3 full + remaining
        // 3 * 64 = 192 chars; remaining = 253 - 192 = 61 chars (label without dot)
        let name_str = format!(
            "{label}.{label}.{label}.{}.",
            "a".repeat(61)
        );
        assert_eq!(name_str.len(), 254); // 253 chars + trailing dot
        assert!(DomainName::new(&name_str).is_ok());
    }

    #[test]
    fn domain_name_too_long_rejected() {
        // Wire length exceeds 255 octets
        let label = "a".repeat(63);
        let name_str = format!(
            "{label}.{label}.{label}.{label}.a."
        );
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
```

- [ ] **Step 6: Implement DomainName**

Add to `crates/bind9-sdk-core/src/domain.rs` after the Label impl:

```rust
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
                reason: format!(
                    "wire format exceeds 255 octets: {} octets",
                    dn.wire_len()
                ),
            });
        }

        Ok(dn)
    }

    /// The DNS root (".").
    pub fn root() -> Self {
        DomainName {
            labels: Vec::new(),
        }
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
        for label in &self.labels {
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
```

- [ ] **Step 7: Run all domain tests**

Run: `cargo test -p bind9-sdk-core -- domain::tests`
Expected: all tests PASS

- [ ] **Step 8: Verify WASM target**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: success

- [ ] **Step 9: Commit**

```bash
git add crates/bind9-sdk-core/src/domain.rs
git commit -m "feat(core): add DomainName and Label newtypes with RFC 1035 validation"
```

### Task 4: Record Primitives — Ttl, Serial, RecordClass

**Files:**
- Create: `crates/bind9-sdk-core/src/record.rs`

**Reference:** Coding architecture spec §2.1

- [ ] **Step 1: Write tests for Serial (RFC 1982 arithmetic is the tricky part)**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // -- Ttl tests --

    #[test]
    fn ttl_valid_range() {
        assert!(Ttl::new(0).is_ok());
        assert!(Ttl::new(86400).is_ok());
        assert!(Ttl::new(2_147_483_647).is_ok()); // max per RFC 8767
    }

    #[test]
    fn ttl_overflow_rejected() {
        assert!(Ttl::new(2_147_483_648).is_err());
    }

    #[test]
    fn ttl_value_accessor() {
        let ttl = Ttl::new(3600).unwrap();
        assert_eq!(ttl.value(), 3600);
    }

    // -- Serial tests (RFC 1982) --

    #[test]
    fn serial_equal() {
        let a = Serial::new(100);
        let b = Serial::new(100);
        assert_eq!(a, b);
    }

    #[test]
    fn serial_simple_greater() {
        let a = Serial::new(100);
        let b = Serial::new(99);
        assert!(a > b);
    }

    #[test]
    fn serial_wrap_around() {
        // u32::MAX is "less than" 0 in RFC 1982 (wrap-around)
        let a = Serial::new(0);
        let b = Serial::new(u32::MAX);
        assert!(a > b);
    }

    #[test]
    fn serial_add_wraps() {
        let s = Serial::new(u32::MAX);
        let result = s + 1;
        assert_eq!(result.value(), 0);
    }

    #[test]
    fn serial_halfway_undefined() {
        // RFC 1982 §3.2: when difference is exactly 2^31, comparison is undefined
        let a = Serial::new(0);
        let b = Serial::new(1 << 31);
        assert_eq!(a.partial_cmp(&b), None);
    }

    // -- RecordClass tests --

    #[test]
    fn record_class_in() {
        assert_eq!(RecordClass::IN.value(), 1);
    }

    #[test]
    fn record_class_display() {
        assert_eq!(alloc::format!("{}", RecordClass::IN), "IN");
    }

    #[test]
    fn record_class_from_u16() {
        assert_eq!(RecordClass::from_value(1), RecordClass::IN);
        assert_eq!(RecordClass::from_value(3), RecordClass::CH);
        assert_eq!(RecordClass::from_value(999), RecordClass::Unknown(999));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bind9-sdk-core -- record::tests`
Expected: FAIL — types not defined

- [ ] **Step 3: Implement Ttl, Serial, RecordClass**

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::format;
use core::fmt;

use crate::error::CoreError;

/// DNS Time-To-Live value.
///
/// Range: 0–2,147,483,647 (signed 32-bit max, per RFC 8767).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ttl(u32);

impl Ttl {
    /// Create a TTL value. Returns error if value exceeds RFC 8767 maximum.
    pub fn new(value: u32) -> Result<Self, CoreError> {
        if value > 2_147_483_647 {
            return Err(CoreError::InvalidRecord(format!(
                "TTL {value} exceeds maximum 2147483647"
            )));
        }
        Ok(Ttl(value))
    }

    /// The raw TTL value in seconds.
    pub fn value(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// DNS zone serial number with RFC 1982 wrap-around arithmetic.
///
/// Serial numbers use sequence space arithmetic where comparison wraps
/// around at 2^32. This means `Serial(0)` is greater than `Serial(u32::MAX)`.
///
/// Comparison is undefined (returns `None`) when the difference is exactly 2^31.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Serial(u32);

impl Serial {
    pub fn new(value: u32) -> Self {
        Serial(value)
    }

    pub fn value(&self) -> u32 {
        self.0
    }
}

impl PartialOrd for Serial {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        if self.0 == other.0 {
            return Some(core::cmp::Ordering::Equal);
        }
        let diff = self.0.wrapping_sub(other.0);
        if diff == 1 << 31 {
            // Undefined comparison per RFC 1982 §3.2
            None
        } else if diff < 1 << 31 {
            Some(core::cmp::Ordering::Greater)
        } else {
            Some(core::cmp::Ordering::Less)
        }
    }
}

impl core::ops::Add<u32> for Serial {
    type Output = Serial;

    fn add(self, rhs: u32) -> Serial {
        Serial(self.0.wrapping_add(rhs))
    }
}

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// DNS record class (RFC 1035 §3.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordClass {
    /// Internet (1) — the only class used in practice
    IN,
    /// Chaos (3)
    CH,
    /// Hesiod (4)
    HS,
    /// Any class (255) — used in queries only
    ANY,
    /// Unknown class value
    Unknown(u16),
}

impl RecordClass {
    /// Wire format value.
    pub fn value(&self) -> u16 {
        match self {
            RecordClass::IN => 1,
            RecordClass::CH => 3,
            RecordClass::HS => 4,
            RecordClass::ANY => 255,
            RecordClass::Unknown(v) => *v,
        }
    }

    /// Parse from wire format value.
    pub fn from_value(value: u16) -> Self {
        match value {
            1 => RecordClass::IN,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            255 => RecordClass::ANY,
            other => RecordClass::Unknown(other),
        }
    }
}

impl fmt::Display for RecordClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordClass::IN => f.write_str("IN"),
            RecordClass::CH => f.write_str("CH"),
            RecordClass::HS => f.write_str("HS"),
            RecordClass::ANY => f.write_str("ANY"),
            RecordClass::Unknown(v) => write!(f, "CLASS{v}"),
        }
    }
}

// ResourceRecord is defined in Task 6 after RecordData is available.
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-core -- record::tests`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/record.rs
git commit -m "feat(core): add Ttl, Serial (RFC 1982), and RecordClass newtypes"
```

## Chunk 2: RecordData, ResourceRecord, Traits, Wiring

### Task 5: RecordData Enum — All Variants

**Files:**
- Create: `crates/bind9-sdk-core/src/rdata.rs`

**Reference:** PRD §3.3 (RecordData), FR-003, coding architecture spec §2.1

This task defines all RecordData variants as data containers. Display (zone file format) and wire encode/decode are deferred to subsequent plans.

- [ ] **Step 1: Write construction tests for representative variants**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainName;
    use core::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn record_data_a() {
        let rd = RecordData::A(Ipv4Addr::new(192, 0, 2, 1));
        assert!(matches!(rd, RecordData::A(addr) if addr == Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn record_data_aaaa() {
        let rd = RecordData::Aaaa(Ipv6Addr::LOCALHOST);
        assert!(matches!(rd, RecordData::Aaaa(addr) if addr == Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn record_data_cname() {
        let target = DomainName::new("www.example.com.").unwrap();
        let rd = RecordData::Cname(target.clone());
        assert!(matches!(rd, RecordData::Cname(ref t) if t == &target));
    }

    #[test]
    fn record_data_soa() {
        let mname = DomainName::new("ns1.example.com.").unwrap();
        let rname = DomainName::new("admin.example.com.").unwrap();
        let rd = RecordData::Soa {
            mname: mname.clone(),
            rname: rname.clone(),
            serial: Serial::new(2024010101),
            refresh: Ttl::new(3600).unwrap(),
            retry: Ttl::new(900).unwrap(),
            expire: Ttl::new(604800).unwrap(),
            minimum: Ttl::new(86400).unwrap(),
        };
        assert!(matches!(rd, RecordData::Soa { serial, .. } if serial.value() == 2024010101));
    }

    #[test]
    fn record_data_mx() {
        let exchange = DomainName::new("mail.example.com.").unwrap();
        let rd = RecordData::Mx {
            preference: 10,
            exchange: exchange.clone(),
        };
        assert!(matches!(rd, RecordData::Mx { preference: 10, .. }));
    }

    #[test]
    fn record_data_txt_multistring() {
        let rd = RecordData::Txt(alloc::vec![
            "v=spf1".into(),
            "include:example.com".into(),
            "~all".into(),
        ]);
        if let RecordData::Txt(ref strings) = rd {
            assert_eq!(strings.len(), 3);
        }
    }

    #[test]
    fn record_data_unknown_preserves_bytes() {
        let data = alloc::vec![0x01, 0x02, 0x03];
        let rd = RecordData::Unknown {
            rtype: 65535,
            rdata: data.clone(),
        };
        assert!(matches!(rd, RecordData::Unknown { rtype: 65535, ref rdata } if rdata == &data));
    }

    // Note: #[non_exhaustive] is only enforced from external crates.
    // The attribute is verified by review, not by an in-crate test.
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bind9-sdk-core -- rdata::tests`
Expected: FAIL — `RecordData` not defined

- [ ] **Step 3: Implement RecordData enum**

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::domain::DomainName;
use crate::record::{Serial, Ttl};

/// DNS record data — every record type is a strongly-typed variant.
///
/// Covers all record types in BIND9 9.20. Unknown types are preserved
/// as raw bytes via the `Unknown` variant.
///
/// This enum is `#[non_exhaustive]` — new variants may be added in minor versions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordData {
    /// A record — IPv4 address (RFC 1035)
    A(Ipv4Addr),

    /// AAAA record — IPv6 address (RFC 3596)
    Aaaa(Ipv6Addr),

    /// CNAME record — canonical name alias (RFC 1035)
    Cname(DomainName),

    /// NS record — authoritative nameserver (RFC 1035)
    Ns(DomainName),

    /// PTR record — pointer for reverse DNS (RFC 1035)
    Ptr(DomainName),

    /// SOA record — start of authority (RFC 1035)
    Soa {
        mname: DomainName,
        rname: DomainName,
        serial: Serial,
        refresh: Ttl,
        retry: Ttl,
        expire: Ttl,
        minimum: Ttl,
    },

    /// MX record — mail exchange (RFC 1035)
    Mx {
        preference: u16,
        exchange: DomainName,
    },

    /// TXT record — text strings (RFC 1035)
    ///
    /// Each element is one character-string (max 255 bytes each).
    Txt(Vec<String>),

    /// SRV record — service locator (RFC 2782)
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: DomainName,
    },

    /// CAA record — certification authority authorization (RFC 8659)
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },

    /// DNSKEY record — public key for DNSSEC (RFC 4034)
    Dnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },

    /// RRSIG record — signature over an RRset (RFC 4034)
    Rrsig {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: DomainName,
        signature: Vec<u8>,
    },

    /// NSEC record — authenticated denial of existence (RFC 4034)
    Nsec {
        next_domain: DomainName,
        type_bitmaps: Vec<u8>,
    },

    /// NSEC3 record — hashed authenticated denial (RFC 5155)
    Nsec3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed_owner: Vec<u8>,
        type_bitmaps: Vec<u8>,
    },

    /// DS record — delegation signer (RFC 4034)
    Ds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },

    /// CDS record — child DS for automated rollover (RFC 7344)
    Cds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },

    /// CDNSKEY record — child DNSKEY for automated rollover (RFC 7344)
    Cdnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },

    /// TLSA record — TLS certificate association (RFC 6698)
    Tlsa {
        usage: u8,
        selector: u8,
        matching_type: u8,
        certificate_data: Vec<u8>,
    },

    /// SSHFP record — SSH host key fingerprint (RFC 4255)
    Sshfp {
        algorithm: u8,
        fp_type: u8,
        fingerprint: Vec<u8>,
    },

    /// CSYNC record — child-to-parent synchronization (RFC 7477)
    Csync {
        soa_serial: u32,
        flags: u16,
        type_bitmaps: Vec<u8>,
    },

    /// RP record — responsible person (RFC 1183)
    ///
    /// GDPR note: `mbox` contains a mailbox URI (personal data per GDPR Art. 4(1)).
    Rp {
        mbox: DomainName,
        txt: DomainName,
    },

    /// Unknown record type — raw RDATA preserved as bytes.
    Unknown {
        rtype: u16,
        rdata: Vec<u8>,
    },
}

// Tests at bottom
#[cfg(test)]
mod tests {
    // ... (as written in Step 1)
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-core -- rdata::tests`
Expected: all tests PASS

- [ ] **Step 5: Verify WASM target**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: success

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/rdata.rs
git commit -m "feat(core): add RecordData enum with all 21 DNS record type variants"
```

### Task 6: ResourceRecord Struct

**Files:**
- Modify: `crates/bind9-sdk-core/src/record.rs`

- [ ] **Step 1: Write ResourceRecord tests**

Add to the existing tests in `record.rs`:

```rust
    // -- ResourceRecord tests --

    #[test]
    fn resource_record_construction() {
        let rr = ResourceRecord {
            name: DomainName::new("example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(3600).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(192, 0, 2, 1)),
        };
        assert_eq!(rr.class, RecordClass::IN);
        assert_eq!(rr.ttl.value(), 3600);
    }

    #[test]
    fn resource_record_equality() {
        let rr1 = ResourceRecord {
            name: DomainName::new("example.com.").unwrap(),
            class: RecordClass::IN,
            ttl: Ttl::new(3600).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(192, 0, 2, 1)),
        };
        let rr2 = ResourceRecord {
            name: DomainName::new("EXAMPLE.COM.").unwrap(), // case-insensitive
            class: RecordClass::IN,
            ttl: Ttl::new(3600).unwrap(),
            rdata: RecordData::A(core::net::Ipv4Addr::new(192, 0, 2, 1)),
        };
        assert_eq!(rr1, rr2);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bind9-sdk-core -- record::tests::resource_record`
Expected: FAIL — `ResourceRecord` not defined or missing imports

- [ ] **Step 3: Uncomment and complete ResourceRecord**

Add the imports and struct to `record.rs`:

```rust
use crate::domain::DomainName;
use crate::rdata::RecordData;

/// A complete DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    /// Owner name (the domain this record belongs to)
    pub name: DomainName,
    /// Record class (almost always IN)
    pub class: RecordClass,
    /// Time to live in seconds
    pub ttl: Ttl,
    /// Record-type-specific data
    pub rdata: RecordData,
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-core -- record::tests`
Expected: all tests PASS (Ttl + Serial + RecordClass + ResourceRecord)

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/record.rs
git commit -m "feat(core): add ResourceRecord struct"
```

### Task 7: Management Trait Definitions

**Files:**
- Create: `crates/bind9-sdk-core/src/traits.rs`

**Reference:** Coding architecture spec §5.1, §5.2

These are trait definitions only — no implementations in this plan. `Bind9Client` (net) and `ZoneFile` (core) implementations come in subsequent plans.

**Note:** The types referenced in trait signatures (`ServerStatus`, `FrozenZone`, `UpdateMessage`, `UpdateResult`, `ZoneSummary`, `Zone`, `ServerStats`, `ZoneStats`) are placeholder structs for now. They will be fleshed out in subsequent plans when their containing modules are implemented.

- [ ] **Step 1: Write compilation test**

The trait definitions should compile and be usable with a mock implementation. Add to `crates/bind9-sdk-core/src/traits.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CoreError;

    // Minimal mock to verify trait is implementable
    struct MockNamedControl;

    impl NamedControl for MockNamedControl {
        type Error = CoreError;

        async fn status(&self) -> Result<ServerStatus, CoreError> {
            Ok(ServerStatus)
        }

        async fn reload(&self) -> Result<(), CoreError> {
            Ok(())
        }

        async fn reload_zone(&self, _zone: &crate::domain::DomainName) -> Result<(), CoreError> {
            Ok(())
        }

        async fn freeze(
            &self,
            _zone: &crate::domain::DomainName,
        ) -> Result<FrozenZone, CoreError> {
            Ok(FrozenZone)
        }
    }

    #[test]
    fn mock_named_control_compiles() {
        // If this compiles, the trait is implementable with CoreError
        let _mock = MockNamedControl;
    }

    struct MockZoneManager;

    impl ZoneManager for MockZoneManager {
        type Error = CoreError;

        async fn list_zones(&self) -> Result<alloc::vec::Vec<ZoneSummary>, CoreError> {
            Ok(alloc::vec![])
        }

        async fn get_zone(
            &self,
            _name: &crate::domain::DomainName,
        ) -> Result<Zone, CoreError> {
            Ok(Zone)
        }
    }

    #[test]
    fn mock_zone_manager_compiles() {
        let _mock = MockZoneManager;
    }

    struct MockDynamicUpdater;

    impl DynamicUpdater for MockDynamicUpdater {
        type Error = CoreError;

        async fn send_update(&self, _update: &UpdateMessage) -> Result<UpdateResult, CoreError> {
            Ok(UpdateResult)
        }
    }

    #[test]
    fn mock_dynamic_updater_compiles() {
        let _mock = MockDynamicUpdater;
    }

    struct MockStatsClient;

    impl StatsClient for MockStatsClient {
        type Error = CoreError;

        async fn server_stats(&self) -> Result<ServerStats, CoreError> {
            Ok(ServerStats)
        }

        async fn zone_stats(
            &self,
            _zone: &crate::domain::DomainName,
        ) -> Result<ZoneStats, CoreError> {
            Ok(ZoneStats)
        }
    }

    #[test]
    fn mock_stats_client_compiles() {
        let _mock = MockStatsClient;
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bind9-sdk-core -- traits::tests`
Expected: FAIL — traits not defined

- [ ] **Step 3: Implement trait definitions**

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::vec::Vec;

use crate::domain::DomainName;

// Placeholder types — fleshed out in subsequent plans.
// These exist so the trait signatures compile now.

/// Server status information from `rndc status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStatus;

/// A zone that has been frozen via `rndc freeze`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenZone;

/// A constructed RFC 2136 dynamic update message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage;

/// Result of sending an RFC 2136 update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateResult;

/// Summary of a zone (name, class, serial).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSummary;

/// Full zone data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone;

/// Server-level statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStats;

/// Zone-level statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneStats;

/// rndc server management.
///
/// Implemented by `Bind9Client` (net crate) for live servers.
/// Test mocks implement with `type Error = CoreError`.
pub trait NamedControl: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn status(&self) -> Result<ServerStatus, Self::Error>;
    async fn reload(&self) -> Result<(), Self::Error>;
    async fn reload_zone(&self, zone: &DomainName) -> Result<(), Self::Error>;
    async fn freeze(&self, zone: &DomainName) -> Result<FrozenZone, Self::Error>;
}

/// RFC 2136 dynamic DNS updates.
///
/// Implemented by `Bind9Client` (net crate).
pub trait DynamicUpdater: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn send_update(&self, update: &UpdateMessage) -> Result<UpdateResult, Self::Error>;
}

/// Zone listing and retrieval.
///
/// Implemented by `Bind9Client` (net crate) for live servers
/// and by `ZoneFile` (core crate) for local file operations.
pub trait ZoneManager: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn list_zones(&self) -> Result<Vec<ZoneSummary>, Self::Error>;
    async fn get_zone(&self, name: &DomainName) -> Result<Zone, Self::Error>;
}

/// BIND9 statistics-channel JSON API.
///
/// Implemented by `Bind9Client` (net crate).
pub trait StatsClient: Send + Sync {
    type Error: core::error::Error + Send + Sync + 'static;

    async fn server_stats(&self) -> Result<ServerStats, Self::Error>;
    async fn zone_stats(&self, zone: &DomainName) -> Result<ZoneStats, Self::Error>;
}

#[cfg(test)]
mod tests {
    // ... (as written in Step 1)
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-core -- traits::tests`
Expected: all tests PASS

- [ ] **Step 5: Verify WASM target**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: success

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/traits.rs
git commit -m "feat(core): add management trait definitions with associated error types"
```

### Task 8: Module Wiring and Re-Exports

**Files:**
- Modify: `crates/bind9-sdk-core/src/lib.rs`
- Modify: `bind9-sdk/src/lib.rs`

- [ ] **Step 1: Add dev-dependencies for proptest and insta**

Add to `crates/bind9-sdk-core/Cargo.toml`:

```toml
[dev-dependencies]
proptest = { workspace = true }
insta = { workspace = true }
```

- [ ] **Step 2: Add curated re-exports to bind9-sdk-core lib.rs**

Update `crates/bind9-sdk-core/src/lib.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod domain;
pub mod error;
pub mod rdata;
pub mod record;
pub mod traits;

// Curated re-exports for common access
pub use domain::{DomainName, Label};
pub use error::CoreError;
pub use rdata::RecordData;
pub use record::{RecordClass, ResourceRecord, Serial, Ttl};
pub use traits::{DynamicUpdater, NamedControl, StatsClient, ZoneManager};
```

- [ ] **Step 3: Update bind9-sdk re-export crate**

Update `bind9-sdk/src/lib.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # bind9-sdk
//!
//! Rust SDK for programmatic BIND9 DNS server management.
//!
//! ## Quick start
//!
//! ```rust
//! use bind9_sdk::{DomainName, RecordData, ResourceRecord, RecordClass, Ttl};
//! use core::net::Ipv4Addr;
//!
//! let name = DomainName::new("example.com.").unwrap();
//! ```

/// Core DNS types, zone parsing, and RFC 2136 message construction.
///
/// This module is `no_std` compatible — safe to use in WASM and embedded contexts.
///
/// **Stability:** Paths under `bind9_sdk::core` are not covered by semver guarantees.
/// Prefer top-level imports (e.g., `use bind9_sdk::DomainName`).
pub use bind9_sdk_core as core;

/// Network operations: rndc TCP wire protocol, nsupdate sender, IXFR/AXFR, statistics HTTP.
///
/// Requires `feature = "net"` (enabled by default).
///
/// **Stability:** Paths under `bind9_sdk::net` are not covered by semver guarantees.
/// Prefer top-level imports.
#[cfg(feature = "net")]
pub use bind9_sdk_net as net;

// Curated top-level re-exports (covered by semver)
pub use bind9_sdk_core::{
    CoreError, DomainName, DynamicUpdater, Label, NamedControl, RecordClass, RecordData,
    ResourceRecord, Serial, StatsClient, Ttl, ZoneManager,
};
```

- [ ] **Step 4: Run full workspace check**

Run: `cargo check --workspace`
Expected: success

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: success (core crate must compile for WASM)

Note: Do NOT run `--workspace` with WASM target — `bind9-sdk-net` and `bind9-sdk-bindings` require std and will fail.

- [ ] **Step 5: Run all tests**

Run: `cargo test -p bind9-sdk-core`
Expected: all tests PASS

Run: `cargo test -p bind9-sdk`
Expected: success (doc test may or may not run depending on setup)

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/lib.rs crates/bind9-sdk-core/Cargo.toml bind9-sdk/src/lib.rs
git commit -m "feat: wire up core modules and curated re-exports in bind9-sdk"
```

### Task 9: Proptest for DomainName and Serial

**Files:**
- Modify: `crates/bind9-sdk-core/src/domain.rs`
- Modify: `crates/bind9-sdk-core/src/record.rs`

**Reference:** Coding architecture spec §7.2

Property-based tests verify invariants across the input space. These are the first proptest tests in the codebase — they establish the pattern for all future proptest usage.

- [ ] **Step 1: Add proptest for DomainName roundtrip**

Add to `crates/bind9-sdk-core/src/domain.rs` tests module:

```rust
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
```

- [ ] **Step 2: Add proptest for Serial RFC 1982 properties**

Add to `crates/bind9-sdk-core/src/record.rs` tests module:

```rust
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn serial_add_then_compare(base: u32, increment in 1u32..=(1 << 31) - 1) {
                let a = Serial::new(base);
                let b = a + increment;
                // Per RFC 1982: if 0 < increment < 2^31, then a < b
                prop_assert!(b > a, "Serial({}) + {} should be > Serial({})", base, increment, base);
            }

            #[test]
            fn serial_reflexive_eq(value: u32) {
                let a = Serial::new(value);
                let b = Serial::new(value);
                prop_assert_eq!(a, b);
            }
        }
    }
```

- [ ] **Step 3: Run proptest tests**

Run: `cargo test -p bind9-sdk-core -- proptests`
Expected: all proptest tests PASS

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-core/src/domain.rs crates/bind9-sdk-core/src/record.rs
git commit -m "test(core): add proptest for DomainName roundtrip and Serial RFC 1982"
```
