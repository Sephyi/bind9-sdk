// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::format;
use core::fmt;

use crate::domain::DomainName;
use crate::error::CoreError;
use crate::rdata::RecordData;

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
    /// Create a serial number from a raw u32 value.
    pub fn new(value: u32) -> Self {
        Serial(value)
    }

    /// The raw serial number value.
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

    use crate::domain::DomainName;
    use crate::rdata::RecordData;

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
}
