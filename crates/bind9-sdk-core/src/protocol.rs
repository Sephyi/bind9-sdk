// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use core::fmt;

/// DNS record type codes (RFC 1035 §3.2.2 and IANA registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordType {
    /// IPv4 host address (type 1).
    A,
    /// IPv6 host address (type 28).
    Aaaa,
    /// Canonical name alias (type 5).
    Cname,
    /// Authoritative name server (type 2).
    Ns,
    /// Domain name pointer for reverse DNS (type 12).
    Ptr,
    /// Start of authority (type 6).
    Soa,
    /// Mail exchange (type 15).
    Mx,
    /// Text record (type 16).
    Txt,
    /// Service locator (type 33).
    Srv,
    /// Certification authority authorization (type 257).
    Caa,
    /// DNS public key for DNSSEC (type 48).
    Dnskey,
    /// DNSSEC signature (type 46).
    Rrsig,
    /// Next secure record for authenticated denial (type 47).
    Nsec,
    /// Next secure record version 3 (type 50).
    Nsec3,
    /// Delegation signer for DNSSEC chain of trust (type 43).
    Ds,
    /// Child copy of DS for CDS bootstrapping (type 59).
    Cds,
    /// Child copy of DNSKEY for CDS bootstrapping (type 60).
    Cdnskey,
    /// TLS certificate association (type 52).
    Tlsa,
    /// SSH public key fingerprint (type 44).
    Sshfp,
    /// Child-to-parent synchronization (type 62).
    Csync,
    /// Responsible person (type 17).
    Rp,
    /// Any other record type not listed above, identified by its numeric code.
    Other(u16),
}

impl RecordType {
    /// Map a raw IANA record type number to the corresponding variant.
    ///
    /// Unknown numbers produce `Other(value)`.
    pub fn from_value(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::Aaaa,
            5 => Self::Cname,
            2 => Self::Ns,
            12 => Self::Ptr,
            6 => Self::Soa,
            15 => Self::Mx,
            16 => Self::Txt,
            33 => Self::Srv,
            257 => Self::Caa,
            48 => Self::Dnskey,
            46 => Self::Rrsig,
            47 => Self::Nsec,
            50 => Self::Nsec3,
            43 => Self::Ds,
            59 => Self::Cds,
            60 => Self::Cdnskey,
            52 => Self::Tlsa,
            44 => Self::Sshfp,
            62 => Self::Csync,
            17 => Self::Rp,
            other => Self::Other(other),
        }
    }

    /// Return the IANA numeric type code for this record type.
    pub fn value(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Cname => 5,
            Self::Ns => 2,
            Self::Ptr => 12,
            Self::Soa => 6,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Srv => 33,
            Self::Caa => 257,
            Self::Dnskey => 48,
            Self::Rrsig => 46,
            Self::Nsec => 47,
            Self::Nsec3 => 50,
            Self::Ds => 43,
            Self::Cds => 59,
            Self::Cdnskey => 60,
            Self::Tlsa => 52,
            Self::Sshfp => 44,
            Self::Csync => 62,
            Self::Rp => 17,
            Self::Other(v) => *v,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => f.write_str("A"),
            Self::Aaaa => f.write_str("AAAA"),
            Self::Cname => f.write_str("CNAME"),
            Self::Ns => f.write_str("NS"),
            Self::Ptr => f.write_str("PTR"),
            Self::Soa => f.write_str("SOA"),
            Self::Mx => f.write_str("MX"),
            Self::Txt => f.write_str("TXT"),
            Self::Srv => f.write_str("SRV"),
            Self::Caa => f.write_str("CAA"),
            Self::Dnskey => f.write_str("DNSKEY"),
            Self::Rrsig => f.write_str("RRSIG"),
            Self::Nsec => f.write_str("NSEC"),
            Self::Nsec3 => f.write_str("NSEC3"),
            Self::Ds => f.write_str("DS"),
            Self::Cds => f.write_str("CDS"),
            Self::Cdnskey => f.write_str("CDNSKEY"),
            Self::Tlsa => f.write_str("TLSA"),
            Self::Sshfp => f.write_str("SSHFP"),
            Self::Csync => f.write_str("CSYNC"),
            Self::Rp => f.write_str("RP"),
            Self::Other(v) => write!(f, "TYPE{v}"),
        }
    }
}

/// DNS response codes (RFC 1035 §4.1.1 + RFC 2136 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Rcode {
    /// No error — the query completed successfully (RCODE 0).
    NoError,
    /// Format error — the server could not interpret the request (RCODE 1).
    FormErr,
    /// Server failure — the server encountered an internal error (RCODE 2).
    ServFail,
    /// Non-existent domain — the queried name does not exist (RCODE 3).
    NxDomain,
    /// Not implemented — the server does not support this query type (RCODE 4).
    NotImp,
    /// Refused — the server refused the request for policy reasons (RCODE 5).
    Refused,
    /// Name exists when it should not (RFC 2136 dynamic update, RCODE 6).
    YxDomain,
    /// RR set exists when it should not (RFC 2136, RCODE 7).
    YxRrset,
    /// RR set that should exist does not (RFC 2136, RCODE 8).
    NxRrset,
    /// Server not authoritative for the zone (RFC 2136, RCODE 9).
    NotAuth,
    /// Name not contained in zone (RFC 2136, RCODE 10).
    NotZone,
    /// Any other response code not listed above, identified by its numeric value.
    Other(u16),
}

impl Rcode {
    /// Map a raw numeric RCODE to the corresponding variant.
    ///
    /// Unknown codes produce `Other(value)`.
    pub fn from_value(value: u16) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YxDomain,
            7 => Self::YxRrset,
            8 => Self::NxRrset,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            other => Self::Other(other),
        }
    }

    /// Return the numeric RCODE value.
    pub fn value(&self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::YxDomain => 6,
            Self::YxRrset => 7,
            Self::NxRrset => 8,
            Self::NotAuth => 9,
            Self::NotZone => 10,
            Self::Other(v) => *v,
        }
    }

    /// Return `true` if this is `NoError` (RCODE 0).
    pub fn is_success(&self) -> bool {
        matches!(self, Self::NoError)
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => f.write_str("NOERROR"),
            Self::FormErr => f.write_str("FORMERR"),
            Self::ServFail => f.write_str("SERVFAIL"),
            Self::NxDomain => f.write_str("NXDOMAIN"),
            Self::NotImp => f.write_str("NOTIMP"),
            Self::Refused => f.write_str("REFUSED"),
            Self::YxDomain => f.write_str("YXDOMAIN"),
            Self::YxRrset => f.write_str("YXRRSET"),
            Self::NxRrset => f.write_str("NXRRSET"),
            Self::NotAuth => f.write_str("NOTAUTH"),
            Self::NotZone => f.write_str("NOTZONE"),
            Self::Other(v) => write!(f, "RCODE{v}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    #[test]
    fn record_type_roundtrip_named() {
        let types = [
            (RecordType::A, 1, "A"),
            (RecordType::Aaaa, 28, "AAAA"),
            (RecordType::Cname, 5, "CNAME"),
            (RecordType::Ns, 2, "NS"),
            (RecordType::Soa, 6, "SOA"),
            (RecordType::Mx, 15, "MX"),
            (RecordType::Txt, 16, "TXT"),
            (RecordType::Srv, 33, "SRV"),
            (RecordType::Caa, 257, "CAA"),
            (RecordType::Ptr, 12, "PTR"),
        ];
        for (rtype, value, name) in types {
            assert_eq!(rtype.value(), value, "value mismatch for {name}");
            assert_eq!(
                RecordType::from_value(value),
                rtype,
                "from_value mismatch for {name}"
            );
            assert_eq!(
                alloc::format!("{rtype}"),
                name,
                "display mismatch for {name}"
            );
        }
    }

    #[test]
    fn record_type_unknown_roundtrip() {
        let rtype = RecordType::from_value(65534);
        assert_eq!(rtype, RecordType::Other(65534));
        assert_eq!(rtype.value(), 65534);
        assert_eq!(alloc::format!("{rtype}"), "TYPE65534");
    }

    #[test]
    fn rcode_roundtrip_named() {
        let codes = [
            (Rcode::NoError, 0, "NOERROR"),
            (Rcode::NxDomain, 3, "NXDOMAIN"),
            (Rcode::Refused, 5, "REFUSED"),
            (Rcode::NotAuth, 9, "NOTAUTH"),
        ];
        for (rcode, value, name) in codes {
            assert_eq!(rcode.value(), value, "value mismatch for {name}");
            assert_eq!(
                Rcode::from_value(value),
                rcode,
                "from_value mismatch for {name}"
            );
            assert_eq!(
                alloc::format!("{rcode}"),
                name,
                "display mismatch for {name}"
            );
        }
    }

    #[test]
    fn rcode_is_success() {
        assert!(Rcode::NoError.is_success());
        assert!(!Rcode::NxDomain.is_success());
        assert!(!Rcode::Refused.is_success());
        assert!(!Rcode::Other(99).is_success());
    }

    #[test]
    fn rcode_unknown_roundtrip() {
        let rcode = Rcode::from_value(999);
        assert_eq!(rcode, Rcode::Other(999));
        assert_eq!(rcode.value(), 999);
    }
}
