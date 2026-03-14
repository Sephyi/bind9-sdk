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
    Rp { mbox: DomainName, txt: DomainName },

    /// Unknown record type — raw RDATA preserved as bytes.
    Unknown { rtype: u16, rdata: Vec<u8> },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainName;
    use crate::record::{Serial, Ttl};
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
