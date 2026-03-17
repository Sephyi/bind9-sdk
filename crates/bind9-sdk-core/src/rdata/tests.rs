// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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
