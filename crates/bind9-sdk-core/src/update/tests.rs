// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;

use alloc::string::ToString;

use crate::domain::DomainName;
use crate::protocol::RecordType;
use crate::rdata::{RecordData, TxtString};
use crate::record::{RecordClass, Ttl};

#[test]
fn update_message_accessors() {
    let msg = UpdateMessage {
        wire_bytes: alloc::vec![0x00, 0x01, 0x28, 0x00],
        id: 0x0001,
        request_mac: None,
        pre_tsig_len: None,
    };
    assert_eq!(msg.as_bytes(), &[0x00, 0x01, 0x28, 0x00]);
    assert_eq!(msg.id(), 0x0001);
    assert!(!msg.is_signed());
    assert!(msg.request_mac().is_none());
}

#[test]
fn update_result_success() {
    let result = UpdateResult {
        rcode: Rcode::NoError,
        id: 42,
    };
    assert!(result.rcode.is_success());
}

#[test]
fn prerequisite_rrset_exists() {
    let prereq = Prerequisite::RrsetExists {
        name: DomainName::new("example.com.").unwrap(),
        rtype: RecordType::A,
    };
    assert!(matches!(prereq, Prerequisite::RrsetExists { .. }));
}

#[test]
fn prerequisite_name_not_exists() {
    let prereq = Prerequisite::NameNotExists {
        name: DomainName::new("missing.example.com.").unwrap(),
    };
    assert!(matches!(prereq, Prerequisite::NameNotExists { .. }));
}

#[test]
fn update_entry_add_record() {
    let rr = ResourceRecord {
        name: DomainName::new("new.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(300).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
    };
    let entry = UpdateEntry::AddRecord(rr);
    assert!(matches!(entry, UpdateEntry::AddRecord(_)));
}

#[test]
fn update_entry_delete_rrset() {
    let entry = UpdateEntry::DeleteRrset {
        name: DomainName::new("old.example.com.").unwrap(),
        rtype: RecordType::A,
    };
    assert!(matches!(entry, UpdateEntry::DeleteRrset { .. }));
}

#[test]
fn update_entry_delete_name() {
    let entry = UpdateEntry::DeleteName {
        name: DomainName::new("gone.example.com.").unwrap(),
    };
    assert!(matches!(entry, UpdateEntry::DeleteName { .. }));
}

// --- UpdateBuilder tests ---

#[test]
#[cfg(feature = "std")]
fn builder_new_creates_unsigned() {
    let zone = DomainName::new("example.com.").unwrap();
    let builder = UpdateBuilder::new(zone, RecordClass::IN).unwrap();
    let _msg = builder.build_unsigned().unwrap();
}

#[test]
#[cfg(not(feature = "std"))]
fn builder_new_requires_explicit_id_without_random_source() {
    let zone = DomainName::new("example.com.").unwrap();
    let error = match UpdateBuilder::new(zone, RecordClass::IN) {
        Ok(_) => panic!("no_std builder creation without an explicit ID must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("use with_id"));
}

#[test]
fn builder_with_id() {
    let zone = DomainName::new("example.com.").unwrap();
    let builder = UpdateBuilder::with_id(0x1234, zone, RecordClass::IN);
    let msg = builder.build_unsigned().unwrap();
    assert_eq!(msg.id(), 0x1234);
}

#[test]
fn builder_add_prerequisite() {
    let zone = DomainName::new("example.com.").unwrap();
    let builder = UpdateBuilder::with_id(1, zone, RecordClass::IN)
        .require_rrset_exists(&DomainName::new("www.example.com.").unwrap(), RecordType::A)
        .require_name_not_exists(&DomainName::new("new.example.com.").unwrap());
    let _msg = builder.build_unsigned().unwrap();
}

#[test]
fn builder_add_records() {
    let zone = DomainName::new("example.com.").unwrap();
    let rr = ResourceRecord {
        name: DomainName::new("www.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(300).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
    };
    let builder = UpdateBuilder::with_id(1, zone, RecordClass::IN).add_record(rr);
    let _msg = builder.build_unsigned().unwrap();
}

#[test]
fn builder_delete_operations() {
    let zone = DomainName::new("example.com.").unwrap();
    let rr = ResourceRecord {
        name: DomainName::new("old.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(0).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 2)),
    };
    let builder = UpdateBuilder::with_id(1, zone, RecordClass::IN)
        .delete_rrset(
            &DomainName::new("del.example.com.").unwrap(),
            RecordType::Aaaa,
        )
        .delete_record(rr)
        .delete_name(&DomainName::new("gone.example.com.").unwrap());
    let _msg = builder.build_unsigned().unwrap();
}

#[test]
fn builder_chaining() {
    let zone = DomainName::new("example.com.").unwrap();
    let rr = ResourceRecord {
        name: DomainName::new("www.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(3600).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(192, 0, 2, 1)),
    };
    let msg = UpdateBuilder::with_id(42, zone, RecordClass::IN)
        .require_name_exists(&DomainName::new("www.example.com.").unwrap())
        .add_record(rr)
        .delete_rrset(&DomainName::new("old.example.com.").unwrap(), RecordType::A)
        .build_unsigned()
        .unwrap();
    assert_eq!(msg.id(), 42);
    assert!(!msg.as_bytes().is_empty());
}

#[test]
fn prerequisite_rejects_empty_rrset_exists_with_data() {
    let zone = DomainName::new("example.com.").unwrap();
    let result = UpdateBuilder::with_id(1, zone, RecordClass::IN).require_rrset_exists_with_data(
        &DomainName::new("test.example.com.").unwrap(),
        RecordType::A,
        alloc::vec![],
    );
    assert!(result.is_err(), "empty records should return Err");
}

// --- Wire format tests ---

#[test]
fn wire_header_opcode_is_update() {
    let zone = DomainName::new("example.com.").unwrap();
    let msg = UpdateBuilder::with_id(0xABCD, zone, RecordClass::IN)
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();

    // Bytes 0-1: ID
    assert_eq!(bytes[0], 0xAB);
    assert_eq!(bytes[1], 0xCD);

    // Byte 2: QR(0) + Opcode(5=UPDATE) + AA(0) + TC(0) + RD(0) = 0x28
    assert_eq!(bytes[2], 0x28);

    // Byte 3: RA(0) + Z(0) + RCODE(0) = 0x00
    assert_eq!(bytes[3], 0x00);
}

#[test]
fn wire_section_counts() {
    let zone = DomainName::new("example.com.").unwrap();
    let rr = ResourceRecord {
        name: DomainName::new("www.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(300).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
    };
    let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
        .require_rrset_exists(&DomainName::new("www.example.com.").unwrap(), RecordType::A)
        .add_record(rr)
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();

    // ZOCOUNT (bytes 4-5): 1
    assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 1);

    // PRCOUNT (bytes 6-7): 1
    assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1);

    // UPCOUNT (bytes 8-9): 1
    assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 1);

    // ADCOUNT (bytes 10-11): 0
    assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), 0);
}

#[test]
fn wire_rrset_exists_with_data_prcount() {
    let zone = DomainName::new("example.com.").unwrap();
    let name = DomainName::new("www.example.com.").unwrap();
    let rr1 = ResourceRecord {
        name: name.clone(),
        class: RecordClass::IN,
        ttl: Ttl::new(300).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
    };
    let rr2 = ResourceRecord {
        name: name.clone(),
        class: RecordClass::IN,
        ttl: Ttl::new(300).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 2)),
    };
    let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
        .require_rrset_exists_with_data(&name, RecordType::A, alloc::vec![rr1, rr2])
        .unwrap()
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();

    // PRCOUNT should be 2 (one RR per record in the RRset)
    assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 2);
}

#[test]
fn wire_rrset_exists_with_data_encoding() {
    let zone = DomainName::new("example.com.").unwrap();
    let name = DomainName::new("www.example.com.").unwrap();
    let rr = ResourceRecord {
        name: name.clone(),
        class: RecordClass::IN,
        ttl: Ttl::new(300).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
    };
    let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
        .require_rrset_exists_with_data(&name, RecordType::A, alloc::vec![rr])
        .unwrap()
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();

    // After header (12) + zone section (13 name + 2 type + 2 class = 17), prerequisite starts at 29
    let prereq_start = 29;

    // Name: \x03www\x07example\x03com\x00 = 17 bytes
    assert_eq!(bytes[prereq_start], 3); // "www" label
    let after_name = prereq_start + 17;

    // TYPE: A (1)
    assert_eq!(
        u16::from_be_bytes([bytes[after_name], bytes[after_name + 1]]),
        1
    );
    // CLASS: IN (1) — zone class, NOT ANY
    assert_eq!(
        u16::from_be_bytes([bytes[after_name + 2], bytes[after_name + 3]]),
        1
    );
    // TTL: 0
    assert_eq!(
        u32::from_be_bytes([
            bytes[after_name + 4],
            bytes[after_name + 5],
            bytes[after_name + 6],
            bytes[after_name + 7]
        ]),
        0
    );
    // RDLENGTH: 4 (IPv4 address)
    assert_eq!(
        u16::from_be_bytes([bytes[after_name + 8], bytes[after_name + 9]]),
        4
    );
    // RDATA: 10.0.0.1
    assert_eq!(&bytes[after_name + 10..after_name + 14], &[10, 0, 0, 1]);
}

#[test]
fn wire_rrset_exists_with_data_mixed_prerequisites() {
    // Mix RrsetExistsWithData (2 records) + RrsetExists (1 RR) = PRCOUNT 3
    let zone = DomainName::new("example.com.").unwrap();
    let name = DomainName::new("www.example.com.").unwrap();
    let rr1 = ResourceRecord {
        name: name.clone(),
        class: RecordClass::IN,
        ttl: Ttl::new(0).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
    };
    let rr2 = ResourceRecord {
        name: name.clone(),
        class: RecordClass::IN,
        ttl: Ttl::new(0).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 2)),
    };
    let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
        .require_rrset_exists_with_data(&name, RecordType::A, alloc::vec![rr1, rr2])
        .unwrap()
        .require_rrset_exists(&name, RecordType::Aaaa)
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();

    // PRCOUNT: 2 (from RrsetExistsWithData) + 1 (from RrsetExists) = 3
    assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 3);
}

#[test]
fn wire_zone_section_present() {
    let zone = DomainName::new("example.com.").unwrap();
    let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();

    // After 12-byte header, zone section:
    // Name: \x07example\x03com\x00 (13 bytes)
    assert_eq!(bytes[12], 7); // label length "example"
    assert_eq!(&bytes[13..20], b"example");
    assert_eq!(bytes[20], 3); // label length "com"
    assert_eq!(&bytes[21..24], b"com");
    assert_eq!(bytes[24], 0); // root label

    // TYPE: SOA (6)
    assert_eq!(u16::from_be_bytes([bytes[25], bytes[26]]), 6);

    // CLASS: IN (1)
    assert_eq!(u16::from_be_bytes([bytes[27], bytes[28]]), 1);
}

#[test]
fn wire_empty_update_just_header_and_zone() {
    let zone = DomainName::new("t.").unwrap();
    let msg = UpdateBuilder::with_id(0, zone, RecordClass::IN)
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();
    // Header (12) + zone name (3: \x01t\x00) + type (2) + class (2) = 19
    assert_eq!(bytes.len(), 19);
}

#[test]
fn wire_signed_message_has_tsig_in_additional() {
    let zone = DomainName::new("example.com.").unwrap();
    let key = crate::tsig::TsigKey::new(
        DomainName::new("test-key.").unwrap(),
        crate::tsig::TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
        .sign(&key, 0)
        .unwrap()
        .build();
    let bytes = msg.as_bytes();

    // ADCOUNT should be 1 (TSIG record in additional section)
    assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), 1);

    // Message should be longer than unsigned (TSIG adds significant bytes)
    assert!(bytes.len() > 19);
}

// --- Sign integration tests ---

#[test]
fn signed_build_produces_valid_message() {
    let zone = DomainName::new("example.com.").unwrap();
    let key = crate::tsig::TsigKey::new(
        DomainName::new("update-key.").unwrap(),
        crate::tsig::TsigAlgorithm::HmacSha256,
        alloc::vec![0x42; 32],
    )
    .unwrap();
    let rr = ResourceRecord {
        name: DomainName::new("new.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(300).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
    };

    let msg = UpdateBuilder::with_id(0x1234, zone, RecordClass::IN)
        .require_name_not_exists(&DomainName::new("new.example.com.").unwrap())
        .add_record(rr)
        .sign(&key, 1710000000)
        .unwrap()
        .build();

    let bytes = msg.as_bytes();
    assert_eq!(msg.id(), 0x1234);

    // Opcode must be UPDATE (5)
    assert_eq!(bytes[2] & 0x78, 0x28);

    // ZOCOUNT = 1
    assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 1);

    // PRCOUNT = 1
    assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1);

    // UPCOUNT = 1
    assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 1);

    // ADCOUNT = 1 (TSIG)
    assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), 1);
}

#[test]
fn wire_multiple_prerequisites_counted() {
    let zone = DomainName::new("example.com.").unwrap();
    let name = DomainName::new("www.example.com.").unwrap();
    let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
        .require_rrset_exists(&name, RecordType::A)
        .require_rrset_not_exists(&name, RecordType::Aaaa)
        .require_name_exists(&name)
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();
    assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 3);
    assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 0);
}

#[test]
fn wire_multiple_updates_counted() {
    let zone = DomainName::new("example.com.").unwrap();
    let rr1 = ResourceRecord {
        name: DomainName::new("a.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(300).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 1)),
    };
    let rr2 = ResourceRecord {
        name: DomainName::new("b.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(300).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(10, 0, 0, 2)),
    };
    let msg = UpdateBuilder::with_id(1, zone, RecordClass::IN)
        .add_record(rr1)
        .add_record(rr2)
        .delete_name(&DomainName::new("c.example.com.").unwrap())
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();
    assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0); // no prereqs
    assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 3); // 3 updates
}

#[test]
fn wire_delete_record_has_rdata() {
    let zone = DomainName::new("t.").unwrap();
    let rr = ResourceRecord {
        name: DomainName::new("t.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(0).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(1, 2, 3, 4)),
    };
    let msg = UpdateBuilder::with_id(0, zone, RecordClass::IN)
        .delete_record(rr)
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();

    // After header (12) + zone (t. = 3 bytes name + 2 type + 2 class = 7), update starts at 19
    let upd_start = 19;
    // Name: \x01t\x00 = 3 bytes
    let after_name = upd_start + 3;

    // TYPE: A (1)
    assert_eq!(
        u16::from_be_bytes([bytes[after_name], bytes[after_name + 1]]),
        1
    );
    // CLASS: NONE (254)
    assert_eq!(
        u16::from_be_bytes([bytes[after_name + 2], bytes[after_name + 3]]),
        254
    );
    // TTL: 0
    assert_eq!(
        u32::from_be_bytes([
            bytes[after_name + 4],
            bytes[after_name + 5],
            bytes[after_name + 6],
            bytes[after_name + 7]
        ]),
        0
    );
    // RDLENGTH: 4
    assert_eq!(
        u16::from_be_bytes([bytes[after_name + 8], bytes[after_name + 9]]),
        4
    );
    // RDATA: 1.2.3.4
    assert_eq!(&bytes[after_name + 10..after_name + 14], &[1, 2, 3, 4]);
}

#[test]
fn wire_delete_rrset_has_no_rdata() {
    let zone = DomainName::new("t.").unwrap();
    let msg = UpdateBuilder::with_id(0, zone, RecordClass::IN)
        .delete_rrset(&DomainName::new("t.").unwrap(), RecordType::Aaaa)
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();

    // After header (12) + zone (7), update at 19
    let upd_start = 19;
    let after_name = upd_start + 3; // \x01t\x00

    // TYPE: AAAA (28)
    assert_eq!(
        u16::from_be_bytes([bytes[after_name], bytes[after_name + 1]]),
        28
    );
    // CLASS: ANY (255)
    assert_eq!(
        u16::from_be_bytes([bytes[after_name + 2], bytes[after_name + 3]]),
        255
    );
    // TTL: 0
    assert_eq!(
        u32::from_be_bytes([
            bytes[after_name + 4],
            bytes[after_name + 5],
            bytes[after_name + 6],
            bytes[after_name + 7]
        ]),
        0
    );
    // RDLENGTH: 0
    assert_eq!(
        u16::from_be_bytes([bytes[after_name + 8], bytes[after_name + 9]]),
        0
    );
    // Nothing after RDLENGTH
    assert_eq!(bytes.len(), after_name + 10);
}

#[test]
fn wire_add_record_has_class_and_ttl() {
    let zone = DomainName::new("t.").unwrap();
    let rr = ResourceRecord {
        name: DomainName::new("t.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(3600).unwrap(),
        rdata: RecordData::A(core::net::Ipv4Addr::new(192, 168, 1, 1)),
    };
    let msg = UpdateBuilder::with_id(0, zone, RecordClass::IN)
        .add_record(rr)
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();

    let upd_start = 19;
    let after_name = upd_start + 3;

    // TYPE: A (1)
    assert_eq!(
        u16::from_be_bytes([bytes[after_name], bytes[after_name + 1]]),
        1
    );
    // CLASS: IN (1) — actual class, not ANY
    assert_eq!(
        u16::from_be_bytes([bytes[after_name + 2], bytes[after_name + 3]]),
        1
    );
    // TTL: 3600
    assert_eq!(
        u32::from_be_bytes([
            bytes[after_name + 4],
            bytes[after_name + 5],
            bytes[after_name + 6],
            bytes[after_name + 7]
        ]),
        3600
    );
    // RDLENGTH: 4
    assert_eq!(
        u16::from_be_bytes([bytes[after_name + 8], bytes[after_name + 9]]),
        4
    );
    // RDATA: 192.168.1.1
    assert_eq!(&bytes[after_name + 10..after_name + 14], &[192, 168, 1, 1]);
}

#[test]
fn wire_prerequisite_rrset_not_exists_class_none() {
    let zone = DomainName::new("t.").unwrap();
    let msg = UpdateBuilder::with_id(0, zone, RecordClass::IN)
        .require_rrset_not_exists(&DomainName::new("t.").unwrap(), RecordType::Mx)
        .build_unsigned()
        .unwrap();
    let bytes = msg.as_bytes();

    // After header (12) + zone (7), prereq at 19
    let after_name = 19 + 3; // \x01t\x00

    // TYPE: MX (15)
    assert_eq!(
        u16::from_be_bytes([bytes[after_name], bytes[after_name + 1]]),
        15
    );
    // CLASS: NONE (254)
    assert_eq!(
        u16::from_be_bytes([bytes[after_name + 2], bytes[after_name + 3]]),
        254
    );
}

#[test]
fn unsigned_and_signed_produce_different_bytes() {
    let zone = DomainName::new("example.com.").unwrap();
    let key = crate::tsig::TsigKey::new(
        DomainName::new("k.").unwrap(),
        crate::tsig::TsigAlgorithm::HmacSha256,
        alloc::vec![0xFF; 32],
    )
    .unwrap();

    let unsigned = UpdateBuilder::with_id(1, zone.clone(), RecordClass::IN)
        .build_unsigned()
        .unwrap();
    let signed = UpdateBuilder::with_id(1, zone, RecordClass::IN)
        .sign(&key, 0)
        .unwrap()
        .build();

    assert_ne!(unsigned.as_bytes(), signed.as_bytes());
    assert!(signed.as_bytes().len() > unsigned.as_bytes().len());
}

#[test]
fn build_rejects_rdata_larger_than_u16() {
    let record = ResourceRecord {
        name: DomainName::new("large.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(60).unwrap(),
        rdata: RecordData::Unknown {
            rtype: 65280,
            rdata: alloc::vec![0xAA; usize::from(u16::MAX) + 1],
        },
    };

    let error =
        UpdateBuilder::with_id(1, DomainName::new("example.com.").unwrap(), RecordClass::IN)
            .add_record(record)
            .build_unsigned()
            .unwrap_err();

    assert!(error.to_string().contains("RDATA") && error.to_string().contains("65535"));
}

#[test]
fn txt_character_string_rejects_larger_than_u8() {
    let error = TxtString::new(alloc::vec![b'x'; 256]).unwrap_err();
    assert!(error.to_string().contains("TXT") && error.to_string().contains("255"));
}

#[test]
fn build_rejects_caa_tag_larger_than_u8() {
    let record = ResourceRecord {
        name: DomainName::new("caa.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(60).unwrap(),
        rdata: RecordData::Caa {
            flags: 0,
            tag: "x".repeat(256),
            value: "ca.example".into(),
        },
    };

    let error =
        UpdateBuilder::with_id(1, DomainName::new("example.com.").unwrap(), RecordClass::IN)
            .add_record(record)
            .build_unsigned()
            .unwrap_err();

    assert!(error.to_string().contains("CAA tag") && error.to_string().contains("255"));
}

#[test]
fn build_rejects_nsec3_salt_larger_than_u8() {
    let record = ResourceRecord {
        name: DomainName::new("hash.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(60).unwrap(),
        rdata: RecordData::Nsec3 {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: alloc::vec![0xBB; 256],
            next_hashed_owner: alloc::vec![0xCC; 20],
            type_bitmaps: alloc::vec![0, 1, 0x40],
        },
    };

    let error =
        UpdateBuilder::with_id(1, DomainName::new("example.com.").unwrap(), RecordClass::IN)
            .add_record(record)
            .build_unsigned()
            .unwrap_err();

    assert!(error.to_string().contains("NSEC3 salt") && error.to_string().contains("255"));
}

#[test]
fn build_rejects_more_than_u16_update_records() {
    let zone = DomainName::new("example.com.").unwrap();
    let name = DomainName::new("bulk.example.com.").unwrap();
    let mut builder = UpdateBuilder::with_id(1, zone, RecordClass::IN);
    for _ in 0..=u16::MAX {
        builder = builder.delete_name(&name);
    }

    let error = builder.build_unsigned().unwrap_err();

    assert!(error.to_string().contains("update count") && error.to_string().contains("65535"));
}

#[test]
fn signing_rejects_message_that_exceeds_dns_limit_after_tsig() {
    let key = crate::tsig::TsigKey::new(
        DomainName::new("update-key.").unwrap(),
        crate::tsig::TsigAlgorithm::HmacSha256,
        alloc::vec![0x11; 32],
    )
    .unwrap();
    let record = ResourceRecord {
        name: DomainName::new("large.example.com.").unwrap(),
        class: RecordClass::IN,
        ttl: Ttl::new(60).unwrap(),
        rdata: RecordData::Unknown {
            rtype: 65280,
            rdata: alloc::vec![0xAA; 65_430],
        },
    };

    let result =
        UpdateBuilder::with_id(1, DomainName::new("example.com.").unwrap(), RecordClass::IN)
            .add_record(record)
            .sign(&key, 1_710_000_000);
    let error = match result {
        Ok(_) => panic!("TSIG must not make the DNS message exceed 65535 bytes"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("TSIG") && error.to_string().contains("65535"));
}

mod proptests {
    use super::*;
    use crate::domain::DomainName;
    use crate::record::RecordClass;
    use proptest::prelude::*;

    proptest! {
        /// Wire-encoded update messages are always at least 12 bytes (DNS header).
        #[test]
        fn wire_length_at_least_dns_header(id in 0u16..=u16::MAX) {
            let zone = DomainName::new("example.com.").unwrap();
            let msg = UpdateBuilder::with_id(id, zone, RecordClass::IN)
                .build_unsigned().unwrap();
            prop_assert!(
                msg.as_bytes().len() >= 12,
                "wire message too short: {} bytes", msg.as_bytes().len()
            );
        }

        /// ZOCOUNT field (bytes 4–5) is always exactly 1 in every UPDATE message.
        ///
        /// RFC 2136 §2 requires exactly one zone section entry.
        #[test]
        fn zocount_is_always_one(id in 0u16..=u16::MAX) {
            let zone = DomainName::new("example.com.").unwrap();
            let msg = UpdateBuilder::with_id(id, zone, RecordClass::IN)
                .build_unsigned().unwrap();
            let bytes = msg.as_bytes();
            let zocount = u16::from_be_bytes([bytes[4], bytes[5]]);
            prop_assert_eq!(zocount, 1, "ZOCOUNT must be 1, got {}", zocount);
        }

        /// The opcode field is always 5 (UPDATE) in messages produced by UpdateBuilder.
        #[test]
        fn opcode_is_update(id in 0u16..=u16::MAX) {
            let zone = DomainName::new("example.com.").unwrap();
            let msg = UpdateBuilder::with_id(id, zone, RecordClass::IN)
                .build_unsigned().unwrap();
            let bytes = msg.as_bytes();
            let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
            let opcode = (flags >> 11) & 0x0F;
            prop_assert_eq!(opcode, 5, "opcode must be 5 (UPDATE), got {}", opcode);
        }
    }
}
