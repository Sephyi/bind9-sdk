// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use alloc::format;
use alloc::string::String;

use crate::zone::rdata_text;
use crate::zone::ZoneFile;

/// Serialize a ZoneFile to canonical zone file text format.
pub(crate) fn serialize(zone_file: &ZoneFile) -> String {
    let mut out = String::new();

    // $ORIGIN directive
    out.push_str(&format!("$ORIGIN {}\n", zone_file.origin));

    // $TTL directive (if set)
    if let Some(ref ttl) = zone_file.default_ttl {
        out.push_str(&format!("$TTL {}\n", ttl.value()));
    }

    // Records
    let mut last_owner: Option<&crate::domain::DomainName> = None;

    for rr in &zone_file.zone.records {
        // Check if we can elide the owner (same as previous)
        if last_owner == Some(&rr.name) {
            out.push_str(&format!(
                "\t{}\t{}\t{}\t{}\n",
                rr.ttl.value(),
                rr.class,
                rdata_type_str(&rr.rdata),
                rdata_text::serialize_rdata(&rr.rdata),
            ));
        } else {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                rr.name,
                rr.ttl.value(),
                rr.class,
                rdata_type_str(&rr.rdata),
                rdata_text::serialize_rdata(&rr.rdata),
            ));
        }

        last_owner = Some(&rr.name);
    }

    out
}

/// Get the type keyword string for a RecordData variant.
fn rdata_type_str(rdata: &crate::rdata::RecordData) -> &'static str {
    use crate::rdata::RecordData;
    match rdata {
        RecordData::A(_) => "A",
        RecordData::Aaaa(_) => "AAAA",
        RecordData::Cname(_) => "CNAME",
        RecordData::Ns(_) => "NS",
        RecordData::Ptr(_) => "PTR",
        RecordData::Soa { .. } => "SOA",
        RecordData::Mx { .. } => "MX",
        RecordData::Txt(_) => "TXT",
        RecordData::Srv { .. } => "SRV",
        RecordData::Caa { .. } => "CAA",
        RecordData::Dnskey { .. } => "DNSKEY",
        RecordData::Rrsig { .. } => "RRSIG",
        RecordData::Nsec { .. } => "NSEC",
        RecordData::Nsec3 { .. } => "NSEC3",
        RecordData::Ds { .. } => "DS",
        RecordData::Cds { .. } => "CDS",
        RecordData::Cdnskey { .. } => "CDNSKEY",
        RecordData::Tlsa { .. } => "TLSA",
        RecordData::Sshfp { .. } => "SSHFP",
        RecordData::Csync { .. } => "CSYNC",
        RecordData::Rp { .. } => "RP",
        RecordData::Unknown { .. } => "TYPE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use crate::domain::DomainName;
    use crate::rdata::RecordData;
    use crate::record::{RecordClass, ResourceRecord, Serial, Ttl};
    use crate::zone::Zone;
    use core::net::Ipv4Addr;

    fn example_zonefile() -> ZoneFile {
        let origin = DomainName::new("example.com.").unwrap();
        ZoneFile {
            origin: origin.clone(),
            default_ttl: Some(Ttl::new(3600).unwrap()),
            zone: Zone {
                name: origin.clone(),
                class: RecordClass::IN,
                records: alloc::vec![
                    ResourceRecord {
                        name: origin.clone(),
                        class: RecordClass::IN,
                        ttl: Ttl::new(3600).unwrap(),
                        rdata: RecordData::Soa {
                            mname: DomainName::new("ns1.example.com.").unwrap(),
                            rname: DomainName::new("admin.example.com.").unwrap(),
                            serial: Serial::new(2026031401),
                            refresh: Ttl::new(3600).unwrap(),
                            retry: Ttl::new(900).unwrap(),
                            expire: Ttl::new(604800).unwrap(),
                            minimum: Ttl::new(86400).unwrap(),
                        },
                    },
                    ResourceRecord {
                        name: origin.clone(),
                        class: RecordClass::IN,
                        ttl: Ttl::new(3600).unwrap(),
                        rdata: RecordData::Ns(DomainName::new("ns1.example.com.").unwrap()),
                    },
                    ResourceRecord {
                        name: origin.clone(),
                        class: RecordClass::IN,
                        ttl: Ttl::new(3600).unwrap(),
                        rdata: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
                    },
                ],
            },
        }
    }

    #[test]
    fn serialize_includes_origin_directive() {
        let zf = example_zonefile();
        let output = serialize(&zf);
        assert!(
            output.starts_with("$ORIGIN example.com.\n"),
            "should start with $ORIGIN: {output}"
        );
    }

    #[test]
    fn serialize_includes_ttl_directive() {
        let zf = example_zonefile();
        let output = serialize(&zf);
        assert!(
            output.contains("$TTL 3600\n"),
            "should contain $TTL: {output}"
        );
    }

    #[test]
    fn serialize_records_present() {
        let zf = example_zonefile();
        let output = serialize(&zf);
        assert!(output.contains("SOA"), "should contain SOA: {output}");
        assert!(output.contains("NS"), "should contain NS: {output}");
        assert!(
            output.contains("192.0.2.1"),
            "should contain A record: {output}"
        );
    }

    #[test]
    fn serialize_records_have_class_and_ttl() {
        let zf = example_zonefile();
        let output = serialize(&zf);
        assert!(
            output.contains("IN"),
            "should contain record class: {output}"
        );
        assert!(output.contains("3600"), "should contain TTL: {output}");
    }

    #[test]
    fn serialize_no_default_ttl() {
        let mut zf = example_zonefile();
        zf.default_ttl = None;
        let output = serialize(&zf);
        assert!(
            !output.contains("$TTL"),
            "should not contain $TTL when None: {output}"
        );
    }

    #[test]
    fn serialize_ends_with_newline() {
        let zf = example_zonefile();
        let output = serialize(&zf);
        assert!(output.ends_with('\n'), "output should end with newline");
    }
}

#[cfg(test)]
mod roundtrip_tests {
    extern crate alloc;
    use crate::zone::ZoneFile;

    #[test]
    fn roundtrip_minimal_zone() {
        let input = "\
$ORIGIN example.com.
$TTL 3600
example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2026031401 3600 900 604800 86400
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN A 192.0.2.1
";
        let zf = ZoneFile::parse(input).unwrap();
        let output = zf.serialize();
        let zf2 = ZoneFile::parse(&output).unwrap();
        assert_eq!(zf.zone.records.len(), zf2.zone.records.len());
        assert_eq!(zf.origin, zf2.origin);
        assert_eq!(zf.zone.records, zf2.zone.records);
    }

    #[test]
    fn roundtrip_multiple_record_types() {
        let input = "\
$ORIGIN example.com.
$TTL 300
example.com. 300 IN SOA ns1.example.com. admin.example.com. 1 3600 900 604800 86400
example.com. 300 IN NS ns1.example.com.
example.com. 300 IN NS ns2.example.com.
example.com. 300 IN A 192.0.2.1
example.com. 300 IN AAAA 2001:db8::1
example.com. 300 IN MX 10 mail.example.com.
www.example.com. 300 IN CNAME example.com.
example.com. 300 IN TXT \"v=spf1 ~all\"
";
        let zf = ZoneFile::parse(input).unwrap();
        let output = zf.serialize();
        let zf2 = ZoneFile::parse(&output).unwrap();
        assert_eq!(zf.zone.records.len(), zf2.zone.records.len());
        for (a, b) in zf.zone.records.iter().zip(zf2.zone.records.iter()) {
            assert_eq!(a.name, b.name, "owner mismatch");
            assert_eq!(a.class, b.class, "class mismatch");
            assert_eq!(a.ttl, b.ttl, "ttl mismatch");
            assert_eq!(a.rdata, b.rdata, "rdata mismatch");
        }
    }

    #[test]
    fn roundtrip_srv_and_caa() {
        let input = "\
$ORIGIN example.com.
$TTL 300
example.com. 300 IN SOA ns1.example.com. admin.example.com. 1 3600 900 604800 86400
_sip._tcp.example.com. 300 IN SRV 10 60 5060 sip.example.com.
example.com. 300 IN CAA 0 issue \"letsencrypt.org\"
";
        let zf = ZoneFile::parse(input).unwrap();
        let output = zf.serialize();
        let zf2 = ZoneFile::parse(&output).unwrap();
        assert_eq!(zf.zone.records.len(), zf2.zone.records.len());
        assert_eq!(zf.zone.records, zf2.zone.records);
    }

    #[test]
    fn roundtrip_preserves_origin() {
        let input = "\
$ORIGIN sub.example.com.
$TTL 600
sub.example.com. 600 IN SOA ns1.example.com. admin.example.com. 1 3600 900 604800 86400
sub.example.com. 600 IN A 10.0.0.1
";
        let zf = ZoneFile::parse(input).unwrap();
        let output = zf.serialize();
        let zf2 = ZoneFile::parse(&output).unwrap();
        assert_eq!(zf.origin, zf2.origin);
    }
}
