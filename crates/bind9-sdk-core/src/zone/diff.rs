// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Zone diff engine — compute and apply differences between two [`Zone`] snapshots.
//!
//! # Overview
//!
//! [`Zone::diff`] compares two zones by record identity `(name, class, rdata)`:
//!
//! - Records in `other` but not `self` → [`DiffEntry::Added`]
//! - Records in `self` but not `other` → [`DiffEntry::Removed`]
//! - Records with identical identity but different TTL → [`DiffEntry::TtlChanged`]
//! - SOA records are excluded from the diff (callers manage serials explicitly)
//!
//! The resulting [`ZoneDiff`] can be:
//!
//! - Displayed with `+`/`-`/`~` human-readable output
//! - Converted to RFC 2136 [`UpdateEntry`] operations via [`ZoneDiff::to_updates`]
//! - Applied to a base zone via [`Zone::apply_diff`]

use alloc::vec::Vec;
use core::fmt;

use crate::rdata::RecordData;
use crate::record::{ResourceRecord, Ttl};
use crate::update::UpdateEntry;
use crate::zone::Zone;

/// A single entry in a zone diff.
///
/// Compares records by identity `(name, class, rdata)`. SOA records are
/// excluded — callers manage serial numbers explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiffEntry {
    /// A record present in the new zone but absent from the old zone.
    Added(ResourceRecord),
    /// A record present in the old zone but absent from the new zone.
    Removed(ResourceRecord),
    /// A record with the same identity (`name`, `class`, `rdata`) but a
    /// different TTL. `record` carries the **new** TTL.
    TtlChanged {
        /// The record with the updated TTL (new zone value).
        record: ResourceRecord,
        /// TTL in the old zone.
        old_ttl: Ttl,
        /// TTL in the new zone (same as `record.ttl`).
        new_ttl: Ttl,
    },
}

/// The computed difference between two [`Zone`] snapshots.
///
/// Obtain via [`Zone::diff`]. Apply via [`Zone::apply_diff`].
/// Convert to RFC 2136 update operations via [`ZoneDiff::to_updates`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneDiff {
    /// Ordered list of diff entries (added, removed, TTL-changed).
    pub entries: Vec<DiffEntry>,
}

impl ZoneDiff {
    /// Returns a slice of all diff entries.
    pub fn entries(&self) -> &[DiffEntry] {
        &self.entries
    }

    /// Returns `true` if there are no differences.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of diff entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Convert this diff to a list of RFC 2136 [`UpdateEntry`] operations.
    ///
    /// - [`DiffEntry::Added`] → [`UpdateEntry::AddRecord`]
    /// - [`DiffEntry::Removed`] → [`UpdateEntry::DeleteRecord`]
    /// - [`DiffEntry::TtlChanged`] → delete old record, then add new record
    ///   (the only way to change a TTL in RFC 2136 is delete-then-add)
    pub fn to_updates(&self) -> Vec<UpdateEntry> {
        let mut ops = Vec::new();
        for entry in &self.entries {
            match entry {
                DiffEntry::Added(rr) => {
                    ops.push(UpdateEntry::AddRecord(rr.clone()));
                }
                DiffEntry::Removed(rr) => {
                    ops.push(UpdateEntry::DeleteRecord(rr.clone()));
                }
                DiffEntry::TtlChanged {
                    record,
                    old_ttl,
                    new_ttl: _,
                } => {
                    // Delete the old record (with old TTL), then add the new one.
                    let old_rr = ResourceRecord {
                        name: record.name.clone(),
                        class: record.class,
                        ttl: *old_ttl,
                        rdata: record.rdata.clone(),
                    };
                    ops.push(UpdateEntry::DeleteRecord(old_rr));
                    ops.push(UpdateEntry::AddRecord(record.clone()));
                }
            }
        }
        ops
    }
}

impl fmt::Display for ZoneDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.entries.is_empty() {
            return f.write_str("(no changes)");
        }
        for entry in &self.entries {
            match entry {
                DiffEntry::Added(rr) => {
                    writeln!(
                        f,
                        "+ {} {} {} {}",
                        rr.name,
                        rr.ttl,
                        rr.class,
                        rdata_type_label(&rr.rdata),
                    )?;
                }
                DiffEntry::Removed(rr) => {
                    writeln!(
                        f,
                        "- {} {} {} {}",
                        rr.name,
                        rr.ttl,
                        rr.class,
                        rdata_type_label(&rr.rdata),
                    )?;
                }
                DiffEntry::TtlChanged {
                    record,
                    old_ttl,
                    new_ttl,
                } => {
                    writeln!(
                        f,
                        "~ {} {}->{} {} {}",
                        record.name,
                        old_ttl,
                        new_ttl,
                        record.class,
                        rdata_type_label(&record.rdata),
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// Returns a short type label for a `RecordData` variant (e.g. `"A"`, `"AAAA"`).
///
/// Used in human-readable diff output. Not the canonical serialization path.
fn rdata_type_label(rdata: &RecordData) -> &'static str {
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
        RecordData::Nsec3param { .. } => "NSEC3PARAM",
        RecordData::Dlv { .. } => "DLV",
        RecordData::Unknown { .. } => "UNKNOWN",
    }
}

/// Returns `true` if this record is a SOA record.
fn is_soa(rr: &ResourceRecord) -> bool {
    matches!(rr.rdata, RecordData::Soa { .. })
}

impl Zone {
    /// Compute the diff between `self` (old zone) and `other` (new zone).
    ///
    /// Records are compared by identity `(name, class, rdata)`. SOA records
    /// are excluded — manage serials separately. Records with identical
    /// identity but different TTL produce a [`DiffEntry::TtlChanged`] entry.
    ///
    /// The algorithm is O(n·m) where n and m are the non-SOA record counts.
    /// Zone files are typically small (hundreds to low thousands of records),
    /// so this is acceptable without requiring `Ord` or `Hash` on `RecordData`.
    pub fn diff(&self, other: &Zone) -> ZoneDiff {
        let old_records: Vec<&ResourceRecord> =
            self.records.iter().filter(|rr| !is_soa(rr)).collect();
        let new_records: Vec<&ResourceRecord> =
            other.records.iter().filter(|rr| !is_soa(rr)).collect();

        let mut entries = Vec::new();

        // Pass 1: find Added and TtlChanged (iterate new records).
        for new_rr in &new_records {
            // Look for a record in old with the same (name, class, rdata).
            let old_match = old_records.iter().find(|old_rr| {
                old_rr.name == new_rr.name
                    && old_rr.class == new_rr.class
                    && old_rr.rdata == new_rr.rdata
            });

            match old_match {
                None => {
                    // Not in old zone → Added.
                    entries.push(DiffEntry::Added((*new_rr).clone()));
                }
                Some(old_rr) if old_rr.ttl != new_rr.ttl => {
                    // Same identity, different TTL → TtlChanged.
                    entries.push(DiffEntry::TtlChanged {
                        record: (*new_rr).clone(),
                        old_ttl: old_rr.ttl,
                        new_ttl: new_rr.ttl,
                    });
                }
                Some(_) => {
                    // Identical record — no change.
                }
            }
        }

        // Pass 2: find Removed (iterate old records).
        for old_rr in &old_records {
            let still_present = new_records.iter().any(|new_rr| {
                new_rr.name == old_rr.name
                    && new_rr.class == old_rr.class
                    && new_rr.rdata == old_rr.rdata
            });
            if !still_present {
                entries.push(DiffEntry::Removed((*old_rr).clone()));
            }
        }

        ZoneDiff { entries }
    }

    /// Apply a [`ZoneDiff`] to produce a new zone.
    ///
    /// SOA records in `self` are carried forward unchanged — the diff engine
    /// excludes SOA from all diff operations. Records are modified as follows:
    ///
    /// - [`DiffEntry::Added`]: the record is appended.
    /// - [`DiffEntry::Removed`]: the first matching record (by identity
    ///   `name + class + rdata`) is removed.
    /// - [`DiffEntry::TtlChanged`]: the first matching record's TTL is updated
    ///   in-place (matched by `name + class + rdata`).
    pub fn apply_diff(&self, diff: &ZoneDiff) -> Zone {
        let mut records = self.records.clone();

        for entry in &diff.entries {
            match entry {
                DiffEntry::Added(rr) => {
                    records.push(rr.clone());
                }
                DiffEntry::Removed(rr) => {
                    if let Some(pos) = records.iter().position(|r| {
                        r.name == rr.name && r.class == rr.class && r.rdata == rr.rdata
                    }) {
                        records.remove(pos);
                    }
                }
                DiffEntry::TtlChanged {
                    record,
                    old_ttl: _,
                    new_ttl,
                } => {
                    if let Some(r) = records.iter_mut().find(|r| {
                        r.name == record.name && r.class == record.class && r.rdata == record.rdata
                    }) {
                        r.ttl = *new_ttl;
                    }
                }
            }
        }

        Zone {
            name: self.name.clone(),
            class: self.class,
            records,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainName;
    use crate::rdata::RecordData;
    use crate::record::{RecordClass, ResourceRecord, Serial, Ttl};
    use crate::update::UpdateEntry;
    use alloc::vec;
    use core::net::Ipv4Addr;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn domain(s: &str) -> DomainName {
        DomainName::new(s).unwrap()
    }

    fn ttl(v: u32) -> Ttl {
        Ttl::new(v).unwrap()
    }

    fn a_record(name: &str, addr: Ipv4Addr, ttl_v: u32) -> ResourceRecord {
        ResourceRecord {
            name: domain(name),
            class: RecordClass::IN,
            ttl: ttl(ttl_v),
            rdata: RecordData::A(addr),
        }
    }

    fn soa_record(name: &str) -> ResourceRecord {
        ResourceRecord {
            name: domain(name),
            class: RecordClass::IN,
            ttl: ttl(3600),
            rdata: RecordData::Soa {
                mname: domain("ns1.example.com."),
                rname: domain("admin.example.com."),
                serial: Serial::new(1),
                refresh: ttl(3600),
                retry: ttl(900),
                expire: ttl(604800),
                minimum: ttl(86400),
            },
        }
    }

    fn base_zone() -> Zone {
        Zone {
            name: domain("example.com."),
            class: RecordClass::IN,
            records: vec![
                soa_record("example.com."),
                a_record("www.example.com.", Ipv4Addr::new(192, 0, 2, 1), 3600),
                a_record("mail.example.com.", Ipv4Addr::new(192, 0, 2, 2), 3600),
            ],
        }
    }

    // ── DiffEntry::Added ─────────────────────────────────────────────────────

    #[test]
    fn diff_added_record() {
        let old = base_zone();
        let mut new = old.clone();
        new.records.push(a_record(
            "ftp.example.com.",
            Ipv4Addr::new(192, 0, 2, 3),
            3600,
        ));

        let diff = old.diff(&new);

        assert_eq!(diff.len(), 1);
        assert!(
            matches!(&diff.entries[0], DiffEntry::Added(rr) if rr.name == domain("ftp.example.com."))
        );
    }

    // ── DiffEntry::Removed ───────────────────────────────────────────────────

    #[test]
    fn diff_removed_record() {
        let old = base_zone();
        let mut new = old.clone();
        // Remove the mail record.
        new.records.retain(
            |rr| !matches!(rr.rdata, RecordData::A(addr) if addr == Ipv4Addr::new(192, 0, 2, 2)),
        );

        let diff = old.diff(&new);

        assert_eq!(diff.len(), 1);
        assert!(
            matches!(&diff.entries[0], DiffEntry::Removed(rr) if rr.name == domain("mail.example.com."))
        );
    }

    // ── DiffEntry::TtlChanged ────────────────────────────────────────────────

    #[test]
    fn diff_ttl_changed() {
        let old = base_zone();
        let mut new = old.clone();
        // Change TTL of the www record from 3600 to 300.
        for rr in &mut new.records {
            if rr.name == domain("www.example.com.") {
                rr.ttl = ttl(300);
            }
        }

        let diff = old.diff(&new);

        assert_eq!(diff.len(), 1);
        assert!(matches!(
            &diff.entries[0],
            DiffEntry::TtlChanged { old_ttl, new_ttl, .. }
                if old_ttl.value() == 3600 && new_ttl.value() == 300
        ));
    }

    // ── SOA excluded ─────────────────────────────────────────────────────────

    #[test]
    fn diff_excludes_soa() {
        let old = base_zone();
        let mut new = old.clone();
        // Bump SOA serial — diff should remain empty.
        for rr in &mut new.records {
            if let RecordData::Soa { serial, .. } = &mut rr.rdata {
                *serial = Serial::new(2);
            }
        }

        let diff = old.diff(&new);
        assert!(diff.is_empty(), "SOA-only changes must not appear in diff");
    }

    // ── identical zones ───────────────────────────────────────────────────────

    #[test]
    fn diff_identical_zones_is_empty() {
        let zone = base_zone();
        let diff = zone.diff(&zone);
        assert!(diff.is_empty());
    }

    // ── to_updates ───────────────────────────────────────────────────────────

    #[test]
    fn to_updates_added_produces_add_record() {
        let rr = a_record("ftp.example.com.", Ipv4Addr::new(192, 0, 2, 5), 3600);
        let diff = ZoneDiff {
            entries: vec![DiffEntry::Added(rr.clone())],
        };
        let ops = diff.to_updates();
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], UpdateEntry::AddRecord(r) if r == &rr));
    }

    #[test]
    fn to_updates_removed_produces_delete_record() {
        let rr = a_record("old.example.com.", Ipv4Addr::new(192, 0, 2, 9), 3600);
        let diff = ZoneDiff {
            entries: vec![DiffEntry::Removed(rr.clone())],
        };
        let ops = diff.to_updates();
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], UpdateEntry::DeleteRecord(r) if r == &rr));
    }

    #[test]
    fn to_updates_ttl_changed_produces_delete_then_add() {
        let new_rr = a_record("www.example.com.", Ipv4Addr::new(192, 0, 2, 1), 300);
        let old_ttl = ttl(3600);
        let diff = ZoneDiff {
            entries: vec![DiffEntry::TtlChanged {
                record: new_rr.clone(),
                old_ttl,
                new_ttl: ttl(300),
            }],
        };
        let ops = diff.to_updates();
        assert_eq!(ops.len(), 2);
        // First op: delete with old TTL
        assert!(matches!(&ops[0], UpdateEntry::DeleteRecord(r) if r.ttl.value() == 3600));
        // Second op: add with new TTL
        assert!(matches!(&ops[1], UpdateEntry::AddRecord(r) if r.ttl.value() == 300));
    }

    // ── apply_diff ───────────────────────────────────────────────────────────

    #[test]
    fn apply_diff_adds_record() {
        let old = base_zone();
        let new_rr = a_record("ftp.example.com.", Ipv4Addr::new(192, 0, 2, 99), 600);
        let diff = ZoneDiff {
            entries: vec![DiffEntry::Added(new_rr.clone())],
        };
        let result = old.apply_diff(&diff);
        assert!(result.records.iter().any(|r| r == &new_rr));
    }

    #[test]
    fn apply_diff_removes_record() {
        let old = base_zone();
        let to_remove = a_record("mail.example.com.", Ipv4Addr::new(192, 0, 2, 2), 3600);
        let diff = ZoneDiff {
            entries: vec![DiffEntry::Removed(to_remove.clone())],
        };
        let result = old.apply_diff(&diff);
        assert!(!result.records.iter().any(|r| r == &to_remove));
    }

    #[test]
    fn apply_diff_updates_ttl() {
        let old = base_zone();
        let new_rr = a_record("www.example.com.", Ipv4Addr::new(192, 0, 2, 1), 300);
        let diff = ZoneDiff {
            entries: vec![DiffEntry::TtlChanged {
                record: new_rr.clone(),
                old_ttl: ttl(3600),
                new_ttl: ttl(300),
            }],
        };
        let result = old.apply_diff(&diff);
        let found = result
            .records
            .iter()
            .find(|r| r.name == domain("www.example.com."));
        assert!(found.is_some());
        assert_eq!(found.unwrap().ttl.value(), 300);
    }

    // ── Display ───────────────────────────────────────────────────────────────

    #[test]
    fn display_empty_diff() {
        let diff = ZoneDiff { entries: vec![] };
        assert_eq!(alloc::format!("{diff}"), "(no changes)");
    }

    #[test]
    fn display_added_entry() {
        let rr = a_record("new.example.com.", Ipv4Addr::new(1, 2, 3, 4), 60);
        let diff = ZoneDiff {
            entries: vec![DiffEntry::Added(rr)],
        };
        let s = alloc::format!("{diff}");
        assert!(s.starts_with("+ "), "expected '+ ' prefix, got: {s}");
        assert!(s.contains("IN"), "expected class in output");
        assert!(s.contains("A"), "expected record type in output");
    }

    #[test]
    fn display_removed_entry() {
        let rr = a_record("gone.example.com.", Ipv4Addr::new(5, 6, 7, 8), 120);
        let diff = ZoneDiff {
            entries: vec![DiffEntry::Removed(rr)],
        };
        let s = alloc::format!("{diff}");
        assert!(s.starts_with("- "), "expected '- ' prefix, got: {s}");
    }

    #[test]
    fn display_ttl_changed_entry() {
        let rr = a_record("www.example.com.", Ipv4Addr::new(192, 0, 2, 1), 300);
        let diff = ZoneDiff {
            entries: vec![DiffEntry::TtlChanged {
                record: rr,
                old_ttl: ttl(3600),
                new_ttl: ttl(300),
            }],
        };
        let s = alloc::format!("{diff}");
        assert!(s.starts_with("~ "), "expected '~ ' prefix, got: {s}");
        assert!(
            s.contains("3600->300"),
            "expected TTL change in output, got: {s}"
        );
    }

    // ── proptest roundtrip ────────────────────────────────────────────────────

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Arbitrary IPv4 address strategy.
        fn arb_ipv4() -> impl Strategy<Value = Ipv4Addr> {
            (1u8..=254, 1u8..=254, 1u8..=254, 1u8..=254)
                .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
        }

        /// Arbitrary A record with a constrained label to produce valid domain names.
        fn arb_a_record() -> impl Strategy<Value = ResourceRecord> {
            (
                "[a-z][a-z0-9]{1,10}",
                arb_ipv4(),
                (1u32..=86400).prop_map(|v| Ttl::new(v).unwrap()),
            )
                .prop_map(|(label, addr, record_ttl)| ResourceRecord {
                    name: DomainName::new(&alloc::format!("{label}.example.com.")).unwrap(),
                    class: RecordClass::IN,
                    ttl: record_ttl,
                    rdata: RecordData::A(addr),
                })
        }

        /// Arbitrary Zone built from a SOA + up to 8 A records.
        fn arb_zone() -> impl Strategy<Value = Zone> {
            proptest::collection::vec(arb_a_record(), 0..8).prop_map(|extra| {
                let origin = DomainName::new("example.com.").unwrap();
                let mut records = vec![ResourceRecord {
                    name: origin.clone(),
                    class: RecordClass::IN,
                    ttl: Ttl::new(3600).unwrap(),
                    rdata: RecordData::Soa {
                        mname: DomainName::new("ns1.example.com.").unwrap(),
                        rname: DomainName::new("admin.example.com.").unwrap(),
                        serial: Serial::new(1),
                        refresh: Ttl::new(3600).unwrap(),
                        retry: Ttl::new(900).unwrap(),
                        expire: Ttl::new(604800).unwrap(),
                        minimum: Ttl::new(86400).unwrap(),
                    },
                }];
                records.extend(extra);
                Zone {
                    name: origin,
                    class: RecordClass::IN,
                    records,
                }
            })
        }

        proptest! {
            /// `apply_diff(diff(a, b))` produces a zone whose non-SOA records
            /// equal those of `b` (the diff roundtrip property).
            #[test]
            fn diff_apply_roundtrip(a in arb_zone(), b in arb_zone()) {
                let diff = a.diff(&b);
                let result = a.apply_diff(&diff);

                // Collect non-SOA records from result and b, sorted by name string for comparison.
                let mut result_records: Vec<_> = result
                    .records
                    .iter()
                    .filter(|rr| !is_soa(rr))
                    .cloned()
                    .collect();
                let mut b_records: Vec<_> = b
                    .records
                    .iter()
                    .filter(|rr| !is_soa(rr))
                    .cloned()
                    .collect();

                // Sort by (name, ttl, rdata debug) for deterministic comparison.
                result_records.sort_by(|x, y| {
                    let nx = alloc::format!("{}{}", x.name, x.ttl);
                    let ny = alloc::format!("{}{}", y.name, y.ttl);
                    nx.cmp(&ny)
                });
                b_records.sort_by(|x, y| {
                    let nx = alloc::format!("{}{}", x.name, x.ttl);
                    let ny = alloc::format!("{}{}", y.name, y.ttl);
                    nx.cmp(&ny)
                });

                prop_assert_eq!(
                    result_records,
                    b_records,
                    "apply_diff(diff(a, b)) must equal b's non-SOA records"
                );
            }

            /// `diff(a, a)` is always empty.
            #[test]
            fn diff_self_is_empty(a in arb_zone()) {
                let diff = a.diff(&a);
                prop_assert!(diff.is_empty(), "diff of zone with itself must be empty");
            }

            /// `to_updates` on an empty diff produces no operations.
            #[test]
            fn empty_diff_no_updates(a in arb_zone()) {
                let diff = a.diff(&a);
                let ops = diff.to_updates();
                prop_assert!(ops.is_empty(), "empty diff must produce no update operations");
            }
        }
    }
}
