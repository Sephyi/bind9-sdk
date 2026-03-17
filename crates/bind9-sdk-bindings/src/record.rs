// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use bind9_sdk_core::rdata::RecordData;
use bind9_sdk_core::record::ResourceRecord;
use napi_derive::napi;
use serde_json::{json, Value};

/// A DNS resource record as a plain JavaScript object.
///
/// All fields are serialized to strings or JSON values for easy
/// consumption from JavaScript/TypeScript.
#[napi(object)]
pub struct JsResourceRecord {
    /// Owner name (fully qualified, with trailing dot).
    pub name: String,
    /// Record class (e.g., `"IN"`).
    pub class: String,
    /// Time-to-live in seconds.
    pub ttl: u32,
    /// Record type name (e.g., `"A"`, `"AAAA"`, `"SOA"`).
    pub rtype: String,
    /// Record data as a JSON value. Structure varies by record type.
    pub rdata: Value,
}

/// Convert an internal `ResourceRecord` to a JS-friendly representation.
pub(crate) fn convert_resource_record(rr: &ResourceRecord) -> JsResourceRecord {
    JsResourceRecord {
        name: rr.name.to_string(),
        class: rr.class.to_string(),
        ttl: rr.ttl.value(),
        rtype: rdata_type_name(&rr.rdata).to_string(),
        rdata: rdata_to_json(&rr.rdata),
    }
}

/// Hex-encode a byte slice.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Map a `RecordData` variant to its DNS type name string.
fn rdata_type_name(rdata: &RecordData) -> &'static str {
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
        RecordData::Unknown { rtype, .. } => {
            // Return a static str; the numeric type is captured in the JSON rdata
            let _ = rtype;
            "UNKNOWN"
        }
        // non_exhaustive: future variants
        _ => "UNKNOWN",
    }
}

/// Convert `RecordData` to a `serde_json::Value` for JS consumption.
#[allow(clippy::too_many_lines)]
fn rdata_to_json(rdata: &RecordData) -> Value {
    match rdata {
        RecordData::A(addr) => json!({ "address": addr.to_string() }),
        RecordData::Aaaa(addr) => json!({ "address": addr.to_string() }),
        RecordData::Cname(name) => json!({ "cname": name.to_string() }),
        RecordData::Ns(name) => json!({ "nsdname": name.to_string() }),
        RecordData::Ptr(name) => json!({ "ptrdname": name.to_string() }),
        RecordData::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => json!({
            "mname": mname.to_string(),
            "rname": rname.to_string(),
            "serial": serial.value(),
            "refresh": refresh.value(),
            "retry": retry.value(),
            "expire": expire.value(),
            "minimum": minimum.value(),
        }),
        RecordData::Mx {
            preference,
            exchange,
        } => json!({
            "preference": preference,
            "exchange": exchange.to_string(),
        }),
        RecordData::Txt(strings) => json!({ "strings": strings }),
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => json!({
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": target.to_string(),
        }),
        RecordData::Caa { flags, tag, value } => json!({
            "flags": flags,
            "tag": tag,
            "value": value,
        }),
        RecordData::Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        } => json!({
            "flags": flags,
            "protocol": protocol,
            "algorithm": algorithm,
            "publicKey": hex(public_key),
        }),
        RecordData::Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        } => json!({
            "typeCovered": type_covered,
            "algorithm": algorithm,
            "labels": labels,
            "originalTtl": original_ttl,
            "signatureExpiration": signature_expiration,
            "signatureInception": signature_inception,
            "keyTag": key_tag,
            "signerName": signer_name.to_string(),
            "signature": hex(signature),
        }),
        RecordData::Nsec {
            next_domain,
            type_bitmaps,
        } => json!({
            "nextDomain": next_domain.to_string(),
            "typeBitmaps": hex(type_bitmaps),
        }),
        RecordData::Nsec3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            type_bitmaps,
        } => json!({
            "hashAlgorithm": hash_algorithm,
            "flags": flags,
            "iterations": iterations,
            "salt": hex(salt),
            "nextHashedOwner": hex(next_hashed_owner),
            "typeBitmaps": hex(type_bitmaps),
        }),
        RecordData::Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => json!({
            "keyTag": key_tag,
            "algorithm": algorithm,
            "digestType": digest_type,
            "digest": hex(digest),
        }),
        RecordData::Cds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => json!({
            "keyTag": key_tag,
            "algorithm": algorithm,
            "digestType": digest_type,
            "digest": hex(digest),
        }),
        RecordData::Cdnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        } => json!({
            "flags": flags,
            "protocol": protocol,
            "algorithm": algorithm,
            "publicKey": hex(public_key),
        }),
        RecordData::Tlsa {
            usage,
            selector,
            matching_type,
            certificate_data,
        } => json!({
            "usage": usage,
            "selector": selector,
            "matchingType": matching_type,
            "certificateData": hex(certificate_data),
        }),
        RecordData::Sshfp {
            algorithm,
            fp_type,
            fingerprint,
        } => json!({
            "algorithm": algorithm,
            "fpType": fp_type,
            "fingerprint": hex(fingerprint),
        }),
        RecordData::Csync {
            soa_serial,
            flags,
            type_bitmaps,
        } => json!({
            "soaSerial": soa_serial,
            "flags": flags,
            "typeBitmaps": hex(type_bitmaps),
        }),
        RecordData::Rp { mbox, txt } => json!({
            "mbox": mbox.to_string(),
            "txt": txt.to_string(),
        }),
        RecordData::Nsec3param {
            hash_algorithm,
            flags,
            iterations,
            salt,
        } => json!({
            "hashAlgorithm": hash_algorithm,
            "flags": flags,
            "iterations": iterations,
            "salt": hex(salt),
        }),
        RecordData::Dlv {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => json!({
            "keyTag": key_tag,
            "algorithm": algorithm,
            "digestType": digest_type,
            "digest": hex(digest),
        }),
        RecordData::Unknown { rtype, rdata } => json!({
            "rtype": rtype,
            "rdata": hex(rdata),
        }),
        // non_exhaustive: future variants get a debug representation
        _ => json!({ "unknown": format!("{rdata:?}") }),
    }
}
