// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

extern crate alloc;
extern crate std;
use super::*;
use crate::domain::DomainName;
use alloc::format;

// --- TsigAlgorithm tests ---

#[test]
fn algorithm_dns_name_sha256() {
    assert_eq!(TsigAlgorithm::HmacSha256.dns_name(), "hmac-sha256.");
}

#[test]
fn algorithm_dns_name_sha512() {
    assert_eq!(TsigAlgorithm::HmacSha512.dns_name(), "hmac-sha512.");
}

#[test]
#[allow(deprecated)]
fn algorithm_dns_name_sha1() {
    assert_eq!(TsigAlgorithm::HmacSha1.dns_name(), "hmac-sha1.");
}

#[test]
fn algorithm_key_length_sha256() {
    assert_eq!(TsigAlgorithm::HmacSha256.key_length(), 32);
}

#[test]
fn algorithm_key_length_sha512() {
    assert_eq!(TsigAlgorithm::HmacSha512.key_length(), 64);
}

#[test]
#[allow(deprecated)]
fn algorithm_key_length_sha1() {
    assert_eq!(TsigAlgorithm::HmacSha1.key_length(), 20);
}

#[test]
fn algorithm_display_sha256() {
    assert_eq!(format!("{}", TsigAlgorithm::HmacSha256), "hmac-sha256");
}

#[test]
fn algorithm_debug() {
    assert_eq!(format!("{:?}", TsigAlgorithm::HmacSha256), "HmacSha256");
}

#[test]
fn algorithm_clone_eq() {
    let a = TsigAlgorithm::HmacSha256;
    let b = a;
    assert_eq!(a, b);
}

// --- TsigKey tests ---

#[test]
fn tsig_key_new_valid() {
    let key = TsigKey::new(
        DomainName::new("tsig-key.example.com.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0u8; 32],
    );
    assert!(key.is_ok());
}

#[test]
fn tsig_key_new_empty_material_rejected() {
    let key = TsigKey::new(
        DomainName::new("tsig-key.example.com.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![],
    );
    assert!(key.is_err());
}

#[test]
fn tsig_key_accessors() {
    let name = DomainName::new("my-key.").unwrap();
    let key = TsigKey::new(
        name.clone(),
        TsigAlgorithm::HmacSha512,
        alloc::vec![0xAB; 64],
    )
    .unwrap();
    assert_eq!(key.name(), &name);
    assert_eq!(key.algorithm(), TsigAlgorithm::HmacSha512);
}

#[test]
fn tsig_key_debug_redacts_material() {
    let key = TsigKey::new(
        DomainName::new("secret-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xFF; 32],
    )
    .unwrap();
    let debug = format!("{:?}", key);
    assert!(
        debug.contains("[REDACTED]"),
        "Debug output must redact key material: {debug}"
    );
    assert!(
        !debug.contains("255"),
        "Debug must not leak key bytes: {debug}"
    );
    assert!(
        !debug.contains("0xff"),
        "Debug must not leak key bytes: {debug}"
    );
    assert!(
        debug.contains("secret-key."),
        "Debug should include key name: {debug}"
    );
    assert!(
        debug.contains("HmacSha256"),
        "Debug should include algorithm: {debug}"
    );
}

// --- from_base64 tests ---

#[test]
fn tsig_key_from_base64_valid() {
    let b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let key = TsigKey::from_base64(
        DomainName::new("b64-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        b64,
    );
    assert!(key.is_ok());
}

#[test]
fn tsig_key_from_base64_with_whitespace() {
    let b64 = "AAAAAAAAAAAAAAAA\n  AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let key = TsigKey::from_base64(
        DomainName::new("b64-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        b64,
    );
    assert!(key.is_ok(), "from_base64 should strip whitespace");
}

#[test]
fn tsig_key_from_base64_invalid() {
    let key = TsigKey::from_base64(
        DomainName::new("bad-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        "not!valid!base64!!!",
    );
    assert!(key.is_err());
}

#[test]
fn tsig_key_from_base64_empty() {
    let key = TsigKey::from_base64(
        DomainName::new("empty-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        "",
    );
    assert!(key.is_err());
}

#[test]
fn tsig_key_from_base64_known_value() {
    let key = TsigKey::from_base64(
        DomainName::new("known-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        "aGVsbG8gd29ybGQ=",
    )
    .unwrap();
    assert_eq!(key.material(), b"hello world");
}

// --- generate tests (std-gated) ---

#[cfg(feature = "std")]
#[test]
fn tsig_key_generate_sha256() {
    let key = TsigKey::generate(
        DomainName::new("gen-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
    )
    .unwrap();
    assert_eq!(key.algorithm(), TsigAlgorithm::HmacSha256);
    assert_eq!(key.material().len(), 32);
}

#[cfg(feature = "std")]
#[test]
fn tsig_key_generate_sha512() {
    let key = TsigKey::generate(
        DomainName::new("gen-key.").unwrap(),
        TsigAlgorithm::HmacSha512,
    )
    .unwrap();
    assert_eq!(key.material().len(), 64);
}

#[cfg(feature = "std")]
#[test]
fn tsig_key_generate_unique() {
    let key1 =
        TsigKey::generate(DomainName::new("k1.").unwrap(), TsigAlgorithm::HmacSha256).unwrap();
    let key2 =
        TsigKey::generate(DomainName::new("k2.").unwrap(), TsigAlgorithm::HmacSha256).unwrap();
    assert_ne!(key1.material(), key2.material());
}

// --- sign/verify tests ---

#[test]
fn sign_produces_correct_length_sha256() {
    let key = TsigKey::new(
        DomainName::new("sign-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let mac = key.sign(b"test message");
    assert_eq!(mac.len(), 32, "HMAC-SHA256 must produce 32-byte MAC");
}

#[test]
fn sign_produces_correct_length_sha512() {
    let key = TsigKey::new(
        DomainName::new("sign-key.").unwrap(),
        TsigAlgorithm::HmacSha512,
        alloc::vec![0xBB; 64],
    )
    .unwrap();
    let mac = key.sign(b"test message");
    assert_eq!(mac.len(), 64, "HMAC-SHA512 must produce 64-byte MAC");
}

#[test]
#[allow(deprecated)]
fn sign_produces_correct_length_sha1() {
    let key = TsigKey::new(
        DomainName::new("sign-key.").unwrap(),
        TsigAlgorithm::HmacSha1,
        alloc::vec![0xCC; 20],
    )
    .unwrap();
    let mac = key.sign(b"test message");
    assert_eq!(mac.len(), 20, "HMAC-SHA1 must produce 20-byte MAC");
}

#[test]
fn verify_valid_signature() {
    let key = TsigKey::new(
        DomainName::new("verify-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0x42; 32],
    )
    .unwrap();
    let message = b"authenticate this message";
    let mac = key.sign(message);
    assert!(key.verify(message, &mac).is_ok());
}

#[test]
fn verify_wrong_mac_rejected() {
    let key = TsigKey::new(
        DomainName::new("verify-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0x42; 32],
    )
    .unwrap();
    let message = b"authenticate this message";
    let bad_mac = alloc::vec![0x00; 32];
    assert!(key.verify(message, &bad_mac).is_err());
}

#[test]
fn verify_wrong_message_rejected() {
    let key = TsigKey::new(
        DomainName::new("verify-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0x42; 32],
    )
    .unwrap();
    let mac = key.sign(b"original message");
    assert!(key.verify(b"tampered message", &mac).is_err());
}

#[test]
fn verify_truncated_mac_rejected() {
    let key = TsigKey::new(
        DomainName::new("verify-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0x42; 32],
    )
    .unwrap();
    let mac = key.sign(b"some message");
    let truncated = &mac[..16];
    assert!(key.verify(b"some message", truncated).is_err());
}

#[test]
fn sign_deterministic_same_key_same_message() {
    let key = TsigKey::new(
        DomainName::new("det-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0x01; 32],
    )
    .unwrap();
    let mac1 = key.sign(b"deterministic");
    let mac2 = key.sign(b"deterministic");
    assert_eq!(mac1, mac2, "Same key + same message must produce same MAC");
}

#[test]
fn sign_different_keys_different_macs() {
    let key1 = TsigKey::new(
        DomainName::new("k1.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0x01; 32],
    )
    .unwrap();
    let key2 = TsigKey::new(
        DomainName::new("k2.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0x02; 32],
    )
    .unwrap();
    let mac1 = key1.sign(b"same message");
    let mac2 = key2.sign(b"same message");
    assert_ne!(mac1, mac2);
}

/// RFC 4231 Test Case 1 for HMAC-SHA256
#[test]
fn sign_rfc_test_vector_sha256() {
    let key = TsigKey::new(
        DomainName::new("test.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0x0b; 20],
    )
    .unwrap();
    let mac = key.sign(b"Hi There");
    let expected = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
        0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
        0xcf, 0xf7,
    ];
    assert_eq!(
        mac.as_slice(),
        &expected,
        "HMAC-SHA256 must match RFC 4231 test vector 1"
    );
}

#[test]
fn verify_roundtrip_sha512() {
    let key = TsigKey::new(
        DomainName::new("sha512-key.").unwrap(),
        TsigAlgorithm::HmacSha512,
        alloc::vec![0xDD; 64],
    )
    .unwrap();
    let message = b"sha512 roundtrip test";
    let mac = key.sign(message);
    assert_eq!(mac.len(), 64);
    assert!(key.verify(message, &mac).is_ok());
}

#[test]
fn verify_wrong_mac_sha512() {
    let key = TsigKey::new(
        DomainName::new("sha512-key.").unwrap(),
        TsigAlgorithm::HmacSha512,
        alloc::vec![0xDD; 64],
    )
    .unwrap();
    let bad_mac = alloc::vec![0x00; 64];
    assert!(key.verify(b"some message", &bad_mac).is_err());
}

#[allow(deprecated)]
#[test]
fn verify_roundtrip_sha1() {
    let key = TsigKey::new(
        DomainName::new("sha1-key.").unwrap(),
        TsigAlgorithm::HmacSha1,
        alloc::vec![0xEE; 20],
    )
    .unwrap();
    let message = b"sha1 roundtrip test";
    let mac = key.sign(message);
    assert_eq!(mac.len(), 20);
    assert!(key.verify(message, &mac).is_ok());
}

#[allow(deprecated)]
#[test]
fn verify_wrong_mac_sha1() {
    let key = TsigKey::new(
        DomainName::new("sha1-key.").unwrap(),
        TsigAlgorithm::HmacSha1,
        alloc::vec![0xEE; 20],
    )
    .unwrap();
    let bad_mac = alloc::vec![0x00; 20];
    assert!(key.verify(b"some message", &bad_mac).is_err());
}

/// RFC 4231 Test Case 1 for HMAC-SHA512
#[test]
fn sign_rfc_test_vector_sha512() {
    let key = TsigKey::new(
        DomainName::new("test.").unwrap(),
        TsigAlgorithm::HmacSha512,
        alloc::vec![0x0b; 20],
    )
    .unwrap();
    let mac = key.sign(b"Hi There");
    let expected = [
        0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c,
        0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1,
        0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae,
        0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20,
        0x3a, 0x12, 0x68, 0x54,
    ];
    assert_eq!(
        mac.as_slice(),
        &expected,
        "HMAC-SHA512 must match RFC 4231 test vector 1"
    );
}

/// RFC 2202 Test Case 1 for HMAC-SHA1
#[allow(deprecated)]
#[test]
fn sign_rfc_test_vector_sha1() {
    let key = TsigKey::new(
        DomainName::new("test.").unwrap(),
        TsigAlgorithm::HmacSha1,
        alloc::vec![0x0b; 20],
    )
    .unwrap();
    let mac = key.sign(b"Hi There");
    let expected = [
        0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c,
        0x8e, 0xf1, 0x46, 0xbe, 0x00,
    ];
    assert_eq!(
        mac.as_slice(),
        &expected,
        "HMAC-SHA1 must match RFC 2202 test vector 1"
    );
}

// --- TsigRecord tests ---

#[test]
fn tsig_record_new_produces_valid_wire() {
    let key = TsigKey::new(
        DomainName::new("test-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let message = alloc::vec![0x00; 12];
    let timestamp = 1710000000u64;

    let record = TsigRecord::new(&key, &message, timestamp, None);

    assert!(!record.wire_bytes.is_empty());
    assert!(record.key_name == DomainName::new("test-key.").unwrap());
    assert_eq!(record.algorithm, TsigAlgorithm::HmacSha256);
    assert_eq!(record.mac.len(), 32);
    assert_eq!(record.time_signed, timestamp);
    assert_eq!(record.fudge, 300);
}

#[test]
fn tsig_record_different_timestamps_different_macs() {
    let key = TsigKey::new(
        DomainName::new("ts-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xBB; 32],
    )
    .unwrap();
    let message = alloc::vec![0x00; 12];

    let r1 = TsigRecord::new(&key, &message, 1000, None);
    let r2 = TsigRecord::new(&key, &message, 2000, None);

    assert_ne!(
        r1.mac, r2.mac,
        "Different timestamps must produce different MACs"
    );
}

#[test]
fn tsig_record_wire_bytes_contains_all_fields() {
    let key = TsigKey::new(
        DomainName::new("k.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xCC; 32],
    )
    .unwrap();
    let message = alloc::vec![
        0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    let record = TsigRecord::new(&key, &message, 1710000000, None);

    let wire = &record.wire_bytes;
    assert!(
        wire.len() > 20,
        "Wire bytes too short: {} bytes",
        wire.len()
    );
}

#[test]
fn tsig_record_canonical_key_name_produces_same_mac() {
    // RFC 8945 §4.3.3: key names are canonicalized to lowercase for MAC.
    // Mixed-case and lowercase key names with identical material must
    // produce identical MACs for the same message and timestamp.
    let material = alloc::vec![0xDD; 32];
    let key_upper = TsigKey::new(
        DomainName::new("My-Key.Example.COM.").unwrap(),
        TsigAlgorithm::HmacSha256,
        material.clone(),
    )
    .unwrap();
    let key_lower = TsigKey::new(
        DomainName::new("my-key.example.com.").unwrap(),
        TsigAlgorithm::HmacSha256,
        material,
    )
    .unwrap();
    let message = alloc::vec![0x00; 12];
    let ts = 1710000000u64;

    let r1 = TsigRecord::new(&key_upper, &message, ts, None);
    let r2 = TsigRecord::new(&key_lower, &message, ts, None);

    assert_eq!(
        r1.mac, r2.mac,
        "Canonical (lowercase) key names must produce identical MACs"
    );
}

#[test]
fn tsig_record_debug_redacts_mac() {
    let key = TsigKey::new(
        DomainName::new("dbg-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xEE; 32],
    )
    .unwrap();
    let record = TsigRecord::new(&key, &alloc::vec![0u8; 12], 1710000000, None);
    let debug = format!("{:?}", record);
    assert!(
        debug.contains("[REDACTED]"),
        "Debug must redact mac: {debug}"
    );
    assert!(
        !debug.contains("238"),
        "Debug must not leak mac bytes: {debug}"
    );
}

#[test]
fn tsig_record_with_request_mac_differs() {
    let key = TsigKey::new(
        DomainName::new("chain-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xBB; 32],
    )
    .unwrap();
    let msg = alloc::vec![0u8; 12];
    let ts = 1710000000u64;

    let r1 = TsigRecord::new(&key, &msg, ts, None);
    let prior_mac = alloc::vec![0xCC; 32];
    let r2 = TsigRecord::new(&key, &msg, ts, Some(&prior_mac));

    assert_ne!(
        &*r1.mac, &*r2.mac,
        "Including request_mac must change the output MAC"
    );
}

// --- parse_from_wire tests ---

#[test]
fn tsig_record_wire_roundtrip() {
    let key = TsigKey::new(
        DomainName::new("rt-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xDD; 32],
    )
    .unwrap();
    let message = alloc::vec![
        0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let ts = 1710000000u64;
    let original = TsigRecord::new(&key, &message, ts, None);

    let parsed = TsigRecord::parse_from_wire(&original.wire_bytes).unwrap();
    assert_eq!(parsed.key_name, original.key_name);
    assert_eq!(parsed.algorithm, original.algorithm);
    assert_eq!(parsed.time_signed, original.time_signed);
    assert_eq!(parsed.fudge, original.fudge);
    assert_eq!(&*parsed.mac, &*original.mac);
    assert_eq!(parsed.original_id, original.original_id);
}

#[test]
fn parse_from_wire_rejects_truncated() {
    let result = TsigRecord::parse_from_wire(&[0x03, b'k', b'e', b'y']);
    assert!(result.is_err());
}

#[test]
fn parse_from_wire_rejects_wrong_type() {
    let key = TsigKey::new(
        DomainName::new("k.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let record = TsigRecord::new(&key, &alloc::vec![0u8; 12], 1710000000, None);
    let mut bad_wire = record.wire_bytes.to_vec();
    // Corrupt the TYPE field (right after the owner name)
    // Owner name for "k." is [1, b'k', 0] = 3 bytes
    bad_wire[3] = 0x00; // TYPE high byte
    bad_wire[4] = 0x01; // TYPE = 1 (A) instead of 250 (TSIG)
    let result = TsigRecord::parse_from_wire(&bad_wire);
    assert!(result.is_err());
}

// --- verify_time tests ---

#[test]
fn tsig_verify_time_rejects_expired_fudge() {
    let key = TsigKey::new(
        DomainName::new("fudge-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let record = TsigRecord::new(&key, &alloc::vec![0u8; 12], 1710000000, None);
    let now = 1710000000 + 600; // 10 minutes later, outside 300s fudge
    assert!(record.verify_time(now).is_err());
}

#[test]
fn tsig_verify_time_accepts_within_fudge() {
    let key = TsigKey::new(
        DomainName::new("fudge-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let record = TsigRecord::new(&key, &alloc::vec![0u8; 12], 1710000000, None);
    let now = 1710000000 + 100; // within 300s fudge
    assert!(record.verify_time(now).is_ok());
}

#[test]
fn tsig_verify_time_accepts_exact_boundary() {
    let key = TsigKey::new(
        DomainName::new("fudge-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let record = TsigRecord::new(&key, &alloc::vec![0u8; 12], 1710000000, None);
    // Exactly at fudge boundary
    assert!(record.verify_time(1710000000 + 300).is_ok());
    assert!(record.verify_time(1710000000 - 300).is_ok());
    // One past boundary
    assert!(record.verify_time(1710000000 + 301).is_err());
}

// --- verify_response tests ---

#[test]
fn tsig_verify_response_valid() {
    let key = TsigKey::new(
        DomainName::new("resp-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let request_msg = alloc::vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let ts = 1710000000u64;
    let request_tsig = TsigRecord::new(&key, &request_msg, ts, None);

    // Simulate a response signed with request_mac chaining
    let response_msg = alloc::vec![
        0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    let response_tsig = TsigRecord::new(&key, &response_msg, ts, Some(&request_tsig.mac));

    let result = TsigRecord::verify_response(
        &key,
        &response_msg,
        &response_tsig,
        &request_tsig.mac,
        ts + 1,
    );
    assert!(result.is_ok());
}

#[test]
fn tsig_verify_response_wrong_mac_rejected() {
    let key = TsigKey::new(
        DomainName::new("resp-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let request_msg = alloc::vec![0u8; 12];
    let ts = 1710000000u64;
    let request_tsig = TsigRecord::new(&key, &request_msg, ts, None);

    let response_msg = alloc::vec![
        0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];
    // Sign with wrong request_mac
    let wrong_mac = alloc::vec![0xFF; 32];
    let response_tsig = TsigRecord::new(&key, &response_msg, ts, Some(&wrong_mac));

    let result = TsigRecord::verify_response(
        &key,
        &response_msg,
        &response_tsig,
        &request_tsig.mac,
        ts + 1,
    );
    assert!(result.is_err());
}

#[test]
fn tsig_verify_response_expired_fudge_rejected() {
    let key = TsigKey::new(
        DomainName::new("resp-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let request_msg = alloc::vec![0u8; 12];
    let ts = 1710000000u64;
    let request_tsig = TsigRecord::new(&key, &request_msg, ts, None);

    let response_msg = alloc::vec![0u8; 12];
    let response_tsig = TsigRecord::new(&key, &response_msg, ts, Some(&request_tsig.mac));

    // now is far outside fudge window
    let result = TsigRecord::verify_response(
        &key,
        &response_msg,
        &response_tsig,
        &request_tsig.mac,
        ts + 600,
    );
    assert!(result.is_err());
}

// --- parse_from_wire error/other_data tests ---

#[test]
fn parse_from_wire_extracts_error_and_other_fields() {
    let key = TsigKey::new(
        DomainName::new("test-key.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let msg = alloc::vec![0u8; 12];
    let timestamp = 1710000000u64;
    let tsig = TsigRecord::new(&key, &msg, timestamp, None);
    let parsed = TsigRecord::parse_from_wire(&tsig.wire_bytes).unwrap();
    assert_eq!(parsed.error, 0);
    assert!(parsed.other_data.is_empty());
}

#[test]
fn parse_from_wire_rejects_nonzero_ttl() {
    let key = TsigKey::new(
        DomainName::new("k.").unwrap(),
        TsigAlgorithm::HmacSha256,
        alloc::vec![0xAA; 32],
    )
    .unwrap();
    let tsig = TsigRecord::new(&key, &alloc::vec![0u8; 12], 1710000000, None);
    let mut bad_wire = tsig.wire_bytes.to_vec();
    // Find TTL field: skip owner name, then TYPE(2) + CLASS(2)
    let mut pos = 0;
    loop {
        let len = bad_wire[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1 + len;
    }
    pos += 4; // TYPE + CLASS
    // Set TTL to 1 (non-zero)
    bad_wire[pos..pos + 4].copy_from_slice(&1u32.to_be_bytes());
    assert!(TsigRecord::parse_from_wire(&bad_wire).is_err());
}

// --- Proptests ---

mod proptests {
    use super::*;
    use crate::domain::DomainName;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn sign_verify_roundtrip(
            key_bytes in proptest::collection::vec(any::<u8>(), 1..=64),
            message in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let key = TsigKey::new(
                DomainName::new("prop-key.").unwrap(),
                TsigAlgorithm::HmacSha256,
                key_bytes,
            ).unwrap();
            let mac = key.sign(&message);
            prop_assert!(key.verify(&message, &mac).is_ok());
        }

        #[test]
        fn sign_verify_different_message_fails(
            key_bytes in proptest::collection::vec(any::<u8>(), 16..=32),
            msg1 in proptest::collection::vec(any::<u8>(), 1..=256),
            msg2 in proptest::collection::vec(any::<u8>(), 1..=256),
        ) {
            prop_assume!(msg1 != msg2);
            let key = TsigKey::new(
                DomainName::new("prop-key.").unwrap(),
                TsigAlgorithm::HmacSha256,
                key_bytes,
            ).unwrap();
            let mac = key.sign(&msg1);
            prop_assert!(key.verify(&msg2, &mac).is_err());
        }

        /// Signing with one key and verifying with a different key must always fail.
        #[test]
        fn sign_with_key_a_verify_with_key_b_fails(
            key_a_bytes in proptest::collection::vec(any::<u8>(), 16..=32),
            key_b_bytes in proptest::collection::vec(any::<u8>(), 16..=32),
            message in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            prop_assume!(key_a_bytes != key_b_bytes);
            let key_a = TsigKey::new(
                DomainName::new("key-a.").unwrap(),
                TsigAlgorithm::HmacSha256,
                key_a_bytes,
            ).unwrap();
            let key_b = TsigKey::new(
                DomainName::new("key-b.").unwrap(),
                TsigAlgorithm::HmacSha256,
                key_b_bytes,
            ).unwrap();
            let mac = key_a.sign(&message);
            prop_assert!(
                key_b.verify(&message, &mac).is_err(),
                "different keys should not produce the same MAC"
            );
        }

        /// MAC length matches the algorithm's declared mac_length() for all inputs.
        #[test]
        fn mac_length_matches_algorithm(
            key_bytes in proptest::collection::vec(any::<u8>(), 1..=64),
            message in proptest::collection::vec(any::<u8>(), 0..=256),
        ) {
            let key = TsigKey::new(
                DomainName::new("len-key.").unwrap(),
                TsigAlgorithm::HmacSha256,
                key_bytes,
            ).unwrap();
            let mac = key.sign(&message);
            prop_assert_eq!(
                mac.len(),
                TsigAlgorithm::HmacSha256.mac_length(),
                "MAC length must equal algorithm mac_length()"
            );
        }
    }
}
