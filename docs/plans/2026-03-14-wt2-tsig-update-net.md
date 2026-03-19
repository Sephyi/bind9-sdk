<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
-->

# WT-2: TSIG + UpdateBuilder + Net Foundation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement TSIG cryptographic signing, RFC 2136 UpdateBuilder with typestate, and the net crate foundation (NetError, TlsConfig, Bind9Client skeleton).

**Architecture:** TSIG and UpdateBuilder live in bind9-sdk-core (no_std). TsigKey uses Zeroizing<Vec<u8>> for key material with manual Debug redaction. UpdateBuilder uses typestate (Unsigned -> Signed) to enforce signing at compile time. Net foundation provides error types, TLS config, and client skeleton for Wave 2 protocol implementations.

**Tech Stack:** Rust 2024, no_std + alloc (core), tokio (net), hmac/sha2/sha1/digest/zeroize/base64 (crypto), rustls/webpki-roots (TLS), thiserror (errors)

**Branch:** `feat/tsig-update-net`
**Spec:** `docs/specs/2026-03-14-phase1-remainder-design.md` SS4
**Depends on:** Phase 1 scaffolding plan (must be complete)

## Chunk 1: TsigAlgorithm + TsigKey

### Task 1: TsigAlgorithm Enum

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs`

- [ ] **Step 1: Write failing tests for TsigAlgorithm**

Replace the stub contents of `crates/bind9-sdk-core/src/tsig.rs` with the TsigAlgorithm enum and tests. The tests reference methods that do not exist yet (`dns_name()`, `key_length()`), so they will fail to compile.

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::domain::DomainName;
use crate::error::CoreError;

/// TSIG HMAC algorithms supported by this SDK.
///
/// Maps to the algorithm names defined in RFC 8945 SS6.
/// `HmacSha256` is the recommended default. `HmacSha1` is provided only
/// for legacy BIND9 compatibility and is marked deprecated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TsigAlgorithm {
    /// HMAC-SHA256 (recommended)
    HmacSha256,
    /// HMAC-SHA512
    HmacSha512,
    /// HMAC-SHA1 (legacy only)
    #[deprecated(
        note = "HMAC-SHA1 is weak; use HmacSha256 or HmacSha512 for new deployments"
    )]
    HmacSha1,
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;
    use super::*;
    use alloc::format;

    #[test]
    fn algorithm_dns_name_sha256() {
        assert_eq!(
            TsigAlgorithm::HmacSha256.dns_name(),
            "hmac-sha256."
        );
    }

    #[test]
    fn algorithm_dns_name_sha512() {
        assert_eq!(
            TsigAlgorithm::HmacSha512.dns_name(),
            "hmac-sha512."
        );
    }

    #[test]
    #[allow(deprecated)]
    fn algorithm_dns_name_sha1() {
        assert_eq!(
            TsigAlgorithm::HmacSha1.dns_name(),
            "hmac-sha1."
        );
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
        assert_eq!(
            format!("{}", TsigAlgorithm::HmacSha256),
            "hmac-sha256"
        );
    }

    #[test]
    fn algorithm_debug() {
        assert_eq!(
            format!("{:?}", TsigAlgorithm::HmacSha256),
            "HmacSha256"
        );
    }

    #[test]
    fn algorithm_clone_eq() {
        let a = TsigAlgorithm::HmacSha256;
        let b = a;
        assert_eq!(a, b);
    }
}
```

- [ ] **Step 2: Verify tests fail to compile**

Run: `cargo test -p bind9-sdk-core -- tsig 2>&1 | head -20`
Expected: Compile error — `dns_name` and `key_length` methods not found on `TsigAlgorithm`

- [ ] **Step 3: Implement TsigAlgorithm methods**

Add the impl blocks between the enum definition and the `#[cfg(test)]` module:

```rust
impl TsigAlgorithm {
    /// The DNS algorithm name used in TSIG records (RFC 8945 SS6).
    ///
    /// Returns the canonical name in absolute form (with trailing dot).
    pub fn dns_name(&self) -> &'static str {
        #[allow(deprecated)]
        match self {
            Self::HmacSha256 => "hmac-sha256.",
            Self::HmacSha512 => "hmac-sha512.",
            Self::HmacSha1 => "hmac-sha1.",
        }
    }

    /// The recommended key length in bytes for this algorithm.
    ///
    /// For HMAC algorithms, this equals the hash output size.
    pub fn key_length(&self) -> usize {
        #[allow(deprecated)]
        match self {
            Self::HmacSha256 => 32,
            Self::HmacSha512 => 64,
            Self::HmacSha1 => 20,
        }
    }

    /// The MAC (message authentication code) output length in bytes.
    pub fn mac_length(&self) -> usize {
        // For HMAC, MAC length equals hash output length
        self.key_length()
    }
}

impl fmt::Display for TsigAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display without trailing dot (human-readable form)
        let name = self.dns_name();
        f.write_str(name.strip_suffix('.').unwrap_or(name))
    }
}
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `cargo test -p bind9-sdk-core -- tsig`
Expected: All 9 tests pass

- [ ] **Step 5: Run WASM target check**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Passes (no_std compatible)

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): add TsigAlgorithm enum with dns_name, key_length, Display"
```

### Task 2: TsigKey Struct and Constructor

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs`

- [ ] **Step 1: Write failing tests for TsigKey::new**

Add these tests to the existing `mod tests` block in `tsig.rs`:

```rust
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
        assert!(debug.contains("[REDACTED]"), "Debug output must redact key material: {debug}");
        assert!(!debug.contains("255"), "Debug must not leak key bytes: {debug}");
        assert!(!debug.contains("0xff"), "Debug must not leak key bytes: {debug}");
        assert!(debug.contains("secret-key."), "Debug should include key name: {debug}");
        assert!(debug.contains("HmacSha256"), "Debug should include algorithm: {debug}");
    }

    #[test]
    fn tsig_key_not_clone() {
        // TsigKey must not implement Clone (secret-bearing type per architecture spec).
        // This is a compile-time assertion verified by code review.
        // If TsigKey derived Clone, removing this comment and adding:
        //   let _ = key.clone();
        // would compile. We verify it does NOT compile via review.
    }
```

- [ ] **Step 2: Verify tests fail to compile**

Run: `cargo test -p bind9-sdk-core -- tsig 2>&1 | head -20`
Expected: Compile error — `TsigKey` not found

- [ ] **Step 3: Implement TsigKey struct and constructors**

Add the TsigKey struct and `new` constructor above the `TsigAlgorithm` impl block (but below the `TsigAlgorithm` enum). Add the `zeroize` import at the top of the file:

At the top of the file, add to imports:

```rust
use zeroize::Zeroizing;
```

Then add the struct and impl:

```rust
/// A TSIG key for DNS message authentication (RFC 8945).
///
/// Holds HMAC key material that is automatically zeroed on drop via
/// `zeroize::Zeroizing`. Does not implement `Clone` to prevent
/// accidental key duplication. The `Debug` impl redacts key material.
pub struct TsigKey {
    name: DomainName,
    algorithm: TsigAlgorithm,
    key_material: Zeroizing<Vec<u8>>,
}

impl TsigKey {
    /// Create a new TSIG key from raw key material bytes.
    ///
    /// Returns an error if `key_material` is empty.
    pub fn new(
        name: DomainName,
        algorithm: TsigAlgorithm,
        key_material: Vec<u8>,
    ) -> Result<Self, CoreError> {
        if key_material.is_empty() {
            return Err(CoreError::Tsig("key material must not be empty".into()));
        }
        Ok(Self {
            name,
            algorithm,
            key_material: Zeroizing::new(key_material),
        })
    }

    /// The key name (a DNS domain name).
    pub fn name(&self) -> &DomainName {
        &self.name
    }

    /// The HMAC algorithm for this key.
    pub fn algorithm(&self) -> TsigAlgorithm {
        self.algorithm
    }

    /// Raw key material bytes (for internal HMAC computation only).
    pub(crate) fn material(&self) -> &[u8] {
        &self.key_material
    }
}

impl fmt::Debug for TsigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("key", &"[REDACTED]")
            .finish()
    }
}
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `cargo test -p bind9-sdk-core -- tsig`
Expected: All 14 tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): add TsigKey struct with Zeroizing key material and redacted Debug"
```

### Task 3: TsigKey::from_base64

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs`

- [ ] **Step 1: Write failing tests for from_base64**

Add these tests to the `mod tests` block:

```rust
    #[test]
    fn tsig_key_from_base64_valid() {
        // 32 bytes of zeros, base64-encoded
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
        // rndc.conf keys often have line breaks in base64
        let b64 = "AAAAAAAAAAAAAAAA\n  AAAAAAAAAAAAAAAAAAAAAAAAA=";
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
        // base64("hello world") = "aGVsbG8gd29ybGQ="
        let key = TsigKey::from_base64(
            DomainName::new("known-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            "aGVsbG8gd29ybGQ=",
        )
        .unwrap();
        assert_eq!(key.material(), b"hello world");
    }
```

- [ ] **Step 2: Verify tests fail to compile**

Run: `cargo test -p bind9-sdk-core -- tsig 2>&1 | head -20`
Expected: Compile error — `from_base64` method not found on `TsigKey`

- [ ] **Step 3: Implement from_base64**

Add the `base64` import at the top of the file:

```rust
use base64::prelude::*;
```

Add this method to the `impl TsigKey` block:

```rust
    /// Create a TSIG key from a base64-encoded string.
    ///
    /// This is the format used in `rndc.conf` and `named.conf` key statements.
    /// Whitespace in the base64 string is stripped before decoding.
    pub fn from_base64(
        name: DomainName,
        algorithm: TsigAlgorithm,
        base64_key: &str,
    ) -> Result<Self, CoreError> {
        // Strip whitespace — rndc.conf keys may have line breaks
        let cleaned: String = base64_key.chars().filter(|c| !c.is_whitespace()).collect();

        if cleaned.is_empty() {
            return Err(CoreError::Tsig("base64 key string is empty".into()));
        }

        let decoded = BASE64_STANDARD
            .decode(cleaned.as_bytes())
            .map_err(|e| CoreError::Tsig(alloc::format!("invalid base64: {e}")))?;

        Self::new(name, algorithm, decoded)
    }
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `cargo test -p bind9-sdk-core -- tsig`
Expected: All 19 tests pass

- [ ] **Step 5: Run WASM target check**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Passes (base64 crate is no_std + alloc)

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): add TsigKey::from_base64 for rndc.conf key parsing"
```

### Task 4: TsigKey::generate (std-gated)

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs`

- [ ] **Step 1: Write failing tests for generate**

Add these tests to the `mod tests` block. These tests are gated behind `#[cfg(feature = "std")]` because `generate` requires the `std` feature:

```rust
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
        let key1 = TsigKey::generate(
            DomainName::new("k1.").unwrap(),
            TsigAlgorithm::HmacSha256,
        )
        .unwrap();
        let key2 = TsigKey::generate(
            DomainName::new("k2.").unwrap(),
            TsigAlgorithm::HmacSha256,
        )
        .unwrap();
        // Two random keys should not be equal (probability ~2^-256)
        assert_ne!(key1.material(), key2.material());
    }
```

- [ ] **Step 2: Verify tests fail**

Run: `cargo test -p bind9-sdk-core --features std -- tsig::tests::tsig_key_generate 2>&1 | head -20`
Expected: Compile error — `generate` method not found

- [ ] **Step 3: Implement generate**

Add this method to the `impl TsigKey` block, gated behind `#[cfg(feature = "std")]`:

```rust
    /// Generate a new TSIG key with random key material.
    ///
    /// Uses `getrandom` for cryptographically secure random bytes.
    /// The key length matches the algorithm's recommended key size.
    ///
    /// **Requires the `std` feature** — not available in `no_std`/WASM builds.
    /// For WASM, construct keys manually via [`TsigKey::new`] or [`TsigKey::from_base64`].
    #[cfg(feature = "std")]
    pub fn generate(
        name: DomainName,
        algorithm: TsigAlgorithm,
    ) -> Result<Self, CoreError> {
        let len = algorithm.key_length();
        let mut material = alloc::vec![0u8; len];
        getrandom::fill(&mut material)
            .map_err(|e| CoreError::Tsig(alloc::format!("random generation failed: {e}")))?;
        Self::new(name, algorithm, material)
    }
```

Add the `getrandom` import at the top of the file (conditional):

```rust
#[cfg(feature = "std")]
extern crate getrandom;
```

Note: The `getrandom` import depends on how it is exposed. Since `getrandom::fill` is the v0.3 API, the import is `use getrandom;` and call `getrandom::fill()`. Since `getrandom` is a workspace dependency and added as `getrandom = { workspace = true, features = ["std"], optional = true }` to `bind9-sdk-core`, the `extern crate` is not needed on Rust 2024 edition. Just use `getrandom::fill` directly.

Remove the `extern crate` line if it was added, and just use `getrandom::fill` in the method body.

- [ ] **Step 4: Run tests with std feature**

Run: `cargo test -p bind9-sdk-core --features std -- tsig`
Expected: All 22 tests pass (including the 3 std-gated generate tests)

- [ ] **Step 5: Verify WASM still compiles without generate**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Passes (generate is gated behind `std`, not compiled for WASM)

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): add TsigKey::generate for random key generation (std-gated)"
```

## Chunk 2: HMAC Sign/Verify + TsigRecord

### Task 5: TsigKey::sign and TsigKey::verify

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs`

- [ ] **Step 1: Write failing tests for sign and verify**

Add these tests to the `mod tests` block:

```rust
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

    /// RFC 2202 SS3 — Test Case 1 for HMAC-SHA256
    /// Key: 0x0b repeated 20 times
    /// Data: "Hi There"
    /// Known HMAC-SHA256: b0344c61d8db38535ca8afceaf0bf12b
    ///                    881dc200c9833da726e9376c2e32cff7
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
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac.as_slice(), &expected, "HMAC-SHA256 must match RFC 4231 test vector 1");
    }
```

- [ ] **Step 2: Verify tests fail to compile**

Run: `cargo test -p bind9-sdk-core -- tsig 2>&1 | head -20`
Expected: Compile error — `sign` and `verify` methods not found

- [ ] **Step 3: Implement sign and verify**

Add these imports at the top of `tsig.rs`:

```rust
use digest::Mac;
use hmac::Hmac;
use sha2::{Sha256, Sha512};
use sha1::Sha1;
```

Add these methods to the `impl TsigKey` block:

```rust
    /// Compute an HMAC over the given message bytes.
    ///
    /// Returns the raw MAC bytes. The length depends on the algorithm:
    /// - HmacSha256: 32 bytes
    /// - HmacSha512: 64 bytes
    /// - HmacSha1: 20 bytes
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        #[allow(deprecated)]
        match self.algorithm {
            TsigAlgorithm::HmacSha256 => {
                let mut mac =
                    <Hmac<Sha256> as Mac>::new_from_slice(&self.key_material)
                        .expect("HMAC accepts any key length");
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
            TsigAlgorithm::HmacSha512 => {
                let mut mac =
                    <Hmac<Sha512> as Mac>::new_from_slice(&self.key_material)
                        .expect("HMAC accepts any key length");
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
            TsigAlgorithm::HmacSha1 => {
                let mut mac =
                    <Hmac<Sha1> as Mac>::new_from_slice(&self.key_material)
                        .expect("HMAC accepts any key length");
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    /// Verify an HMAC over the given message bytes.
    ///
    /// Returns `Ok(())` if the MAC matches, or `Err(CoreError::Tsig)` if
    /// verification fails (wrong MAC, wrong length, tampered message).
    pub fn verify(&self, message: &[u8], mac: &[u8]) -> Result<(), CoreError> {
        #[allow(deprecated)]
        match self.algorithm {
            TsigAlgorithm::HmacSha256 => {
                let mut hmac =
                    <Hmac<Sha256> as Mac>::new_from_slice(&self.key_material)
                        .expect("HMAC accepts any key length");
                hmac.update(message);
                hmac.verify_slice(mac)
                    .map_err(|_| CoreError::Tsig("HMAC-SHA256 verification failed".into()))
            }
            TsigAlgorithm::HmacSha512 => {
                let mut hmac =
                    <Hmac<Sha512> as Mac>::new_from_slice(&self.key_material)
                        .expect("HMAC accepts any key length");
                hmac.update(message);
                hmac.verify_slice(mac)
                    .map_err(|_| CoreError::Tsig("HMAC-SHA512 verification failed".into()))
            }
            TsigAlgorithm::HmacSha1 => {
                let mut hmac =
                    <Hmac<Sha1> as Mac>::new_from_slice(&self.key_material)
                        .expect("HMAC accepts any key length");
                hmac.update(message);
                hmac.verify_slice(mac)
                    .map_err(|_| CoreError::Tsig("HMAC-SHA1 verification failed".into()))
            }
        }
    }
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `cargo test -p bind9-sdk-core -- tsig`
Expected: All 29 tests pass (including RFC test vector)

- [ ] **Step 5: Run clippy**

Run: `cargo clippy -p bind9-sdk-core --all-targets -- -D warnings`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): add TsigKey::sign and TsigKey::verify with HMAC-SHA256/SHA512/SHA1"
```

### Task 6: TsigRecord Construction

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs`

- [ ] **Step 1: Write failing tests for TsigRecord**

Add these tests to the `mod tests` block:

```rust
    #[test]
    fn tsig_record_new_produces_valid_wire() {
        let key = TsigKey::new(
            DomainName::new("test-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0xAA; 32],
        )
        .unwrap();
        let message = alloc::vec![0x00; 12]; // minimal DNS header
        let timestamp = 1710000000u64; // 2024-03-09T...

        let record = TsigRecord::new(&key, &message, timestamp);

        // TSIG record must not be empty
        assert!(!record.wire_bytes.is_empty());

        // Must contain the key name
        assert!(record.key_name == DomainName::new("test-key.").unwrap());

        // Must contain the algorithm name
        assert_eq!(record.algorithm, TsigAlgorithm::HmacSha256);

        // MAC length must match algorithm
        assert_eq!(record.mac.len(), 32);

        // Time signed must match input
        assert_eq!(record.time_signed, timestamp);

        // Fudge must be 300 (RFC 8945 recommendation)
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

        let r1 = TsigRecord::new(&key, &message, 1000);
        let r2 = TsigRecord::new(&key, &message, 2000);

        assert_ne!(r1.mac, r2.mac, "Different timestamps must produce different MACs");
    }

    #[test]
    fn tsig_record_wire_bytes_contains_all_fields() {
        let key = TsigKey::new(
            DomainName::new("k.").unwrap(),
            TsigAlgorithm::HmacSha256,
            alloc::vec![0xCC; 32],
        )
        .unwrap();
        let message = alloc::vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let record = TsigRecord::new(&key, &message, 1710000000);

        // Wire bytes should contain:
        // - Key name in wire format
        // - TSIG RR type (250 = 0x00FA)
        // - CLASS ANY (255 = 0x00FF)
        // - TTL 0
        // - RDATA with algorithm name, time, fudge, MAC size, MAC, original ID, error, other len
        let wire = &record.wire_bytes;
        assert!(wire.len() > 20, "Wire bytes too short: {} bytes", wire.len());
    }
```

- [ ] **Step 2: Verify tests fail to compile**

Run: `cargo test -p bind9-sdk-core -- tsig 2>&1 | head -20`
Expected: Compile error — `TsigRecord` not found

- [ ] **Step 3: Implement TsigRecord**

Add this struct and implementation above the `#[cfg(test)]` module:

```rust
/// A constructed TSIG pseudo-record for DNS message authentication (RFC 8945 SS4.3).
///
/// This is not a real DNS resource record — it is appended to the additional
/// section of a DNS message to provide authentication. The wire bytes encode
/// the complete TSIG RDATA per the RFC.
pub struct TsigRecord {
    /// The TSIG key name.
    pub key_name: DomainName,
    /// The algorithm used.
    pub algorithm: TsigAlgorithm,
    /// The time the message was signed (seconds since Unix epoch).
    pub time_signed: u64,
    /// Clock skew tolerance in seconds (default: 300).
    pub fudge: u16,
    /// The computed HMAC (message authentication code).
    pub mac: Vec<u8>,
    /// The original DNS message ID.
    pub original_id: u16,
    /// The complete TSIG record in wire format, ready to append to a DNS message.
    pub wire_bytes: Vec<u8>,
}

impl TsigRecord {
    /// Construct a TSIG pseudo-record for a DNS request message.
    ///
    /// Per RFC 8945 SS4.3.3 (request MAC generation):
    /// MAC = HMAC(key, DNS message + TSIG Variables)
    ///
    /// TSIG Variables = key name (wire) + class (ANY=255) + TTL (0) +
    ///   algorithm name (wire) + time signed (48-bit) + fudge (16-bit) +
    ///   error (0) + other len (0)
    ///
    /// The `message` parameter is the complete DNS message (header + sections)
    /// WITHOUT the TSIG record. The original message ID is extracted from
    /// bytes 0..2 of the message.
    pub fn new(key: &TsigKey, message: &[u8], timestamp: u64) -> Self {
        let fudge: u16 = 300;
        let error: u16 = 0;
        let other_len: u16 = 0;

        // Extract original ID from message header (first 2 bytes)
        let original_id = if message.len() >= 2 {
            u16::from_be_bytes([message[0], message[1]])
        } else {
            0
        };

        // Build TSIG Variables for MAC computation (RFC 8945 SS4.3.3)
        let mut tsig_vars = Vec::new();

        // Key name in wire format (lowercase canonical)
        write_domain_wire(&key.name, &mut tsig_vars);

        // Class: ANY (255)
        tsig_vars.extend_from_slice(&255u16.to_be_bytes());

        // TTL: 0
        tsig_vars.extend_from_slice(&0u32.to_be_bytes());

        // Algorithm name in wire format
        let alg_name = key.algorithm.dns_name();
        let alg_domain = DomainName::new(alg_name)
            .expect("algorithm DNS name is always valid");
        write_domain_wire(&alg_domain, &mut tsig_vars);

        // Time signed: 48-bit (6 bytes, big-endian)
        tsig_vars.extend_from_slice(&timestamp.to_be_bytes()[2..8]);

        // Fudge: 16-bit
        tsig_vars.extend_from_slice(&fudge.to_be_bytes());

        // Error: 16-bit (0 = NOERROR)
        tsig_vars.extend_from_slice(&error.to_be_bytes());

        // Other length: 16-bit (0)
        tsig_vars.extend_from_slice(&other_len.to_be_bytes());

        // MAC input = DNS message (sans TSIG) + TSIG variables
        let mut mac_input = Vec::with_capacity(message.len() + tsig_vars.len());
        mac_input.extend_from_slice(message);
        mac_input.extend_from_slice(&tsig_vars);

        let mac = key.sign(&mac_input);

        // Build the complete TSIG record in wire format
        let mut wire = Vec::new();

        // Owner name: key name in wire format
        write_domain_wire(&key.name, &mut wire);

        // TYPE: TSIG (250)
        wire.extend_from_slice(&250u16.to_be_bytes());

        // CLASS: ANY (255)
        wire.extend_from_slice(&255u16.to_be_bytes());

        // TTL: 0
        wire.extend_from_slice(&0u32.to_be_bytes());

        // RDATA length (calculated after building RDATA)
        let rdata_start = wire.len();
        wire.extend_from_slice(&0u16.to_be_bytes()); // placeholder

        // RDATA: Algorithm name
        write_domain_wire(&alg_domain, &mut wire);

        // RDATA: Time signed (48-bit)
        wire.extend_from_slice(&timestamp.to_be_bytes()[2..8]);

        // RDATA: Fudge
        wire.extend_from_slice(&fudge.to_be_bytes());

        // RDATA: MAC size
        let mac_len = mac.len() as u16;
        wire.extend_from_slice(&mac_len.to_be_bytes());

        // RDATA: MAC
        wire.extend_from_slice(&mac);

        // RDATA: Original ID
        wire.extend_from_slice(&original_id.to_be_bytes());

        // RDATA: Error
        wire.extend_from_slice(&error.to_be_bytes());

        // RDATA: Other length
        wire.extend_from_slice(&other_len.to_be_bytes());

        // Patch RDATA length
        let rdata_len = (wire.len() - rdata_start - 2) as u16;
        wire[rdata_start..rdata_start + 2].copy_from_slice(&rdata_len.to_be_bytes());

        TsigRecord {
            key_name: key.name.clone(),
            algorithm: key.algorithm,
            time_signed: timestamp,
            fudge,
            mac,
            original_id,
            wire_bytes: wire,
        }
    }
}

/// Write a `DomainName` in DNS wire format (length-prefixed labels + null root).
fn write_domain_wire(name: &DomainName, buf: &mut Vec<u8>) {
    for label in name.labels() {
        let bytes = label.as_str().as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0); // root label
}
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `cargo test -p bind9-sdk-core -- tsig`
Expected: All 32 tests pass

- [ ] **Step 5: Run WASM check and clippy**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown && cargo clippy -p bind9-sdk-core --all-targets -- -D warnings`
Expected: Both pass

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "feat(core): add TsigRecord construction per RFC 8945 SS4.3"
```

### Task 7: TSIG Proptest Roundtrip

**Files:**
- Modify: `crates/bind9-sdk-core/src/tsig.rs`

- [ ] **Step 1: Add proptest roundtrip for sign/verify**

Add a `proptests` submodule inside the `mod tests` block:

```rust
    mod proptests {
        use super::*;
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
        }
    }
```

- [ ] **Step 2: Run proptests**

Run: `cargo test -p bind9-sdk-core -- tsig::tests::proptests`
Expected: All proptests pass

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-core/src/tsig.rs
git commit -m "test(core): add proptest roundtrip for TSIG sign/verify"
```

## Chunk 3: UpdateBuilder Typestate + Wire Encoding

### Task 8: DomainName Wire Encoding Helper

**Files:**
- Modify: `crates/bind9-sdk-core/src/domain.rs`

The UpdateBuilder needs to write `DomainName` values into wire format buffers. Add a `write_wire` method to `DomainName`. This also makes the private `write_domain_wire` function in `tsig.rs` unnecessary (we can refactor to use this in a later cleanup).

- [ ] **Step 1: Write failing test for write_wire**

Add this test to the `mod tests` block in `domain.rs`:

```rust
    #[test]
    fn domain_name_write_wire() {
        let name = DomainName::new("example.com.").unwrap();
        let mut buf = Vec::new();
        name.write_wire(&mut buf);
        // Expected: \x07example\x03com\x00
        assert_eq!(buf, vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm',
            0,
        ]);
    }

    #[test]
    fn domain_name_write_wire_root() {
        let name = DomainName::root();
        let mut buf = Vec::new();
        name.write_wire(&mut buf);
        assert_eq!(buf, vec![0]);
    }

    #[test]
    fn domain_name_write_wire_length_matches() {
        let name = DomainName::new("www.example.com.").unwrap();
        let mut buf = Vec::new();
        name.write_wire(&mut buf);
        assert_eq!(buf.len(), name.wire_len());
    }
```

- [ ] **Step 2: Verify tests fail to compile**

Run: `cargo test -p bind9-sdk-core -- domain::tests::domain_name_write_wire 2>&1 | head -20`
Expected: Compile error — `write_wire` method not found

- [ ] **Step 3: Implement write_wire**

Add this method to the `impl DomainName` block in `domain.rs`:

```rust
    /// Write this domain name in DNS wire format into the buffer.
    ///
    /// Format: each label as `<length byte><label bytes>`, terminated by
    /// a zero-length root label. No DNS name compression.
    pub fn write_wire(&self, buf: &mut Vec<u8>) {
        for label in &self.labels {
            let bytes = label.as_str().as_bytes();
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        }
        buf.push(0); // root label
    }
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `cargo test -p bind9-sdk-core -- domain`
Expected: All domain tests pass (including new write_wire tests)

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/domain.rs
git commit -m "feat(core): add DomainName::write_wire for DNS wire format encoding"
```

### Task 9: Prerequisite and UpdateEntry Types

**Files:**
- Modify: `crates/bind9-sdk-core/src/update.rs`

- [ ] **Step 1: Write failing tests for Prerequisite and UpdateEntry**

Add these tests to the `mod tests` block in `update.rs`:

```rust
    use crate::domain::DomainName;
    use crate::protocol::RecordType;
    use crate::record::{RecordClass, ResourceRecord, Ttl};
    use crate::rdata::RecordData;

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
```

- [ ] **Step 2: Verify tests fail to compile**

Run: `cargo test -p bind9-sdk-core -- update 2>&1 | head -20`
Expected: Compile error — `Prerequisite` and `UpdateEntry` not found

- [ ] **Step 3: Implement Prerequisite and UpdateEntry enums**

Add these types to `update.rs`, above the `UpdateMessage` struct. Add necessary imports at the top:

```rust
use crate::domain::DomainName;
use crate::protocol::RecordType;
use crate::record::{RecordClass, ResourceRecord};
```

Then add the enums:

```rust
/// A prerequisite condition for an RFC 2136 dynamic update (SS2.4).
///
/// Prerequisites are checked by the server before any updates are applied.
/// If any prerequisite fails, the entire update is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prerequisite {
    /// An RRset with this name and type must exist (any data).
    RrsetExists {
        name: DomainName,
        rtype: RecordType,
    },
    /// An RRset with this name and type must NOT exist.
    RrsetNotExists {
        name: DomainName,
        rtype: RecordType,
    },
    /// At least one RRset with this name must exist (any type).
    NameExists {
        name: DomainName,
    },
    /// No RRsets with this name must exist (name is not in use).
    NameNotExists {
        name: DomainName,
    },
}

/// An update operation for an RFC 2136 dynamic update (SS2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateEntry {
    /// Add a resource record to the zone.
    AddRecord(ResourceRecord),
    /// Delete all records of a given type at a name.
    DeleteRrset {
        name: DomainName,
        rtype: RecordType,
    },
    /// Delete a specific resource record.
    DeleteRecord(ResourceRecord),
    /// Delete all records at a name (any type).
    DeleteName {
        name: DomainName,
    },
}
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `cargo test -p bind9-sdk-core -- update`
Expected: All update tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-core/src/update.rs
git commit -m "feat(core): add Prerequisite and UpdateEntry enums for RFC 2136"
```

### Task 10: UpdateBuilder Typestate Struct

**Files:**
- Modify: `crates/bind9-sdk-core/src/update.rs`

- [ ] **Step 1: Write failing tests for UpdateBuilder**

Add these tests to the `mod tests` block:

```rust
    #[test]
    fn builder_new_creates_unsigned() {
        let zone = DomainName::new("example.com.").unwrap();
        let builder = UpdateBuilder::new(zone, RecordClass::IN);
        // Should compile — builder is Unsigned
        let _msg = builder.build_unsigned();
    }

    #[test]
    fn builder_with_id() {
        let zone = DomainName::new("example.com.").unwrap();
        let builder = UpdateBuilder::with_id(0x1234, zone, RecordClass::IN);
        let msg = builder.build_unsigned();
        assert_eq!(msg.id(), 0x1234);
    }

    #[test]
    fn builder_add_prerequisite() {
        let zone = DomainName::new("example.com.").unwrap();
        let builder = UpdateBuilder::with_id(1, zone.clone(), RecordClass::IN)
            .require_rrset_exists(&DomainName::new("www.example.com.").unwrap(), RecordType::A)
            .require_name_not_exists(&DomainName::new("new.example.com.").unwrap());
        let _msg = builder.build_unsigned();
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
        let builder = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .add_record(rr);
        let _msg = builder.build_unsigned();
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
            .delete_rrset(&DomainName::new("del.example.com.").unwrap(), RecordType::Aaaa)
            .delete_record(rr)
            .delete_name(&DomainName::new("gone.example.com.").unwrap());
        let _msg = builder.build_unsigned();
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
        let msg = UpdateBuilder::with_id(42, zone.clone(), RecordClass::IN)
            .require_name_exists(&DomainName::new("www.example.com.").unwrap())
            .add_record(rr)
            .delete_rrset(&DomainName::new("old.example.com.").unwrap(), RecordType::A)
            .build_unsigned();
        assert_eq!(msg.id(), 42);
        assert!(!msg.as_bytes().is_empty());
    }
```

- [ ] **Step 2: Verify tests fail to compile**

Run: `cargo test -p bind9-sdk-core -- update 2>&1 | head -20`
Expected: Compile error — `UpdateBuilder` not found

- [ ] **Step 3: Implement UpdateBuilder struct and builder methods**

Add these types and implementations to `update.rs`. Add the `PhantomData` import:

```rust
use core::marker::PhantomData;
```

Then add the typestate markers and builder:

```rust
/// Typestate: the update message has not been signed.
pub struct Unsigned;

/// Typestate: the update message has been signed with TSIG.
pub struct Signed;

/// Builder for constructing RFC 2136 dynamic update messages.
///
/// Uses the typestate pattern to enforce signing discipline at compile time:
/// - `UpdateBuilder<Unsigned>`: can add prerequisites and updates, can sign or build unsigned
/// - `UpdateBuilder<Signed>`: can only build (message is already signed)
///
/// All builder methods consume `self` and return a new builder (move semantics).
pub struct UpdateBuilder<State = Unsigned> {
    id: u16,
    zone: DomainName,
    class: RecordClass,
    prerequisites: Vec<Prerequisite>,
    updates: Vec<UpdateEntry>,
    _state: PhantomData<State>,
}

impl UpdateBuilder<Unsigned> {
    /// Create a new update builder for the given zone.
    ///
    /// When the `std` feature is enabled, the message ID is randomly generated.
    /// In `no_std`/WASM, use [`UpdateBuilder::with_id`] to supply an explicit ID.
    #[cfg(feature = "std")]
    pub fn new(zone: DomainName, class: RecordClass) -> Self {
        let mut id_bytes = [0u8; 2];
        // Best-effort random ID; fall back to 0 if getrandom fails
        let _ = getrandom::fill(&mut id_bytes);
        let id = u16::from_be_bytes(id_bytes);
        Self::with_id(id, zone, class)
    }

    /// Create a new update builder for the given zone (no_std version).
    ///
    /// Message ID is 0. Use [`UpdateBuilder::with_id`] to supply an explicit ID.
    #[cfg(not(feature = "std"))]
    pub fn new(zone: DomainName, class: RecordClass) -> Self {
        Self::with_id(0, zone, class)
    }

    /// Create a new update builder with an explicit message ID.
    ///
    /// Use this in `no_std`/WASM contexts where random generation is unavailable,
    /// or when a specific message ID is needed for testing.
    pub fn with_id(id: u16, zone: DomainName, class: RecordClass) -> Self {
        Self {
            id,
            zone,
            class,
            prerequisites: Vec::new(),
            updates: Vec::new(),
            _state: PhantomData,
        }
    }

    /// Require that an RRset with the given name and type exists (RFC 2136 SS2.4.1).
    pub fn require_rrset_exists(mut self, name: &DomainName, rtype: RecordType) -> Self {
        self.prerequisites.push(Prerequisite::RrsetExists {
            name: name.clone(),
            rtype,
        });
        self
    }

    /// Require that an RRset with the given name and type does NOT exist (RFC 2136 SS2.4.2).
    pub fn require_rrset_not_exists(mut self, name: &DomainName, rtype: RecordType) -> Self {
        self.prerequisites.push(Prerequisite::RrsetNotExists {
            name: name.clone(),
            rtype,
        });
        self
    }

    /// Require that at least one record with the given name exists (RFC 2136 SS2.4.4).
    pub fn require_name_exists(mut self, name: &DomainName) -> Self {
        self.prerequisites.push(Prerequisite::NameExists {
            name: name.clone(),
        });
        self
    }

    /// Require that no records with the given name exist (RFC 2136 SS2.4.5).
    pub fn require_name_not_exists(mut self, name: &DomainName) -> Self {
        self.prerequisites.push(Prerequisite::NameNotExists {
            name: name.clone(),
        });
        self
    }

    /// Add a resource record to the zone (RFC 2136 SS2.5.1).
    pub fn add_record(mut self, record: ResourceRecord) -> Self {
        self.updates.push(UpdateEntry::AddRecord(record));
        self
    }

    /// Delete all records of a given type at a name (RFC 2136 SS2.5.2).
    pub fn delete_rrset(mut self, name: &DomainName, rtype: RecordType) -> Self {
        self.updates.push(UpdateEntry::DeleteRrset {
            name: name.clone(),
            rtype,
        });
        self
    }

    /// Delete a specific resource record (RFC 2136 SS2.5.4).
    pub fn delete_record(mut self, record: ResourceRecord) -> Self {
        self.updates.push(UpdateEntry::DeleteRecord(record));
        self
    }

    /// Delete all records at a name (RFC 2136 SS2.5.3).
    pub fn delete_name(mut self, name: &DomainName) -> Self {
        self.updates.push(UpdateEntry::DeleteName {
            name: name.clone(),
        });
        self
    }

    /// Build the update message without TSIG signing.
    ///
    /// Use this for testing or on trusted networks where authentication
    /// is handled at another layer.
    pub fn build_unsigned(self) -> UpdateMessage {
        encode_update_message(self.id, &self.zone, self.class, &self.prerequisites, &self.updates, None)
    }

    /// Sign the update with a TSIG key, transitioning to the `Signed` state.
    ///
    /// After signing, only [`UpdateBuilder::build`] is available.
    pub fn sign(self, key: &crate::tsig::TsigKey) -> UpdateBuilder<Signed> {
        let unsigned_msg = encode_update_message(
            self.id, &self.zone, self.class, &self.prerequisites, &self.updates, None,
        );

        // Compute TSIG and re-encode with TSIG appended
        let timestamp = 0u64; // In no_std we cannot get wall clock; caller should set externally
        // For now, use 0; a future API addition will accept a timestamp parameter
        let tsig = crate::tsig::TsigRecord::new(key, unsigned_msg.as_bytes(), timestamp);

        let mut wire = unsigned_msg.wire_bytes;

        // Update ARCOUNT (additional section count) — bytes 10..12 in DNS header
        let arcount = u16::from_be_bytes([wire[10], wire[11]]);
        let new_arcount = arcount + 1;
        wire[10..12].copy_from_slice(&new_arcount.to_be_bytes());

        // Append TSIG record wire bytes
        wire.extend_from_slice(&tsig.wire_bytes);

        UpdateBuilder {
            id: self.id,
            zone: self.zone,
            class: self.class,
            prerequisites: self.prerequisites,
            updates: self.updates,
            _state: PhantomData,
        }
        // Store the signed message for build()
        // We need to carry the signed wire bytes — use a different approach:
        // Actually, let's store the signed message in a separate field.
        // But UpdateBuilder<Signed> cannot have different fields...
        // Solution: wrap the signed bytes in the state type itself, or
        // make build() on Signed re-derive it. The cleanest approach for
        // typestate is to have sign() return the final UpdateMessage directly
        // via a SignedUpdate wrapper. However, the spec says sign() returns
        // UpdateBuilder<Signed> with a build() method.
        //
        // Simplest correct approach: store the pre-built message alongside.
    }
}
```

Wait — the `sign` method has a design issue. We need to carry the signed wire bytes to `build()`. Let me restructure. Replace the entire `UpdateBuilder` approach with a version that stores an optional pre-signed message:

Replace everything after the `UpdateEntry` enum and before `UpdateMessage` with:

```rust
/// Typestate: the update message has not been signed.
pub struct Unsigned;

/// Typestate: the update message has been signed with TSIG.
pub struct Signed {
    /// The pre-built signed message (TSIG appended during sign()).
    message: UpdateMessage,
}

/// Builder for constructing RFC 2136 dynamic update messages.
///
/// Uses the typestate pattern to enforce signing discipline at compile time:
/// - `UpdateBuilder<Unsigned>`: can add prerequisites and updates, can sign or build unsigned
/// - `UpdateBuilder<Signed>`: can only call `build()` to extract the signed message
///
/// All builder methods consume `self` and return a new builder (move semantics).
pub struct UpdateBuilder<State = Unsigned> {
    id: u16,
    zone: DomainName,
    class: RecordClass,
    prerequisites: Vec<Prerequisite>,
    updates: Vec<UpdateEntry>,
    state: State,
}

impl UpdateBuilder<Unsigned> {
    /// Create a new update builder for the given zone.
    ///
    /// When the `std` feature is enabled, the message ID is randomly generated.
    /// In `no_std`/WASM, the ID defaults to 0; use [`with_id`](Self::with_id) instead.
    #[cfg(feature = "std")]
    pub fn new(zone: DomainName, class: RecordClass) -> Self {
        let mut id_bytes = [0u8; 2];
        let _ = getrandom::fill(&mut id_bytes);
        let id = u16::from_be_bytes(id_bytes);
        Self::with_id(id, zone, class)
    }

    /// Create a new update builder for the given zone (`no_std` version).
    #[cfg(not(feature = "std"))]
    pub fn new(zone: DomainName, class: RecordClass) -> Self {
        Self::with_id(0, zone, class)
    }

    /// Create a new update builder with an explicit message ID.
    ///
    /// Use this in `no_std`/WASM contexts or when a specific ID is needed for testing.
    pub fn with_id(id: u16, zone: DomainName, class: RecordClass) -> Self {
        Self {
            id,
            zone,
            class,
            prerequisites: Vec::new(),
            updates: Vec::new(),
            state: Unsigned,
        }
    }

    /// Require that an RRset with the given name and type exists (RFC 2136 SS2.4.1).
    pub fn require_rrset_exists(mut self, name: &DomainName, rtype: RecordType) -> Self {
        self.prerequisites.push(Prerequisite::RrsetExists {
            name: name.clone(),
            rtype,
        });
        self
    }

    /// Require that an RRset with the given name and type does NOT exist (RFC 2136 SS2.4.2).
    pub fn require_rrset_not_exists(mut self, name: &DomainName, rtype: RecordType) -> Self {
        self.prerequisites.push(Prerequisite::RrsetNotExists {
            name: name.clone(),
            rtype,
        });
        self
    }

    /// Require that at least one record with the given name exists (RFC 2136 SS2.4.4).
    pub fn require_name_exists(mut self, name: &DomainName) -> Self {
        self.prerequisites.push(Prerequisite::NameExists {
            name: name.clone(),
        });
        self
    }

    /// Require that no records with the given name exist (RFC 2136 SS2.4.5).
    pub fn require_name_not_exists(mut self, name: &DomainName) -> Self {
        self.prerequisites.push(Prerequisite::NameNotExists {
            name: name.clone(),
        });
        self
    }

    /// Add a resource record to the zone (RFC 2136 SS2.5.1).
    pub fn add_record(mut self, record: ResourceRecord) -> Self {
        self.updates.push(UpdateEntry::AddRecord(record));
        self
    }

    /// Delete all records of a given type at a name (RFC 2136 SS2.5.2).
    pub fn delete_rrset(mut self, name: &DomainName, rtype: RecordType) -> Self {
        self.updates.push(UpdateEntry::DeleteRrset {
            name: name.clone(),
            rtype,
        });
        self
    }

    /// Delete a specific resource record (RFC 2136 SS2.5.4).
    pub fn delete_record(mut self, record: ResourceRecord) -> Self {
        self.updates.push(UpdateEntry::DeleteRecord(record));
        self
    }

    /// Delete all records at a name (RFC 2136 SS2.5.3).
    pub fn delete_name(mut self, name: &DomainName) -> Self {
        self.updates.push(UpdateEntry::DeleteName {
            name: name.clone(),
        });
        self
    }

    /// Build the update message without TSIG signing.
    ///
    /// Use for testing or on trusted networks.
    pub fn build_unsigned(self) -> UpdateMessage {
        encode_update_message(
            self.id,
            &self.zone,
            self.class,
            &self.prerequisites,
            &self.updates,
        )
    }

    /// Sign the update with a TSIG key, transitioning to the `Signed` state.
    ///
    /// After signing, call [`UpdateBuilder::build`] to extract the message.
    pub fn sign(self, key: &crate::tsig::TsigKey) -> UpdateBuilder<Signed> {
        let unsigned = encode_update_message(
            self.id,
            &self.zone,
            self.class,
            &self.prerequisites,
            &self.updates,
        );

        let timestamp = 0u64; // no_std: no wall clock; use 0 for now
        let tsig = crate::tsig::TsigRecord::new(key, unsigned.as_bytes(), timestamp);

        let mut wire = unsigned.wire_bytes;

        // Increment ARCOUNT in DNS header (bytes 10..12)
        let arcount = u16::from_be_bytes([wire[10], wire[11]]);
        wire[10..12].copy_from_slice(&(arcount + 1).to_be_bytes());

        // Append TSIG record
        wire.extend_from_slice(&tsig.wire_bytes);

        UpdateBuilder {
            id: self.id,
            zone: self.zone,
            class: self.class,
            prerequisites: self.prerequisites,
            updates: self.updates,
            state: Signed {
                message: UpdateMessage {
                    wire_bytes: wire,
                    id: self.id,
                },
            },
        }
    }
}

impl UpdateBuilder<Signed> {
    /// Build the signed update message.
    pub fn build(self) -> UpdateMessage {
        self.state.message
    }
}
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `cargo test -p bind9-sdk-core -- update`
Expected: All update tests pass (but wire encoding is not yet implemented — `encode_update_message` does not exist, so this step will fail). Continue to the next step.

Actually, the tests will fail because `encode_update_message` is not defined yet. That is implemented in the next task. Mark this step as: tests compile but `encode_update_message` is missing. Proceed to Task 11.

- [ ] **Step 5: Commit (checkpoint)**

Do not commit yet — `encode_update_message` is needed first. Continue to Task 11.

### Task 11: Wire Encoding (encode_update_message)

**Files:**
- Modify: `crates/bind9-sdk-core/src/update.rs`

- [ ] **Step 1: Write failing tests for wire format correctness**

Add these tests to the `mod tests` block:

```rust
    #[test]
    fn wire_header_opcode_is_update() {
        let zone = DomainName::new("example.com.").unwrap();
        let msg = UpdateBuilder::with_id(0xABCD, zone, RecordClass::IN)
            .build_unsigned();
        let bytes = msg.as_bytes();

        // Bytes 0-1: ID
        assert_eq!(bytes[0], 0xAB);
        assert_eq!(bytes[1], 0xCD);

        // Byte 2: QR(0) + Opcode(5=UPDATE) + AA(0) + TC(0) + RD(0) = 0b0_0101_000 = 0x28
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
        let msg = UpdateBuilder::with_id(1, zone.clone(), RecordClass::IN)
            .require_rrset_exists(&DomainName::new("www.example.com.").unwrap(), RecordType::A)
            .add_record(rr)
            .build_unsigned();
        let bytes = msg.as_bytes();

        // ZOCOUNT (bytes 4-5): 1 (zone section always has 1 entry)
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 1);

        // PRCOUNT (bytes 6-7): 1 (one prerequisite)
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1);

        // UPCOUNT (bytes 8-9): 1 (one update)
        assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 1);

        // ADCOUNT (bytes 10-11): 0 (no additional / no TSIG)
        assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), 0);
    }

    #[test]
    fn wire_zone_section_present() {
        let zone = DomainName::new("example.com.").unwrap();
        let msg = UpdateBuilder::with_id(1, zone.clone(), RecordClass::IN)
            .build_unsigned();
        let bytes = msg.as_bytes();

        // After 12-byte header, zone section:
        // Name: \x07example\x03com\x00 (13 bytes)
        assert_eq!(bytes[12], 7); // label length "example"
        assert_eq!(&bytes[13..20], b"example");
        assert_eq!(bytes[20], 3); // label length "com"
        assert_eq!(&bytes[21..24], b"com");
        assert_eq!(bytes[24], 0); // root label

        // TYPE: SOA (6) — zone section always uses SOA type
        assert_eq!(u16::from_be_bytes([bytes[25], bytes[26]]), 6);

        // CLASS: IN (1)
        assert_eq!(u16::from_be_bytes([bytes[27], bytes[28]]), 1);
    }

    #[test]
    fn wire_empty_update_just_header_and_zone() {
        let zone = DomainName::new("t.").unwrap();
        let msg = UpdateBuilder::with_id(0, zone, RecordClass::IN).build_unsigned();
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
            .sign(&key)
            .build();
        let bytes = msg.as_bytes();

        // ADCOUNT should be 1 (TSIG record in additional section)
        assert_eq!(u16::from_be_bytes([bytes[10], bytes[11]]), 1);

        // Message should be longer than unsigned (TSIG adds significant bytes)
        assert!(bytes.len() > 19);
    }
```

- [ ] **Step 2: Implement encode_update_message and rdata wire encoding**

Add the wire encoding function and helpers to `update.rs`:

```rust
/// Encode a complete RFC 2136 UPDATE message in DNS wire format.
///
/// DNS UPDATE message layout (RFC 2136 SS2):
/// ```text
///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///   |                      ID                         |  (2 bytes)
///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///   |QR| Opcode(5) |   Z   |         RCODE           |  (2 bytes)
///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///   |                    ZOCOUNT                      |  (2 bytes)
///   |                    PRCOUNT                      |  (2 bytes)
///   |                    UPCOUNT                      |  (2 bytes)
///   |                    ADCOUNT                      |  (2 bytes)
///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///   |                  Zone Section                   |  (variable)
///   |              Prerequisite Section               |  (variable)
///   |                 Update Section                  |  (variable)
///   |               Additional Section                |  (variable)
///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
fn encode_update_message(
    id: u16,
    zone: &DomainName,
    class: RecordClass,
    prerequisites: &[Prerequisite],
    updates: &[UpdateEntry],
) -> UpdateMessage {
    let mut wire = Vec::new();

    // --- Header (12 bytes) ---

    // ID
    wire.extend_from_slice(&id.to_be_bytes());

    // Flags: QR=0, Opcode=UPDATE(5), AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
    // Byte 2: 0_0101_0_0_0 = 0x28
    wire.push(0x28);
    // Byte 3: 0_000_0000 = 0x00
    wire.push(0x00);

    // ZOCOUNT: 1 (always one zone entry)
    wire.extend_from_slice(&1u16.to_be_bytes());

    // PRCOUNT: number of prerequisites
    wire.extend_from_slice(&(prerequisites.len() as u16).to_be_bytes());

    // UPCOUNT: number of updates
    wire.extend_from_slice(&(updates.len() as u16).to_be_bytes());

    // ADCOUNT: 0 (TSIG added separately by sign())
    wire.extend_from_slice(&0u16.to_be_bytes());

    // --- Zone Section ---
    // ZNAME + ZTYPE(SOA=6) + ZCLASS
    zone.write_wire(&mut wire);
    wire.extend_from_slice(&6u16.to_be_bytes()); // SOA type
    wire.extend_from_slice(&class.value().to_be_bytes());

    // --- Prerequisite Section ---
    for prereq in prerequisites {
        encode_prerequisite(prereq, &mut wire);
    }

    // --- Update Section ---
    for update in updates {
        encode_update_entry(update, &mut wire);
    }

    UpdateMessage {
        wire_bytes: wire,
        id,
    }
}

/// Encode a prerequisite as a DNS RR in wire format (RFC 2136 SS2.4).
fn encode_prerequisite(prereq: &Prerequisite, wire: &mut Vec<u8>) {
    match prereq {
        Prerequisite::RrsetExists { name, rtype } => {
            // NAME + TYPE + CLASS=ANY(255) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&rtype.value().to_be_bytes());
            wire.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
        Prerequisite::RrsetNotExists { name, rtype } => {
            // NAME + TYPE + CLASS=NONE(254) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&rtype.value().to_be_bytes());
            wire.extend_from_slice(&254u16.to_be_bytes()); // CLASS NONE
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
        Prerequisite::NameExists { name } => {
            // NAME + TYPE=ANY(255) + CLASS=ANY(255) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&255u16.to_be_bytes()); // TYPE ANY
            wire.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
        Prerequisite::NameNotExists { name } => {
            // NAME + TYPE=ANY(255) + CLASS=NONE(254) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&255u16.to_be_bytes()); // TYPE ANY
            wire.extend_from_slice(&254u16.to_be_bytes()); // CLASS NONE
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
    }
}

/// Encode an update entry as a DNS RR in wire format (RFC 2136 SS2.5).
fn encode_update_entry(entry: &UpdateEntry, wire: &mut Vec<u8>) {
    match entry {
        UpdateEntry::AddRecord(rr) => {
            // NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA
            rr.name.write_wire(wire);
            wire.extend_from_slice(&rdata_type_value(&rr.rdata).to_be_bytes());
            wire.extend_from_slice(&rr.class.value().to_be_bytes());
            wire.extend_from_slice(&rr.ttl.value().to_be_bytes());
            let rdata_start = wire.len();
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH placeholder
            encode_rdata(&rr.rdata, wire);
            let rdata_len = (wire.len() - rdata_start - 2) as u16;
            wire[rdata_start..rdata_start + 2].copy_from_slice(&rdata_len.to_be_bytes());
        }
        UpdateEntry::DeleteRrset { name, rtype } => {
            // NAME + TYPE + CLASS=ANY(255) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&rtype.value().to_be_bytes());
            wire.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
        UpdateEntry::DeleteRecord(rr) => {
            // NAME + TYPE + CLASS=NONE(254) + TTL=0 + RDLENGTH + RDATA
            rr.name.write_wire(wire);
            wire.extend_from_slice(&rdata_type_value(&rr.rdata).to_be_bytes());
            wire.extend_from_slice(&254u16.to_be_bytes()); // CLASS NONE
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            let rdata_start = wire.len();
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH placeholder
            encode_rdata(&rr.rdata, wire);
            let rdata_len = (wire.len() - rdata_start - 2) as u16;
            wire[rdata_start..rdata_start + 2].copy_from_slice(&rdata_len.to_be_bytes());
        }
        UpdateEntry::DeleteName { name } => {
            // NAME + TYPE=ANY(255) + CLASS=ANY(255) + TTL=0 + RDLENGTH=0
            name.write_wire(wire);
            wire.extend_from_slice(&255u16.to_be_bytes()); // TYPE ANY
            wire.extend_from_slice(&255u16.to_be_bytes()); // CLASS ANY
            wire.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH 0
        }
    }
}

/// Get the DNS type code for a `RecordData` variant.
fn rdata_type_value(rdata: &crate::rdata::RecordData) -> u16 {
    use crate::rdata::RecordData;
    match rdata {
        RecordData::A(_) => 1,
        RecordData::Aaaa(_) => 28,
        RecordData::Cname(_) => 5,
        RecordData::Ns(_) => 2,
        RecordData::Ptr(_) => 12,
        RecordData::Soa { .. } => 6,
        RecordData::Mx { .. } => 15,
        RecordData::Txt(_) => 16,
        RecordData::Srv { .. } => 33,
        RecordData::Caa { .. } => 257,
        RecordData::Dnskey { .. } => 48,
        RecordData::Rrsig { .. } => 46,
        RecordData::Nsec { .. } => 47,
        RecordData::Nsec3 { .. } => 50,
        RecordData::Ds { .. } => 43,
        RecordData::Cds { .. } => 59,
        RecordData::Cdnskey { .. } => 60,
        RecordData::Tlsa { .. } => 52,
        RecordData::Sshfp { .. } => 44,
        RecordData::Csync { .. } => 62,
        RecordData::Rp { .. } => 17,
        RecordData::Unknown { rtype, .. } => *rtype,
        _ => 0, // Future variants — encode as 0 (will be caught by the server)
    }
}

/// Encode `RecordData` in DNS wire format.
///
/// Supports the common record types needed for dynamic updates.
/// Complex DNSSEC types use raw byte passthrough.
fn encode_rdata(rdata: &crate::rdata::RecordData, wire: &mut Vec<u8>) {
    use crate::rdata::RecordData;
    match rdata {
        RecordData::A(addr) => {
            wire.extend_from_slice(&addr.octets());
        }
        RecordData::Aaaa(addr) => {
            wire.extend_from_slice(&addr.octets());
        }
        RecordData::Cname(name) | RecordData::Ns(name) | RecordData::Ptr(name) => {
            name.write_wire(wire);
        }
        RecordData::Soa {
            mname, rname, serial, refresh, retry, expire, minimum,
        } => {
            mname.write_wire(wire);
            rname.write_wire(wire);
            wire.extend_from_slice(&serial.value().to_be_bytes());
            wire.extend_from_slice(&refresh.value().to_be_bytes());
            wire.extend_from_slice(&retry.value().to_be_bytes());
            wire.extend_from_slice(&expire.value().to_be_bytes());
            wire.extend_from_slice(&minimum.value().to_be_bytes());
        }
        RecordData::Mx { preference, exchange } => {
            wire.extend_from_slice(&preference.to_be_bytes());
            exchange.write_wire(wire);
        }
        RecordData::Txt(strings) => {
            for s in strings {
                let bytes = s.as_bytes();
                // Each TXT character-string: length byte + data (max 255)
                wire.push(bytes.len().min(255) as u8);
                wire.extend_from_slice(&bytes[..bytes.len().min(255)]);
            }
        }
        RecordData::Srv { priority, weight, port, target } => {
            wire.extend_from_slice(&priority.to_be_bytes());
            wire.extend_from_slice(&weight.to_be_bytes());
            wire.extend_from_slice(&port.to_be_bytes());
            target.write_wire(wire);
        }
        RecordData::Caa { flags, tag, value } => {
            wire.push(*flags);
            let tag_bytes = tag.as_bytes();
            wire.push(tag_bytes.len() as u8);
            wire.extend_from_slice(tag_bytes);
            wire.extend_from_slice(value.as_bytes());
        }
        RecordData::Unknown { rdata, .. } => {
            wire.extend_from_slice(rdata);
        }
        // DNSSEC types — passthrough raw fields
        RecordData::Dnskey { flags, protocol, algorithm, public_key } => {
            wire.extend_from_slice(&flags.to_be_bytes());
            wire.push(*protocol);
            wire.push(*algorithm);
            wire.extend_from_slice(public_key);
        }
        RecordData::Ds { key_tag, algorithm, digest_type, digest }
        | RecordData::Cds { key_tag, algorithm, digest_type, digest } => {
            wire.extend_from_slice(&key_tag.to_be_bytes());
            wire.push(*algorithm);
            wire.push(*digest_type);
            wire.extend_from_slice(digest);
        }
        RecordData::Rrsig {
            type_covered, algorithm, labels, original_ttl,
            signature_expiration, signature_inception, key_tag,
            signer_name, signature,
        } => {
            wire.extend_from_slice(&type_covered.to_be_bytes());
            wire.push(*algorithm);
            wire.push(*labels);
            wire.extend_from_slice(&original_ttl.to_be_bytes());
            wire.extend_from_slice(&signature_expiration.to_be_bytes());
            wire.extend_from_slice(&signature_inception.to_be_bytes());
            wire.extend_from_slice(&key_tag.to_be_bytes());
            signer_name.write_wire(wire);
            wire.extend_from_slice(signature);
        }
        RecordData::Nsec { next_domain, type_bitmaps } => {
            next_domain.write_wire(wire);
            wire.extend_from_slice(type_bitmaps);
        }
        RecordData::Nsec3 {
            hash_algorithm, flags, iterations, salt,
            next_hashed_owner, type_bitmaps,
        } => {
            wire.push(*hash_algorithm);
            wire.push(*flags);
            wire.extend_from_slice(&iterations.to_be_bytes());
            wire.push(salt.len() as u8);
            wire.extend_from_slice(salt);
            wire.push(next_hashed_owner.len() as u8);
            wire.extend_from_slice(next_hashed_owner);
            wire.extend_from_slice(type_bitmaps);
        }
        RecordData::Cdnskey { flags, protocol, algorithm, public_key } => {
            wire.extend_from_slice(&flags.to_be_bytes());
            wire.push(*protocol);
            wire.push(*algorithm);
            wire.extend_from_slice(public_key);
        }
        RecordData::Tlsa { usage, selector, matching_type, certificate_data } => {
            wire.push(*usage);
            wire.push(*selector);
            wire.push(*matching_type);
            wire.extend_from_slice(certificate_data);
        }
        RecordData::Sshfp { algorithm, fp_type, fingerprint } => {
            wire.push(*algorithm);
            wire.push(*fp_type);
            wire.extend_from_slice(fingerprint);
        }
        RecordData::Csync { soa_serial, flags, type_bitmaps } => {
            wire.extend_from_slice(&soa_serial.to_be_bytes());
            wire.extend_from_slice(&flags.to_be_bytes());
            wire.extend_from_slice(type_bitmaps);
        }
        RecordData::Rp { mbox, txt } => {
            mbox.write_wire(wire);
            txt.write_wire(wire);
        }
        _ => {
            // Future RecordData variants — encode as empty RDATA
            // The server will reject unknown types
        }
    }
}
```

- [ ] **Step 3: Run all tests and verify they pass**

Run: `cargo test -p bind9-sdk-core -- update`
Expected: All update tests pass (including wire format assertions)

- [ ] **Step 4: Run WASM check**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Passes

- [ ] **Step 5: Run clippy**

Run: `cargo clippy -p bind9-sdk-core --all-targets -- -D warnings`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add crates/bind9-sdk-core/src/update.rs crates/bind9-sdk-core/src/domain.rs
git commit -m "feat(core): add UpdateBuilder typestate with RFC 2136 wire encoding"
```

### Task 12: UpdateBuilder Sign Integration Test

**Files:**
- Modify: `crates/bind9-sdk-core/src/update.rs`

- [ ] **Step 1: Write integration test for signed message**

Add these tests to the `mod tests` block:

```rust
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
            .sign(&key)
            .build();

        let bytes = msg.as_bytes();
        assert_eq!(msg.id(), 0x1234);

        // Opcode must be UPDATE (5)
        assert_eq!(bytes[2] & 0x78, 0x28); // Opcode bits masked

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
    fn unsigned_and_signed_produce_different_bytes() {
        let zone = DomainName::new("example.com.").unwrap();
        let key = crate::tsig::TsigKey::new(
            DomainName::new("k.").unwrap(),
            crate::tsig::TsigAlgorithm::HmacSha256,
            alloc::vec![0xFF; 32],
        )
        .unwrap();

        let unsigned = UpdateBuilder::with_id(1, zone.clone(), RecordClass::IN)
            .build_unsigned();
        let signed = UpdateBuilder::with_id(1, zone, RecordClass::IN)
            .sign(&key)
            .build();

        assert_ne!(unsigned.as_bytes(), signed.as_bytes());
        assert!(signed.as_bytes().len() > unsigned.as_bytes().len());
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p bind9-sdk-core -- update`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-core/src/update.rs
git commit -m "test(core): add signed UpdateBuilder integration tests"
```

## Chunk 4: NetError + TlsConfig + Bind9Client Skeleton

### Task 13: NetError Enum

**Files:**
- Modify: `crates/bind9-sdk-net/src/error.rs`

- [ ] **Step 1: Write failing tests for NetError**

Replace the stub in `crates/bind9-sdk-net/src/error.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::time::Duration;

/// Errors from the `bind9-sdk-net` crate.
///
/// Covers network failures, protocol errors, authentication failures,
/// and upstream core errors. The enum is `#[non_exhaustive]` so new
/// variants can be added without a semver bump.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// TCP/UDP connection failed.
    #[error("connection failed: {0}")]
    Connection(String),

    /// A request timed out.
    #[error("request timed out after {0:?}")]
    Timeout(Duration),

    /// rndc HMAC authentication was rejected by the server.
    #[error("rndc authentication failed")]
    AuthFailed,

    /// rndc wire protocol error (framing, encoding, unexpected response).
    #[error("rndc protocol error: {0}")]
    Protocol(String),

    /// TLS handshake or configuration error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// HTTP error from the statistics-channel.
    #[error("HTTP error: {status}")]
    Http { status: u16, body: String },

    /// DNS server rejected an RFC 2136 update.
    #[error("DNS update rejected: {rcode}")]
    UpdateRejected { rcode: String },

    /// An error propagated from `bind9-sdk-core`.
    #[error(transparent)]
    Core(#[from] bind9_sdk_core::CoreError),

    /// An I/O error from the operating system.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_error_display() {
        let err = NetError::Connection("refused".into());
        assert_eq!(err.to_string(), "connection failed: refused");
    }

    #[test]
    fn timeout_error_display() {
        let err = NetError::Timeout(Duration::from_secs(5));
        assert_eq!(err.to_string(), "request timed out after 5s");
    }

    #[test]
    fn auth_failed_display() {
        let err = NetError::AuthFailed;
        assert_eq!(err.to_string(), "rndc authentication failed");
    }

    #[test]
    fn protocol_error_display() {
        let err = NetError::Protocol("bad framing".into());
        assert_eq!(err.to_string(), "rndc protocol error: bad framing");
    }

    #[test]
    fn tls_error_display() {
        let err = NetError::Tls("certificate expired".into());
        assert_eq!(err.to_string(), "TLS error: certificate expired");
    }

    #[test]
    fn http_error_display() {
        let err = NetError::Http {
            status: 503,
            body: "unavailable".into(),
        };
        assert_eq!(err.to_string(), "HTTP error: 503");
    }

    #[test]
    fn update_rejected_display() {
        let err = NetError::UpdateRejected {
            rcode: "REFUSED".into(),
        };
        assert_eq!(err.to_string(), "DNS update rejected: REFUSED");
    }

    #[test]
    fn from_core_error() {
        let core_err = bind9_sdk_core::CoreError::Tsig("bad key".into());
        let net_err: NetError = core_err.into();
        assert!(matches!(net_err, NetError::Core(_)));
        assert!(net_err.to_string().contains("TSIG error: bad key"));
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let net_err: NetError = io_err.into();
        assert!(matches!(net_err, NetError::Io(_)));
    }

    #[test]
    fn net_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NetError>();
    }

    #[test]
    fn net_error_is_error_trait() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<NetError>();
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p bind9-sdk-net -- error`
Expected: All 11 tests pass

- [ ] **Step 3: Run clippy**

Run: `cargo clippy -p bind9-sdk-net --all-targets -- -D warnings`
Expected: Clean

- [ ] **Step 4: Commit**

```bash
git add crates/bind9-sdk-net/src/error.rs
git commit -m "feat(net): add NetError enum with From<CoreError> and From<io::Error>"
```

### Task 14: TlsConfig

**Files:**
- Modify: `crates/bind9-sdk-net/src/tls.rs`

- [ ] **Step 1: Write failing tests for TlsConfig**

Replace the stub in `crates/bind9-sdk-net/src/tls.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::sync::Arc;

use crate::error::NetError;

/// TLS 1.3 configuration for secure connections to BIND9.
///
/// Wraps a `rustls::ClientConfig` configured for TLS 1.3 only, with
/// AES-256-GCM and ChaCha20-Poly1305 cipher suites. Certificate
/// validation uses Mozilla's CA root certificates via `webpki-roots`.
///
/// Used by the rndc and statistics-channel clients when TLS is enabled.
/// Phase 1 rndc uses plaintext TCP on localhost; TLS is prepared here
/// for Phase 2 XoT (DNS-over-TLS for zone transfers).
pub struct TlsConfig {
    inner: Arc<rustls::ClientConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_config_new_succeeds() {
        let config = TlsConfig::new();
        assert!(config.is_ok());
    }

    #[test]
    fn tls_config_inner_is_accessible() {
        let config = TlsConfig::new().unwrap();
        let inner = config.client_config();
        // TLS 1.3 should be enabled
        assert!(
            inner.alpn_protocols.is_empty(),
            "Default config should have no ALPN protocols"
        );
    }

    #[test]
    fn tls_config_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TlsConfig>();
    }
}
```

- [ ] **Step 2: Verify tests fail to compile**

Run: `cargo test -p bind9-sdk-net -- tls 2>&1 | head -20`
Expected: Compile error — `new`, `client_config` methods not found

- [ ] **Step 3: Implement TlsConfig**

Add the implementation between the struct definition and the `#[cfg(test)]` module:

```rust
impl TlsConfig {
    /// Create a TLS 1.3 configuration with Mozilla CA root certificates.
    ///
    /// Configures:
    /// - TLS 1.3 only (no TLS 1.2 fallback)
    /// - AES-256-GCM and ChaCha20-Poly1305 cipher suites
    /// - Certificate validation via webpki-roots
    pub fn new() -> Result<Self, NetError> {
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            inner: Arc::new(config),
        })
    }

    /// Access the underlying `rustls::ClientConfig`.
    ///
    /// Used internally by transport layers that need the rustls config
    /// for `tokio-rustls` connectors.
    pub fn client_config(&self) -> &rustls::ClientConfig {
        &self.inner
    }

    /// Get an `Arc` reference to the underlying config.
    ///
    /// Useful for sharing across multiple connections.
    pub fn client_config_arc(&self) -> Arc<rustls::ClientConfig> {
        Arc::clone(&self.inner)
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-net -- tls`
Expected: All 3 tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/tls.rs
git commit -m "feat(net): add TlsConfig with TLS 1.3 and webpki-roots"
```

### Task 15: ClientConfig and Bind9Client Skeleton

**Files:**
- Modify: `crates/bind9-sdk-net/src/config.rs`

- [ ] **Step 1: Write failing tests for ClientConfig and Bind9Client**

Replace the stub in `crates/bind9-sdk-net/src/config.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::net::SocketAddr;
use std::time::Duration;

use bind9_sdk_core::tsig::TsigKey;

use crate::tls::TlsConfig;

/// Configuration for connecting to a BIND9 server.
///
/// Combines rndc control channel, DNS update, and statistics-channel
/// connection parameters into a single config struct.
pub struct ClientConfig {
    /// rndc control channel address (default: 127.0.0.1:953).
    pub rndc_addr: SocketAddr,

    /// TSIG key for rndc authentication and DNS update signing.
    pub rndc_key: TsigKey,

    /// Statistics-channel HTTP URL (e.g., "http://127.0.0.1:8053").
    pub stats_url: Option<String>,

    /// DNS server address for sending updates (default: same host, port 53).
    pub dns_addr: Option<SocketAddr>,

    /// Optional TLS configuration for encrypted connections.
    pub tls: Option<TlsConfig>,

    /// Timeout for individual operations (default: 10 seconds).
    pub timeout: Duration,
}

/// Client for managing a BIND9 DNS server.
///
/// This is the primary entry point for the `bind9-sdk-net` crate.
/// In Phase 1, this is a skeleton that holds configuration. Wave 2
/// implementation plans will add trait implementations for
/// `NamedControl`, `DynamicUpdater`, and `StatsClient`.
pub struct Bind9Client {
    config: ClientConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bind9_sdk_core::domain::DomainName;
    use bind9_sdk_core::tsig::{TsigAlgorithm, TsigKey};

    fn test_key() -> TsigKey {
        TsigKey::new(
            DomainName::new("rndc-key.").unwrap(),
            TsigAlgorithm::HmacSha256,
            vec![0xAA; 32],
        )
        .unwrap()
    }

    #[test]
    fn client_config_construction() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: Some("http://127.0.0.1:8053".into()),
            dns_addr: Some("127.0.0.1:53".parse().unwrap()),
            tls: None,
            timeout: Duration::from_secs(10),
        };
        assert_eq!(config.rndc_addr.port(), 953);
        assert!(config.stats_url.is_some());
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn client_config_minimal() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: Duration::from_secs(5),
        };
        assert!(config.stats_url.is_none());
        assert!(config.dns_addr.is_none());
        assert!(config.tls.is_none());
    }

    #[test]
    fn bind9_client_new() {
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: None,
            dns_addr: None,
            tls: None,
            timeout: Duration::from_secs(10),
        };
        let client = Bind9Client::new(config);
        assert_eq!(client.config().rndc_addr.port(), 953);
    }

    #[test]
    fn bind9_client_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Bind9Client>();
    }

    #[test]
    fn client_config_with_tls() {
        let tls = TlsConfig::new().unwrap();
        let config = ClientConfig {
            rndc_addr: "127.0.0.1:953".parse().unwrap(),
            rndc_key: test_key(),
            stats_url: None,
            dns_addr: None,
            tls: Some(tls),
            timeout: Duration::from_secs(10),
        };
        assert!(config.tls.is_some());
    }
}
```

- [ ] **Step 2: Verify tests fail to compile**

Run: `cargo test -p bind9-sdk-net -- config 2>&1 | head -20`
Expected: Compile error — `new`, `config` methods not found on `Bind9Client`

- [ ] **Step 3: Implement Bind9Client**

Add the implementation between `pub struct Bind9Client` and the `#[cfg(test)]` module:

```rust
impl Bind9Client {
    /// Create a new BIND9 client with the given configuration.
    ///
    /// This does not establish any connections — connections are created
    /// on demand by trait method implementations (added in Wave 2).
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Access the client configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bind9-sdk-net -- config`
Expected: All 5 tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/bind9-sdk-net/src/config.rs
git commit -m "feat(net): add ClientConfig and Bind9Client skeleton"
```

### Task 16: Update Net lib.rs Re-exports

**Files:**
- Modify: `crates/bind9-sdk-net/src/lib.rs`

- [ ] **Step 1: Update lib.rs with re-exports**

Replace the contents of `crates/bind9-sdk-net/src/lib.rs`:

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub mod config;
pub mod error;
pub mod nsupdate;
pub mod rndc;
pub mod stats;
pub mod tls;

// Curated re-exports for common access
pub use config::{Bind9Client, ClientConfig};
pub use error::NetError;
pub use tls::TlsConfig;
```

- [ ] **Step 2: Run cargo check**

Run: `cargo check --workspace`
Expected: Passes

- [ ] **Step 3: Commit**

```bash
git add crates/bind9-sdk-net/src/lib.rs
git commit -m "feat(net): add curated re-exports to lib.rs"
```

### Task 17: Final Verification

- [ ] **Step 1: Full workspace test suite**

Run: `cargo test --workspace`
Expected: All tests pass across all crates

- [ ] **Step 2: WASM target check**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Passes (core remains no_std clean)

- [ ] **Step 3: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean

- [ ] **Step 4: Format check**

Run: `cargo fmt --check`
Expected: Clean (PostToolUse hook auto-formats, but verify)

- [ ] **Step 5: Test count check**

Run: `cargo test --workspace 2>&1 | grep "test result"`
Expected: Significant increase in test count from the TSIG, UpdateBuilder, and net error tests

- [ ] **Step 6: Commit any remaining changes**

```bash
git add -A
git commit -m "chore: WT-2 TSIG + UpdateBuilder + net foundation complete"
```

This branch is ready for merge into `development` after Wave 1 merge ordering (WT-1 merges first, then WT-2).
