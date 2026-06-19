<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

# Compliance Audit Findings

**Date:** 2026-03-19
**Audited commit:** `ab391ce` (HEAD, `development` branch)
**Scope:** Source code audit against GDPR, NIS2 (EU 2022/2555), NIST SP 800-53/800-81/800-57, ISO 27001:2022 Annex A, SOC 2 Type II TSC, and cryptographic/transport security.

## Executive Summary

Four independent compliance audits were conducted across the bind9-sdk codebase. The SDK demonstrates strong foundational security: `#![forbid(unsafe_code)]`, TSIG key zeroization, typestate-enforced authentication, bounded parsers, and structured tracing with key material redaction.

**Three HIGH-severity findings** recur across multiple audits and must be addressed before any compliance claim:

1. **Zone transfer TSIG response verification is absent** — acknowledged MITM vulnerability (transfer/mod.rs:194-197)
2. **rndc connections use plaintext TCP with no TLS or locality check** — all rndc commands traverse cleartext even to remote servers
3. **TLS 1.2 is compiled in despite documentation claiming TLS 1.3 only** — `rustls` `tls12` feature contradicts stated posture

Additional HIGH findings from the crypto audit: rndc `extract_hmac_input` failure silently falls back to HMAC over empty input (R-1).

**Counts by severity:** 5 HIGH, 11 MEDIUM, 7 LOW, 13 INFO

## HIGH Severity Findings

### H-01: Zone Transfer TSIG Response Verification Absent

| Field | Value |
| --- | --- |
| ID | H-01 |
| Frameworks | NIST SP 800-53 SC-28, NIST SP 800-81 §4.1, SOC 2 CC7.1, RFC 8945 §5.3.1 |
| Source agents | NIS2/NIST, ISO/SOC2, Crypto/Transport (TS-3) |
| File | `crates/bind9-sdk-net/src/transfer/mod.rs:194-197` |

**Description:** When a caller provides a `tsig_key` to `axfr()` or `ixfr()`, the query is TSIG-signed but responses are not verified. A TODO comment explicitly acknowledges: "a man-in-the-middle could inject unsigned records into a TSIG-authenticated transfer stream." Per RFC 8945 §5.3.1, every message in a zone transfer stream MUST be verified with TSIG.

**Current state:** Query signing works. Response verification is not implemented. Callers who pass a TSIG key reasonably expect end-to-end integrity.

**Recommendation:** Implement per-message TSIG verification in the transfer stream before records are yielded to the caller. Until implemented, either reject `tsig_key` arguments (returning `NetError`) or emit `tracing::warn!` at every call that response TSIG verification is not active.

**Effort:** 2-3 days (wire parsing infrastructure exists; needs verification loop per RFC 8945 §5.3.1)

### H-02: rndc Connections Use Plaintext TCP Without TLS or Locality Check

| Field | Value |
| --- | --- |
| ID | H-02 |
| Frameworks | NIST SP 800-53 SC-8, NIS2 Art. 21(2)(h), SOC 2 CC6.7, Crypto/Transport (TS-1) |
| Source agents | NIS2/NIST, ISO/SOC2, Crypto/Transport |
| File | `crates/bind9-sdk-net/src/rndc/mod.rs:123-133` |

**Description:** `RndcConnection::connect` accepts any `SocketAddr` and opens plaintext TCP with no TLS and no locality check. The zone transfer client correctly enforces `TlsRequired` for non-localhost (`transfer/mod.rs:67-71`), but the rndc client has no equivalent. The `ClientConfig.tls` field exists but is unused — `config.rs:107` warns "TLS transports are not implemented yet."

**Current state:** All rndc commands (including `sign`, `validation`, `addzone`) traverse plaintext TCP even to remote servers. Eavesdroppers can observe commands, zone names, and server configuration.

**Recommendation:** Add `is_localhost` check in `RndcConnection::connect` analogous to the transfer client. Reject non-localhost rndc connections without TLS (return `NetError::TlsRequired`), or at minimum emit `tracing::warn!` at every non-localhost connection attempt.

**Effort:** 0.5 days (locality check pattern already exists in transfer module)

### H-03: TLS Version Contradiction — TLS 1.2 Compiled In Despite TLS 1.3 Claim

| Field | Value |
| --- | --- |
| ID | H-03 |
| Frameworks | ISO 27001:2022 A.8.24, SOC 2 CC6.7, NIS2 Art. 21(2)(h), Crypto/Transport (TS-2) |
| Source agents | NIS2/NIST, ISO/SOC2, Crypto/Transport |
| Files | `crates/bind9-sdk-net/src/tls.rs:34-37`, `Cargo.toml:82` |

**Description:** Documentation states "TLS 1.3 only (no TLS 1.2 fallback)." However, `Cargo.toml` enables `rustls = { features = ["ring", "tls12"] }` and the code uses `with_safe_default_protocol_versions()`, which in rustls 0.23 offers both TLS 1.2 and 1.3. This is a direct contradiction.

**Current state:** TLS 1.2 negotiation is possible when both ends support it. The compliance claim "TLS 1.3 only" is false.

**Recommendation:** Remove `tls12` from rustls features and use `.with_protocol_versions(&[&rustls::version::TLS13])`. Alternatively, update all documentation to accurately state "TLS 1.2 and 1.3 supported."

**Effort:** 0.5 days

### H-04: rndc HMAC Input Extraction Failure Falls Back to Empty Slice

| Field | Value |
| --- | --- |
| ID | H-04 |
| Frameworks | NIST SP 800-53 IA-3, Crypto/Transport (R-1) |
| Source agents | Crypto/Transport |
| File | `crates/bind9-sdk-net/src/rndc/mod.rs:680` |

**Description:** `extract_hmac_input(&payload).unwrap_or_default()` silently replaces `None` with an empty `Vec<u8>` when the `_auth` key is not the first entry in the server's wire payload. The HMAC is then computed over zero bytes. In a MITM scenario, a crafted response with `_ctrl`/`_auth` reversed and `_auth.hsha = HMAC(key, "")` would pass verification.

**Current state:** The invariant violation is silent. The HMAC is still computed and compared — the outcome depends on what the server sent for `_auth.hsha`.

**Recommendation:** Return `NetError::AuthFailed` explicitly when `extract_hmac_input` returns `None`. Do not compute or compare any HMAC when input extraction fails.

**Effort:** 0.5 days

### H-05: Statistics Channel Allows Plaintext HTTP to Remote Hosts

| Field | Value |
| --- | --- |
| ID | H-05 |
| Frameworks | NIST SP 800-53 SC-8, NIS2 Art. 21(2)(h) |
| Source agents | NIS2/NIST |
| File | `crates/bind9-sdk-net/src/stats.rs:97-107` |

**Description:** `StatsHttpClient::new()` builds an HTTP client with no TLS enforcement. Stats URLs accept any `http://` URL with no `is_localhost` check. The stats channel exposes operational data (zone serials, query counts, server version). Callers must opt into `with_auth()` — unauthenticated access is the default.

**Current state:** No TLS enforcement, no mandatory auth, no localhost restriction.

**Recommendation:** Validate that stats URL uses `https://` for non-localhost addresses. Add API documentation warning that unauthenticated access is the default.

**Effort:** 1 day

## MEDIUM Severity Findings

### M-01: Auth Failure Events Not Logged at warn/error Level

| Field | Value |
| --- | --- |
| ID | M-01 |
| Frameworks | NIST SP 800-53 AU-3, NIS2 Art. 21(2)(b), SOC 2 CC7.1, ISO 27001:2022 A.12.4 |
| Source agents | NIS2/NIST, ISO/SOC2, GDPR |

**Description:** `NetError::AuthFailed` and `NetError::TsigRejected` are returned to callers but no `tracing::warn!` or `tracing::error!` is emitted by the SDK itself. Auth success is logged at debug (`rndc/mod.rs:227`). Forensic reconstruction of failed auth attempts requires caller-side logging.

**Recommendation:** Add `tracing::warn!(key_name = ..., remote = ..., "rndc auth failed")` inside `authenticate()` before returning `AuthFailed`. Add structured fields: `remote = %addr`, `key_name = %key.name()`, `result = "failure"`.

**Effort:** 0.5 days

### M-02: No `cargo deny` / SBOM Configuration

| Field | Value |
| --- | --- |
| ID | M-02 |
| Frameworks | NIS2 Art. 21(2)(d) |
| Source agents | NIS2/NIST |

**Description:** No `deny.toml` file exists. `cargo-deny` is not configured. No SBOM generation tooling (no `cargo-cyclonedx`, `cargo-sbom`, or `syft`). `cargo audit` is listed in commands but `cargo deny check` has no config to operate on.

**Recommendation:** Create `deny.toml` at workspace root with `[advisories]`, `[bans]`, and `[licenses]` sections. Add `cargo-cyclonedx` or `cargo-sbom` to the release pipeline.

**Effort:** 1 day

### M-03: No Key Lifecycle Metadata

| Field | Value |
| --- | --- |
| ID | M-03 |
| Frameworks | NIST SP 800-57 §5.3.4, §5.3.7, NIST SP 800-53 IA-5 |
| Source agents | NIS2/NIST |

**Description:** `TsigKey` has no expiry, activation window, creation time, or rotation mechanism. Keys have no lifecycle state. No `TsigKey::rotate()`, no key version/epoch field, no dual-key window support.

**Recommendation:** Add optional `KeyMetadata { created_at: u64, expires_at: Option<u64> }` to `TsigKey`. Add `TsigKey::is_valid_at(now: u64) -> bool`. Document key rotation guidance referencing BIND9 `rndc reconfig` flow.

**Effort:** 2 days

### M-04: GDPR — No DPIA Document Exists

| Field | Value |
| --- | --- |
| ID | M-04 |
| Frameworks | GDPR Art. 35 |
| Source agents | GDPR |

**Description:** No Data Protection Impact Assessment exists anywhere in the repository. The stats-channel integration and zone transfer use cases should be DPIA-assessed. The SDK is a library (not a data controller), but a DPIA template for operators is expected given the README compliance claim.

**Recommendation:** Draft a brief DPIA covering: processing purposes for stats/transfer, necessity/proportionality analysis, and risk mitigations. Can be a `PRIVACY.md` or section in docs.

**Effort:** 1 day

### M-05: GDPR — SOA `rname` Field Missing GDPR Documentation

| Field | Value |
| --- | --- |
| ID | M-05 |
| Frameworks | GDPR, PRD REQ-GDPR-2, REQ-ZONE-5 |
| Source agents | GDPR |
| File | `crates/bind9-sdk-core/src/rdata/mod.rs:40-41` |

**Description:** `RecordData::Soa { rname }` field doc says "mailbox of the zone administrator" but has no GDPR note. `RecordData::Rp` (line 241) correctly has one. PRD §8.5 requires SOA RNAME be "documented as potentially personal data."

**Recommendation:** Add `/// # Privacy` doc section matching the `Rp` record pattern.

**Effort:** 15 minutes

### M-06: rndc HMAC Comparison Uses Non-Constant-Time Equality

| Field | Value |
| --- | --- |
| ID | M-06 |
| Frameworks | SOC 2 CC6.1 |
| Source agents | ISO/SOC2 |
| File | `crates/bind9-sdk-net/src/rndc/mod.rs:496` |

**Description:** `verify_authenticated_response()` compares `expected_hmac.as_slice() != received_hmac.as_slice()` using standard byte slice comparison (not guaranteed constant-time in Rust). The TSIG path correctly uses `hmac.verify_slice(mac)` (constant-time).

**Recommendation:** Refactor rndc response verification to use the HMAC crate's constant-time `verify_slice` path.

**Effort:** 0.5 days

### M-07: TSIG Timestamp Silently Falls Back to 0 on Clock Failure

| Field | Value |
| --- | --- |
| ID | M-07 |
| Frameworks | Crypto/Transport (T-3) |
| Source agents | Crypto/Transport |
| Files | `crates/bind9-sdk-net/src/nsupdate.rs:259-262`, `crates/bind9-sdk-net/src/transfer/wire.rs:497-500` |

**Description:** If `SystemTime::now()` is before `UNIX_EPOCH` (clock misconfiguration, VM time jump), `unwrap_or(0)` silently produces `now = 0`. TSIG verification then fails with opaque errors. The `rndc/mod.rs:current_unix_time()` handles this correctly.

**Recommendation:** Return `NetError::Protocol("system clock is before Unix epoch")` instead of silently falling back to 0. Apply the `rndc/mod.rs` pattern to both sites.

**Effort:** 0.5 days

### M-08: `$INCLUDE` Recursion Is Unbounded

| Field | Value |
| --- | --- |
| ID | M-08 |
| Frameworks | ISO 27001:2022 A.8.26, Crypto/Transport (W-1) |
| Source agents | ISO/SOC2, Crypto/Transport |
| File | `crates/bind9-sdk-core/src/zone/parser/record.rs:206-218` |

**Description:** `parse_zone` is called recursively for `$INCLUDE` directives with no depth counter. Mutually recursive includes cause stack overflow. Denial-of-service vector when parsing user-supplied zone files.

**Recommendation:** Add `depth: usize` parameter to internal `parse_zone` and return `CoreError::ZoneParse` when `depth > MAX_INCLUDE_DEPTH` (suggest 8 or 16). Not a public API change.

**Effort:** 0.5 days

### M-09: rndc Serial Counter Wrap-Around Undocumented

| Field | Value |
| --- | --- |
| ID | M-09 |
| Frameworks | Crypto/Transport (R-3) |
| Source agents | Crypto/Transport |
| File | `crates/bind9-sdk-net/src/rndc/mod.rs:265` |

**Description:** After 2^32 - 1 commands, the serial wraps to initial value via `wrapping_add`. A server that has seen serial N could accept a replayed message from the initial N. Unreachable in practice but undocumented.

**Recommendation:** Document the wrap behaviour. Consider detecting wrap and returning `NetError::Protocol("serial counter exhausted")`.

**Effort:** 0.5 days

### M-10: `ClientConfig` Lacks `Debug` Impl with Key Redaction

| Field | Value |
| --- | --- |
| ID | M-10 |
| Frameworks | Crypto/Transport (M-3) |
| Source agents | Crypto/Transport |
| File | `crates/bind9-sdk-net/src/config.rs` |

**Description:** `ClientConfig` has no `Debug` impl. If a caller derives `Debug` on a wrapper struct, there is no explicit redaction contract at the config level. `TsigKey`'s own `Debug` impl would protect it, but the absence at the config level is inconsistent.

**Recommendation:** Implement `Debug` for `ClientConfig` with `[REDACTED]` for `rndc_key`.

**Effort:** 15 minutes

### M-11: No Failover / Multi-Server Support

| Field | Value |
| --- | --- |
| ID | M-11 |
| Frameworks | NIS2 Art. 21(2)(c), SOC 2 A1.2 |
| Source agents | NIS2/NIST, ISO/SOC2 |

**Description:** `ClientConfig` holds a single `rndc_addr`. No multi-server failover, no retry-on-error logic. `RndcPool` limits concurrency but does not retry against alternate servers.

**Recommendation:** Add optional `Vec<SocketAddr>` fallback list to `ClientConfig`. Document resilience expectations.

**Effort:** 2-3 days

## LOW Severity Findings

### L-01: No Runtime Warning on HMAC-SHA1 Algorithm Selection

| Field | Value |
| --- | --- |
| ID | L-01 |
| Frameworks | ISO 27001:2022 A.8.24, NIST SP 800-81 §3.2, Crypto/Transport (T-1) |
| Source agents | ISO/SOC2, NIS2/NIST, Crypto/Transport |

**Description:** `#[deprecated]` fires at compile time only. Callers consuming via binary (CLI, Node.js) receive no operational warning. `parse_from_wire` accepts `hmac-sha1.` with `#[allow(deprecated)]` suppressor.

**Recommendation:** Add `tracing::warn!` at `TsigKey::new()` when `algorithm == HmacSha1` and at `parse_from_wire` when SHA-1 is parsed from wire.

**Effort:** 15 minutes

### L-02: Key Length Warning Is `std`-Only; Silent in `no_std` Builds

| Field | Value |
| --- | --- |
| ID | L-02 |
| Frameworks | Crypto/Transport (T-2) |
| Source agents | Crypto/Transport |
| File | `crates/bind9-sdk-core/src/tsig/key.rs:46-55` |

**Description:** Short-key warning behind `#[cfg(feature = "std")]`. In `no_std` builds (WASM/embedded), a 1-byte key for HMAC-SHA256 is accepted silently.

**Recommendation:** Either promote to a hard error or document the `no_std` gap explicitly.

**Effort:** 0.5 days

### L-03: `TsigKey` Missing `Display` Impl

| Field | Value |
| --- | --- |
| ID | L-03 |
| Frameworks | GDPR (secret handling), coding architecture spec §2.3 |
| Source agents | GDPR |
| File | `crates/bind9-sdk-core/src/tsig/key.rs` |

**Description:** Architecture spec says "Manual `Display` impl — same redaction rule" for secret-bearing types. `TsigKey` has no `Display` impl. Rust won't compile `format!("{}", key)` (benign), but contradicts the internal spec.

**Recommendation:** Add `Display` impl with `[REDACTED]` for key material.

**Effort:** 15 minutes

### L-04: `mac_input` Buffer Not Zeroized After MAC Computation

| Field | Value |
| --- | --- |
| ID | L-04 |
| Frameworks | NIST SP 800-57 §5.3.5, Crypto/Transport (M-4) |
| Source agents | Crypto/Transport |
| File | `crates/bind9-sdk-core/src/tsig/record.rs:116-122` |

**Description:** The `mac_input` buffer in `TsigRecord::new` and `verify_response` is a plain `Vec<u8>`, not wrapped in `Zeroizing`. Contains the full DNS message + TSIG variables. Dropped without zeroing — content remains in freed heap memory.

**Recommendation:** Wrap `mac_input` in `Zeroizing::new(Vec::with_capacity(...))`.

**Effort:** 15 minutes

### L-05: TSIG `original_id` Not Cross-Checked Against Message ID

| Field | Value |
| --- | --- |
| ID | L-05 |
| Frameworks | RFC 8945 §4.3.2, Crypto/Transport (T-5) |
| Source agents | Crypto/Transport |
| File | `crates/bind9-sdk-core/src/tsig/record.rs:78-82` |

**Description:** In `parse_from_wire`, the `original_id` field is accepted as-is without cross-checking against the enclosing message's ID field. For TCP zone transfers with message ID reuse, this could allow a subtle mismatch.

**Recommendation:** Cross-check `response_tsig.original_id` against `response_message[0..2]` in `verify_response`.

**Effort:** 0.5 days

### L-06: DNS Label Character Set Not Validated in Transfer Wire Parser

| Field | Value |
| --- | --- |
| ID | L-06 |
| Frameworks | RFC 1035 §2.3.1, Crypto/Transport (W-6) |
| Source agents | Crypto/Transport |
| File | `crates/bind9-sdk-net/src/transfer/wire.rs:169-171` |

**Description:** The parser accepts any valid UTF-8 as a DNS label. RFC 1035 restricts labels to letters, digits, and hyphens. Zone data from AXFR could contain syntactically invalid labels.

**Recommendation:** Confirm whether `DomainName::new` enforces label syntax; if not, add validation in `parse_name`.

**Effort:** 0.5 days

### L-07: CLI Secret Storage and In-Memory Protection

| Field | Value |
| --- | --- |
| ID | L-07 |
| Frameworks | NIST SP 800-57 §5.3.2, §5.3.3 |
| Source agents | NIS2/NIST |
| File | `crates/bind9-sdk-cli/src/config.rs:46` |

**Description:** `AuthConfig.key_secret` is a plain `String` (base64) in memory. The TSIG key secret is also stored as plaintext in `config.toml` on disk. Two gaps: (1) the in-memory string is not zeroized on drop and could linger in freed heap memory or appear in core dumps, and (2) the on-disk config file contains the secret in cleartext.

**Recommendation:** Use both:
- **`keyring`** crate for persistent storage — stores secrets in the OS credential store (macOS Keychain, Linux Secret Service, Windows Credential Manager). Eliminates plaintext secrets in `config.toml`. Add a `bind9 auth set-key` CLI command for initial key storage.
- **`secrecy::SecretString`** for the in-memory transit path between reading from the keychain and constructing the `TsigKey` (which already uses `Zeroizing<Vec<u8>>`). Ensures the base64 string is zeroized on drop and redacted in `Debug`/`Display`.

**Effort:** 1-2 days

## INFO Findings

| ID | Framework | Description |
| --- | --- | --- |
| I-01 | NIST SP 800-53 AU-2 | No formal `AuditEvent` enum or event taxonomy for security-relevant events |
| I-02 | NIST SP 800-53 AU-12 | `bind9-sdk-core` has no `tracing` calls (tracing is optional, `std`-only) |
| I-03 | NIST SP 800-53 IA-7 | RustCrypto is not FIPS-140 certified; may require documented exception for regulated NIS2 operators |
| I-04 | NIST SP 800-81 §6 | View-scoped rndc commands missing; BIND9 multi-view deployments cannot be targeted per-view |
| I-05 | ISO 27001:2022 A.8.25 | No fuzzing infrastructure (Phase 6 planned work) |
| I-06 | SOC 2 CC7.2 | No metrics emission (counters for auth successes/failures/timeouts); all tracing at debug level |
| I-07 | GDPR | Zone name emitted in `#[instrument]` spans (`transfer/mod.rs:113,137`); server IPs at DEBUG |
| I-08 | GDPR | No standalone data flow document mapping data categories through the SDK |
| I-09 | Crypto (RNG-1) | All random sources use `getrandom` correctly; no weak PRNGs |
| I-10 | Crypto (M-1, M-2) | `TsigKey` and `TsigRecord` secret handling fully correct |
| I-11 | Crypto (R-4) | Asymmetric nonce handling between rndc auth and command not explicitly tested |
| I-12 | Crypto (TS-4) | Stats-channel HTTPS has no certificate pinning (expected for current deployment model) |
| I-13 | Crypto (W-7) | `getrandom` failure for update message ID silently falls back to ID=0 in `no_std` |

## Compliance Matrix Summary

| Framework | Control | Status | Key Gap |
| --- | --- | --- | --- |
| **GDPR** | Data minimization | PARTIAL | Zone name in spans; server IPs at DEBUG |
| **GDPR** | Right to erasure | COMPLIANT | No file writes, no caches |
| **GDPR** | DPIA | NON-COMPLIANT | No DPIA document (M-04) |
| **GDPR** | SOA rname documentation | NON-COMPLIANT | Missing GDPR doc note (M-05) |
| **NIS2 Art. 21(2)(b)** | Incident handling | PARTIAL | Auth failures not logged (M-01) |
| **NIS2 Art. 21(2)(c)** | Business continuity | PARTIAL | No failover (M-11) |
| **NIS2 Art. 21(2)(d)** | Supply chain | PARTIAL | No deny.toml/SBOM (M-02) |
| **NIS2 Art. 21(2)(h)** | Encryption | GAP | rndc plaintext (H-02), TLS 1.2 (H-03), stats plaintext (H-05) |
| **NIST SP 800-53 SC-8** | Transmission confidentiality | GAP | rndc (H-02), stats (H-05) |
| **NIST SP 800-53 SC-28** | Transaction integrity | GAP | Transfer TSIG unverified (H-01) |
| **NIST SP 800-53 IA-3** | Device authentication | COMPLIANT | Full RFC 8945 TSIG implementation |
| **NIST SP 800-53 IA-5** | Key management | PARTIAL | No lifecycle metadata (M-03) |
| **NIST SP 800-53 AU-3** | Audit record content | PARTIAL | Auth failures lack structured fields (M-01) |
| **NIST SP 800-53 SI-10** | Input validation | COMPLIANT | Bounded parsers, validated types |
| **NIST SP 800-57 §5.3.5** | Key destruction | COMPLIANT | `Zeroizing<Vec<u8>>` on all key material |
| **NIST SP 800-81 §4.1** | Zone transfer security | GAP | Response TSIG unverified (H-01) |
| **NIST SP 800-81 §5** | Dynamic update security | COMPLIANT | UpdateBuilder sign + response verify |
| **ISO 27001 A.8.24** | Cryptography | PARTIAL | TLS 1.2 contradiction (H-03) |
| **ISO 27001 A.8.25** | Secure SDLC | VERIFIED | forbid(unsafe), CI, proptest; no fuzzing yet |
| **ISO 27001 A.8.26** | App sec requirements | VERIFIED | Bounded parsers, validated types, record limits |
| **SOC 2 CC6.1** | Logical access | VERIFIED | TSIG auth, typestate, nonce/serial validation |
| **SOC 2 CC6.7** | Data transmission | PARTIAL | TLS 1.2 (H-03); rndc/stats plaintext (H-02, H-05) |
| **SOC 2 CC7.1** | Unauthorized activity | PARTIAL | Auth failures typed but no tracing events (M-01) |
| **SOC 2 CC8.1** | Change management | VERIFIED | CI pipeline, pinned toolchain, cargo audit |

## Action Items

### Immediate (before v0.1.0 publish)

1. **H-04** — Fix `extract_hmac_input` fallback (0.5 days)
2. **H-02** — Add localhost check to rndc connect (0.5 days)
3. **H-03** — Remove `tls12` feature or fix documentation (0.5 days)
4. **M-05** — Add GDPR doc note to SOA `rname` (15 minutes)
5. **M-10** — Add `Debug` impl to `ClientConfig` (15 minutes)
6. **L-03** — Add `Display` impl to `TsigKey` (15 minutes)
7. **L-04** — Wrap `mac_input` in `Zeroizing` (15 minutes)
8. **L-01** — Add runtime SHA-1 warning (15 minutes)

### Phase 6

9. **H-01** — Implement transfer TSIG response verification (2-3 days)
10. **M-01** — Add auth failure tracing events (0.5 days)
11. **M-02** — Create `deny.toml`, add SBOM pipeline (1 day)
12. **M-07** — Fix clock fallback in nsupdate/transfer (0.5 days)
13. **M-08** — Add `$INCLUDE` depth limit (0.5 days)
14. **M-06** — Constant-time rndc HMAC comparison (0.5 days)

### Future

15. **M-03** — Key lifecycle metadata (2 days)
16. **M-04** — Draft DPIA / PRIVACY.md (1 day)
17. **M-11** — Multi-server failover (2-3 days)
18. **M-09** — Serial wrap detection (0.5 days)
