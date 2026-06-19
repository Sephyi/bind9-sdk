<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
-->

# DNS Infrastructure Security Report: Hidden-Primary / Distributed-Secondary Architecture

**Date**: 2026-03-19
**Scope**: Comprehensive threat analysis for a DNSSEC-signed hidden-primary nameserver architecture with untrusted secondary VPS instances
**Research**: 9 parallel research agents covering DNSSEC chain security, zone transfer attacks, secondary compromise, primary hardening, infrastructure-level attacks, OS selection, Kicksecure evaluation, OPSEC workstation hardware, and AMD/Snapdragon/ECC alternatives

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Under Analysis](#2-architecture-under-analysis)
3. [DNSSEC: What It Protects and What It Doesn't](#3-dnssec-what-it-protects-and-what-it-doesnt)
4. [Zone Transfer Security](#4-zone-transfer-security)
5. [Compromised Secondary Attack Scenarios](#5-compromised-secondary-attack-scenarios)
6. [Primary Server Hardening](#6-primary-server-hardening)
7. [Infrastructure-Level Attacks](#7-infrastructure-level-attacks)
8. [OS Selection for the Primary VM](#8-os-selection-for-the-primary-vm)
9. [Consolidated Threat Matrix](#9-consolidated-threat-matrix)
10. [Prioritized Mitigation Roadmap](#10-prioritized-mitigation-roadmap)
11. [Kicksecure Evaluation for BIND9 VM](#11-kicksecure-evaluation-for-bind9-vm)
12. [OPSEC Workstation: Hardware and OS Selection](#12-opsec-workstation-hardware-and-os-selection)
13. [Sources](#13-sources)

## 1. Executive Summary

**Your core question**: "If I use DNSSEC with a hidden primary on hardened hardware and cheap VPS secondaries, am I protected against record manipulation?"

**The answer**: DNSSEC substantially raises the bar, but it is not a complete defense. Here is the honest assessment:

### What DNSSEC guarantees

- A compromised secondary **cannot forge new records** that pass DNSSEC validation — the signing keys never leave your primary. This protects ~36% of global DNS traffic that flows through validating resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9 all validate).
- RRSIG stripping (removing signatures to make the zone appear unsigned) fails because the DS record in the parent zone proves the zone is signed — validating resolvers will reject unsigned answers.

### What DNSSEC does NOT protect

- **~64% of global DNS traffic** flows through non-validating resolvers. For those users, a compromised secondary can serve any data it wants — completely fabricated records, no cryptographic check.
- **Replay attacks**: A compromised secondary can serve old-but-validly-signed data for the entire RRSIG validity period (default 14 days in BIND9 KASP). This is an unsolved problem in standard DNSSEC (Yan et al., 2008).
- **Availability attacks**: DNSSEC provides zero protection against DoS. A compromised secondary can return SERVFAIL or selectively drop records.
- **Registrar-level attacks**: If an attacker compromises your registrar account and changes both NS records and DS records, they fully bypass DNSSEC by replacing the trust anchor. This is the highest-impact single attack vector.

### Key finding: the registrar is your weakest link

The single most impactful mitigation is **registry lock** on your domain — not any DNS protocol feature. Registry lock requires out-of-band phone verification before any NS or DS record change at the TLD level, defeating registrar account compromise entirely. This costs $100–500/year and is available for .com/.net/.org and most major TLDs.

### Hardware security assessment

AMD SME/SEV RAM encryption on your primary protects against physical memory extraction (cold boot, bus snooping) but provides **zero protection against OS-level compromise**. Once the BIND9 process loads keys into memory, any root-level attacker sees plaintext. SEV-SNP (the latest generation) has been broken by multiple academic attacks in 2024–2025 (WeSee, Heracles, RMPocalypse, StackWarp). Full disk encryption protects at-rest data only. The real protection for DNSSEC keys is a hardware HSM (YubiHSM 2, ~$650), which prevents key extraction even from a compromised OS.

### OS recommendation

**Rocky Linux 9** for the primary VM. SELinux's label-based MAC (`named_t` type enforcement) is the strongest containment available, unaffected by the March 2026 CrackArmor AppArmor vulnerabilities. Add ISC's repository for BIND 9.20. Runner-up: Debian Trixie (fastest BIND CVE patching, ~24h turnaround).

## 2. Architecture Under Analysis

```txt
                    ┌─────────────────────────────────────────────┐
                    │         HIDDEN PRIMARY (Dedicated Server)    │
                    │  AMD Ryzen Pro (SME/SEV), FDE, VM            │
                    │  BIND9 9.20 + KASP (DNSSEC signing)         │
                    │  rndc: localhost only (port 953)             │
                    │  NOT in NS records                          │
                    └───────┬──────────┬──────────┬───────────────┘
                            │          │          │
                     XoT+TSIG    XoT+TSIG    XoT+TSIG
                     (per-key)   (per-key)   (per-key)
                            │          │          │
                    ┌───────▼──┐ ┌─────▼────┐ ┌──▼──────────┐
                    │ Secondary │ │ Secondary │ │ Secondary   │
                    │ VPS #1    │ │ VPS #2    │ │ VPS #3      │
                    │ Provider A│ │ Provider B│ │ Provider C  │
                    │ (cheap)   │ │ (cheap)   │ │ (cheap)     │
                    └───────────┘ └──────────┘ └─────────────┘
                         │              │              │
                    Public DNS     Public DNS     Public DNS
                    (NS records)   (NS records)   (NS records)
```

**Trust model**: The primary is trusted. Secondaries are explicitly untrusted — assume any or all can be fully compromised at any time.

## 3. DNSSEC: What It Protects and What It Doesn't

### 3.1 The Two Guarantees

DNSSEC provides exactly two properties:

1. **Data origin authentication**: A validating resolver can verify that an RRset was signed by the zone operator's private key
2. **Data integrity**: Signed data has not been modified since signing

DNSSEC does NOT provide: confidentiality, encryption, availability, or freshness.

### 3.2 Chain of Trust

```txt
Root Trust Anchor (hardcoded in resolvers)
    │ Root KSK signs Root DNSKEY RRset
    │ Root ZSK signs DS records for TLDs
    ▼
DS record for .com (hash of .com KSK, signed by root ZSK)
    │ .com KSK authenticated via DS match
    │ .com ZSK signs DS records for domains
    ▼
DS record for example.com (hash of example.com KSK)
    │ example.com KSK authenticated via DS match
    │ example.com ZSK signs all zone RRsets
    ▼
A, MX, TXT records + RRSIGs (cryptographically bound)
```

The chain has one critical external dependency: the **DS record in the parent zone** is controlled by your registrar/registry, not by you. This is the single point where DNSSEC can be bypassed from above.

### 3.3 Replay Attacks — The Unsolved Problem

A compromised secondary cannot forge new records but **can serve old validly-signed records** for the entire RRSIG validity period. This is formally characterized as an unsolved problem (Yan, Osterweil et al., "Limiting Replay Vulnerabilities in DNSSEC", Colorado State / UCLA, 2008).

| RRSIG validity | Replay window | Operational risk if primary goes down |
| --- | --- | --- |
| 3 days | 3 days | Primary must be reachable every 1–2 days |
| 7 days | 7 days | Moderate — 5-day buffer with daily re-signing |
| 14 days (KASP default) | 14 days | Good — 11-day buffer with 3-day re-signing |
| 30 days | 30 days | Maximum replay exposure |

**Recommendation**: 14-day RRSIG validity with 3-day re-signing interval. This limits replay to 14 days while tolerating 11 days of primary unavailability.

**Canary record mitigation**: Deploy a `_canary.example.com TXT` record with 60-second TTL, monitored externally every minute. If a compromised secondary stops refreshing, the canary diverges and triggers an alert within minutes.

### 3.4 NSEC/NSEC3 Zone Walking

- **NSEC**: Trivially walkable. The chain literally hands over every label in the zone in O(n) queries.
- **NSEC3**: Hashes names with a salt, but SHA-1 hashes are fast enough for offline dictionary attacks. Tools like `hashcat` recover common subdomains easily.
- **Recommendation**: Use NSEC3 with `opt-out` disabled and a random salt. Accept that NSEC3 raises the bar but does not eliminate enumeration for common names. Do not put security-sensitive internal names in public zones.

### 3.5 DNSSEC Validation Adoption (2025–2026)

| Metric | Value | Source |
| --- | --- | --- |
| Global traffic through validating resolvers | ~36% | APNIC Labs, Feb–Mar 2026 |
| Second-level domains with DS records | ~7–8% | SIDN Labs 2025 |
| Cloudflare 1.1.1.1 | Validates | Cloudflare docs |
| Google 8.8.8.8 | Validates | Google docs |
| Quad9 9.9.9.9 | Validates | Quad9 docs |
| Comcast (US) | ~95% of users | APNIC / ICANN 82, Mar 2025 |
| Romania | ~9% | APNIC / ICANN 82 |

**Implication**: For the ~64% of traffic through non-validating resolvers, a compromised secondary can serve completely fabricated records with zero cryptographic check.

### 3.6 Algorithm Security

| Algorithm | DNSSEC # | Status (2026) | Recommendation |
| --- | --- | --- | --- |
| RSA/SHA-1 | 5 | Deprecated | Do not use |
| RSA/SHA-256 | 8 | Secure classically, large keys | Acceptable |
| ECDSA P-256 | 13 | **Recommended**, widely deployed | Best default |
| Ed25519 | 15 | **Recommended**, smallest signatures | Best if resolver support sufficient |

All current algorithms are broken by a cryptographically relevant quantum computer (CRQC) via Shor's algorithm. Timeline estimate: 2030–2035. Post-quantum DNSSEC algorithms (Falcon-512, MAYO-2, SLH-DSA) are in active research (Verisign/ISC/NLnet Labs, NIST PQC Conference Aug 2025) but not yet standardized. No action needed today, but ensure KASP supports algorithm rollover.

**Critical**: Sign with a single strong algorithm only. Multi-algorithm zones are vulnerable to the USENIX 2023 downgrade attack (Heftrig et al.) where an attacker strips the stronger algorithm's signatures.

## 4. Zone Transfer Security

### 4.1 TSIG Authentication

TSIG (RFC 8945) provides HMAC-based authentication of zone transfer messages. The shared secret never traverses the wire.

| Property | Assessment |
| --- | --- |
| HMAC-SHA256 with 256-bit key | Computationally infeasible to brute-force (2^256 search space) |
| HMAC-SHA512 with 512-bit key | Preferred for high-value zones; side-channel resistant on AMD64 |
| Replay window | Default 300s fudge; tighten to 60s on NTP-synchronized servers |
| Per-message chaining | MAC chaining prevents re-ordering/splicing within a transfer |

**Critical requirement**: Use a **separate, unique TSIG key per secondary**. If secondary ns2 is compromised, only that key needs rotation. A shared key multiplies blast radius.

### 4.2 XoT (DNS Zone Transfer over TLS, RFC 9103)

XoT adds confidentiality and transport-layer integrity on top of TSIG. BIND 9.18+ supports XoT.

| Without XoT | With XoT |
| --- | --- |
| Zone contents visible to passive observers | Encrypted — only TLS metadata visible |
| Active MITM: cannot inject (TSIG blocks) but can read | Cannot read, cannot inject |
| Datacenter staff can see all records | Datacenter staff sees only connection metadata |

**TLS configuration**:
- Use TLS 1.3 exclusively (`protocols { TLSv1.3; };`)
- Use SPKI pinning or a private CA — no reliance on public CA ecosystem
- Mutual TLS (mTLS) is the strongest mode: primary validates secondary's client certificate
- Block TCP/53 from secondary IPs at firewall — force all transfers through TCP/853

**TLS downgrade prevention**: If the secondary is configured for XoT, BIND 9.18+ does not fall back to cleartext on TLS failure. The transfer simply fails and retries later.

### 4.3 Datacenter-Level MITM

| Scenario | TSIG only | XoT + TSIG |
| --- | --- | --- |
| Passive eavesdropping | Can read all zone data | Cannot read (TLS encrypted) |
| Active record injection | Blocked (TSIG MAC fails) | Blocked (TLS + TSIG) |
| BGP-level rerouting | TSIG blocks injection; attacker reads data | TLS cert mismatch → connection fails |
| Transfer metadata leakage | Timing, frequency, size visible | Timing and approximate size visible |

### 4.4 IXFR-Specific Risks

- **CVE-2021-25214**: Malformed IXFR with mismatched SOA owner name could crash `named` on the secondary. Patched in BIND 9.16.15+.
- **SOA serial manipulation**: Requires TSIG key compromise. A forged high serial can freeze zone updates (DoS). TSIG prevents this without key compromise.
- **AXFR vs IXFR**: IXFR's more complex parsing has historically had more bugs. AXFR-only is a valid simplification if bandwidth permits.

### 4.5 NOTIFY Security

NOTIFY messages are not authenticated by default. Configure TSIG-authenticated NOTIFY:

```txt
# Primary: send TSIG-signed NOTIFY
also-notify { <ns1-ip> key "primary-to-ns1"; };

# Secondary: only accept NOTIFY from primary with TSIG
allow-notify { <primary-ip>; key "primary-to-ns1"; };
```

Forged NOTIFYs cannot cause transfers from malicious servers — BIND always fetches from its configured `primaries` list, never from the NOTIFY source.

### 4.6 Recommended Zone Transfer Configuration

**Primary `named.conf`**:

```txt
tls primary-xot {
    cert-file "/etc/named/tls/primary.crt";
    key-file  "/etc/named/tls/primary.key";
    ca-file   "/etc/named/tls/private-ca.crt";  // mTLS client validation
    protocols { TLSv1.3; };
    ciphers "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
    session-tickets no;
};

listen-on port 853 tls primary-xot { <primary-ip>; };

zone "example.com" {
    type primary;
    allow-transfer {
        !{ !<ns1-ip>/32; any; }; key "primary-to-ns1";
        !{ !<ns2-ip>/32; any; }; key "primary-to-ns2";
    };
    also-notify {
        <ns1-ip> key "primary-to-ns1";
        <ns2-ip> key "primary-to-ns2";
    };
};
```

**Secondary `named.conf`**:

```txt
tls ns1-to-primary {
    protocols { TLSv1.3; };
    cert-file "/etc/named/tls/ns1.crt";      // Client cert for mTLS
    key-file  "/etc/named/tls/ns1.key";
    tls-auth-type spki;
    tls-spki-hash "<base64-sha256-of-primary-pubkey>";
};

zone "example.com" {
    type secondary;
    primaries { <primary-ip> port 853 tls ns1-to-primary key "primary-to-ns1"; };
    allow-notify { <primary-ip>; key "primary-to-ns1"; };
};
```

## 5. Compromised Secondary Attack Scenarios

### 5.1 Attack Capability Matrix

| Attack | Validating resolvers (~36%) | Non-validating resolvers (~64%) |
| --- | --- | --- |
| Modified A/AAAA/MX records | Rejected (RRSIG mismatch → SERVFAIL) | **Accepted** — full record manipulation |
| RRSIG stripping (make zone appear unsigned) | Rejected (DS at parent proves zone is signed) | **Accepted** |
| Replay old validly-signed data | **Accepted** for RRSIG validity period | **Accepted** |
| Selective NXDOMAIN | SERVFAIL (no valid NSEC chain) | **Accepted** — targeted record suppression |
| SERVFAIL for all queries | Zone degrades proportionally to compromised/total | Same |
| DDoS amplification via secondary | N/A (amplification target is third party) | Same |

### 5.2 TSIG Key Extraction — Lateral Movement

A compromised secondary holds its TSIG key in `named.conf` in plaintext. An attacker with root reads it trivially. With the extracted key:

| Capability | Risk | Mitigation |
| --- | --- | --- |
| Pull current zone via AXFR from primary | Low (zone is already public) | Per-secondary keys limit scope |
| Trigger zone transfer exhaustion (DoS) | Medium | Rate-limit transfers on primary |
| Dynamic update injection if key is in `allow-update` | **CRITICAL** — full zone compromise | **Never** put transfer keys in `allow-update` |
| Forge NOTIFY to trigger SOA polls | Low | TSIG-authenticated NOTIFY |

**The most dangerous misconfiguration**: If the transfer TSIG key is also listed in `allow-update` on the primary, the attacker can inject records that the primary signs and distributes to all secondaries. This is a full, DNSSEC-valid zone compromise. **The transfer TSIG key must never appear in `allow-update`.**

### 5.3 Lateral Movement to Primary

| Path | Feasibility | Mitigation |
| --- | --- | --- |
| TSIG key → AXFR requests | Possible (zone enumeration) | Per-secondary keys; rate limiting |
| TSIG key → dynamic update | Only if misconfigured | Separate update/transfer keys |
| rndc from secondary to primary | Should not exist | Firewall port 953 to localhost |
| Network scan of primary IP | Primary IP exposed in secondary's `named.conf` | Firewall primary to accept only known secondary IPs |

### 5.4 BGP Hijacking + Compromised Secondary

The MyEtherWallet incident (April 2018) is the canonical case: BGP hijack of Amazon Route 53 prefixes redirected DNS queries to an attacker server serving fake A records. $152,000 stolen. The targeted domain was **not DNSSEC-signed**.

Against a DNSSEC-signed zone:
- Validating resolvers: reject forged answers (no valid RRSIG) → SERVFAIL
- Non-validating resolvers: accept forged answers → attack succeeds

**RPKI/ROA** reduces BGP hijack feasibility. Current enforcement by VPS provider (Aug 2025 survey):

| Provider | RPKI Enforcement |
| --- | --- |
| AWS, Azure, DigitalOcean, Vultr | Yes |
| OVH, Linode/Akamai, Contabo, Oracle Cloud | No |

Choose secondary VPS providers that enforce RPKI.

## 6. Primary Server Hardening

### 6.1 AMD SME/SEV — Honest Assessment

| Feature | Protects Against | Does NOT Protect Against |
| --- | --- | --- |
| SME (Secure Memory Encryption) | Cold boot attacks, memory bus snooping, physical RAM extraction | Any software-level access (root, kernel exploit, ptrace) |
| SEV (Secure Encrypted Virtualization) | Malicious hypervisor reading VM RAM (in theory) | SEVered attack (2018), WeSee (2024), Heracles (2025), StackWarp (2025) |
| SEV-SNP (Secure Nested Paging) | Page remapping by hypervisor | RMPocalypse (2025), CounterSEVeillance (2025) |
| Full Disk Encryption (LUKS2) | Disk theft, powered-off access | Running VM compromise (already decrypted) |

**Bottom line**: RAM encryption and FDE are physical-layer protections. Once the VM is running and `named` has loaded DNSSEC keys into memory, **any root-level attacker sees plaintext keys**. The memory controller decrypts transparently for the CPU.

### 6.2 DNSSEC Key Protection — HSM

BIND9 stores DNSSEC private keys as files in the key directory (default `/var/named/`). Any process running as `named`, `root`, or in the `bind` group reads them in plaintext.

**PKCS#11 / HSM integration** (BIND 9.20 + OpenSSL 3 providers):

| HSM Option | Key Extraction Protected | Signing Abuse Protected | Cost |
| --- | --- | --- | --- |
| SoftHSM2 | No (files on disk) | No | Free |
| YubiHSM 2 | Yes (tamper-resistant) | No (compromised named can still sign) | ~$650 |
| Thales Luna / Entrust nShield | Yes (FIPS 140-3 validated) | No | $5,000+ |

HSM prevents key extraction but not signing API abuse by a compromised `named` process. However, key extraction is the catastrophic scenario (attacker signs offline, indefinitely), while signing abuse requires maintaining access to the running process.

**Recommendation**: Store KSK in a YubiHSM 2 (USB, PKCS#11). ZSK can remain in software (rotated every 90 days via KASP). Maintain encrypted offline backup of all key material.

### 6.3 rndc Channel

rndc is effectively root access to `named`. Anyone with the rndc key can stop the server, flush zones, modify signing parameters, and enable query logging.

- **Restrict to localhost only**: `controls { inet 127.0.0.1 port 953 allow { 127.0.0.1; }; };`
- **rndc key ≠ TSIG key**: Generate separately with `rndc-confgen` and `tsig-keygen`
- **Firewall port 953** from all external IPs
- **Remote management**: SSH tunnel (`ssh -L 953:localhost:953`) rather than network-exposed rndc

### 6.4 Hidden Primary Configuration Checklist

- Primary's IP **not** in NS records (verify: `dig NS example.com @a.gtld-servers.net`)
- SOA MNAME set to a public secondary hostname, not the primary's hostname
- `recursion no;` globally
- `allow-query { none; };` or restricted to secondary IPs
- `allow-transfer` requires both IP match and TSIG key

**Firewall rules (nftables)**:

```txt
Input:  ACCEPT TCP/853 from [secondary IPs]   # XoT zone transfers
Input:  ACCEPT TCP/953 from 127.0.0.1         # rndc
Input:  ACCEPT TCP/22 from [VPN/jump host]    # SSH management
Input:  DROP everything else
Output: ACCEPT TCP/853 to [secondary IPs]     # Zone transfer responses
Output: ACCEPT UDP/123 to [NTP servers]       # Time sync (NTS preferred)
Output: ACCEPT TCP/443 to [package repos]     # Security updates
Output: DROP everything else
```

### 6.5 Side-Channel Attacks

- **AMD Transient Scheduler Attacks (TSA)**: July 2025 disclosure, affects Zen 3/4. Post-exploitation only (requires code execution on host). Apply microcode updates.
- **Spectre/Inception (SRSO)**: CVE-2023-20569, affects Zen 3/4. Microcode patches available.
- **On dedicated hardware with single VM**: Cross-VM side channels are not applicable. The main risk is firmware-level attackers (very low probability on dedicated hardware).
- **Disable SMT/hyperthreading** if security is paramount — eliminates an entire class of timing side channels.

## 7. Infrastructure-Level Attacks

### 7.1 Registrar/Registry Attacks — The Highest-Impact Vector

**Probability: 3/5 — Impact: 5/5**

An attacker who compromises your registrar account can change NS records and/or remove DS records at the TLD level. This is above the DNSSEC trust anchor — if both NS and DS are changed, DNSSEC is fully bypassed.

**Real-world precedent**: Sea Turtle campaign (2017–2019, attributed to nation-state actor) compromised registrars and at least one ccTLD registry, modifying NS records for 40+ organizations across 13 countries. (Cisco Talos, April/July 2019)

**Mitigations**:

| Control | What It Defeats | Cost |
| --- | --- | --- |
| Registry Lock (serverUpdateProhibited + serverDeleteProhibited) | Registrar account compromise → NS/DS changes | $100–500/year |
| Hardware MFA (FIDO2/WebAuthn) on registrar | Credential phishing, SIM swap | ~$25 per key |
| DS record monitoring (automated dig every 5 min) | Detect unauthorized DS changes | Free |
| Certificate Transparency monitoring | Detect attacker obtaining TLS certs for your domain | Free (SSLMate Certspotter) |

**Registry lock is the single most impactful mitigation in this entire report.**

### 7.2 BGP Hijacking

**Probability: 3/5 — Impact: 4/5 for non-validating resolvers, 1/5 for validating resolvers**

An attacker announces more-specific BGP routes for your secondary NS IPs, intercepting DNS queries. With DNSSEC: validating resolvers reject forged answers. Without: full record manipulation.

RPKI/ROA is the defense but at ~33% global enforcement (end-2025), coverage is incomplete. ASPA (path validation) has only 87 deployments globally.

**Mitigations**: Choose VPS providers with RPKI enforcement. Set up BGP monitoring (Cloudflare Radar, RIPE Stat). Distribute secondaries across 3+ distinct ASNs.

### 7.3 DDoS Against All Secondaries

**Probability: 4/5 — Impact: 3/5 (availability only)**

If all public secondaries are DDoSed simultaneously, the zone becomes unreachable. The hidden primary is protected (its IP is not public), but all query-answering servers are targets.

**Mitigations**: Multi-provider distribution (3+ providers, 3+ geographies). DNS anycast (commercial option: Cloudflare DNS, NS1). Response Rate Limiting on all secondaries. Higher TTLs for DDoS resilience (300–3600s).

### 7.4 Time-Based Attacks (NTP Manipulation)

**Probability: 3/5 — Impact: 3–4/5**

NTP runs in cleartext by default. An attacker who shifts a resolver's clock can:
- Expire valid RRSIGs → DNSSEC validation fails → zone appears broken
- Accept expired RRSIGs → replay window extended
- Measured as operationally feasible by SIDN Labs (2020) and Malhotra et al. (2019)

**Mitigation**: NTS (Network Time Security, RFC 8915) — cryptographically authenticated NTP. Supported by Chrony 4.0+.

```txt
# /etc/chrony.conf
server time.cloudflare.com iburst nts
server time.nist.gov iburst nts
makestep 1.0 3
rtcsync
```

Deploy NTS on **all** nameserver hosts (primary and secondaries).

### 7.5 Supply Chain Attacks

| Vector | Probability | Impact | Mitigation |
| --- | --- | --- | --- |
| Compromised OS image from VPS provider | 2/5 | 5/5 | Use official distro images; verify checksums |
| Backdoored BIND9 package | 1/5 | 5/5 | Use ISC official packages; Debian reproducible builds |
| Compromised hypervisor at VPS | 1–2/5 | 5/5 | Treat secondaries as untrusted; per-secondary TSIG keys |
| XZ-style supply chain attack (CVE-2024-3094) | 1/5 | 5/5 | Minimal packages; `cargo audit`; distribution packages only |

### 7.6 IPv6 Attack Surface

- **RA spoofing**: Malicious Router Advertisements in shared datacenter L2 can redirect DNS/traffic. Mitigate with `ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j DROP`.
- **IPv6 BGP**: Lower RPKI coverage than IPv4, making IPv6 BGP hijacking easier.
- **Recommendation**: Disable IPv6 on nameservers if not needed. If needed, use static configuration (no SLAAC).

### 7.7 DoH/DoT Resolver Interaction

Major DoH/DoT resolvers (Cloudflare, Google, Quad9) all validate DNSSEC. Users behind these resolvers get DNSSEC protection regardless of their stub resolver configuration. The AD bit in responses confirms validation.

**KeyTrap (CVE-2023-50387)**: A single malicious DNS packet can exhaust a validating resolver's CPU for up to 16 hours. Patched in BIND 9.16.48+, 9.18.24+. Keep BIND9 current.

**DANE (RFC 6698)**: DNSSEC-authenticated TLS certificate pinning via TLSA records. Eliminates dependence on the WebPKI CA hierarchy. Growing adoption in email (SMTP DANE). As of March 2026, CAs must check DNSSEC status during domain validation — closing the BGP hijack + ACME DV certificate attack vector for DNSSEC-signed domains.

## 8. OS Selection for the Primary VM

### 8.1 Candidate Evaluation

| OS | MAC Framework | BIND 9.20 | Support Lifecycle | CIS Benchmark | Verdict |
| --- | --- | --- | --- | --- | --- |
| **Rocky Linux 9** | SELinux (enforcing, `named_t`) | Via ISC repo | 10 years (→ 2032) | v2.0.0 available | **Winner** |
| **Debian Trixie 13** | AppArmor (CrackArmor tainted) | Native (Surý maintains) | ~5 years | None | Runner-up |
| Alpine Linux | None default | Available | ~2 years per release | None | Disqualified (no MAC, no systemd) |
| Arch Linux | None default | Rolling | None | None | Disqualified (rolling = unstable) |
| NixOS | None default | Incomplete module | ~2 years | None | Disqualified (no MAC, incomplete BIND module) |
| Wolfi OS | N/A | N/A | N/A | N/A | Not an OS (container userland only) |

### 8.2 Why Rocky Linux 9

**SELinux is the decisive advantage.** The `named_t` type enforcement policy:
- Confines `named` to labeled directories only
- Prevents arbitrary file reads/writes even with root in the `named` process
- Prevents `execve` of non-DNS binaries
- Operates independently of Unix DAC (root ≠ escape)
- Unaffected by the March 2026 CrackArmor AppArmor vulnerabilities (Qualys TRU)

Additional advantages:
- **FIPS 140-3** validated crypto (CIQ, April 2025) — relevant for NIS2/NIST compliance
- **CIS Benchmark v2.0.0** with automated assessment (CIS-CAT Pro)
- **10-year support** — suitable for long-running infrastructure
- Full **AMD SEV/SME guest support**

**The BIND 9.20 gap**: Rocky ships BIND 9.16 by default (EOL from ISC). Add ISC's official RPM repository for BIND 9.20. This is a signed, supported repository.

### 8.3 Why Not Debian Trixie

Debian Trixie has the **fastest BIND CVE patching** (~24h turnaround, maintained by Ondrej Surý who is also BIND 9 development director at ISC). However:

- **CrackArmor** (Qualys, 12 March 2026): Nine AppArmor vulnerabilities enabling local privilege escalation to root, container escapes, and profile bypass. Affects all AppArmor 3.x/4.x (Debian, Ubuntu, SUSE).
- For a DNSSEC signing key server, "tainted MAC framework" is not acceptable.
- Workaround: Install SELinux on Debian (possible but non-default and less tested).

### 8.4 General Hardening Checklist (Any OS)

**Minimal install**:
- Remove: `at`, `cron`, `postfix`/`sendmail`, `avahi`, `bluetooth`, `cups`, `nfs-utils`, `rpcbind`, `telnet`, `ftp`
- Expected listening services: `sshd`, `named` — nothing else

**systemd service sandboxing for `named`**:

```ini
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_NET_BIND_SERVICE
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
PrivateDevices=yes
ReadWritePaths=/var/named /var/run/named
```

**SSH hardening**: Ed25519 keys only, `PermitRootLogin no`, `PasswordAuthentication no`, non-standard port, access via VPN/jump host only.

**sysctl hardening**:

```ini
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 3
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
```

**File integrity monitoring**: AIDE or Tripwire on `/etc/named/`, `/var/named/`, DNSSEC key files. Alert immediately on any modification.

**auditd** rules for DNSSEC key access, `named.conf` changes, `ptrace` calls, and privilege escalation.

**Automated security updates**: `dnf-automatic` (Rocky) or `unattended-upgrades` (Debian) with security-only policy.

## 9. Consolidated Threat Matrix

| # | Attack Vector | Prob. | Impact | DNSSEC Helps? | Primary Mitigation |
| --- | --- | --- | --- | --- | --- |
| 1 | Registrar compromise → NS+DS change | 3/5 | 5/5 | No (bypassed) | Registry lock + FIDO2 MFA |
| 2 | BGP hijack of secondary NS IPs | 3/5 | 4/5 | Partial (36% protected) | RPKI, multi-ASN secondaries, DNSSEC |
| 3 | Compromised secondary → record manipulation | 2/5 | 4/5 | Yes (validating resolvers) | DNSSEC + monitoring |
| 4 | Compromised secondary → replay old signed data | 2/5 | 3/5 | No | Short RRSIG validity, canary records |
| 5 | DDoS against all secondaries | 4/5 | 3/5 | No | Multi-provider, anycast, high TTLs |
| 6 | NTP manipulation → DNSSEC bypass | 3/5 | 3/5 | Victim | NTS on all hosts |
| 7 | Datacenter MITM on zone transfers | 2/5 | 4/5 | N/A | XoT + TSIG + mTLS |
| 8 | TSIG key extraction → dynamic update injection | 2/5 | 5/5 | Amplifies attack | Separate transfer/update TSIG keys |
| 9 | OS-level compromise of primary | 1/5 | 5/5 | N/A | SELinux, HSM, minimal surface |
| 10 | Supply chain (compromised BIND9/OS) | 1/5 | 5/5 | N/A | Official packages, integrity monitoring |
| 11 | ZSK extraction from primary memory | 1/5 | 5/5 | N/A | HSM (YubiHSM 2) |
| 12 | KeyTrap DoS against public resolvers | 2/5 | 3/5 | Weaponizes DNSSEC | Keep BIND9 patched |
| 13 | IPv6 RA spoofing at datacenter | 3/5 | 2/5 | No | Disable SLAAC, ip6tables RA drop |
| 14 | NSEC/NSEC3 zone walking | 4/5 | 1/5 | Enables it | NSEC3; don't put sensitive names in public zones |

## 10. Prioritized Mitigation Roadmap

### Tier 1 — Immediate, Highest Impact

1. **Registry lock on the domain** — Defeats registrar account compromise for NS/DS changes. The single most impactful control. Contact registrar, verify availability for your TLD, activate with out-of-band verification.

2. **Per-secondary TSIG keys (HMAC-SHA512)** — One key per secondary. Never share. Never list in `allow-update`. Generate: `tsig-keygen -a hmac-sha512 primary-to-ns1.example.com`.

3. **Hardware MFA (FIDO2) on registrar account** — TOTP is phishable. Hardware keys require physical presence.

4. **XoT (TLS 1.3) on all zone transfers** — No cleartext fallback. Private CA or SPKI pinning. Firewall TCP/53 from secondary IPs.

5. **NTS for time synchronization** — Chrony + NTS on all hosts. Prevents NTP manipulation → RRSIG expiry attacks.

### Tier 2 — Important, Medium Effort

6. **DNSSEC monitoring** — Automated DS record checks every 5 minutes from trusted host. CT log monitoring (SSLMate Certspotter). RRSIG expiry monitoring.

7. **BGP monitoring for secondary NS IPs** — Cloudflare Radar, RIPE Stat, or BGPmon. Alert on unexpected origin ASN.

8. **HSM for KSK storage** — YubiHSM 2 via PKCS#11 on primary. Prevents key extraction from compromised OS.

9. **Rocky Linux 9 with SELinux enforcing** — `named_t` type enforcement on primary. ISC repo for BIND 9.20.

10. **Choose VPS providers with RPKI enforcement** — AWS, Azure, DigitalOcean, Vultr. Avoid OVH, Linode, Contabo for secondary NS.

### Tier 3 — Operational Hardening

11. **Canary record monitoring** — `_canary.example.com TXT` with 60s TTL, externally monitored. Detects replay attacks and stale-serving compromised secondaries.

12. **systemd sandboxing for `named`** — `NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet`, `MemoryDenyWriteExecute`.

13. **Offline encrypted KSK backup** — GPG-encrypted, on air-gapped media, two geographically separated copies. Test restoration.

14. **Disable IPv6 or static-only** — Drop ICMPv6 RA on all hosts. Eliminates RA spoofing attack surface.

15. **RRL on all secondaries** — `rate-limit { responses-per-second 15; };` in BIND. Prevents compromised secondary from DDoS amplification.

### Tier 4 — Long-Term Architecture

16. **DANE/TLSA records** — Pin TLS certificates in DNS for mail (SMTP DANE) and web. Eliminates CA dependency for DNSSEC-signed domains.

17. **Multi-provider anycast** — Distribute secondary NS via anycast for DDoS resilience. Commercial (Cloudflare DNS, NS1) or self-operated with portable PI space.

18. **Algorithm agility preparation** — Ensure KASP supports algorithm rollover. Monitor IETF for post-quantum DNSSEC algorithm standardization (expected 2026–2028).

19. **"Sitting Ducks" prevention** — Before decommissioning any secondary VPS, update NS records first. Never leave NS pointing to infrastructure you no longer control.

20. **Warm standby primary** — A secondary that holds key material (via HSM replication) and can be promoted to primary if the primary is destroyed. Reduces KSK recovery time from days to hours.

## 11. Kicksecure Evaluation for BIND9 VM

### 11.1 What is Kicksecure?

Kicksecure is a security-hardened Debian derivative from the Whonix project. It applies opinionated security defaults on top of Debian Trixie via the `security-misc` package (576 stars, 30 contributors, last push 2026-03-14). It is primarily desktop-oriented but supports server deployment via distro-morphing from a minimal Debian Trixie install.

### 11.2 Kicksecure's Genuine Security Advantages

What Kicksecure provides that neither Rocky Linux 9 nor plain Debian ships by default:

| Feature | What It Does | Rocky Default? |
| --- | --- | --- |
| `slab_nomerge` | Reduces heap overflow impact | No |
| `slub_debug=FZ` | Slab sanity checks and red zones | No |
| `init_on_alloc=1 init_on_free=1` | Zeroes memory at alloc/free | No |
| `randomize_kstack_offset=on` | Randomizes kernel stack per syscall | No |
| io_uring disabled | Eliminates major kernel CVE source | No |
| SMT disabled (`nosmt=force`) | Closes Spectre/MDS side channels | No |
| Maximum CPU mitigations | All at strictest level, not `mitigations=auto` | No |
| TCP timestamps disabled | Prevents uptime fingerprinting of hidden primary | No |
| Strict IOMMU (`iommu=force iommu.strict=1`) | Anti-DMA attack enforcement | No |
| jitterentropy | Distrusts CPU RDRAND for entropy | No |
| `kptr_restrict=2` | Hides kernel pointers regardless of privilege | No |
| `kernel.yama.ptrace_scope=3` | Restricts ptrace to root only | No |
| SUID/SGID automated removal | `permission-hardener` strips non-essential SUID bits | No |
| Extensive module blacklisting | FireWire, Thunderbolt, legacy protocols disabled | No |
| `novsyscall` | Disables vsyscalls (ROP mitigation) | No |
| 32-bit process support disabled | Eliminates 32-bit attack surface | No |

### 11.3 Why Kicksecure Is NOT a Replacement for Rocky Linux 9

**Critical weakness: AppArmor (not SELinux)**. Kicksecure uses AppArmor from Debian. CrackArmor (Qualys, March 2026) — nine confused-deputy vulnerabilities enabling privilege escalation to root and profile bypass — directly affects Kicksecure. The `named` AppArmor profile is path-based, not inode-based, making it weaker for daemon containment.

**hardened_malloc is deprecated** (February 2024). The biggest differentiator is gone.

**No CIS Benchmark**, no FIPS 140-3, no SCAP/oscap tooling, ~5-year support lifecycle vs Rocky's 10 years.

Kicksecure's own documentation acknowledges: "SELinux is a lot more secure than AppArmor — more fine-grained, inode-based rather than path-based, capable of filtering kernel ioctls." They chose AppArmor for usability, not security superiority.

### 11.4 Recommended Approach: Rocky Linux 9 + Kicksecure Kernel Hardening

Apply Kicksecure's `security-misc` sysctl and boot parameters on Rocky Linux 9:

**GRUB boot parameters** (`/etc/default/grub`):

```txt
GRUB_CMDLINE_LINUX="... slab_nomerge slub_debug=FZ init_on_alloc=1 \
  init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on \
  novsyscall debugfs=off iommu=force iommu.strict=1 nosmt=force \
  spectre_v2=on spec_store_bypass_disable=on l1tf=full,force \
  mds=full,nosmt"
```

**Sysctl hardening** (`/etc/sysctl.d/99-kicksecure-hardening.conf`):

```ini
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 3
kernel.io_uring_disabled = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
kernel.unprivileged_userns_clone = 0
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
```

**Module blacklist** (`/etc/modprobe.d/security-blacklist.conf`):

```txt
install firewire-core /bin/true
install thunderbolt /bin/true
install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install vivid /bin/true
```

This gives you **SELinux `named_t` containment + KSPP kernel hardening + 10-year support + CIS Benchmark** — the best of both worlds.

## 12. OPSEC Workstation: Hardware and OS Selection

### 12.1 Architecture: QubesOS + Whonix (Combined)

QubesOS (Xen-based compartmentalization) runs Whonix *inside* it as isolated VMs. You get:

- Every activity in a separate VM (browsing, email, banking, work — all isolated)
- Tor routing via sys-whonix gateway for selected VMs
- Disposable VMs: fresh Whonix workstation per anonymous task, discarded after
- Hardware device isolation via VT-d/IOMMU (USB controller in dedicated VM)
- Evil Maid detection via Heads + TPM + Nitrokey HOTP

This is the gold standard. Standalone Whonix on a general hypervisor provides Tor anonymization but not compartmentalization.

**QubesOS requirements**: VT-x, VT-d/IOMMU, TPM 2.0, 32 GB RAM minimum (64 GB ideal), NVMe SSD.

### 12.2 Custom Firmware: Coreboot + Heads

**The problem**: Standard UEFI is millions of lines of proprietary code. Intel ME runs a full Minix OS below your OS with independent network access and DMA. Firmware rootkits (LoJax, MoonBounce, CosmicStrand) survive OS reinstalls. Intel ME CVEs (SA-00086, CVE-2025-20037) allow code execution at ring -3. Evil Maid attacks reflash UEFI to capture disk encryption passphrases.

**Coreboot** replaces proprietary UEFI with auditable open-source firmware. Minimal hardware init, then hands off to a payload.

**Heads** is a security payload on top of Coreboot providing:

- **Measured boot**: Every boot component hashed into TPM PCRs
- **HOTP/TOTP verification**: On each boot, TPM-derived one-time password verified on Nitrokey hardware token. If firmware was tampered with, the code changes — detected before entering disk passphrase
- **Intel ME neutralization**: `me_cleaner` + HAP bit strips ME down to minimal init stub
- **Anti Evil Maid**: The combination detects firmware tampering between boots

**Dasharo** (from 3mdeb) is a professional Coreboot distribution with structured releases, signing, and subscription updates. Used by NovaCustom and Nitrokey.

### 12.3 Hardware Recommendation

**Primary: NovaCustom V54 Series** (~€1,800–2,100)

| Spec | Details |
| --- | --- |
| CPU | Intel Core Ultra 7 155H (Meteor Lake, current gen) |
| RAM | 32–64 GB DDR5 |
| Storage | 1 TB NVMe PCIe Gen4 |
| Firmware | Dasharo Coreboot + **Heads** (Qubes-certified) |
| Intel ME | Neutralized via Dasharo ME management |
| VT-x / VT-d / TPM 2.0 | Yes / Yes / Yes |
| QubesOS | **Officially certified** (Release 4, Sep 2025) |
| Screen | 14", FHD+ or 2.8K |
| Manufacturer | Netherlands (EU), 3-year warranty |

Add a **Nitrokey 3A NFC** (~€55) for HOTP boot verification.

**Runner-up: NitroPad V56** — same Dasharo firmware, same CLEVO chassis, 16" screen, bundled Nitrokey, tamper-evident packaging (~€100 extra). Choose if supply-chain interdiction is in your threat model.

**If hardware kill switches required**: Purism Librem 14 (~$1,500) — physical WiFi/BT and camera/mic kill switches, anti-interdiction service. Trade-off: 2020-era CPU, no official Qubes certification.

### 12.4 MacBook Air M2 — Not Suitable

QubesOS requires Xen (x86 only). Apple Silicon doesn't expose VT-d/IOMMU to user-space hypervisors. Whonix can run in UTM/QEMU on macOS but without compartmentalization. The Secure Enclave is excellent for macOS security but irrelevant for this use case. Keep it for daily non-OPSEC use.

### 12.5 What to Install

1. **QubesOS 4.2+** with LUKS2 full disk encryption
2. **Whonix templates** (sys-whonix gateway + whonix-ws workstation)
3. **Disposable Whonix VMs** for anonymous tasks
4. **Heads HOTP** verification with Nitrokey on every boot
5. **sys-usb** isolated via VT-d (default when IOMMU present)
6. **Separate AppVMs** for each security domain (personal, work, DNS management, banking)

### 12.6 Hardware Security Checklist

- [x] VT-x (hardware virtualization) — required for QubesOS
- [x] VT-d / AMD-Vi (IOMMU) — required for USB VM isolation
- [x] TPM 2.0 — required for Heads HOTP/TOTP
- [x] Coreboot + Heads — tamper-evident boot
- [x] Intel ME neutralized — reduced firmware attack surface
- [ ] Hardware kill switches — Librem 14 only
- [x] 32 GB+ RAM — for QubesOS compartmentalization
- [x] NVMe SSD — for VM I/O performance
- [ ] Anti-interdiction — NitroPad (tamper-evident packaging) or Librem 14 (glitter nail polish + photos)

### 12.7 Alternative Hardware: AMD, Snapdragon, ECC

#### Snapdragon X2 Elite Extreme — Not Viable

Three hard blockers simultaneously: no QubesOS (Xen requires x86), no Coreboot, no Heads. Qualcomm's TrustZone is OEM-controlled with no owner-controlled measured boot. Windows on ARM is the only OS option. Do not consider this platform for OPSEC.

#### AMD Ryzen Pro — Compelling Features, Missing Firmware Security

AMD Ryzen Pro offers two features Intel consumer chips lack:

| Feature | What It Does | Available On |
| --- | --- | --- |
| **AMD Memory Guard (SME)** | Transparent AES-128 RAM encryption, key in Secure Processor | Ryzen Pro 7040/8040/AI 300 mobile |
| **ECC support** | Error-correcting memory at silicon level | Ryzen Pro (but almost no laptop routes ECC pins) |

**The blocker**: As of March 2026, there is **no production-ready Coreboot port for any AMD Ryzen laptop**. The Framework 16 AMD port (9elements + openSIL) is WIP — memory training not yet complete. **Heads has zero AMD laptop support.** There is no `me_cleaner` equivalent for AMD PSP, and AMD Platform Secure Boot (PSB) **fuses the laptop to the OEM's signing key at the silicon level** — you cannot replace or neutralize PSP firmware.

**QubesOS on AMD**: Functional (multiple HCL reports for Framework 13 AMD, ThinkPad T14 AMD) but officially "not recommended" by the Qubes team due to inconsistent security support. AMD-Vi (IOMMU) works. Requires `kernel-latest` and occasional workarounds.

**Xen + AMD SME compatibility**: Not production-validated by Qubes. Open issue #6105 (since 2020). Some users report needing to disable Memory Guard for Qubes stability. This may eliminate AMD's main advantage.

#### ECC RAM in Laptops — The Pin-Routing Problem

Ryzen Pro supports ECC at the silicon level, but almost no laptop motherboard routes the ECC check-bit lines:

| Laptop | ECC? | Notes |
| --- | --- | --- |
| ThinkPad P16 Gen 2 (Xeon W) | **Yes** (confirmed) | Intel Xeon mobile, not Ryzen. ~$2,500+ |
| Dell Precision 7680/7780 (Xeon W) | **Yes** | Desktop-replacement class, 3+ kg, $3,000+ |
| ThinkPad T14s Gen 6 AMD | No | Soldered LPDDR5x, non-ECC |
| Framework 13 AMD | No | ECC pins not routed on mainboard |
| ThinkPad P16v AMD | No | Standard DDR5 only |

**The intersection of ECC + SME + Coreboot/Heads does not exist in any shipping laptop.**

ECC is meaningful for cryptographic workstations (Rowhammer protection, bit-flip integrity), but getting it requires Intel Xeon mobile workstations that don't support Coreboot/Heads either.

#### The Trade-off Matrix

| Feature | Intel + Heads (NovaCustom V54) | AMD Ryzen Pro (no Coreboot) | Snapdragon X2 |
| --- | --- | --- | --- |
| QubesOS | Certified | Community HCL, "not recommended" | Not supported |
| Coreboot/Heads | Yes, production | No (WIP, 12-18 months out) | No |
| ME/PSP neutralization | Yes (me_cleaner + HAP) | No (PSB fuses OEM key to silicon) | No |
| ECC RAM | No | Possible (Xeon workstations only) | No |
| RAM encryption (SME) | No | Yes (Memory Guard, Xen compat. unverified) | TrustZone (OEM-controlled) |
| Evil Maid detection | Yes (Heads + TPM + Nitrokey) | No | No |
| Price | ~€1,400–2,200 | ~€900–1,800 | ~$1,200–1,800 |

#### Verdict: Intel + Heads Remains the Correct Choice

AMD SME is genuinely valuable (cold boot protection is real), but for a maximum-OPSEC workstation:

1. **Coreboot/Heads addresses a threat layer AMD cannot**: pre-boot integrity and physical adversary detection. A sophisticated adversary with 10 minutes of physical access to your NovaCustom V54 will be detected via Heads TPM attestation. The same adversary with a Framework AMD returns it with an undetectable firmware implant.

2. **AMD PSB is worse than neutralized Intel ME**: Intel ME can be partially disabled via me_cleaner. AMD PSP on modern laptops has OEM keys burned into silicon fuses — no owner-controlled firmware path exists.

3. **Xen/SME compatibility is unvalidated** — you may need to disable Memory Guard for Qubes stability, eliminating AMD's one advantage.

**Future watch**: If the Framework 16 AMD Coreboot port reaches production (late 2026/early 2027), and Heads follows, and PSB is off on that hardware generation, then AMD + Coreboot + Heads + Qubes becomes genuinely competitive. That intersection does not exist today.

**Budget option**: Framework 13 AMD (~$900–1,200) running Qubes 4.2 is workable for threat models focused on remote adversaries. Accept that you trust AMD PSP and Framework's firmware supply chain. Use LUKS2, enable UEFI Secure Boot with custom keys, and understand Evil Maid detection is not available.

### 12.8 Revised Architecture: EPYC Homeserver + MacBook Thin Client

**Threat model clarification**: The primary physical threat is **device seizure** (forceful removal with unlimited subsequent access), NOT Evil Maid (tamper and return). This fundamentally changes the hardware recommendation.

**Key insight**: A laptop you carry around is the worst form factor for a seizure threat model. A homeserver you access remotely means the OPSEC workstation never leaves your controlled physical location.

#### Why This Architecture Is Superior

| Concern | Security Laptop (any) | EPYC Homeserver + MacBook Thin Client |
| --- | --- | --- |
| Seizure risk | High (portable, border crossings, raids) | MacBook: contains nothing. Server: in your home |
| Cold boot attack | Laptop RAM is accessible | Server in locked location; MacBook has no secrets |
| ECC RAM | Almost impossible in laptops | Already present on EPYC |
| RAM encryption | AMD mobile SME only | SEV-ES (per-VM, stronger than SME) |
| Compartmentalization | QubesOS (specific hardware required) | KVM/libvirt with SEV — each VM independently encrypted |
| Performance | Limited by laptop thermal/power | EPYC = massively more cores, RAM, I/O |
| Cost | €1,500–2,200 for new security laptop | €0 — hardware already owned |

#### Architecture Diagram

```txt
┌─────────────────┐     WireGuard/SSH      ┌──────────────────────────┐
│  MacBook Air M2  │ ◄──────────────────► │  EPYC 2nd Gen Homeserver  │
│  (thin client)   │     + YubiKey         │  ECC RAM + SEV-ES         │
│  No sensitive    │                       │  LUKS2 host encryption    │
│  data on disk    │                       │                            │
│                  │                       │  ┌──────────────────────┐ │
│                  │                       │  │ OPSEC VM (Whonix)    │ │
│                  │                       │  │ SEV-encrypted memory │ │
│                  │                       │  └──────────────────────┘ │
│                  │                       │  ┌──────────────────────┐ │
│                  │                       │  │ DNS Management VM    │ │
│                  │                       │  │ bind9-sdk, rndc keys │ │
│                  │                       │  └──────────────────────┘ │
│                  │                       │  ┌──────────────────────┐ │
│                  │                       │  │ General Work VM      │ │
│                  │                       │  └──────────────────────┘ │
└─────────────────┘                       └──────────────────────────┘
```

#### EPYC Server Configuration

- **Host OS**: Rocky Linux 9 (SELinux enforcing) or Debian Trixie — minimal, runs only libvirt/KVM
- **SEV-ES**: Enable per-VM in libvirt XML (`<launchSecurity type="sev">`)
- **LUKS2**: Full disk encryption on host and all VM disk images
- **Firewall**: No inbound except WireGuard VPN port (single UDP port)
- **VMs**: Whonix Gateway + Workstation, DNS Management, General Work — each SEV-encrypted independently
- **Kicksecure kernel hardening** on host (sysctl + boot params from §11.4)

#### MacBook M2 Configuration

- **WireGuard VPN** to homeserver (single UDP port, modern crypto, minimal attack surface)
- **SSH with YubiKey FIDO2 resident key** — no SSH private key on MacBook disk at all
- **Optional Tor routing**: `torsocks ssh ...` for network-level anonymity (server IP never exposed)
- **No sensitive data on disk** — MacBook is a window, not a vault
- **If seized**: Attacker gets a MacBook with a WireGuard config (requires YubiKey they don't have) and nothing else

#### Remote Access Hardening

- **WireGuard** (not OpenVPN) — smallest attack surface
- **SSH**: Ed25519 or FIDO2 keys only, `PasswordAuthentication no`, `AllowUsers` restricted
- **Tor hidden service** (`.onion`) for SSH — server IP never exposed, no DNS, no cleartext metadata
- **Dead-man switch**: If server unreachable for X hours, auto-shutdown VMs (keys die with power)
- **No suspend on server VMs** — always full shutdown when not in use (SEV keys live only in running state)

#### The One Weakness: Network Dependency

Cannot work offline. Mitigations:
- Redundant internet on server (primary + LTE failover)
- MacBook handles non-sensitive work locally
- For truly critical offline OPSEC: keep a Framework 13 AMD (~$1,000) as emergency fallback with Whonix

#### EPYC 2nd Gen (Rome) SEV Capabilities

| Feature | Status | Protection |
| --- | --- | --- |
| SME (system-wide RAM encryption) | Supported | Cold boot attack protection |
| SEV (per-VM memory encryption) | Supported | VM memory opaque to hypervisor |
| SEV-ES (encrypted state) | Supported | VM register state also encrypted |
| SEV-SNP (secure nested paging) | Not supported (3rd gen Milan+) | N/A — but SEV-ES is sufficient |
| ECC RAM | Present | Rowhammer protection, bit-flip integrity |

**This is the recommended OPSEC architecture.** It leverages hardware you already own, provides stronger protection than any purchasable laptop, and costs nothing additional.

## 13. Sources

### Academic Papers

- Yan, Osterweil et al., "Limiting Replay Vulnerabilities in DNSSEC," Colorado State / UCLA, NPSEC 2008
- Zhang et al., "Proving DNSSEC Correctness: A Formal Approach," arXiv:2512.11431, December 2025
- Zhang et al., "Your Shield is My Sword: RUC Attack," USENIX Security 2025
- Heftrig, Schulmann et al., "KeyTrap: Algorithmic Complexity Attacks on DNSSEC," ATHENE, February 2024
- Heftrig, Shulman, Waidner, "Downgrading DNSSEC," USENIX Security 2023
- Malhotra et al., "The Impact of Time on DNS Security," IACR ePrint 2019/788
- Chung, Harvey, Kaliski et al., "Post-Quantum Diversity for DNSSEC," Verisign/ISC/NLnet Labs, NIST PQC Conference August 2025
- Schutijser et al., "Evaluating Post-Quantum Cryptography in DNSSEC Signing," SIDN Labs, TMA 2025
- Hetzner et al., "SEVered: Subverting AMD's Virtual Machine Encryption," EuroSec 2018
- WeSee (IEEE S&P 2024, ETH Zurich), Heracles (CCS 2025), RMPocalypse (CCS 2025), CounterSEVeillance (NDSS 2025)
- StackWarp CVE-2025-29943 (Rescana, January 2026)

### RFCs

- RFC 4033–4035: DNSSEC Introduction, Records, Protocol Modifications
- RFC 6781: DNSSEC Operational Practices v2
- RFC 8945: TSIG (obsoletes RFC 2845)
- RFC 9103: DNS Zone Transfer over TLS (XoT)
- RFC 8915: Network Time Security (NTS)
- RFC 7344/8078: CDS/CDNSKEY Automated Trust Maintenance
- RFC 9904: DNSSEC Algorithm Implementation Requirements (November 2025)
- RFC 5155: NSEC3; RFC 9276: NSEC3 Guidance (deprecating high iterations)

### Industry Reports and Advisories

- APNIC Labs DNSSEC validation statistics, February–March 2026
- APNIC / ICANN 82 DNSSEC Workshop, March 2025 (per-country validation rates)
- Cisco Talos, "Sea Turtle DNS Hijacking," April/July 2019
- Internet Society, "Amazon Route 53 BGP Hijack," April 2018
- SIDN Labs, "Accurate, secure system time is vital for DNSSEC," February 2020
- Cloudflare, "Remediating new DNSSEC resource exhaustion vulnerabilities," February 2024
- Cloudflare, "How Cloudflare auto-mitigated world record 3.8 Tbps DDoS attack," October 2024
- Qualys TRU, "CrackArmor: Critical AppArmor Flaws," March 12, 2026
- CIQ, "FIPS 140-3 Compliance for Rocky Linux," April 2025
- Trail of Bits, LUKS2 Confidential VM vulnerabilities, October 2025
- ISC BIND9 Security Configurations: bind9.readthedocs.io chapter 7
- ISC KASP documentation: kb.isc.org/docs/dnssec-key-and-signing-policy
- CIS Rocky Linux 9 Benchmark v2.0.0
- RPKI deployment: Job Snijders, APNIC Blog, February 2026; RIPE Labs, January 2025
- RPKI provider enforcement survey: Rohith Kumar Ankam, August 2025
- Root KSK-2024 rollover: Verisign Blog, Duane Wessels, March 2025
- Infoblox/Eclypsium, "Sitting Ducks" domain hijacking, November 2024

### Kicksecure and OPSEC Sources

- Kicksecure `security-misc` GitHub: github.com/Kicksecure/security-misc
- Kicksecure hardened_malloc deprecation (Feb 2024): kicksecure.com/wiki/Hardened_Malloc (archived)
- Kicksecure AppArmor assessment: kicksecure.com/wiki/AppArmor (madaidan quote on SELinux superiority)
- CrackArmor (Qualys TRU, March 2026): qualys.com/blog/vulnerabilities-threat-research/2026/03/12/crackarmor
- KSPP Recommended Settings: kspp.github.io/Recommended_Settings
- QubesOS certified hardware list: qubes-os.org/doc/certified-hardware (Sep 2025)
- NovaCustom V54/V56 Heads certification: qubes-os.org/news/2025/05/20
- NitroPad V54/V56 with Heads: nitrokey.com/news/2024
- Purism Librem 14: puri.sm/products/librem-14
- Star Labs StarBook QubesOS certification: qubes-os.org/doc/certified-hardware/starlabs-starbook
- Intel ME SA-00086 (2017), CVE-2025-20037 (2025): zeropath.com/blog/cve-2025-20037
- Coreboot project: coreboot.org
- Heads firmware: github.com/osresearch/heads
- Framework 16 AMD Coreboot+openSIL port (9elements, March 2026): phoronix.com/news/Framework-16-Coreboot-openSIL
- AMD PRO Technologies Security Whitepaper (Feb 2025): amd.com/en/documents/products/processors/technologies
- IOActive Labs, AMD PSB analysis (Feb 2024): labs.ioactive.com/2024/02/exploring-amd-platform-secure-boot
- PSPReverse/PSPTool: github.com/PSPReverse/PSPTool
- mkopec/psb_status (AMD PSB fuse detection): github.com/mkopec/psb_status
- Qubes AMD IOMMU issue #9030 (Framework AMD): github.com/QubesOS/qubes-issues/issues/9030
- Qubes AMD SEV/SME issue #6105: github.com/QubesOS/qubes-issues/issues/6105
- Linux kernel AMD memory encryption docs: docs.kernel.org/x86/amd-memory-encryption.html
