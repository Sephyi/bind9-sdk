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
        /// Primary name server for the zone.
        mname: DomainName,
        /// Mailbox of the zone administrator (encoded as a domain name).
        rname: DomainName,
        /// Zone serial number; must increase on every change.
        serial: Serial,
        /// Interval (seconds) before a secondary should refresh from primary.
        refresh: Ttl,
        /// Interval (seconds) before a secondary retries a failed refresh.
        retry: Ttl,
        /// Maximum time (seconds) a secondary may serve stale data if primary unreachable.
        expire: Ttl,
        /// Negative caching TTL (RFC 2308): minimum TTL for NXDOMAIN/NODATA responses.
        minimum: Ttl,
    },

    /// MX record — mail exchange (RFC 1035)
    Mx {
        /// Priority value — lower is preferred when multiple MX records exist.
        preference: u16,
        /// Hostname of the mail server.
        exchange: DomainName,
    },

    /// TXT record — text strings (RFC 1035)
    ///
    /// Each element is one character-string (max 255 bytes each).
    Txt(Vec<String>),

    /// SRV record — service locator (RFC 2782)
    Srv {
        /// Selection priority; lower values are preferred.
        priority: u16,
        /// Relative weight for load balancing among equal-priority targets.
        weight: u16,
        /// TCP or UDP port on the target host.
        port: u16,
        /// Domain name of the host providing the service.
        target: DomainName,
    },

    /// CAA record — certification authority authorization (RFC 8659)
    Caa {
        /// Flags byte; bit 0 (Issuer Critical) is the only defined flag.
        flags: u8,
        /// Property tag (`"issue"`, `"issuewild"`, or `"iodef"`).
        tag: String,
        /// Property value (CA domain or contact URI).
        value: String,
    },

    /// DNSKEY record — public key for DNSSEC (RFC 4034)
    Dnskey {
        /// Flags field: Zone Key (bit 7) and Secure Entry Point (bit 15).
        flags: u16,
        /// Protocol field; always 3 per RFC 4034.
        protocol: u8,
        /// IANA algorithm number (e.g., 13 = ECDSA P-256 / SHA-256).
        algorithm: u8,
        /// Raw public key material (base64-decoded).
        public_key: Vec<u8>,
    },

    /// RRSIG record — signature over an RRset (RFC 4034)
    Rrsig {
        /// Record type this RRSIG covers.
        type_covered: u16,
        /// IANA algorithm number used to create the signature.
        algorithm: u8,
        /// Number of labels in the original SIGNER'S NAME field.
        labels: u8,
        /// Original TTL of the covered RRset.
        original_ttl: u32,
        /// Signature expiration time (Unix timestamp).
        signature_expiration: u32,
        /// Signature inception time (Unix timestamp).
        signature_inception: u32,
        /// Key tag identifying the DNSKEY that signed this RRset.
        key_tag: u16,
        /// Domain name of the signing zone.
        signer_name: DomainName,
        /// Cryptographic signature bytes.
        signature: Vec<u8>,
    },

    /// NSEC record — authenticated denial of existence (RFC 4034)
    Nsec {
        /// Next owner name in canonical order for the zone.
        next_domain: DomainName,
        /// Bitmap of RR types present at this owner name.
        type_bitmaps: Vec<u8>,
    },

    /// NSEC3 record — hashed authenticated denial (RFC 5155)
    Nsec3 {
        /// Hash algorithm identifier (1 = SHA-1).
        hash_algorithm: u8,
        /// Flags byte; bit 0 = Opt-Out.
        flags: u8,
        /// Number of additional hash iterations.
        iterations: u16,
        /// Random salt appended before hashing.
        salt: Vec<u8>,
        /// Base32hex-decoded hash of the next owner name.
        next_hashed_owner: Vec<u8>,
        /// Bitmap of RR types present at this hashed owner.
        type_bitmaps: Vec<u8>,
    },

    /// DS record — delegation signer (RFC 4034)
    Ds {
        /// Key tag of the referenced DNSKEY.
        key_tag: u16,
        /// Algorithm of the referenced DNSKEY.
        algorithm: u8,
        /// Digest algorithm used (1 = SHA-1, 2 = SHA-256, 4 = SHA-384).
        digest_type: u8,
        /// Cryptographic digest of the DNSKEY record.
        digest: Vec<u8>,
    },

    /// CDS record — child DS for automated rollover (RFC 7344)
    Cds {
        /// Key tag of the referenced DNSKEY.
        key_tag: u16,
        /// Algorithm of the referenced DNSKEY.
        algorithm: u8,
        /// Digest algorithm used.
        digest_type: u8,
        /// Cryptographic digest of the DNSKEY record.
        digest: Vec<u8>,
    },

    /// CDNSKEY record — child DNSKEY for automated rollover (RFC 7344)
    Cdnskey {
        /// Flags field mirroring the parent DNSKEY.
        flags: u16,
        /// Protocol field; always 3.
        protocol: u8,
        /// IANA algorithm number.
        algorithm: u8,
        /// Raw public key material.
        public_key: Vec<u8>,
    },

    /// TLSA record — TLS certificate association (RFC 6698)
    Tlsa {
        /// Certificate usage field (0–3).
        usage: u8,
        /// Selector field: full certificate (0) or public key (1).
        selector: u8,
        /// Matching type: full data (0), SHA-256 (1), or SHA-512 (2).
        matching_type: u8,
        /// Certificate association data.
        certificate_data: Vec<u8>,
    },

    /// SSHFP record — SSH host key fingerprint (RFC 4255)
    Sshfp {
        /// Public key algorithm (1 = RSA, 2 = DSA, 3 = ECDSA, 4 = Ed25519).
        algorithm: u8,
        /// Fingerprint type (1 = SHA-1, 2 = SHA-256).
        fp_type: u8,
        /// Fingerprint bytes.
        fingerprint: Vec<u8>,
    },

    /// CSYNC record — child-to-parent synchronization (RFC 7477)
    Csync {
        /// SOA serial of the child zone at the time of this record.
        soa_serial: u32,
        /// Flags (bit 0 = Immediate, bit 1 = soaminimum).
        flags: u16,
        /// Bitmap of RR types the parent should import from the child.
        type_bitmaps: Vec<u8>,
    },

    /// RP record — responsible person (RFC 1183)
    ///
    /// GDPR note: `mbox` contains a mailbox URI (personal data per GDPR Art. 4(1)).
    Rp {
        /// Mailbox of the responsible person, encoded as a domain name.
        mbox: DomainName,
        /// Domain name of a TXT record with additional contact information.
        txt: DomainName,
    },

    /// Unknown record type — raw RDATA preserved as bytes.
    Unknown {
        /// The IANA numeric record type code.
        rtype: u16,
        /// Raw RDATA bytes, unparsed.
        rdata: Vec<u8>,
    },
}

#[cfg(test)]
mod tests;
