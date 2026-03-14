<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# 🌐 bind9-sdk &emsp; ![MSRV] ![License]

[MSRV]: https://img.shields.io/badge/MSRV-1.94-orange.svg
[License]: https://img.shields.io/badge/license-TBD-yellow.svg

**The BIND9 management SDK that should have existed a decade ago.**

> [!CAUTION]
> This project is in its very early stages. I decided to share it from the beginning anyway. If you're interested in contributing, feel free to reach out — contact info is on [my profile](https://github.com/Sephyi).

A Rust-native library for programmatic BIND9 DNS server management. Implements the full rndc wire protocol, RFC 1035 zone file parsing, RFC 2136 dynamic updates (nsupdate), IXFR/AXFR zone transfers, and the BIND9 statistics-channel JSON API — all with zero shell subprocess dependencies.

Ships as three coordinated artifacts from one codebase: a **Rust crate** on crates.io, a **browser WASM bundle** via wasm-pack, and a **Node.js native addon** via napi-rs.

## 🛡️ Compliance & Security

Designed to meet GDPR, NIS2, NIST SP 800-53/800-81/800-57, ISO 27001:2022, and SOC 2 Type II requirements for DNS infrastructure. Secure defaults out of the box.

- **Authentication** — No anonymous rndc. TSIG secrets zeroized on drop, never in logs or errors.
- **Transport** — XoT for non-localhost transfers. TLS 1.3 only. Strict cert validation default.
- **DNSSEC** — All IANA algorithms (8–16). Ed25519 default. KSK rollover safety gates.
- **Logging** — Tamper-evident structured JSON. Forward-integrity ratchet. SIEM-ready.
- **GDPR** — No IP-attributable data logged by default. Personal data fields documented.
- **Supply Chain** — SBOM per release. `cargo audit` in CI. `#![forbid(unsafe_code)]` in core.
- **Defaults** — HMAC-MD5 rejected. HMAC-SHA1 warns. HMAC-SHA512 default.

## 💛 Sponsor

If you find bind9-sdk useful, consider [**sponsoring my work**](https://github.com/sponsors/Sephyi).

## 📄 License

License not yet decided. The codebase currently carries PolyForm-Noncommercial-1.0.0 headers as a placeholder.

Copyright 2026 [Sephyi](https://sephy.io)
