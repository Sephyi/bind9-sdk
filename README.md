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

## 💛 Sponsor

If you find bind9-sdk useful, consider [**sponsoring my work**](https://github.com/sponsors/Sephyi).

## 📄 License

License not yet decided. The codebase currently carries PolyForm-Noncommercial-1.0.0 headers as a placeholder.

Copyright 2026 [Sephyi](https://sephy.io)
