<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

# bind9-sdk fuzzing (FR-061)

`cargo-fuzz` (libFuzzer) targets for every untrusted-input parser in the SDK.
This is a **detached** workspace (note the empty `[workspace]` table in
`Cargo.toml`) so the parent workspace and the stable MSRV build never attempt
to compile libFuzzer targets, which require a nightly toolchain.

## Targets

| Target | Entry point | Input |
| --- | --- | --- |
| `fuzz_zone_parser` | `bind9_sdk_core::fuzz::zone` | RFC 1035 master file |
| `fuzz_zone_roundtrip` | `bind9_sdk_core::fuzz::zone_roundtrip` | parse→serialize→parse idempotence |
| `fuzz_named_conf` | `bind9_sdk_core::fuzz::named_conf` | bounded `named.conf` |
| `fuzz_tsig_wire` | `bind9_sdk_core::fuzz::tsig_wire` | TSIG RR wire bytes |
| `fuzz_rndc_response` | `bind9_sdk_net::fuzz::rndc_response` | rndc ISC control message |
| `fuzz_stats_json` | `bind9_sdk_net::fuzz::stats_json` | statistics-channel JSON |
| `fuzz_transfer_wire` | `bind9_sdk_net::fuzz::transfer_wire` | AXFR/IXFR DNS wire |
| `fuzz_update_response` | `bind9_sdk_net::fuzz::update_response` | nsupdate DNS response |

The entry points live behind the `fuzzing` feature of `bind9-sdk-core` and
`bind9-sdk-net`. They are deliberately **not** semver-stable.

## Running

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_zone_parser            # run until a crash
cargo +nightly fuzz run fuzz_zone_parser -- -max_total_time=60   # bounded
```

Seed corpora live in `corpus/<target>/` and are seeded from the live BIND 9.20
fixtures under `tests/bind9/`.

## Regression policy

Every fuzz-discovered crash MUST be:

1. Saved as a reproducer under `artifacts/<target>/`.
2. Added as an adversarial input to the in-crate `--features fuzzing`
   regression tests (`crates/*/src/fuzz.rs`), which run in normal CI via
   `cargo test --features fuzzing`.
3. Fixed in the parser.

## Release gate

CI runs a **bounded** smoke fuzz (`-max_total_time=30` per target) on every
push. The PRD FR-061 acceptance criterion of a **24-hour clean run per target**
is a manual pre-`v1.0.0` release gate and is **not** satisfied by the CI smoke
run. Do not mark FR-061 fully complete until a real 24h run is recorded here.
