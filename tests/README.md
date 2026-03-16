<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Integration Tests

## BIND9 Test Instance

Integration and end-to-end tests require a live BIND9 9.20 instance. A containerized setup is provided under `tests/bind9/`.

### Starting the Test Server

```bash
cd tests/bind9
podman-compose up -d
```

Or with Docker:

```bash
cd tests/bind9
docker compose up -d
```

Allow approximately 3 seconds for BIND9 to become ready before running tests. The compose file includes a healthcheck that polls `rndc status` every 2 seconds.

### Running Integration Tests

Integration tests are marked with `#[ignore]` and excluded from the default `cargo test` run. Once the BIND9 container is healthy:

```bash
cargo test --workspace -- --ignored
```

### Stopping the Test Server

```bash
cd tests/bind9
podman-compose down
```

Or with Docker:

```bash
cd tests/bind9
docker compose down
```

## Test BIND9 Configuration

### Ports

| Port | Protocol | Service |
| --- | --- | --- |
| 15353 | UDP/TCP | DNS queries (mapped from container port 53) |
| 9953 | TCP | rndc control channel (mapped from container port 953) |
| 8053 | TCP | Statistics channel (JSON) |

All ports are bound to `127.0.0.1` only.

### rndc Test Key

| Property | Value |
| --- | --- |
| Key name | `rndc-test-key` |
| Algorithm | hmac-sha256 |
| Secret (base64) | `dGVzdGtleWZvcmJpbmQ5c2RrdGVzdGluZzEyMzQ1Ng==` |

This key is used for both the rndc control channel and for dynamic updates (`allow-update`) on the `example.com` zone.

### Zones

| Zone | Type | File |
| --- | --- | --- |
| `example.com` | primary | `zones/example.com.zone` |

The `example.com` zone is configured with `allow-update` using the test key, enabling RFC 2136 dynamic update testing.

## Security Note

The test key secret is intentionally committed to the repository. It is a deterministic test-only value and must never be used in production. The container binds exclusively to localhost.
