<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
-->

# Security Policy

## Reporting a Vulnerability

**Do not open a public issue.**

**Preferred:** Use GitHub's private vulnerability reporting — click
**"Report a vulnerability"** on the
[Security tab](../../security/advisories/new) of this repository. This
creates a private advisory draft with a CVE workflow.

**Alternative:** Email [me@sephy.io](mailto:me@sephy.io) with details.

Include as much detail as possible:

- Description of the vulnerability
- Steps to reproduce
- Affected component (core, net, CLI, bindings)
- Potential impact

You will receive an acknowledgment within 7 days. Fixes for confirmed
vulnerabilities will be released as patch versions with a security advisory.

## Scope

Security issues in the following areas are in scope:

- TSIG key material exposure or mishandling
- DNS wire format parsing (buffer overflows, panics on malformed input)
- rndc authentication bypass or protocol vulnerabilities
- TLS configuration weaknesses
- napi-rs FFI boundary safety
- Dependency vulnerabilities (RustCrypto, rustls, tokio)
