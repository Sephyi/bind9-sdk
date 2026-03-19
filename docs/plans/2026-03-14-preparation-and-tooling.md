<!--
SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
-->

# Preparation & Tooling Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update toolchain, dependencies, hooks, agents, PRD, and CLAUDE.md to prepare for Phase 1 implementation.

**Architecture:** Config-first approach — update toolchain and deps first, then add guardrail hooks to enforce standards, then update documentation (agents, PRD, CLAUDE.md). Every step is verified before committing.

**Tech Stack:** Rust 1.94.0 (edition 2024), Cargo workspace, bash hooks, markdown agent definitions.

**Spec:** `docs/specs/2026-03-14-preparation-and-tooling-design.md`

## File Map

| Action | File | Responsibility |
| --- | --- | --- |
| Modify | `rust-toolchain.toml` | Pin Rust 1.94.0 |
| Modify | `Cargo.toml` | Workspace deps, rust-version, remove resolver |
| Modify | `bind9-sdk/Cargo.toml` | Add `parallel` feature |
| Modify | `crates/bind9-sdk-core/Cargo.toml` | Add `parallel`, `zeroize` deps |
| Modify | `crates/bind9-sdk-net/Cargo.toml` | No changes (deps already correct) |
| Modify | `crates/bind9-sdk-bindings/Cargo.toml` | Update description, remove wasm-bindgen, note napi v3 |
| Create | `.claude/hooks/wasm-check.sh` | PostToolUse: no_std validation |
| Create | `.claude/hooks/clippy-gate.sh` | PostToolUse: clippy per-crate |
| Create | `.claude/hooks/spdx-header-check.sh` | PreToolUse: SPDX header enforcement |
| Create | `.claude/hooks/edition-check.sh` | PreToolUse: edition 2024 in new Cargo.toml |
| Create | `.claude/hooks/dep-freshness.sh` | PostToolUse: dep version warnings |
| Create | `.claude/known-dep-versions.toml` | Reference versions for dep-freshness |
| Modify | `.claude/settings.json` | Register all new hooks |
| Rewrite | `.claude/agents/rust-security-reviewer.md` | bind9-sdk security checks + compliance |
| Rewrite | `.claude/agents/api-compat-reviewer.md` | bind9-sdk API compat checks |
| Create | `.claude/agents/rfc-compliance-checker.md` | RFC requirement verification |
| Create | `.claude/agents/dnssec-security-auditor.md` | DNSSEC key management audit |
| Modify | `PRD.md` | RFC fixes, compliance section, security arch |
| Modify | `CLAUDE.md` | Updated agents, hooks, commands, compliance |

## Chunk 1: Toolchain & Dependencies

### Task 1: Update rust-toolchain.toml

**Files:**
- Modify: `rust-toolchain.toml:6`

- [ ] **Step 1: Pin channel to 1.94.0**

Change line 6 from `channel = "stable"` to `channel = "1.94.0"`:

```toml
[toolchain]
channel = "1.94.0"
components = ["rustfmt", "clippy"]
targets = ["wasm32-unknown-unknown"]
```

- [ ] **Step 2: Verify toolchain installs**

Run: `cd "/Users/sephyi/Library/Mobile Documents/com~apple~CloudDocs/Development/bind9-sdk" && rustup show active-toolchain`
Expected: `1.94.0-aarch64-apple-darwin` (or similar with 1.94.0)

If Rust 1.94.0 is not yet released (check with `rustup check`), use the latest stable available and add a comment in the file noting the target.

- [ ] **Step 3: Commit**

```bash
git add rust-toolchain.toml
git commit -m "chore: pin rust toolchain to 1.94.0"
```

### Task 2: Update workspace Cargo.toml

**Files:**
- Modify: `Cargo.toml:6,20,22-46`

- [ ] **Step 1: Remove resolver and update rust-version**

Remove `resolver = "2"` (line 6) — edition 2024 defaults to resolver 3. Update `rust-version` (line 20) from `"1.85"` to `"1.94"`.

Lines 1-4 (SPDX header) are unchanged. After edit, lines 5-20 should read:

```toml
[workspace]
members = [
    "bind9-sdk",
    "crates/bind9-sdk-core",
    "crates/bind9-sdk-net",
    "crates/bind9-sdk-bindings",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
authors = ["Sephyi <me@sephy.io>"]
license = "AGPL-3.0-only OR LicenseRef-Commercial"
repository = "https://github.com/sephyi/bind9-sdk"
rust-version = "1.94"
```

- [ ] **Step 2: Update workspace dependencies**

Replace the entire `[workspace.dependencies]` section (lines 22-46) with:

```toml
[workspace.dependencies]
# Internal crates
bind9-sdk-core = { path = "crates/bind9-sdk-core", version = "0.1.0" }
bind9-sdk-net = { path = "crates/bind9-sdk-net", version = "0.1.0" }

# Crypto — RustCrypto, no_std compatible
hmac = { version = "0.12", default-features = false }
sha2 = { version = "0.10", default-features = false }
digest = { version = "0.10", default-features = false }

# Serialization — core uses no_std subset, net layer uses std
serde = { version = "1", default-features = false, features = ["derive", "alloc"] }
serde_json = { version = "1" }

# Async runtime (net layer and above only)
tokio = { version = "1.50", features = ["full"] }

# Data parallelism (optional, std only — not available in WASM)
rayon = { version = "1.11" }

# HTTP client for statistics-channel (net layer)
reqwest = { version = "0.13", default-features = false, features = ["json", "rustls-tls"] }

# Error handling — thiserror 2.x supports no_std via default-features = false
thiserror = { version = "2", default-features = false }

# Logging
tracing = { version = "0.1" }

# Secret zeroization — no_std compatible (consumed by bind9-sdk-core for TsigKey and key material types)
zeroize = { version = "1", default-features = false, features = ["derive"] }

# Testing (consumed via [dev-dependencies] in each crate)
proptest = { version = "1.10" }
insta = { version = "1.46" }
```

Note: `tokio` version bumped to `1.50`, `reqwest` bumped to `0.13` (breaking change from 0.12). `rayon`, `zeroize`, `proptest`, `insta` are new additions. `rayon` has no `optional = true` at workspace level — optionality is handled per-crate via feature gates.

**Version fallbacks**: These versions were verified as of 2026-03-14. If any do not resolve:
- `tokio 1.50` → use `tokio = { version = "1", features = ["full"] }` (any 1.x)
- `reqwest 0.13` → keep `reqwest = { version = "0.12", ... }` and note the 0.13 bump is deferred
- `proptest 1.10` → use `proptest = { version = "1" }`
- `insta 1.46` → use `insta = { version = "1" }`

- [ ] **Step 3: Run `cargo update` to resolve new dep versions**

Run: `cargo update`
Expected: Lockfile updated with new versions. No errors.

- [ ] **Step 4: Run `cargo check --workspace`**

Run: `cargo check --workspace`
Expected: Compiles with no errors.

If `reqwest 0.13` or `tokio 1.50` do not resolve, adjust versions downward to the actual latest and re-run.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: update workspace deps — reqwest 0.13, rayon, zeroize, proptest, insta"
```

### Task 3: Update individual crate Cargo.toml files

**Files:**
- Modify: `bind9-sdk/Cargo.toml:15-19`
- Modify: `crates/bind9-sdk-core/Cargo.toml:15-27`
- Modify: `crates/bind9-sdk-bindings/Cargo.toml:7,18-38`

- [ ] **Step 1: Add `parallel` feature to bind9-sdk re-export crate**

In `bind9-sdk/Cargo.toml`, add the `parallel` feature after the `net` feature (line 19):

```toml
[features]
default = ["net"]
# Network layer: rndc TCP client, nsupdate sender, IXFR/AXFR, statistics HTTP client
net = ["dep:bind9-sdk-net"]
# Data parallelism: Rayon-based parallel zone parsing (implies std; incompatible with WASM)
parallel = ["bind9-sdk-core/parallel", "dep:rayon"]

[dependencies]
bind9-sdk-core = { workspace = true, features = ["std"] }
bind9-sdk-net = { workspace = true, optional = true }
rayon = { workspace = true, optional = true }
```

- [ ] **Step 2: Add `parallel` feature and `zeroize` to bind9-sdk-core**

In `crates/bind9-sdk-core/Cargo.toml`, update features and deps:

```toml
[features]
default = []
# Enables std::error::Error impls and std-dependent utilities
std = ["thiserror/std", "serde?/std"]  # Note: spec §2.4 shows std = [] but existing thiserror/serde forwarding is needed for correct std::error::Error impls. Retained.
# Enables serde Serialize/Deserialize on DNS types
serde = ["dep:serde"]
# Enables Rayon-based parallel zone parsing (implies std; incompatible with WASM)
parallel = ["std", "dep:rayon"]

[dependencies]
hmac = { workspace = true }
sha2 = { workspace = true }
digest = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true, optional = true }
zeroize = { workspace = true }
rayon = { workspace = true, optional = true }
```

- [ ] **Step 3: Update bind9-sdk-bindings — remove wasm-bindgen, note napi v3 pending**

In `crates/bind9-sdk-bindings/Cargo.toml`, update description and remove wasm-bindgen:

```toml
[package]
name = "bind9-sdk-bindings"
description = "Node.js and Bun native bindings for bind9-sdk via napi-rs v3"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[lib]
crate-type = ["cdylib", "rlib"]

[features]
default = []
# Node.js/Bun native addon via napi-rs (full surface including rndc/IXFR/nsupdate)
# NOTE: napi v2 → v3 migration happens in Phase 4. Pinned at v2 until then.
nodejs = ["dep:napi", "dep:napi-derive", "dep:bind9-sdk-net"]

[dependencies]
bind9-sdk-core = { workspace = true }
bind9-sdk-net = { workspace = true, optional = true }

[dependencies.napi]
version = "2"
optional = true

[dependencies.napi-derive]
version = "2"
optional = true
```

Key changes: removed `browser` feature, `wasm-bindgen` dep, and the `[target.'cfg(target_arch = "wasm32")'.dependencies]` section entirely. Updated description.

- [ ] **Step 4: Verify workspace builds**

Run: `cargo check --workspace`
Expected: Compiles with no errors.

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Compiles (no_std core must not depend on std-only deps).

- [ ] **Step 5: Commit**

```bash
git add bind9-sdk/Cargo.toml crates/bind9-sdk-core/Cargo.toml crates/bind9-sdk-bindings/Cargo.toml
git commit -m "chore: update crate features — add parallel/zeroize, remove wasm-bindgen"
```

### Task 4: Remove stale llm-prompt-quality-reviewer agent (if present)

**Files:**
- Delete: `.claude/agents/llm-prompt-quality-reviewer.md` (may not exist)

- [ ] **Step 1: Remove if present, skip if absent**

Run: `rm -f .claude/agents/llm-prompt-quality-reviewer.md`

If the file existed, commit:

```bash
git add -A .claude/agents/
git commit -m "chore: remove stale llm-prompt-quality-reviewer agent"
```

If the file did not exist, skip to Task 5.

## Chunk 2: Guardrail Hooks

### Task 5: Create wasm-check.sh hook

**Files:**
- Create: `.claude/hooks/wasm-check.sh`

- [ ] **Step 1: Write the hook script**

```bash
#!/bin/bash
# PostToolUse hook: run WASM target check on bind9-sdk-core edits.
# Catches no_std violations (std imports, tokio/net leakage) immediately.

INPUT=$(cat)

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

# Only trigger for .rs files in bind9-sdk-core
if [[ "$FILE_PATH" != *.rs ]]; then
  exit 0
fi

if [[ "$FILE_PATH" != *crates/bind9-sdk-core/* ]]; then
  exit 0
fi

if [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

cargo check -p bind9-sdk-core --target wasm32-unknown-unknown 2>&1
```

- [ ] **Step 2: Make executable**

Run: `chmod +x .claude/hooks/wasm-check.sh`

- [ ] **Step 3: Test the hook manually**

Run: `echo '{"tool_input":{"file_path":"crates/bind9-sdk-core/src/lib.rs"}}' | .claude/hooks/wasm-check.sh`
Expected: `cargo check` output, exit 0 (compilation succeeds).

Run: `echo '{"tool_input":{"file_path":"crates/bind9-sdk-net/src/lib.rs"}}' | .claude/hooks/wasm-check.sh`
Expected: Exits 0 immediately (skipped — not a core crate file).

### Task 6: Create clippy-gate.sh hook

**Files:**
- Create: `.claude/hooks/clippy-gate.sh`

- [ ] **Step 1: Write the hook script**

```bash
#!/bin/bash
# PostToolUse hook: run clippy on the affected crate after .rs edits.
# Determines crate from file path. Adds ~2-5s latency per edit — acceptable
# tradeoff for catching issues at edit time.

INPUT=$(cat)

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

if [[ "$FILE_PATH" != *.rs ]]; then
  exit 0
fi

if [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

# Determine crate name from path
if [[ "$FILE_PATH" == *crates/bind9-sdk-core/* ]]; then
  CRATE="bind9-sdk-core"
elif [[ "$FILE_PATH" == *crates/bind9-sdk-net/* ]]; then
  CRATE="bind9-sdk-net"
elif [[ "$FILE_PATH" == *crates/bind9-sdk-bindings/* ]]; then
  CRATE="bind9-sdk-bindings"
elif [[ "$FILE_PATH" == *bind9-sdk/src/* ]]; then
  CRATE="bind9-sdk"
else
  exit 0
fi

cargo clippy -p "$CRATE" -- -D warnings 2>&1
```

- [ ] **Step 2: Make executable**

Run: `chmod +x .claude/hooks/clippy-gate.sh`

- [ ] **Step 3: Test the hook manually**

Run: `echo '{"tool_input":{"file_path":"crates/bind9-sdk-core/src/lib.rs"}}' | .claude/hooks/clippy-gate.sh`
Expected: clippy output, exit 0.

### Task 7: Create spdx-header-check.sh hook

**Files:**
- Create: `.claude/hooks/spdx-header-check.sh`

- [ ] **Step 1: Write the hook script**

```bash
#!/bin/bash
# PreToolUse hook: block new file creation without SPDX header.
# Checks tool_input.content for the appropriate SPDX header based on file extension.
# Exit 2 blocks the tool call.

INPUT=$(cat)

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
CONTENT=$(echo "$INPUT" | jq -r '.tool_input.content // empty' 2>/dev/null)

if [ -z "$FILE_PATH" ] || [ -z "$CONTENT" ]; then
  exit 0
fi

# Only check new files (Write tool creates files)
# Skip if file already exists (Edit tool modifies existing files)
if [ -f "$FILE_PATH" ]; then
  exit 0
fi

# Determine expected SPDX prefix based on extension
case "$FILE_PATH" in
  *.rs)
    if ! echo "$CONTENT" | head -5 | grep -q "SPDX-FileCopyrightText:"; then
      echo "BLOCK: New .rs file missing SPDX header. Add '// SPDX-FileCopyrightText:' and '// SPDX-License-Identifier:' at the top." >&2
      exit 2
    fi
    ;;
  *.toml)
    if ! echo "$CONTENT" | head -5 | grep -q "SPDX-FileCopyrightText:"; then
      echo "BLOCK: New .toml file missing SPDX header. Add '# SPDX-FileCopyrightText:' and '# SPDX-License-Identifier:' at the top." >&2
      exit 2
    fi
    ;;
  *.md)
    if ! echo "$CONTENT" | head -5 | grep -q "SPDX-FileCopyrightText:"; then
      echo "BLOCK: New .md file missing SPDX header. Add '<!-- SPDX-FileCopyrightText:' and '<!-- SPDX-License-Identifier:' at the top." >&2
      exit 2
    fi
    ;;
esac

exit 0
```

- [ ] **Step 2: Make executable**

Run: `chmod +x .claude/hooks/spdx-header-check.sh`

### Task 8: Create edition-check.sh hook

**Files:**
- Create: `.claude/hooks/edition-check.sh`

- [ ] **Step 1: Write the hook script**

```bash
#!/bin/bash
# PreToolUse hook: warn if new Cargo.toml files lack edition = "2024".
# Non-blocking (exit 0) — prints warning only.

INPUT=$(cat)

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
CONTENT=$(echo "$INPUT" | jq -r '.tool_input.content // empty' 2>/dev/null)

if [ -z "$FILE_PATH" ] || [ -z "$CONTENT" ]; then
  exit 0
fi

# Only check new Cargo.toml files
BASENAME=$(basename "$FILE_PATH")
if [ "$BASENAME" != "Cargo.toml" ]; then
  exit 0
fi

if [ -f "$FILE_PATH" ]; then
  exit 0
fi

if ! echo "$CONTENT" | grep -q 'edition.*=.*"2024"'; then
  if ! echo "$CONTENT" | grep -q 'edition.workspace.*=.*true'; then
    echo "WARNING: New Cargo.toml does not specify edition = \"2024\" or edition.workspace = true." >&2
  fi
fi

exit 0
```

- [ ] **Step 2: Make executable**

Run: `chmod +x .claude/hooks/edition-check.sh`

### Task 9: Create dep-freshness.sh hook and known-dep-versions.toml

**Files:**
- Create: `.claude/known-dep-versions.toml`
- Create: `.claude/hooks/dep-freshness.sh`

- [ ] **Step 1: Write the known versions reference file**

```toml
# Known minimum dependency versions for bind9-sdk.
# Used by dep-freshness.sh hook to warn about outdated pinned versions.
# Updated: 2026-03-14

[versions]
hmac = "0.12"
sha2 = "0.10"
digest = "0.10"
serde = "1"
serde_json = "1"
tokio = "1.50"
rayon = "1.11"
reqwest = "0.13"
thiserror = "2"
tracing = "0.1"
zeroize = "1"
proptest = "1.10"
insta = "1.46"
```

- [ ] **Step 2: Write the hook script**

```bash
#!/bin/bash
# PostToolUse hook: warn if Cargo.toml dep versions are below known minimums.
# Non-blocking (exit 0) — prints warnings only.
# Compares against .claude/known-dep-versions.toml.

INPUT=$(cat)

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

BASENAME=$(basename "$FILE_PATH")
if [ "$BASENAME" != "Cargo.toml" ]; then
  exit 0
fi

if [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

KNOWN="$CLAUDE_PROJECT_DIR/.claude/known-dep-versions.toml"
if [ ! -f "$KNOWN" ]; then
  exit 0
fi

# Simple grep-based check: for each known dep, see if the edited Cargo.toml
# references it with an older major.minor version.
# This is a lightweight heuristic, not a full semver parser.
while IFS='=' read -r dep version; do
  dep=$(echo "$dep" | tr -d ' "')
  version=$(echo "$version" | tr -d ' "')
  [ -z "$dep" ] || [ -z "$version" ] && continue
  [[ "$dep" == \#* ]] && continue
  [[ "$dep" == "["* ]] && continue

  # Check if this dep appears in the edited file with a different version
  if grep -q "^${dep}\b" "$FILE_PATH" 2>/dev/null || grep -q "\"${dep}\"" "$FILE_PATH" 2>/dev/null; then
    FILE_VERSION=$(grep -E "${dep}.*version" "$FILE_PATH" | grep -oE '"[0-9]+\.[0-9]+"' | head -1 | tr -d '"')
    if [ -n "$FILE_VERSION" ] && [ "$FILE_VERSION" != "$version" ]; then
      echo "WARNING: $dep version $FILE_VERSION in $FILE_PATH — known minimum is $version" >&2
    fi
  fi
done < "$KNOWN"

exit 0
```

- [ ] **Step 3: Make executable**

Run: `chmod +x .claude/hooks/dep-freshness.sh`

### Task 10: Update .claude/settings.json with all hooks

**Files:**
- Modify: `.claude/settings.json`

- [ ] **Step 1: Update settings.json with all hook registrations**

Replace the entire file content with:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/superpowers-check.sh"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/rust-fmt.sh",
            "timeout": 10
          },
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/wasm-check.sh",
            "timeout": 30
          },
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/clippy-gate.sh",
            "timeout": 30
          },
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/dep-freshness.sh",
            "timeout": 10
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/block-generated-files.sh"
          },
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/spdx-header-check.sh"
          },
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/edition-check.sh"
          }
        ]
      }
    ]
  }
}
```

- [ ] **Step 2: Commit all hooks**

```bash
git add .claude/hooks/wasm-check.sh .claude/hooks/clippy-gate.sh \
  .claude/hooks/spdx-header-check.sh .claude/hooks/edition-check.sh \
  .claude/hooks/dep-freshness.sh .claude/known-dep-versions.toml \
  .claude/settings.json
git commit -m "chore: add guardrail hooks — wasm-check, clippy-gate, spdx-header, edition, dep-freshness"
```

## Chunk 3: Agent Definitions

### Task 11: Rewrite rust-security-reviewer agent

**Files:**
- Rewrite: `.claude/agents/rust-security-reviewer.md`

- [ ] **Step 1: Update the agent definition**

The existing agent at `.claude/agents/rust-security-reviewer.md` is already bind9-sdk-specific (it was rewritten in a previous session). Update it to add the missing checks from the spec (§6.1):

The existing file's last checklist section is `### I. Integer and Arithmetic Safety`. Add these new sections after it:

**Section J (new): NIS2 Logging Compliance**

```markdown
### J. NIS2 Logging Compliance

1. All rndc commands must emit a structured log entry with: event type, timestamp, zone (if applicable), command, result, session UUID
2. All RFC 2136 updates must emit a structured log entry with: zone, record type, operation (add/delete), prerequisite result
3. All TSIG authentication failures must emit a structured log entry with: peer address, algorithm, failure reason, timestamp
4. All zone transfers (AXFR/IXFR) must emit structured log entries: start, record count, completion/failure, duration
5. All DNSSEC key lifecycle events (generation, publication, activation, retirement, revocation, removal) must emit structured log entries
6. No log entry may contain TSIG key material, private key bytes, or client IP addresses from stats-channel (unless explicitly configured)
7. Log entries must use RFC 3339 timestamps with microsecond precision in UTC
```

**Section K (new): TLS Configuration**

```markdown
### K. TLS Configuration

1. Verify all TLS connections enforce TLS 1.3 minimum — no TLS 1.2 fallback. Check `rustls` configuration for `protocol_versions` or equivalent.
2. Verify cipher suite list contains only AES-256-GCM and ChaCha20-Poly1305 — no AES-128, no CBC modes.
3. Verify certificate validation is strict by default — no `danger_accept_invalid_certs`, no `danger_accept_invalid_hostnames`.
4. If TOFU/SPKI pinning is supported, verify pin comparison is constant-time.
```

**Section L (new): Secret Handling**

```markdown
### L. Secret Handling

1. TSIG keys and rndc keys must never be written to disk (no file caching, no temp files, no serialization to persistent storage).
2. No memoization or caching of key material in static variables or lazy statics.
3. All key material types must implement `Drop` with zeroization (via `ZeroizeOnDrop` derive or manual `Drop` impl).
```

Also update the frontmatter description to mention zeroization, NIS2 logging, and TLS:

```yaml
description: >
  Security audit for bind9-sdk Rust code. Reviews TSIG/crypto key exposure, DNS name parsing
  safety, rndc wire protocol input validation, RFC 2136 update injection, WASM boundary safety,
  napi-rs FFI safety, zeroization, NIS2 logging compliance, TLS configuration, and secret handling.
  Invoke after changes to any crate in crates/bind9-sdk-core/, crates/bind9-sdk-net/,
  crates/bind9-sdk-bindings/, or Cargo.toml.
```

- [ ] **Step 2: Verify the frontmatter parses correctly**

Run: `head -15 .claude/agents/rust-security-reviewer.md`
Expected: Valid YAML frontmatter with `---` delimiters, name, description, tools fields.

### Task 12: Rewrite api-compat-reviewer agent

**Files:**
- Rewrite: `.claude/agents/api-compat-reviewer.md`

- [ ] **Step 1: Update the agent definition**

The existing agent is already bind9-sdk-specific. Update it to add the checks from the spec (§6.2) that are missing:

The existing file's last section is `## bind9-sdk-Specific Notes` (starts around line 90). Add these new subsections at the end of that section, before the file's closing `---`:

**Re-export coverage check:**

```markdown
### Re-export Coverage

Before reporting, verify that ALL `pub` types in `bind9-sdk-core` and `bind9-sdk-net` are re-exported through `bind9-sdk/src/lib.rs`. Any public type that is NOT re-exported is a gap — users cannot access it through the published crate.

Run:
1. `grep -rn "^pub " crates/bind9-sdk-core/src/ crates/bind9-sdk-net/src/` to list all public items
2. `grep -rn "pub use" bind9-sdk/src/lib.rs` to list all re-exports
3. Report any public items not covered by re-exports
```

**#[non_exhaustive] enforcement:**

```markdown
### Non-Exhaustive Enforcement

These enums MUST have `#[non_exhaustive]`:
- `RecordData` — new DNS record types will be added
- `RndcCommand` — new rndc commands may be added
- `DnssecAlgorithm` — post-quantum algorithms expected ~2027-2028
- Any other enum representing an extensible registry (IANA-sourced)

Report any such enum missing `#[non_exhaustive]` as a BREAKING CHANGE risk.
```

**Send + Sync bounds:**

```markdown
### Send + Sync on Public Traits

Traits intended for external implementation (`ZoneManager`, `NamedControl`, `DynamicUpdater`, `StatsClient`) must carry `Send + Sync` bounds if their methods are used in async contexts. Verify:
1. Trait definition includes `: Send + Sync` or equivalent where used with `dyn Trait`
2. All concrete implementations satisfy these bounds
```

- [ ] **Step 2: Verify frontmatter**

Run: `head -5 .claude/agents/api-compat-reviewer.md`
Expected: Valid YAML frontmatter.

### Task 13: Create rfc-compliance-checker agent

**Files:**
- Create: `.claude/agents/rfc-compliance-checker.md`

- [ ] **Step 1: Write the agent definition**

```markdown
---
name: rfc-compliance-checker
description: >
  Verify implementation matches referenced RFC requirements, check edge cases,
  report deviations with section references. Input: RFC number + module path
  (e.g., "8945 crates/bind9-sdk-core/src/tsig.rs").
tools:
  - Read
  - Grep
  - Glob
  - Bash
  - WebFetch
  - WebSearch
---

You are an RFC compliance checker for bind9-sdk. You verify that Rust implementations correctly follow the MUST, SHOULD, and MAY requirements from IETF RFCs.

## Constraints

- **Do NOT modify any files.** Report findings only.
- You may use WebFetch/WebSearch to retrieve RFC text.

## Input

You receive an RFC number and a module path. Example: `8945 crates/bind9-sdk-core/src/tsig.rs`

## Process

### Step 1: Retrieve the RFC

Fetch the RFC text. Prefer the text version from `https://www.rfc-editor.org/rfc/rfcNNNN.txt`.

### Step 2: Extract Requirements

Parse the RFC for all instances of:
- **MUST** / **MUST NOT** — mandatory requirements
- **SHOULD** / **SHOULD NOT** — recommended requirements
- **MAY** — optional requirements

For each, note the section number and the exact requirement text.

### Step 3: Read the Implementation

Read the module file(s) at the given path. If the path is a directory, read all `.rs` files in it.

### Step 4: Cross-Reference

For each RFC requirement, determine whether the implementation:
- **COMPLIANT** — requirement is correctly implemented
- **DEVIATION** — requirement is implemented but deviates from the RFC (document how)
- **NOT_IMPLEMENTED** — requirement is not implemented at all
- **NOT_APPLICABLE** — requirement does not apply to this module's scope

### Step 5: Check Edge Cases

For each RFC, check documented edge cases. Common examples:
- RFC 8945 §5: BADTIME handling, BADSIG handling, clock skew tolerance
- RFC 1035 §4.1.4: Message compression pointer loops
- RFC 2136 §3.4: Prerequisite evaluation order
- RFC 5936 §2.2: AXFR connection reuse

### Step 6: Report

```
## RFC NNNN Compliance Report

**Module:** `path/to/module.rs`
**Date:** YYYY-MM-DD

### MUST Requirements

| § | Requirement | Status | Notes |
| --- | --- | --- | --- |
| 5.1 | Client MUST verify HMAC | COMPLIANT | Uses ct_eq in tsig.rs:142 |
| 5.2 | Timestamp within 300s | DEVIATION | Window is 600s (configurable) |

### SHOULD Requirements

| § | Requirement | Status | Notes |
| --- | --- | --- | --- |

### Edge Cases

| § | Case | Status | Notes |
| --- | --- | --- | --- |

### Summary

- MUST: N compliant, N deviations, N not implemented
- SHOULD: N compliant, N deviations, N not implemented
- Edge cases: N covered, N missing

**Verdict:** COMPLIANT | DEVIATIONS_FOUND | NON_COMPLIANT
```

## bind9-sdk RFCs

The following RFCs are relevant to this project. Check the PRD (Appendix C) for the full list:

- **RFC 8945** — TSIG (crates/bind9-sdk-core/src/tsig*)
- **RFC 1035** — DNS wire format, zone file format (crates/bind9-sdk-core/src/domain*, src/zone*, src/record*)
- **RFC 2136** — Dynamic updates (crates/bind9-sdk-core/src/update*)
- **RFC 1995** — IXFR (crates/bind9-sdk-net/src/transfer*)
- **RFC 5936** — AXFR (crates/bind9-sdk-net/src/transfer*)
- **RFC 9103** — XoT (crates/bind9-sdk-net/src/tls*, src/transfer*)
- **RFC 7766** — DNS over TCP (crates/bind9-sdk-net/)
- **RFC 4343** — DNS case insensitivity (crates/bind9-sdk-core/src/domain*)
- **RFC 9077** — NSEC/NSEC3 TTL (crates/bind9-sdk-core/src/record*)
```

- [ ] **Step 2: Verify frontmatter**

Run: `head -10 .claude/agents/rfc-compliance-checker.md`
Expected: Valid YAML frontmatter with name, description, tools.

### Task 14: Create dnssec-security-auditor agent

**Files:**
- Create: `.claude/agents/dnssec-security-auditor.md`

- [ ] **Step 1: Write the agent definition**

```markdown
---
name: dnssec-security-auditor
description: >
  DNSSEC key management security audit. Reviews key material exposure, zeroization,
  per-zone key isolation, KASP timing constraints, CDS/CDNSKEY bootstrapping,
  algorithm agility, and DS propagation safety. Invoke after changes to DNSSEC-related
  code in crates/bind9-sdk-core/ or crates/bind9-sdk-net/.
tools:
  - Read
  - Grep
  - Glob
  - Bash
---

You are a DNSSEC security auditor for bind9-sdk. You verify that DNSSEC key management code follows security best practices and RFC requirements.

## Constraints

- **Do NOT modify any files.** Report findings only.

## Step 1: Identify Scope

Search for DNSSEC-related code:

```bash
grep -rn "dnssec\|DnssecAlgorithm\|DnssecKey\|Kasp\|kasp\|Dnskey\|dnskey\|DNSKEY\|CDS\|CDNSKEY\|DS\|RRSIG\|NSEC\|ksk\|zsk\|KSK\|ZSK\|key_tag\|key_roll" crates/ --include="*.rs"
```

## Step 2: Security Checklist

### A. Key Material Exposure

1. No DNSSEC key material (private key bytes, key tags with material) in `Debug` output — verify manual `Debug` impl with redaction
2. No key material in `Display` output or error messages
3. No key material in log output (`tracing::info!`, `tracing::debug!`, etc.)
4. No key material in `panic!` or `unreachable!` messages

### B. Zeroization

1. All types holding key material must derive `Zeroize` + `ZeroizeOnDrop`
2. Types: `TsigKey`, `DnssecKeyMetadata`, any struct with `key_material`, `secret`, `hmac_key` fields
3. Verify `Drop` is called — no `mem::forget` on key material types
4. No `Clone` on key material types (cloning defeats zeroization tracking)

### C. Per-Zone Key Isolation

1. Key types must be scoped to a zone — verify key structs contain a zone name field
2. No global key store that mixes keys from different zones
3. Key lookup must be by zone name, not by a global index
4. Verify that compromising one zone's key does not expose other zones

### D. KASP Policy Validation

1. Rollover timing constraints per RFC 7583:
   - Publication interval ≥ propagation delay + DNSKEY TTL
   - Sign interval considers signature validity and clock skew
   - Retirement delay accounts for zone TTL + propagation
2. Verify timing calculations do not overflow or underflow
3. Verify rollover state machine transitions are valid (no skipping states)

### E. CDS/CDNSKEY Bootstrapping (RFC 9615)

1. CDS/CDNSKEY records must only be published after DNSSEC chain is fully established
2. Signal verification: verify the CDS/CDNSKEY signal process checks for:
   - Correct algorithm match
   - Correct digest type
   - Key tag consistency
3. Bootstrap removal: after DS is confirmed in parent, CDS/CDNSKEY records should be removed

### F. Algorithm Agility

1. No hardcoded algorithm numbers in match arms without a wildcard/default case
2. `DnssecAlgorithm` enum should be `#[non_exhaustive]`
3. Algorithm validation should check against the IANA registry subset, not a hardcoded list
4. Warn if Algorithm 5 (RSASHA1) or 7 (RSASHA1-NSEC3-SHA1) are accepted without a `SecurityWarning`

### G. DS Propagation Safety

1. KSK rollover must NOT retire old KSK until DS record is confirmed in parent zone
2. DS propagation check must query the parent zone's authoritative servers, not a recursive resolver
3. Timeout and retry logic for DS propagation checks
4. Verify the DS record matches the new KSK (algorithm, digest type, key tag)

## Step 3: Report Format

For each finding:

```
### [SEVERITY] Category: Title

**File:** `path/to/file.rs:LINE`

**Description:**
What the issue is, with the relevant code snippet.

**Recommendation:**
Specific fix suggestion.
```

Severity:
- **CRITICAL**: Key material exposure, missing zeroization on key types
- **HIGH**: Missing per-zone isolation, KASP timing overflow, DS propagation bypass
- **MEDIUM**: Missing algorithm agility, hardcoded algorithm numbers
- **LOW**: Missing SecurityWarning on weak algorithms, incomplete CDS cleanup

## Step 4: Summary

| Severity | Count | Categories |
| --- | --- | --- |
| CRITICAL | N | ... |
| HIGH | N | ... |
| MEDIUM | N | ... |
| LOW | N | ... |

**Verdict:** `PASS` | `REVIEW` | `BLOCK`
```

- [ ] **Step 2: Verify frontmatter**

Run: `head -10 .claude/agents/dnssec-security-auditor.md`
Expected: Valid YAML frontmatter.

- [ ] **Step 3: Commit all agent changes**

```bash
git add .claude/agents/rust-security-reviewer.md \
  .claude/agents/api-compat-reviewer.md \
  .claude/agents/rfc-compliance-checker.md \
  .claude/agents/dnssec-security-auditor.md
git commit -m "chore: rewrite security/compat agents, add rfc-compliance and dnssec auditor"
```

## Chunk 4: PRD Revision

### Task 15: Apply PRD.md revisions

**Files:**
- Modify: `PRD.md` (multiple sections)

This task uses the `prd-manager:prd-maintain` skill for safe edit-only updates. **Do NOT use Write tool on PRD.md** — only Edit.

The spec (§3.1–3.9) defines all required PRD changes. Apply them in this order:

- [ ] **Step 1: Fix stale RFC references**

Per spec §3.1, apply these edits:
- Replace `RFC 8499` references with `RFC 9499 (March 2024)` and note "Superseded — DNS Terminology BCP 219"
- Replace `RFC 8624` references with `RFC 9904 (November 2025)` and note "Superseded — DNSSEC algorithm recommendation process"
- Fix RFC 2136 status from "Internet Standard" to "Proposed Standard"
- Fix RFC 1995 status from "Internet Standard" to "Proposed Standard"
- Fix RFC 5936 status from "Internet Standard" to "Proposed Standard"
- Add historical note for RFC 4635 (HMAC-SHA256/SHA512 algorithm names, absorbed by RFC 8945)

- [ ] **Step 2: Add missing RFCs to Appendix C**

Per spec §3.2, add 12 operationally critical and 6 informational RFCs to the RFC reference table. See spec for the complete list with crate assignments and rationale.

- [ ] **Step 3: Add Compliance Requirements section**

Per spec §3.3, add a new top-level section with 33 requirements across 8 categories:
- REQ-AUTH-1 through REQ-AUTH-4
- REQ-TLS-1 through REQ-TLS-3
- REQ-DNSSEC-1 through REQ-DNSSEC-5
- REQ-LOG-1 through REQ-LOG-6
- REQ-ZONE-1 through REQ-ZONE-5
- REQ-GDPR-1 through REQ-GDPR-3
- REQ-SC-1 through REQ-SC-4
- REQ-SEC-DEFAULT-1 through REQ-SEC-DEFAULT-3

Each with regulatory source citations. Copy the requirement text from the spec verbatim.

- [ ] **Step 4: Add Security Architecture section**

Per spec §3.4, add hidden-primary / distributed-secondary architecture documentation.

- [ ] **Step 5: Update priority rebalancing**

Per spec §3.5, update distribution priorities: P0 Rust crate, P1 npm (napi-rs v3), P2 WASM (napi-rs fallback).

- [ ] **Step 6: Add Parallelism Architecture section**

Per spec §3.6, add tokio (async I/O) + rayon (CPU-bound) architecture with bridge pattern.

- [ ] **Step 7: Add new RecordData variants**

Per spec §3.7, document `Csync` (RFC 7477) and `Rp` (RFC 1183, GDPR-flagged) in the RecordData enum section.

- [ ] **Step 8: Update PRD sections for napi-rs v3 transition**

Per spec §3.8, update FR-030, FR-031, Phase 3, DR-003, TR-004, TR-006.

- [ ] **Step 9: Update Rust version references**

Per spec §3.9, update `rust-version = "1.94"`, document available language features, update dep version table.

- [ ] **Step 10: Update DEC-004 for Ed25519 recommendation**

Add a note to DEC-004 that it will be revisited per RFC 9904 and the spec's recommendation to default to Ed25519 over Algorithm 13.

- [ ] **Step 11: Bump PRD version**

Update version from `0.1` to `0.2` and add a changelog entry noting all changes made.

- [ ] **Step 12: Commit**

```bash
git add PRD.md
git commit -m "docs(prd): v0.2 — RFC fixes, compliance section, security arch, napi-rs v3, Rust 1.94"
```

## Chunk 5: CLAUDE.md & Verification

### Task 16: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update description paragraph**

Replace the second paragraph (line 10, "Distributes as three...") with:

```markdown
Distributes as two coordinated artifacts from one codebase: a Rust crate (`bind9-sdk` on crates.io) and a Node.js/Bun native addon (napi-rs v3 from `bind9-sdk-bindings`, with automatic WASM fallback).
```

- [ ] **Step 2: Update Prerequisites**

Update lines 14-17:

```markdown
## Prerequisites

- Rust 1.94.0 — `rust-toolchain.toml` pins channel and installs `wasm32-unknown-unknown`
- BIND9 9.20 — for integration tests (Podman rootless or native `named`)
```

Remove the `wasm-pack` prerequisite line.

- [ ] **Step 3: Update Commands section**

Add `cargo audit` and `cargo deny check` after the existing commands. Update the WASM build command:

```markdown
# Browser WASM build — via napi-rs v3 (replaces wasm-pack)
# napi build --target wasm32-wasip1-threads --release

# Node.js/Bun native addon build (full surface)
cargo build --release --manifest-path crates/bind9-sdk-bindings/Cargo.toml --features nodejs

# Audit
cargo audit
cargo deny check
```

- [ ] **Step 4: Update Workspace Architecture diagram**

Update the `npm/` line and note about napi-rs v3:

```
├── npm/                       ← npm package output (napi-rs v3 native + WASM artifacts)
```

- [ ] **Step 5: Update Crate Responsibilities table**

Update the `bind9-sdk-bindings` row:

```markdown
| `bind9-sdk-bindings` | — | `nodejs` | napi-rs v3 exports: native `.node` + `wasm32-wasip1-threads` WASM fallback |
```

- [ ] **Step 6: Update Feature Flags table**

Remove the `browser` row. Update `nodejs` description. Add `parallel` row:

```markdown
| `parallel` | `bind9-sdk-core` | Enables Rayon-based parallel zone parsing (implies `std`, incompatible with WASM) |
```

- [ ] **Step 7: Update Key Design Decision 5 (WASM boundary split)**

Replace with napi-rs v3 unified approach:

```markdown
5. **napi-rs v3 unified bindings** — napi-rs v3 compiles to both native `.node` files and `wasm32-wasip1-threads` WASM from the same binding code. The `browser` feature and wasm-bindgen dependency are removed. `wasm32-unknown-unknown` is retained in `rust-toolchain.toml` solely for the `no_std` validation hook on `bind9-sdk-core`.
```

- [ ] **Step 8: Update Gotchas**

Update the `wasm32-unknown-unknown` gotcha and napi-rs gotcha. Remove the `wasm-pack` reference in the napi-rs gotcha.

- [ ] **Step 9: Update Hooks table**

Replace the hooks table with the full 8-hook version from spec §4.3 (including `dep-freshness.sh`).

- [ ] **Step 10: Update Agents table**

Replace the agents table with the 5-agent version from spec §4.2. Remove all stale commitbee notes.

- [ ] **Step 11: Add Compliance section**

Add after the Agents section:

```markdown
## Compliance

SDK targets compliance with GDPR, NIS2 (EU 2022/2555), NIST SP 800-53/800-81/800-57, ISO 27001:2022, and SOC 2 Type II requirements relevant to DNS infrastructure. All defaults exceed minimum compliance thresholds. See PRD §[TBD] (Compliance Requirements) for full requirement set.
```

- [ ] **Step 12: Add Verification Workflow section**

Add after the Compliance section, per spec §4.6.

- [ ] **Step 13: Update References**

Remove the `wasm-pack` reference. Update `napi-rs` note. Add specs and plans paths.

- [ ] **Step 14: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude): update for napi-rs v3, new hooks/agents, compliance, verification workflow"
```

### Task 17: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Verify Rust toolchain**

Run: `rustup show active-toolchain`
Expected: `1.94.0-aarch64-apple-darwin` (or current latest stable if 1.94 is not yet released)

- [ ] **Step 2: Resolve and check workspace**

Run: `cargo update && cargo check --workspace`
Expected: Clean compilation, no errors.

- [ ] **Step 3: Verify WASM target check**

Run: `cargo check -p bind9-sdk-core --target wasm32-unknown-unknown`
Expected: Clean compilation (no_std core must not depend on std).

- [ ] **Step 4: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: No warnings, no errors.

- [ ] **Step 5: Run fmt check**

Run: `cargo fmt --check`
Expected: No formatting issues.

- [ ] **Step 6: Run tests**

Run: `cargo test --workspace`
Expected: All tests pass (currently minimal — skeleton crates).

- [ ] **Step 7: Verify all agents parse**

Run: `for f in .claude/agents/*.md; do echo "--- $f ---"; head -5 "$f"; done`
Expected: Each agent file has valid `---` delimited YAML frontmatter.

- [ ] **Step 8: Verify all hooks are executable**

Run: `ls -la .claude/hooks/*.sh`
Expected: All hook files have execute permission.

- [ ] **Step 9: Verify git status is clean**

Run: `git status`
Expected: Clean working tree, no untracked files.
