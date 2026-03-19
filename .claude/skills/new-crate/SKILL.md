<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

---
name: new-crate
description: Scaffold a new crate in the bind9-sdk workspace with correct Cargo.toml workspace inheritance, SPDX headers, and optional no_std setup
disable-model-invocation: true
argument-hint: "<crate-name> [--no-std] [--net]"
allowed-tools: Bash, Edit, Write, Read
---

Scaffold a new workspace crate. All boilerplate is generated correctly — workspace inheritance, SPDX headers, optional `no_std`, and verification.

## Input

`$ARGUMENTS`: crate name and optional flags.

Examples:
- `bind9-sdk-dnssec` — standard std crate
- `bind9-sdk-wasm --no-std` — no_std + alloc crate
- `bind9-sdk-cli --net` — tokio-dependent crate

Parse flags:
- `--no-std`: add `#![no_std]` + `extern crate alloc;` + `thiserror` with `default-features = false`
- `--net`: add `tokio` workspace dependency

## Step 1: Validate name

Crate name must start with `bind9-sdk-`. If not, ask the user to confirm they want a non-prefixed name before proceeding.

Crate path: `crates/<crate-name>/` for all `bind9-sdk-*` crates.

If the directory already exists, stop and report — do not overwrite.

## Step 2: Read workspace root Cargo.toml

```bash
cat "$CLAUDE_PROJECT_DIR/Cargo.toml"
```

Note the existing `[workspace] members` list. The new crate path (`crates/<crate-name>`) must be inserted in alphabetical order.

## Step 3: Create crate directory

```bash
mkdir -p "$CLAUDE_PROJECT_DIR/crates/<crate-name>/src"
```

## Step 4: Write `crates/<crate-name>/Cargo.toml`

```toml
# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

[package]
name = "<crate-name>"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
keywords.workspace = true
categories.workspace = true
description = "TODO: add description for <crate-name>"
```

Add `[dependencies]` section:
- Always include nothing by default
- For `--no-std`: add `thiserror = { version = "2", default-features = false }`
- For `--net`: add `tokio = { workspace = true }`
- For `--no-std` (to ensure alloc): confirm `alloc` is available via `#![no_std]` — no crate dep needed, it's built-in

## Step 5: Write `crates/<crate-name>/src/lib.rs`

```rust
// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// (for --no-std only):
#![no_std]
extern crate alloc;

#![forbid(unsafe_code)]

//! <crate-name> — TODO: module doc comment.
```

Note: `#![forbid(unsafe_code)]` is always included. For `--no-std`, include `#![no_std]` and `extern crate alloc;` before the doc comment. For std crates, omit those two lines.

## Step 6: Add crate to workspace

Edit the root `Cargo.toml` `members` array to insert `"crates/<crate-name>"` in the correct alphabetical position.

Read the current `members` list first, determine the insertion point, then use the Edit tool to add the entry.

## Step 7: Verify

```bash
cd "$CLAUDE_PROJECT_DIR"
cargo check -p <crate-name>
```

For `--no-std` crates, also run:

```bash
cargo check -p <crate-name> --target wasm32-unknown-unknown
```

## Step 8: Report

Output:
- Files created: `crates/<crate-name>/Cargo.toml`, `crates/<crate-name>/src/lib.rs`
- Workspace members updated: root `Cargo.toml`
- `cargo check` result
- WASM check result (if `--no-std`)
- Reminder: update `description` in `Cargo.toml` before publishing
- Reminder: add SPDX annotation to `REUSE.toml` if any non-source files are created (run `/reuse-annotate`)
