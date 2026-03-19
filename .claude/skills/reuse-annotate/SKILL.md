---
name: reuse-annotate
description: Add SPDX/REUSE license headers to new files, with inline or REUSE.toml fallback for unsupported file types
disable-model-invocation: true
argument-hint: "<file-path(s)>"
allowed-tools: Bash
---

Add REUSE-compliant SPDX headers to the specified file(s).

## Pre-flight

reuse CLI available: !`which reuse 2>/dev/null && reuse --version 2>/dev/null || echo "REUSE_NOT_INSTALLED"`

If `REUSE_NOT_INSTALLED` appears above, tell the user to install it with `pipx install reuse` and stop.

## Project defaults

- Copyright: `Sephyi <me@sephy.io>`
- License: `AGPL-3.0-only OR LicenseRef-Commercial`
- Year: !`date +%Y`

## Files to annotate

$ARGUMENTS

If `$ARGUMENTS` is empty, ask the user which file(s) to annotate.

## Decision: inline header vs REUSE.toml

For each file in `$ARGUMENTS`, determine the right approach:

**Use `reuse annotate` (inline header) for:**
Source and config files that support comments: `.rs`, `.ts`, `.js`, `.py`, `.go`, `.sh`, `.toml`, `.yaml`, `.yml`, `.css`, `.html`, `.sql`, `Dockerfile`, `Makefile`, `.md` (HTML comment)

**Use REUSE.toml `[[annotations]]` for:**
Files without comment syntax or auto-generated files: binary files (images, fonts), `Cargo.lock`, lockfiles, test snapshots (`tests/snapshots/**`), any file where `reuse annotate` would break the file format

### For inline-eligible files

```bash
reuse annotate \
  --copyright "Sephyi <me@sephy.io>" \
  --license AGPL-3.0-only OR LicenseRef-Commercial \
  --year !`date +%Y` \
  --force \
  $ARGUMENTS
```

(`--force` is safe — reuse annotate is idempotent and `--force` handles re-annotation cleanly)

### For REUSE.toml-eligible files

Add an `[[annotations]]` block to `REUSE.toml` following the existing pattern:

```toml
[[annotations]]
path = "<file-or-glob>"
precedence = "aggregate"
SPDX-FileCopyrightText = "!`date +%Y` Sephyi <me@sephy.io>"
SPDX-License-Identifier = "AGPL-3.0-only OR LicenseRef-Commercial"
SPDX-FileComment = "<brief reason why inline header cannot be used>"
```

Group related files under a single glob where possible (e.g., `.claude/skills/**/*.md`).

## Verify

```bash
reuse lint
```

Report any remaining violations. If all files pass, confirm compliance.

## Error Recovery

| Failure | Action |
| --- | --- |
| `reuse` CLI not installed | Stop immediately. Print: "Install: pip install reuse". Do not attempt manual header insertion. |
| File already has SPDX header | Skip with note. Use `--force` flag only if explicitly requested. |
| File has no comment syntax | Switch to REUSE.toml annotation automatically. Report which file triggered this. |
| `reuse lint` fails after annotation | Report the specific violation. Do not mark as complete until lint passes. |
