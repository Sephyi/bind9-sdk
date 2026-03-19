#!/bin/bash
# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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
