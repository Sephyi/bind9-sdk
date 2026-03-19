#!/bin/bash
# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

# PreToolUse hook: block manual edits to auto-generated files.
# Reads PreToolUse JSON from stdin. Exit 2 blocks the tool call;
# error message on stderr is shown to Claude.

FILE_PATH=$(jq -r '.tool_input.file_path // empty' 2>/dev/null)

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

BASENAME=$(basename "$FILE_PATH")

case "$BASENAME" in
  Cargo.lock)
    echo "BLOCK: Do not manually edit Cargo.lock. Use 'cargo update', 'cargo add', or 'cargo upgrade' to modify dependencies." >&2
    exit 2
    ;;
  *)
    exit 0
    ;;
esac
