#!/bin/bash
# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

# PostToolUse hook: warn if Cargo.toml dep versions are below known minimums.
# Non-blocking (exit 0) — prints warnings only.

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

# Simple grep-based check: lightweight heuristic, not a full semver parser.
while IFS='=' read -r dep version; do
  dep=$(echo "$dep" | tr -d ' "')
  version=$(echo "$version" | tr -d ' "')
  [ -z "$dep" ] || [ -z "$version" ] && continue
  [[ "$dep" == \#* ]] && continue
  [[ "$dep" == "["* ]] && continue

  if grep -q "^${dep}\b" "$FILE_PATH" 2>/dev/null || grep -q "\"${dep}\"" "$FILE_PATH" 2>/dev/null; then
    FILE_VERSION=$(grep -E "${dep}.*version" "$FILE_PATH" | grep -oE '"[0-9]+\.[0-9]+"' | head -1 | tr -d '"')
    if [ -n "$FILE_VERSION" ] && [ "$FILE_VERSION" != "$version" ]; then
      echo "WARNING: $dep version $FILE_VERSION in $FILE_PATH — known minimum is $version" >&2
    fi
  fi
done < "$KNOWN"

exit 0
