#!/bin/bash
# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

# PreToolUse hook: block bare `use std::` in bind9-sdk-core (no_std crate).
# Allows `use std::` when preceded by #[cfg(feature = "std")] or inside #[cfg(test)].

FILE_PATH="${TOOL_INPUT_FILE_PATH:-}"

# Only check core crate source files
case "$FILE_PATH" in
  */bind9-sdk-core/src/*.rs) ;;
  *) exit 0 ;;
esac

# Get the new content being written/edited
CONTENT="${TOOL_INPUT_NEW_STRING:-${TOOL_INPUT_CONTENT:-}}"
[ -z "$CONTENT" ] && exit 0

# Check for bare `use std::` not guarded by cfg
if echo "$CONTENT" | grep -qE '^\s*use std::'; then
  # Allow if the content also contains the cfg guard
  if echo "$CONTENT" | grep -qE '#\[cfg\(feature\s*=\s*"std"\)\]|#\[cfg\(test\)\]'; then
    exit 0
  fi
  echo "BLOCKED: bare 'use std::' in no_std crate bind9-sdk-core."
  echo "Gate behind #[cfg(feature = \"std\")] or use core::/alloc:: equivalents."
  exit 1
fi

exit 0
