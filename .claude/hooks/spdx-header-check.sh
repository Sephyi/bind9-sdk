#!/bin/bash
# PreToolUse hook: block new file creation without SPDX header.
# Exit 2 blocks the tool call.

INPUT=$(cat)

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
CONTENT=$(echo "$INPUT" | jq -r '.tool_input.content // empty' 2>/dev/null)

if [ -z "$FILE_PATH" ] || [ -z "$CONTENT" ]; then
  exit 0
fi

# Only check new files — skip if file already exists
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
