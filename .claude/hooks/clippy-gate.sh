#!/bin/bash
# PostToolUse hook: run clippy on the affected crate after .rs edits.
# Determines crate from file path. Adds ~2-5s latency per edit.

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
