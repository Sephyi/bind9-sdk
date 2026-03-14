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
