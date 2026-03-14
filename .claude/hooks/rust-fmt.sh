#!/bin/bash
# PostToolUse hook: format .rs files with rustfmt after Edit/Write
# Reads tool input JSON from stdin, extracts file_path, skips non-Rust files.

INPUT=$(cat)

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)

# Skip if no file path
if [ -z "$FILE_PATH" ]; then
  exit 0
fi

# Skip non-.rs files (Cargo.toml, CLAUDE.md, snapshots, etc.)
if [[ "$FILE_PATH" != *.rs ]]; then
  exit 0
fi

# Skip if file was deleted after write
if [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

# Format only the specific file — avoids whole-crate formatting and race conditions
# with parallel subagents. Natural exit code: rustfmt failure surfaces to Claude.
rustfmt "$FILE_PATH" 2>&1
