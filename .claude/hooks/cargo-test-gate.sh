#!/bin/bash
# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

# PostToolUse hook: run targeted cargo test for the crate containing the edited file.
# Only runs lib tests (fast, ~1-3s per crate). Full suite via /ci-check.
#
# Opt-out: set CLAUDE_SKIP_TEST_GATE=1 to disable during rapid iteration.

[ "${CLAUDE_SKIP_TEST_GATE:-}" = "1" ] && exit 0

# Read file path from stdin JSON (same as other hooks — TOOL_INPUT_FILE_PATH is not set by Claude Code)
INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)

if [ -z "$FILE_PATH" ] || [[ "$FILE_PATH" != *.rs ]]; then
  exit 0
fi

# Map file path to crate — use prefix matching so tsig/, update/, zone/parser/ etc. all match
case "$FILE_PATH" in
  */crates/bind9-sdk-core/src*)      CRATE="bind9-sdk-core" ;;
  */crates/bind9-sdk-net/src*)       CRATE="bind9-sdk-net" ;;
  */crates/bind9-sdk-bindings/src*)  CRATE="bind9-sdk-bindings" ;;
  */bind9-sdk/src*)                  CRATE="bind9-sdk" ;;
  *) exit 0 ;;
esac

# Run only the lib tests for the affected crate (fast path)
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
cargo test -p "$CRATE" --lib --quiet 2>&1 | tail -3

# Report but don't block — clippy-gate already blocks on errors
exit 0
