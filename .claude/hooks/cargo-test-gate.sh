#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
#
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# PostToolUse hook: run targeted cargo test for the crate containing the edited file.
# Only runs lib tests (fast, ~1-3s per crate). Full suite via /ci-check.
#
# Opt-out: set CLAUDE_SKIP_TEST_GATE=1 to disable during rapid iteration.

[ "${CLAUDE_SKIP_TEST_GATE:-}" = "1" ] && exit 0

FILE_PATH="${TOOL_INPUT_FILE_PATH:-}"

# Only trigger on Rust source files inside crates/
case "$FILE_PATH" in
  */crates/bind9-sdk-core/src/*.rs)  CRATE="bind9-sdk-core" ;;
  */crates/bind9-sdk-net/src/*.rs)   CRATE="bind9-sdk-net" ;;
  */crates/bind9-sdk-bindings/src/*.rs) CRATE="bind9-sdk-bindings" ;;
  */bind9-sdk/src/*.rs)              CRATE="bind9-sdk" ;;
  *) exit 0 ;;
esac

# Run only the lib tests for the affected crate (fast path)
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
cargo test -p "$CRATE" --lib --quiet 2>&1 | tail -3

# Report but don't block — clippy-gate already blocks on errors
exit 0
