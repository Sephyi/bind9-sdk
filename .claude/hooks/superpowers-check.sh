#!/bin/bash
# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

# SessionStart hook: verify superpowers plugin is active.
# Superpowers registers its own SessionStart hook that injects 'using-superpowers'
# content automatically. If the plugin directory is missing, skills like brainstorming,
# TDD, debugging, and dispatching-parallel-agents will silently not be available.

SUPERPOWERS_DIR="$HOME/.claude/plugins/cache/claude-plugins-official/superpowers"

if [ ! -d "$SUPERPOWERS_DIR" ]; then
  echo "WARNING: superpowers plugin not found at $SUPERPOWERS_DIR" >&2
  echo "Skills (brainstorming, TDD, debugging, parallel-agents) may not be active." >&2
  echo "Fix: claude plugin install claude-plugins-official/superpowers" >&2
  # Exit 0 — warn only, do not block the session
fi

exit 0
