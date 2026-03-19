#!/bin/bash
# SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

# Stop hook: catch cross-file rustfmt drift after a Claude session.
#
# PostToolUse rust-fmt.sh formats each edited file individually, but if Claude
# edits file A which triggers a formatting side-effect on file B (e.g. imports
# reordered by rustfmt), file B won't be re-formatted unless Claude also edits it.
# This Stop hook runs cargo fmt --all --check and warns if drift is found.
#
# Non-blocking (exit 0) — prints a warning so Claude can fix before committing.

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0

if ! cargo fmt --check --all --quiet 2>/dev/null; then
  echo "WARNING: rustfmt drift detected across workspace. Run 'cargo fmt --all' before committing." >&2
fi

exit 0
