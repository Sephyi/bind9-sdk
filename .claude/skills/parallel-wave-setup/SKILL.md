<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

---
name: parallel-wave-setup
description: Set up multiple worktrees for parallel plan execution in one shot — reads N plan files, creates all worktrees, validates pre-conditions, and outputs a ready-to-go launch table
disable-model-invocation: true
argument-hint: "<wt-ids...> (e.g., wt3 wt4 wt5)"
allowed-tools: Bash, Read, Glob, Grep
---

Set up multiple git worktrees simultaneously for parallel Wave execution.

## Input

`$ARGUMENTS` is a space-separated list of worktree IDs, e.g. `wt3 wt4 wt5`.

If empty, ask which worktrees to set up.

## Step 1: Parse worktree IDs

Extract each ID from `$ARGUMENTS`. For each ID (e.g. `wt3`), extract the number (e.g. `3`).

## Step 2: Resolve plan files and read metadata

For each worktree ID, find the matching plan doc:

```bash
ls docs/plans/*wt${NUMBER}* 2>/dev/null
```

Read the first 50 lines of each plan file. Extract:
- **Branch name** (from `**Branch:**` line)
- **Goal** (from `**Goal:**` or `**Objective:**` line)
- **Dependencies** — note any "requires WT-N complete" language that implies sequential ordering

Build a dependency graph:
- Identify which worktrees can start immediately (no deps or deps already merged)
- Identify which must wait (deps on other worktrees in this batch)

## Step 3: Verify pre-conditions on development branch

For each worktree:
- Use `grep` to check that key types/traits/functions mentioned in pre-conditions exist in `development` HEAD
- Report READY / BLOCKED / MISSING for each

If any pre-condition is MISSING (not just BLOCKED waiting for another WT), stop and report what's missing.

## Step 4: Ensure development is current

```bash
cd "$CLAUDE_PROJECT_DIR"
git fetch origin development
git checkout development
git pull --ff-only
```

Report if pull brought any new commits.

## Step 5: Verify .worktrees/ is gitignored

```bash
git check-ignore -q .worktrees 2>/dev/null || {
  echo "ERROR: .worktrees/ not in .gitignore" >&2
  exit 1
}
```

## Step 6: Create all worktrees

For each worktree in READY state (no unresolved deps), create it:

```bash
# For each WT: wt-number=3, branch=feat/rndc-protocol, etc.
WORKTREE_PATH="$CLAUDE_PROJECT_DIR/.worktrees/<branch-name>"
git worktree add "$WORKTREE_PATH" -b "<branch-name>" development
```

For each worktree in BLOCKED state (waiting for another WT): do NOT create it yet. Just report it in the summary.

After creating all READY worktrees, run a quick compile check in each:

```bash
cd "$WORKTREE_PATH"
cargo check --workspace --quiet 2>&1 | tail -2
```

## Step 7: Output parallel execution table

```
## Parallel Wave Setup Complete

### Dependency Order
<Print a simple diagram:>
  WT-3 ──────┐
  WT-4 ──────┼──→ development (merge in sequence after all complete)
  WT-5 ← WT-3 (depends on WT-3 completing first)

### Worktree Status

| WT | Branch | Path | Status | First Task | Open With |
| --- | --- | --- | --- | --- | --- |
| wt3 | feat/rndc-protocol | .worktrees/feat/rndc-protocol | READY | Chunk 1: ... | code .worktrees/feat/rndc-protocol |
| wt4 | feat/stats-nsupdate | .worktrees/feat/stats-nsupdate | READY | Chunk 1: ... | code .worktrees/feat/stats-nsupdate |
| wt5 | feat/wt5-hardening | .worktrees/feat/wt5-hardening | BLOCKED (needs wt3) | — | — |

### Parallel Tracks

**Start simultaneously:**
- WT-3: `code .worktrees/<branch>`
- WT-4: `code .worktrees/<branch>`

**After WT-3 merges to development:**
- WT-5: run `/wave-setup wt5` (will re-read plan with updated pre-conditions)

### Merge Order (when worktrees complete)

Merge fastest/least risky first. Suggested order:
1. WT-4 (independent of WT-3)
2. WT-3
3. WT-5 (after WT-3)

Each merge: `git checkout development && git merge --ff-only <branch>`, then run `/ci-check` before next merge.
```

## Notes

- Each parallel worktree runs in a SEPARATE Claude Code window — open each path in a new `code`/`cursor` session
- Worktrees share the same object store but have independent working trees and HEAD pointers
- Do NOT edit the same file in two worktrees simultaneously — coordinate by crate ownership
- If two worktrees need to touch the same file, that's a sign they should be sequential, not parallel
