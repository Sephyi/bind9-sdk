<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

---
name: wave-setup
description: Create an isolated git worktree for a Wave worktree plan, branch off development, and print the plan summary
disable-model-invocation: true
argument-hint: "<wt-number> (e.g., wt3, wt4, wt5)"
allowed-tools: Bash, Read, Glob, Grep
---

Set up a git worktree for the specified Wave worktree plan.

## Input

`$ARGUMENTS` is the worktree identifier, e.g., `wt3`, `wt4`, `wt5`.

If `$ARGUMENTS` is empty, ask the user which worktree to set up.

## Step 1: Resolve plan file

Find the plan doc matching the worktree number:

```bash
ls docs/plans/*wt${NUMBER}* docs/plans/*wave*${NUMBER}* 2>/dev/null
```

If no plan file found, report and stop.

## Step 2: Read plan metadata

Read the first 40 lines of the plan file to extract:
- **Branch name** (from `**Branch:**` line)
- **Goal** (from `**Goal:**` line)
- **Pre-conditions** section

## Step 3: Verify pre-conditions

Check that the current `development` branch has the required exports/types mentioned in pre-conditions. Use `grep` to verify key items exist in the codebase. Report any missing pre-conditions and stop if critical ones are absent.

## Step 4: Create worktree

```bash
# Ensure .worktrees/ directory exists and is gitignored
cd "$CLAUDE_PROJECT_DIR"
git check-ignore -q .worktrees 2>/dev/null || {
  echo "ERROR: .worktrees/ is not in .gitignore — add it before creating project-local worktrees" >&2
  exit 1
}

# Ensure development is up to date
git fetch origin development
git checkout development
git pull --ff-only

# Create worktree inside .worktrees/ (gitignored, project-local)
WORKTREE_PATH="$CLAUDE_PROJECT_DIR/.worktrees/<branch-name>"
BRANCH_NAME="<branch from plan>"

git worktree add "$WORKTREE_PATH" -b "$BRANCH_NAME" development
```

If the worktree path already exists, report and ask user whether to reuse or remove it.

## Step 5: Run setup in worktree

```bash
cd "$WORKTREE_PATH"
cargo check --workspace --quiet 2>&1 | tail -3
```

Report any compilation errors. If clean, confirm worktree is ready.

## Step 6: Print summary

Output:
- Worktree path (relative: `.worktrees/<branch>`)
- Branch name
- Plan file path
- Goal (one line)
- Number of chunks and tasks
- First chunk/task name to start with
- Suggested command to open: `code .worktrees/<branch>` (VSCode) or `cursor .worktrees/<branch>`
