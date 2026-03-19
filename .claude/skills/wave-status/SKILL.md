<!-- SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io> -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

---
name: wave-status
description: Show status of all active git worktrees — branch, commit count ahead of development, test count, and merge readiness
disable-model-invocation: true
argument-hint: "[merge <wt-branch>]"
allowed-tools: Bash, Read
---

Show or act on the status of all active git worktrees.

## Mode

- No arguments → show status of all active worktrees
- `merge <branch>` → fast-forward merge the named branch into development and clean up its worktree

---

## Status Mode (no arguments)

### Step 1: List worktrees

```bash
cd "$CLAUDE_PROJECT_DIR"
git worktree list --porcelain
```

Skip the main worktree (the one without a branch prefix of `feat/` or `fix/`).

### Step 2: For each feature worktree, gather stats

```bash
# Commits ahead of development
git -C "$WORKTREE_PATH" log development..HEAD --oneline | wc -l

# Files changed vs development
git -C "$WORKTREE_PATH" diff --stat development...HEAD | tail -1

# Test count (quick — parse test function count)
grep -r "^    fn test_" "$WORKTREE_PATH/crates" --include="*.rs" | wc -l

# Clippy status (fast check, non-blocking)
git -C "$WORKTREE_PATH" status --short | head -5
```

### Step 3: For each worktree, assess merge readiness

READY: no outstanding changes (clean working tree), ahead of development by ≥ 1 commit
IN PROGRESS: uncommitted changes present
STALE: branch is behind development (needs rebase)
EMPTY: 0 commits ahead — nothing done yet

### Step 4: Output status table

```
## Wave Worktree Status

| Branch | Path | Ahead | Files Changed | Status | Action |
| --- | --- | --- | --- | --- | --- |
| feat/rndc-protocol | .worktrees/feat/rndc-protocol | 8 | +1200/-45 | READY | /wave-status merge feat/rndc-protocol |
| feat/stats-nsupdate | .worktrees/feat/stats-nsupdate | 3 | +450/-12 | IN PROGRESS | — |

**Suggested merge order**: feat/rndc-protocol first (READY, lower risk), then feat/stats-nsupdate after it lands
```

---

## Merge Mode (`merge <branch>`)

Merge the specified worktree branch into development and remove the worktree.

### Step 1: Run CI gate first

```bash
cd "$WORKTREE_PATH"
cargo fmt --check --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p bind9-sdk-core --target wasm32-unknown-unknown
```

If any stage fails, STOP and report. Do not merge with failing checks.

### Step 2: Fast-forward merge

```bash
cd "$CLAUDE_PROJECT_DIR"
git checkout development
git merge --ff-only <branch>
```

If `--ff-only` fails (branch diverged), report and ask whether to rebase or squash-merge. Do NOT force-merge without asking.

### Step 3: Remove worktree

```bash
git worktree remove "$WORKTREE_PATH"
git branch -d <branch>
```

### Step 4: Confirm

```bash
git log --oneline -5
cargo test --workspace --quiet 2>&1 | tail -3
```

Report how many commits were merged and the current test count.

### Step 5: Check remaining worktrees

Run status mode again to show remaining worktrees. If any were BLOCKED on this branch, note they are now unblocked.
