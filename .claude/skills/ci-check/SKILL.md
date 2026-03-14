---
name: ci-check
description: Run the bind9-sdk CI verification gate (fmt, clippy, tests, audit) and report results with actionable feedback
disable-model-invocation: true
argument-hint: "[fast|full|test <name>]"
allowed-tools: Bash
---

Run the bind9-sdk CI verification gate. Stages run **sequentially but independently** — do not chain with `&&`. Run each as a separate Bash command so all failures are reported even if an early stage fails.

## Mode (from $ARGUMENTS)

- No arguments or `full` → all stages: fmt, clippy, test, audit
- `fast` → fmt and clippy only (skip tests and audit — useful during rapid iteration)
- `test <name>` → fmt, clippy, then `cargo test --test <name>` for a specific integration test

## Stages

Run each applicable stage as a separate Bash command in the project root:

1. **Format check**: `cargo fmt --check`
2. **Clippy**: `cargo clippy --all-targets -- -D warnings`
3. **Tests**: `cargo test --all-targets` (or `cargo test --test <name>` for targeted mode)
4. **Audit**: `cargo audit` — skip with a note if `cargo-audit` is not installed; suggest `cargo install cargo-audit`

## Output

After all stages complete, produce a summary table:

| Stage | Status | Details |
|-------|--------|---------|
| Format | PASS/FAIL | Run `cargo fmt` to fix if failed |
| Clippy | PASS/FAIL | Warning count and specific warnings if failed |
| Tests | PASS/FAIL | Failed test names and output if failed |
| Audit | PASS/FAIL/SKIP | Advisory IDs and affected crates if failed |

If any stage failed, **offer to fix the issues immediately** — e.g., run `cargo fmt` for format failures, fix clippy warnings inline, investigate failing tests.

## Error Recovery

| Failure | Action |
| --- | --- |
| `cargo audit` not installed | Skip audit stage, print "Install: cargo install cargo-audit". Continue with other stages. |
| `cargo clippy` fails with errors | Report all errors. Do not continue to test stage — fix clippy first. |
| `cargo fmt --check` fails | Run `cargo fmt` to fix, then re-run check. |
| Tests fail | Report failing test names. Do not block — report and let user decide. |
