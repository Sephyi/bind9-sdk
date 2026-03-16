// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Compile-fail test to verify RndcConnection typestate enforcement.
//!
//! This test verifies that calling `command()` on an `Unauthenticated`
//! connection does not compile.

#[test]
fn rndc_typestate_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/rndc_unauthenticated_command.rs");
}
