// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Compile-fail test to verify RndcConnection typestate enforcement.
//!
//! This test verifies that calling `command()` on an `Unauthenticated`
//! connection does not compile.

#[test]
fn rndc_typestate_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/rndc_unauthenticated_command.rs");
}
