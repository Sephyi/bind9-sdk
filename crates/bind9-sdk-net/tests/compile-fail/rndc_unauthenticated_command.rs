// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! This file MUST NOT compile. It verifies that `command()` is not
//! available on `RndcConnection<Unauthenticated>`.

use bind9_sdk_net::rndc::command::RndcCommand;
use bind9_sdk_net::rndc::{RndcConnection, Unauthenticated};

async fn should_not_compile() {
    // This line must fail to compile because command() is only
    // available on RndcConnection<Authenticated>.
    let addr = "127.0.0.1:953".parse().unwrap();
    let mut conn: RndcConnection<Unauthenticated> = RndcConnection::connect(addr).await.unwrap();
    conn.command(RndcCommand::Status).await.unwrap();
}

fn main() {}
