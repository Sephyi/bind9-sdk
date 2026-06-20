// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! DNSSEC key-rollover workflow helpers (FR-071).
//!
//! Builds on `rndc dnssec -status` (KASP) introspection and `rndc dnssec
//! -checkds` to drive a CDS/CDNSKEY KSK rollover. The state is derived purely
//! from the observable KASP key states reported by BIND, so [`derive_state`] is
//! side-effect free and unit-testable; [`RolloverWorkflow::check`] reads the
//! live status and [`RolloverWorkflow::advance`] performs the one rndc action
//! the current state permits.
//!
//! Deviation from the PRD sketch: no `deadline: DateTime<Utc>` field is exposed
//! because `rndc dnssec -status` does not report KASP transition timestamps in
//! the parsed surface, and the crate does not depend on `chrono`. Timing-based
//! gating remains BIND's responsibility.

use bind9_sdk_core::domain::DomainName;

use crate::config::Bind9Client;
use crate::error::NetError;
use crate::rndc::command::DsState;
use crate::rndc::dnssec::{DnssecStatus, KeyRole};

/// Coarse KSK rollover state derived from KASP key states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RolloverState {
    /// No rollover in progress; keys are stable (or the zone is unsigned).
    Stable,
    /// A new KSK is published and its DS must appear in the parent zone before
    /// the rollover can proceed (CDS/CDNSKEY awaiting parent pickup).
    WaitingForDs,
    /// The new DS has been confirmed to BIND; the rollover is progressing.
    DsPublished,
    /// An old KSK is being withdrawn (retiring).
    OldKeyRetired,
}

/// The next action a caller may take to advance the rollover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RolloverAction {
    /// Nothing to do; wait for BIND/KASP to progress.
    Wait,
    /// Submit the new KSK's DS to the parent (registrar), then confirm.
    SubmitDsToParent,
    /// Tell BIND the parent DS is published (`rndc dnssec -checkds -published`).
    ConfirmDsPublished,
}

/// A KSK rollover workflow snapshot for a zone (FR-071).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RolloverWorkflow {
    /// Zone the workflow applies to.
    pub zone: DomainName,
    /// Current derived rollover state.
    pub state: RolloverState,
    /// The next action the operator/automation may take.
    pub next_action: RolloverAction,
}

/// Derive the rollover state purely from a parsed DNSSEC status (no I/O).
pub fn derive_state(status: &DnssecStatus) -> (RolloverState, RolloverAction) {
    let mut new_ksk_pending = false;
    let mut old_ksk_retiring = false;

    for key in &status.keys {
        if !matches!(key.role, KeyRole::Ksk | KeyRole::Csk) {
            continue;
        }
        match key.state.to_ascii_uppercase().as_str() {
            // New key introduced into the zone, not yet trusted in the parent.
            "RUMOURED" => new_ksk_pending = true,
            // Key on its way out.
            "UNRETENTIVE" | "HIDDEN" => old_ksk_retiring = true,
            _ => {}
        }
    }

    if new_ksk_pending {
        (
            RolloverState::WaitingForDs,
            RolloverAction::SubmitDsToParent,
        )
    } else if old_ksk_retiring {
        (RolloverState::OldKeyRetired, RolloverAction::Wait)
    } else {
        (RolloverState::Stable, RolloverAction::Wait)
    }
}

impl RolloverWorkflow {
    /// Read the live DNSSEC status and report the current rollover state
    /// without side effects (FR-071).
    pub async fn check(client: &Bind9Client, zone: &DomainName) -> Result<Self, NetError> {
        let status = client.dnssec_status(zone).await?;
        let (state, next_action) = derive_state(&status);
        Ok(Self {
            zone: zone.clone(),
            state,
            next_action,
        })
    }

    /// Execute the next rndc command the current state permits (FR-071).
    ///
    /// When the rollover is [`RolloverState::WaitingForDs`], this informs BIND
    /// that the parent DS is published (`rndc dnssec -checkds -published`) and
    /// returns the re-checked workflow. In any other state it is a no-op that
    /// simply re-reads the current state.
    pub async fn advance(client: &Bind9Client, zone: &DomainName) -> Result<Self, NetError> {
        let current = Self::check(client, zone).await?;
        if current.state == RolloverState::WaitingForDs {
            client.dnssec_checkds(zone, DsState::Published).await?;
        }
        Self::check(client, zone).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rndc::dnssec::DnssecKeyInfo;

    fn status(keys: Vec<DnssecKeyInfo>) -> DnssecStatus {
        DnssecStatus {
            policy: "default".into(),
            keys,
        }
    }

    fn key(role: KeyRole, state: &str) -> DnssecKeyInfo {
        DnssecKeyInfo {
            tag: 1,
            algorithm: Some("ECDSAP256SHA256".into()),
            role,
            state: state.into(),
        }
    }

    #[test]
    fn stable_when_all_omnipresent() {
        let s = status(vec![key(KeyRole::Csk, "OMNIPRESENT")]);
        assert_eq!(derive_state(&s).0, RolloverState::Stable);
    }

    #[test]
    fn waiting_for_ds_when_new_ksk_rumoured() {
        let s = status(vec![
            key(KeyRole::Ksk, "OMNIPRESENT"),
            key(KeyRole::Ksk, "RUMOURED"),
        ]);
        let (state, action) = derive_state(&s);
        assert_eq!(state, RolloverState::WaitingForDs);
        assert_eq!(action, RolloverAction::SubmitDsToParent);
    }

    #[test]
    fn old_key_retired_when_ksk_hidden() {
        let s = status(vec![
            key(KeyRole::Ksk, "OMNIPRESENT"),
            key(KeyRole::Ksk, "HIDDEN"),
        ]);
        assert_eq!(derive_state(&s).0, RolloverState::OldKeyRetired);
    }

    #[test]
    fn zsk_states_do_not_drive_ksk_rollover() {
        let s = status(vec![
            key(KeyRole::Ksk, "OMNIPRESENT"),
            key(KeyRole::Zsk, "RUMOURED"),
        ]);
        assert_eq!(derive_state(&s).0, RolloverState::Stable);
    }
}
