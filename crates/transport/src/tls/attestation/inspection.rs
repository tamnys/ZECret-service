//! Diagnostic authentication consumes the session but never grants query authority.

use super::{
    PhalaTrustedRpcSession, PreviewRpcSession, PrivateDeadline, UnverifiedPublicEvidence,
    VerifiedRpcSession, collateral_expired,
};
use crate::tls::MAX_CONNECTION_LIFETIME;
use serde::Serialize;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zrpc_protocol::Backend;
use zrpc_verifier::{
    ApprovedRelease, PhalaTrustedPolicy, PhalaTrustedRelease, ReleasePolicy,
    gcp::BoundGcpWorkloadInspection,
    offline::{
        BoundQuoteInspection, InspectionStatus, inspect_phala_public_preview_quote_and_report_data,
    },
    workload::{
        BoundWorkloadInspection, PhalaTrustedWorkloadPolicy, WorkloadInspection, WorkloadPolicy,
        inspect_phala_public_preview_workload, inspect_phala_trusted_workload_and_report_data,
        inspect_workload_and_report_data,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointInspectionIssue {
    ConnectionExpired,
    ConnectionClosed,
    ClockUnavailable,
    ClockChangedDuringInspection,
    CollateralExpiredDuringInspection,
    MalformedQuoteEncoding,
    ChallengeMismatch,
}

#[derive(Clone, Copy)]
enum InspectionPolicy<'a> {
    Exact(&'a WorkloadPolicy),
    PhalaTrusted(&'a PhalaTrustedWorkloadPolicy),
}

/// The checks describe this inspection only, not an approved release or a
/// continuing connection capability. Raw evidence and identifiers are omitted.
#[derive(Debug, Serialize)]
pub struct EndpointInspection {
    pub operation: &'static str,
    pub platform: Backend,
    pub evidence: Option<BoundWorkloadInspection>,
    pub hardware_evidence: Option<BoundQuoteInspection>,
    pub gcp_evidence: Option<BoundGcpWorkloadInspection>,
    pub local_session_lifetime: InspectionStatus,
    pub session_observed_open: InspectionStatus,
    pub local_clock: InspectionStatus,
    pub release_policy_provenance: InspectionStatus,
    pub approved_workload_ownership: InspectionStatus,
    pub freshness: InspectionStatus,
    pub live_key_binding: InspectionStatus,
    pub private_accepted: bool,
    pub query_sent: bool,
    pub network_used: bool,
    pub issue: Option<EndpointInspectionIssue>,
    // Only the authorization path consumes this in-memory timestamp. It is
    // derived from the authenticated QVL claim and never serialized as policy.
    #[serde(skip)]
    pub(super) private_collateral_deadline: Option<PrivateDeadline>,
}

impl EndpointInspection {
    pub(super) fn new() -> Self {
        Self {
            operation: "endpoint_evidence_inspection",
            platform: Backend::PhalaDstack,
            evidence: None,
            hardware_evidence: None,
            gcp_evidence: None,
            local_session_lifetime: InspectionStatus::NotChecked,
            session_observed_open: InspectionStatus::NotChecked,
            local_clock: InspectionStatus::NotChecked,
            release_policy_provenance: InspectionStatus::NotChecked,
            approved_workload_ownership: InspectionStatus::NotChecked,
            freshness: InspectionStatus::NotChecked,
            live_key_binding: InspectionStatus::NotChecked,
            private_accepted: false,
            query_sent: false,
            // Construction follows the consumed nonce-only public exchange.
            network_used: true,
            issue: None,
            private_collateral_deadline: None,
        }
    }

    /// Suitable for a diagnostic command's exit code only. Explicit local
    /// expectations are not approved release policy, and private mode remains
    /// unavailable even if every diagnostic comparison passes.
    pub fn diagnostic_passed(&self) -> bool {
        self.issue.is_none()
            && self.local_session_lifetime == InspectionStatus::Verified
            && self.session_observed_open == InspectionStatus::Verified
            && self.local_clock == InspectionStatus::Verified
            && (match self.platform {
                Backend::GcpTdx => self
                    .gcp_evidence
                    .as_ref()
                    .is_some_and(|evidence| evidence.diagnostic_passed()),
                Backend::PhalaDstack => self.evidence.as_ref().is_some_and(|evidence| {
                    let quote = &evidence.workload.quote;
                    quote.issue.is_none()
                        && evidence.workload.workload_issue.is_none()
                        && evidence.workload.runtime_event_integrity == InspectionStatus::Verified
                        && evidence.workload.os_measurement_policy == InspectionStatus::Verified
                        && evidence.workload.app_configuration_policy == InspectionStatus::Verified
                        && quote.hardware_authenticity == InspectionStatus::Verified
                        && quote.security_policy == InspectionStatus::Verified
                        && quote.workload_policy == InspectionStatus::Verified
                        && evidence.authenticated_report_data_match == InspectionStatus::Verified
                }),
            })
    }

    /// A public-read gate only. This deliberately leaves workload identity,
    /// release provenance, and private approval unverified.
    pub fn public_preview_passed(&self) -> bool {
        self.platform == Backend::PhalaDstack
            && self.issue.is_none()
            && self.local_session_lifetime == InspectionStatus::Verified
            && self.session_observed_open == InspectionStatus::Verified
            && self.local_clock == InspectionStatus::Verified
            && self.freshness == InspectionStatus::Verified
            && self.live_key_binding == InspectionStatus::Verified
            && self.private_collateral_deadline.is_some()
            && self.hardware_evidence.as_ref().is_some_and(|evidence| {
                evidence.quote.issue.is_none()
                    && evidence.quote.hardware_authenticity == InspectionStatus::Verified
                    && evidence.quote.security_policy == InspectionStatus::Verified
                    && evidence.authenticated_report_data_match == InspectionStatus::Verified
            })
            && self.evidence.is_none()
            && self.approved_workload_ownership == InspectionStatus::NotChecked
            && !self.private_accepted
    }
}

impl UnverifiedPublicEvidence {
    /// Authenticate supplied collateral and the peer's quote/event log, compare
    /// an explicit local workload policy, and compare authenticated REPORTDATA
    /// with this original TLS session's private exporter. Provider report_data,
    /// vm_config, verification flags and timestamps are never authority inputs.
    ///
    /// This consumes and closes the session. CPU verification uses the current
    /// system clock; no historical clock, expected exporter or nonce can be
    /// supplied by callers. No private-query or VerifiedChannel result exists.
    pub fn inspect(
        self,
        collateral_json: &[u8],
        raw_app_compose: &[u8],
        policy: &WorkloadPolicy,
    ) -> EndpointInspection {
        self.inspect_against(
            collateral_json,
            raw_app_compose,
            InspectionPolicy::Exact(policy),
        )
    }

    /// Retain the original connection only for typed public reads after
    /// current-time QVL, nonce and exporter checks. No workload measurement is
    /// accepted or inferred. A failed report returns no RPC session.
    pub fn inspect_for_public_preview(
        self,
        collateral_json: &[u8],
    ) -> Result<(EndpointInspection, Option<PreviewRpcSession>), zrpc_protocol::SafeError> {
        self._session.origin.require_managed()?;
        let report = self.inspect_public_preview_evidence(collateral_json);
        if !report.public_preview_passed() {
            return Ok((report, None));
        }
        let deadline = report
            .private_collateral_deadline
            .ok_or_else(collateral_expired)?;
        let preview = PreviewRpcSession::from_public_preview_inspection(
            self._session,
            self.deadline,
            self.authority,
            deadline,
        )?;
        Ok((report, Some(preview)))
    }

    /// Compare the peer's fresh quote and event log with caller-supplied
    /// launch bytes under the public-preview TCB appraisal. This is only a
    /// diagnostic: the policy is not a reviewed release and the connection is
    /// consumed without yielding either public or private RPC authority.
    pub fn inspect_public_preview_launch(
        self,
        collateral_json: &[u8],
        raw_app_compose: &[u8],
        policy: &WorkloadPolicy,
    ) -> Result<(EndpointInspection, Option<WorkloadInspection>), zrpc_protocol::SafeError> {
        self._session.origin.require_managed()?;
        let mut report = self.inspect_public_preview_evidence(collateral_json);
        report.operation = "public_preview_launch_inspection";
        if !report.public_preview_passed() {
            return Ok((report, None));
        }
        let quote = hex::decode(&self.evidence.quote).map_err(|_| {
            zrpc_protocol::SafeError::new(
                zrpc_protocol::ErrorCode::InvalidRequest,
                "Attestation quote encoding is invalid.",
            )
        })?;
        let workload = inspect_phala_public_preview_workload(
            &quote,
            collateral_json,
            self.evidence.event_log.as_bytes(),
            raw_app_compose,
            policy,
        );
        Ok((report, Some(workload)))
    }

    fn inspect_public_preview_evidence(&self, collateral_json: &[u8]) -> EndpointInspection {
        let mut report = EndpointInspection::new();
        self.check_session(&mut report);
        if report.issue.is_some() {
            return report;
        }
        let before = SystemTime::now();
        let Ok(before_unix) = before.duration_since(UNIX_EPOCH) else {
            report.local_clock = InspectionStatus::Rejected;
            report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            return report;
        };
        report.local_clock = InspectionStatus::Verified;
        if self.evidence.nonce != self.nonce {
            report.freshness = InspectionStatus::Rejected;
            report.issue = Some(EndpointInspectionIssue::ChallengeMismatch);
            return report;
        }
        let quote = match hex::decode(&self.evidence.quote) {
            Ok(quote) => quote,
            Err(_) => {
                report.issue = Some(EndpointInspectionIssue::MalformedQuoteEncoding);
                return report;
            }
        };
        report.hardware_evidence = Some(inspect_phala_public_preview_quote_and_report_data(
            &quote,
            collateral_json,
            &self.expected_report_data,
        ));
        report.live_key_binding = report
            .hardware_evidence
            .as_ref()
            .unwrap()
            .authenticated_report_data_match;
        // The response's nonce echo alone is not authenticated freshness.
        // It becomes a signed claim only when the verified quote authenticates
        // REPORTDATA bound to this nonce-context TLS exporter.
        if report.live_key_binding == InspectionStatus::Verified {
            report.freshness = InspectionStatus::Verified;
        }
        self.check_session(&mut report);
        let after_instant = Instant::now();
        let after = SystemTime::now();
        let Ok(after_unix) = after.duration_since(UNIX_EPOCH) else {
            report.local_clock = InspectionStatus::Rejected;
            report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            return report;
        };
        let inspection = &report.hardware_evidence.as_ref().unwrap().quote;
        match inspection.checked_at_unix_seconds {
            None => {
                report.local_clock = InspectionStatus::Rejected;
                report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            }
            Some(checked)
                if after < before
                    || checked < before_unix.as_secs()
                    || checked > after_unix.as_secs() =>
            {
                report.local_clock = InspectionStatus::Rejected;
                report.issue = Some(EndpointInspectionIssue::ClockChangedDuringInspection);
            }
            _ => {
                if let Some(expiration) = inspection.collateral_earliest_expiration_unix_seconds {
                    match PrivateDeadline::from_inspection_snapshot(
                        expiration,
                        after,
                        after_instant,
                    ) {
                        Some(deadline) => report.private_collateral_deadline = Some(deadline),
                        None => {
                            report.issue.get_or_insert(
                                EndpointInspectionIssue::CollateralExpiredDuringInspection,
                            );
                        }
                    }
                }
            }
        }
        report
    }

    /// Only client-packaged reviewed releases can authorize the retained TLS
    /// sender. Every selected release is compared against authenticated quote
    /// claims and the exact session exporter; none are learned from the peer.
    pub fn authorize(
        self,
        collateral_json: &[u8],
        raw_app_compose: &[u8],
        selection: &ReleasePolicy,
    ) -> Result<VerifiedRpcSession, zrpc_protocol::SafeError> {
        self._session.origin.require_managed()?;
        let releases = ApprovedRelease::selected(selection)?;
        if releases.is_empty() {
            return Err(zrpc_protocol::SafeError::new(
                zrpc_protocol::ErrorCode::UnknownRelease,
                "This client has no selected reviewed release.",
            ));
        }
        let collateral_deadline = releases.iter().find_map(|release| {
            let Some(policy) = release.workload() else {
                return None;
            };
            if !release.matches_launch_config(raw_app_compose) {
                return None;
            }
            let report = self.inspect_against(
                collateral_json,
                raw_app_compose,
                InspectionPolicy::Exact(policy),
            );
            report
                .diagnostic_passed()
                .then_some(report.private_collateral_deadline)
                .flatten()
        });
        let Some(collateral_deadline) = collateral_deadline else {
            return Err(zrpc_protocol::SafeError::new(
                zrpc_protocol::ErrorCode::PrivateModeUnavailable,
                "Hardware, workload, freshness or live TLS key did not match a reviewed release.",
            ));
        };
        // Ownership moves, so this is the same sender that received the quote.
        VerifiedRpcSession::from_authenticated_inspection(
            self._session,
            self.deadline,
            self.authority,
            collateral_deadline,
        )
    }

    /// Authorize the explicitly qualified Phala-trusting profile. This has a
    /// separate packaged catalog and never accepts diagnostic preview evidence.
    pub fn authorize_phala_trusted(
        self,
        collateral_json: &[u8],
        raw_app_compose: &[u8],
        selection: &PhalaTrustedPolicy,
    ) -> Result<PhalaTrustedRpcSession, zrpc_protocol::SafeError> {
        self._session.origin.require_managed()?;
        let releases = PhalaTrustedRelease::selected(selection)?;
        if releases.is_empty() {
            return Err(zrpc_protocol::SafeError::new(
                zrpc_protocol::ErrorCode::UnknownRelease,
                "This client has no selected reviewed Phala-trusting release.",
            ));
        }
        let collateral_deadline = releases.iter().find_map(|release| {
            let policy = release.workload();
            if !release.matches_launch_config(raw_app_compose) {
                return None;
            }
            let report = self.inspect_against(
                collateral_json,
                raw_app_compose,
                InspectionPolicy::PhalaTrusted(policy),
            );
            report
                .diagnostic_passed()
                .then_some(report.private_collateral_deadline)
                .flatten()
        });
        let Some(collateral_deadline) = collateral_deadline else {
            return Err(zrpc_protocol::SafeError::new(
                zrpc_protocol::ErrorCode::PrivateModeUnavailable,
                "Hardware, workload, freshness or live TLS key did not match a reviewed Phala-trusting release.",
            ));
        };
        PhalaTrustedRpcSession::from_authenticated_inspection(
            self._session,
            self.deadline,
            self.authority,
            collateral_deadline,
        )
    }

    fn inspect_against(
        &self,
        collateral_json: &[u8],
        raw_app_compose: &[u8],
        policy: InspectionPolicy<'_>,
    ) -> EndpointInspection {
        let mut report = EndpointInspection::new();
        self.check_session(&mut report);
        if report.issue.is_some() {
            return report;
        }
        let before = SystemTime::now();
        let Ok(before_unix) = before.duration_since(UNIX_EPOCH) else {
            report.local_clock = InspectionStatus::Rejected;
            report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            return report;
        };
        report.local_clock = InspectionStatus::Verified;
        if self.evidence.nonce != self.nonce {
            report.issue = Some(EndpointInspectionIssue::ChallengeMismatch);
            return report;
        }
        let quote = match hex::decode(&self.evidence.quote) {
            Ok(quote) => quote,
            Err(_) => {
                report.issue = Some(EndpointInspectionIssue::MalformedQuoteEncoding);
                return report;
            }
        };
        report.evidence = Some(match policy {
            InspectionPolicy::PhalaTrusted(policy) => {
                inspect_phala_trusted_workload_and_report_data(
                    &quote,
                    collateral_json,
                    self.evidence.event_log.as_bytes(),
                    raw_app_compose,
                    policy,
                    &self.expected_report_data,
                )
            }
            InspectionPolicy::Exact(policy) => inspect_workload_and_report_data(
                &quote,
                collateral_json,
                self.evidence.event_log.as_bytes(),
                raw_app_compose,
                policy,
                &self.expected_report_data,
            ),
        });
        // Recheck after synchronous cryptographic/event-log work: its cost must
        // not extend the original lifetime or leave a closed session accepted.
        self.check_session(&mut report);
        let after_instant = Instant::now();
        let after = SystemTime::now();
        let Ok(after_unix) = after.duration_since(UNIX_EPOCH) else {
            report.local_clock = InspectionStatus::Rejected;
            report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            return report;
        };
        let inspection = &report.evidence.as_ref().unwrap().workload.quote;
        match inspection.checked_at_unix_seconds {
            None => {
                report.local_clock = InspectionStatus::Rejected;
                report.issue = Some(EndpointInspectionIssue::ClockUnavailable);
            }
            Some(checked)
                if after < before
                    || checked < before_unix.as_secs()
                    || checked > after_unix.as_secs() =>
            {
                report.local_clock = InspectionStatus::Rejected;
                report.issue = Some(EndpointInspectionIssue::ClockChangedDuringInspection);
            }
            _ => {
                // The original authenticated validity instant is reported by
                // QVL. Evidence that expires during CPU work cannot pass now.
                if let Some(expiration) = inspection.collateral_earliest_expiration_unix_seconds {
                    match PrivateDeadline::from_inspection_snapshot(
                        expiration,
                        after,
                        after_instant,
                    ) {
                        Some(deadline) => report.private_collateral_deadline = Some(deadline),
                        None => {
                            report.issue.get_or_insert(
                                EndpointInspectionIssue::CollateralExpiredDuringInspection,
                            );
                        }
                    }
                }
            }
        }
        report
    }

    fn check_session(&self, report: &mut EndpointInspection) {
        let now = Instant::now();
        if now >= self.deadline
            || now
                .checked_duration_since(self.established)
                .is_none_or(|age| age >= MAX_CONNECTION_LIFETIME)
        {
            report.local_session_lifetime = InspectionStatus::Rejected;
            report
                .issue
                .get_or_insert(EndpointInspectionIssue::ConnectionExpired);
        } else {
            report.local_session_lifetime = InspectionStatus::Verified;
        }
        if self._session.sender.is_closed() || self._session.driver.is_finished() {
            report.session_observed_open = InspectionStatus::Rejected;
            report
                .issue
                .get_or_insert(EndpointInspectionIssue::ConnectionClosed);
        } else {
            report.session_observed_open = InspectionStatus::Verified;
        }
    }
}

#[cfg(test)]
mod tests;
