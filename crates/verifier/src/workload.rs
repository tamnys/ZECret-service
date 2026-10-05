//! Offline comparison with an explicit local policy, never release approval.
//! The dstack v0.5.9 KMS boot sequence is the supported evidence format.
use crate::offline::{self, InspectionStatus, OfflineInspection};
use cc_eventlog::{RuntimeEvent, TdxEvent};
use dcap_qvl::quote::TDReport10;
use ez_hash::{Hasher, Sha256, Sha384};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadPolicy {
    pub schema_version: u32,
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub mrtd: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub rtmr0: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub rtmr1: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub rtmr2: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub os_image_hash: [u8; 32],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub compose_hash: [u8; 32],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub mr_kms: [u8; 32],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub app_id: [u8; 20],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub instance_id: [u8; 20],
    pub storage_fs: StorageFs,
    pub key_provider: KeyProviderPolicy,
}

/// A separately packaged expectation for the explicit Phala-trusting profile.
/// It still pins the guest, app and KMS public-key identity, but deliberately
/// does not claim that Phala's KMS code measurement has been independently
/// approved. It cannot be supplied by a diagnostic policy file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhalaKeyPinnedWorkloadPolicy {
    pub schema_version: u32,
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub mrtd: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub rtmr0: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub rtmr1: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub rtmr2: [u8; 48],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub os_image_hash: [u8; 32],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub compose_hash: [u8; 32],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub app_id: [u8; 20],
    #[serde(deserialize_with = "decode_hash", serialize_with = "encode_hash")]
    pub instance_id: [u8; 20],
    pub storage_fs: StorageFs,
    pub key_provider: KeyProviderPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhalaTrustedWorkloadPolicy {
    Exact(WorkloadPolicy),
    KmsKeyPinned(PhalaKeyPinnedWorkloadPolicy),
}

impl PhalaKeyPinnedWorkloadPolicy {
    pub(crate) fn validate(&self) -> Result<(), WorkloadIssue> {
        if self.schema_version != 2
            || self.key_provider.name != "kms"
            || self.key_provider.id.is_empty()
            || self.app_id == [0; 20]
            || self.instance_id == [0; 20]
        {
            return Err(WorkloadIssue::InvalidPolicy);
        }
        Ok(())
    }
}

impl PhalaTrustedWorkloadPolicy {
    pub fn os_image_hash(&self) -> &[u8; 32] {
        match self {
            Self::Exact(policy) => &policy.os_image_hash,
            Self::KmsKeyPinned(policy) => &policy.os_image_hash,
        }
    }

    pub fn compose_hash(&self) -> &[u8; 32] {
        match self {
            Self::Exact(policy) => &policy.compose_hash,
            Self::KmsKeyPinned(policy) => &policy.compose_hash,
        }
    }

    pub fn key_provider(&self) -> &KeyProviderPolicy {
        match self {
            Self::Exact(policy) => &policy.key_provider,
            Self::KmsKeyPinned(policy) => &policy.key_provider,
        }
    }
}

#[derive(Clone, Copy)]
enum ExpectedWorkload<'a> {
    Exact(&'a WorkloadPolicy),
    PhalaKmsKeyPinned(&'a PhalaKeyPinnedWorkloadPolicy),
}

struct WorkloadFields<'a> {
    mrtd: &'a [u8; 48],
    rtmr0: &'a [u8; 48],
    rtmr1: &'a [u8; 48],
    rtmr2: &'a [u8; 48],
    os_image_hash: &'a [u8; 32],
    compose_hash: &'a [u8; 32],
    mr_kms: Option<&'a [u8; 32]>,
    app_id: &'a [u8; 20],
    instance_id: &'a [u8; 20],
    storage_fs: StorageFs,
    key_provider: &'a KeyProviderPolicy,
}

impl<'a> ExpectedWorkload<'a> {
    fn fields(self) -> Result<WorkloadFields<'a>, WorkloadIssue> {
        match self {
            Self::Exact(policy) => {
                policy.validate()?;
                Ok(WorkloadFields {
                    mrtd: &policy.mrtd,
                    rtmr0: &policy.rtmr0,
                    rtmr1: &policy.rtmr1,
                    rtmr2: &policy.rtmr2,
                    os_image_hash: &policy.os_image_hash,
                    compose_hash: &policy.compose_hash,
                    mr_kms: Some(&policy.mr_kms),
                    app_id: &policy.app_id,
                    instance_id: &policy.instance_id,
                    storage_fs: policy.storage_fs,
                    key_provider: &policy.key_provider,
                })
            }
            Self::PhalaKmsKeyPinned(policy) => {
                policy.validate()?;
                Ok(WorkloadFields {
                    mrtd: &policy.mrtd,
                    rtmr0: &policy.rtmr0,
                    rtmr1: &policy.rtmr1,
                    rtmr2: &policy.rtmr2,
                    os_image_hash: &policy.os_image_hash,
                    compose_hash: &policy.compose_hash,
                    mr_kms: None,
                    app_id: &policy.app_id,
                    instance_id: &policy.instance_id,
                    storage_fs: policy.storage_fs,
                    key_provider: &policy.key_provider,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageFs {
    Ext4,
    Zfs,
}

impl StorageFs {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Ext4 => b"ext4",
            Self::Zfs => b"zfs",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyProviderPolicy {
    pub name: String,
    pub id: String,
}

pub(crate) fn decode_hash<'de, D: Deserializer<'de>, const N: usize>(
    d: D,
) -> Result<[u8; N], D::Error> {
    let value = String::deserialize(d)?;
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| serde::de::Error::custom("invalid fixed-size hex value"))?;
    Ok(bytes)
}

pub(crate) fn encode_hash<S: Serializer, const N: usize>(
    value: &[u8; N],
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(value))
}

impl WorkloadPolicy {
    /// This parses operator-supplied expectations. It does not approve their
    /// provenance, measure an OS image, or register an approved release.
    pub fn from_json(bytes: &[u8]) -> Result<Self, WorkloadIssue> {
        let shape: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| WorkloadIssue::InvalidPolicy)?;
        if !shape.is_object() || !shape.get("key_provider").is_some_and(|v| v.is_object()) {
            return Err(WorkloadIssue::InvalidPolicy);
        }
        // Deserialize the original bytes so duplicate known fields are rejected.
        let policy: Self =
            serde_json::from_slice(bytes).map_err(|_| WorkloadIssue::InvalidPolicy)?;
        policy.validate()?;
        Ok(policy)
    }

    pub(crate) fn validate(&self) -> Result<(), WorkloadIssue> {
        if self.schema_version != 1
            || self.key_provider.name != "kms"
            || self.key_provider.id.is_empty()
        {
            return Err(WorkloadIssue::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadIssue {
    InvalidPolicy,
    UnsupportedEndianness,
    MalformedEventLog,
    UnsupportedEventFormat,
    RuntimeMeasurementMismatch,
    MissingBootEvent,
    AmbiguousBootEvent,
    UnexpectedBootEvent,
    InvalidBootSequence,
    OsMeasurementMismatch,
    OsImageDigestMismatch,
    ComposeHashMismatch,
    ApplicationIdentityMismatch,
    KeyProviderMismatch,
    KmsMeasurementMismatch,
    StoragePolicyMismatch,
}

/// Matching a supplied policy is a diagnostic, not approval of that policy or a
/// capability to send a query. No authenticated claims are returned to callers.
#[derive(Debug, Serialize)]
pub struct WorkloadInspection {
    #[serde(flatten)]
    pub quote: OfflineInspection,
    pub policy_source: &'static str,
    pub runtime_event_integrity: InspectionStatus,
    pub os_measurement_policy: InspectionStatus,
    pub app_configuration_policy: InspectionStatus,
    pub workload_issue: Option<WorkloadIssue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportDataIssue {
    AuthenticatedReportDataMismatch,
}

/// A comparison against caller-supplied expected bytes, not proof of how those
/// bytes were obtained, approved workload ownership, or private-query authority.
#[derive(Debug, Serialize)]
pub struct BoundWorkloadInspection {
    #[serde(flatten)]
    pub workload: WorkloadInspection,
    pub authenticated_report_data_match: InspectionStatus,
    pub binding_issue: Option<ReportDataIssue>,
}

/// Inspect supplied files at the system clock. There is no network fetch,
/// historical-time override, inferred expectation or release-registration path.
pub fn inspect_workload(
    quote: &[u8],
    collateral_json: &[u8],
    event_log_json: &[u8],
    raw_app_compose: &[u8],
    policy: &WorkloadPolicy,
) -> WorkloadInspection {
    inspect_workload_using(
        event_log_json,
        raw_app_compose,
        ExpectedWorkload::Exact(policy),
        None,
        |inspect| offline::inspect_quote_with_claims(quote, collateral_json, inspect),
    )
    .workload
}

/// Public-preview-only consistency check of a signed quote, replayed runtime
/// events, and caller-supplied launch bytes. Caller expectations can come from
/// the same provider and are not independent approval. This does not verify a
/// live TLS key or grant private-query authority.
pub fn inspect_phala_public_preview_workload(
    quote: &[u8],
    collateral_json: &[u8],
    event_log_json: &[u8],
    raw_app_compose: &[u8],
    policy: &WorkloadPolicy,
) -> WorkloadInspection {
    let mut report = inspect_workload_using(
        event_log_json,
        raw_app_compose,
        ExpectedWorkload::Exact(policy),
        None,
        |inspect| {
            offline::inspect_phala_public_preview_quote_with_claims(quote, collateral_json, inspect)
        },
    )
    .workload;
    report.quote.operation = "public_preview_workload_inspection";
    report.policy_source = "caller_supplied_public_preview_not_release_approval";
    report
}

/// Evaluate a client-packaged Phala-managed release's exact workload and the
/// original TLS exporter's signed REPORTDATA under its explicit TDX appraisal.
/// Only the transport can turn a successful result into a retained session.
pub fn inspect_phala_trusted_workload_and_report_data(
    quote: &[u8],
    collateral_json: &[u8],
    event_log_json: &[u8],
    raw_app_compose: &[u8],
    policy: &PhalaTrustedWorkloadPolicy,
    expected_report_data: &[u8; 64],
) -> BoundWorkloadInspection {
    let expected = match policy {
        PhalaTrustedWorkloadPolicy::Exact(policy) => ExpectedWorkload::Exact(policy),
        PhalaTrustedWorkloadPolicy::KmsKeyPinned(policy) => {
            ExpectedWorkload::PhalaKmsKeyPinned(policy)
        }
    };
    let mut result = inspect_workload_using(
        event_log_json,
        raw_app_compose,
        expected,
        Some(expected_report_data),
        |inspect| offline::inspect_phala_trusted_quote_with_claims(quote, collateral_json, inspect),
    );
    result.workload.policy_source = "client_packaged_phala_trusted_release";
    result
}

/// Authenticate supplied evidence at the current system clock before comparing
/// signed REPORTDATA. Echoed report_data strings or provider assertions are not
/// inputs. A match never approves the policy or constructs a verified channel.
pub fn inspect_workload_and_report_data(
    quote: &[u8],
    collateral_json: &[u8],
    event_log_json: &[u8],
    raw_app_compose: &[u8],
    policy: &WorkloadPolicy,
    expected_report_data: &[u8; 64],
) -> BoundWorkloadInspection {
    inspect_workload_using(
        event_log_json,
        raw_app_compose,
        ExpectedWorkload::Exact(policy),
        Some(expected_report_data),
        |inspect| offline::inspect_quote_with_claims(quote, collateral_json, inspect),
    )
}

fn inspect_workload_using(
    event_log_json: &[u8],
    raw_app_compose: &[u8],
    policy: ExpectedWorkload<'_>,
    expected_report_data: Option<&[u8; 64]>,
    inspect_quote: impl FnOnce(&mut dyn FnMut(&dcap_qvl::QuoteClaims)) -> OfflineInspection,
) -> BoundWorkloadInspection {
    let mut checks = Checks::new();
    let mut report_data = InspectionStatus::NotChecked;
    let mut quote = inspect_quote(&mut |claims| {
        // The callback runs only after the selected hardware appraisal passed.
        // Public-preview appraisal is weaker than private release policy;
        // expected bytes and measurements cannot replace either boundary.
        if let Some(td) = claims.report.as_td10() {
            if let Some(expected) = expected_report_data {
                report_data = compare_report_data(td, expected);
            }
            checks.issue =
                check_workload(td, event_log_json, raw_app_compose, policy, &mut checks).err();
        } else {
            checks.issue = Some(WorkloadIssue::UnsupportedEventFormat);
        }
    });
    quote.operation = "offline_workload_inspection";
    if checks.issue.is_some() {
        quote.workload_policy = InspectionStatus::Rejected;
    } else if checks.app == InspectionStatus::Verified {
        quote.workload_policy = InspectionStatus::Verified;
    }
    let workload = WorkloadInspection {
        quote,
        policy_source: "explicit_local_input_not_release_approval",
        runtime_event_integrity: checks.runtime,
        os_measurement_policy: checks.os,
        app_configuration_policy: checks.app,
        workload_issue: checks.issue,
    };
    BoundWorkloadInspection {
        workload,
        authenticated_report_data_match: report_data,
        binding_issue: (report_data == InspectionStatus::Rejected)
            .then_some(ReportDataIssue::AuthenticatedReportDataMismatch),
    }
}

fn compare_report_data(td: &TDReport10, expected: &[u8; 64]) -> InspectionStatus {
    if td.report_data == *expected {
        InspectionStatus::Verified
    } else {
        InspectionStatus::Rejected
    }
}

struct Checks {
    runtime: InspectionStatus,
    os: InspectionStatus,
    app: InspectionStatus,
    issue: Option<WorkloadIssue>,
}

impl Checks {
    fn new() -> Self {
        Self {
            runtime: InspectionStatus::NotChecked,
            os: InspectionStatus::NotChecked,
            app: InspectionStatus::NotChecked,
            issue: None,
        }
    }
}

fn runtime_events(bytes: &[u8]) -> Result<Vec<RuntimeEvent>, WorkloadIssue> {
    // Keep upstream byte decoding, while requiring unambiguous object-shaped
    // entries and rejecting fields its permissive serde model would ignore.
    let shape: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| WorkloadIssue::MalformedEventLog)?;
    let entries = shape.as_array().ok_or(WorkloadIssue::MalformedEventLog)?;
    for entry in entries {
        let object = entry.as_object().ok_or(WorkloadIssue::MalformedEventLog)?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "imr" | "event_type" | "digest" | "event" | "event_payload"
            )
        }) {
            return Err(WorkloadIssue::MalformedEventLog);
        }
    }
    let events: Vec<TdxEvent> =
        serde_json::from_slice(bytes).map_err(|_| WorkloadIssue::MalformedEventLog)?;
    let mut runtime = Vec::new();
    for event in events {
        if event.imr > 3 || (event.imr == 3) != event.is_runtime_event() {
            return Err(WorkloadIssue::UnsupportedEventFormat);
        }
        if let Some(measured) = event.to_runtime_event() {
            if !event.digest.is_empty() && event.digest != measured.sha384_digest() {
                return Err(WorkloadIssue::MalformedEventLog);
            }
            runtime.push(measured);
        }
    }
    Ok(runtime)
}

// Exact successful KMS boot order at the pinned dstack v0.5.9 source:
// dstack-util/src/system_setup.rs measure_app_info, request_app_keys,
// verify_app and setup_fs. Additional post-ready runtime events remain in replay.
const BOOT_SEQUENCE: [&str; 10] = [
    "system-preparing",
    "app-id",
    "compose-hash",
    "instance-id",
    "boot-mr-done",
    "mr-kms",
    "os-image-hash",
    "key-provider",
    "storage-fs",
    "system-ready",
];

fn boot_events(events: &[RuntimeEvent]) -> Result<&[RuntimeEvent], WorkloadIssue> {
    let mut ready = events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.event == "system-ready");
    let end = ready.next().ok_or(WorkloadIssue::MissingBootEvent)?.0;
    if ready.next().is_some() {
        return Err(WorkloadIssue::AmbiguousBootEvent);
    }
    let boot = &events[..=end];
    for name in BOOT_SEQUENCE {
        let mut found = boot.iter().filter(|event| event.event == name);
        if found.next().is_none() {
            return Err(WorkloadIssue::MissingBootEvent);
        }
        if found.next().is_some() {
            return Err(WorkloadIssue::AmbiguousBootEvent);
        }
    }
    if boot
        .iter()
        .any(|event| !BOOT_SEQUENCE.contains(&event.event.as_str()))
    {
        return Err(WorkloadIssue::UnexpectedBootEvent);
    }
    if !boot
        .iter()
        .map(|event| event.event.as_str())
        .eq(BOOT_SEQUENCE)
    {
        return Err(WorkloadIssue::InvalidBootSequence);
    }
    if [0, 4, 9].iter().any(|&i| !boot[i].payload.is_empty()) {
        return Err(WorkloadIssue::InvalidBootSequence);
    }
    Ok(boot)
}

fn check_workload(
    td: &TDReport10,
    event_log_json: &[u8],
    raw_app_compose: &[u8],
    policy: ExpectedWorkload<'_>,
    checks: &mut Checks,
) -> Result<(), WorkloadIssue> {
    let policy = policy.fields()?;
    // Upstream RuntimeEvent uses to_ne_bytes; the pinned dstack target is LE.
    if !cfg!(target_endian = "little") {
        return Err(WorkloadIssue::UnsupportedEndianness);
    }
    checks.runtime = InspectionStatus::Rejected;
    let runtime = runtime_events(event_log_json)?;
    if cc_eventlog::replay_events::<Sha384>(&runtime, None) != td.rt_mr3 {
        return Err(WorkloadIssue::RuntimeMeasurementMismatch);
    }
    checks.runtime = InspectionStatus::Verified;
    checks.app = InspectionStatus::Rejected;
    let boot = boot_events(&runtime)?;
    checks.os = InspectionStatus::Rejected;
    if td.mr_td != *policy.mrtd
        || td.rt_mr0 != *policy.rtmr0
        || td.rt_mr1 != *policy.rtmr1
        || td.rt_mr2 != *policy.rtmr2
    {
        return Err(WorkloadIssue::OsMeasurementMismatch);
    }
    if boot[6].payload != *policy.os_image_hash {
        return Err(WorkloadIssue::OsImageDigestMismatch);
    }
    checks.os = InspectionStatus::Verified;
    let actual_compose = Sha256::hash(raw_app_compose);
    if actual_compose != *policy.compose_hash || boot[2].payload != *policy.compose_hash {
        return Err(WorkloadIssue::ComposeHashMismatch);
    }
    if boot[1].payload != *policy.app_id || boot[3].payload != *policy.instance_id {
        return Err(WorkloadIssue::ApplicationIdentityMismatch);
    }
    if policy
        .mr_kms
        .is_some_and(|expected| boot[5].payload != *expected)
        || boot[5].payload.len() != 32
    {
        return Err(WorkloadIssue::KmsMeasurementMismatch);
    }
    if boot[8].payload != policy.storage_fs.as_bytes() {
        return Err(WorkloadIssue::StoragePolicyMismatch);
    }
    let provider_shape: serde_json::Value =
        serde_json::from_slice(&boot[7].payload).map_err(|_| WorkloadIssue::KeyProviderMismatch)?;
    if !provider_shape.is_object() {
        return Err(WorkloadIssue::KeyProviderMismatch);
    }
    let provider: KeyProviderPolicy =
        serde_json::from_slice(&boot[7].payload).map_err(|_| WorkloadIssue::KeyProviderMismatch)?;
    if provider != *policy.key_provider {
        return Err(WorkloadIssue::KeyProviderMismatch);
    }
    checks.app = InspectionStatus::Verified;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_qvl::quote::{Quote, Report};
    use parity_scale_codec::Encode;

    const RAW_COMPOSE: &[u8] = br#"{"simulation":"POLICY_UNIT_ONLY"}"#;
    const QUOTE: &[u8] = include_bytes!("../../../tests/fixtures/dcap/tdx_quote.exact.bin");
    const COLLATERAL: &[u8] =
        include_bytes!("../../../tests/fixtures/dcap/tdx_quote_collateral.json");

    // Deliberately fabricated expectations and report fields. These exercise
    // policy comparisons only and are never authentic evidence or release data.
    fn policy_unit_only() -> (WorkloadPolicy, TDReport10, Vec<RuntimeEvent>) {
        let policy = WorkloadPolicy {
            schema_version: 1,
            mrtd: [1; 48],
            rtmr0: [2; 48],
            rtmr1: [3; 48],
            rtmr2: [4; 48],
            os_image_hash: [5; 32],
            compose_hash: Sha256::hash(RAW_COMPOSE),
            mr_kms: [6; 32],
            app_id: [7; 20],
            instance_id: [8; 20],
            storage_fs: StorageFs::Ext4,
            key_provider: KeyProviderPolicy {
                name: "kms".into(),
                id: "POLICY_UNIT_ONLY".into(),
            },
        };
        let payloads = [
            vec![],
            policy.app_id.to_vec(),
            policy.compose_hash.to_vec(),
            policy.instance_id.to_vec(),
            vec![],
            policy.mr_kms.to_vec(),
            policy.os_image_hash.to_vec(),
            serde_json::to_vec(&policy.key_provider).unwrap(),
            b"ext4".to_vec(),
            vec![],
        ];
        let events = BOOT_SEQUENCE
            .into_iter()
            .zip(payloads)
            .map(|(name, payload)| RuntimeEvent::new(name.into(), payload))
            .collect::<Vec<_>>();
        let quote = Quote::parse(QUOTE).unwrap();
        let mut td = quote.report.as_td10().unwrap().clone();
        td.mr_td = policy.mrtd;
        td.rt_mr0 = policy.rtmr0;
        td.rt_mr1 = policy.rtmr1;
        td.rt_mr2 = policy.rtmr2;
        td.rt_mr3 = cc_eventlog::replay_events::<Sha384>(&events, None);
        (policy, td, events)
    }

    fn log_json(events: &[RuntimeEvent]) -> Vec<u8> {
        serde_json::to_vec(
            &events
                .iter()
                .cloned()
                .map(TdxEvent::from)
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn policy_check(
        policy: &WorkloadPolicy,
        td: &TDReport10,
        events: &[RuntimeEvent],
        raw: &[u8],
    ) -> Result<(), WorkloadIssue> {
        check_workload(
            td,
            &log_json(events),
            raw,
            ExpectedWorkload::Exact(policy),
            &mut Checks::new(),
        )
    }

    fn key_pinned(policy: &WorkloadPolicy) -> PhalaKeyPinnedWorkloadPolicy {
        PhalaKeyPinnedWorkloadPolicy {
            schema_version: 2,
            mrtd: policy.mrtd,
            rtmr0: policy.rtmr0,
            rtmr1: policy.rtmr1,
            rtmr2: policy.rtmr2,
            os_image_hash: policy.os_image_hash,
            compose_hash: policy.compose_hash,
            app_id: policy.app_id,
            instance_id: policy.instance_id,
            storage_fs: policy.storage_fs,
            key_provider: policy.key_provider.clone(),
        }
    }

    #[test]
    fn synthetic_key_pinned_policy_allows_only_changed_kms_measurement() {
        let (exact, mut td, mut events) = policy_unit_only();
        let pinned = key_pinned(&exact);
        let check = |td: &TDReport10, events: &[RuntimeEvent]| {
            check_workload(
                td,
                &log_json(events),
                RAW_COMPOSE,
                ExpectedWorkload::PhalaKmsKeyPinned(&pinned),
                &mut Checks::new(),
            )
        };
        assert_eq!(check(&td, &events), Ok(()));
        events[5].payload[0] ^= 1;
        td.rt_mr3 = cc_eventlog::replay_events::<Sha384>(&events, None);
        assert_eq!(check(&td, &events), Ok(()));
        assert_eq!(
            policy_check(&exact, &td, &events, RAW_COMPOSE),
            Err(WorkloadIssue::KmsMeasurementMismatch)
        );
        for (index, expected) in [
            (1, WorkloadIssue::ApplicationIdentityMismatch),
            (2, WorkloadIssue::ComposeHashMismatch),
            (3, WorkloadIssue::ApplicationIdentityMismatch),
            (6, WorkloadIssue::OsImageDigestMismatch),
            (7, WorkloadIssue::KeyProviderMismatch),
            (8, WorkloadIssue::StoragePolicyMismatch),
        ] {
            let mut changed = events.clone();
            changed[index].payload[0] ^= 1;
            let mut changed_td = td.clone();
            changed_td.rt_mr3 = cc_eventlog::replay_events::<Sha384>(&changed, None);
            assert_eq!(check(&changed_td, &changed), Err(expected));
        }
        let mut malformed = events.clone();
        malformed[5].payload.pop();
        let mut changed_td = td.clone();
        changed_td.rt_mr3 = cc_eventlog::replay_events::<Sha384>(&malformed, None);
        assert_eq!(
            check(&changed_td, &malformed),
            Err(WorkloadIssue::KmsMeasurementMismatch)
        );
        let mut stale_td = td.clone();
        stale_td.rt_mr3[0] ^= 1;
        assert_eq!(
            check(&stale_td, &events),
            Err(WorkloadIssue::RuntimeMeasurementMismatch)
        );
    }

    fn historical_bound(quote: &[u8], expected: &[u8; 64]) -> BoundWorkloadInspection {
        let (policy, _, _) = policy_unit_only();
        inspect_workload_using(
            b"[]",
            RAW_COMPOSE,
            ExpectedWorkload::Exact(&policy),
            Some(expected),
            |inspect| {
                offline::inspect_fixture_quote_with_claims(
                    quote,
                    COLLATERAL,
                    1_752_919_234,
                    inspect,
                )
            },
        )
    }

    #[test]
    fn authentic_fixture_strict_rejection_keeps_report_data_and_workload_unchecked() {
        let quote = Quote::parse(QUOTE).unwrap();
        let expected = quote.report.as_td10().unwrap().report_data;
        let report = historical_bound(QUOTE, &expected);
        assert_eq!(
            report.workload.quote.hardware_authenticity,
            InspectionStatus::Verified
        );
        assert_eq!(
            report.workload.quote.security_policy,
            InspectionStatus::Rejected
        );
        assert_eq!(
            report.authenticated_report_data_match,
            InspectionStatus::NotChecked
        );
        // Authentic hardware signatures do not bypass strict appraisal, even
        // when caller-supplied expected bytes equal the signed report field.
        assert_eq!(
            report.workload.quote.workload_policy,
            InspectionStatus::NotChecked
        );
        assert_eq!(report.binding_issue, None);
        assert_eq!(
            report.workload.quote.live_key_binding,
            InspectionStatus::NotChecked
        );
        assert_eq!(
            report.workload.quote.freshness,
            InspectionStatus::NotChecked
        );
        assert!(!report.workload.quote.private_accepted && !report.workload.quote.query_sent);
    }

    #[test]
    fn strict_rejected_and_tampered_quotes_never_reach_report_data_comparison() {
        let mut quote = Quote::parse(QUOTE).unwrap();
        let expected = quote.report.as_td10().unwrap().report_data;
        let mut wrong_expected = expected;
        wrong_expected[0] ^= 1;
        let mismatch = historical_bound(QUOTE, &wrong_expected);
        assert_eq!(
            mismatch.workload.quote.hardware_authenticity,
            InspectionStatus::Verified
        );
        assert_eq!(
            mismatch.authenticated_report_data_match,
            InspectionStatus::NotChecked
        );
        assert_eq!(
            mismatch.workload.quote.security_policy,
            InspectionStatus::Rejected
        );
        assert_eq!(mismatch.binding_issue, None);
        match &mut quote.report {
            Report::TD10(td) => td.report_data[0] ^= 1,
            _ => panic!("fixture type changed"),
        }
        let tampered = historical_bound(&quote.encode(), &wrong_expected);
        assert_eq!(
            tampered.workload.quote.hardware_authenticity,
            InspectionStatus::Rejected
        );
        assert_eq!(
            tampered.authenticated_report_data_match,
            InspectionStatus::NotChecked
        );
        assert!(!tampered.workload.quote.private_accepted);
    }

    #[test]
    fn synthetic_comparator_only_equality_and_mismatch_are_not_authentication() {
        let (_, mut synthetic_td, _) = policy_unit_only();
        synthetic_td.report_data = [7; 64];
        assert_eq!(
            compare_report_data(&synthetic_td, &[7; 64]),
            InspectionStatus::Verified
        );
        let mut mismatch = [7; 64];
        mismatch[0] ^= 1;
        assert_eq!(
            compare_report_data(&synthetic_td, &mismatch),
            InspectionStatus::Rejected
        );
        // This pure comparison is below authentication. These fabricated bytes
        // cannot cause a real inspected quote to bypass its strict rejection.
        let authentic_but_rejected = historical_bound(QUOTE, &synthetic_td.report_data);
        assert_eq!(
            authentic_but_rejected.authenticated_report_data_match,
            InspectionStatus::NotChecked
        );
        assert!(!authentic_but_rejected.workload.quote.private_accepted);
    }

    #[test]
    fn production_clock_cannot_reuse_historical_fixture_validity() {
        let quote = Quote::parse(QUOTE).unwrap();
        let expected = quote.report.as_td10().unwrap().report_data;
        let (policy, _, _) = policy_unit_only();
        let report = inspect_workload_and_report_data(
            QUOTE,
            COLLATERAL,
            b"[]",
            RAW_COMPOSE,
            &policy,
            &expected,
        );
        assert_eq!(
            report.workload.quote.hardware_authenticity,
            InspectionStatus::Rejected
        );
        assert_eq!(
            report.authenticated_report_data_match,
            InspectionStatus::NotChecked
        );
        assert_eq!(report.workload.quote.time_source, "system_clock");
        assert!(!report.workload.quote.private_accepted && !report.workload.quote.network_used);
    }

    #[test]
    fn policy_unit_only_matches_do_not_authenticate_fabricated_quote() {
        let (policy, td, events) = policy_unit_only();
        assert_eq!(policy_check(&policy, &td, &events, RAW_COMPOSE), Ok(()));
        let mut quote = Quote::parse(QUOTE).unwrap();
        quote.report = Report::TD10(td);
        let report = inspect_workload(
            &quote.encode(),
            COLLATERAL,
            &log_json(&events),
            RAW_COMPOSE,
            &policy,
        );
        assert_eq!(
            report.quote.hardware_authenticity,
            InspectionStatus::Rejected
        );
        assert_eq!(report.quote.workload_policy, InspectionStatus::NotChecked);
        assert_eq!(report.runtime_event_integrity, InspectionStatus::NotChecked);
        assert_eq!(report.quote.freshness, InspectionStatus::NotChecked);
        assert_eq!(report.quote.live_key_binding, InspectionStatus::NotChecked);
        assert!(
            !report.quote.private_accepted
                && !report.quote.query_sent
                && !report.quote.network_used
        );
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("POLICY_UNIT_ONLY")
        );
    }

    #[test]
    fn explicit_policy_rejects_missing_wrong_size_duplicate_and_unknown_fields() {
        let (policy, _, _) = policy_unit_only();
        let raw = serde_json::to_vec(&policy).unwrap();
        assert_eq!(WorkloadPolicy::from_json(&raw), Ok(policy));
        for key in [
            "mrtd",
            "rtmr0",
            "rtmr1",
            "rtmr2",
            "os_image_hash",
            "compose_hash",
            "mr_kms",
            "app_id",
            "instance_id",
            "storage_fs",
            "key_provider",
            "schema_version",
        ] {
            let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            value.as_object_mut().unwrap().remove(key);
            assert_eq!(
                WorkloadPolicy::from_json(&serde_json::to_vec(&value).unwrap()),
                Err(WorkloadIssue::InvalidPolicy)
            );
        }
        for (key, value) in [
            ("mrtd", serde_json::json!("00")),
            ("verified", serde_json::json!(true)),
            ("key_provider", serde_json::json!(["kms", "id"])),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            changed[key] = value;
            assert_eq!(
                WorkloadPolicy::from_json(&serde_json::to_vec(&changed).unwrap()),
                Err(WorkloadIssue::InvalidPolicy)
            );
        }
        let raw = String::from_utf8(raw).unwrap();
        let duplicate = raw.replacen('{', "{\"schema_version\":1,", 1);
        assert_eq!(
            WorkloadPolicy::from_json(duplicate.as_bytes()),
            Err(WorkloadIssue::InvalidPolicy)
        );
        let duplicate_provider =
            raw.replace("\"name\":\"kms\"", "\"name\":\"kms\",\"name\":\"kms\"");
        assert_eq!(
            WorkloadPolicy::from_json(duplicate_provider.as_bytes()),
            Err(WorkloadIssue::InvalidPolicy)
        );
    }

    #[test]
    fn policy_unit_only_rejects_every_os_register_and_exact_compose_mismatch() {
        let (policy, td, events) = policy_unit_only();
        for index in 0..4 {
            let mut changed = td.clone();
            let register = match index {
                0 => &mut changed.mr_td,
                1 => &mut changed.rt_mr0,
                2 => &mut changed.rt_mr1,
                _ => &mut changed.rt_mr2,
            };
            register[0] ^= 1;
            assert_eq!(
                policy_check(&policy, &changed, &events, RAW_COMPOSE),
                Err(WorkloadIssue::OsMeasurementMismatch)
            );
        }
        let mut raw = RAW_COMPOSE.to_vec();
        raw.push(b'\n');
        assert_eq!(
            policy_check(&policy, &td, &events, &raw),
            Err(WorkloadIssue::ComposeHashMismatch)
        );
        for (index, issue) in [
            (1, WorkloadIssue::ApplicationIdentityMismatch),
            (2, WorkloadIssue::ComposeHashMismatch),
            (3, WorkloadIssue::ApplicationIdentityMismatch),
            (5, WorkloadIssue::KmsMeasurementMismatch),
            (6, WorkloadIssue::OsImageDigestMismatch),
            (7, WorkloadIssue::KeyProviderMismatch),
            (8, WorkloadIssue::StoragePolicyMismatch),
        ] {
            let mut events = events.clone();
            events[index].payload[0] ^= 1;
            let mut changed = td.clone();
            changed.rt_mr3 = cc_eventlog::replay_events::<Sha384>(&events, None);
            assert_eq!(
                policy_check(&policy, &changed, &events, RAW_COMPOSE),
                Err(issue)
            );
        }
    }

    #[test]
    fn policy_unit_only_authenticates_tail_and_rejects_ambiguous_boot_fields() {
        let (policy, td, mut events) = policy_unit_only();
        events.push(RuntimeEvent::new(
            "after-ready".into(),
            b"POLICY_UNIT_ONLY".to_vec(),
        ));
        assert_eq!(
            policy_check(&policy, &td, &events, RAW_COMPOSE),
            Err(WorkloadIssue::RuntimeMeasurementMismatch)
        );
        let mut td = td;
        td.rt_mr3 = cc_eventlog::replay_events::<Sha384>(&events, None);
        assert_eq!(policy_check(&policy, &td, &events, RAW_COMPOSE), Ok(()));
        for name in BOOT_SEQUENCE {
            let mut duplicated = events.clone();
            let duplicate = duplicated.iter().find(|e| e.event == name).unwrap().clone();
            duplicated.insert(0, duplicate);
            let mut changed = td.clone();
            changed.rt_mr3 = cc_eventlog::replay_events::<Sha384>(&duplicated, None);
            assert_eq!(
                policy_check(&policy, &changed, &duplicated, RAW_COMPOSE),
                Err(WorkloadIssue::AmbiguousBootEvent)
            );
        }
        let mut missing = events.clone();
        missing.retain(|e| e.event != "compose-hash");
        let mut changed = td.clone();
        changed.rt_mr3 = cc_eventlog::replay_events::<Sha384>(&missing, None);
        assert_eq!(
            policy_check(&policy, &changed, &missing, RAW_COMPOSE),
            Err(WorkloadIssue::MissingBootEvent)
        );
        events.swap(1, 2);
        changed.rt_mr3 = cc_eventlog::replay_events::<Sha384>(&events, None);
        assert_eq!(
            policy_check(&policy, &changed, &events, RAW_COMPOSE),
            Err(WorkloadIssue::InvalidBootSequence)
        );
    }

    #[test]
    fn malformed_event_objects_indices_types_and_digests_are_rejected() {
        let (_, _, events) = policy_unit_only();
        let raw = log_json(&events);
        for (key, value) in [
            ("imr", serde_json::json!(0)),
            ("event_type", serde_json::json!(0)),
            ("digest", serde_json::json!("00")),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            changed[0][key] = value;
            assert!(runtime_events(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        for invalid in [b"{}".as_slice(), b"[[]]", b"[{\"verified\":true}]"] {
            assert!(runtime_events(invalid).is_err());
        }
        let duplicate =
            String::from_utf8(raw)
                .unwrap()
                .replacen("\"imr\":3", "\"imr\":3,\"imr\":3", 1);
        assert!(runtime_events(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn upstream_replay_compatibility_only_has_no_authenticated_collateral_tuple() {
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/dstack/quote-report.json"
        ))
        .unwrap();
        let events = runtime_events(fixture["event_log"].as_str().unwrap().as_bytes()).unwrap();
        let quote =
            Quote::parse(&hex::decode(fixture["quote"].as_str().unwrap()).unwrap()).unwrap();
        // This compares decoded fixture data only. It does NOT authenticate
        // hardware, collateral, the workload, freshness or a live public key.
        assert_eq!(
            cc_eventlog::replay_events::<Sha384>(&events, None),
            quote.report.as_td10().unwrap().rt_mr3
        );
        assert_eq!(
            hex::encode(events[0].sha384_digest()),
            "f9974020ef507068183313d0ca808e0d1ca9b2d1ad0c61f5784e7157c362c06536f5ddacdad4451693f48fcc72fff624"
        );
        assert_eq!(
            boot_events(&events).unwrap_err(),
            WorkloadIssue::MissingBootEvent
        );
    }
}
