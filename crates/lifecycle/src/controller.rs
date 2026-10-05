//! Local controller model. The provider trait is sealed to the in-memory mock;
//! this module cannot activate a real provider, scheduler, or deployment.
//! JSON restoration checks an independently retained original binding, but is
//! not authenticated storage or protection against operator filesystem edits.

use crate::{
    DELETE_THRESHOLD_MICROUSD, DeploymentManifest, LifecycleError, MAX_LIFETIME_SECONDS,
    ManifestSource, TOTAL_CEILING_MICROUSD, WatchdogAction, add, duration_cost, nonempty,
    reconciliation::{ObservationRecord, ObservedDetail, ObservedUsage},
    watchdog,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExperimentBinding {
    experiment_id: String,
    workspace_id: String,
    started_at_unix_seconds: u64,
    deletion_deadline_unix_seconds: u64,
    total_ceiling_microusd: u64,
    delete_threshold_microusd: u64,
}

impl ExperimentBinding {
    pub fn experiment_id(&self) -> &str {
        &self.experiment_id
    }

    /// The original operator-bound workspace; this is not provider authentication.
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
    #[cfg(unix)]
    pub(crate) fn original_window(&self) -> (u64, u64) {
        (
            self.started_at_unix_seconds,
            self.deletion_deadline_unix_seconds,
        )
    }

    pub fn new(
        experiment_id: String,
        workspace_id: String,
        started_at_unix_seconds: u64,
        deletion_deadline_unix_seconds: u64,
    ) -> Result<Self, LifecycleError> {
        let binding = Self {
            experiment_id,
            workspace_id,
            started_at_unix_seconds,
            deletion_deadline_unix_seconds,
            total_ceiling_microusd: TOTAL_CEILING_MICROUSD,
            delete_threshold_microusd: DELETE_THRESHOLD_MICROUSD,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), LifecycleError> {
        if !nonempty(&self.experiment_id)
            || !nonempty(&self.workspace_id)
            || self.total_ceiling_microusd != TOTAL_CEILING_MICROUSD
            || self.delete_threshold_microusd != DELETE_THRESHOLD_MICROUSD
            || !self
                .deletion_deadline_unix_seconds
                .checked_sub(self.started_at_unix_seconds)
                .is_some_and(|duration| duration > 0 && duration <= MAX_LIFETIME_SECONDS)
        {
            return Err(LifecycleError("invalid original experiment binding"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Attempt {
    started_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeletionState {
    Tracking,
    DeletionRequested,
    AbsentFromInventory,
    BillingReconciliationPending,
}

/// One explicitly tracked CVM, including its attached disk cost. This is not a
/// fabricated independently addressable Phala disk resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrackedCvm {
    pub cvm_id: String,
    pub app_id: String,
    #[serde(default)]
    pub instance_id: Option<String>,
    pub created_at_unix_seconds: u64,
    pub compute_and_disk_microusd_per_hour: u64,
}

/// Operator-reviewed split of an already tracked combined rate. This cannot
/// reduce the historical cost floor or establish deletion/billing finality.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateBasisEntry {
    pub cvm_id: String,
    pub compute_microusd_per_hour: u64,
    pub storage_microusd_per_hour: u64,
    pub deletion_basis: ComputeStopBasis,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComputeStopBasis {
    TrackedDelete204,
    OperatorAssertedManualDeletion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateBasisEvent {
    pub source_generation: u64,
    pub committed_generation: u64,
    pub recorded_at_unix_seconds: u64,
    pub quote_reference: String,
    pub entries: Vec<RateBasisEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrackedResource {
    attempt_id: String,
    cvm: TrackedCvm,
    deletion: DeletionState,
}

/// Domain representation of an exact monetary token, not an f64 conversion.
/// A future HTTP adapter must preserve/normalize decimal tokens without binary
/// floating point. Refunds never silently reduce this conservative expense log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UsageRecord {
    pub billing_key: String,
    pub app_id: String,
    pub instance_id: String,
    pub usage_type: String,
    pub cost_usd_decimal: String,
}

/// Nonnegative JSON decimal USD, rounded up to an integer microdollar.
/// Rejects unsupported syntax and overflow rather than estimating a value.
pub fn decimal_usd_to_microusd(value: &str) -> Result<u64, LifecycleError> {
    crate::amount::ExactUsd::parse_json_number(value)?.ceil_microusd()
}

/// An observation about one attempted request, never proof of resource or disk
/// disappearance. The local store does not authenticate these observations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DeletionOutcome {
    Initiated204,
    NotFound404,
    Rejected { status: u16 },
    TransportUncertain,
}
impl DeletionOutcome {
    fn validate(self) -> Result<(), LifecycleError> {
        if let Self::Rejected { status } = self {
            if !(100..=599).contains(&status) || matches!(status, 204 | 404) {
                return Err(LifecycleError("invalid deletion response classification"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeletionOutcomeRecord {
    pub recorded_at_unix_seconds: u64,
    pub outcome: DeletionOutcome,
}

/// Retained narrow readback for a separately selected retry. Deserializing this
/// history grants no authentication, dispatch or permission for another retry.
///
/// ```compile_fail
/// use zrpc_lifecycle::{controller::DeletionRetryRecord, persistence::LedgerStore};
/// fn cannot_prepare(store: &mut LedgerStore, restored: DeletionRetryRecord) {
///     store.prepare_deletion_retry(0, "workspace", "target", restored, 0);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeletionRetryRecord {
    pub prior_intent_generation: u64,
    pub started_at_unix_seconds: u64,
    pub readback_at_unix_seconds: u64,
    pub detail: ObservedDetail,
}

impl DeletionRetryRecord {
    fn validate(
        &self,
        target: &TrackedCvm,
        workspace: &str,
        recorded_at: u64,
    ) -> Result<(), LifecycleError> {
        if self.started_at_unix_seconds < target.created_at_unix_seconds
            || self.started_at_unix_seconds > self.readback_at_unix_seconds
            || self.readback_at_unix_seconds > recorded_at
        {
            return Err(LifecycleError("invalid deletion retry readback time"));
        }
        self.detail.validate(target, workspace)
    }
}

/// Append-only local journal entry. No network dispatch or approval is implied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeletionIntentRecord {
    pub reviewed_generation: u64,
    pub committed_generation: u64,
    pub target: TrackedCvm,
    pub recorded_at_unix_seconds: u64,
    pub outcome: Option<DeletionOutcomeRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<DeletionRetryRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerData {
    binding: ExperimentBinding,
    initial_cost_microusd: u64,
    conservative_cost_floor_microusd: u64,
    last_observed_at_unix_seconds: u64,
    attempts: BTreeMap<String, Attempt>,
    resources: BTreeMap<String, TrackedResource>,
    usage: BTreeMap<String, UsageRecord>,
    #[serde(default)]
    deletion_intents: Vec<DeletionIntentRecord>,
    #[serde(default)]
    observations: Vec<ObservationRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rate_basis_events: Vec<RateBasisEvent>,
}

/// Fields are private; attempt APIs cannot replace the original policy or
/// remove earlier resources/costs. The separate Unix persistence module checks
/// successors under an OS lock; serialization alone is not durable activation.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct ExperimentLedger(LedgerData);

impl ExperimentLedger {
    #[cfg(unix)]
    pub(crate) fn planning_cost_at(&self, now: u64) -> Result<u64, LifecycleError> {
        self.validate()?;
        if now < self.0.last_observed_at_unix_seconds {
            return Err(LifecycleError("plan predates the committed ledger"));
        }
        Ok(self
            .0
            .conservative_cost_floor_microusd
            .max(self.modeled_cost(now)?)
            .max(self.observed_cost()?))
    }

    #[cfg(unix)]
    pub(crate) fn tracked_rates(&self) -> impl Iterator<Item = (&str, u64)> {
        self.0
            .resources
            .iter()
            .map(|(id, resource)| (id.as_str(), resource.cvm.compute_and_disk_microusd_per_hour))
    }

    pub fn new(
        binding: ExperimentBinding,
        initial_cost_microusd: u64,
    ) -> Result<Self, LifecycleError> {
        binding.validate()?;
        Ok(Self(LedgerData {
            last_observed_at_unix_seconds: binding.started_at_unix_seconds,
            binding,
            initial_cost_microusd,
            conservative_cost_floor_microusd: initial_cost_microusd,
            attempts: BTreeMap::new(),
            resources: BTreeMap::new(),
            usage: BTreeMap::new(),
            deletion_intents: Vec::new(),
            observations: Vec::new(),
            rate_basis_events: Vec::new(),
        }))
    }

    pub fn binding(&self) -> &ExperimentBinding {
        &self.0.binding
    }

    pub fn deletion_intents(&self) -> &[DeletionIntentRecord] {
        &self.0.deletion_intents
    }

    pub fn observations(&self) -> &[ObservationRecord] {
        &self.0.observations
    }

    pub fn rate_basis_events(&self) -> &[RateBasisEvent] {
        &self.0.rate_basis_events
    }

    pub fn conservative_cost_floor_microusd(&self) -> u64 {
        self.0.conservative_cost_floor_microusd
    }

    pub(crate) fn workspace_id(&self) -> &str {
        &self.0.binding.workspace_id
    }

    #[cfg(unix)]
    pub(crate) fn tracked_cvms(&self) -> impl Iterator<Item = &TrackedCvm> {
        self.0.resources.values().map(|resource| &resource.cvm)
    }

    #[cfg(unix)]
    pub(crate) fn append_observation(
        &mut self,
        record: ObservationRecord,
    ) -> Result<(), LifecycleError> {
        self.validate()?;
        record.validate(self.workspace_id())?;
        if record.usage_start_unix_seconds != self.0.binding.started_at_unix_seconds
            || record.usage_cutoff_unix_seconds < self.0.last_observed_at_unix_seconds
            || record.tracked.len() != self.0.resources.len()
            || record.tracked.iter().any(|observed| {
                self.0
                    .resources
                    .get(&observed.target.cvm_id)
                    .is_none_or(|resource| resource.cvm != observed.target)
            })
            || record.known_cost_floor_microusd
                != self.planning_cost_at(record.finished_at_unix_seconds)?
        {
            return Err(LifecycleError(
                "observation differs from committed experiment",
            ));
        }
        // Validate the entire successor before changing this ledger. Provider
        // usage is retained as unjoined data and never enters accepted charges.
        let mut next = self.clone();
        let recorded_at = record.recorded_at_unix_seconds;
        next.0.observations.push(record);
        // A newly observed reappearance can restore the full compute rate.
        // Recompute after installing this observation so the retained floor
        // captures that increase in the same durable transition.
        next.advance_cost(recorded_at)?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn append_rate_basis(
        &mut self,
        source_generation: u64,
        quote_reference: String,
        entries: Vec<RateBasisEntry>,
        now: u64,
    ) -> Result<(), LifecycleError> {
        self.validate()?;
        let event = RateBasisEvent {
            source_generation,
            committed_generation: source_generation
                .checked_add(1)
                .ok_or(LifecycleError("rate basis generation overflow"))?,
            recorded_at_unix_seconds: now,
            quote_reference,
            entries,
        };
        let mut next = self.clone();
        next.0.rate_basis_events.push(event);
        // Install the complete reviewed batch before advancing the clock. A
        // one-resource-at-a-time update would irreversibly accrue the old full
        // rate for the other deleted resources in the same batch.
        next.advance_cost(now)?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn append_deletion_intent(
        &mut self,
        reviewed_generation: u64,
        workspace: &str,
        cvm_id: &str,
        now: u64,
    ) -> Result<usize, LifecycleError> {
        self.append_deletion_record(reviewed_generation, workspace, cvm_id, None, now)
    }

    #[cfg(unix)]
    pub(crate) fn append_deletion_retry(
        &mut self,
        reviewed_generation: u64,
        workspace: &str,
        cvm_id: &str,
        retry: DeletionRetryRecord,
        now: u64,
    ) -> Result<usize, LifecycleError> {
        self.append_deletion_record(reviewed_generation, workspace, cvm_id, Some(retry), now)
    }

    #[cfg(unix)]
    fn append_deletion_record(
        &mut self,
        reviewed_generation: u64,
        workspace: &str,
        cvm_id: &str,
        retry: Option<DeletionRetryRecord>,
        now: u64,
    ) -> Result<usize, LifecycleError> {
        self.validate()?;
        if workspace != self.workspace_id() {
            return Err(LifecycleError("deletion workspace differs from experiment"));
        }
        let target = self
            .0
            .resources
            .get(cvm_id)
            .ok_or(LifecycleError("deletion target is not already tracked"))?
            .cvm
            .clone();
        let prior = self
            .0
            .deletion_intents
            .iter()
            .rev()
            .find(|intent| intent.target.cvm_id == cvm_id);
        match (prior, &retry) {
            (None, None) => {}
            (Some(prior), Some(retry))
                if retry.prior_intent_generation == prior.committed_generation
                    && retry.started_at_unix_seconds >= self.0.last_observed_at_unix_seconds =>
            {
                retry.validate(&target, workspace, now)?;
            }
            _ => {
                return Err(LifecycleError(
                    "deletion requires first intent or explicit latest-intent reconciliation",
                ));
            }
        }
        let committed_generation = reviewed_generation
            .checked_add(1)
            .ok_or(LifecycleError("deletion generation overflow"))?;
        let index = self.0.deletion_intents.len();
        let mut next = self.clone();
        next.advance_cost(now)?;
        next.0.deletion_intents.push(DeletionIntentRecord {
            reviewed_generation,
            committed_generation,
            target,
            recorded_at_unix_seconds: now,
            outcome: None,
            retry,
        });
        next.validate()?;
        *self = next;
        Ok(index)
    }

    #[cfg(unix)]
    pub(crate) fn finish_deletion_intent(
        &mut self,
        index: usize,
        outcome: DeletionOutcome,
        now: u64,
    ) -> Result<(), LifecycleError> {
        outcome.validate()?;
        let intent = self
            .0
            .deletion_intents
            .get(index)
            .ok_or(LifecycleError("deletion intent is missing"))?;
        if intent.outcome.is_some()
            || now < intent.recorded_at_unix_seconds
            || self.0.deletion_intents[index + 1..]
                .iter()
                .any(|later| later.target.cvm_id == intent.target.cvm_id)
        {
            return Err(LifecycleError(
                "deletion outcome cannot replace prior history",
            ));
        }
        self.advance_cost(now)?;
        self.0.deletion_intents[index].outcome = Some(DeletionOutcomeRecord {
            recorded_at_unix_seconds: now,
            outcome,
        });
        Ok(())
    }

    /// Persistence may append history, never replace known identities, costs,
    /// or billing records with a fresh ledger carrying the same binding.
    #[cfg(unix)]
    pub(crate) fn validate_successor(&self, previous: &Self) -> Result<(), LifecycleError> {
        self.validate()?;
        previous.validate()?;
        if !self.0.observations.starts_with(&previous.0.observations) {
            return Err(LifecycleError(
                "observation journal would alter prior history",
            ));
        }
        if !self
            .0
            .rate_basis_events
            .starts_with(&previous.0.rate_basis_events)
        {
            return Err(LifecycleError(
                "rate basis journal would alter prior history",
            ));
        }
        if self.0.deletion_intents.len() < previous.0.deletion_intents.len()
            || previous
                .0
                .deletion_intents
                .iter()
                .zip(&self.0.deletion_intents)
                .enumerate()
                .any(|(index, (prior, next))| {
                    let mut expected = prior.clone();
                    if expected.outcome.is_none() {
                        if next.outcome.as_ref().is_some_and(|outcome| {
                            outcome.recorded_at_unix_seconds
                                < previous.0.last_observed_at_unix_seconds
                                || self.0.deletion_intents[index + 1..]
                                    .iter()
                                    .any(|later| later.target.cvm_id == prior.target.cvm_id)
                        }) {
                            return true;
                        }
                        expected.outcome = next.outcome.clone();
                    }
                    &expected != next
                })
        {
            return Err(LifecycleError("deletion journal would alter prior history"));
        }
        if self.0.binding != previous.0.binding
            || self.0.initial_cost_microusd != previous.0.initial_cost_microusd
            || self.0.conservative_cost_floor_microusd < previous.0.conservative_cost_floor_microusd
            || self.0.last_observed_at_unix_seconds < previous.0.last_observed_at_unix_seconds
            || previous
                .0
                .attempts
                .iter()
                .any(|(id, value)| self.0.attempts.get(id) != Some(value))
            || previous
                .0
                .usage
                .iter()
                .any(|(id, value)| self.0.usage.get(id) != Some(value))
            || previous.0.resources.iter().any(|(id, value)| {
                self.0
                    .resources
                    .get(id)
                    .is_none_or(|next| next.attempt_id != value.attempt_id || next.cvm != value.cvm)
            })
        {
            return Err(LifecycleError(
                "ledger successor would reset or alter experiment history",
            ));
        }
        Ok(())
    }

    pub fn from_json(bytes: &[u8], original: &ExperimentBinding) -> Result<Self, LifecycleError> {
        original.validate()?;
        let data: LedgerData = serde_json::from_slice(bytes)
            .map_err(|_| LifecycleError("invalid experiment ledger JSON"))?;
        if &data.binding != original {
            return Err(LifecycleError(
                "ledger differs from original experiment binding",
            ));
        }
        let ledger = Self(data);
        ledger.validate()?;
        Ok(ledger)
    }

    fn validate(&self) -> Result<(), LifecycleError> {
        self.0.binding.validate()?;
        if self.0.last_observed_at_unix_seconds < self.0.binding.started_at_unix_seconds
            || self.0.conservative_cost_floor_microusd < self.0.initial_cost_microusd
        {
            return Err(LifecycleError("invalid ledger cost or clock"));
        }
        for (id, attempt) in &self.0.attempts {
            if !nonempty(id)
                || attempt.started_at_unix_seconds < self.0.binding.started_at_unix_seconds
                || attempt.started_at_unix_seconds >= self.0.binding.deletion_deadline_unix_seconds
            {
                return Err(LifecycleError("invalid ledger attempt"));
            }
        }
        let mut instances = BTreeSet::new();
        for (id, resource) in &self.0.resources {
            self.validate_resource(&resource.attempt_id, &resource.cvm)?;
            if id != &resource.cvm.cvm_id
                || resource
                    .cvm
                    .instance_id
                    .as_ref()
                    .is_some_and(|instance| !instances.insert(instance))
            {
                return Err(LifecycleError("invalid or duplicate tracked resource"));
            }
        }
        for (key, usage) in &self.0.usage {
            self.validate_usage(usage)?;
            if key != &usage.billing_key {
                return Err(LifecycleError("invalid billing record key"));
            }
        }
        let mut rated = BTreeSet::new();
        let mut prior_rate_generation = None;
        let mut prior_rate_time = self.0.binding.started_at_unix_seconds;
        for event in &self.0.rate_basis_events {
            if event.source_generation.checked_add(1) != Some(event.committed_generation)
                || prior_rate_generation.is_some_and(|prior| prior >= event.committed_generation)
                || event.recorded_at_unix_seconds < prior_rate_time
                || event.recorded_at_unix_seconds > self.0.last_observed_at_unix_seconds
                || !nonempty(&event.quote_reference)
                || event.entries.is_empty()
            {
                return Err(LifecycleError("invalid rate basis event"));
            }
            for entry in &event.entries {
                let resource = self
                    .0
                    .resources
                    .get(&entry.cvm_id)
                    .ok_or(LifecycleError("rate basis target is not tracked"))?;
                if !rated.insert(entry.cvm_id.as_str())
                    || entry.compute_microusd_per_hour == 0
                    || entry.storage_microusd_per_hour == 0
                    || entry
                        .compute_microusd_per_hour
                        .checked_add(entry.storage_microusd_per_hour)
                        != Some(resource.cvm.compute_and_disk_microusd_per_hour)
                    || resource.cvm.created_at_unix_seconds > event.recorded_at_unix_seconds
                {
                    return Err(LifecycleError("invalid rate basis for tracked CVM"));
                }
            }
            prior_rate_generation = Some(event.committed_generation);
            prior_rate_time = event.recorded_at_unix_seconds;
        }
        let mut deletion_targets: BTreeMap<&str, &DeletionIntentRecord> = BTreeMap::new();
        let mut prior_generation = None;
        for intent in &self.0.deletion_intents {
            if intent.reviewed_generation.checked_add(1) != Some(intent.committed_generation)
                || prior_generation.is_some_and(|prior| prior >= intent.committed_generation)
                || self
                    .0
                    .resources
                    .get(&intent.target.cvm_id)
                    .is_none_or(|resource| resource.cvm != intent.target)
                || intent.recorded_at_unix_seconds < intent.target.created_at_unix_seconds
                || intent.recorded_at_unix_seconds > self.0.last_observed_at_unix_seconds
            {
                return Err(LifecycleError("invalid deletion journal identity or time"));
            }
            match (
                deletion_targets.get(intent.target.cvm_id.as_str()),
                &intent.retry,
            ) {
                (None, None) => {}
                (Some(prior), Some(retry))
                    if retry.prior_intent_generation == prior.committed_generation
                        && retry.started_at_unix_seconds >= prior.recorded_at_unix_seconds
                        && prior.outcome.as_ref().is_none_or(|outcome| {
                            retry.started_at_unix_seconds >= outcome.recorded_at_unix_seconds
                        }) =>
                {
                    retry.validate(
                        &intent.target,
                        self.workspace_id(),
                        intent.recorded_at_unix_seconds,
                    )?;
                }
                _ => return Err(LifecycleError("invalid deletion retry history")),
            }
            deletion_targets.insert(&intent.target.cvm_id, intent);
            prior_generation = Some(intent.committed_generation);
            if let Some(outcome) = &intent.outcome {
                outcome.outcome.validate()?;
                if outcome.recorded_at_unix_seconds < intent.recorded_at_unix_seconds
                    || outcome.recorded_at_unix_seconds > self.0.last_observed_at_unix_seconds
                {
                    return Err(LifecycleError("invalid deletion outcome time"));
                }
            }
        }
        self.validate_observations()?;
        if self.modeled_cost(self.0.last_observed_at_unix_seconds)?
            > self.0.conservative_cost_floor_microusd
            || self.observed_cost()? > self.0.conservative_cost_floor_microusd
        {
            return Err(LifecycleError("ledger cost floor omits known costs"));
        }
        Ok(())
    }

    fn validate_observations(&self) -> Result<(), LifecycleError> {
        let mut prior_generation = None;
        let mut prior_recorded = self.0.binding.started_at_unix_seconds;
        let mut prior_floor = self.0.initial_cost_microusd;
        let mut prior_rows: BTreeMap<(&str, &str), &ObservedUsage> = BTreeMap::new();
        for (index, record) in self.0.observations.iter().enumerate() {
            record.validate(self.workspace_id())?;
            if record.usage_start_unix_seconds != self.0.binding.started_at_unix_seconds
                || record.usage_cutoff_unix_seconds < prior_recorded
                || record.recorded_at_unix_seconds > self.0.last_observed_at_unix_seconds
                || prior_generation.is_some_and(|generation| record.source_generation < generation)
                || record.known_cost_floor_microusd < prior_floor
                || record.known_cost_floor_microusd > self.0.conservative_cost_floor_microusd
                || record.tracked.iter().any(|observed| {
                    self.0
                        .resources
                        .get(&observed.target.cvm_id)
                        .is_none_or(|resource| resource.cvm != observed.target)
                })
                || self
                    .0
                    .deletion_intents
                    .iter()
                    .any(|intent| intent.committed_generation == record.committed_generation)
            {
                return Err(LifecycleError("invalid observation journal history"));
            }
            // Use the resources actually retained by this earlier record.
            // Resources added later must not retroactively invalidate it.
            let modeled_at_finish = self.modeled_cost_for_targets(
                record.tracked.iter().map(|observed| &observed.target),
                // The scan's quoted floor came from its source snapshot, before
                // this observation could change the compute-stop assessment.
                &self.0.observations[..index],
                record.source_generation,
                record.finished_at_unix_seconds,
            )?;
            if record.known_cost_floor_microusd < modeled_at_finish {
                return Err(LifecycleError("observation omits its known modeled cost"));
            }
            for (app, rows) in &record.usage_by_app {
                for row in rows {
                    let key = (app.as_str(), row.billing_key.as_str());
                    if prior_rows.get(&key).is_some_and(|prior| *prior != row) {
                        return Err(LifecycleError("conflicting historical provider usage"));
                    }
                    prior_rows.insert(key, row);
                }
            }
            prior_generation = Some(record.committed_generation);
            prior_recorded = record.recorded_at_unix_seconds;
            prior_floor = record.known_cost_floor_microusd;
        }
        Ok(())
    }

    pub fn begin_attempt(&mut self, attempt_id: String, now: u64) -> Result<(), LifecycleError> {
        self.advance_cost(now)?;
        if !nonempty(&attempt_id) || self.0.attempts.contains_key(&attempt_id) {
            return Err(LifecycleError("attempt ID must be nonempty and unique"));
        }
        if now >= self.0.binding.deletion_deadline_unix_seconds
            || self.0.conservative_cost_floor_microusd >= DELETE_THRESHOLD_MICROUSD
        {
            return Err(LifecycleError(
                "experiment already requires deletion; retry forbidden",
            ));
        }
        self.0.attempts.insert(
            attempt_id,
            Attempt {
                started_at_unix_seconds: now,
            },
        );
        Ok(())
    }

    fn validate_resource(&self, attempt_id: &str, cvm: &TrackedCvm) -> Result<(), LifecycleError> {
        let attempt = self
            .0
            .attempts
            .get(attempt_id)
            .ok_or(LifecycleError("unknown attempt"))?;
        if !nonempty(&cvm.cvm_id)
            || !nonempty(&cvm.app_id)
            || cvm.instance_id.as_ref().is_some_and(|id| !nonempty(id))
            || cvm.created_at_unix_seconds < attempt.started_at_unix_seconds
            || cvm.compute_and_disk_microusd_per_hour == 0
        {
            return Err(LifecycleError("invalid explicitly tracked CVM"));
        }
        Ok(())
    }

    pub fn track_cvm(
        &mut self,
        workspace_id: &str,
        attempt_id: &str,
        cvm: TrackedCvm,
    ) -> Result<(), LifecycleError> {
        if workspace_id != self.0.binding.workspace_id {
            return Err(LifecycleError("resource workspace differs from experiment"));
        }
        self.validate_resource(attempt_id, &cvm)?;
        if self.0.resources.contains_key(&cvm.cvm_id)
            || self
                .0
                .resources
                .values()
                .any(|r| cvm.instance_id.is_some() && r.cvm.instance_id == cvm.instance_id)
        {
            return Err(LifecycleError("resource is already tracked"));
        }
        self.0.resources.insert(
            cvm.cvm_id.clone(),
            TrackedResource {
                attempt_id: attempt_id.to_owned(),
                cvm,
                deletion: DeletionState::Tracking,
            },
        );
        // Recording a partially created resource is allowed even at the deletion
        // threshold: refusing its identity would make cleanup less complete.
        self.advance_cost(self.0.last_observed_at_unix_seconds)
    }

    /// Retain an explicitly supplied resource even if creation finished after
    /// the original deadline. This only records cleanup scope; it cannot start
    /// an attempt, renew the deadline, or authorize provider creation.
    #[cfg(unix)]
    pub(crate) fn record_cvm_at(
        &mut self,
        attempt_id: &str,
        cvm: TrackedCvm,
        now: u64,
    ) -> Result<(), LifecycleError> {
        if cvm.created_at_unix_seconds > now {
            return Err(LifecycleError("resource creation is in the future"));
        }
        let mut next = self.clone();
        let workspace = next.0.binding.workspace_id.clone();
        next.track_cvm(&workspace, attempt_id, cvm)?;
        next.advance_cost(now)?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    fn validate_usage(&self, usage: &UsageRecord) -> Result<u64, LifecycleError> {
        if !nonempty(&usage.billing_key)
            || !nonempty(&usage.usage_type)
            || !self.0.resources.values().any(|r| {
                r.cvm.app_id == usage.app_id
                    && r.cvm.instance_id.as_deref() == Some(usage.instance_id.as_str())
            })
        {
            return Err(LifecycleError(
                "billing record is outside tracked experiment",
            ));
        }
        decimal_usd_to_microusd(&usage.cost_usd_decimal)
    }

    pub fn record_usage(&mut self, usage: UsageRecord) -> Result<(), LifecycleError> {
        self.validate_usage(&usage)?;
        if let Some(existing) = self.0.usage.get(&usage.billing_key) {
            if existing.app_id != usage.app_id
                || existing.instance_id != usage.instance_id
                || existing.usage_type != usage.usage_type
                || crate::amount::ExactUsd::parse_json_number(&existing.cost_usd_decimal)?
                    != crate::amount::ExactUsd::parse_json_number(&usage.cost_usd_decimal)?
            {
                return Err(LifecycleError("conflicting duplicate billing record"));
            }
            return Ok(());
        }
        let amount = decimal_usd_to_microusd(&usage.cost_usd_decimal)?;
        let observed = add(self.observed_cost()?, amount)?;
        self.0.usage.insert(usage.billing_key.clone(), usage);
        self.0.conservative_cost_floor_microusd =
            self.0.conservative_cost_floor_microusd.max(observed);
        Ok(())
    }

    fn observed_cost(&self) -> Result<u64, LifecycleError> {
        self.0
            .usage
            .values()
            .try_fold(self.0.initial_cost_microusd, |sum, row| {
                add(sum, decimal_usd_to_microusd(&row.cost_usd_decimal)?)
            })
    }

    fn compute_stop_at(
        &self,
        cvm: &TrackedCvm,
        basis: &ComputeStopBasis,
        observations: &[ObservationRecord],
        now: u64,
    ) -> Option<u64> {
        let mut seen_present = false;
        let mut first_absence = None;
        for record in observations
            .iter()
            .filter(|record| record.finished_at_unix_seconds <= now)
        {
            let Some(observed) = record
                .tracked
                .iter()
                .find(|observed| observed.target.cvm_id == cvm.cvm_id)
            else {
                continue;
            };
            if observed.inventory.is_some()
                || matches!(&observed.detail, ObservedDetail::Present(_))
            {
                // A resource that returns after an apparent deletion gets the
                // full rate again; no earlier absence can discount it.
                if first_absence.is_some() {
                    return None;
                }
                seen_present = true;
                continue;
            }
            if first_absence.is_none()
                && observed.inventory.is_none()
                && matches!(&observed.detail, ObservedDetail::NotFound)
                && match basis {
                    ComputeStopBasis::OperatorAssertedManualDeletion => seen_present,
                    ComputeStopBasis::TrackedDelete204 => {
                        self.0.deletion_intents.iter().any(|intent| {
                            intent.target.cvm_id == cvm.cvm_id
                                && intent.outcome.as_ref().is_some_and(|outcome| {
                                    matches!(outcome.outcome, DeletionOutcome::Initiated204)
                                        && outcome.recorded_at_unix_seconds
                                            <= record.finished_at_unix_seconds
                                })
                        })
                    }
                }
            {
                first_absence = Some(record.finished_at_unix_seconds);
            }
        }
        first_absence
    }

    fn modeled_cost_for_targets<'a>(
        &self,
        mut targets: impl Iterator<Item = &'a TrackedCvm>,
        observations: &[ObservationRecord],
        source_generation: u64,
        now: u64,
    ) -> Result<u64, LifecycleError> {
        targets.try_fold(self.0.initial_cost_microusd, |sum, cvm| {
            let seconds = now.saturating_sub(cvm.created_at_unix_seconds);
            let basis = self
                .0
                .rate_basis_events
                .iter()
                .filter(|event| event.committed_generation <= source_generation)
                .flat_map(|event| &event.entries)
                .find(|entry| entry.cvm_id == cvm.cvm_id);
            let cost = match basis.and_then(|basis| {
                self.compute_stop_at(cvm, &basis.deletion_basis, observations, now)
                    .map(|stop| (basis, stop))
            }) {
                Some((basis, stop)) => add(
                    duration_cost(
                        cvm.compute_and_disk_microusd_per_hour,
                        stop.saturating_sub(cvm.created_at_unix_seconds),
                    )?,
                    duration_cost(basis.storage_microusd_per_hour, now.saturating_sub(stop))?,
                )?,
                None => duration_cost(cvm.compute_and_disk_microusd_per_hour, seconds)?,
            };
            add(sum, cost)
        })
    }

    fn modeled_cost(&self, now: u64) -> Result<u64, LifecycleError> {
        self.modeled_cost_for_targets(
            self.0.resources.values().map(|resource| &resource.cvm),
            &self.0.observations,
            u64::MAX,
            now,
        )
    }

    fn advance_cost(&mut self, now: u64) -> Result<(), LifecycleError> {
        if now < self.0.last_observed_at_unix_seconds {
            return Err(LifecycleError("controller clock moved backwards"));
        }
        self.0.conservative_cost_floor_microusd = self
            .0
            .conservative_cost_floor_microusd
            .max(self.modeled_cost(now)?)
            .max(self.observed_cost()?);
        self.0.last_observed_at_unix_seconds = now;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderError {
    Unauthorized,
    Forbidden,
    Unavailable,
    MalformedResponse,
}

#[derive(Debug, Clone)]
pub struct InventoryItem {
    pub cvm_id: String,
    pub workspace_id: String,
    /// Provider status is informational. Stopped is never deleted or free.
    pub status: String,
}
#[derive(Debug, Clone)]
pub struct InventoryPage {
    pub workspace_id: String,
    pub page: u64,
    pub pages: u64,
    pub total: u64,
    pub items: Vec<InventoryItem>,
}
#[derive(Debug, Clone)]
pub enum DetailReply {
    Present(InventoryItem),
    Absent404,
}
#[derive(Debug, Clone, Copy)]
pub enum DeleteReply {
    Initiated204,
    Absent404,
}
#[derive(Debug, Clone)]
pub struct UsagePage {
    pub records: Vec<UsageRecord>,
    pub total: u64,
}

mod sealed {
    pub trait Sealed {}
}

/// These are proposed internal operations, not Phala SDK method names. Only the
/// in-memory implementation can implement this trait. There is no live adapter.
pub trait MockProvider: sealed::Sealed {
    fn workspace_identity(&mut self) -> Result<String, ProviderError>;
    fn inventory_page(&mut self, page: u64) -> Result<InventoryPage, ProviderError>;
    fn detail(&mut self, cvm_id: &str) -> Result<DetailReply, ProviderError>;
    fn usage_page(
        &mut self,
        app_id: &str,
        start: u64,
        end: u64,
        offset: u64,
    ) -> Result<UsagePage, ProviderError>;
    fn delete(&mut self, cvm_id: &str) -> Result<DeleteReply, ProviderError>;
}

/// Replies must be supplied explicitly. Missing replies are errors, never
/// fabricated absence, free billing, or successful deletion.
#[derive(Debug, Clone)]
pub struct ScriptedMockProvider {
    pub workspace: Result<String, ProviderError>,
    pub inventory: BTreeMap<u64, Result<InventoryPage, ProviderError>>,
    pub details: BTreeMap<String, Result<DetailReply, ProviderError>>,
    pub usage: BTreeMap<(String, u64), Result<UsagePage, ProviderError>>,
    pub deletion: BTreeMap<String, Result<DeleteReply, ProviderError>>,
    pub deletion_requests: Vec<String>,
    pub usage_requests: Vec<(String, u64, u64, u64)>,
}

impl sealed::Sealed for ScriptedMockProvider {}
impl MockProvider for ScriptedMockProvider {
    fn workspace_identity(&mut self) -> Result<String, ProviderError> {
        self.workspace.clone()
    }
    fn inventory_page(&mut self, page: u64) -> Result<InventoryPage, ProviderError> {
        self.inventory
            .get(&page)
            .cloned()
            .unwrap_or(Err(ProviderError::MalformedResponse))
    }
    fn detail(&mut self, id: &str) -> Result<DetailReply, ProviderError> {
        self.details
            .get(id)
            .cloned()
            .unwrap_or(Err(ProviderError::MalformedResponse))
    }
    fn usage_page(
        &mut self,
        app: &str,
        start: u64,
        end: u64,
        offset: u64,
    ) -> Result<UsagePage, ProviderError> {
        self.usage_requests
            .push((app.to_owned(), start, end, offset));
        self.usage
            .get(&(app.to_owned(), offset))
            .cloned()
            .unwrap_or(Err(ProviderError::MalformedResponse))
    }
    fn delete(&mut self, id: &str) -> Result<DeleteReply, ProviderError> {
        self.deletion_requests.push(id.to_owned());
        self.deletion
            .get(id)
            .cloned()
            .unwrap_or(Err(ProviderError::MalformedResponse))
    }
}

fn full_inventory(
    provider: &mut impl MockProvider,
    workspace: &str,
) -> Result<BTreeSet<String>, ProviderError> {
    let mut ids = BTreeSet::new();
    let mut page = 1;
    let mut expected = None;
    loop {
        let reply = provider.inventory_page(page)?;
        let metadata = (reply.pages, reply.total);
        if reply.workspace_id != workspace
            || reply.page != page
            || expected.is_some_and(|value| value != metadata)
            || (reply.pages == 0 && (page != 1 || reply.total != 0 || !reply.items.is_empty()))
            || (reply.pages != 0 && page > reply.pages)
        {
            return Err(ProviderError::MalformedResponse);
        }
        expected = Some(metadata);
        for item in reply.items {
            if item.workspace_id != workspace
                || !nonempty(&item.cvm_id)
                || !nonempty(&item.status)
                || !ids.insert(item.cvm_id)
            {
                return Err(ProviderError::MalformedResponse);
            }
        }
        if reply.pages == 0 || page == reply.pages {
            if u64::try_from(ids.len()).ok() != Some(reply.total) {
                return Err(ProviderError::MalformedResponse);
            }
            return Ok(ids);
        }
        page = page
            .checked_add(1)
            .ok_or(ProviderError::MalformedResponse)?;
    }
}

fn collect_usage(
    ledger: &mut ExperimentLedger,
    provider: &mut impl MockProvider,
    now: u64,
) -> Result<(), LifecycleError> {
    let apps: BTreeSet<_> = ledger
        .0
        .resources
        .values()
        .map(|r| r.cvm.app_id.clone())
        .collect();
    for app in apps {
        let mut offset = 0_u64;
        let mut scanned_keys = BTreeSet::new();
        loop {
            let page = provider
                .usage_page(&app, ledger.0.binding.started_at_unix_seconds, now, offset)
                .map_err(|_| LifecycleError("billing retrieval incomplete"))?;
            if u64::try_from(page.records.len()).ok() != Some(page.total) {
                return Err(LifecycleError("billing pagination is inconsistent"));
            }
            if page.records.is_empty() {
                break;
            }
            let previous = scanned_keys.len();
            for record in page.records {
                if record.app_id != app {
                    return Err(LifecycleError("billing app does not match request"));
                }
                scanned_keys.insert(record.billing_key.clone());
                ledger.record_usage(record)?;
            }
            if scanned_keys.len() == previous {
                return Err(LifecycleError("billing pagination made no progress"));
            }
            offset = offset
                .checked_add(page.total)
                .ok_or(LifecycleError("billing offset overflow"))?;
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct ControllerReport {
    pub simulation: bool,
    pub live_activation_available: bool,
    pub provider_action_performed: bool,
    pub action: WatchdogAction,
    pub conservative_cost_microusd: u64,
    pub inventory_complete: bool,
    pub usage_complete: bool,
    pub resources: BTreeMap<String, DeletionState>,
    pub untracked_inventory_ids: Vec<String>,
    pub independent_disk_deletion_verified: bool,
    pub cleanup_complete: bool,
    pub issues: Vec<String>,
}

/// One explicitly invoked local mock tick; no timer, network, activation, or
/// persistence. Inventory errors do not prevent requesting deletion of known
/// IDs at the policy trigger, but can never establish their absence.
pub fn tick_mock(
    ledger: &mut ExperimentLedger,
    provider: &mut impl MockProvider,
    now: u64,
) -> Result<ControllerReport, LifecycleError> {
    ledger.validate()?;
    ledger.advance_cost(now)?;
    if provider
        .workspace_identity()
        .map_err(|_| LifecycleError("provider identity unavailable"))?
        != ledger.0.binding.workspace_id
    {
        return Err(LifecycleError("provider workspace differs from experiment"));
    }
    let mut issues = Vec::new();
    let usage_complete = match collect_usage(ledger, provider, now) {
        Ok(()) => true,
        Err(error) => {
            issues.push(error.0.to_owned());
            false
        }
    };
    let decision = watchdog(
        &DeploymentManifest {
            source: ManifestSource::SyntheticFixture,
            experiment_id: ledger.0.binding.experiment_id.clone(),
            started_at_unix_seconds: ledger.0.binding.started_at_unix_seconds,
            deletion_deadline_unix_seconds: Some(ledger.0.binding.deletion_deadline_unix_seconds),
            initial_cost_microusd: ledger.0.conservative_cost_floor_microusd,
            quote_reference: "local controller ledger; not a provider quote".to_owned(),
            resources: Vec::new(),
        },
        now,
        ledger.0.conservative_cost_floor_microusd,
    )?;
    let inventory = full_inventory(provider, &ledger.0.binding.workspace_id);
    if inventory.is_err() {
        issues.push("complete workspace inventory unavailable; absence unproven".to_owned());
    }
    for (id, resource) in &mut ledger.0.resources {
        let mut absent = false;
        let previous = resource.deletion;
        if matches!(
            previous,
            DeletionState::AbsentFromInventory | DeletionState::BillingReconciliationPending
        ) {
            // A past observation is not current absence after an inventory or
            // authorization failure. Preserve no optimistic current status.
            resource.deletion = DeletionState::DeletionRequested;
        }
        if let Ok(ids) = &inventory {
            if !ids.contains(id) {
                match provider.detail(id) {
                    Ok(DetailReply::Absent404) => {
                        absent = true;
                        resource.deletion = match previous {
                            DeletionState::AbsentFromInventory
                            | DeletionState::BillingReconciliationPending
                                if usage_complete =>
                            {
                                DeletionState::BillingReconciliationPending
                            }
                            _ => DeletionState::AbsentFromInventory,
                        };
                    }
                    _ => issues
                        .push("resource detail does not corroborate inventory absence".to_owned()),
                }
            } else if matches!(
                previous,
                DeletionState::AbsentFromInventory | DeletionState::BillingReconciliationPending
            ) {
                resource.deletion = DeletionState::DeletionRequested;
                issues.push("previously absent tracked resource is present again".to_owned());
            }
        }
        if decision.action == WatchdogAction::DeleteAll && !absent {
            match provider.delete(id) {
                Ok(DeleteReply::Initiated204 | DeleteReply::Absent404) => {
                    resource.deletion = DeletionState::DeletionRequested
                }
                Err(_) => issues
                    .push("deletion request unconfirmed; cleanup remains incomplete".to_owned()),
            }
        }
    }
    let untracked_inventory_ids = inventory
        .as_ref()
        .map(|ids| {
            ids.iter()
                .filter(|id| !ledger.0.resources.contains_key(*id))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    issues.push(
        "independent disk disappearance and final billing reconciliation are unavailable"
            .to_owned(),
    );
    Ok(ControllerReport {
        simulation: true,
        live_activation_available: false,
        provider_action_performed: false,
        action: decision.action,
        conservative_cost_microusd: ledger.0.conservative_cost_floor_microusd,
        inventory_complete: inventory.is_ok(),
        usage_complete,
        resources: ledger
            .0
            .resources
            .iter()
            .map(|(id, r)| (id.clone(), r.deletion))
            .collect(),
        untracked_inventory_ids,
        independent_disk_deletion_verified: false,
        cleanup_complete: false,
        issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconciliation::{ObservedCvm, ObservedTarget};

    const START: u64 = 1_000;
    fn ledger() -> ExperimentLedger {
        let binding = ExperimentBinding::new(
            "experiment".into(),
            "workspace".into(),
            START,
            START + MAX_LIFETIME_SECONDS,
        )
        .unwrap();
        let mut ledger = ExperimentLedger::new(binding, 0).unwrap();
        ledger.begin_attempt("first".into(), START).unwrap();
        ledger
            .track_cvm("workspace", "first", cvm("one", START))
            .unwrap();
        ledger
    }
    fn cvm(id: &str, created: u64) -> TrackedCvm {
        TrackedCvm {
            cvm_id: id.into(),
            app_id: "app".into(),
            instance_id: Some(format!("instance-{id}")),
            created_at_unix_seconds: created,
            compute_and_disk_microusd_per_hour: 243_120,
        }
    }

    fn rate(id: &str) -> RateBasisEntry {
        RateBasisEntry {
            cvm_id: id.into(),
            compute_microusd_per_hour: 232_000,
            storage_microusd_per_hour: 11_120,
            deletion_basis: ComputeStopBasis::TrackedDelete204,
        }
    }
    fn observation(
        ledger: &ExperimentLedger,
        source_generation: u64,
        at: u64,
        present: bool,
    ) -> ObservationRecord {
        let target = ledger.0.resources["one"].cvm.clone();
        let cvm = ObservedCvm {
            id: target.cvm_id.clone(),
            status: "running".into(),
            app_id: Some(target.app_id.clone()),
            instance_id: target.instance_id.clone(),
            vm_uuid: None,
            workspace_id: Some("workspace".into()),
            created_at: None,
            deleted_at: None,
        };
        ObservationRecord {
            source_generation,
            committed_generation: source_generation + 1,
            usage_start_unix_seconds: START,
            usage_cutoff_unix_seconds: at,
            finished_at_unix_seconds: at,
            recorded_at_unix_seconds: at,
            known_cost_floor_microusd: ledger.planning_cost_at(at).unwrap(),
            inventory_total: u64::from(present),
            inventory_pages: u64::from(present),
            untracked_inventory_ids: Vec::new(),
            tracked: vec![ObservedTarget {
                target,
                inventory: present.then(|| cvm.clone()),
                detail: if present {
                    ObservedDetail::Present(cvm)
                } else {
                    ObservedDetail::NotFound
                },
            }],
            usage_by_app: BTreeMap::from([("app".into(), Vec::new())]),
        }
    }

    #[test]
    fn confirmed_absence_stops_only_compute_and_reappearance_restores_full_rate() {
        let mut ledger = ledger();
        ledger
            .append_observation(observation(&ledger, 1, START + 3600, true))
            .unwrap();
        let intent = ledger
            .append_deletion_intent(2, "workspace", "one", START + 3600)
            .unwrap();
        ledger
            .finish_deletion_intent(intent, DeletionOutcome::Initiated204, START + 3600)
            .unwrap();
        ledger
            .append_observation(observation(&ledger, 3, START + 7200, false))
            .unwrap();
        assert_eq!(ledger.planning_cost_at(START + 10_800).unwrap(), 729_360);
        ledger
            .append_rate_basis(
                4,
                "reviewed Phala tdx.large 80 GB quote".into(),
                vec![rate("one")],
                START + 7200,
            )
            .unwrap();
        assert_eq!(ledger.conservative_cost_floor_microusd(), 486_240);
        assert_eq!(ledger.planning_cost_at(START + 10_800).unwrap(), 497_360);
        ledger
            .append_observation(observation(&ledger, 5, START + 10_800, true))
            .unwrap();
        assert_eq!(ledger.conservative_cost_floor_microusd(), 729_360);
        assert_eq!(ledger.planning_cost_at(START + 14_400).unwrap(), 972_480);
    }

    #[test]
    fn unexplained_absence_and_invalid_rate_splits_never_discount_compute() {
        let mut ledger = ledger();
        ledger
            .append_observation(observation(&ledger, 1, START + 3600, false))
            .unwrap();
        let mut wrong = rate("one");
        wrong.storage_microusd_per_hour -= 1;
        assert!(
            ledger
                .append_rate_basis(2, "quote".into(), vec![wrong], START + 3600)
                .is_err()
        );
        assert!(ledger.rate_basis_events().is_empty());
        ledger
            .append_rate_basis(2, "quote".into(), vec![rate("one")], START + 3600)
            .unwrap();
        assert_eq!(ledger.planning_cost_at(START + 7200).unwrap(), 486_240);
        assert!(
            ledger
                .append_rate_basis(3, "quote".into(), vec![rate("one")], START + 3600)
                .is_err()
        );
    }

    #[test]
    fn manual_delete_assertion_still_requires_prior_presence_and_complete_absence() {
        let mut ledger = ledger();
        ledger
            .append_observation(observation(&ledger, 1, START + 3600, true))
            .unwrap();
        ledger
            .append_observation(observation(&ledger, 2, START + 7200, false))
            .unwrap();
        let mut manual = rate("one");
        manual.deletion_basis = ComputeStopBasis::OperatorAssertedManualDeletion;
        ledger
            .append_rate_basis(
                3,
                "manual deletion and reviewed quote".into(),
                vec![manual],
                START + 7200,
            )
            .unwrap();
        assert_eq!(ledger.planning_cost_at(START + 10_800).unwrap(), 497_360);
    }
    fn page(ids: &[&str]) -> InventoryPage {
        InventoryPage {
            workspace_id: "workspace".into(),
            page: 1,
            pages: 1,
            total: ids.len() as u64,
            items: ids
                .iter()
                .map(|id| InventoryItem {
                    cvm_id: (*id).into(),
                    workspace_id: "workspace".into(),
                    status: "running".into(),
                })
                .collect(),
        }
    }
    fn provider() -> ScriptedMockProvider {
        ScriptedMockProvider {
            workspace: Ok("workspace".into()),
            inventory: BTreeMap::from([(1, Ok(page(&["one"])))]),
            details: BTreeMap::from([("one".into(), Ok(DetailReply::Absent404))]),
            usage: BTreeMap::from([(
                ("app".into(), 0),
                Ok(UsagePage {
                    records: vec![],
                    total: 0,
                }),
            )]),
            deletion: BTreeMap::from([("one".into(), Ok(DeleteReply::Initiated204))]),
            deletion_requests: vec![],
            usage_requests: vec![],
        }
    }
    fn usage(key: &str, cost: &str) -> UsageRecord {
        UsageRecord {
            billing_key: key.into(),
            app_id: "app".into(),
            instance_id: "instance-one".into(),
            usage_type: "storage".into(),
            cost_usd_decimal: cost.into(),
        }
    }

    #[test]
    fn null_instance_tracks_cost_without_fabricating_billing_identity() {
        let binding = ExperimentBinding::new(
            "experiment".into(),
            "workspace".into(),
            START,
            START + MAX_LIFETIME_SECONDS,
        )
        .unwrap();
        let mut ledger = ExperimentLedger::new(binding.clone(), 0).unwrap();
        ledger.begin_attempt("first".into(), START).unwrap();
        let mut first = cvm("one", START);
        first.instance_id = None;
        ledger.track_cvm("workspace", "first", first).unwrap();
        let mut second = cvm("two", START);
        second.instance_id = None;
        ledger.track_cvm("workspace", "first", second).unwrap();
        assert!(ledger.record_usage(usage("unjoined", "1.00")).is_err());
        assert_eq!(ledger.planning_cost_at(START + 3600).unwrap(), 2 * 243_120);
        let restored =
            ExperimentLedger::from_json(&serde_json::to_vec(&ledger).unwrap(), &binding).unwrap();
        assert_eq!(restored.tracked_cvms().count(), 2);
    }

    #[test]
    fn decimals_are_exact_rounded_up_and_checked() {
        assert_eq!(decimal_usd_to_microusd("40.84416").unwrap(), 40_844_160);
        assert_eq!(decimal_usd_to_microusd("0.0000001").unwrap(), 1);
        assert_eq!(decimal_usd_to_microusd("45.000000000").unwrap(), 45_000_000);
        assert_eq!(decimal_usd_to_microusd("4.084416E1").unwrap(), 40_844_160);
        for invalid in [
            "-1",
            "NaN",
            "01",
            "1.",
            ".1",
            " 1",
            "1.2.3",
            "18446744073710",
        ] {
            assert!(decimal_usd_to_microusd(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn billing_dedup_compares_exact_values_without_rewriting_original_lexemes() {
        let mut ledger = ledger();
        ledger.record_usage(usage("same", "1e-7")).unwrap();
        let before = serde_json::to_vec(&ledger).unwrap();
        ledger.record_usage(usage("same", "0.00000010")).unwrap();
        assert_eq!(before, serde_json::to_vec(&ledger).unwrap());
        // Both round to one microUSD but represent different provider charges.
        assert!(ledger.record_usage(usage("same", "2e-7")).is_err());
        assert_eq!(before, serde_json::to_vec(&ledger).unwrap());
    }

    #[test]
    fn restart_and_retries_preserve_original_deadline_and_budget() {
        let mut ledger = ledger();
        let original = ledger.binding().clone();
        let now = START + 3600;
        ledger.begin_attempt("retry".into(), now).unwrap();
        ledger
            .track_cvm("workspace", "retry", cvm("two", now))
            .unwrap();
        let bytes = serde_json::to_vec(&ledger).unwrap();
        let mut restored = ExperimentLedger::from_json(&bytes, &original).unwrap();
        assert_eq!(restored.binding(), &original);
        let report = tick_mock(&mut restored, &mut provider(), now + 3600).unwrap();
        assert_eq!(report.conservative_cost_microusd, 3 * 243_120);
        assert!(
            restored
                .begin_attempt("late".into(), START + MAX_LIFETIME_SECONDS)
                .is_err()
        );
        for field in [
            "deletion_deadline_unix_seconds",
            "started_at_unix_seconds",
            "total_ceiling_microusd",
            "delete_threshold_microusd",
        ] {
            let mut edited: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let value = edited["binding"][field].as_u64().unwrap();
            edited["binding"][field] = serde_json::json!(value + 1);
            assert!(
                ExperimentLedger::from_json(&serde_json::to_vec(&edited).unwrap(), &original)
                    .is_err()
            );
        }
    }

    #[test]
    fn initiated_deletion_stays_pending_until_independent_readback() {
        let mut ledger = ledger();
        let mut provider = provider();
        let deadline = START + MAX_LIFETIME_SECONDS;
        let first = tick_mock(&mut ledger, &mut provider, deadline).unwrap();
        assert_eq!(first.resources["one"], DeletionState::DeletionRequested);
        assert!(!first.cleanup_complete);
        provider.inventory.insert(1, Ok(page(&[])));
        let second = tick_mock(&mut ledger, &mut provider, deadline).unwrap();
        assert_eq!(second.resources["one"], DeletionState::AbsentFromInventory);
        let third = tick_mock(&mut ledger, &mut provider, deadline).unwrap();
        assert_eq!(
            third.resources["one"],
            DeletionState::BillingReconciliationPending
        );
        assert_eq!(provider.deletion_requests, ["one"]);
        assert!(
            !third.independent_disk_deletion_verified
                && !third.cleanup_complete
                && !third.live_activation_available
        );
    }

    #[test]
    fn workspace_and_auth_errors_never_establish_absence() {
        let mut ledger = ledger();
        let mut provider = provider();
        provider.workspace = Ok("another-workspace".into());
        assert!(tick_mock(&mut ledger, &mut provider, START + MAX_LIFETIME_SECONDS).is_err());
        assert!(provider.deletion_requests.is_empty());
        provider.workspace = Ok("workspace".into());
        provider.inventory.insert(1, Ok(page(&[])));
        for error in [ProviderError::Unauthorized, ProviderError::Forbidden] {
            provider.details.insert("one".into(), Err(error));
            let report =
                tick_mock(&mut ledger, &mut provider, START + MAX_LIFETIME_SECONDS).unwrap();
            assert_eq!(report.resources["one"], DeletionState::DeletionRequested);
            assert!(!report.cleanup_complete);
        }
    }

    #[test]
    fn partial_inventory_cannot_prove_absence_and_untracked_ids_are_never_deleted() {
        let mut ledger = ledger();
        let mut provider = provider();
        let mut first = page(&["unrelated"]);
        first.pages = 2;
        first.total = 2;
        provider.inventory.insert(1, Ok(first));
        provider
            .inventory
            .insert(2, Err(ProviderError::Unavailable));
        let report = tick_mock(&mut ledger, &mut provider, START + MAX_LIFETIME_SECONDS).unwrap();
        assert!(!report.inventory_complete);
        assert_eq!(report.resources["one"], DeletionState::DeletionRequested);
        let mut second = page(&["one"]);
        second.page = 2;
        second.pages = 2;
        second.total = 2;
        provider.inventory.insert(2, Ok(second));
        let report = tick_mock(&mut ledger, &mut provider, START + MAX_LIFETIME_SECONDS).unwrap();
        assert_eq!(report.untracked_inventory_ids, ["unrelated"]);
        assert!(provider.deletion_requests.iter().all(|id| id == "one"));
    }

    #[test]
    fn partial_creation_and_lost_delete_response_remain_recoverable() {
        let mut ledger = ledger();
        ledger
            .begin_attempt("failed-partway".into(), START)
            .unwrap();
        let mut provider = provider();
        provider
            .deletion
            .insert("one".into(), Err(ProviderError::Unavailable));
        let first = tick_mock(&mut ledger, &mut provider, START + MAX_LIFETIME_SECONDS).unwrap();
        assert_eq!(first.resources["one"], DeletionState::Tracking);
        provider.inventory.insert(1, Ok(page(&[])));
        let second = tick_mock(&mut ledger, &mut provider, START + MAX_LIFETIME_SECONDS).unwrap();
        assert_eq!(second.resources["one"], DeletionState::AbsentFromInventory);
        assert_eq!(provider.deletion_requests, ["one"]);
    }

    #[test]
    fn paginated_usage_deduplicates_and_triggers_cumulative_deletion() {
        let mut ledger = ledger();
        let mut provider = provider();
        provider.usage.insert(
            ("app".into(), 0),
            Ok(UsagePage {
                records: vec![usage("first", "44")],
                total: 1,
            }),
        );
        provider.usage.insert(
            ("app".into(), 1),
            Ok(UsagePage {
                records: vec![usage("second", "1")],
                total: 1,
            }),
        );
        provider.usage.insert(
            ("app".into(), 2),
            Ok(UsagePage {
                records: vec![],
                total: 0,
            }),
        );
        let report = tick_mock(&mut ledger, &mut provider, START).unwrap();
        assert_eq!(report.action, WatchdogAction::DeleteAll);
        assert_eq!(report.conservative_cost_microusd, 45_000_000);
        assert_eq!(
            tick_mock(&mut ledger, &mut provider, START)
                .unwrap()
                .conservative_cost_microusd,
            45_000_000
        );
        assert!(ledger.begin_attempt("over-budget".into(), START).is_err());
        assert!(ledger.record_usage(usage("first", "43")).is_err());
        assert!(
            provider
                .usage_requests
                .iter()
                .all(|(_, start, end, _)| *start == START && *end == START)
        );
    }

    #[test]
    fn missing_or_late_billing_never_lowers_the_cost_floor() {
        let mut ledger = ledger();
        let mut provider = provider();
        let first = tick_mock(&mut ledger, &mut provider, START + 3600).unwrap();
        assert_eq!(first.conservative_cost_microusd, 243_120);
        provider
            .usage
            .insert(("app".into(), 0), Err(ProviderError::Unavailable));
        provider.inventory.insert(1, Ok(page(&[])));
        let second = tick_mock(&mut ledger, &mut provider, START + 7200).unwrap();
        assert!(!second.usage_complete);
        assert_eq!(second.conservative_cost_microusd, 486_240);
        ledger.record_usage(usage("late", "2")).unwrap();
        let third = tick_mock(&mut ledger, &mut provider, START + 7200).unwrap();
        assert_eq!(third.conservative_cost_microusd, 2_000_000);
        assert!(!third.cleanup_complete);
    }

    #[test]
    fn earlier_absence_is_revoked_when_current_readback_fails() {
        let mut ledger = ledger();
        let mut provider = provider();
        provider.inventory.insert(1, Ok(page(&[])));
        let deadline = START + MAX_LIFETIME_SECONDS;
        assert_eq!(
            tick_mock(&mut ledger, &mut provider, deadline)
                .unwrap()
                .resources["one"],
            DeletionState::AbsentFromInventory
        );
        provider
            .details
            .insert("one".into(), Err(ProviderError::Forbidden));
        let report = tick_mock(&mut ledger, &mut provider, deadline).unwrap();
        assert_eq!(report.resources["one"], DeletionState::DeletionRequested);
        assert!(!report.cleanup_complete);
    }

    #[test]
    fn stopped_resources_keep_the_conservative_compute_and_disk_floor() {
        let mut ledger = ledger();
        let mut provider = provider();
        let mut stopped = page(&["one"]);
        stopped.items[0].status = "stopped".into();
        provider.inventory.insert(1, Ok(stopped));
        let report = tick_mock(&mut ledger, &mut provider, START + 3600).unwrap();
        assert_eq!(report.conservative_cost_microusd, 243_120);
        assert_eq!(report.resources["one"], DeletionState::Tracking);
        assert!(!report.cleanup_complete);
    }

    #[test]
    fn duplicate_or_inconsistent_pagination_fails_without_erasing_known_usage() {
        let mut ledger = ledger();
        let mut provider = provider();
        let repeated = UsagePage {
            records: vec![usage("same", "1")],
            total: 1,
        };
        provider
            .usage
            .insert(("app".into(), 0), Ok(repeated.clone()));
        provider.usage.insert(("app".into(), 1), Ok(repeated));
        let report = tick_mock(&mut ledger, &mut provider, START).unwrap();
        assert!(!report.usage_complete);
        assert_eq!(report.conservative_cost_microusd, 1_000_000);
    }

    #[cfg(unix)]
    mod retry {
        use super::*;
        use crate::reconciliation::ObservedCvm;

        fn record(prior: u64, at: u64) -> DeletionRetryRecord {
            DeletionRetryRecord {
                prior_intent_generation: prior,
                started_at_unix_seconds: at,
                readback_at_unix_seconds: at,
                detail: ObservedDetail::Present(ObservedCvm {
                    id: "one".into(),
                    status: "deleting".into(),
                    app_id: Some("app".into()),
                    instance_id: Some("instance-one".into()),
                    vm_uuid: Some("separate-provider-uuid".into()),
                    workspace_id: Some("workspace".into()),
                    created_at: None,
                    deleted_at: None,
                }),
            }
        }

        #[test]
        fn retry_projection_rejects_conflicts_and_bad_time_without_mutation() {
            let mut before = ledger();
            before
                .append_deletion_intent(0, "workspace", "one", START)
                .unwrap();
            for case in [
                "prior",
                "start",
                "readback",
                "id",
                "app",
                "instance",
                "workspace",
                "uuid",
                "status",
            ] {
                let mut bad = record(1, START + 1);
                match case {
                    "prior" => bad.prior_intent_generation = 0,
                    "start" => bad.started_at_unix_seconds = START - 1,
                    "readback" => bad.readback_at_unix_seconds = START + 2,
                    field => {
                        let ObservedDetail::Present(cvm) = &mut bad.detail else {
                            unreachable!()
                        };
                        match field {
                            "id" => cvm.id = "other".into(),
                            "app" => cvm.app_id = Some("other".into()),
                            "instance" => cvm.instance_id = Some("other".into()),
                            "workspace" => cvm.workspace_id = Some("other".into()),
                            "uuid" => cvm.vm_uuid = Some(" ".into()),
                            _ => cvm.status.clear(),
                        }
                    }
                }
                let mut changed = before.clone();
                assert!(
                    changed
                        .append_deletion_retry(1, "workspace", "one", bad, START + 1)
                        .is_err(),
                    "{case}"
                );
                assert_eq!(
                    serde_json::to_value(changed).unwrap(),
                    serde_json::to_value(&before).unwrap()
                );
            }
            for missing in [true, false] {
                let mut retry = record(1, START + 1);
                if missing {
                    let ObservedDetail::Present(cvm) = &mut retry.detail else {
                        unreachable!()
                    };
                    cvm.app_id = None;
                    cvm.instance_id = None;
                    cvm.workspace_id = None;
                } else {
                    retry.detail = ObservedDetail::NotFound;
                }
                let mut changed = before.clone();
                changed
                    .append_deletion_retry(1, "workspace", "one", retry, START + 1)
                    .unwrap();
                assert_eq!(changed.0.resources["one"].deletion, DeletionState::Tracking);
                assert_eq!(changed.deletion_intents()[0], before.deletion_intents()[0]);
            }
        }

        #[test]
        fn retry_history_requires_latest_parent_and_keeps_superseded_pending_immutable() {
            let mut history = ledger();
            history
                .append_deletion_intent(0, "workspace", "one", START)
                .unwrap();
            let legacy = serde_json::to_value(&history).unwrap();
            assert!(legacy["deletion_intents"][0].get("retry").is_none());
            assert!(
                ExperimentLedger::from_json(
                    &serde_json::to_vec(&legacy).unwrap(),
                    history.binding()
                )
                .is_ok()
            );
            history
                .append_deletion_retry(1, "workspace", "one", record(1, START + 1), START + 1)
                .unwrap();
            assert!(
                history
                    .finish_deletion_intent(0, DeletionOutcome::Initiated204, START + 1)
                    .is_err()
            );
            let mut retroactive = history.clone();
            retroactive.0.deletion_intents[0].outcome = Some(DeletionOutcomeRecord {
                recorded_at_unix_seconds: START + 1,
                outcome: DeletionOutcome::NotFound404,
            });
            assert!(retroactive.validate().is_ok());
            assert!(retroactive.validate_successor(&history).is_err());
            history
                .append_deletion_retry(2, "workspace", "one", record(2, START + 2), START + 2)
                .unwrap();
            let original = serde_json::to_value(&history).unwrap();
            for case in [
                "missing_link",
                "skipped_parent",
                "first_has_parent",
                "future_readback",
            ] {
                let mut bad = original.clone();
                let intents = &mut bad["deletion_intents"];
                match case {
                    "missing_link" => {
                        intents[1].as_object_mut().unwrap().remove("retry");
                    }
                    "skipped_parent" => intents[2]["retry"]["prior_intent_generation"] = 1.into(),
                    "first_has_parent" => {
                        intents[0]["retry"] = serde_json::to_value(record(0, START)).unwrap()
                    }
                    _ => intents[2]["retry"]["readback_at_unix_seconds"] = (START + 3).into(),
                }
                assert!(
                    ExperimentLedger::from_json(
                        &serde_json::to_vec(&bad).unwrap(),
                        history.binding()
                    )
                    .is_err(),
                    "{case}"
                );
            }
        }
    }
}
