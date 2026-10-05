use super::*;
use crate::{DELETE_THRESHOLD_MICROUSD, MAX_LIFETIME_SECONDS};
use std::sync::atomic::{AtomicU64, Ordering};

const START: u64 = 1_000;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.codex-tmp/lifecycle-operator-tests");
        fs::create_dir_all(&base).unwrap();
        let path = fs::canonicalize(base).unwrap().join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn original(&self) -> PathBuf {
        self.0.join("original.json")
    }
    fn store(&self) -> PathBuf {
        self.0.join("state")
    }
    fn initialize(&self, initial_cost: u64) -> LedgerStore {
        LedgerStore::initialize_experiment_at(
            &self.original(),
            &self.store(),
            "experiment".into(),
            "workspace".into(),
            START + MAX_LIFETIME_SECONDS,
            initial_cost,
            START,
        )
        .unwrap()
    }
    fn bytes(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut result = BTreeMap::new();
        for entry in fs::read_dir(&self.0).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                for inner in fs::read_dir(path).unwrap() {
                    let path = inner.unwrap().path();
                    result.insert(path.clone(), fs::read(path).unwrap());
                }
            } else {
                result.insert(path.clone(), fs::read(path).unwrap());
            }
        }
        result
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn cvm(id: &str, created_at: u64) -> TrackedCvm {
    TrackedCvm {
        cvm_id: id.into(),
        app_id: "app".into(),
        instance_id: Some(format!("instance-{id}")),
        created_at_unix_seconds: created_at,
        compute_and_disk_microusd_per_hour: 243_120,
    }
}

fn attempt(store: &mut LedgerStore, generation: u64, id: &str, now: u64) {
    store
        .record_attempt_at_with_hook(generation, id.into(), now, &mut |_| Ok(()))
        .unwrap();
}

#[test]
fn reviewed_rate_basis_is_one_append_only_ledger_transition() {
    let temp = Temp::new();
    let mut store = temp.initialize(0);
    attempt(&mut store, 0, "first", START);
    store
        .record_cvm_at_with_hook(1, "first", cvm("one", START), START, &mut |_| Ok(()))
        .unwrap();
    let entry = RateBasisEntry {
        cvm_id: "one".into(),
        compute_microusd_per_hour: 232_000,
        storage_microusd_per_hour: 11_120,
        deletion_basis: crate::controller::ComputeStopBasis::TrackedDelete204,
    };
    let mut forged = store.ledger().unwrap().clone();
    forged
        .append_rate_basis(2, "reviewed quote".into(), vec![entry.clone()], START + 1)
        .unwrap();
    assert_eq!(store.commit(&forged), Err(StoreError::InvalidState));
    assert_eq!(
        store.inspect_at(START + 1).unwrap().reference.generation(),
        2
    );
    store
        .record_rate_basis_at_with_hook(
            2,
            "reviewed quote".into(),
            vec![entry.clone()],
            START + 1,
            &mut |_| Ok(()),
        )
        .unwrap();
    assert_eq!(
        store.inspect_at(START + 1).unwrap().reference.generation(),
        3
    );
    assert_eq!(
        store.ledger().unwrap().rate_basis_events()[0].entries,
        [entry.clone()]
    );
    let prior = temp.bytes();
    assert!(
        store
            .record_rate_basis_at_with_hook(
                2,
                "reviewed quote".into(),
                vec![entry],
                START + 1,
                &mut |_| Ok(()),
            )
            .is_err()
    );
    assert_eq!(prior, temp.bytes());
    drop(store);
    let reopened = LedgerStore::open(&temp.original()).unwrap();
    assert_eq!(
        reopened
            .inspect_at(START + 1)
            .unwrap()
            .reference
            .generation(),
        3
    );
    assert_eq!(prior, temp.bytes());
}

#[test]
fn public_operator_workflow_uses_actual_time_and_reopens_committed_history() {
    let temp = Temp::new();
    let before = wall_clock().unwrap();
    let mut store = LedgerStore::initialize_experiment(
        &temp.original(),
        &temp.store(),
        "experiment".into(),
        "workspace".into(),
        before + MAX_LIFETIME_SECONDS,
        17,
    )
    .unwrap();
    let (start, deadline) = store.ledger().unwrap().binding().original_window();
    assert!(start >= before && start <= wall_clock().unwrap());
    assert_eq!(deadline, before + MAX_LIFETIME_SECONDS);
    assert_eq!(
        store
            .record_attempt(0, "first".into())
            .unwrap()
            .generation(),
        1
    );
    let target = cvm("one", wall_clock().unwrap());
    assert_eq!(
        store
            .record_cvm(1, "first", target.clone())
            .unwrap()
            .generation(),
        2
    );
    let bytes = temp.bytes();
    let view = store.inspect().unwrap();
    assert_eq!(view.reference.generation(), 2);
    assert!(!view.has_uncommitted_draft);
    assert!(view.evaluated_at_unix_seconds >= start);
    assert!(view.conservative_cost_floor_microusd >= 17);
    assert_eq!(
        view.ledger.tracked_cvms().collect::<Vec<_>>(),
        vec![&target]
    );
    let serialized = serde_json::to_value(&view).unwrap();
    assert_eq!(serialized["ledger"]["usage"], serde_json::json!({}));
    assert_eq!(
        serialized["ledger"]["deletion_intents"],
        serde_json::json!([])
    );
    assert_eq!(serialized["ledger"]["observations"], serde_json::json!([]));
    assert_eq!(bytes, temp.bytes());
    drop(store);
    let reopened = LedgerStore::open(&temp.original()).unwrap();
    assert_eq!(
        json_bytes(reopened.ledger().unwrap()).unwrap(),
        json_bytes(&view.ledger).unwrap()
    );
    assert_eq!(bytes, temp.bytes());
}

#[test]
fn initialization_rejects_invalid_windows_existing_outputs_and_partial_publication() {
    let temp = Temp::new();
    for deadline in [START, START - 1, START + MAX_LIFETIME_SECONDS + 1] {
        assert!(matches!(
            LedgerStore::initialize_experiment_at(
                &temp.original(),
                &temp.store(),
                "experiment".into(),
                "workspace".into(),
                deadline,
                0,
                START,
            ),
            Err(StoreError::InvalidState)
        ));
        assert!(temp.bytes().is_empty());
    }
    let pending = sibling(&temp.original(), ".pending").unwrap();
    fs::write(&pending, b"interrupted original publication").unwrap();
    let before = temp.bytes();
    assert!(matches!(
        LedgerStore::initialize_experiment_at(
            &temp.original(),
            &temp.store(),
            "experiment".into(),
            "workspace".into(),
            START + MAX_LIFETIME_SECONDS,
            0,
            START,
        ),
        Err(StoreError::ExistingOutput)
    ));
    assert_eq!(before, temp.bytes());

    let temp = Temp::new();
    let store = temp.initialize(0);
    let before = temp.bytes();
    drop(store);
    assert!(matches!(
        LedgerStore::initialize_experiment_at(
            &temp.original(),
            &temp.store(),
            "replacement".into(),
            "workspace".into(),
            START + MAX_LIFETIME_SECONDS,
            0,
            START + 1,
        ),
        Err(StoreError::ExistingOutput)
    ));
    assert_eq!(before, temp.bytes());
}

#[test]
fn invalid_duplicate_stale_and_clock_reversed_operations_never_write() {
    let temp = Temp::new();
    let mut store = temp.initialize(0);
    attempt(&mut store, 0, "first", START + 20);
    let before = temp.bytes();
    for (generation, id, now) in [
        (0, "second", START + 21),
        (1, "first", START + 21),
        (1, "", START + 21),
        (1, "second", START + 19),
    ] {
        assert!(matches!(
            store.record_attempt_at_with_hook(generation, id.into(), now, &mut |_| Ok(())),
            Err(StoreError::InvalidState)
        ));
        assert_eq!(before, temp.bytes());
    }
    for (generation, id, created, now) in [
        (0, "first", START + 20, START + 21),
        (1, "missing", START + 20, START + 21),
        (1, "first", START + 19, START + 21),
        (1, "first", START + 22, START + 21),
        (1, "first", START + 20, START + 19),
    ] {
        assert!(matches!(
            store.record_cvm_at_with_hook(
                generation,
                id,
                cvm("one", created),
                now,
                &mut |_| Ok(())
            ),
            Err(StoreError::InvalidState)
        ));
        assert_eq!(before, temp.bytes());
    }
    store
        .record_cvm_at_with_hook(1, "first", cvm("one", START + 20), START + 21, &mut |_| {
            Ok(())
        })
        .unwrap();
    let before = temp.bytes();
    assert!(matches!(
        store.record_cvm_at_with_hook(2, "first", cvm("one", START + 20), START + 22, &mut |_| Ok(
            ()
        )),
        Err(StoreError::InvalidState)
    ));
    assert_eq!(before, temp.bytes());
    assert!(matches!(
        store.inspect_at(START + 20),
        Err(StoreError::InvalidState)
    ));
    assert_eq!(before, temp.bytes());
}

#[test]
fn late_resources_remain_recordable_after_deadline_and_deletion_threshold() {
    let temp = Temp::new();
    let mut store = temp.initialize(DELETE_THRESHOLD_MICROUSD - 1);
    attempt(&mut store, 0, "first", START);
    let binding = json_bytes(store.ledger().unwrap().binding()).unwrap();
    let created = START + MAX_LIFETIME_SECONDS + 1;
    let now = created + 3_600;
    store
        .record_cvm_at_with_hook(1, "first", cvm("late", created), now, &mut |_| Ok(()))
        .unwrap();
    assert!(
        store.ledger().unwrap().conservative_cost_floor_microusd() >= DELETE_THRESHOLD_MICROUSD
    );
    store
        .record_cvm_at_with_hook(2, "first", cvm("later", now), now, &mut |_| Ok(()))
        .unwrap();
    let before = temp.bytes();
    assert!(matches!(
        store.record_attempt_at_with_hook(3, "retry".into(), now, &mut |_| Ok(())),
        Err(StoreError::InvalidState)
    ));
    assert_eq!(before, temp.bytes());
    assert_eq!(
        json_bytes(store.ledger().unwrap().binding()).unwrap(),
        binding
    );
    drop(store);
    let reopened = LedgerStore::open(&temp.original()).unwrap();
    let view = reopened.inspect_at(now).unwrap();
    assert_eq!(view.reference.generation(), 3);
    assert_eq!(view.ledger.tracked_cvms().count(), 2);
    assert!(view.ledger.deletion_intents().is_empty());
    assert!(view.ledger.observations().is_empty());
    let before = temp.bytes();
    let later_view = reopened.inspect_at(now + 3_600).unwrap();
    assert!(later_view.conservative_cost_floor_microusd > view.conservative_cost_floor_microusd);
    assert_eq!(
        json_bytes(&later_view.ledger).unwrap(),
        json_bytes(&view.ledger).unwrap()
    );
    assert_eq!(before, temp.bytes());

    let temp = Temp::new();
    let mut store = temp.initialize(DELETE_THRESHOLD_MICROUSD);
    let before = temp.bytes();
    assert!(matches!(
        store.record_attempt_at_with_hook(0, "first".into(), START, &mut |_| Ok(())),
        Err(StoreError::InvalidState)
    ));
    assert_eq!(before, temp.bytes());

    let temp = Temp::new();
    let mut store = temp.initialize(0);
    let before = temp.bytes();
    assert!(matches!(
        store.record_attempt_at_with_hook(
            0,
            "first".into(),
            START + MAX_LIFETIME_SECONDS,
            &mut |_| Ok(())
        ),
        Err(StoreError::InvalidState)
    ));
    assert_eq!(before, temp.bytes());
}

#[test]
fn inspection_and_explicit_recovery_preserve_history_without_promoting_drafts() {
    let temp = Temp::new();
    let mut store = temp.initialize(0);
    attempt(&mut store, 0, "first", START);
    let committed = json_bytes(store.ledger().unwrap()).unwrap();
    fs::write(temp.store().join(PENDING), b"not a committed snapshot").unwrap();
    let before = temp.bytes();
    let view = store.inspect_at(START + 1).unwrap();
    assert!(view.has_uncommitted_draft);
    assert_eq!(view.reference.generation(), 1);
    assert_eq!(json_bytes(&view.ledger).unwrap(), committed);
    assert_eq!(before, temp.bytes());
    assert!(matches!(
        store.record_attempt(1, "second".into()),
        Err(StoreError::PendingRecovery)
    ));
    assert!(matches!(
        store.discard_uncommitted_draft_at(0),
        Err(StoreError::InvalidState)
    ));
    assert_eq!(before, temp.bytes());
    assert_eq!(
        store.discard_uncommitted_draft_at(1).unwrap().generation(),
        1
    );
    let after = temp.bytes();
    let mut expected = before;
    expected.remove(&temp.store().join(PENDING));
    assert_eq!(expected, after);
    assert_eq!(json_bytes(store.ledger().unwrap()).unwrap(), committed);
    assert!(!store.inspect_at(START + 1).unwrap().has_uncommitted_draft);
    assert_eq!(
        store.discard_uncommitted_draft_at(1).unwrap().generation(),
        1
    );
    assert_eq!(after, temp.bytes());
    // Committed corruption is never repaired or bypassed by either operation.
    fs::write(
        temp.store().join(snapshot_name(0)),
        b"truncated committed snapshot",
    )
    .unwrap();
    fs::write(temp.store().join(PENDING), b"still pending").unwrap();
    let corrupted = temp.bytes();
    assert!(matches!(
        store.inspect_at(START + 1),
        Err(StoreError::InvalidState)
    ));
    assert!(matches!(
        store.discard_uncommitted_draft_at(1),
        Err(StoreError::InvalidState)
    ));
    assert_eq!(corrupted, temp.bytes());
}

#[test]
fn operator_write_failures_require_reload_and_preserve_previous_or_successor() {
    for resource in [false, true] {
        for point in [
            CommitPoint::DraftCreated,
            CommitPoint::DraftWritten,
            CommitPoint::DraftSynced,
            CommitPoint::SnapshotLinked,
            CommitPoint::DirectorySynced,
            CommitPoint::DraftRemoved,
        ] {
            let temp = Temp::new();
            let mut store = temp.initialize(0);
            if resource {
                attempt(&mut store, 0, "first", START);
            }
            let prior_generation = store.generation;
            let prior = json_bytes(store.ledger().unwrap()).unwrap();
            let mut next = store.ledger().unwrap().clone();
            let mut hook = |at| {
                if at == point {
                    Err(StoreError::Io)
                } else {
                    Ok(())
                }
            };
            let result = if resource {
                next.record_cvm_at("first", cvm("one", START), START + 1)
                    .unwrap();
                store.record_cvm_at_with_hook(
                    prior_generation,
                    "first",
                    cvm("one", START),
                    START + 1,
                    &mut hook,
                )
            } else {
                next.begin_attempt("first".into(), START + 1).unwrap();
                store.record_attempt_at_with_hook(
                    prior_generation,
                    "first".into(),
                    START + 1,
                    &mut hook,
                )
            };
            assert!(matches!(result, Err(StoreError::Io)));
            assert!(matches!(
                store.inspect_at(START + 2),
                Err(StoreError::ReloadRequired)
            ));
            assert!(matches!(
                store.discard_uncommitted_draft_at(prior_generation),
                Err(StoreError::ReloadRequired)
            ));
            drop(store);
            let mut reopened = LedgerStore::open(&temp.original()).unwrap();
            let view = reopened.inspect_at(START + 2).unwrap();
            let published = matches!(
                point,
                CommitPoint::SnapshotLinked
                    | CommitPoint::DirectorySynced
                    | CommitPoint::DraftRemoved
            );
            let expected_generation = prior_generation + u64::from(published);
            assert_eq!(view.reference.generation(), expected_generation);
            let expected = if published {
                json_bytes(&next).unwrap()
            } else {
                prior
            };
            assert_eq!(json_bytes(&view.ledger).unwrap(), expected);
            assert_eq!(
                view.has_uncommitted_draft,
                point != CommitPoint::DraftRemoved
            );
            reopened
                .discard_uncommitted_draft_at(expected_generation)
                .unwrap();
            assert_eq!(json_bytes(reopened.ledger().unwrap()).unwrap(), expected);
            assert_eq!(
                reopened.planning_reference().unwrap().generation(),
                expected_generation
            );
        }
    }
}
