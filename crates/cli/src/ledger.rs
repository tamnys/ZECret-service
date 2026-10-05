//! Local operator assertions and durable bookkeeping. No credentials, provider
//! client, scheduler, deployment, charge acceptance or private query path.

use super::{exhausted, print_json, required};
use std::path::PathBuf;
use zrpc_lifecycle::controller::{ComputeStopBasis, RateBasisEntry, TrackedCvm};

pub(super) const USAGE: &str = r"zrpc lifecycle ledger init --original-binding FILE --store-directory DIR --experiment-id ID --workspace-id ID --deletion-deadline UNIX_SECONDS --initial-cost-microusd INTEGER
zrpc lifecycle ledger record-attempt --original-binding FILE --expected-generation INTEGER --attempt-id ID
zrpc lifecycle ledger record-cvm --original-binding FILE --expected-generation INTEGER --attempt-id ID --cvm-id CANONICAL_ID --app-id ID (--instance-id ID | --instance-id-pending) --created-at UNIX_SECONDS --compute-and-disk-microusd-per-hour INTEGER
zrpc lifecycle ledger record-rate-basis --original-binding FILE --expected-generation INTEGER --quote-reference REVIEWED_REFERENCE --rate CVM_ID:COMPUTE_MICROUSD_PER_HOUR:STORAGE_MICROUSD_PER_HOUR:tracked204|operator_manual [--rate ...]
zrpc lifecycle ledger inspect --original-binding FILE
zrpc lifecycle ledger discard-draft --original-binding FILE --expected-generation INTEGER
zrpc lifecycle ledger --help
All paths are absolute. All listed options are required. These commands make no network request.
Initialize before resources are created: the original experiment starts at the actual system time.
The deadline must be within 168 hours of that start and is never renewed. Initial cost must include prior experiment expenses.
Record the attempt before creation, then each returned canonical CVM identity and its conservative rate before the next resource.
Use --instance-id-pending only when the provider reports null; it does not prove a usage-identity mapping.
Identity, rates and creation time are operator assertions, not authenticated provider evidence or permission to spend.
Rate basis is an append-only operator assertion that splits an existing combined rate. tracked204 requires a recorded successful DELETE outcome; operator_manual requires the operator's separate manual-deletion assertion and earlier observed presence. Both require a later complete authenticated absence before compute stops accruing in the model. Storage keeps accruing; prior cost floors never decrease. This does not establish final billing or disk cleanup.
inspect is read-only, including when a draft is pending. It computes a current modeled floor without committing it.
discard-draft explicitly removes only an uncommitted draft; it never promotes it, erases a committed intent or authorizes retry.
No command resets or replaces an original/store. After uncertain writes, inspect retained state rather than initialize again.
Deployment, private mode, billing reconciliation and cleanup acceptance remain unavailable.";

enum Operation {
    Init {
        original: PathBuf,
        store_directory: PathBuf,
        experiment_id: String,
        workspace_id: String,
        deadline: u64,
        initial_cost: u64,
    },
    Attempt {
        original: PathBuf,
        generation: u64,
        attempt_id: String,
    },
    Cvm {
        original: PathBuf,
        generation: u64,
        attempt_id: String,
        target: TrackedCvm,
    },
    RateBasis {
        original: PathBuf,
        generation: u64,
        quote_reference: String,
        entries: Vec<RateBasisEntry>,
    },
    Inspect {
        original: PathBuf,
    },
    Discard {
        original: PathBuf,
        generation: u64,
    },
}

fn text_arg(args: &mut Vec<String>, flag: &str) -> Result<String, String> {
    let value = required(args, flag)?;
    if value.trim().is_empty() {
        return Err("identifier must not be empty".into());
    }
    Ok(value)
}
fn number(args: &mut Vec<String>, flag: &str) -> Result<u64, String> {
    required(args, flag)?
        .parse()
        .map_err(|_| "option requires a nonnegative representable integer".into())
}
fn absolute(args: &mut Vec<String>, flag: &str) -> Result<PathBuf, String> {
    let value = PathBuf::from(required(args, flag)?);
    if !value.is_absolute() {
        return Err("local ledger paths must be absolute".into());
    }
    Ok(value)
}
fn pending_instance(args: &mut Vec<String>) -> Result<Option<String>, String> {
    let pending = args.iter().position(|arg| arg == "--instance-id-pending");
    let supplied = args.iter().any(|arg| arg == "--instance-id");
    match (pending, supplied) {
        (Some(_), true) => Err("choose exactly one instance identity option".into()),
        (Some(index), false) => {
            args.remove(index);
            Ok(None)
        }
        (None, _) => text_arg(args, "--instance-id").map(Some),
    }
}
fn rate_entries(args: &mut Vec<String>) -> Result<Vec<RateBasisEntry>, String> {
    let mut entries = Vec::new();
    while let Some(index) = args.iter().position(|arg| arg == "--rate") {
        args.remove(index);
        let value = args
            .get(index)
            .ok_or("--rate requires CVM_ID:COMPUTE:STORAGE:DELETION_BASIS")?
            .clone();
        args.remove(index);
        let mut parts = value.split(':');
        let cvm_id = parts.next().unwrap_or_default();
        let compute = parts.next().ok_or("--rate requires four fields")?;
        let storage = parts.next().ok_or("--rate requires four fields")?;
        let deletion_basis = parts.next().ok_or("--rate requires four fields")?;
        if cvm_id.is_empty() || parts.next().is_some() {
            return Err("--rate requires exactly four fields".into());
        }
        let deletion_basis = match deletion_basis {
            "tracked204" => ComputeStopBasis::TrackedDelete204,
            "operator_manual" => ComputeStopBasis::OperatorAssertedManualDeletion,
            _ => return Err("unsupported deletion basis".into()),
        };
        if entries
            .iter()
            .any(|entry: &RateBasisEntry| entry.cvm_id == cvm_id)
        {
            return Err("duplicate rate basis target".into());
        }
        entries.push(RateBasisEntry {
            cvm_id: cvm_id.to_owned(),
            compute_microusd_per_hour: compute.parse().map_err(|_| "invalid compute rate")?,
            storage_microusd_per_hour: storage.parse().map_err(|_| "invalid storage rate")?,
            deletion_basis,
        });
    }
    if entries.is_empty() {
        return Err("at least one --rate is required".into());
    }
    Ok(entries)
}
fn parse(mut args: Vec<String>) -> Result<Operation, String> {
    if args.is_empty() {
        return Err("ledger operation required; use lifecycle ledger --help".into());
    }
    let operation = args.remove(0);
    let original = absolute(&mut args, "--original-binding")?;
    let result = match operation.as_str() {
        "init" => Operation::Init {
            original,
            store_directory: absolute(&mut args, "--store-directory")?,
            experiment_id: text_arg(&mut args, "--experiment-id")?,
            workspace_id: text_arg(&mut args, "--workspace-id")?,
            deadline: number(&mut args, "--deletion-deadline")?,
            initial_cost: number(&mut args, "--initial-cost-microusd")?,
        },
        "record-attempt" => Operation::Attempt {
            original,
            generation: number(&mut args, "--expected-generation")?,
            attempt_id: text_arg(&mut args, "--attempt-id")?,
        },
        "record-cvm" => Operation::Cvm {
            original,
            generation: number(&mut args, "--expected-generation")?,
            attempt_id: text_arg(&mut args, "--attempt-id")?,
            target: TrackedCvm {
                cvm_id: text_arg(&mut args, "--cvm-id")?,
                app_id: text_arg(&mut args, "--app-id")?,
                instance_id: pending_instance(&mut args)?,
                created_at_unix_seconds: number(&mut args, "--created-at")?,
                compute_and_disk_microusd_per_hour: number(
                    &mut args,
                    "--compute-and-disk-microusd-per-hour",
                )?,
            },
        },
        "record-rate-basis" => Operation::RateBasis {
            original,
            generation: number(&mut args, "--expected-generation")?,
            quote_reference: text_arg(&mut args, "--quote-reference")?,
            entries: rate_entries(&mut args)?,
        },
        "inspect" => Operation::Inspect { original },
        "discard-draft" => Operation::Discard {
            original,
            generation: number(&mut args, "--expected-generation")?,
        },
        _ => return Err("unsupported ledger operation; use lifecycle ledger --help".into()),
    };
    exhausted(&args)?;
    Ok(result)
}

pub(super) fn run(args: Vec<String>) -> Result<(), String> {
    if args.as_slice() == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    execute(parse(args)?)
}

#[cfg(unix)]
fn execute(operation: Operation) -> Result<(), String> {
    use zrpc_lifecycle::persistence::LedgerStore;
    let (store, label, discarded) = match operation {
        Operation::Init {
            original,
            store_directory,
            experiment_id,
            workspace_id,
            deadline,
            initial_cost,
        } => (
            LedgerStore::initialize_experiment(
                &original,
                &store_directory,
                experiment_id,
                workspace_id,
                deadline,
                initial_cost,
            )
            .map_err(|error| error.to_string())?,
            "initialize",
            None,
        ),
        Operation::Attempt {
            original,
            generation,
            attempt_id,
        } => {
            let mut store = LedgerStore::open(&original).map_err(|error| error.to_string())?;
            store
                .record_attempt(generation, attempt_id)
                .map_err(|error| error.to_string())?;
            (store, "record_attempt", None)
        }
        Operation::Cvm {
            original,
            generation,
            attempt_id,
            target,
        } => {
            let mut store = LedgerStore::open(&original).map_err(|error| error.to_string())?;
            store
                .record_cvm(generation, &attempt_id, target)
                .map_err(|error| error.to_string())?;
            (store, "record_cvm", None)
        }
        Operation::RateBasis {
            original,
            generation,
            quote_reference,
            entries,
        } => {
            let mut store = LedgerStore::open(&original).map_err(|error| error.to_string())?;
            store
                .record_rate_basis(generation, quote_reference, entries)
                .map_err(|error| error.to_string())?;
            (store, "record_rate_basis", None)
        }
        Operation::Inspect { original } => (
            LedgerStore::open(&original).map_err(|error| error.to_string())?,
            "inspect",
            None,
        ),
        Operation::Discard {
            original,
            generation,
        } => {
            let mut store = LedgerStore::open(&original).map_err(|error| error.to_string())?;
            let pending = store.has_uncommitted_draft();
            store
                .discard_uncommitted_draft_at(generation)
                .map_err(|error| error.to_string())?;
            (store, "discard_draft", Some(pending))
        }
    };
    let inspection = store.inspect().map_err(|error| error.to_string())?;
    print_json(serde_json::json!({
        "mode": "local_ledger_operation",
        "operation": label,
        "operator_assertions_only": true,
        "clock_source": "system_clock",
        "provider_authenticated": false,
        "network_used": false,
        "provider_mutations_performed": false,
        "private_accepted": false,
        "query_sent": false,
        "deployment_enabled": false,
        "deletion_retry_authorized": false,
        "billing_reconciled": false,
        "independent_disk_deletion_verified": false,
        "cleanup_complete": false,
        "pending_draft_discarded": discarded,
        "inspection": inspection,
    }))
}

#[cfg(not(unix))]
fn execute(_operation: Operation) -> Result<(), String> {
    Err("local ledger operations require the Unix ledger store".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments(command: &str) -> Vec<String> {
        let mut args = vec![command, "--original-binding", "/operator/original.json"];
        match command {
            "init" => args.extend([
                "--store-directory",
                "/operator/store",
                "--experiment-id",
                "synthetic",
                "--workspace-id",
                "synthetic",
                "--deletion-deadline",
                "1",
                "--initial-cost-microusd",
                "0",
            ]),
            "record-attempt" => {
                args.extend(["--expected-generation", "0", "--attempt-id", "first"])
            }
            "record-cvm" => args.extend([
                "--expected-generation",
                "0",
                "--attempt-id",
                "first",
                "--cvm-id",
                "synthetic",
                "--app-id",
                "synthetic",
                "--instance-id",
                "synthetic",
                "--created-at",
                "1",
                "--compute-and-disk-microusd-per-hour",
                "1",
            ]),
            "record-rate-basis" => args.extend([
                "--expected-generation",
                "0",
                "--quote-reference",
                "https://cloud.phala.com/about/pricing",
                "--rate",
                "cvm_synthetic:232000:11120:tracked204",
            ]),
            "discard-draft" => args.extend(["--expected-generation", "0"]),
            _ => (),
        }
        args.into_iter().map(str::to_owned).collect()
    }
    #[test]
    fn every_operation_requires_exact_arguments_and_never_accepts_provider_or_clock_authority() {
        for command in [
            "init",
            "record-attempt",
            "record-cvm",
            "record-rate-basis",
            "inspect",
            "discard-draft",
        ] {
            let base = arguments(command);
            assert!(parse(base.clone()).is_ok());
            for index in (1..base.len()).step_by(2) {
                let mut missing = base.clone();
                missing.drain(index..index + 2);
                assert!(parse(missing).is_err());
                let mut missing_value = base.clone();
                missing_value.remove(index + 1);
                assert!(parse(missing_value).is_err());
                let mut duplicate = base.clone();
                duplicate.extend_from_slice(&base[index..index + 2]);
                assert!(parse(duplicate).is_err());
            }
            for flag in [
                "--now",
                "--started-at",
                "--api-key",
                "--endpoint",
                "--reset",
                "--force",
                "--ledger-json",
                "--usage",
                "--retry",
                "--deploy",
            ] {
                let mut args = base.clone();
                args.extend([flag.into(), "SENSITIVE-MARKER".into()]);
                let Err(error) = parse(args) else {
                    panic!("unsupported authority accepted")
                };
                assert!(!error.contains("SENSITIVE-MARKER"));
            }
        }
    }
    #[test]
    fn invalid_paths_numbers_and_empty_identifiers_reject_without_echo() {
        for (command, flag, invalid) in [
            ("init", "--original-binding", "relative"),
            ("init", "--store-directory", "relative"),
            ("init", "--experiment-id", " "),
            ("init", "--workspace-id", ""),
            ("init", "--deletion-deadline", "18446744073709551616"),
            ("init", "--initial-cost-microusd", "-1"),
            (
                "record-attempt",
                "--expected-generation",
                "SENSITIVE-MARKER",
            ),
            ("record-cvm", "--created-at", "-1"),
            ("record-cvm", "--compute-and-disk-microusd-per-hour", "1.5"),
            (
                "record-rate-basis",
                "--rate",
                "cvm_synthetic:bad:11120:tracked204",
            ),
            ("record-rate-basis", "--quote-reference", " "),
        ] {
            let mut args = arguments(command);
            let index = args.iter().position(|arg| arg == flag).unwrap();
            args[index + 1] = invalid.into();
            let Err(error) = parse(args) else {
                panic!("invalid option accepted")
            };
            assert!(!error.contains("SENSITIVE-MARKER"));
        }
    }
    #[test]
    fn null_instance_requires_explicit_pending_flag() {
        let mut args = arguments("record-cvm");
        let index = args.iter().position(|arg| arg == "--instance-id").unwrap();
        args.splice(index..index + 2, ["--instance-id-pending".into()]);
        let Operation::Cvm { target, .. } = parse(args.clone()).unwrap() else {
            panic!("wrong operation")
        };
        assert!(target.instance_id.is_none());
        args.extend(["--instance-id".into(), "invented".into()]);
        assert!(parse(args).is_err());
    }
}
