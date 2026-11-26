use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

use crate::finding::Findings;
use crate::verification::{Gate, Obligation, Project, owned_file};
use crate::workspace;

mod record;

use record::{Outcome, Record};

const LOCKFILE: &str = "Cargo.lock";

#[derive(Debug)]
struct Revision {
	commit: String,
	lockfile_digest: String,
}

pub(crate) fn check(root: &Path, directory: &Path, projects: &[Project], findings: &mut Findings) {
	let revision = match revision(root) {
		Ok(revision) => revision,
		Err(error) => {
			findings.add(root, error);
			return;
		}
	};
	check_records(root, directory, projects, &revision, findings);
}

fn check_records(
	root: &Path,
	directory: &Path,
	projects: &[Project],
	revision: &Revision,
	findings: &mut Findings,
) {
	let required = projects
		.iter()
		.flat_map(|project| {
			project
				.obligations
				.iter()
				.map(move |entry| (project, entry))
		})
		.collect::<Vec<_>>();
	let mut satisfied = BTreeSet::new();
	let mut ids = BTreeSet::new();
	for file in record_files(directory, findings) {
		let Some(record) = record::read(&file, findings) else {
			continue;
		};
		if !ids.insert(record.evidence_id.clone()) {
			findings.add(
				&file,
				format_args!("duplicate evidence ID {}", record.evidence_id),
			);
		}
		if !record.validate(&file, findings) || record.outcome != Outcome::Pass {
			continue;
		}
		let Some(gate) = record.kind.gate() else {
			continue;
		};
		if record.commit != revision.commit
			|| record.lockfile_digest.as_deref() != Some(&revision.lockfile_digest)
		{
			findings.add(
				&file,
				"record commit or lockfile digest does not match the clean checkout",
			);
			continue;
		}
		let log = PathBuf::from(format!("{}.log", record.evidence_id));
		if !matches_digest(directory, &log, record.artifact_digest.as_deref(), findings) {
			continue;
		}
		if fs::metadata(directory.join(&log)).is_ok_and(|metadata| metadata.len() == 0) {
			findings.add(&file, "executed evidence has an empty tool log");
			continue;
		}
		for id in &record.obligation_ids {
			let Some((project, entry)) = required.iter().find(|(_, entry)| entry.id == *id) else {
				findings.add(&file, format_args!("undeclared obligation {id}"));
				continue;
			};
			if !entry.gates.contains(&gate) {
				findings.add(&file, format_args!("{id} does not declare the {gate} gate"));
				continue;
			}
			if !entry
				.requirement_ids
				.iter()
				.all(|id| record.requirement_ids.contains(id))
			{
				findings.add(&file, format_args!("record omits requirement IDs for {id}"));
				continue;
			}
			if record.assumptions != entry.assumptions {
				findings.add(
					&file,
					format_args!("record changes the scope assumptions of {id}"),
				);
				continue;
			}
			if matches_digest(
				&project.root,
				&entry.source,
				Some(&record.source_digest),
				findings,
			) && matches_command(root, project, entry, &record, gate)
				&& matches_gate(directory, project, entry, &record, gate, findings)
			{
				satisfied.insert((id.clone(), gate));
			} else {
				findings.add(
					&file,
					format_args!("{id} evidence does not bind its declared {gate} gate and oracle"),
				);
			}
		}
	}
	for (_, entry) in required {
		for gate in &entry.gates {
			if !satisfied.contains(&(entry.id.clone(), *gate)) {
				findings.add(
					directory,
					format_args!("missing passing {gate} evidence for {}", entry.id),
				);
			}
		}
	}
}

fn matches_command(
	root: &Path,
	project: &Project,
	entry: &Obligation,
	record: &Record,
	gate: Gate,
) -> bool {
	if gate == Gate::Rust {
		return entry.rust.as_ref().is_some_and(|link| {
			let mut command = vec![
				"cargo",
				"nextest",
				"run",
				"--locked",
				"-p",
				&project.package_name,
			];
			let features = link.features.join(",");
			if !link.features.is_empty() {
				command.extend(["--no-default-features", "--features", &features]);
			}
			command.extend(["--no-tests", "fail", "--", "--exact", &link.test]);
			record
				.redacted_command
				.iter()
				.map(String::as_str)
				.eq(command)
				&& record.matches_features(&link.features)
		});
	}
	let script = project.root.join("verification/check.sh");
	let Ok(script) = script.strip_prefix(root) else {
		return false;
	};
	matches!(record.redacted_command.as_slice(), [command, argument] if Path::new(command) == script && argument == &gate.to_string())
}

fn matches_gate(
	directory: &Path,
	project: &Project,
	entry: &Obligation,
	record: &Record,
	gate: Gate,
	findings: &mut Findings,
) -> bool {
	match gate {
		Gate::Rust => entry
			.rust
			.as_ref()
			.is_some_and(|link| oracle_matches(record, &link.oracle) && record.seeds == link.seeds),
		Gate::Lean => entry.lean.as_ref().is_some_and(|link| {
			record.detail.theorem.as_deref() == Some(&link.theorem)
				&& oracle_matches(record, &link.oracle)
				&& record.detail.axioms_tcb == link.axioms_tcb
				&& record.detail.extraction_digest == record.generated_input_digest
				&& matches_digest(
					&project.root,
					&link.generated,
					record.detail.extraction_digest.as_deref(),
					findings,
				)
		}),
		Gate::Kani => entry.kani.as_ref().is_some_and(|link| {
			record.detail.harness.as_deref() == Some(&link.harness)
				&& oracle_matches(record, &link.oracle)
				&& record.model_bounds == link.model_bounds
				&& record
					.detail
					.unwind_bound
					.as_deref()
					.and_then(|bound| bound.parse::<u32>().ok())
					== Some(link.unwind_bound)
				&& record
					.redacted_command
					.iter()
					.all(|arg| !arg.contains("--no-unwinding-checks"))
		}),
		Gate::Tlc => entry.tlc.as_ref().is_some_and(|link| {
			let trace = PathBuf::from(format!("{}.trace", record.evidence_id));
			oracle_matches(record, &link.oracle)
				&& record.model_bounds == link.model_bounds
				&& record.detail.fairness == link.fairness
				&& record.seeds == link.seeds
				&& record
					.detail
					.state_count
					.as_deref()
					.and_then(|count| count.parse::<u64>().ok())
					.is_some_and(|count| count > 0)
				&& !record.model_bounds.is_empty()
				&& matches_digest(
					directory,
					&trace,
					record.detail.trace_digest.as_deref(),
					findings,
				)
		}),
	}
}

fn oracle_matches(record: &Record, oracle: &Option<String>) -> bool {
	oracle
		.as_ref()
		.is_none_or(|oracle| &record.oracle == oracle)
}

fn record_files(directory: &Path, findings: &mut Findings) -> Vec<PathBuf> {
	let entries = match fs::read_dir(directory) {
		Ok(entries) => entries,
		Err(error) => {
			findings.add(directory, error);
			return Vec::new();
		}
	};
	let mut records = Vec::new();
	for entry in entries {
		match entry {
			Ok(entry) if entry.path().extension().is_some_and(|ext| ext == "json") => {
				records.push(entry.path())
			}
			Ok(_) => (),
			Err(error) => findings.add(directory, error),
		}
	}
	records.sort_unstable();
	records
}

fn revision(root: &Path) -> io::Result<Revision> {
	let status = git(
		root,
		&["status", "--porcelain=v1", "--untracked-files=normal"],
	)?;
	if !status.stdout.is_empty() {
		return Err(io::Error::other(
			"gate evidence requires a clean tracked checkout",
		));
	}
	let output = git(root, &["rev-parse", "--verify", "HEAD"])?;
	let commit = str::from_utf8(&output.stdout)
		.map_err(io::Error::other)?
		.trim()
		.to_owned();
	if !workspace::is_commit(&commit) {
		return Err(io::Error::other("Git did not return a full commit ID"));
	}
	let lockfile_digest = file_digest(&owned_file(root, Path::new(LOCKFILE))?)?;
	Ok(Revision {
		commit,
		lockfile_digest,
	})
}

fn git(root: &Path, args: &[&str]) -> io::Result<Output> {
	let output = Command::new("git").args(args).current_dir(root).output()?;
	if output.status.success() {
		Ok(output)
	} else {
		Err(io::Error::other(format!(
			"git {} exited with {}",
			args.join(" "),
			output.status
		)))
	}
}

fn matches_digest(
	root: &Path,
	relative: &Path,
	expected: Option<&str>,
	findings: &mut Findings,
) -> bool {
	let path = root.join(relative);
	match owned_file(root, relative).and_then(|path| file_digest(&path)) {
		Ok(actual) if Some(actual.as_str()) == expected => true,
		Ok(_) => {
			findings.add(&path, "SHA-256 digest does not match the evidence record");
			false
		}
		Err(error) => {
			findings.add(&path, error);
			false
		}
	}
}

fn file_digest(path: &Path) -> io::Result<String> {
	let mut hash = Sha256::new();
	io::copy(&mut File::open(path)?, &mut hash)?;
	Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests;
