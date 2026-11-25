use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::finding::Findings;
use crate::{evidence, source, verification, workspace};

const CHECK: &str = "check";
const CHECK_EVIDENCE: &str = "check-evidence";

enum Command {
	Check,
	CheckEvidence(PathBuf),
}

pub(crate) fn run(args: impl Iterator<Item = OsString>) -> ExitCode {
	let args = args.collect::<Vec<_>>();
	let command = match args.as_slice() {
		[command] if command == CHECK => Command::Check,
		[command, directory] if command == CHECK_EVIDENCE => {
			Command::CheckEvidence(directory.into())
		}
		_ => {
			eprintln!(
				"Usage: cargo run --locked -p xtask -- {CHECK} | {CHECK_EVIDENCE} <evidence-dir>"
			);
			return ExitCode::FAILURE;
		}
	};
	let metadata = match workspace::metadata() {
		Ok(metadata) => metadata,
		Err(error) => {
			eprintln!("cannot resolve locked workspace metadata: {error}");
			return ExitCode::FAILURE;
		}
	};
	let mut findings = Findings::default();
	let root = metadata.workspace_root.as_std_path();
	let files = source::files(root, &mut findings);
	workspace::check(&metadata, &files, &mut findings);
	for path in &files {
		source::check(path, &mut findings);
	}
	let projects = verification::check(&metadata, &files, &mut findings);
	if findings.is_empty() {
		match command {
			Command::Check => {
				let gates = projects
					.iter()
					.flat_map(|project| &project.obligations)
					.map(|obligation| obligation.gates.len())
					.sum::<usize>();
				println!("EES-1 workspace, Rust source and EVS-1 obligation structure passed.");
				println!(
					"{gates} declared verification gates require independent execution and evidence. Review main's call graph and domain ownership."
				);
			}
			Command::CheckEvidence(directory) => {
				evidence::check(root, &directory, &projects, &mut findings);
				if findings.is_empty() {
					println!(
						"Current checkout has passing evidence for every declared verification gate."
					);
				}
			}
		}
	}
	if findings.is_empty() {
		ExitCode::SUCCESS
	} else {
		eprint!("{findings}");
		ExitCode::FAILURE
	}
}
