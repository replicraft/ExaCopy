use std::num::NonZeroUsize;
use std::path::PathBuf;

mod parser;
#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
mod remote;

pub(crate) use parser::parse;
#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
pub(crate) use remote::{RemoteCommand, RemoteMetadata, RemoteOptions, RemoteRequest};

pub(crate) enum Command {
	Help(String),
	Version,
	Diff(DiffCommand),
	Copy(CopyCommand),
	Plan(PlanCommand),
	ManifestCreate {
		path: PathBuf,
	},
	Verify(VerifyCommand),
	Recover(RecoveryCommand),
	#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
	Remote(RemoteCommand),
	InitProfile(PathBuf),
}

pub(crate) struct DiffCommand {
	pub(crate) left: PathBuf,
	pub(crate) right: PathBuf,
	pub(crate) workers: Option<NonZeroUsize>,
	pub(crate) profile: DiffProfile,
	pub(crate) format: Format,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiffProfile {
	Default,
	ManagedMacos,
	LocalNtfs,
}

pub(crate) struct CopyCommand {
	pub(crate) source: PathBuf,
	pub(crate) target: PathBuf,
	pub(crate) profile: PathBuf,
	pub(crate) format: Format,
}

pub(crate) struct PlanCommand {
	pub(crate) source: PathBuf,
	pub(crate) destination: PathBuf,
	pub(crate) profile: PathBuf,
	pub(crate) output: PathBuf,
}

pub(crate) struct VerifyCommand {
	pub(crate) path: PathBuf,
	pub(crate) manifest: PathBuf,
	pub(crate) format: Format,
}

pub(crate) struct RecoveryCommand {
	pub(crate) action: RecoveryAction,
	pub(crate) job: PathBuf,
	pub(crate) profile: PathBuf,
	pub(crate) format: Format,
}

pub(crate) enum RecoveryAction {
	Inspect,
	Finish,
	FromSource {
		action: SourceRecoveryAction,
		source_root: PathBuf,
	},
}

#[derive(Clone, Copy)]
pub(crate) enum SourceRecoveryAction {
	Retry,
	Resume,
}

#[derive(Clone, Copy)]
pub(crate) enum Format {
	Human,
	Json,
}
