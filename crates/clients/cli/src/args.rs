use std::num::NonZeroUsize;
use std::path::PathBuf;

mod parser;

pub(crate) use parser::parse;

pub(crate) enum Command {
	Help(String),
	Diff(DiffCommand),
	Copy(CopyCommand),
	Recover(RecoveryCommand),
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
}

pub(crate) struct CopyCommand {
	pub(crate) source: PathBuf,
	pub(crate) target: PathBuf,
	pub(crate) profile: PathBuf,
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
