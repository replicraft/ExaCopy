use std::num::NonZeroUsize;
#[cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]
use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;

mod parser;
#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
mod remote;

pub(crate) use parser::parse;
#[cfg(all(target_os = "linux", feature = "experimental-verified-prefix-resume"))]
pub(crate) use remote::RemoteResumeStrategy;
#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
pub(crate) use remote::{
	JobPathDisplay, RemoteCommand, RemoteMetadata, RemoteOptions, RemoteRequest,
};

pub(crate) enum Command {
	Help(String),
	Version,
	Diff(DiffCommand),
	Copy(CopyCommand),
	Plan(PlanCommand),
	SyncPreview(SyncPreviewCommand),
	#[cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]
	SyncManaged(SyncManagedCommand),
	ManifestCreate {
		path: PathBuf,
	},
	Verify(VerifyCommand),
	Recover(RecoveryCommand),
	#[cfg(all(
		target_os = "windows",
		feature = "experimental-windows-bootstrap-inspect"
	))]
	InspectWindowsBootstrap(InspectWindowsBootstrapCommand),
	#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
	InspectApfs(InspectApfsCommand),
	#[cfg(all(target_os = "linux", feature = "experimental-verified-prefix-resume"))]
	RemoteInspectWitness(RemoteInspectWitnessCommand),
	#[cfg(all(target_os = "linux", feature = "experimental-linux-public-apply"))]
	InspectPublicStage(PublicStageInspectCommand),
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

pub(crate) struct SyncPreviewCommand {
	pub(crate) parent: PathBuf,
	pub(crate) roots: [PathBuf; 2],
	pub(crate) subject: PathBuf,
}

#[cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]
pub(crate) enum SyncManagedCommand {
	ProfileIdentity {
		profile: PathBuf,
	},
	Init(ManagedSyncInitArgs),
	Preview {
		profile: PathBuf,
		owner_key: [u8; 32],
		selection: [u8; 16],
	},
	PrepareRecreate(ManagedSyncRecreateArgs),
	ExportRecreate {
		pair_id: [u8; 16],
		command: ManagedSyncRecreateArgs,
	},
}

#[cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]
pub(crate) struct ManagedSyncRecreateArgs {
	pub(crate) profile: PathBuf,
	pub(crate) owner_key: [u8; 32],
	pub(crate) selection: [u8; 16],
	pub(crate) from: exacopy_model::SyncSide,
	pub(crate) reviewed: exacopy_model::SyncConflict,
	pub(crate) expires_in_seconds: Option<NonZeroU32>,
}

#[cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]
pub(crate) struct ManagedSyncInitArgs {
	pub(crate) profile: PathBuf,
	pub(crate) profile_device: u64,
	pub(crate) profile_inode: NonZeroU64,
	pub(crate) owner_key: [u8; 32],
	pub(crate) selection: [u8; 16],
	pub(crate) revision: NonZeroU64,
	pub(crate) approve_request: [u8; 32],
}

pub(crate) struct VerifyCommand {
	pub(crate) path: PathBuf,
	pub(crate) manifest: PathBuf,
	pub(crate) format: Format,
}

#[cfg(all(target_os = "linux", feature = "experimental-linux-public-apply"))]
pub(crate) struct PublicStageInspectCommand {
	pub(crate) job: PathBuf,
	pub(crate) owner_key: [u8; 32],
	pub(crate) format: Format,
}

#[cfg(all(target_os = "linux", feature = "experimental-verified-prefix-resume"))]
pub(crate) struct RemoteInspectWitnessCommand {
	pub(crate) job: PathBuf,
	pub(crate) selection_report: PathBuf,
	pub(crate) destination_qualification: PathBuf,
	pub(crate) qualification_trust: PathBuf,
	pub(crate) continuation_qualification: PathBuf,
	pub(crate) continuation_trust: PathBuf,
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

#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
pub(crate) struct InspectApfsCommand {
	pub(crate) stage_container: PathBuf,
	pub(crate) job: exacopy_platform::macos::staging::jobs::JobName,
	pub(crate) owner_profile: exacopy_journal::OwnerProfileId,
	pub(crate) owner_key: [u8; 32],
	pub(crate) destination_root: exacopy_journal::RootCapabilityId,
	pub(crate) format: Format,
}

#[cfg(all(
	target_os = "windows",
	feature = "experimental-windows-bootstrap-inspect"
))]
pub(crate) struct InspectWindowsBootstrapCommand {
	pub(crate) root: PathBuf,
	pub(crate) root_identity: exacopy_journal::windows_bootstrap::WindowsBootstrapFileIdentity,
	pub(crate) profile: exacopy_journal::OwnerProfileId,
	pub(crate) owner_key: [u8; 32],
	pub(crate) job: exacopy_journal::JournalJobId,
}
