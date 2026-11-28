//! Opt-in effect and observation capabilities for one checked Linux public copy.

use std::io;

use exacopy_model::{CopyBinding, PublishNoClobber};

use crate::UnixComponent;
use crate::linux_copy::{
	CheckpointPages, CopySourceRoot, CopyWorkspace, PublishableStageDirectory,
};
use crate::linux_job::{JobBootstrapRoot, JobFileIdentity, JobJournalDirectory, JobWorkspace};
use crate::linux_publication::{FreshReceiptError, FreshReceiptWorkspace};
use crate::linux_staging::{SourceMetadata, StageReader, StageWriter};

/// A fixed private or parent namespace role in the selected invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyRole {
	/// The exclusive private job directory.
	Job,
	/// The signed owner artifact.
	Owner,
	/// The canonical private Plan artifact.
	PrivatePlan,
	/// The journal directory.
	JournalDirectory,
	/// The freshly allocated first journal segment.
	FirstSegment,
	/// The private stage directory.
	StageDirectory,
	/// The private stage file.
	Stage,
	/// The private checkpoint directory.
	CheckpointDirectory,
	/// An immutable range page at its allocated ordinal.
	CheckpointPage(u32),
	/// The private receipt directory.
	ReceiptDirectory,
	/// The canonical private receipt artifact.
	Receipt,
	/// The held destination directory.
	Destination,
}

/// A journal phase chosen by the engine from the actual record being appended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyRecord {
	/// JobPrepared.
	Prepared,
	/// EntryPrepared.
	Entry,
	/// RangeCheckpoint.
	Range,
	/// StageSealed.
	Seal,
	/// VerificationRecorded.
	Verification,
	/// MetadataRecorded.
	Metadata,
	/// The mandatory v2 PublishIntent.
	Intent,
	/// PublishObserved.
	Observation,
	/// DurabilityRecorded.
	Durability,
	/// ReceiptCommitted.
	ReceiptCommit,
}

/// A checked, bounded private effect in the already selected invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyStep {
	/// Exclusive creation of the supplied role.
	Create(ApplyRole),
	/// Writes inside one validated window, including any actual partial-write retries.
	Write(ApplyRole, u64, usize),
	/// Sets the exact stage extent.
	SetStageExtent(u64),
	/// Sets the checked ordinary mode.
	SetStagePermissions,
	/// Sets the checked access and modification times.
	SetStageTimes,
	/// A barrier on this role.
	Sync(ApplyRole),
	/// One journal append and its barrier.
	Append(ApplyRecord),
}

/// Application-owned authority for a scoped synchronous mutation.
/// Each implementation must keep revocation serialized through its returned guard.
pub trait LocalApplyAdmission {
	/// A linear admission guard dropped when the started operation returns.
	type Guard<'gate>
	where
		Self: 'gate;

	/// Revalidates current scope and authority immediately before a bounded effect.
	/// # Errors
	/// A refusal prevents the selected mutation.
	fn enter(&self, step: ApplyStep) -> io::Result<Self::Guard<'_>>;
}

/// A source root able to verify an exact name against the original read handle.
pub trait ExactSourceRoot: CopySourceRoot {
	/// Rechecks the selected raw name and original held source without reopening its data.
	/// # Errors
	/// Refuses a changed, rebound or unavailable source.
	fn recheck_exact_regular_name(
		&self,
		name: UnixComponent<'_>,
		source: &Self::Source,
	) -> Result<(), Self::Error>;
}

/// Guarded bootstrap operations on the actual destination root.
pub trait GuardedJobRoot<'root>: JobBootstrapRoot<'root> {
	/// Exact native refusal or uncertain job creation.
	type CreateError;

	/// Enters authority immediately before creating the original private job.
	/// # Errors
	/// Preserves the native creation outcome and leaves all created entries.
	fn create_job_admitted(
		&'root self,
		name: UnixComponent<'_>,
		admission: &impl LocalApplyAdmission,
	) -> Result<Self::Job, Self::CreateError>;

	/// Synchronizes the selected held destination with fresh authority.
	/// # Errors
	/// Refuses unsafe state, inactive authority, or a barrier failure.
	fn sync_destination_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<(), Self::Error>;
}

/// The only bootstrap records that can be sealed within the original job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyJobRecord {
	/// The signed owner.
	Owner,
	/// The canonical private Plan.
	PrivatePlan,
}

/// Read-only custody of a record created inside the original leased job.
pub trait HeldJobRecord<Job: ?Sized> {
	/// Exact cause of failing to observe the retained record.
	type Error;

	/// Reads exactly the original same-inode record and requires EOF.
	/// # Errors
	/// Refuses name, inode, captured evidence, extent or custody changes.
	fn read_exact_job_record(&self, job: &Job, output: &mut [u8]) -> Result<(), Self::Error>;
}

/// Guarded effect capabilities held alongside the original job lease.
pub trait GuardedCopyJob:
	CopyWorkspace + FreshReceiptWorkspace<Error = <Self as JobWorkspace>::Error>
{
	/// An owned read-only pin from the actual creation descriptor.
	type HeldRecord: HeldJobRecord<Self, Error = <Self as JobWorkspace>::Error>;

	/// Exact native checked-publication failure, independent of a stage borrow.
	type CheckedPublishError;

	/// The original journal directory with checked capabilities.
	type CheckedJournal<'job>: GuardedJournalDirectory<Error = <Self as JobWorkspace>::Error, Segment = Self::Segment>
	where
		Self: 'job;

	/// The original stage directory with checked capabilities.
	type CheckedStage<'job>: GuardedStageDirectory<
			Error = <Self as JobWorkspace>::Error,
			Identity = Self::Identity,
			Metadata = Self::Metadata,
			PublishError = Self::PublishError,
			CheckedPublishError = Self::CheckedPublishError,
		>
	where
		Self: 'job;

	/// The original checkpoint directory with checked capabilities.
	type CheckedCheckpoints<'job>: GuardedCheckpointPages<Error = <Self as JobWorkspace>::Error>
	where
		Self: 'job;

	/// Seals one exact private record using separately admitted creation, write and sync.
	/// # Errors
	/// Refuses authority, custody, size or I/O failures, preserving any private entry.
	fn seal_job_record(
		&self,
		role: ApplyJobRecord,
		bytes: &[u8],
		admission: &impl LocalApplyAdmission,
	) -> Result<Self::HeldRecord, <Self as JobWorkspace>::Error>;

	/// Creates the original journal directory under a fresh guard.
	/// # Errors
	/// Refuses lost authority, an unsafe directory or failed creation.
	fn create_journal_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<Self::CheckedJournal<'_>, <Self as JobWorkspace>::Error>;

	/// Creates the original staging directory under a fresh guard.
	/// # Errors
	/// Refuses lost authority, an unsafe directory or failed creation.
	fn create_stage_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<Self::CheckedStage<'_>, <Self as JobWorkspace>::Error>;

	/// Creates the original checkpoints directory under a fresh guard.
	/// # Errors
	/// Refuses lost authority, an unsafe directory or failed creation.
	fn create_checkpoints_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<Self::CheckedCheckpoints<'_>, <Self as JobWorkspace>::Error>;

	/// Synchronizes the original job directory under a fresh guard.
	/// # Errors
	/// Refuses lost authority, an unsafe directory or a barrier failure.
	fn sync_job_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<(), <Self as JobWorkspace>::Error>;

	/// Seals one checked receipt with separately guarded mutations and barriers.
	/// # Errors
	/// Refuses unsafe state, lost authority, extent or I/O failures.
	fn seal_fresh_receipt_admitted(
		&self,
		bytes: &[u8],
		admission: &impl LocalApplyAdmission,
	) -> Result<Self::HeldReceipt<'_>, FreshReceiptError<<Self as JobWorkspace>::Error>>;
}

/// Guarded operations on the original first journal directory.
pub trait GuardedJournalDirectory: JobJournalDirectory {
	/// Allocates the exact first segment under a fresh guard.
	/// # Errors
	/// Refuses change, lost authority or failed creation.
	fn create_first_segment_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<Self::Segment, Self::Error>;

	/// Synchronizes the original journal directory under a fresh guard.
	/// # Errors
	/// Refuses change, lost authority or a barrier failure.
	fn sync_journal_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<(), Self::Error>;
}

/// Guarded staging operations that retain the ordinary holder and writer types.
pub trait GuardedStageDirectory: PublishableStageDirectory {
	/// Exact native checked-publication failure.
	type CheckedPublishError;

	/// The original exclusive writer, with guarded effects.
	type CheckedWriter<'stage>: GuardedStageWriter<
			CheckedPublishError = Self::CheckedPublishError,
			Error = Self::Error,
			Identity = Self::Identity,
			Metadata = Self::Metadata,
		>
	where
		Self: 'stage;

	/// Exclusively creates the stage under a fresh guard.
	/// # Errors
	/// Refuses lost authority, an unsafe directory or failed creation.
	fn create_file_admitted(
		&self,
		name: UnixComponent<'_>,
		target: UnixComponent<'_>,
		binding: CopyBinding,
		admission: &impl LocalApplyAdmission,
	) -> Result<Self::CheckedWriter<'_>, Self::Error>;

	/// Synchronizes the original staging directory under a fresh guard.
	/// # Errors
	/// Refuses lost authority, an unsafe directory or a barrier failure.
	fn sync_stage_admitted(&self, admission: &impl LocalApplyAdmission) -> Result<(), Self::Error>;
}

/// Guarded operations on the exclusive stage data writer.
pub trait GuardedStageWriter:
	StageWriter<Reader: GuardedStageReader + CheckedPublication<Error = Self::CheckedPublishError>>
{
	/// Exact native checked-publication failure.
	type CheckedPublishError;

	/// Writes only within this admitted window, reacquiring before each actual write.
	/// # Errors
	/// Refuses invalid extent, changed state, lost authority or a write failure.
	fn write_window_admitted(
		&mut self,
		offset: u64,
		bytes: &[u8],
		admission: &impl LocalApplyAdmission,
	) -> Result<(), Self::Error>;

	/// Sets the exact stage extent under a fresh guard.
	/// # Errors
	/// Refuses invalid extent, changed state, lost authority or a resize failure.
	fn set_len_admitted(
		&mut self,
		length: u64,
		admission: &impl LocalApplyAdmission,
	) -> Result<(), Self::Error>;

	/// Synchronizes the stage data under a fresh guard.
	/// # Errors
	/// Refuses changed state, lost authority or a barrier failure.
	fn flush_stage_admitted(
		&mut self,
		admission: &impl LocalApplyAdmission,
	) -> Result<(), Self::Error>;
}

/// Guarded metadata and barrier capabilities for the original closed stage.
pub trait GuardedStageReader: StageReader {
	/// Applies required metadata with separate admission at each mutation and barrier.
	/// # Errors
	/// Refuses unsafe metadata, changed state, lost authority or an effect failure.
	fn apply_metadata_admitted(
		self,
		metadata: Self::Metadata,
		accessed_at: <Self::Metadata as SourceMetadata>::Timestamp,
		admission: &impl LocalApplyAdmission,
	) -> Result<Self, Self::Error>;

	/// Synchronizes the stage's parent under a fresh guard.
	/// # Errors
	/// Refuses changed state, lost authority or a barrier failure.
	fn seal_stage_admitted(&self, admission: &impl LocalApplyAdmission) -> Result<(), Self::Error>;
}

/// Guarded immutable checkpoint page persistence.
pub trait GuardedCheckpointPages: CheckpointPages {
	/// Guards the fixed page creation, bounded writes, and both barriers separately.
	/// # Errors
	/// Refuses an invalid page, lost authority, changed state or failed I/O.
	fn persist_page_admitted(
		&self,
		ordinal: u32,
		bytes: &[u8],
		admission: &impl LocalApplyAdmission,
	) -> Result<(), Self::Error>;
}

/// Native facts established on the original stage just before final admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRenameFacts<'name> {
	/// Binding of the original stage and model permit.
	pub binding: CopyBinding,
	/// Exact original staged inode.
	pub stage: JobFileIdentity,
	/// Original stage directory.
	pub stage_directory: JobFileIdentity,
	/// Original held destination parent.
	pub destination: JobFileIdentity,
	/// Exact selected target component.
	pub target: UnixComponent<'name>,
}

/// Checked observation of the renamed file and both synchronized directories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedFacts {
	/// The original stage inode now observed under the exact target name.
	pub target: JobFileIdentity,
	/// The original staging directory whose barrier completed.
	pub stage_directory: JobFileIdentity,
	/// The original destination directory whose barrier completed.
	pub destination: JobFileIdentity,
}

/// Read-only custody of the original file after exclusive publication.
pub trait HeldCheckedPublication {
	/// Exact native observation failure.
	type Error;

	/// Rechecks the original held published inode, metadata and both names.
	/// # Errors
	/// Refuses a changed inode, metadata, namespace or original directory.
	fn recheck_published(&self) -> Result<PublishedFacts, Self::Error>;
}

/// An explicit held-stage rename and settlement failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum CheckedRenameFailure<Native, Refusal> {
	/// Native readiness refused before syscall submission.
	Preflight(Native),
	/// The coordinator's final readiness checks refused before submission.
	Refused(Refusal),
	/// Final effect admission refused before submission.
	Admission(io::Error),
	/// Kernel no-replace conflict, without claiming a public result.
	Conflict(Native),
	/// Definite kernel refusal without the attempted namespace effect.
	NotPerformed(Native),
	/// The submitted syscall result is uncertain even if subsequent checks pass.
	Uncertain {
		/// Original native effect error.
		cause: Native,
		/// Optional observed namespace or metadata failure.
		observation: Option<Native>,
		/// Optional stage, destination or both barrier failures.
		barriers: Option<Native>,
	},
	/// The syscall acknowledged publication but verification or persistence failed.
	PublishedIncomplete {
		/// Optional observed namespace or metadata failure.
		observation: Option<Native>,
		/// Optional stage, destination or both barrier failures.
		barriers: Option<Native>,
	},
}

/// Checked preserve-mode exclusive publication of the original closed stage.
pub trait CheckedPublication: Sized {
	/// Exact native effect or observation error.
	type Error;
	/// The original pinned file after checked publication.
	type Held: HeldCheckedPublication<Error = Self::Error>;

	/// Prepares the native rename, runs final readiness, then enters the immediate syscall.
	/// Drops its rename guard before settlement. After acknowledged success or ambiguous
	/// submission, checks the original names and attempts both original-directory
	/// barriers independently. It never repeats or compensates the rename.
	/// # Errors
	/// Reports pre-effect refusal, conflict, uncertainty or incomplete settlement.
	fn publish_checked<Fence, Refusal, Guard>(
		self,
		permit: PublishNoClobber,
		final_check: impl FnOnce() -> Result<Fence, Refusal>,
		enter: impl FnOnce(Fence, NativeRenameFacts<'_>) -> io::Result<Guard>,
	) -> Result<Self::Held, CheckedRenameFailure<Self::Error, Refusal>>;
}
