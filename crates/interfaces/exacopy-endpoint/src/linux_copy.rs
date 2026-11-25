//! Observations needed to plan and revalidate the Linux single-file copy profile.

use exacopy_model::PublishNoClobber;

use crate::UnixComponent;
use crate::linux_job::{JobFileIdentity, JobWorkspace};
use crate::linux_publication::{PublicationFailure, ReceiptWorkspace};
use crate::linux_staging::{SourceMetadata, StageWriter, StagingDirectory, StagingSource};

/// A captured Linux timestamp as reported by the platform.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct InodeTimestamp {
	/// Seconds relative to the Unix epoch.
	pub seconds: i64,
	/// Nanoseconds within the second, validated by the consuming record contract.
	pub nanoseconds: u32,
}

/// Captured metadata of the same held regular file used for staging.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CopySourceObservation {
	/// Source mode bits.
	pub mode: u32,
	/// Owner UID in the current user namespace.
	pub owner: u32,
	/// Owner GID in the current user namespace.
	pub group: u32,
	/// Number of links to this same inode.
	pub links: u64,
	/// Access time captured before adapter data reads.
	pub accessed_at: InodeTimestamp,
	/// Captured content modification time.
	pub modified_at: InodeTimestamp,
	/// Captured inode change time.
	pub changed_at: InodeTimestamp,
}

/// Read-only selection beneath a held source directory.
pub trait CopySourceRoot {
	/// The error from opening or observing a source file.
	type Error;

	/// The opened file and the observations captured through its read-only handle.
	type Source: CopySource<Error = Self::Error>;

	/// Returns the held source root's observed identity.
	fn identity(&self) -> JobFileIdentity;

	/// Opens the named regular file under this root and pins the object read-only.
	/// # Errors
	/// Fails if the file is unsafe, unsupported, or cannot be opened and observed.
	fn open_regular(&self, name: UnixComponent<'_>) -> Result<Self::Source, Self::Error>;
}

/// A stageable source with the captured inode observations needed for planning.
pub trait CopySource: StagingSource<Identity: Into<JobFileIdentity>> {
	/// Reports the original observations bound to the held file.
	fn copy_observation(&self) -> CopySourceObservation;
}

/// The result of observing a destination component without modifying it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TargetObservation {
	/// The component was absent at the instant of the observation.
	Absent,
	/// Some other object already occupied the component.
	Occupied,
}

/// Read-only observations of the intended destination namespace.
pub trait CopyDestinationView {
	/// The exact adapter error from target lookup.
	type Error;

	/// Returns the held destination root's observed device and inode.
	fn identity(&self) -> JobFileIdentity;

	/// Observes the selected target beneath the held root without following links.
	/// # Errors
	/// Fails if the held directory identity or the selected name cannot be checked.
	fn observe_target(&self, target: UnixComponent<'_>) -> Result<TargetObservation, Self::Error>;
}

/// The independently named stage and checkpoint directories of a prepared job.
pub trait CopyWorkspace:
	JobWorkspace + ReceiptWorkspace<Error = <Self as JobWorkspace>::Error>
{
	/// The native identity shared by the source and the stage.
	type Identity: Copy + Eq + Into<JobFileIdentity>;

	/// The captured source metadata type accepted by the stage.
	type Metadata: SourceMetadata;

	/// The native exclusive-publication error.
	type PublishError;

	/// A private stage directory borrowing this held job.
	type Stage<'job>: PublishableStageDirectory<
			Error = <Self as JobWorkspace>::Error,
			Identity = Self::Identity,
			Metadata = Self::Metadata,
			PublishError = Self::PublishError,
		>
	where
		Self: 'job;

	/// A private directory for immutable range checkpoint pages.
	type Checkpoints<'job>: CheckpointPages<Error = <Self as JobWorkspace>::Error>
	where
		Self: 'job;

	/// Exclusively creates the owned stage directory, without claiming synchronization.
	/// # Errors
	/// Fails if exclusive creation or the job identity cannot be confirmed.
	fn create_stage_directory(&self) -> Result<Self::Stage<'_>, <Self as JobWorkspace>::Error>;

	/// Exclusively creates the owned checkpoint directory, without claiming synchronization.
	/// # Errors
	/// Fails if exclusive creation or the job identity cannot be confirmed.
	fn create_checkpoint_directory(
		&self,
	) -> Result<Self::Checkpoints<'_>, <Self as JobWorkspace>::Error>;
}

/// A directory whose closed reader can consume a one-use publication authorization.
pub trait PublishableStageDirectory: StagingDirectory {
	/// The exact native exclusive-publication failure.
	type PublishError;

	/// Returns the held stage directory's identity.
	fn identity(&self) -> JobFileIdentity;

	/// Attempts the exclusive namespace operation for the closed stage and its exact permit.
	/// # Errors
	/// Returns the conflict or uncertainty classification with the original cause.
	fn publish<'stage>(
		&'stage self,
		stage: <Self::Writer<'stage> as StageWriter>::Reader,
		authorization: PublishNoClobber,
	) -> Result<(), PublicationFailure<Self::PublishError>>
	where
		Self: 'stage;
}

/// A held private directory accepting exclusive, immutable range checkpoint records.
pub trait CheckpointPages {
	/// The exact adapter failure when creating or synchronizing the page.
	type Error;

	/// Exclusively creates the bounded page and synchronizes file and directory.
	/// # Errors
	/// Fails on existing pages, changed identity, or incomplete writes or barriers.
	fn persist_page(&self, ordinal: u32, bytes: &[u8]) -> Result<(), Self::Error>;
}
