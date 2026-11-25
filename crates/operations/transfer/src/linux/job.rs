use std::error::Error;
use std::fmt;
use std::io::Write as _;

use ed25519_dalek::SigningKey;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DestinationRootBinding, DurableJournal, DurableJournalError, JobPrepared, JournalContext,
	LinuxFileIdentity, OwnerError, OwnerManifest, OwnerProfileId, OwnerRecord, OwnerStateDirectory,
	OwnerTimestamp, OwnerToken, RootCapabilityId, SyncedFrame,
};
use exacopy_platform::linux::{
	DestinationRoot, FileIdentity, JobDirectory, StageDirectory, StageError,
};

/// Inputs supplied by the caller from its authorized destination and trusted local profile.
#[derive(Debug, Clone, Copy)]
pub struct JobBootstrap<'name> {
	/// The freshly allocated private job directory name authorized by the caller.
	pub name: UnixComponent<'name>,
	/// The trusted job, run, and canonical plan binding.
	pub context: JournalContext,
	/// The capability UUID for the held destination root.
	pub destination_id: RootCapabilityId,
	/// The local profile whose independently trusted key signs ownership.
	pub profile: OwnerProfileId,
	/// The recorded creation time.
	pub created: OwnerTimestamp,
	/// A fresh independent cryptographic token allocated by the caller for this job.
	pub owner_token: OwnerToken,
}

/// A private job root with a signed owner record and the first synchronized journal frame.
///
/// The caller owns profile key custody and must allocate unique names and tokens. The
/// bootstrap writes no copy payload and issues no publication authorization.
#[derive(Debug)]
pub struct PreparedJob<'root> {
	directory: JobDirectory<'root>,
	owner: OwnerRecord,
	initial_frame: SyncedFrame,
}

impl<'root> PreparedJob<'root> {
	/// Creates an exclusive private job here and persists its ownership and preparation frame.
	///
	/// A full file barrier precedes the directory barriers for the owner record. The first
	/// segment entry and its enclosing directories are synchronized before the preparation
	/// frame is written and synchronized. This records completed Linux barrier calls.
	///
	/// # Errors
	/// Stops on a naming conflict, invalid ownership evidence, or any I/O or journal failure.
	/// Created entries remain for later inspection and are never adopted on retry.
	pub fn create(
		destination: &'root DestinationRoot,
		request: JobBootstrap<'_>,
		signer: &SigningKey,
	) -> Result<Self, JobBootstrapError> {
		if request.owner_token.as_bytes() == request.context.job.as_bytes()
			|| request.owner_token.as_bytes() == request.profile.as_bytes()
		{
			return Err(JobBootstrapError::Owner(OwnerError::InvalidToken));
		}
		let destination_identity = native_identity(destination.identity());
		let directory = destination
			.create_job_directory(request.name)
			.map_err(JobStep::CreateJob.error())?;
		let owner = OwnerRecord::sign(
			OwnerManifest {
				token: request.owner_token,
				job: request.context.job,
				profile: request.profile,
				created: request.created,
				destination_device: destination_identity.device(),
				state_root: native_identity(directory.identity()),
				plan_digest: request.context.plan_digest,
				directories: vec![OwnerStateDirectory::Journal, OwnerStateDirectory::Stage],
			},
			signer,
		)
		.map_err(JobBootstrapError::Owner)?;
		let mut record = directory
			.create_owner_record()
			.map_err(JobStep::CreateOwner.error())?;
		record
			.write_all(owner.as_bytes())
			.map_err(JobBootstrapError::WriteOwner)?;
		record.sync_all().map_err(JobBootstrapError::SyncOwner)?;
		drop(record);

		let journal_directory = directory
			.create_journal_directory()
			.map_err(JobStep::CreateJournal.error())?;
		let segment = journal_directory
			.create_first_segment()
			.map_err(JobStep::CreateSegment.error())?;
		let mut journal =
			DurableJournal::from_new_file(segment).map_err(JobBootstrapError::Journal)?;
		journal_directory
			.sync_directory()
			.map_err(JobStep::SyncJournal.error())?;
		directory
			.sync_directory()
			.map_err(JobStep::SyncJob.error())?;
		destination
			.sync_directory()
			.map_err(JobStep::SyncDestination.error())?;

		let initial = JobPrepared {
			context: request.context,
			owner_digest: owner.digest(),
			destination_root: DestinationRootBinding {
				id: request.destination_id,
				identity: destination_identity,
			},
		};
		let initial_frame = journal
			.append(FrameKind::JobPrepared, &initial.encode())
			.map_err(JobBootstrapError::Journal)?;
		Ok(Self {
			directory,
			owner,
			initial_frame,
		})
	}

	/// Returns the exact signed owner record written to this job's private root.
	#[must_use]
	pub const fn owner(&self) -> &OwnerRecord {
		&self.owner
	}

	/// Returns the file-barrier evidence for the initial preparation record.
	#[must_use]
	pub const fn initial_frame(&self) -> &SyncedFrame {
		&self.initial_frame
	}

	/// Exclusively creates the owner-approved stage directory for this job.
	///
	/// # Errors
	/// Reports a creation collision, changed identity, or failure to synchronize the entry.
	pub fn create_stage_directory(&self) -> Result<StageDirectory<'_>, StageError> {
		let stage = self.directory.create_stage_directory()?;
		self.directory.sync_directory()?;
		Ok(stage)
	}
}

fn native_identity(identity: FileIdentity) -> LinuxFileIdentity {
	LinuxFileIdentity::new(identity.device(), identity.inode())
}

/// An attempted namespace operation during private job bootstrap.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum JobStep {
	/// Exclusive job root creation.
	CreateJob,
	/// Exclusive signed owner file creation.
	CreateOwner,
	/// Exclusive journal directory creation.
	CreateJournal,
	/// Exclusive first segment creation.
	CreateSegment,
	/// Synchronization of the directory holding the segment entry.
	SyncJournal,
	/// Synchronization of the private job root.
	SyncJob,
	/// Synchronization of the destination directory holding the job entry.
	SyncDestination,
}

impl JobStep {
	fn error(self) -> impl FnOnce(StageError) -> JobBootstrapError {
		move |source| JobBootstrapError::Platform { step: self, source }
	}
}

/// A failed job bootstrap leaves any created private entries for inspection.
#[derive(Debug)]
#[non_exhaustive]
pub enum JobBootstrapError {
	/// A held directory operation failed.
	Platform {
		/// The attempted namespace operation.
		step: JobStep,
		/// The adapter's cause.
		source: StageError,
	},
	/// Signing or validating the bounded owner manifest failed.
	Owner(OwnerError),
	/// Complete writing of the owner record failed.
	WriteOwner(std::io::Error),
	/// The owner file barrier failed.
	SyncOwner(std::io::Error),
	/// Preparing or synchronizing the first journal frame failed.
	Journal(DurableJournalError),
}

impl fmt::Display for JobBootstrapError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Platform { step, source } => write!(
				formatter,
				"job namespace operation {step:?} failed ({source})"
			),
			Self::Owner(error) => write!(formatter, "job owner evidence failed ({error})"),
			Self::WriteOwner(error) => write!(
				formatter,
				"writing the private owner record failed ({error})"
			),
			Self::SyncOwner(error) => write!(
				formatter,
				"synchronizing the private owner record failed ({error})"
			),
			Self::Journal(error) => write!(formatter, "initial job journal failed ({error})"),
		}
	}
}

impl Error for JobBootstrapError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Platform { source, .. } => Some(source),
			Self::Owner(error) => Some(error),
			Self::WriteOwner(error) | Self::SyncOwner(error) => Some(error),
			Self::Journal(error) => Some(error),
		}
	}
}
