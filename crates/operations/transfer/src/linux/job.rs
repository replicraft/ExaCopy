use std::error::Error;
use std::fmt;
use std::fs::File;

use ed25519_dalek::SigningKey;
use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_copy::CopyWorkspace;
use exacopy_endpoint::linux_job::{JobBootstrapRoot, JobWorkspace};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurableJournal, DurableJournalError, JobPrepared, JournalContext, OwnerError, OwnerProfileId,
	OwnerRecord, OwnerTimestamp, OwnerToken, RootCapabilityId, SyncedFrame,
};

use super::LocalCopyPlan;
use protocol::{BootstrapFailure, InitialJournal};

mod protocol;

#[cfg(test)]
mod tests;

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
pub struct PreparedJob<D> {
	directory: D,
	owner: OwnerRecord,
	initial_frame: SyncedFrame,
}

impl<D: JobWorkspace<Segment = File>> PreparedJob<D> {
	/// Creates an exclusive private job here and persists its ownership and preparation frame.
	///
	/// A full file barrier precedes the directory barriers for the owner record. The first
	/// segment entry and its enclosing directories are synchronized before the preparation
	/// frame is written and synchronized. This records completed Linux barrier calls.
	///
	/// # Errors
	/// Stops on a naming conflict, invalid ownership evidence, or any I/O or journal failure.
	/// Created entries remain for later inspection and are never adopted on retry.
	pub fn create<'root, R>(
		destination: &'root R,
		request: JobBootstrap<'_>,
		signer: &SigningKey,
	) -> Result<Self, BootstrapError<D::Error>>
	where
		R: JobBootstrapRoot<'root, Job = D, Error = D::Error>,
	{
		let prepared = protocol::prepare::<_, DurableJournal>(destination, request, signer, None)?;
		Ok(Self {
			directory: prepared.directory,
			owner: prepared.owner,
			initial_frame: prepared.initial_frame,
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
	pub fn create_stage_directory(&self) -> Result<D::Stage<'_>, <D as JobWorkspace>::Error>
	where
		D: CopyWorkspace,
	{
		let stage = self.directory.create_stage_directory()?;
		JobWorkspace::sync_directory(&self.directory)?;
		Ok(stage)
	}
}

pub(super) fn prepare_durable_copy<'root, Root>(
	destination: &'root Root,
	plan: &LocalCopyPlan<'_>,
	profile: super::CopyProfile<'_>,
) -> Result<(Root::Job, DurableJournal), BootstrapError<Root::Error>>
where
	Root: JobBootstrapRoot<'root, Job: JobWorkspace<Segment = File>>,
{
	let request = JobBootstrap {
		name: plan.attempt().job_name,
		context: plan.context(),
		destination_id: plan.destination().root.id,
		profile: profile.id,
		created: profile.created,
		owner_token: profile.owner_token,
	};
	let prepared = protocol::prepare::<_, DurableJournal>(
		destination,
		request,
		profile.signer,
		Some(&plan.encode()),
	)?;
	Ok((prepared.directory, prepared.journal))
}

/// An attempted namespace operation during private job bootstrap.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum JobStep {
	/// Exclusive job root creation.
	CreateJob,
	/// Exclusive signed owner file creation.
	CreateOwner,
	/// Exclusive canonical copy plan creation.
	CreatePlan,
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

/// A failed job bootstrap leaves any created private entries for inspection.
#[derive(Debug)]
#[non_exhaustive]
pub enum BootstrapError<S> {
	/// A held directory operation failed.
	Platform {
		/// The attempted namespace operation.
		step: JobStep,
		/// The adapter's cause.
		source: S,
	},
	/// Signing or validating the bounded owner manifest failed.
	Owner(OwnerError),
	/// Complete writing of the owner record failed.
	WriteOwner(std::io::Error),
	/// The owner file barrier failed.
	SyncOwner(std::io::Error),
	/// Writing the canonical copy plan failed.
	WritePlan(std::io::Error),
	/// The canonical copy plan barrier failed.
	SyncPlan(std::io::Error),
	/// Preparing or synchronizing the first journal frame failed.
	Journal(DurableJournalError),
}

impl<S: fmt::Display> fmt::Display for BootstrapError<S> {
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
			Self::WritePlan(error) => {
				write!(formatter, "writing the private copy plan failed ({error})")
			}
			Self::SyncPlan(error) => write!(
				formatter,
				"synchronizing the private copy plan failed ({error})"
			),
			Self::Journal(error) => write!(formatter, "initial job journal failed ({error})"),
		}
	}
}

impl<S: Error + 'static> Error for BootstrapError<S> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Platform { source, .. } => Some(source),
			Self::Owner(error) => Some(error),
			Self::WriteOwner(error)
			| Self::SyncOwner(error)
			| Self::WritePlan(error)
			| Self::SyncPlan(error) => Some(error),
			Self::Journal(error) => Some(error),
		}
	}
}

impl InitialJournal for DurableJournal {
	type Segment = File;
	type Error = DurableJournalError;
	type Frame = SyncedFrame;

	fn from_new_segment(segment: File) -> Result<Self, Self::Error> {
		Self::from_new_file(segment)
	}

	fn append_job_prepared(
		&mut self,
		preparation: JobPrepared,
	) -> Result<Self::Frame, Self::Error> {
		self.append(FrameKind::JobPrepared, &preparation.encode())
	}
}

impl<S> From<BootstrapFailure<S, DurableJournalError>> for BootstrapError<S> {
	fn from(error: BootstrapFailure<S, DurableJournalError>) -> Self {
		match error {
			BootstrapFailure::Namespace(step, source) => Self::Platform { step, source },
			BootstrapFailure::Owner(source) => Self::Owner(source),
			BootstrapFailure::WriteOwner(source) => Self::WriteOwner(source),
			BootstrapFailure::SyncOwner(source) => Self::SyncOwner(source),
			BootstrapFailure::WritePlan(source) => Self::WritePlan(source),
			BootstrapFailure::SyncPlan(source) => Self::SyncPlan(source),
			BootstrapFailure::Journal(source) => Self::Journal(source),
		}
	}
}
