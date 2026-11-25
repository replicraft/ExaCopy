use std::io::{self, Write as _};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::linux_job::{
	JobBootstrapRoot, JobFileIdentity, JobJournalDirectory, JobRecord, JobWorkspace,
};
use exacopy_journal::{
	DestinationRootBinding, JobPrepared, LinuxFileIdentity, OwnerError, OwnerManifest, OwnerRecord,
	OwnerStateDirectory,
};

use super::{JobBootstrap, JobStep};

/// Admits an exclusively created first segment and provides synchronized append evidence.
pub(super) trait InitialJournal: Sized {
	type Segment;
	type Error;
	type Frame;

	fn from_new_segment(segment: Self::Segment) -> Result<Self, Self::Error>;
	fn append_job_prepared(&mut self, preparation: JobPrepared)
	-> Result<Self::Frame, Self::Error>;
}

pub(super) struct Prepared<Directory, Journal, Frame> {
	pub(super) directory: Directory,
	pub(super) owner: OwnerRecord,
	pub(super) journal: Journal,
	pub(super) initial_frame: Frame,
}

#[derive(Debug)]
pub(super) enum BootstrapFailure<NamespaceError, JournalError> {
	Namespace(JobStep, NamespaceError),
	Owner(OwnerError),
	WriteOwner(io::Error),
	SyncOwner(io::Error),
	WritePlan(io::Error),
	SyncPlan(io::Error),
	Journal(JournalError),
}

impl JobStep {
	fn failure<NamespaceError, JournalError>(
		self,
	) -> impl FnOnce(NamespaceError) -> BootstrapFailure<NamespaceError, JournalError> {
		move |source| BootstrapFailure::Namespace(self, source)
	}
}

type PreparationResult<Directory, NamespaceError, Journal> = Result<
	Prepared<Directory, Journal, <Journal as InitialJournal>::Frame>,
	BootstrapFailure<NamespaceError, <Journal as InitialJournal>::Error>,
>;

pub(super) fn prepare<'root, Root, Journal>(
	destination: &'root Root,
	request: JobBootstrap<'_>,
	signer: &SigningKey,
	plan: Option<&[u8]>,
) -> PreparationResult<Root::Job, Root::Error, Journal>
where
	Root: JobBootstrapRoot<'root>,
	Journal: InitialJournal<Segment = <Root::Job as JobWorkspace>::Segment>,
{
	if request.owner_token.as_bytes() == request.context.job.as_bytes()
		|| request.owner_token.as_bytes() == request.profile.as_bytes()
	{
		return Err(BootstrapFailure::Owner(OwnerError::InvalidToken));
	}
	let destination_identity = journal_identity(destination.identity());
	let directory = destination
		.create_job_directory(request.name)
		.map_err(JobStep::CreateJob.failure())?;
	let directories = if plan.is_some() {
		vec![
			OwnerStateDirectory::Checkpoints,
			OwnerStateDirectory::Journal,
			OwnerStateDirectory::Receipts,
			OwnerStateDirectory::Stage,
		]
	} else {
		vec![OwnerStateDirectory::Journal, OwnerStateDirectory::Stage]
	};
	let owner = OwnerRecord::sign(
		OwnerManifest {
			token: request.owner_token,
			job: request.context.job,
			profile: request.profile,
			created: request.created,
			destination_device: destination_identity.device(),
			state_root: journal_identity(directory.identity()),
			plan_digest: request.context.plan_digest,
			directories,
		},
		signer,
	)
	.map_err(BootstrapFailure::Owner)?;
	let mut record = directory
		.create_owner_record()
		.map_err(JobStep::CreateOwner.failure())?;
	record
		.write_all(owner.as_bytes())
		.map_err(BootstrapFailure::WriteOwner)?;
	record.sync_all().map_err(BootstrapFailure::SyncOwner)?;
	drop(record);
	if let Some(bytes) = plan {
		let mut artifact = directory
			.create_plan_record()
			.map_err(JobStep::CreatePlan.failure())?;
		artifact
			.write_all(bytes)
			.map_err(BootstrapFailure::WritePlan)?;
		artifact.sync_all().map_err(BootstrapFailure::SyncPlan)?;
	}

	let journal_directory = directory
		.create_journal_directory()
		.map_err(JobStep::CreateJournal.failure())?;
	let segment = journal_directory
		.create_first_segment()
		.map_err(JobStep::CreateSegment.failure())?;
	let mut journal = Journal::from_new_segment(segment).map_err(BootstrapFailure::Journal)?;
	journal_directory
		.sync_directory()
		.map_err(JobStep::SyncJournal.failure())?;
	directory
		.sync_directory()
		.map_err(JobStep::SyncJob.failure())?;
	destination
		.sync_directory()
		.map_err(JobStep::SyncDestination.failure())?;

	let initial = JobPrepared {
		context: request.context,
		owner_digest: owner.digest(),
		destination_root: DestinationRootBinding {
			id: request.destination_id,
			identity: destination_identity,
		},
	};
	let initial_frame = journal
		.append_job_prepared(initial)
		.map_err(BootstrapFailure::Journal)?;
	drop(journal_directory);
	Ok(Prepared {
		directory,
		owner,
		initial_frame,
		journal,
	})
}

fn journal_identity(identity: JobFileIdentity) -> LinuxFileIdentity {
	LinuxFileIdentity::new(identity.device, identity.inode)
}
