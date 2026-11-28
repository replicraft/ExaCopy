use std::io::{self, Write as _};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::linux_job::{
	JobBootstrapRoot, JobFileIdentity, JobJournalDirectory, JobRecord, JobWorkspace,
};
use exacopy_journal::{
	DestinationRootBinding, JobPrepared, LinuxFileIdentity, OwnerDigest, OwnerError, OwnerManifest,
	OwnerRecord, OwnerStateDirectory, PublicApplyBinding, PublicApplyOwnerManifest,
	PublicApplyOwnerRecord,
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

pub(super) struct Prepared<Directory, Journal, Frame, O = OwnerRecord> {
	pub(super) directory: Directory,
	pub(super) owner: O,
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

type PreparationResult<Directory, NamespaceError, Journal, O = OwnerRecord> = Result<
	Prepared<Directory, Journal, <Journal as InitialJournal>::Frame, O>,
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
	prepare_with_owner(destination, request, plan, |manifest| {
		OwnerRecord::sign(manifest, signer)
	})
}

pub(super) fn prepare_public<'root, Root, Journal>(
	destination: &'root Root,
	request: JobBootstrap<'_>,
	signer: &SigningKey,
	plan: &[u8],
	binding: PublicApplyBinding,
) -> PreparationResult<Root::Job, Root::Error, Journal, PublicApplyOwnerRecord>
where
	Root: JobBootstrapRoot<'root>,
	Journal: InitialJournal<Segment = <Root::Job as JobWorkspace>::Segment>,
{
	prepare_with_owner(destination, request, Some(plan), |owner| {
		PublicApplyOwnerRecord::sign(PublicApplyOwnerManifest { owner, binding }, signer)
	})
}

trait PreparedOwner {
	fn bytes_and_digest(&self) -> (&[u8], OwnerDigest);
}

impl PreparedOwner for OwnerRecord {
	fn bytes_and_digest(&self) -> (&[u8], OwnerDigest) {
		(self.as_bytes(), self.digest())
	}
}

impl PreparedOwner for PublicApplyOwnerRecord {
	fn bytes_and_digest(&self) -> (&[u8], OwnerDigest) {
		(self.as_bytes(), self.digest())
	}
}

fn prepare_with_owner<'root, Root, Journal, O>(
	destination: &'root Root,
	request: JobBootstrap<'_>,
	plan: Option<&[u8]>,
	sign: impl FnOnce(OwnerManifest) -> Result<O, OwnerError>,
) -> PreparationResult<Root::Job, Root::Error, Journal, O>
where
	Root: JobBootstrapRoot<'root>,
	Journal: InitialJournal<Segment = <Root::Job as JobWorkspace>::Segment>,
	O: PreparedOwner,
{
	validate_owner_token(request).map_err(BootstrapFailure::Owner)?;
	let destination_identity = journal_identity(destination.identity());
	let directory = destination
		.create_job_directory(request.name)
		.map_err(JobStep::CreateJob.failure())?;
	let owner = sign(owner_manifest(
		request,
		destination_identity,
		directory.identity(),
		plan.is_some(),
	))
	.map_err(BootstrapFailure::Owner)?;
	let (owner_bytes, owner_digest) = owner.bytes_and_digest();
	let mut record = directory
		.create_owner_record()
		.map_err(JobStep::CreateOwner.failure())?;
	record
		.write_all(owner_bytes)
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
		owner_digest,
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

fn validate_owner_token(request: JobBootstrap<'_>) -> Result<(), OwnerError> {
	if request.owner_token.as_bytes() == request.context.job.as_bytes()
		|| request.owner_token.as_bytes() == request.profile.as_bytes()
	{
		return Err(OwnerError::InvalidToken);
	}
	Ok(())
}

fn owner_manifest(
	request: JobBootstrap<'_>,
	destination: LinuxFileIdentity,
	job: JobFileIdentity,
	has_plan: bool,
) -> OwnerManifest {
	let directories = if has_plan {
		vec![
			OwnerStateDirectory::Checkpoints,
			OwnerStateDirectory::Journal,
			OwnerStateDirectory::Receipts,
			OwnerStateDirectory::Stage,
		]
	} else {
		vec![OwnerStateDirectory::Journal, OwnerStateDirectory::Stage]
	};
	OwnerManifest {
		token: request.owner_token,
		job: request.context.job,
		profile: request.profile,
		created: request.created,
		destination_device: destination.device(),
		state_root: journal_identity(job),
		plan_digest: request.context.plan_digest,
		directories,
	}
}

fn journal_identity(identity: JobFileIdentity) -> LinuxFileIdentity {
	LinuxFileIdentity::new(identity.device, identity.inode)
}
