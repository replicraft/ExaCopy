use ed25519_dalek::SigningKey;
use exacopy_content::validate_stream_input;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::{
	DestinationRootBinding, DurableJournal, OwnerProfileId, OwnerTimestamp, OwnerToken,
	RootCapabilityId, SyncedFrame,
};
use exacopy_model::{CopyBinding, CopyEvent, EntryId, JobId, RunEpoch, StageId};
use exacopy_platform::linux::{
	DestinationRoot, PublishError, ReadError, ReadRoot, SourceFile, StageError, TargetStatus,
};

use super::job::native_identity;
use super::{
	CopyReceipt, DestinationPlanBinding, LocalCopyPlan, PlanAttempt, PreparedJob, ReceiptEvidence,
	SourcePlanBinding, StageRequest, check_source, observe, stage_with_preparation,
};

pub(super) mod checkpoints;
mod error;
mod protocol;
pub(super) mod records;

#[cfg(test)]
pub(super) mod crash_tests;

use checkpoints::StageRecords;
pub use error::LocalCopyError;
pub(super) use protocol::ProtocolError;
pub(super) use protocol::Publication;
use records::{EntryEvidence, SealEvidence};

/// The independently authorized Linux directories and their caller-assigned capability IDs.
#[derive(Clone, Copy)]
pub struct CopyRoots<'root> {
	/// Authorizes selecting one regular source beneath this held directory.
	pub source: &'root ReadRoot,
	/// Identifies the source authorization.
	pub source_id: RootCapabilityId,
	/// Authorizes a private job and exclusive creation under this held directory.
	pub destination: &'root DestinationRoot,
	/// Identifies the destination authorization.
	pub destination_id: RootCapabilityId,
}

/// The caller's trusted signing profile and fresh per-job ownership evidence.
#[derive(Clone, Copy)]
pub struct CopyProfile<'profile> {
	/// Identity associated with the locally trusted signing key.
	pub id: OwnerProfileId,
	/// Key managed by the caller's trust store.
	pub signer: &'profile SigningKey,
	/// Recorded creation time.
	pub created: OwnerTimestamp,
	/// Independent cryptographically random token reserved for this job.
	pub owner_token: OwnerToken,
}

/// Observes one regular source and an absent target under the authorized roots.
///
/// The resulting plan binds the observations and names for this attempt. Planning may
/// update source access time through a bounded EOF probe. Applying the plan reopens the
/// source through the authorized root and checks the current observations again.
///
/// # Errors
/// Reports unsafe, unsupported, or occupied names and failures to observe the source.
pub fn plan_new_file<'name>(
	roots: CopyRoots<'_>,
	attempt: PlanAttempt<'name>,
	source: UnixComponent<'name>,
	target: UnixComponent<'name>,
) -> Result<LocalCopyPlan<'name>, LocalCopyError> {
	check_absent(roots.destination, target)?;
	let file = roots
		.source
		.open_regular(source)
		.map_err(LocalCopyError::Source)?;
	check_source(&file).map_err(LocalCopyError::SourcePolicy)?;
	let source = capture_source(roots, &file, source)?;
	let destination = DestinationPlanBinding {
		root: destination_binding(roots),
		component: target,
	};
	LocalCopyPlan::new(attempt, source, destination).map_err(LocalCopyError::Plan)
}

/// Executes the planned single-file Linux copy with independent verification and a receipt.
///
/// The authorized roots must still match the plan and the target must be absent. The
/// private owner, plan and journal record the operation. A synchronized intent precedes
/// the exclusive rename. The receipt is synchronized and then bound by a final journal
/// frame. Completed barrier calls do not qualify the filesystem for power-loss durability.
///
/// # Errors
/// Preserves the source, pre-existing target and any private job material on failure.
/// Once intent is written, a failure can require inventory of the actual namespace.
pub fn copy_new_file<'name>(
	roots: CopyRoots<'_>,
	plan: &LocalCopyPlan<'name>,
	profile: CopyProfile<'_>,
	scratch: &mut [u8],
) -> Result<CopyReceipt<'name>, LocalCopyError> {
	let planned_source = plan.source();
	if destination_binding(roots) != plan.destination().root
		|| roots.source_id != planned_source.root_id
		|| native_identity(roots.source.identity()) != planned_source.root_identity
	{
		return Err(LocalCopyError::StalePlan);
	}
	let target = plan.destination().component;
	check_absent(roots.destination, target)?;
	let file = roots
		.source
		.open_regular(planned_source.component)
		.map_err(LocalCopyError::Source)?;
	if capture_source(roots, &file, planned_source.component)? != planned_source {
		return Err(LocalCopyError::StalePlan);
	}
	validate_stream_input(file.len(), scratch.len())
		.map_err(|error| LocalCopyError::SourcePolicy(super::StageFailure::Input(error)))?;
	check_source(&file).map_err(LocalCopyError::SourcePolicy)?;

	let context = plan.context();
	let attempt = plan.attempt();
	let binding = CopyBinding::new(
		// LocalCopyPlan always contains an already validated UUIDv7.
		JobId::try_from_bytes(*context.job.as_bytes()).map_err(|_| LocalCopyError::StalePlan)?,
		EntryId::new(1),
		RunEpoch::new(context.epoch.get()),
		StageId::from_bytes(*attempt.entry.as_bytes()),
	);
	let evidence = EntryEvidence::new(
		file.observation(),
		context,
		attempt.entry,
		plan.destination(),
	)?;
	let (job, mut journal) = PreparedJob::with_plan(roots.destination, plan, profile)
		.map_err(LocalCopyError::Bootstrap)?;
	#[cfg(test)]
	crash_tests::pause_at(crash_tests::Checkpoint::PlanSynced);
	let directory = job
		.create_stage_directory()
		.map_err(LocalCopyError::CreateStage)?;
	let pages = job
		.directory()
		.create_checkpoint_directory()
		.map_err(LocalCopyError::CreateCheckpoints)?;
	job.directory()
		.sync_directory()
		.map_err(LocalCopyError::CreateCheckpoints)?;
	let request = StageRequest {
		stage_name: attempt.stage_name,
		target,
		binding,
	};
	let mut verified = stage_with_preparation(
		&file,
		&directory,
		request,
		scratch,
		Some(StageRecords::new(&evidence, &pages, &mut journal)),
	)
	.map_err(LocalCopyError::Stage)?;

	let sealed = evidence.seal(&verified)?;
	let metadata_frame = sealed.record(&mut journal)?;
	#[cfg(test)]
	crash_tests::pause_at(crash_tests::Checkpoint::StageSealed);
	check_source(&file).map_err(LocalCopyError::SourcePolicy)?;
	let publication = Publication {
		context,
		plan,
		binding,
		stage_directory: native_identity(directory.identity()),
	};
	let durability = publication.complete(
		&mut journal,
		&mut verified.session,
		verified.stage,
		&sealed,
		&metadata_frame,
	)?;
	let receipt = CopyReceipt::from_synced_durability(
		ReceiptEvidence {
			context,
			entry: attempt.entry,
			source: planned_source.file_identity,
			destination: plan.destination().root,
			target,
			stream: sealed.verification.stage(),
		},
		&durability,
	)
	.map_err(LocalCopyError::Receipt)?;
	protocol::persist_receipt(
		job.directory(),
		&mut journal,
		publication.intent_context(),
		&receipt,
		&durability,
	)?;
	observe(&mut verified.session, binding, CopyEvent::ReceiptRecorded)
		.map_err(LocalCopyError::PublicationModel)?;
	Ok(receipt)
}

fn check_absent(root: &DestinationRoot, name: UnixComponent<'_>) -> Result<(), LocalCopyError> {
	match root
		.target_status(name)
		.map_err(LocalCopyError::InspectTarget)?
	{
		TargetStatus::Absent => Ok(()),
		TargetStatus::Occupied => Err(LocalCopyError::Conflict),
	}
}

fn destination_binding(roots: CopyRoots<'_>) -> DestinationRootBinding {
	DestinationRootBinding {
		id: roots.destination_id,
		identity: native_identity(roots.destination.identity()),
	}
}

fn capture_source<'name>(
	roots: CopyRoots<'_>,
	file: &SourceFile,
	name: UnixComponent<'name>,
) -> Result<SourcePlanBinding<'name>, LocalCopyError> {
	let observation = file.observation();
	Ok(SourcePlanBinding {
		root_id: roots.source_id,
		root_identity: native_identity(roots.source.identity()),
		file_identity: native_identity(file.identity()),
		length: file.len(),
		modified_at: records::timestamp(observation.modified_at())
			.map_err(LocalCopyError::Preparation)?,
		changed_at: records::timestamp(observation.changed_at())
			.map_err(LocalCopyError::Preparation)?,
		component: name,
	})
}

impl Publication<'_, '_> {
	pub(super) fn complete(
		&self,
		journal: &mut DurableJournal,
		session: &mut exacopy_model::CopySession,
		stage: exacopy_platform::linux::ClosedStage<'_>,
		sealed: &SealEvidence,
		metadata: &SyncedFrame,
	) -> Result<SyncedFrame, LocalCopyError> {
		self.complete_with(journal, session, stage, sealed, metadata)
			.map_err(LocalCopyError::from)
	}
}

impl From<ProtocolError<ReadError, StageError, PublishError>> for LocalCopyError {
	fn from(error: ProtocolError<ReadError, StageError, PublishError>) -> Self {
		match error {
			ProtocolError::Journal { kind, source } => Self::Journal { kind, source },
			ProtocolError::Model(error) => Self::PublicationModel(error),
			ProtocolError::Record(error) => Self::PublicationRecord(error),
			ProtocolError::Publication { source, recording } => {
				Self::Publication { source, recording }
			}
			ProtocolError::ReceiptNamespace(error) => Self::ReceiptNamespace(error),
			ProtocolError::ReceiptIo(error) => Self::ReceiptIo(error),
		}
	}
}
