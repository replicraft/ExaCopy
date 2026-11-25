use ed25519_dalek::SigningKey;
use exacopy_content::validate_stream_input;
use exacopy_endpoint::linux_copy::{
	CopyDestinationView, CopySource, CopySourceRoot, CopyWorkspace, PublishableStageDirectory as _,
};
use exacopy_endpoint::linux_job::{JobBootstrapRoot, JobWorkspace};
use exacopy_endpoint::linux_staging::StageReader as _;
use exacopy_endpoint::{JournalSegment, ReadView as _};
use exacopy_journal::{OwnerProfileId, OwnerTimestamp, OwnerToken};
use exacopy_model::{CopyBinding, CopyEvent, EntryId, JobId, RunEpoch, StageId};

use super::job::prepare_durable_copy;
use super::{
	CopyCheckpoint, CopyReceipt, LocalCopyPlan, ReceiptEvidence, StageRequest, check_source,
	observe,
};

pub(super) mod checkpoints;
mod error;
mod planning;
mod protocol;
mod public_apply;
pub(super) mod records;

use checkpoints::StageRecords;
pub use error::CopyError;
pub use planning::{PlanningRoots, plan_with_capabilities};
use planning::{
	capture_source, check_absent, destination_binding, journal_identity, source_root_identity,
};
pub(super) use protocol::ProtocolError;
pub(super) use protocol::Publication;
pub use public_apply::{PublicApplyStage, PublicApplyStageRequest, stage_public_apply};
use records::EntryEvidence;

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

type CopyFailure<R, D, J> =
	CopyError<R, <D as CopyDestinationView>::Error, <J as CopyWorkspace>::PublishError>;
type CopyResult<'name, R, D, J> = Result<CopyReceipt<'name>, CopyFailure<R, D, J>>;

/// Executes the planned preserve-mode copy through independently authorized capabilities.
///
/// This coordinator holds the stage through read-back and required metadata and
/// synchronizes intent before passing the model's consumed permission to the adapter.
/// # Errors
/// Refuses changed authority or observations. Once the intent barrier is attempted,
/// the job and its artifacts may require reconciliation.
pub fn copy_with_capabilities<'root, 'name, S, D, J>(
	planning: PlanningRoots<'root, S, D>,
	plan: &LocalCopyPlan<'name>,
	profile: CopyProfile<'_>,
	scratch: &mut [u8],
	checkpoint: fn(CopyCheckpoint),
) -> CopyResult<'name, S::Error, D, J>
where
	S: CopySourceRoot<Source: CopySource<Identity = J::Identity, Metadata = J::Metadata>>,
	D: CopyDestinationView
		+ JobBootstrapRoot<'root, Job = J, Error = <D as CopyDestinationView>::Error>,
	J: CopyWorkspace + JobWorkspace<Error = <D as CopyDestinationView>::Error>,
	J::Segment: JournalSegment,
{
	let file = preflight_source::<S, D, J>(&planning, plan, scratch.len())?;
	let planned_source = plan.source();
	let target = plan.destination().component;

	let context = plan.context();
	let attempt = plan.attempt();
	let binding = CopyBinding::new(
		// LocalCopyPlan always contains an already validated UUIDv7.
		JobId::try_from_bytes(*context.job.as_bytes()).map_err(|_| CopyError::StalePlan)?,
		EntryId::new(1),
		RunEpoch::new(context.epoch.get()),
		StageId::from_bytes(*attempt.entry.as_bytes()),
	);
	let evidence = EntryEvidence::new(
		file.copy_observation(),
		planned_source.file_identity,
		file.length(),
		context,
		attempt.entry,
		plan.destination(),
	)?;
	let (job, mut journal) =
		prepare_durable_copy(planning.destination, plan, profile).map_err(CopyError::Bootstrap)?;
	checkpoint(CopyCheckpoint::PlanSynced);
	let directory = job
		.create_stage_directory()
		.map_err(CopyError::CreateStage)?;
	JobWorkspace::sync_directory(&job).map_err(CopyError::CreateStage)?;
	let pages = job
		.create_checkpoint_directory()
		.map_err(CopyError::CreateCheckpoints)?;
	JobWorkspace::sync_directory(&job).map_err(CopyError::CreateCheckpoints)?;
	let request = StageRequest {
		stage_name: attempt.stage_name,
		target,
		binding,
	};
	let mut records = StageRecords::new(&evidence, &pages, &mut journal, checkpoint);
	let (stage, mut session, digest) = crate::linux_staging::stage_verified(
		&file,
		&directory,
		request,
		scratch,
		Some(&mut records),
	)
	.map_err(CopyError::Stage)?
	.into_parts();
	checkpoint(CopyCheckpoint::CopyMetadataApplied);

	let sealed = evidence.seal_stream(
		journal_identity(stage.identity().into()),
		stage.length(),
		digest,
	)?;
	let metadata_frame = sealed.record(&mut journal)?;
	checkpoint(CopyCheckpoint::StageSealed);
	check_source(&file).map_err(CopyError::SourcePolicy)?;
	let publication = Publication {
		context,
		plan,
		binding,
		stage_directory: journal_identity(directory.identity()),
	};
	let durability = publication.complete_using(
		&mut journal,
		&mut session,
		&sealed,
		&metadata_frame,
		checkpoint,
		|permit| directory.publish(stage, permit),
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
	.map_err(CopyError::Receipt)?;
	protocol::persist_receipt(
		&job,
		&mut journal,
		publication.intent_context(),
		&receipt,
		&durability,
		checkpoint,
	)?;
	observe(&mut session, binding, CopyEvent::ReceiptRecorded)
		.map_err(CopyError::PublicationModel)?;
	Ok(receipt)
}

fn preflight_source<'root, S, D, J>(
	planning: &PlanningRoots<'root, S, D>,
	plan: &LocalCopyPlan<'_>,
	scratch_len: usize,
) -> Result<S::Source, CopyFailure<S::Error, D, J>>
where
	S: CopySourceRoot<Source: CopySource<Identity = J::Identity, Metadata = J::Metadata>>,
	D: CopyDestinationView
		+ JobBootstrapRoot<'root, Job = J, Error = <D as CopyDestinationView>::Error>,
	J: CopyWorkspace + JobWorkspace<Error = <D as CopyDestinationView>::Error>,
	J::Segment: JournalSegment,
{
	let planned_source = plan.source();
	let planned_destination = plan.destination().root;
	if destination_binding(planning) != planned_destination
		|| journal_identity(JobBootstrapRoot::identity(planning.destination))
			!= planned_destination.identity
		|| planning.source_id != planned_source.root_id
		|| source_root_identity(planning.source) != planned_source.root_identity
	{
		return Err(CopyError::StalePlan);
	}
	let target = plan.destination().component;
	check_absent(planning.destination, target)?;
	let file = planning
		.source
		.open_regular(planned_source.component)
		.map_err(CopyError::Source)?;
	if capture_source(planning, &file, planned_source.component)? != planned_source {
		return Err(CopyError::StalePlan);
	}
	validate_stream_input(file.length(), scratch_len).map_err(|error| {
		CopyError::SourcePolicy(crate::linux_staging::StageFailure::Input(error))
	})?;
	check_source(&file).map_err(CopyError::SourcePolicy)?;

	Ok(file)
}

impl<R, S, P> From<ProtocolError<R, S, P>> for CopyError<R, S, P> {
	fn from(error: ProtocolError<R, S, P>) -> Self {
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
