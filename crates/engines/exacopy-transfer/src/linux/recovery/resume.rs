use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_copy::{CopySource, CopySourceRoot};
use exacopy_endpoint::linux_recovery::{RecoveryInventoryView, RecoveryJobView, RecoveryRecord};

use super::super::CopyCheckpoint;
use super::super::job::check_linux_barrier;
use super::finish::{completion, finish_with_lease};
use super::source::open_source;
use super::{
	FinishFailure, LeaseReadError, RecoveryDisposition, RecoveryHistory, RecoveryProfile,
	RecoverySource, RecoveryStageLease, RecoveryStep,
};

mod engine;
mod error;
mod leased;

pub use engine::StageDirectory as ResumeStageDirectory;
use engine::{Evidence, Resume, RetainedStage};

/// Resumes an interrupted, journaled copy from its bound private stage.
///
/// The current source grant must match the original plan and preparation. The job must
/// have an intact pre-intent journal and a bound private stage. A synchronized new
/// generation precedes writes under the exclusive job lease. For a writable stage,
/// reuse requires the historical digest to agree in both held streams. A stage that
/// already has the planned permissions can proceed through a read-only data handle
/// after fresh full-stream agreement. Both paths finish metadata and require a new
/// exclusive publication intent. Source consistency is live observed.
///
/// Existing publication intents remain subject to their ordinary recovery paths.
/// If publication already happened, this function can complete its receipt under the same lease.
///
/// # Errors
/// A mismatched source grant or current metadata, unsafe stage, unsupported history or
/// failed verification cannot authorize publication. Partial writes remain in the original
/// private stage. Uncertain publication and receipt effects require reconciliation.
pub fn resume_with_lease<L, S>(
	lease: &L,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	source: RecoverySource<'_, S>,
	scratch: &mut [u8],
	checkpoint: fn(CopyCheckpoint),
) -> super::SourceRecoveryResult<L>
where
	L: RecoveryStageLease,
	S: CopySourceRoot<
			Source: CopySource<
				Identity = <L::File as RecoveryRecord>::Identity,
				Metadata = L::Metadata,
			>,
			Error = LeaseReadError<L>,
		>,
{
	check_linux_barrier::<L::Segment<'_>>().map_err(FinishFailure::Resume)?;
	let job = lease.job();
	let history = RecoveryHistory::load(job, name, profile)?;
	let plan = history.plan()?;
	let names = job
		.inventory(plan.attempt().stage_name, plan.destination().component)
		.map_err(RecoveryStep::Namespace.platform())?;
	let current = history.inspect(job, &names, scratch)?;
	match current.disposition {
		RecoveryDisposition::RetainedPreparation if history.journal.stage.is_some() => {
			let stage = names.stage().ok_or(FinishFailure::IncompleteEvidence)?;

			let reopened = open_source(&plan, &history.journal, source)?;
			let resume = Resume::admit::<
				L::EffectError,
				L::PublishError,
				FinishFailure<LeaseReadError<L>, L::EffectError>,
			>(
				Evidence {
					plan: &plan,
					replay: &history.journal,
					ranges: &history.ranges,
					owner: history.owner.digest(),
				},
				&reopened,
				RetainedStage {
					reader: stage,
					identity: stage.identity(),
					mode: stage.observation().mode,
				},
				scratch.len(),
				L::source_timestamp,
			)
			.map_err(leased::resume_error::<L>)?;
			let mut directory = lease
				.reopen_stage(&names)
				.map_err(completion(RecoveryStep::Namespace))?;
			resume
				.execute(
					&mut directory,
					&leased::HeldRecords {
						lease,
						journal: &history.journal_file,
						checkpoint,
					},
					scratch,
				)
				.map_err(leased::resume_error::<L>)?;
		}
		RecoveryDisposition::PublishedNeedsBarriers
		| RecoveryDisposition::PublishedNeedsReceipt { .. } => {}
		_ => return Ok(current),
	}
	finish_with_lease(lease, name, profile, scratch).map_err(super::after_admission)
}
