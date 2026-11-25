use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_copy::{CopySource, CopySourceRoot};
use exacopy_endpoint::linux_recovery::{RecoveryJobView, RecoveryRecord};
use exacopy_journal::RootCapabilityId;

use super::super::CopyCheckpoint;
use super::super::job::check_linux_barrier;
use super::finish::finish_with_lease;
use super::source::open_source;
use super::{FinishFailure, RecoveryDisposition, RecoveryHistory, RecoveryProfile, RecoveryStep};

mod engine;
mod error;
mod held;

use engine::RetryHistory;
pub use error::SourceRecoveryFailure;

/// The current source-directory grant for this retained copy.
#[derive(Clone, Copy)]
pub struct RecoverySource<'root, S> {
	/// A held directory opened with current authority to read the source.
	pub root: &'root S,
	/// The source capability ID independently assigned by the caller.
	pub id: RootCapabilityId,
}

/// Rechecks recovery and attempts a retained stage through the supplied exclusive lease.
///
/// # Errors
/// Refuses stale authority, changed evidence, and uncertain publication results.
pub fn retry_with_lease<L, S>(
	lease: &L,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	source: RecoverySource<'_, S>,
	scratch: &mut [u8],
	checkpoint: fn(CopyCheckpoint),
) -> super::SourceRecoveryResult<L>
where
	L: super::RecoveryStageLease,
	S: CopySourceRoot<
			Source: CopySource<
				Identity = <L::File as RecoveryRecord>::Identity,
				Metadata = L::Metadata,
			>,
			Error = super::LeaseReadError<L>,
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
		RecoveryDisposition::PossibleRetry => {
			let stage = held::HeldStage::new(lease, &names)?;
			let source = open_source(&plan, &history.journal, source)?;
			engine::publish(
				RetryHistory {
					plan: &plan,
					journal: &history.journal,
					owner: history.owner.digest(),
				},
				&source,
				&stage,
				|boundary| held::open_journal(lease, &history.journal_file, boundary, checkpoint),
				scratch,
			)
			.map_err(held::retry_error)?;
		}
		RecoveryDisposition::PublishedNeedsBarriers
		| RecoveryDisposition::PublishedNeedsReceipt { .. } => {}
		_ => return Ok(current),
	}

	finish_with_lease(lease, name, profile, scratch).map_err(super::after_admission)
}
