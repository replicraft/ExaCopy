use exacopy_content::validate_stream_input;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::RootCapabilityId;
use exacopy_platform::linux::{DestinationRoot, ReadRoot};

use super::finish::{acquire_lease, finish_leased};
use super::source::open_source;
use super::{
	RecoveryDisposition, RecoveryFinishError, RecoveryHistory, RecoveryInspectError,
	RecoveryInspection, RecoveryProfile, RecoveryStep,
};

mod engine;
mod error;
mod native;

use engine::RetryHistory;
pub use error::RecoveryRetryError;
use native::{NativeRetainedStage, NativeRetryJournal};

/// The current source-directory grant for this retained copy.
#[derive(Clone, Copy)]
pub struct RecoverySource<'root> {
	/// A held directory opened with current authority to read the source.
	pub root: &'root ReadRoot,
	/// The source capability ID independently assigned by the caller.
	pub id: RootCapabilityId,
}

/// Retries the no-clobber publication of a retained, sealed Linux stage.
///
/// The source grant and fresh source read must match the accepted copy history. An exclusive
/// recovery lease, freshly checked private stage, and new synchronized publication intent
/// are required before publication. If the target is already published, recovery can finish
/// its existing receipt under the same lease without another namespace mutation.
///
/// # Errors
/// Conflicting or incomplete evidence leaves existing files and journal records available
/// for inspection. An ambiguous effect must be reconciled against current filesystem state.
pub fn retry_recovery(
	destination: &DestinationRoot,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	source: RecoverySource<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryRetryError> {
	validate_stream_input(0, scratch.len()).map_err(RecoveryInspectError::Input)?;
	let lease = acquire_lease(destination, name)?;
	let job = lease.job();
	let history = RecoveryHistory::load(job, name, profile)?;
	let plan = history.plan()?;
	let names = job
		.inventory(plan.attempt().stage_name, plan.destination().component)
		.map_err(RecoveryStep::Namespace.platform())?;
	let current = history.inspect(job, &names, scratch)?;
	match current.disposition {
		RecoveryDisposition::PossibleRetry => {
			let stage = NativeRetainedStage::new(&lease, &names)?;
			let source = open_source(&plan, &history.journal, source)?;
			engine::publish(
				RetryHistory {
					plan: &plan,
					journal: &history.journal,
					owner: history.owner.digest(),
				},
				&source,
				&stage,
				|boundary| NativeRetryJournal::open(&lease, &history.journal_file, boundary),
				scratch,
			)
			.map_err(native::retry_error)?;
		}
		RecoveryDisposition::PublishedNeedsBarriers
		| RecoveryDisposition::PublishedNeedsReceipt { .. } => {}
		_ => return Ok(current),
	}

	finish_leased(&lease, name, profile, scratch)
		.map_err(|error| match error {
			RecoveryFinishError::Inspection(error) => RecoveryFinishError::Completion(error),
			error => error,
		})
		.map_err(RecoveryRetryError::Recovery)
}
