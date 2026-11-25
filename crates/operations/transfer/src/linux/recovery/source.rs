use exacopy_endpoint::linux_staging::StagingSource as _;
use exacopy_endpoint::{
	ReadView as _,
	linux_copy::{CopySource, CopySourceRoot},
};

use super::super::{JournalReplay, LocalCopyPlan, check_source};
use super::{FinishFailure, RecoverySource, SourceRecoveryFailure, record_identity};

pub(super) fn open_source<R: CopySourceRoot, N, P>(
	plan: &LocalCopyPlan<'_>,
	journal: &JournalReplay,
	grant: RecoverySource<'_, R>,
) -> Result<R::Source, SourceRecoveryFailure<R::Error, N, P>> {
	let planned = plan.source();
	if grant.id != planned.root_id
		|| record_identity(grant.root.identity()) != planned.root_identity
	{
		return Err(SourceRecoveryFailure::SourceMismatch);
	}
	let source = grant
		.root
		.open_regular(planned.component)
		.map_err(SourceRecoveryFailure::OpenSource)?;
	let current = source.copy_observation();
	let modified = current.modified_at;
	let changed = current.changed_at;
	let original = journal
		.source_metadata
		.ok_or(FinishFailure::IncompleteEvidence)?;
	if record_identity(source.identity().into()) != planned.file_identity
		|| source.length() != planned.length
		|| modified.seconds != planned.modified_at.seconds()
		|| modified.nanoseconds != planned.modified_at.nanoseconds()
		|| changed.seconds != planned.changed_at.seconds()
		|| changed.nanoseconds != planned.changed_at.nanoseconds()
		|| current.mode != original.mode()
		|| current.owner != original.owner()
		|| current.group != original.group()
		|| current.links != original.link_count()
	{
		return Err(SourceRecoveryFailure::SourceMismatch);
	}
	check_source(&source).map_err(SourceRecoveryFailure::SourcePolicy)?;
	Ok(source)
}
