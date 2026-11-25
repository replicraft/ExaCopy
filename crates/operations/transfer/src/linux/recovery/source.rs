use exacopy_platform::linux::SourceFile;

use super::super::{JournalReplay, LocalCopyPlan, check_source};
use super::finish::required;
use super::{RecoveryRetryError, RecoverySource, native_identity};

pub(super) fn open_source(
	plan: &LocalCopyPlan<'_>,
	journal: &JournalReplay,
	grant: RecoverySource<'_>,
) -> Result<SourceFile, RecoveryRetryError> {
	let planned = plan.source();
	if grant.id != planned.root_id
		|| native_identity(grant.root.identity()) != planned.root_identity
	{
		return Err(RecoveryRetryError::SourceMismatch);
	}
	let source = grant
		.root
		.open_regular(planned.component)
		.map_err(RecoveryRetryError::OpenSource)?;
	let current = source.observation();
	let modified = current.modified_at();
	let changed = current.changed_at();
	let original = required(journal.source_metadata)?;
	if native_identity(source.identity()) != planned.file_identity
		|| current.len() != planned.length
		|| modified.seconds() != planned.modified_at.seconds()
		|| modified.nanoseconds() != planned.modified_at.nanoseconds()
		|| changed.seconds() != planned.changed_at.seconds()
		|| changed.nanoseconds() != planned.changed_at.nanoseconds()
		|| current.mode() != original.mode()
		|| current.owner() != original.owner()
		|| current.group() != original.group()
		|| current.link_count() != original.link_count()
	{
		return Err(RecoveryRetryError::SourceMismatch);
	}
	check_source(&source).map_err(RecoveryRetryError::SourcePolicy)?;
	Ok(source)
}
