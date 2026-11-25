use std::io::Read;

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	JournalContext, JournalEntryId, OwnerRecord, OwnerStateDirectory, RangeCheckpoint,
	SourceMeasurementId,
};

use super::{JournalReplayError, Scan, require_binding};

impl<R: Read> Scan<R> {
	pub(super) fn read_ranges(
		&mut self,
		context: JournalContext,
		entry: JournalEntryId,
		source: SourceMeasurementId,
		owner: &OwnerRecord,
	) -> Result<Option<Frame>, JournalReplayError> {
		while let Some(frame) = self.read_next()? {
			match frame.kind() {
				FrameKind::StageSealed => return Ok(Some(frame)),
				FrameKind::RangeCheckpoint => {
					let record = RangeCheckpoint::from_frame(&frame)?;
					let count = self.summary.checkpoints.len();
					require_binding(
						FrameKind::RangeCheckpoint,
						record.context == context
							&& record.entry == entry
							&& record.source == source
							&& usize::try_from(record.page.ordinal()).ok() == count.checked_add(1)
							&& owner
								.manifest()
								.directories
								.contains(&OwnerStateDirectory::Checkpoints),
					)?;
					self.summary.checkpoints.push(record);
				}
				found => {
					return Err(JournalReplayError::UnexpectedRecord {
						expected: Some(FrameKind::StageSealed),
						found,
					});
				}
			}
		}
		Ok(None)
	}
}
