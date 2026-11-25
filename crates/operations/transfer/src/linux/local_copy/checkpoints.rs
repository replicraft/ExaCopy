use exacopy_content::{ContentDigest, CopyMeasureError, RangeMeasurement, copy_and_checkpoint_at};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurableJournal, JournalContext, JournalEntryId, RangeCheckpoint, RangePage,
	SourceMeasurementId, StreamDigest,
};
use exacopy_platform::linux::{CheckpointDirectory, FileIdentity, SourceFile, WriteStage};

use super::super::StageFailure;
use super::super::job::native_identity;
use super::records::EntryEvidence;

pub(in crate::linux) struct StageRecords<'job, 'name> {
	entry: &'job EntryEvidence<'name>,
	pages: &'job CheckpointDirectory<'job>,
	journal: &'job mut DurableJournal,
}

impl<'job, 'name> StageRecords<'job, 'name> {
	pub(super) const fn new(
		entry: &'job EntryEvidence<'name>,
		pages: &'job CheckpointDirectory<'job>,
		journal: &'job mut DurableJournal,
	) -> Self {
		Self {
			entry,
			pages,
			journal,
		}
	}

	pub(in crate::linux) fn begin(
		self,
		stage: FileIdentity,
	) -> Result<RangeRecorder<'job>, StageFailure> {
		let measurement = self.entry.record(self.journal, native_identity(stage))?;
		Ok(RangeRecorder {
			context: self.entry.context,
			entry: self.entry.entry,
			pages: self.pages,
			journal: self.journal,
			measurement,
			ordinal: 1,
		})
	}
}

pub(in crate::linux) struct RangeRecorder<'job> {
	context: JournalContext,
	entry: JournalEntryId,
	measurement: SourceMeasurementId,
	pages: &'job CheckpointDirectory<'job>,
	journal: &'job mut DurableJournal,
	ordinal: u32,
}

impl RangeRecorder<'_> {
	pub(in crate::linux) fn copy(
		mut self,
		source: &SourceFile,
		stage: &mut WriteStage<'_>,
		scratch: &mut [u8],
	) -> Result<ContentDigest, StageFailure> {
		copy_and_checkpoint_at(
			source.len(),
			scratch,
			|offset, bytes| source.read_exact_at(offset, bytes),
			|offset, bytes, range| {
				stage.write_all_at(offset, bytes).map_err(|source| {
					StageFailure::Copy(CopyMeasureError::Write { offset, source })
				})?;
				if let Some(range) = range {
					self.record(source, stage, range)?;
				}
				Ok(())
			},
		)
		.map_err(|error| match error {
			CopyMeasureError::InvalidInput(error) => StageFailure::Input(error),
			CopyMeasureError::Read { offset, source } => {
				StageFailure::Copy(CopyMeasureError::Read { offset, source })
			}
			CopyMeasureError::Write { source, .. } => source,
		})
	}

	fn record(
		&mut self,
		source: &SourceFile,
		stage: &mut WriteStage<'_>,
		range: RangeMeasurement,
	) -> Result<(), StageFailure> {
		source.recheck_observation().map_err(StageFailure::Source)?;
		stage.flush().map_err(StageFailure::Stage)?;
		let page = RangePage::new(
			self.ordinal,
			range.offset,
			range.length,
			StreamDigest::from_bytes(*range.digest.as_bytes()),
			self.measurement,
		)
		.map_err(StageFailure::CheckpointEvidence)?;
		self.pages
			.write_page(self.ordinal, &page.encode())
			.map_err(StageFailure::CheckpointPage)?;
		#[cfg(test)]
		super::crash_tests::pause_range_at(super::crash_tests::Checkpoint::RangePageSynced);
		let record = RangeCheckpoint {
			context: self.context,
			entry: self.entry,
			page: page.reference(),
			source: self.measurement,
		};
		let _ = self
			.journal
			.append(FrameKind::RangeCheckpoint, &record.encode())
			.map_err(StageFailure::CheckpointJournal)?;
		#[cfg(test)]
		super::crash_tests::pause_range_at(super::crash_tests::Checkpoint::RangeFrameSynced);
		// The stream recorder issues at most 4,096 checkpoints.
		self.ordinal += 1;
		Ok(())
	}
}
