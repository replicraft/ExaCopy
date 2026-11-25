use exacopy_content::RangeMeasurement;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurableJournal, RangeCheckpoint, RangePage, SourceMeasurementId, StreamDigest,
};
use exacopy_platform::linux::{CheckpointDirectory, FileIdentity, ReadError, StageError};

use crate::linux_staging::StageRecords as StageRecordSink;

use super::super::StageFailure;
use super::super::job::native_identity;
use super::records::EntryEvidence;

pub(in crate::linux) struct StageRecords<'job, 'name> {
	entry: &'job EntryEvidence<'name>,
	pages: &'job CheckpointDirectory<'job>,
	journal: &'job mut DurableJournal,
	ordinal: u32,
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
			ordinal: 1,
		}
	}
}

impl StageRecordSink<FileIdentity, ReadError, StageError> for StageRecords<'_, '_> {
	fn begin(&mut self, stage: FileIdentity) -> Result<SourceMeasurementId, StageFailure> {
		self.entry.record(self.journal, native_identity(stage))
	}

	fn record(
		&mut self,
		measurement: SourceMeasurementId,
		range: RangeMeasurement,
	) -> Result<(), StageFailure> {
		let page = RangePage::new(
			self.ordinal,
			range.offset,
			range.length,
			StreamDigest::from_bytes(*range.digest.as_bytes()),
			measurement,
		)
		.map_err(StageFailure::CheckpointEvidence)?;
		self.pages
			.write_page(self.ordinal, &page.encode())
			.map_err(StageFailure::CheckpointPage)?;
		#[cfg(test)]
		super::crash_tests::pause_range_at(super::crash_tests::Checkpoint::RangePageSynced);
		let record = RangeCheckpoint {
			context: self.entry.context,
			entry: self.entry.entry,
			page: page.reference(),
			source: measurement,
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
