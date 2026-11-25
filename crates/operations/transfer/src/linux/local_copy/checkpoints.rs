use exacopy_content::RangeMeasurement;
use exacopy_endpoint::linux_copy::CheckpointPages;
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurableJournal, RangeCheckpoint, RangePage, SourceMeasurementId, StreamDigest,
};

use crate::linux_staging::{StageFailure, StageRecords as StageRecordSink};

use super::planning::journal_identity;
use super::records::EntryEvidence;

pub(in crate::linux) struct StageRecords<'job, 'name, Pages> {
	entry: &'job EntryEvidence<'name>,
	pages: &'job Pages,
	journal: &'job mut DurableJournal,
	ordinal: u32,
}

impl<'job, 'name, Pages> StageRecords<'job, 'name, Pages> {
	pub(super) const fn new(
		entry: &'job EntryEvidence<'name>,
		pages: &'job Pages,
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

impl<Identity, ReadError, Pages> StageRecordSink<Identity, ReadError, Pages::Error>
	for StageRecords<'_, '_, Pages>
where
	Identity: Into<JobFileIdentity>,
	Pages: CheckpointPages,
{
	fn begin(
		&mut self,
		stage: Identity,
	) -> Result<SourceMeasurementId, StageFailure<ReadError, Pages::Error>> {
		self.entry
			.record(self.journal, journal_identity(stage.into()))
	}

	fn record(
		&mut self,
		measurement: SourceMeasurementId,
		range: RangeMeasurement,
	) -> Result<(), StageFailure<ReadError, Pages::Error>> {
		let page = RangePage::new(
			self.ordinal,
			range.offset,
			range.length,
			StreamDigest::from_bytes(*range.digest.as_bytes()),
			measurement,
		)
		.map_err(StageFailure::CheckpointEvidence)?;
		self.pages
			.persist_page(self.ordinal, &page.encode())
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
