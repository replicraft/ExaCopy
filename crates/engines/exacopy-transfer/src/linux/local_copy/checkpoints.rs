use exacopy_content::RangeMeasurement;
use exacopy_endpoint::JournalSegment;
use exacopy_endpoint::linux_copy::CheckpointPages;
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurableJournal, RangeCheckpoint, RangePage, SourceMeasurementId, StreamDigest,
};

use crate::linux_staging::{StageFailure, StageRecords as StageRecordSink};

use super::planning::journal_identity;
use super::records::EntryEvidence;
use crate::linux::CopyCheckpoint;

pub(in crate::linux) struct StageRecords<'job, 'name, Pages, Segment> {
	entry: &'job EntryEvidence<'name>,
	pages: &'job Pages,
	journal: &'job mut DurableJournal<Segment>,
	ordinal: u32,
	checkpoint: fn(CopyCheckpoint),
}

impl<'job, 'name, Pages, Segment> StageRecords<'job, 'name, Pages, Segment> {
	pub(super) const fn new(
		entry: &'job EntryEvidence<'name>,
		pages: &'job Pages,
		journal: &'job mut DurableJournal<Segment>,
		checkpoint: fn(CopyCheckpoint),
	) -> Self {
		Self {
			entry,
			pages,
			journal,
			ordinal: 1,
			checkpoint,
		}
	}
}

impl<Identity, ReadError, Pages, Segment> StageRecordSink<Identity, ReadError, Pages::Error>
	for StageRecords<'_, '_, Pages, Segment>
where
	Identity: Into<JobFileIdentity>,
	Pages: CheckpointPages,
	Segment: JournalSegment,
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
		(self.checkpoint)(CopyCheckpoint::RangePageSynced);
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
		(self.checkpoint)(CopyCheckpoint::RangeFrameSynced);
		// The stream recorder issues at most 4,096 checkpoints.
		self.ordinal += 1;
		Ok(())
	}
}
