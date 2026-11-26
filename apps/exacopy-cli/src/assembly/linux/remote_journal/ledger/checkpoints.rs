use exacopy_journal::StreamDigest;
use exacopy_journal::remote_download::{MAX_REMOTE_CHECKPOINT_BYTES, MAX_REMOTE_CHECKPOINTS};
use exacopy_platform::linux::FileIdentity;
use exacopy_transfer::remote_capture::{CaptureCheckpoint, CaptureCheckpoints, SourceEpoch};

use super::{Attempt, Body, Error, PrefixBarrier, PrefixScope, RemoteJobJournal};

pub(in crate::assembly::linux) struct CheckpointLedger<'journal, 'lease> {
	journal: &'journal mut RemoteJobJournal<'lease>,
	barrier: &'journal PrefixBarrier,
}

impl<'journal, 'lease> CheckpointLedger<'journal, 'lease> {
	pub(super) const fn new(
		journal: &'journal mut RemoteJobJournal<'lease>,
		barrier: &'journal PrefixBarrier,
	) -> Self {
		Self { journal, barrier }
	}
}

impl CaptureCheckpoints<FileIdentity> for CheckpointLedger<'_, '_> {
	type Error = Error;

	fn record(&mut self, file: FileIdentity, range: CaptureCheckpoint) -> Result<(), Error> {
		let Some(Attempt::Prepared(active)) = &self.journal.active else {
			return Err(Error::Binding);
		};
		let epochs = active.allocation.epochs;
		let expected = PrefixScope {
			job: self.journal.lease.job().identity(),
			prepared: active.head,
			source: SourceEpoch::new(epochs.source),
			stage: active.file,
		};
		let end = range.offset.checked_add(range.length);
		let barrier = self.barrier.take_current(expected, end.unwrap_or(0));
		let ordinal = active
			.ordinal
			.checked_add(1)
			.filter(|count| *count <= MAX_REMOTE_CHECKPOINTS)
			.ok_or(Error::Attempt)?;
		let end = end
			.filter(|end| *end <= active.allocation.source.length().get())
			.ok_or(Error::Attempt)?;
		if file != expected.stage
			|| range.epoch != expected.source
			|| range.offset != active.covered
			|| !(1..=MAX_REMOTE_CHECKPOINT_BYTES).contains(&range.length)
			|| !barrier
		{
			return Err(Error::Binding);
		}
		self.journal.append(Body::RangeCheckpoint {
			prepared: expected.prepared,
			epochs,
			ordinal,
			offset: range.offset,
			length: range.length,
			digest: StreamDigest::from_bytes(range.digest),
		})?;
		if let Some(Attempt::Prepared(active)) = &mut self.journal.active {
			active.ordinal = ordinal;
			active.covered = end;
		}
		Ok(())
	}
}
