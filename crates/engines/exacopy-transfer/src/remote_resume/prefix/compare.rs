use std::ops::Range;

use exacopy_content::StreamInputError;
use exacopy_journal::remote_download::checkpoints::RemotePrefixHistory;

use crate::remote_capture::{CapturedReadAt, SourceEpoch};

use super::{PrefixVerificationError as Error, RetainedPrefixView};

pub(super) enum Mismatch {
	Source { offset: u64 },
	Checkpoint { offset: u64 },
	Tail { offset: u64 },
}

pub(super) struct Comparison<'view, R, L> {
	source: &'view mut R,
	retained: &'view L,
	epoch: SourceEpoch,
	length: u64,
	source_window: &'view mut [u8],
	retained_window: &'view mut [u8],
	step: u64,
	prefix: blake3::Hasher,
}

impl<'view, R: CapturedReadAt, L: RetainedPrefixView> Comparison<'view, R, L> {
	pub(super) fn new(
		source: &'view mut R,
		retained: &'view L,
		epoch: SourceEpoch,
		length: u64,
		source_window: &'view mut [u8],
		retained_window: &'view mut [u8],
		step: u64,
	) -> Self {
		Self {
			source,
			retained,
			epoch,
			length,
			source_window,
			retained_window,
			step,
			prefix: blake3::Hasher::new(),
		}
	}

	pub(super) async fn recheck_source(&mut self) -> Result<(), Error<R::Error, L::Error>> {
		self.check_source()?;
		self.source
			.recheck()
			.await
			.map_err(Error::SourceObservation)?;
		self.check_source()
	}

	pub(super) fn recheck_stage(
		&self,
		inventory: &RemotePrefixHistory<'_>,
		extent: u64,
	) -> Result<(), Error<R::Error, L::Error>> {
		self.retained
			.recheck_observation()
			.map_err(Error::StageObservation)?;
		let native = self.retained.identity();
		let expected = inventory.prepared();
		if native.name.as_bytes() != inventory.name()
			|| native.directory != expected.directory
			|| native.file != expected.file
		{
			return Err(Error::StageIdentity);
		}
		let actual = self.retained.length();
		if actual != extent {
			return Err(Error::StageExtentChanged {
				expected: extent,
				actual,
			});
		}
		Ok(())
	}

	fn check_source(&self) -> Result<(), Error<R::Error, L::Error>> {
		if self.source.epoch() != self.epoch {
			return Err(Error::Epoch);
		}
		let actual = self.source.length();
		if actual != self.length {
			return Err(Error::SourceExtent {
				expected: self.length,
				actual,
			});
		}
		Ok(())
	}

	pub(super) async fn check(
		&mut self,
		range: Range<u64>,
		expected: Option<[u8; 32]>,
	) -> Result<Option<Mismatch>, Error<R::Error, L::Error>> {
		let mut historical = expected.map(|_| blake3::Hasher::new());
		let mut mismatch = false;
		let mut offset = range.start;
		while offset < range.end {
			let length = self.step.min(range.end - offset);
			let amount = usize::try_from(length)
				.map_err(|_| Error::Input(StreamInputError::FileTooLong { length }))?;
			self.check_source()?;
			self.source
				.read_exact_at(offset, &mut self.source_window[..amount])
				.await
				.map_err(|cause| Error::SourceRead { offset, cause })?;
			self.check_source()?;
			let local = &mut self.retained_window[..amount];
			self.retained
				.read_exact_at(offset, local)
				.map_err(|cause| Error::StageRead { offset, cause })?;
			let source = &self.source_window[..amount];
			mismatch |= *source != *local;
			if let Some(historical) = &mut historical {
				historical.update(local);
			}
			self.prefix.update(source);
			offset =
				offset
					.checked_add(length)
					.ok_or(Error::Input(StreamInputError::FileTooLong {
						length: range.end,
					}))?;
		}
		Ok(match (expected, historical) {
			(Some(digest), Some(hasher)) if hasher.finalize().as_bytes() != &digest => {
				Some(Mismatch::Checkpoint {
					offset: range.start,
				})
			}
			(Some(_), _) if mismatch => Some(Mismatch::Source {
				offset: range.start,
			}),
			(None, _) if mismatch => Some(Mismatch::Tail {
				offset: range.start,
			}),
			_ => None,
		})
	}

	pub(super) fn into_hasher(self) -> blake3::Hasher {
		self.prefix
	}
}
