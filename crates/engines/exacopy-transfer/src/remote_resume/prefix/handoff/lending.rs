use std::convert::Infallible;

use exacopy_content::{StreamInputError, validate_stream_input};
use exacopy_journal::remote_download::replay::RemotePreparedStage;
use exacopy_journal::remote_download::witness::RemoteWitnessBinding;
use exacopy_journal::remote_download::{RemoteDownloadContext, RemoteScopeDigest};

use crate::remote_capture::{CapturedReadAt, SourceEpoch};

use super::{Error, VerifiedHeldRetainedPrefix, VerifiedRetainedPrefix};

/// Custody of the original retained reader after a scoped operation.
#[must_use]
pub struct LentRetainedReader<L> {
	retained: L,
}

impl<L> LentRetainedReader<L> {
	/// Borrows the exact original local reader without replacing or releasing it.
	#[must_use]
	pub const fn reader(&self) -> &L {
		&self.retained
	}
}

impl<'source, R: CapturedReadAt, L> VerifiedHeldRetainedPrefix<'source, R, L> {
	/// Lends the exact original reader and its matched source state together.
	///
	/// The caller may run independently admitted native work against the
	/// borrowed reader while reading from the opaque source cursor. Neither a
	/// borrowed reader nor a writable capability tied to it can escape this
	/// callback. The result keeps custody of the original reader, and releases
	/// the live source borrow for application transport retirement.
	pub async fn with_reader<T>(
		mut self,
		run: impl for<'held> AsyncFnOnce(LentRetainedSuffix<'held, 'source, R, L>) -> T,
	) -> (T, LentRetainedReader<L>) {
		let next = Some(self.prefix.extent);
		let result = run(LentRetainedSuffix {
			reader: &self.retained,
			prefix: &mut self.prefix,
			next,
		})
		.await;
		(
			result,
			LentRetainedReader {
				retained: self.retained,
			},
		)
	}
}

/// The exact retained reader borrowed beside its matched bounded source cursor.
#[must_use]
pub struct LentRetainedSuffix<'held, 'source, R, L> {
	reader: &'held L,
	prefix: &'held mut VerifiedRetainedPrefix<'source, R>,
	next: Option<u64>,
}

impl<'held, R: CapturedReadAt, L> LentRetainedSuffix<'held, '_, R, L> {
	/// Borrows the same reader used to compare the verified prefix.
	#[must_use]
	pub const fn reader(&self) -> &'held L {
		self.reader
	}

	/// Borrows the same held source to compare its adapter-specific admission.
	#[must_use]
	pub const fn source(&self) -> &R {
		self.prefix.source
	}

	/// Returns the exact compared prefix only before the first suffix read.
	#[must_use]
	pub fn initial_prefix(&self) -> Option<&VerifiedRetainedPrefix<'_, R>> {
		(self.next == Some(self.prefix.extent)).then_some(&*self.prefix)
	}

	/// Reports where the next bounded source read will start.
	///
	/// A failed or cancelled read leaves no usable cursor.
	#[must_use]
	pub const fn next_offset(&self) -> Option<u64> {
		self.next
	}

	/// Returns fresh bytes at the checked cursor, preserving the running source hash.
	///
	/// # Errors
	/// Refuses invalid scratch or a failed, cancelled or stale source read.
	pub async fn read_next<'buffer>(
		&mut self,
		scratch: &'buffer mut [u8],
	) -> Result<Option<&'buffer [u8]>, Error<R::Error, Infallible>> {
		read_next_suffix(self.prefix, &mut self.next, scratch).await
	}

	/// Confirms actual source EOF and handle closure, even for a zero-byte suffix.
	///
	/// # Errors
	/// Refuses incomplete coverage, stale source observations or failed terminal checks.
	pub async fn finish(mut self) -> Result<SuffixSourceObservation, Error<R::Error, Infallible>> {
		let offset = self.next.take().ok_or(Error::ContinuationStopped)?;
		let length = self.prefix.source_length;
		if offset != length {
			return Err(Error::IncompleteContinuation { offset, length });
		}
		check_source(self.prefix)?;
		self.prefix
			.source
			.finish()
			.await
			.map_err(Error::SourceFinish)?;
		check_source(self.prefix)?;
		Ok(SuffixSourceObservation {
			context: self.prefix.context,
			scope: self.prefix.scope,
			stage: self.prefix.stage,
			epoch: self.prefix.epoch,
			length,
			digest: self.prefix.digest(),
		})
	}
}

/// Complete source input, independently of any native write or stage read-back.
#[derive(Debug)]
#[must_use]
pub struct SuffixSourceObservation {
	context: RemoteDownloadContext,
	scope: RemoteScopeDigest,
	stage: RemotePreparedStage,
	epoch: SourceEpoch,
	length: u64,
	digest: [u8; 32],
}

impl SuffixSourceObservation {
	pub(crate) fn matches_witness(&self, binding: RemoteWitnessBinding) -> bool {
		self.context == binding.context()
			&& self.scope == binding.scope()
			&& self.stage.head == binding.prepared()
			&& self.stage.file == binding.stage()
			&& self.epoch.get() == binding.epochs().source.get()
			&& self.length == binding.coverage().end().get()
	}

	/// Original fresh source epoch.
	#[must_use]
	pub const fn epoch(&self) -> SourceEpoch {
		self.epoch
	}

	/// Exact source extent confirmed at EOF.
	#[must_use]
	pub const fn length(&self) -> u64 {
		self.length
	}

	/// Whole-source BLAKE3 digest of prefix and suffix supplied by this pass.
	#[must_use]
	pub const fn digest(&self) -> [u8; 32] {
		self.digest
	}
}

pub(super) async fn read_next_suffix<'buffer, R: CapturedReadAt, L>(
	prefix: &mut VerifiedRetainedPrefix<'_, R>,
	next_position: &mut Option<u64>,
	scratch: &'buffer mut [u8],
) -> Result<Option<&'buffer [u8]>, Error<R::Error, L>> {
	let offset = next_position.take().ok_or(Error::ContinuationStopped)?;
	check_source(prefix)?;
	let remaining = prefix.source_length - offset;
	if remaining == 0 {
		*next_position = Some(offset);
		return Ok(None);
	}
	validate_stream_input(remaining, scratch.len()).map_err(Error::Input)?;
	let width = scratch.len().min(prefix.source.max_window_bytes().get());
	validate_stream_input(remaining, width).map_err(Error::Input)?;
	let length = remaining.min(
		u64::try_from(width)
			.map_err(|_| Error::Input(StreamInputError::ScratchTooLarge { length: width }))?,
	);
	let count = usize::try_from(length)
		.map_err(|_| Error::Input(StreamInputError::FileTooLong { length }))?;
	let bytes = &mut scratch[..count];
	prefix
		.source
		.read_exact_at(offset, bytes)
		.await
		.map_err(|cause| Error::SourceRead { offset, cause })?;
	check_source(prefix)?;
	prefix.hasher.update(bytes);
	*next_position = Some(offset + length);
	Ok(Some(bytes))
}

pub(super) fn check_source<R: CapturedReadAt, L>(
	prefix: &VerifiedRetainedPrefix<'_, R>,
) -> Result<(), Error<R::Error, L>> {
	if prefix.source.epoch() != prefix.epoch {
		return Err(Error::Epoch);
	}
	let actual = prefix.source.length();
	if actual != prefix.source_length {
		return Err(Error::SourceExtent {
			expected: prefix.source_length,
			actual,
		});
	}
	Ok(())
}
