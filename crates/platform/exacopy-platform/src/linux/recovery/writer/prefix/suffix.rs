use std::fs::File;
use std::io;
use std::ops::Range;
use std::os::unix::fs::FileExt as _;
use std::sync::atomic::Ordering;

use exacopy_endpoint::{MAX_FILE_LENGTH, ReadView};
use exacopy_model::retained_prefix::TailWrite;
use rustix::fs;

use super::{
	RecoveryFile, RetainedPrefixRead, RetainedPrefixSelection, StageError,
	check_no_visible_attributes,
};
use crate::linux::handle::mount_id;
use crate::linux::source::{SourceObservation, reopen_regular_for_write};

mod custody;
pub use custody::SyncedSuffixRange;
const MAX_INTERRUPTS: usize = 8;

/// An actual syscall about to be submitted for the same retained stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SuffixEffect {
	/// Full file barrier over the original compared prefix.
	PrefixBarrier {
		/// Exact adopted prefix end.
		end: u64,
	},
	/// Positional write over a bounded suffix interval.
	Write {
		/// Next checked private suffix offset.
		offset: u64,
		/// Number of bytes in this submission.
		length: usize,
	},
	/// Full file barrier after one complete suffix range.
	CheckpointBarrier {
		/// Exact confirmed end of the completed interval.
		end: u64,
	},
}

/// Failure of scoped retained-stage observation or submission.
#[derive(Debug)]
#[non_exhaustive]
pub enum SuffixError<E> {
	/// State could not be checked before submission.
	Observation(StageError),
	/// The application refused the proposed effect.
	Admission {
		/// Previously confirmed physical end. The refused effect did not start.
		confirmed_end: u64,
		/// Original application refusal.
		cause: E,
	},
	/// A native effect or its outcome could not be confirmed.
	Submitted {
		/// Last confirmed cursor before the uncertain effect.
		confirmed_end: u64,
		/// Native or observation failure.
		cause: StageError,
	},
}

/// The same retained stage read guard with its adopted prefix synced.
#[must_use]
pub struct SyncedRetainedPrefix<'view, 'lease> {
	reader: &'view RetainedPrefixRead<'lease>,
	end: u64,
}

impl<'lease> RetainedPrefixRead<'lease> {
	/// Checks and synchronizes the exact compared extent on the held inode.
	///
	/// The application supplies a gate for the live scope/grant/route and checks
	/// its selected reservation before entering. This operation issues no writer.
	///
	/// # Errors
	/// Refuses a stale stage, extent, live gate or failed file barrier.
	pub fn sync_adopted<G, E>(
		&self,
		expected_end: u64,
		enter: impl FnOnce(RetainedPrefixSelection<'_>, SuffixEffect) -> Result<G, E>,
	) -> Result<SyncedRetainedPrefix<'_, 'lease>, SuffixError<E>> {
		self.sync_adopted_with(expected_end, enter, |file| fs::fsync(file))
	}

	pub(super) fn sync_adopted_with<G, E>(
		&self,
		expected_end: u64,
		enter: impl FnOnce(RetainedPrefixSelection<'_>, SuffixEffect) -> Result<G, E>,
		sync: impl FnOnce(&File) -> rustix::io::Result<()>,
	) -> Result<SyncedRetainedPrefix<'_, 'lease>, SuffixError<E>> {
		self.recheck_observation()
			.map_err(SuffixError::Observation)?;
		if self.suffix_spent.get() || self.length() != expected_end {
			return Err(SuffixError::Observation(StageError::IdentityChanged));
		}
		// A returned sync failure can consume Linux writeback-error evidence.
		self.suffix_spent.set(true);
		let guard = enter(
			self.selection(),
			SuffixEffect::PrefixBarrier { end: expected_end },
		)
		.map_err(|cause| SuffixError::Admission {
			confirmed_end: expected_end,
			cause,
		})?;
		// The original reader holds the stage mutex through this lease-local latch.
		// Never reacquire a new stage capability to replay an uncertain barrier.
		self.lease
			.suffix_barrier_started
			.store(true, Ordering::Relaxed);
		let result = sync(&self.stage.file);
		drop(guard);
		result.map_err(|error| SuffixError::Submitted {
			confirmed_end: expected_end,
			cause: StageError::BarrierFailed(error.into()),
		})?;
		self.recheck_observation()
			.map_err(|cause| SuffixError::Submitted {
				confirmed_end: expected_end,
				cause,
			})?;
		Ok(SyncedRetainedPrefix {
			reader: self,
			end: expected_end,
		})
	}
}

impl<'view, 'lease> SyncedRetainedPrefix<'view, 'lease> {
	/// Reopens the same pinned inode for tail-only writes without truncation.
	///
	/// The application callback must verify the exact current reservation,
	/// synced and independently reread kind-40 successor, and live job authority.
	/// It cannot replace the originally borrowed stage reader. Zero-tail passes
	/// keep the synced read view and need no writer.
	///
	/// # Errors
	/// Refuses a changed original stage, missing admission or invalid new extent.
	pub fn open_suffix_writer<E>(
		self,
		source_end: u64,
		admit_continuation: impl FnOnce(RetainedPrefixSelection<'_>, Range<u64>) -> Result<(), E>,
	) -> Result<RetainedSuffixWriter<'view, 'lease>, SuffixError<E>> {
		if source_end <= self.end || source_end > MAX_FILE_LENGTH {
			return Err(SuffixError::Observation(StageError::InvalidLength));
		}
		self.reader
			.recheck_observation()
			.map_err(SuffixError::Observation)?;
		admit_continuation(self.reader.selection(), self.end..source_end).map_err(|cause| {
			SuffixError::Admission {
				confirmed_end: self.end,
				cause,
			}
		})?;
		let original = self.reader.stage.observation();
		let (file, stat) = reopen_regular_for_write(&self.reader.stage.file)
			.map_err(|cause| SuffixError::Observation(StageError::ReadBack(cause)))?;
		if SourceObservation::capture(&stat)
			.map_err(|cause| SuffixError::Observation(StageError::ReadBack(cause)))?
			!= original
		{
			return Err(SuffixError::Observation(StageError::IdentityChanged));
		}
		self.reader
			.recheck_observation()
			.map_err(SuffixError::Observation)?;
		Ok(RetainedSuffixWriter {
			reader: self.reader,
			file,
			source_end,
			stamp: original,
			phase: Phase::Ready,
		})
	}
	/// Opens independent read-back when the compared prefix is already the entire source.
	///
	/// The same synced and independently reread continuation admission is required.
	/// No writable descriptor is opened on this branch.
	///
	/// # Errors
	/// Refuses an extent mismatch, stale held stage, or missing continuation admission.
	pub fn zero_tail_readback<E>(
		self,
		source_end: u64,
		admit_continuation: impl FnOnce(RetainedPrefixSelection<'_>, Range<u64>) -> Result<(), E>,
	) -> Result<RetainedSuffixReadback<'view, 'lease>, SuffixError<E>> {
		if source_end != self.end {
			return Err(SuffixError::Observation(StageError::InvalidLength));
		}
		self.reader
			.recheck_observation()
			.map_err(SuffixError::Observation)?;
		admit_continuation(self.reader.selection(), self.end..source_end).map_err(|cause| {
			SuffixError::Admission {
				confirmed_end: self.end,
				cause,
			}
		})?;
		let original = self.reader.stage.observation();
		let file =
			check_named(self.reader, original, self.end).map_err(SuffixError::Observation)?;
		original
			.recheck(file.observation())
			.map_err(|cause| SuffixError::Observation(StageError::ReadBack(cause)))?;
		Ok(RetainedSuffixReadback {
			reader: self.reader,
			file,
		})
	}
}

enum Phase {
	Ready,
	Writing { range: Range<u64> },
	NeedsCheckpoint { start: u64 },
	Stopped,
}

/// Held stage descriptor whose cursor can advance only inside an issued suffix range.
#[must_use]
pub struct RetainedSuffixWriter<'view, 'lease> {
	reader: &'view RetainedPrefixRead<'lease>,
	file: File,
	source_end: u64,
	stamp: SourceObservation,
	phase: Phase,
}

impl<'view, 'lease> RetainedSuffixWriter<'view, 'lease> {
	/// Starts the exact next range after the application confirms the journal predecessor.
	///
	/// The application must check that this model permit was minted for the
	/// same live job, protected held stage, continuation head and source pass.
	///
	/// # Errors
	/// Refuses overlapping, oversized, empty, stale or out-of-order ranges.
	pub fn begin_range<E>(
		&mut self,
		permit: &TailWrite,
		admit_range: impl FnOnce(&TailWrite) -> Result<(), E>,
	) -> Result<(), SuffixError<E>> {
		let prior = std::mem::replace(&mut self.phase, Phase::Stopped);
		let range = permit.range();
		if !matches!(prior, Phase::Ready)
			|| range.start != self.stamp.len()
			|| range.end <= range.start
			|| range.end > self.source_end
		{
			return Err(SuffixError::Observation(StageError::InvalidLength));
		}
		self.check_current().map_err(SuffixError::Observation)?;
		admit_range(permit).map_err(|cause| SuffixError::Admission {
			confirmed_end: self.stamp.len(),
			cause,
		})?;
		self.phase = Phase::Writing { range };
		Ok(())
	}

	/// Writes a complete nonempty subwindow at the current suffix cursor.
	///
	/// Every syscall checks the exact native predecessor and takes its own
	/// application authority. A positive short result advances only by its
	/// confirmed count. Failed operations permanently stop this descriptor.
	///
	/// # Errors
	/// Refuses invalid extents, changed native observations, authority refusal,
	/// and any unconfirmed write.
	pub fn write_next<G, E>(
		&mut self,
		bytes: &[u8],
		mut enter: impl FnMut(RetainedPrefixSelection<'_>, SuffixEffect) -> Result<G, E>,
	) -> Result<(), SuffixError<E>> {
		let Phase::Writing { range } = std::mem::replace(&mut self.phase, Phase::Stopped) else {
			return Err(SuffixError::Observation(StageError::PriorBarrierFailure));
		};
		u64::try_from(bytes.len())
			.ok()
			.filter(|length| *length > 0 && *length <= range.end - self.stamp.len())
			.ok_or(SuffixError::Observation(StageError::InvalidLength))?;
		let mut remaining = bytes;
		let mut interrupts = 0;
		while !remaining.is_empty() {
			let offset = self.stamp.len();
			self.check_current().map_err(|cause| {
				if offset == range.start {
					SuffixError::Observation(cause)
				} else {
					SuffixError::Submitted {
						confirmed_end: offset,
						cause,
					}
				}
			})?;
			let guard = enter(
				self.reader.selection(),
				SuffixEffect::Write {
					offset,
					length: remaining.len(),
				},
			)
			.map_err(|cause| SuffixError::Admission {
				confirmed_end: offset,
				cause,
			})?;
			let outcome = self.file.write_at(remaining, offset);
			drop(guard);
			let after = |cause| SuffixError::Submitted {
				confirmed_end: offset,
				cause,
			};
			match outcome {
				Ok(n) if n > 0 && n <= remaining.len() => {
					let next = offset + u64::try_from(n).expect("bounded subwindow length");
					self.stamp = self.observe(next).map_err(after)?;
					remaining = &remaining[n..];
				}
				Err(error)
					if error.kind() == io::ErrorKind::Interrupted
						&& interrupts < MAX_INTERRUPTS =>
				{
					self.check_current().map_err(after)?;
					interrupts += 1;
				}
				Ok(_) => return Err(after(StageError::System(io::ErrorKind::WriteZero.into()))),
				Err(error) => return Err(after(StageError::System(error))),
			}
		}
		self.phase = Phase::Writing { range };
		Ok(())
	}

	/// Syncs the exact completed range before a canonical checkpoint can be written.
	///
	/// # Errors
	/// Refuses an unfinished or poisoned range and any unavailable observation or barrier.
	pub fn sync_range<G, E>(
		&mut self,
		enter: impl FnOnce(RetainedPrefixSelection<'_>, SuffixEffect) -> Result<G, E>,
	) -> Result<u64, SuffixError<E>> {
		let Phase::Writing { range } = std::mem::replace(&mut self.phase, Phase::Stopped) else {
			return Err(SuffixError::Observation(StageError::PriorBarrierFailure));
		};
		let end = self.stamp.len();
		if end != range.end {
			return Err(SuffixError::Observation(StageError::InvalidLength));
		}
		self.check_current().map_err(SuffixError::Observation)?;
		let guard = enter(
			self.reader.selection(),
			SuffixEffect::CheckpointBarrier { end },
		)
		.map_err(|cause| SuffixError::Admission {
			confirmed_end: end,
			cause,
		})?;
		let result = fs::fsync(&self.file);
		drop(guard);
		result.map_err(|error| SuffixError::Submitted {
			confirmed_end: end,
			cause: StageError::BarrierFailed(error.into()),
		})?;
		self.check_current()
			.map_err(|cause| SuffixError::Submitted {
				confirmed_end: end,
				cause,
			})?;
		self.phase = Phase::NeedsCheckpoint { start: range.start };
		Ok(end)
	}

	/// Accepts an application-confirmed synced/read-back checkpoint before the next range.
	///
	/// # Errors
	/// Refuses a changed inode, incorrect order or mismatched checkpoint.
	pub fn confirm_checkpoint<E>(
		&mut self,
		admit_checkpoint: impl FnOnce(u64) -> Result<(), E>,
	) -> Result<(), SuffixError<E>> {
		let phase = std::mem::replace(&mut self.phase, Phase::Stopped);
		if !matches!(phase, Phase::NeedsCheckpoint { .. }) {
			return Err(SuffixError::Observation(StageError::PriorBarrierFailure));
		}
		self.check_current().map_err(SuffixError::Observation)?;
		admit_checkpoint(self.stamp.len()).map_err(|cause| SuffixError::Admission {
			confirmed_end: self.stamp.len(),
			cause,
		})?;
		self.phase = Phase::Ready;
		Ok(())
	}

	fn check_current(&self) -> Result<(), StageError> {
		let latest = self.observe(self.stamp.len())?;
		self.stamp.recheck(latest).map_err(StageError::ReadBack)
	}

	/// Closes the only writer and independently opens the exact same private inode.
	///
	/// # Errors
	/// Refuses incomplete capture, an unconfirmed checkpoint, or changed final custody.
	pub fn finish(self) -> Result<RetainedSuffixReadback<'view, 'lease>, StageError> {
		if !matches!(self.phase, Phase::Ready) || self.stamp.len() != self.source_end {
			return Err(StageError::Unflushed);
		}
		self.check_current()?;
		let reader = self.reader;
		let final_stamp = self.stamp;
		drop(self);
		let file = check_named(reader, final_stamp, final_stamp.len())?;
		final_stamp
			.recheck(file.observation())
			.map_err(StageError::ReadBack)?;
		Ok(RetainedSuffixReadback { reader, file })
	}

	fn observe(&self, expected_end: u64) -> Result<SourceObservation, StageError> {
		if mount_id(&self.file)? != self.reader.inventory.job.root.mount {
			return Err(StageError::IdentityChanged);
		}
		let held =
			SourceObservation::capture(&fs::fstat(&self.file)?).map_err(StageError::ReadBack)?;
		let named = check_named(self.reader, self.stamp, expected_end)?;
		held.recheck(named.observation())
			.map_err(StageError::ReadBack)?;
		Ok(held)
	}
}

fn check_named(
	reader: &RetainedPrefixRead<'_>,
	prior: SourceObservation,
	expected_end: u64,
) -> Result<RecoveryFile, StageError> {
	let selected = reader.selection();
	let job = reader.inventory.job;
	let inventory = job.inventory(selected.stage, selected.target)?;
	if inventory.target().is_some()
		|| inventory.stage_directory_identity().map(Into::into) != Some(selected.directory)
	{
		return Err(StageError::IdentityChanged);
	}
	inventory.recheck()?;
	let named = inventory.stage().ok_or(StageError::IdentityChanged)?;
	let stamp = named.observation();
	if stamp.len() != expected_end
		|| stamp.identity() != prior.identity()
		|| stamp.mode() != prior.mode()
		|| stamp.owner() != prior.owner()
		|| stamp.group() != prior.group()
	{
		return Err(StageError::IdentityChanged);
	}
	check_no_visible_attributes(&named.file)?;
	named.check_logical_eof().map_err(StageError::ReadBack)?;
	named.recheck_observation().map_err(StageError::ReadBack)?;
	inventory.recheck()?;
	inventory.stage.ok_or(StageError::IdentityChanged)
}

/// Independent read-back of the completed private stage under the original retained guard.
///
/// This view supplies neither selected stream metadata authorization nor publication.
#[must_use]
pub struct RetainedSuffixReadback<'view, 'lease> {
	reader: &'view RetainedPrefixRead<'lease>,
	file: RecoveryFile,
}

impl ReadView for RetainedSuffixReadback<'_, '_> {
	type Error = StageError;

	fn length(&self) -> u64 {
		self.file.len()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		let expected = self.file.observation();
		let current = check_named(self.reader, expected, expected.len())?;
		self.file
			.recheck_observation()
			.map_err(StageError::ReadBack)?;
		expected
			.recheck(current.observation())
			.map_err(StageError::ReadBack)
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.file
			.read_exact_at(offset, bytes)
			.map_err(StageError::ReadBack)
	}
}
