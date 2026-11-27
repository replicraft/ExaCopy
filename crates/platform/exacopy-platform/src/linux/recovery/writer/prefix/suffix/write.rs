use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt as _;

use super::{
	Phase, RetainedPrefixSelection, RetainedSuffixWriter, StageError, SuffixEffect, SuffixError,
};

const MAX_INTERRUPTS: usize = 8;

impl RetainedSuffixWriter<'_, '_> {
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
		enter: impl FnMut(RetainedPrefixSelection<'_>, SuffixEffect) -> Result<G, E>,
	) -> Result<(), SuffixError<E>> {
		self.write_next_observed(bytes, || Ok(()), enter)
	}

	/// Checks additional read-only custody before each write's authority gate.
	///
	/// The observer also runs before short-write and interrupted-write retries,
	/// after native writer checks and before the application acquires authority.
	///
	/// # Errors
	/// Also refuses unavailable or changed observations and stops this writer.
	pub fn write_next_observed<G, E>(
		&mut self,
		bytes: &[u8],
		observe: impl FnMut() -> Result<(), E>,
		enter: impl FnMut(RetainedPrefixSelection<'_>, SuffixEffect) -> Result<G, E>,
	) -> Result<(), SuffixError<E>> {
		self.write_next_with(bytes, observe, enter, File::write_at)
	}

	pub(in crate::linux::recovery::writer::prefix) fn write_next_with<G, E>(
		&mut self,
		bytes: &[u8],
		mut observe: impl FnMut() -> Result<(), E>,
		mut enter: impl FnMut(RetainedPrefixSelection<'_>, SuffixEffect) -> Result<G, E>,
		mut write: impl FnMut(&File, &[u8], u64) -> io::Result<usize>,
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
			observe().map_err(|cause| SuffixError::Admission {
				confirmed_end: offset,
				cause,
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
			let outcome = write(&self.file, remaining, offset);
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
}
