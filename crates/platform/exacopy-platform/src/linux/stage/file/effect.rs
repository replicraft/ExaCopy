use std::io;
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::{IoError, write_all_at};
use rustix::fs;

use super::{StageError, WriteBarrier, WriteStage};

impl WriteStage<'_> {
	/// Writes the requested range, entering the caller's authority immediately before
	/// each positional write, including partial-transfer and interrupted retries.
	///
	/// # Errors
	/// Refusal before any write is reported as [StageError::Admission]. Once a
	/// write was submitted, failed completion reports [StageError::WriteOutcomeUnknown]
	/// with the backend's first position without confirmed progress. The private file remains.
	pub fn write_all_at_admitted<G>(
		&mut self,
		offset: u64,
		bytes: &[u8],
		enter: impl FnMut() -> io::Result<G>,
	) -> Result<(), StageError> {
		self.barrier.require_usable()?;
		self.barrier = WriteBarrier::Pending;
		write_admitted(offset, bytes, enter, |position, remaining| {
			self.file.write_at(remaining, position)
		})
	}

	/// Admits the full file barrier after checking the held stage's private name.
	///
	/// # Errors
	/// Refuses changed state, failed admission or a failed file barrier.
	pub fn flush_admitted<G>(
		&mut self,
		enter: impl FnOnce() -> io::Result<G>,
	) -> Result<(), StageError> {
		self.flush_admitted_with(enter, |file| fs::fsync(file))
	}
}

pub(in crate::linux) fn write_admitted<G>(
	offset: u64,
	bytes: &[u8],
	mut enter: impl FnMut() -> io::Result<G>,
	mut transfer: impl FnMut(u64, &[u8]) -> io::Result<usize>,
) -> Result<(), StageError> {
	let mut submitted = false;
	let mut refusal = None;
	let result = write_all_at(offset, bytes, |position, remaining| {
		// Endpoint retry is for interrupted I/O, never for a refusal to start it.
		let guard = match enter() {
			Ok(guard) => guard,
			Err(cause) => {
				refusal = Some(cause);
				return Err(io::ErrorKind::PermissionDenied.into());
			}
		};
		submitted = true;
		let result = transfer(position, remaining);
		drop(guard);
		result
	});
	if let Some(cause) = refusal {
		return match result {
			Err(IoError::System { offset, .. }) if submitted => {
				Err(StageError::WriteOutcomeUnknown(IoError::System {
					offset,
					source: cause,
				}))
			}
			_ => Err(StageError::Admission(cause)),
		};
	}
	result.map_err(|cause| {
		if submitted {
			StageError::WriteOutcomeUnknown(cause)
		} else {
			StageError::Write(cause)
		}
	})
}

#[cfg(test)]
mod tests {
	use std::cell::Cell;

	use super::*;

	#[test]
	fn first_admission_refusal_preserves_cause_without_submitting_a_pwrite() {
		let result = write_admitted(
			100,
			b"new",
			|| Err::<(), _>(io::Error::other("expired before first write")),
			|_, _| panic!("refusal reached a write"),
		);
		assert!(matches!(
			result,
			Err(StageError::Admission(cause)) if cause.to_string() == "expired before first write"
		));
	}

	#[test]
	fn an_interrupted_admission_cannot_trigger_a_write_retry() {
		let attempts = Cell::new(0);
		let result = write_admitted(
			100,
			b"new",
			|| {
				attempts.set(attempts.get() + 1);
				Err::<(), _>(io::ErrorKind::Interrupted.into())
			},
			|_, _| panic!("refusal reached a write"),
		);
		assert!(
			matches!(result, Err(StageError::Admission(cause)) if cause.kind() == io::ErrorKind::Interrupted)
		);
		assert_eq!(attempts.get(), 1);
	}

	#[test]
	fn first_submitted_kernel_error_is_distinct_from_admission_refusal() {
		let result = write_admitted(
			100,
			b"new",
			|| Ok(()),
			|_, _| Err(io::Error::other("kernel write error")),
		);
		assert!(matches!(
			result,
			Err(StageError::WriteOutcomeUnknown(IoError::System { offset: 100, source }))
				if source.to_string() == "kernel write error"
		));
	}

	#[test]
	fn current_authority_is_required_again_on_partial_and_interrupted_writes() {
		for first in [Ok(1), Err(io::ErrorKind::Interrupted)] {
			let attempts = Cell::new(0);
			let writes = Cell::new(0);
			let result = write_admitted(
				100,
				b"new",
				|| {
					let next = attempts.get() + 1;
					attempts.set(next);
					if next == 1 {
						Ok(())
					} else {
						Err(io::Error::other("deadline expired between write syscalls"))
					}
				},
				|offset, bytes| {
					assert_eq!(writes.get(), 0);
					assert_eq!(offset, 100);
					assert_eq!(bytes, b"new");
					writes.set(1);
					first.map_err(io::Error::from)
				},
			);
			let expected_offset = if first.is_ok() { 101 } else { 100 };
			assert!(
				matches!(result, Err(StageError::WriteOutcomeUnknown(IoError::System { offset, .. })) if offset == expected_offset)
			);
			assert_eq!(attempts.get(), 2);
			assert_eq!(writes.get(), 1);
		}
	}
}
