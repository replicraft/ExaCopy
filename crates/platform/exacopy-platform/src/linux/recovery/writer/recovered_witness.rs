use std::ffi::OsStr;
use std::io::{self, Write as _};
use std::sync::MutexGuard;
use std::sync::atomic::Ordering;
use std::{error, fmt};

use rustix::fs::{self, OFlags};

use super::{
	FilePolicy, HeldFirstSegment, RecoveryFile, RecoveryWriteLease, ReservedJournalRead,
	SourceObservation, StageError, WitnessObservationAppend, mount_id, recheck_regular,
};
use crate::linux::WitnessedPublicPins;
use crate::linux::handle::file_identity;
use crate::linux::job::OWNER;

// Keep the native aperture within the first-segment limit and within the
// selector-2 observation bound in the witnessed closeout contract.
const MAX_SEGMENT_END: u64 = 64 * 1024 * 1024;
const FRAME_OVERHEAD: usize = 92;
const MAX_OBSERVATION_FRAME: usize = 476 + FRAME_OVERHEAD;

impl RecoveryWriteLease<'_> {
	/// Pins the original owner and an exclusive, append-only first segment for recovery.
	///
	/// The caller authenticates the owner and complete journal, establishes a clean
	/// selector-2 kind-7 cut, and checks the public bytes before requesting an append.
	/// The stage and journal writer exclusions last through successor reinspection.
	/// # Errors
	/// Refuses active writers and missing, unsafe, changed or oversized records.
	pub fn hold_recovered_witness_journal(
		&self,
	) -> Result<RecoveredWitnessJournal<'_>, StageError> {
		let stage_access = self.try_stage_access()?;
		let journal_access = self.try_journal_access()?;
		let owner = self.job().open_owner()?;
		let segment = self.job().open_first_segment()?;
		if owner.is_empty()
			|| segment.is_empty()
			|| segment.len() > MAX_SEGMENT_END
			|| owner.identity() == segment.identity()
		{
			return Err(StageError::IdentityChanged);
		}
		let held = self.hold_first_segment_with_access(&segment, journal_access)?;
		let journal = RecoveredWitnessJournal {
			lease: self,
			owner,
			segment,
			held,
			_stage_access: stage_access,
			phase: Phase::Ready,
		};
		journal.recheck(journal.segment.len())?;
		Ok(journal)
	}
}

/// One held native observation writer and read aperture on the exclusive recovery lease.
#[must_use]
pub struct RecoveredWitnessJournal<'lease> {
	lease: &'lease RecoveryWriteLease<'lease>,
	owner: RecoveryFile,
	segment: RecoveryFile,
	held: HeldFirstSegment<'lease>,
	_stage_access: MutexGuard<'lease, ()>,
	phase: Phase,
}

#[derive(Debug, PartialEq, Eq)]
enum Phase {
	Ready,
	Spent,
	Observed,
}

impl fmt::Debug for RecoveredWitnessJournal<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("RecoveredWitnessJournal")
			.field("phase", &self.phase)
			.finish_non_exhaustive()
	}
}

/// Failure of the one-shot recovered observation append under the exclusive lease.
#[derive(Debug)]
pub enum RecoveredWitnessJournalError<E> {
	/// Native custody or metadata could not be confirmed before submission.
	Preflight(StageError),
	/// The proposed consecutive heads or frame width were outside supported bounds.
	Bounds,
	/// The live submission gate refused before writing.
	Gate(E),
	/// Writing or synchronizing the frame failed after submission began.
	Submitted(io::Error),
	/// The exact appended bytes or current native custody could not be confirmed.
	Readback(StageError),
}

impl<E: fmt::Display> fmt::Display for RecoveredWitnessJournalError<E> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Preflight(cause) => {
				write!(formatter, "recovered journal preflight failed: {cause}")
			}
			Self::Bounds => formatter.write_str("recovered journal frame is outside bounds"),
			Self::Gate(cause) => write!(formatter, "recovered journal gate refused: {cause}"),
			Self::Submitted(cause) => {
				write!(
					formatter,
					"recovered journal submission is uncertain: {cause}"
				)
			}
			Self::Readback(cause) => {
				write!(formatter, "recovered journal read-back failed: {cause}")
			}
		}
	}
}

impl<E: error::Error + 'static> error::Error for RecoveredWitnessJournalError<E> {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match self {
			Self::Preflight(cause) | Self::Readback(cause) => Some(cause),
			Self::Gate(cause) => Some(cause),
			Self::Submitted(cause) => Some(cause),
			Self::Bounds => None,
		}
	}
}

impl RecoveredWitnessJournal<'_> {
	/// Returns the original held owner record for bounded authentication.
	#[must_use]
	pub const fn owner(&self) -> &RecoveryFile {
		&self.owner
	}

	/// Opens a fresh byte-zero read aperture bounded by the checked logical EOF.
	/// # Errors
	/// Refuses changed custody, unconfirmed EOF, or a spent, unconfirmed holder.
	pub fn journal(&self) -> Result<(ReservedJournalRead<'_>, u64), StageError> {
		let end = self.segment.len();
		self.recheck(end)?;
		Ok((ReservedJournalRead::new(&self.segment), end))
	}

	/// Confirms that the replayed EOF still belongs to the original held segment.
	/// # Errors
	/// Refuses changed owner or journal observations and spent, unconfirmed holders.
	pub fn recheck(&self, expected_end: u64) -> Result<(), StageError> {
		if self.phase == Phase::Spent {
			return Err(StageError::PriorBarrierFailure);
		}
		if expected_end != self.segment.len() {
			return Err(StageError::IdentityChanged);
		}
		self.check_records()
	}

	/// Appends a single prepared recovered observation, then syncs and rereads it.
	///
	/// The caller authenticates the exact previous head, the proposed tag-4 frame
	/// and the same public pins used for read-back. After native checks, the gate
	/// rechecks current qualification and obtains the matching live grant and
	/// independent retention approval. The holder repeats native custody checks
	/// under the guard. The final confirmation only checks the guard's current
	/// authority and deadlines immediately before submission. Both callbacks and
	/// the guard must leave credentials and held objects intact and avoid reentering
	/// the lease. The guard spans submission and synchronization. The caller
	/// independently authenticates the complete successor from byte zero.
	/// # Errors
	/// Any call spends this append capability. Once submission begins, the lease
	/// permanently refuses any further journal writer, including if the append,
	/// sync, read-back or later semantic replay is uncertain.
	pub fn append_recovered_observation<G, E>(
		&mut self,
		pins: &WitnessedPublicPins<'_, '_>,
		proposed: WitnessObservationAppend,
		enter_gate: impl FnOnce() -> Result<G, E>,
		confirm_gate: impl FnOnce(&mut G) -> Result<(), E>,
	) -> Result<(), RecoveredWitnessJournalError<E>> {
		use RecoveredWitnessJournalError as Error;

		if self.phase != Phase::Ready {
			return Err(Error::Preflight(StageError::PriorBarrierFailure));
		}
		self.phase = Phase::Spent;
		if !matches_bounds(self.segment.len(), &proposed) {
			return Err(Error::Bounds);
		}
		if !pins.matches_lease(self.lease) {
			return Err(Error::Preflight(StageError::IdentityChanged));
		}
		pins.recheck().map_err(Error::Preflight)?;
		self.check_records().map_err(Error::Preflight)?;

		let mut guard = enter_gate().map_err(Error::Gate)?;
		pins.recheck().map_err(Error::Preflight)?;
		self.check_records().map_err(Error::Preflight)?;
		confirm_gate(&mut guard).map_err(Error::Gate)?;
		// Journal and stage access remain held. A partial write or a panic after
		// this point still fences every later writer on this lease.
		self.lease
			.recovered_observation_started
			.store(true, Ordering::Relaxed);
		let result = self
			.held
			.file
			.write_all(&proposed.encoded)
			.and_then(|()| self.held.file.sync_all());
		drop(guard);
		result.map_err(Error::Submitted)?;

		self.observe_successor(&proposed).map_err(Error::Readback)?;
		pins.recheck().map_err(Error::Readback)?;
		self.phase = Phase::Observed;
		Ok(())
	}

	fn check_records(&self) -> Result<(), StageError> {
		let job = self.lease.job();
		let mount = job.root.mount;
		if file_identity(&self.lease.lock)? != job.identity()
			|| mount_id(&self.lease.lock)? != mount
		{
			return Err(StageError::IdentityChanged);
		}
		job.recheck()?;
		recheck_regular(
			&job.directory.file,
			OsStr::new(OWNER),
			mount,
			FilePolicy::Record,
			Some(&self.owner),
		)?;
		self.owner
			.check_logical_eof()
			.map_err(StageError::ReadBack)?;
		self.owner
			.recheck_observation()
			.map_err(StageError::ReadBack)?;
		let flags = fs::fcntl_getfl(&self.held.file)?;
		if !flags.contains(OFlags::APPEND | OFlags::NOATIME)
			|| flags.intersection(OFlags::ACCMODE) != OFlags::RDWR
		{
			return Err(StageError::UnsafeFile);
		}
		self.held.recheck(self.lease, &self.segment)
	}

	fn observe_successor(&mut self, proposed: &WitnessObservationAppend) -> Result<(), StageError> {
		let before = self.segment.observation();
		let stat = fs::fstat(&self.segment.file)?;
		FilePolicy::Record.check(&stat)?;
		let current = SourceObservation::capture(&stat).map_err(StageError::ReadBack)?;
		if current.identity() != before.identity()
			|| current.native_mode() != before.native_mode()
			|| current.owner() != before.owner()
			|| current.group() != before.group()
			|| current.link_count() != before.link_count()
			|| current.accessed_at() != before.accessed_at()
			|| current.len() != proposed.successor.end
		{
			return Err(StageError::IdentityChanged);
		}
		// Only the metadata observation advances. Both original descriptors stay held.
		self.segment.observation = current;
		self.check_records()?;
		let mut buffer = [0_u8; MAX_OBSERVATION_FRAME];
		let exact = &mut buffer[..proposed.encoded.len()];
		self.segment
			.read_exact_at(proposed.previous.end, exact)
			.map_err(StageError::ReadBack)?;
		if exact != proposed.encoded.as_slice() {
			return Err(StageError::IdentityChanged);
		}
		self.check_records()
	}
}

fn matches_bounds(end: u64, proposed: &WitnessObservationAppend) -> bool {
	let Ok(width) = u64::try_from(proposed.encoded.len()) else {
		return false;
	};
	proposed.encoded.len() > FRAME_OVERHEAD
		&& proposed.encoded.len() <= MAX_OBSERVATION_FRAME
		&& proposed.previous.end == end
		&& proposed.previous.sequence != 0
		&& proposed.previous.digest != [0; 32]
		&& end.checked_add(width) == Some(proposed.successor.end)
		&& proposed.previous.sequence.checked_add(1) == Some(proposed.successor.sequence)
		&& proposed.successor.digest != [0; 32]
		&& proposed.successor.digest != proposed.previous.digest
		&& proposed.successor.end <= MAX_SEGMENT_END
}

#[cfg(test)]
mod tests;
