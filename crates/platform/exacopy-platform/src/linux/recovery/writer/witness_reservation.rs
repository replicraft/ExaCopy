use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::Ordering;

use rustix::fs;

use crate::linux::source::check_logical_eof;
use crate::linux::{RemoteDestinationEligibility, SourceObservation};

use super::{
	FIRST_SEGMENT, FilePolicy, HeldFirstSegment, JOURNAL, RecoveryFile, RecoveryWriteLease,
	RetainedPrefixRead, RetainedPrefixSelection, StageError, mount_id, open_checked_record,
	recheck_regular,
};

mod continuation;
mod native;
mod types;

pub use continuation::{
	ActiveWitnessReservation, ContinuationReservationError, PendingProtectedWitness,
	ReservedContinuationRequest, SealedProtectedWitness, WitnessPrepublicationAppend,
	WitnessPrepublicationPhase,
};
pub use types::{
	WitnessReservationAuthority, WitnessReservationEffect, WitnessReservationError,
	WitnessReservationGateRequest, WitnessReservationObservationError, WitnessReservationPlan,
};

use native::{AnonymousReceipt, allocate, open_anonymous};
use types::Effect;

#[cfg(test)]
mod tests;

impl RecoveryWriteLease<'_> {
	/// Reserves anonymous receipt and first-segment capacity under one held lease.
	///
	/// The caller authenticates the complete old scan on `expected_segment`, independently
	/// verifies the selected operation-2 attestation, and computes the whole-pass bound.
	/// Project its authenticated digest and native facts into the selected
	/// `RemoteDestinationQualification` to obtain eligibility. Eligibility matches native
	/// facts. The caller still validates current grant and explicit retention approval.
	///
	/// Acquire the job flock, retained-stage hold, journal writer mutex, then the
	/// caller's authority serialization, in that order. Enter this method without
	/// holding the authority lock. The gate checks the exact request, current grant,
	/// retention approval and trusted clock under its guard for each syscall. Neither
	/// the gate callback nor its guard's destructor may do I/O, reenter the lease,
	/// access the stage or journal, or change credentials. Guard drop only releases
	/// authority serialization after the submitted syscall.
	///
	/// Replay the old bytes from the returned aperture, compare the complete accepted
	/// history and head, and recheck the reservation. Use its stored plan and authority
	/// commitments to bind that evidence to the original reservation.
	///
	/// # Errors
	/// Refuses mismatched or changed bindings, failed authorization, and native
	/// allocation or observation failures. A failed journal reservation may have
	/// allocated blocks while preserving logical bytes. Reconcile before reuse.
	pub fn reserve_witness_closeout<'lease, G, E>(
		&'lease self,
		eligibility: &'lease RemoteDestinationEligibility<'_>,
		stage: &'lease RetainedPrefixRead<'_>,
		expected_segment: &RecoveryFile,
		plan: WitnessReservationPlan,
		authority: WitnessReservationAuthority,
		mut enter_gate: impl FnMut(WitnessReservationGateRequest<'_>) -> Result<G, E>,
	) -> Result<PendingWitnessReservation<'lease>, WitnessReservationError<E>> {
		use WitnessReservationError as Error;

		if authority.qualification != eligibility.qualification_digest() {
			return Err(Error::QualificationMismatch);
		}
		let held = HeldReservation {
			lease: self,
			eligibility,
			stage,
		};
		held.recheck().map_err(Error::Preflight)?;
		if expected_segment.len() != plan.accepted().end {
			return Err(Error::Preflight(StageError::IdentityChanged.into()));
		}
		let journal = self
			.hold_first_segment_for_append(expected_segment)
			.map_err(|error| Error::Preflight(error.into()))?;
		let before = expected_segment.observation();
		let segment = before.identity();
		let job = self.job();
		let mut request = WitnessReservationGateRequest {
			effect: Effect::ReceiptCreate,
			authority,
			plan,
			destination: job.destination_identity(),
			job: job.identity(),
			stage: stage.selection(),
			journal_directory: journal.journal.identity,
			segment,
			receipt: None,
		};

		held.recheck_before(&journal, expected_segment)
			.map_err(Error::Preflight)?;
		let receipt_file = submit(&mut enter_gate, request, || {
			open_anonymous(&job.directory.file)
		})?;
		let initial_receipt = AnonymousReceipt::observe(File::from(receipt_file), &held, segment)
			.map_err(|error| Error::after(Effect::ReceiptCreate, error))?;
		request.effect = Effect::ReceiptAllocate;
		request.receipt = Some(initial_receipt.observation.identity());

		held.recheck_before(&journal, expected_segment)
			.map_err(|error| Error::after(Effect::ReceiptCreate, error))?;
		initial_receipt
			.recheck(&held)
			.map_err(|error| Error::after(Effect::ReceiptCreate, error))?;
		submit(&mut enter_gate, request, || initial_receipt.allocate())?;
		let receipt = initial_receipt
			.after_allocation(&held, segment)
			.map_err(|error| Error::after(Effect::ReceiptAllocate, error))?;

		held.recheck_before(&journal, expected_segment)
			.map_err(|error| Error::after(Effect::ReceiptAllocate, error))?;
		receipt
			.recheck(&held)
			.map_err(|error| Error::after(Effect::ReceiptAllocate, error))?;
		request.effect = Effect::JournalAllocate;
		self.submit_journal_allocation(&journal, &mut enter_gate, request)?;

		PendingWitnessReservation::observe(
			held,
			journal,
			receipt,
			before,
			request.plan,
			request.authority,
		)
		.map_err(|error| Error::after(Effect::JournalAllocate, error))
	}

	fn submit_journal_allocation<G, E>(
		&self,
		journal: &HeldFirstSegment<'_>,
		enter_gate: &mut impl FnMut(WitnessReservationGateRequest<'_>) -> Result<G, E>,
		request: WitnessReservationGateRequest<'_>,
	) -> Result<(), WitnessReservationError<E>> {
		let (offset, length) = request.plan.allocation();
		submit(enter_gate, request, || {
			// The held mutex serializes this one-way lease state with append opens.
			self.journal_reservation_started
				.store(true, Ordering::Relaxed);
			allocate(&journal.file, offset, length)
		})
	}
}

fn submit<G, E, T>(
	enter_gate: &mut impl FnMut(WitnessReservationGateRequest<'_>) -> Result<G, E>,
	request: WitnessReservationGateRequest<'_>,
	syscall: impl FnOnce() -> rustix::io::Result<T>,
) -> Result<T, WitnessReservationError<E>> {
	let effect = request.effect;
	let guard =
		enter_gate(request).map_err(|source| WitnessReservationError::Gate { effect, source })?;
	let result = syscall();
	drop(guard);
	result.map_err(|error| WitnessReservationError::after(effect, StageError::from(error)))
}

#[derive(Debug)]
struct HeldReservation<'lease> {
	lease: &'lease RecoveryWriteLease<'lease>,
	eligibility: &'lease RemoteDestinationEligibility<'lease>,
	stage: &'lease RetainedPrefixRead<'lease>,
}

impl HeldReservation<'_> {
	fn recheck(&self) -> Result<(), WitnessReservationObservationError> {
		if rustix::process::geteuid().is_root() {
			return Err(WitnessReservationObservationError::PrivilegedExecution);
		}
		self.eligibility.recheck_for(self.lease.job().root)?;
		self.stage.recheck_for_lease(self.lease)?;
		Ok(())
	}

	fn recheck_before(
		&self,
		journal: &HeldFirstSegment<'_>,
		expected: &RecoveryFile,
	) -> Result<(), WitnessReservationObservationError> {
		self.recheck()?;
		expected.check_logical_eof().map_err(StageError::ReadBack)?;
		journal.recheck(self.lease, expected)?;
		Ok(())
	}
}

/// The original same-lane reservation and a separately opened read-only journal.
#[must_use]
pub struct PendingWitnessReservation<'lease> {
	held: HeldReservation<'lease>,
	journal: HeldFirstSegment<'lease>,
	readback: RecoveryFile,
	receipt: AnonymousReceipt,
	plan: WitnessReservationPlan,
	authority: WitnessReservationAuthority,
	_same_lane: PhantomData<Rc<()>>,
}

impl std::fmt::Debug for PendingWitnessReservation<'_> {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("PendingWitnessReservation")
			.finish_non_exhaustive()
	}
}

impl<'lease> PendingWitnessReservation<'lease> {
	fn observe(
		held: HeldReservation<'lease>,
		journal: HeldFirstSegment<'lease>,
		receipt: AnonymousReceipt,
		before: SourceObservation,
		plan: WitnessReservationPlan,
		authority: WitnessReservationAuthority,
	) -> Result<Self, WitnessReservationObservationError> {
		let mount = held.lease.job.root.mount;
		let readback =
			open_checked_record(&journal.journal.file, OsStr::new(FIRST_SEGMENT), mount)?
				.ok_or(StageError::IdentityChanged)?;
		native::check_after_allocation(before, readback.observation())?;
		let reserved = Self {
			held,
			journal,
			readback,
			receipt,
			plan,
			authority,
			_same_lane: PhantomData,
		};
		reserved.check_current()?;
		Ok(reserved)
	}

	fn check_current(&self) -> Result<(), WitnessReservationObservationError> {
		self.held.recheck()?;
		self.receipt.recheck(&self.held)?;
		self.readback
			.check_logical_eof()
			.map_err(StageError::ReadBack)?;
		self.journal.recheck(self.held.lease, &self.readback)?;
		Ok(())
	}

	/// Returns the original checked journal interval and accepted boundary.
	#[must_use]
	pub const fn plan(&self) -> WitnessReservationPlan {
		self.plan
	}

	/// Returns the commitments supplied to each original authorization gate.
	#[must_use]
	pub const fn authority(&self) -> WitnessReservationAuthority {
		self.authority
	}

	/// Opens a borrowed read aperture at offset zero for full semantic replay.
	///
	/// # Errors
	/// Refuses changed or unavailable post-reservation observations.
	pub fn replay(&self) -> Result<ReservedJournalRead<'_>, WitnessReservationError> {
		self.recheck()?;
		Ok(ReservedJournalRead {
			readback: &self.readback,
			offset: 0,
			_same_lane: PhantomData,
		})
	}

	/// Checks the original held lease and both reservations after semantic replay.
	///
	/// # Errors
	/// A changed or unavailable observation requires reconciliation.
	pub fn recheck(&self) -> Result<(), WitnessReservationError> {
		self.check_current()
			.map_err(|error| WitnessReservationError::after(Effect::JournalAllocate, error))
	}
}

impl HeldFirstSegment<'_> {
	fn recheck(
		&self,
		lease: &RecoveryWriteLease<'_>,
		expected: &RecoveryFile,
	) -> Result<(), StageError> {
		let job = lease.job();
		let parent = &job.directory.file;
		let mount = job.root.mount;
		let journal_name = OsStr::new(JOURNAL);
		job.recheck()?;
		self.journal.recheck(parent, journal_name, mount)?;
		let stat = fs::fstat(&self.file)?;
		FilePolicy::Record.check(&stat)?;
		if mount_id(&self.file)? != mount || fs::tell(&self.file)? != expected.len() {
			return Err(StageError::IdentityChanged);
		}
		let current = SourceObservation::capture(&stat).map_err(StageError::ReadBack)?;
		expected
			.observation()
			.recheck(current)
			.map_err(StageError::ReadBack)?;
		check_logical_eof(&self.file, expected.len()).map_err(StageError::ReadBack)?;
		expected
			.recheck_observation()
			.map_err(StageError::ReadBack)?;
		recheck_regular(
			&self.journal.file,
			OsStr::new(FIRST_SEGMENT),
			mount,
			FilePolicy::Record,
			Some(expected),
		)?;
		self.journal.recheck(parent, journal_name, mount)?;
		job.recheck()
	}
}

/// Independent read-only replay cursor on the admitted logical journal bytes.
#[derive(Debug)]
pub struct ReservedJournalRead<'reservation> {
	readback: &'reservation RecoveryFile,
	offset: u64,
	_same_lane: PhantomData<Rc<()>>,
}

impl Read for ReservedJournalRead<'_> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		let remaining = self
			.readback
			.len()
			.checked_sub(self.offset)
			.ok_or_else(|| io::Error::other("reservation cursor passed its accepted EOF"))?;
		let count = usize::try_from(remaining)
			.unwrap_or(usize::MAX)
			.min(buffer.len());
		if count == 0 {
			if remaining == 0 {
				self.readback
					.check_logical_eof()
					.map_err(io::Error::other)?;
			}
			return Ok(0);
		}
		self.readback
			.read_exact_at(self.offset, &mut buffer[..count])
			.map_err(io::Error::other)?;
		let read = u64::try_from(count).map_err(io::Error::other)?;
		self.offset = self
			.offset
			.checked_add(read)
			.ok_or_else(|| io::Error::other("reservation cursor overflow"))?;
		Ok(count)
	}
}
