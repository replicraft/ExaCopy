use std::num::NonZeroU16;
use std::ops::Range;

use exacopy_content::{StreamInputError, validate_stream_input};
use exacopy_endpoint::connection_retry::{ConnectionBinding, RetryError};
use exacopy_journal::remote_download::RemoteDownloadOwnerRecord;
use exacopy_journal::remote_download::continuation::RemoteContinuationExpectation;
use exacopy_model::retained_prefix::{Head, Live, Refusal};
use exacopy_platform::linux::{
	DestinationRoot, RecoveryFile, RecoveryWriteLease, RemoteDestinationEligibility,
	ReservedContinuationRequest, StageError, SuffixEffect, SuffixError, WitnessCredentialLane,
	WitnessReservationAuthority, WitnessReservationError,
};
use exacopy_sftp::{SftpSource, SftpSourceError};
use exacopy_transfer::remote_resume::prefix::{LentRetainedSuffix, VerifiedHeldRetainedPrefix};
use exacopy_transfer::remote_witnessed_finalization::WitnessedPrepublicationFailure;

use super::prepublication::WitnessedAdapterError;
use super::publication::{
	self, SubmittedPublication, WitnessedReceiptProgress, WitnessedSubmitError,
};
use super::{WitnessAdmissionError, WitnessFailure, WitnessPass, WitnessPrefix};
use crate::assembly::linux::remote_continued::activation::{
	AdmissionError, Kind40Admission, model_head, reservation_plan,
};
use crate::assembly::linux::remote_continued::checkpoints::{
	CheckedRange, CheckpointFailure, CheckpointPass, PlannedRange,
};
use crate::assembly::linux::remote_download::BoundRouteRetirement;

mod prior;

pub(in crate::assembly::linux::remote_continued) struct PositiveTailWitness<'scope> {
	pub(in crate::assembly::linux::remote_continued) root: &'scope DestinationRoot,
	pub(in crate::assembly::linux::remote_continued) lease: &'scope RecoveryWriteLease<'scope>,
	pub(in crate::assembly::linux::remote_continued) eligibility:
		&'scope RemoteDestinationEligibility<'scope>,
	pub(in crate::assembly::linux::remote_continued) owner: &'scope RemoteDownloadOwnerRecord,
	pub(in crate::assembly::linux::remote_continued) owner_file: &'scope RecoveryFile,
	pub(in crate::assembly::linux::remote_continued) segment: &'scope RecoveryFile,
	pub(in crate::assembly::linux::remote_continued) expected:
		&'scope RemoteContinuationExpectation<'scope>,
	pub(in crate::assembly::linux::remote_continued) retirement: BoundRouteRetirement,
	pub(in crate::assembly::linux::remote_continued) scratch: &'scope mut [u8],
}

#[derive(Debug)]
pub(in crate::assembly::linux::remote_continued) enum PositiveTailFailure {
	Preflight(PositiveTailCause),
	/// This call reached native reservation or a later phase. Keep the original
	/// artifacts and reconcile before reuse. The head is capture evidence only.
	Reconcile {
		last_confirmed_capture: Head,
		cause: Box<PositiveTailCause>,
	},
}

#[derive(Debug)]
pub(in crate::assembly::linux::remote_continued) enum PositiveTailCause {
	Binding,
	Input(StreamInputError),
	Prior(prior::OriginalCaptureError),
	Gate(WitnessAdmissionError),
	Model(Refusal),
	Reservation(WitnessReservationError<WitnessAdmissionError>),
	PendingReservation(WitnessReservationError),
	Prefix(SuffixError<WitnessAdmissionError>),
	Continuation(AdmissionError<WitnessAdmissionError>),
	Checkpoint(CheckpointFailure<SftpSourceError, WitnessAdmissionError>),
	Stage(StageError),
	Link(WitnessFailure<SftpSourceError>),
	Prepublication(Box<WitnessedPrepublicationFailure<WitnessedAdapterError>>),
	Publication(WitnessedSubmitError),
}

impl<'scope, 'name> WitnessPass<'scope, 'name> {
	/// Continues a clean original checkpoint capture on its exact single-link inode.
	/// Reads the entire authenticated source, including the retained prefix,
	/// and independently rehashes the complete local file before kind 41.
	pub(in crate::assembly::linux::remote_continued) async fn run_positive_tail_receipt<Check, T>(
		&self,
		proof: VerifiedHeldRetainedPrefix<'_, SftpSource<'_, Check>, WitnessPrefix<'_>>,
		run: PositiveTailWitness<'_>,
		finish: impl for<'view, 'lease> FnOnce(
			SubmittedPublication<'view, 'lease, 'scope, 'name>,
			WitnessedReceiptProgress,
		) -> T,
	) -> Result<T, PositiveTailFailure>
	where
		Check: FnMut(ConnectionBinding) -> Result<(), RetryError>,
	{
		let (result, _original) = proof
			.with_reader(async |live| self.positive_tail(live, run, finish).await)
			.await;
		result
	}

	async fn positive_tail<Check, T>(
		&self,
		mut live: LentRetainedSuffix<'_, '_, SftpSource<'_, Check>, WitnessPrefix<'_>>,
		run: PositiveTailWitness<'_>,
		finish: impl for<'view, 'lease> FnOnce(
			SubmittedPublication<'view, 'lease, 'scope, 'name>,
			WitnessedReceiptProgress,
		) -> T,
	) -> Result<T, PositiveTailFailure>
	where
		Check: FnMut(ConnectionBinding) -> Result<(), RetryError>,
	{
		use PositiveTailCause as Error;
		use PositiveTailFailure::Preflight;

		let claims = run.expected.claims;
		let adopted = claims.adopted_end.get();
		let source_end = claims.source.length().get();
		let binding = live.source().binding();
		let observation = live.source().observation();
		let reader = live.reader().native();
		validate_stream_input(source_end, run.scratch.len())
			.map_err(|cause| Preflight(Error::Input(cause)))?;
		if self.budget.checkpoint_count() == 0
			|| adopted == 0
			|| source_end <= adopted
			|| adopted != self.names.adopted_extent
			|| source_end != self.names.source_extent
			|| source_end != observation.length
			|| claims.source.mode() != observation.mode
			|| claims.source.modified_seconds() != observation.modified
			|| claims.context != self.names.context
			|| claims.scope != self.names.scope
			|| reader.selection() != self.names.retained
			|| !reader.matches_lease(run.lease)
			|| live.next_offset() != Some(adopted)
			|| binding != run.retirement.binding()
			|| !std::ptr::eq(self.current.verified(), self.selection.qualification)
			|| &run.eligibility.qualification_digest()
				!= self.current.verified().digest().as_bytes()
			|| run.eligibility.facts() != self.current.facts()
		{
			return Err(Preflight(Error::Binding));
		}

		let consent = self.approval.commitment();
		let authority = WitnessReservationAuthority {
			qualification: run.eligibility.qualification_digest(),
			base_grant: consent.base_grant_digest,
			retention_approval: consent.approval_digest,
		};
		let lane =
			WitnessCredentialLane::observe().map_err(|cause| Preflight(Error::Stage(cause)))?;
		let custody = prior::CaptureCustody::new(&run, &lane);
		let recheck = || custody.recheck().map_err(WitnessAdmissionError::Custody);
		let enter = || {
			let approval = self
				.approval
				.enter(self.grant, self.names)
				.map_err(WitnessAdmissionError::Consent)?;
			run.retirement
				.enter_capture(binding, approval)
				.map_err(WitnessAdmissionError::Route)
		};

		let plan = reservation_plan(self.budget).map_err(|_| Preflight(Error::Binding))?;
		let admission = Kind40Admission {
			trust: self.trust,
			signer: self.signer,
			selection: self.selection,
			expected: run.expected,
			budget: self.budget,
		};
		let proof = live.initial_prefix().ok_or(Preflight(Error::Binding))?;
		custody
			.confirm_owner(self.names, run.owner)
			.map_err(|cause| Preflight(Error::Prior(cause)))?;
		let (encoded, successor) = {
			recheck().map_err(|cause| Preflight(Error::Gate(cause)))?;
			let _guard = enter().map_err(|cause| Preflight(Error::Gate(cause)))?;
			admission
				.preview(proof, authority, plan)
				.map_err(|cause| Preflight(Error::Continuation(cause)))?
		};
		let mut state = prior::admit_original(
			&custody,
			&admission,
			proof,
			(encoded, successor),
			self.names,
			authority,
		)
		.map_err(|cause| Preflight(Error::Prior(cause)))?;

		let basis = state.basis();
		let mut sampled = Live {
			guard: basis.prior().guard,
			head: basis.prior().head,
			source: basis.pass().source,
			local_end: adopted,
		};
		// From reservation onward a failure may leave allocated storage, newer
		// data or frames. Capturing the last accepted head confers no retry.
		let reservation = run
			.lease
			.reserve_witness_closeout_observed(
				run.eligibility,
				reader,
				run.segment,
				plan,
				authority,
				(
					|| custody.recheck(),
					|request| {
						if request.stage != self.names.retained
							|| request.authority != authority
							|| request.plan != plan
							|| request.job != run.lease.job().identity()
							|| request.destination != run.root.identity()
							|| request.segment != run.segment.identity()
						{
							return Err(WitnessAdmissionError::Binding);
						}
						enter()
					},
				),
			)
			.map_err(|cause| reconcile(sampled.head, Error::Reservation(cause)))?;
		recheck().map_err(|cause| reconcile(sampled.head, Error::Gate(cause)))?;
		reservation
			.recheck()
			.map_err(|cause| reconcile(sampled.head, Error::PendingReservation(cause)))?;
		let synced = reader
			.sync_adopted(adopted, |actual, effect| {
				if actual != self.names.retained
					|| effect != (SuffixEffect::PrefixBarrier { end: adopted })
				{
					return Err(WitnessAdmissionError::Binding);
				}
				enter()
			})
			.map_err(|cause| reconcile(sampled.head, Error::Prefix(cause)))?;
		state
			.prefix_barrier(sampled, basis)
			.map_err(|cause| reconcile(sampled.head, Error::Model(cause)))?;

		let job = run.lease.job().identity();
		let destination = run.root.identity();
		let segment = run.segment.identity();
		let check_journal = |request: ReservedContinuationRequest<'_>, previous: Head| {
			if request.stage != self.names.retained
				|| request.authority != authority
				|| request.plan != plan
				|| request.job != job
				|| request.destination != destination
				|| request.segment != segment
				|| request.previous != previous
			{
				return Err(WitnessAdmissionError::Binding);
			}
			enter()
		};
		let mut active = admission
			.commit(&live, reservation, &synced, recheck, |request| {
				if request.successor != model_head(successor) {
					return Err(WitnessAdmissionError::Binding);
				}
				check_journal(request, sampled.head)
			})
			.map_err(|cause| reconcile(sampled.head, Error::Continuation(cause)))?;
		sampled.head = active.head();
		state
			.continued(sampled, basis, model_head(successor))
			.map_err(|cause| reconcile(sampled.head, Error::Model(cause)))?;

		// Writable reopen is a checked nonmutating aperture. Admission locks
		// do not enclose its native probes. Actual writes and barriers each
		// acquire their own current guard.
		recheck().map_err(|cause| reconcile(sampled.head, Error::Gate(cause)))?;
		active
			.check_before_suffix(&synced)
			.map_err(WitnessAdmissionError::Custody)
			.map_err(|cause| reconcile(sampled.head, Error::Gate(cause)))?;
		let mut writer = synced
			.open_suffix_writer(source_end, |actual, interval| {
				if actual != self.names.retained
					|| interval != (adopted..source_end)
					|| active.head() != sampled.head
				{
					return Err(WitnessAdmissionError::Binding);
				}
				let _guard = enter()?;
				Ok(())
			})
			.map_err(|cause| reconcile(sampled.head, Error::Prefix(cause)))?;

		let pass = CheckpointPass {
			trust: self.trust,
			selection: self.selection,
			context: self.names.context,
			epochs: claims.epochs,
			lineage: sampled.head,
		};
		for slot in 1..=self.budget.checkpoint_count() {
			let ordinal =
				NonZeroU16::new(slot).ok_or_else(|| reconcile(sampled.head, Error::Binding))?;
			let range = self
				.budget
				.checkpoint_range(ordinal)
				.ok_or_else(|| reconcile(sampled.head, Error::Binding))?;
			pass.capture_range(
				CheckedRange {
					state: &mut state,
					journal: &mut active,
					writer: &mut writer,
					source: &mut live,
					scratch: run.scratch,
				},
				PlannedRange {
					budget: self.budget,
					live: sampled,
					ordinal,
				},
				recheck,
				|actual, effect| {
					if actual != self.names.retained || !within_range(effect, &range) {
						return Err(WitnessAdmissionError::Binding);
					}
					enter()
				},
				|request| check_journal(request, sampled.head),
			)
			.await
			.map_err(|cause| reconcile(active.head(), Error::Checkpoint(cause)))?;
			sampled.head = active.head();
			// A successful range confirms the synced native end and exact
			// subsequent checkpoint on the same writer.
			sampled.local_end = range.end;
		}
		recheck().map_err(|cause| reconcile(sampled.head, Error::Gate(cause)))?;
		let stage = writer
			.finish_for_witness(lane)
			.map_err(|cause| reconcile(sampled.head, Error::Stage(cause)))?;
		let linked = self
			.close_and_link(live, run.retirement, stage, active, run.scratch)
			.await
			.map_err(|cause| reconcile(sampled.head, Error::Link(cause)))?;
		let prepared = linked
			.prepare_publication(run.scratch)
			.map_err(|cause| reconcile(sampled.head, Error::Prepublication(cause)))?;
		let mut submitted = publication::submit(prepared)
			.map_err(|cause| reconcile(sampled.head, Error::Publication(cause)))?;
		let progress = publication::complete_receipt(&mut submitted);
		Ok(finish(submitted, progress))
	}
}

fn within_range(effect: SuffixEffect, range: &Range<u64>) -> bool {
	match effect {
		SuffixEffect::Write { offset, length } => {
			offset >= range.start
				&& length > 0
				&& offset
					.checked_add(length as u64)
					.is_some_and(|end| end <= range.end)
		}
		SuffixEffect::CheckpointBarrier { end } => end == range.end,
		_ => false,
	}
}

fn reconcile(last_confirmed_capture: Head, cause: PositiveTailCause) -> PositiveTailFailure {
	PositiveTailFailure::Reconcile {
		last_confirmed_capture,
		cause: Box::new(cause),
	}
}

#[cfg(test)]
pub(in crate::assembly::linux::remote_continued) use prior::check_original_vector;

#[cfg(test)]
mod tests {
	use super::{SuffixEffect, within_range};

	#[test]
	fn positive_tail_effect_gate_cannot_write_the_prefix_or_cross_the_range() {
		let range = 4..8;
		assert!(!within_range(
			SuffixEffect::Write {
				offset: 3,
				length: 1
			},
			&range
		));
		assert!(!within_range(
			SuffixEffect::Write {
				offset: 4,
				length: 0
			},
			&range
		));
		assert!(within_range(
			SuffixEffect::Write {
				offset: 4,
				length: 4
			},
			&range
		));
		assert!(within_range(
			SuffixEffect::Write {
				offset: 6,
				length: 2
			},
			&range
		));
		assert!(!within_range(
			SuffixEffect::Write {
				offset: 6,
				length: 3
			},
			&range
		));
		assert!(!within_range(
			SuffixEffect::Write {
				offset: u64::MAX,
				length: 2
			},
			&range
		));
		assert!(!within_range(
			SuffixEffect::PrefixBarrier { end: 4 },
			&range
		));
		assert!(!within_range(
			SuffixEffect::CheckpointBarrier { end: 7 },
			&range
		));
		assert!(within_range(
			SuffixEffect::CheckpointBarrier { end: 8 },
			&range
		));
	}
}
