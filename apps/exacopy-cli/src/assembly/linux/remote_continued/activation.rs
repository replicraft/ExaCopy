use super::prefix::WitnessPrefix;
use std::io::{Cursor, Read};
use std::num::NonZeroU64;

use ed25519_dalek::SigningKey;
use exacopy_journal::frame::{FrameKind, FrameWriteError, FrameWriter};
use exacopy_journal::remote_download::continuation::RemoteContinuationExpectation;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::budget::WitnessedPassBudget;
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedReplayPhase, RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
};
use exacopy_journal::remote_download::{RemoteBootstrapTrust, RemoteDownloadError};
use exacopy_model::retained_prefix::Head;
use exacopy_platform::linux::{
	ActiveWitnessReservation, ContinuationReservationError, PendingWitnessReservation,
	ReservedContinuationRequest, SyncedRetainedPrefix, WitnessReservationAuthority,
	WitnessReservationError, WitnessReservationPlan,
};
use exacopy_transfer::remote_capture::CapturedReadAt;
use exacopy_transfer::remote_resume::prefix::{LentRetainedSuffix, VerifiedRetainedPrefix};

#[derive(Debug)]
pub(super) enum AdmissionError<E> {
	Binding,
	Format(RemoteDownloadError),
	Frame(FrameWriteError),
	Observation(E),
	Gate(E),
	Native(Box<ContinuationReservationError<Self>>),
}

pub(super) struct Kind40Admission<'context, 'names> {
	pub(super) trust: &'context RemoteBootstrapTrust<'context>,
	pub(super) signer: &'context SigningKey,
	pub(super) selection: &'context RemoteWitnessedReplaySelection<'context>,
	pub(super) expected: &'context RemoteContinuationExpectation<'names>,
	pub(super) budget: WitnessedPassBudget,
}

impl Kind40Admission<'_, '_> {
	pub(super) fn commit<'lease, R: CapturedReadAt, G, E>(
		&self,
		live: &LentRetainedSuffix<'_, '_, R, WitnessPrefix<'lease>>,
		reservation: PendingWitnessReservation<'lease>,
		prefix: &SyncedRetainedPrefix<'_, '_>,
		observe: impl FnOnce() -> Result<(), E>,
		enter: impl FnOnce(ReservedContinuationRequest<'_>) -> Result<G, E>,
	) -> Result<ActiveWitnessReservation<'lease>, AdmissionError<E>> {
		let proof = live.initial_prefix().ok_or(AdmissionError::Binding)?;
		if !prefix.matches_reader(live.reader().native()) {
			return Err(AdmissionError::Binding);
		}
		let (encoded, successor) =
			self.preview(proof, reservation.authority(), reservation.plan())?;
		reservation
			.append_continuation(
				prefix,
				model_head(successor),
				&encoded,
				|old| {
					confirm_selected(
						old.chain(Cursor::new(encoded.as_slice())),
						self.trust,
						self.selection,
						successor,
					)?;
					observe().map_err(AdmissionError::Observation)
				},
				|request| enter(request).map_err(AdmissionError::Gate),
				|actual| confirm_selected(actual, self.trust, self.selection, successor),
			)
			.map_err(|cause| AdmissionError::Native(Box::new(cause)))
	}

	pub(super) fn preview<R: CapturedReadAt, E>(
		&self,
		proof: &VerifiedRetainedPrefix<'_, R>,
		authority: WitnessReservationAuthority,
		plan: WitnessReservationPlan,
	) -> Result<(Vec<u8>, RemoteReplayBoundary), AdmissionError<E>> {
		let claims = self.expected.claims;
		if claims.context != proof.context()
			|| claims.scope != proof.scope()
			|| claims.previous != proof.boundary()
			|| self.budget.boundary() != claims.previous
			|| self.budget.retained_end() != claims.adopted_end
			|| self.budget.fresh_source_length() != claims.source.length()
			|| u64::from(self.budget.new_run().get()) != claims.epochs.run.get()
			|| reservation_plan(self.budget).ok() != Some(plan)
			|| claims.prior.prepared != proof.stage().head
			|| claims.prior.active != proof.active_preparation()
			|| claims.prior.epochs != proof.previous_epochs()
			|| claims.directory != proof.stage().directory
			|| claims.stage != proof.stage().file
			|| claims.coverage.basis != proof.coverage_basis()
			|| claims.coverage.end.get() != proof.checkpoint_extent()
			|| claims.epochs.source.get() != proof.epoch().get()
			|| claims.source.length().get() != proof.source_length()
			|| claims.adopted_end.get() != proof.extent()
			|| claims.prefix_digest.as_bytes() != &proof.digest()
			|| claims.grant_digest != self.selection.grant_digest
			|| claims.grant_digest != authority.base_grant
			|| &claims.qualification_digest != self.selection.qualification.digest().as_bytes()
			|| claims.qualification_digest != authority.qualification
		{
			return Err(AdmissionError::Binding);
		}
		let canonical = self
			.trust
			.sign_continuation(self.expected, self.signer)
			.map_err(AdmissionError::Format)?;
		let mut frame = FrameWriter::new(Vec::new(), claims.previous.head);
		let head = frame
			.append(FrameKind::RemoteCaptureContinued, &canonical)
			.map_err(AdmissionError::Frame)?;
		let encoded = frame.into_inner();
		let offset = u64::try_from(encoded.len())
			.ok()
			.and_then(|size| claims.previous.offset.checked_add(size))
			.ok_or(AdmissionError::Binding)?;
		Ok((encoded, RemoteReplayBoundary { head, offset }))
	}
}

pub(super) fn confirm_selected<E>(
	input: impl Read,
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteWitnessedReplaySelection<'_>,
	successor: RemoteReplayBoundary,
) -> Result<(), AdmissionError<E>> {
	let replay = replay_remote_witnessed_closeout(input, trust, selection)
		.map_err(AdmissionError::Format)?;
	if replay.issue().is_some()
		|| replay.boundary() != successor
		|| replay.phase() != RemoteWitnessedReplayPhase::ContinuedCapture
	{
		return Err(AdmissionError::Binding);
	}
	Ok(())
}

pub(super) fn model_head(boundary: RemoteReplayBoundary) -> Head {
	Head {
		digest: boundary.head.digest(),
		sequence: boundary.head.sequence(),
		end: boundary.offset,
	}
}

pub(super) fn reservation_plan(
	budget: WitnessedPassBudget,
) -> Result<WitnessReservationPlan, WitnessReservationError> {
	let frames = NonZeroU64::new(u64::from(budget.reserved_frames()))
		.ok_or(WitnessReservationError::Bounds)?;
	WitnessReservationPlan::new(model_head(budget.boundary()), budget.reserved_end(), frames)
}
