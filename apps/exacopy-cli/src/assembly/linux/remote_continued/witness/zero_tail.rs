use crate::assembly::linux::remote_continued::prefix::WitnessPrefix;
use std::io::{Cursor, Read as _};

use exacopy_content::{StreamInputError, validate_stream_input};
use exacopy_endpoint::connection_retry::{ConnectionBinding, RetryError};
use exacopy_journal::remote_download::continuation::RemoteContinuationExpectation;
use exacopy_platform::linux::{
	RecoveryFile, RecoveryWriteLease, RemoteDestinationEligibility, StageError, SuffixError,
	WitnessCredentialLane, WitnessReservationAuthority, WitnessReservationError,
};
use exacopy_sftp::{SftpSource, SftpSourceError};
use exacopy_transfer::remote_resume::prefix::VerifiedHeldRetainedPrefix;
use exacopy_transfer::remote_witnessed_finalization::{
	WitnessedPrepublicationFailure, WitnessedPublicationIntent,
};

use super::prepublication::WitnessedAdapterError;
use super::publication::{self, SubmittedPublication, WitnessedSubmitError};

use super::{LinkedWitnessedStage, WitnessAdmissionError, WitnessFailure, WitnessPass};
use crate::assembly::linux::remote_continued::activation::{
	AdmissionError, Kind40Admission, confirm_selected, reservation_plan,
};
use crate::assembly::linux::remote_download::BoundRouteRetirement;

pub(in crate::assembly::linux::remote_continued) struct ZeroTailWitness<'scope> {
	pub(in crate::assembly::linux::remote_continued) lease: &'scope RecoveryWriteLease<'scope>,
	pub(in crate::assembly::linux::remote_continued) eligibility:
		&'scope RemoteDestinationEligibility<'scope>,
	pub(in crate::assembly::linux::remote_continued) segment: &'scope RecoveryFile,
	pub(in crate::assembly::linux::remote_continued) expected:
		&'scope RemoteContinuationExpectation<'scope>,
	pub(in crate::assembly::linux::remote_continued) retirement: BoundRouteRetirement,
	pub(in crate::assembly::linux::remote_continued) scratch: &'scope mut [u8],
}

#[derive(Debug)]
pub(in crate::assembly::linux::remote_continued) enum ZeroTailWitnessFailure {
	Binding,
	Preflight(StageError),
	Reservation(WitnessReservationError<WitnessAdmissionError>),
	Prefix(SuffixError<WitnessAdmissionError>),
	Continuation(AdmissionError<WitnessAdmissionError>),
	Link(WitnessFailure<SftpSourceError>),
	PrepublicationInput(StreamInputError),
	Prepublication(Box<WitnessedPrepublicationFailure<WitnessedAdapterError>>),
	Publication(Box<WitnessedSubmitError>),
}

impl<'scope, 'name> WitnessPass<'scope, 'name> {
	/// Runs a complete zero-tail pass under the one original stage and route.
	/// The final callback may inspect two-link custody inside the reader scope.
	pub(in crate::assembly::linux::remote_continued) async fn run_zero_tail<Check, T>(
		&self,
		proof: VerifiedHeldRetainedPrefix<'_, SftpSource<'_, Check>, WitnessPrefix<'_>>,
		run: ZeroTailWitness<'_>,
		finish: impl for<'view, 'lease> FnOnce(LinkedWitnessedStage<'view, 'lease, 'scope, 'name>) -> T,
	) -> Result<T, ZeroTailWitnessFailure>
	where
		Check: FnMut(ConnectionBinding) -> Result<(), RetryError>,
	{
		self.with_zero_tail_link(proof, run, |linked, scratch| {
			linked
				.confirm_digest(scratch)
				.map_err(ZeroTailWitnessFailure::Link)?;
			Ok(finish(linked))
		})
		.await
	}

	/// Keeps the originating held stage and original OP2 reservation through checked kind 7.
	/// The caller supplies the native eligibility matched to the same independently selected OP2.
	pub(in crate::assembly::linux::remote_continued) async fn run_zero_tail_prepublication<
		Check,
		T,
	>(
		&self,
		proof: VerifiedHeldRetainedPrefix<'_, SftpSource<'_, Check>, WitnessPrefix<'_>>,
		run: ZeroTailWitness<'_>,
		finish: impl for<'view, 'lease> FnOnce(
			WitnessedPublicationIntent<LinkedWitnessedStage<'view, 'lease, 'scope, 'name>>,
		) -> T,
	) -> Result<T, ZeroTailWitnessFailure>
	where
		Check: FnMut(ConnectionBinding) -> Result<(), RetryError>,
	{
		validate_stream_input(self.names.source_extent, run.scratch.len())
			.map_err(ZeroTailWitnessFailure::PrepublicationInput)?;
		self.with_zero_tail_link(proof, run, |linked, scratch| {
			linked
				.prepare_publication(scratch)
				.map(finish)
				.map_err(ZeroTailWitnessFailure::Prepublication)
		})
		.await
	}

	/// Runs the private live compositor through a single witnessed publication.
	pub(in crate::assembly::linux::remote_continued) async fn run_zero_tail_publication<Check, T>(
		&self,
		proof: VerifiedHeldRetainedPrefix<'_, SftpSource<'_, Check>, WitnessPrefix<'_>>,
		run: ZeroTailWitness<'_>,
		finish: impl for<'view, 'lease> FnOnce(SubmittedPublication<'view, 'lease>) -> T,
	) -> Result<T, ZeroTailWitnessFailure>
	where
		Check: FnMut(ConnectionBinding) -> Result<(), RetryError>,
	{
		self.run_zero_tail_prepublication(proof, run, |prepared| {
			publication::submit(prepared)
				.map(finish)
				.map_err(|cause| ZeroTailWitnessFailure::Publication(Box::new(cause)))
		})
		.await?
	}

	async fn with_zero_tail_link<Check, T>(
		&self,
		proof: VerifiedHeldRetainedPrefix<'_, SftpSource<'_, Check>, WitnessPrefix<'_>>,
		run: ZeroTailWitness<'_>,
		finish: impl for<'view, 'lease> FnOnce(
			LinkedWitnessedStage<'view, 'lease, 'scope, 'name>,
			&mut [u8],
		) -> Result<T, ZeroTailWitnessFailure>,
	) -> Result<T, ZeroTailWitnessFailure>
	where
		Check: FnMut(ConnectionBinding) -> Result<(), RetryError>,
	{
		use ZeroTailWitnessFailure as Error;

		let (result, _original) = proof
			.with_reader(async |live| {
				let claims = run.expected.claims;
				let source_end = claims.source.length().get();
				let binding = live.source().binding();
				let observation = live.source().observation();
				let reader = live.reader().native();
				if self.budget.checkpoint_count() != 0
					|| source_end != claims.adopted_end.get()
					|| source_end != self.names.source_extent
					|| claims.source.length().get() != observation.length
					|| claims.source.mode() != observation.mode
					|| claims.source.modified_seconds() != observation.modified
					|| claims.context != self.names.context
					|| claims.scope != self.names.scope
					|| reader.selection() != self.names.retained
					|| !reader.matches_lease(run.lease)
					|| binding != run.retirement.binding()
					|| !std::ptr::eq(self.current.verified(), self.selection.qualification)
					|| &run.eligibility.qualification_digest()
						!= self.current.verified().digest().as_bytes()
					|| run.eligibility.facts() != self.current.facts()
				{
					return Err(Error::Binding);
				}
				let consent = self.approval.commitment();
				let authority = WitnessReservationAuthority {
					qualification: *self.current.verified().digest().as_bytes(),
					base_grant: consent.base_grant_digest,
					retention_approval: consent.approval_digest,
				};
				let lane = WitnessCredentialLane::observe().map_err(Error::Preflight)?;
				let enter = || {
					lane.recheck().map_err(WitnessAdmissionError::Stage)?;
					let approval = self
						.approval
						.enter(self.grant, self.names)
						.map_err(WitnessAdmissionError::Consent)?;
					run.retirement
						.enter_capture(binding, approval)
						.map_err(WitnessAdmissionError::Route)
				};
				let plan = reservation_plan(self.budget).map_err(|_| Error::Binding)?;
				let admission = Kind40Admission {
					trust: self.trust,
					signer: self.signer,
					selection: self.selection,
					expected: run.expected,
					budget: self.budget,
				};
				let proposed = {
					let _guard = enter().map_err(|_| Error::Binding)?;
					admission
						.preview(
							live.initial_prefix().ok_or(Error::Binding)?,
							authority,
							plan,
						)
						.map_err(Error::Continuation)?
				};
				verify_held_prior(&run, &admission, proposed)?;
				let reservation = run
					.lease
					.reserve_witness_closeout(
						run.eligibility,
						reader,
						run.segment,
						plan,
						authority,
						|request| {
							if request.authority != authority
								|| request.stage != self.names.retained
								|| request.plan != plan
							{
								return Err(WitnessAdmissionError::Binding);
							}
							enter()
						},
					)
					.map_err(Error::Reservation)?;
				let synced = reader
					.sync_adopted(source_end, |actual, _| {
						if actual != self.names.retained {
							return Err(WitnessAdmissionError::Binding);
						}
						enter()
					})
					.map_err(Error::Prefix)?;
				let active = admission
					.commit(&live, reservation, &synced, |request| {
						if request.authority != authority
							|| request.stage != self.names.retained
							|| request.plan != plan
						{
							return Err(WitnessAdmissionError::Binding);
						}
						enter()
					})
					.map_err(Error::Continuation)?;
				let stage = synced
					.zero_tail_for_witness(source_end, lane, |actual, interval| {
						if actual != self.names.retained
							|| interval.start != source_end
							|| interval.end != source_end
						{
							return Err(WitnessAdmissionError::Binding);
						}
						active
							.check_active()
							.map_err(WitnessAdmissionError::Custody)
					})
					.map_err(Error::Prefix)?;
				let linked = self
					.close_and_link(live, run.retirement, stage, active, run.scratch)
					.await
					.map_err(Error::Link)?;
				finish(linked, run.scratch)
			})
			.await;
		result
	}
}

fn verify_held_prior(
	run: &ZeroTailWitness<'_>,
	admission: &Kind40Admission<'_, '_>,
	(encoded, successor): (
		Vec<u8>,
		exacopy_journal::remote_download::replay::RemoteReplayBoundary,
	),
) -> Result<(), ZeroTailWitnessFailure> {
	use ZeroTailWitnessFailure as Error;

	// Only exact old journal bytes from the protected job may contribute to reserve.
	let mut held = run
		.lease
		.job()
		.open_first_segment()
		.map_err(Error::Preflight)?;
	if held.observation() != run.segment.observation()
		|| held.len() != admission.expected.claims.previous.offset
	{
		return Err(Error::Binding);
	}
	held.check_logical_eof()
		.map_err(StageError::ReadBack)
		.map_err(Error::Preflight)?;
	let length = held.len();
	confirm_selected(
		(&mut held).take(length).chain(Cursor::new(encoded)),
		admission.trust,
		admission.selection,
		successor,
	)
	.map_err(Error::Continuation)?;
	held.recheck_observation()
		.map_err(StageError::ReadBack)
		.map_err(Error::Preflight)?;
	run.segment
		.recheck_observation()
		.map_err(StageError::ReadBack)
		.map_err(Error::Preflight)?;
	held.check_logical_eof()
		.map_err(StageError::ReadBack)
		.map_err(Error::Preflight)?;
	Ok(())
}
