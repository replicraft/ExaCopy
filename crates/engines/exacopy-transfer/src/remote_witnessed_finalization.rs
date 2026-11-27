//! Prepublication sequencing for a live retained suffix with a protected witness.

use std::io::Read;

use exacopy_content::{MeasureError, measure_at, validate_stream_input};
use exacopy_endpoint::ReadView;
use exacopy_journal::StreamDigest;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::remote_download::finalization::RemoteLocalMetadata;
use exacopy_journal::remote_download::qualification::continuation::CurrentRemoteWitnessQualification;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::budget::{
	WitnessedPassBudget, WitnessedPassBudgetError, WitnessedPassProgress as Progress,
};
use exacopy_journal::remote_download::witness::replay::{
	PreparedWitnessedCloseout, RemoteWitnessedCloseoutReplay, RemoteWitnessedReplayPhase as Phase,
	RemoteWitnessedReplaySelection, WitnessedPrepublicationFact as Fact,
	replay_remote_witnessed_closeout,
};
use exacopy_journal::remote_download::witness::{RemoteWitnessCoverage, RemoteWitnessIntent};
use exacopy_journal::remote_download::{RemoteBootstrapTrust, RemoteDownloadError};

use crate::remote_resume::prefix::SuffixSourceObservation;

/// One held live stage and journal from the originating witness operation.
///
/// Implementations consume the live checked link that follows kind 41 and keep
/// the stage, protected alias, original journal writer and receipt reservation
/// under the same original exclusive lease. Historical inspection cannot
/// construct this native capability. The read view is an independent aperture
/// over the held two-link stage and confirms exact EOF around whole read-back.
pub trait HeldWitnessPrepublication: ReadView {
	/// Independently opened read aperture over the complete selected first segment.
	type JournalRead<'held>: Read
	where
		Self: 'held;

	/// Returns the complete source proof paired with this original linked stage.
	///
	/// The native holder must retain the proof from the exact lent source
	/// cursor that finished in the originating link operation. That operation
	/// independently confirmed termination of its bound route.
	fn source(&self) -> &SuffixSourceObservation;

	/// Reaffirms exact live custody, current authority and absent public target.
	///
	/// Verify the original witness, reservation, exact current head and OP2
	/// facts, both held aliases, and current grant and consent. Confirm that the
	/// stage observation still matches the closed, barriered two-link stage. The application
	/// resolves actual trusted time and independently authorized selection.
	///
	/// # Errors
	/// Refuses changed names, lease, authority, qualification or reservation.
	fn check_live(&self, expected: WitnessedLiveCut<'_, '_>) -> Result<(), Self::Error>;

	/// Opens an independent scan from byte zero with the original logical EOF.
	///
	/// # Errors
	/// Refuses uncertain journal identity, observation or access.
	fn read_journal(&self) -> Result<Self::JournalRead<'_>, Self::Error>;

	/// Confirms the fixed metadata policy on the exact same held stage.
	///
	/// Check owner and group, mode 0600, absence of visible attributes and ACLs,
	/// exact EOF and full file barrier coverage of the held stage. This check
	/// observes the existing fixed local metadata without mutating it.
	///
	/// # Errors
	/// Refuses incomplete metadata or changed observed stage.
	fn check_metadata(&self) -> Result<RemoteLocalMetadata, Self::Error>;

	/// Checks admission, appends and fully synchronizes one canonical frame.
	///
	/// Recheck the exact current grant, consent, native names, journal head
	/// and reservation with a live guard held through submission. Only a
	/// wholly pre-submission refusal may return `Refused`; a possibly
	/// submitted failure consumes the appender. Success requires an exact
	/// native read-back of the appended bytes and resulting logical EOF.
	///
	/// # Errors
	/// Reports definite pre-submission refusal or uncertain submitted effect.
	fn append(
		&mut self,
		expected: WitnessedLiveCut<'_, '_>,
		frame: &PreparedWitnessedCloseout,
	) -> Result<(), WitnessedAppendError<Self::Error>>;
}

/// The exact selected inputs a native prepublication gate must independently check.
#[derive(Clone, Copy, Debug)]
pub struct WitnessedLiveCut<'current, 'facts> {
	/// Previously checked live OP2 qualification, matched to exact native facts.
	pub current: &'current CurrentRemoteWitnessQualification<'facts>,
	/// Exact signed witness intent recorded by the originating live operation.
	pub witness: RemoteWitnessIntent,
	/// Same bounded reservation and checkpoint schedule used for that operation.
	pub budget: WitnessedPassBudget,
	/// Exact current pre-append journal cut.
	pub previous: RemoteReplayBoundary,
}

/// Submission status for the held native journal append.
#[derive(Debug)]
pub enum WitnessedAppendError<E> {
	/// The native effect was refused before it began.
	Refused(E),
	/// Current held custody or history became unconfirmed before submission.
	Unconfirmed(E),
	/// The native effect began or cannot be ruled out.
	Uncertain(E),
}

/// Inputs selected independently of the held journal bytes.
pub struct WitnessedPrepublicationRequest<'scope, 'history> {
	/// Exact authenticated owner and signed destination.
	pub trust: &'scope RemoteBootstrapTrust<'history>,
	/// Independent archive selections used throughout the complete scan.
	pub selection: &'scope RemoteWitnessedReplaySelection<'history>,
	/// Original held current native facts matched to OP2.
	pub current: &'scope CurrentRemoteWitnessQualification<'history>,
	/// The active signed kind 41, obtained under the original live stage.
	pub witness: RemoteWitnessIntent,
	/// Whole-pass plan bound to the original held native reservation.
	pub budget: WitnessedPassBudget,
}

/// Confirmed durable intent with the same held stage and journal still in custody.
///
/// This result supplies no fresh admission or public rename submission.
#[derive(Debug)]
#[must_use]
pub struct WitnessedPublicationIntent<H> {
	held: H,
	boundary: RemoteReplayBoundary,
}

impl<H> WitnessedPublicationIntent<H> {
	/// Exact independently scanned durable kind-7 fence.
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.boundary
	}

	/// Returns the original native holder and the exact durable intent cut.
	pub fn into_parts(self) -> (H, RemoteReplayBoundary) {
		(self.held, self.boundary)
	}
}

/// Failure of the witnessed prepublication phase traversal.
#[derive(Debug)]
pub struct WitnessedPrepublicationFailure<E> {
	/// Last exact independently confirmed journal cut on the held lease.
	pub confirmed: Option<RemoteReplayBoundary>,
	/// Whether a submission or later observation requires reconciliation.
	pub requires_reconciliation: bool,
	/// Exact check or native append failure.
	pub cause: WitnessedPrepublicationCause<E>,
}

/// Refusal or uncertainty recorded at the failing prepublication operation.
#[derive(Debug)]
pub enum WitnessedPrepublicationCause<E> {
	/// Source, witness, qualified selection or active phase disagreed.
	Binding,
	/// Native custody, access or metadata check failed.
	Native(E),
	/// Independent whole-stage read failed.
	ReadBack(MeasureError<E>),
	/// Either whole extent or digest differed from the completed live source.
	Verification,
	/// The exact canonical record or journal replay failed.
	Format(RemoteDownloadError),
	/// Insufficient exact remaining reservation.
	Budget(WitnessedPassBudgetError),
	/// Selected append was refused or its result is uncertain.
	Append {
		/// Frame the engine requested on this cut.
		kind: FrameKind,
		/// Whether the native effect could have started.
		error: WitnessedAppendError<E>,
	},
}

/// Records only the live prepublication phases 4, 5, 6 and 7, in that order.
///
/// Independently measure the same held stage, check required metadata, select
/// the exact signed target, and confirm every synced frame by whole semantic
/// replay from byte zero. On refusal or uncertainty the consumed holder drops.
/// A restart must reconcile independently; this entry point starts at live 41.
///
/// # Errors
/// Refuses changed or unconfirmed inputs and stops at the first failure.
pub fn prepare_witnessed_publication<H: HeldWitnessPrepublication>(
	request: WitnessedPrepublicationRequest<'_, '_>,
	mut held: H,
	scratch: &mut [u8],
) -> Result<WitnessedPublicationIntent<H>, WitnessedPrepublicationFailure<H::Error>> {
	use WitnessedPrepublicationCause as Cause;

	let first = request.witness.boundary();
	let source = held.source();
	let binding = request.witness.binding();
	let coverage = binding.coverage();
	let complete = match coverage {
		RemoteWitnessCoverage::ContinuedPrefix { .. } => request.budget.checkpoint_count() == 0,
		RemoteWitnessCoverage::Checkpoint { ordinal, .. } => {
			ordinal == request.budget.checkpoint_count()
		}
	};
	if !std::ptr::eq(request.selection.qualification, request.current.verified())
		|| !source.matches_witness(binding)
		|| !complete
		|| request.budget.fresh_source_length() != coverage.end()
		|| u64::from(request.budget.new_run().get()) != binding.epochs().run.get()
	{
		return Err(failure(None, false, Cause::Binding));
	}
	let length = source.length();
	let source = StreamDigest::from_bytes(source.digest());
	validate_stream_input(length, scratch.len()).map_err(|cause| {
		failure(
			None,
			false,
			Cause::ReadBack(MeasureError::InvalidInput(cause)),
		)
	})?;

	let mut replay = scan(&request, &held).map_err(|cause| failure(None, true, cause))?;
	if replay.boundary() != first
		|| replay.issue().is_some()
		|| replay.phase() != Phase::WitnessIntentRequiresInspection
		|| replay.witness() != Some(request.witness)
	{
		return Err(failure(None, true, Cause::Binding));
	}
	replay = advance(
		&request,
		&mut held,
		replay,
		Fact::Sealed,
		(Progress::WitnessIntent, Progress::Sealed, Phase::Sealed),
	)?;

	let confirmed = replay.boundary();
	held.recheck_observation()
		.map_err(|cause| failure(Some(confirmed), true, Cause::Native(cause)))?;
	if held.length() != length {
		return Err(failure(Some(confirmed), true, Cause::Verification));
	}
	let observed = measure_at(length, scratch, |offset, bytes| {
		held.read_exact_at(offset, bytes)
	})
	.map_err(|cause| failure(Some(confirmed), true, Cause::ReadBack(cause)))?;
	held.recheck_observation()
		.map_err(|cause| failure(Some(confirmed), true, Cause::Native(cause)))?;
	let stage = StreamDigest::from_bytes(*observed.as_bytes());
	if stage != source {
		return Err(failure(Some(confirmed), true, Cause::Verification));
	}
	replay = advance(
		&request,
		&mut held,
		replay,
		Fact::Verified { source, stage },
		(Progress::Sealed, Progress::Verified, Phase::Verified),
	)?;

	let confirmed = replay.boundary();
	let metadata = held
		.check_metadata()
		.map_err(|cause| failure(Some(confirmed), true, Cause::Native(cause)))?;
	let ids = request.current.facts().ids();
	if (metadata.uid, metadata.gid) != (ids.effective_uid, ids.effective_gid) {
		return Err(failure(Some(confirmed), true, Cause::Binding));
	}
	replay = advance(
		&request,
		&mut held,
		replay,
		Fact::Metadata(metadata),
		(
			Progress::Verified,
			Progress::MetadataReady,
			Phase::MetadataReady,
		),
	)?;

	let confirmed = replay.boundary();
	if held
		.check_metadata()
		.map_err(|cause| failure(Some(confirmed), true, Cause::Native(cause)))?
		!= metadata
	{
		return Err(failure(Some(confirmed), true, Cause::Binding));
	}
	replay = advance(
		&request,
		&mut held,
		replay,
		Fact::PublishIntent,
		(
			Progress::MetadataReady,
			Progress::PublishIntent,
			Phase::PublishIntentRequiresObservation,
		),
	)?;
	Ok(WitnessedPublicationIntent {
		held,
		boundary: replay.boundary(),
	})
}

fn advance<H: HeldWitnessPrepublication>(
	request: &WitnessedPrepublicationRequest<'_, '_>,
	held: &mut H,
	replay: RemoteWitnessedCloseoutReplay,
	fact: Fact,
	(before, after, phase): (Progress, Progress, Phase),
) -> Result<RemoteWitnessedCloseoutReplay, WitnessedPrepublicationFailure<H::Error>> {
	use WitnessedPrepublicationCause as Cause;

	let confirmed = replay.boundary();
	let cut = WitnessedLiveCut {
		current: request.current,
		witness: request.witness,
		budget: request.budget,
		previous: confirmed,
	};
	let frame = replay
		.prepare_prepublication(request.trust, request.witness, fact)
		.map_err(|cause| failure(Some(confirmed), false, Cause::Format(cause)))?;
	drop(replay);
	request
		.budget
		.recheck_remaining(confirmed, before)
		.and_then(|_| request.budget.recheck_remaining(frame.successor(), after))
		.map_err(|cause| failure(Some(confirmed), false, Cause::Budget(cause)))?;
	held.check_live(cut)
		.map_err(|cause| failure(Some(confirmed), true, Cause::Native(cause)))?;
	held.append(cut, &frame).map_err(|error| {
		failure(
			Some(confirmed),
			matches!(
				error,
				WitnessedAppendError::Unconfirmed(_) | WitnessedAppendError::Uncertain(_)
			),
			Cause::Append {
				kind: frame.kind(),
				error,
			},
		)
	})?;
	let actual = scan(request, held).map_err(|cause| failure(Some(confirmed), true, cause))?;
	if actual.issue().is_some()
		|| actual.phase() != phase
		|| actual.boundary() != frame.successor()
		|| actual.witness() != Some(request.witness)
	{
		return Err(failure(Some(confirmed), true, Cause::Binding));
	}
	Ok(actual)
}

fn scan<H: HeldWitnessPrepublication>(
	request: &WitnessedPrepublicationRequest<'_, '_>,
	held: &H,
) -> Result<RemoteWitnessedCloseoutReplay, WitnessedPrepublicationCause<H::Error>> {
	let read = held
		.read_journal()
		.map_err(WitnessedPrepublicationCause::Native)?;
	replay_remote_witnessed_closeout(read, request.trust, request.selection)
		.map_err(WitnessedPrepublicationCause::Format)
}

fn failure<E>(
	confirmed: Option<RemoteReplayBoundary>,
	requires_reconciliation: bool,
	cause: WitnessedPrepublicationCause<E>,
) -> WitnessedPrepublicationFailure<E> {
	WitnessedPrepublicationFailure {
		confirmed,
		requires_reconciliation,
		cause,
	}
}
