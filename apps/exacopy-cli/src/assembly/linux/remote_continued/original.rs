//! Continues one clean original V1 checkpoint under first witnessed authority.

use std::num::{NonZeroU16, NonZeroU64};

use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_remote_qualification::RemoteDestinationQualification;
use exacopy_endpoint::remote_source::{SftpPath, SftpPathRoot, SourceEpoch};
use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_journal::remote_download::continuation::{
	RemoteContinuationClaims, RemoteContinuationCoverage, RemoteContinuationExpectation,
	RemoteContinuationPrior,
};
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationPhase, RemoteFinalizationReplay, replay_remote_finalization_with_checkpoints,
};
use exacopy_journal::remote_download::qualification::continuation::VerifiedRemoteWitnessQualification;
use exacopy_journal::remote_download::replay::{MAX_REMOTE_REPLAY_ATTEMPTS, RemoteReplayBoundary};
use exacopy_journal::remote_download::witness::budget::WitnessedPassBudget;
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
};
use exacopy_journal::remote_download::witness::witnessed_receipt_names;
use exacopy_journal::remote_download::{
	RemoteDownloadScope, RemoteEpochs, RemoteSourceObservation,
};
use exacopy_journal::{JournalJobId, StreamDigest, StreamLength};
use exacopy_platform::linux::{
	DestinationRoot, RemoteDestinationEligibility, RetainedPrefixSelection,
	observe_remote_destination,
};
use exacopy_sftp::{PendingSftpPathRequest, open_pending_path_source};
use exacopy_transfer::remote_resume::prefix::verify_held_retained_prefix;

use crate::profile::LocalProfile;

use super::super::remote_download::{
	ConnectedRemoteSource, RemoteGrant, measure_running_executable,
};
use super::super::remote_journal::{
	CheckedOriginalWitnessStartup, CheckedResumeStartup, CurrentGrant, component,
};
use super::super::remote_witness_authority::{
	BoundWitnessStage, ExplicitWitnessSelection, SelectedWitnessOwner, WitnessRetentionApproval,
};
use super::prefix::WitnessPrefix;
use super::witness::WitnessPass;
use super::witness::positive_tail::{PositiveTailFailure, PositiveTailWitness};

mod outcome;

pub(crate) use outcome::{OriginalWitnessError, OriginalWitnessResult};

const SCRATCH_BYTES: usize = 64 * 1024;

/// Independently selected authority for one first witnessed continuation.
pub(crate) struct OriginalWitnessResume<'scope> {
	pub(crate) root: &'scope DestinationRoot,
	pub(crate) profile: &'scope LocalProfile,
	pub(crate) job: JournalJobId,
	pub(crate) scope: &'scope RemoteDownloadScope,
	pub(crate) initial_v1_qualification: [u8; 32],
	pub(crate) fresh_v1_qualification: [u8; 32],
	pub(crate) qualification: &'scope VerifiedRemoteWitnessQualification,
	pub(crate) grant: &'scope RemoteGrant,
	pub(crate) consent: ExplicitWitnessSelection,
}

/// Continues the same held original stage from current-source proof to witnessed closeout.
///
/// The caller authenticates the exact approved job, projected scope and independent
/// qualification, selects explicit retention consent and holds the startup lease
/// through authentication. The connection must belong to this exact live grant.
/// This entry supports only an original V1 capture with a positive tail.
///
/// # Errors
/// Refuses an ineligible or changed startup, qualification, current source, grant,
/// consent or retained byte. A failed operation after reservation requires reconciliation.
pub(crate) async fn continue_original_capture(
	request: OriginalWitnessResume<'_>,
	startup: CheckedOriginalWitnessStartup<'_>,
	connection: ConnectedRemoteSource<'_>,
) -> Result<OriginalWitnessResult, OriginalWitnessError> {
	use OriginalWitnessError as Error;

	let scope_digest = request.scope.digest().map_err(|_| Error::Authority)?;
	let grant_digest = request
		.grant
		.recheck(scope_digest)
		.map_err(|_| Error::Authority)?;
	let (mut session, mut route) = connection
		.into_current(scope_digest, request.grant)
		.map_err(Error::Source)?;
	let held = startup
		.open_witnessed(request.root, request.profile, request.job, request.scope)
		.map_err(|_| Error::Startup)?;
	let owner_key = request.profile.verification_key();
	let trust = held
		.dialect
		.trust(&held.owner, request.profile.id(), &owner_key)
		.map_err(|_| Error::Startup)?;
	let facts = observe_remote_destination(request.root).map_err(|_| Error::Qualification)?;
	let build = measure_running_executable().map_err(|_| Error::Qualification)?;
	let current = request
		.qualification
		.match_current(build, &facts)
		.map_err(|_| Error::Qualification)?;
	let qualification = RemoteDestinationQualification::new(
		facts.clone(),
		*request.qualification.digest().as_bytes(),
	)
	.ok_or(Error::Qualification)?;
	let eligibility = RemoteDestinationEligibility::admit(request.root, Some(&qualification))
		.map_err(|_| Error::Qualification)?;
	let selection = RemoteWitnessedReplaySelection {
		initial_v1_qualification: request.initial_v1_qualification,
		fresh_v1_qualification: request.fresh_v1_qualification,
		qualification: request.qualification,
		grant_digest,
	};
	let job = held.lease.job();
	// The selected mixed reader validates independent owner/route/profile and
	// framing before the current data path opens. Its existing V1 scan never
	// supplies effects or a fallback branch.
	let mixed = replay_remote_witnessed_closeout(
		held.open_segment().map_err(|_| Error::Startup)?,
		&trust,
		&selection,
	)
	.map_err(|_| Error::Qualification)?;
	if mixed.issue().is_some() || mixed.boundary() != held.boundary {
		return Err(Error::Startup);
	}
	let replay = replay_remote_finalization_with_checkpoints(
		held.open_segment().map_err(|_| Error::Startup)?,
		&trust,
		selection.initial_v1_qualification,
		None,
	)
	.map_err(|_| Error::Startup)?;
	held.open_segment().map_err(|_| Error::Startup)?;
	let consumed = original_runs(&replay, held.boundary)?;
	let checkpoints = replay.active_checkpoints().map_err(|_| Error::Startup)?;
	let history = checkpoints.prefix_history().map_err(|_| Error::Startup)?;
	let prepared = history.prepared();
	let stage = component(history.name()).map_err(|_| Error::Startup)?;
	let target = component(request.scope.destination.target()).map_err(|_| Error::Startup)?;
	let native_selection = RetainedPrefixSelection {
		stage,
		target,
		directory: JobFileIdentity {
			device: prepared.directory.device(),
			inode: prepared.directory.inode(),
		},
		file: JobFileIdentity {
			device: prepared.file.device(),
			inode: prepared.file.inode(),
		},
	};
	let inventory = job.inventory(stage, target).map_err(|_| Error::Startup)?;
	held.check_donor(&inventory).map_err(|_| Error::Startup)?;
	let reader = held
		.lease
		.read_retained_prefix(&inventory, native_selection)
		.map_err(|_| Error::Startup)?;
	let adopted = StreamLength::new(reader.length()).map_err(|_| Error::Startup)?;
	let source_epoch = history
		.epochs()
		.source
		.checked_add(1)
		.ok_or(Error::Startup)?;
	let epoch = SourceEpoch::new(source_epoch);
	let raw = request.scope.source.path();
	let components = raw
		.strip_prefix(b"/")
		.unwrap_or(raw)
		.split(|byte| *byte == b'/')
		.map(component)
		.collect::<Result<Vec<_>, _>>()
		.map_err(|_| Error::Startup)?;
	let path = match request.scope.source.path_root() {
		SftpPathRoot::AccountRelative => SftpPath::AccountRelative(&components),
		SftpPathRoot::Absolute => SftpPath::Absolute(&components),
	};
	let pending = open_pending_path_source(
		&mut session,
		PendingSftpPathRequest {
			path,
			attempt: route.attempt(),
			epoch,
		},
		&mut route,
	)
	.await
	.map_err(Error::Source)?;
	let observed = pending.observation();
	let source_extent = StreamLength::new(observed.length).map_err(|_| Error::Prefix)?;
	let observation = RemoteSourceObservation::new(source_extent, observed.mode, observed.modified)
		.map_err(|_| Error::Prefix)?;
	if adopted.get() == 0 || adopted.get() >= source_extent.get() {
		return Err(Error::Prefix);
	}
	let budget = WitnessedPassBudget::plan(held.boundary, adopted, source_extent, consumed)
		.map_err(|_| Error::Prefix)?;
	let run = NonZeroU64::from(budget.new_run());
	let (pending_name, final_name) =
		witnessed_receipt_names(history.context().entry, run, *checkpoints.nonce());
	let pending_name = component(&pending_name).map_err(|_| Error::Startup)?;
	let final_name = component(&final_name).map_err(|_| Error::Startup)?;
	held.lease
		.require_job_root_names_absent([pending_name, final_name])
		.map_err(|_| Error::Startup)?;
	let names = BoundWitnessStage {
		context: history.context(),
		scope: scope_digest,
		job: held.owner.manifest().job_directory,
		retained: native_selection,
		adopted_extent: adopted.get(),
		source_extent: source_extent.get(),
	};
	let approval = WitnessRetentionApproval::admit(
		request.consent,
		SelectedWitnessOwner {
			owner: &held.owner,
			approved_scope: request.scope,
		},
		&held.lease,
		&reader,
		names,
		request.grant,
		grant_digest,
	)
	.map_err(|_| Error::Authority)?;
	let binding = route
		.admit_pending(&pending)
		.map_err(|cause| Error::Source(exacopy_sftp::SftpSourceError::Binding(cause)))?;
	let retirement = route
		.prepare_retirement(binding)
		.map_err(|cause| Error::Source(exacopy_sftp::SftpSourceError::Binding(cause)))?;
	let mut source = pending
		.activate(binding, |binding| route.check_binding(binding))
		.map_err(Error::Source)?;
	let mut scratch = vec![0; SCRATCH_BYTES];
	let proof = verify_held_retained_prefix(
		&history,
		&mut source,
		epoch,
		WitnessPrefix(reader),
		&mut scratch,
	)
	.await
	.map_err(outcome::prefix_error)?;

	let bootstrap = replay
		.stage_directory_prepared()
		.ok_or(Error::Startup)?
		.head();
	let expected = RemoteContinuationExpectation {
		claims: RemoteContinuationClaims {
			context: history.context(),
			scope: scope_digest,
			previous: held.boundary,
			prior: RemoteContinuationPrior {
				bootstrap,
				allocation: checkpoints.allocation(),
				prepared: prepared.head,
				active: history.active(),
				epochs: history.epochs(),
				name: stage,
				nonce: *checkpoints.nonce(),
			},
			directory: prepared.directory,
			stage: prepared.file,
			coverage: RemoteContinuationCoverage {
				basis: history.coverage_basis(),
				end: StreamLength::new(history.covered_extent()).map_err(|_| Error::Prefix)?,
			},
			epochs: RemoteEpochs {
				run,
				source: source_epoch,
			},
			source: observation,
			adopted_end: adopted,
			prefix_digest: StreamDigest::from_bytes(proof.prefix().digest()),
			grant_digest,
			qualification_digest: *request.qualification.digest().as_bytes(),
		},
		prior_source_extent: history.source().length(),
	};
	let pass = WitnessPass {
		trust: &trust,
		selection: &selection,
		current: &current,
		signer: request.profile.signer(),
		budget,
		approval: &approval,
		grant: request.grant,
		names,
	};
	let result = pass
		.run_positive_tail_receipt(
			proof,
			PositiveTailWitness {
				root: request.root,
				lease: &held.lease,
				eligibility: &eligibility,
				owner: &held.owner,
				owner_file: &held.owner_file,
				segment: &held.segment,
				expected: &expected,
				retirement,
				scratch: &mut scratch,
			},
			|submitted, progress| outcome::project(submitted.observation(), progress),
		)
		.await;
	match result {
		Ok(outcome) => Ok(outcome),
		Err(PositiveTailFailure::Preflight(cause)) => Err(outcome::preflight_error(cause)),
		Err(PositiveTailFailure::Reconcile {
			last_confirmed_capture,
			..
		}) => Ok(OriginalWitnessResult::ReconcileBeforeConfirmedPublication {
			last_confirmed_capture,
		}),
	}
}

/// Refuses a selected original restart before transport authentication.
pub(crate) fn preflight_original(
	replay: &RemoteFinalizationReplay<'_>,
	boundary: RemoteReplayBoundary,
) -> Result<(), OriginalWitnessError> {
	original_runs(replay, boundary).map(|_| ())
}

/// Pins the original donor under the selected shared startup lease.
///
/// The caller retains this token while authenticating the carrier.
pub(crate) fn hold_original_witness_startup<'held>(
	startup: CheckedResumeStartup<'held>,
	replay: &RemoteFinalizationReplay<'_>,
	target: UnixComponent<'_>,
) -> Result<CheckedOriginalWitnessStartup<'held>, OriginalWitnessError> {
	let boundary = replay.boundary();
	preflight_original(replay, boundary)?;
	let checkpoints = replay
		.active_checkpoints()
		.map_err(|_| OriginalWitnessError::Startup)?;
	let history = checkpoints
		.prefix_history()
		.map_err(|_| OriginalWitnessError::Startup)?;
	startup
		.hold_witnessed_donor(target, &history)
		.map_err(|_| OriginalWitnessError::Startup)
}

fn original_runs(
	replay: &RemoteFinalizationReplay<'_>,
	boundary: RemoteReplayBoundary,
) -> Result<NonZeroU16, OriginalWitnessError> {
	use OriginalWitnessError::Startup;
	if replay.issue().is_some()
		|| replay.boundary() != boundary
		|| replay.phase() != RemoteFinalizationPhase::Capture
		|| !replay.retirements().is_empty()
		|| replay.attempts().len() >= MAX_REMOTE_REPLAY_ATTEMPTS
	{
		return Err(Startup);
	}
	let active = replay.active_checkpoints().map_err(|_| Startup)?;
	let consumed = u16::try_from(replay.attempts().len())
		.ok()
		.and_then(NonZeroU16::new)
		.ok_or(Startup)?;
	if u64::from(consumed.get()) != active.epochs().run.get() || active.boundary() != boundary {
		return Err(Startup);
	}
	Ok(consumed)
}
