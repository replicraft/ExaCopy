use exacopy_content::{measure_at, validate_stream_input};
use exacopy_endpoint::linux_copy::InodeTimestamp;
use exacopy_endpoint::linux_recovery::{
	ApplyContinuity, ApplyNameObservation, ApplyNamesSelection, ApplyRecoveryEnvironment,
	ApplyRecoveryMetadata, HeldPublicApplyNames, HeldPublicApplyRecords, PublicApplyReadView,
	RecoveryRecord,
};
use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_journal::{
	ApplyQualification, DestinationRootBinding, LinuxFileIdentity, MAX_OWNER_BYTES,
	MAX_RANGE_PAGE_BYTES, PlanDigest, PublicApplyOwnerRecord,
};

use crate::linux::replay::{PublicApplyReplay, check_public_stage_plan, replay_public_apply};
use crate::linux::{
	JournalBoundary, JournalTail, LocalCopyPlan, MAX_LOCAL_COPY_PLAN_BYTES,
	MAX_LOCAL_JOURNAL_BYTES, PublicApplyCommitError,
};
use crate::public_plan::AdmittedCopyPlan;

use super::public_apply::STAGE_DIRECTORIES;
use super::{
	AuthenticatedPublicStage, InspectionError, RecoveryProfile, RecoveryStep, load_range_pages,
	read_artifact, record_identity,
};

mod receipt;
mod scope;

/// Independent archival selection for one original public apply attempt.
pub struct PublicApplyReconcileSelection<'call, 'bundle, 'name> {
	/// Independently selected recovery verifier and owner profile.
	pub profile: RecoveryProfile<'call>,
	/// Exact retained public Plan and sole canonical page.
	pub approved: &'call AdmittedCopyPlan<'bundle>,
	/// Exact private Plan digest retained outside the job.
	pub private_plan: PlanDigest,
	/// Independently assigned destination ID and held native identity.
	pub destination: DestinationRootBinding,
	/// Explicit selected raw private job name.
	pub job_name: UnixComponent<'name>,
	/// Independently retained historical qualification, which conveys no current grant.
	pub qualification: ApplyQualification,
}

/// Historical and current observations of the selected public apply job.
#[derive(Debug)]
#[non_exhaustive]
pub enum PublicApplyReconciliation {
	/// The fixed owner name was absent under the original shared lease.
	OwnerMissing,
	/// The selected verification profile authenticated the original owner claims.
	Authenticated {
		/// Exact signed association and selected private Plan digest.
		evidence: Box<AuthenticatedPublicStage>,
		/// Recorded history and separately observed current evidence.
		history: Box<PublicApplyHistory>,
	},
}

/// Independent status of the available archived artifacts.
#[derive(Debug)]
#[non_exhaustive]
pub enum PublicApplyHistory {
	/// The fixed private Plan name was absent.
	PlanMissing,
	/// The fixed first journal segment was absent.
	JournalMissing,
	/// Exact historical boundary and independently observed current evidence.
	Journal {
		/// Last complete semantically accepted frame.
		boundary: JournalBoundary,
		/// Clean EOF or incomplete last frame. The partial bytes carry no claims.
		tail: JournalTail,
		/// Highest recorded phase, without implying any current right or result.
		phase: PublicApplyArchivedPhase,
		/// Whether current native continuity was accepted for measured candidates.
		continuity: ApplyContinuity,
		/// Current private stage name.
		stage: PublicApplyCurrentName,
		/// Current public target name.
		target: PublicApplyCurrentName,
		/// Current receipt association to recorded history.
		receipt: PublicApplyReceiptObservation,
		/// Whether the archived closure and current observations jointly match.
		assessment: PublicApplyAssessment,
	},
}

/// Latest accepted historical phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicApplyArchivedPhase {
	/// No complete intent accepted.
	PreIntent,
	/// The exact v2 intent was accepted.
	Intent,
	/// A published observation was recorded.
	PublishedRecorded,
	/// Directory barriers were recorded.
	DurabilityRecorded,
	/// A receipt commitment was recorded. The current artifact is separate evidence.
	ReceiptCommitted,
}

/// Current stage or target observation scoped to the shared read lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicApplyCurrentName {
	/// The observed name was absent.
	Absent,
	/// A current occupant differs from the recorded candidate, or no candidate was recorded.
	Other(LinuxFileIdentity),
	/// Native identity numbers match the recorded candidate, without verified continuity or bytes.
	RecordedIdentityNumbersUnverified,
	/// The selected present candidate's stream failed exact measurement.
	StreamMismatch,
	/// The selected current candidate matched the approved stream and required metadata.
	VerifiedStream,
}

/// Current fixed receipt name and archived commit association.
#[derive(Debug)]
pub enum PublicApplyReceiptObservation {
	/// No receipt currently occupies the selected name.
	Absent,
	/// A private receipt is present, but no complete commit frame was accepted.
	PresentUncommitted,
	/// Actual current receipt bytes match the checked physical journal closure.
	MatchesCommit,
	/// Current bytes and accepted history failed joint semantic validation.
	Inconsistent(PublicApplyCommitError),
}

/// Overall observation, with no continuation permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicApplyAssessment {
	/// Clean preparation history, with no observed public target or receipt.
	PreIntent,
	/// Current evidence is insufficient to match a complete recorded publication.
	NeedsReconciliation,
	/// Clean committed history and current verified evidence match on the qualified held scope.
	CurrentMatchesCommittedEvidence,
}

type Inspection<V, T> = Result<
	T,
	InspectionError<
		<<V as PublicApplyReadView>::Record as ReadView>::Error,
		<V as PublicApplyReadView>::Error,
	>,
>;

/// Examines one selected public apply through the original native read-lease capabilities.
/// All artifact and namespace observations are read-only. An expired Plan remains
/// historical evidence. Missing current native continuity excludes all candidate stream reads.
/// # Errors
/// Refuses untrusted or incompatible archive evidence, malformed history and losses
/// of current observation or custody. No result supplies write authority.
pub fn reconcile_public_apply_with_lease<V: PublicApplyReadView>(
	view: &V,
	selected: PublicApplyReconcileSelection<'_, '_, '_>,
	scratch: &mut [u8],
) -> Inspection<V, PublicApplyReconciliation> {
	validate_stream_input(0, scratch.len()).map_err(InspectionError::Input)?;
	let environment = selected.qualification.environment;
	if selected.approved.body().fields().expires_at.is_none()
		|| selected.qualification.record.as_bytes() == &[0; 32]
		|| environment.boot_id == [0; 16]
		|| environment.mount_namespace == 0
		|| environment.unique_mount == 0
		|| environment.device != selected.destination.identity.device()
	{
		return Err(InspectionError::PlanBinding);
	}
	let (job, destination) = view.identities();
	if selected.destination.identity != record_identity(destination) {
		return Err(InspectionError::OwnerBinding);
	}
	let mut records = view
		.hold_apply_records()
		.map_err(RecoveryStep::Namespace.platform())?;
	let Some(owner_file) = records.owner() else {
		records
			.recheck_records()
			.map_err(RecoveryStep::Namespace.platform())?;
		return Ok(PublicApplyReconciliation::OwnerMissing);
	};
	let key = selected.profile.verifying_key;
	if key.is_weak() || key.to_edwards().compress().as_bytes() != key.as_bytes() {
		return Err(InspectionError::OwnerBinding);
	}
	let owner = PublicApplyOwnerRecord::decode(
		&read_artifact(owner_file, RecoveryStep::Owner, MAX_OWNER_BYTES)?,
		selected.profile.id,
		key,
	)
	.map_err(InspectionError::Owner)?;
	let manifest = owner.manifest();
	if manifest.owner.plan_digest != selected.private_plan
		|| manifest.owner.state_root != record_identity(job)
		|| manifest.owner.destination_device != destination.device
		|| manifest.owner.directories != STAGE_DIRECTORIES
		|| !scope::select_owner(&owner, &selected)
	{
		return Err(InspectionError::OwnerBinding);
	}
	let history = inspect_history(view, &mut records, &selected, &owner, scratch)?;
	records
		.recheck_records()
		.map_err(RecoveryStep::Namespace.platform())?;
	Ok(PublicApplyReconciliation::Authenticated {
		evidence: Box::new(AuthenticatedPublicStage {
			owner_digest: owner.digest(),
			private_plan: manifest.owner.plan_digest,
			binding: manifest.binding,
		}),
		history: Box::new(history),
	})
}

fn inspect_history<V: PublicApplyReadView>(
	view: &V,
	records: &mut V::Records<'_>,
	selected: &PublicApplyReconcileSelection<'_, '_, '_>,
	owner: &PublicApplyOwnerRecord,
	scratch: &mut [u8],
) -> Inspection<V, PublicApplyHistory> {
	let Some(plan_file) = records.plan() else {
		return Ok(PublicApplyHistory::PlanMissing);
	};
	let plan_bytes = read_artifact(plan_file, RecoveryStep::Plan, MAX_LOCAL_COPY_PLAN_BYTES)?;
	let plan = LocalCopyPlan::decode(&plan_bytes).map_err(InspectionError::Plan)?;
	if !scope::select_plan(&plan, selected) || check_public_stage_plan(&plan, owner).is_err() {
		return Err(InspectionError::PlanBinding);
	}
	let Some(segment) = records.segment() else {
		return Ok(PublicApplyHistory::JournalMissing);
	};
	let observed_length = segment.length();
	if observed_length > MAX_LOCAL_JOURNAL_BYTES {
		return Err(InspectionError::Oversize(RecoveryStep::Journal));
	}
	let history = replay_public_apply(&mut *segment, &plan, owner, selected.qualification)
		.map_err(InspectionError::Journal)?;
	let journal = &history.journal;
	let tail_bytes = match journal.tail {
		JournalTail::Clean => 0,
		JournalTail::Torn { bytes_read } => bytes_read as u64,
	};
	if journal.boundary.offset.checked_add(tail_bytes) != Some(observed_length) {
		return Err(InspectionError::RecordChanged(RecoveryStep::Journal));
	}
	segment
		.check_logical_eof()
		.map_err(RecoveryStep::Journal.read())?;
	let _ = load_range_pages(journal, plan.source().length, |page| {
		let step = RecoveryStep::Checkpoint;
		let file = view
			.open_apply_checkpoint(page.ordinal())
			.map_err(step.platform())?;
		read_artifact(&file, step, MAX_RANGE_PAGE_BYTES)
	})?;
	let receipt = receipt::observe(records, &plan, owner, selected.qualification, &history)?;
	let names = view
		.pin_apply_names(names_selection(&plan, selected.qualification, &history))
		.map_err(RecoveryStep::Namespace.platform())?;
	names
		.recheck_names()
		.map_err(RecoveryStep::Namespace.platform())?;
	let continuity = names.continuity();
	let stage = observe(names.stage(), continuity, &history, scratch)?;
	let target = observe(names.target(), continuity, &history, scratch)?;
	let current_stage_dir = names.stage_directory_identity().map(record_identity);
	let stage_dir_matches = journal
		.durability
		.is_some_and(|record| Some(record.barriers().stage_directory) == current_stage_dir);
	let phase = phase(&history);
	let assessment = assess(
		phase,
		journal.tail,
		continuity,
		stage,
		target,
		&receipt,
		stage_dir_matches,
	);
	records
		.recheck_records()
		.map_err(RecoveryStep::Namespace.platform())?;
	names
		.recheck_names()
		.map_err(RecoveryStep::Namespace.platform())?;
	records
		.recheck_records()
		.map_err(RecoveryStep::Namespace.platform())?;
	Ok(PublicApplyHistory::Journal {
		boundary: journal.boundary,
		tail: journal.tail,
		phase,
		continuity,
		stage,
		target,
		receipt,
		assessment,
	})
}

pub(super) fn names_selection<'name>(
	plan: &LocalCopyPlan<'name>,
	qualification: ApplyQualification,
	history: &PublicApplyReplay,
) -> ApplyNamesSelection<'name> {
	let journal = &history.journal;
	let required = journal
		.verification
		.zip(journal.metadata)
		.map(|(stream, record)| {
			let metadata = record.metadata;
			ApplyRecoveryMetadata {
				length: stream.stage().length.get(),
				mode: metadata.mode(),
				uid: metadata.uid,
				gid: metadata.gid,
				accessed_at: InodeTimestamp {
					seconds: metadata.accessed_at.seconds(),
					nanoseconds: metadata.accessed_at.nanoseconds(),
				},
				modified_at: InodeTimestamp {
					seconds: metadata.modified_at.seconds(),
					nanoseconds: metadata.modified_at.nanoseconds(),
				},
			}
		});
	let environment = qualification.environment;
	ApplyNamesSelection {
		stage: plan.attempt().stage_name,
		target: plan.destination().component,
		candidate: journal.stage.map(scope::identity),
		source_root: scope::identity(plan.source().root_identity),
		environment: journal.intent.map(|_| ApplyRecoveryEnvironment {
			boot_id: environment.boot_id,
			mount_namespace: environment.mount_namespace,
			unique_mount: environment.unique_mount,
			device: environment.device,
		}),
		required,
	}
}

fn observe<F: RecoveryRecord, E>(
	actual: ApplyNameObservation<'_, F>,
	continuity: ApplyContinuity,
	history: &PublicApplyReplay,
	scratch: &mut [u8],
) -> Result<PublicApplyCurrentName, InspectionError<F::Error, E>> {
	use PublicApplyCurrentName as Outcome;
	let journal = &history.journal;
	match actual {
		ApplyNameObservation::Absent => Ok(Outcome::Absent),
		ApplyNameObservation::Present(identity) => {
			let identity = record_identity(identity);
			Ok(if Some(identity) == journal.stage {
				Outcome::RecordedIdentityNumbersUnverified
			} else {
				Outcome::Other(identity)
			})
		}
		ApplyNameObservation::Readable(file) => {
			let identity = record_identity(file.identity().into());
			if Some(identity) != journal.stage {
				return Ok(Outcome::Other(identity));
			}
			if continuity != ApplyContinuity::MatchedQualifiedScope {
				return Ok(Outcome::RecordedIdentityNumbersUnverified);
			}
			let Some((verification, metadata)) = journal.verification.zip(journal.metadata) else {
				return Ok(Outcome::RecordedIdentityNumbersUnverified);
			};
			let expected = verification.stage();
			if identity != expected.identity {
				return Err(InspectionError::RecordChanged(RecoveryStep::Stream));
			}
			if file.length() != expected.length.get() {
				return Ok(Outcome::StreamMismatch);
			}
			let actual = file.observation();
			let required = metadata.metadata;
			if actual.mode != required.mode()
				|| actual.owner != required.uid
				|| actual.group != required.gid
				|| actual.links != 1
				|| (actual.accessed_at.seconds, actual.accessed_at.nanoseconds)
					!= (
						required.accessed_at.seconds(),
						required.accessed_at.nanoseconds(),
					)
				|| (actual.modified_at.seconds, actual.modified_at.nanoseconds)
					!= (
						required.modified_at.seconds(),
						required.modified_at.nanoseconds(),
					)
				|| file
					.extended_attributes()
					.map_err(RecoveryStep::Stream.read())?
					!= exacopy_endpoint::linux_staging::ExtendedAttributes::NoneVisible
			{
				return Ok(Outcome::RecordedIdentityNumbersUnverified);
			}
			let digest = measure_at(file.length(), scratch, |offset, bytes| {
				file.read_exact_at(offset, bytes)
			})
			.map_err(InspectionError::ReadBack)?;
			file.check_logical_eof()
				.map_err(RecoveryStep::Stream.read())?;
			file.recheck_inode().map_err(RecoveryStep::Stream.read())?;
			Ok(if digest.as_bytes() == expected.digest.as_bytes() {
				Outcome::VerifiedStream
			} else {
				Outcome::StreamMismatch
			})
		}
	}
}

fn phase(history: &PublicApplyReplay) -> PublicApplyArchivedPhase {
	use PublicApplyArchivedPhase as Phase;
	let journal = &history.journal;
	if journal.receipt.is_some() {
		Phase::ReceiptCommitted
	} else if journal.durability.is_some() {
		Phase::DurabilityRecorded
	} else if journal.observation.is_some() {
		Phase::PublishedRecorded
	} else if journal.intent.is_some() {
		Phase::Intent
	} else {
		Phase::PreIntent
	}
}

fn assess(
	phase: PublicApplyArchivedPhase,
	tail: JournalTail,
	continuity: ApplyContinuity,
	stage: PublicApplyCurrentName,
	target: PublicApplyCurrentName,
	receipt: &PublicApplyReceiptObservation,
	stage_dir_matches: bool,
) -> PublicApplyAssessment {
	use PublicApplyAssessment as Outcome;
	if phase == PublicApplyArchivedPhase::ReceiptCommitted
		&& tail == JournalTail::Clean
		&& continuity == ApplyContinuity::MatchedQualifiedScope
		&& stage == PublicApplyCurrentName::Absent
		&& target == PublicApplyCurrentName::VerifiedStream
		&& matches!(receipt, PublicApplyReceiptObservation::MatchesCommit)
		&& stage_dir_matches
	{
		Outcome::CurrentMatchesCommittedEvidence
	} else if phase == PublicApplyArchivedPhase::PreIntent
		&& tail == JournalTail::Clean
		&& target == PublicApplyCurrentName::Absent
		&& matches!(receipt, PublicApplyReceiptObservation::Absent)
	{
		Outcome::PreIntent
	} else {
		Outcome::NeedsReconciliation
	}
}
