use std::num::NonZeroU64;

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinDurabilityRecorded, DarwinEntryPrepared, DarwinJobPrepared, DarwinMetadataRecorded,
	DarwinOwnerRecord, DarwinPublicationOutcome, DarwinPublishIntent, DarwinPublishObserved,
	DarwinReceiptCommitted, DarwinRootBinding, DarwinStageSealed, DarwinVerificationRecorded,
	ObservedTimestamp, OwnerTimestamp,
};

use super::{DarwinReplayAuthority, DarwinReplayError, DarwinReplayStatus};
use crate::macos::plan::DarwinCopyPlan;

pub(super) fn expected_job(
	plan: &DarwinCopyPlan<'_>,
	owner: &DarwinOwnerRecord,
	authority: DarwinReplayAuthority<'_>,
) -> Result<DarwinJobPrepared, DarwinReplayError> {
	let manifest = owner.manifest();
	let source = plan.source();
	let destination = plan.destination();
	if plan.attempt().profile != authority.profile
		|| manifest.state_root != authority.state_root
		|| manifest.state_root_uid != authority.state_root_uid
		|| source.metadata.uid() != authority.state_root_uid
		|| manifest.state_root.may_alias(source.root_identity)
		|| manifest.state_root.may_alias(source.file_identity)
	{
		return Err(DarwinReplayError::OwnerBinding);
	}
	Ok(DarwinJobPrepared::new(
		plan.context(),
		owner,
		DarwinRootBinding {
			id: destination.root_id,
			identity: destination.root_identity,
		},
	)?)
}

pub(super) fn history(
	frames: &[Frame],
	expected_job: DarwinJobPrepared,
	plan: &DarwinCopyPlan<'_>,
	owner: &DarwinOwnerRecord,
) -> Result<DarwinReplayStatus, DarwinReplayError> {
	let [job, remaining @ ..] = frames else {
		return Ok(DarwinReplayStatus::Incomplete);
	};
	let job = DarwinJobPrepared::from_frame(job)?;
	require_binding(FrameKind::JobPrepared, job == expected_job)?;
	let [entry, remaining @ ..] = remaining else {
		return Ok(DarwinReplayStatus::Incomplete);
	};
	let preparation = DarwinEntryPrepared::from_frame(entry)?;
	preparation.validate_job(&job)?;
	require_binding(
		FrameKind::EntryPrepared,
		entry_matches(&preparation, plan, owner),
	)?;

	let [seal, remaining @ ..] = remaining else {
		return Ok(DarwinReplayStatus::Incomplete);
	};
	let seal = DarwinStageSealed::from_frame(seal)?;
	seal.check_prerequisite(entry)?;
	let [verification, remaining @ ..] = remaining else {
		return Ok(DarwinReplayStatus::Incomplete);
	};
	let verification = DarwinVerificationRecorded::from_frame(verification)?;
	verification.check_prerequisites(entry, &seal)?;
	let [metadata_frame, remaining @ ..] = remaining else {
		return Ok(DarwinReplayStatus::Incomplete);
	};
	let metadata = DarwinMetadataRecorded::from_frame(metadata_frame)?;
	metadata.check_prerequisites(entry, &seal, &verification)?;
	let [intent_frame, remaining @ ..] = remaining else {
		return Ok(DarwinReplayStatus::Incomplete);
	};
	let intent = DarwinPublishIntent::from_frame(intent_frame)?;
	intent.check_prerequisites(NonZeroU64::MIN, entry, &seal, &verification, &metadata)?;
	publication(remaining, metadata_frame, intent_frame)
}

fn entry_matches(
	entry: &DarwinEntryPrepared<'_>,
	plan: &DarwinCopyPlan<'_>,
	owner: &DarwinOwnerRecord,
) -> bool {
	let prepared = entry.preparation();
	let observed = prepared.source;
	let expected = plan.source();
	let times = observed.times();
	let permissions = observed.metadata();
	let state_root = owner.manifest().state_root;
	entry.entry() == plan.attempt().entry
		&& observed.root()
			== DarwinRootBinding {
				id: expected.root_id,
				identity: expected.root_identity,
			}
		&& observed.component() == expected.component
		&& observed.identity() == expected.file_identity
		&& observed.length() == expected.length
		&& permissions.owner() == expected.metadata.uid()
		&& permissions.group() == expected.metadata.gid()
		&& permissions.mode() == u32::from(expected.metadata.mode())
		&& same_time(times.accessed_at, expected.metadata.accessed_at())
		&& same_time(times.modified_at, expected.metadata.modified_at())
		&& same_time(times.changed_at, expected.metadata.changed_at())
		&& prepared.target_component == plan.destination().component
		&& !prepared.stage.directory.may_alias(state_root)
		&& !prepared.stage.identity.may_alias(state_root)
}

fn publication(
	frames: &[Frame],
	metadata: &Frame,
	intent: &Frame,
) -> Result<DarwinReplayStatus, DarwinReplayError> {
	let [observed_frame, remaining @ ..] = frames else {
		return Ok(DarwinReplayStatus::Uncertain);
	};
	let observed = DarwinPublishObserved::from_frame(observed_frame)?;
	observed.validate_intent(intent)?;
	let status = match observed.outcome() {
		DarwinPublicationOutcome::RejectedBeforeRename => DarwinReplayStatus::Incomplete,
		DarwinPublicationOutcome::Conflict => DarwinReplayStatus::Conflict,
		DarwinPublicationOutcome::UncertainRename => DarwinReplayStatus::Uncertain,
		DarwinPublicationOutcome::RenameConfirmedIncomplete
		| DarwinPublicationOutcome::Published => DarwinReplayStatus::PublishedIncomplete,
		DarwinPublicationOutcome::ReconciledPublished => {
			return Err(DarwinReplayError::UnsupportedRecoveryObservation);
		}
	};
	let [durability_frame, remaining @ ..] = remaining else {
		return Ok(status);
	};
	let durability = DarwinDurabilityRecorded::from_frame(durability_frame)?;
	durability.validate_evidence(metadata, intent, observed_frame)?;
	let [committed] = remaining else {
		return Ok(status);
	};
	let commitment = DarwinReceiptCommitted::from_frame(committed)?;
	// Check the chain references here. The artifact independently supplies its digest.
	commitment.validate_evidence(durability_frame, commitment.digest())?;
	Ok(DarwinReplayStatus::Complete)
}

fn require_binding(kind: FrameKind, matches: bool) -> Result<(), DarwinReplayError> {
	if matches {
		Ok(())
	} else {
		Err(DarwinReplayError::RecordBinding { kind })
	}
}

fn same_time(owner: OwnerTimestamp, observed: ObservedTimestamp) -> bool {
	(owner.seconds(), owner.nanoseconds()) == (observed.seconds(), observed.nanoseconds())
}
