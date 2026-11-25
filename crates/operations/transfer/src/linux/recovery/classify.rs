use exacopy_content::measure_at;
use exacopy_journal::{MetadataRecorded, PublicationOutcome, StreamEvidence};
use exacopy_platform::linux::{ExtendedAttributes, RecoveryFile, RecoveryInventory};

use super::super::job::native_identity;
use super::super::{JournalReplay, JournalTail};
use super::{RecoveryDisposition, RecoveryInspectError, RecoveryIssue, RecoveryStep};

pub(super) fn classify(
	names: &RecoveryInventory<'_>,
	journal: &JournalReplay,
	receipt_present: bool,
	scratch: &mut [u8],
) -> Result<RecoveryDisposition, RecoveryInspectError> {
	use RecoveryDisposition::RequiresReconciliation as unresolved;

	let stage = names.stage();
	let target = names.target();
	let stage_matches =
		stage.is_some_and(|file| Some(native_identity(file.identity())) == journal.stage);
	let target_matches =
		target.is_some_and(|file| Some(native_identity(file.identity())) == journal.stage);
	let current = if stage_matches {
		stage
	} else {
		target.filter(|_| target_matches)
	};
	if let (Some(file), Some(verification)) = (current, journal.verification)
		&& let Some(issue) = verify(file, verification.stage(), journal.metadata, scratch)?
	{
		return Ok(unresolved(issue));
	}

	if journal.boundary.head.sequence() == 0 {
		return Ok(unresolved(RecoveryIssue::MissingPreparation));
	}
	if target.is_some() && !target_matches {
		return Ok(RecoveryDisposition::Conflict);
	}
	if stage.is_some() && !stage_matches {
		return Ok(unresolved(RecoveryIssue::UnrecognizedStage));
	}
	if journal.intent.is_none() {
		return Ok(match (stage, target, journal.stage, journal.tail) {
			(_, Some(_), _, _) => unresolved(RecoveryIssue::ContradictoryNames),
			(None, None, Some(_), _) => unresolved(RecoveryIssue::MissingStageAndTarget),
			(_, None, _, JournalTail::Torn { .. }) => unresolved(RecoveryIssue::TornJournal),
			(_, None, _, JournalTail::Clean) => RecoveryDisposition::RetainedPreparation,
		});
	}

	match (stage, target) {
		(Some(_), None) => Ok(private_stage(journal)),
		(None, Some(_)) => Ok(published_stage(names, journal, receipt_present)),
		(Some(_), Some(_)) => Ok(unresolved(RecoveryIssue::ContradictoryNames)),
		(None, None) => Ok(unresolved(RecoveryIssue::MissingStageAndTarget)),
	}
}

fn private_stage(journal: &JournalReplay) -> RecoveryDisposition {
	match (
		journal.tail,
		journal.observation.map(|event| event.outcome()),
	) {
		(JournalTail::Torn { .. }, _) => {
			RecoveryDisposition::RequiresReconciliation(RecoveryIssue::TornJournal)
		}
		(JournalTail::Clean, None) => RecoveryDisposition::PossibleRetry,
		(JournalTail::Clean, Some(PublicationOutcome::Published { .. })) => {
			RecoveryDisposition::RequiresReconciliation(RecoveryIssue::ContradictoryOutcome)
		}
		(JournalTail::Clean, Some(_)) => {
			RecoveryDisposition::RequiresReconciliation(RecoveryIssue::RecordedAttempt)
		}
	}
}

fn published_stage(
	names: &RecoveryInventory<'_>,
	journal: &JournalReplay,
	receipt_present: bool,
) -> RecoveryDisposition {
	use RecoveryDisposition::RequiresReconciliation as unresolved;

	if matches!(
		journal.observation.map(|event| event.outcome()),
		Some(PublicationOutcome::NotPerformed { .. })
	) {
		return unresolved(RecoveryIssue::ContradictoryOutcome);
	}
	let Some(stage_directory) = names.stage_directory_identity().map(native_identity) else {
		return unresolved(RecoveryIssue::StageDirectoryBinding);
	};
	let Some(durability) = journal.durability else {
		return RecoveryDisposition::PublishedNeedsBarriers;
	};
	if stage_directory != durability.barriers().stage_directory {
		return unresolved(RecoveryIssue::StageDirectoryBinding);
	}
	if journal.receipt.is_none() {
		return RecoveryDisposition::PublishedNeedsReceipt {
			artifact_present: receipt_present,
		};
	}
	if !receipt_present {
		return unresolved(RecoveryIssue::MissingCommittedReceipt);
	}
	match journal.tail {
		JournalTail::Clean => RecoveryDisposition::Complete,
		JournalTail::Torn { .. } => unresolved(RecoveryIssue::TornJournal),
	}
}

fn verify(
	file: &RecoveryFile,
	expected: StreamEvidence,
	metadata: Option<MetadataRecorded>,
	scratch: &mut [u8],
) -> Result<Option<RecoveryIssue>, RecoveryInspectError> {
	if file.len() != expected.length.get() {
		return Ok(Some(RecoveryIssue::StreamMismatch));
	}
	let digest = measure_at(file.len(), scratch, |offset, bytes| {
		file.read_exact_at(offset, bytes)
	})
	.map_err(RecoveryInspectError::ReadBack)?;
	file.check_logical_eof()
		.map_err(RecoveryStep::Stream.read())?;
	if digest.as_bytes() != expected.digest.as_bytes() {
		return Ok(Some(RecoveryIssue::StreamMismatch));
	}
	if let Some(recorded) = metadata {
		let observed = file.observation();
		let modified = observed.modified_at();
		let expected = recorded.metadata;
		let attributes = file
			.extended_attributes()
			.map_err(RecoveryStep::Stream.read())?;
		if observed.mode() != expected.mode()
			|| observed.owner() != expected.uid
			|| observed.group() != expected.gid
			|| observed.link_count() != 1
			|| modified.seconds() != expected.modified_at.seconds()
			|| modified.nanoseconds() != expected.modified_at.nanoseconds()
			|| attributes != ExtendedAttributes::NoneVisible
		{
			return Ok(Some(RecoveryIssue::MetadataMismatch));
		}
	}
	Ok(None)
}
