use exacopy_journal::{LinuxFileIdentity, MetadataRecorded, PublicationOutcome, StreamEvidence};

use super::super::{JournalReplay, JournalTail};
use super::{RecoveryDisposition, RecoveryIssue};

#[cfg(test)]
mod tests;

// Pair an identity observed from an open file with its held read capability.
pub(super) struct ObservedFile<'file, F> {
	identity: LinuxFileIdentity,
	file: &'file F,
}

impl<'file, F> ObservedFile<'file, F> {
	pub(super) fn new(identity: LinuxFileIdentity, file: &'file F) -> Self {
		Self { identity, file }
	}
}

pub(super) struct ObservedNames<'file, F> {
	pub(super) stage: Option<ObservedFile<'file, F>>,
	pub(super) target: Option<ObservedFile<'file, F>>,
	pub(super) stage_directory: Option<LinuxFileIdentity>,
}

// Only matching stage inodes are eligible for read-back. The caller rechecks
// the live namespace and artifact bindings before returning this disposition.
pub(super) fn classify<F, E>(
	names: ObservedNames<'_, F>,
	journal: &JournalReplay,
	receipt_present: bool,
	verify: impl FnOnce(
		&F,
		StreamEvidence,
		Option<MetadataRecorded>,
	) -> Result<Option<RecoveryIssue>, E>,
) -> Result<RecoveryDisposition, E> {
	use RecoveryDisposition::RequiresReconciliation as unresolved;

	let stage = names.stage.as_ref();
	let target = names.target.as_ref();
	let known_stage = stage.filter(|file| Some(file.identity) == journal.stage);
	let known_target = target.filter(|file| Some(file.identity) == journal.stage);
	if let (Some(current), Some(verification)) =
		(known_stage.or(known_target), journal.verification)
		&& let Some(issue) = verify(current.file, verification.stage(), journal.metadata)?
	{
		return Ok(unresolved(issue));
	}

	if journal.boundary.head.sequence() == 0 {
		return Ok(unresolved(RecoveryIssue::MissingPreparation));
	}
	if target.is_some() && known_target.is_none() {
		return Ok(RecoveryDisposition::Conflict);
	}
	if stage.is_some() && known_stage.is_none() {
		return Ok(unresolved(RecoveryIssue::UnrecognizedStage));
	}
	let changed_directory = journal
		.recovery_stage_directory
		.is_some_and(|identity| Some(identity) != names.stage_directory);
	if journal.intent.is_none() {
		if changed_directory {
			return Ok(unresolved(RecoveryIssue::StageDirectoryBinding));
		}
		return Ok(match (stage, target, journal.stage, journal.tail) {
			(_, Some(_), _, _) => unresolved(RecoveryIssue::ContradictoryNames),
			(None, None, Some(_), _) => unresolved(RecoveryIssue::MissingStageAndTarget),
			(_, None, _, JournalTail::Torn { .. }) => unresolved(RecoveryIssue::TornJournal),
			(_, None, _, JournalTail::Clean) => RecoveryDisposition::RetainedPreparation,
		});
	}

	match (stage, target) {
		(Some(_), None) if changed_directory => {
			Ok(unresolved(RecoveryIssue::StageDirectoryBinding))
		}
		(Some(_), None) => Ok(private_stage(journal)),
		(None, Some(_)) => Ok(published_stage(
			names.stage_directory,
			journal,
			receipt_present,
		)),
		(Some(_), Some(_)) => Ok(unresolved(RecoveryIssue::ContradictoryNames)),
		(None, None) => Ok(unresolved(RecoveryIssue::MissingStageAndTarget)),
	}
}

fn private_stage(journal: &JournalReplay) -> RecoveryDisposition {
	if journal.published_recovery && journal.tail == JournalTail::Clean {
		return RecoveryDisposition::RequiresReconciliation(RecoveryIssue::ContradictoryOutcome);
	}
	match (
		journal.tail,
		journal.observation.map(|event| event.outcome()),
	) {
		(JournalTail::Torn { .. }, _) => {
			RecoveryDisposition::RequiresReconciliation(RecoveryIssue::TornJournal)
		}
		(JournalTail::Clean, None | Some(PublicationOutcome::Uncertain { .. })) => {
			RecoveryDisposition::PossibleRetry
		}
		(JournalTail::Clean, Some(PublicationOutcome::Published { .. })) => {
			RecoveryDisposition::RequiresReconciliation(RecoveryIssue::ContradictoryOutcome)
		}
		(JournalTail::Clean, Some(_)) => {
			RecoveryDisposition::RequiresReconciliation(RecoveryIssue::RecordedAttempt)
		}
	}
}

fn published_stage(
	stage_directory: Option<LinuxFileIdentity>,
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
	let Some(stage_directory) = stage_directory else {
		return unresolved(RecoveryIssue::StageDirectoryBinding);
	};
	if journal
		.recovery_stage_directory
		.is_some_and(|identity| identity != stage_directory)
	{
		return unresolved(RecoveryIssue::StageDirectoryBinding);
	}
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
