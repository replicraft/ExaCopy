use exacopy_journal::frame::ChainHead;
use exacopy_journal::{
	JournalContext, JournalEntryId, JournalEpoch, JournalJobId, PlanDigest, PublishIntentContext,
	StreamDigest, StreamLength, VerificationRecorded,
};

use super::super::super::JournalBoundary;
use super::{JournalReplay, JournalTail, StreamEvidence, classify};
use super::{LinuxFileIdentity, ObservedFile, ObservedNames, RecoveryDisposition, RecoveryIssue};

const STAGE: LinuxFileIdentity = LinuxFileIdentity::new(1, 2);
const INCUMBENT: LinuxFileIdentity = LinuxFileIdentity::new(1, 3);
const DIRECTORY: LinuxFileIdentity = LinuxFileIdentity::new(1, 4);
fn stage_stream() -> StreamEvidence {
	StreamEvidence {
		identity: STAGE,
		length: StreamLength::new(1).unwrap(),
		digest: StreamDigest::from_bytes([0x1a; 32]),
	}
}

fn journal_at_intent() -> JournalReplay {
	let context = JournalContext {
		job: JournalJobId::from_bytes([1, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
			.unwrap(),
		epoch: JournalEpoch::new(1),
		plan_digest: PlanDigest::from_bytes([1; 32]),
	};
	let entry = JournalEntryId::from_bytes([0x24; 16]);
	let source = StreamEvidence {
		identity: LinuxFileIdentity::new(2, 1),
		..stage_stream()
	};
	JournalReplay {
		boundary: JournalBoundary {
			head: ChainHead::after(6, [9; 32]).unwrap(),
			offset: 600,
		},
		tail: JournalTail::Clean,
		source: None,
		source_link_count: None,
		source_metadata: None,
		preparation_head: None,
		stage: Some(STAGE),
		checkpoints: Vec::new(),
		sealed: None,
		verification: Some(
			VerificationRecorded::new(context, entry, source, stage_stream()).unwrap(),
		),
		verification_head: None,
		metadata: None,
		metadata_head: None,
		intent: Some(PublishIntentContext {
			job: context.job,
			epoch: context.epoch,
			entry,
			effect_sequence: 1,
			plan_digest: context.plan_digest,
		}),
		intent_head: None,
		observation: None,
		observation_head: None,
		durability: None,
		durability_head: None,
		latest_epoch: context.epoch,
		last_effect_sequence: 1,
		recovery_stage_directory: None,
		published_recovery: false,
		receipt: None,
	}
}

#[test]
fn never_requests_readback_of_an_incumbent() {
	let names = ObservedNames {
		stage: None,
		target: Some(ObservedFile::new(INCUMBENT, &())),
		stage_directory: Some(DIRECTORY),
	};
	let result = classify::<_, ()>(names, &journal_at_intent(), false, |_, _, _| {
		panic!("read-back must only consume the recorded stage inode")
	});
	assert_eq!(result, Ok(RecoveryDisposition::Conflict));
}

#[test]
fn verifies_the_held_stage_in_preference_to_a_contradictory_target() {
	let names = ObservedNames {
		stage: Some(ObservedFile::new(STAGE, &"private stage")),
		target: Some(ObservedFile::new(STAGE, &"public target")),
		stage_directory: Some(DIRECTORY),
	};
	let result = classify::<_, ()>(names, &journal_at_intent(), false, |file, stream, _| {
		assert_eq!(*file, "private stage");
		assert_eq!(stream, stage_stream());
		Ok(None)
	});
	assert_eq!(
		result,
		Ok(RecoveryDisposition::RequiresReconciliation(
			RecoveryIssue::ContradictoryNames
		))
	);
}

#[test]
fn propagates_inconclusive_readback_of_the_published_inode() {
	let names = || ObservedNames {
		stage: None,
		target: Some(ObservedFile::new(STAGE, &"public target")),
		stage_directory: Some(DIRECTORY),
	};
	let journal = journal_at_intent();
	let result = classify(names(), &journal, false, |file, stream, _| {
		assert_eq!(*file, "public target");
		assert_eq!(stream, stage_stream());
		Err("incomplete read-back")
	});
	assert_eq!(result, Err("incomplete read-back"));
	let result = classify::<_, ()>(names(), &journal, false, |_, _, _| {
		Ok(Some(RecoveryIssue::StreamMismatch))
	});
	assert_eq!(
		result,
		Ok(RecoveryDisposition::RequiresReconciliation(
			RecoveryIssue::StreamMismatch
		))
	);
	assert_eq!(
		classify::<_, ()>(names(), &journal, false, |_, _, _| Ok(None)),
		Ok(RecoveryDisposition::PublishedNeedsBarriers)
	);
}
