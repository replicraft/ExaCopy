use exacopy_journal::{
	RecoveryDirectories, RetainedPublicationDecision, RetainedPublicationEvidence,
};

use super::*;

#[test]
fn recovery_decisions_reserve_effect_numbers_even_before_the_new_intent() {
	let fixture = Fixture::new();
	let original = fixture.records();
	let mut history = History::new(&fixture, fixture.records(), 6);
	let epoch = original.intent.context.epoch.get();
	reserve(&mut history, &original, epoch, 2);
	let interrupted = fixture.replay(&history.bytes).unwrap();
	assert_eq!(interrupted.latest_epoch.get(), epoch + 1);
	assert_eq!(interrupted.last_effect_sequence, 2);
	assert_eq!(interrupted.intent_head, Some(history.intent));
	assert_eq!(interrupted.metadata_head, Some(history.metadata));

	let fresh = reserve(&mut history, &original, epoch + 1, 3);
	let intent = renewed_intent(&original, &fresh, 3);
	let head = history.append(FrameKind::PublishIntent, &intent.encode());
	let updated = fixture.replay(&history.bytes).unwrap();
	assert_eq!(updated.latest_epoch.get(), epoch + 2);
	assert_eq!(updated.last_effect_sequence, 3);
	assert_eq!(updated.intent_head, Some(head));
	assert_eq!(updated.verification, Some(fresh));
	assert_eq!(updated.intent, Some(intent.context));

	history.observe();
	assert!(
		fixture.replay(&history.bytes).is_err(),
		"an observation of the old effect must be rejected"
	);
}

#[test]
fn new_intent_requires_the_reserved_sequence_and_fresh_verification_digest() {
	let fixture = Fixture::new();
	let records = fixture.records();
	let epoch = records.intent.context.epoch.get();
	for wrong_sequence in [false, true] {
		let mut history = History::new(&fixture, fixture.records(), 6);
		let fresh = reserve(&mut history, &records, epoch, 2);
		let mut intent = renewed_intent(&records, &fresh, 2);
		if wrong_sequence {
			intent.context.effect_sequence += 1;
		} else {
			intent.target.verification_digest = records.verification.record_digest();
		}
		history.append(FrameKind::PublishIntent, &intent.encode());
		assert_binding(&fixture, &history.bytes, FrameKind::PublishIntent);
	}
	let mut history = History::new(&fixture, fixture.records(), 6);
	history.start(epoch);
	let intent = renewed_intent(&records, &reverified(&records, epoch + 1), 2);
	history.append(FrameKind::PublishIntent, &intent.encode());
	assert_binding(&fixture, &history.bytes, FrameKind::PublishIntent);
}

#[test]
fn durable_published_recovery_decision_prevents_stage_republication() {
	let fixture = Fixture::new();
	let records = fixture.records();
	let mut history = History::new(&fixture, fixture.records(), 6);
	let epoch = records.intent.context.epoch.get();
	history.start(epoch);
	history.decide(epoch + 1, history.decision_evidence());
	assert!(fixture.replay(&history.bytes).unwrap().published_recovery);
	history.start(epoch + 1);
	history.append(
		FrameKind::VerificationRecorded,
		&reverified(&records, epoch + 2).encode(),
	);
	assert_binding(&fixture, &history.bytes, FrameKind::VerificationRecorded);
}

fn reserve(
	history: &mut History,
	records: &Records,
	prior_epoch: u64,
	sequence: u64,
) -> VerificationRecorded {
	let started = history.start(prior_epoch);
	let fresh = reverified(records, prior_epoch + 1);
	let verification = history.append(FrameKind::VerificationRecorded, &fresh.encode());
	let mut record = records.metadata;
	record.context = fresh.context;
	let metadata = history.append(FrameKind::MetadataRecorded, &record.encode());
	let decision = RetainedPublicationDecision::new(
		fresh.context,
		fresh.entry,
		started,
		RetainedPublicationEvidence {
			stage: STAGE,
			directories: RecoveryDirectories {
				stage: STAGE_DIRECTORY,
				destination: records.intent.target.parent,
			},
			verification,
			metadata,
		},
		sequence,
	)
	.unwrap();
	history.append(FrameKind::RecoveryDecision, &decision.encode());
	fresh
}

fn reverified(records: &Records, epoch: u64) -> VerificationRecorded {
	VerificationRecorded::new(
		JournalContext {
			epoch: JournalEpoch::new(epoch),
			..records.verification.context
		},
		records.verification.entry,
		records.verification.source(),
		records.verification.stage(),
	)
	.unwrap()
}

fn renewed_intent(
	records: &Records,
	fresh: &VerificationRecorded,
	sequence: u64,
) -> PublishIntent<'static> {
	let mut intent = records.intent;
	intent.context.epoch = fresh.context.epoch;
	intent.context.effect_sequence = sequence;
	intent.target.verification_digest = fresh.record_digest();
	intent
}
