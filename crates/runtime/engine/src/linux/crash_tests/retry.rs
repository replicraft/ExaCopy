use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DurabilityRecorded, LOCAL_RECEIPT_LOCATION, LinuxFileIdentity, PublicationOutcome,
	PublishIntent, PublishObserved, ReceiptCommitted, RecoveryStarted, RetainedPublicationDecision,
};
use exacopy_platform::linux::StageError;

use super::evidence::{SEGMENT, SUCCESS_ORDER, assert_absent, read_frames};
use super::{
	Checkpoint, DESTINATION_DIRECTORY, Fixture, INCUMBENT_BYTES, JOB, PROCEED, PublishError,
	STAGE_DIRECTORY, STAGE_FILE, Snapshot, TARGET, assert_crash, component, connect_checkpoint,
	fixture_signer, open_destination, open_source, profile_id, source_id,
};
use crate::linux::{
	CopyReceipt, RecoveryDisposition, RecoveryInspection, RecoveryProfile, RecoveryRetryError,
	RecoverySource, finish_recovery, inspect_recovery, retry_recovery,
};

const INITIAL_ORDER: &[FrameKind] = SUCCESS_ORDER.split_at(6).0;
const INITIAL_INTENT: usize = INITIAL_ORDER.len() - 1;
const RETRY_DECISION: &[FrameKind] = &[
	FrameKind::RecoveryStarted,
	FrameKind::VerificationRecorded,
	FrameKind::MetadataRecorded,
	FrameKind::RecoveryDecision,
];
const RETRY_INTENT: &[FrameKind] = &[FrameKind::PublishIntent];
const PUBLISHED_RECOVERY: &[FrameKind] = &[FrameKind::RecoveryStarted, FrameKind::RecoveryDecision];
const OBSERVATION: &[FrameKind] = &[FrameKind::PublishObserved];
const COMPLETION: &[FrameKind] = &[FrameKind::DurabilityRecorded, FrameKind::ReceiptCommitted];

#[test]
fn kill_after_retry_decision_before_intent() {
	kill_after_retry(Checkpoint::RetryDecisionSynced);
}

#[test]
fn kill_after_retry_intent_before_rename() {
	kill_after_retry(Checkpoint::RetryIntentSynced);
}

#[test]
fn kill_after_retry_rename_before_observation() {
	kill_after_retry(Checkpoint::RetryRenamedAndSynced);
}

#[test]
fn late_incumbent_blocks_retry_after_intent() {
	let fixture = Fixture::new();
	let source = leave_initial_intent(&fixture);
	let stage_path = fixture.job().join(STAGE_DIRECTORY).join(STAGE_FILE);
	let target_path = fixture.destination().join(TARGET);
	let stage = Snapshot::read(&stage_path);
	let (mut worker, mut stream) = fixture.pause_worker(Checkpoint::RetryIntentSynced);
	let mut incumbent = File::create_new(&target_path).expect("create the late retry incumbent");
	incumbent
		.write_all(INCUMBENT_BYTES)
		.expect("write the late retry incumbent's bytes");
	drop(incumbent);
	let incumbent = Snapshot::read(&target_path);
	let frames = read_frames(
		&fixture,
		&[INITIAL_ORDER, RETRY_DECISION, RETRY_INTENT].concat(),
	);
	assert_retry(
		&frames[INITIAL_ORDER.len()..],
		&frames[INITIAL_INTENT],
		2,
		stage.identity,
	);
	let segment = segment_bytes(&fixture);
	stream.write_all(&[PROCEED]).expect("allow retry rename");
	assert!(
		worker.finish().success(),
		"retry child must reject the new incumbent"
	);
	let conflict = inspect(&fixture);
	assert_eq!(conflict.disposition, RecoveryDisposition::Conflict);
	assert_eq!(
		retry(&fixture.0).expect("repeat retry with an incumbent"),
		conflict
	);
	assert_eq!(
		segment_bytes(&fixture),
		segment,
		"retry recorded publication despite conflict"
	);
	assert_eq!(Snapshot::read(&fixture.source()), source);
	assert_eq!(Snapshot::read(&stage_path), stage);
	assert_eq!(Snapshot::read(&target_path), incumbent);
	assert_absent(&fixture.job().join(LOCAL_RECEIPT_LOCATION));
}

fn kill_after_retry(checkpoint: Checkpoint) {
	let fixture = Fixture::new();
	let source = leave_initial_intent(&fixture);
	let stage_path = fixture.job().join(STAGE_DIRECTORY).join(STAGE_FILE);
	let target_path = fixture.destination().join(TARGET);
	let stage = Snapshot::read(&stage_path);
	let original = segment_bytes(&fixture);
	let (mut worker, _stream) = fixture.pause_worker(checkpoint);
	worker.kill_at(checkpoint);

	let has_retry_intent = checkpoint != Checkpoint::RetryDecisionSynced;
	let renamed = checkpoint == Checkpoint::RetryRenamedAndSynced;
	let intent_order = if has_retry_intent { RETRY_INTENT } else { &[] };
	let interrupted_order = [INITIAL_ORDER, RETRY_DECISION, intent_order].concat();
	let frames = read_frames(&fixture, &interrupted_order);
	assert_retry(
		&frames[INITIAL_ORDER.len()..],
		&frames[INITIAL_INTENT],
		2,
		stage.identity,
	);
	let interrupted = segment_bytes(&fixture);
	assert!(
		interrupted.starts_with(&original),
		"retry altered the original segment prefix"
	);
	assert_absent(&fixture.job().join(LOCAL_RECEIPT_LOCATION));
	assert_eq!(
		Snapshot::read(&fixture.source()),
		source,
		"interrupted retry changed source"
	);

	let expected = if renamed {
		assert_absent(&stage_path);
		let published = Snapshot::read(&target_path);
		assert_eq!(
			published.identity, stage.identity,
			"retry must publish the sealed inode"
		);
		published.assert_copied_from(&source);
		RecoveryDisposition::PublishedNeedsBarriers
	} else {
		assert_absent(&target_path);
		assert_eq!(
			Snapshot::read(&stage_path),
			stage,
			"interrupted retry changed stage"
		);
		RecoveryDisposition::PossibleRetry
	};
	assert_eq!(inspect(&fixture).disposition, expected, "{checkpoint:?}");

	let result = retry(&fixture.0).expect("reconcile the interrupted retained-stage retry");
	assert_eq!(
		result.disposition,
		RecoveryDisposition::Complete,
		"{checkpoint:?}"
	);
	assert!(
		segment_bytes(&fixture).starts_with(&interrupted),
		"restart rewrote journal evidence"
	);
	let last_intent = if has_retry_intent {
		interrupted_order.len() - 1
	} else {
		INITIAL_INTENT
	};
	let final_order = if renamed {
		[
			interrupted_order.as_slice(),
			PUBLISHED_RECOVERY,
			OBSERVATION,
			COMPLETION,
		]
		.concat()
	} else {
		[
			interrupted_order.as_slice(),
			RETRY_DECISION,
			RETRY_INTENT,
			OBSERVATION,
			PUBLISHED_RECOVERY,
			COMPLETION,
		]
		.concat()
	};
	let recovered = read_frames(&fixture, &final_order);
	let completed_intent = if renamed {
		&recovered[last_intent]
	} else {
		let first = interrupted_order.len();
		let end = first + RETRY_DECISION.len() + RETRY_INTENT.len();
		assert_retry(
			&recovered[first..end],
			&recovered[last_intent],
			3,
			stage.identity,
		);
		&recovered[end - 1]
	};
	assert_completion(&fixture, &recovered, completed_intent, stage.identity);

	let published = Snapshot::read(&target_path);
	assert_eq!(
		published.identity, stage.identity,
		"recovery must keep the sealed inode"
	);
	published.assert_copied_from(&source);
	assert_absent(&stage_path);
	let final_segment = segment_bytes(&fixture);
	let final_receipt =
		fs::read(fixture.job().join(LOCAL_RECEIPT_LOCATION)).expect("read receipt before rerun");
	assert_eq!(
		retry(&fixture.0).expect("repeat retry after recovery"),
		result
	);
	assert_eq!(
		finish_recovery(
			&open_destination(&fixture.destination()),
			component(JOB),
			profile(&fixture_signer().verifying_key()),
			&mut [0; 11],
		)
		.expect("repeat finish after recovery"),
		result
	);
	assert_eq!(inspect(&fixture), result);
	assert_eq!(
		Snapshot::read(&fixture.source()),
		source,
		"restart changed the source"
	);
	assert_eq!(
		Snapshot::read(&target_path),
		published,
		"completion changed the published inode"
	);
	assert_eq!(
		segment_bytes(&fixture),
		final_segment,
		"completion appended more history"
	);
	assert_eq!(
		fs::read(fixture.job().join(LOCAL_RECEIPT_LOCATION)).expect("read receipt after rerun"),
		final_receipt,
		"completion changed the receipt"
	);
}

fn leave_initial_intent(fixture: &Fixture) -> Snapshot {
	let source = Snapshot::read(&fixture.source());
	let (mut worker, _stream) = fixture.pause_worker(Checkpoint::IntentSynced);
	worker.kill_at(Checkpoint::IntentSynced);
	assert_crash(fixture, Checkpoint::IntentSynced, &source);
	source
}

fn assert_retry(
	frames: &[Frame],
	prior_intent: &Frame,
	effect_sequence: u64,
	stage: LinuxFileIdentity,
) {
	let [started, verification, metadata, decision, rest @ ..] = frames else {
		panic!("retry must record start, verification, metadata and decision");
	};
	let start = RecoveryStarted::from_frame(started).expect("decode the surviving retry start");
	let decision = RetainedPublicationDecision::from_frame(decision)
		.expect("decode the surviving retry decision");
	assert_eq!(
		start.evidence().intent,
		prior_intent.head(),
		"retry must cite the active intent"
	);
	assert_eq!(
		start.context().epoch.get(),
		effect_sequence,
		"retry must use a fresh generation"
	);
	assert_eq!(decision.context(), start.context());
	assert_eq!(decision.started(), started.head());
	assert_eq!(decision.evidence().verification, verification.head());
	assert_eq!(decision.evidence().metadata, metadata.head());
	assert_eq!(decision.evidence().stage, stage);
	assert_eq!(
		decision.effect_sequence(),
		effect_sequence,
		"retry must reserve a new effect"
	);
	if let [intent] = rest {
		let intent = PublishIntent::from_frame(intent).expect("decode the surviving retry intent");
		assert_eq!(intent.context.epoch, decision.context().epoch);
		assert_eq!(intent.context.effect_sequence, decision.effect_sequence());
		assert_eq!(intent.target.stage, stage);
	}
}

fn assert_completion(
	fixture: &Fixture,
	frames: &[Frame],
	completed_intent: &Frame,
	stage: LinuxFileIdentity,
) {
	let [.., durability, committed] = frames else {
		panic!("completed journal must end with barriers and receipt commitment");
	};
	let observed = frames
		.iter()
		.find(|frame| frame.kind() == FrameKind::PublishObserved)
		.expect("find the only publication observation in the recovered journal");
	let observed = PublishObserved::from_frame(observed).expect("decode recorded publication");
	observed
		.validate_intent(completed_intent)
		.expect("bind publication to the effect that ran");
	assert_eq!(
		observed.outcome(),
		PublicationOutcome::Published { target: stage }
	);
	let barriers = DurabilityRecorded::from_frame(durability).expect("decode publication barriers");
	assert_eq!(barriers.context(), observed.context());
	let receipt =
		fs::read(fixture.job().join(LOCAL_RECEIPT_LOCATION)).expect("read the recovered receipt");
	let receipt = CopyReceipt::decode(&receipt).expect("decode the recovered receipt");
	assert_eq!(receipt.evidence().context.epoch, observed.context().epoch);
	assert_eq!(receipt.evidence().stream.identity, stage);
	ReceiptCommitted::from_frame(committed)
		.expect("decode final receipt commitment")
		.validate_evidence(
			durability,
			exacopy_journal::ReceiptDigest::from_bytes(receipt.digest()),
		)
		.expect("verify receipt commitment against the on-disk artifact");
}

fn segment_bytes(fixture: &Fixture) -> Vec<u8> {
	fs::read(fixture.job().join(SEGMENT)).expect("reopen first journal segment")
}

fn inspect(fixture: &Fixture) -> RecoveryInspection {
	inspect_recovery(
		&open_destination(&fixture.destination()),
		component(JOB),
		profile(&fixture_signer().verifying_key()),
		&mut [0; 11],
	)
	.expect("inspect the interrupted retry")
}

fn retry(root: &Path) -> Result<RecoveryInspection, RecoveryRetryError> {
	retry_recovery(
		&open_destination(&root.join(DESTINATION_DIRECTORY)),
		component(JOB),
		profile(&fixture_signer().verifying_key()),
		RecoverySource {
			root: &open_source(root),
			id: source_id(),
		},
		&mut [0; 11],
	)
}

fn profile(verifying_key: &ed25519_dalek::VerifyingKey) -> RecoveryProfile<'_> {
	RecoveryProfile {
		id: profile_id(),
		verifying_key,
	}
}

#[test]
#[ignore = "subprocess entrypoint for the native retained-stage retry crash tests"]
fn retry_worker() {
	let root = connect_checkpoint();
	let result = retry(&root);
	assert!(
		matches!(
			result,
			Err(RecoveryRetryError::Publish(PublishError::StageChanged(
				StageError::IdentityChanged,
			)))
		),
		"retry must reject the late incumbent during final namespace validation, got {result:?}"
	);
}
