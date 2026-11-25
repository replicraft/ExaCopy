use ed25519_dalek::SigningKey;
use exacopy_journal::{RangePage, RangeResumeEvidence, RangeResumeStarted, StreamDigest};

use super::*;

#[test]
fn checkpoints_bind_to_allowed_owner_directory_and_exact_preparation() {
	let fixture = with_checkpoints();
	let mut records = fixture.records();
	let preparation = EntryPrepared::new(records.job.context, records.seal.entry, records.entry)
		.unwrap()
		.encode();
	let source = SourceMeasurementId::from_prepared_payload(&preparation);
	let checkpoint = RangeCheckpoint {
		context: records.job.context,
		entry: records.seal.entry,
		page: page(1, 0, source).reference(),
		source,
	};
	let second = RangeCheckpoint {
		page: page(2, 8, source).reference(),
		..checkpoint
	};
	let seal = records.seal.encode();

	let bytes = journal_prefix(
		&records.job,
		&preparation,
		&[
			(FrameKind::RangeCheckpoint, checkpoint.encode()),
			(FrameKind::RangeCheckpoint, second.encode()),
			(FrameKind::StageSealed, seal.clone()),
		],
	);
	let replay = fixture.replay(&bytes).unwrap();
	assert_eq!(replay.checkpoints, [checkpoint, second]);
	assert_eq!(replay.sealed, Some(records.seal));
	assert!(replay.intent.is_none());

	let wrong_source = SourceMeasurementId::from_prepared_payload(b"different entry");
	for bad in [
		second,
		RangeCheckpoint {
			entry: JournalEntryId::from_bytes([42; 16]),
			..checkpoint
		},
		RangeCheckpoint {
			context: JournalContext {
				epoch: JournalEpoch::new(4),
				..checkpoint.context
			},
			..checkpoint
		},
		RangeCheckpoint {
			page: page(1, 0, wrong_source).reference(),
			source: wrong_source,
			..checkpoint
		},
	] {
		let bytes = journal_prefix(
			&records.job,
			&preparation,
			&[(FrameKind::RangeCheckpoint, bad.encode())],
		);
		assert_checkpoint_mismatch(fixture.replay(&bytes));
	}

	let bytes = journal_prefix(
		&records.job,
		&preparation,
		&[
			(FrameKind::StageSealed, seal),
			(FrameKind::RangeCheckpoint, checkpoint.encode()),
		],
	);
	assert!(matches!(
		fixture.replay(&bytes),
		Err(JournalReplayError::UnexpectedRecord {
			found: FrameKind::RangeCheckpoint,
			..
		})
	));

	let original = Fixture::new();
	records.job.owner_digest = original.owner.digest();
	let bytes = journal_prefix(
		&records.job,
		&preparation,
		&[(FrameKind::RangeCheckpoint, checkpoint.encode())],
	);
	assert_checkpoint_mismatch(original.replay(&bytes));
}

#[test]
fn range_resume_binds_the_original_stage_and_resets_preintent_evidence() {
	let fixture = with_checkpoints();
	let records = fixture.records();
	let prepared = EntryPrepared::new(records.job.context, records.seal.entry, records.entry)
		.unwrap()
		.encode();
	let source = SourceMeasurementId::from_prepared_payload(&prepared);
	let checkpoint = RangeCheckpoint {
		context: records.job.context,
		entry: records.seal.entry,
		page: page(1, 0, source).reference(),
		source,
	};
	let prefix = journal_prefix(
		&records.job,
		&prepared,
		&[
			(FrameKind::RangeCheckpoint, checkpoint.encode()),
			(FrameKind::StageSealed, records.seal.encode()),
			(
				FrameKind::VerificationRecorded,
				records.verification.encode(),
			),
			(FrameKind::MetadataRecorded, records.metadata.encode()),
		],
	);
	let original = fixture.replay(&prefix).unwrap();
	let evidence = RangeResumeEvidence {
		preparation: original.preparation_head.unwrap(),
		preceding: original.boundary.head,
		stage: STAGE,
		stage_directory: STAGE_DIRECTORY,
		authorization: fixture.owner.digest(),
	};
	let epoch = JournalEpoch::new(original.latest_epoch.get() + 1);
	let context = JournalContext {
		epoch,
		..records.job.context
	};
	let entry = records.seal.entry;

	let make_history = |evidence| {
		let record =
			RangeResumeStarted::new(context, entry, original.latest_epoch, evidence).unwrap();
		let mut bytes = prefix.clone();
		FrameWriter::new(&mut bytes, original.boundary.head)
			.append(FrameKind::RecoveryStarted, &record.encode())
			.unwrap();
		bytes
	};
	for incompatible in [
		RangeResumeEvidence {
			preparation: ChainHead::after(2, [0x42; 32]).unwrap(),
			..evidence
		},
		RangeResumeEvidence {
			authorization: OwnerDigest::from_bytes([0x33; 32]),
			..evidence
		},
		RangeResumeEvidence {
			stage: OTHER_STAGE,
			..evidence
		},
		RangeResumeEvidence {
			stage_directory: fixture.plan.destination().root.identity,
			..evidence
		},
	] {
		assert!(matches!(
			fixture.replay(&make_history(incompatible)),
			Err(JournalReplayError::RecordBinding {
				kind: FrameKind::RecoveryStarted
			})
		));
	}

	let mut resumed = make_history(evidence);
	let current = fixture.replay(&resumed).unwrap();
	assert_eq!(current.latest_epoch, epoch);
	assert_eq!(current.checkpoints, [checkpoint]);
	assert_eq!(current.recovery_stage_directory, Some(STAGE_DIRECTORY));
	assert!(current.sealed.is_none());
	assert!(current.verification.is_none());
	assert!(current.verification_head.is_none());
	assert!(current.metadata.is_none());
	assert!(current.metadata_head.is_none());
	assert!(current.intent.is_none());
	FrameWriter::new(&mut resumed, current.boundary.head)
		.append(FrameKind::StageSealed, &records.seal.encode())
		.unwrap();
	assert!(matches!(
		fixture.replay(&resumed),
		Err(JournalReplayError::RecordBinding {
			kind: FrameKind::StageSealed
		})
	));
}

fn with_checkpoints() -> Fixture {
	let mut fixture = Fixture::new();
	let mut manifest = fixture.owner.manifest().clone();
	manifest
		.directories
		.insert(0, OwnerStateDirectory::Checkpoints);
	fixture.owner = OwnerRecord::sign(manifest, &SigningKey::from_bytes(&[9; 32])).unwrap();
	fixture
}

fn page(ordinal: u32, offset: u64, source: SourceMeasurementId) -> RangePage {
	RangePage::new(
		ordinal,
		offset,
		8,
		StreamDigest::from_bytes([7; 32]),
		source,
	)
	.unwrap()
}

fn journal_prefix(job: &JobPrepared, entry: &[u8], suffix: &[(FrameKind, Vec<u8>)]) -> Vec<u8> {
	let mut bytes = Vec::new();
	let mut writer = FrameWriter::new(&mut bytes, ChainHead::start());
	writer
		.append(FrameKind::JobPrepared, &job.encode())
		.unwrap();
	writer.append(FrameKind::EntryPrepared, entry).unwrap();
	for (kind, payload) in suffix {
		writer.append(*kind, payload).unwrap();
	}
	bytes
}

fn assert_checkpoint_mismatch(result: Result<JournalReplay, JournalReplayError>) {
	assert!(matches!(
		result,
		Err(JournalReplayError::RecordBinding {
			kind: FrameKind::RangeCheckpoint
		})
	));
}
