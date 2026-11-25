use ed25519_dalek::SigningKey;
use exacopy_journal::{RangePage, StreamDigest};

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
