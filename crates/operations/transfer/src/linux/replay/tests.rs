use std::io;

use exacopy_journal::frame::{FrameProblem, FrameWriter};
use exacopy_journal::{
	JournalEpoch, LinuxPublicationBarriers, ObservedTimestamp, OwnerDigest, PlanDigest,
	PublicationOutcome, ReceiptDigest, SourceTimes, StreamEvidence, StreamLength,
	VerificationDigest,
};

use super::*;

mod fixture;
mod recovery;

use fixture::{Fixture, JOB_ROOT, KINDS, OTHER_STAGE, Records, STAGE, STAGE_DIRECTORY, component};

#[test]
fn every_byte_cut_reports_only_the_complete_prefix() {
	let fixture = Fixture::new();
	let (bytes, boundaries) = fixture.records().bytes(KINDS.len());
	for cut in 0..=bytes.len() {
		let summary = fixture.replay(&bytes[..cut]).unwrap();
		let cut = u64::try_from(cut).unwrap();
		let boundary = boundaries
			.iter()
			.rfind(|boundary| boundary.offset <= cut)
			.unwrap();
		let completed = boundary.head.sequence();
		assert_eq!(summary.boundary, *boundary, "cut at {cut}");
		assert_eq!(
			summary.tail,
			if cut == boundary.offset {
				JournalTail::Clean
			} else {
				JournalTail::Torn {
					bytes_read: usize::try_from(cut - boundary.offset).unwrap(),
				}
			},
			"cut at {cut}"
		);
		assert_eq!(summary.stage, (completed >= 2).then_some(STAGE));
		assert_eq!(summary.source.is_some(), completed >= 2);
		assert_eq!(summary.sealed.is_some(), completed >= 3);
		assert_eq!(summary.verification.is_some(), completed >= 4);
		assert_eq!(summary.metadata.is_some(), completed >= 5);
		assert_eq!(summary.intent.is_some(), completed >= 6);
		assert_eq!(summary.observation.is_some(), completed >= 7);
		assert_eq!(summary.durability.is_some(), completed >= 8);
		assert_eq!(summary.receipt.is_some(), completed >= 9);
	}
}

#[test]
fn owner_and_preparation_substitutions_are_refused() {
	let fixture = Fixture::new();
	let mut attempt = fixture.plan.attempt();
	attempt.epoch = JournalEpoch::new(2);
	let other_plan =
		LocalCopyPlan::new(attempt, fixture.plan.source(), fixture.plan.destination()).unwrap();
	assert!(matches!(
		replay_journal(&[][..], &other_plan, &fixture.owner),
		Err(JournalReplayError::OwnerBinding)
	));

	let (bytes, _) = fixture.records().bytes(1);
	let other_owner = Fixture::owner_for(&fixture.plan, LinuxFileIdentity::new(1, 42));
	assert!(matches!(
		replay_journal(&bytes[..], &fixture.plan, &other_owner),
		Err(JournalReplayError::RecordBinding {
			kind: FrameKind::JobPrepared
		})
	));

	check_substitution(&fixture, FrameKind::JobPrepared, |records| {
		records.job.owner_digest = OwnerDigest::from_bytes([1; 32]);
	});
	check_substitution(&fixture, FrameKind::EntryPrepared, |records| {
		records.entry.target.component = component(b"substitute");
	});
	check_substitution(&fixture, FrameKind::EntryPrepared, |records| {
		records.entry.stage = JOB_ROOT;
	});
	check_substitution(&fixture, FrameKind::EntryPrepared, |records| {
		let source = records.entry.source;
		records.entry.source = LiveSourceView::new(
			source.identity(),
			source.length(),
			SourceTimes {
				changed_at: ObservedTimestamp::new(0, 0).unwrap(),
				..source.times()
			},
		)
		.unwrap();
	});
}

fn check_substitution(fixture: &Fixture, expected: FrameKind, change: impl FnOnce(&mut Records)) {
	let mut records = fixture.records();
	change(&mut records);
	let (bytes, _) = records.bytes(KINDS.len());
	assert!(
		matches!(
			fixture.replay(&bytes),
			Err(JournalReplayError::RecordBinding { kind }) if kind == expected
		),
		"substitution in {expected:?}"
	);
}

#[test]
fn sealed_verified_metadata_and_intent_evidence_must_match_exactly() {
	let fixture = Fixture::new();
	check_substitution(&fixture, FrameKind::StageSealed, |records| {
		records.seal.stage = OTHER_STAGE;
	});
	check_substitution(&fixture, FrameKind::StageSealed, |records| {
		records.seal.length = StreamLength::new(0).unwrap();
	});
	check_substitution(&fixture, FrameKind::VerificationRecorded, |records| {
		let verification = records.verification;
		records.verification = VerificationRecorded::new(
			verification.context,
			verification.entry,
			verification.source(),
			StreamEvidence {
				identity: OTHER_STAGE,
				..verification.stage()
			},
		)
		.unwrap();
	});
	check_substitution(&fixture, FrameKind::MetadataRecorded, |records| {
		records.metadata.stage = OTHER_STAGE;
	});
	check_substitution(&fixture, FrameKind::MetadataRecorded, |records| {
		records.metadata.metadata.uid += 1;
	});
	check_substitution(&fixture, FrameKind::MetadataRecorded, |records| {
		records.metadata.metadata.accessed_at = OwnerTimestamp::new(23, 8).unwrap();
	});
	check_substitution(&fixture, FrameKind::PublishIntent, |records| {
		records.intent.target.verification_digest = VerificationDigest::from_bytes([7; 32]);
	});
	check_substitution(&fixture, FrameKind::PublishIntent, |records| {
		records.intent.context.effect_sequence = 2;
	});
	check_substitution(&fixture, FrameKind::PublishIntent, |records| {
		records.intent.context.plan_digest = PlanDigest::from_bytes([6; 32]);
	});
}

#[test]
fn exact_publication_links_and_published_outcome_are_required() {
	let fixture = Fixture::new();

	let mut records = fixture.records();
	records.outcome = PublicationOutcome::Published {
		target: OTHER_STAGE,
	};
	let (bytes, _) = records.bytes(7);
	assert!(matches!(
		fixture.replay(&bytes),
		Err(JournalReplayError::Publication(_))
	));

	let mut records = fixture.records();
	records.outcome = PublicationOutcome::NotPerformed {
		stage: STAGE,
		target: Some(OTHER_STAGE),
	};
	let (bytes, boundaries) = records.bytes(KINDS.len());
	let observed_only = &bytes[..usize::try_from(boundaries[7].offset).unwrap()];
	let summary = fixture.replay(observed_only).unwrap();
	assert!(matches!(
		summary.observation.unwrap().outcome(),
		PublicationOutcome::NotPerformed { .. }
	));
	assert!(matches!(
		fixture.replay(&bytes),
		Err(JournalReplayError::Publication(_))
	));

	let records = fixture.records();
	let intent = records.intent;
	let (bytes, _) = records.transform(KINDS.len(), |kind, payload, boundaries| {
		if kind == FrameKind::DurabilityRecorded {
			*payload = DurabilityRecorded::new(
				intent.context,
				boundaries[7].head,
				LinuxPublicationBarriers {
					metadata: ChainHead::after(5, [1; 32]).unwrap(),
					stage_directory: STAGE_DIRECTORY,
					destination_directory: intent.target.parent,
				},
			)
			.unwrap()
			.encode();
		}
	});
	assert!(matches!(
		fixture.replay(&bytes),
		Err(JournalReplayError::Publication(_))
	));

	let (bytes, _) = fixture
		.records()
		.transform(KINDS.len(), |kind, payload, _| {
			if kind == FrameKind::ReceiptCommitted {
				*payload = ReceiptCommitted::new(
					intent.context,
					ReceiptDigest::from_bytes([0x56; 32]),
					ChainHead::after(8, [1; 32]).unwrap(),
				)
				.unwrap()
				.encode();
			}
		});
	assert!(matches!(
		fixture.replay(&bytes),
		Err(JournalReplayError::RecordBinding {
			kind: FrameKind::ReceiptCommitted
		})
	));
}

#[test]
fn corrupt_unsupported_reordered_and_appended_records_are_refused() {
	let fixture = Fixture::new();
	let (mut bytes, boundaries) = fixture.records().bytes(KINDS.len());

	let corrupt_offset = boundaries[2].offset - 1;
	bytes[usize::try_from(corrupt_offset).unwrap()] ^= 0xff;
	assert!(matches!(
		fixture.replay(&bytes),
		Err(JournalReplayError::Frame(FrameReadError::Corrupt {
			problem: FrameProblem::Digest,
			..
		}))
	));

	let (mut bytes, _) = fixture.records().bytes(KINDS.len());
	const KIND_OFFSET: usize = 10;
	bytes[KIND_OFFSET..KIND_OFFSET + 2].copy_from_slice(&u16::MAX.to_le_bytes());
	assert!(matches!(
		fixture.replay(&bytes),
		Err(JournalReplayError::Frame(FrameReadError::Corrupt {
			problem: FrameProblem::UnsupportedKind(u16::MAX),
			..
		}))
	));

	for limit in [1, KINDS.len()] {
		let (mut bytes, boundaries) = fixture.records().bytes(limit);
		FrameWriter::new(&mut bytes, boundaries[limit].head)
			.append(FrameKind::JobPrepared, &[])
			.unwrap();
		assert!(matches!(
			fixture.replay(&bytes),
			Err(JournalReplayError::UnexpectedRecord {
				found: FrameKind::JobPrepared,
				..
			})
		));
	}

	let (mut bytes, boundaries) = fixture.records().bytes(1);
	let forged_head = ChainHead::after(7, boundaries[1].head.digest()).unwrap();
	FrameWriter::new(&mut bytes, forged_head)
		.append(FrameKind::EntryPrepared, &[])
		.unwrap();
	assert!(matches!(
		fixture.replay(&bytes),
		Err(JournalReplayError::NonconsecutiveSequence { sequence: 8 })
	));
}

#[test]
fn reader_failure_is_not_a_torn_tail() {
	struct Failure;
	impl Read for Failure {
		fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
			Err(io::ErrorKind::PermissionDenied.into())
		}
	}

	let fixture = Fixture::new();
	let (bytes, _) = fixture.records().bytes(5);
	assert!(matches!(
		replay_journal(bytes.as_slice().chain(Failure), &fixture.plan, &fixture.owner),
		Err(JournalReplayError::Frame(FrameReadError::Io { source, .. }))
			if source.kind() == io::ErrorKind::PermissionDenied
	));
}
