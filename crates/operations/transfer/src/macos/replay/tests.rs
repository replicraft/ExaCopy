use std::io::{self, Read as _};
use std::num::{NonZeroU32, NonZeroU64};

use ed25519_dalek::SigningKey;
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{
	DarwinPublicationOutcome, DarwinReceiptCommitted, DarwinReceiptDigest, DarwinSourceView,
};

use super::{
	DarwinJournalBoundary, DarwinJournalTail, DarwinReplayAuthority, DarwinReplayError,
	DarwinReplayStatus, replay_journal,
};

mod fixture;
mod receipt;

use fixture::{Fixture, identity, name};

#[test]
fn retains_every_clean_prefix_and_each_byte_of_torn_tail() {
	let fixture = Fixture::new();
	let mut history = fixture.records.prefix(8);
	let committed =
		DarwinReceiptCommitted::new(history.last(), DarwinReceiptDigest::from_bytes([0xAA; 32]))
			.unwrap();
	history.append(FrameKind::ReceiptCommitted, &committed.encode());
	let statuses = [
		DarwinReplayStatus::Incomplete,
		DarwinReplayStatus::Incomplete,
		DarwinReplayStatus::Incomplete,
		DarwinReplayStatus::Incomplete,
		DarwinReplayStatus::Incomplete,
		DarwinReplayStatus::Incomplete,
		DarwinReplayStatus::Uncertain,
		DarwinReplayStatus::PublishedIncomplete,
		DarwinReplayStatus::PublishedIncomplete,
		DarwinReplayStatus::Complete,
	];
	let mut start = 0;
	let mut head = ChainHead::start();
	for (index, expected_status) in statuses.into_iter().enumerate() {
		let replay = fixture.replay(&history.bytes[..start]).unwrap();
		let boundary = DarwinJournalBoundary {
			head,
			offset: start as u64,
		};
		assert_eq!(replay.boundary(), boundary);
		assert_eq!(replay.tail(), DarwinJournalTail::Clean);
		assert_eq!(replay.status(), expected_status);
		for frame in &history.frames[..index] {
			assert_eq!(replay.frame(frame.kind()), Some(frame));
		}
		let Some(frame) = history.frames.get(index) else {
			break;
		};
		let end = history.ends[index];
		for cut in (start + 1)..end {
			let replay = fixture.replay(&history.bytes[..cut]).unwrap();
			assert_eq!(replay.boundary(), boundary, "torn prefix at byte {cut}");
			assert_eq!(
				replay.tail(),
				DarwinJournalTail::Torn {
					bytes_read: cut - start
				}
			);
			assert_eq!(replay.status(), expected_status);
			assert!(replay.frame(frame.kind()).is_none());
		}
		start = end;
		head = frame.head();
	}
}

#[test]
fn distinguishes_terminal_adapter_outcomes_and_rejects_reconciliation() {
	let fixture = Fixture::new();
	let cases = [
		(
			DarwinPublicationOutcome::RejectedBeforeRename,
			DarwinReplayStatus::Incomplete,
		),
		(
			DarwinPublicationOutcome::Conflict,
			DarwinReplayStatus::Conflict,
		),
		(
			DarwinPublicationOutcome::UncertainRename,
			DarwinReplayStatus::Uncertain,
		),
		(
			DarwinPublicationOutcome::RenameConfirmedIncomplete,
			DarwinReplayStatus::PublishedIncomplete,
		),
	];
	for (outcome, status) in cases {
		let mut history = fixture.records.prefix(6);
		let payload = fixture.observation(history.last(), outcome);
		history.append(FrameKind::PublishObserved, &payload);
		assert_eq!(fixture.replay(&history.bytes).unwrap().status(), status);
		history.append(
			FrameKind::DurabilityRecorded,
			fixture.records.frames[7].payload(),
		);
		assert!(matches!(
			fixture.replay(&history.bytes),
			Err(DarwinReplayError::Phase(_))
		));
	}

	let mut history = fixture.records.prefix(6);
	let payload = fixture.observation(
		history.last(),
		DarwinPublicationOutcome::ReconciledPublished,
	);
	history.append(FrameKind::PublishObserved, &payload);
	assert!(matches!(
		fixture.replay(&history.bytes),
		Err(DarwinReplayError::UnsupportedRecoveryObservation)
	));
}

#[test]
fn refuses_wrong_trust_credentials_and_private_directory_identity_even_before_first_frame() {
	let fixture = Fixture::new();
	let owner = fixture.owner.as_bytes();
	let changed_key = SigningKey::from_bytes(&[23; 32]).verifying_key();
	let mut changed_signature = owner.to_vec();
	*changed_signature.last_mut().unwrap() ^= 1;
	assert!(matches!(
		replay_journal(
			&[][..],
			&fixture.plan,
			owner,
			DarwinReplayAuthority {
				key: &changed_key,
				..fixture.authority()
			}
		),
		Err(DarwinReplayError::Owner(_))
	));
	assert!(matches!(
		replay_journal(
			&[][..],
			&fixture.plan,
			&changed_signature,
			fixture.authority()
		),
		Err(DarwinReplayError::Owner(_))
	));
	for authority in [
		DarwinReplayAuthority {
			state_root: identity(50),
			..fixture.authority()
		},
		DarwinReplayAuthority {
			state_root_uid: NonZeroU32::new(502).unwrap(),
			..fixture.authority()
		},
	] {
		assert!(matches!(
			replay_journal(&[][..], &fixture.plan, owner, authority),
			Err(DarwinReplayError::OwnerBinding)
		));
	}
}

#[test]
fn rejects_a_stale_source_wrong_target_and_stage_alias_to_signed_job_root() {
	let fixture = Fixture::new();
	let entry = fixture.entry();
	let source = entry.source;
	let changed_source = DarwinSourceView::new(
		source.root(),
		source.component(),
		source.identity(),
		source.length() + 1,
		source.times(),
		source.metadata(),
	)
	.unwrap();
	for preparation in [
		exacopy_journal::DarwinEntryPreparation {
			source: changed_source,
			..entry
		},
		exacopy_journal::DarwinEntryPreparation {
			target_component: name(b"elsewhere"),
			..entry
		},
		exacopy_journal::DarwinEntryPreparation {
			stage: exacopy_journal::DarwinStageObservation {
				directory: fixture.authority().state_root,
				..entry.stage
			},
			..entry
		},
	] {
		let history = fixture.prepared(preparation);
		assert!(matches!(
			fixture.replay(&history.bytes),
			Err(DarwinReplayError::RecordBinding {
				kind: FrameKind::EntryPrepared
			})
		));
	}
}

#[test]
fn rejects_unknown_order_or_epochs_and_complete_extra_frames() {
	let fixture = Fixture::new();
	for kind in [
		FrameKind::RangeCheckpoint,
		FrameKind::RecoveryStarted,
		FrameKind::RecoveryDecision,
	] {
		let mut history = fixture.records.prefix(2);
		history.append(kind, &[]);
		assert!(matches!(
			fixture.replay(&history.bytes),
			Err(DarwinReplayError::UnexpectedRecord {
				expected: Some(FrameKind::StageSealed), found
			}) if found == kind
		));
	}
	let mut history = fixture.records.prefix(8);
	let committed =
		DarwinReceiptCommitted::new(history.last(), DarwinReceiptDigest::from_bytes([0x32; 32]))
			.unwrap();
	history.append(FrameKind::ReceiptCommitted, &committed.encode());
	history.append(FrameKind::ReceiptCommitted, &committed.encode());
	assert!(matches!(
		fixture.replay(&history.bytes),
		Err(DarwinReplayError::UnexpectedRecord {
			expected: None,
			found: FrameKind::ReceiptCommitted
		})
	));
}

#[test]
fn refuses_integrity_errors_and_never_scans_past_the_failed_frame() {
	let fixture = Fixture::new();
	let frames = &fixture.records.frames;
	let mut no_chain = fixture.records.prefix(1);
	let foreign = ChainHead::after(1, [0x31; 32]).unwrap();
	no_chain.append_after(foreign, FrameKind::EntryPrepared, frames[1].payload());
	no_chain.bytes.extend(&fixture.records.bytes);
	assert!(matches!(
		fixture.replay(&no_chain.bytes),
		Err(DarwinReplayError::Frame(_))
	));

	let mut gap = fixture.records.prefix(1);
	let skipped = ChainHead::after(2, gap.last().head().digest()).unwrap();
	gap.append_after(skipped, FrameKind::EntryPrepared, frames[1].payload());
	assert!(matches!(
		fixture.replay(&gap.bytes),
		Err(DarwinReplayError::NonconsecutiveSequence { sequence: 3 })
	));

	let mut flipped = fixture.records.bytes.clone();
	flipped[fixture.records.ends[1] - 1] ^= 1;
	assert!(matches!(
		fixture.replay(&flipped),
		Err(DarwinReplayError::Frame(_))
	));

	struct BrokenReader;
	impl io::Read for BrokenReader {
		fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
			Err(io::Error::other("unreadable journal"))
		}
	}
	let reader = fixture.records.bytes.as_slice().chain(BrokenReader);
	assert!(matches!(
		replay_journal(
			reader,
			&fixture.plan,
			fixture.owner.as_bytes(),
			fixture.authority()
		),
		Err(DarwinReplayError::Frame(
			exacopy_journal::frame::FrameReadError::Io { .. }
		))
	));
}

#[test]
fn binds_the_first_effect_and_requires_references_to_actual_accepted_frames() {
	let fixture = Fixture::new();
	let mut history = fixture.records.prefix(2);
	fixture.write_intent(&mut history, NonZeroU64::new(2).unwrap());
	assert!(matches!(
		fixture.replay(&history.bytes),
		Err(DarwinReplayError::Phase(_))
	));

	let foreign_anchor = ChainHead::after(5, [0xB3; 32]).unwrap();
	let mut detached = fixture::History::default();
	detached.append_after(
		foreign_anchor,
		FrameKind::PublishIntent,
		fixture.records.frames[5].payload(),
	);
	let mut history = fixture.records.prefix(6);
	let payload = fixture.observation(detached.last(), DarwinPublicationOutcome::Published);
	history.append(FrameKind::PublishObserved, &payload);
	assert!(matches!(
		fixture.replay(&history.bytes),
		Err(DarwinReplayError::Phase(_))
	));

	let foreign_anchor = ChainHead::after(7, [0xA3; 32]).unwrap();
	detached.append_after(
		foreign_anchor,
		FrameKind::DurabilityRecorded,
		fixture.records.frames[7].payload(),
	);
	let committed =
		DarwinReceiptCommitted::new(detached.last(), DarwinReceiptDigest::from_bytes([0xD3; 32]))
			.unwrap();
	let mut history = fixture.records.prefix(8);
	history.append(FrameKind::ReceiptCommitted, &committed.encode());
	assert!(matches!(
		fixture.replay(&history.bytes),
		Err(DarwinReplayError::Phase(_))
	));
}
