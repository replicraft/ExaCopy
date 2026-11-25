use exacopy_content::CheckpointCandidate;
use exacopy_journal::{
	JournalEpoch, PublicationOutcome, PublishObserved, RangeResumeStarted, ReceiptCommitted,
};

use super::*;
use fixtures::{Fixture, SOURCE, STAGE, Simulation};

mod fixtures;

#[test]
fn resumes_verified_prefix_and_rewrites_mismatched_ranges_before_publication() {
	let fixture = Fixture::new();
	let simulation = Simulation::new(&fixture, b"abXX", false);
	let candidates = [
		CheckpointCandidate {
			offset: 0,
			length: 2,
			digest: *blake3::hash(b"ab").as_bytes(),
		},
		CheckpointCandidate {
			offset: 2,
			length: 2,
			digest: *blake3::hash(b"cd").as_bytes(),
		},
	];

	simulation.resume(PRIVATE_STAGE_MODE, &candidates).unwrap();

	assert_eq!(&*simulation.0.stage.borrow(), SOURCE);
	assert_eq!(simulation.0.writes.borrow().as_slice(), [(2, 2), (4, 2)]);
	let frames = simulation.0.frames();
	assert_eq!(
		frames[2..]
			.iter()
			.map(|frame| frame.kind())
			.collect::<Vec<_>>(),
		[
			FrameKind::RecoveryStarted,
			FrameKind::StageSealed,
			FrameKind::VerificationRecorded,
			FrameKind::MetadataRecorded,
			FrameKind::PublishIntent,
			FrameKind::PublishObserved,
			FrameKind::DurabilityRecorded,
			FrameKind::ReceiptCommitted,
		]
	);
	let started = RangeResumeStarted::from_frame(&frames[2]).unwrap();
	assert_eq!(started.context().epoch, JournalEpoch::new(4));
	assert_eq!(started.evidence().stage, STAGE);
	assert_eq!(started.evidence().preparation, simulation.1.head);
	assert_eq!(started.evidence().authorization, fixture.owner);
	let committed = ReceiptCommitted::from_frame(&frames[9]).unwrap();
	assert_eq!(committed.context().epoch, JournalEpoch::new(4));
	assert_eq!(simulation.0.receipts.get(), 1);
}

#[test]
fn a_failed_journal_reopen_provides_no_write_or_publication_authority() {
	let fixture = Fixture::new();
	let simulation = Simulation::new(&fixture, b"abXX", true);

	assert!(matches!(
		simulation.resume(PRIVATE_STAGE_MODE, &[]),
		Err(ResumeError::Records(_))
	));
	assert_eq!(&*simulation.0.stage.borrow(), b"abXX");
	assert!(simulation.0.writes.borrow().is_empty());
	assert_eq!(simulation.0.frames().len(), 2);
	assert_eq!(simulation.0.receipts.get(), 0);
}

#[test]
fn read_only_retained_mismatch_leaves_the_epoch_and_stage_unchanged() {
	let fixture = Fixture::new();
	let simulation = Simulation::new(&fixture, b"ABcdef", false);

	assert!(matches!(
		simulation.resume(fixtures::PLANNED_MODE, &[]),
		Err(ResumeError::ResumeStage(StageFailure::DigestMismatch))
	));
	assert_eq!(&*simulation.0.stage.borrow(), b"ABcdef");
	assert!(simulation.0.writes.borrow().is_empty());
	assert_eq!(simulation.0.frames().len(), 2);
	assert_eq!(simulation.0.receipts.get(), 0);
}

#[test]
fn uncertain_publication_records_uncertainty_without_committing_a_receipt() {
	let fixture = Fixture::new();
	let simulation = Simulation::new(&fixture, b"abcdef", false);
	simulation.0.uncertain_publication.set(true);

	assert!(matches!(
		simulation.resume(fixtures::PLANNED_MODE, &[]),
		Err(ResumeError::Publish(_))
	));
	assert!(simulation.0.writes.borrow().is_empty());
	let frames = simulation.0.frames();
	assert_eq!(frames.len(), 8);
	let observed = PublishObserved::from_frame(&frames[7]).unwrap();
	assert!(matches!(
		observed.outcome(),
		PublicationOutcome::Uncertain { .. }
	));
	assert_eq!(simulation.0.receipts.get(), 0);
}
