//! Exercise strict remote finalization with framed memory capabilities.

#![cfg(any(
	target_os = "linux",
	all(target_os = "macos", feature = "experimental-apfs-copy")
))]

use std::rc::Rc;

use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::remote_download::finalization::{
	RemoteDownloadReceipt, RemoteFinalizationBody, RemoteFinalizationRecord,
	RemotePublicationObservation,
};
use exacopy_transfer::remote_finalization::{
	FinalizationCause, FinalizationProgress, RemoteFinalizationOutcome,
};
use exacopy_transfer::remote_resume::TargetState;

#[path = "remote_finalization_engine/fixtures.rs"]
mod fixtures;

use fixtures::{
	Fault, RETIRED_STAGE, ReplayBeforeFinalization, STAGE, Step, TestRun, verify_committed_receipt,
};

const DATA: &[u8] = b"held SFTP bytes";
const INTENT: Step = Step::Append(FrameKind::PublishIntent);
const COMMIT: Step = Step::Append(FrameKind::ReceiptCommitted);

#[test]
fn exact_intent_precedes_one_effect_and_receipt_barriers_precede_commit() {
	for data in [DATA, b""] {
		let run = TestRun::new(data, Fault::None);
		let owner = run.owner().clone();
		let tape = Rc::clone(&run.tape);
		let journal = Rc::clone(&run.bytes);
		let (result, persisted) = run.execute();
		let RemoteFinalizationOutcome::PublishedWithOmissions(receipt) = result.unwrap() else {
			panic!("published receipt");
		};
		assert_eq!(receipt.canonical_receipt, persisted);
		assert_eq!(receipt.capture.length, u64::try_from(data.len()).unwrap());
		assert_eq!(
			receipt.capture.source_digest,
			*blake3::hash(data).as_bytes()
		);
		assert_eq!(receipt.target, STAGE);
		assert_eq!(
			RemoteDownloadReceipt::decode(&persisted)
				.unwrap()
				.digest()
				.unwrap(),
			receipt.digest
		);
		assert_eq!(
			*tape.borrow(),
			[
				Step::Authority(1),
				Step::ReceiptJob(1),
				Step::Location,
				Step::Metadata,
				Step::StageCheck(1),
				Step::Append(FrameKind::StageSealed),
				Step::Append(FrameKind::VerificationRecorded),
				Step::Append(FrameKind::MetadataRecorded),
				Step::StageCheck(2),
				Step::Authority(2),
				INTENT,
				Step::StageCheck(3),
				Step::Authority(3),
				Step::NativeFence,
				Step::Publish,
				Step::Append(FrameKind::PublishObserved),
				Step::Append(FrameKind::DurabilityRecorded),
				Step::ReceiptJob(2),
				Step::ReceiptDirectory,
				Step::ReceiptFile,
				Step::ReceiptWrite,
				Step::ReceiptFileSync,
				Step::ReceiptDirectorySync,
				Step::JobDirectorySync,
				COMMIT,
			]
		);
		let held = journal.borrow();
		verify_committed_receipt(&owner, held.get_ref(), &persisted);
		let mut reader = FrameReader::new(held.get_ref().as_slice(), ChainHead::start());
		let commit = std::iter::from_fn(|| reader.next_frame().unwrap())
			.last()
			.unwrap();
		assert_eq!(commit.head(), receipt.commitment);
		assert_eq!(
			RemoteFinalizationRecord::from_frame(&commit)
				.unwrap()
				.body(),
			RemoteFinalizationBody::ReceiptCommitted {
				digest: receipt.digest
			}
		);
	}
}

#[test]
fn recorded_retirement_allows_fresh_capture_to_commit_its_receipt() {
	let run = TestRun::after_retirement(DATA);
	let owner = run.owner().clone();
	let journal = Rc::clone(&run.bytes);
	let (result, persisted) = run.execute();
	let RemoteFinalizationOutcome::PublishedWithOmissions(receipt) = result.unwrap() else {
		panic!("fresh stage must publish");
	};
	let held = journal.borrow();
	let replay = verify_committed_receipt(&owner, held.get_ref(), &persisted);
	assert_eq!(receipt.target, STAGE);
	assert_eq!(receipt.capture.epoch.get(), 8);
	assert_eq!(replay.boundary().head, receipt.commitment);
	assert_eq!(replay.committed_digest(), Some(receipt.digest));
	let [old, active] = replay.attempts() else {
		panic!("exactly the retired and fresh attempts");
	};
	let [retired] = replay.retirements() else {
		panic!("one retained retirement");
	};
	assert_eq!(retired.stage, RETIRED_STAGE);
	assert_eq!(old.prepared().unwrap().file, RETIRED_STAGE);
	assert_eq!(active.prepared().unwrap().file, STAGE);
	assert_eq!(active.epochs().run.get(), 2);
}

#[test]
fn refuses_ineligible_replay_before_native_or_journal_effects() {
	for prefix in [
		ReplayBeforeFinalization::Sealed,
		ReplayBeforeFinalization::Uncertain,
		ReplayBeforeFinalization::Torn,
		ReplayBeforeFinalization::WrongQualification,
	] {
		let run = TestRun::new(DATA, Fault::None);
		let tape = Rc::clone(&run.tape);
		let (outcome, bytes) = run.with_refused_prefix(prefix);
		assert!(matches!(
			outcome.unwrap_err().cause,
			FinalizationCause::Binding
		));
		assert!(tape.borrow().is_empty());
		assert!(bytes.is_empty());
	}
}

#[test]
fn stale_authority_or_stage_never_reaches_a_public_effect() {
	for fault in [
		Fault::Boundary,
		Fault::StageMismatch,
		Fault::WrongNames,
		Fault::WrongStage,
		Fault::WrongDirectory,
		Fault::WrongParent,
		Fault::WrongStageName,
		Fault::ChangedReadyNames,
		Fault::Stop(Step::Location),
		Fault::Stop(Step::ReceiptJob(1)),
		Fault::Grant(1),
		Fault::Grant(2),
		Fault::Grant(3),
		Fault::Qualification(2),
		Fault::Qualification(3),
		Fault::Target(1, TargetState::Unknown),
		Fault::Target(3, TargetState::Occupied),
		Fault::Stop(Step::Metadata),
		Fault::Stop(Step::StageCheck(2)),
		Fault::Stop(Step::StageCheck(3)),
	] {
		let run = TestRun::new(DATA, fault);
		let tape = Rc::clone(&run.tape);
		let (outcome, bytes) = run.execute();
		let failure = outcome.unwrap_err();
		assert!(!tape.borrow().contains(&Step::Publish), "{fault:?}");
		assert!(bytes.is_empty(), "{fault:?}");
		if matches!(
			fault,
			Fault::WrongNames
				| Fault::WrongStage
				| Fault::WrongDirectory
				| Fault::WrongParent
				| Fault::WrongStageName
				| Fault::Stop(Step::Location)
		) {
			assert!(!tape.borrow().contains(&Step::Metadata), "{fault:?}");
		}
		if fault == Fault::ChangedReadyNames {
			assert!(tape.borrow().contains(&Step::Metadata));
		}

		assert_eq!(
			tape.borrow().contains(&INTENT),
			failure.progress == FinalizationProgress::IntentMayBeRecorded,
			"{fault:?}"
		);
	}
}

#[test]
fn bad_acknowledgements_and_receipt_cuts_stop_at_first_unconfirmed_boundary() {
	for (fault, published) in [
		(Fault::Stop(Step::Append(FrameKind::StageSealed)), false),
		(Fault::Ack(FrameKind::VerificationRecorded), false),
		(
			Fault::Stop(Step::Append(FrameKind::MetadataRecorded)),
			false,
		),
		(Fault::Stop(INTENT), false),
		(Fault::Ack(FrameKind::PublishIntent), false),
		(Fault::Offset(FrameKind::PublishIntent), false),
		(Fault::WrongBarrier(FrameKind::PublishIntent), false),
		(Fault::Stop(Step::Append(FrameKind::PublishObserved)), true),
		(
			Fault::Stop(Step::Append(FrameKind::DurabilityRecorded)),
			true,
		),
		(Fault::Stop(Step::ReceiptJob(2)), true),
		(Fault::Stop(Step::ReceiptDirectory), true),
		(Fault::Stop(Step::ReceiptFile), true),
		(Fault::Stop(Step::ReceiptWrite), true),
		(Fault::Stop(Step::ReceiptFileSync), true),
		(Fault::Stop(Step::ReceiptDirectorySync), true),
		(Fault::Stop(Step::JobDirectorySync), true),
		(Fault::Stop(COMMIT), true),
		(Fault::Ack(FrameKind::ReceiptCommitted), true),
	] {
		let run = TestRun::new(DATA, fault);
		let tape = Rc::clone(&run.tape);
		let (outcome, _) = run.execute();
		let failure = outcome.unwrap_err();
		assert_eq!(
			tape.borrow().contains(&Step::Publish),
			published,
			"{fault:?}"
		);
		if published {
			assert_eq!(
				failure.progress,
				FinalizationProgress::PublishedIncomplete,
				"{fault:?}"
			);
		} else {
			assert!(
				!tape.borrow().contains(&Step::ReceiptDirectory),
				"{fault:?}"
			);
			assert!(
				matches!(
					failure.progress,
					FinalizationProgress::PrivateJournalUncertain
						| FinalizationProgress::IntentMayBeRecorded
				),
				"{fault:?}"
			);
		}
		if let Fault::Stop(step) = fault {
			assert_eq!(tape.borrow().last(), Some(&step), "{fault:?}");
		}
	}
}

#[test]
fn conflict_and_uncertain_effect_never_produce_a_receipt() {
	for fault in [
		Fault::Conflict,
		Fault::Uncertain,
		Fault::WrongPublishedIdentity,
	] {
		let run = TestRun::new(DATA, fault);
		let tape = Rc::clone(&run.tape);
		let journal = Rc::clone(&run.bytes);
		let (result, bytes) = run.execute();
		assert!(bytes.is_empty());
		assert_eq!(
			tape.borrow()
				.iter()
				.filter(|step| **step == Step::Publish)
				.count(),
			1
		);
		assert!(!tape.borrow().contains(&COMMIT));
		let held = journal.borrow();
		let mut reader = FrameReader::new(held.get_ref().as_slice(), ChainHead::start());
		let frame = std::iter::from_fn(|| reader.next_frame().unwrap())
			.last()
			.unwrap();
		let record = RemoteFinalizationRecord::from_frame(&frame).unwrap();
		match result {
			Ok(RemoteFinalizationOutcome::Conflict { observation }) if fault == Fault::Conflict => {
				assert_eq!(frame.head(), observation);
				assert_eq!(
					record.body(),
					RemoteFinalizationBody::PublishObserved(RemotePublicationObservation::Conflict)
				);
			}
			Err(failure) => {
				assert_eq!(failure.progress, FinalizationProgress::PublicationUncertain);
				if fault == Fault::Uncertain {
					assert!(
						matches!(failure.cause, FinalizationCause::Publication { observation: Some(head), .. } if head == frame.head())
					);
					assert!(matches!(
						record.body(),
						RemoteFinalizationBody::PublishObserved(
							RemotePublicationObservation::Uncertain { .. }
						)
					));
				} else {
					assert_eq!(record.body().kind(), FrameKind::PublishIntent);
				}
			}
			other => panic!("unexpected outcome for {fault:?}: {other:?}"),
		}
	}
}

#[test]
fn intact_capture_from_another_job_refuses_before_metadata_effect() {
	let selected = TestRun::new(DATA, Fault::None);
	let mut other_job = *selected.owner().manifest().job.as_bytes();
	other_job[15] ^= 2;
	let donor = TestRun::for_job(DATA, Fault::None, other_job);
	assert_ne!(
		selected.owner().manifest().job,
		donor.owner().manifest().job
	);
	assert_eq!(
		selected.owner().manifest().scope,
		donor.owner().manifest().scope
	);

	let selected_tape = Rc::clone(&selected.tape);
	let donor_tape = Rc::clone(&donor.tape);
	let journal = Rc::clone(&selected.bytes);
	let before = journal.borrow().get_ref().to_vec();
	let (result, persisted) = selected.with_capture_from(donor).execute();

	let failure = result.unwrap_err();
	assert!(matches!(failure.cause, FinalizationCause::Binding));
	assert_eq!(failure.progress, FinalizationProgress::BeforeIntent);
	assert!(
		!donor_tape.borrow().contains(&Step::Metadata),
		"foreign stage received metadata"
	);
	assert!(!selected_tape.borrow().contains(&Step::Publish));
	assert_eq!(*journal.borrow().get_ref(), before);
	assert!(persisted.is_empty());
}

#[test]
fn grant_refusal_at_native_fence_leaves_intent_for_reconciliation() {
	let run = TestRun::new(DATA, Fault::NativeFence);
	let tape = Rc::clone(&run.tape);
	let (result, persisted) = run.execute();
	let failure = result.unwrap_err();
	assert_eq!(failure.progress, FinalizationProgress::PublicationUncertain);
	assert!(matches!(
		failure.cause,
		FinalizationCause::Publication {
			observation: Some(_),
			..
		}
	));
	assert!(tape.borrow().contains(&INTENT));
	assert!(tape.borrow().contains(&Step::NativeFence));
	assert!(!tape.borrow().contains(&Step::Publish));
	assert!(persisted.is_empty());
}
