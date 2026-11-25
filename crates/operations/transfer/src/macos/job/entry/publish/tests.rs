use std::cell::RefCell;
use std::fs::File;
use std::io;

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinNamespaceObservation, DarwinPublicationBarriers, DarwinPublicationOutcome,
	DarwinPublishObserved, DarwinRequiredMetadata, DurableJournal, DurableJournalError,
	OwnerTimestamp, StreamDigest, SyncedFrame,
};
use exacopy_model::{CopyBinding, PublishNoClobber};
use exacopy_platform::macos::ManagedReadError;
use exacopy_platform::macos::publication::PublishError;
use exacopy_platform::macos::staging::jobs::JobError;

use crate::macos::job::tests::with_publication_fixture;
use crate::macos::receipt::DarwinCopyReceipt;

use super::capabilities::{
	FailedEffect, PreparedCopy, PublicationFailure, PublicationJournal, PublishedEvidence,
	ReceiptStore, VerifiedCopy, VerifiedStreams,
};
use super::{DarwinCopyFailure, PreparedEvidence, PublicationProgress, engine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
	SourceBeforeRead,
	Verified,
	SourceAfterMetadata,
	Append(FrameKind),
	Publish,
	Persist,
}

#[derive(Debug, Clone, Copy)]
enum Scenario {
	Success,
	SourceChanged,
	IntentBarrierFailed,
	WrongIntentToken,
	Conflict,
	ReceiptFailed,
}

const THROUGH_METADATA: &[Step] = &[
	Step::SourceBeforeRead,
	Step::Verified,
	Step::Append(FrameKind::StageSealed),
	Step::Append(FrameKind::VerificationRecorded),
	Step::Append(FrameKind::MetadataRecorded),
	Step::SourceAfterMetadata,
];

#[test]
fn coordinator_refuses_publication_without_current_source_and_exact_synced_intent() {
	for (scenario, unexpected_intent) in [
		(Scenario::SourceChanged, false),
		(Scenario::IntentBarrierFailed, true),
		(Scenario::WrongIntentToken, true),
	] {
		run(scenario, |result, progress, script| {
			let mut expected = THROUGH_METADATA.to_vec();
			if unexpected_intent {
				expected.push(Step::Append(FrameKind::PublishIntent));
			}
			match scenario {
				Scenario::SourceChanged => assert!(matches!(
					result,
					Err(DarwinCopyFailure::Source(ManagedReadError::SourceChanged))
				)),
				Scenario::IntentBarrierFailed => assert!(matches!(
					result,
					Err(DarwinCopyFailure::Journal {
						kind: FrameKind::PublishIntent,
						error: DurableJournalError::Sync(_),
					})
				)),
				Scenario::WrongIntentToken => {
					assert!(matches!(result, Err(DarwinCopyFailure::UnexpectedBarrier)));
				}
				_ => unreachable!("non-refusal scenario in intent refusal test"),
			}
			assert_eq!(progress, PublicationProgress::Private, "{scenario:?}");
			assert_eq!(*script.steps.borrow(), expected, "{scenario:?}");
		});
	}
}

#[test]
fn coordinator_records_conflict_and_keeps_receipt_uncommitted() {
	run(Scenario::Conflict, |result, progress, script| {
		assert!(matches!(
			result,
			Err(DarwinCopyFailure::Publish { error, recording: None })
				if matches!(*error, PublishError::Conflict { .. })
		));
		assert_eq!(progress, PublicationProgress::IntentSynchronized);
		assert_eq!(
			*script.steps.borrow(),
			[
				THROUGH_METADATA,
				&[
					Step::Append(FrameKind::PublishIntent),
					Step::Publish,
					Step::Append(FrameKind::PublishObserved),
				],
			]
			.concat()
		);
		let observations = script.observations.borrow();
		assert_eq!(
			observations[0].outcome(),
			DarwinPublicationOutcome::Conflict
		);
		assert_eq!(
			observations[0].names().target,
			DarwinNamespaceObservation::Unobserved
		);
		assert!(script.receipt.borrow().is_empty());
	});
}

#[test]
fn coordinator_commits_only_after_receipt_persistence() {
	for scenario in [Scenario::Success, Scenario::ReceiptFailed] {
		run(scenario, |result, progress, script| {
			let mut expected = THROUGH_METADATA.to_vec();
			expected.extend([
				Step::Append(FrameKind::PublishIntent),
				Step::Publish,
				Step::Append(FrameKind::PublishObserved),
				Step::Append(FrameKind::DurabilityRecorded),
				Step::Persist,
			]);
			match scenario {
				Scenario::Success => {
					let receipt = result.unwrap();
					assert_eq!(*script.receipt.borrow(), receipt.encode());
					assert_eq!(progress, PublicationProgress::ReceiptCommitted);
					expected.push(Step::Append(FrameKind::ReceiptCommitted));
				}
				Scenario::ReceiptFailed => {
					assert!(matches!(result, Err(DarwinCopyFailure::PersistReceipt(_))));
					assert_eq!(progress, PublicationProgress::Renamed);
					assert!(script.receipt.borrow().is_empty());
				}
				_ => unreachable!("non-receipt scenario in receipt commitment test"),
			}
			assert_eq!(*script.steps.borrow(), expected);
		});
	}
}

struct Script {
	scenario: Scenario,
	steps: RefCell<Vec<Step>>,
	observations: RefCell<Vec<DarwinPublishObserved>>,
	receipt: RefCell<Vec<u8>>,
}

impl Script {
	fn step(&self, step: Step) {
		self.steps.borrow_mut().push(step);
	}
}

struct ScriptedCopy<'test> {
	script: &'test Script,
	binding: CopyBinding,
	streams: VerifiedStreams,
	metadata: DarwinRequiredMetadata,
	barriers: DarwinPublicationBarriers,
}

impl PreparedCopy for ScriptedCopy<'_> {
	type Verified = Self;

	fn binding(&self) -> CopyBinding {
		self.binding
	}

	fn check_source_before_read(&self) -> Result<(), DarwinCopyFailure> {
		self.script.step(Step::SourceBeforeRead);
		Ok(())
	}

	fn verify(self, _scratch: &mut [u8]) -> Result<Self, DarwinCopyFailure> {
		self.script.step(Step::Verified);
		Ok(self)
	}
}

impl VerifiedCopy for ScriptedCopy<'_> {
	fn observe_streams(&self) -> Result<VerifiedStreams, DarwinCopyFailure> {
		Ok(VerifiedStreams { ..self.streams })
	}

	fn required_metadata(&self) -> Result<DarwinRequiredMetadata, DarwinCopyFailure> {
		Ok(self.metadata)
	}

	fn check_source_after_metadata(&self) -> Result<(), DarwinCopyFailure> {
		self.script.step(Step::SourceAfterMetadata);
		if matches!(self.script.scenario, Scenario::SourceChanged) {
			return Err(DarwinCopyFailure::Source(ManagedReadError::SourceChanged));
		}
		Ok(())
	}

	fn publish_exclusively(
		self,
		authorization: PublishNoClobber,
	) -> Result<PublishedEvidence, PublicationFailure> {
		assert_eq!(authorization.binding(), self.binding);
		self.script.step(Step::Publish);
		if matches!(self.script.scenario, Scenario::Conflict) {
			return Err(PublicationFailure {
				cause: Box::new(PublishError::Conflict { policy_error: None }),
				effect: FailedEffect::Conflict,
			});
		}
		Ok(PublishedEvidence {
			target: Ok(self.streams.stage),
			barriers: Ok(self.barriers),
		})
	}
}

struct Journal<'test> {
	script: &'test Script,
	journal: &'test mut DurableJournal,
	wrong_token: Option<SyncedFrame>,
}

impl PublicationJournal for Journal<'_> {
	fn append(
		&mut self,
		kind: FrameKind,
		payload: Vec<u8>,
	) -> Result<(Frame, SyncedFrame), DurableJournalError> {
		self.script.step(Step::Append(kind));
		if kind == FrameKind::PublishIntent
			&& matches!(self.script.scenario, Scenario::IntentBarrierFailed)
		{
			return Err(DurableJournalError::Sync(io::Error::other(
				"fixture barrier failure",
			)));
		}
		let (frame, synced) = self.journal.append_frame(kind, payload)?;
		if kind == FrameKind::PublishObserved {
			self.script
				.observations
				.borrow_mut()
				.push(DarwinPublishObserved::from_frame(&frame).unwrap());
		}
		if kind == FrameKind::PublishIntent
			&& let Some(wrong) = self.wrong_token.take()
		{
			return Ok((frame, wrong));
		}
		Ok((frame, synced))
	}
}

impl ReceiptStore for Script {
	fn persist(&self, bytes: &[u8]) -> Result<(), DarwinCopyFailure> {
		self.step(Step::Persist);
		if matches!(self.scenario, Scenario::ReceiptFailed) {
			return Err(DarwinCopyFailure::PersistReceipt(JobError::IdentityChanged));
		}
		self.receipt.replace(bytes.to_vec());
		Ok(())
	}
}

fn run(
	scenario: Scenario,
	check: impl FnOnce(Result<DarwinCopyReceipt<'_>, DarwinCopyFailure>, PublicationProgress, &Script),
) {
	with_publication_fixture(|entry, path| {
		let script = Script {
			scenario,
			steps: RefCell::new(Vec::new()),
			observations: RefCell::new(Vec::new()),
			receipt: RefCell::new(Vec::new()),
		};
		let mut journal = Journal {
			script: &script,
			journal: entry.journal,
			wrong_token: None,
		};
		if matches!(scenario, Scenario::WrongIntentToken) {
			let file = File::options()
				.read(true)
				.write(true)
				.create_new(true)
				.open(path.join("alternate-journal"))
				.unwrap();
			let mut other =
				DurableJournal::from_new_file_with_barrier(file, entry.synced.barrier()).unwrap();
			journal.wrong_token = Some(
				other
					.append(FrameKind::PublishIntent, b"another intent")
					.unwrap(),
			);
		}
		let prep = entry.preparation.preparation();
		let source = entry.plan.source();
		let metadata = source.metadata;
		let owner_time = |time: exacopy_journal::ObservedTimestamp| {
			OwnerTimestamp::new(time.seconds(), time.nanoseconds()).unwrap()
		};
		let copy = ScriptedCopy {
			script: &script,
			binding: entry.writer.as_ref().unwrap().binding(),
			streams: VerifiedStreams {
				stage: prep.stage.identity,
				length: source.length,
				source_digest: StreamDigest::from_bytes([1; 32]),
				stage_digest: StreamDigest::from_bytes([1; 32]),
			},
			metadata: DarwinRequiredMetadata::new(
				u32::from(metadata.mode()),
				metadata.uid(),
				metadata.gid(),
				owner_time(metadata.accessed_at()),
				owner_time(metadata.modified_at()),
			)
			.unwrap(),
			barriers: DarwinPublicationBarriers {
				stage_directory: prep.stage.directory,
				destination_directory: entry.plan.destination().root_identity,
			},
		};
		let mut progress = PublicationProgress::Private;
		let result = engine::execute(
			PreparedEvidence {
				frame: &entry.frame,
				source: prep.source.identity(),
				plan: &entry.plan,
			},
			copy,
			&mut journal,
			&script,
			&mut [0; 128],
			&mut progress,
		);
		check(result, progress, &script);
	});
}
