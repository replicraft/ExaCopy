use std::cell::RefCell;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinNamespaceObservation, DarwinPhaseError, DarwinPublicationBarriers,
	DarwinPublicationOutcome, DarwinPublishIntent, DarwinPublishObserved, DarwinRequiredMetadata,
	DurableJournal, DurableJournalError, OwnerTimestamp, StreamDigest, SyncedFrame,
};
use exacopy_model::{CopyBinding, PublishNoClobber};
use exacopy_transfer::macos::job::entry::publish::{
	CoordinatorError, CopyFailure, FailedEffect, PreparedCopy, PublicationFailure,
	PublicationJournal, PublishedEvidence, ReceiptStore, VerifiedCopy, VerifiedStreams, execute,
};

use crate::assembly::macos::job::tests::with_publication_fixture;
use crate::assembly::macos::receipt::DarwinCopyReceipt;

use super::{PreparedEvidence, PublicationProgress};

#[derive(Debug)]
struct SourceChanged;

#[derive(Debug)]
enum PublishCause {
	Conflict,
	Renamed,
}

#[derive(Debug)]
struct ReceiptWriteFailed;

type ScriptFailure = CopyFailure<SourceChanged, PublishCause, ReceiptWriteFailed>;

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
	WrongIntentPayload,
	RenamedRecordingFailed,
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
		(Scenario::WrongIntentPayload, true),
	] {
		run(scenario, |result, progress, script| {
			let mut expected = THROUGH_METADATA.to_vec();
			if unexpected_intent {
				expected.push(Step::Append(FrameKind::PublishIntent));
			}
			match scenario {
				Scenario::SourceChanged => {
					assert!(matches!(result, Err(CopyFailure::Adapter(SourceChanged))))
				}
				Scenario::IntentBarrierFailed => assert!(matches!(
					result,
					Err(CopyFailure::Coordinator(CoordinatorError::Journal {
						kind: FrameKind::PublishIntent,
						error: DurableJournalError::Sync(_),
					}))
				)),
				Scenario::WrongIntentToken => {
					assert!(matches!(
						result,
						Err(CopyFailure::Coordinator(
							CoordinatorError::UnexpectedBarrier
						))
					));
				}
				Scenario::WrongIntentPayload => assert!(matches!(
					result,
					Err(CopyFailure::Coordinator(CoordinatorError::Record(
						DarwinPhaseError::BindingMismatch
					)))
				)),
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
			Err(CopyFailure::Publish {
				error: PublishCause::Conflict,
				recording: None
			})
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
fn confirmed_rename_survives_failed_outcome_recording() {
	run(
		Scenario::RenamedRecordingFailed,
		|result, progress, script| {
			let Err(CopyFailure::Publish {
				error: PublishCause::Renamed,
				recording: Some(recording),
			}) = result
			else {
				panic!("failed recording must retain the original rename evidence");
			};
			assert!(matches!(
				*recording,
				CoordinatorError::Journal {
					kind: FrameKind::PublishObserved,
					error: DurableJournalError::Sync(_),
				}
			));
			assert_eq!(progress, PublicationProgress::Renamed);
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
			assert!(script.receipt.borrow().is_empty());
		},
	);
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
					assert!(matches!(
						result,
						Err(CopyFailure::PersistReceipt(ReceiptWriteFailed))
					));
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
	type Error = SourceChanged;
	type PublishError = PublishCause;
	type Verified = Self;

	fn binding(&self) -> CopyBinding {
		self.binding
	}

	fn check_source_before_read(&self) -> Result<(), SourceChanged> {
		self.script.step(Step::SourceBeforeRead);
		Ok(())
	}

	fn verify(self, _scratch: &mut [u8]) -> Result<Self, SourceChanged> {
		self.script.step(Step::Verified);
		Ok(self)
	}
}

impl VerifiedCopy for ScriptedCopy<'_> {
	type Error = SourceChanged;
	type PublishError = PublishCause;

	fn observe_streams(&self) -> Result<VerifiedStreams, SourceChanged> {
		Ok(VerifiedStreams { ..self.streams })
	}

	fn required_metadata(&self) -> Result<DarwinRequiredMetadata, SourceChanged> {
		Ok(self.metadata)
	}

	fn check_source_after_metadata(&self) -> Result<(), SourceChanged> {
		self.script.step(Step::SourceAfterMetadata);
		if matches!(self.script.scenario, Scenario::SourceChanged) {
			return Err(SourceChanged);
		}
		Ok(())
	}

	fn publish_exclusively(
		self,
		authorization: PublishNoClobber,
	) -> Result<PublishedEvidence, PublicationFailure<Self::PublishError>> {
		assert_eq!(authorization.binding(), self.binding);
		self.script.step(Step::Publish);
		match self.script.scenario {
			Scenario::Conflict => {
				return Err(PublicationFailure {
					cause: PublishCause::Conflict,
					effect: FailedEffect::Conflict,
				});
			}
			Scenario::RenamedRecordingFailed => {
				return Err(PublicationFailure {
					cause: PublishCause::Renamed,
					effect: FailedEffect::Renamed {
						target: Some(Ok(self.streams.stage)),
					},
				});
			}
			_ => {}
		}
		Ok(PublishedEvidence {
			target: Ok(self.streams.stage),
			barriers: Ok(self.barriers),
		})
	}
}

struct Journal<'test> {
	script: &'test Script,
	journal: &'test mut dyn PublicationJournal,
	wrong_token: Option<SyncedFrame>,
}

impl PublicationJournal for Journal<'_> {
	fn append(
		&mut self,
		kind: FrameKind,
		mut payload: Vec<u8>,
	) -> Result<(Frame, SyncedFrame), DurableJournalError> {
		self.script.step(Step::Append(kind));
		if matches!(
			(kind, self.script.scenario),
			(FrameKind::PublishIntent, Scenario::IntentBarrierFailed)
				| (FrameKind::PublishObserved, Scenario::RenamedRecordingFailed)
		) {
			return Err(DurableJournalError::Sync(io::Error::other(
				"fixture barrier failure",
			)));
		}
		if kind == FrameKind::PublishIntent
			&& matches!(self.script.scenario, Scenario::WrongIntentPayload)
		{
			substitute_metadata_digest(&mut payload);
		}
		let (frame, synced) = self.journal.append(kind, payload)?;
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

fn substitute_metadata_digest(payload: &mut [u8]) {
	let digest = *DarwinPublishIntent::decode(payload)
		.unwrap()
		.metadata_digest()
		.as_bytes();
	let offset = payload
		.windows(digest.len())
		.position(|window| window == digest)
		.expect("the canonical intent contains its metadata digest");
	payload[offset] ^= 1;
	let substituted = DarwinPublishIntent::decode(payload).unwrap();
	assert_ne!(substituted.metadata_digest().as_bytes(), &digest);
}

impl ReceiptStore for Script {
	type Error = ReceiptWriteFailed;

	fn persist(&self, bytes: &[u8]) -> Result<(), ReceiptWriteFailed> {
		self.step(Step::Persist);
		if matches!(self.scenario, Scenario::ReceiptFailed) {
			return Err(ReceiptWriteFailed);
		}
		self.receipt.replace(bytes.to_vec());
		Ok(())
	}
}

fn run(
	scenario: Scenario,
	check: impl FnOnce(Result<DarwinCopyReceipt<'_>, ScriptFailure>, PublicationProgress, &Script),
) {
	with_publication_fixture(|entry, _| {
		let script = Script {
			scenario,
			steps: RefCell::new(Vec::new()),
			observations: RefCell::new(Vec::new()),
			receipt: RefCell::new(Vec::new()),
		};
		let mut journal = Journal {
			script: &script,
			journal: &mut entry.journal,
			wrong_token: None,
		};
		if matches!(scenario, Scenario::WrongIntentToken) {
			let mut other =
				DurableJournal::from_new_segment(SimulatedIntentSegment(Cursor::new(Vec::new())))
					.unwrap();
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
			binding: entry.attempt.binding().unwrap(),
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
		let result = execute(
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

// This alternate branch is a frame provenance control, with no native barrier claim.
struct SimulatedIntentSegment(Cursor<Vec<u8>>);

impl Read for SimulatedIntentSegment {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		self.0.read(bytes)
	}
}

impl Write for SimulatedIntentSegment {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.0.write(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.0.flush()
	}
}

impl Seek for SimulatedIntentSegment {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.0.seek(position)
	}
}

impl JournalSegment for SimulatedIntentSegment {
	const BARRIER: JournalFileBarrier = JournalFileBarrier::DarwinFullFsync;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		Ok(Some(self.0.get_ref().len() as u64))
	}

	fn sync(&self) -> io::Result<()> {
		Ok(())
	}
}
