use std::cell::RefCell;
use std::io;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_staging::{ExtendedAttributes, SourceMetadata};
use exacopy_journal::frame::FrameWriter;
use exacopy_journal::{
	BasicMetadata, DestinationRootBinding, JournalEntryId, JournalJobId, ObservedTimestamp,
	OwnerTimestamp, RootCapabilityId, StreamDigest, StreamLength,
};
use exacopy_model::PublishNoClobber;

use crate::linux::{DestinationPlanBinding, JournalTail, PlanAttempt, SourcePlanBinding};

use super::*;

type Trace = RefCell<Vec<Action>>;

pub(super) struct Fixture {
	pub(super) plan: LocalCopyPlan<'static>,
	pub(super) journal: JournalReplay,
	pub(super) owner: OwnerDigest,
}

pub(super) type MockFailure = RetryError<FailurePoint, FailurePoint, FailurePoint, FailurePoint>;

impl Fixture {
	pub(super) fn new() -> Self {
		let timestamp = ObservedTimestamp::new(0, 0).unwrap();
		let plan = LocalCopyPlan::new(
			PlanAttempt {
				job: JournalJobId::from_bytes(uuid(1)).unwrap(),
				epoch: JournalEpoch::new(1),
				entry: JournalEntryId::from_bytes([2; 16]),
				job_name: UnixComponent::new(b"job").unwrap(),
				stage_name: UnixComponent::new(b"stage").unwrap(),
			},
			SourcePlanBinding {
				root_id: RootCapabilityId::from_bytes(uuid(3)).unwrap(),
				root_identity: LinuxFileIdentity::new(1, 1),
				file_identity: LinuxFileIdentity::new(1, 2),
				length: u64::try_from(CONTENT.len()).unwrap(),
				modified_at: timestamp,
				changed_at: timestamp,
				component: UnixComponent::new(b"source").unwrap(),
			},
			DestinationPlanBinding {
				root: DestinationRootBinding {
					id: RootCapabilityId::from_bytes(uuid(4)).unwrap(),
					identity: LinuxFileIdentity::new(1, 3),
				},
				component: UnixComponent::new(b"target\xFE").unwrap(),
			},
		)
		.unwrap();
		let context = JournalContext {
			epoch: PRIOR_EPOCH,
			..plan.context()
		};
		let entry = plan.attempt().entry;
		let stage = StreamEvidence {
			identity: STAGE,
			length: StreamLength::new(plan.source().length).unwrap(),
			digest: StreamDigest::from_bytes(*blake3::hash(CONTENT).as_bytes()),
		};
		let source = StreamEvidence {
			identity: plan.source().file_identity,
			..stage
		};
		let intent = ChainHead::after(6, [6; 32]).unwrap();
		let journal = JournalReplay {
			boundary: JournalBoundary {
				head: intent,
				offset: 601,
			},
			tail: JournalTail::Clean,
			source: None,
			source_link_count: None,
			source_metadata: None,
			preparation_head: None,
			stage: Some(STAGE),
			checkpoints: vec![],
			sealed: None,
			verification: Some(VerificationRecorded::new(context, entry, source, stage).unwrap()),
			verification_head: None,
			metadata: Some(MetadataRecorded {
				context,
				entry,
				stage: STAGE,
				metadata: BasicMetadata::new(
					MODE,
					1000,
					1000,
					OwnerTimestamp::new(ACCESS_SECONDS, ACCESS_NANOS).unwrap(),
					OwnerTimestamp::new(0, 0).unwrap(),
				)
				.unwrap(),
			}),
			metadata_head: None,
			intent: None,
			intent_head: Some(intent),
			observation: None,
			observation_head: None,
			durability: None,
			durability_head: None,
			latest_epoch: PRIOR_EPOCH,
			last_effect_sequence: PRIOR_EFFECT,
			recovery_stage_directory: Some(STAGE_DIRECTORY),
			published_recovery: false,
			receipt: None,
		};
		Self {
			plan,
			journal,
			owner: OwnerDigest::from_bytes([9; 32]),
		}
	}

	pub(super) fn run(
		&self,
		failure: Option<FailurePoint>,
	) -> (Result<(), MockFailure>, Vec<Action>, Vec<u8>) {
		let trace = Trace::default();
		let effects = Effects {
			trace: &trace,
			failure,
		};
		let mut bytes = Vec::new();
		let result = publish(
			RetryHistory {
				plan: &self.plan,
				journal: &self.journal,
				owner: self.owner,
			},
			&effects,
			&effects,
			|boundary| {
				trace.borrow_mut().push(Action::JournalOpen);
				assert_eq!(boundary, self.journal.boundary);
				Ok(Appender {
					effects: &effects,
					writer: FrameWriter::new(&mut bytes, boundary.head),
				})
			},
			&mut [0; CONTENT.len()],
		);
		(result, trace.into_inner(), bytes)
	}
}

fn uuid(marker: u8) -> [u8; 16] {
	let mut bytes = [marker; 16];
	bytes[6] = 0x70;
	bytes[8] = 0x80;
	bytes
}

struct Effects<'test> {
	trace: &'test Trace,
	failure: Option<FailurePoint>,
}

impl ReadView for Effects<'_> {
	type Error = FailurePoint;

	fn length(&self) -> u64 {
		u64::try_from(CONTENT.len()).unwrap()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		let mut trace = self.trace.borrow_mut();
		trace.push(Action::SourceCheck);
		if self.failure == Some(FailurePoint::SourceChanged)
			&& trace.contains(&Action::Sync(FrameKind::PublishIntent))
		{
			return Err(FailurePoint::SourceChanged);
		}
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		assert_eq!(offset, 0);
		self.trace.borrow_mut().push(Action::Measure);
		if self.failure == Some(FailurePoint::SourceBytes) {
			buffer.fill(0);
		} else {
			buffer.copy_from_slice(CONTENT);
		}
		Ok(())
	}
}

#[derive(Clone, Copy)]
struct SourceMode;

impl SourceMetadata for SourceMode {
	type Timestamp = ();

	fn mode(self) -> u32 {
		MODE
	}

	fn accessed_at(self) {}
}

impl StagingSource for Effects<'_> {
	type Identity = LinuxFileIdentity;
	type Metadata = SourceMode;

	fn identity(&self) -> Self::Identity {
		LinuxFileIdentity::new(1, 2)
	}

	fn metadata(&self) -> SourceMode {
		SourceMode
	}

	fn extended_attributes(&self) -> Result<ExtendedAttributes, Self::Error> {
		Ok(ExtendedAttributes::NoneVisible)
	}

	fn recheck_metadata(&self) -> Result<(), Self::Error> {
		Ok(())
	}
}

impl RetainedStage for Effects<'_> {
	type NamespaceError = FailurePoint;
	type ReadBackError = FailurePoint;
	type PublishError = FailurePoint;
	type Publisher<'lease>
		= Publisher<'lease>
	where
		Self: 'lease;

	fn identity(&self) -> RetainedIdentity {
		RetainedIdentity {
			file: if self.failure == Some(FailurePoint::StageIdentity) {
				LinuxFileIdentity::new(1, 8)
			} else {
				STAGE
			},
			directory: if self.failure == Some(FailurePoint::StageDirectory) {
				LinuxFileIdentity::new(1, 9)
			} else {
				STAGE_DIRECTORY
			},
		}
	}

	fn flush(&self, binding: CopyBinding) -> Result<Self::Publisher<'_>, Self::NamespaceError> {
		self.trace.borrow_mut().push(Action::Flush);
		Ok(Publisher {
			effects: self,
			binding,
		})
	}

	fn verify_readback(
		&self,
		stream: StreamEvidence,
		metadata: MetadataRecorded,
		_scratch: &mut [u8],
	) -> Result<Option<RecoveryIssue>, Self::ReadBackError> {
		self.trace.borrow_mut().push(Action::ReadBack);
		assert_eq!(stream.identity, STAGE);
		assert_eq!(metadata.stage, STAGE);
		Ok((self.failure == Some(FailurePoint::StageReadBack))
			.then_some(RecoveryIssue::StreamMismatch))
	}

	fn accessed_at(&self) -> (i64, u32) {
		if self.failure == Some(FailurePoint::AccessTime) {
			return (0, 0);
		}
		(ACCESS_SECONDS, ACCESS_NANOS)
	}

	fn recheck_namespace(&self) -> Result<(), Self::NamespaceError> {
		self.trace.borrow_mut().push(Action::NamespaceCheck);
		Ok(())
	}
}

struct Publisher<'test> {
	effects: &'test Effects<'test>,
	binding: CopyBinding,
}

impl ExclusivePublication for Publisher<'_> {
	type Error = FailurePoint;

	fn publish_no_clobber(
		self,
		authorization: PublishNoClobber,
	) -> Result<(), PublicationFailure<Self::Error>> {
		assert_eq!(authorization.binding(), self.binding);
		self.effects.trace.borrow_mut().push(Action::Publish);
		if self.effects.failure == Some(FailurePoint::UncertainPublication) {
			return Err(PublicationFailure::Uncertain(
				FailurePoint::UncertainPublication,
			));
		}
		Ok(())
	}
}

struct Appender<'test> {
	effects: &'test Effects<'test>,
	writer: FrameWriter<&'test mut Vec<u8>>,
}

impl RetryJournal for Appender<'_> {
	fn append_synced(
		&mut self,
		kind: FrameKind,
		payload: &[u8],
	) -> Result<ChainHead, DurableJournalError> {
		self.effects.trace.borrow_mut().push(Action::Sync(kind));
		let head = self
			.writer
			.append(kind, payload)
			.map_err(DurableJournalError::Frame)?;
		if kind == FrameKind::PublishIntent
			&& self.effects.failure == Some(FailurePoint::IntentBarrier)
		{
			return Err(DurableJournalError::Sync(io::Error::other(
				"injected barrier failure",
			)));
		}
		Ok(head)
	}
}
