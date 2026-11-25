use ed25519_dalek::SigningKey;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameWriter;
use exacopy_journal::{
	BasicMetadata, DestinationRootBinding, EntryPreparation, JournalEpoch, JournalJobId,
	LinuxPublicationBarriers, ObservedTimestamp, OwnerManifest, OwnerProfileId, OwnerToken,
	PreparedTarget, PublicationOutcome, PublicationPrimitive, PublishIntentTarget, ReceiptDigest,
	RootCapabilityId, SourceInodeMetadata, SourceTimes, StreamDigest, StreamEvidence, StreamLength,
	TargetObservation,
};

use super::*;
use crate::linux::{DestinationPlanBinding, PlanAttempt, SourcePlanBinding};

pub(super) const STAGE: LinuxFileIdentity = LinuxFileIdentity::new(1, 14);
pub(super) const STAGE_DIRECTORY: LinuxFileIdentity = LinuxFileIdentity::new(1, 15);
pub(super) const JOB_ROOT: LinuxFileIdentity = LinuxFileIdentity::new(1, 16);
pub(super) const OTHER_STAGE: LinuxFileIdentity = LinuxFileIdentity::new(1, 17);
const MODE: u32 = 0o640;
const UID: u32 = 1000;
const GID: u32 = 1001;

pub(super) const KINDS: [FrameKind; 9] = [
	FrameKind::JobPrepared,
	FrameKind::EntryPrepared,
	FrameKind::StageSealed,
	FrameKind::VerificationRecorded,
	FrameKind::MetadataRecorded,
	FrameKind::PublishIntent,
	FrameKind::PublishObserved,
	FrameKind::DurabilityRecorded,
	FrameKind::ReceiptCommitted,
];

fn uuid(marker: u8) -> [u8; 16] {
	let mut bytes = [marker; 16];
	bytes[6] = 0x70;
	bytes[8] = 0x80;
	bytes
}

pub(super) fn component(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).unwrap()
}

fn plan() -> LocalCopyPlan<'static> {
	LocalCopyPlan::new(
		PlanAttempt {
			job: JournalJobId::from_bytes(uuid(1)).unwrap(),
			epoch: JournalEpoch::new(3),
			entry: JournalEntryId::from_bytes([2; 16]),
			job_name: component(b"job"),
			stage_name: component(b"stage"),
		},
		SourcePlanBinding {
			root_id: RootCapabilityId::from_bytes(uuid(4)).unwrap(),
			root_identity: LinuxFileIdentity::new(1, 10),
			file_identity: LinuxFileIdentity::new(1, 11),
			length: 28,
			modified_at: ObservedTimestamp::new(-1, 5).unwrap(),
			changed_at: ObservedTimestamp::new(10, 45).unwrap(),
			component: component(b"source\xff"),
		},
		DestinationPlanBinding {
			root: DestinationRootBinding {
				id: RootCapabilityId::from_bytes(uuid(8)).unwrap(),
				identity: LinuxFileIdentity::new(1, 13),
			},
			component: component(b"target\xfe"),
		},
	)
	.unwrap()
}

pub(super) struct Fixture {
	pub(super) plan: LocalCopyPlan<'static>,
	pub(super) owner: OwnerRecord,
}

impl Fixture {
	pub(super) fn new() -> Self {
		let plan = plan();
		let owner = Self::owner_for(&plan, JOB_ROOT);
		Self { plan, owner }
	}

	pub(super) fn owner_for(
		plan: &LocalCopyPlan<'_>,
		state_root: LinuxFileIdentity,
	) -> OwnerRecord {
		let key = SigningKey::from_bytes(&[9; 32]);
		let profile = OwnerProfileId::from_bytes(uuid(5)).unwrap();
		let owner = OwnerRecord::sign(
			OwnerManifest {
				token: OwnerToken::from_bytes([2; 16]).unwrap(),
				job: plan.attempt().job,
				profile,
				created: OwnerTimestamp::new(0, 0).unwrap(),
				destination_device: 1,
				state_root,
				plan_digest: plan.digest(),
				directories: vec![
					OwnerStateDirectory::Journal,
					OwnerStateDirectory::Receipts,
					OwnerStateDirectory::Stage,
				],
			},
			&key,
		)
		.unwrap();
		OwnerRecord::decode(owner.as_bytes(), profile, &key.verifying_key()).unwrap()
	}

	pub(super) fn replay(&self, bytes: &[u8]) -> Result<JournalReplay, JournalReplayError> {
		replay_journal(bytes, &self.plan, &self.owner)
	}

	pub(super) fn records(&self) -> Records {
		let context = self.plan.context();
		let entry = self.plan.attempt().entry;
		let source = self.plan.source();
		let destination = self.plan.destination();
		let accessed_at = ObservedTimestamp::new(23, 7).unwrap();
		let stage_stream = StreamEvidence {
			identity: STAGE,
			length: StreamLength::new(source.length).unwrap(),
			digest: StreamDigest::from_bytes([0x85; 32]),
		};
		let verification = VerificationRecorded::new(
			context,
			entry,
			StreamEvidence {
				identity: source.file_identity,
				..stage_stream
			},
			stage_stream,
		)
		.unwrap();
		Records {
			job: JobPrepared {
				context,
				owner_digest: self.owner.digest(),
				destination_root: destination.root,
			},
			entry: EntryPreparation {
				source: LiveSourceView::new(
					source.file_identity,
					source.length,
					SourceTimes {
						accessed_at,
						modified_at: source.modified_at,
						changed_at: source.changed_at,
					},
				)
				.unwrap(),
				stage: STAGE,
				target: PreparedTarget {
					root: destination.root.id,
					component: destination.component,
					observation: TargetObservation::AbsentObserved,
				},
				source_metadata: SourceInodeMetadata::no_visible_extended_attributes(
					MODE, UID, GID, 1,
				)
				.unwrap(),
			},
			seal: StageSealed {
				context,
				entry,
				stage: STAGE,
				length: stage_stream.length,
			},
			verification,
			metadata: MetadataRecorded {
				context,
				entry,
				stage: STAGE,
				metadata: BasicMetadata::new(
					MODE,
					UID,
					GID,
					OwnerTimestamp::new(accessed_at.seconds(), accessed_at.nanoseconds()).unwrap(),
					OwnerTimestamp::new(
						source.modified_at.seconds(),
						source.modified_at.nanoseconds(),
					)
					.unwrap(),
				)
				.unwrap(),
			},
			intent: PublishIntent {
				context: publication_context(context, entry),
				target: PublishIntentTarget {
					stage: STAGE,
					parent: destination.root.identity,
					component: destination.component,
					verification_digest: verification.record_digest(),
					primitive: PublicationPrimitive::LinuxRenameNoReplace,
				},
			},
			outcome: PublicationOutcome::Published { target: STAGE },
		}
	}
}

pub(super) struct Records {
	pub(super) job: JobPrepared,
	pub(super) entry: EntryPreparation<'static>,
	pub(super) seal: StageSealed,
	pub(super) verification: VerificationRecorded,
	pub(super) metadata: MetadataRecorded,
	pub(super) intent: PublishIntent<'static>,
	pub(super) outcome: PublicationOutcome,
}

impl Records {
	pub(super) fn bytes(self, limit: usize) -> (Vec<u8>, Vec<JournalBoundary>) {
		self.transform(limit, |_, _, _| {})
	}

	pub(super) fn transform(
		self,
		limit: usize,
		mut change: impl FnMut(FrameKind, &mut Vec<u8>, &[JournalBoundary]),
	) -> (Vec<u8>, Vec<JournalBoundary>) {
		let mut bytes = Vec::new();
		let mut boundaries = vec![JournalBoundary {
			head: ChainHead::start(),
			offset: 0,
		}];
		for kind in KINDS.into_iter().take(limit) {
			let mut payload = match kind {
				FrameKind::JobPrepared => self.job.encode(),
				FrameKind::EntryPrepared => {
					EntryPrepared::new(self.job.context, self.seal.entry, self.entry)
						.unwrap()
						.encode()
				}
				FrameKind::StageSealed => self.seal.encode(),
				FrameKind::VerificationRecorded => self.verification.encode(),
				FrameKind::MetadataRecorded => self.metadata.encode(),
				FrameKind::PublishIntent => self.intent.encode(),
				FrameKind::PublishObserved => {
					PublishObserved::new(self.intent.context, boundaries[6].head, self.outcome)
						.unwrap()
						.encode()
				}
				FrameKind::DurabilityRecorded => DurabilityRecorded::new(
					self.intent.context,
					boundaries[7].head,
					LinuxPublicationBarriers {
						metadata: boundaries[5].head,
						stage_directory: STAGE_DIRECTORY,
						destination_directory: self.intent.target.parent,
					},
				)
				.unwrap()
				.encode(),
				FrameKind::ReceiptCommitted => ReceiptCommitted::new(
					self.intent.context,
					ReceiptDigest::from_bytes([0x56; 32]),
					boundaries[8].head,
				)
				.unwrap()
				.encode(),
				_ => unreachable!("the fixture only emits the local v1 sequence"),
			};
			change(kind, &mut payload, &boundaries);
			let mut writer = FrameWriter::new(&mut bytes, boundaries.last().unwrap().head);
			let head = writer.append(kind, &payload).unwrap();
			boundaries.push(JournalBoundary {
				head,
				offset: u64::try_from(bytes.len()).unwrap(),
			});
		}
		(bytes, boundaries)
	}
}
