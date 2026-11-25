use std::num::{NonZeroU32, NonZeroU64};

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	DarwinDurabilityRecorded, DarwinEntryPreparation, DarwinEntryPrepared, DarwinFileIdentity,
	DarwinJobPrepared, DarwinMetadataRecorded, DarwinNamespaceObservation, DarwinOwnerManifest,
	DarwinOwnerRecord, DarwinPublicationBarriers, DarwinPublicationNames, DarwinPublicationOutcome,
	DarwinPublishIntent, DarwinPublishObserved, DarwinRequiredMetadata, DarwinRootBinding,
	DarwinSourceMetadata, DarwinSourceTimes, DarwinSourceView, DarwinStageId,
	DarwinStageObservation, DarwinStageSealed, DarwinStreamEvidence, DarwinVerificationRecorded,
	DarwinVolumeIdentity, JournalEntryId, JournalEpoch, JournalJobId, ObservedTimestamp,
	OwnerProfileId, OwnerTimestamp, OwnerToken, RootCapabilityId, StreamDigest, StreamLength,
	TargetObservation,
};

use super::super::{DarwinJournalReplay, DarwinReplayAuthority, DarwinReplayError, replay_journal};
use crate::macos::plan::{
	DarwinCopyPlan, DestinationPlanBinding, PlanAttempt, SourceMetadata, SourcePlanBinding,
};

pub(super) const OWNER_UID: NonZeroU32 = NonZeroU32::new(501).unwrap();

pub(super) struct Fixture {
	pub(super) plan: DarwinCopyPlan<'static>,
	pub(super) owner: DarwinOwnerRecord,
	pub(super) key: VerifyingKey,
	pub(super) stage: DarwinStageObservation<'static>,
	pub(super) records: History,
}

impl Fixture {
	pub(super) fn new() -> Self {
		let attempt = PlanAttempt {
			job: JournalJobId::from_bytes(uuid(0x11, 7)).unwrap(),
			epoch: JournalEpoch::new(1),
			entry: JournalEntryId::from_bytes([0x22; 16]),
			profile: OwnerProfileId::from_bytes(uuid(0x33, 4)).unwrap(),
		};
		let source = SourcePlanBinding {
			root_id: RootCapabilityId::from_bytes(uuid(0x44, 4)).unwrap(),
			root_identity: identity(2),
			file_identity: identity(3),
			length: 11,
			metadata: SourceMetadata::new(
				0o600,
				OWNER_UID.get(),
				20,
				ObservedTimestamp::new(-5, 17).unwrap(),
				ObservedTimestamp::new(8, 0).unwrap(),
				ObservedTimestamp::new(9, 1).unwrap(),
			)
			.unwrap(),
			component: name(b"source-\x80"),
		};
		let destination = DestinationPlanBinding {
			root_id: RootCapabilityId::from_bytes(uuid(0x55, 4)).unwrap(),
			root_identity: identity(4),
			component: name(b"target-\x81"),
		};
		let plan = DarwinCopyPlan::new(attempt, source, destination).unwrap();
		let signer = SigningKey::from_bytes(&[0x77; 32]);
		let owner = DarwinOwnerRecord::sign(
			DarwinOwnerManifest {
				token: OwnerToken::from_bytes([0x66; 16]).unwrap(),
				job: attempt.job,
				profile: attempt.profile,
				created: OwnerTimestamp::new(1, 2).unwrap(),
				destination_volume: destination.root_identity.volume(),
				state_root: identity(5),
				state_root_uid: OWNER_UID,
				plan_digest: plan.digest(),
			},
			&signer,
		)
		.unwrap();
		let stage = DarwinStageObservation {
			id: DarwinStageId::from_bytes([0x88; 16]),
			directory: identity(6),
			identity: identity(7),
			component: name(b"payload"),
		};
		let mut fixture = Self {
			plan,
			owner,
			key: signer.verifying_key(),
			stage,
			records: History::default(),
		};
		let mut records = fixture.prepared(fixture.entry());
		fixture.write_intent(&mut records, NonZeroU64::MIN);
		records.append(
			FrameKind::PublishObserved,
			&fixture.observation(records.last(), DarwinPublicationOutcome::Published),
		);
		let durability = fixture.durability(&records);
		records.append(FrameKind::DurabilityRecorded, &durability.encode());
		fixture.records = records;
		fixture
	}

	pub(super) fn authority(&self) -> DarwinReplayAuthority<'_> {
		DarwinReplayAuthority {
			profile: self.plan.attempt().profile,
			key: &self.key,
			state_root: self.owner.manifest().state_root,
			state_root_uid: OWNER_UID,
		}
	}

	pub(super) fn replay(&self, bytes: &[u8]) -> Result<DarwinJournalReplay, DarwinReplayError> {
		replay_journal(bytes, &self.plan, self.owner.as_bytes(), self.authority())
	}

	pub(super) fn entry(&self) -> DarwinEntryPreparation<'static> {
		let source = self.plan.source();
		let metadata = source.metadata;
		DarwinEntryPreparation {
			source: DarwinSourceView::new(
				DarwinRootBinding {
					id: source.root_id,
					identity: source.root_identity,
				},
				source.component,
				source.file_identity,
				source.length,
				DarwinSourceTimes {
					accessed_at: owner_time(metadata.accessed_at()),
					modified_at: owner_time(metadata.modified_at()),
					changed_at: owner_time(metadata.changed_at()),
				},
				DarwinSourceMetadata::new(
					u32::from(metadata.mode()),
					metadata.uid(),
					metadata.gid(),
				)
				.unwrap(),
			)
			.unwrap(),
			stage: self.stage,
			target_component: self.plan.destination().component,
			target_observation: TargetObservation::AbsentObserved,
		}
	}

	pub(super) fn prepared(&self, preparation: DarwinEntryPreparation<'_>) -> History {
		let destination = self.plan.destination();
		let job = DarwinJobPrepared::new(
			self.plan.context(),
			&self.owner,
			DarwinRootBinding {
				id: destination.root_id,
				identity: destination.root_identity,
			},
		)
		.unwrap();
		let entry = DarwinEntryPrepared::new(&job, self.plan.attempt().entry, preparation).unwrap();
		let mut records = History::default();
		records.append(FrameKind::JobPrepared, &job.encode());
		records.append(FrameKind::EntryPrepared, &entry.encode());
		records
	}

	pub(super) fn write_intent(&self, records: &mut History, effect: NonZeroU64) {
		let entry = &records.frames[1];
		let length = StreamLength::new(self.plan.source().length).unwrap();
		let seal = DarwinStageSealed::new(entry, self.stage.identity, length).unwrap();
		let stage = DarwinStreamEvidence {
			identity: self.stage.identity,
			length,
			digest: StreamDigest::from_bytes([0x99; 32]),
		};
		let source = DarwinStreamEvidence {
			identity: self.plan.source().file_identity,
			..stage
		};
		let verification = DarwinVerificationRecorded::new(entry, &seal, source, stage).unwrap();
		let source_view = self.entry().source;
		let metadata = DarwinRequiredMetadata::new(
			source_view.metadata().mode(),
			source_view.metadata().owner(),
			source_view.metadata().group(),
			source_view.times().accessed_at,
			source_view.times().modified_at,
		)
		.unwrap();
		let metadata =
			DarwinMetadataRecorded::new(entry, &seal, &verification, stage.identity, metadata)
				.unwrap();
		let intent = DarwinPublishIntent::new(effect, entry, &seal, &verification, &metadata)
			.unwrap()
			.encode();
		records.append(FrameKind::StageSealed, &seal.encode());
		records.append(FrameKind::VerificationRecorded, &verification.encode());
		records.append(FrameKind::MetadataRecorded, &metadata.encode());
		records.append(FrameKind::PublishIntent, &intent);
	}

	pub(super) fn observation(&self, intent: &Frame, outcome: DarwinPublicationOutcome) -> Vec<u8> {
		let names = match outcome {
			DarwinPublicationOutcome::Published | DarwinPublicationOutcome::ReconciledPublished => {
				DarwinPublicationNames {
					target: DarwinNamespaceObservation::Present(self.stage.identity),
					stage: DarwinNamespaceObservation::Absent,
				}
			}
			DarwinPublicationOutcome::Conflict => DarwinPublicationNames {
				target: DarwinNamespaceObservation::Present(identity(8)),
				stage: DarwinNamespaceObservation::Present(self.stage.identity),
			},
			_ => DarwinPublicationNames {
				target: DarwinNamespaceObservation::Unobserved,
				stage: DarwinNamespaceObservation::Unobserved,
			},
		};
		DarwinPublishObserved::new(intent, outcome, names)
			.unwrap()
			.encode()
	}

	pub(super) fn durability(&self, records: &History) -> DarwinDurabilityRecorded {
		DarwinDurabilityRecorded::new(
			&records.frames[4],
			&records.frames[5],
			&records.frames[6],
			DarwinPublicationBarriers {
				stage_directory: self.stage.directory,
				destination_directory: self.plan.destination().root_identity,
			},
		)
		.unwrap()
	}
}

#[derive(Default)]
pub(super) struct History {
	pub(super) bytes: Vec<u8>,
	pub(super) frames: Vec<Frame>,
	pub(super) ends: Vec<usize>,
}

impl History {
	pub(super) fn append(&mut self, kind: FrameKind, payload: &[u8]) {
		self.append_after(
			self.frames.last().map_or(ChainHead::start(), Frame::head),
			kind,
			payload,
		);
	}

	pub(super) fn append_after(&mut self, head: ChainHead, kind: FrameKind, payload: &[u8]) {
		let mut writer = FrameWriter::new(Vec::new(), head);
		writer.append(kind, payload).unwrap();
		let bytes = writer.into_inner();
		let mut reader = FrameReader::new(bytes.as_slice(), head);
		self.frames.push(reader.next_frame().unwrap().unwrap());
		self.bytes.extend(bytes);
		self.ends.push(self.bytes.len());
	}

	pub(super) fn prefix(&self, count: usize) -> Self {
		let mut prefix = Self::default();
		for frame in &self.frames[..count] {
			prefix.append(frame.kind(), frame.payload());
		}
		prefix
	}

	pub(super) fn last(&self) -> &Frame {
		self.frames.last().unwrap()
	}
}

pub(super) fn name(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).unwrap()
}

pub(super) fn identity(inode: u64) -> DarwinFileIdentity {
	DarwinFileIdentity::new(
		DarwinVolumeIdentity::new(9, [2, 17]).unwrap(),
		NonZeroU64::new(inode).unwrap(),
		None,
		OwnerTimestamp::new(1, 5).unwrap(),
	)
}

fn owner_time(timestamp: ObservedTimestamp) -> OwnerTimestamp {
	OwnerTimestamp::new(timestamp.seconds(), timestamp.nanoseconds()).unwrap()
}

fn uuid(fill: u8, version: u8) -> [u8; 16] {
	let mut bytes = [fill; 16];
	bytes[6] = version << 4;
	bytes[8] = 0x80;
	bytes
}
