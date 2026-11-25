use std::num::{NonZeroU32, NonZeroU64};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	DarwinEntryPreparation, DarwinEntryPrepared, DarwinFileIdentity, DarwinJobPrepared,
	DarwinMetadataRecorded, DarwinOwnerManifest, DarwinOwnerRecord, DarwinPublishIntent,
	DarwinRequiredMetadata, DarwinRootBinding, DarwinSourceMetadata, DarwinSourceTimes,
	DarwinSourceView, DarwinStageId, DarwinStageObservation, DarwinStageSealed,
	DarwinStreamEvidence, DarwinVerificationRecorded, DarwinVolumeIdentity, JournalContext,
	JournalEntryId, JournalEpoch, JournalJobId, OwnerProfileId, OwnerTimestamp, OwnerToken,
	PlanDigest, RootCapabilityId, StreamDigest, StreamLength, TargetObservation,
};

pub(super) const ENTRY: JournalEntryId = JournalEntryId::from_bytes([13; 16]);
const PRIVATE_STAGE: &[u8] = b"stage";
pub(super) const PUBLIC_NAME: &[u8] = b"target-\x80";
const STAGE_TOKEN: DarwinStageId = DarwinStageId::from_bytes([0x44; 16]);

pub(super) fn frame(kind: FrameKind, payload: &[u8], head: ChainHead) -> Frame {
	let mut writer = FrameWriter::new(Vec::new(), head);
	writer.append(kind, payload).unwrap();
	FrameReader::new(writer.into_inner().as_slice(), head)
		.next_frame()
		.unwrap()
		.unwrap()
}

pub(super) struct Fixture<'a> {
	pub(super) frame: Frame,
	pub(super) job: Frame,
	pub(super) owner: DarwinOwnerRecord,
	identity: DarwinFileIdentity,
	pub(super) length: StreamLength,
	pub(super) stage: DarwinStageObservation<'a>,
	pub(super) parent: DarwinFileIdentity,
	pub(super) required: DarwinRequiredMetadata,
}

impl<'a> Fixture<'a> {
	pub(super) fn new(length: u64, target: &'a [u8]) -> Self {
		Self::with_epoch(length, target, u64::MAX)
	}

	pub(super) fn with_epoch(length: u64, target: &'a [u8], epoch: u64) -> Self {
		let mut job = [1; 16];
		job[6] = 0x70;
		job[8] = 0x80;
		let context = JournalContext {
			job: JournalJobId::from_bytes(job).unwrap(),
			epoch: JournalEpoch::new(epoch),
			plan_digest: PlanDigest::from_bytes([0x54; 32]),
		};
		let owner = DarwinOwnerRecord::sign(
			DarwinOwnerManifest {
				token: OwnerToken::from_bytes([0xaa; 16]).unwrap(),
				job: context.job,
				profile: OwnerProfileId::from_bytes([0x22; 16]).unwrap(),
				created: OwnerTimestamp::new(1_i64, 14).unwrap(),
				destination_volume: native(10).volume(),
				state_root: native(10),
				state_root_uid: NonZeroU32::new(501).unwrap(),
				plan_digest: context.plan_digest,
			},
			&SigningKey::from_bytes(&[0x99; 32]),
		)
		.unwrap();
		let parent = native(11);
		let destination = DarwinRootBinding {
			id: capability(0x35),
			identity: parent,
		};
		let job = DarwinJobPrepared::new(context, &owner, destination).unwrap();
		let identity = native(12);
		let source_root = DarwinRootBinding {
			id: capability(0x36),
			identity: native(13),
		};
		let times = DarwinSourceTimes {
			accessed_at: OwnerTimestamp::new(-2, 3).unwrap(),
			modified_at: OwnerTimestamp::new(40, 0).unwrap(),
			changed_at: OwnerTimestamp::new(41, 0).unwrap(),
		};
		let permissions =
			DarwinSourceMetadata::new(0o600, owner.manifest().state_root_uid, 20).unwrap();
		let source = DarwinSourceView::new(
			source_root,
			UnixComponent::new(b"source").unwrap(),
			identity,
			length,
			times,
			permissions,
		)
		.unwrap();
		let stage = DarwinStageObservation {
			id: STAGE_TOKEN,
			directory: native(14),
			identity: native(15),
			component: UnixComponent::new(PRIVATE_STAGE).unwrap(),
		};
		let entry = DarwinEntryPrepared::new(
			&job,
			ENTRY,
			DarwinEntryPreparation {
				source,
				stage,
				target_component: UnixComponent::new(target).unwrap(),
				target_observation: TargetObservation::AbsentObserved,
			},
		)
		.unwrap();
		let job = frame(FrameKind::JobPrepared, &job.encode(), ChainHead::start());
		let frame = frame(FrameKind::EntryPrepared, &entry.encode(), job.head());
		let required = DarwinRequiredMetadata::new(
			permissions.mode(),
			permissions.owner(),
			permissions.group(),
			times.accessed_at,
			times.modified_at,
		)
		.unwrap();
		Self {
			frame,
			job,
			owner,
			identity,
			length: StreamLength::new(length).unwrap(),
			stage,
			parent,
			required,
		}
	}

	pub(super) fn seal(&self) -> DarwinStageSealed {
		DarwinStageSealed::new(&self.frame, self.stage.identity, self.length).unwrap()
	}

	pub(super) fn measurements(&self) -> (DarwinStreamEvidence, DarwinStreamEvidence) {
		let digest = StreamDigest::from_bytes([0x88; 32]);
		let source = DarwinStreamEvidence {
			identity: self.identity,
			length: self.length,
			digest,
		};
		let stage = DarwinStreamEvidence {
			identity: self.stage.identity,
			length: self.length,
			digest,
		};
		(source, stage)
	}

	pub(super) fn verify(&self, seal: &DarwinStageSealed) -> DarwinVerificationRecorded {
		let (source, stage) = self.measurements();
		DarwinVerificationRecorded::new(&self.frame, seal, source, stage).unwrap()
	}

	pub(super) fn metadata(
		&self,
		seal: &DarwinStageSealed,
		verification: &DarwinVerificationRecorded,
	) -> DarwinMetadataRecorded {
		DarwinMetadataRecorded::new(
			&self.frame,
			seal,
			verification,
			self.stage.identity,
			self.required,
		)
		.unwrap()
	}

	pub(super) fn intent(
		&self,
		seal: &DarwinStageSealed,
		verification: &DarwinVerificationRecorded,
		metadata: &DarwinMetadataRecorded,
	) -> DarwinPublishIntent<'_> {
		DarwinPublishIntent::new(NonZeroU64::MAX, &self.frame, seal, verification, metadata)
			.unwrap()
	}
}

pub(super) fn native(inode: u64) -> DarwinFileIdentity {
	DarwinFileIdentity::new(
		DarwinVolumeIdentity::new(-2, [u32::MAX, u32::MAX - 1]).unwrap(),
		NonZeroU64::new(inode).unwrap(),
		Some(NonZeroU32::MAX),
		OwnerTimestamp::new(i64::MIN, 999_999_999).unwrap(),
	)
}

fn capability(byte: u8) -> RootCapabilityId {
	let mut bytes = [byte; 16];
	bytes[6] = 0x40;
	bytes[8] = 0x80;
	RootCapabilityId::from_bytes(bytes).unwrap()
}
