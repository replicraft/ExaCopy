use core::num::{NonZeroU32, NonZeroU64};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::{
	DarwinEntryPreparation, DarwinFileIdentity, DarwinOwnerManifest, DarwinOwnerRecord,
	DarwinRootBinding, DarwinSourceMetadata, DarwinSourceTimes, DarwinSourceView, DarwinStageId,
	DarwinStageObservation, DarwinVolumeIdentity, DestinationRootBinding, EntryPreparation,
	EntryPrepared, JobPrepared, JournalContext, JournalEntryId, JournalEpoch, JournalJobId,
	LinuxFileIdentity, LiveSourceView, ObservedTimestamp, OwnerProfileId, OwnerTimestamp,
	OwnerToken, PlanDigest, PreparedTarget, RootCapabilityId, SourceInodeMetadata, SourceTimes,
	TargetObservation,
};

pub(super) fn context() -> JournalContext {
	let bytes = [
		0x01, 0x82, 0x79, 0x74, 0x55, 0x90, 0x7a, 0x14, 0x88, 0x88, 0x9c, 0x84, 0x07, 0xc7, 0x18,
		0xca,
	];
	JournalContext {
		job: JournalJobId::from_bytes(bytes).unwrap(),
		epoch: JournalEpoch::new(170),
		plan_digest: PlanDigest::from_bytes(core::array::from_fn(|i| u8::try_from(i).unwrap())),
	}
}

pub(super) fn entry_id() -> JournalEntryId {
	JournalEntryId::from_bytes([
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x47, 0x77, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
		0x22,
	])
}

pub(super) fn origin_volume() -> DarwinVolumeIdentity {
	DarwinVolumeIdentity::new(-17, [0x0123_4567, 0x89ab_cdef]).unwrap()
}

pub(super) fn output_volume() -> DarwinVolumeIdentity {
	DarwinVolumeIdentity::new(-23, [0x7654_3210, 0xfedc_ba98]).unwrap()
}

pub(super) fn identity(
	volume: DarwinVolumeIdentity,
	inode: u64,
	generation: Option<u32>,
) -> DarwinFileIdentity {
	DarwinFileIdentity::new(
		volume,
		NonZeroU64::new(inode).unwrap(),
		generation.map(|value| NonZeroU32::new(value).unwrap()),
		time(-2, 345),
	)
}

pub(super) fn time(seconds: i64, fraction: u32) -> OwnerTimestamp {
	OwnerTimestamp::new(seconds, fraction).unwrap()
}

pub(super) fn destination() -> DarwinRootBinding {
	let bytes = [
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff,
	];
	DarwinRootBinding {
		id: RootCapabilityId::from_bytes(bytes).unwrap(),
		identity: identity(output_volume(), 31, Some(17)),
	}
}

pub(super) fn owner(token_byte: u8) -> DarwinOwnerRecord {
	let context = context();
	let manifest = DarwinOwnerManifest {
		token: OwnerToken::from_bytes([token_byte; 16]).unwrap(),
		job: context.job,
		profile: OwnerProfileId::from_bytes([0xaa; 16]).unwrap(),
		created: time(-11, 12345),
		destination_volume: output_volume(),
		state_root: identity(output_volume(), 41, Some(79)),
		state_root_uid: NonZeroU32::new(501).unwrap(),
		plan_digest: context.plan_digest,
	};
	DarwinOwnerRecord::sign(manifest, &SigningKey::from_bytes(&[0xdb; 32])).unwrap()
}

pub(super) fn component(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).unwrap()
}

pub(super) fn source(component: UnixComponent<'_>, length: u64) -> DarwinSourceView<'_> {
	let bytes = [
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x47, 0x88, 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
		0x16,
	];
	DarwinSourceView::new(
		DarwinRootBinding {
			id: RootCapabilityId::from_bytes(bytes).unwrap(),
			identity: identity(origin_volume(), 21, None),
		},
		component,
		identity(origin_volume(), 22, Some(18)),
		length,
		DarwinSourceTimes {
			accessed_at: time(-6, 123),
			modified_at: time(25, 456),
			changed_at: time(26, 789),
		},
		DarwinSourceMetadata::new(0o600, NonZeroU32::new(501).unwrap(), 20).unwrap(),
	)
	.unwrap()
}

pub(super) fn preparation() -> DarwinEntryPreparation<'static> {
	DarwinEntryPreparation {
		source: source(component(b"source\xff"), 65_536),
		stage: DarwinStageObservation {
			id: DarwinStageId::from_bytes(core::array::from_fn(|i| {
				u8::try_from(i + 0x80).unwrap()
			})),
			directory: identity(output_volume(), 32, None),
			identity: identity(output_volume(), 33, Some(19)),
			component: component(b"stage\xfe"),
		},
		target_component: component(b"target\xfd"),
		target_observation: TargetObservation::AbsentObserved,
	}
}

pub(super) fn linux_records() -> (Vec<u8>, Vec<u8>) {
	let context = context();
	let id = destination().id;
	let root = DestinationRootBinding {
		id,
		identity: LinuxFileIdentity::new(11, 17),
	};
	let job = JobPrepared {
		context,
		owner_digest: owner(0xcd).digest(),
		destination_root: root,
	};
	let observed = ObservedTimestamp::new(0, 0).unwrap();
	let times = SourceTimes {
		accessed_at: observed,
		modified_at: observed,
		changed_at: observed,
	};
	let entry = EntryPrepared::new(
		context,
		entry_id(),
		EntryPreparation {
			source: LiveSourceView::new(LinuxFileIdentity::new(11, 21), 3, times).unwrap(),
			stage: LinuxFileIdentity::new(11, 22),
			target: PreparedTarget {
				root: id,
				component: component(b"target"),
				observation: TargetObservation::AbsentObserved,
			},
			source_metadata: SourceInodeMetadata::no_visible_extended_attributes(0o600, 501, 20, 1)
				.unwrap(),
		},
	)
	.unwrap();
	(job.encode(), entry.encode())
}
