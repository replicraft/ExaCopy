use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use exacopy_journal::frame::{ChainHead, Frame, FrameKind};
use exacopy_journal::{
	BasicMetadata, DarwinMetadataRecorded, DarwinPhaseError, DarwinPublishIntent,
	DarwinStageSealed, DarwinVerificationRecorded, JournalContext, JournalEntryId, JournalEpoch,
	JournalJobId, LinuxFileIdentity, MetadataRecorded, OwnerTimestamp, PlanDigest,
	PublicationPrimitive, PublishIntent, PublishIntentContext, PublishIntentTarget, StageSealed,
	StreamDigest, StreamEvidence, StreamLength, VerificationRecorded,
};

use super::fixture::frame;

const MAJOR: usize = 4;
const MINOR: usize = 6;
const REQUIRED_FEATURES: usize = 8;
const RECORD_DOMAIN: &[u8] = b"ExaCopy/journal-darwin-phase/v2\0";

// Independently assembled using a small, Python standard-library-only deterministic
// CBOR encoder and explicit field maps. Digest references are synthetic bytes.
const VECTORS: [(FrameKind, &str); 4] = [
	(FrameKind::StageSealed, include_str!("seal.hex")),
	(
		FrameKind::VerificationRecorded,
		include_str!("verification.hex"),
	),
	(FrameKind::MetadataRecorded, include_str!("metadata.hex")),
	(FrameKind::PublishIntent, include_str!("intent.hex")),
];

#[test]
fn independent_vectors_match_canonical_payloads_and_phase_digest_domains() {
	for (kind, golden) in VECTORS {
		let golden = bytes(golden);
		let (encoded, digest) = match kind {
			FrameKind::StageSealed => {
				let seal = DarwinStageSealed::decode(&golden).unwrap();
				assert_eq!(seal.length().get(), MAX_FILE_LENGTH);
				assert_eq!(seal.stage().volume().device(), -2);
				assert_eq!(seal.stage().volume().physical_fsid(), [257, u32::MAX]);
				assert_eq!(seal.stage().generation(), None);
				(seal.encode(), seal.record_digest())
			}
			FrameKind::VerificationRecorded => {
				let verification = DarwinVerificationRecorded::decode(&golden).unwrap();
				assert_eq!(verification.source().length.get(), MAX_FILE_LENGTH);
				assert_eq!(verification.source().identity.birth().seconds(), i64::MIN);
				assert_eq!(verification.stage().digest.as_bytes(), &[0x88; 32]);
				(verification.encode(), verification.record_digest())
			}
			FrameKind::MetadataRecorded => {
				let metadata = DarwinMetadataRecorded::decode(&golden).unwrap();
				assert_eq!(metadata.metadata().permissions().mode(), 0o600);
				assert_eq!(
					metadata.metadata().permissions().owner().get(),
					2_147_483_647
				);
				assert_eq!(metadata.metadata().permissions().group(), 2_147_483_647);
				assert_eq!(metadata.metadata().accessed_at.seconds(), i64::MAX);
				assert_eq!(metadata.metadata().accessed_at.nanoseconds(), 999_999_999);
				(metadata.encode(), metadata.record_digest())
			}
			FrameKind::PublishIntent => {
				let intent = DarwinPublishIntent::decode(&golden).unwrap();
				assert_eq!(intent.effect_sequence().get(), u64::MAX);
				assert_eq!(intent.target().component.as_bytes(), b"project-\xff\x80");
				assert_eq!(intent.target().stage.inode().get(), 30);
				assert_eq!(
					intent.target().stage_directory.generation().unwrap().get(),
					100
				);
				assert_eq!(intent.target().parent.generation().unwrap().get(), u32::MAX);
				(intent.encode(), intent.record_digest())
			}
			_ => panic!("unexpected golden discriminator {kind:?}"),
		};
		assert_eq!(encoded, golden, "canonical {kind:?} payload");
		let mut digest_input = RECORD_DOMAIN.to_vec();
		digest_input.extend_from_slice(&kind.code().to_le_bytes());
		digest_input.extend_from_slice(&golden);
		assert_eq!(digest.as_bytes(), blake3::hash(&digest_input).as_bytes());
		assert_eq!(
			decode_frame(kind, &frame(kind, &golden, ChainHead::start())),
			Ok(())
		);
	}
}

#[test]
fn wrong_profile_and_wrong_frame_kind_are_refused() {
	for ((kind, golden), (linux_kind, linux)) in VECTORS.into_iter().zip(linux_payloads()) {
		let golden = bytes(golden);
		assert_eq!(kind, linux_kind);
		assert!(
			decode(kind, &linux).is_err(),
			"{kind:?} rejected Linux profile"
		);
		let refused = match kind {
			FrameKind::StageSealed => StageSealed::decode(&golden).is_err(),
			FrameKind::VerificationRecorded => VerificationRecorded::decode(&golden).is_err(),
			FrameKind::MetadataRecorded => MetadataRecorded::decode(&golden).is_err(),
			FrameKind::PublishIntent => PublishIntent::decode(&golden).is_err(),
			_ => panic!("unexpected golden discriminator {kind:?}"),
		};
		assert!(refused, "Linux decoder rejected managed APFS {kind:?}");
		assert_eq!(
			decode_frame(
				kind,
				&frame(FrameKind::JobPrepared, &golden, ChainHead::start())
			),
			Err(DarwinPhaseError::WrongKind {
				expected: kind,
				actual: FrameKind::JobPrepared
			})
		);
		for offset in [MAJOR, MINOR, REQUIRED_FEATURES] {
			let mut incompatible = golden.clone();
			incompatible[offset] ^= 1;
			assert!(
				decode(kind, &incompatible).is_err(),
				"{kind:?} rejected profile byte {offset}"
			);
		}
	}
}

#[test]
fn every_phase_refuses_truncation_noncanonical_cbor_trailing_data_and_oversize() {
	for (kind, golden) in VECTORS {
		let golden = bytes(golden);
		for end in 0..golden.len() {
			assert!(
				decode(kind, &golden[..end]).is_err(),
				"{kind:?} accepted truncation at {end}"
			);
		}
		let mut noncanonical = golden.clone();
		noncanonical.insert(MAJOR, 0x18);
		assert_eq!(
			decode(kind, &noncanonical),
			Err(DarwinPhaseError::NonCanonical)
		);

		let mut indefinite = golden.clone();
		indefinite[0] = 0xbf;
		indefinite.push(0xff);
		assert!(decode(kind, &indefinite).is_err());

		let mut trailing = golden;
		trailing.push(0);
		assert_eq!(
			decode(kind, &trailing),
			Err(DarwinPhaseError::TrailingBytes)
		);
		assert_eq!(
			decode(kind, &[0; 1024]),
			Err(DarwinPhaseError::PayloadTooLong)
		);
	}
}

#[test]
fn stage_barrier_metadata_result_readback_and_exclusive_primitive_are_required() {
	for (kind, golden) in VECTORS {
		let mut unsupported = bytes(golden);
		let index = unsupported.len() - 1;
		if kind != FrameKind::VerificationRecorded {
			unsupported[index] = if kind == FrameKind::PublishIntent {
				1
			} else {
				0
			};
			assert_eq!(
				decode(kind, &unsupported),
				Err(DarwinPhaseError::UnsupportedEvidence)
			);
		}
	}

	let mut verification = bytes(VECTORS[1].1);
	let method_offset = find(&verification, &[0xaa; 32]) + 33;
	verification[method_offset] = 0;
	assert_eq!(
		DarwinVerificationRecorded::decode(&verification),
		Err(DarwinPhaseError::UnsupportedEvidence)
	);

	let mut metadata = bytes(VECTORS[2].1);
	let absence = metadata.len() - 3;
	metadata[absence] = 0;
	assert_eq!(
		DarwinMetadataRecorded::decode(&metadata),
		Err(DarwinPhaseError::UnsupportedEvidence)
	);

	let mut seal = bytes(VECTORS[0].1);
	let workers = seal.len() - 3;
	seal[workers] = 2;
	assert_eq!(
		DarwinStageSealed::decode(&seal),
		Err(DarwinPhaseError::UnsupportedEvidence)
	);
}

#[test]
fn payload_refuses_forged_measurements_names_sequences_and_platforms() {
	let mut verification = bytes(VECTORS[1].1);
	let last = verification.len() - 1;
	verification[last] ^= 1;
	assert_eq!(
		DarwinVerificationRecorded::decode(&verification),
		Err(DarwinPhaseError::StreamMismatch)
	);

	let mut seal = bytes(VECTORS[0].1);
	let extent = find(&seal, &MAX_FILE_LENGTH.to_be_bytes());
	seal[extent] = 0x80;
	assert_eq!(
		DarwinStageSealed::decode(&seal),
		Err(DarwinPhaseError::StreamMismatch)
	);

	let mut intent = bytes(VECTORS[3].1);
	let raw_name = find(&intent, b"project-\xff\x80");
	intent[raw_name] = b'/';
	assert_eq!(
		DarwinPublishIntent::decode(&intent),
		Err(DarwinPhaseError::InvalidComponent)
	);

	let mut intent = bytes(VECTORS[3].1);
	let effect = find(&intent, &u64::MAX.to_be_bytes());
	intent.splice(effect - 1..effect + size_of::<u64>(), [0]);
	assert_eq!(
		DarwinPublishIntent::decode(&intent),
		Err(DarwinPhaseError::InvalidEffectSequence)
	);

	let mut intent = bytes(VECTORS[3].1);
	let first_platform = find(&intent, &[0x00, 0xa3, 0x00, 0x02, 0x01, 0x44]);
	intent[first_platform + 3] = 1;
	assert!(
		DarwinPublishIntent::decode(&intent).is_err(),
		"Linux identity discriminator"
	);
}

#[test]
fn recorded_group_is_bounded_by_darwin_gid_max() {
	let mut payload = bytes(VECTORS[2].1);
	let group = find(&payload, &[0x1a, 0x7f, 0xff, 0xff, 0xff, 0x02, 0x1a, 0x7f]) + 6;
	payload[group + 1] = 0xff;
	assert_eq!(
		DarwinMetadataRecorded::decode(&payload),
		Err(DarwinPhaseError::MetadataMismatch),
	);
	payload.splice(group..group + 5, [0x00]);
	let result = DarwinMetadataRecorded::decode(&payload).unwrap();
	assert_eq!(result.metadata().permissions().group(), 0);
}

#[test]
fn intent_refuses_cross_volume_or_aliased_roles_even_with_different_birth_evidence() {
	let mut intent = bytes(VECTORS[3].1);
	let narrowed_inode = find(&intent, &[1, 0x48, 29, 0, 0, 0, 0, 0, 0, 0]);
	intent[narrowed_inode + 2] = 30;
	assert_eq!(
		DarwinPublishIntent::decode(&intent),
		Err(DarwinPhaseError::AliasedIdentity)
	);

	let mut intent = bytes(VECTORS[3].1);
	let device = intent
		.windows(5)
		.rposition(|window| window == [0x44, 0xfe, 0xff, 0xff, 0xff])
		.unwrap();
	intent[device + 1] = 0xfd;
	assert_eq!(
		DarwinPublishIntent::decode(&intent),
		Err(DarwinPhaseError::VolumeMismatch)
	);
}

fn bytes(hex: &str) -> Vec<u8> {
	let hex: Vec<_> = hex
		.bytes()
		.filter(|byte| !byte.is_ascii_whitespace())
		.collect();
	let (pairs, remainder) = hex.as_chunks::<2>();
	assert!(remainder.is_empty(), "hex length");
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn find(input: &[u8], needle: &[u8]) -> usize {
	input
		.windows(needle.len())
		.position(|part| part == needle)
		.expect("test fixture part")
}

fn decode(kind: FrameKind, bytes: &[u8]) -> Result<(), DarwinPhaseError> {
	match kind {
		FrameKind::StageSealed => DarwinStageSealed::decode(bytes).map(|_| ()),
		FrameKind::VerificationRecorded => DarwinVerificationRecorded::decode(bytes).map(|_| ()),
		FrameKind::MetadataRecorded => DarwinMetadataRecorded::decode(bytes).map(|_| ()),
		FrameKind::PublishIntent => DarwinPublishIntent::decode(bytes).map(|_| ()),
		_ => panic!("unexpected fixture discriminator {kind:?}"),
	}
}

fn decode_frame(kind: FrameKind, frame: &Frame) -> Result<(), DarwinPhaseError> {
	match kind {
		FrameKind::StageSealed => DarwinStageSealed::from_frame(frame).map(|_| ()),
		FrameKind::VerificationRecorded => {
			DarwinVerificationRecorded::from_frame(frame).map(|_| ())
		}
		FrameKind::MetadataRecorded => DarwinMetadataRecorded::from_frame(frame).map(|_| ()),
		FrameKind::PublishIntent => DarwinPublishIntent::from_frame(frame).map(|_| ()),
		_ => panic!("unexpected fixture discriminator {kind:?}"),
	}
}

fn linux_payloads() -> [(FrameKind, Vec<u8>); 4] {
	let mut job = [0x22; 16];
	job[6] = 0x70;
	job[8] = 0x80;
	let context = JournalContext {
		job: JournalJobId::from_bytes(job).unwrap(),
		epoch: JournalEpoch::new(257),
		plan_digest: PlanDigest::from_bytes([0x12; 32]),
	};
	let entry = JournalEntryId::from_bytes([0x33; 16]);
	let identity = LinuxFileIdentity::new(1, 2);
	let length = StreamLength::new(0).unwrap();
	let stage = StreamEvidence {
		identity,
		length,
		digest: StreamDigest::from_bytes([5; 32]),
	};
	let source = StreamEvidence {
		identity: LinuxFileIdentity::new(1, 3),
		..stage
	};
	let seal = StageSealed {
		context,
		entry,
		stage: identity,
		length,
	};
	let verification = VerificationRecorded::new(context, entry, source, stage).unwrap();
	let time = OwnerTimestamp::new(0, 0).unwrap();
	let metadata = MetadataRecorded {
		context,
		entry,
		stage: identity,
		metadata: BasicMetadata::new(0o600, 501, 10, time, time).unwrap(),
	};
	let intent = PublishIntent {
		context: PublishIntentContext {
			job: context.job,
			epoch: context.epoch,
			entry,
			effect_sequence: 1,
			plan_digest: context.plan_digest,
		},
		target: PublishIntentTarget {
			stage: identity,
			parent: LinuxFileIdentity::new(1, 4),
			component: UnixComponent::new(b"dest").unwrap(),
			verification_digest: verification.record_digest(),
			primitive: PublicationPrimitive::LinuxRenameNoReplace,
		},
	};
	[
		(FrameKind::StageSealed, seal.encode()),
		(FrameKind::VerificationRecorded, verification.encode()),
		(FrameKind::MetadataRecorded, metadata.encode()),
		(FrameKind::PublishIntent, intent.encode()),
	]
}
