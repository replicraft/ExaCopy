use std::num::{NonZeroU32, NonZeroU64};

use exacopy_endpoint::MAX_UNIX_COMPONENT_BYTES;
use exacopy_journal::{DarwinVolumeIdentity, OwnerTimestamp};

use super::*;

const fn uuid(marker: u8) -> [u8; 16] {
	let mut bytes = [marker; 16];
	bytes[6] = 0x70;
	bytes[8] = 0x80;
	bytes
}

fn profile(marker: u8) -> OwnerProfileId {
	OwnerProfileId::from_bytes(uuid(marker)).unwrap()
}

fn root(marker: u8) -> RootCapabilityId {
	RootCapabilityId::from_bytes(uuid(marker)).unwrap()
}

fn component(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).unwrap()
}

fn timestamp(seconds: i64, nanoseconds: u32) -> ObservedTimestamp {
	ObservedTimestamp::new(seconds, nanoseconds).unwrap()
}

fn identity(
	volume: DarwinVolumeIdentity,
	inode: u64,
	generation: Option<NonZeroU32>,
	birth_seconds: i64,
	birth_nanoseconds: u32,
) -> DarwinFileIdentity {
	DarwinFileIdentity::new(
		volume,
		NonZeroU64::new(inode).unwrap(),
		generation,
		OwnerTimestamp::new(birth_seconds, birth_nanoseconds).unwrap(),
	)
}

fn fixture() -> DarwinCopyPlan<'static> {
	let source_volume = DarwinVolumeIdentity::new(-2, [5, 6]).unwrap();
	let destination_volume = DarwinVolumeIdentity::new(13, [17, 18]).unwrap();
	DarwinCopyPlan::new(
		PlanAttempt {
			job: JournalJobId::from_bytes(uuid(1)).unwrap(),
			epoch: JournalEpoch::new(3),
			entry: JournalEntryId::from_bytes([2; 16]),
			profile: profile(9),
		},
		SourcePlanBinding {
			root_id: root(4),
			root_identity: identity(source_volume, 8, None, -11, 7),
			file_identity: identity(source_volume, 9, NonZeroU32::new(11), -3, 6),
			length: 28,
			metadata: SourceMetadata::new(
				0o600,
				501,
				20,
				timestamp(-1, 5),
				timestamp(10, 45),
				timestamp(-40, 600),
			)
			.unwrap(),
			component: component(b"src\xff"),
		},
		DestinationPlanBinding {
			root_id: root(8),
			root_identity: identity(destination_volume, 10, None, 0, 8),
			component: component(b"new\xfe"),
		},
	)
	.unwrap()
}

// Deterministic CBOR from an independent encoder using the format field order,
// with both native generation states, a signed device number and raw byte names.
const DARWIN_GOLDEN: &[u8] = &[
	0x85, 0x83, 0x02, 0x00, 0x01, 0x85, 0x00, 0x00, 0x00, 0x01, 0x01, 0x84, 0x50, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x70, 0x01, 0x80, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x50, 0x02,
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x50,
	0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x70, 0x09, 0x80, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
	0x86, 0x50, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x70, 0x04, 0x80, 0x04, 0x04, 0x04, 0x04, 0x04,
	0x04, 0x04, 0xa4, 0x00, 0xa3, 0x00, 0x02, 0x01, 0x44, 0xfe, 0xff, 0xff, 0xff, 0x02, 0x82, 0x05,
	0x06, 0x01, 0x48, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xf6, 0x03, 0xa2, 0x00,
	0x2a, 0x01, 0x07, 0xa4, 0x00, 0xa3, 0x00, 0x02, 0x01, 0x44, 0xfe, 0xff, 0xff, 0xff, 0x02, 0x82,
	0x05, 0x06, 0x01, 0x48, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0b, 0x03, 0xa2,
	0x00, 0x22, 0x01, 0x06, 0x18, 0x1c, 0x86, 0x19, 0x01, 0x80, 0x19, 0x01, 0xf5, 0x14, 0x82, 0x20,
	0x05, 0x82, 0x0a, 0x18, 0x2d, 0x82, 0x38, 0x27, 0x19, 0x02, 0x58, 0x44, 0x73, 0x72, 0x63, 0xff,
	0x83, 0x50, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x70, 0x08, 0x80, 0x08, 0x08, 0x08, 0x08, 0x08,
	0x08, 0x08, 0xa4, 0x00, 0xa3, 0x00, 0x02, 0x01, 0x44, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x82, 0x11,
	0x12, 0x01, 0x48, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xf6, 0x03, 0xa2, 0x00,
	0x00, 0x01, 0x08, 0x44, 0x6e, 0x65, 0x77, 0xfe,
];

// The existing valid Linux v1 plan golden.
const LINUX_V1_GOLDEN: &[u8] = &[
	0x85, 0x82, 0x01, 0x00, 0x85, 0, 0, 0, 0, 0, // record prefix and fixed policy
	0x85, 0x50, 1, 1, 1, 1, 1, 1, 0x70, 1, 0x80, 1, 1, 1, 1, 1, 1, 1, // job UUID
	3, 0x50, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // epoch and entry
	0x43, b'j', b'o', b'b', 0x45, b's', b't', b'a', b'g', b'e', 0x87, 0x50, 4, 4, 4, 4, 4, 4, 0x70,
	4, 0x80, 4, 4, 4, 4, 4, 4, 4, // source root
	0x82, 5, 6, 0x82, 5, 7, 0x18, 28, 0x82, 0x20, 5, 0x82, 10, 0x18, 45, // file and times
	0x44, b's', b'r', b'c', 0xff, 0x83, 0x50, 8, 8, 8, 8, 8, 8, 0x70, 8, 0x80, 8, 8, 8, 8, 8, 8,
	8, // destination root
	0x82, 9, 10, 0x44, b'n', b'e', b'w', 0xfe,
];

#[test]
fn matches_independent_canonical_plan_and_domain() {
	let plan = fixture();
	assert_eq!(plan.encode(), DARWIN_GOLDEN);
	assert_eq!(
		DarwinCopyPlan::decode(DARWIN_GOLDEN, profile(9)).unwrap(),
		plan
	);
	let mut preimage = b"ExaCopy/darwin-managed-apfs-copy-plan/v2\0".to_vec();
	preimage.extend_from_slice(DARWIN_GOLDEN);
	assert_eq!(plan.digest().as_bytes(), blake3::hash(&preimage).as_bytes());
	let mut linux_preimage = b"ExaCopy/local-copy-plan/v1\0".to_vec();
	linux_preimage.extend_from_slice(DARWIN_GOLDEN);
	assert_ne!(
		plan.digest().as_bytes(),
		blake3::hash(&linux_preimage).as_bytes()
	);
	assert_eq!(plan.context().job, plan.attempt().job);
	assert_eq!(plan.context().epoch, plan.attempt().epoch);
	assert_eq!(plan.context().plan_digest, plan.digest());
}

#[test]
fn refuses_linux_plan_other_profile_and_unsupported_contracts() {
	assert!(matches!(
		DarwinCopyPlan::decode(LINUX_V1_GOLDEN, profile(9)),
		Err(DarwinCopyPlanError::UnsupportedVersion)
	));
	assert!(matches!(
		DarwinCopyPlan::decode(DARWIN_GOLDEN, profile(10)),
		Err(DarwinCopyPlanError::ProfileMismatch)
	));

	for (index, replacement) in [(2, 1), (3, 1), (4, 0), (4, 3)] {
		let mut bytes = DARWIN_GOLDEN.to_vec();
		bytes[index] = replacement;
		assert!(matches!(
			DarwinCopyPlan::decode(&bytes, profile(9)),
			Err(DarwinCopyPlanError::UnsupportedVersion)
		));
	}
	for index in 6..=10 {
		let mut bytes = DARWIN_GOLDEN.to_vec();
		bytes[index] = 2;
		assert!(matches!(
			DarwinCopyPlan::decode(&bytes, profile(9)),
			Err(DarwinCopyPlanError::UnsupportedPolicy)
		));
	}
}

#[test]
fn valid_changes_to_bound_evidence_change_digest() {
	let original = fixture().digest();
	for (index, replacement) in [
		(13, 6),    // Job identifier.
		(29, 4),    // Epoch.
		(31, 3),    // Entry identifier.
		(48, 10),   // Owner profile.
		(76, 8),    // Source root grant.
		(99, 13),   // Source root inode.
		(114, 8),   // Source root birth fraction.
		(132, 12),  // Source file inode.
		(141, 12),  // Source file generation.
		(147, 7),   // Source file birth fraction.
		(149, 29),  // Stream extent.
		(156, 246), // Owner UID.
		(157, 21),  // Group GID.
		(160, 6),   // Access time.
		(164, 46),  // Modification time.
		(170, 89),  // Change time.
		(175, 254), // Raw source component.
		(178, 3),   // Destination root grant.
		(201, 14),  // Destination native device.
		(207, 19),  // Destination FSID.
		(211, 11),  // Destination inode.
		(231, 255), // Raw target component.
	] {
		let mut bytes = DARWIN_GOLDEN.to_vec();
		bytes[index] = replacement;
		let expected_profile = if index == 48 {
			let mut uuid = uuid(9);
			uuid[0] = 10;
			OwnerProfileId::from_bytes(uuid).unwrap()
		} else {
			profile(9)
		};
		let changed = DarwinCopyPlan::decode(&bytes, expected_profile)
			.unwrap_or_else(|error| panic!("mutating byte {index} failed: {error}"));
		assert_ne!(changed.digest(), original, "mutating plan byte {index}");
	}
}

#[test]
fn rejects_every_truncation_trailing_bytes_and_oversize() {
	for end in 0..DARWIN_GOLDEN.len() {
		assert!(
			DarwinCopyPlan::decode(&DARWIN_GOLDEN[..end], profile(9)).is_err(),
			"accepted plan truncated at byte {end}"
		);
	}
	assert!(matches!(
		DarwinCopyPlan::decode(&[0; MAX_DARWIN_COPY_PLAN_BYTES + 1], profile(9)),
		Err(DarwinCopyPlanError::PayloadTooLarge)
	));
	let mut bytes = DARWIN_GOLDEN.to_vec();
	bytes.push(0);
	assert!(matches!(
		DarwinCopyPlan::decode(&bytes, profile(9)),
		Err(DarwinCopyPlanError::NonCanonical)
	));
}

#[test]
fn rejects_nonpreferred_integers_strings_and_collection_headers() {
	for (index, widened) in [
		(0, [0x98, 5]),    // Plan array length.
		(2, [0x18, 2]),    // Major version.
		(29, [0x18, 3]),   // Epoch.
		(82, [0xb8, 4]),   // Native identity map length.
		(141, [0x18, 11]), // Native generation.
		(171, [0x58, 4]),  // Raw component byte string length.
	] {
		let mut bytes = DARWIN_GOLDEN.to_vec();
		bytes.splice(index..=index, widened);
		assert!(
			matches!(
				DarwinCopyPlan::decode(&bytes, profile(9)),
				Err(DarwinCopyPlanError::NonCanonical)
			),
			"wrong refusal for overwide encoding at byte {index}"
		);
	}
	for (index, byte) in [
		(0, 0x9f),   // Indefinite plan.
		(82, 0xbf),  // Indefinite identity.
		(83, 1),     // Repeated identity key.
		(83, 4),     // Unknown identity key.
		(171, 0x5f), // Indefinite component.
	] {
		let mut bytes = DARWIN_GOLDEN.to_vec();
		bytes[index] = byte;
		assert!(DarwinCopyPlan::decode(&bytes, profile(9)).is_err());
	}
}

#[test]
fn rejects_malformed_native_identity_timestamp_and_components() {
	for (index, replacement) in [
		(86, 1),   // Linux platform tag in Darwin identity.
		(89, 255), // Darwin NODEV.
		(99, 0),   // Zero inode.
		(141, 0),  // Explicit zero generation.
	] {
		let mut bytes = DARWIN_GOLDEN.to_vec();
		bytes[index] = replacement;
		assert!(
			matches!(
				DarwinCopyPlan::decode(&bytes, profile(9)),
				Err(DarwinCopyPlanError::InvalidIdentity)
			),
			"wrong refusal for malformed identity at byte {index}"
		);
	}
	for index in [114, 160] {
		let mut bytes = DARWIN_GOLDEN.to_vec();
		bytes.splice(index..=index, [0x1a, 0x3b, 0x9a, 0xca, 0x00]);
		assert!(matches!(
			DarwinCopyPlan::decode(&bytes, profile(9)),
			Err(DarwinCopyPlanError::InvalidTimestamp)
		));
	}

	for invalid in [&b""[..], b".", b"..", b"/", b"\0", b"a/b", b"a\0b"] {
		for fields in [171..176, 227..232] {
			let mut bytes = DARWIN_GOLDEN.to_vec();
			let length = u8::try_from(invalid.len()).unwrap();
			bytes.splice(
				fields,
				[0x40 | length].into_iter().chain(invalid.iter().copied()),
			);
			assert!(matches!(
				DarwinCopyPlan::decode(&bytes, profile(9)),
				Err(DarwinCopyPlanError::InvalidComponent(_))
			));
		}
	}
}

#[test]
fn preserves_independent_same_parent_grants_and_rejects_conflicting_observations() {
	let plan = fixture();
	let mut destination = plan.destination();
	destination.root_identity = plan.source().root_identity;
	let shared_parent = DarwinCopyPlan::new(plan.attempt(), plan.source(), destination).unwrap();
	assert_ne!(
		shared_parent.source().root_id,
		shared_parent.destination().root_id
	);
	let bytes = shared_parent.encode();
	assert_eq!(
		DarwinCopyPlan::decode(&bytes, profile(9)).unwrap(),
		shared_parent
	);

	destination.component = plan.source().component;
	assert!(matches!(
		DarwinCopyPlan::new(plan.attempt(), plan.source(), destination),
		Err(DarwinCopyPlanError::ConflictingNames)
	));
	destination.root_identity = plan.destination().root_identity;
	assert!(DarwinCopyPlan::new(plan.attempt(), plan.source(), destination).is_ok());

	destination.root_id = plan.source().root_id;
	assert!(matches!(
		DarwinCopyPlan::new(plan.attempt(), plan.source(), destination),
		Err(DarwinCopyPlanError::ConflictingIdentities)
	));
	destination.root_id = plan.destination().root_id;
	let source_root = plan.source().root_identity;
	destination.root_identity = identity(
		source_root.volume(),
		source_root.inode().get(),
		source_root.generation(),
		1,
		0,
	);
	assert!(matches!(
		DarwinCopyPlan::new(plan.attempt(), plan.source(), destination),
		Err(DarwinCopyPlanError::ConflictingIdentities)
	));
	destination.root_identity = plan.source().file_identity;
	assert!(matches!(
		DarwinCopyPlan::new(plan.attempt(), plan.source(), destination),
		Err(DarwinCopyPlanError::ConflictingIdentities)
	));

	let mut source = plan.source();
	source.file_identity = destination.root_identity;
	source.root_identity = plan.destination().root_identity;
	assert!(matches!(
		DarwinCopyPlan::new(plan.attempt(), source, plan.destination()),
		Err(DarwinCopyPlanError::SourceOutsideRootVolume)
	));
	source = plan.source();
	source.file_identity = source.root_identity;
	assert!(matches!(
		DarwinCopyPlan::new(plan.attempt(), source, plan.destination()),
		Err(DarwinCopyPlanError::ConflictingIdentities)
	));
	source = plan.source();
	source.length = MAX_FILE_LENGTH + 1;
	assert!(matches!(
		DarwinCopyPlan::new(plan.attempt(), source, plan.destination()),
		Err(DarwinCopyPlanError::SourceTooLong)
	));
}

#[test]
fn fixed_basic_metadata_refuses_unsupported_modes_and_ownership() {
	let t = timestamp(0, 0);
	for (mode, uid, gid) in [
		(0o400, 1, 0),
		(0o640, 1, 0),
		(0o1600, 1, 0),
		(0o600, 0, 0),
		(0o600, DARWIN_UID_MAX + 1, 0),
		(0o600, 1, DARWIN_GID_MAX + 1),
	] {
		assert!(matches!(
			SourceMetadata::new(mode, uid, gid, t, t, t),
			Err(DarwinCopyPlanError::UnsupportedMetadata)
		));
	}
	assert!(SourceMetadata::new(0o600, 1, 0, t, t, t).is_ok());

	let mut bytes = DARWIN_GOLDEN.to_vec();
	bytes[153] = 0xa0; // 0640 instead of 0600.
	assert!(matches!(
		DarwinCopyPlan::decode(&bytes, profile(9)),
		Err(DarwinCopyPlanError::UnsupportedMetadata)
	));
}

#[test]
fn exactly_fits_maximum_wire_buffer() {
	let plan = fixture();
	let source_volume = DarwinVolumeIdentity::new(i32::MIN, [u32::MAX; 2]).unwrap();
	let destination_volume = DarwinVolumeIdentity::new(i32::MAX, [u32::MAX, u32::MAX - 1]).unwrap();
	let generation = NonZeroU32::new(u32::MAX);
	let nanoseconds = 999_999_999;
	let t = timestamp(i64::MIN, nanoseconds);
	let max = DarwinCopyPlan::new(
		PlanAttempt {
			epoch: JournalEpoch::new(u64::MAX),
			..plan.attempt()
		},
		SourcePlanBinding {
			root_identity: identity(source_volume, u64::MAX, generation, i64::MIN, nanoseconds),
			file_identity: identity(
				source_volume,
				u64::MAX - 1,
				generation,
				i64::MAX,
				nanoseconds,
			),
			length: MAX_FILE_LENGTH,
			metadata: SourceMetadata::new(0o600, DARWIN_UID_MAX, DARWIN_GID_MAX, t, t, t).unwrap(),
			component: component(&[b's'; MAX_UNIX_COMPONENT_BYTES]),
			..plan.source()
		},
		DestinationPlanBinding {
			root_identity: identity(
				destination_volume,
				u64::MAX,
				generation,
				i64::MIN,
				nanoseconds,
			),
			component: component(&[b't'; MAX_UNIX_COMPONENT_BYTES]),
			..plan.destination()
		},
	)
	.unwrap();
	let encoded = max.encode();
	assert_eq!(encoded.len(), MAX_DARWIN_COPY_PLAN_BYTES);
	assert_eq!(DarwinCopyPlan::decode(&encoded, profile(9)).unwrap(), max);
}
