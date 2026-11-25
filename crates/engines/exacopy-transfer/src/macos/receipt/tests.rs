use std::num::{NonZeroU32, NonZeroU64};

use exacopy_endpoint::{MAX_FILE_LENGTH, MAX_UNIX_COMPONENT_BYTES, UnixComponent};
use exacopy_journal::{
	DarwinVolumeIdentity, JournalEpoch, JournalJobId, PlanDigest, RootCapabilityId, StreamDigest,
	StreamLength,
};

use super::*;

mod association;

const TARGET: &[u8] = b"target-\xff";
const OWNER: NonZeroU32 = NonZeroU32::new(501).unwrap();

fn uuid(marker: u8, version: u8) -> [u8; 16] {
	let mut bytes = [marker; 16];
	bytes[6] = version << 4;
	bytes[8] = 0x80;
	bytes
}

fn native(
	device: i32,
	fsid: [u32; 2],
	inode: u64,
	generation: Option<NonZeroU32>,
	seconds: i64,
	nanos: u32,
) -> DarwinFileIdentity {
	DarwinFileIdentity::new(
		DarwinVolumeIdentity::new(device, fsid).unwrap(),
		NonZeroU64::new(inode).unwrap(),
		generation,
		OwnerTimestamp::new(seconds, nanos).unwrap(),
	)
}

fn receipt_fixture() -> DarwinCopyReceipt<'static> {
	DarwinCopyReceipt::from_evidence(
		DarwinCopyReceiptEvidence {
			context: JournalContext {
				job: JournalJobId::from_bytes(uuid(0x41, 7)).unwrap(),
				epoch: JournalEpoch::new(31),
				plan_digest: PlanDigest::from_bytes([0x43; 32]),
			},
			entry: JournalEntryId::from_bytes([0x42; 16]),
			source: native(-2, [8, 9], 11, NonZeroU32::new(5), -11, 300),
			destination: DestinationPlanBinding {
				root_id: RootCapabilityId::from_bytes(uuid(0x44, 4)).unwrap(),
				root_identity: native(15, [23, 24], 14, None, 1, 0),
				component: UnixComponent::new(TARGET).unwrap(),
			},
			stream: DarwinStreamEvidence {
				identity: native(15, [23, 24], 15, NonZeroU32::new(7), -1, 20),
				length: StreamLength::new(99).unwrap(),
				digest: StreamDigest::from_bytes([0x45; 32]),
			},
			metadata: DarwinRequiredMetadata::new(
				0o600,
				OWNER,
				20,
				OwnerTimestamp::new(-3, 21).unwrap(),
				OwnerTimestamp::new(7, 0).unwrap(),
			)
			.unwrap(),
			stage_directory: native(15, [23, 24], 13, None, 2, 0),
		},
		ChainHead::after(9, [0x46; 32]).unwrap(),
	)
	.unwrap()
}

// Constructed with an independent CBOR writer from the fixed field order.
fn golden() -> Vec<u8> {
	include_str!("tests/receipt.hex")
		.lines()
		.flat_map(|line| {
			(0..line.len())
				.step_by(2)
				.map(|index| u8::from_str_radix(&line[index..index + 2], 16).unwrap())
		})
		.collect()
}

#[test]
fn canonical_golden_retains_raw_target_and_domain() {
	let bytes = golden();
	let receipt = receipt_fixture();
	assert_eq!(receipt.encode(), bytes);
	assert_eq!(DarwinCopyReceipt::decode(&bytes).unwrap(), receipt);
	assert_eq!(receipt.evidence().destination.component.as_bytes(), TARGET);
	let expected = blake3::Hasher::new()
		.update(b"ExaCopy/darwin-copy-receipt/v1\0")
		.update(&bytes)
		.finalize();
	assert_eq!(receipt.digest().as_bytes(), expected.as_bytes());
	let linux_domain = blake3::Hasher::new()
		.update(b"ExaCopy/linux-copy-receipt/v1\0")
		.update(&bytes)
		.finalize();
	assert_ne!(receipt.digest().as_bytes(), linux_domain.as_bytes());
}

#[test]
fn rejects_unsupported_profiles_and_nominally_successful_durability_upgrades() {
	let bytes = golden();
	for (index, value, expected) in [
		(2, 2, DarwinCopyReceiptError::UnsupportedVersion),
		(3, 1, DarwinCopyReceiptError::UnsupportedVersion),
		(4, 1, DarwinCopyReceiptError::UnsupportedVersion),
		(6, 1, DarwinCopyReceiptError::UnsupportedProfile),
		(7, 1, DarwinCopyReceiptError::UnsupportedProfile),
		(7, 2, DarwinCopyReceiptError::UnsupportedProfile),
	] {
		let mut altered = bytes.clone();
		altered[index] = value;
		assert_eq!(DarwinCopyReceipt::decode(&altered), Err(expected));
	}
	let mut linux_v1_shape = bytes;
	linux_v1_shape[0] = 0xab;
	assert_eq!(
		DarwinCopyReceipt::decode(&linux_v1_shape),
		Err(DarwinCopyReceiptError::InvalidCbor)
	);
}

#[test]
fn rejects_truncation_trailing_nonminimal_and_oversized_input() {
	let bytes = golden();
	for end in 0..bytes.len() {
		assert!(
			DarwinCopyReceipt::decode(&bytes[..end]).is_err(),
			"truncation at {end}"
		);
	}
	let mut trailing = bytes.clone();
	trailing.push(0);
	assert_eq!(
		DarwinCopyReceipt::decode(&trailing),
		Err(DarwinCopyReceiptError::NonCanonical)
	);
	let mut nonminimal = bytes.clone();
	nonminimal.splice(2..3, [0x18, 1]);
	assert_eq!(
		DarwinCopyReceipt::decode(&nonminimal),
		Err(DarwinCopyReceiptError::NonCanonical)
	);
	let mut indefinite = bytes;
	indefinite[0] = 0x9f;
	indefinite.push(0xff);
	assert_eq!(
		DarwinCopyReceipt::decode(&indefinite),
		Err(DarwinCopyReceiptError::InvalidCbor)
	);
	assert_eq!(
		DarwinCopyReceipt::decode(&[0; MAX_DARWIN_COPY_RECEIPT_BYTES + 1]),
		Err(DarwinCopyReceiptError::TooLarge)
	);
}

#[test]
fn rejects_malformed_native_metadata_and_durability_reference_fields() {
	let bytes = golden();
	for (pattern, offset, replacement, error) in [
		(
			&[0x48, 15, 0, 0, 0, 0, 0, 0, 0][..],
			1,
			14,
			DarwinCopyReceiptError::IdentityMismatch,
		),
		(
			&[0x48, 11, 0, 0, 0, 0, 0, 0, 0][..],
			1,
			0,
			DarwinCopyReceiptError::IdentityMismatch,
		),
		(
			&[0x85, 0x19, 0x01, 0x80][..],
			3,
			0xc0,
			DarwinCopyReceiptError::InvalidMetadata,
		),
		(
			&[0x82, 0x09, 0x58, 0x20, 0x46][..],
			1,
			0,
			DarwinCopyReceiptError::InvalidDurabilityFrame,
		),
	] {
		let mut altered = bytes.clone();
		let index = altered
			.windows(pattern.len())
			.position(|view| view == pattern)
			.unwrap();
		altered[index + offset] = replacement;
		assert_eq!(DarwinCopyReceipt::decode(&altered), Err(error));
	}

	let mut invalid_component = bytes;
	let name = invalid_component
		.windows(TARGET.len())
		.position(|view| view == TARGET)
		.unwrap();
	invalid_component[name] = b'/';
	assert!(matches!(
		DarwinCopyReceipt::decode(&invalid_component),
		Err(DarwinCopyReceiptError::InvalidTarget(_))
	));
}

#[test]
fn maximum_native_values_name_and_extent_fit_the_fixed_buffer() {
	let name = [b'p'; MAX_UNIX_COMPONENT_BYTES];
	let extreme = |inode| {
		native(
			i32::MIN,
			[u32::MAX, u32::MAX - 1],
			inode,
			Some(NonZeroU32::MAX),
			i64::MIN,
			999_999_999,
		)
	};
	let mut fields = receipt_fixture().evidence();
	fields.context.epoch = JournalEpoch::new(u64::MAX);
	fields.source = extreme(u64::MAX - 3);
	fields.destination.component = UnixComponent::new(&name).unwrap();
	fields.destination.root_identity = extreme(u64::MAX - 2);
	fields.stream.identity = extreme(u64::MAX - 1);
	fields.stream.length = StreamLength::new(MAX_FILE_LENGTH).unwrap();
	fields.stage_directory = extreme(u64::MAX);
	let latest = OwnerTimestamp::new(i64::MAX, 999_999_999).unwrap();
	let earliest = OwnerTimestamp::new(i64::MIN, 999_999_999).unwrap();
	fields.metadata = DarwinRequiredMetadata::new(
		0o600,
		NonZeroU32::new(2_147_483_647).unwrap(),
		2_147_483_647,
		earliest,
		latest,
	)
	.unwrap();
	let receipt =
		DarwinCopyReceipt::from_evidence(fields, ChainHead::after(u64::MAX, [6; 32]).unwrap())
			.unwrap();
	let bytes = receipt.encode();
	assert_eq!(bytes.len(), MAX_DARWIN_COPY_RECEIPT_BYTES);
	assert_eq!(DarwinCopyReceipt::decode(&bytes).unwrap(), receipt);
}
