use super::*;
use exacopy_endpoint::MAX_FILE_LENGTH;

// Independently enumerated v1 body with a raw non-UTF-8 name.
const GOLDEN: &str = concat!(
	"ab00830100000150019a000000007000800000000000000102020350019a0000000070008000000000000004",
	"045820111111111111111111111111111111111111111111111111111111111111111105820102",
	"068250019a0000000070008000000000000003820304074266ff088382030503",
	"58206437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85098209",
	"582022222222222222222222222222222222222222222222222222222222222222220a01",
);

fn fixture(target: &[u8]) -> ReceiptEvidence<'_> {
	let id = |tail| {
		[
			0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, tail,
		]
	};
	ReceiptEvidence {
		context: JournalContext {
			job: JournalJobId::from_bytes(id(1)).unwrap(),
			epoch: JournalEpoch::new(2),
			plan_digest: PlanDigest::from_bytes([0x11; 32]),
		},
		entry: JournalEntryId::from_bytes(id(4)),
		source: LinuxFileIdentity::new(1, 2),
		destination: DestinationRootBinding {
			id: RootCapabilityId::from_bytes(id(3)).unwrap(),
			identity: LinuxFileIdentity::new(3, 4),
		},
		target: UnixComponent::new(target).unwrap(),
		stream: StreamEvidence {
			identity: LinuxFileIdentity::new(3, 5),
			length: StreamLength::new(3).unwrap(),
			digest: StreamDigest::from_bytes(*blake3::hash(b"abc").as_bytes()),
		},
	}
}

fn from_hex(hex: &str) -> Vec<u8> {
	let (pairs, tail) = hex.as_bytes().as_chunks::<2>();
	assert!(tail.is_empty(), "hex fixture has an incomplete byte");
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn sample() -> CopyReceipt<'static> {
	CopyReceipt::from_evidence(fixture(b"f\xff"), ChainHead::after(9, [0x22; 32]).unwrap()).unwrap()
}

#[test]
fn canonical_bytes_bind_the_entire_receipt() {
	let receipt = sample();
	let golden = from_hex(GOLDEN);
	assert_eq!(receipt.encode(), golden);
	let decoded = CopyReceipt::decode(&golden).unwrap();
	assert_eq!(decoded, receipt);

	let mut digest_input = b"ExaCopy/linux-copy-receipt/v1\0".to_vec();
	digest_input.extend_from_slice(&golden);
	assert_eq!(decoded.digest(), *blake3::hash(&digest_input).as_bytes());
	assert_ne!(decoded.digest(), *blake3::hash(&golden).as_bytes());

	let changed_frame =
		CopyReceipt::from_evidence(receipt.evidence(), ChainHead::after(9, [0x23; 32]).unwrap())
			.unwrap();
	assert_ne!(decoded.digest(), changed_frame.digest());
}

#[test]
fn largest_supported_fields_fit_the_artifact_limit() {
	let name = [0xff; MAX_UNIX_COMPONENT_BYTES];
	let mut evidence = fixture(&name);
	evidence.context.epoch = JournalEpoch::new(u64::MAX);
	evidence.source = LinuxFileIdentity::new(u64::MAX - 1, u64::MAX);
	evidence.destination.identity = LinuxFileIdentity::new(u64::MAX, u64::MAX);
	evidence.stream.identity = LinuxFileIdentity::new(u64::MAX, u64::MAX - 1);
	evidence.stream.length = StreamLength::new(MAX_FILE_LENGTH).unwrap();
	let head = ChainHead::after(u64::MAX, [1; 32]).unwrap();
	let receipt = CopyReceipt::from_evidence(evidence, head).unwrap();
	let encoded = receipt.encode();
	assert_eq!(encoded.len(), MAX_COPY_RECEIPT_BYTES);
	assert_eq!(CopyReceipt::decode(&encoded), Ok(receipt));
}

#[test]
fn every_truncation_of_a_receipt_is_rejected() {
	let golden = from_hex(GOLDEN);
	for end in 0..golden.len() {
		assert!(
			CopyReceipt::decode(&golden[..end]).is_err(),
			"prefix length {end}"
		);
	}
}

#[test]
fn rejects_oversized_noncanonical_and_incompatible_artifacts() {
	let too_large = [0; MAX_COPY_RECEIPT_BYTES + 1];
	assert_eq!(CopyReceipt::decode(&too_large), Err(ReceiptError::TooLarge));

	let golden = from_hex(GOLDEN);
	let mut trailing = golden.clone();
	trailing.push(0);
	assert_eq!(
		CopyReceipt::decode(&trailing),
		Err(ReceiptError::NonCanonical)
	);

	let mut nonminimal = golden.clone();
	nonminimal.splice(1..2, [0x18, 0x00]);
	assert_eq!(
		CopyReceipt::decode(&nonminimal),
		Err(ReceiptError::NonCanonical)
	);

	let mut major = golden.clone();
	major[3] = 2;
	assert_eq!(
		CopyReceipt::decode(&major),
		Err(ReceiptError::UnsupportedVersion)
	);

	let mut required_feature = golden.clone();
	required_feature[5] = 1;
	assert_eq!(
		CopyReceipt::decode(&required_feature),
		Err(ReceiptError::UnsupportedVersion)
	);

	let mut profile = golden.clone();
	*profile.last_mut().unwrap() = 0;
	assert_eq!(
		CopyReceipt::decode(&profile),
		Err(ReceiptError::UnsupportedProfile)
	);

	let mut duplicate = golden;
	duplicate[1] = 1;
	assert_eq!(
		CopyReceipt::decode(&duplicate),
		Err(ReceiptError::InvalidCbor)
	);
}

#[test]
fn rejects_bindings_that_cannot_describe_exclusive_publication() {
	let receipt = sample();
	let mut configured = receipt.evidence();
	configured.source = configured.stream.identity;
	assert_eq!(
		CopyReceipt::from_evidence(configured, receipt.durability_frame()),
		Err(ReceiptError::IdentityMismatch)
	);

	configured.source = receipt.evidence().source;
	configured.destination.identity = configured.stream.identity;
	assert_eq!(
		CopyReceipt::from_evidence(configured, receipt.durability_frame()),
		Err(ReceiptError::IdentityMismatch)
	);

	configured.destination.identity = LinuxFileIdentity::new(4, 7);
	assert_eq!(
		CopyReceipt::from_evidence(configured, receipt.durability_frame()),
		Err(ReceiptError::IdentityMismatch)
	);
}

#[test]
fn rejects_path_components_and_invalid_durability_anchors() {
	let golden = from_hex(GOLDEN);
	let target = golden
		.windows(3)
		.position(|item| item == [0x42, b'f', 0xff])
		.unwrap();
	let mut wrong_path = golden.clone();
	wrong_path[target + 1] = b'/';
	assert_eq!(
		CopyReceipt::decode(&wrong_path),
		Err(ReceiptError::InvalidTarget(NameError::Separator))
	);

	let mut no_digest = golden.clone();
	let digest_end = golden.len() - 2;
	no_digest[digest_end - 32..digest_end].fill(0);
	assert_eq!(
		CopyReceipt::decode(&no_digest),
		Err(ReceiptError::InvalidDurabilityFrame)
	);

	let mut sequence_zero = golden;
	sequence_zero[digest_end - 35] = 0;
	assert_eq!(
		CopyReceipt::decode(&sequence_zero),
		Err(ReceiptError::InvalidDurabilityFrame)
	);
}
