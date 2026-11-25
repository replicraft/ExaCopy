//! Regression vectors for the canonical local publication intent payload.

use exacopy_endpoint::{MAX_UNIX_COMPONENT_BYTES, NameError, UnixComponent};
use exacopy_journal::{
	IntentError, JournalEntryId, JournalEpoch, JournalJobId, LinuxFileIdentity, PlanDigest,
	PublicationPrimitive, PublishIntent, PublishIntentContext, PublishIntentTarget,
	VerificationDigest,
};

use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader, FrameWriter};

// Produced by a separate Python encoder that builds RFC 8949 CBOR from numeric-keyed maps.
const GOLDEN: &[u8] = b"\xa8\x00\xa3\x00\x01\x01\x00\x02\x00\x01\x50\x01\x82\x79\x74\x55\
\x90\x7a\x14\x88\x88\x9c\x84\x07\xc7\x18\xca\x02\x1a\x00\x01\x00\
\x00\x03\x50\x11\x22\x33\x44\x55\x66\x47\x77\x88\x99\xaa\xbb\xcc\
\xdd\xee\xff\x04\x18\x18\x05\x58\x20\x00\x01\x02\x03\x04\x05\x06\
\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\
\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x06\x00\x0a\xa5\x00\xa4\x00\
\x01\x01\x48\x08\x07\x06\x05\x04\x03\x02\x01\x02\x48\x18\x17\x16\
\x15\x14\x13\x12\x11\x03\xf6\x01\xa4\x00\x01\x01\x48\x08\x07\x06\
\x05\x04\x03\x02\x01\x02\x48\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\x03\
\xf6\x02\xa2\x00\x01\x01\x48\x72\x65\x70\x6f\x72\x74\xff\x5c\x03\
\x58\x20\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\
\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\
\x3e\x3f\x04\x01";

const STAGE_PLATFORM: usize = 96;
const STAGE_GENERATION: usize = 118;
const COMPONENT_ENCODING: usize = 148;
const COMPONENT_LENGTH: usize = 150;
const PRIMITIVE: usize = 195;

#[test]
fn matches_the_independent_kind_7_golden_vector() {
	let intent = fixture(b"report\xff\\");
	assert_eq!(intent.encode(), GOLDEN);
	let decoded = PublishIntent::decode(GOLDEN).expect("the golden is canonical CBOR");
	assert_eq!(decoded, intent);
	assert_eq!(decoded.target.component.as_bytes(), b"report\xff\\");
	assert_eq!(decoded.encode(), GOLDEN);
}

#[test]
fn requires_the_publish_intent_frame_discriminator() {
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	writer
		.append(FrameKind::PublishObserved, GOLDEN)
		.expect("append a different record kind with the same payload");
	writer
		.append(FrameKind::PublishIntent, GOLDEN)
		.expect("append encoded publication intent");
	let bytes = writer.into_inner();
	let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());

	let observed = reader
		.next_frame()
		.expect("the observed frame is structurally valid")
		.expect("observed frame is present");
	assert_eq!(
		PublishIntent::from_frame(&observed),
		Err(IntentError::WrongRecordKind)
	);

	let intent = reader
		.next_frame()
		.expect("the intent frame is structurally valid")
		.expect("intent frame is present");
	assert_eq!(
		PublishIntent::from_frame(&intent),
		Ok(fixture(b"report\xff\\"))
	);
}

#[test]
fn accepts_maximal_local_component_and_u64_values() {
	let component = [b'\xff'; MAX_UNIX_COMPONENT_BYTES];
	let mut intent = fixture(&component);
	intent.context.epoch = JournalEpoch::new(u64::MAX);
	intent.context.effect_sequence = u64::MAX;
	intent.target.stage = LinuxFileIdentity::new(u64::MAX, u64::MAX);

	let encoded = intent.encode();
	assert_eq!(encoded.len(), 455);
	assert_eq!(PublishIntent::decode(&encoded), Ok(intent));
}

#[test]
fn rejects_every_truncated_golden_prefix() {
	for end in 0..GOLDEN.len() {
		assert_eq!(
			PublishIntent::decode(&GOLDEN[..end]),
			Err(IntentError::Truncated),
			"prefix ending at byte {end}"
		);
	}
}

#[test]
fn rejects_noncanonical_payload_corpus() {
	let cases: &[(_, _, _, &[u8])] = &[
		(
			"nonminimal map length",
			IntentError::NonCanonical,
			0..1,
			&[0xb8, 8],
		),
		("indefinite map", IntentError::InvalidCbor, 0..1, &[0xbf]),
		(
			"nonminimal map key",
			IntentError::NonCanonical,
			1..2,
			&[0x18, 0],
		),
		(
			"nonminimal epoch",
			IntentError::NonCanonical,
			28..33,
			&[0x1b, 0, 0, 0, 0, 0, 1, 0, 0],
		),
		(
			"nonminimal byte string length",
			IntentError::NonCanonical,
			COMPONENT_LENGTH..COMPONENT_LENGTH + 1,
			&[0x58, 8],
		),
		(
			"indefinite byte string",
			IntentError::InvalidCbor,
			COMPONENT_LENGTH..COMPONENT_LENGTH + 1,
			&[0x5f],
		),
		(
			"text component",
			IntentError::InvalidCbor,
			COMPONENT_LENGTH..COMPONENT_LENGTH + 1,
			&[0x68],
		),
		(
			"array instead of version map",
			IntentError::InvalidCbor,
			2..3,
			&[0x83],
		),
		(
			"floating-point field",
			IntentError::InvalidCbor,
			28..29,
			&[0xfa],
		),
		(
			"wrong map length",
			IntentError::UnexpectedMap,
			0..1,
			&[0xa7],
		),
		(
			"duplicate epoch key",
			IntentError::UnexpectedKey {
				expected: 3,
				actual: 2,
			},
			33..34,
			&[2],
		),
		(
			"out-of-order context key",
			IntentError::UnexpectedKey {
				expected: 2,
				actual: 3,
			},
			27..28,
			&[3],
		),
		(
			"unknown mandatory key",
			IntentError::UnexpectedKey {
				expected: 6,
				actual: 7,
			},
			89..90,
			&[7],
		),
		(
			"undeclared extension key",
			IntentError::UnexpectedKey {
				expected: 10,
				actual: 128,
			},
			91..92,
			&[0x18, 128],
		),
		(
			"trailing item",
			IntentError::TrailingBytes,
			GOLDEN.len()..GOLDEN.len(),
			&[1],
		),
	];
	for (description, error, range, replacement) in cases {
		let mut payload = GOLDEN.to_vec();
		payload.splice(range.clone(), replacement.iter().copied());
		assert_eq!(
			PublishIntent::decode(&payload),
			Err(*error),
			"{description}"
		);
	}
}

#[test]
fn rejects_unsupported_context_and_profile() {
	for (offset, octet, error) in [
		(4, 2, IntentError::UnsupportedVersion),
		(6, 1, IntentError::UnsupportedVersion),
		(8, 1, IntentError::UnsupportedFeatures),
		(90, 1, IntentError::UnsupportedFeatures),
		(STAGE_PLATFORM, 2, IntentError::UnsupportedPlatform),
		(STAGE_GENERATION, 0x40, IntentError::UnsupportedGeneration),
		(
			COMPONENT_ENCODING,
			2,
			IntentError::UnsupportedComponentEncoding,
		),
		(PRIMITIVE, 2, IntentError::UnsupportedPrimitive),
	] {
		let mut payload = GOLDEN.to_vec();
		payload[offset] = octet;
		assert_eq!(PublishIntent::decode(&payload), Err(error), "byte {offset}");
	}

	for (index, octet) in [(17, 0x4a), (19, 0x48)] {
		let mut payload = GOLDEN.to_vec();
		payload[index] = octet;
		assert!(matches!(
			PublishIntent::decode(&payload),
			Err(IntentError::InvalidJob(_))
		));
	}
}

#[test]
fn validates_the_raw_unix_name_before_returning_the_payload() {
	for (name, error) in [
		(b"".as_slice(), NameError::Empty),
		(b".", NameError::Reserved),
		(b"..", NameError::Reserved),
		(b"/absolute", NameError::Separator),
		(b"a/b", NameError::Separator),
		(b"a\0b", NameError::Nul),
	] {
		let mut payload = GOLDEN.to_vec();
		payload.splice(
			COMPONENT_LENGTH..COMPONENT_LENGTH + 9,
			[0x40 + name.len() as u8]
				.into_iter()
				.chain(name.iter().copied()),
		);
		assert_eq!(
			PublishIntent::decode(&payload),
			Err(IntentError::InvalidComponent(error)),
			"component {name:?}"
		);
	}
}

#[test]
fn refuses_excessive_length_and_invalid_fixed_widths() {
	let mut oversized_name = GOLDEN.to_vec();
	oversized_name.splice(
		COMPONENT_LENGTH..COMPONENT_LENGTH + 9,
		[0x59, 1, 0].into_iter().chain([b'a'; 256]),
	);
	assert_eq!(
		PublishIntent::decode(&oversized_name),
		Err(IntentError::Length)
	);

	for offset in [56, 98, 108, 124, 134, 161] {
		let mut payload = GOLDEN.to_vec();
		payload[offset] -= 1;
		assert_eq!(
			PublishIntent::decode(&payload),
			Err(IntentError::Length),
			"byte {offset}"
		);
	}

	let mut oversized_payload = GOLDEN.to_vec();
	oversized_payload.resize(456, 0);
	assert_eq!(
		PublishIntent::decode(&oversized_payload),
		Err(IntentError::Length)
	);

	for offset in [10, 34, COMPONENT_LENGTH] {
		let mut overflow = GOLDEN.to_vec();
		overflow.splice(offset..offset + 1, [0x5b].into_iter().chain([0xff; 8]));
		assert!(PublishIntent::decode(&overflow).is_err(), "byte {offset}");
	}
}

fn fixture(component: &[u8]) -> PublishIntent<'_> {
	let device = 0x0102_0304_0506_0708;
	PublishIntent {
		context: PublishIntentContext {
			job: JournalJobId::from_bytes([
				0x01, 0x82, 0x79, 0x74, 0x55, 0x90, 0x7a, 0x14, 0x88, 0x88, 0x9c, 0x84, 0x07, 0xc7,
				0x18, 0xca,
			])
			.expect("fixture uses an RFC UUIDv7"),
			epoch: JournalEpoch::new(65_536),
			entry: JournalEntryId::from_bytes([
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
				0xee, 0xff,
			]),
			effect_sequence: 24,
			plan_digest: PlanDigest::from_bytes(std::array::from_fn(|index| index as u8)),
		},
		target: PublishIntentTarget {
			stage: LinuxFileIdentity::new(device, 0x1112_1314_1516_1718),
			parent: LinuxFileIdentity::new(device, 0xf1f2_f3f4_f5f6_f7f8),
			component: UnixComponent::new(component).expect("fixture uses a valid Unix component"),
			verification_digest: VerificationDigest::from_bytes(std::array::from_fn(|index| {
				32 + index as u8
			})),
			primitive: PublicationPrimitive::LinuxRenameNoReplace,
		},
	}
}
