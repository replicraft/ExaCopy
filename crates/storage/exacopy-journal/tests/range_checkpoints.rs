//! Wire and admission checks for an immutable range page and its kind-3 record.

use exacopy_endpoint::MAX_FILE_LENGTH;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	EntryPrepared, MAX_CHECKPOINT_RANGE_BYTES, MAX_RANGE_CHECKPOINTS, MAX_RANGE_PAGE_BYTES,
	PreparedError, RangeCheckpoint, RangePage, SourceMeasurementId, StreamDigest,
	VerificationRecordError,
};

const PAGE: &[u8] = include_bytes!("../fuzz/corpus/journal_frame/range-page");
const CHECKPOINT: &[u8] = include_bytes!("../fuzz/corpus/journal_frame/range-checkpoint");
const SOURCE_DIGEST: [u8; 32] =
	*b"\x53\x9e\x00\xdb\x4e\xb6\x98\xe9\xca\x4a\xc7\x92\x71\x7f\x0a\x36\
\x16\xab\x03\xb1\x96\x77\xe2\x4c\x82\x41\x2c\xde\x0d\xea\xf9\xa9";
const PAGE_DIGEST: [u8; 32] = *b"\xce\xff\xf8\x0a\x38\xc0\xfe\x3a\xa8\x72\xa6\x10\x0c\xc5\x3a\xac\
\x82\x47\xc4\xe7\x20\x32\xd3\x50\x53\x3a\x24\x23\x38\xe1\x75\xee";

// This is the RFC 8949 entry-preparation vector from prepared.rs.
const ENTRY: &[u8] = b"\xa7\x00\xa3\x00\x01\x01\x00\x02\x00\x01\x50\x01\x82\x79\x74\x55\
\x90\x7a\x14\x88\x88\x9c\x84\x07\xc7\x18\xca\x02\x18\x18\x03\x50\
\xaa\xbb\xcc\xdd\xee\xff\x47\x77\x99\x88\x77\x66\x55\x44\x33\x22\
\x05\x58\x20\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\
\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\
\x1d\x1e\x1f\x06\x00\x0a\xa4\x00\xa6\x00\x00\x01\xa4\x00\x01\x01\
\x48\x08\x07\x06\x05\x04\x03\x02\x01\x02\x48\x18\x17\x16\x15\x14\
\x13\x12\x11\x03\xf6\x02\x1a\x00\x01\x00\x00\x03\x82\x21\x19\x01\
\x90\x04\x82\x19\x02\xbc\x00\x05\x82\x19\x02\xbc\x19\x01\xf4\x01\
\xa4\x00\x01\x01\x48\x08\x07\x06\x05\x04\x03\x02\x01\x02\x48\xf8\
\xf7\xf6\xf5\xf4\xf3\xf2\xf1\x03\xf6\x02\xa2\x00\x50\x11\x22\x33\
\x44\x55\x66\x47\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x01\x81\xa2\
\x00\x01\x01\x48\x72\x65\x70\x6f\x72\x74\xff\x5c\x03\xa2\x00\xa5\
\x00\x19\x01\xa0\x01\x19\x04\xd2\x02\x19\x10\xe1\x03\x01\x04\x00\
\x01\x00";

fn digest() -> StreamDigest {
	StreamDigest::from_bytes(core::array::from_fn(|index| {
		u8::try_from(index).expect("digest is 32 bytes")
	}))
}

fn source() -> SourceMeasurementId {
	SourceMeasurementId::from_prepared_payload(ENTRY)
}

fn framed(kind: FrameKind, payload: &[u8]) -> Frame {
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	writer.append(kind, payload).expect("bounded frame");
	let bytes = writer.into_inner();
	FrameReader::new(bytes.as_slice(), ChainHead::start())
		.next_frame()
		.expect("intact frame")
		.expect("frame present")
}

fn replacing(input: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
	let positions: Vec<_> = input
		.windows(old.len())
		.enumerate()
		.filter_map(|(index, bytes)| (bytes == old).then_some(index))
		.collect();
	let [index] = positions.as_slice() else {
		panic!("mutation must identify one field");
	};
	[&input[..*index], new, &input[*index + old.len()..]].concat()
}

#[test]
fn range_page_and_checkpoint_match_independent_cbor_and_digest_vectors() {
	let prepared = EntryPrepared::decode(ENTRY).expect("canonical prepared fixture");
	let source = source();
	assert_eq!(source.as_bytes(), &SOURCE_DIGEST);
	assert_ne!(
		source,
		SourceMeasurementId::from_prepared_payload(&ENTRY[1..])
	);

	let page = RangePage::new(24, 1025, 1024, digest(), source).expect("valid range");
	assert_eq!(page.encode(), PAGE);
	assert_eq!(RangePage::decode(PAGE), Ok(page));
	assert_eq!(page.ordinal(), 24);
	assert_eq!(page.offset(), 1025);
	assert_eq!(page.length(), 1024);
	assert_eq!(page.digest(), digest());
	assert_eq!(page.source(), source);

	let reference = page.reference();
	assert_eq!(reference.digest(), &PAGE_DIGEST);
	assert_eq!(reference.byte_length(), PAGE.len());
	assert_eq!(reference.ordinal(), page.ordinal());

	let checkpoint = RangeCheckpoint {
		context: prepared.context,
		entry: prepared.entry,
		page: reference,
		source,
	};
	assert_eq!(checkpoint.encode(), CHECKPOINT);
	assert_eq!(
		RangeCheckpoint::from_frame(&framed(FrameKind::RangeCheckpoint, CHECKPOINT)),
		Ok(checkpoint)
	);
	assert_eq!(
		RangeCheckpoint::from_frame(&framed(FrameKind::EntryPrepared, CHECKPOINT)),
		Err(VerificationRecordError::WrongRecordKind {
			expected: FrameKind::RangeCheckpoint,
			actual: FrameKind::EntryPrepared,
		})
	);
}

#[test]
fn page_reference_changes_if_any_range_evidence_changes() {
	let source = source();
	let expected = RangePage::decode(PAGE).expect("canonical page").reference();
	let changed = [
		RangePage::new(25, 1025, 1024, digest(), source),
		RangePage::new(24, 1026, 1024, digest(), source),
		RangePage::new(24, 1025, 1023, digest(), source),
		RangePage::new(24, 1025, 1024, StreamDigest::from_bytes([0x7f; 32]), source),
		RangePage::new(
			24,
			1025,
			1024,
			digest(),
			SourceMeasurementId::from_prepared_payload(&ENTRY[..ENTRY.len() - 1]),
		),
	];
	for variant in changed {
		let reference = variant.expect("variant remains bounded").reference();
		assert_eq!(reference.byte_length(), expected.byte_length());
		assert_ne!(reference.digest(), expected.digest());
	}
}

#[test]
fn page_range_and_ordinal_bounds_admit_the_exact_end_and_reject_overflow() {
	let maximum = RangePage::new(
		MAX_RANGE_CHECKPOINTS,
		MAX_FILE_LENGTH - MAX_CHECKPOINT_RANGE_BYTES,
		MAX_CHECKPOINT_RANGE_BYTES,
		digest(),
		source(),
	)
	.expect("maximum supported range fields");
	let minimum = RangePage::new(1, 0, 1, digest(), source()).expect("minimum range fields");
	assert_eq!(maximum.encode().len(), MAX_RANGE_PAGE_BYTES);
	for page in [minimum, maximum] {
		assert_eq!(RangePage::decode(&page.encode()), Ok(page));
		let fixture = RangeCheckpoint::decode(CHECKPOINT).expect("canonical checkpoint");
		let checkpoint = RangeCheckpoint {
			page: page.reference(),
			..fixture
		};
		assert_eq!(
			RangeCheckpoint::decode(&checkpoint.encode()),
			Ok(checkpoint)
		);
	}

	for ordinal in [0, MAX_RANGE_CHECKPOINTS + 1, u32::MAX] {
		assert_eq!(
			RangePage::new(ordinal, 0, 1, digest(), source()),
			Err(VerificationRecordError::InvalidRangeOrdinal)
		);
	}
	for (offset, length) in [
		(0, 0),
		(0, MAX_CHECKPOINT_RANGE_BYTES + 1),
		(MAX_FILE_LENGTH, 1),
		(MAX_FILE_LENGTH + 1, 1),
		(u64::MAX, 2),
	] {
		assert_eq!(
			RangePage::new(1, offset, length, digest(), source()),
			Err(VerificationRecordError::InvalidCheckpointRange)
		);
	}
}

#[test]
fn decoders_refuse_truncation_noncanonical_maps_duplicate_keys_and_extra_bytes() {
	type Decode = fn(&[u8]) -> Result<(), VerificationRecordError>;
	let cases: [(&[u8], Decode); 2] = [
		(PAGE, |bytes| RangePage::decode(bytes).map(|_| ())),
		(CHECKPOINT, |bytes| {
			RangeCheckpoint::decode(bytes).map(|_| ())
		}),
	];
	for (bytes, decode) in cases {
		for cut in 0..bytes.len() {
			assert_eq!(
				decode(&bytes[..cut]),
				Err(VerificationRecordError::Truncated),
				"prefix {cut}"
			);
		}
		assert_eq!(
			decode(&[bytes, b"\xf6"].concat()),
			Err(VerificationRecordError::TrailingBytes)
		);
		assert_eq!(
			decode(&[b"\xb8\x07", &bytes[1..]].concat()),
			Err(VerificationRecordError::NonCanonical)
		);
		assert_eq!(
			decode(&[b"\xbf", &bytes[1..]].concat()),
			Err(VerificationRecordError::InvalidCbor)
		);
	}
	assert_eq!(
		RangePage::decode(&replacing(
			PAGE,
			b"\x01\x18\x18\x02",
			b"\x01\x19\x00\x18\x02"
		)),
		Err(VerificationRecordError::NonCanonical)
	);
	assert_eq!(
		RangePage::decode(&replacing(PAGE, b"\x01\x18\x18\x02", b"\x01\x18\x18\x01")),
		Err(VerificationRecordError::InvalidCbor)
	);
	assert_eq!(
		RangeCheckpoint::decode(&replacing(
			CHECKPOINT,
			b"\x01\x18\x56\x02\x18\x18",
			b"\x01\x18\x56\x01\x18\x18"
		)),
		Err(VerificationRecordError::InvalidCbor)
	);
}

#[test]
fn page_decoder_refuses_unsupported_values_and_digest_widths() {
	use VerificationRecordError::{
		InvalidCbor, InvalidCheckpointRange, InvalidRangeOrdinal, UnsupportedEvidence,
	};
	let variants: [(&[u8], &[u8], VerificationRecordError); 7] = [
		(b"\xa7\x00\x01", b"\xa7\x00\x02", UnsupportedEvidence),
		(b"\x02\x00\x03", b"\x02\x01\x03", UnsupportedEvidence),
		(b"\x01\x18\x18\x02", b"\x01\x00\x02", InvalidRangeOrdinal),
		(
			b"\x01\x18\x18\x02",
			b"\x01\x19\x10\x01\x02",
			InvalidRangeOrdinal,
		),
		(
			b"\x04\x19\x04\x00\x05",
			b"\x04\x00\x05",
			InvalidCheckpointRange,
		),
		(
			b"\x04\x19\x04\x00\x05",
			b"\x04\x1a\x04\x00\x00\x01\x05",
			InvalidCheckpointRange,
		),
		(b"\x05\x58\x20", b"\x05\x58\x1f", InvalidCbor),
	];
	for (old, new, error) in variants {
		assert_eq!(RangePage::decode(&replacing(PAGE, old, new)), Err(error));
	}
	assert_eq!(
		RangePage::decode(&[0; MAX_RANGE_PAGE_BYTES + 1]),
		Err(VerificationRecordError::PayloadTooLong)
	);
}

#[test]
fn checkpoint_decoder_refuses_invalid_reference_bounds_unknown_features_and_incomplete_barriers() {
	use VerificationRecordError::{
		InvalidCbor, InvalidRangeOrdinal, InvalidRangePageLength, NonCanonical, UnsupportedEvidence,
	};
	let variants: [(&[u8], &[u8], VerificationRecordError); 7] = [
		(b"\x01\x18\x56\x02", b"\x01\x00\x02", InvalidRangePageLength),
		(
			b"\x01\x18\x56\x02",
			b"\x01\x18\x60\x02",
			InvalidRangePageLength,
		),
		(b"\x01\x18\x56\x02", b"\x01\x19\x00\x56\x02", NonCanonical),
		(
			b"\x02\x18\x18\x01\x58",
			b"\x02\x00\x01\x58",
			InvalidRangeOrdinal,
		),
		(
			b"\x02\x18\x18\x01\x58",
			b"\x02\x19\x10\x01\x01\x58",
			InvalidRangeOrdinal,
		),
		(
			b"\xa3\x00\xa3\x00\x58\x20",
			b"\xa3\x00\xa3\x00\x58\x1f",
			InvalidCbor,
		),
		(
			b"\xf9\xa9\x02\x01",
			b"\xf9\xa9\x02\x00",
			UnsupportedEvidence,
		),
	];
	for (old, new, error) in variants {
		assert_eq!(
			RangeCheckpoint::decode(&replacing(CHECKPOINT, old, new)),
			Err(error)
		);
	}
	let mut unknown_features = CHECKPOINT.to_vec();
	unknown_features[8] = 1;
	assert_eq!(
		RangeCheckpoint::decode(&unknown_features),
		Err(VerificationRecordError::Common(
			PreparedError::UnsupportedFeatures
		))
	);
}
