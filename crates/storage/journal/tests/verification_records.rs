//! Local kind-4, kind-5 and kind-6 journal contract vectors.

use exacopy_endpoint::MAX_FILE_LENGTH;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	BasicMetadata, JournalContext, JournalEntryId, JournalEpoch, JournalJobId, LinuxFileIdentity,
	MetadataOmission, MetadataRecorded, OwnerTimestamp, PlanDigest, PreparedError, StageSealed,
	StreamDigest, StreamEvidence, StreamLength, VerificationRecordError, VerificationRecorded,
};

// Fixed vectors from an independent numeric-key RFC 8949 encoder.
const ENTRY_HEADER: &[u8] =
	b"\xa7\x00\xa3\x00\x01\x01\x00\x02\x00\x01\x50\x01\x82\x79\x74\x55\x90\x7a\
\x14\x88\x88\x9c\x84\x07\xc7\x18\xca\x02\x18\x18\x03\x50\x11\x22\x33\x44\
\x55\x66\x47\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x05\x58\x20\x55\x55\x55\
\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\
\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x06\x00\x0a";
const SEALED_BODY: &[u8] =
	b"\xa4\x00\x81\xa2\x00\xa4\x00\x01\x01\x48\x21\x00\x00\x00\x00\x00\x00\x00\
\x02\x48\x41\x00\x00\x00\x00\x00\x00\x00\x03\xf6\x01\x19\x04\x01\x01\x01\
\x02\x18\x18\x03\x01";
const VERIFIED_BODY: &[u8] =
	b"\xa4\x00\x01\x01\xa4\x00\x01\x01\x48\x21\x00\x00\x00\x00\x00\x00\x00\x02\
\x48\x40\x00\x00\x00\x00\x00\x00\x00\x03\xf6\x02\xa4\x00\x01\x01\x48\x21\
\x00\x00\x00\x00\x00\x00\x00\x02\x48\x41\x00\x00\x00\x00\x00\x00\x00\x03\
\xf6\x03\x82\xa2\x00\x19\x04\x01\x01\x58\x20\x00\x01\x02\x03\x04\x05\x06\
\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\
\x19\x1a\x1b\x1c\x1d\x1e\x1f\xa2\x00\x19\x04\x01\x01\x58\x20\x00\x01\x02\
\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\
\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
const METADATA_BODY: &[u8] =
	b"\xa4\x00\x01\x01\xa6\x00\xa4\x00\x01\x01\x48\x21\x00\x00\x00\x00\x00\x00\
\x00\x02\x48\x41\x00\x00\x00\x00\x00\x00\x00\x03\xf6\x01\x19\x01\xa0\x02\
\x19\x03\xe8\x03\x19\x03\xe9\x04\xa2\x00\x20\x01\x1a\x3b\x9a\xc9\xff\x05\
\xa2\x00\x1a\x65\x53\xf1\x00\x01\x18\x7b\x02\x84\x01\x02\x03\x04\x03\x01";
const EPOCH: u64 = 24;
const EXTENT: u64 = 1_025;
const SOURCE: LinuxFileIdentity = LinuxFileIdentity::new(33, 64);
const STAGE: LinuxFileIdentity = LinuxFileIdentity::new(33, 65);
const ENTRY: JournalEntryId = JournalEntryId::from_bytes([
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
]);

fn context() -> JournalContext {
	JournalContext {
		job: JournalJobId::from_bytes([
			0x01, 0x82, 0x79, 0x74, 0x55, 0x90, 0x7a, 0x14, 0x88, 0x88, 0x9c, 0x84, 0x07, 0xc7,
			0x18, 0xca,
		])
		.expect("fixture is an RFC UUIDv7"),
		epoch: JournalEpoch::new(EPOCH),
		plan_digest: PlanDigest::from_bytes([0x55; 32]),
	}
}

fn stream(identity: LinuxFileIdentity) -> StreamEvidence {
	StreamEvidence {
		identity,
		length: StreamLength::new(EXTENT).expect("fixture extent is supported"),
		digest: StreamDigest::from_bytes(core::array::from_fn(|index| {
			u8::try_from(index).expect("digest is 32 bytes")
		})),
	}
}

fn metadata() -> BasicMetadata {
	BasicMetadata::new(
		0o640,
		1000,
		1001,
		OwnerTimestamp::new(-1, 999_999_999).expect("valid access time"),
		OwnerTimestamp::new(1_700_000_000, 123).expect("valid modification time"),
	)
	.expect("ordinary metadata values")
}

fn golden(body: &[u8]) -> Vec<u8> {
	[ENTRY_HEADER, body].concat()
}

fn replacing(input: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
	let matches: Vec<_> = input
		.windows(old.len())
		.enumerate()
		.filter(|(_, bytes)| *bytes == old)
		.collect();
	let [(offset, _)] = matches.as_slice() else {
		panic!("mutation must identify one offset")
	};
	[&input[..*offset], new, &input[*offset + old.len()..]].concat()
}

fn framed(kind: FrameKind, payload: &[u8]) -> Frame {
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	writer
		.append(kind, payload)
		.expect("frame fixture is bounded");
	let bytes = writer.into_inner();
	FrameReader::new(bytes.as_slice(), ChainHead::start())
		.next_frame()
		.expect("frame is intact")
		.expect("frame is present")
}

#[test]
fn stage_sealed_matches_the_canonical_record_and_binds_the_epoch() {
	let expected = StageSealed {
		context: context(),
		entry: ENTRY,
		stage: STAGE,
		length: stream(STAGE).length,
	};
	let bytes = golden(SEALED_BODY);
	assert_eq!(expected.encode(), bytes);
	assert_eq!(
		StageSealed::from_frame(&framed(FrameKind::StageSealed, &bytes)),
		Ok(expected)
	);
	let wrong_epoch = replacing(&bytes, b"\x02\x18\x18\x03\x01", b"\x02\x18\x19\x03\x01");
	assert_eq!(
		StageSealed::decode(&wrong_epoch),
		Err(VerificationRecordError::EpochMismatch)
	);
}

#[test]
fn canonical_verification_digest_binds_the_complete_record() {
	let context = context();
	let source = stream(SOURCE);
	let stage = stream(STAGE);
	let record =
		VerificationRecorded::new(context, ENTRY, source, stage).expect("matching observations");
	let bytes = golden(VERIFIED_BODY);
	assert_eq!(record.encode(), bytes);
	let decoded =
		VerificationRecorded::from_frame(&framed(FrameKind::VerificationRecorded, &bytes))
			.expect("canonical verification payload");
	assert_eq!(decoded, record);
	assert_eq!(decoded.source(), source);
	assert_eq!(decoded.stage(), stage);
	let expected = blake3::hash(&[b"ExaCopy/journal-verification/v1\0", bytes.as_slice()].concat());
	assert_eq!(record.record_digest().as_bytes(), expected.as_bytes());
	let changed = [
		VerificationRecorded::new(
			JournalContext {
				epoch: JournalEpoch::new(EPOCH + 1),
				..context
			},
			ENTRY,
			source,
			stage,
		),
		VerificationRecorded::new(
			JournalContext {
				plan_digest: PlanDigest::from_bytes([0x42; 32]),
				..context
			},
			ENTRY,
			source,
			stage,
		),
		VerificationRecorded::new(
			context,
			JournalEntryId::from_bytes([0x76; 16]),
			source,
			stage,
		),
		VerificationRecorded::new(
			context,
			ENTRY,
			source,
			StreamEvidence {
				identity: LinuxFileIdentity::new(33, 66),
				..stage
			},
		),
	];
	for variant in changed {
		assert_ne!(
			variant
				.expect("changed record remains valid")
				.record_digest(),
			record.record_digest()
		);
	}
}

#[test]
fn verified_record_rejects_length_digest_and_identity_mismatches() {
	let context = context();
	let source = stream(SOURCE);
	let stage = stream(STAGE);
	let variants = [
		(
			StreamEvidence {
				length: StreamLength::new(EXTENT + 1).expect("supported extent"),
				..stage
			},
			VerificationRecordError::MismatchedStreams,
		),
		(
			StreamEvidence {
				digest: StreamDigest::from_bytes([0xff; 32]),
				..stage
			},
			VerificationRecordError::MismatchedStreams,
		),
		(source, VerificationRecordError::AliasedIdentity),
	];
	for (invalid, error) in variants {
		assert_eq!(
			VerificationRecorded::new(context, ENTRY, source, invalid),
			Err(error)
		);
	}
	let mut bytes = golden(VERIFIED_BODY);
	*bytes
		.last_mut()
		.expect("fixture ends with the stage digest") ^= 1;
	assert_eq!(
		VerificationRecorded::decode(&bytes),
		Err(VerificationRecordError::MismatchedStreams)
	);
	let alias = replacing(
		&golden(VERIFIED_BODY),
		b"\x02\x48\x41\x00\x00\x00\x00\x00\x00\x00",
		b"\x02\x48\x40\x00\x00\x00\x00\x00\x00\x00",
	);
	assert_eq!(
		VerificationRecorded::decode(&alias),
		Err(VerificationRecordError::AliasedIdentity)
	);
}

#[test]
fn metadata_matches_the_canonical_descriptor_and_reports_omissions() {
	let expected = MetadataRecorded {
		context: context(),
		entry: ENTRY,
		stage: STAGE,
		metadata: metadata(),
	};
	let bytes = golden(METADATA_BODY);
	assert_eq!(expected.encode(), bytes);
	let decoded = MetadataRecorded::from_frame(&framed(FrameKind::MetadataRecorded, &bytes))
		.expect("canonical metadata record");
	assert_eq!(decoded, expected);
	assert_eq!(
		decoded.omissions(),
		[
			MetadataOmission::HiddenExtendedAttributes,
			MetadataOmission::HardLinkTopology,
			MetadataOmission::SparseAllocation,
			MetadataOmission::InodeChangeTime,
		]
	);
	assert_eq!(decoded.metadata.accessed_at.seconds(), -1);
	assert_eq!(decoded.metadata.mode(), 0o640);
}

#[test]
fn all_decoders_reject_wrong_frames_truncation_trailing_and_nonminimal_encoding() {
	type InvalidDecoder = fn(&[u8]) -> Result<(), VerificationRecordError>;
	let cases: [(&[u8], InvalidDecoder); 3] = [
		(SEALED_BODY, |bytes| StageSealed::decode(bytes).map(|_| ())),
		(VERIFIED_BODY, |bytes| {
			VerificationRecorded::decode(bytes).map(|_| ())
		}),
		(METADATA_BODY, |bytes| {
			MetadataRecorded::decode(bytes).map(|_| ())
		}),
	];
	for (body, decode) in cases {
		let bytes = golden(body);
		for cut in 0..bytes.len() {
			assert_eq!(
				decode(&bytes[..cut]),
				Err(VerificationRecordError::Truncated),
				"prefix {cut}"
			);
		}
		assert_eq!(
			decode(&[bytes.as_slice(), b"\xf6"].concat()),
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
		assert_eq!(
			decode(&[0; 257]),
			Err(VerificationRecordError::PayloadTooLong)
		);
		let wrong = framed(FrameKind::PublishIntent, &bytes);
		assert_eq!(
			StageSealed::from_frame(&wrong),
			Err(VerificationRecordError::WrongRecordKind {
				expected: FrameKind::StageSealed,
				actual: FrameKind::PublishIntent
			})
		);
		assert_eq!(
			VerificationRecorded::from_frame(&wrong),
			Err(VerificationRecordError::WrongRecordKind {
				expected: FrameKind::VerificationRecorded,
				actual: FrameKind::PublishIntent
			})
		);
		assert_eq!(
			MetadataRecorded::from_frame(&wrong),
			Err(VerificationRecordError::WrongRecordKind {
				expected: FrameKind::MetadataRecorded,
				actual: FrameKind::PublishIntent
			})
		);
	}
}

#[test]
fn refuses_missing_barriers_and_unknown_evidence() {
	let bytes = golden(SEALED_BODY);
	let missing_flush = replacing(&bytes, b"\x02\x18\x18\x03\x01", b"\x02\x18\x18\x03\x00");
	assert_eq!(
		StageSealed::decode(&missing_flush),
		Err(VerificationRecordError::UnsupportedEvidence)
	);
	let missing_join = replacing(&bytes, b"\x01\x01\x02\x18\x18", b"\x01\x00\x02\x18\x18");
	assert_eq!(
		StageSealed::decode(&missing_join),
		Err(VerificationRecordError::UnsupportedEvidence)
	);
	let impossible_extent = replacing(
		&bytes,
		b"\x19\x04\x01",
		b"\x1b\x80\x00\x00\x00\x00\x00\x00\x00",
	);
	assert_eq!(
		StageSealed::decode(&impossible_extent),
		Err(VerificationRecordError::UnsupportedLength)
	);
	let mut feature_bits = bytes;
	feature_bits[8] = 1;
	assert_eq!(
		StageSealed::decode(&feature_bits),
		Err(VerificationRecordError::Common(
			PreparedError::UnsupportedFeatures
		))
	);
	let mut method = golden(VERIFIED_BODY);
	method[ENTRY_HEADER.len() + 2] = 0;
	assert_eq!(
		VerificationRecorded::decode(&method),
		Err(VerificationRecordError::UnsupportedEvidence)
	);
}

#[test]
fn metadata_refuses_privileged_modes_invalid_times_and_incorrect_omissions() {
	let bytes = golden(METADATA_BODY);
	let mode = replacing(&bytes, b"\x01\x19\x01\xa0\x02", b"\x01\x19\x09\xa0\x02");
	assert_eq!(
		MetadataRecorded::decode(&mode),
		Err(VerificationRecordError::UnsupportedMode)
	);
	let nanos = replacing(&bytes, b"\x1a\x3b\x9a\xc9\xff", b"\x1a\x3b\x9a\xca\x00");
	assert_eq!(
		MetadataRecorded::decode(&nanos),
		Err(VerificationRecordError::InvalidTimestamp)
	);
	let wide_negative = replacing(&bytes, b"\xa2\x00\x20\x01", b"\xa2\x00\x38\x00\x01");
	assert_eq!(
		MetadataRecorded::decode(&wide_negative),
		Err(VerificationRecordError::NonCanonical)
	);
	let uid = replacing(
		&bytes,
		b"\x02\x19\x03\xe8\x03",
		b"\x02\x1b\x00\x00\x00\x01\x00\x00\x00\x00\x03",
	);
	assert_eq!(
		MetadataRecorded::decode(&uid),
		Err(VerificationRecordError::InvalidPrincipal)
	);
	let omission = replacing(
		&bytes,
		b"\x02\x84\x01\x02\x03\x04",
		b"\x02\x84\x01\x02\x03\x01",
	);
	assert_eq!(
		MetadataRecorded::decode(&omission),
		Err(VerificationRecordError::UnsupportedEvidence)
	);
	let missing_flush = replacing(&bytes, b"\x04\x03\x01", b"\x04\x03\x00");
	assert_eq!(
		MetadataRecorded::decode(&missing_flush),
		Err(VerificationRecordError::UnsupportedEvidence)
	);
}

#[test]
fn largest_native_fields_fit_the_bounded_codec() {
	let context = JournalContext {
		epoch: JournalEpoch::new(u64::MAX),
		..context()
	};
	let stage = StreamEvidence {
		length: StreamLength::new(MAX_FILE_LENGTH).expect("maximum supported length"),
		..stream(STAGE)
	};
	let source = StreamEvidence {
		identity: SOURCE,
		..stage
	};
	let verified = VerificationRecorded::new(context, ENTRY, source, stage)
		.expect("matching supported extents");
	assert_eq!(verified.encode().len(), 242);
	assert_eq!(
		VerificationRecorded::decode(&verified.encode()),
		Ok(verified)
	);
	let metadata = BasicMetadata::new(
		0o777,
		u32::MAX,
		u32::MAX,
		OwnerTimestamp::new(i64::MIN, 0).expect("minimum timestamp"),
		OwnerTimestamp::new(i64::MAX, 999_999_999).expect("maximum timestamp"),
	)
	.expect("metadata fields are representable");
	let metadata = MetadataRecorded {
		context,
		entry: ENTRY,
		stage: STAGE,
		metadata,
	};
	assert_eq!(MetadataRecorded::decode(&metadata.encode()), Ok(metadata));
}
