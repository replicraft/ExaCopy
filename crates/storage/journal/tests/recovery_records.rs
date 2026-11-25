//! Independent CBOR vectors and cross-record binding tests for recovery evidence.

#[path = "recovery_records/bindings.rs"]
mod bindings;
#[path = "recovery_records/range_resume.rs"]
mod range_resume;
#[path = "recovery_records/retained.rs"]
mod retained;

use exacopy_endpoint::MAX_FILE_LENGTH;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	JournalContext, JournalEntryId, JournalEpoch, JournalJobId, LinuxFileIdentity, OwnerDigest,
	PlanDigest, PreparedError, PublishedRecoveryEvidence, RecoveryDecision, RecoveryRecordError,
	RecoveryStartEvidence, RecoveryStarted, StreamDigest, StreamEvidence, StreamLength,
};

const JOB: [u8; 16] = [
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x76, 0x07, 0x88, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const ENTRY: JournalEntryId = JournalEntryId::from_bytes([0x11; 16]);
const STAGE_DIR: LinuxFileIdentity = LinuxFileIdentity::new(5, 7);
const TARGET_DIR: LinuxFileIdentity = LinuxFileIdentity::new(5, 8);
const FILE: LinuxFileIdentity = LinuxFileIdentity::new(5, 9);
const OWNER: OwnerDigest = OwnerDigest::from_bytes([0x44; 32]);

const RECOVERY_HEADER: &str = concat!(
	"a700a3000101000200",
	"0150000102030405760788090a0b0c0d0e0f",
	"0203",
	"035011111111111111111111111111111111",
	"0558202222222222222222222222222222222222222222222222222222222222222222",
	"06000a",
);
const STARTED_BODY: &str = concat!(
	"a3000201a2",
	"00820758203333333333333333333333333333333333333333333333333333333333333333",
	"01820858205555555555555555555555555555555555555555555555555555555555555555",
	"0258204444444444444444444444444444444444444444444444444444444444444444",
);
const DECISION_BODY: &str = concat!(
	"a4000101a4",
	"00a40001014805000000000000000248090000000000000003f6",
	"01a40001014805000000000000000248080000000000000003f6",
	"02a40001014805000000000000000248070000000000000003f6",
	"030002a5",
	"00820958206666666666666666666666666666666666666666666666666666666666666666",
	"01820558207777777777777777777777777777777777777777777777777777777777777777",
	"02820658208888888888888888888888888888888888888888888888888888888888888888",
	"0318240458209999999999999999999999999999999999999999999999999999999999999999",
	"03f6",
);

fn golden(body: &str) -> Vec<u8> {
	let hex = [RECOVERY_HEADER, body].concat();
	let (digits, remainder) = hex.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty(), "fixture has an incomplete hex byte");
	digits
		.iter()
		.map(|digits| {
			let digits = std::str::from_utf8(digits).expect("ASCII fixture");
			u8::from_str_radix(digits, 16).expect("hex fixture")
		})
		.collect()
}

fn context(epoch: u64) -> JournalContext {
	JournalContext {
		job: JournalJobId::from_bytes(JOB).expect("fixture UUIDv7"),
		epoch: JournalEpoch::new(epoch),
		plan_digest: PlanDigest::from_bytes([0x22; 32]),
	}
}

fn reference(sequence: u64, byte: u8) -> ChainHead {
	ChainHead::after(sequence, [byte; 32]).expect("fixture noninitial reference")
}

fn stream() -> StreamEvidence {
	StreamEvidence {
		identity: FILE,
		length: StreamLength::new(36).expect("fixture logical length"),
		digest: StreamDigest::from_bytes([0x99; 32]),
	}
}

fn started_evidence() -> RecoveryStartEvidence {
	RecoveryStartEvidence {
		intent: reference(7, 0x33),
		preceding: reference(8, 0x55),
		authorization: OWNER,
	}
}

fn decision_evidence() -> PublishedRecoveryEvidence {
	PublishedRecoveryEvidence {
		target: FILE,
		destination_directory: TARGET_DIR,
		stage_directory: STAGE_DIR,
		verification: reference(5, 0x77),
		stream: stream(),
		metadata: reference(6, 0x88),
	}
}

#[test]
fn recovery_records_match_independent_cbor_vectors() {
	let start = RecoveryStarted::new(context(3), ENTRY, JournalEpoch::new(2), started_evidence())
		.expect("valid start");
	let bytes = golden(STARTED_BODY);
	assert_eq!(start.encode(), bytes);
	assert_eq!(RecoveryStarted::decode(&bytes), Ok(start));

	let decision =
		RecoveryDecision::new(context(3), ENTRY, reference(9, 0x66), decision_evidence())
			.expect("valid decision");
	let bytes = golden(DECISION_BODY);
	assert_eq!(decision.encode(), bytes);
	assert_eq!(RecoveryDecision::decode(&bytes), Ok(decision));
}

#[test]
fn malformed_or_noncanonical_cbor_is_refused() {
	check_invalid_encodings(STARTED_BODY, |bytes| {
		RecoveryStarted::decode(bytes).map(|_| ())
	});
	check_invalid_encodings(DECISION_BODY, |bytes| {
		RecoveryDecision::decode(bytes).map(|_| ())
	});
}

fn check_invalid_encodings(body: &str, decode: impl Fn(&[u8]) -> Result<(), RecoveryRecordError>) {
	let bytes = golden(body);
	for end in 0..bytes.len() {
		assert!(
			decode(&bytes[..end]).is_err(),
			"accepted prefix length {end}"
		);
	}
	let mut nonminimal = bytes.clone();
	nonminimal.insert(1, 0x18);
	assert_eq!(decode(&nonminimal), Err(RecoveryRecordError::NonCanonical));

	let mut indefinite = bytes.clone();
	indefinite[0] = 0xbf;
	assert_eq!(decode(&indefinite), Err(RecoveryRecordError::InvalidCbor));

	let mut duplicate = bytes.clone();
	duplicate[5] = 0;
	assert_eq!(decode(&duplicate), Err(RecoveryRecordError::InvalidCbor));

	let mut trailing = bytes;
	trailing.push(0);
	assert_eq!(decode(&trailing), Err(RecoveryRecordError::TrailingBytes));
	assert_eq!(decode(&[0; 385]), Err(RecoveryRecordError::PayloadTooLong));
}

#[test]
fn unsupported_versions_features_and_reserved_reference_digests_are_refused() {
	let mut start = golden(STARTED_BODY);
	start[4] = 2;
	assert_eq!(
		RecoveryStarted::decode(&start),
		Err(RecoveryRecordError::Common(
			PreparedError::UnsupportedVersion
		))
	);

	let mut decision = golden(DECISION_BODY);
	decision[8] = 1;
	assert_eq!(
		RecoveryDecision::decode(&decision),
		Err(RecoveryRecordError::Common(
			PreparedError::UnsupportedFeatures
		))
	);

	let mut start = golden(STARTED_BODY);
	let at = start
		.windows(32)
		.position(|window| window == [0x33; 32])
		.expect("original intent digest");
	start[at..at + 32].fill(0);
	assert_eq!(
		RecoveryStarted::decode(&start),
		Err(RecoveryRecordError::InvalidReference)
	);
}

#[test]
fn unsupported_reconciliation_code_stage_state_and_effect_id_are_refused() {
	let start = RECOVERY_HEADER.len() / 2;
	let mut bytes = golden(DECISION_BODY);
	bytes[start + 2] = 2;
	assert_eq!(
		RecoveryDecision::decode(&bytes),
		Err(RecoveryRecordError::UnsupportedEvidence)
	);

	let mut bytes = golden(DECISION_BODY);
	let private_name_state = bytes
		.windows(4)
		.position(|window| window == [0x03, 0x00, 0x02, 0xa5])
		.expect("private-name state followed by the next map")
		+ 1;
	bytes[private_name_state] = 1;
	assert_eq!(
		RecoveryDecision::decode(&bytes),
		Err(RecoveryRecordError::UnsupportedEvidence)
	);

	let mut bytes = golden(DECISION_BODY);
	*bytes.last_mut().expect("the explicit empty effect binding") = 1;
	assert_eq!(
		RecoveryDecision::decode(&bytes),
		Err(RecoveryRecordError::InvalidCbor)
	);
}

#[test]
fn reserved_out_of_order_and_forked_references_are_refused() {
	let references = started_evidence();
	for (intent, preceding, expected) in [
		(
			ChainHead::start(),
			references.preceding,
			RecoveryRecordError::InvalidReference,
		),
		(
			references.intent,
			ChainHead::start(),
			RecoveryRecordError::InvalidReference,
		),
		(
			reference(8, 0x56),
			references.preceding,
			RecoveryRecordError::InvalidFrameOrder,
		),
		(
			reference(9, 0x55),
			references.preceding,
			RecoveryRecordError::InvalidFrameOrder,
		),
	] {
		assert_eq!(
			RecoveryStarted::new(
				context(3),
				ENTRY,
				JournalEpoch::new(2),
				RecoveryStartEvidence {
					intent,
					preceding,
					..references
				},
			),
			Err(expected),
		);
	}
	let references = decision_evidence();
	assert_eq!(
		RecoveryDecision::new(context(3), ENTRY, references.metadata, references),
		Err(RecoveryRecordError::InvalidFrameOrder)
	);
	assert_eq!(
		RecoveryDecision::new(
			context(3),
			ENTRY,
			reference(9, 0x66),
			PublishedRecoveryEvidence {
				verification: references.metadata,
				..references
			},
		),
		Err(RecoveryRecordError::InvalidFrameOrder)
	);
}

#[test]
fn a_recovery_epoch_is_the_immediate_successor_and_cannot_wrap() {
	for (prior, next) in [(2, 2), (2, 1), (2, 4), (u64::MAX, 0)] {
		assert_eq!(
			RecoveryStarted::new(
				context(next),
				ENTRY,
				JournalEpoch::new(prior),
				started_evidence()
			),
			Err(RecoveryRecordError::InvalidEpoch),
			"admitted epoch progression {prior} to {next}",
		);
	}
}

#[test]
fn largest_supported_values_fit_the_bounded_codecs() {
	let context = context(u64::MAX);
	let before_start = reference(u64::MAX - 2, 0x55);
	let start = RecoveryStarted::new(
		context,
		ENTRY,
		JournalEpoch::new(u64::MAX - 1),
		RecoveryStartEvidence {
			intent: before_start,
			preceding: before_start,
			authorization: OWNER,
		},
	)
	.expect("highest epoch and adjacent intent");
	assert_eq!(RecoveryStarted::decode(&start.encode()), Ok(start));

	let target = LinuxFileIdentity::new(u64::MAX, u64::MAX);
	let decision = RecoveryDecision::new(
		context,
		ENTRY,
		reference(u64::MAX - 1, 0x66),
		PublishedRecoveryEvidence {
			target,
			destination_directory: LinuxFileIdentity::new(u64::MAX, u64::MAX - 1),
			stage_directory: LinuxFileIdentity::new(u64::MAX, u64::MAX - 2),
			verification: reference(u64::MAX - 4, 0x77),
			stream: StreamEvidence {
				identity: target,
				length: StreamLength::new(MAX_FILE_LENGTH).expect("maximal logical length"),
				..stream()
			},
			metadata: reference(u64::MAX - 3, 0x88),
		},
	)
	.expect("maximum widths fit local profile");
	assert_eq!(RecoveryDecision::decode(&decision.encode()), Ok(decision));
}

#[test]
fn directory_and_target_identities_must_share_a_device_without_aliasing() {
	let evidence = decision_evidence();
	for invalid in [
		PublishedRecoveryEvidence {
			destination_directory: STAGE_DIR,
			..evidence
		},
		PublishedRecoveryEvidence {
			destination_directory: FILE,
			..evidence
		},
		PublishedRecoveryEvidence {
			stage_directory: FILE,
			..evidence
		},
		PublishedRecoveryEvidence {
			stage_directory: LinuxFileIdentity::new(6, 7),
			..evidence
		},
		PublishedRecoveryEvidence {
			stream: StreamEvidence {
				identity: LinuxFileIdentity::new(5, 10),
				..stream()
			},
			..evidence
		},
	] {
		assert_eq!(
			RecoveryDecision::new(context(3), ENTRY, reference(9, 0x66), invalid),
			Err(RecoveryRecordError::InvalidIdentityScope),
		);
	}
}

fn append(writer: &mut FrameWriter<Vec<u8>>, kind: FrameKind, payload: &[u8]) -> ChainHead {
	writer.append(kind, payload).expect("write fixture frame")
}

fn path_frame(anchor: ChainHead, kind: FrameKind, payload: &[u8]) -> Frame {
	let mut writer = FrameWriter::new(Vec::new(), anchor);
	append(&mut writer, kind, payload);
	FrameReader::new(writer.into_inner().as_slice(), anchor)
		.next_frame()
		.expect("read framed bytes")
		.expect("one fixture frame")
}

#[test]
fn intact_envelopes_require_the_exact_predecessor_sequence_and_digest() {
	let start = RecoveryStarted::new(context(3), ENTRY, JournalEpoch::new(2), started_evidence())
		.expect("valid start");
	let decision =
		RecoveryDecision::new(context(3), ENTRY, reference(9, 0x66), decision_evidence())
			.expect("valid decision");
	for anchor in [reference(8, 0x56), reference(9, 0x55)] {
		let frame = path_frame(anchor, FrameKind::RecoveryStarted, &start.encode());
		assert_eq!(
			RecoveryStarted::from_frame(&frame),
			Err(RecoveryRecordError::InvalidFrameOrder)
		);
	}
	for anchor in [reference(9, 0x67), reference(10, 0x66)] {
		let frame = path_frame(anchor, FrameKind::RecoveryDecision, &decision.encode());
		assert_eq!(
			RecoveryDecision::from_frame(&frame),
			Err(RecoveryRecordError::InvalidFrameOrder)
		);
	}
	let frame = path_frame(
		start.evidence().preceding,
		FrameKind::RecoveryDecision,
		&start.encode(),
	);
	assert_eq!(
		RecoveryStarted::from_frame(&frame),
		Err(RecoveryRecordError::WrongRecordKind {
			expected: FrameKind::RecoveryStarted,
			actual: FrameKind::RecoveryDecision,
		})
	);
}
