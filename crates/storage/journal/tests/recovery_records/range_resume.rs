use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	JournalEpoch, LinuxFileIdentity, RangeResumeEvidence, RangeResumeStarted, RecoveryRecordError,
	RecoveryStarted,
};

use super::{
	ENTRY, FILE, OWNER, RECOVERY_HEADER, STAGE_DIR, STARTED_BODY, append, check_invalid_encodings,
	context, golden, path_frame, reference,
};

const RESUME_BODY: &str = concat!(
	"a4000201a4",
	"00820258203333333333333333333333333333333333333333333333333333333333333333",
	"01820858205555555555555555555555555555555555555555555555555555555555555555",
	"02a40001014805000000000000000248090000000000000003f6",
	"03a40001014805000000000000000248070000000000000003f6",
	"0258204444444444444444444444444444444444444444444444444444444444444444",
	"0301",
);

fn evidence() -> RangeResumeEvidence {
	RangeResumeEvidence {
		preparation: reference(2, 0x33),
		preceding: reference(8, 0x55),
		stage: FILE,
		stage_directory: STAGE_DIR,
		authorization: OWNER,
	}
}

fn resume(evidence: RangeResumeEvidence) -> Result<RangeResumeStarted, RecoveryRecordError> {
	RangeResumeStarted::new(context(3), ENTRY, JournalEpoch::new(2), evidence)
}

#[test]
fn resume_matches_the_independent_canonical_vector_and_legacy_refuses_it() {
	let record = resume(evidence()).expect("valid range resume");
	let bytes = golden(RESUME_BODY);
	assert_eq!(record.encode(), bytes);
	assert_eq!(RangeResumeStarted::decode(&bytes), Ok(record));
	assert_eq!(record.context(), context(3));
	assert_eq!(record.entry(), ENTRY);
	assert_eq!(record.prior_epoch(), JournalEpoch::new(2));
	assert_eq!(record.evidence(), evidence());
	assert_eq!(
		RecoveryStarted::decode(&bytes),
		Err(RecoveryRecordError::InvalidCbor),
	);
	assert_eq!(
		RangeResumeStarted::decode(&golden(STARTED_BODY)),
		Err(RecoveryRecordError::InvalidCbor),
	);
}

#[test]
fn bounded_codec_refuses_malformed_shapes_and_unknown_profiles() {
	check_invalid_encodings(RESUME_BODY, |bytes| {
		RangeResumeStarted::decode(bytes).map(|_| ())
	});

	let mut bytes = golden(RESUME_BODY);
	*bytes.last_mut().expect("explicit local profile code") = 2;
	assert_eq!(
		RangeResumeStarted::decode(&bytes),
		Err(RecoveryRecordError::UnsupportedEvidence),
	);

	let mut bytes = golden(RESUME_BODY);
	bytes[RECOVERY_HEADER.len() / 2 + 4] = 0xa2;
	assert_eq!(
		RangeResumeStarted::decode(&bytes),
		Err(RecoveryRecordError::InvalidCbor),
	);

	for digest_byte in [0x33, 0x55] {
		let mut bytes = golden(RESUME_BODY);
		let at = bytes
			.windows(32)
			.position(|window| window == [digest_byte; 32])
			.expect("fixture reference digest");
		bytes[at..at + 32].fill(0);
		assert_eq!(
			RangeResumeStarted::decode(&bytes),
			Err(RecoveryRecordError::InvalidReference),
		);
	}
}

#[test]
fn pre_intent_resume_requires_a_next_epoch_and_valid_history_references() {
	for (prior, next) in [(2, 2), (2, 1), (2, 4), (u64::MAX, 0)] {
		assert_eq!(
			RangeResumeStarted::new(context(next), ENTRY, JournalEpoch::new(prior), evidence()),
			Err(RecoveryRecordError::InvalidEpoch),
		);
	}

	for (preparation, preceding, expected) in [
		(
			ChainHead::start(),
			evidence().preceding,
			RecoveryRecordError::InvalidReference,
		),
		(
			evidence().preparation,
			ChainHead::start(),
			RecoveryRecordError::InvalidReference,
		),
		(
			reference(1, 0x33),
			evidence().preceding,
			RecoveryRecordError::InvalidFrameOrder,
		),
		(
			reference(8, 0x33),
			evidence().preceding,
			RecoveryRecordError::InvalidFrameOrder,
		),
		(
			reference(9, 0x33),
			evidence().preceding,
			RecoveryRecordError::InvalidFrameOrder,
		),
	] {
		assert_eq!(
			resume(RangeResumeEvidence {
				preparation,
				preceding,
				..evidence()
			}),
			Err(expected),
		);
	}
}

#[test]
fn retained_stage_and_directory_must_be_distinct_on_the_same_device() {
	for stage_directory in [FILE, LinuxFileIdentity::new(6, STAGE_DIR.inode())] {
		assert_eq!(
			resume(RangeResumeEvidence {
				stage_directory,
				..evidence()
			}),
			Err(RecoveryRecordError::InvalidIdentityScope),
		);
	}
}

#[test]
fn largest_valid_resume_references_and_epoch_round_trip() {
	let preparation = reference(u64::MAX - 1, 0x33);
	let record = RangeResumeStarted::new(
		context(u64::MAX),
		ENTRY,
		JournalEpoch::new(u64::MAX - 1),
		RangeResumeEvidence {
			preparation,
			preceding: preparation,
			stage: LinuxFileIdentity::new(u64::MAX, u64::MAX),
			stage_directory: LinuxFileIdentity::new(u64::MAX, u64::MAX - 1),
			..evidence()
		},
	)
	.expect("maximum active epoch and last available predecessor");
	let frame = path_frame(preparation, FrameKind::RecoveryStarted, &record.encode());
	assert_eq!(RangeResumeStarted::from_frame(&frame), Ok(record));
}

#[test]
fn a_resume_frame_cites_its_exact_predecessor() {
	let anchor = ChainHead::start();
	let mut writer = FrameWriter::new(Vec::new(), anchor);
	append(&mut writer, FrameKind::JobPrepared, b"opaque job payload");
	let preparation = append(
		&mut writer,
		FrameKind::EntryPrepared,
		b"opaque entry payload",
	);
	let record = resume(RangeResumeEvidence {
		preparation,
		preceding: preparation,
		..evidence()
	})
	.expect("resume permits a directly preceding entry preparation");
	let bytes = record.encode();
	append(&mut writer, FrameKind::RecoveryStarted, &bytes);

	let encoded = writer.into_inner();
	let mut reader = FrameReader::new(encoded.as_slice(), anchor);
	for kind in [FrameKind::JobPrepared, FrameKind::EntryPrepared] {
		let frame = reader
			.next_frame()
			.expect("verified frame")
			.expect("fixture frame");
		assert_eq!(frame.kind(), kind);
	}
	let frame = reader
		.next_frame()
		.expect("verified range resume frame")
		.expect("last fixture frame");
	assert_eq!(RangeResumeStarted::from_frame(&frame), Ok(record));
	assert_eq!(
		RecoveryStarted::from_frame(&frame),
		Err(RecoveryRecordError::InvalidCbor),
	);
	assert!(reader.next_frame().expect("reader reaches EOF").is_none());

	for anchor in [
		reference(preparation.sequence(), 0x55),
		ChainHead::after(preparation.sequence() + 1, preparation.digest())
			.expect("later sequence with the correct digest"),
	] {
		let frame = path_frame(anchor, FrameKind::RecoveryStarted, &bytes);
		assert_eq!(
			RangeResumeStarted::from_frame(&frame),
			Err(RecoveryRecordError::InvalidFrameOrder),
		);
	}

	let frame = path_frame(preparation, FrameKind::RecoveryDecision, &bytes);
	assert_eq!(
		RangeResumeStarted::from_frame(&frame),
		Err(RecoveryRecordError::WrongRecordKind {
			expected: FrameKind::RecoveryStarted,
			actual: FrameKind::RecoveryDecision,
		}),
	);
}
