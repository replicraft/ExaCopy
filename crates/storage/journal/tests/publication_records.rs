//! Deterministic local publication journal vectors and cross-frame binding checks.

use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	BasicMetadata, DurabilityRecorded, JournalContext, JournalEntryId, JournalEpoch, JournalJobId,
	LOCAL_RECEIPT_LOCATION, LinuxFileIdentity, LinuxPublicationBarriers, MetadataRecorded,
	NamespaceObservation, OwnerTimestamp, PlanDigest, PublicationOutcome, PublicationPrimitive,
	PublicationRecordError, PublishIntent, PublishIntentContext, PublishIntentTarget,
	PublishObserved, ReceiptCommitted, ReceiptDigest, VerificationDigest,
};

const JOB: [u8; 16] = [
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x76, 0x07, 0x88, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const FILE: LinuxFileIdentity = LinuxFileIdentity::new(5, 9);
const STAGE_DIR: LinuxFileIdentity = LinuxFileIdentity::new(5, 7);
const TARGET_DIR: LinuxFileIdentity = LinuxFileIdentity::new(5, 8);

const HEADER: &str = concat!(
	"a800a3000101000200",
	"0150000102030405760788090a0b0c0d0e0f",
	"0202",
	"035011111111111111111111111111111111",
	"0405",
	"0558202222222222222222222222222222222222222222222222222222222222222222",
	"06000a",
);
const PUBLISHED_BODY: &str = concat!(
	"a400820658203333333333333333333333333333333333333333333333333333333333333333",
	"018202a40001014805000000000000000248090000000000000003f6",
	"0281010301",
);
const DURABILITY_BODY: &str = concat!(
	"a3000101a4",
	"00820758204444444444444444444444444444444444444444444444444444444444444444",
	"01820558205555555555555555555555555555555555555555555555555555555555555555",
	"02a40001014805000000000000000248070000000000000003f6",
	"03a40001014805000000000000000248080000000000000003f6",
	"0200",
);
const RECEIPT_BODY: &str = concat!(
	"a40058207777777777777777777777777777777777777777777777777777777777777777",
	"017572656365697074732f726563656970742e63626f72",
	"02010381a2000101820858206666666666666666666666666666666666666666666666666666666666666666",
);

fn context() -> PublishIntentContext {
	PublishIntentContext {
		job: JournalJobId::from_bytes(JOB).expect("fixture UUIDv7"),
		epoch: JournalEpoch::new(2),
		entry: JournalEntryId::from_bytes([0x11; 16]),
		effect_sequence: 5,
		plan_digest: PlanDigest::from_bytes([0x22; 32]),
	}
}

fn reference(sequence: u64, byte: u8) -> ChainHead {
	ChainHead::after(sequence, [byte; 32]).expect("fixture noninitial reference")
}

fn barriers(metadata: ChainHead) -> LinuxPublicationBarriers {
	LinuxPublicationBarriers {
		metadata,
		stage_directory: STAGE_DIR,
		destination_directory: TARGET_DIR,
	}
}

fn receipt_digest() -> ReceiptDigest {
	ReceiptDigest::from_bytes([0x77; 32])
}

fn golden(body: &str) -> Vec<u8> {
	let hex = [HEADER, body].concat();
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

#[test]
fn publication_records_match_independent_cbor_goldens() {
	let published = PublishObserved::new(
		context(),
		reference(6, 0x33),
		PublicationOutcome::Published { target: FILE },
	)
	.expect("fixture published observation");
	let durability =
		DurabilityRecorded::new(context(), reference(7, 0x44), barriers(reference(5, 0x55)))
			.expect("fixture durability observation");
	let receipt = ReceiptCommitted::new(context(), receipt_digest(), reference(8, 0x66))
		.expect("fixture receipt");

	let bytes = golden(PUBLISHED_BODY);
	assert_eq!(published.encode(), bytes);
	assert_eq!(PublishObserved::decode(&bytes), Ok(published));

	let bytes = golden(DURABILITY_BODY);
	assert_eq!(durability.encode(), bytes);
	assert_eq!(DurabilityRecorded::decode(&bytes), Ok(durability));

	let bytes = golden(RECEIPT_BODY);
	assert_eq!(receipt.encode(), bytes);
	assert_eq!(ReceiptCommitted::decode(&bytes), Ok(receipt));
	assert_eq!(LOCAL_RECEIPT_LOCATION, "receipts/receipt.cbor");
}

#[test]
fn all_codecs_reject_truncation_reordering_trailing_and_nonminimal_encodings() {
	test_invalid_encodings(PUBLISHED_BODY, |bytes| {
		PublishObserved::decode(bytes).map(|_| ())
	});
	test_invalid_encodings(DURABILITY_BODY, |bytes| {
		DurabilityRecorded::decode(bytes).map(|_| ())
	});
	test_invalid_encodings(RECEIPT_BODY, |bytes| {
		ReceiptCommitted::decode(bytes).map(|_| ())
	});
}

fn test_invalid_encodings(
	body: &str,
	decode: impl Fn(&[u8]) -> Result<(), PublicationRecordError>,
) {
	let bytes = golden(body);
	for end in 0..bytes.len() {
		assert!(
			decode(&bytes[..end]).is_err(),
			"accepted prefix length {end}"
		);
	}
	let mut wide_key = bytes.clone();
	wide_key.insert(1, 0x18);
	assert_eq!(decode(&wide_key), Err(PublicationRecordError::NonCanonical));
	let mut displaced_key = bytes.clone();
	displaced_key[1] = 1;
	assert_eq!(
		decode(&displaced_key),
		Err(PublicationRecordError::InvalidCbor)
	);
	let mut suffix = bytes;
	suffix.push(0);
	assert_eq!(decode(&suffix), Err(PublicationRecordError::TrailingBytes));
	assert_eq!(
		decode(&[0; 257]),
		Err(PublicationRecordError::PayloadTooLong)
	);
}

#[test]
fn outcome_needs_compatible_namespace_observations() {
	for outcome in [
		PublicationOutcome::NotPerformed {
			target: None,
			stage: FILE,
		},
		PublicationOutcome::NotPerformed {
			target: Some(LinuxFileIdentity::new(5, 20)),
			stage: FILE,
		},
		PublicationOutcome::Uncertain {
			target: NamespaceObservation::Unobserved,
			stage_name: NamespaceObservation::Absent,
		},
		PublicationOutcome::Uncertain {
			target: NamespaceObservation::Present(FILE),
			stage_name: NamespaceObservation::Present(FILE),
		},
	] {
		let record = PublishObserved::new(context(), reference(6, 0x33), outcome)
			.expect("valid observation evidence");
		assert_eq!(PublishObserved::decode(&record.encode()), Ok(record));
	}
	let incompatible = PublicationOutcome::NotPerformed {
		target: Some(FILE),
		stage: FILE,
	};
	assert_eq!(
		PublishObserved::new(context(), reference(6, 0x33), incompatible),
		Err(PublicationRecordError::InconsistentObservation)
	);

	let mut published = golden(PUBLISHED_BODY);
	let end = published.len();
	published[end - 3] = 0;
	assert_eq!(
		PublishObserved::decode(&published),
		Err(PublicationRecordError::InconsistentObservation)
	);
	let mut reserved_ref = golden(PUBLISHED_BODY);
	let start = HEADER.len() / 2 + 6;
	reserved_ref[start..start + 32].fill(0);
	assert_eq!(
		PublishObserved::decode(&reserved_ref),
		Err(PublicationRecordError::InvalidReference)
	);
}

#[test]
fn stronger_durability_and_alternate_receipt_locations_are_unsupported() {
	let mut durability = golden(DURABILITY_BODY);
	*durability.last_mut().expect("level byte") = 2;
	assert_eq!(
		DurabilityRecorded::decode(&durability),
		Err(PublicationRecordError::UnsupportedEvidence)
	);
	let mut receipt = golden(RECEIPT_BODY);
	let position = receipt
		.windows(LOCAL_RECEIPT_LOCATION.len())
		.position(|window| window == LOCAL_RECEIPT_LOCATION.as_bytes())
		.expect("literal receipt location");
	receipt[position] = b'/';
	assert_eq!(
		ReceiptCommitted::decode(&receipt),
		Err(PublicationRecordError::UnsupportedEvidence)
	);
	let mut receipt = golden(RECEIPT_BODY);
	let final_state = position + LOCAL_RECEIPT_LOCATION.len() + 1;
	receipt[final_state] = 2;
	assert_eq!(
		ReceiptCommitted::decode(&receipt),
		Err(PublicationRecordError::UnsupportedEvidence)
	);
}

#[test]
fn widest_supported_values_fit_the_bounded_codec() {
	let mut context = context();
	context.epoch = JournalEpoch::new(u64::MAX);
	context.effect_sequence = u64::MAX;
	let barriers = LinuxPublicationBarriers {
		metadata: reference(u64::MAX - 2, 0xff),
		stage_directory: LinuxFileIdentity::new(u64::MAX, u64::MAX - 1),
		destination_directory: LinuxFileIdentity::new(u64::MAX, u64::MAX),
	};
	let record = DurabilityRecorded::new(context, reference(u64::MAX - 1, 0xff), barriers)
		.expect("same volume and correctly ordered evidence");
	let bytes = record.encode();
	assert_eq!(bytes.len(), 252);
	assert_eq!(DurabilityRecorded::decode(&bytes), Ok(record));
	assert_eq!(
		DurabilityRecorded::new(context, barriers.metadata, barriers),
		Err(PublicationRecordError::InvalidFrameOrder)
	);
	assert_eq!(
		DurabilityRecorded::new(
			context,
			reference(u64::MAX - 1, 0xff),
			LinuxPublicationBarriers {
				destination_directory: barriers.stage_directory,
				..barriers
			},
		),
		Err(PublicationRecordError::InvalidBarrierScope)
	);
	assert_eq!(
		DurabilityRecorded::new(
			context,
			reference(u64::MAX - 1, 0xff),
			LinuxPublicationBarriers {
				destination_directory: LinuxFileIdentity::new(1, 1),
				..barriers
			},
		),
		Err(PublicationRecordError::InvalidBarrierScope)
	);
}

fn intent(context: PublishIntentContext) -> PublishIntent<'static> {
	PublishIntent {
		context,
		target: PublishIntentTarget {
			stage: FILE,
			parent: TARGET_DIR,
			component: UnixComponent::new(b"output").expect("fixture component"),
			verification_digest: VerificationDigest::from_bytes([3; 32]),
			primitive: PublicationPrimitive::LinuxRenameNoReplace,
		},
	}
}

fn metadata(context: PublishIntentContext) -> MetadataRecorded {
	let timestamp = OwnerTimestamp::new(1, 2).expect("fixture timestamp");
	MetadataRecorded {
		context: JournalContext {
			job: context.job,
			epoch: context.epoch,
			plan_digest: context.plan_digest,
		},
		entry: context.entry,
		stage: FILE,
		metadata: BasicMetadata::new(0o600, 1000, 1000, timestamp, timestamp)
			.expect("fixture metadata"),
	}
}

struct Fixture {
	metadata: Frame,
	intent: Frame,
	observed: Frame,
	durability: Frame,
	receipt: Frame,
}

fn framed_evidence(outcome: PublicationOutcome) -> Fixture {
	let context = context();
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	let metadata = writer
		.append(FrameKind::MetadataRecorded, &metadata(context).encode())
		.expect("append metadata");
	let intent = writer
		.append(FrameKind::PublishIntent, &intent(context).encode())
		.expect("append intent");
	let observed = PublishObserved::new(context, intent, outcome).expect("construct observation");
	let observed = writer
		.append(FrameKind::PublishObserved, &observed.encode())
		.expect("append observation");
	let durability = DurabilityRecorded::new(context, observed, barriers(metadata))
		.expect("construct barrier observation");
	let durability = writer
		.append(FrameKind::DurabilityRecorded, &durability.encode())
		.expect("append barriers");
	let receipt = ReceiptCommitted::new(context, receipt_digest(), durability)
		.expect("construct receipt commitment");
	writer
		.append(FrameKind::ReceiptCommitted, &receipt.encode())
		.expect("append commitment");
	let bytes = writer.into_inner();
	let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
	let mut next = || {
		reader
			.next_frame()
			.expect("valid frame")
			.expect("fixture frame")
	};
	Fixture {
		metadata: next(),
		intent: next(),
		observed: next(),
		durability: next(),
		receipt: next(),
	}
}

#[test]
fn exact_frame_references_and_context_bind_the_publication_evidence() {
	let frames = framed_evidence(PublicationOutcome::Published { target: FILE });
	let observed = PublishObserved::from_frame(&frames.observed).expect("valid observation frame");
	assert_eq!(observed.validate_intent(&frames.intent), Ok(()));
	let durability =
		DurabilityRecorded::from_frame(&frames.durability).expect("valid durability frame");
	assert_eq!(
		durability.validate_evidence(&frames.metadata, &frames.intent, &frames.observed),
		Ok(())
	);
	let receipt = ReceiptCommitted::from_frame(&frames.receipt).expect("valid receipt frame");
	assert_eq!(
		receipt.validate_evidence(&frames.durability, receipt_digest()),
		Ok(())
	);
	assert_eq!(
		receipt.validate_evidence(&frames.durability, ReceiptDigest::from_bytes([0x7a; 32])),
		Err(PublicationRecordError::BindingMismatch)
	);
	assert_eq!(
		PublishObserved::from_frame(&frames.metadata),
		Err(PublicationRecordError::WrongRecordKind {
			expected: FrameKind::PublishObserved,
			actual: FrameKind::MetadataRecorded,
		})
	);
	assert_eq!(
		durability.validate_evidence(&frames.metadata, &frames.intent, &frames.intent),
		Err(PublicationRecordError::BindingMismatch)
	);

	let mut other_context = context();
	other_context.effect_sequence += 1;
	let mismatched = PublishObserved::new(other_context, observed.intent(), observed.outcome())
		.expect("standalone observation");
	assert_eq!(
		mismatched.validate_intent(&frames.intent),
		Err(PublicationRecordError::BindingMismatch)
	);
	let wrong_digest = reference(observed.intent().sequence(), 0xfe);
	let mismatched = PublishObserved::new(context(), wrong_digest, observed.outcome())
		.expect("syntactically valid reference");
	assert_eq!(
		mismatched.validate_intent(&frames.intent),
		Err(PublicationRecordError::BindingMismatch)
	);
	let wrong_identity = PublicationOutcome::Published {
		target: LinuxFileIdentity::new(5, 99),
	};
	let mismatched = PublishObserved::new(context(), observed.intent(), wrong_identity)
		.expect("syntactically valid observation");
	assert_eq!(
		mismatched.validate_intent(&frames.intent),
		Err(PublicationRecordError::InconsistentObservation)
	);
	let later = PublishObserved::new(
		context(),
		frames.receipt.head(),
		PublicationOutcome::Published { target: FILE },
	)
	.expect("valid payload alone");
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	writer
		.append(FrameKind::PublishObserved, &later.encode())
		.expect("append syntactic frame");
	let bytes = writer.into_inner();
	let frame = FrameReader::new(bytes.as_slice(), ChainHead::start())
		.next_frame()
		.expect("valid frame integrity")
		.expect("written frame");
	assert_eq!(
		PublishObserved::from_frame(&frame),
		Err(PublicationRecordError::InvalidFrameOrder)
	);
}

#[test]
fn incomplete_publication_cannot_support_barrier_evidence() {
	let frames = framed_evidence(PublicationOutcome::Uncertain {
		target: NamespaceObservation::Present(FILE),
		stage_name: NamespaceObservation::Unobserved,
	});
	let durability =
		DurabilityRecorded::from_frame(&frames.durability).expect("syntactic evidence");
	assert_eq!(
		durability.validate_evidence(&frames.metadata, &frames.intent, &frames.observed),
		Err(PublicationRecordError::InconsistentObservation)
	);
}
