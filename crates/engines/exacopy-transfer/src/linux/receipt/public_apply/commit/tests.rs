use exacopy_endpoint::UnixComponent;
use exacopy_journal::{
	ApplyCrashProfile, ApplyProcessCrashEnvironment, ApplyQualificationDigest,
	ApprovedPublicPlanDigest, DestinationRootBinding, JournalContext, JournalEntryId, JournalEpoch,
	JournalJobId, OwnerDigest, PlanDigest, PublicPlanEntryId, RootCapabilityId, StreamDigest,
	StreamEvidence, StreamLength,
};

use super::*;

fn hex(text: &str) -> Vec<u8> {
	text.lines()
		.flat_map(|line| {
			let (pairs, remainder) = line.as_bytes().as_chunks::<2>();
			assert!(remainder.is_empty());
			pairs
				.iter()
				.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		})
		.collect()
}

macro_rules! vector {
	($case:literal) => {
		(
			hex(include_str!(concat!("vectors/", $case, "-journal.hex"))),
			hex(include_str!(concat!("vectors/", $case, "-receipt.hex"))),
		)
	};
}

fn id(marker: u8) -> [u8; 16] {
	let mut result = *uuid::uuid!("019a0000-0000-7000-8000-000000000000").as_bytes();
	result[15] = marker;
	result
}

fn timestamp(seconds: i64, nanos: u32) -> OwnerTimestamp {
	OwnerTimestamp::new(seconds, nanos).unwrap()
}

fn selection() -> PublicApplyCommitSelection<'static> {
	let stream = hex("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
	PublicApplyCommitSelection {
		seal: ChainHead::after(4, [0x44; 32]).unwrap(),
		association: PublicApplyAssociation {
			owner_digest: OwnerDigest::from_bytes([0xa1; 32]),
			public_plan: ApprovedPublicPlanDigest::from_bytes([0xa2; 32]),
			public_entry: PublicPlanEntryId::from_bytes(id(8)).unwrap(),
		},
		qualification: ApplyQualification {
			record: ApplyQualificationDigest::from_bytes([0xa3; 32]),
			profile: ApplyCrashProfile::Arm64UbuntuExt4FixtureV1,
			environment: ApplyProcessCrashEnvironment {
				boot_id: [0xa4; 16],
				mount_namespace: 130_248,
				unique_mount: 546_721,
				device: 3,
			},
		},
		copy: ReceiptEvidence {
			context: JournalContext {
				job: JournalJobId::from_bytes(id(1)).unwrap(),
				epoch: JournalEpoch::new(2),
				plan_digest: PlanDigest::from_bytes([0x11; 32]),
			},
			entry: JournalEntryId::from_bytes(id(4)),
			source: LinuxFileIdentity::new(3, 2),
			destination: DestinationRootBinding {
				id: RootCapabilityId::from_bytes(id(3)).unwrap(),
				identity: LinuxFileIdentity::new(3, 4),
			},
			target: UnixComponent::new(b"f\xff").unwrap(),
			stream: StreamEvidence {
				identity: LinuxFileIdentity::new(3, 5),
				length: StreamLength::new(3).unwrap(),
				digest: StreamDigest::from_bytes(stream.try_into().unwrap()),
			},
		},
		metadata: BasicMetadata::new(0o640, 1000, 1001, timestamp(90, 123), timestamp(91, 456))
			.unwrap(),
		stage_directory: LinuxFileIdentity::new(3, 6),
		owner_created: timestamp(100, 0),
		expires_at: Some(timestamp(200, 0)),
	}
}

#[test]
fn independent_v2_commit_checks_the_complete_terminal_suffix() {
	let (journal, bytes) = vector!("valid");
	let selected = selection();
	PublicApplyReceipt::validate_commit(journal.as_slice(), &bytes, selected).unwrap();
	let exact = ChainHead::after(
		10,
		hex("9690f004b607869379282d8211a47aba82bceb353ed35d19a5de496fbb1f07f8")
			.try_into()
			.unwrap(),
	)
	.unwrap();
	assert_eq!(
		PublicApplyReceipt::validate_commit_boundary(journal.as_slice(), &bytes, selected).unwrap(),
		exact,
	);

	let mut reader = FrameReader::new(journal.as_slice(), selected.seal);
	let verification = reader.next_frame().unwrap().unwrap();
	let metadata = reader.next_frame().unwrap().unwrap();
	let intent = reader.next_frame().unwrap().unwrap();
	let observed_frame = reader.next_frame().unwrap().unwrap();
	let durability = reader.next_frame().unwrap().unwrap();
	let receipt = reader.next_frame().unwrap().unwrap();
	assert!(reader.next_frame().unwrap().is_none());
	assert_eq!(verification.kind(), FrameKind::VerificationRecorded);
	assert_eq!(receipt.kind(), FrameKind::ReceiptCommitted);
	assert!(PublicApplyIntent::from_frame(&intent).is_ok());
	assert!(
		PublishObserved::from_frame(&observed_frame)
			.unwrap()
			.validate_intent(&intent)
			.is_err()
	);
	assert!(
		DurabilityRecorded::from_frame(&durability)
			.unwrap()
			.validate_evidence(&metadata, &intent, &observed_frame)
			.is_err()
	);
}

#[test]
fn independently_relinked_near_misses_cannot_commit() {
	let selected = selection();
	for (journal, bytes) in [
		vector!("wrong_intent_link"),
		vector!("not_performed"),
		vector!("wrong_stage_directory"),
	] {
		assert!(matches!(
			PublicApplyReceipt::validate_commit(journal.as_slice(), &bytes, selected),
			Err(PublicApplyCommitError::Binding)
		));
	}
	let (journal, bytes) = vector!("legacy");
	assert!(matches!(
		PublicApplyReceipt::validate_commit(journal.as_slice(), &bytes, selected),
		Err(PublicApplyCommitError::Intent(_))
	));
	let (journal, bytes) = vector!("wrong_receipt_digest");
	assert!(matches!(
		PublicApplyReceipt::validate_commit(journal.as_slice(), &bytes, selected),
		Err(PublicApplyCommitError::Publication(
			PublicationRecordError::BindingMismatch
		))
	));
	let (journal, bytes) = vector!("sequence_gap");
	assert!(matches!(
		PublicApplyReceipt::validate_commit(journal.as_slice(), &bytes, selected),
		Err(PublicApplyCommitError::Order(FrameKind::ReceiptCommitted))
	));
}

#[test]
fn refuses_a_consistent_source_identity_alias_of_the_destination_directory() {
	let (journal, receipt_bytes) = vector!("source_aliases_destination");
	let mut selected = selection();
	selected.copy.source = selected.copy.destination.identity;
	let receipt = PublicApplyReceipt::decode(&receipt_bytes).unwrap();
	assert_eq!(receipt.private().evidence(), selected.copy);

	// The independently encoded near miss has intact envelopes and receipt links.
	// Compatibility decoding still accepts the old structural shape.
	let mut reader = FrameReader::new(journal.as_slice(), selected.seal);
	let verification = reader.next_frame().unwrap().unwrap();
	let proof = VerificationRecorded::from_frame(&verification).unwrap();
	assert_eq!(proof.source().identity, selected.copy.destination.identity);
	let metadata = reader.next_frame().unwrap().unwrap();
	let intent = reader.next_frame().unwrap().unwrap();
	let proposal = PublicApplyIntent::from_frame(&intent).unwrap();
	check_seal_records(&verification, &metadata, &proposal, selected).unwrap();
	assert!(receipt.matches_intent(intent.head(), &proposal));
	let observed_frame = reader.next_frame().unwrap().unwrap();
	let observed = PublishObserved::from_frame(&observed_frame).unwrap();
	assert_eq!(observed.intent(), intent.head());
	let durability = reader.next_frame().unwrap().unwrap();
	let barriers = DurabilityRecorded::from_frame(&durability).unwrap();
	assert_eq!(barriers.observed(), observed_frame.head());
	assert_eq!(receipt.private().durability_frame(), durability.head());
	let commitment = reader.next_frame().unwrap().unwrap();
	assert!(reader.next_frame().unwrap().is_none());
	ReceiptCommitted::from_frame(&commitment)
		.unwrap()
		.validate_evidence(&durability, receipt.digest())
		.unwrap();

	assert!(matches!(
		PublicApplyReceipt::validate_commit(journal.as_slice(), &receipt_bytes, selected),
		Err(PublicApplyCommitError::Binding)
	));
}

#[test]
fn rejects_a_different_independent_owner_scope_or_original_expiry() {
	let (journal, bytes) = vector!("valid");
	let expected = selection();
	let mut changed_owner = expected;
	changed_owner.association.owner_digest = OwnerDigest::from_bytes([0xb1; 32]);
	let mut changed_public_plan = expected;
	changed_public_plan.association.public_plan = ApprovedPublicPlanDigest::from_bytes([0xb2; 32]);
	let mut changed_source = expected;
	changed_source.copy.source = LinuxFileIdentity::new(3, 9);
	let mut changed_root = expected;
	changed_root.copy.destination.id = RootCapabilityId::from_bytes(id(9)).unwrap();
	let mut changed_stream = expected;
	changed_stream.copy.stream.digest = StreamDigest::from_bytes([0xb3; 32]);
	let mut changed_qualification = expected;
	changed_qualification.qualification.environment.boot_id = [0xb4; 16];
	for selection in [
		changed_owner,
		changed_public_plan,
		changed_source,
		changed_root,
		changed_stream,
		changed_qualification,
		PublicApplyCommitSelection {
			expires_at: Some(timestamp(120, 0)),
			..expected
		},
		PublicApplyCommitSelection {
			owner_created: timestamp(120, 1),
			..expected
		},
	] {
		assert!(matches!(
			PublicApplyReceipt::validate_commit(journal.as_slice(), &bytes, selection),
			Err(PublicApplyCommitError::Binding)
		));
	}
}

#[test]
fn rejects_missing_torn_corrupt_or_post_commit_bytes() {
	let (mut journal, mut bytes) = vector!("valid");
	let selected = selection();
	assert!(matches!(
		PublicApplyReceipt::validate_commit(&[][..], &bytes, selected),
		Err(PublicApplyCommitError::Missing(
			FrameKind::VerificationRecorded
		))
	));
	assert!(matches!(
		PublicApplyReceipt::validate_commit(&journal[..journal.len() - 1], &bytes, selected),
		Err(PublicApplyCommitError::Envelope(
			FrameReadError::TornTail { .. }
		))
	));
	let mut corrupted = journal.clone();
	corrupted[0] ^= 1;
	assert!(matches!(
		PublicApplyReceipt::validate_commit(corrupted.as_slice(), &bytes, selected),
		Err(PublicApplyCommitError::Envelope(
			FrameReadError::Corrupt { .. }
		))
	));
	let stale = PublicApplyCommitSelection {
		seal: ChainHead::after(selected.seal.sequence(), [0x45; 32]).unwrap(),
		..selected
	};
	assert!(matches!(
		PublicApplyReceipt::validate_commit(journal.as_slice(), &bytes, stale),
		Err(PublicApplyCommitError::Envelope(
			FrameReadError::Corrupt { .. }
		))
	));

	journal.push(0);
	assert!(matches!(
		PublicApplyReceipt::validate_commit(journal.as_slice(), &bytes, selected),
		Err(PublicApplyCommitError::TrailingOrOversize)
	));
	journal.pop();
	bytes.push(0);
	assert!(matches!(
		PublicApplyReceipt::validate_commit(journal.as_slice(), &bytes, selected),
		Err(PublicApplyCommitError::Receipt(
			PublicApplyReceiptError::NonCanonical
		))
	));
}

#[test]
fn interruptions_in_a_partial_header_terminate_without_progress() {
	let (journal, bytes) = vector!("valid");
	let mut input = InterruptedRead::new(&journal[..1], 0);
	let refusal = PublicApplyReceipt::validate_commit(&mut input, &bytes, selection());
	assert!(matches!(
		refusal,
		Err(PublicApplyCommitError::Envelope(FrameReadError::Io { offset: 0, source }))
			if source.kind() == io::ErrorKind::Other
	));
	let exhausted = usize::from(MAX_INTERRUPTED_RETRIES) + 1;
	assert_eq!(input.after_prefix, exhausted);
	assert_eq!(input.calls, 1 + exhausted);
}

#[test]
fn perpetual_eof_interruptions_use_the_remaining_shared_budget() {
	let (journal, bytes) = vector!("valid");
	for before_prefix in [0, MAX_INTERRUPTED_RETRIES] {
		let mut input = InterruptedRead::new(&journal, before_prefix);
		let refusal = PublicApplyReceipt::validate_commit(&mut input, &bytes, selection());
		assert!(matches!(
			refusal,
			Err(PublicApplyCommitError::TerminalProbe(error))
				if error.kind() == io::ErrorKind::Other
		));
		assert!(input.prefix.is_empty());
		assert_eq!(input.before_prefix, 0);
		let exhausted = usize::from(MAX_INTERRUPTED_RETRIES) + 1;
		assert_eq!(input.after_prefix, exhausted - usize::from(before_prefix));
		assert!(input.calls <= journal.len() + exhausted);
	}
}

struct InterruptedRead<'a> {
	prefix: &'a [u8],
	before_prefix: u8,
	after_prefix: usize,
	calls: usize,
}

impl<'a> InterruptedRead<'a> {
	fn new(prefix: &'a [u8], before_prefix: u8) -> Self {
		Self {
			prefix,
			before_prefix,
			after_prefix: 0,
			calls: 0,
		}
	}
}

impl Read for InterruptedRead<'_> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		self.calls += 1;
		if self.before_prefix != 0 {
			self.before_prefix -= 1;
		} else if !self.prefix.is_empty() {
			return self.prefix.read(output);
		} else {
			self.after_prefix += 1;
		}
		// Fail the test if an accidentally unbounded retry loop consumes
		// more interrupts than allowed, without waiting on an actual signal.
		assert!(self.after_prefix <= usize::from(MAX_INTERRUPTED_RETRIES) + 1);
		Err(io::ErrorKind::Interrupted.into())
	}
}
