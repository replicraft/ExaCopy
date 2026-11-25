use exacopy_endpoint::{MAX_FILE_LENGTH, MAX_UNIX_COMPONENT_BYTES, UnixComponent};
use exacopy_journal::{
	ApplyCrashProfile, ApplyIntentEvidence, ApplyProcessCrashEnvironment, ApplyQualification,
	DestinationRootBinding, JournalContext, JournalEntryId, JournalEpoch, JournalJobId,
	LinuxFileIdentity, OwnerTimestamp, PlanDigest, PublicationPrimitive, PublishIntent,
	PublishIntentContext, PublishIntentTarget, RootCapabilityId, StreamDigest, StreamEvidence,
	StreamLength, VerificationDigest,
};

use super::super::ReceiptEvidence;
use super::*;

fn golden() -> Vec<u8> {
	// Independently generated from the v1 private and v2 wrapper field layouts.
	include_str!("golden.hex")
		.split_ascii_whitespace()
		.flat_map(|line| {
			line.as_bytes()
				.as_chunks::<2>()
				.0
				.iter()
				.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		})
		.collect()
}

fn id(last: u8) -> [u8; 16] {
	[
		0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last,
	]
}

fn head(sequence: u64, marker: u8) -> ChainHead {
	ChainHead::after(sequence, [marker; 32]).unwrap()
}

fn association() -> PublicApplyAssociation {
	PublicApplyAssociation {
		owner_digest: OwnerDigest::from_bytes([0xa1; 32]),
		public_plan: ApprovedPublicPlanDigest::from_bytes([0xa2; 32]),
		public_entry: PublicPlanEntryId::from_bytes(id(8)).unwrap(),
	}
}

fn qualification() -> ApplyQualificationDigest {
	ApplyQualificationDigest::from_bytes([0xa3; 32])
}

fn evidence(target: &[u8]) -> ReceiptEvidence<'_> {
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

fn paired_intent(
	receipt: &PublicApplyReceipt<'_>,
	association: PublicApplyAssociation,
) -> PublicApplyIntent<'static> {
	let data = receipt.private().evidence();
	PublicApplyIntent::new(
		PublishIntent {
			context: PublishIntentContext {
				job: data.context.job,
				epoch: data.context.epoch,
				entry: data.entry,
				effect_sequence: 1,
				plan_digest: data.context.plan_digest,
			},
			target: PublishIntentTarget {
				stage: data.stream.identity,
				parent: data.destination.identity,
				component: UnixComponent::new(b"f\xff").unwrap(),
				verification_digest: VerificationDigest::from_bytes([0x91; 32]),
				primitive: PublicationPrimitive::LinuxRenameNoReplace,
			},
		},
		association,
		ApplyIntentEvidence {
			verification: head(5, 0x55),
			metadata: head(6, 0x66),
			qualification: ApplyQualification {
				record: qualification(),
				profile: ApplyCrashProfile::Arm64UbuntuExt4FixtureV1,
				environment: ApplyProcessCrashEnvironment {
					boot_id: [0xa4; 16],
					mount_namespace: 130_248,
					unique_mount: 546_721,
					device: 3,
				},
			},
			intent_time: OwnerTimestamp::new(-1, 800_000_000).unwrap(),
		},
	)
	.unwrap()
}

#[test]
fn independently_encoded_v2_artifact_fixes_the_exact_receipt_domain() {
	let private = CopyReceipt::from_evidence(evidence(b"f\xff"), head(9, 0x22)).unwrap();
	let receipt =
		PublicApplyReceipt::new(private, association(), head(7, 0x77), qualification()).unwrap();
	let golden = golden();
	assert_eq!(receipt.encode(), golden);
	assert_eq!(PublicApplyReceipt::decode(&golden), Ok(receipt));
	assert_eq!(receipt.private().evidence(), private.evidence());
	assert!(CopyReceipt::decode(&golden).is_err());
	assert!(PublicApplyReceipt::decode(&private.encode()).is_err());
	let mut expected = b"ExaCopy/linux-public-apply-receipt/v1\0".to_vec();
	expected.extend_from_slice(&golden);
	assert_eq!(
		receipt.digest().as_bytes(),
		blake3::hash(&expected).as_bytes()
	);
	assert_ne!(receipt.digest().as_bytes(), &private.digest());
}

#[test]
fn exact_association_and_qualification_are_checked_against_public_intent() {
	let bytes = golden();
	let record = PublicApplyReceipt::decode(&bytes).unwrap();
	let intent = paired_intent(&record, record.association());
	assert!(record.matches_intent(head(7, 0x77), &intent));
	assert!(!record.matches_intent(head(7, 0x78), &intent));
	let association = record.association();
	for changed in [
		PublicApplyAssociation {
			owner_digest: OwnerDigest::from_bytes([0xcc; 32]),
			..association
		},
		PublicApplyAssociation {
			public_plan: ApprovedPublicPlanDigest::from_bytes([0xcc; 32]),
			..association
		},
		PublicApplyAssociation {
			public_entry: PublicPlanEntryId::from_bytes(id(9)).unwrap(),
			..association
		},
	] {
		let changed_intent = paired_intent(&record, changed);
		assert!(!record.matches_intent(head(7, 0x77), &changed_intent));
	}
	let shifted_intent = PublicApplyIntent::new(
		*intent.private(),
		association,
		ApplyIntentEvidence {
			verification: head(4, 0x44),
			metadata: head(5, 0x55),
			..intent.evidence()
		},
	)
	.unwrap();
	assert!(!record.matches_intent(head(7, 0x77), &shifted_intent));
	let changed = PublicApplyReceipt::new(
		*record.private(),
		record.association(),
		record.intent(),
		ApplyQualificationDigest::from_bytes([0xee; 32]),
	)
	.unwrap();
	assert!(!changed.matches_intent(head(7, 0x77), &intent));
	assert_ne!(record.digest(), changed.digest());
	assert_eq!(
		PublicApplyReceipt::new(
			*record.private(),
			record.association(),
			head(6, 0x66),
			qualification()
		),
		Err(PublicApplyReceiptError::Binding),
	);
}

#[test]
fn rejects_truncation_nonminimal_wrapper_unknown_features_and_trailing_bytes() {
	let bytes = golden();
	for end in 0..bytes.len() {
		assert!(
			PublicApplyReceipt::decode(&bytes[..end]).is_err(),
			"truncated at {end}"
		);
	}
	let mut changed = bytes.clone();
	changed.splice(3..4, [0x18, 2]);
	assert_eq!(
		PublicApplyReceipt::decode(&changed),
		Err(PublicApplyReceiptError::NonCanonical)
	);
	let mut changed = bytes.clone();
	changed[5] = 0;
	assert_eq!(
		PublicApplyReceipt::decode(&changed),
		Err(PublicApplyReceiptError::UnsupportedVersion)
	);
	let mut changed = bytes;
	changed.push(0);
	assert_eq!(
		PublicApplyReceipt::decode(&changed),
		Err(PublicApplyReceiptError::NonCanonical)
	);
	assert_eq!(
		PublicApplyReceipt::decode(&[0; MAX_PUBLIC_APPLY_RECEIPT_BYTES + 1]),
		Err(PublicApplyReceiptError::Length)
	);
}

#[test]
fn maximum_private_names_extents_and_references_fit() {
	let name = [0xff; MAX_UNIX_COMPONENT_BYTES];
	let mut source = evidence(&name);
	source.context.epoch = JournalEpoch::new(u64::MAX);
	source.source = LinuxFileIdentity::new(u64::MAX - 1, u64::MAX);
	source.destination.identity = LinuxFileIdentity::new(u64::MAX, u64::MAX);
	source.stream.identity = LinuxFileIdentity::new(u64::MAX, u64::MAX - 1);
	source.stream.length = StreamLength::new(MAX_FILE_LENGTH).unwrap();
	let private = CopyReceipt::from_evidence(source, head(u64::MAX, 0x22)).unwrap();
	let receipt = PublicApplyReceipt::new(
		private,
		association(),
		head(u64::MAX - 2, 0x77),
		qualification(),
	)
	.unwrap();
	let encoded = receipt.encode();
	assert!(encoded.len() <= MAX_PUBLIC_APPLY_RECEIPT_BYTES);
	assert_eq!(PublicApplyReceipt::decode(&encoded), Ok(receipt));
}
