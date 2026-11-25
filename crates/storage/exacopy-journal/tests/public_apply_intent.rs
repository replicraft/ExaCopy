//! Independent canonical and framing controls for kind-7 public apply.

use exacopy_endpoint::{MAX_UNIX_COMPONENT_BYTES, UnixComponent};
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	ApplyCrashProfile, ApplyIntentEvidence, ApplyProcessCrashEnvironment, ApplyQualification,
	ApplyQualificationDigest, ApprovedPublicPlanDigest, JournalEntryId, JournalEpoch, JournalJobId,
	LinuxFileIdentity, MAX_PUBLIC_APPLY_INTENT_BYTES, OwnerDigest, OwnerTimestamp, PlanDigest,
	PublicApplyAssociation, PublicApplyIntent, PublicApplyIntentError, PublicPlanEntryId,
	PublicationPrimitive, PublishIntent, PublishIntentContext, PublishIntentTarget,
	VerificationDigest,
};

fn id(last: u8) -> [u8; 16] {
	[
		0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, last,
	]
}

fn head(sequence: u64, marker: u8) -> ChainHead {
	ChainHead::after(sequence, [marker; 32]).unwrap()
}

fn fields(
	target: &[u8],
) -> (
	PublishIntent<'_>,
	PublicApplyAssociation,
	ApplyIntentEvidence,
) {
	(
		PublishIntent {
			context: PublishIntentContext {
				job: JournalJobId::from_bytes(id(1)).unwrap(),
				epoch: JournalEpoch::new(2),
				entry: JournalEntryId::from_bytes(id(4)),
				effect_sequence: 1,
				plan_digest: PlanDigest::from_bytes([0x11; 32]),
			},
			target: PublishIntentTarget {
				stage: LinuxFileIdentity::new(3, 5),
				parent: LinuxFileIdentity::new(3, 4),
				component: UnixComponent::new(target).unwrap(),
				verification_digest: VerificationDigest::from_bytes([0x91; 32]),
				primitive: PublicationPrimitive::LinuxRenameNoReplace,
			},
		},
		PublicApplyAssociation {
			owner_digest: OwnerDigest::from_bytes([0xa1; 32]),
			public_plan: ApprovedPublicPlanDigest::from_bytes([0xa2; 32]),
			public_entry: PublicPlanEntryId::from_bytes(id(8)).unwrap(),
		},
		ApplyIntentEvidence {
			verification: head(5, 0x55),
			metadata: head(6, 0x66),
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
			intent_time: OwnerTimestamp::new(-1, 800_000_000).unwrap(),
		},
	)
}

fn golden() -> Vec<u8> {
	// Authored independently from the nested v1 and outer v2 field registries.
	include_str!("public_apply_intent.hex")
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

#[test]
fn independently_encoded_vector_has_mandatory_version_and_owner_association() {
	let (private, association, evidence) = fields(b"f\xff");
	let intent = PublicApplyIntent::new(private, association, evidence).unwrap();
	let bytes = golden();
	assert_eq!(intent.encode(), bytes);
	let decoded = PublicApplyIntent::decode(&bytes).unwrap();
	assert_eq!(*decoded.private(), private);
	assert_eq!(decoded.association(), association);
	assert_eq!(decoded.evidence(), evidence);
	assert!(PublishIntent::decode(&bytes).is_err());
	assert!(PublicApplyIntent::decode(&private.encode()).is_err());
}

#[test]
fn enclosing_kind_and_exact_predecessor_are_required() {
	let (private, association, evidence) = fields(b"f\xff");
	let encoded = PublicApplyIntent::new(private, association, evidence)
		.unwrap()
		.encode();
	let mut writer = FrameWriter::new(Vec::new(), evidence.metadata);
	writer.append(FrameKind::PublishIntent, &encoded).unwrap();
	let bytes = writer.into_inner();
	let mut reader = FrameReader::new(bytes.as_slice(), evidence.metadata);
	let frame = reader.next_frame().unwrap().unwrap();
	assert!(PublicApplyIntent::from_frame(&frame).is_ok());
	assert!(PublishIntent::from_frame(&frame).is_err());

	for (anchor, kind, error) in [
		(
			head(6, 0x67),
			FrameKind::PublishIntent,
			PublicApplyIntentError::FrameBinding,
		),
		(
			head(7, 0x66),
			FrameKind::PublishIntent,
			PublicApplyIntentError::FrameBinding,
		),
		(
			evidence.metadata,
			FrameKind::MetadataRecorded,
			PublicApplyIntentError::WrongRecordKind,
		),
	] {
		let mut writer = FrameWriter::new(Vec::new(), anchor);
		writer.append(kind, &encoded).unwrap();
		let bytes = writer.into_inner();
		let frame = FrameReader::new(bytes.as_slice(), anchor)
			.next_frame()
			.unwrap()
			.unwrap();
		assert_eq!(PublicApplyIntent::from_frame(&frame), Err(error));
	}
}

#[test]
fn refuses_truncation_trailing_and_noncanonical_or_unknown_version() {
	let bytes = golden();
	for position in 0..bytes.len() {
		assert!(PublicApplyIntent::decode(&bytes[..position]).is_err());
	}
	let mut edited = bytes.clone();
	edited.push(0);
	assert_eq!(
		PublicApplyIntent::decode(&edited),
		Err(PublicApplyIntentError::NonCanonical)
	);
	let mut edited = bytes.clone();
	edited.splice(4..5, [0x18, 2]);
	assert_eq!(
		PublicApplyIntent::decode(&edited),
		Err(PublicApplyIntentError::NonCanonical)
	);
	let mut edited = bytes;
	edited[8] = 0;
	assert_eq!(
		PublicApplyIntent::decode(&edited),
		Err(PublicApplyIntentError::UnsupportedVersion)
	);
	assert_eq!(
		PublicApplyIntent::decode(&[0; MAX_PUBLIC_APPLY_INTENT_BYTES + 1]),
		Err(PublicApplyIntentError::Length)
	);
}

#[test]
fn maximum_sized_inner_name_and_profile_fields_fit_fixed_encoding() {
	let component = [0xff; MAX_UNIX_COMPONENT_BYTES];
	let (mut private, association, mut evidence) = fields(&component);
	private.context.epoch = JournalEpoch::new(u64::MAX);
	private.target.stage = LinuxFileIdentity::new(u64::MAX, u64::MAX);
	private.target.parent = LinuxFileIdentity::new(u64::MAX, u64::MAX - 1);
	evidence.qualification.environment.mount_namespace = u64::MAX;
	evidence.qualification.environment.unique_mount = u64::MAX;
	evidence.qualification.environment.device = u64::MAX;
	evidence.verification = head(u64::MAX - 2, 0x55);
	evidence.metadata = head(u64::MAX - 1, 0x66);
	evidence.intent_time = OwnerTimestamp::new(i64::MIN, 999_999_999).unwrap();
	let intent = PublicApplyIntent::new(private, association, evidence).unwrap();
	let bytes = intent.encode();
	assert!(bytes.len() <= MAX_PUBLIC_APPLY_INTENT_BYTES);
	assert_eq!(PublicApplyIntent::decode(&bytes), Ok(intent));
}

#[test]
fn typed_constructor_rejects_noninitial_effect_and_incompatible_profile_facts() {
	let (private, association, evidence) = fields(b"f\xff");
	for context in [
		PublishIntentContext {
			epoch: JournalEpoch::new(0),
			..private.context
		},
		PublishIntentContext {
			entry: JournalEntryId::from_bytes([0; 16]),
			..private.context
		},
		PublishIntentContext {
			effect_sequence: 2,
			..private.context
		},
	] {
		let changed = PublishIntent { context, ..private };
		assert_eq!(
			PublicApplyIntent::new(changed, association, evidence),
			Err(PublicApplyIntentError::Binding)
		);
	}
	for stage in [private.target.parent, LinuxFileIdentity::new(9, 5)] {
		let target = PublishIntentTarget {
			stage,
			..private.target
		};
		let changed = PublishIntent { target, ..private };
		assert_eq!(
			PublicApplyIntent::new(changed, association, evidence),
			Err(PublicApplyIntentError::Binding)
		);
	}
	let environment = evidence.qualification.environment;
	for invalid in [
		ApplyProcessCrashEnvironment {
			boot_id: [0; 16],
			..environment
		},
		ApplyProcessCrashEnvironment {
			mount_namespace: 0,
			..environment
		},
		ApplyProcessCrashEnvironment {
			unique_mount: 0,
			..environment
		},
		ApplyProcessCrashEnvironment {
			device: 9,
			..environment
		},
	] {
		let mut changed = evidence;
		changed.qualification.environment = invalid;
		assert_eq!(
			PublicApplyIntent::new(private, association, changed),
			Err(PublicApplyIntentError::Binding)
		);
	}
	for (verification, metadata) in [
		(ChainHead::start(), head(1, 0x11)),
		(evidence.verification, head(7, 0x66)),
		(head(u64::MAX - 1, 0x55), head(u64::MAX, 0x66)),
	] {
		let changed = ApplyIntentEvidence {
			verification,
			metadata,
			..evidence
		};
		assert_eq!(
			PublicApplyIntent::new(private, association, changed),
			Err(PublicApplyIntentError::FrameBinding)
		);
	}
}
