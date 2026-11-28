use exacopy_journal::frame::{ChainHead, FrameKind, FrameWriter};
use exacopy_journal::{
	ApplyCrashProfile, ApplyIntentEvidence, ApplyProcessCrashEnvironment, ApplyQualification,
	ApplyQualificationDigest, DurabilityRecorded, LinuxFileIdentity, LinuxPublicationBarriers,
	OwnerTimestamp, PublicApplyAssociation, PublicApplyIntent, PublicApplyOwnerRecord,
	PublicationOutcome, PublicationPrimitive, PublishIntent, PublishIntentContext,
	PublishIntentTarget, PublishObserved, ReceiptCommitted, ReceiptDigest, VerificationRecorded,
};

use crate::linux::replay::replay_public_apply;
use crate::linux::{JournalReplayError, JournalTail, LocalCopyPlan};

use super::fixture::{BYTES, STAGE, journal_payloads, owner, plan};

#[test]
fn public_reconciliation_accepts_each_exact_prefix_and_preserves_torn_boundary() {
	let plan = plan();
	let owner = owner(plan);
	let (cuts, qualification) = history(plan, &owner);
	for (index, &end) in cuts.ends.iter().enumerate() {
		let replay = replay_public_apply(&cuts.bytes[..end], &plan, &owner, qualification).unwrap();
		assert_eq!(replay.journal.boundary.offset, end as u64);
		assert_eq!(replay.journal.boundary.head.sequence(), (index + 1) as u64);
		assert_eq!(replay.journal.tail, JournalTail::Clean);
		assert_eq!(replay.journal.intent.is_some(), index >= 5);
		assert_eq!(replay.journal.observation.is_some(), index >= 6);
		assert_eq!(replay.journal.durability.is_some(), index >= 7);
		assert_eq!(replay.journal.receipt.is_some(), index == 8);
		if index >= 2 {
			assert_eq!(replay.seal.unwrap().offset, cuts.ends[2] as u64);
		}
		if index < cuts.ends.len() - 1 {
			let replay =
				replay_public_apply(&cuts.bytes[..end + 1], &plan, &owner, qualification).unwrap();
			assert_eq!(replay.journal.boundary.offset, end as u64);
			assert_eq!(replay.journal.tail, JournalTail::Torn { bytes_read: 1 });
		}
	}
}

#[test]
fn public_reconciliation_refuses_unselected_qualification_and_literal_terminal_trailing_bytes() {
	let plan = plan();
	let owner = owner(plan);
	let (mut cuts, qualification) = history(plan, &owner);
	let foreign = ApplyQualification {
		record: ApplyQualificationDigest::from_bytes([2; 32]),
		..qualification
	};
	assert!(matches!(
		replay_public_apply(cuts.bytes.as_slice(), &plan, &owner, foreign),
		Err(JournalReplayError::RecordBinding {
			kind: FrameKind::PublishIntent
		})
	));
	cuts.bytes.push(cuts.bytes[0]);
	assert!(matches!(
		replay_public_apply(cuts.bytes.as_slice(), &plan, &owner, qualification),
		Err(JournalReplayError::TrailingAfterReceipt)
	));
}

#[test]
fn oversized_torn_history_stops_reading_at_the_public_suffix_bound() {
	let plan = plan();
	let owner = owner(plan);
	let (cuts, qualification) = history(plan, &owner);
	let seal_end = cuts.ends[2];
	let seal = &cuts.bytes[..seal_end];
	let selected = replay_public_apply(seal, &plan, &owner, qualification).unwrap();
	let mut extra = FrameWriter::new(Vec::new(), selected.journal.boundary.head);
	extra
		.append(FrameKind::VerificationRecorded, &[0; 9000])
		.unwrap();
	let extra = extra.into_inner();
	let mut bytes = seal.to_vec();
	bytes.extend_from_slice(&extra[..8192]);
	let mut input = bytes.as_slice();
	assert!(matches!(
		replay_public_apply(&mut input, &plan, &owner, qualification),
		Err(JournalReplayError::PublicSuffixTooLarge)
	));
	assert_eq!(bytes.len() - input.len(), seal_end + 4097);
}

#[test]
fn external_environment_selection_cannot_admit_readable_preintent_names() {
	use super::super::super::public_reconcile::names_selection;

	let plan = plan();
	let owner = owner(plan);
	let (cuts, qualification) = history(plan, &owner);
	let before =
		replay_public_apply(&cuts.bytes[..cuts.ends[4]], &plan, &owner, qualification).unwrap();
	let selected = names_selection(&plan, qualification, &before);
	assert!(selected.candidate.is_some() && selected.required.is_some());
	assert_eq!(selected.environment, None);

	let after =
		replay_public_apply(&cuts.bytes[..cuts.ends[5]], &plan, &owner, qualification).unwrap();
	let selected = names_selection(&plan, qualification, &after);
	let bound = selected.environment.unwrap();
	assert_eq!(bound.boot_id, qualification.environment.boot_id);
	assert_eq!(
		bound.mount_namespace,
		qualification.environment.mount_namespace
	);
	assert_eq!(bound.unique_mount, qualification.environment.unique_mount);
	assert_eq!(bound.device, qualification.environment.device);
}

struct Cuts {
	bytes: Vec<u8>,
	ends: Vec<usize>,
}

fn history(plan: LocalCopyPlan<'_>, owner: &PublicApplyOwnerRecord) -> (Cuts, ApplyQualification) {
	let binding = owner.manifest().binding;
	let target = plan.destination();
	let context = plan.context();
	let entry = plan.attempt().entry;
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	let mut ends = Vec::new();
	let mut length = 0;
	let mut write = |kind, payload: Vec<u8>| {
		let head = writer.append(kind, &payload).unwrap();
		length += exacopy_journal::frame::FRAME_OVERHEAD_BYTES + payload.len();
		ends.push(length);
		head
	};
	let records = journal_payloads(plan, owner, BYTES);
	let verification = VerificationRecorded::decode(&records[3].1).unwrap();
	let heads: Vec<_> = records
		.into_iter()
		.map(|(kind, bytes)| write(kind, bytes))
		.collect();
	let qualification = ApplyQualification {
		record: ApplyQualificationDigest::from_bytes([1; 32]),
		profile: ApplyCrashProfile::Arm64UbuntuExt4FixtureV1,
		environment: ApplyProcessCrashEnvironment {
			boot_id: [1; 16],
			mount_namespace: 2,
			unique_mount: 3,
			device: 7,
		},
	};
	let publication = PublishIntentContext {
		job: context.job,
		epoch: context.epoch,
		entry,
		effect_sequence: 1,
		plan_digest: context.plan_digest,
	};
	let intent = PublicApplyIntent::new(
		PublishIntent {
			context: publication,
			target: PublishIntentTarget {
				stage: STAGE,
				parent: target.root.identity,
				component: target.component,
				verification_digest: verification.record_digest(),
				primitive: PublicationPrimitive::LinuxRenameNoReplace,
			},
		},
		PublicApplyAssociation {
			owner_digest: owner.digest(),
			public_plan: binding.public_plan,
			public_entry: binding.public_entry,
		},
		ApplyIntentEvidence {
			verification: heads[3],
			metadata: heads[4],
			qualification,
			intent_time: OwnerTimestamp::new(1, 1).unwrap(),
		},
	)
	.unwrap();
	let intent = write(FrameKind::PublishIntent, intent.encode());
	let observed = PublishObserved::new(
		publication,
		intent,
		PublicationOutcome::Published { target: STAGE },
	)
	.unwrap();
	let observed = write(FrameKind::PublishObserved, observed.encode());
	let durable = DurabilityRecorded::new(
		publication,
		observed,
		LinuxPublicationBarriers {
			metadata: heads[4],
			stage_directory: LinuxFileIdentity::new(7, 25),
			destination_directory: target.root.identity,
		},
	)
	.unwrap();
	let durable = write(FrameKind::DurabilityRecorded, durable.encode());
	let committed =
		ReceiptCommitted::new(publication, ReceiptDigest::from_bytes([4; 32]), durable).unwrap();
	write(FrameKind::ReceiptCommitted, committed.encode());
	let bytes = writer.into_inner();
	assert_eq!(ends.last(), Some(&bytes.len()));
	(Cuts { bytes, ends }, qualification)
}
