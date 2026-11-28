use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

use exacopy_endpoint::linux_recovery::ApplyContinuity;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	ApplyIntentEvidence, ApprovedPublicPlanDigest, DurabilityRecorded, LinuxFileIdentity,
	LinuxPublicationBarriers, MetadataRecorded, OwnerDigest, OwnerTimestamp,
	PublicApplyAssociation, PublicApplyIntent, PublicPlanEntryId, PublicationOutcome,
	PublicationPrimitive, PublishIntent, PublishIntentContext, PublishIntentTarget,
	PublishObserved, ReceiptCommitted, VerificationRecorded,
};
use exacopy_transfer::linux::{
	CopyReceipt, JournalBoundary, JournalTail, LocalCopyPlan, PublicApplyArchivedPhase,
	PublicApplyAssessment, PublicApplyCurrentName, PublicApplyHistory, PublicApplyReceipt,
	PublicApplyReceiptObservation, PublicApplyReconcileSelection, PublicApplyReconciliation,
	ReceiptEvidence,
};

use super::{APPROVED, CopyRoots, Fixture, reconcile_public_apply};

pub(super) fn assert_archived_terminal(
	fixture: &Fixture,
	roots: CopyRoots<'_>,
	selected: PublicApplyReconcileSelection<'_, '_, '_>,
	plan: &LocalCopyPlan<'_>,
	owner: OwnerDigest,
	intent_time: OwnerTimestamp,
	scratch: &mut [u8],
) {
	let attempt = plan.attempt();
	let journal_path = fixture.journal(attempt);
	let stage_path = fixture.stage(attempt);
	let stage = fs::symlink_metadata(&stage_path).unwrap();
	let source = fs::symlink_metadata(fixture.source()).unwrap();
	let directory = fs::symlink_metadata(stage_path.parent().unwrap()).unwrap();
	let stage_directory = LinuxFileIdentity::new(directory.dev(), directory.ino());
	let prefix = fs::read(&journal_path).unwrap();
	let (terminal, suffix, receipt) = terminal_fixture(
		&prefix,
		plan,
		&selected,
		owner,
		intent_time,
		stage_directory,
	);
	let receipts = fixture.job(attempt).join("receipts");
	let receipt_path = receipts.join("receipt.cbor");
	// Only this fixture plants the terminal history. The stage remains private.
	// These frames model an archive, not evidence of an exercised publish path.
	DirBuilder::new().mode(0o700).create(&receipts).unwrap();
	{
		let mut file = OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(&receipt_path)
			.unwrap();
		file.write_all(&receipt).unwrap();
	}
	{
		let mut file = OpenOptions::new().append(true).open(&journal_path).unwrap();
		file.write_all(&suffix).unwrap();
	}
	let journal = fs::symlink_metadata(&journal_path).unwrap();
	let receipt_file = fs::symlink_metadata(&receipt_path).unwrap();
	let PublicApplyReconciliation::Authenticated { evidence, history } =
		reconcile_public_apply(roots.destination, None, selected, scratch).unwrap()
	else {
		panic!("expected authenticated terminal archive");
	};
	assert_eq!(evidence.owner_digest, owner);
	assert_eq!(evidence.private_plan, plan.digest());
	assert!(matches!(
		*history,
		PublicApplyHistory::Journal {
			boundary,
			tail: JournalTail::Clean,
			phase: PublicApplyArchivedPhase::ReceiptCommitted,
			continuity: ApplyContinuity::Unqualified,
			stage: PublicApplyCurrentName::RecordedIdentityNumbersUnverified,
			target: PublicApplyCurrentName::Absent,
			receipt: PublicApplyReceiptObservation::MatchesCommit,
			assessment: PublicApplyAssessment::NeedsReconciliation,
		} if boundary == terminal
	));
	for (path, original) in [
		(stage_path.as_path(), stage),
		(journal_path.as_path(), journal),
		(receipt_path.as_path(), receipt_file),
	] {
		let after = fs::symlink_metadata(path).unwrap();
		assert_eq!(
			(after.dev(), after.ino(), after.len()),
			(original.dev(), original.ino(), original.len())
		);
		assert_eq!(
			(after.atime(), after.atime_nsec()),
			(original.atime(), original.atime_nsec())
		);
	}
	let after = fs::symlink_metadata(fixture.source()).unwrap();
	assert_eq!(
		(
			source.dev(),
			source.ino(),
			source.atime(),
			source.atime_nsec()
		),
		(after.dev(), after.ino(), after.atime(), after.atime_nsec())
	);
	assert_eq!(
		fs::read(&journal_path).unwrap(),
		[prefix.as_slice(), suffix.as_slice()].concat()
	);
	assert_eq!(fs::read(receipt_path).unwrap(), receipt);
	assert_eq!(fs::read(fixture.source()).unwrap(), APPROVED);
	assert_eq!(fs::read(stage_path).unwrap(), APPROVED);
	assert!(!fixture.target().try_exists().unwrap());
}

fn terminal_fixture(
	prefix: &[u8],
	plan: &LocalCopyPlan<'_>,
	selected: &PublicApplyReconcileSelection<'_, '_, '_>,
	owner: OwnerDigest,
	intent_time: OwnerTimestamp,
	stage_directory: LinuxFileIdentity,
) -> (JournalBoundary, Vec<u8>, Vec<u8>) {
	let mut reader = FrameReader::new(prefix, ChainHead::start());
	let mut verification_frame = None;
	let mut metadata_frame = None;
	while let Some(frame) = reader.next_frame().unwrap() {
		match frame.kind() {
			FrameKind::VerificationRecorded => assert!(verification_frame.replace(frame).is_none()),
			FrameKind::MetadataRecorded => assert!(metadata_frame.replace(frame).is_none()),
			_ => {}
		}
	}
	let verification_frame = verification_frame.unwrap();
	let metadata_frame = metadata_frame.unwrap();
	assert_eq!(reader.head(), metadata_frame.head());
	assert_eq!(reader.offset(), u64::try_from(prefix.len()).unwrap());
	let measured = VerificationRecorded::from_frame(&verification_frame).unwrap();
	let metadata = MetadataRecorded::from_frame(&metadata_frame).unwrap();
	let context = plan.context();
	let entry = plan.attempt().entry;
	let stage = measured.stage();
	assert_eq!(metadata.stage, stage.identity);
	let destination = plan.destination();
	let effect = PublishIntentContext {
		job: context.job,
		epoch: context.epoch,
		entry,
		effect_sequence: 1,
		plan_digest: context.plan_digest,
	};
	let association = PublicApplyAssociation {
		owner_digest: owner,
		public_plan: ApprovedPublicPlanDigest::from_bytes(selected.approved.body().digest()),
		public_entry: PublicPlanEntryId::from_bytes(*selected.approved.entry().entry_id.as_bytes())
			.unwrap(),
	};
	let intent = PublicApplyIntent::new(
		PublishIntent {
			context: effect,
			target: PublishIntentTarget {
				stage: stage.identity,
				parent: destination.root.identity,
				component: destination.component,
				verification_digest: measured.record_digest(),
				primitive: PublicationPrimitive::LinuxRenameNoReplace,
			},
		},
		association,
		ApplyIntentEvidence {
			verification: verification_frame.head(),
			metadata: metadata_frame.head(),
			qualification: selected.qualification,
			intent_time,
		},
	)
	.unwrap();
	let mut suffix = FrameWriter::new(Vec::new(), metadata_frame.head());
	let intent_head = suffix
		.append(FrameKind::PublishIntent, &intent.encode())
		.unwrap();
	let observed = PublishObserved::new(
		effect,
		intent_head,
		PublicationOutcome::Published {
			target: stage.identity,
		},
	)
	.unwrap();
	let observed_head = suffix
		.append(FrameKind::PublishObserved, &observed.encode())
		.unwrap();
	let durable = DurabilityRecorded::new(
		effect,
		observed_head,
		LinuxPublicationBarriers {
			metadata: metadata_frame.head(),
			stage_directory,
			destination_directory: destination.root.identity,
		},
	)
	.unwrap();
	let durability_head = suffix
		.append(FrameKind::DurabilityRecorded, &durable.encode())
		.unwrap();
	let expected = ReceiptEvidence {
		context,
		entry,
		source: measured.source().identity,
		destination: destination.root,
		target: destination.component,
		stream: stage,
	};
	let literal = private_receipt_bytes(expected, durability_head);
	let private = CopyReceipt::decode(&literal).unwrap();
	assert_eq!(private.evidence(), expected);
	assert_eq!(private.durability_frame(), durability_head);
	let receipt = PublicApplyReceipt::new(
		private,
		association,
		intent_head,
		selected.qualification.record,
	)
	.unwrap();
	let committed = ReceiptCommitted::new(effect, receipt.digest(), durability_head).unwrap();
	let head = suffix
		.append(FrameKind::ReceiptCommitted, &committed.encode())
		.unwrap();
	let suffix = suffix.into_inner();
	let offset = u64::try_from(prefix.len() + suffix.len()).unwrap();
	(JournalBoundary { head, offset }, suffix, receipt.encode())
}

// Literal registered v1 inner receipt. Its actual canonical decoder runs before
// the v2 wrapper. No internal production constructor or manifest change is needed.
fn private_receipt_bytes(evidence: ReceiptEvidence<'_>, durability: ChainHead) -> Vec<u8> {
	let mut bytes = vec![0xab, 0, 0x83, 1, 0, 0, 1];
	put_bytes(&mut bytes, evidence.context.job.as_bytes());
	bytes.push(2);
	put_argument(&mut bytes, 0, evidence.context.epoch.get());
	bytes.push(3);
	put_bytes(&mut bytes, evidence.entry.as_bytes());
	bytes.push(4);
	put_bytes(&mut bytes, evidence.context.plan_digest.as_bytes());
	bytes.push(5);
	put_identity(&mut bytes, evidence.source);
	bytes.extend([6, 0x82]);
	put_bytes(&mut bytes, evidence.destination.id.as_bytes());
	put_identity(&mut bytes, evidence.destination.identity);
	bytes.push(7);
	put_bytes(&mut bytes, evidence.target.as_bytes());
	bytes.extend([8, 0x83]);
	put_identity(&mut bytes, evidence.stream.identity);
	put_argument(&mut bytes, 0, evidence.stream.length.get());
	put_bytes(&mut bytes, evidence.stream.digest.as_bytes());
	bytes.extend([9, 0x82]);
	put_argument(&mut bytes, 0, durability.sequence());
	put_bytes(&mut bytes, &durability.digest());
	bytes.extend([10, 1]);
	bytes
}

fn put_identity(out: &mut Vec<u8>, value: LinuxFileIdentity) {
	out.push(0x82);
	put_argument(out, 0, value.device());
	put_argument(out, 0, value.inode());
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
	put_argument(out, 0x40, u64::try_from(value.len()).unwrap());
	out.extend_from_slice(value);
}

fn put_argument(out: &mut Vec<u8>, major: u8, value: u64) {
	if value < 24 {
		out.push(major | u8::try_from(value).unwrap());
	} else if let Ok(value) = u8::try_from(value) {
		out.extend([major | 24, value]);
	} else if let Ok(value) = u16::try_from(value) {
		out.push(major | 25);
		out.extend(value.to_be_bytes());
	} else if let Ok(value) = u32::try_from(value) {
		out.push(major | 26);
		out.extend(value.to_be_bytes());
	} else {
		out.push(major | 27);
		out.extend(value.to_be_bytes());
	}
}
