use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::{
	ApplyCrashProfile, ApplyProcessCrashEnvironment, ApplyQualification, ApplyQualificationDigest,
	ApprovedPublicPlanDigest, ApprovedStreamDigest, JournalEntryId, JournalEpoch, JournalJobId,
	LinuxFileIdentity, OwnerToken, PublicApplyIntent,
};
use exacopy_platform::linux::StageError;
use exacopy_transfer::linux::{
	CopyError, CopyProfile, InspectionError, JournalTail, PublicApplyIntentObservation,
	PublicApplyIntentSelection, PublicApplyStageRequest, PublicStageHistory, PublicStageInspection,
	PublicStageObservation, RecoveryIssue, stage_public_apply_and_propose_intent,
};

use super::super::{CopyRoots, inspect_recovery, plan_new_file};
use super::{inspect, stage};

mod checked_apply;
#[path = "../../../../verification/public_stage_ext4/checked_component.rs"]
mod checked_component;
mod fixture;
mod late_journal;

use fixture::{Fixture, SOURCE, TARGET, attempt, component};

#[test]
#[ignore = "requires the task-owned unprivileged whole-ext4 public-stage fixture"]
fn approved_stage_reopens_with_exact_owner_and_preserves_uncertain_evidence() {
	let fixture = Fixture::new();
	let (source_root, destination) = fixture.open_roots();
	let roots = Fixture::roots(&source_root, &destination);
	let (bundle, selection) = Fixture::plan(roots);
	let approved = exacopy_transfer::public_plan::admit_single_file_plan(
		bundle.canonical_body(),
		bundle.canonical_page(),
		selection,
	)
	.unwrap();
	let original = attempt("original-stage", 1);
	let private = plan_new_file(roots, original, component(SOURCE), component(TARGET)).unwrap();
	let binding = Fixture::binding(&approved, original);
	assert_eq!(
		binding.stream_digest,
		ApprovedStreamDigest::from_bytes(*blake3::hash(fixture::APPROVED).as_bytes())
	);
	let mut scratch = fixture::buffer();
	let profile = fixture.profile();
	let request = PublicApplyStageRequest {
		approved: &approved,
		private_plan: &private,
		binding,
		profile,
	};
	assert!(matches!(
		stage(
			roots,
			PublicApplyStageRequest {
				binding: exacopy_journal::PublicApplyBinding {
					public_plan: ApprovedPublicPlanDigest::from_bytes([0; 32]),
					..binding
				},
				..request
			},
			&mut scratch
		),
		Err(CopyError::StalePlan)
	));
	assert!(!fixture.job(original).try_exists().unwrap());
	assert_missing_qualification_refuses(&fixture, roots, &request, &mut scratch);
	checked_apply::assert_unenrolled_grant_refused(&fixture, roots, &mut scratch);
	assert_proposal_uses_held_stage(&fixture, roots, &request, &mut scratch);
	late_journal::assert_late_readback_refusal(&fixture, roots, &request, &mut scratch);
	let staged = stage(roots, PublicApplyStageRequest { ..request }, &mut scratch).unwrap();
	let original_stage = fixture.stage(original);
	let journal = fixture.journal(original);
	let journal_before = fs::read(&journal).unwrap();

	// Reopen independently after all handles from the staging invocation are gone.
	drop(destination);
	let destination = fixture.open_destination();
	let recovery = fixture.recovery();
	let (evidence, boundary) =
		match inspect(&destination, original.job_name, recovery, &mut scratch).unwrap() {
			PublicStageInspection::Authenticated {
				evidence,
				history:
					PublicStageHistory::Journal {
						boundary,
						tail: JournalTail::Clean,
						observation: PublicStageObservation::RetainedVerifiedStage,
					},
			} => (evidence, boundary),
			other => panic!("unexpected public stage observation: {other:?}"),
		};
	assert_eq!(evidence.owner_digest, staged.owner_digest);
	assert_eq!(evidence.private_plan, private.context().plan_digest);
	assert_eq!(evidence.binding, binding);
	assert_eq!(fs::read(&original_stage).unwrap(), fixture::APPROVED);
	assert!(!fixture.target().try_exists().unwrap());
	assert_eq!(fs::read(&journal).unwrap(), journal_before);
	assert!(matches!(
		inspect(
			&destination,
			original.job_name,
			fixture.wrong_recovery(),
			&mut scratch
		),
		Err(InspectionError::Owner(_))
	));
	assert!(matches!(
		inspect_recovery(&destination, original.job_name, recovery, &mut scratch),
		Err(InspectionError::Owner(_))
	));

	// A fresh private observation can match a changed file's identity and length,
	// while both measured streams still disagree with the original public approval.
	let source = fixture.source();
	let identity = fs::metadata(&source).unwrap().ino();
	fs::write(&source, fixture::CHANGED).unwrap();
	assert_eq!(fs::metadata(&source).unwrap().ino(), identity);
	let roots = Fixture::roots(&source_root, &destination);
	let changed = attempt("changed-stage", 2);
	let private_changed =
		plan_new_file(roots, changed, component(SOURCE), component(TARGET)).unwrap();
	assert!(matches!(
		stage(
			roots,
			PublicApplyStageRequest {
				private_plan: &private_changed,
				binding: Fixture::binding(&approved, changed),
				..request
			},
			&mut scratch
		),
		Err(CopyError::StalePlan)
	));
	assert_eq!(fs::read(fixture.stage(changed)).unwrap(), fixture::CHANGED);
	assert!(matches!(
		inspect(&destination, changed.job_name, recovery, &mut scratch).unwrap(),
		PublicStageInspection::Authenticated {
			history: PublicStageHistory::Journal {
				observation: PublicStageObservation::RetainedPartialStage,
				..
			},
			..
		}
	));
	assert!(!fixture.target().try_exists().unwrap());

	// A fixture-owned partial write simulates a torn suffix without enabling
	// any recovery mutation. The accepted boundary and both streams persist.
	let mut file = OpenOptions::new().append(true).open(&journal).unwrap();
	file.write_all(&journal_before[..1]).unwrap();
	file.sync_all().unwrap();
	drop(file);
	let torn = fs::read(&journal).unwrap();
	assert!(matches!(
		inspect(&destination, original.job_name, recovery, &mut scratch).unwrap(),
		PublicStageInspection::Authenticated {
			history: PublicStageHistory::Journal {
				boundary: accepted,
				tail,
				observation: PublicStageObservation::RequiresReconciliation(RecoveryIssue::TornJournal),
			},
			..
		} if accepted == boundary && tail != JournalTail::Clean
	));
	let late = attempt("occupied-target", 3);
	let private_late = plan_new_file(roots, late, component(SOURCE), component(TARGET)).unwrap();
	fs::write(fixture.target(), fixture::INCUMBENT).unwrap();
	fs::set_permissions(fixture.target(), fs::Permissions::from_mode(0o600)).unwrap();
	let incumbent_inode = fs::metadata(fixture.target()).unwrap().ino();
	assert!(matches!(
		stage(
			roots,
			PublicApplyStageRequest {
				private_plan: &private_late,
				binding: Fixture::binding(&approved, late),
				..request
			},
			&mut scratch
		),
		Err(CopyError::Conflict)
	));
	assert!(!fixture.job(late).try_exists().unwrap());
	assert!(matches!(
		inspect(&destination, original.job_name, recovery, &mut scratch).unwrap(),
		PublicStageInspection::Authenticated {
			history: PublicStageHistory::Journal {
				observation: PublicStageObservation::UnexpectedTarget,
				..
			},
			..
		}
	));
	assert_eq!(
		fs::metadata(fixture.target()).unwrap().ino(),
		incumbent_inode
	);
	assert_eq!(fs::read(fixture.target()).unwrap(), fixture::INCUMBENT);
	assert_eq!(fs::read(&journal).unwrap(), torn);
	assert_eq!(fs::read(original_stage).unwrap(), fixture::APPROVED);
	assert_eq!(fs::read(source).unwrap(), fixture::CHANGED);
	drop(destination);
	drop(source_root);
	fixture.finish();
	checked_component::exercise();
	println!("EXACOPY_PUBLIC_STAGE_EXT4_RESULT preserved_and_cleaned");
}

fn assert_missing_qualification_refuses(
	fixture: &Fixture,
	roots: CopyRoots<'_>,
	request: &PublicApplyStageRequest<'_, '_, '_>,
	scratch: &mut [u8],
) {
	use super::qualification::{
		LocalApplyQualificationEnrollment, QualifiedPublicApplyProposalError,
		stage_qualified_public_apply,
	};

	let path = fixture
		.source()
		.with_file_name("absent-local-qualification");
	let attestor = ed25519_dalek::SigningKey::from_bytes(&[0x56; 32]).verifying_key();
	let enrollment = LocalApplyQualificationEnrollment {
		record_path: &path,
		record_digest: ApplyQualificationDigest::from_bytes([0x64; 32]),
		attestor_id: [0x58; 16],
		attestor_key: &attestor,
	};
	let source = fs::symlink_metadata(fixture.source()).unwrap();
	assert!(!path.try_exists().unwrap());
	assert!(matches!(
		stage_qualified_public_apply(
			roots,
			&enrollment,
			PublicApplyStageRequest { ..*request },
			scratch,
		),
		Err(QualifiedPublicApplyProposalError::Snapshot(_))
	));
	assert!(!path.try_exists().unwrap());
	assert!(
		!fixture
			.job(request.private_plan.attempt())
			.try_exists()
			.unwrap()
	);
	assert!(!fixture.target().try_exists().unwrap());
	let after = fs::symlink_metadata(fixture.source()).unwrap();
	assert_eq!((source.dev(), source.ino()), (after.dev(), after.ino()));
	assert_eq!(fs::read(fixture.source()).unwrap(), fixture::APPROVED);
}

fn assert_proposal_uses_held_stage(
	fixture: &Fixture,
	roots: CopyRoots<'_>,
	request: &PublicApplyStageRequest<'_, '_, '_>,
	scratch: &mut [u8],
) {
	let attempt = attempt("proposed-stage", 4);
	let private_plan = plan_new_file(roots, attempt, component(SOURCE), component(TARGET)).unwrap();
	let binding = Fixture::binding(request.approved, attempt);
	let request = PublicApplyStageRequest {
		private_plan: &private_plan,
		binding,
		profile: CopyProfile {
			owner_token: OwnerToken::from_bytes([10; 16]).unwrap(),
			..request.profile
		},
		..*request
	};
	let qualification = fixture_qualification(private_plan.source().root_identity.device());
	let observation = PublicApplyIntentObservation {
		now: request.profile.created,
		profile: qualification.profile,
		environment: qualification.environment,
	};
	let mut observations = 0;
	let mut held_stage = None;
	let intent = stage_public_apply_and_propose_intent(
		roots,
		request,
		PublicApplyIntentSelection {
			approved_plan: binding.public_plan,
			qualification,
		},
		scratch,
		|_| {},
		|| {
			match observations {
				0 => assert!(!fixture.job(attempt).try_exists().unwrap()),
				1 => {
					let job = roots
						.destination
						.open_recovery_job(attempt.job_name)
						.unwrap();
					assert!(matches!(job.try_read_lease(), Err(StageError::JobBusy)));
					let stage = fs::metadata(fixture.stage(attempt)).unwrap();
					held_stage = Some(LinuxFileIdentity::new(stage.dev(), stage.ino()));
				}
				_ => panic!("unexpected extra proposal observation"),
			}
			observations += 1;
			Some(observation)
		},
	)
	.unwrap();
	assert_eq!(observations, 2);
	assert_eq!(held_stage, Some(intent.private().target.stage));

	let bytes = fs::read(fixture.journal(attempt)).unwrap();
	let mut frames = FrameReader::new(bytes.as_slice(), ChainHead::start());
	let mut accepted = Vec::new();
	while let Some(frame) = frames.next_frame().unwrap() {
		accepted.push((frame.kind(), frame.head()));
	}
	let [
		..,
		(FrameKind::StageSealed, _),
		(FrameKind::VerificationRecorded, verification),
		(FrameKind::MetadataRecorded, metadata),
	] = accepted.as_slice()
	else {
		panic!("expected a clean verified stage prefix ending at metadata");
	};
	assert!(
		!accepted
			.iter()
			.any(|(kind, _)| *kind == FrameKind::PublishIntent)
	);
	assert_eq!(intent.evidence().verification, *verification);
	assert_eq!(intent.evidence().metadata, *metadata);
	assert_eq!(PublicApplyIntent::decode(&intent.encode()).unwrap(), intent);
	let stage = fixture.stage(attempt);
	let physical = fs::metadata(&stage).unwrap();
	assert_eq!(
		intent.private().target.stage,
		LinuxFileIdentity::new(physical.dev(), physical.ino())
	);
	assert_eq!(fs::read(stage).unwrap(), fixture::APPROVED);
	assert!(!fixture.target().try_exists().unwrap());
	let job = roots
		.destination
		.open_recovery_job(attempt.job_name)
		.unwrap();
	assert!(job.try_read_lease().is_ok());
}

fn fixture_qualification(device: u64) -> ApplyQualification {
	// The proposal compares these fixture claims. This test does not qualify publication.
	ApplyQualification {
		record: ApplyQualificationDigest::from_bytes([0x44; 32]),
		profile: ApplyCrashProfile::Arm64UbuntuExt4FixtureV1,
		environment: ApplyProcessCrashEnvironment {
			boot_id: [0x55; 16],
			mount_namespace: 1,
			unique_mount: 2,
			device,
		},
	}
}

fn synthetic_job(marker: u8) -> (JournalJobId, JournalEntryId, JournalEpoch) {
	let mut job = *uuid::uuid!("019a0000-0000-7000-8000-000000000003").as_bytes();
	job[15] = marker;
	(
		JournalJobId::from_bytes(job).unwrap(),
		JournalEntryId::from_bytes([marker; 16]),
		JournalEpoch::new(1),
	)
}
