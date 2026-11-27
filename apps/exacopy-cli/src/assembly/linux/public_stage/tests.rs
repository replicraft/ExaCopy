use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use exacopy_journal::{
	ApprovedPublicPlanDigest, ApprovedStreamDigest, JournalEntryId, JournalEpoch, JournalJobId,
};
use exacopy_transfer::linux::{
	CopyError, InspectionError, JournalTail, PublicApplyStageRequest, PublicStageHistory,
	PublicStageInspection, PublicStageObservation, RecoveryIssue,
};

use super::super::{inspect_recovery, plan_new_file};
use super::{inspect, stage};

mod fixture;

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
