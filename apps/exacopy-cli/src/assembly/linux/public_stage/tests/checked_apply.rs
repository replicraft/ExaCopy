use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::super::reconcile::reconcile_public_apply;
use exacopy_endpoint::linux_recovery::ApplyContinuity;
use exacopy_journal::{
	ApplyCrashProfile, ApplyProcessCrashEnvironment, ApplyQualification, ApplyQualificationDigest,
	OwnerTimestamp, PlanDigest,
};
use exacopy_plan::{PlanBody, UnixTimestamp};
use exacopy_transfer::linux::{CopyProfile, PublicApplyStageRequest};
use exacopy_transfer::linux::{
	InspectionError, JournalTail, PublicApplyArchivedPhase, PublicApplyAssessment,
	PublicApplyCurrentName, PublicApplyHistory, PublicApplyReceiptObservation,
	PublicApplyReconcileSelection, PublicApplyReconciliation, RecoveryProfile,
};
use exacopy_transfer::public_plan::admit_single_file_plan;

use super::super::checked::{
	AppliedPublicPlanError, LiveQualificationError, apply_qualified_public_plan,
};
use super::super::grant::{
	LocalApplyGrantError, LocalApplyHostSelection, LocalApplyIssuer, LocalApplyRootSelection,
};
use super::super::qualification::{
	LocalApplyQualificationEnrollment, QualifiedPublicApplyProposalError,
};
use super::fixture::{APPROVED, Fixture, SOURCE, TARGET, attempt, component};
use super::{CopyRoots, plan_new_file};

mod terminal;

pub(super) fn assert_unenrolled_grant_refused(
	fixture: &Fixture,
	roots: CopyRoots<'_>,
	scratch: &mut [u8],
) {
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
	let seconds = i64::try_from(now.as_secs()).unwrap();
	let observed = UnixTimestamp::new(seconds, now.subsec_nanos()).unwrap();
	let (bundle, selection) = Fixture::plan_at(roots, observed);
	let exported = PlanBody::from_canonical_cbor(bundle.digest(), bundle.canonical_body()).unwrap();
	let expiry = seconds.checked_add(60 * 60).unwrap();
	let mut fields = exported.fields().clone();
	fields.expires_at = Some(UnixTimestamp::new(expiry, 0).unwrap());
	let finite = PlanBody::new(fields).unwrap();
	let approved = admit_single_file_plan(
		finite.canonical_cbor(),
		bundle.canonical_page(),
		exacopy_transfer::public_plan::ExpectedCopyPlan {
			digest: finite.digest(),
			..selection
		},
	)
	.unwrap();
	let name = attempt("unenrolled-checked", 7);
	let private = plan_new_file(roots, name, component(SOURCE), component(TARGET)).unwrap();
	let mut binding = Fixture::binding(&approved, name);
	binding.expires_at = Some(OwnerTimestamp::new(expiry, 0).unwrap());
	let profile = CopyProfile {
		created: OwnerTimestamp::new(seconds, now.subsec_nanos()).unwrap(),
		..fixture.profile()
	};
	let request = PublicApplyStageRequest {
		approved: &approved,
		private_plan: &private,
		binding,
		profile,
	};
	let attestor = ed25519_dalek::SigningKey::from_bytes(&[0x74; 32]).verifying_key();
	let key = profile.signer.verifying_key();
	let path = fixture.source().with_file_name("missing-apply-enrollment");
	let enrollment = LocalApplyQualificationEnrollment {
		record_path: &path,
		record_digest: ApplyQualificationDigest::from_bytes([0x21; 32]),
		attestor_id: [0x71; 16],
		attestor_key: &attestor,
	};
	let source = fs::symlink_metadata(fixture.source()).unwrap();
	let issue = || {
		LocalApplyIssuer::from_host_selection(LocalApplyHostSelection {
			approved_plan: binding.public_plan,
			public_entry: binding.public_entry,
			source: LocalApplyRootSelection {
				alias: roots.source_id,
				identity: private.source().root_identity,
				name: component(SOURCE),
			},
			destination: LocalApplyRootSelection {
				alias: roots.destination_id,
				identity: private.destination().root.identity,
				name: component(TARGET),
			},
			owner_profile: profile.id,
			owner_key: &key,
			enrollment: &enrollment,
			duration: Duration::from_secs(60),
		})
		.unwrap()
		.issue(binding.public_plan, roots, &request)
		.unwrap()
	};
	let grant = issue();
	assert!(matches!(
		apply_qualified_public_plan(
			roots,
			PublicApplyStageRequest { ..request },
			&grant,
			scratch
		),
		Err(AppliedPublicPlanError::Admission(
			LiveQualificationError::Qualification(QualifiedPublicApplyProposalError::Snapshot(_),)
		))
	));
	assert!(matches!(
		apply_qualified_public_plan(
			roots,
			PublicApplyStageRequest { ..request },
			&grant,
			scratch
		),
		Err(AppliedPublicPlanError::Admission(
			LiveQualificationError::Grant(LocalApplyGrantError::Spent,)
		))
	));
	let revoked = issue();
	revoked.revoke();
	assert!(matches!(
		apply_qualified_public_plan(
			roots,
			PublicApplyStageRequest { ..request },
			&revoked,
			scratch
		),
		Err(AppliedPublicPlanError::Admission(
			LiveQualificationError::Grant(LocalApplyGrantError::Revoked,)
		))
	));
	assert!(!path.try_exists().unwrap());
	assert!(!fixture.job(name).try_exists().unwrap());
	assert!(!fixture.target().try_exists().unwrap());
	let after = fs::symlink_metadata(fixture.source()).unwrap();
	assert_eq!((source.dev(), source.ino()), (after.dev(), after.ino()));
	assert_eq!(fs::read(fixture.source()).unwrap(), APPROVED);
	assert_archived_preintent(fixture, roots, request, scratch);
}

fn assert_archived_preintent(
	fixture: &Fixture,
	roots: CopyRoots<'_>,
	request: PublicApplyStageRequest<'_, '_, '_>,
	scratch: &mut [u8],
) {
	let PublicApplyStageRequest {
		approved,
		private_plan,
		profile,
		..
	} = request;
	let attempt = private_plan.attempt();
	let staged = super::super::stage(roots, request, scratch).unwrap();
	let key = profile.signer.verifying_key();
	let source = fs::symlink_metadata(fixture.source()).unwrap();
	let stage = fs::symlink_metadata(fixture.stage(attempt)).unwrap();
	let segment = fs::symlink_metadata(fixture.journal(attempt)).unwrap();
	let selected = || PublicApplyReconcileSelection {
		profile: RecoveryProfile {
			id: profile.id,
			verifying_key: &key,
		},
		approved,
		private_plan: private_plan.digest(),
		destination: private_plan.destination().root,
		job_name: attempt.job_name,
		qualification: ApplyQualification {
			record: ApplyQualificationDigest::from_bytes([0xf1; 32]),
			profile: ApplyCrashProfile::Arm64UbuntuExt4FixtureV1,
			environment: ApplyProcessCrashEnvironment {
				boot_id: [0xf2; 16],
				mount_namespace: 17,
				unique_mount: 29,
				device: private_plan.destination().root.identity.device(),
			},
		},
	};
	// The fixture supplies a finite protected pre-intent cut and no continuity
	// capability. It does not simulate current qualification or a publication.
	let PublicApplyReconciliation::Authenticated { evidence, history } =
		reconcile_public_apply(roots.destination, None, selected(), scratch).unwrap()
	else {
		panic!("expected authenticated pre-intent observations");
	};
	assert_eq!(evidence.owner_digest, staged.owner_digest);
	assert!(matches!(*history, PublicApplyHistory::Journal {
		phase: PublicApplyArchivedPhase::PreIntent,
		tail: JournalTail::Clean,
		continuity: ApplyContinuity::Unqualified,
		stage: PublicApplyCurrentName::RecordedIdentityNumbersUnverified,
		target: PublicApplyCurrentName::Absent,
		receipt: PublicApplyReceiptObservation::Absent,
		assessment: PublicApplyAssessment::PreIntent,
		boundary,
	} if boundary.offset == segment.len()));
	let mut wrong = selected();
	wrong.private_plan = PlanDigest::from_bytes([0xf3; 32]);
	assert!(matches!(
		reconcile_public_apply(roots.destination, None, wrong, scratch),
		Err(InspectionError::OwnerBinding)
	));
	let after = fs::symlink_metadata(fixture.stage(attempt)).unwrap();
	assert_eq!(
		(stage.dev(), stage.ino(), stage.atime(), stage.atime_nsec()),
		(after.dev(), after.ino(), after.atime(), after.atime_nsec())
	);
	let after = fs::symlink_metadata(fixture.source()).unwrap();
	assert_eq!((source.dev(), source.ino()), (after.dev(), after.ino()));
	assert_eq!(fs::read(fixture.stage(attempt)).unwrap(), APPROVED);
	assert_eq!(fs::read(fixture.source()).unwrap(), APPROVED);
	assert!(!fixture.target().try_exists().unwrap());
	terminal::assert_archived_terminal(
		fixture,
		roots,
		selected(),
		private_plan,
		staged.owner_digest,
		profile.created,
		scratch,
	);
}
