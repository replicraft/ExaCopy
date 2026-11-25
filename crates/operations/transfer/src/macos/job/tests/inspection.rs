use super::*;
use crate::macos::inspection::{
	DarwinInspectionAuthority, DarwinInspectionError, DarwinReceiptArtifact, inspect_job,
};
use crate::macos::replay::{DarwinJournalTail, DarwinReplayStatus};

#[test]
fn reopened_job_binds_trusted_destination_and_keeps_live_names_separate_from_history() {
	let fixture = Fixture::new();
	let root = fixture.root();
	let source = fixture.source(&root);
	let container = root.open_stage_directory(component(PRIVATE)).unwrap();
	let signer = SigningKey::from_bytes(&[4; 32]);
	let request = fixture.request(&source, &container, &signer);
	let plan = fixture.plan(&root, request);
	let name = JobName::from_uuid_bytes(*plan.attempt().job.as_bytes()).unwrap();
	let path = fixture.0.join(PRIVATE).join(name.to_string());
	let destination = admit_destination(plan.destination(), request).unwrap();
	let stage = with_admitted_job(&plan, request, name, destination, |job| {
		job.with_admitted_entry(|entry| entry.preparation().preparation().stage.identity)
			.unwrap()
	})
	.unwrap();
	let journal_before = fs::read(path.join(FIRST_SEGMENT)).unwrap();
	let incumbent = b"existing public contents";
	fs::write(fixture.0.join(TARGET), incumbent).unwrap();

	let recovery = container.open_recovery_job(name).unwrap();
	let authority = DarwinInspectionAuthority {
		profile: request.profile.id,
		key: &signer.verifying_key(),
		destination_root: request.destination_root_id,
	};
	let inspected = inspect_job(&recovery, authority).unwrap();
	assert_eq!(inspected.plan_bytes, plan.encode());
	assert_eq!(inspected.replay.status(), DarwinReplayStatus::Incomplete);
	assert_eq!(inspected.replay.tail(), DarwinJournalTail::Clean);
	assert_eq!(
		inspected.replay.boundary().offset,
		u64::try_from(journal_before.len()).unwrap()
	);
	assert_eq!(inspected.receipt, DarwinReceiptArtifact::Missing);
	assert!(inspected.stage_directory.is_some());
	let observed_stage = inspected.stage.unwrap();
	assert_eq!(native_identity(observed_stage.identity()).unwrap(), stage);
	assert_eq!(observed_stage.length(), 0);
	assert_eq!(
		inspected.target.unwrap().length(),
		u64::try_from(incumbent.len()).unwrap()
	);

	assert!(matches!(
		inspect_job(
			&recovery,
			DarwinInspectionAuthority {
				destination_root: root_id([11; 16]),
				..authority
			}
		),
		Err(DarwinInspectionError::PlanBinding)
	));
	assert!(matches!(
		inspect_job(
			&recovery,
			DarwinInspectionAuthority {
				key: &SigningKey::from_bytes(&[5; 32]).verifying_key(),
				..authority
			}
		),
		Err(DarwinInspectionError::Replay(_))
	));
	assert_eq!(fs::read(path.join(FIRST_SEGMENT)).unwrap(), journal_before);
	assert_eq!(fs::read(fixture.0.join(TARGET)).unwrap(), incumbent);
}
