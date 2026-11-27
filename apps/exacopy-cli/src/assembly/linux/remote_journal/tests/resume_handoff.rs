use exacopy_journal::remote_download::finalization_replay::replay_remote_finalization;
use exacopy_platform::linux::RecoveryJob;

use super::super::lease::read_owner;
use super::super::startup::CheckedResumeStartup;
use super::*;

fn observed_job(fixture: &Fixture) -> RecoveryJob<'_> {
	let name = job_name(fixture.job);
	fixture
		.root
		.open_recovery_job(component(name.as_bytes()).unwrap())
		.unwrap()
}

fn checked_startup<'held>(
	fixture: &Fixture,
	job: &'held RecoveryJob<'held>,
) -> CheckedResumeStartup<'held> {
	let lease = job.try_read_lease().unwrap();
	let owner_file = job.open_owner().unwrap();
	let dialect = fixture.activation().dialect;
	let owner = read_owner(&owner_file, &fixture.profile, dialect).unwrap();
	let key = fixture.profile.verification_key();
	let trust = dialect.trust(&owner, fixture.profile.id(), &key).unwrap();
	let mut segment = job.open_first_segment().unwrap();
	let replay = replay_remote_finalization(
		&mut segment,
		&trust,
		fixture.qualification.digest.get(),
		None,
	)
	.unwrap();
	assert!(replay.issue().is_none());
	assert_eq!(replay.boundary().offset, segment.len());
	segment.check_logical_eof().unwrap();
	CheckedResumeStartup::new(lease, owner_file, segment, replay.boundary())
}

#[test]
fn exact_startup_can_take_the_exclusive_writer_when_history_is_unchanged() {
	let fixture = Fixture::new();
	fixture.bootstrap();
	let job = observed_job(&fixture);
	let startup = checked_startup(&fixture, &job);
	let original = fs::read(fixture.segment()).unwrap();
	let resumed =
		RemoteJobLease::open_resumed(&fixture.profile, fixture.job, fixture.activation(), startup)
			.unwrap();
	assert_eq!(resumed.job().identity(), job.identity());
	assert_eq!(fs::read(fixture.segment()).unwrap(), original);
	assert!(!fixture.target().exists());
	assert!(!fixture.stage("capture-1").exists());
}

#[test]
fn a_competing_writer_between_leases_cannot_advance_the_selected_resume() {
	let fixture = Fixture::new();
	fixture.bootstrap();
	let job = observed_job(&fixture);
	let startup = checked_startup(&fixture, &job);
	let name = job_name(fixture.job);
	assert!(matches!(
		fixture
			.root
			.try_recovery_write_lease(component(name.as_bytes()).unwrap(), job.identity()),
		Err(StageError::JobBusy)
	));
	let history = startup.release_for_exclusive();
	let original = fs::read(fixture.segment()).unwrap();
	{
		// Another cooperating writer wins after shared release and commits a
		// legitimate fresh allocation. The original observed files stay pinned.
		let competing =
			RemoteJobLease::open_existing(&fixture.profile, fixture.job, fixture.activation())
				.unwrap();
		let candidate = competing.candidate(component(STAGE).unwrap()).unwrap();
		let mut writer = competing.open_writer(&candidate).unwrap();
		let allocation = writer
			.allocate(&candidate, epoch(1), observation(), NONCE)
			.unwrap();
		drop(allocation);
	}
	let advanced = fs::read(fixture.segment()).unwrap();
	assert!(advanced.starts_with(&original) && advanced.len() > original.len());
	assert!(matches!(
		RemoteJobLease::open_selected_resume(
			&fixture.profile,
			fixture.job,
			fixture.activation(),
			&history
		),
		Err(Error::Binding)
	));
	assert_eq!(fs::read(fixture.segment()).unwrap(), advanced);
	assert!(!fixture.stage("capture-1").exists());
	assert!(!fixture.target().exists());
}

#[test]
fn same_byte_replacements_of_owner_or_journal_refuse_the_selected_resume() {
	for record in ["owner.cbor", "journal/00000000000000000001.exajnl"] {
		let fixture = Fixture::new();
		fixture.bootstrap();
		let job = observed_job(&fixture);
		let history = checked_startup(&fixture, &job).release_for_exclusive();
		let path = fixture.job_path().join(record);
		let bytes = fs::read(&path).unwrap();
		let preserved = path.with_extension("original");
		fs::rename(&path, &preserved).unwrap();
		OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(&path)
			.unwrap()
			.write_all(&bytes)
			.unwrap();

		// Both replacements pass ordinary owner/history validation in isolation.
		assert!(
			RemoteJobLease::open_existing(&fixture.profile, fixture.job, fixture.activation(),)
				.is_ok()
		);
		assert!(matches!(
			RemoteJobLease::open_selected_resume(
				&fixture.profile,
				fixture.job,
				fixture.activation(),
				&history
			),
			Err(Error::Binding)
		));
		assert_eq!(fs::read(&path).unwrap(), bytes);
		assert_eq!(fs::read(&preserved).unwrap(), bytes);
		assert!(!fixture.stage("capture-1").exists());
		assert!(!fixture.target().exists());
	}
}

#[test]
fn a_fresh_signed_job_at_the_same_name_cannot_replace_the_selected_resume() {
	let fixture = Fixture::new();
	fixture.bootstrap();
	let job = observed_job(&fixture);
	let history = checked_startup(&fixture, &job).release_for_exclusive();
	let retained_path = fixture.job_path().with_extension("original");
	fs::rename(fixture.job_path(), &retained_path).unwrap();
	fixture.bootstrap();
	let reopened = observed_job(&fixture);
	assert_ne!(job.identity(), reopened.identity());
	assert!(
		RemoteJobLease::open_existing(&fixture.profile, fixture.job, fixture.activation(),).is_ok()
	);
	let replacement = fs::read(fixture.segment()).unwrap();
	assert!(matches!(
		RemoteJobLease::open_selected_resume(
			&fixture.profile,
			fixture.job,
			fixture.activation(),
			&history
		),
		Err(Error::Binding)
	));
	assert_eq!(fs::read(fixture.segment()).unwrap(), replacement);
	assert!(retained_path.is_dir());
	assert!(!fixture.stage("capture-1").exists());
	assert!(!fixture.target().exists());
}
