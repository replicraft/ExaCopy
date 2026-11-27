use std::num::NonZeroU64;

use exacopy_journal::remote_download::RemoteEpochs;
use exacopy_journal::remote_download::finalization_replay::replay_remote_finalization;

use super::super::ResumeCapacity;
use super::super::lease::read_owner;
use super::super::startup::{check_capacity, check_resume_startup};
use super::*;

fn observe_startup(fixture: &Fixture) -> Result<(), Error> {
	let name = job_name(fixture.job);
	let job = fixture
		.root
		.open_recovery_job(component(name.as_bytes()).unwrap())
		.unwrap();
	let _lease = job.try_read_lease().unwrap();
	let dialect = fixture.activation().dialect;
	let owner = read_owner(&job.open_owner().unwrap(), &fixture.profile, dialect).unwrap();
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
	check_resume_startup(&job, component(TARGET).unwrap(), &replay)
}

fn append_unbound_allocations(lease: &RemoteJobLease<'_>, numbers: std::ops::RangeInclusive<u8>) {
	let name = format!("capture-{}", numbers.start());
	let first = lease
		.candidate(component(name.as_bytes()).unwrap())
		.unwrap();
	let mut writer = lease.open_writer(&first).unwrap();
	for number in numbers {
		let name = format!("capture-{number}");
		let candidate = lease
			.candidate(component(name.as_bytes()).unwrap())
			.unwrap();
		let allocation = writer
			.allocate(
				&candidate,
				epoch(u64::from(number)),
				observation(),
				[number; 16],
			)
			.unwrap();
		drop(allocation);
	}
}

#[test]
fn signed_startup_accepts_sixty_three_allocations_and_refuses_sixty_four() {
	let fixture = Fixture::new();
	append_unbound_allocations(&fixture.open_bootstrap(fixture.bootstrap()), 1..=63);
	assert!(observe_startup(&fixture).is_ok());
	{
		let lease =
			RemoteJobLease::open_existing(&fixture.profile, fixture.job, fixture.activation())
				.unwrap();
		append_unbound_allocations(&lease, 64..=64);
	}
	let journal = fs::read(fixture.segment()).unwrap();
	assert!(matches!(
		observe_startup(&fixture),
		Err(Error::ResumeCapacity(ResumeCapacity::AllocationsExhausted))
	));
	assert_eq!(fs::read(fixture.segment()).unwrap(), journal);
	assert!(!fixture.target().exists());
	assert_eq!(
		fs::read_dir(fixture.job_path().join("stage"))
			.unwrap()
			.count(),
		0
	);
}

#[test]
fn source_or_run_epoch_exhaustion_has_its_own_typed_refusal() {
	for epochs in [
		RemoteEpochs {
			run: NonZeroU64::MIN,
			source: NonZeroU64::MAX,
		},
		RemoteEpochs {
			run: NonZeroU64::MAX,
			source: NonZeroU64::MIN,
		},
	] {
		assert_eq!(
			check_capacity(1, Some(epochs)),
			Err(ResumeCapacity::EpochsExhausted)
		);
	}
}

#[test]
fn clean_startup_refuses_orphan_files_at_unbound_allocations() {
	let fixture = Fixture::new();
	append_unbound_allocations(&fixture.open_bootstrap(fixture.bootstrap()), 1..=2);
	assert!(observe_startup(&fixture).is_ok());
	let orphan = fixture.stage("capture-1");
	fs::write(&orphan, b"unbound local evidence").unwrap();
	let journal = fs::read(fixture.segment()).unwrap();
	assert!(matches!(
		observe_startup(&fixture),
		Err(Error::UnknownStage)
	));
	assert_eq!(fs::read(&orphan).unwrap(), b"unbound local evidence");
	assert_eq!(fs::read(fixture.segment()).unwrap(), journal);
	assert!(!fixture.target().exists());
}

#[test]
fn clean_startup_checks_superseded_stage_identity_and_extent() {
	let fixture = Fixture::new();
	{
		let lease = fixture.open_bootstrap(fixture.bootstrap());
		let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
		let mut writer = lease.open_writer(&candidate).unwrap();
		let mut allocation = writer
			.allocate(&candidate, epoch(1), observation(), NONCE)
			.unwrap();
		drop(allocation.create(&mut writer).unwrap());
	}
	{
		let lease =
			RemoteJobLease::open_existing(&fixture.profile, fixture.job, fixture.activation())
				.unwrap();
		append_unbound_allocations(&lease, 2..=2);
	}
	assert!(observe_startup(&fixture).is_ok());
	let original = fixture.stage("capture-1");
	OpenOptions::new()
		.write(true)
		.open(&original)
		.unwrap()
		.set_len(LENGTH + 1)
		.unwrap();
	assert!(matches!(
		observe_startup(&fixture),
		Err(Error::UnknownStage)
	));
	let preserved = fixture.stage("prior");
	fs::rename(&original, &preserved).unwrap();
	fs::write(&original, b"replacement").unwrap();
	let journal = fs::read(fixture.segment()).unwrap();
	assert!(matches!(
		observe_startup(&fixture),
		Err(Error::UnknownStage)
	));
	assert_eq!(fs::read(original).unwrap(), b"replacement");
	assert_eq!(fs::metadata(preserved).unwrap().len(), LENGTH + 1);
	assert_eq!(fs::read(fixture.segment()).unwrap(), journal);
}

#[test]
fn clean_bootstrap_requires_the_signed_empty_stage_directory() {
	let fixture = Fixture::new();
	fixture.bootstrap();
	assert!(observe_startup(&fixture).is_ok());
	let stage = fixture.job_path().join("stage");
	let preserved = fixture.job_path().join("prior-stage");
	fs::rename(&stage, &preserved).unwrap();
	assert!(matches!(
		observe_startup(&fixture),
		Err(Error::UnknownStage)
	));
	fs::DirBuilder::new().mode(0o700).create(&stage).unwrap();
	assert!(matches!(
		observe_startup(&fixture),
		Err(Error::UnknownStage)
	));
	assert!(preserved.is_dir());
}
