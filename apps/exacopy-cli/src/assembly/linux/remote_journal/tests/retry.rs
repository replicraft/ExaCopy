use super::super::{RemoteRetryLease, RetryCaptureStamp, lease::retry::check_capacity};
use super::{
	Error, Fixture, NONCE, RemoteJobLease, RemoteSourceObservation, STAGE, StageError, component,
	epoch, observation,
};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

const PREFIX: &[u8] = b"prefix";
const FRESH: &[u8] = b"capture-2";
const FRESH_NONCE: [u8; 16] = [0x62; 16];

fn stamp(fixture: &Fixture) -> RetryCaptureStamp {
	let lease = fixture.open_bootstrap(fixture.bootstrap());
	let name = component(STAGE).unwrap();
	let candidate = lease.candidate(name).unwrap();
	let mut ledger = lease.open_writer(&candidate).unwrap();
	let mut allocation = ledger
		.allocate(&candidate, epoch(1), observation(), NONCE)
		.unwrap();
	let mut bound = allocation.create(&mut ledger).unwrap();
	bound.writer.write_all_at(0, PREFIX).unwrap();
	drop(bound);
	let extent = PREFIX.len() as u64;
	assert!(matches!(
		ledger.stamp_failed_read(name, epoch(1), extent),
		Err(Error::Native(StageError::JobBusy))
	));
	drop(allocation);
	assert!(matches!(
		ledger.stamp_failed_read(name, epoch(2), extent),
		Err(Error::Binding)
	));
	assert!(matches!(
		ledger.stamp_failed_read(name, epoch(1), extent - 1),
		Err(Error::UnknownStage)
	));
	ledger.stamp_failed_read(name, epoch(1), extent).unwrap()
}

fn reopen<'fixture>(
	fixture: &'fixture Fixture,
	stamp: RetryCaptureStamp,
) -> Result<RemoteRetryLease<'fixture>, Error> {
	RemoteJobLease::open_retry(
		&fixture.profile,
		fixture.job,
		fixture.activation(),
		stamp,
		FRESH.into(),
		FRESH_NONCE,
	)
}

fn replace_with_same_bytes(path: &std::path::Path) {
	let original = fs::read(path).unwrap();
	fs::rename(path, path.with_extension("original")).unwrap();
	let mut new = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.unwrap();
	new.write_all(&original).unwrap();
}

#[test]
fn retry_stamp_holds_pins_without_retaining_the_old_flock() {
	let fixture = Fixture::new();
	let stamp = stamp(&fixture);
	let name = super::job_name(fixture.job);
	let inspect = fixture
		.root
		.open_recovery_job(component(name.as_bytes()).unwrap())
		.unwrap();
	let lease = inspect.try_read_lease().unwrap();
	drop(lease);
	let mut before = vec![0; usize::try_from(stamp.segment.len()).unwrap()];
	stamp.segment.read_exact_at(0, &mut before).unwrap();
	let retry = reopen(&fixture, stamp).unwrap();
	assert_eq!(retry.previous_source_observation(), observation());
	assert!(matches!(inspect.try_read_lease(), Err(StageError::JobBusy)));
	retry.recheck().unwrap();
	assert_eq!(fs::read(fixture.segment()).unwrap(), before);
	assert_eq!(fs::read(fixture.stage("capture-1")).unwrap(), PREFIX);
	assert!(!fixture.stage("capture-2").exists());
	assert!(!fixture.target().exists());
	drop(retry);
	assert!(inspect.try_read_lease().is_ok());
}

#[test]
fn retry_refuses_replaced_owner_segment_and_private_inode_even_with_identical_bytes() {
	for role in ["owner", "segment", "stage"] {
		let fixture = Fixture::new();
		let stamp = stamp(&fixture);
		let path = match role {
			"owner" => fixture.job_path().join("owner.cbor"),
			"segment" => fixture.segment(),
			_ => fixture.stage("capture-1"),
		};
		replace_with_same_bytes(&path);
		assert!(
			reopen(&fixture, stamp).is_err(),
			"replaced {role} was admitted"
		);
		assert!(!fixture.target().exists());
	}
}

#[test]
fn retry_refuses_changed_extent_and_late_incumbent_under_the_new_lease() {
	let fixture = Fixture::new();
	let issued = stamp(&fixture);
	let lease = reopen(&fixture, issued).unwrap();
	fs::write(fixture.target(), b"incumbent").unwrap();
	assert!(matches!(lease.recheck(), Err(Error::Conflict)));
	assert_eq!(fs::read(fixture.target()).unwrap(), b"incumbent");

	let fixture = Fixture::new();
	let issued = stamp(&fixture);
	fs::OpenOptions::new()
		.append(true)
		.open(fixture.stage("capture-1"))
		.unwrap()
		.write_all(b"!")
		.unwrap();
	assert!(matches!(reopen(&fixture, issued), Err(Error::UnknownStage)));
	assert!(!fixture.target().exists());
}

#[test]
fn retry_refuses_a_moving_or_torn_accepted_head() {
	let fixture = Fixture::new();
	let issued = stamp(&fixture);
	let lease =
		RemoteJobLease::open_existing(&fixture.profile, fixture.job, fixture.activation()).unwrap();
	let candidate = lease.candidate(component(FRESH).unwrap()).unwrap();
	let mut ledger = lease.open_writer(&candidate).unwrap();
	ledger
		.allocate(&candidate, epoch(2), observation(), FRESH_NONCE)
		.unwrap();
	drop(ledger);
	drop(lease);
	assert!(matches!(reopen(&fixture, issued), Err(Error::Binding)));
	assert_eq!(fs::read(fixture.stage("capture-1")).unwrap(), PREFIX);

	let fixture = Fixture::new();
	let issued = stamp(&fixture);
	fs::OpenOptions::new()
		.append(true)
		.open(fixture.segment())
		.unwrap()
		.write_all(b"!")
		.unwrap();
	assert!(reopen(&fixture, issued).is_err());
	assert!(!fixture.target().exists());
}

#[test]
fn retry_refuses_old_name_nonce_and_changed_grant() {
	for (name, nonce) in [(STAGE, FRESH_NONCE), (FRESH, NONCE)] {
		let fixture = Fixture::new();
		let issued = stamp(&fixture);
		assert!(matches!(
			RemoteJobLease::open_retry(
				&fixture.profile,
				fixture.job,
				fixture.activation(),
				issued,
				name.into(),
				nonce,
			),
			Err(Error::Attempt)
		));
	}
	let fixture = Fixture::new();
	let issued = stamp(&fixture);
	fixture.grant.digest.set([0x37; 32]);
	assert!(matches!(reopen(&fixture, issued), Err(Error::Binding)));
}

#[test]
fn retry_capacity_requires_space_for_a_fresh_preparation_and_a_new_epoch() {
	let fixture = Fixture::new();
	let mut issued = stamp(&fixture);
	check_capacity(&issued, FRESH, FRESH_NONCE).unwrap();
	let offset = issued.boundary.offset;
	issued.boundary.offset = exacopy_journal::MAX_FIRST_SEGMENT_BYTES - 1;
	assert!(matches!(
		check_capacity(&issued, FRESH, FRESH_NONCE),
		Err(Error::Attempt)
	));
	issued.boundary.offset = offset;
	issued.epochs.source = std::num::NonZeroU64::MAX;
	assert!(matches!(
		check_capacity(&issued, FRESH, FRESH_NONCE),
		Err(Error::Attempt)
	));
}

#[test]
fn retry_refuses_a_rebound_stage_directory_and_an_occupied_fresh_name() {
	let fixture = Fixture::new();
	let issued = stamp(&fixture);
	let old = fixture.job_path().join("stage-previous");
	let directory = fixture.job_path().join("stage");
	fs::rename(&directory, &old).unwrap();
	let mut create = fs::DirBuilder::new();
	use std::os::unix::fs::DirBuilderExt as _;
	create.mode(0o700).create(&directory).unwrap();
	fs::rename(old.join("capture-1"), fixture.stage("capture-1")).unwrap();
	assert!(reopen(&fixture, issued).is_err());
	assert_eq!(fs::read(fixture.stage("capture-1")).unwrap(), PREFIX);

	let fixture = Fixture::new();
	let issued = stamp(&fixture);
	OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(fixture.stage("capture-2"))
		.unwrap()
		.write_all(b"private incumbent")
		.unwrap();
	assert!(matches!(reopen(&fixture, issued), Err(Error::Conflict)));
	assert_eq!(
		fs::read(fixture.stage("capture-2")).unwrap(),
		b"private incumbent"
	);
}

#[test]
fn retry_consumes_the_exact_successor_and_preserves_the_previous_stage() {
	let fixture = Fixture::new();
	let retry = reopen(&fixture, stamp(&fixture)).unwrap();
	let prior = fixture.replay().boundary();
	let (lease, preview, _pins) = retry.consume(observation(), epoch(2)).unwrap();
	let wrong = lease.candidate(component(b"other-slot").unwrap()).unwrap();
	let mut ledger = lease.open_fresh_capture(&wrong).unwrap();
	assert!(matches!(
		ledger.allocate_retry(&wrong, &preview, observation()),
		Err(Error::Binding)
	));
	drop(ledger);
	assert_eq!(fixture.replay().boundary(), prior);
	assert!(!fixture.stage("other-slot").exists());

	let candidate = lease.candidate(component(preview.name()).unwrap()).unwrap();
	let mut ledger = lease.open_fresh_capture(&candidate).unwrap();
	let mut allocation = ledger
		.allocate_retry(&candidate, &preview, observation())
		.unwrap();
	let bound = allocation.create(&mut ledger).unwrap();
	let replay = fixture.replay();
	let [old, new] = replay.attempts() else {
		panic!("one exact successor")
	};
	assert_eq!(old.name(), STAGE);
	assert_eq!(new.name(), FRESH);
	assert_eq!(*new.nonce(), FRESH_NONCE);
	assert_eq!(new.epochs().source, epoch(2));
	assert_eq!(new.allocation().sequence(), prior.head.sequence() + 1);
	assert_eq!(
		new.prepared().unwrap().head.sequence(),
		prior.head.sequence() + 2
	);
	assert_eq!(bound.length, observation().length().get());
	assert_eq!(fs::read(fixture.stage("capture-1")).unwrap(), PREFIX);
	assert!(fs::read(fixture.stage("capture-2")).unwrap().is_empty());
	assert!(!fixture.target().exists());
}

#[test]
fn retry_refuses_revocation_after_allocation_before_stage_creation() {
	let fixture = Fixture::new();
	let retry = reopen(&fixture, stamp(&fixture)).unwrap();
	let (lease, preview, _pins) = retry.consume(observation(), epoch(2)).unwrap();
	let candidate = lease.candidate(component(preview.name()).unwrap()).unwrap();
	let mut ledger = lease.open_fresh_capture(&candidate).unwrap();
	let mut allocation = ledger
		.allocate_retry(&candidate, &preview, observation())
		.unwrap();
	let allocated = fs::read(fixture.segment()).unwrap();
	fixture.grant.refuse_after(0);
	assert!(matches!(
		allocation.create(&mut ledger),
		Err(Error::Grant(_))
	));
	assert_eq!(fs::read(fixture.segment()).unwrap(), allocated);
	assert!(!fixture.stage("capture-2").exists());
	assert_eq!(fs::read(fixture.stage("capture-1")).unwrap(), PREFIX);
	assert!(!fixture.target().exists());
}

#[test]
fn retry_refuses_wrong_epoch_or_fresh_source_before_a_new_allocation() {
	for (source, next_epoch) in [
		(observation(), epoch(3)),
		(
			RemoteSourceObservation::new(
				exacopy_journal::StreamLength::new(19).unwrap(),
				0o100600,
				1,
			)
			.unwrap(),
			epoch(2),
		),
	] {
		let fixture = Fixture::new();
		let retry = reopen(&fixture, stamp(&fixture)).unwrap();
		let prior = fixture.replay().boundary();
		assert!(matches!(
			retry.consume(source, next_epoch),
			Err(Error::Binding)
		));
		assert_eq!(fixture.replay().boundary(), prior);
		assert!(!fixture.stage("capture-2").exists());
	}
}
