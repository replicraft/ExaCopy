use std::fs;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::num::NonZeroU64;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

use super::super::ReplayIssue;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::remote_download::replay::RemoteReplayState;

use super::{Error, Fixture, NONCE, RemoteJobLease, STAGE, component, observation};

#[test]
fn startup_resolves_the_actual_signed_stage_directory_before_first_allocation() {
	let fixture = Fixture::new();
	fixture.bootstrap();
	let bytes = fs::read(fixture.segment()).unwrap();
	let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
	let job = reader.next_frame().unwrap().unwrap();
	let signed = reader.next_frame().unwrap().unwrap();
	assert_eq!(job.kind(), FrameKind::JobPrepared);
	assert_eq!(signed.kind(), FrameKind::StageDirectoryPrepared);
	assert_eq!(signed.previous_digest(), job.head().digest());
	assert!(reader.next_frame().unwrap().is_none());
	let replay = fixture.replay();
	assert!(matches!(
		replay.state(),
		RemoteReplayState::StageDirectoryPrepared
	));
	assert_eq!(replay.boundary().head, signed.head());

	let lease = reopen(&fixture).unwrap();
	let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
	let mut journal = lease.open_writer(&candidate).unwrap();
	let mut allocation = journal
		.allocate(&candidate, NonZeroU64::MIN, observation(), NONCE)
		.unwrap();
	let bound = allocation.create(&mut journal).unwrap();
	assert_eq!(bound.prefix_scope.prepared.sequence(), 4);
	assert_eq!(fixture.replay().attempts()[0].allocation().sequence(), 3);
	assert_eq!(fs::metadata(fixture.stage("capture-1")).unwrap().len(), 0);
	assert!(!fixture.target().exists());
}

#[test]
fn clean_and_torn_prebootstrap_suffixes_remain_read_only() {
	let fixture = Fixture::new();
	let bootstrap = fixture.bootstrap();
	let complete = fs::read(fixture.segment()).unwrap();
	let mut reader = FrameReader::new(complete.as_slice(), ChainHead::start());
	let job = reader.next_frame().unwrap().unwrap();
	let first_end = reader.offset();
	let mut segment = fs::OpenOptions::new()
		.write(true)
		.open(fixture.segment())
		.unwrap();
	segment.set_len(first_end).unwrap();
	assert!(matches!(
		reopen(&fixture),
		Err(Error::Lifecycle { boundary, issue: Some(ReplayIssue::PreBootstrap), .. }) if boundary.head == job.head()
	));
	segment.seek(SeekFrom::Start(first_end)).unwrap();
	segment.write_all(b"EXA").unwrap();
	drop(segment);
	assert!(matches!(
		RemoteJobLease::open_bootstrap(&fixture.profile, fixture.job, fixture.activation(), bootstrap),
		Err(Error::Lifecycle { boundary, issue: Some(ReplayIssue::Torn), .. }) if boundary.head == job.head()
	));
	assert!(fs::read(fixture.segment()).unwrap().ends_with(b"EXA"));
	assert_eq!(
		fs::read_dir(fixture.job_path().join("stage"))
			.unwrap()
			.count(),
		0
	);
	assert!(!fixture.target().exists());
}

#[test]
fn a_rebound_signed_stage_directory_refuses_a_writable_segment() {
	let fixture = Fixture::new();
	fixture.bootstrap();
	let lease = reopen(&fixture).unwrap();
	let selected = component(STAGE).unwrap();
	let candidate = lease.candidate(selected).unwrap();
	let stage = fixture.job_path().join("stage");
	let preserved = fixture.job_path().join("preserved");
	let before = fs::read(fixture.segment()).unwrap();
	fs::rename(&stage, &preserved).unwrap();
	fs::DirBuilder::new().mode(0o700).create(&stage).unwrap();
	assert!(matches!(
		lease.open_writer(&candidate),
		Err(Error::Native(_))
	));
	assert!(matches!(
		lease.candidate(selected),
		Err(Error::UnknownStage)
	));
	assert_eq!(fs::read(fixture.segment()).unwrap(), before);
	assert!(preserved.is_dir());
	assert_eq!(fs::read_dir(&stage).unwrap().count(), 0);
}

#[test]
fn post_create_rebind_retires_writer_and_retains_the_unbound_artifacts() {
	let fixture = Fixture::new();
	{
		let lease = fixture.open_bootstrap(fixture.bootstrap());
		let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
		let mut journal = lease.open_writer(&candidate).unwrap();
		let mut allocation = journal
			.allocate(&candidate, NonZeroU64::MIN, observation(), NONCE)
			.unwrap();
		let selected = fixture.stage("capture-1");
		let orphan = fixture.stage("retained-orphan");
		let failure = allocation.create_with_fault(&mut journal, || {
			fs::rename(&selected, &orphan).unwrap();
			let mut incumbent = fs::OpenOptions::new()
				.write(true)
				.create_new(true)
				.mode(0o600)
				.open(&selected)
				.unwrap();
			incumbent.write_all(b"incumbent private evidence").unwrap();
		});
		assert!(matches!(failure, Err(Error::Native(_))));
		drop(failure);
		drop(allocation);
		let fresh = lease
			.candidate(component(b"capture-next").unwrap())
			.unwrap();
		assert!(matches!(
			journal.allocate(&fresh, super::epoch(2), observation(), [0x62; 16]),
			Err(Error::Stopped)
		));
		let replay = fixture.replay();
		assert_eq!(replay.boundary().head.sequence(), 3);
		assert_eq!(replay.attempts().len(), 1);
		assert!(replay.attempts()[0].prepared().is_none());
	}
	assert!(matches!(reopen(&fixture), Err(Error::UnknownStage)));
	assert_eq!(
		fs::read(fixture.stage("capture-1")).unwrap(),
		b"incumbent private evidence"
	);
	assert_eq!(
		fs::metadata(fixture.stage("retained-orphan"))
			.unwrap()
			.len(),
		0
	);
	assert!(!fixture.stage("capture-next").exists());
	assert!(!fixture.target().exists());
}

fn reopen(fixture: &Fixture) -> Result<RemoteJobLease<'_>, Error> {
	RemoteJobLease::open_existing(&fixture.profile, fixture.job, fixture.activation())
}

#[test]
fn initial_bootstrap_checks_the_effect_gate_at_job_creation_and_owner_write() {
	for allowed in [0, 2] {
		let fixture = super::Fixture::new();
		let activation = fixture.activation();
		fixture.grant.refuse_after(allowed);
		let outcome = super::bootstrap(
			&fixture.profile,
			fixture.job,
			super::OwnerTimestamp::new(1, 0).unwrap(),
			super::OwnerToken::from_bytes([0x51; 16]).unwrap(),
			activation,
		);
		match (allowed, outcome) {
			(0, Err(super::Error::BootstrapNotCreated(cause)))
			| (2, Err(super::Error::BootstrapIncomplete(cause))) => {
				assert!(matches!(*cause, super::Error::Grant(_)));
			}
			_ => panic!("bootstrap disposition did not match the physical boundary"),
		}
		assert_eq!(fixture.job_path().exists(), allowed != 0);
		if allowed != 0 {
			assert!(
				std::fs::read(fixture.job_path().join("owner.cbor"))
					.unwrap()
					.is_empty()
			);
		}
		assert!(!fixture.segment().exists());
		assert!(!fixture.target().exists());
	}
}

#[test]
fn bootstrap_never_adopts_an_incumbent_job_path() {
	let fixture = super::Fixture::new();
	let occupied = fixture.job_path();
	std::fs::create_dir(&occupied).unwrap();
	std::fs::write(occupied.join("incumbent"), b"existing owner").unwrap();
	let outcome = super::bootstrap(
		&fixture.profile,
		fixture.job,
		super::OwnerTimestamp::new(1, 0).unwrap(),
		super::OwnerToken::from_bytes([0x51; 16]).unwrap(),
		fixture.activation(),
	);
	assert!(
		matches!(outcome, Err(super::Error::BootstrapNotCreated(cause))
		if matches!(*cause, super::Error::Native(exacopy_platform::linux::StageError::AlreadyExists)))
	);
	assert_eq!(
		std::fs::read(occupied.join("incumbent")).unwrap(),
		b"existing owner"
	);
	assert!(!occupied.join("owner.cbor").exists());
	assert!(!fixture.segment().exists());
}

#[test]
fn revoked_preflight_cannot_report_a_created_job() {
	let fixture = super::Fixture::new();
	let activation = fixture.activation();
	*fixture.grant.active.lock().unwrap() = false;
	let outcome = super::bootstrap(
		&fixture.profile,
		fixture.job,
		super::OwnerTimestamp::new(1, 0).unwrap(),
		super::OwnerToken::from_bytes([0x51; 16]).unwrap(),
		activation,
	);
	assert!(
		matches!(outcome, Err(super::Error::BootstrapNotCreated(cause))
		if matches!(*cause, super::Error::Grant(_)))
	);
	assert_eq!(fixture.grant.effect_entries.get(), 0);
	assert!(!fixture.job_path().exists());
}
