use std::cell::Cell;
use std::env;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::num::{NonZeroU16, NonZeroU64};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use exacopy_endpoint::ssh_sftp::SshAuthority;
use exacopy_journal::remote_download::qualification::RemoteQualificationRouteClass;
use exacopy_journal::remote_download::replay::{
	RemoteDownloadReplay, replay_remote_download_with_bootstrap,
};
use exacopy_journal::remote_download::{
	RemoteDownloadDestination, RemoteDownloadDurability, RemoteDownloadRoute, RemoteDownloadScope,
	RemoteDownloadSource, RemoteScopeDigest, RemoteSourceObservation, RemoteUncertainBoundary,
};
use exacopy_journal::{JournalEntryId, JournalJobId, OwnerTimestamp, OwnerToken, StreamLength};
use exacopy_platform::linux::{DestinationRoot, FileIdentity, StageError};
use exacopy_transfer::remote_metadata::{RemoteMetadataSelection, admit_sftp_metadata};

use crate::linux_path::open_destination;
use crate::profile::{self, LocalProfile};

use super::admission::{CurrentGrant, CurrentQualification, RemoteActivation};
use super::lease::{RemoteJobLease, bootstrap};
use super::{BootstrapIdentity, Error, component, job_name, record_identity};

const JOB: [u8; 16] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x7c, 0xde, 0x8f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
];
const NONCE: [u8; 16] = [0x61; 16];
const LENGTH: u64 = 13;
const STAGE: &[u8] = b"capture-1";
const TARGET: &[u8] = b"target";

#[test]
fn fresh_job_syncs_exact_predecessor_before_creating_each_stage() {
	let fixture = Fixture::new();
	let created = fixture.bootstrap();
	let lease = fixture.open_bootstrap(created);
	let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
	let mut journal = lease.open_writer(&candidate).unwrap();
	assert!(matches!(
		lease.open_writer(&candidate),
		Err(Error::Native(StageError::JobBusy))
	));
	assert_eq!(fixture.replay().boundary().head.sequence(), 2);
	assert!(!fixture.stage("capture-1").exists());
	let mut allocation = journal
		.allocate(&candidate, NonZeroU64::MIN, observation(), NONCE)
		.unwrap();
	let unbound = fixture.replay();
	let [attempt] = unbound.attempts() else {
		panic!("one allocation")
	};
	assert_eq!(unbound.boundary().head, attempt.allocation());
	assert_eq!(attempt.name(), STAGE);
	assert_eq!(attempt.prepared(), None);
	assert!(!fixture.stage("capture-1").exists());
	let bound = allocation.create(&mut journal).unwrap();
	let prepared = fixture.replay();
	let [attempt] = prepared.attempts() else {
		panic!("one prepared allocation")
	};
	assert_eq!(attempt.prepared().unwrap().head, prepared.boundary().head);
	assert_eq!(
		attempt.prepared().unwrap().file,
		record_identity(bound.writer.identity())
	);
	assert_eq!(
		attempt.prepared().unwrap().directory,
		record_identity(bound.directory)
	);
	assert_eq!(bound.length, LENGTH);
	assert_eq!(bound.name.as_bytes(), STAGE);
	assert_eq!(bound.target.as_bytes(), TARGET);
	assert_eq!(fs::metadata(fixture.stage("capture-1")).unwrap().len(), 0);
	assert!(!fixture.target().exists());
}

#[test]
fn recovery_burns_an_abandoned_allocation_and_preserves_the_previous_stage() {
	let fixture = Fixture::new();
	{
		let lease = fixture.open_bootstrap(fixture.bootstrap());
		let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
		let mut journal = lease.open_writer(&candidate).unwrap();
		let mut first = journal
			.allocate(&candidate, NonZeroU64::MIN, observation(), NONCE)
			.unwrap();
		let mut bound = first.create(&mut journal).unwrap();
		bound.writer.write_all_at(0, b"retained").unwrap();
		bound.writer.flush().unwrap();
		drop(bound);
		drop(first);
		let next = lease.candidate(component(b"capture-2").unwrap()).unwrap();
		drop(
			journal
				.allocate(&next, epoch(7), observation(), [0x62; 16])
				.unwrap(),
		);
	}
	assert!(!fixture.stage("capture-2").exists());
	let lease =
		RemoteJobLease::open_existing(&fixture.profile, fixture.job, fixture.activation()).unwrap();
	let new = lease.candidate(component(b"capture-3").unwrap()).unwrap();
	let mut journal = lease.open_writer(&new).unwrap();
	assert!(matches!(
		journal.allocate(&new, epoch(7), observation(), [0x63; 16]),
		Err(Error::Attempt)
	));
	let mut third = journal
		.allocate(&new, epoch(8), observation(), [0x63; 16])
		.unwrap();
	let bound = third.create(&mut journal).unwrap();
	let replay = fixture.replay();
	let [first, second, third] = replay.attempts() else {
		panic!("three consecutive allocations")
	};
	assert_eq!(
		(
			first.epochs().run.get(),
			second.epochs().run.get(),
			third.epochs().run.get()
		),
		(1, 2, 3)
	);
	assert!(second.prepared().is_none());
	assert_ne!(
		first.prepared().unwrap().file,
		record_identity(bound.writer.identity())
	);
	assert_eq!(fs::read(fixture.stage("capture-1")).unwrap(), b"retained");
	assert!(!fixture.target().exists());
}

#[test]
fn lease_refuses_current_scope_changes_and_a_rebound_segment() {
	let fixture = Fixture::new();
	let created = fixture.bootstrap();
	let mut changed = fixture.scope.clone();
	changed.maximum_extent = StreamLength::new(LENGTH - 1).unwrap();
	let changed_grant = FixtureGrant::new(&changed);
	let wrong = fixture.activate(&changed, &changed_grant).unwrap();
	assert!(matches!(
		RemoteJobLease::open_existing(&fixture.profile, fixture.job, wrong),
		Err(Error::Binding)
	));
	let lease = fixture.open_bootstrap(created);
	let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
	let mut journal = lease.open_writer(&candidate).unwrap();
	let original = fixture.segment().with_extension("retained");
	fs::rename(fixture.segment(), &original).unwrap();
	let old_bytes = fs::read(&original).unwrap();
	let mut replacement = OpenOptions::new()
		.create_new(true)
		.mode(0o600)
		.write(true)
		.open(fixture.segment())
		.unwrap();
	replacement.write_all(&old_bytes).unwrap();
	drop(replacement);
	assert!(matches!(
		journal.allocate(&candidate, NonZeroU64::MIN, observation(), NONCE),
		Err(Error::Binding)
	));
	assert_eq!(fs::read(&original).unwrap(), old_bytes);
	assert_eq!(fs::read(fixture.segment()).unwrap(), old_bytes);
	assert!(!fixture.stage("capture-1").exists());
}

#[test]
fn a_recorded_creation_uncertainty_stops_the_writer_and_recovery() {
	let fixture = Fixture::new();
	{
		let lease = fixture.open_bootstrap(fixture.bootstrap());
		let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
		let mut journal = lease.open_writer(&candidate).unwrap();
		let mut first = journal
			.allocate(&candidate, NonZeroU64::MIN, observation(), NONCE)
			.unwrap();
		journal
			.record_failure(RemoteUncertainBoundary::Creation)
			.unwrap();
		assert!(matches!(first.create(&mut journal), Err(Error::Binding)));
	}
	assert_eq!(
		fixture.replay().recorded_uncertainty().unwrap().boundary,
		RemoteUncertainBoundary::Creation,
	);
	assert!(matches!(
		RemoteJobLease::open_existing(&fixture.profile, fixture.job, fixture.activation()),
		Err(Error::Lifecycle {
			issue: Some(super::ReplayIssue::Refused),
			..
		})
	));
	assert!(!fixture.stage("capture-1").exists());
	assert!(!fixture.target().exists());
}

struct Fixture {
	directory: TempRoot,
	root: DestinationRoot,
	profile: LocalProfile,
	job: JournalJobId,
	scope: RemoteDownloadScope,
	grant: FixtureGrant,
	qualification: FixtureQualification,
}

impl Fixture {
	fn new() -> Self {
		Self::with_route(RemoteDownloadRoute::ResolvedDirect {
			endpoint: "127.0.0.1:22".parse().unwrap(),
		})
	}

	fn with_route(route: RemoteDownloadRoute) -> Self {
		let directory = TempRoot::new();
		let profile_path = directory.0.join("profile");
		profile::init(&profile_path).unwrap();
		let profile = LocalProfile::open(&profile_path).unwrap();
		let destination = directory.0.join("destination");
		DirBuilder::new().mode(0o700).create(&destination).unwrap();
		let root = open_destination(&destination).unwrap();
		let job = JournalJobId::from_bytes(JOB).unwrap();
		let authority =
			SshAuthority::new("transfer.example", NonZeroU16::new(22).unwrap(), "reader").unwrap();
		let source =
			RemoteDownloadSource::new(authority, [0x51; 32], route, b"inbox/file").unwrap();
		let destination = RemoteDownloadDestination::new(
			profile.root_id(root.identity()).unwrap(),
			record_identity(root.identity()),
			component(TARGET).unwrap(),
		);
		let scope = RemoteDownloadScope::new(
			JournalEntryId::from_bytes([0x22; 16]),
			source,
			destination,
			StreamLength::new(LENGTH).unwrap(),
			admit_sftp_metadata(RemoteMetadataSelection::SftpDataOnlyV1)
				.unwrap()
				.digest(),
			RemoteDownloadDurability::ProcessCrash,
		)
		.unwrap();
		let grant = FixtureGrant::new(&scope);
		let qualification = FixtureQualification {
			root: root.identity(),
			digest: Cell::new(QUALIFICATION),
			route: Cell::new(
				if matches!(route, RemoteDownloadRoute::EmbeddedWireGuard { .. }) {
					RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1
				} else {
					RemoteQualificationRouteClass::DirectPinnedTcpV1
				},
			),
		};
		Self {
			directory,
			root,
			profile,
			job,
			scope,
			grant,
			qualification,
		}
	}

	fn activate<'root>(
		&'root self,
		scope: &'root RemoteDownloadScope,
		grant: &'root FixtureGrant,
	) -> Result<RemoteActivation<'root>, Error> {
		let selected = admit_sftp_metadata(RemoteMetadataSelection::SftpDataOnlyV1).unwrap();
		RemoteActivation::admit(&self.root, scope, selected, grant, &self.qualification)
	}

	fn activation(&self) -> RemoteActivation<'_> {
		self.activate(&self.scope, &self.grant).unwrap()
	}

	fn bootstrap(&self) -> BootstrapIdentity {
		bootstrap(
			&self.profile,
			self.job,
			OwnerTimestamp::new(1, 0).unwrap(),
			OwnerToken::from_bytes([0x51; 16]).unwrap(),
			self.activation(),
		)
		.unwrap()
	}

	fn open_bootstrap(&self, created: BootstrapIdentity) -> RemoteJobLease<'_> {
		RemoteJobLease::open_bootstrap(&self.profile, self.job, self.activation(), created).unwrap()
	}

	fn replay(&self) -> RemoteDownloadReplay {
		let owner = fs::read(self.job_path().join("owner.cbor")).unwrap();
		let key = self.profile.verification_key();
		let dialect = self.activation().dialect;
		let owner = dialect.decode(&owner, self.profile.id(), &key).unwrap();
		let trust = dialect.trust(&owner, self.profile.id(), &key).unwrap();
		let journal = fs::read(self.segment()).unwrap();
		replay_remote_download_with_bootstrap(journal.as_slice(), &trust).unwrap()
	}

	fn target(&self) -> PathBuf {
		self.directory.0.join("destination").join("target")
	}

	fn stage(&self, name: &str) -> PathBuf {
		self.job_path().join("stage").join(name)
	}

	fn segment(&self) -> PathBuf {
		self.job_path().join("journal/00000000000000000001.exajnl")
	}

	fn job_path(&self) -> PathBuf {
		self.directory
			.0
			.join("destination")
			.join(job_name(self.job))
	}
}

fn epoch(value: u64) -> NonZeroU64 {
	NonZeroU64::new(value).unwrap()
}

fn observation() -> RemoteSourceObservation {
	RemoteSourceObservation::new(StreamLength::new(LENGTH).unwrap(), 0o100640, 19).unwrap()
}

struct TempRoot(PathBuf);

impl TempRoot {
	fn new() -> Self {
		static NEXT: AtomicUsize = AtomicUsize::new(0);
		for _ in 0..128 {
			let suffix = NEXT.fetch_add(1, Ordering::Relaxed);
			let path = env::temp_dir().join(format!("exc-remote-job-{}-{suffix}", process::id()));
			match DirBuilder::new().mode(0o700).create(&path) {
				Ok(()) => return Self(path),
				Err(cause) if cause.kind() == ErrorKind::AlreadyExists => {}
				Err(cause) => panic!("could not create private fixture: {cause}"),
			}
		}
		panic!("could not reserve private fixture")
	}
}

impl Drop for TempRoot {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(Path::new(&self.0));
	}
}

mod bootstrap_fixtures;
mod capture;
mod finalization;
mod reconcile;
mod retry;

const QUALIFICATION: [u8; 32] = [0x66; 32];

struct FixtureGrant {
	scope: RemoteScopeDigest,
	digest: Cell<[u8; 32]>,
	active: Mutex<bool>,
	effect_entries: Cell<usize>,
	refuse_effect: Cell<Option<usize>>,
}

impl FixtureGrant {
	fn new(scope: &RemoteDownloadScope) -> Self {
		Self {
			scope: scope.digest().unwrap(),
			digest: Cell::new([0x13; 32]),
			active: Mutex::new(true),
			effect_entries: Cell::new(0),
			refuse_effect: Cell::new(None),
		}
	}
	fn refuse_after(&self, allowed: usize) {
		self.refuse_effect
			.set(Some(self.effect_entries.get() + allowed + 1));
	}

	fn refuse() -> Error {
		use exacopy_endpoint::connection_retry::{PermanentFailure, RetryBlock, RetryError};

		Error::Grant(RetryError::Blocked(RetryBlock::Permanent(
			PermanentFailure::GrantRevoked,
		)))
	}
}

impl CurrentGrant for FixtureGrant {
	fn recheck(&self, scope: RemoteScopeDigest) -> Result<[u8; 32], Error> {
		if scope != self.scope {
			return Err(Error::Binding);
		}
		if !*self.active.lock().unwrap() {
			return Err(Self::refuse());
		}
		Ok(self.digest.get())
	}
	fn enter_effect(
		&self,
		scope: RemoteScopeDigest,
		digest: [u8; 32],
	) -> Result<MutexGuard<'_, bool>, Error> {
		if (scope, digest) != (self.scope, self.digest.get()) {
			return Err(Error::Binding);
		}
		let mut active = self.active.lock().unwrap();
		let entry = self.effect_entries.get() + 1;
		self.effect_entries.set(entry);
		if self.refuse_effect.get() == Some(entry) {
			*active = false;
		}
		if !*active {
			return Err(Self::refuse());
		}
		Ok(active)
	}
}

struct FixtureQualification {
	root: FileIdentity,
	digest: Cell<[u8; 32]>,
	route: Cell<RemoteQualificationRouteClass>,
}

impl CurrentQualification for FixtureQualification {
	fn recheck(
		&self,
		root: &DestinationRoot,
		route: RemoteQualificationRouteClass,
	) -> Result<[u8; 32], Error> {
		if self.route.get() != route {
			return Err(Error::UnsupportedRoute);
		}
		if root.identity() != self.root {
			return Err(Error::Binding);
		}
		Ok(self.digest.get())
	}
}

mod lifecycle;
