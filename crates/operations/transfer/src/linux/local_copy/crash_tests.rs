//! Native process-crash tests using only fresh private fixtures and the spawned test child.

use std::cell::RefCell;
use std::env;
use std::fs::{self, DirBuilder, File};
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use exacopy_journal::{JournalEntryId, JournalEpoch, JournalJobId};
use rustix::process::Signal;

use super::{
	CopyProfile, CopyRoots, DestinationRoot, LocalCopyError, OwnerProfileId, OwnerTimestamp,
	OwnerToken, PlanAttempt, PublishError, ReadRoot, RootCapabilityId, SigningKey, UnixComponent,
	copy_new_file, plan_new_file,
};

mod evidence;
mod retry;

use evidence::{STAGE_DIRECTORY, Snapshot, assert_conflict, assert_crash};

const TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const PROCEED: u8 = 0;
const SOCKET: &str = "checkpoints.sock";
const SOURCE_DIRECTORY: &str = "source";
const DESTINATION_DIRECTORY: &str = "destination";
const SOURCE: &str = "original";
const TARGET: &str = "published";
const JOB: &str = "fixture-job";
const STAGE_FILE: &str = "partial";
const SOURCE_BYTES: &[u8] = b"independent source and stage streams\0\xff\n";
const INCUMBENT_BYTES: &[u8] = b"late incumbent owned by another writer";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(in crate::linux) enum Checkpoint {
	PlanSynced = 1,
	StageSealed,
	IntentSynced,
	RenamedAndSynced,
	ReceiptSynced,
	ReceiptCommitted,
	RetryDecisionSynced,
	RetryIntentSynced,
	RetryRenamedAndSynced,
}

impl Checkpoint {
	const COPY_ORDER: [Self; 6] = [
		Self::PlanSynced,
		Self::StageSealed,
		Self::IntentSynced,
		Self::RenamedAndSynced,
		Self::ReceiptSynced,
		Self::ReceiptCommitted,
	];
	const RETRY_ORDER: [Self; 3] = [
		Self::RetryDecisionSynced,
		Self::RetryIntentSynced,
		Self::RetryRenamedAndSynced,
	];

	fn worker(self) -> (&'static str, &'static [Self]) {
		match self {
			Self::RetryDecisionSynced | Self::RetryIntentSynced | Self::RetryRenamedAndSynced => {
				("retry::retry_worker", &Self::RETRY_ORDER)
			}
			_ => ("copy_worker", &Self::COPY_ORDER),
		}
	}
}

thread_local! {
	static CHECKPOINT_CHANNEL: RefCell<Option<UnixStream>> = const { RefCell::new(None) };
}

pub(in crate::linux) fn pause_at(checkpoint: Checkpoint) {
	CHECKPOINT_CHANNEL.with_borrow_mut(|channel| {
		if let Some(channel) = channel {
			channel
				.write_all(&[checkpoint as u8])
				.expect("announce checkpoint to the parent");
			let mut response = [0_u8; 1];
			channel
				.read_exact(&mut response)
				.expect("wait for the parent's checkpoint decision");
			assert_eq!(response, [PROCEED], "unexpected checkpoint decision");
		}
	});
}

#[test]
fn kill_after_plan_sync() {
	kill_at(Checkpoint::PlanSynced);
}

#[test]
fn kill_after_seal_before_intent() {
	kill_at(Checkpoint::StageSealed);
}

#[test]
fn kill_after_intent_before_rename() {
	kill_at(Checkpoint::IntentSynced);
}

#[test]
fn kill_after_rename_before_observation_frame() {
	kill_at(Checkpoint::RenamedAndSynced);
}

#[test]
fn kill_after_receipt_sync_before_commit() {
	kill_at(Checkpoint::ReceiptSynced);
}

#[test]
fn kill_after_receipt_commit() {
	kill_at(Checkpoint::ReceiptCommitted);
}

#[test]
fn late_incumbent_survives_exclusive_rename() {
	let fixture = Fixture::new();
	let source = Snapshot::read(&fixture.source());
	let (mut worker, mut stream) = fixture.pause_worker(Checkpoint::IntentSynced);
	let incumbent_path = fixture.destination().join(TARGET);
	let mut incumbent = File::create_new(&incumbent_path).expect("create a late incumbent");
	incumbent
		.write_all(INCUMBENT_BYTES)
		.expect("write incumbent bytes");
	drop(incumbent);
	let incumbent = Snapshot::read(&incumbent_path);
	let stage = Snapshot::read(&fixture.job().join(STAGE_DIRECTORY).join(STAGE_FILE));
	stream
		.write_all(&[PROCEED])
		.expect("allow exclusive rename");
	assert!(worker.finish().success(), "child must detect a conflict");
	assert_eq!(Snapshot::read(&fixture.source()), source, "source changed");
	assert_conflict(&fixture, &stage, &incumbent);
}

fn kill_at(checkpoint: Checkpoint) {
	let fixture = Fixture::new();
	let source = Snapshot::read(&fixture.source());
	let (mut worker, _stream) = fixture.pause_worker(checkpoint);
	worker.kill_at(checkpoint);
	assert_eq!(
		Snapshot::read(&fixture.source()),
		source,
		"source changed at {checkpoint:?}"
	);
	assert_crash(&fixture, checkpoint, &source);
}

#[test]
#[ignore = "subprocess entrypoint for the native copy crash tests"]
fn copy_worker() {
	let root = connect_checkpoint();
	let source = open_source(&root);
	let destination = open_destination(&root.join(DESTINATION_DIRECTORY));
	let roots = CopyRoots {
		source: &source,
		source_id: source_id(),
		destination: &destination,
		destination_id: RootCapabilityId::from_bytes(uuid_v4(2)).expect("fixture target UUID"),
	};
	let mut job = uuid_v4(3);
	job[6] = 0x70;
	let attempt = PlanAttempt {
		job: JournalJobId::from_bytes(job).expect("fixture job UUIDv7"),
		epoch: JournalEpoch::new(1),
		entry: JournalEntryId::from_bytes([4; 16]),
		job_name: component(JOB),
		stage_name: component(STAGE_FILE),
	};
	let plan = plan_new_file(roots, attempt, component(SOURCE), component(TARGET))
		.expect("plan the copy into the absent target");
	let signer = fixture_signer();
	let profile = CopyProfile {
		id: profile_id(),
		signer: &signer,
		created: OwnerTimestamp::new(1_700_000_000, 0).expect("fixture timestamp"),
		owner_token: OwnerToken::from_bytes([6; 16]).expect("fixture owner token"),
	};
	let result = copy_new_file(roots, &plan, profile, &mut [0; 11]);
	assert!(
		matches!(
			result,
			Err(LocalCopyError::Publication {
				source: PublishError::Conflict,
				recording: None,
			})
		),
		"a worker surviving the checkpoints must see the late incumbent, got {result:?}"
	);
}

fn connect_checkpoint() -> PathBuf {
	let root = env::current_dir().expect("locate the isolated fixture root");
	let channel = UnixStream::connect(root.join(SOCKET)).expect("connect to the fixture parent");
	channel
		.set_read_timeout(Some(TIMEOUT))
		.expect("bound the child's checkpoint wait");
	CHECKPOINT_CHANNEL.with(|socket| socket.replace(Some(channel)));
	root
}

fn open_source(root: &Path) -> ReadRoot {
	ReadRoot::from_directory(
		File::open(root.join(SOURCE_DIRECTORY)).expect("hold the source directory"),
	)
	.expect("admit the held source directory")
}

fn source_id() -> RootCapabilityId {
	RootCapabilityId::from_bytes(uuid_v4(1)).expect("fixture source UUID")
}

const fn uuid_v4(marker: u8) -> [u8; 16] {
	let mut uuid = [marker; 16];
	uuid[6] = 0x40;
	uuid[8] = 0x80;
	uuid
}

fn fixture_signer() -> SigningKey {
	SigningKey::from_bytes(&[7; 32])
}

fn profile_id() -> OwnerProfileId {
	OwnerProfileId::from_bytes([5; 16]).expect("fixture profile identity")
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("valid synthetic path component")
}

fn open_destination(path: &Path) -> DestinationRoot {
	DestinationRoot::from_directory(File::open(path).expect("hold the destination directory"))
		.expect("admit the held destination directory")
}

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);
		const MAX_ATTEMPTS: usize = 128;
		for _ in 0..MAX_ATTEMPTS {
			let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
			let root = env::temp_dir().join(format!("exc-crash-{}-{sequence}", process::id()));
			match DirBuilder::new().mode(0o700).create(&root) {
				Ok(()) => {
					let fixture = Self(root);
					fs::create_dir(fixture.0.join(SOURCE_DIRECTORY))
						.expect("create fixture source directory");
					DirBuilder::new()
						.mode(0o700)
						.create(fixture.destination())
						.expect("create fixture destination directory");
					fs::write(fixture.source(), SOURCE_BYTES).expect("write fixture source");
					fs::set_permissions(fixture.source(), fs::Permissions::from_mode(0o640))
						.expect("set fixture source mode");
					return fixture;
				}
				Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
				Err(error) => panic!("create private crash fixture: {error}"),
			}
		}
		panic!("could not reserve a private crash fixture");
	}

	fn source(&self) -> PathBuf {
		self.0.join(SOURCE_DIRECTORY).join(SOURCE)
	}

	fn destination(&self) -> PathBuf {
		self.0.join(DESTINATION_DIRECTORY)
	}

	fn job(&self) -> PathBuf {
		self.destination().join(JOB)
	}

	fn pause_worker(&self, stop: Checkpoint) -> (Worker, UnixStream) {
		let socket = self.0.join(SOCKET);
		let listener = UnixListener::bind(&socket).expect("bind checkpoint socket");
		listener
			.set_nonblocking(true)
			.expect("bound the wait for the child to connect");
		let (_, module) = module_path!()
			.split_once("::")
			.expect("derive the libtest module name");
		let (entrypoint, checkpoints) = stop.worker();
		let worker = Command::new(env::current_exe().expect("locate the test binary"))
			.current_dir(&self.0)
			.args(["--exact", "--ignored", "--nocapture"])
			.arg(format!("{module}::{entrypoint}"))
			.stdout(Stdio::null())
			.spawn()
			.expect("spawn the Linux fixture worker");
		let mut worker = Worker(worker);
		let deadline = Instant::now() + TIMEOUT;
		let mut stream = loop {
			match listener.accept() {
				Ok((stream, _)) => break stream,
				Err(error) if error.kind() == ErrorKind::WouldBlock => {
					let status = worker.0.try_wait().expect("check fixture worker");
					assert!(status.is_none(), "fixture worker exited early: {status:?}");
					assert!(Instant::now() < deadline, "fixture worker did not connect");
					thread::sleep(POLL_INTERVAL);
				}
				Err(error) => panic!("accept the fixture worker's connection: {error}"),
			}
		};
		fs::remove_file(socket).expect("release the checkpoint socket name for the next worker");
		stream
			.set_read_timeout(Some(TIMEOUT))
			.expect("bound the parent's checkpoint wait");
		for &checkpoint in checkpoints {
			let mut ready = [0_u8; 1];
			stream
				.read_exact(&mut ready)
				.unwrap_or_else(|error| panic!("wait for checkpoint {checkpoint:?}: {error}"));
			assert_eq!(ready, [checkpoint as u8], "unexpected checkpoint order");
			if checkpoint == stop {
				return (worker, stream);
			}
			stream
				.write_all(&[PROCEED])
				.expect("resume the fixture worker");
		}
		panic!("checkpoint {stop:?} missing from protocol");
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		if thread::panicking() {
			eprintln!("retained Linux crash fixture at {}", self.0.display());
		} else {
			let _ = fs::remove_dir_all(&self.0);
		}
	}
}

struct Worker(Child);

impl Worker {
	fn kill_at(&mut self, checkpoint: Checkpoint) {
		self.0.kill().expect("SIGKILL the blocked fixture worker");
		let status = self.finish();
		assert_eq!(
			status.signal(),
			Some(Signal::KILL.as_raw()),
			"expected SIGKILL at {checkpoint:?}, observed {status}"
		);
	}

	fn finish(&mut self) -> ExitStatus {
		let deadline = Instant::now() + TIMEOUT;
		loop {
			if let Some(status) = self.0.try_wait().expect("reap the fixture worker") {
				return status;
			}
			assert!(Instant::now() < deadline, "fixture worker did not exit");
			thread::sleep(POLL_INTERVAL);
		}
	}
}

impl Drop for Worker {
	fn drop(&mut self) {
		if !matches!(self.0.try_wait(), Ok(Some(_))) {
			let _ = self.0.kill();
			let _ = self.0.wait();
		}
	}
}
