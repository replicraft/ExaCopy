//! A diagnostic process-kill campaign for actual Linux destination primitives.

use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use exacopy_endpoint::UnixComponent;
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, PublishNoClobber, RunEpoch,
	StageId,
};
use rustix::process::Signal;

use super::{DestinationRoot, Scratch, observe_remote_destination};

const FIXTURE_ENV: &str = "EXACOPY_REMOTE_CRASH_DIAGNOSTIC_FIXTURE";
const WORKER: &str = "linux::process_crash::remote_destination::tests::campaign::native_worker";
const MARKER: &str = "EXACOPY_REMOTE_NATIVE_CUT ";
const TIMEOUT: Duration = Duration::from_secs(15);
const ORDER: [&str; 4] = [
	"private-created",
	"data-synced",
	"closed-readback",
	"published-and-synced",
];
const JOB: &str = "private-job";
const STAGE: &str = "private-stream";
const TARGET: &str = "selected-target";
const DATA: &[u8] = b"fixture logical bytes\x00\xff\n";

#[test]
#[ignore = "requires native Linux and a disposable writable ext4 TMPDIR"]
fn destination_substrate_preserves_bytes_at_each_native_process_cut() {
	for cut in ORDER {
		let fixture = Scratch::new();
		let root = DestinationRoot::from_directory(fixture.open()).unwrap();
		let native = observe_remote_destination(&root).expect("require native ext4 observation");
		let mut worker = Worker::start(&fixture.path(""));
		worker.stop_at(cut);
		assert_eq!(observe_remote_destination(&root).unwrap(), native);
		let held = root.open_recovery_job(component(JOB)).unwrap();
		let lease = root
			.try_recovery_write_lease(component(JOB), held.identity())
			.unwrap();
		let names = lease
			.job()
			.inventory(component(STAGE), component(TARGET))
			.unwrap();
		names.recheck().unwrap();
		if cut == "published-and-synced" {
			assert!(names.stage().is_none());
			assert_eq!(fs::read(fixture.path(TARGET)).unwrap(), DATA);
		} else {
			assert!(names.target().is_none());
			let stage = fs::read(fixture.path(JOB).join("stage").join(STAGE)).unwrap();
			assert_eq!(stage, if cut == "private-created" { &[] } else { DATA });
		}
		println!("\nEXACOPY_REMOTE_SUBSTRATE_PASS {cut}");
	}
}

#[test]
#[ignore = "spawned only by the native destination substrate test"]
fn native_worker() {
	let Some(path) = env::var_os(FIXTURE_ENV) else {
		return;
	};
	let root = DestinationRoot::from_directory(File::open(path).unwrap()).unwrap();
	let job = root.create_job_directory(component(JOB)).unwrap();
	let stage_directory = job.create_stage_directory().unwrap();
	let binding = binding();
	let mut stage = stage_directory
		.create_file(component(STAGE), component(TARGET), binding)
		.unwrap();
	stage_directory.sync_directory().unwrap();
	job.sync_directory().unwrap();
	root.sync_directory().unwrap();
	pause("private-created");

	stage.write_all_at(0, DATA).unwrap();
	stage.flush().unwrap();
	pause("data-synced");
	let stage = stage.close_writes().unwrap();
	let mut measured = [0; DATA.len()];
	stage.read_exact_at(0, &mut measured).unwrap();
	assert_eq!(measured, DATA);
	pause("closed-readback");

	stage
		.publish_no_clobber(diagnostic_permit(binding))
		.unwrap();
	pause("published-and-synced");
}

fn pause(cut: &str) {
	let mut output = io::stdout().lock();
	writeln!(output, "{MARKER}{cut}").unwrap();
	output.flush().unwrap();
	let mut next = [0];
	io::stdin().read_exact(&mut next).unwrap();
	assert_eq!(next, [1]);
}

fn component(bytes: &str) -> UnixComponent<'_> {
	UnixComponent::new(bytes.as_bytes()).unwrap()
}

fn binding() -> CopyBinding {
	let id = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap();
	CopyBinding::new(
		id,
		EntryId::new(1),
		RunEpoch::new(1),
		StageId::from_bytes([0x13; 16]),
	)
}

fn diagnostic_permit(binding: CopyBinding) -> PublishNoClobber {
	// This purposely injects model evidence. The diagnostic cannot qualify a download.
	let mut session = CopySession::new(binding);
	for event in [
		CopyEvent::StagePrepared,
		CopyEvent::WritersJoined,
		CopyEvent::DataFlushed,
		CopyEvent::ReadbackVerified,
		CopyEvent::MetadataReady,
		CopyEvent::StageSealed,
	] {
		let _ = session.apply(binding, event).unwrap();
	}
	let Some(CopyEffect::PublishNoClobber(permit)) = session
		.apply(binding, CopyEvent::PublishIntentRecorded)
		.unwrap()
	else {
		panic!("diagnostic private fixture permit")
	};
	permit
}

struct Worker {
	child: Child,
	events: mpsc::Receiver<String>,
	reader: Option<thread::JoinHandle<()>>,
}

impl Worker {
	fn start(fixture: &Path) -> Self {
		let mut child = Command::new(env::current_exe().unwrap())
			.args(["--exact", WORKER, "--ignored", "--nocapture"])
			.env(FIXTURE_ENV, fixture)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.spawn()
			.unwrap();
		let output = child.stdout.take().unwrap();
		let (send, events) = mpsc::sync_channel(4);
		let reader = thread::spawn(move || {
			for line in BufReader::new(output).lines().map_while(Result::ok) {
				if let Some((_, cut)) = line.split_once(MARKER)
					&& send.send(cut.to_owned()).is_err()
				{
					break;
				}
			}
		});
		Self {
			child,
			events,
			reader: Some(reader),
		}
	}

	fn stop_at(&mut self, expected: &str) {
		for ordered in ORDER {
			assert_eq!(
				self.events
					.recv_timeout(TIMEOUT)
					.expect("owned worker boundary"),
				ordered
			);
			if expected == ordered {
				self.child.kill().unwrap();
				assert_eq!(
					self.child.wait().unwrap().signal(),
					Some(Signal::KILL.as_raw())
				);
				return;
			}
			self.child.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
		}
		panic!("unknown destination diagnostic cut")
	}
}

impl Drop for Worker {
	fn drop(&mut self) {
		if !matches!(self.child.try_wait(), Ok(Some(_))) {
			let _ = self.child.kill();
		}
		let _ = self.child.wait();
		if let Some(reader) = self.reader.take() {
			let _ = reader.join();
		}
	}
}
