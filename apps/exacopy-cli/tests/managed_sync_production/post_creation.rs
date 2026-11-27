//! Exercise exclusive creation followed by refusal in an isolated test process.

use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::fs::{Mode, OFlags, fcntl_getfl, fcntl_setfl};
use rustix::process::umask;

use super::{
	ManagedSyncInit, ManagedSyncPreviewError, SLOT, Sandbox, SyncProfileStoreError, TestResult,
	initialize_managed_preview, open_child,
};

use super::history::{Artifact, NAMES};
use super::rig::{FIXTURE_PARENT, read};

const CHILD: &str = "EXACOPY_MANAGED_SYNC_POST_CREATION_CHILD";
const CASE: &str = "production_managed_init_then_preview_exact_p063_history";
const CHILD_TIMEOUT: Duration = Duration::from_secs(15);
const REAP_TIMEOUT: Duration = Duration::from_secs(2);
const WAIT_INTERVAL: Duration = Duration::from_millis(10);
const OUTPUT_LIMIT: u16 = 4096;
const SUCCESS: &str =
	"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in ";

pub(super) const CLEAN_MARKER: &str =
	"managed_sync_post_creation=unconfirmed_retained_cleanup_verified";

pub(super) fn is_child() -> bool {
	std::env::var_os(CHILD).is_some_and(|mode| mode == "1")
}

pub(super) fn run_child() -> TestResult {
	let fixture_parent = std::env::var_os(FIXTURE_PARENT).ok_or("missing fixture parent")?;
	// Re-execute the running Linux ELF by its kernel-held image identity.
	let mut child = Command::new("/proc/self/exe")
		.args([
			"--ignored",
			"--exact",
			"--nocapture",
			"--test-threads=1",
			"--color",
			"never",
			CASE,
		])
		.env_clear()
		.env(CHILD, "1")
		.env(FIXTURE_PARENT, fixture_parent)
		.env("LC_ALL", "C")
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()?;
	let status = wait_for_child(&mut child);
	let stdout =
		read_output(child.stdout.take().ok_or("missing child stdout")?).map_err(|error| {
			io::Error::other(format!(
				"post-creation child stdout failed ({status:?}): {error}"
			))
		})?;
	let stderr =
		read_output(child.stderr.take().ok_or("missing child stderr")?).map_err(|error| {
			io::Error::other(format!(
				"post-creation child stderr failed ({status:?}): {error}"
			))
		})?;
	let lines: Vec<_> = stdout
		.lines()
		.map(str::trim)
		.filter(|line| !line.is_empty())
		.collect();
	let selected = format!("test {CASE} ...");
	if !status.as_ref().is_ok_and(ExitStatus::success)
		|| !stderr.is_empty()
		|| !matches!(lines.as_slice(), ["running 1 test", test, CLEAN_MARKER, "ok", result]
			if *test == selected && result.starts_with(SUCCESS))
	{
		return Err(io::Error::other(format!(
			"post-creation control failed ({status:?})\n{stdout}\n{stderr}"
		))
		.into());
	}
	Ok(())
}

fn wait_for_child(child: &mut Child) -> io::Result<ExitStatus> {
	let observed = poll_exit(child, CHILD_TIMEOUT);
	if let Ok(Some(status)) = observed {
		return Ok(status);
	}
	let kill = child.kill();
	match poll_exit(child, REAP_TIMEOUT) {
		Ok(Some(_)) => observed?.ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::TimedOut,
				"post-creation child exceeded its deadline",
			)
		}),
		reap => Err(io::Error::other(format!(
			"post-creation child termination unconfirmed (wait={observed:?}, kill={kill:?}, reap={reap:?})"
		))),
	}
}

fn poll_exit(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
	let start = Instant::now();
	loop {
		match child.try_wait()? {
			None if start.elapsed() < timeout => thread::sleep(WAIT_INTERVAL),
			status => return Ok(status),
		}
	}
}

fn read_output(mut pipe: impl AsFd + io::Read) -> io::Result<String> {
	// After exit, reject unexpectedly open pipes and cap the diagnostic bytes.
	fcntl_setfl(&pipe, fcntl_getfl(&pipe)? | OFlags::NONBLOCK)?;
	let mut bytes = Vec::new();
	pipe.by_ref()
		.take(u64::from(OUTPUT_LIMIT) + 1)
		.read_to_end(&mut bytes)?;
	if bytes.len() > usize::from(OUTPUT_LIMIT) {
		return Err(io::Error::other(
			"post-creation child exceeded its output bound",
		));
	}
	String::from_utf8(bytes).map_err(io::Error::other)
}

pub(super) fn verify_history(history: &File, artifacts: &[Artifact; 4]) -> TestResult {
	for (name, artifact) in NAMES.into_iter().zip(artifacts) {
		assert_eq!(read(history, name.as_bytes())?, artifact.bytes);
	}
	Ok(())
}

pub(super) fn exercise(
	sandbox: &mut Sandbox,
	profile: &File,
	request: ManagedSyncInit<'_>,
) -> TestResult {
	let replay = ManagedSyncInit { ..request };

	// Only the dedicated child runs under this mask. O_EXCL can create the
	// slot, but the resulting mode cannot satisfy private record custody.
	let previous = umask(Mode::RUSR | Mode::WUSR);
	let first = initialize_managed_preview(request);
	umask(previous);
	let slot = open_child(profile, SLOT, OFlags::PATH)?;
	sandbox.track_created_slot(profile, SLOT)?;
	assert!(matches!(
		first,
		Err(ManagedSyncPreviewError::Store(SyncProfileStoreError::CreationUnconfirmed(cause)))
			if matches!(*cause, SyncProfileStoreError::Unprotected)
	));
	let incumbent = slot.metadata()?;
	assert!(incumbent.is_file());
	assert_eq!(
		(
			incumbent.mode() & 0o7777,
			incumbent.size(),
			incumbent.nlink()
		),
		(0, 0, 1)
	);

	assert!(matches!(
		initialize_managed_preview(replay),
		Err(ManagedSyncPreviewError::Store(
			SyncProfileStoreError::AlreadyExists
		))
	));
	let after = open_child(profile, SLOT, OFlags::PATH)?.metadata()?;
	assert_eq!(
		(
			after.dev(),
			after.ino(),
			after.mode(),
			after.size(),
			after.nlink()
		),
		(
			incumbent.dev(),
			incumbent.ino(),
			incumbent.mode(),
			incumbent.size(),
			incumbent.nlink()
		),
	);
	Ok(())
}
