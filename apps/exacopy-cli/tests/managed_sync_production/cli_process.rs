//! Exact runner-selected Linux executable and bounded, owned invocations.

use std::ffi::OsString;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsFd, AsRawFd as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::fs::{self, MemfdFlags, Mode, OFlags, ResolveFlags, SealFlags};
use rustix::io::Errno;
use rustix::process::{Pid, WaitId, WaitIdOptions, geteuid, waitid};
use sha2::{Digest as _, Sha256};

use super::TestResult;

const MAX_IMAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_STDIN_BYTES: usize = 24 * 1024;
const MAX_OUTPUT_BYTES: usize = 4096;
const MAX_SIGNED_EXPORT_STDOUT_BYTES: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(15);
const REAP_DEADLINE: Duration = Duration::from_secs(2);
const WAIT_TICK: Duration = Duration::from_millis(10);

pub(super) struct Cli {
	executable: File,
	stamp: Stamp,
	pub(super) sha256: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Stamp {
	device: u64,
	inode: u64,
	bytes: u64,
	mode: u32,
	owner: (u32, u32),
	links: u64,
	mtime: (i64, i64),
	ctime: (i64, i64),
}

impl From<&Metadata> for Stamp {
	fn from(meta: &Metadata) -> Self {
		Self {
			device: meta.dev(),
			inode: meta.ino(),
			bytes: meta.size(),
			mode: meta.mode(),
			owner: (meta.uid(), meta.gid()),
			links: meta.nlink(),
			mtime: (meta.mtime(), meta.mtime_nsec()),
			ctime: (meta.ctime(), meta.ctime_nsec()),
		}
	}
}

#[derive(Debug)]
pub(super) struct UnconfirmedProcess(String);

impl fmt::Display for UnconfirmedProcess {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(&self.0)
	}
}

impl std::error::Error for UnconfirmedProcess {}

pub(super) struct Output {
	pub(super) status: ExitStatus,
	pub(super) stdout: Vec<u8>,
	pub(super) stderr: Vec<u8>,
}

impl Cli {
	pub(super) fn from_runner() -> TestResult<Self> {
		let fd = decimal("EXACOPY_MANAGED_SYNC_CLI_FD")?;
		if !(3..=i32::MAX as u64).contains(&fd) {
			return Err("invalid passed CLI descriptor".into());
		}
		let sha256 = std::env::var("EXACOPY_MANAGED_SYNC_CLI_SHA256")?;
		if sha256.len() != 64
			|| !sha256
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
		{
			return Err("invalid selected CLI SHA-256".into());
		}
		let proc = File::from(fs::openat2(
			fs::CWD,
			c"/proc",
			OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
			Mode::empty(),
			ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
		)?);
		if fs::fstatfs(&proc)?.f_type != fs::PROC_SUPER_MAGIC || proc.metadata()?.ino() != 1 {
			return Err("CLI binding requires the verified procfs root".into());
		}
		let flags = inherited_flags(&proc, fd)?;
		if flags.intersects(OFlags::ACCMODE | OFlags::PATH) {
			return Err("passed CLI descriptor must be read-only and readable".into());
		}
		let executable = File::from(fs::openat(
			&proc,
			format!("self/fd/{fd}").as_str(),
			OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
			Mode::empty(),
		)?);
		let metadata = executable.metadata()?;
		let stamp = Stamp::from(&metadata);
		if !metadata.is_file()
			|| stamp.owner.0 != geteuid().as_raw()
			|| stamp.links == 0
			|| stamp.mode & 0o500 != 0o500
			|| stamp.mode & 0o7022 != 0
			|| u64::from(stamp.mode & 0o7777) != decimal("EXACOPY_MANAGED_SYNC_CLI_MODE")?
			|| stamp.device != decimal("EXACOPY_MANAGED_SYNC_CLI_DEV")?
			|| stamp.inode != decimal("EXACOPY_MANAGED_SYNC_CLI_INO")?
			|| stamp.inode == 0
			|| stamp.bytes != decimal("EXACOPY_MANAGED_SYNC_CLI_SIZE")?
			|| !(4..=MAX_IMAGE_BYTES).contains(&stamp.bytes)
		{
			return Err("passed CLI descriptor does not match the pinned private artifact".into());
		}
		let candidate = Self {
			executable,
			stamp,
			sha256,
		};
		let mut magic = [0; 4];
		candidate.executable.read_exact_at(&mut magic, 0)?;
		if magic != *b"\x7fELF" {
			return Err("passed CLI artifact is not an ELF".into());
		}
		candidate.verify_digest()?;
		Ok(candidate)
	}

	pub(super) fn verify_digest(&self) -> TestResult {
		self.recheck()?;
		let mut hasher = Sha256::new();
		let mut buffer = [0; 16 * 1024];
		let mut offset = 0;
		while offset < self.stamp.bytes {
			let count = usize::try_from((self.stamp.bytes - offset).min(buffer.len().try_into()?))?;
			self.executable
				.read_exact_at(&mut buffer[..count], offset)?;
			hasher.update(&buffer[..count]);
			offset += u64::try_from(count)?;
		}
		if self.executable.read_at(&mut buffer[..1], offset)? != 0
			|| format!("{:x}", hasher.finalize()) != self.sha256
		{
			return Err(
				"held CLI artifact extent or SHA-256 differs from the approved image".into(),
			);
		}
		self.recheck()
	}

	pub(super) fn invoke(
		&self,
		args: &[OsString],
		input: &[u8],
		read_only_output: Option<File>,
	) -> TestResult<Output> {
		self.invoke_with_stdout_limit(args, input, read_only_output, MAX_OUTPUT_BYTES)
	}

	pub(super) fn invoke_signed_export(
		&self,
		args: &[OsString],
		input: &[u8],
	) -> TestResult<Output> {
		self.invoke_with_stdout_limit(args, input, None, MAX_SIGNED_EXPORT_STDOUT_BYTES)
	}

	fn invoke_with_stdout_limit(
		&self,
		args: &[OsString],
		input: &[u8],
		read_only_output: Option<File>,
		stdout_limit: usize,
	) -> TestResult<Output> {
		self.recheck()?;
		let capture = read_only_output.is_none();
		let stdout = read_only_output.map_or_else(Stdio::piped, Stdio::from);
		// The fixed proc link resolves our own
		// held, independently checked ELF, with no executable search.
		let mut launch = Command::new(format!("/proc/self/fd/{}", self.executable.as_raw_fd()));
		launch
			.args(args)
			.env_clear()
			.env("LC_ALL", "C")
			.stdin(Stdio::from(input_file(input)?))
			.stdout(stdout)
			.stderr(Stdio::piped());
		let mut child = launch.spawn()?;
		let output = observe(&mut child, capture, stdout_limit)?;
		self.recheck()?;
		Ok(output)
	}

	fn recheck(&self) -> TestResult {
		if Stamp::from(&self.executable.metadata()?) != self.stamp {
			return Err("pinned CLI artifact changed during fixture".into());
		}
		Ok(())
	}
}

fn inherited_flags(proc: &File, fd: u64) -> TestResult<OFlags> {
	let file = File::from(fs::openat(
		proc,
		format!("self/fdinfo/{fd}").as_str(),
		OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
		Mode::empty(),
	)?);
	let mut output = String::new();
	file.take(4097).read_to_string(&mut output)?;
	if output.len() > 4096 {
		return Err("CLI descriptor status exceeds its bound".into());
	}
	let mut flags = output
		.lines()
		.filter_map(|line| line.strip_prefix("flags:\t"));
	let value = u32::from_str_radix(flags.next().ok_or("missing CLI descriptor flags")?, 8)?;
	if flags.next().is_some() {
		return Err("duplicate CLI descriptor flags".into());
	}
	Ok(OFlags::from_bits_retain(value))
}

fn decimal(name: &str) -> TestResult<u64> {
	let text = std::env::var(name)?;
	let scalar: u64 = text.parse()?;
	if scalar.to_string() != text {
		return Err(io::Error::other(format!("noncanonical CLI pin {name}")).into());
	}
	Ok(scalar)
}

fn input_file(input: &[u8]) -> TestResult<File> {
	if input.len() > MAX_STDIN_BYTES {
		return Err("CLI fixture stdin exceeds its bound".into());
	}
	let mut file = File::from(fs::memfd_create(
		c"exacopy-managed-sync-input",
		MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
	)?);
	file.write_all(input)?;
	file.seek(SeekFrom::Start(0))?;
	fs::fcntl_add_seals(
		&file,
		SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
	)?;
	Ok(file)
}

fn observe(child: &mut Child, capture: bool, stdout_limit: usize) -> TestResult<Output> {
	let pid = i32::try_from(child.id())
		.ok()
		.and_then(Pid::from_raw)
		.ok_or_else(|| UnconfirmedProcess("invalid CLI child process ID".into()))?;
	let mut stdout_pipe = child.stdout.take();
	let mut stderr_pipe = child.stderr.take();
	let mut stdout = Vec::new();
	let mut stderr = Vec::new();
	let observation = (|| -> TestResult {
		if capture != stdout_pipe.is_some() || stderr_pipe.is_none() {
			return Err("missing CLI child output pipe".into());
		}
		if let Some(pipe) = stdout_pipe.as_ref() {
			nonblocking(pipe)?;
		}
		if let Some(pipe) = stderr_pipe.as_ref() {
			nonblocking(pipe)?;
		}
		let start = Instant::now();
		loop {
			drain(stdout_pipe.as_mut(), &mut stdout, stdout_limit)?;
			drain(stderr_pipe.as_mut(), &mut stderr, MAX_OUTPUT_BYTES)?;
			match waitid(
				WaitId::Pid(pid),
				WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
			) {
				Ok(Some(_)) => return Ok(()),
				Ok(None) | Err(Errno::INTR) => {}
				Err(Errno::CHILD) => {
					return Err(
						UnconfirmedProcess("CLI child status lost before cleanup".into()).into(),
					);
				}
				Err(error) => return Err(error.into()),
			}
			if start.elapsed() >= DEADLINE {
				return Err("managed CLI child exceeded deadline".into());
			}
			thread::sleep(WAIT_TICK);
		}
	})();

	if let Err(error) = &observation
		&& error.is::<UnconfirmedProcess>()
	{
		return Err(UnconfirmedProcess(error.to_string()).into());
	}

	// Keep the exact child in the outer runner's process group. On failure,
	// terminate and reap this child directly before touching fixture state.
	let status = if observation.is_ok() {
		reap(child)
	} else {
		let termination = child.kill();
		let status = reap(child);
		if status.is_err() {
			return Err(UnconfirmedProcess(format!(
				"CLI child cleanup unconfirmed ({termination:?}, {status:?}); observation={observation:?}",
			))
			.into());
		}
		status
	};
	let status =
		status.map_err(|error| UnconfirmedProcess(format!("CLI child reap failed ({error})")))?;
	observation?;
	if !drain(stdout_pipe.as_mut(), &mut stdout, stdout_limit)?
		|| !drain(stderr_pipe.as_mut(), &mut stderr, MAX_OUTPUT_BYTES)?
	{
		return Err(
			UnconfirmedProcess("CLI output remained open after child cleanup".into()).into(),
		);
	}
	Ok(Output {
		status,
		stdout,
		stderr,
	})
}

fn reap(child: &mut Child) -> io::Result<ExitStatus> {
	let start = Instant::now();
	loop {
		if let Some(status) = child.try_wait()? {
			return Ok(status);
		}
		if start.elapsed() >= REAP_DEADLINE {
			return Err(io::Error::new(
				io::ErrorKind::TimedOut,
				"CLI process could not be reaped",
			));
		}
		thread::sleep(WAIT_TICK);
	}
}

fn nonblocking(pipe: impl AsFd) -> io::Result<()> {
	fs::fcntl_setfl(&pipe, fs::fcntl_getfl(&pipe)? | OFlags::NONBLOCK)?;
	Ok(())
}

fn drain(mut pipe: Option<impl io::Read>, output: &mut Vec<u8>, limit: usize) -> io::Result<bool> {
	let Some(pipe) = pipe.as_mut() else {
		return Ok(true);
	};
	let mut bytes = [0; 1024];
	loop {
		match pipe.read(&mut bytes) {
			Ok(0) => return Ok(true),
			Ok(length) if output.len() + length <= limit => {
				output.extend_from_slice(&bytes[..length])
			}
			Ok(_) => {
				return Err(io::Error::other(
					"managed CLI child exceeded its output bound",
				));
			}
			Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
			Err(error) => return Err(error),
		}
	}
}
