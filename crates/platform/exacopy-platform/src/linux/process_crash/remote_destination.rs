use std::error::Error;
use std::os::unix::ffi::OsStrExt as _;
use std::{fmt, io};

use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_remote_qualification::{
	MAX_REMOTE_KERNEL_FIELD_BYTES, MAX_REMOTE_MOUNT_RECORD_BYTES, RemoteDestinationFacts,
	RemoteDestinationIds, RemoteDestinationQualification, RemoteKernelArchitecture,
};
use nix::sys::utsname::{UtsName, uname};
use rustix::fs;
use rustix::process::{getegid, geteuid};

use super::super::mount_observation::{MountObservations, ProcMounts};
use super::{KERNEL_BOOT_ID_BYTES, mount, parse_boot_id};
use crate::linux::{DestinationRoot, ProcessCrashProfileError, StageError};

#[cfg(test)]
mod tests;

/// An authenticated qualification projection matched to one held Linux destination.
///
/// The caller authenticates the qualification under its independently selected
/// attestor, and verifies the selected transport profile, build and campaign before projecting
/// the record here. This capability checks the corresponding current native
/// facts. Publication and receipt barriers are separate operation evidence.
#[derive(Debug)]
pub struct RemoteDestinationEligibility<'root> {
	root: &'root DestinationRoot,
	expected: &'root RemoteDestinationQualification,
}

impl<'root> RemoteDestinationEligibility<'root> {
	/// Admits the exact selected qualification under the held destination.
	///
	/// # Errors
	/// Refuses an absent verified projection, unsupported facts or a mismatch.
	pub fn admit(
		root: &'root DestinationRoot,
		expected: Option<&'root RemoteDestinationQualification>,
	) -> Result<Self, RemoteDestinationEligibilityError> {
		let expected = expected.ok_or(RemoteDestinationEligibilityError::Unqualified)?;
		let evidence = Self { root, expected };
		evidence.recheck_for(root)?;
		Ok(evidence)
	}

	/// Rechecks the same held destination and its exact native facts.
	///
	/// # Errors
	/// Refuses a different root capability or changed/unavailable observations.
	pub fn recheck_for(
		&self,
		root: &DestinationRoot,
	) -> Result<(), RemoteDestinationEligibilityError> {
		if !std::ptr::eq(root, self.root) {
			return Err(RemoteDestinationEligibilityError::DifferentRoot);
		}
		if &observe_remote_destination(root)? != self.expected.facts() {
			return Err(RemoteDestinationEligibilityError::EnvironmentChanged);
		}
		Ok(())
	}

	/// Returns the digest of the selected authenticated qualification record.
	#[must_use]
	pub const fn qualification_digest(&self) -> [u8; 32] {
		self.expected.digest()
	}
}

/// Observes bounded native destination facts without any source root or write.
///
/// The selected ext4 mountinfo row is retained exactly, including native paths,
/// flags and option order. Admission compares it within one boot and mount
/// namespace. Changed row bytes require requalification for this profile.
///
/// # Errors
/// Refuses an unsafe root, unsupported kernel or mount, and absent, oversized
/// or inconsistent observations.
pub fn observe_remote_destination(
	root: &DestinationRoot,
) -> Result<RemoteDestinationFacts, RemoteDestinationEligibilityError> {
	let proc = ProcMounts::open().map_err(RemoteDestinationEligibilityError::Proc)?;
	let first = observe(root, &proc)?;
	if first != observe(root, &proc)? {
		return Err(RemoteDestinationEligibilityError::EnvironmentChanged);
	}
	Ok(first)
}

fn observe(
	root: &DestinationRoot,
	proc: &ProcMounts,
) -> Result<RemoteDestinationFacts, RemoteDestinationEligibilityError> {
	use RemoteDestinationEligibilityError as Error;

	root.check_current().map_err(Error::Destination)?;
	let current = crate::linux::handle::file_identity(&root.directory)
		.map_err(|source| Error::Mount(source.into()))?;
	if current != root.identity() {
		return Err(Error::EnvironmentChanged);
	}
	let kernel = read_kernel(uname)?;
	if kernel.sysname().as_bytes() != b"Linux" {
		return Err(Error::UnsupportedKernel);
	}
	let architecture = match kernel.machine().as_bytes() {
		b"x86_64" if cfg!(target_arch = "x86_64") => RemoteKernelArchitecture::X86_64,
		b"aarch64" if cfg!(target_arch = "aarch64") => RemoteKernelArchitecture::Aarch64,
		_ => return Err(Error::UnsupportedKernel),
	};
	let boot_id = parse_boot_id(
		&proc
			.root_file(c"sys/kernel/random/boot_id", KERNEL_BOOT_ID_BYTES)
			.map_err(Error::Proc)?,
	)
	.ok_or(Error::UnsupportedKernel)?;
	let namespace = proc.namespace_id().map_err(Error::Proc)?;
	let mount = mount::observe(&root.directory).map_err(Error::Mount)?;
	if mount.id != root.mount || mount.device != current.device() {
		return Err(Error::UnsupportedMount);
	}
	let table = proc.mount_table().map_err(Error::Proc)?;
	let row = remote_mount_row(&table, mount)?;
	let release = kernel_field(proc, c"sys/kernel/osrelease", kernel.release().as_bytes())?;
	let build = kernel_field(proc, c"sys/kernel/version", kernel.version().as_bytes())?;
	let facts = RemoteDestinationFacts::new(
		RemoteDestinationIds {
			root: JobFileIdentity {
				device: current.device(),
				inode: current.inode(),
			},
			effective_uid: geteuid().as_raw(),
			effective_gid: getegid().as_raw(),
			boot_id,
			mount_namespace: namespace,
			mount_id: mount.id,
			unique_mount: mount.unique_id,
		},
		architecture,
		&release,
		&build,
		row,
	)
	.ok_or(Error::UnsupportedObservation)?;
	root.check_current().map_err(Error::Destination)?;
	if proc.namespace_id().map_err(Error::Proc)? != namespace
		|| mount::observe(&root.directory).map_err(Error::Mount)? != mount
	{
		return Err(Error::EnvironmentChanged);
	}
	Ok(facts)
}

fn read_kernel(
	call: impl FnOnce() -> nix::Result<UtsName>,
) -> Result<UtsName, RemoteDestinationEligibilityError> {
	call().map_err(|cause| RemoteDestinationEligibilityError::KernelIo(cause.into()))
}

fn remote_mount_row(
	table: &MountObservations,
	mount: mount::Mount,
) -> Result<&[u8], RemoteDestinationEligibilityError> {
	use RemoteDestinationEligibilityError as Error;
	let record = table.record(mount.id).ok_or(Error::UnsupportedMount)?;
	if record.device != (fs::major(mount.device), fs::minor(mount.device))
		|| record.root != b"/"
		|| record.filesystem != b"ext4"
		|| !is_writable(record.mount_options)
		|| !is_writable(record.super_options)
	{
		return Err(Error::UnsupportedMount);
	}
	table
		.record_bytes(mount.id)
		.filter(|row| row.len() <= MAX_REMOTE_MOUNT_RECORD_BYTES)
		.ok_or(Error::UnsupportedObservation)
}

fn is_writable(options: &[u8]) -> bool {
	let mut flags = options.split(|byte| *byte == b',');
	flags.next() == Some(b"rw")
		&& flags.all(|flag| !flag.is_empty() && !matches!(flag, b"ro" | b"rw"))
}

fn kernel_field(
	proc: &ProcMounts,
	path: &std::ffi::CStr,
	uname: &[u8],
) -> Result<Vec<u8>, RemoteDestinationEligibilityError> {
	use RemoteDestinationEligibilityError as Error;
	let mut text = proc
		.root_file(path, MAX_REMOTE_KERNEL_FIELD_BYTES + 1)
		.map_err(Error::Proc)?;
	if text.pop() != Some(b'\n') || text != uname {
		return Err(Error::UnsupportedKernel);
	}
	Ok(text)
}

/// A refused or changed destination-only qualification.
#[derive(Debug)]
#[non_exhaustive]
pub enum RemoteDestinationEligibilityError {
	/// The caller supplied no independently verified qualification.
	Unqualified,
	/// This is a different held root capability.
	DifferentRoot,
	/// Exact native facts differ from the selected qualification.
	EnvironmentChanged,
	/// The kernel build, architecture or observations are unsupported.
	UnsupportedKernel,
	/// The held mount is outside the supported whole writable ext4 scope.
	UnsupportedMount,
	/// A native field violated the qualification projection bounds.
	UnsupportedObservation,
	/// The held destination failed its managed-root policy.
	Destination(StageError),
	/// Bounded procfs observations failed.
	Proc(io::Error),
	/// The native uname syscall failed.
	KernelIo(io::Error),
	/// The held native mount could not be identified.
	Mount(ProcessCrashProfileError),
}

impl fmt::Display for RemoteDestinationEligibilityError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Unqualified => "no verified remote destination qualification was supplied",
			Self::DifferentRoot => "remote qualification belongs to a different held destination",
			Self::EnvironmentChanged => "the remote destination qualification environment changed",
			Self::UnsupportedKernel => {
				"the Linux kernel observations are outside the supported scope"
			}
			Self::UnsupportedMount => "the held mount is outside the remote destination scope",
			Self::UnsupportedObservation => "a native observation exceeds the qualification bounds",
			Self::Destination(_) => "the held remote destination root became unsafe",
			Self::Proc(_) => "the bounded Linux qualification observations could not be read",
			Self::KernelIo(_) => "the Linux kernel identification call failed",
			Self::Mount(_) => "the held Linux mount could not be identified for qualification",
		})
	}
}

impl Error for RemoteDestinationEligibilityError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Destination(cause) => Some(cause),
			Self::Proc(cause) | Self::KernelIo(cause) => Some(cause),
			Self::Mount(cause) => Some(cause),
			_ => None,
		}
	}
}
