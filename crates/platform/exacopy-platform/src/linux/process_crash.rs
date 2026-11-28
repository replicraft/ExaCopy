//! Matches held roots to the exact environment of the Linux process-kill evidence.

use std::error::Error;
use std::fmt;
use std::io;

use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_recovery::ApplyRecoveryEnvironment;
use rustix::io::Errno;

use super::mount_observation::ProcMounts;
use super::{DestinationRoot, ReadRoot, StageError};

mod mount;
mod remote_destination;

pub use remote_destination::{
	RemoteDestinationEligibility, RemoteDestinationEligibilityError, observe_remote_destination,
};
#[cfg(test)]
mod tests;

const MAX_KERNEL_FIELD_BYTES: usize = 256;
pub(super) const KERNEL_BOOT_ID_BYTES: usize = 37;
const KERNEL_RELEASE: &[u8] = b"6.8.0-147-generic\n";
const KERNEL_BUILD: &[u8] = b"#147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:39:52 UTC 2026\n";

/// The profile of the witnessed native qualification environment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessCrashProfileId {
	/// The ARM64 Ubuntu/ext4 fixture with Linux 6.8.0-147-generic.
	Arm64UbuntuExt4FixtureV1,
}

/// Factual environment information from one evaluated boot and mount namespace.
///
/// Values decoded from an untrusted plan or discovered at the point of apply
/// supply no qualification. Provision the expected value independently from
/// controlled native evidence before matching a request to this profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessCrashEnvironment {
	/// Linux boot identity as the 16 bytes of the kernel's boot UUID.
	pub boot_id: [u8; 16],
	/// Mount namespace identifier observed through the calling thread's procfs view.
	pub mount_namespace: u64,
	/// The unique mount identity of the evaluated root mount in this boot.
	pub unique_mount: u64,
	/// The Linux device number of that mount.
	pub device: u64,
}

/// The requested roots match the independently selected native environment.
///
/// This capability is eligibility evidence only. The caller still needs checked
/// intent, publication, barrier and receipt evidence for a process-crash claim.
/// The profile assumes a trusted kernel and mount namespace, an intact backing
/// device, and process interruption with the kernel remaining live. Same-mount
/// source and destination roots are specific to this evaluated fixture.
/// Cross-volume process-crash qualification remains separate.
pub struct ProcessCrashEligibility<'root> {
	expected: ProcessCrashEnvironment,
	source: &'root ReadRoot,
	destination: &'root DestinationRoot,
}

impl<'root> ProcessCrashEligibility<'root> {
	/// Matches separately provisioned evidence to the exact two held roots.
	/// # Errors
	/// Reports unsupported native facts, mismatched evidence, or failed observation.
	pub fn admit(
		expected: ProcessCrashEnvironment,
		source: &'root ReadRoot,
		destination: &'root DestinationRoot,
	) -> Result<Self, ProcessCrashProfileError> {
		let eligible = Self {
			expected,
			source,
			destination,
		};
		eligible.recheck()?;
		Ok(eligible)
	}

	/// The fixed profile for the matching environment.
	#[must_use]
	pub const fn profile_id(&self) -> ProcessCrashProfileId {
		ProcessCrashProfileId::Arm64UbuntuExt4FixtureV1
	}

	pub(super) fn recheck_for_apply_inspection(
		&self,
		source: JobFileIdentity,
		destination: &DestinationRoot,
		expected: ApplyRecoveryEnvironment,
	) -> Result<(), ProcessCrashProfileError> {
		if !std::ptr::eq(self.destination, destination)
			|| JobFileIdentity::from(self.source.identity()) != source
		{
			return Err(ProcessCrashProfileError::EnvironmentChanged);
		}
		let observed = self.recheck_observed()?;
		if (
			observed.boot_id,
			observed.mount_namespace,
			observed.unique_mount,
			observed.device,
		) != (
			expected.boot_id,
			expected.mount_namespace,
			expected.unique_mount,
			expected.device,
		) {
			return Err(ProcessCrashProfileError::EnvironmentChanged);
		}
		Ok(())
	}

	/// Re-observes the original roots and environment before publication intent.
	/// # Errors
	/// Reports unavailable or changed native evidence.
	pub fn recheck(&self) -> Result<(), ProcessCrashProfileError> {
		self.recheck_observed().map(|_| ())
	}

	/// Returns the newly observed native facts after checking the original enrollment.
	/// # Errors
	/// Reports unavailable or changed native evidence for the same held roots.
	pub fn recheck_observed(&self) -> Result<ProcessCrashEnvironment, ProcessCrashProfileError> {
		let current = observe_process_crash_environment(self.source, self.destination)?;
		if current != self.expected {
			return Err(ProcessCrashProfileError::EnvironmentChanged);
		}
		Ok(current)
	}
}

/// Observes factual native values for a controlled qualification run.
/// # Errors
/// Refuses unsupported systems or mounts, missing observations, and native failures.
pub fn observe_process_crash_environment(
	source: &ReadRoot,
	destination: &DestinationRoot,
) -> Result<ProcessCrashEnvironment, ProcessCrashProfileError> {
	if !cfg!(target_arch = "aarch64") {
		return Err(ProcessCrashProfileError::UnsupportedKernel);
	}
	destination
		.check_current()
		.map_err(ProcessCrashProfileError::Destination)?;
	let proc = ProcMounts::open().map_err(proc_error)?;
	if proc
		.root_file(c"sys/kernel/osrelease", MAX_KERNEL_FIELD_BYTES)
		.map_err(proc_error)?
		!= KERNEL_RELEASE
		|| proc
			.root_file(c"sys/kernel/version", MAX_KERNEL_FIELD_BYTES)
			.map_err(proc_error)?
			!= KERNEL_BUILD
	{
		return Err(ProcessCrashProfileError::UnsupportedKernel);
	}
	let boot_id = parse_boot_id(
		&proc
			.root_file(c"sys/kernel/random/boot_id", KERNEL_BOOT_ID_BYTES)
			.map_err(proc_error)?,
	)
	.ok_or(ProcessCrashProfileError::UnsupportedProc)?;
	let mount_namespace = proc.namespace_id().map_err(proc_error)?;
	let source_directory = source.directory();
	let source_mount = mount::observe(source_directory)?;
	let destination_mount = mount::observe(&destination.directory)?;
	if source_mount != destination_mount
		|| source_mount.device != source.identity().device()
		|| destination_mount.device != destination.identity().device()
		|| destination_mount.id != destination.mount
	{
		return Err(ProcessCrashProfileError::UnsupportedMount);
	}
	let mountinfo = proc.mount_table().map_err(proc_error)?;
	if !mountinfo
		.record(destination_mount.id)
		.is_some_and(|record| mount::is_fixture_mount(&record, destination_mount))
		|| proc.namespace_id().map_err(proc_error)? != mount_namespace
		|| mount::observe(source_directory)? != source_mount
		|| mount::observe(&destination.directory)? != destination_mount
	{
		return Err(ProcessCrashProfileError::UnsupportedMount);
	}
	Ok(ProcessCrashEnvironment {
		boot_id,
		mount_namespace,
		unique_mount: destination_mount.unique_id,
		device: destination_mount.device,
	})
}

fn proc_error(error: io::Error) -> ProcessCrashProfileError {
	match error.kind() {
		io::ErrorKind::Unsupported | io::ErrorKind::InvalidData => {
			ProcessCrashProfileError::UnsupportedProc
		}
		_ => ProcessCrashProfileError::Io(error),
	}
}

pub(super) fn parse_boot_id(bytes: &[u8]) -> Option<[u8; 16]> {
	let text = bytes.strip_suffix(b"\n")?;
	if text.len() != 36 {
		return None;
	}
	let mut id = [0; 16];
	let mut digits = 0;
	for (index, &byte) in text.iter().enumerate() {
		if matches!(index, 8 | 13 | 18 | 23) {
			if byte != b'-' {
				return None;
			}
			continue;
		}
		let nibble = match byte {
			b'0'..=b'9' => byte - b'0',
			b'a'..=b'f' => byte - b'a' + 10,
			_ => return None,
		};
		id[digits / 2] = (id[digits / 2] << 4) | nibble;
		digits += 1;
	}
	(id != [0; 16]).then_some(id)
}

/// Why the current roots could not enter the process-crash profile.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProcessCrashProfileError {
	/// The architecture or kernel build is outside the evaluated profile.
	UnsupportedKernel,
	/// Required native process observations could not be established.
	UnsupportedProc,
	/// The held mounts or native mount records are outside the profile.
	UnsupportedMount,
	/// Fresh observations differ from the separately provisioned evidence.
	EnvironmentChanged,
	/// The held destination no longer meets its managed-root contract.
	Destination(StageError),
	/// A native read or descriptor operation failed.
	Io(io::Error),
}

impl fmt::Display for ProcessCrashProfileError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnsupportedKernel => {
				formatter.write_str("the kernel lacks process-crash profile evidence")
			}
			Self::UnsupportedProc => formatter
				.write_str("the process-crash profile requires bounded native procfs observations"),
			Self::UnsupportedMount => {
				formatter.write_str("the held roots lack matching process-crash mount evidence")
			}
			Self::EnvironmentChanged => formatter.write_str(
				"the observed environment differs from the selected process-crash profile",
			),
			Self::Destination(_) => {
				formatter.write_str("process-crash destination root admission failed")
			}
			Self::Io(_) => formatter.write_str("process-crash environment observation failed"),
		}
	}
}

impl Error for ProcessCrashProfileError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Destination(error) => Some(error),
			Self::Io(error) => Some(error),
			_ => None,
		}
	}
}

impl From<Errno> for ProcessCrashProfileError {
	fn from(error: Errno) -> Self {
		Self::Io(error.into())
	}
}
