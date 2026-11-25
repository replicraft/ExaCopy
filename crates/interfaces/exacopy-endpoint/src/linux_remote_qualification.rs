//! Bounded native facts shared by the Linux adapter and qualification record owner.

use crate::linux_job::JobFileIdentity;

/// Maximum bytes for either exact kernel field, excluding its delimiter.
pub const MAX_REMOTE_KERNEL_FIELD_BYTES: usize = 256;
/// Maximum bytes for the exact selected mountinfo row, excluding its newline.
pub const MAX_REMOTE_MOUNT_RECORD_BYTES: usize = 2048;

/// Native machine architecture admitted by the destination-only adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteKernelArchitecture {
	/// Native Linux x86-64.
	X86_64,
	/// Native Linux AArch64.
	Aarch64,
}

/// Held directory and execution context for one Linux destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteDestinationIds {
	/// The destination directory device and inode. Its device equals the held mount's.
	pub root: JobFileIdentity,
	/// Effective Linux user ID in the observed context.
	pub effective_uid: u32,
	/// Effective Linux group ID in the observed context.
	pub effective_gid: u32,
	/// Exact UUID of the running Linux kernel boot.
	pub boot_id: [u8; 16],
	/// Calling thread's mount namespace inode number.
	pub mount_namespace: u64,
	/// Ordinary kernel mount number used to join the mountinfo row.
	pub mount_id: u64,
	/// Kernel unique mount ID for the held descriptor.
	pub unique_mount: u64,
}

/// Bounded destination-only facts, suitable for an authenticated record projection.
///
/// The native adapter establishes these observations. The structural constructor
/// supplies no evidence of native execution or qualification.
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteDestinationFacts {
	ids: RemoteDestinationIds,
	architecture: RemoteKernelArchitecture,
	kernel_release: Box<[u8]>,
	kernel_build: Box<[u8]>,
	mount_record: Box<[u8]>,
}

impl RemoteDestinationFacts {
	/// Accepts exact bounded fields and nonreserved native identities.
	#[must_use]
	pub fn new(
		ids: RemoteDestinationIds,
		architecture: RemoteKernelArchitecture,
		kernel_release: &[u8],
		kernel_build: &[u8],
		mount_record: &[u8],
	) -> Option<Self> {
		if ids.root.inode == 0
			|| ids.boot_id == [0; 16]
			|| ids.mount_namespace == 0
			|| ids.mount_id == 0
			|| ids.unique_mount == 0
			|| !bounded(kernel_release, MAX_REMOTE_KERNEL_FIELD_BYTES)
			|| !bounded(kernel_build, MAX_REMOTE_KERNEL_FIELD_BYTES)
			|| !bounded(mount_record, MAX_REMOTE_MOUNT_RECORD_BYTES)
		{
			return None;
		}
		Some(Self {
			ids,
			architecture,
			kernel_release: kernel_release.into(),
			kernel_build: kernel_build.into(),
			mount_record: mount_record.into(),
		})
	}

	/// Returns the bound native identities.
	#[must_use]
	pub const fn ids(&self) -> RemoteDestinationIds {
		self.ids
	}

	/// Returns the observed native architecture.
	#[must_use]
	pub const fn architecture(&self) -> RemoteKernelArchitecture {
		self.architecture
	}

	/// Returns the exact bounded kernel release field.
	#[must_use]
	pub fn kernel_release(&self) -> &[u8] {
		&self.kernel_release
	}

	/// Returns the exact bounded kernel build field.
	#[must_use]
	pub fn kernel_build(&self) -> &[u8] {
		&self.kernel_build
	}

	/// Returns the exact mountinfo row, including mount paths and option order.
	#[must_use]
	pub fn mount_record(&self) -> &[u8] {
		&self.mount_record
	}
}

fn bounded(bytes: &[u8], limit: usize) -> bool {
	!bytes.is_empty()
		&& bytes.len() <= limit
		&& !bytes.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
}

impl std::fmt::Debug for RemoteDestinationFacts {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("RemoteDestinationFacts")
			.field("ids", &self.ids)
			.field("architecture", &self.architecture)
			.finish_non_exhaustive()
	}
}

/// Facts and exact signed-record digest supplied to the native adapter.
///
/// The caller authenticates the separately selected qualification and checks its
/// route, campaign and build before constructing this structural projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteDestinationQualification {
	facts: RemoteDestinationFacts,
	exact_record_digest: [u8; 32],
}

impl RemoteDestinationQualification {
	/// Wraps checked fields and refuses the reserved zero digest.
	#[must_use]
	pub fn new(facts: RemoteDestinationFacts, exact_record_digest: [u8; 32]) -> Option<Self> {
		(exact_record_digest != [0; 32]).then_some(Self {
			facts,
			exact_record_digest,
		})
	}

	/// Returns the exact facts projected from the selected record.
	#[must_use]
	pub const fn facts(&self) -> &RemoteDestinationFacts {
		&self.facts
	}

	/// Returns the exact signed-record digest.
	#[must_use]
	pub const fn digest(&self) -> [u8; 32] {
		self.exact_record_digest
	}
}
