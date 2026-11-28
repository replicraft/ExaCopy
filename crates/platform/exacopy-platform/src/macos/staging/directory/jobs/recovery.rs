use std::fmt;
use std::fs::File;
use std::os::fd::AsFd as _;
use std::path::Path;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, AtFlags, FileType, Mode, Stat};
use rustix::io::Errno;

use self::record::{FIRST_SEGMENT_LIMIT, RECORD_LIMIT, RecordParent};
use super::super::super::super::{
	DIRECTORY_MODE, DIRECTORY_OPEN, PhysicalFsid, acl, with_materialization_disabled,
};
use super::super::{
	ManagedStageGrant, ManagedStageRoot, open_provisioned_directory, provisioned_path_components,
};
use super::receipt::{RECEIPT, RECEIPT_PENDING, name_is_occupied};
use super::record::{FIRST_SEGMENT, OWNER, PLAN};
use super::{
	DirectoryIdentity, DirectoryLease, JOURNAL, JobArtifact, JobName, ManagedObjectIdentity,
	RECEIPTS, StageDirectory, StageError, checked_component,
};

mod error;
mod inventory;
mod name;
mod record;

pub use error::RecoveryError;
pub use inventory::{
	RecoveryFileObservation, RecoveryInventory, RecoveryName, RecoveryStageReader,
};
pub use record::RecoveryRecord;

/// Opens an existing private job under an explicitly provisioned destination and container.
///
/// Walks the raw absolute destination path one component at a time without
/// following symlinks and with dataless materialization disabled. The grant
/// attests a stable trusted namespace and excludes mount and lookup triggers.
/// The container is a single existing child of that destination. The callback
/// borrows the read-only job while the destination, container and job leases
/// are held. The caller independently selects its record verification authority.
/// # Errors
/// Reports invalid paths, unsafe or changed evidence, missing objects, and
/// conflicting leases before invoking the callback.
pub fn with_provisioned_recovery_job<T>(
	destination: &Path,
	container: UnixComponent<'_>,
	job: JobName,
	grant: ManagedStageGrant,
	observe: impl for<'job> FnOnce(&RecoveryJob<'job>) -> T,
) -> Result<T, RecoveryError> {
	let relative = provisioned_path_components(destination)?;
	let directory = with_materialization_disabled(|| open_provisioned_directory(relative))?;
	let root = ManagedStageRoot::from_provisioned_directory(directory, grant)?;
	let container = root.open_stage_directory(container)?;
	let job = container.open_recovery_job(job)?;
	Ok(observe(&job))
}

impl StageDirectory<'_> {
	/// Independently opens the canonical private name for a known job.
	///
	/// Holds a process-bound exclusive advisory lease on the job and borrows the
	/// managed destination and container leases. The result carries observations.
	/// Record authentication and association with a trusted profile belong to the caller.
	///
	/// # Errors
	/// Rejects nested stage directories, missing or unsafe objects, inconclusive
	/// namespace evidence and lease conflicts.
	pub fn open_recovery_job(&self, name: JobName) -> Result<RecoveryJob<'_>, RecoveryError> {
		if self.job.is_some() {
			return Err(RecoveryError::NestedJob);
		}
		let component = name.to_string().into_boxed_str();
		with_materialization_disabled(|| {
			self.check_current()?;
			let directory =
				RecoveryDirectory::open(&self.lease, component.as_bytes(), JobArtifact::Directory)?;
			self.check_current()?;
			Ok(RecoveryJob {
				container: self,
				name,
				component,
				directory,
			})
		})
	}
}

/// Read-only inspection of one job held under the managed APFS coordination contract.
pub struct RecoveryJob<'container> {
	container: &'container StageDirectory<'container>,
	name: JobName,
	component: Box<str>,
	directory: RecoveryDirectory,
}

impl RecoveryJob<'_> {
	/// Returns the typed private job name used for admission.
	#[must_use]
	pub const fn name(&self) -> JobName {
		self.name
	}

	/// Returns the native job directory observation taken at admission.
	#[must_use]
	pub const fn identity(&self) -> ManagedObjectIdentity {
		self.directory.identity
	}

	/// Returns the effective UID checked against the private job directory.
	#[must_use]
	pub const fn owner_uid(&self) -> u32 {
		self.directory.lease.owner
	}

	/// Revalidates the job binding and returns the observed destination root.
	///
	/// # Errors
	/// Fails when any held ancestor or the named job cannot be revalidated.
	pub fn observe_destination(&self) -> Result<ManagedObjectIdentity, RecoveryError> {
		with_materialization_disabled(|| {
			self.check_current()?;
			Ok(self.container.root.lease.observe_identity()?)
		})
	}

	/// Opens the fixed private owner bytes for bounded read-only inspection.
	///
	/// # Errors
	/// Rejects missing, unsafe, rebound or out-of-bounds records.
	pub fn open_owner(&self) -> Result<RecoveryRecord<'_>, RecoveryError> {
		self.open_record(JobArtifact::Owner, OWNER, RECORD_LIMIT)
	}

	/// Opens the fixed private plan bytes for bounded read-only inspection.
	///
	/// # Errors
	/// Rejects missing, unsafe, rebound or out-of-bounds records.
	pub fn open_plan(&self) -> Result<RecoveryRecord<'_>, RecoveryError> {
		self.open_record(JobArtifact::Plan, PLAN, RECORD_LIMIT)
	}

	/// Opens the fixed first journal segment under an independent journal lease.
	///
	/// Empty segments and incomplete frames are opaque bytes in this interface.
	///
	/// # Errors
	/// Rejects missing, unsafe, rebound or oversized records and lease conflicts.
	pub fn open_first_segment(&self) -> Result<RecoveryRecord<'_>, RecoveryError> {
		with_materialization_disabled(|| {
			self.check_current()?;
			let journal =
				RecoveryDirectory::open(&self.directory.lease, JOURNAL, JobArtifact::Journal)?;
			RecoveryRecord::open(
				RecordParent::Child {
					job: self,
					directory: journal,
					name: JOURNAL,
				},
				JobArtifact::FirstSegment,
				FIRST_SEGMENT,
				FIRST_SEGMENT_LIMIT,
			)
		})
	}

	/// Observes and opens the fixed initial receipt under a private receipt directory lease.
	///
	/// An absent receipt or absent private receipt directory returns `None`.
	/// The result contains opaque bytes awaiting interpretation by the caller.
	///
	/// # Errors
	/// Reports a pending receipt by name without opening it. Rejects unsafe or
	/// rebound final names, invalid record extents and lease conflicts.
	pub fn open_receipt(&self) -> Result<Option<RecoveryRecord<'_>>, RecoveryError> {
		with_materialization_disabled(|| {
			self.check_current()?;
			let Some(directory) = RecoveryDirectory::open_optional(
				&self.directory.lease,
				RECEIPTS,
				JobArtifact::Receipts,
			)?
			else {
				self.check_current()?;
				check_absent(
					&self.directory.lease,
					component(RECEIPTS, JobArtifact::Receipts)?,
					JobArtifact::Receipts,
				)?;
				return Ok(None);
			};
			directory.check_current(&self.directory.lease, RECEIPTS)?;
			let pending = component(RECEIPT_PENDING.to_bytes(), JobArtifact::ReceiptPending)?;
			if name_is_occupied(&directory.lease, pending)? {
				return Err(RecoveryError::PendingReceipt);
			}
			let parent = RecordParent::Child {
				job: self,
				directory,
				name: RECEIPTS,
			};
			RecoveryRecord::open_optional(
				parent,
				JobArtifact::Receipt,
				RECEIPT.to_bytes(),
				RECORD_LIMIT,
			)
		})
	}

	fn open_record(
		&self,
		artifact: JobArtifact,
		name: &'static [u8],
		limit: u64,
	) -> Result<RecoveryRecord<'_>, RecoveryError> {
		with_materialization_disabled(|| {
			RecoveryRecord::open(RecordParent::Job(self), artifact, name, limit)
		})
	}

	fn check_current(&self) -> Result<(), RecoveryError> {
		self.container.check_current()?;
		self.directory
			.check_current(&self.container.lease, self.component.as_bytes())
	}
}

impl fmt::Debug for RecoveryJob<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("RecoveryJob")
			.finish_non_exhaustive()
	}
}

struct RecoveryDirectory {
	lease: DirectoryLease,
	identity: ManagedObjectIdentity,
	artifact: JobArtifact,
}

impl RecoveryDirectory {
	fn open(
		parent: &DirectoryLease,
		raw_name: &[u8],
		artifact: JobArtifact,
	) -> Result<Self, RecoveryError> {
		let component = component(raw_name, artifact)?;
		let named = named_stat(parent, component, artifact)?;
		Self::bind(parent, raw_name, artifact, &named)
	}

	fn open_optional(
		parent: &DirectoryLease,
		raw_name: &[u8],
		artifact: JobArtifact,
	) -> Result<Option<Self>, RecoveryError> {
		let component = component(raw_name, artifact)?;
		match named_stat(parent, component, artifact) {
			Ok(named) => Self::bind(parent, raw_name, artifact, &named).map(Some),
			Err(RecoveryError::Missing(_)) => Ok(None),
			Err(error) => Err(error),
		}
	}

	fn bind(
		parent: &DirectoryLease,
		raw_name: &[u8],
		artifact: JobArtifact,
		named: &Stat,
	) -> Result<Self, RecoveryError> {
		let expected = DirectoryIdentity::from_stat(named, parent.identity.physical_fsid)
			.map_err(|_| RecoveryError::InvalidObject(artifact))?;
		if !private_directory(named, parent.owner) {
			return Err(RecoveryError::InvalidObject(artifact));
		}
		let file = File::from(fs::openat(
			&parent.file,
			raw_name,
			DIRECTORY_OPEN,
			Mode::empty(),
		)?);
		let lease = DirectoryLease::bind(file, expected).map_err(|error| match error {
			StageError::DirectoryBusy => RecoveryError::DirectoryBusy(artifact),
			StageError::DirectoryChanged => RecoveryError::InvalidObject(artifact),
			error => error.into(),
		})?;
		let directory = Self {
			identity: lease.identity.observe(&lease.file)?,
			lease,
			artifact,
		};
		directory.check_current(parent, raw_name)?;
		Ok(directory)
	}

	fn check_current(&self, parent: &DirectoryLease, raw_name: &[u8]) -> Result<(), RecoveryError> {
		self.lease.check_current()?;
		let component = component(raw_name, self.artifact)?;
		let named = named_stat(parent, component, self.artifact)?;
		let held = fs::fstat(&self.lease.file)?;
		if !self.lease.identity.matches_stat(&named)
			|| !self.lease.identity.matches_stat(&held)
			|| !private_directory(&held, parent.owner)
			|| !private_directory(&named, parent.owner)
			|| !acl::has_basic_acl(self.lease.file.as_fd())?
			|| !name::matches(&self.lease.file, component)?
		{
			return Err(RecoveryError::InvalidObject(self.artifact));
		}
		Ok(())
	}
}

fn private_directory(stat: &Stat, owner: u32) -> bool {
	FileType::from_raw_mode(stat.st_mode) == FileType::Directory
		&& Mode::from_raw_mode(stat.st_mode) == DIRECTORY_MODE
		&& stat.st_flags == 0
		&& stat.st_uid == owner
}

fn component(raw_name: &[u8], artifact: JobArtifact) -> Result<UnixComponent<'_>, RecoveryError> {
	checked_component(raw_name).map_err(|_| RecoveryError::InvalidObject(artifact))
}

fn named_stat(
	parent: &DirectoryLease,
	name: UnixComponent<'_>,
	artifact: JobArtifact,
) -> Result<Stat, RecoveryError> {
	lookup_stat(parent, name, RecoveryError::InvalidObject(artifact))?
		.ok_or(RecoveryError::Missing(artifact))
}

fn check_absent(
	parent: &DirectoryLease,
	name: UnixComponent<'_>,
	artifact: JobArtifact,
) -> Result<(), RecoveryError> {
	if lookup_stat(parent, name, RecoveryError::InvalidObject(artifact))?.is_some() {
		return Err(RecoveryError::InvalidObject(artifact));
	}
	Ok(())
}

fn lookup_stat(
	parent: &DirectoryLease,
	name: UnixComponent<'_>,
	mismatch: RecoveryError,
) -> Result<Option<Stat>, RecoveryError> {
	let observed = match fs::statat(&parent.file, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW) {
		Ok(stat) => stat,
		Err(Errno::NOENT) => return Ok(None),
		Err(error) => return Err(error.into()),
	};
	if observed.st_dev != parent.identity.device
		|| PhysicalFsid::named(parent.file.as_fd(), name)? != Some(parent.identity.physical_fsid)
	{
		return Err(mismatch);
	}
	Ok(Some(observed))
}
