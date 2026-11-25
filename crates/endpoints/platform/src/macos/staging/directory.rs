use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;
use std::path::Path;
use std::process;

use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, Stat};
use rustix::io::Errno;

use super::super::{
	DIRECTORY_OPEN, DirectoryIdentity, ManagedObjectIdentity, ManagedReadError, ManagedReadGrant,
	ManagedRegularFile, PhysicalFsid, ReadDirectory, capture_directory, check_directory_authority,
	open_provisioned_directory, provisioned_path_components, volume, with_materialization_disabled,
};
use super::entropy::fill_stage_entropy;
use super::identity::RANDOM_STAGE_ID_BYTES;
use super::{StageBindingContext, StageError, WriteStage};

pub mod jobs;

#[cfg(test)]
mod tests;

/// Owner attestation for a provisioned destination and its private staging child.
#[derive(Debug)]
pub struct ManagedStageGrant(());

impl ManagedStageGrant {
	/// Records authorization for the exact local APFS directory and its provisioned staging child.
	///
	/// The caller establishes a materialized, stable, trusted namespace outside File Provider
	/// and supplies a held root opened without redirection or lookup triggers. The exact staging
	/// child must already be reserved for this application. Neither root nor child may have
	/// untrusted retained handles or aliases. Every cooperating same-UID actor must hold an
	/// exclusive Darwin flock on an independently opened directory descriptor before mutating the
	/// directory or its entries, including through aliases. The caller excludes privileged actors
	/// and other processes which do not follow this coordination contract.
	///
	/// The acquiring process owns the capabilities. Do not fork while an operation can hold
	/// a stage writer, from exclusive creation through closing or dropping the writer.
	/// No child may use an inherited staging capability or descriptor. Close-on-exec
	/// applies after successful exec. A successful close in the acquiring process only
	/// confirms closure of that process's write descriptor.
	#[must_use]
	pub const fn trusted_owner_authorizes_provisioned_root() -> Self {
		Self(())
	}
}

/// A held destination on local APFS with a process-bound exclusive advisory lease.
///
/// Drop in the acquiring process explicitly requests release of the lock on the held
/// open description.
pub struct ManagedStageRoot {
	lease: DirectoryLease,
}

impl ManagedStageRoot {
	/// Independently opens and locks the supplied, authorized destination directory.
	///
	/// # Errors
	/// Rejects unqualified roots, lease conflicts, and directory or thread policy failures.
	pub fn from_provisioned_directory(
		directory: File,
		_grant: ManagedStageGrant,
	) -> Result<Self, StageError> {
		with_materialization_disabled(|| {
			let imported = capture_directory(&directory)?;
			let reopened = fs::openat(&directory, c".", DIRECTORY_OPEN, Mode::empty())?;
			let lease = DirectoryLease::bind(reopened.into(), imported)?;
			Ok(Self { lease })
		})
	}

	/// Returns a fresh identity observation of the held destination parent.
	/// # Errors
	/// Refuses an invalid lease, changed identity or unavailable filesystem evidence.
	pub fn observe_identity(&self) -> Result<ManagedObjectIdentity, StageError> {
		with_materialization_disabled(|| self.lease.observe_identity())
	}

	/// Opens a separately authorized source under this destination's exclusive lease.
	///
	/// The read grant must cover the selected file and the independently resolved absolute
	/// source parent. The source parent must have the same held physical directory identity
	/// as the destination. The read view borrows this lease and exposes only positioned reads
	/// and revalidation.
	///
	/// # Errors
	/// Rejects an unqualified source parent or child, a different parent identity, a lease
	/// owned by another process, changed observations, and filesystem or thread policy failures.
	pub fn open_regular_source<'root>(
		&'root self,
		source_parent: &Path,
		name: UnixComponent<'root>,
		_grant: ManagedReadGrant,
	) -> Result<ManagedRegularFile<'root>, ManagedReadError> {
		let directory = ReadDirectory {
			directory: &self.lease.file,
			owner: self.lease.owner,
			identity: self.lease.identity,
			lease_process: self.lease.lease_process,
		};
		directory.check_process()?;
		let relative = provisioned_path_components(source_parent)?;
		with_materialization_disabled(|| {
			let source = open_provisioned_directory(relative)?;
			let identity = capture_directory(&source)?;
			if identity != directory.identity {
				return Err(ManagedReadError::UnsupportedNamespace);
			}
			check_directory_authority(&source, directory.owner, identity)?;
			directory.open_with_policy(name)
		})
	}

	/// Selects an already provisioned owner-private staging child on the same volume.
	///
	/// The existing child reserves its name in the destination, including on APFS volumes
	/// where multiple spellings can address the same entry.
	///
	/// # Errors
	/// Rejects changed, inaccessible, unqualified, or already leased directories.
	pub fn open_stage_directory<'root>(
		&'root self,
		name: UnixComponent<'root>,
	) -> Result<StageDirectory<'root>, StageError> {
		self.lease.check_process()?;
		with_materialization_disabled(|| {
			self.lease.check_current()?;
			let observed = self.lease.named_stat(name)?;
			if FileType::from_raw_mode(observed.st_mode) != FileType::Directory {
				return Err(StageError::DirectoryChanged);
			}
			let child = fs::openat(
				&self.lease.file,
				name.as_bytes(),
				DIRECTORY_OPEN,
				Mode::empty(),
			)?;
			let identity =
				DirectoryIdentity::from_stat(&observed, self.lease.identity.physical_fsid)?;
			let lease = DirectoryLease::bind(child.into(), identity)?;
			let directory = StageDirectory {
				root: self,
				job: None,
				name,
				lease,
			};
			directory.check_current()?;
			Ok(directory)
		})
	}
}

impl fmt::Debug for ManagedStageRoot {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("ManagedStageRoot")
			.finish_non_exhaustive()
	}
}

/// A held private directory with exclusive leases on its namespace ancestors.
pub struct StageDirectory<'root> {
	root: &'root ManagedStageRoot,
	job: Option<&'root jobs::JobDirectory<'root>>,
	name: UnixComponent<'root>,
	lease: DirectoryLease,
}

impl StageDirectory<'_> {
	/// Returns a fresh identity observation of the held and named staging directory.
	/// # Errors
	/// Refuses changed or unavailable namespace evidence and invalid leases.
	pub fn observe_identity(&self) -> Result<ManagedObjectIdentity, StageError> {
		with_materialization_disabled(|| {
			self.check_current()?;
			Ok(self.lease.identity.observe(&self.lease.file)?)
		})
	}

	/// Exclusively creates a private file bound to its transaction, target and logical extent.
	///
	/// The adapter generates the attempt's StageId before creation. Attempts within this
	/// process receive distinct IDs. Random bits make a repeated ID across processes unlikely.
	///
	/// # Errors
	/// Rejects unsupported lengths, name collisions, unsafe directories, ID allocation failures,
	/// and filesystem or thread policy failures. A possibly created stage is retained and its
	/// allocated identity is returned for reconciliation.
	pub fn create_file<'stage>(
		&'stage self,
		name: UnixComponent<'stage>,
		target: UnixComponent<'stage>,
		context: StageBindingContext,
		length: u64,
	) -> Result<WriteStage<'stage>, StageError> {
		self.create_file_with_entropy(name, target, context, length, fill_stage_entropy)
	}

	fn create_file_with_entropy<'stage>(
		&'stage self,
		name: UnixComponent<'stage>,
		target: UnixComponent<'stage>,
		context: StageBindingContext,
		length: u64,
		entropy: impl FnOnce(&mut [u8; RANDOM_STAGE_ID_BYTES]) -> io::Result<()>,
	) -> Result<WriteStage<'stage>, StageError> {
		self.check_process()?;
		if self
			.job
			.is_some_and(|job| job.name().job_id() != context.job())
		{
			return Err(StageError::JobBindingMismatch);
		}
		if length > MAX_FILE_LENGTH {
			return Err(StageError::InvalidLength);
		}
		let mut attempted = None;
		let result = with_materialization_disabled(|| {
			self.check_current()?;
			self.check_target_absent(target)?;
			let identity = context.allocate(entropy)?;
			attempted = Some(identity);
			WriteStage::create(self, name, target, identity, length)
		});
		match (attempted, result) {
			(Some(identity), Err(source)) if !matches!(source, StageError::NameCollision) => {
				Err(StageError::CreateUncertain {
					identity,
					source: Box::new(source),
				})
			}
			(_, result) => result,
		}
	}

	pub(super) fn check_process(&self) -> Result<(), StageError> {
		self.root.lease.check_process()?;
		self.lease.check_process()
	}

	pub(super) fn check_current(&self) -> Result<(), StageError> {
		self.check_process()?;
		self.root.lease.check_current()?;
		self.lease.check_current()?;
		let named = match self.job {
			Some(job) => job.named_stage_stat(self.name)?,
			None => self.root.lease.named_stat(self.name)?,
		};
		if !self.lease.identity.matches_stat(&named) {
			return Err(StageError::DirectoryChanged);
		}
		Ok(())
	}

	fn check_target_absent(&self, target: UnixComponent<'_>) -> Result<(), StageError> {
		match fs::statat(
			self.destination(),
			target.as_bytes(),
			AtFlags::SYMLINK_NOFOLLOW,
		) {
			Ok(_) => Err(StageError::NameCollision),
			Err(Errno::NOENT) => Ok(()),
			Err(error) => Err(error.into()),
		}
	}

	pub(super) fn observe_directories(
		&self,
	) -> Result<(ManagedObjectIdentity, ManagedObjectIdentity), StageError> {
		self.check_current()?;
		Ok((
			self.lease.identity.observe(&self.lease.file)?,
			self.root.lease.identity.observe(&self.root.lease.file)?,
		))
	}

	pub(super) fn destination(&self) -> &File {
		&self.root.lease.file
	}

	pub(super) fn descriptor(&self) -> &File {
		&self.lease.file
	}

	pub(super) fn owner(&self) -> u32 {
		self.lease.owner
	}

	pub(super) fn physical_fsid(&self) -> PhysicalFsid {
		self.lease.identity.physical_fsid
	}

	pub(super) fn named_stat(&self, name: UnixComponent<'_>) -> Result<Stat, StageError> {
		self.lease.named_stat(name)
	}
}

impl fmt::Debug for StageDirectory<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("StageDirectory")
			.finish_non_exhaustive()
	}
}

struct DirectoryLease {
	file: File,
	owner: u32,
	identity: DirectoryIdentity,
	lease_process: u32,
}

impl DirectoryLease {
	fn bind(file: File, expected: DirectoryIdentity) -> Result<Self, StageError> {
		let identity = capture_directory(&file)?;
		if identity != expected {
			return Err(StageError::DirectoryChanged);
		}
		let owner = rustix::process::geteuid().as_raw();
		check_directory_authority(&file, owner, identity)?;
		if !volume::supports_managed_root(file.as_fd())? {
			return Err(ManagedReadError::UnsupportedNamespace.into());
		}
		let lease = Self::lock(file, owner, identity)?;
		lease.check_current()?;
		Ok(lease)
	}

	fn lock(file: File, owner: u32, identity: DirectoryIdentity) -> Result<Self, StageError> {
		match fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
			Ok(()) => {}
			Err(Errno::AGAIN) => return Err(StageError::DirectoryBusy),
			Err(error) => return Err(error.into()),
		}
		Ok(Self {
			file,
			owner,
			identity,
			lease_process: process::id(),
		})
	}

	fn check_process(&self) -> Result<(), StageError> {
		if self.lease_process != process::id() {
			return Err(StageError::WrongProcess);
		}
		Ok(())
	}

	fn check_current(&self) -> Result<(), StageError> {
		self.check_process()?;
		Ok(check_directory_authority(
			&self.file,
			self.owner,
			self.identity,
		)?)
	}

	fn observe_identity(&self) -> Result<ManagedObjectIdentity, StageError> {
		self.check_current()?;
		Ok(self.identity.observe(&self.file)?)
	}

	fn named_stat(&self, name: UnixComponent<'_>) -> Result<Stat, StageError> {
		let stat = fs::statat(&self.file, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW)?;
		if stat.st_dev != self.identity.device
			|| PhysicalFsid::named(self.file.as_fd(), name)? != Some(self.identity.physical_fsid)
		{
			return Err(StageError::DirectoryChanged);
		}
		Ok(stat)
	}
}

impl Drop for DirectoryLease {
	fn drop(&mut self) {
		// Closing our descriptor may leave the open description alive after fork.
		// Only the acquiring process may explicitly release the lock on it.
		if self.lease_process == process::id() {
			let _ = fs::flock(&self.file, FlockOperation::Unlock);
		}
	}
}
