use std::fs::File;

use rustix::fs::{self, FlockOperation, Mode, OFlags};

use super::super::job::try_lock_job;
use super::{CHILD_RESOLVE, RecoveryJob, StageError, file_identity, mount_id};

/// An ongoing, read-only inspection lease on one local private job.
///
/// This pins a separately opened directory description with an advisory shared
/// lock. Cooperating copy writers use the exclusive lock on the same inode.
#[must_use]
pub struct RecoveryReadLease<'lease> {
	file: File,
	job: &'lease RecoveryJob<'lease>,
}

impl<'lease> RecoveryReadLease<'lease> {
	/// Borrows the exact held job for read-only observations under this lease.
	#[must_use]
	pub const fn job(&self) -> &'lease RecoveryJob<'lease> {
		self.job
	}

	pub(super) fn recheck(&self) -> Result<(), StageError> {
		if file_identity(&self.file)? != self.job.identity()
			|| mount_id(&self.file)? != self.job.root.mount
		{
			return Err(StageError::IdentityChanged);
		}
		self.job.recheck()
	}
}

impl RecoveryJob<'_> {
	/// Claims a nonblocking shared lease for consistent cooperative inspection.
	///
	/// # Errors
	/// Reports a busy job, unsupported lock, or changed binding.
	pub fn try_read_lease(&self) -> Result<RecoveryReadLease<'_>, StageError> {
		let file = lock_job(self, FlockOperation::NonBlockingLockShared)?;
		Ok(RecoveryReadLease { file, job: self })
	}
}

pub(super) fn lock_job(
	job: &RecoveryJob<'_>,
	operation: FlockOperation,
) -> Result<File, StageError> {
	job.recheck()?;
	let file = reopen_directory(&job.directory.file, job.identity(), job.root.mount)?;
	try_lock_job(&file, operation)?;
	job.recheck()?;
	Ok(file)
}

pub(super) fn reopen_directory(
	directory: &File,
	identity: super::FileIdentity,
	mount: u64,
) -> Result<File, StageError> {
	let file = fs::openat2(
		directory,
		c".",
		OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
		Mode::empty(),
		CHILD_RESOLVE,
	)?
	.into();
	if file_identity(&file)? != identity || mount_id(&file)? != mount {
		return Err(StageError::IdentityChanged);
	}
	Ok(file)
}
