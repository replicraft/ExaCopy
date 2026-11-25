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
	_file: File,
	_job: &'lease RecoveryJob<'lease>,
}

impl RecoveryJob<'_> {
	/// Claims a nonblocking shared lease for consistent cooperative inspection.
	///
	/// # Errors
	/// Reports a busy job, unsupported lock, or changed binding.
	pub fn try_read_lease(&self) -> Result<RecoveryReadLease<'_>, StageError> {
		let file = lock_job(self, FlockOperation::NonBlockingLockShared)?;
		Ok(RecoveryReadLease {
			_file: file,
			_job: self,
		})
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
