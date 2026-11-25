use std::fs::File;

use exacopy_model::PublishNoClobber;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags};
use rustix::io::{self, Errno};

use super::super::handle::{FileIdentity, mount_id};
use super::directory::CHILD_RESOLVE;
use super::{ClosedStage, DirectoryBarriersError, PublishError, StageError};

#[cfg(test)]
mod tests;

impl ClosedStage<'_> {
	/// Consumes the stage and matching model authorization for one exclusive rename.
	///
	/// The model authorization relies on the coordinator's evidence for read-back
	/// verification, required metadata, and durable intent for this target.
	/// The target component was fixed at stage creation. This adapter checks the
	/// held stage and uses only Linux's no-replace rename.
	/// After a successful rename, it requests a barrier on each affected directory.
	/// It then observes the target's identity and the absence of the private name.
	///
	/// # Errors
	///
	/// A precondition failure, conflict or unsupported operation leaves the stage
	/// in place. An uncertain result requires reconciliation. A failed
	/// post-rename barrier or observation leaves the rename in effect.
	/// No failure path removes or rolls back namespace entries.
	pub fn publish_no_clobber(self, authorization: PublishNoClobber) -> Result<(), PublishError> {
		self.publish_with_barriers(authorization, |directory| fs::fsync(directory))
	}

	fn publish_with_barriers(
		self,
		authorization: PublishNoClobber,
		mut sync: impl FnMut(&File) -> io::Result<()>,
	) -> Result<(), PublishError> {
		if authorization.binding() != self.location.binding {
			return Err(PublishError::BindingMismatch);
		}
		self.check_current().map_err(PublishError::StageChanged)?;

		let stage = &self.location.directory.directory;
		let destination = &self.location.directory.root.directory;
		fs::renameat_with(
			stage,
			self.location.name.as_os_str(),
			destination,
			self.location.target.as_os_str(),
			RenameFlags::NOREPLACE,
		)
		.map_err(rename_error)?;

		let stage_result = sync(stage);
		let destination_result = sync(destination);
		let error = match (stage_result, destination_result) {
			(Ok(()), Ok(())) => {
				return self
					.observe_publication()
					.map_err(PublishError::ObservationFailed);
			}
			(Err(stage), Ok(())) => DirectoryBarriersError::Stage(stage.into()),
			(Ok(()), Err(destination)) => DirectoryBarriersError::Destination(destination.into()),
			(Err(stage), Err(destination)) => DirectoryBarriersError::Both {
				stage: stage.into(),
				destination: destination.into(),
			},
		};
		Err(PublishError::BarriersFailed(error))
	}

	fn observe_publication(&self) -> Result<(), StageError> {
		let stage = self.location.directory;
		stage.check_current()?;
		match fs::statat(
			&stage.directory,
			self.location.name.as_os_str(),
			AtFlags::SYMLINK_NOFOLLOW,
		) {
			Err(Errno::NOENT) => {}
			Ok(_) => return Err(StageError::IdentityChanged),
			Err(error) => return Err(error.into()),
		}
		let target = fs::openat2(
			&stage.root.directory,
			self.location.target.as_os_str(),
			OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
			Mode::empty(),
			CHILD_RESOLVE,
		)?;
		let stat = fs::fstat(&target)?;
		if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
			|| FileIdentity::from_stat(&stat) != self.identity()
			|| mount_id(&target)? != stage.root.mount
		{
			return Err(StageError::IdentityChanged);
		}
		Ok(())
	}
}

fn rename_error(source: Errno) -> PublishError {
	match source {
		Errno::EXIST => PublishError::Conflict,
		Errno::INVAL | Errno::NOSYS | Errno::OPNOTSUPP | Errno::XDEV => {
			PublishError::Unsupported(source.into())
		}
		_ => PublishError::Uncertain(source.into()),
	}
}
