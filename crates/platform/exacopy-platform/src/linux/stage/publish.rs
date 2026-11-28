use std::ffi::OsStr;
use std::fs::File;

use exacopy_model::PublishNoClobber;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags, Stat};
use rustix::io::{self, Errno};

use super::super::handle::{FileIdentity, mount_id};
use super::directory::CHILD_RESOLVE;
use super::{ClosedStage, DestinationRoot, DirectoryBarriersError, PublishError, StageError};

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
		sync: impl FnMut(&File) -> io::Result<()>,
	) -> Result<(), PublishError> {
		if authorization.binding() != self.location.binding {
			return Err(PublishError::BindingMismatch);
		}
		self.check_current().map_err(PublishError::StageChanged)?;

		let stage = self.location.directory;
		let names = PublicationNames {
			stage: &stage.directory,
			stage_name: self.location.name.as_os_str(),
			destination: stage.root,
			target_name: self.location.target.as_os_str(),
		};
		names.rename()?;
		names.sync_directories(sync)?;
		stage
			.check_current()
			.map_err(PublishError::ObservationFailed)?;
		names
			.observe_target(self.identity())
			.map_err(PublishError::ObservationFailed)?;
		Ok(())
	}
}

pub(in crate::linux) struct PublicationNames<'scope> {
	pub stage: &'scope File,
	pub stage_name: &'scope OsStr,
	pub destination: &'scope DestinationRoot,
	pub target_name: &'scope OsStr,
}

impl PublicationNames<'_> {
	pub(in crate::linux) fn rename(&self) -> Result<(), PublishError> {
		fs::renameat_with(
			self.stage,
			self.stage_name,
			&self.destination.directory,
			self.target_name,
			RenameFlags::NOREPLACE,
		)
		.map_err(rename_error)
	}

	pub(in crate::linux) fn sync_directories(
		&self,
		sync: impl FnMut(&File) -> io::Result<()>,
	) -> Result<(), PublishError> {
		self.sync_directory_pair(sync)
			.map_err(PublishError::BarriersFailed)
	}

	pub(in crate::linux) fn sync_directory_pair(
		&self,
		mut sync: impl FnMut(&File) -> io::Result<()>,
	) -> Result<(), DirectoryBarriersError> {
		let stage_result = sync(self.stage);
		let destination_result = sync(&self.destination.directory);
		let error = match (stage_result, destination_result) {
			(Ok(()), Ok(())) => return Ok(()),
			(Err(stage), Ok(())) => DirectoryBarriersError::Stage(stage.into()),
			(Ok(()), Err(destination)) => DirectoryBarriersError::Destination(destination.into()),
			(Err(stage), Err(destination)) => DirectoryBarriersError::Both {
				stage: stage.into(),
				destination: destination.into(),
			},
		};
		Err(error)
	}

	pub(in crate::linux) fn observe_target(
		&self,
		identity: FileIdentity,
	) -> Result<Stat, StageError> {
		match fs::statat(self.stage, self.stage_name, AtFlags::SYMLINK_NOFOLLOW) {
			Err(Errno::NOENT) => {}
			Ok(_) => return Err(StageError::IdentityChanged),
			Err(error) => return Err(error.into()),
		}
		let target = fs::openat2(
			&self.destination.directory,
			self.target_name,
			OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
			Mode::empty(),
			CHILD_RESOLVE,
		)?;
		let stat = fs::fstat(&target)?;
		if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
			|| FileIdentity::from_stat(&stat) != identity
			|| mount_id(&target)? != self.destination.mount
		{
			return Err(StageError::IdentityChanged);
		}
		Ok(stat)
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
