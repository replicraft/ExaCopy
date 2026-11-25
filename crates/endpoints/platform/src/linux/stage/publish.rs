use exacopy_model::PublishNoClobber;
use rustix::fs::{self, RenameFlags};
use rustix::io::Errno;

use super::{ClosedStage, DirectoryBarriersError, PublishError};

impl ClosedStage<'_> {
	/// Consumes the stage and matching model authorization for one exclusive rename.
	///
	/// The model authorization relies on the coordinator's evidence for read-back
	/// verification, required metadata, and durable intent for this target.
	/// The target component was fixed at stage creation. This adapter checks the
	/// held stage and uses only Linux's no-replace rename.
	/// After a successful rename, it requests a barrier on each affected directory.
	///
	/// # Errors
	///
	/// A precondition failure, conflict or unsupported operation leaves the stage
	/// in place. An uncertain result requires reconciliation. A failed
	/// post-rename barrier leaves the successful rename in effect.
	/// No failure path removes or rolls back namespace entries.
	pub fn publish_no_clobber(self, authorization: PublishNoClobber) -> Result<(), PublishError> {
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

		let stage_result = fs::fsync(stage);
		let destination_result = fs::fsync(destination);
		let error = match (stage_result, destination_result) {
			(Ok(()), Ok(())) => return Ok(()),
			(Err(stage), Ok(())) => DirectoryBarriersError::Stage(stage.into()),
			(Ok(()), Err(destination)) => DirectoryBarriersError::Destination(destination.into()),
			(Err(stage), Err(destination)) => DirectoryBarriersError::Both {
				stage: stage.into(),
				destination: destination.into(),
			},
		};
		Err(PublishError::BarriersFailed(error))
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
