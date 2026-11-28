use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_apply::{
	CheckedPublication, CheckedRenameFailure, HeldCheckedPublication, NativeRenameFacts,
	PublishedFacts,
};
use exacopy_model::PublishNoClobber;
use rustix::fs::{self, Mode, Stat};

use super::super::{ClosedStage, check_content_stamp, check_no_visible_attributes};
use crate::linux::handle::{FileIdentity, mount_id};
use crate::linux::stage::PublicationNames;
use crate::linux::{DirectoryBarriersError, PublishError, StageError, TargetStatus};

#[cfg(test)]
mod tests;

/// Native failures during the original checked stage publication.
#[derive(Debug)]
#[non_exhaustive]
pub enum CheckedStageError {
	/// The original stage or namespace refused readiness or observation.
	Custody(Box<StageError>),
	/// The supplied model permit names another attempt.
	Binding,
	/// The exact submitted no-replace result.
	Rename(Box<PublishError>),
	/// A separately recorded failure of one or both original-directory barriers.
	Barriers(Box<DirectoryBarriersError>),
}

impl CheckedStageError {
	fn custody(cause: StageError) -> Self {
		Self::Custody(Box::new(cause))
	}

	fn rename(cause: PublishError) -> Self {
		Self::Rename(Box::new(cause))
	}

	fn barriers(cause: DirectoryBarriersError) -> Self {
		Self::Barriers(Box::new(cause))
	}
}

impl fmt::Display for CheckedStageError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Custody(cause) => {
				write!(formatter, "checked publication custody failed ({cause})")
			}
			Self::Binding => {
				formatter.write_str("checked publication permit belongs to another stage")
			}
			Self::Rename(cause) => fmt::Display::fmt(cause, formatter),
			Self::Barriers(cause) => fmt::Display::fmt(cause, formatter),
		}
	}
}

impl Error for CheckedStageError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Custody(cause) => Some(cause.as_ref()),
			Self::Binding => None,
			Self::Rename(cause) => Some(cause.as_ref()),
			Self::Barriers(cause) => Some(cause.as_ref()),
		}
	}
}

/// The original independently verified inode, held after checked publication.
pub struct NativePublishedStage<'stage> {
	stage: ClosedStage<'stage>,
	settled: Stat,
}

impl fmt::Debug for NativePublishedStage<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("NativePublishedStage")
			.field("identity", &self.stage.identity())
			.finish_non_exhaustive()
	}
}

impl<'stage> CheckedPublication for ClosedStage<'stage> {
	type Error = CheckedStageError;
	type Held = NativePublishedStage<'stage>;

	fn publish_checked<Fence, Refusal, Guard>(
		self,
		permit: PublishNoClobber,
		final_check: impl FnOnce() -> Result<Fence, Refusal>,
		enter: impl FnOnce(Fence, NativeRenameFacts<'_>) -> io::Result<Guard>,
	) -> Result<Self::Held, CheckedRenameFailure<Self::Error, Refusal>> {
		self.publish_checked_with(
			permit,
			final_check,
			enter,
			|names| names.rename(),
			|directory| fs::fsync(directory),
		)
	}
}

impl<'stage> ClosedStage<'stage> {
	fn publish_checked_with<Fence, Refusal, Guard>(
		self,
		permit: PublishNoClobber,
		final_check: impl FnOnce() -> Result<Fence, Refusal>,
		enter: impl FnOnce(Fence, NativeRenameFacts<'_>) -> io::Result<Guard>,
		submit: impl FnOnce(&PublicationNames<'_>) -> Result<(), PublishError>,
		sync: impl FnMut(&File) -> rustix::io::Result<()>,
	) -> Result<NativePublishedStage<'stage>, CheckedRenameFailure<CheckedStageError, Refusal>>
	{
		use CheckedRenameFailure as Failure;

		if permit.binding() != self.location.binding {
			return Err(Failure::Preflight(CheckedStageError::Binding));
		}
		let (before, facts) = self
			.checked_readiness()
			.map_err(|cause| Failure::Preflight(CheckedStageError::custody(cause)))?;
		let names = self.checked_names();
		let fence = final_check().map_err(Failure::Refused)?;
		let guard = enter(fence, facts).map_err(Failure::Admission)?;
		let rename = submit(&names);
		drop(guard);

		let ambiguous = match rename {
			Ok(()) => None,
			Err(cause @ PublishError::Conflict) => {
				return Err(Failure::Conflict(CheckedStageError::rename(cause)));
			}
			Err(cause @ PublishError::Unsupported(_)) => {
				return Err(Failure::NotPerformed(CheckedStageError::rename(cause)));
			}
			Err(cause) => Some(CheckedStageError::rename(cause)),
		};

		// Neither expiry nor a failed observation stops settlement of a submitted rename.
		let first = self.observe_renamed(&names, &before);
		let barriers = names.sync_directory_pair(sync);
		let final_state = self.observe_renamed(&names, &before);
		let observation = first.and_then(|first| {
			let final_state = final_state?;
			check_same_metadata(&first, &final_state)?;
			Ok(final_state)
		});
		if let Some(cause) = ambiguous {
			return Err(Failure::Uncertain {
				cause,
				observation: observation.err().map(CheckedStageError::custody),
				barriers: barriers.err().map(CheckedStageError::barriers),
			});
		}
		match (observation, barriers) {
			(Ok(settled), Ok(())) => Ok(NativePublishedStage {
				stage: self,
				settled,
			}),
			(observation, barriers) => Err(Failure::PublishedIncomplete {
				observation: observation.err().map(CheckedStageError::custody),
				barriers: barriers.err().map(CheckedStageError::barriers),
			}),
		}
	}
}

impl HeldCheckedPublication for NativePublishedStage<'_> {
	type Error = CheckedStageError;

	fn recheck_published(&self) -> Result<PublishedFacts, Self::Error> {
		let names = self.stage.checked_names();
		let current = self
			.stage
			.observe_renamed(&names, &self.settled)
			.map_err(CheckedStageError::custody)?;
		check_same_metadata(&self.settled, &current).map_err(CheckedStageError::custody)?;
		Ok(PublishedFacts {
			target: self.stage.identity().into(),
			stage_directory: self.stage.location.directory.identity().into(),
			destination: names.destination.identity().into(),
		})
	}
}

impl ClosedStage<'_> {
	fn checked_names(&self) -> PublicationNames<'_> {
		let directory = self.location.directory;
		PublicationNames {
			stage: &directory.directory,
			stage_name: self.location.name.as_os_str(),
			destination: directory.root,
			target_name: self.location.target.as_os_str(),
		}
	}

	fn checked_readiness(&self) -> Result<(Stat, NativeRenameFacts<'_>), StageError> {
		let directory = self.location.directory;
		if !self.metadata_applied || !directory.is_fresh_job_stage() {
			return Err(StageError::MetadataMismatch);
		}
		self.check_current()?;
		let named = self
			.location
			.check_named_file(Mode::from_raw_mode(self.stat.st_mode))?;
		let held = self.observe_held()?;
		check_same_metadata(&self.stat, &named)?;
		check_same_metadata(&self.stat, &held)?;
		let target = UnixComponent::new(self.location.target.as_os_str().as_bytes())
			.map_err(|_| StageError::IdentityChanged)?;
		if directory.root.target_status(target)? != TargetStatus::Absent {
			return Err(StageError::AlreadyExists);
		}
		Ok((
			held,
			NativeRenameFacts {
				binding: self.location.binding,
				stage: self.identity().into(),
				stage_directory: directory.identity().into(),
				destination: directory.root.identity().into(),
				target,
			},
		))
	}

	fn observe_held(&self) -> Result<Stat, StageError> {
		let current = fs::fstat(&self.file)?;
		if FileIdentity::from_stat(&current) != self.identity()
			|| mount_id(&self.file)? != self.location.directory.root.mount
		{
			return Err(StageError::IdentityChanged);
		}
		check_no_visible_attributes(&self.file)?;
		Ok(current)
	}

	fn observe_renamed(
		&self,
		names: &PublicationNames<'_>,
		before: &Stat,
	) -> Result<Stat, StageError> {
		self.location.directory.check_current()?;
		let named = names.observe_target(self.identity())?;
		let held = self.observe_held()?;
		check_same_metadata(&named, &held)?;
		// Only the namespace transition may establish a new ctime, which is
		// compared unmodified across later post-rename observations.
		let mut expected = *before;
		expected.st_ctime = held.st_ctime;
		expected.st_ctime_nsec = held.st_ctime_nsec;
		check_same_metadata(&expected, &held)?;
		self.location.directory.check_current()?;
		Ok(held)
	}
}

fn check_same_metadata(expected: &Stat, current: &Stat) -> Result<(), StageError> {
	check_content_stamp(expected, current)?;
	if FileIdentity::from_stat(expected) != FileIdentity::from_stat(current)
		|| expected.st_mode != current.st_mode
		|| expected.st_uid != current.st_uid
		|| expected.st_gid != current.st_gid
		|| current.st_nlink != 1
		|| expected.st_atime != current.st_atime
		|| expected.st_atime_nsec != current.st_atime_nsec
	{
		return Err(StageError::MetadataMismatch);
	}
	Ok(())
}
