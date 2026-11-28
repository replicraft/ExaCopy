use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io;

use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_recovery::{
	ApplyContinuity, ApplyNameObservation, ApplyNamesSelection, ApplyRecoveryEnvironment,
	ApplyRecoveryMetadata, HeldPublicApplyNames,
};
use rustix::fs;

use crate::linux::ProcessCrashEligibility;
use crate::linux::handle::mount_id_no_follow;
use crate::linux::stage::check_no_visible_attributes;

use super::super::{
	FileIdentity, FilePolicy, PrivateDirectory, RecoveryFile, RecoveryReadLease, STAGE,
	SourceObservation, StageError, check_absent, component, mount_id, open_path,
	reopen_regular_without_atime,
};

/// Current stage and target pins retaining the shared job lease.
pub struct PublicApplyRecoveryNames<'view> {
	lease: &'view RecoveryReadLease<'view>,
	continuity: Option<Continuity<'view>>,
	stage_directory: Option<PrivateDirectory>,
	stage_name: Box<OsStr>,
	target_name: Box<OsStr>,
	stage: Option<CurrentName>,
	target: Option<CurrentName>,
}

#[derive(Clone, Copy)]
struct Continuity<'view> {
	eligibility: &'view ProcessCrashEligibility<'view>,
	source_root: JobFileIdentity,
	environment: ApplyRecoveryEnvironment,
}

impl<'view> PublicApplyRecoveryNames<'view> {
	pub(super) fn open(
		lease: &'view RecoveryReadLease<'view>,
		eligibility: Option<&'view ProcessCrashEligibility<'view>>,
		selection: ApplyNamesSelection<'_>,
	) -> Result<Self, StageError> {
		lease.recheck()?;
		let job = lease.job();
		let continuity = eligibility
			.zip(selection.environment)
			.filter(|(eligible, environment)| {
				eligible
					.recheck_for_apply_inspection(selection.source_root, job.root, *environment)
					.is_ok()
			})
			.map(|(eligibility, environment)| Continuity {
				eligibility,
				source_root: selection.source_root,
				environment,
			});
		let current_requirements = if continuity.is_some() {
			selection.candidate.zip(selection.required)
		} else {
			None
		};
		let mount = job.root.mount;
		let stage_name = component(selection.stage);
		let target_name = component(selection.target);
		let stage_directory =
			PrivateDirectory::open(&job.directory.file, OsStr::new(STAGE), mount)?;
		let stage = match &stage_directory {
			Some(directory) => {
				CurrentName::open(&directory.file, stage_name, mount, current_requirements)?
			}
			None => None,
		};
		let target = CurrentName::open(
			&job.root.directory,
			target_name,
			mount,
			current_requirements,
		)?;
		let held = Self {
			lease,
			continuity,
			stage_directory,
			stage_name: stage_name.into(),
			target_name: target_name.into(),
			stage,
			target,
		};
		held.recheck_names()?;
		Ok(held)
	}
}

impl fmt::Debug for PublicApplyRecoveryNames<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("PublicApplyRecoveryNames")
			.field("continuity", &self.continuity())
			.finish_non_exhaustive()
	}
}

impl HeldPublicApplyNames for PublicApplyRecoveryNames<'_> {
	type Record = RecoveryFile;
	type Error = StageError;

	fn continuity(&self) -> ApplyContinuity {
		if self.continuity.is_some() {
			ApplyContinuity::MatchedQualifiedScope
		} else {
			ApplyContinuity::Unqualified
		}
	}

	fn stage_directory_identity(&self) -> Option<JobFileIdentity> {
		self.stage_directory
			.as_ref()
			.map(|directory| directory.identity.into())
	}

	fn stage(&self) -> ApplyNameObservation<'_, Self::Record> {
		view(self.stage.as_ref())
	}

	fn target(&self) -> ApplyNameObservation<'_, Self::Record> {
		view(self.target.as_ref())
	}

	fn recheck_names(&self) -> Result<(), Self::Error> {
		self.lease.recheck()?;
		let job = self.lease.job();
		if let Some(continuity) = self.continuity {
			continuity
				.eligibility
				.recheck_for_apply_inspection(
					continuity.source_root,
					job.root,
					continuity.environment,
				)
				.map_err(|cause| StageError::System(io::Error::other(cause)))?;
		}
		let mount = job.root.mount;
		let job_directory = &job.directory.file;
		let directory_name = OsStr::new(STAGE);
		match &self.stage_directory {
			Some(directory) => {
				directory.recheck(job_directory, directory_name, mount)?;
				recheck_name(
					&directory.file,
					&self.stage_name,
					mount,
					self.stage.as_ref(),
				)?;
				directory.recheck(job_directory, directory_name, mount)?;
			}
			None => check_absent(job_directory, directory_name)?,
		}
		recheck_name(
			&job.root.directory,
			&self.target_name,
			mount,
			self.target.as_ref(),
		)?;
		self.lease.recheck()
	}
}

struct CurrentName {
	pin: File,
	identity: FileIdentity,
	candidate: Option<RecoveryFile>,
}

impl CurrentName {
	fn open(
		parent: &File,
		name: &OsStr,
		mount: u64,
		required: Option<(JobFileIdentity, ApplyRecoveryMetadata)>,
	) -> Result<Option<Self>, StageError> {
		let Some(pin) = open_path(parent, name)? else {
			return Ok(None);
		};
		let before = fs::fstat(&pin)?;
		let identity = FileIdentity::from_stat(&before);
		if mount_id_no_follow(&pin)? != mount {
			return Err(StageError::IdentityChanged);
		}
		let candidate = match required {
			Some((expected, metadata))
				if JobFileIdentity::from(identity) == expected
					&& FilePolicy::Stage.check(&before).is_ok() =>
			{
				let stamp = SourceObservation::capture(&before).map_err(StageError::ReadBack)?;
				open_candidate(&pin, mount, stamp, metadata)?
			}
			_ => None,
		};
		Ok(Some(Self {
			pin,
			identity,
			candidate,
		}))
	}
}

fn open_candidate(
	pin: &File,
	mount: u64,
	stamp: SourceObservation,
	required: ApplyRecoveryMetadata,
) -> Result<Option<RecoveryFile>, StageError> {
	if stamp.len() != required.length
		|| stamp.mode() != required.mode
		|| stamp.owner() != required.uid
		|| stamp.group() != required.gid
		|| (
			stamp.accessed_at().seconds(),
			stamp.accessed_at().nanoseconds(),
		) != (
			required.accessed_at.seconds,
			required.accessed_at.nanoseconds,
		)
		|| (
			stamp.modified_at().seconds(),
			stamp.modified_at().nanoseconds(),
		) != (
			required.modified_at.seconds,
			required.modified_at.nanoseconds,
		) {
		return Ok(None);
	}
	let (file, opened) = reopen_regular_without_atime(pin).map_err(StageError::ReadBack)?;
	if mount_id(&file)? != mount {
		return Err(StageError::IdentityChanged);
	}
	FilePolicy::Stage.check(&opened)?;
	same_full_stat(stamp, &opened)?;
	check_no_visible_attributes(&file)?;
	Ok(Some(RecoveryFile {
		file,
		observation: stamp,
	}))
}

fn same_full_stat(stamp: SourceObservation, stat: &fs::Stat) -> Result<(), StageError> {
	let observed = SourceObservation::capture(stat).map_err(StageError::ReadBack)?;
	if observed.accessed_at() != stamp.accessed_at() {
		return Err(StageError::MetadataMismatch);
	}
	stamp.recheck(observed).map_err(StageError::ReadBack)
}

fn view(name: Option<&CurrentName>) -> ApplyNameObservation<'_, RecoveryFile> {
	match name {
		None => ApplyNameObservation::Absent,
		Some(name) => match &name.candidate {
			Some(candidate) => ApplyNameObservation::Readable(candidate),
			None => ApplyNameObservation::Present(name.identity.into()),
		},
	}
}

fn recheck_name(
	parent: &File,
	component: &OsStr,
	mount: u64,
	held: Option<&CurrentName>,
) -> Result<(), StageError> {
	match (open_path(parent, component)?, held) {
		(None, None) => Ok(()),
		(Some(named), Some(held)) => {
			let current = fs::fstat(&named)?;
			if FileIdentity::from_stat(&current) != held.identity
				|| mount_id_no_follow(&named)? != mount
				|| FileIdentity::from_stat(&fs::fstat(&held.pin)?) != held.identity
			{
				return Err(StageError::IdentityChanged);
			}
			if let Some(candidate) = &held.candidate {
				FilePolicy::Stage.check(&current)?;
				same_full_stat(candidate.observation, &current)?;
				same_full_stat(candidate.observation, &fs::fstat(&candidate.file)?)?;
				check_no_visible_attributes(&candidate.file)?;
			}
			Ok(())
		}
		_ => Err(StageError::IdentityChanged),
	}
}

#[cfg(test)]
mod tests;
