use std::fmt;
use std::fs::File;
use std::os::fd::AsFd as _;

use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use rustix::fs::{self, FileType, Mode, OFlags, Stat};

use super::super::super::super::super::{
	EVENT_ONLY, FILE_MODE, PhysicalFsid, UNSUPPORTED_OBJECT_FLAGS, file::same_observation,
};
use super::super::STAGE;
use super::{
	DirectoryLease, JobArtifact, ManagedObjectIdentity, RecoveryDirectory, RecoveryError,
	RecoveryJob, acl, check_absent, component, lookup_stat, name, with_materialization_disabled,
};

const OBSERVE: OFlags = EVENT_ONLY
	.union(OFlags::NOFOLLOW)
	.union(OFlags::NONBLOCK)
	.union(OFlags::CLOEXEC);

/// The selected name whose namespace observation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryName {
	/// The payload name within the private stage directory.
	Stage,
	/// The public target name within the held destination root.
	Target,
}

/// Native identity and logical extent of a checked regular inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryFileObservation {
	identity: ManagedObjectIdentity,
	length: u64,
}

impl RecoveryFileObservation {
	/// Returns the observed native device, volume and inode identity.
	#[must_use]
	pub const fn identity(self) -> ManagedObjectIdentity {
		self.identity
	}

	/// Returns the observed logical length in bytes.
	#[must_use]
	pub const fn length(self) -> u64 {
		self.length
	}
}

impl RecoveryJob<'_> {
	/// Captures the selected private stage and public target names.
	///
	/// Pass the authorized plan components only after binding them to this job.
	/// The stage directory gets its own lease when present. Each present regular
	/// inode is held through an event-only descriptor that grants no content reads.
	/// Public APFS aliases still occupy the target. A private stage uses exact spelling.
	///
	/// # Errors
	/// Refuses unsafe namespace bindings, changed observations, and system failures.
	pub fn inventory<'job>(
		&'job self,
		stage: UnixComponent<'job>,
		target: UnixComponent<'job>,
	) -> Result<RecoveryInventory<'job>, RecoveryError> {
		with_materialization_disabled(|| {
			self.check_current()?;
			let directory =
				RecoveryDirectory::open_optional(&self.directory.lease, STAGE, JobArtifact::Stage)?;
			let staged = match &directory {
				Some(directory) => HeldEntry::open(&directory.lease, stage, RecoveryName::Stage)?,
				None => None,
			};
			let target_entry =
				HeldEntry::open(&self.container.root.lease, target, RecoveryName::Target)?;
			let inventory = RecoveryInventory {
				job: self,
				directory,
				stage_name: stage,
				target_name: target,
				stage: staged,
				target: target_entry,
			};
			inventory.check_current()?;
			Ok(inventory)
		})
	}
}

/// Revalidatable observations of the stage directory and two selected names.
pub struct RecoveryInventory<'job> {
	job: &'job RecoveryJob<'job>,
	directory: Option<RecoveryDirectory>,
	stage_name: UnixComponent<'job>,
	target_name: UnixComponent<'job>,
	stage: Option<HeldEntry>,
	target: Option<HeldEntry>,
}

impl RecoveryInventory<'_> {
	/// Returns the held stage directory identity, if the directory was present.
	#[must_use]
	pub fn stage_directory_identity(&self) -> Option<ManagedObjectIdentity> {
		self.directory.as_ref().map(|directory| directory.identity)
	}

	/// Returns the checked private stage observation, if its name was present.
	#[must_use]
	pub fn stage(&self) -> Option<RecoveryFileObservation> {
		self.stage.as_ref().map(|stage| stage.observation)
	}

	/// Returns the checked public target observation, if its name was occupied.
	#[must_use]
	pub fn target(&self) -> Option<RecoveryFileObservation> {
		self.target.as_ref().map(|target| target.observation)
	}

	/// Revalidates held directories, absence observations and checked regular inodes.
	///
	/// # Errors
	/// Fails if any observed name or authority changed or cannot be revalidated.
	pub fn revalidate(&self) -> Result<(), RecoveryError> {
		with_materialization_disabled(|| self.check_current())
	}

	fn check_current(&self) -> Result<(), RecoveryError> {
		self.job.check_current()?;
		let job = &self.job.directory.lease;
		if let Some(directory) = &self.directory {
			directory.check_current(job, STAGE)?;
			HeldEntry::recheck(
				self.stage.as_ref(),
				&directory.lease,
				self.stage_name,
				RecoveryName::Stage,
			)?;
			directory.check_current(job, STAGE)?;
		} else {
			check_absent(
				job,
				component(STAGE, JobArtifact::Stage)?,
				JobArtifact::Stage,
			)?;
		}
		HeldEntry::recheck(
			self.target.as_ref(),
			&self.job.container.root.lease,
			self.target_name,
			RecoveryName::Target,
		)?;
		self.job.check_current()
	}
}

impl fmt::Debug for RecoveryInventory<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("RecoveryInventory")
			.finish_non_exhaustive()
	}
}

struct HeldEntry {
	file: File,
	initial: Stat,
	observation: RecoveryFileObservation,
}

impl HeldEntry {
	fn open(
		parent: &DirectoryLease,
		component: UnixComponent<'_>,
		role: RecoveryName,
	) -> Result<Option<Self>, RecoveryError> {
		let Some(initial) = lookup_stat(parent, component, RecoveryError::InvalidEntry(role))?
		else {
			return Ok(None);
		};
		let observation = observe(&initial, parent, role)?;
		let file = File::from(fs::openat(
			&parent.file,
			component.as_bytes(),
			OBSERVE,
			Mode::empty(),
		)?);
		Ok(Some(Self {
			file,
			initial,
			observation,
		}))
	}

	fn recheck(
		expected: Option<&Self>,
		parent: &DirectoryLease,
		component: UnixComponent<'_>,
		role: RecoveryName,
	) -> Result<(), RecoveryError> {
		match (
			expected,
			lookup_stat(parent, component, RecoveryError::InvalidEntry(role))?,
		) {
			(None, None) => Ok(()),
			(Some(entry), Some(named)) => {
				let held = fs::fstat(&entry.file)?;
				if !same_observation(&named, &entry.initial)
					|| !same_observation(&held, &entry.initial)
					|| PhysicalFsid::held(entry.file.as_fd())?
						!= Some(parent.identity.physical_fsid)
				{
					return Err(RecoveryError::InvalidEntry(role));
				}
				if role == RecoveryName::Stage
					&& (!acl::has_basic_acl(entry.file.as_fd())?
						|| !name::matches(&entry.file, component)?)
				{
					return Err(RecoveryError::InvalidEntry(role));
				}
				Ok(())
			}
			_ => Err(RecoveryError::InvalidEntry(role)),
		}
	}
}

fn observe(
	stat: &Stat,
	parent: &DirectoryLease,
	role: RecoveryName,
) -> Result<RecoveryFileObservation, RecoveryError> {
	if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
		|| stat.st_nlink != 1
		|| stat.st_flags & UNSUPPORTED_OBJECT_FLAGS != 0
	{
		return Err(RecoveryError::InvalidEntry(role));
	}
	if role == RecoveryName::Stage
		&& (Mode::from_raw_mode(stat.st_mode) != FILE_MODE
			|| stat.st_uid != parent.owner
			|| stat.st_flags != 0)
	{
		return Err(RecoveryError::InvalidEntry(role));
	}
	let identity = ManagedObjectIdentity::from_stat(stat, parent.identity.physical_fsid)
		.ok_or(RecoveryError::InvalidEntry(role))?;
	let length = u64::try_from(stat.st_size)
		.ok()
		.filter(|&length| length <= MAX_FILE_LENGTH)
		.ok_or(RecoveryError::InvalidEntry(role))?;
	Ok(RecoveryFileObservation { identity, length })
}
