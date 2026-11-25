use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsFd as _;
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, FileType, Mode, OFlags, Stat};

use super::super::super::super::super::{FILE_MODE, PhysicalFsid, file::same_observation};
use super::{
	DirectoryLease, JobArtifact, ManagedObjectIdentity, RecoveryDirectory, RecoveryError,
	RecoveryJob, acl, check_absent, component, name, named_stat, with_materialization_disabled,
};

pub(super) const RECORD_LIMIT: u64 = super::super::record::MAX_RECORD_BYTES as u64;
// The local first-segment format caps its journal at 64 MiB.
pub(super) const FIRST_SEGMENT_LIMIT: u64 = 64 * 1024 * 1024;
const READ_RECORD: OFlags = OFlags::RDONLY
	.union(OFlags::NOFOLLOW)
	.union(OFlags::NONBLOCK)
	.union(OFlags::CLOEXEC);

pub(super) enum RecordParent<'job> {
	Job(&'job RecoveryJob<'job>),
	Child {
		job: &'job RecoveryJob<'job>,
		directory: RecoveryDirectory,
		name: &'static [u8],
	},
}

impl RecordParent<'_> {
	fn lease(&self) -> &DirectoryLease {
		match self {
			Self::Job(job) => &job.directory.lease,
			Self::Child { directory, .. } => &directory.lease,
		}
	}

	fn check_current(&self) -> Result<(), RecoveryError> {
		match self {
			Self::Job(job) => job.check_current(),
			Self::Child {
				job,
				directory,
				name,
			} => {
				job.check_current()?;
				directory.check_current(&job.directory.lease, name)
			}
		}
	}
}

/// Bounded private record bytes returned through a leased read-only stream.
///
/// Reads recheck the parent chain and the identity, extent and metadata of
/// the held and named record. Read errors can leave partial bytes in the
/// caller's buffer. Ordinary reads can update the private file's access time.
pub struct RecoveryRecord<'job> {
	file: File,
	parent: RecordParent<'job>,
	artifact: JobArtifact,
	component: UnixComponent<'static>,
	initial: Stat,
	identity: ManagedObjectIdentity,
	length: u64,
	position: u64,
}

impl<'job> RecoveryRecord<'job> {
	pub(super) fn open(
		parent: RecordParent<'job>,
		artifact: JobArtifact,
		raw_name: &'static [u8],
		limit: u64,
	) -> Result<Self, RecoveryError> {
		parent.check_current()?;
		let component = component(raw_name, artifact)?;
		let initial = named_stat(parent.lease(), component, artifact)?;
		Self::bind(parent, artifact, component, limit, initial)
	}

	pub(super) fn open_optional(
		parent: RecordParent<'job>,
		artifact: JobArtifact,
		raw_name: &'static [u8],
		limit: u64,
	) -> Result<Option<Self>, RecoveryError> {
		parent.check_current()?;
		let component = component(raw_name, artifact)?;
		match named_stat(parent.lease(), component, artifact) {
			Ok(initial) => Self::bind(parent, artifact, component, limit, initial).map(Some),
			Err(RecoveryError::Missing(_)) => {
				parent.check_current()?;
				check_absent(parent.lease(), component, artifact)?;
				Ok(None)
			}
			Err(error) => Err(error),
		}
	}

	fn bind(
		parent: RecordParent<'job>,
		artifact: JobArtifact,
		component: UnixComponent<'static>,
		limit: u64,
		initial: Stat,
	) -> Result<Self, RecoveryError> {
		let lease = parent.lease();
		if !private_regular_file(&initial, lease.owner) {
			return Err(RecoveryError::InvalidObject(artifact));
		}
		let length =
			u64::try_from(initial.st_size).map_err(|_| RecoveryError::InvalidObject(artifact))?;
		if length > limit || (length == 0 && artifact != JobArtifact::FirstSegment) {
			return Err(RecoveryError::InvalidLength {
				artifact,
				length,
				limit,
			});
		}
		let identity = ManagedObjectIdentity::from_stat(&initial, lease.identity.physical_fsid)
			.ok_or(RecoveryError::InvalidObject(artifact))?;
		let file = File::from(fs::openat(
			&lease.file,
			component.as_bytes(),
			READ_RECORD,
			Mode::empty(),
		)?);
		let record = Self {
			file,
			parent,
			artifact,
			component,
			initial,
			identity,
			length,
			position: 0,
		};
		record.check_current()?;
		Ok(record)
	}

	/// Returns the observed logical length, including any incomplete final frame bytes.
	#[must_use]
	pub const fn len(&self) -> u64 {
		self.length
	}

	/// Returns whether the record's observed extent is empty.
	#[must_use]
	pub const fn is_empty(&self) -> bool {
		self.length == 0
	}

	/// Returns the native identity recorded during admission.
	#[must_use]
	pub const fn identity(&self) -> ManagedObjectIdentity {
		self.identity
	}

	/// Rechecks the held and named record and parent observations.
	///
	/// # Errors
	/// Returns a typed error for an invalid or changed binding and failed system calls.
	pub fn revalidate(&self) -> Result<(), RecoveryError> {
		with_materialization_disabled(|| self.check_current())
	}

	fn check_current(&self) -> Result<(), RecoveryError> {
		self.parent.check_current()?;
		let lease = self.parent.lease();
		let named = named_stat(lease, self.component, self.artifact)?;
		let held = fs::fstat(&self.file)?;
		if !same_observation(&named, &self.initial)
			|| !same_observation(&held, &self.initial)
			|| PhysicalFsid::held(self.file.as_fd())? != Some(lease.identity.physical_fsid)
			|| !acl::has_basic_acl(self.file.as_fd())?
			|| !name::matches(&self.file, self.component)?
		{
			return Err(RecoveryError::InvalidObject(self.artifact));
		}
		Ok(())
	}

	fn read_bounded(&mut self, buffer: &mut [u8]) -> Result<usize, RecoveryError> {
		// The cursor starts at zero and advances only by bytes within the captured extent.
		let remaining = self.length - self.position;
		let capacity = usize::try_from(remaining).unwrap_or(usize::MAX);
		let capacity = capacity.min(buffer.len());
		let count = with_materialization_disabled(|| {
			self.check_current()?;
			if capacity == 0 {
				return Ok::<_, RecoveryError>(0);
			}
			let count = self.file.read_at(&mut buffer[..capacity], self.position)?;
			self.check_current()?;
			if count == 0 {
				return Err(RecoveryError::InvalidObject(self.artifact));
			}
			Ok(count)
		})?;
		self.position +=
			u64::try_from(count).map_err(|_| RecoveryError::InvalidObject(self.artifact))?;
		Ok(count)
	}
}

impl Read for RecoveryRecord<'_> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		self.read_bounded(buffer).map_err(io::Error::other)
	}
}

impl fmt::Debug for RecoveryRecord<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("RecoveryRecord")
			.finish_non_exhaustive()
	}
}

fn private_regular_file(stat: &Stat, owner: u32) -> bool {
	FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
		&& Mode::from_raw_mode(stat.st_mode) == FILE_MODE
		&& stat.st_flags == 0
		&& stat.st_uid == owner
		&& stat.st_nlink == 1
}
