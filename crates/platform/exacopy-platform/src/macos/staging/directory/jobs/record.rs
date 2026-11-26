use std::fs::File;
use std::os::fd::AsFd as _;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, FileType, Mode, OFlags};

use super::super::super::super::{FILE_MODE, PhysicalFsid, acl, file::same_observation};
use super::checked_component;
use super::{Creation, DirectoryLease, JobArtifact, JobDirectory, JobError, JobStep};
use super::{DarwinJournalSegment, JOURNAL, JournalDirectory, ManagedObjectIdentity};

mod artifact;

use artifact::write_record;
#[cfg(test)]
pub(super) use artifact::write_record_with_namespace_barrier;

pub(super) const OWNER: &[u8] = b"owner.cbor";
pub(super) const PLAN: &[u8] = b"plan.cbor";
pub(super) const FIRST_SEGMENT: &[u8] = b"00000000000000000001.exajnl";

pub(super) const MAX_RECORD_BYTES: usize = 64 * 1024;
const CREATE_FLAGS: OFlags = OFlags::CREATE
	.union(OFlags::EXCL)
	.union(OFlags::NOFOLLOW)
	.union(OFlags::NONBLOCK)
	.union(OFlags::CLOEXEC);

impl JobDirectory<'_> {
	/// Exclusively writes and synchronizes the supplied owner envelope bytes.
	///
	/// The caller authenticates and binds the envelope to this job before calling.
	///
	/// # Errors
	/// Rejects empty records, records above 64 KiB, collisions, and failed
	/// identity, write, close or barrier checks.
	pub fn write_owner_record(&self, bytes: &[u8]) -> Result<ManagedObjectIdentity, JobError> {
		write_record(
			&self.directory.lease,
			checked_component(OWNER)?,
			bytes,
			Creation::new(self.name, JobArtifact::Owner),
			|| self.check_current(),
		)
	}

	/// Exclusively writes and synchronizes the supplied canonical plan bytes.
	///
	/// The caller binds the plan to this job before calling.
	///
	/// # Errors
	/// Rejects empty records, records above 64 KiB, collisions, and failed
	/// identity, write, close or barrier checks.
	pub fn write_plan_record(&self, bytes: &[u8]) -> Result<ManagedObjectIdentity, JobError> {
		write_record(
			&self.directory.lease,
			checked_component(PLAN)?,
			bytes,
			Creation::new(self.name, JobArtifact::Plan),
			|| self.check_current(),
		)
	}
}

impl<'job> JournalDirectory<'job> {
	/// Exclusively creates a first segment and transfers its held namespace to the writer.
	///
	/// The typed segment owns the only write descriptor and keeps this directory
	/// and its borrowing relationship with the held job alive through barriers.
	///
	/// # Errors
	/// Rejects collisions and failed identity or namespace checks. Uncertain
	/// segments remain in place for reconciliation.
	pub fn create_first_segment(self) -> Result<DarwinJournalSegment<'job>, JobError> {
		let name = checked_component(FIRST_SEGMENT)?;
		let lease = &self.directory.lease;
		let (file, identity) =
			Creation::new(self.job.name, JobArtifact::FirstSegment).run(|creation| {
				self.check_current()?;
				let (file, identity) =
					create_empty_with_access(lease, name, creation, OFlags::RDWR)?;
				creation.step = Some(JobStep::NamespaceBarrier);
				fs::fsync(&lease.file)?;
				creation.step = Some(JobStep::Revalidate);
				self.check_current()?;
				check_record(lease, name, &file, 0, Some(identity))?;
				Ok((file, identity))
			})?;
		Ok(DarwinJournalSegment::new(file, identity, self))
	}

	pub(super) fn check_current(&self) -> Result<(), JobError> {
		self.job.check_current()?;
		self.directory
			.check_current(&self.job.directory.lease, checked_component(JOURNAL)?)
	}
}

pub(super) fn record_length(bytes: &[u8]) -> Result<u64, JobError> {
	if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
		return Err(JobError::InvalidLength);
	}
	u64::try_from(bytes.len()).map_err(|_| JobError::InvalidLength)
}

pub(super) fn create_empty(
	lease: &DirectoryLease,
	name: UnixComponent<'_>,
	creation: &mut Creation,
) -> Result<(File, ManagedObjectIdentity), JobError> {
	create_empty_with_access(lease, name, creation, OFlags::WRONLY)
}

fn create_empty_with_access(
	lease: &DirectoryLease,
	name: UnixComponent<'_>,
	creation: &mut Creation,
	access: OFlags,
) -> Result<(File, ManagedObjectIdentity), JobError> {
	let file = creation.create(|| {
		fs::openat(
			&lease.file,
			name.as_bytes(),
			CREATE_FLAGS | access,
			FILE_MODE,
		)
	})?;
	creation.step = Some(JobStep::Bind);
	let file = File::from(file);
	let identity = check_record(lease, name, &file, 0, None)?;
	Ok((file, identity))
}

pub(super) fn check_record(
	parent: &DirectoryLease,
	name: UnixComponent<'_>,
	file: &File,
	length: u64,
	expected: Option<ManagedObjectIdentity>,
) -> Result<ManagedObjectIdentity, JobError> {
	let held = fs::fstat(file)?;
	let named = parent.named_stat(name)?;
	let identity = ManagedObjectIdentity::from_stat(&held, parent.identity.physical_fsid)
		.ok_or(JobError::IdentityChanged)?;
	if FileType::from_raw_mode(held.st_mode) != FileType::RegularFile
		|| held.st_uid != parent.owner
		|| held.st_nlink != 1
		|| Mode::from_raw_mode(held.st_mode) != FILE_MODE
		|| held.st_flags != 0
		|| u64::try_from(held.st_size).ok() != Some(length)
		|| expected.is_some_and(|expected| expected != identity)
		|| ManagedObjectIdentity::from_stat(&named, parent.identity.physical_fsid) != Some(identity)
		|| !same_observation(&named, &held)
		|| PhysicalFsid::held(file.as_fd())? != Some(parent.identity.physical_fsid)
		|| !acl::has_no_stage_acl_entries(file.as_fd())?
	{
		return Err(JobError::IdentityChanged);
	}
	Ok(identity)
}
