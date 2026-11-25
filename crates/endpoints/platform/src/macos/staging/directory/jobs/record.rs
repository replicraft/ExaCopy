use std::fs::File;
use std::os::fd::AsFd as _;
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::{UnixComponent, write_all_at};
use rustix::fs::{self, FileType, Mode, OFlags};

use super::super::super::super::{FILE_MODE, PhysicalFsid, acl, file::same_observation};
use super::super::super::close::close_writer;
use super::checked_component;
use super::{Creation, DirectoryLease, JobArtifact, JobDirectory, JobError, JobStep};
use super::{JOURNAL, JournalDirectory, ManagedObjectIdentity, RECEIPTS, ReceiptDirectory};

pub(super) const OWNER: &[u8] = b"owner.cbor";
pub(super) const PLAN: &[u8] = b"plan.cbor";
pub(super) const FIRST_SEGMENT: &[u8] = b"00000000000000000001.exajnl";
pub(super) const RECEIPT: &[u8] = b"receipt.cbor";

pub(super) const MAX_RECORD_BYTES: usize = 64 * 1024;
const CREATE_RECORD: OFlags = OFlags::WRONLY
	.union(OFlags::CREATE)
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

impl JournalDirectory<'_> {
	/// Exclusively creates the empty first journal segment and barriers its namespace.
	///
	/// The sole writable descriptor goes to the journal writer. The coordinator
	/// must keep this leased job and journal namespace alive while the writer
	/// owns it. The journal layer owns file barriers for its appended frames.
	///
	/// # Errors
	/// Rejects collisions and failed identity or namespace checks. An uncertain
	/// segment is retained and no writable descriptor is returned.
	pub fn create_first_segment(&self) -> Result<File, JobError> {
		let name = checked_component(FIRST_SEGMENT)?;
		let lease = &self.directory.lease;
		let check_parent = || {
			self.job.check_current()?;
			self.directory
				.check_current(&self.job.directory.lease, checked_component(JOURNAL)?)
		};
		Creation::new(self.job.name, JobArtifact::FirstSegment).run(|creation| {
			check_parent()?;
			let (file, identity) = create_empty(lease, name, creation)?;
			creation.step = Some(JobStep::NamespaceBarrier);
			fs::fsync(&lease.file)?;
			creation.step = Some(JobStep::Revalidate);
			check_parent()?;
			check_record(lease, name, &file, 0, Some(identity))?;
			Ok(file)
		})
	}
}

impl ReceiptDirectory<'_> {
	/// Exclusively writes the supplied initial receipt bytes and synchronizes its namespace.
	///
	/// The caller supplies a receipt from the journal-coordinated transfer.
	///
	/// # Errors
	/// Rejects empty records, records above 64 KiB, collisions, and failed
	/// identity, write, close or barrier checks.
	pub fn write_receipt(&self, bytes: &[u8]) -> Result<ManagedObjectIdentity, JobError> {
		write_record(
			&self.directory.lease,
			checked_component(RECEIPT)?,
			bytes,
			Creation::new(self.job.name, JobArtifact::Receipt),
			|| {
				self.job.check_current()?;
				self.directory
					.check_current(&self.job.directory.lease, checked_component(RECEIPTS)?)
			},
		)
	}
}

fn write_record(
	lease: &DirectoryLease,
	name: UnixComponent<'_>,
	bytes: &[u8],
	creation: Creation,
	check_parent: impl Fn() -> Result<(), JobError>,
) -> Result<ManagedObjectIdentity, JobError> {
	write_record_with(lease, name, bytes, creation, check_parent, |file| {
		fs::fcntl_fullfsync(file)
	})
}

pub(super) fn write_record_with(
	lease: &DirectoryLease,
	name: UnixComponent<'_>,
	bytes: &[u8],
	creation: Creation,
	check_parent: impl Fn() -> Result<(), JobError>,
	file_barrier: impl FnOnce(&File) -> rustix::io::Result<()>,
) -> Result<ManagedObjectIdentity, JobError> {
	if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
		return Err(JobError::InvalidLength);
	}
	let length = u64::try_from(bytes.len()).map_err(|_| JobError::InvalidLength)?;
	creation.run(|creation| {
		check_parent()?;
		let (file, identity) = create_empty(lease, name, creation)?;
		creation.step = Some(JobStep::Write);
		write_all_at(0, bytes, |offset, remaining| {
			file.write_at(remaining, offset)
		})
		.map_err(super::StageError::Write)?;
		check_record(lease, name, &file, length, Some(identity))?;
		creation.step = Some(JobStep::FileBarrier);
		file_barrier(&file)?;
		creation.step = Some(JobStep::Close);
		close_writer(file)?;
		creation.step = Some(JobStep::NamespaceBarrier);
		fs::fsync(&lease.file)?;
		creation.step = Some(JobStep::Revalidate);
		check_parent()?;
		let named = lease.named_stat(name)?;
		if ManagedObjectIdentity::from_stat(&named, lease.identity.physical_fsid) != Some(identity)
		{
			return Err(JobError::IdentityChanged);
		}
		Ok(identity)
	})
}

fn create_empty(
	lease: &DirectoryLease,
	name: UnixComponent<'_>,
	creation: &mut Creation,
) -> Result<(File, ManagedObjectIdentity), JobError> {
	let file =
		creation.create(|| fs::openat(&lease.file, name.as_bytes(), CREATE_RECORD, FILE_MODE))?;
	creation.step = Some(JobStep::Bind);
	let file = File::from(file);
	let identity = check_record(lease, name, &file, 0, None)?;
	Ok((file, identity))
}

fn check_record(
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
