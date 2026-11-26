use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;
use std::os::unix::fs::FileExt as _;

use apfs_mounted::publication::{RenameAttempt, RenameEvidence, attempt_exclusive_rename};
use apfs_mounted::writer::{full_file_sync, sync_directory};
use apfs_mounted::{EntryName, ObjectIdentity};
use exacopy_endpoint::{UnixComponent, read_exact_at, write_all_at};
use rustix::fs::{self, AtFlags, Mode, OFlags};
use rustix::io::Errno;

use super::super::super::super::{ManagedReadError, file::same_observation, volume};
use super::super::super::close::close_writer;
use super::record::{check_record, create_empty, record_length};
use super::{
	Creation, DirectoryLease, JobArtifact, JobError, JobStep, ManagedObjectIdentity, RECEIPTS,
	ReceiptDirectory, StageError, checked_component,
};

pub(super) const RECEIPT: &CStr = c"receipt.cbor";
pub(super) const RECEIPT_PENDING: &CStr = c"receipt.pending";
const READ_CHUNK_BYTES: usize = 4096;
const READ_PENDING: OFlags = OFlags::RDONLY
	.union(OFlags::NOFOLLOW)
	.union(OFlags::NONBLOCK)
	.union(OFlags::CLOEXEC);

impl ReceiptDirectory<'_> {
	/// Publishes a checked immutable receipt within the leased private receipt directory.
	///
	/// The coordinator supplies bytes derived from synchronized journal evidence. A
	/// fixed exclusive pending file holds the bytes through its full file barrier,
	/// writer closure and exact read-back. Publication uses a native no-clobber
	/// rename followed by a directory barrier and identity revalidation.
	///
	/// # Errors
	/// Rejects out-of-bounds bytes, occupied names, and failed identity, write,
	/// read-back, close, publication or barrier checks. Any affected artifacts
	/// remain in place for reconciliation.
	pub fn write_receipt(&self, bytes: &[u8]) -> Result<ManagedObjectIdentity, JobError> {
		self.write_receipt_impl(
			bytes,
			|file, offset, remaining| file.write_at(remaining, offset),
			|file| full_file_sync(file).map_err(|error| error.error),
			|lease| sync_directory(&lease.directory).map_err(|error| error.error),
		)
	}

	#[cfg(test)]
	pub(super) fn write_receipt_with(
		&self,
		bytes: &[u8],
		write: impl FnMut(&File, u64, &[u8]) -> io::Result<usize>,
		file_barrier: impl FnOnce(&File) -> rustix::io::Result<()>,
		directory_barrier: impl FnOnce(&File) -> rustix::io::Result<()>,
	) -> Result<ManagedObjectIdentity, JobError> {
		self.write_receipt_impl(
			bytes,
			write,
			|file| file_barrier(file).map_err(Into::into),
			|lease| directory_barrier(&lease.file).map_err(Into::into),
		)
	}

	fn write_receipt_impl(
		&self,
		bytes: &[u8],
		mut write: impl FnMut(&File, u64, &[u8]) -> io::Result<usize>,
		file_barrier: impl FnOnce(&File) -> io::Result<()>,
		directory_barrier: impl FnOnce(&DirectoryLease) -> io::Result<()>,
	) -> Result<ManagedObjectIdentity, JobError> {
		let length = record_length(bytes)?;
		let pending = checked_component(RECEIPT_PENDING.to_bytes())?;
		let final_name = checked_component(RECEIPT.to_bytes())?;
		let pending_native = EntryName::new(pending.as_bytes()).map_err(StageError::Name)?;
		let final_native = EntryName::new(final_name.as_bytes()).map_err(StageError::Name)?;
		let lease = &self.directory.lease;
		Creation::new(self.job.name, JobArtifact::ReceiptPending).run(|creation| {
			self.check_current()?;
			if name_is_occupied(lease, final_name)? {
				return Err(self.final_occupied());
			}
			if !volume::supports_exclusive_rename(lease.file.as_fd())? {
				return Err(ManagedReadError::UnsupportedNamespace.into());
			}
			let (file, identity) = create_empty(lease, pending, creation)?;
			creation.step = Some(JobStep::Write);
			write_all_at(0, bytes, |offset, remaining| {
				write(&file, offset, remaining)
			})
			.map_err(StageError::Write)?;
			check_record(lease, pending, &file, length, Some(identity))?;
			creation.step = Some(JobStep::FileBarrier);
			file_barrier(&file)?;

			creation.step = Some(JobStep::Verify);
			self.check_current()?;
			check_record(lease, pending, &file, length, Some(identity))?;
			let reader = File::from(fs::openat(
				&lease.file,
				pending.as_bytes(),
				READ_PENDING,
				Mode::empty(),
			)?);
			check_record(lease, pending, &reader, length, Some(identity))?;
			creation.step = Some(JobStep::Close);
			close_writer(file)?;

			creation.step = Some(JobStep::Verify);
			let before_read = fs::fstat(&reader)?;
			verify_contents(&reader, bytes)?;
			self.check_current()?;
			check_record(lease, pending, &reader, length, Some(identity))?;
			if !same_observation(&before_read, &fs::fstat(&reader)?) {
				return Err(JobError::IdentityChanged);
			}

			let expected = ObjectIdentity::held(&reader).map_err(io::Error::other)?;
			if ManagedObjectIdentity::from_mounted(&expected) != identity {
				return Err(JobError::IdentityChanged);
			}
			creation.artifact = JobArtifact::Receipt;
			creation.step = Some(JobStep::Publish);
			let renamed = match attempt_exclusive_rename(
				&lease.directory,
				&pending_native,
				&lease.directory,
				&final_native,
				&reader,
				&expected,
			) {
				RenameAttempt::Renamed(renamed) => renamed,
				RenameAttempt::Conflict => return Err(self.final_occupied()),
				RenameAttempt::NotAttempted(error) => return Err(io::Error::other(error).into()),
				RenameAttempt::Uncertain(error) => return Err(error.into()),
				_ => return Err(io::Error::other("unknown mounted receipt rename result").into()),
			};
			creation.step = Some(JobStep::NamespaceBarrier);
			let barrier = directory_barrier(lease);
			let observation = renamed.observe();
			barrier?;
			creation.step = Some(JobStep::Revalidate);
			self.check_current()?;
			if !matches!(observation, RenameEvidence::Confirmed { target } if target == expected) {
				return Err(JobError::IdentityChanged);
			}
			check_record(lease, final_name, &reader, length, Some(identity))
		})
	}

	fn check_current(&self) -> Result<(), JobError> {
		self.job.check_current()?;
		self.directory
			.check_current(&self.job.directory.lease, checked_component(RECEIPTS)?)
	}

	fn final_occupied(&self) -> JobError {
		JobError::Occupied {
			job: self.job.name,
			artifact: JobArtifact::Receipt,
		}
	}
}

pub(super) fn name_is_occupied(
	lease: &DirectoryLease,
	name: UnixComponent<'_>,
) -> rustix::io::Result<bool> {
	match fs::statat(&lease.file, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW) {
		Ok(_) => Ok(true),
		Err(Errno::NOENT) => Ok(false),
		Err(error) => Err(error),
	}
}

fn verify_contents(file: &File, expected: &[u8]) -> Result<(), JobError> {
	let mut buffer = [0; READ_CHUNK_BYTES];
	let mut offset = 0_u64;
	for chunk in expected.chunks(buffer.len()) {
		let observed = &mut buffer[..chunk.len()];
		read_exact_at(offset, observed, |offset, bytes| {
			file.read_at(bytes, offset)
		})
		.map_err(StageError::Read)?;
		if observed != chunk {
			return Err(JobError::ReceiptMismatch);
		}
		let length = u64::try_from(chunk.len()).map_err(|_| JobError::InvalidLength)?;
		offset = offset.checked_add(length).ok_or(JobError::InvalidLength)?;
	}
	Ok(())
}
