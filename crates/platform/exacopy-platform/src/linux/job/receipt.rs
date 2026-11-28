use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::linux_publication::{
	FreshReceiptError, FreshReceiptWorkspace, HeldFreshReceipt,
};
use exacopy_endpoint::read_exact_at;
use rustix::fs;

use super::super::handle::{FileIdentity, mount_id};
use super::super::source::{
	ReadError, SourceObservation, check_logical_eof, reopen_regular_without_atime,
};
use super::super::stage::{FILE_MODE, check_named_file};
use super::{JobDirectory, RECEIPT, ReceiptDirectory, StageError};

// Fits both registered local copy receipt formats independently of their codecs.
const MAX_RECEIPT_BYTES: usize = 1024;

/// Original private receipt, with a read-only file and its original parents held.
pub struct NativeHeldReceipt<'job> {
	directory: ReceiptDirectory<'job>,
	file: File,
	observation: SourceObservation,
}

impl fmt::Debug for NativeHeldReceipt<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("NativeHeldReceipt")
			.field("identity", &self.observation.identity())
			.finish_non_exhaustive()
	}
}

impl FreshReceiptWorkspace for JobDirectory<'_> {
	type Error = StageError;
	type HeldReceipt<'job>
		= NativeHeldReceipt<'job>
	where
		Self: 'job;

	fn seal_fresh_receipt(
		&self,
		bytes: &[u8],
	) -> Result<Self::HeldReceipt<'_>, FreshReceiptError<Self::Error>> {
		use FreshReceiptError as Error;

		if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
			return Err(Error::Namespace(StageError::InvalidLength));
		}
		let directory = self.create_receipt_directory().map_err(Error::Namespace)?;
		let (mut writer, created) = directory
			.0
			.create_file_admitted(RECEIPT, || Ok(()))
			.map_err(Error::Namespace)?;
		writer.write_all(bytes).map_err(Error::Io)?;
		writer.sync_all().map_err(Error::Io)?;
		let (file, stat) = reopen_regular_without_atime(&writer)
			.map_err(StageError::ReadBack)
			.map_err(Error::Namespace)?;
		let observation = SourceObservation::capture(&stat)
			.map_err(StageError::ReadBack)
			.map_err(Error::Namespace)?;
		let mount = self.root.mount;
		if observation.identity() != FileIdentity::from_stat(&created)
			|| mount_id(&file)
				.map_err(StageError::from)
				.map_err(Error::Namespace)?
				!= mount
		{
			return Err(Error::Namespace(StageError::IdentityChanged));
		}
		// Retire the sole writer. File drop does not report a close result.
		drop(writer);
		let sealed = NativeHeldReceipt {
			directory,
			file,
			observation,
		};
		sealed.recheck().map_err(Error::Namespace)?;
		sealed
			.directory
			.sync_directory()
			.map_err(Error::Namespace)?;
		self.sync_directory().map_err(Error::Namespace)?;
		Ok(sealed)
	}
}

impl HeldFreshReceipt for NativeHeldReceipt<'_> {
	type Error = StageError;

	fn read_exact_receipt(&self, output: &mut [u8]) -> Result<(), Self::Error> {
		let length = u64::try_from(output.len()).map_err(|_| StageError::InvalidLength)?;
		if output.is_empty() || output.len() > MAX_RECEIPT_BYTES || length != self.observation.len()
		{
			return Err(StageError::InvalidLength);
		}
		self.recheck()?;
		read_exact_at(0, output, |offset, remaining| {
			self.file.read_at(remaining, offset)
		})
		.map_err(ReadError::Io)
		.map_err(StageError::ReadBack)?;
		check_logical_eof(&self.file, length).map_err(StageError::ReadBack)?;
		self.recheck()
	}
}

impl NativeHeldReceipt<'_> {
	fn recheck(&self) -> Result<(), StageError> {
		let directory = &self.directory.0;
		directory.check_current()?;
		let named = check_named_file(
			&directory.directory,
			OsStr::new(RECEIPT),
			self.observation.identity(),
			directory.job.root.mount,
			FILE_MODE,
		)?;
		let held = fs::fstat(&self.file)?;
		for stat in [&named, &held] {
			let observed = SourceObservation::capture(stat).map_err(StageError::ReadBack)?;
			self.observation
				.recheck(observed)
				.map_err(StageError::ReadBack)?;
		}
		directory.check_current()
	}
}
