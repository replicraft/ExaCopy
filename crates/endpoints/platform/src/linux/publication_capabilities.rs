use std::fs::File;
use std::io::{self, Write};

use exacopy_endpoint::linux_publication::{
	ExclusivePublication, PublicationFailure, ReceiptDirectory as ReceiptDirectoryCapability,
	ReceiptRecord, ReceiptWorkspace,
};
use exacopy_model::PublishNoClobber;

use super::{ClosedStage, JobDirectory, PublishError, ReceiptDirectory, StageError};

impl ExclusivePublication for ClosedStage<'_> {
	type Error = PublishError;

	fn publish_no_clobber(
		self,
		authorization: PublishNoClobber,
	) -> Result<(), PublicationFailure<Self::Error>> {
		ClosedStage::publish_no_clobber(self, authorization).map_err(|source| match source {
			PublishError::Conflict => PublicationFailure::Conflict(source),
			_ => PublicationFailure::Uncertain(source),
		})
	}
}

impl<'job, 'root: 'job> ReceiptWorkspace<'job> for JobDirectory<'root> {
	type Error = StageError;
	type Directory = ReceiptDirectory<'job>;

	fn create_receipt_directory(&'job self) -> Result<Self::Directory, Self::Error> {
		JobDirectory::create_receipt_directory(self)
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		JobDirectory::sync_directory(self)
	}
}

impl ReceiptDirectoryCapability for ReceiptDirectory<'_> {
	type Error = StageError;
	type Record = NativeReceiptRecord;

	fn create_receipt_record(&self) -> Result<Self::Record, Self::Error> {
		ReceiptDirectory::create_receipt_record(self).map(NativeReceiptRecord)
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		ReceiptDirectory::sync_directory(self)
	}
}

/// Exclusive file handle to one new native receipt record.
pub struct NativeReceiptRecord(File);

impl Write for NativeReceiptRecord {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.0.write(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.0.flush()
	}
}

impl ReceiptRecord for NativeReceiptRecord {
	fn sync_all(&self) -> io::Result<()> {
		self.0.sync_all()
	}
}
