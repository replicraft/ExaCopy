use exacopy_endpoint::linux_publication::{ReceiptDirectory, ReceiptWorkspace};
use exacopy_journal::LinuxFileIdentity;
use exacopy_journal::remote_download::finalization::MAX_REMOTE_RECEIPT_BYTES;
use exacopy_platform::linux::{RecoveryJob, RecoveryReceiptDirectory, RecoveryWriteLease};
use exacopy_transfer::remote_finalization::RemoteReceiptWorkspace;

use super::super::recovery::NewReceipt;
use super::{Error, record_identity};

pub(in crate::assembly::linux) struct HeldReceiptWorkspace<'job>(
	pub(super) &'job RecoveryWriteLease<'job>,
);

impl RemoteReceiptWorkspace for HeldReceiptWorkspace<'_> {
	fn check_job(&self, expected: LinuxFileIdentity) -> Result<(), Self::Error> {
		self.0.job().recheck()?;
		if record_identity(self.0.job().identity()) != expected {
			return Err(Error::Binding);
		}
		Ok(())
	}
}

impl ReceiptWorkspace for HeldReceiptWorkspace<'_> {
	type Error = Error;
	type Directory<'job>
		= HeldReceipts<'job>
	where
		Self: 'job;

	fn create_receipt_directory(&self) -> Result<Self::Directory<'_>, Self::Error> {
		Ok(HeldReceipts(self.0.create_receipt_directory()?))
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		Ok(self.0.sync_job_directory()?)
	}
}

pub(in crate::assembly::linux) struct HeldReceipts<'job>(RecoveryReceiptDirectory<'job>);

impl ReceiptDirectory for HeldReceipts<'_> {
	type Error = Error;
	type Record = NewReceipt;

	fn create_receipt_record(&self) -> Result<Self::Record, Self::Error> {
		Ok(NewReceipt(self.0.create_receipt()?))
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		Ok(self.0.sync_directory()?)
	}
}

pub(super) fn read_receipt(job: &RecoveryJob<'_>) -> Result<Vec<u8>, Error> {
	let file = job.open_receipt()?;
	let length = usize::try_from(file.len())
		.ok()
		.filter(|length| (1..=MAX_REMOTE_RECEIPT_BYTES).contains(length))
		.ok_or(Error::Binding)?;
	let mut bytes = vec![0; length];
	file.read_exact_at(0, &mut bytes)?;
	file.check_logical_eof()?;
	file.recheck_observation()?;
	job.recheck()?;
	Ok(bytes)
}
