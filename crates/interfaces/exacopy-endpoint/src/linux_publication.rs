//! Capabilities for publishing a verified Linux stage and recording its receipt.

use std::error::Error;
use std::fmt;
use std::io::{self, Write};

use exacopy_model::PublishNoClobber;

/// A failed attempt to publish an exclusive staged file.
#[derive(Debug)]
pub enum PublicationFailure<E> {
	/// The target was occupied and its content was preserved.
	Conflict(E),
	/// The attempt did not establish a confirmed publication outcome.
	Uncertain(E),
}

/// An owned private file that can attempt one exclusive publication.
pub trait ExclusivePublication {
	/// The adapter's exact publication failure.
	type Error;

	/// Publishes against the bound absent target and completes the required directory barriers.
	/// # Errors
	/// Preserves incumbent content. An unconfirmed outcome requires namespace reconciliation.
	fn publish_no_clobber(
		self,
		authorization: PublishNoClobber,
	) -> Result<(), PublicationFailure<Self::Error>>;
}

/// The owned job namespace in which a receipt can be recorded.
pub trait ReceiptWorkspace {
	/// The failure to create or synchronize an owned directory or entry.
	type Error;

	/// The privately held directory in which the receipt may be created.
	type Directory<'job>: ReceiptDirectory<Error = Self::Error>
	where
		Self: 'job;

	/// Exclusively creates and holds a private receipt directory.
	/// # Errors
	/// Fails if the directory already exists or cannot be safely created.
	fn create_receipt_directory(&self) -> Result<Self::Directory<'_>, Self::Error>;

	/// Synchronizes the job directory containing the receipt directory entry.
	/// # Errors
	/// Fails if the held directory or its barrier cannot be confirmed.
	fn sync_directory(&self) -> Result<(), Self::Error>;
}

/// The held private receipt directory and authority to create its fixed record.
pub trait ReceiptDirectory {
	/// The failure to create or synchronize an owned directory or entry.
	type Error;

	/// The exclusive writable handle to the new receipt record.
	type Record: ReceiptRecord;

	/// Creates the new receipt record exclusively.
	/// # Errors
	/// Fails if the entry already exists or the record cannot be safely created.
	fn create_receipt_record(&self) -> Result<Self::Record, Self::Error>;

	/// Synchronizes the directory containing the new receipt record.
	/// # Errors
	/// Fails if the directory identity or barrier cannot be confirmed.
	fn sync_directory(&self) -> Result<(), Self::Error>;
}

/// The already created record for a single new receipt.
pub trait ReceiptRecord: Write {
	/// Synchronizes the written record before the containing directory barrier.
	/// # Errors
	/// Fails if the adapter cannot confirm the record's file barrier.
	fn sync_all(&self) -> io::Result<()>;
}

/// The result of failing to create, sync, or seal a fresh Linux receipt.
#[derive(Debug)]
#[non_exhaustive]
pub enum FreshReceiptError<E> {
	/// The original job or receipt namespace could not be confirmed.
	Namespace(E),
	/// Writing or synchronizing the newly created record failed.
	Io(io::Error),
}

impl<E: fmt::Display> fmt::Display for FreshReceiptError<E> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Namespace(error) => write!(formatter, "fresh receipt custody failed: {error}"),
			Self::Io(error) => write!(formatter, "fresh receipt write or sync failed: {error}"),
		}
	}
}

impl<E: Error + 'static> Error for FreshReceiptError<E> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Namespace(error) => Some(error),
			Self::Io(error) => Some(error),
		}
	}
}

/// Linux-only receipt acquisition under the original fresh copy job.
pub trait FreshReceiptWorkspace {
	/// Native receipt namespace and read-back failure.
	type Error;

	/// The original receipt reopened read-only, pinned beneath this job.
	type HeldReceipt<'job>: HeldFreshReceipt<Error = Self::Error>
	where
		Self: 'job;

	/// Exclusively writes the selected receipt bytes and synchronizes file and both directories.
	/// Success retires the original write handle and pins the same already-created object
	/// for separate read-back, keeping its directory and the existing job lease held.
	/// # Errors
	/// Refuses unsafe custody, an incumbent, or failed I/O. Preserve created evidence.
	fn seal_fresh_receipt(
		&self,
		bytes: &[u8],
	) -> Result<Self::HeldReceipt<'_>, FreshReceiptError<Self::Error>>;
}

/// A read-only pin of the original fresh receipt, under the same held job.
pub trait HeldFreshReceipt {
	/// Failure to confirm the exact receipt bytes, EOF or namespace.
	type Error;

	/// Rereads exactly one receipt into the supplied buffer and checks adjacent native EOF.
	/// Revalidates the original file, receipt directory and job around the read.
	/// # Errors
	/// Refuses an unexpected extent, changed aliases, or unavailable observations.
	fn read_exact_receipt(&self, output: &mut [u8]) -> Result<(), Self::Error>;
}
