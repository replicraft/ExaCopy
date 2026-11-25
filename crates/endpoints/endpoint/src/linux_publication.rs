//! Capabilities for publishing a verified Linux stage and recording its receipt.

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
pub trait ReceiptWorkspace<'job> {
	/// The failure to create or synchronize an owned directory or entry.
	type Error;

	/// The privately held directory in which the receipt may be created.
	type Directory: ReceiptDirectory<Error = Self::Error>;

	/// Exclusively creates and holds a private receipt directory.
	/// # Errors
	/// Fails if the directory already exists or cannot be safely created.
	fn create_receipt_directory(&'job self) -> Result<Self::Directory, Self::Error>;

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
