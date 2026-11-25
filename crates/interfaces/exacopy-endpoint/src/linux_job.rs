//! Capability contracts for creating and synchronizing a private Linux job.

use std::io::{self, Write};

use crate::UnixComponent;

/// The device and inode of a held Linux namespace object.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct JobFileIdentity {
	/// Device number obtained from the held object.
	pub device: u64,
	/// Inode number obtained from the held object.
	pub inode: u64,
}

/// A held destination that can exclusively create a new private job.
pub trait JobBootstrapRoot<'root> {
	/// The exact cause of a namespace or directory barrier failure.
	type Error;

	/// A newly created and exclusively held job.
	type Job: JobWorkspace<Error = Self::Error>;

	/// Returns the identity of the held destination directory.
	fn identity(&self) -> JobFileIdentity;

	/// Creates a new private job below this destination.
	/// # Errors
	/// Fails on a naming conflict, uncertain identity, or failed creation. A failed
	/// attempt may leave private entries available for inspection.
	fn create_job_directory(&'root self, name: UnixComponent<'_>)
	-> Result<Self::Job, Self::Error>;

	/// Synchronizes the directory that holds the job entry.
	/// # Errors
	/// Fails if the held directory identity or its barrier cannot be confirmed.
	fn sync_directory(&self) -> Result<(), Self::Error>;
}

/// A checked, exclusively held job directory.
pub trait JobWorkspace {
	/// The exact cause of a namespace or directory barrier failure.
	type Error;

	/// An exclusive, newly created owner or plan record.
	type Record: JobRecord;

	/// An unshared handle to the newly created first segment.
	type Segment;

	/// The private journal directory for this job.
	type Journal<'job>: JobJournalDirectory<Error = Self::Error, Segment = Self::Segment>
	where
		Self: 'job;

	/// Returns the held job identity.
	fn identity(&self) -> JobFileIdentity;

	/// Exclusively creates the fixed owner record.
	/// # Errors
	/// Fails if the held job changed or the record cannot be exclusively created.
	fn create_owner_record(&self) -> Result<Self::Record, Self::Error>;

	/// Exclusively creates the fixed plan record.
	/// # Errors
	/// Fails if the held job changed or the record cannot be exclusively created.
	fn create_plan_record(&self) -> Result<Self::Record, Self::Error>;

	/// Exclusively creates the fixed journal directory.
	/// # Errors
	/// Fails if the held job changed or the directory cannot be exclusively created.
	fn create_journal_directory(&self) -> Result<Self::Journal<'_>, Self::Error>;

	/// Synchronizes the job directory that holds the private records and journal entry.
	/// # Errors
	/// Fails if the held directory identity or its barrier cannot be confirmed.
	fn sync_directory(&self) -> Result<(), Self::Error>;
}

/// An exclusive writer to a new private job record.
pub trait JobRecord: Write {
	/// Synchronizes the new record, including its metadata.
	/// # Errors
	/// Fails if the adapter cannot confirm the record's full file barrier.
	fn sync_all(&self) -> io::Result<()>;
}

/// A job's held private journal directory.
pub trait JobJournalDirectory {
	/// The exact cause of a namespace or directory barrier failure.
	type Error;

	/// An unshared handle to the newly created first segment.
	type Segment;

	/// Exclusively creates the fixed first segment.
	/// # Errors
	/// Fails if the directory changed or the segment cannot be exclusively created.
	fn create_first_segment(&self) -> Result<Self::Segment, Self::Error>;

	/// Synchronizes the journal directory that holds the first segment entry.
	/// # Errors
	/// Fails if the held directory identity or its barrier cannot be confirmed.
	fn sync_directory(&self) -> Result<(), Self::Error>;
}
