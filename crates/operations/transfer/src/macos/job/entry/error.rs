use std::{error::Error, fmt};

use exacopy_endpoint::NameError;
use exacopy_journal::{DarwinPreparedError, DurableJournalError, OwnerError, PreparedError};
use exacopy_platform::macos::staging::StageError;
use exacopy_platform::macos::staging::jobs::{JobError, JobName};

use super::super::JobAdmissionError;
use super::engine::{PreparationFailure, RequestError};

/// The retained job and cause of a failed Darwin entry preparation.
#[derive(Debug)]
pub struct EntryPreparationError {
	job: JobName,
	failure: EntryPreparationFailure,
}

impl EntryPreparationError {
	pub(super) const fn new(job: JobName, failure: EntryPreparationFailure) -> Self {
		Self { job, failure }
	}

	/// Returns the retained job whose state may require reconciliation.
	#[must_use]
	pub const fn job(&self) -> JobName {
		self.job
	}

	/// Returns the boundary at which preparation stopped.
	#[must_use]
	pub const fn failure(&self) -> &EntryPreparationFailure {
		&self.failure
	}
}

impl fmt::Display for EntryPreparationError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			formatter,
			"private entry preparation stopped ({})",
			self.failure
		)
	}
}

impl Error for EntryPreparationError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(&self.failure)
	}
}

/// The prerequisite or effect that stopped Darwin entry preparation.
#[derive(Debug)]
#[non_exhaustive]
pub enum EntryPreparationFailure {
	/// This writer already attempted to create its only stage.
	AlreadyAttempted,
	/// The source no longer meets the admitted plan or strict metadata policy.
	Source(JobAdmissionError),
	/// The fixed private payload name did not satisfy component bounds.
	StageComponent(NameError),
	/// The private stage directory could not be exclusively prepared.
	Directory(JobError),
	/// The private stage file or its live identities failed an adapter check.
	Stage(StageError),
	/// The live native identity or time did not fit its record representation.
	Observation(OwnerError),
	/// The source metadata did not fit its record representation.
	Metadata(PreparedError),
	/// The stage, source, job and target observations could not be bound into one record.
	Binding(DarwinPreparedError),
	/// Appending or synchronizing the exact entry preparation envelope failed.
	Journal(DurableJournalError),
}

impl fmt::Display for EntryPreparationFailure {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::AlreadyAttempted => {
				formatter.write_str("private stage preparation already attempted")
			}
			Self::Source(error) => write!(formatter, "source revalidation failed ({error})"),
			Self::StageComponent(error) => {
				write!(formatter, "invalid private stage component ({error})")
			}
			Self::Directory(error) => {
				write!(formatter, "stage directory preparation failed ({error})")
			}
			Self::Stage(error) => write!(formatter, "private stage admission failed ({error})"),
			Self::Observation(error) => {
				write!(formatter, "unsupported native observation ({error})")
			}
			Self::Metadata(error) => write!(formatter, "unsupported source metadata ({error})"),
			Self::Binding(error) => write!(formatter, "entry preparation binding failed ({error})"),
			Self::Journal(error) => write!(formatter, "entry preparation journal failed ({error})"),
		}
	}
}

impl Error for EntryPreparationFailure {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(match self {
			Self::AlreadyAttempted => return None,
			Self::Source(error) => error,
			Self::StageComponent(error) => error,
			Self::Directory(error) => error,
			Self::Stage(error) => error,
			Self::Observation(error) => error,
			Self::Metadata(error) => error,
			Self::Binding(error) => error,
			Self::Journal(error) => error,
		})
	}
}

impl From<OwnerError> for EntryPreparationFailure {
	fn from(error: OwnerError) -> Self {
		Self::Observation(error)
	}
}

impl From<DarwinPreparedError> for EntryPreparationFailure {
	fn from(error: DarwinPreparedError) -> Self {
		Self::Binding(error)
	}
}

impl From<RequestError> for EntryPreparationFailure {
	fn from(error: RequestError) -> Self {
		match error {
			RequestError::AlreadyAttempted => Self::AlreadyAttempted,
			RequestError::StageComponent(error) => Self::StageComponent(error),
			RequestError::Observation(error) => Self::Observation(error),
			RequestError::Metadata(error) => Self::Metadata(error),
			RequestError::Binding(error) => Self::Binding(error),
		}
	}
}

impl From<PreparationFailure<StageError>> for EntryPreparationFailure {
	fn from(error: PreparationFailure<StageError>) -> Self {
		match error {
			PreparationFailure::Stage(error) => Self::Stage(error),
			PreparationFailure::Observation(error) => Self::Observation(error),
			PreparationFailure::Binding(error) => Self::Binding(error),
			PreparationFailure::Journal(error) => Self::Journal(error),
		}
	}
}
