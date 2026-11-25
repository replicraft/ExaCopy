use std::{error::Error, fmt};

use exacopy_journal::frame::FrameKind;
use exacopy_journal::{DarwinPhaseError, DurableJournalError, OwnerError};
use exacopy_model::TransitionError;
use exacopy_platform::macos::ManagedReadError;
use exacopy_platform::macos::publication::PublishError;
use exacopy_platform::macos::staging::StageError;
use exacopy_platform::macos::staging::jobs::{JobError, JobName};
use exacopy_transfer::macos::job::entry::publish::PublicationProgress;

use crate::macos::StageTransferError;
use crate::macos::receipt::DarwinCopyReceiptError;

/// A failed copy with its retained private job and last established publication boundary.
#[derive(Debug)]
pub struct DarwinCopyError {
	job: JobName,
	progress: PublicationProgress,
	failure: Box<DarwinCopyFailure>,
}

impl DarwinCopyError {
	pub(super) fn new(
		job: JobName,
		progress: PublicationProgress,
		failure: DarwinCopyFailure,
	) -> Self {
		Self {
			job,
			progress,
			failure: Box::new(failure),
		}
	}

	/// Identifies the private job left available for reconciliation.
	#[must_use]
	pub const fn job(&self) -> JobName {
		self.job
	}

	/// Returns the last established namespace boundary.
	#[must_use]
	pub const fn progress(&self) -> PublicationProgress {
		self.progress
	}

	/// Returns the typed cause, with the native publication classification if attempted.
	#[must_use]
	pub fn failure(&self) -> &DarwinCopyFailure {
		&self.failure
	}
}

impl fmt::Display for DarwinCopyError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			formatter,
			"managed APFS copy stopped at {:?} ({})",
			self.progress, self.failure
		)
	}
}

impl Error for DarwinCopyError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(self.failure.as_ref())
	}
}

/// The operation or evidence failure that ended a managed APFS copy.
#[derive(Debug)]
#[non_exhaustive]
pub enum DarwinCopyFailure {
	/// The entry's single writer was already consumed.
	AlreadyAttempted,
	/// Source observations or strict metadata could no longer be established.
	Source(ManagedReadError),
	/// The private copy, independent verification, or metadata barrier failed.
	Transfer(StageTransferError),
	/// A fresh stage observation disagreed with the metadata-ready capability.
	Stage(StageError),
	/// A native observation could not fit its journal representation.
	Observation(OwnerError),
	/// The managed APFS journal record did not bind to its prerequisites.
	Record(DarwinPhaseError),
	/// The copy model rejected a coordinator observation.
	Model(TransitionError),
	/// The copy model returned an effect different from the requested phase.
	UnexpectedEffect,
	/// The intent append did not report the required Darwin file barrier.
	UnexpectedBarrier,
	/// Writing or synchronizing a journal frame failed.
	Journal {
		/// The last attempted kind.
		kind: FrameKind,
		/// The exact append failure.
		error: DurableJournalError,
	},
	/// Native publication returned an error or incomplete evidence.
	Publish {
		/// The original native classification.
		error: Box<PublishError>,
		/// An additional failure while trying to record the observed outcome.
		recording: Option<Box<Self>>,
	},
	/// The receipt could not be bound to its plan and synchronized evidence.
	Receipt(DarwinCopyReceiptError),
	/// Writing or synchronizing the immutable receipt failed after publication.
	PersistReceipt(JobError),
}

impl From<DarwinPhaseError> for DarwinCopyFailure {
	fn from(error: DarwinPhaseError) -> Self {
		Self::Record(error)
	}
}

impl fmt::Display for DarwinCopyFailure {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::AlreadyAttempted => formatter.write_str("private copy already attempted"),
			Self::Source(error) => write!(formatter, "source revalidation failed ({error})"),
			Self::Transfer(error) => error.fmt(formatter),
			Self::Stage(error) => write!(formatter, "sealed stage revalidation failed ({error})"),
			Self::Observation(error) => error.fmt(formatter),
			Self::Record(error) => error.fmt(formatter),
			Self::Model(error) => error.fmt(formatter),
			Self::UnexpectedEffect => formatter.write_str("unexpected model effect"),
			Self::UnexpectedBarrier => {
				formatter.write_str("intent lacks the required Darwin file barrier")
			}
			Self::Journal { kind, error } => {
				write!(formatter, "journal append failed for {kind:?} ({error})")
			}
			Self::Publish { error, .. } => error.fmt(formatter),
			Self::Receipt(error) => error.fmt(formatter),
			Self::PersistReceipt(error) => {
				write!(formatter, "receipt persistence failed ({error})")
			}
		}
	}
}

impl Error for DarwinCopyFailure {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(match self {
			Self::AlreadyAttempted | Self::UnexpectedEffect | Self::UnexpectedBarrier => {
				return None;
			}
			Self::Source(error) => error,
			Self::Transfer(error) => error,
			Self::Stage(error) => error,
			Self::Observation(error) => error,
			Self::Record(error) => error,
			Self::Model(error) => error,
			Self::Journal { error, .. } => error,
			Self::Publish { error, .. } => error.as_ref(),
			Self::Receipt(error) => error,
			Self::PersistReceipt(error) => error,
		})
	}
}
