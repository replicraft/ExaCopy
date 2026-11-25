use std::error::Error;
use std::fmt;

use exacopy_content::{CopyMeasureError, MeasureError, ResumeMeasureError, StreamInputError};
use exacopy_endpoint::IoError;
use exacopy_endpoint::linux_staging::ExtendedAttributes;
use exacopy_journal::{DurableJournalError, PreparedError, VerificationRecordError};
use exacopy_model::{CopyPhase, TransitionError};

/// A failed private staging attempt, with its last observed model phase.
#[derive(Debug)]
pub struct StageCopyError<ReadError, StageError> {
	pub(super) phase: CopyPhase,
	pub(super) failure: StageFailure<ReadError, StageError>,
}

impl<ReadError, StageError> StageCopyError<ReadError, StageError> {
	/// The last phase supported by observations before the failure.
	#[must_use]
	pub const fn phase(&self) -> CopyPhase {
		self.phase
	}

	/// The typed cause of the failure.
	#[must_use]
	pub const fn failure(&self) -> &StageFailure<ReadError, StageError> {
		&self.failure
	}
}

impl<ReadError: fmt::Display, StageError: fmt::Display> fmt::Display
	for StageCopyError<ReadError, StageError>
{
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			formatter,
			"staging stopped in {:?} with {}",
			self.phase, self.failure
		)
	}
}

impl<ReadError: Error + 'static, StageError: Error + 'static> Error
	for StageCopyError<ReadError, StageError>
{
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(&self.failure)
	}
}

/// A reason the coordinator could not return a verified stage.
#[derive(Debug)]
#[non_exhaustive]
pub enum StageFailure<ReadError, StageError> {
	/// The requested length or scratch capacity is unsupported.
	Input(StreamInputError),
	/// Reading current source observations failed.
	Source(ReadError),
	/// Source attributes were present or could not be enumerated in this profile.
	SourceAttributes(ExtendedAttributes),
	/// The source uses special mode bits outside the supported metadata profile.
	UnsupportedSourceMode {
		/// Observed source permission mode.
		mode: u32,
	},
	/// Creating, flushing, closing, or applying metadata to the stage failed.
	Stage(StageError),
	/// The initial journal record could not describe this stage.
	EntryPreparation(PreparedError),
	/// The initial journal record could not be synchronized before the copy.
	EntryJournal(DurableJournalError),
	/// The immutable checkpoint range could not be encoded.
	CheckpointEvidence(VerificationRecordError),
	/// Creating or synchronizing the immutable checkpoint page failed.
	CheckpointPage(StageError),
	/// The checkpoint could not be synchronized in the journal.
	CheckpointJournal(DurableJournalError),
	/// The stage aliases the held source identity.
	Alias,
	/// A bounded source read or stage write failed while copying.
	Copy(CopyMeasureError<ReadError, StageError>),
	/// Reading the source or stage, writing a range, or confirming repeated reads failed.
	Resume(ResumeMeasureError<ReadError, ReadError, StageError>),
	/// Independent read-back could not complete.
	Readback(MeasureError<IoError>),
	/// The closed stage length differs from the source length.
	LengthMismatch {
		/// Logical length recorded for the source.
		expected: u64,
		/// Logical length observed on the closed stage.
		actual: u64,
	},
	/// The independently observed logical stream digests differ.
	DigestMismatch,
	/// The decision model rejected an observation.
	Model(TransitionError),
	/// The model did not emit the request expected at this protocol step.
	UnexpectedEffect,
}

impl<ReadError, StageError> From<TransitionError> for StageFailure<ReadError, StageError> {
	fn from(error: TransitionError) -> Self {
		Self::Model(error)
	}
}

impl<ReadError: fmt::Display, StageError: fmt::Display> fmt::Display
	for StageFailure<ReadError, StageError>
{
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Input(error) => write!(formatter, "invalid stream limits ({error})"),
			Self::Source(error) => write!(formatter, "source observation failed ({error})"),
			Self::SourceAttributes(attributes) => {
				write!(formatter, "unsupported source attributes ({attributes:?})")
			}
			Self::UnsupportedSourceMode { mode } => {
				write!(formatter, "unsupported source permission mode {mode:#o}")
			}
			Self::Stage(error) => write!(formatter, "private stage operation failed ({error})"),
			Self::EntryPreparation(error) => {
				write!(formatter, "invalid entry preparation evidence ({error})")
			}
			Self::EntryJournal(error) => {
				write!(formatter, "entry preparation journal failed ({error})")
			}
			Self::CheckpointEvidence(error) => {
				write!(formatter, "invalid range checkpoint evidence ({error})")
			}
			Self::CheckpointPage(error) => {
				write!(formatter, "private range page failed ({error})")
			}
			Self::CheckpointJournal(error) => {
				write!(formatter, "range checkpoint journal failed ({error})")
			}
			Self::Alias => formatter.write_str("source and private stage alias the same inode"),
			Self::Copy(error) => write!(formatter, "source-to-stage transfer failed ({error})"),
			Self::Resume(error) => write!(formatter, "partial range transfer failed ({error})"),
			Self::Readback(error) => {
				write!(formatter, "independent stage read-back failed ({error})")
			}
			Self::LengthMismatch { expected, actual } => write!(
				formatter,
				"stage length {actual} differs from source length {expected}"
			),
			Self::DigestMismatch => {
				formatter.write_str("stage read-back digest differs from the source stream")
			}
			Self::Model(error) => write!(formatter, "copy observation was rejected ({error})"),
			Self::UnexpectedEffect => {
				formatter.write_str("copy model returned an unexpected effect")
			}
		}
	}
}

impl<ReadError: Error + 'static, StageError: Error + 'static> Error
	for StageFailure<ReadError, StageError>
{
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Input(error) => Some(error),
			Self::Source(error) => Some(error),
			Self::Stage(error) | Self::CheckpointPage(error) => Some(error),
			Self::EntryPreparation(error) => Some(error),
			Self::CheckpointEvidence(error) => Some(error),
			Self::EntryJournal(error) | Self::CheckpointJournal(error) => Some(error),
			Self::Copy(error) => Some(error),
			Self::Resume(error) => Some(error),
			Self::Readback(error) => Some(error),
			Self::Model(error) => Some(error),
			_ => None,
		}
	}
}
