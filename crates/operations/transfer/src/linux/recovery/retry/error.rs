use std::{error::Error, fmt};

use exacopy_content::MeasureError;
use exacopy_journal::VerificationRecordError;
use exacopy_platform::linux::{PublishError, ReadError};

use super::super::super::{LocalCopyError, StageFailure};
use super::super::{RecoveryFinishError, RecoveryInspectError, RecoveryIssue};

/// A retained-stage recovery attempt that could not establish or publish its evidence.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecoveryRetryError {
	/// The authenticated job or its journal could not be used or finished.
	Recovery(RecoveryFinishError),
	/// The current source directory grant, identity, metadata, or bytes disagree with the plan.
	SourceMismatch,
	/// Opening the expected raw source component under the supplied grant failed.
	OpenSource(ReadError),
	/// A source observation or required source policy failed.
	SourcePolicy(StageFailure),
	/// A full source reread could not complete.
	MeasureSource(MeasureError<ReadError>),
	/// A freshly read retained stage disagrees with the journal.
	Stage(RecoveryIssue),
	/// Fresh measurements cannot form compatible verification evidence.
	Verification(VerificationRecordError),
	/// The previous decision consumed the last available effect sequence.
	EffectSequenceExhausted,
	/// The new epoch session did not accept its expected event.
	Model(StageFailure),
	/// Preparing, rewriting or fully verifying the retained partial stage failed.
	ResumeStage(StageFailure),
	/// Recording or publishing the newly verified copy failed.
	ResumeCopy(Box<LocalCopyError>),
	/// The exclusive rename or its postconditions failed after the fresh synchronized intent.
	Publish(PublishError),
}

impl From<RecoveryFinishError> for RecoveryRetryError {
	fn from(error: RecoveryFinishError) -> Self {
		Self::Recovery(error)
	}
}

impl From<RecoveryInspectError> for RecoveryRetryError {
	fn from(error: RecoveryInspectError) -> Self {
		Self::Recovery(error.into())
	}
}

impl fmt::Display for RecoveryRetryError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Recovery(error) => error.fmt(formatter),
			Self::SourceMismatch => {
				formatter.write_str("current source grant or evidence disagrees with the copy")
			}
			Self::OpenSource(error) => {
				write!(formatter, "could not reopen the expected source ({error})")
			}
			Self::SourcePolicy(error) => {
				write!(formatter, "current source policy failed ({error})")
			}
			Self::MeasureSource(error) => write!(formatter, "current source read failed ({error})"),
			Self::Stage(issue) => {
				write!(formatter, "retained stage evidence disagrees ({issue:?})")
			}
			Self::Verification(error) => write!(
				formatter,
				"fresh verification evidence is incompatible ({error})"
			),
			Self::EffectSequenceExhausted => {
				formatter.write_str("publication effect sequence is exhausted")
			}
			Self::Model(error) => write!(formatter, "retry transition rejected ({error})"),
			Self::ResumeStage(error) => write!(formatter, "partial stage resume failed ({error})"),
			Self::ResumeCopy(error) => {
				write!(formatter, "resumed copy could not complete ({error})")
			}
			Self::Publish(error) => write!(formatter, "retry publication failed ({error})"),
		}
	}
}

impl Error for RecoveryRetryError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Recovery(error) => Some(error),
			Self::OpenSource(error) => Some(error),
			Self::Model(error) | Self::SourcePolicy(error) | Self::ResumeStage(error) => {
				Some(error)
			}
			Self::ResumeCopy(error) => Some(error.as_ref()),
			Self::MeasureSource(error) => Some(error),
			Self::Verification(error) => Some(error),
			Self::Publish(error) => Some(error),
			_ => None,
		}
	}
}
