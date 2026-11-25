use std::{error::Error, fmt};

use exacopy_content::MeasureError;
use exacopy_journal::VerificationRecordError;

use super::super::super::CopyError;
use super::super::{FinishFailure, InspectionError, RecoveryIssue};
use crate::linux_staging::StageFailure;

/// A retained-stage recovery attempt that could not establish or publish its evidence.
#[derive(Debug)]
#[non_exhaustive]
pub enum SourceRecoveryFailure<R, S, P> {
	/// The authenticated job or its journal could not be used or finished.
	Recovery(FinishFailure<R, S>),
	/// The current source directory grant, identity, metadata, or bytes disagree with the plan.
	SourceMismatch,
	/// Opening the expected raw source component under the supplied grant failed.
	OpenSource(R),
	/// A source observation or required source policy failed.
	SourcePolicy(StageFailure<R, S>),
	/// A full source reread could not complete.
	MeasureSource(MeasureError<R>),
	/// A freshly read retained stage disagrees with the journal.
	Stage(RecoveryIssue),
	/// Fresh measurements cannot form compatible verification evidence.
	Verification(VerificationRecordError),
	/// The previous decision consumed the last available effect sequence.
	EffectSequenceExhausted,
	/// The new epoch session did not accept its expected event.
	Model(StageFailure<R, S>),
	/// Preparing, rewriting or fully verifying the retained partial stage failed.
	ResumeStage(StageFailure<R, S>),
	/// Recording or publishing the newly verified copy failed.
	ResumeCopy(Box<CopyError<R, S, P>>),
	/// The exclusive rename or its postconditions failed after the fresh synchronized intent.
	Publish(P),
}

impl<R, S, P> From<FinishFailure<R, S>> for SourceRecoveryFailure<R, S, P> {
	fn from(error: FinishFailure<R, S>) -> Self {
		Self::Recovery(error)
	}
}

impl<R, S, P> From<InspectionError<R, S>> for SourceRecoveryFailure<R, S, P> {
	fn from(error: InspectionError<R, S>) -> Self {
		Self::Recovery(error.into())
	}
}

impl<R: fmt::Display, S: fmt::Display, P: fmt::Display> fmt::Display
	for SourceRecoveryFailure<R, S, P>
{
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

impl<R: Error + 'static, S: Error + 'static, P: Error + 'static> Error
	for SourceRecoveryFailure<R, S, P>
{
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
