use std::{error::Error, fmt, io};

use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurableJournalError, OwnerError, PreparedError, PublicationRecordError, VerificationRecordError,
};

use crate::linux_staging::{StageCopyError, StageFailure};

use super::super::job::BootstrapError;
use super::super::{LocalCopyPlanError, ReceiptError};

/// A refused or incomplete single-file copy or planning operation.
#[derive(Debug)]
#[non_exhaustive]
pub enum CopyError<R, S, P> {
	/// The target was already occupied at preflight.
	Conflict,
	/// The held roots or source observations did not match the exact plan.
	StalePlan,
	/// A target lookup failed.
	InspectTarget(S),
	/// The planned source could not be opened.
	Source(R),
	/// The source, attributes, or stream limits were outside the supported profile.
	SourcePolicy(StageFailure<R, S>),
	/// The local plan could not be constructed.
	Plan(LocalCopyPlanError),
	/// A preparation observation could not be validated.
	Preparation(PreparedError),
	/// The private job could not be established.
	Bootstrap(BootstrapError<S>),
	/// The stage directory could not be created and synchronized.
	CreateStage(S),
	/// The immutable checkpoint directory could not be created and synchronized.
	CreateCheckpoints(S),
	/// The copy or read-back of the private stage failed.
	Stage(StageCopyError<R, S>),
	/// Verified-stage evidence could not be encoded.
	Verification(VerificationRecordError),
	/// A native metadata timestamp could not be encoded.
	Timestamp(OwnerError),
	/// An effect record could not be synchronized. If this occurs from intent onward,
	/// reconciliation must determine the exact on-disk record and namespace.
	Journal {
		/// The frame whose append or barrier failed.
		kind: FrameKind,
		/// The journal writer's failure.
		source: DurableJournalError,
	},
	/// The publication model rejected an expected step.
	PublicationModel(StageFailure<R, S>),
	/// Construction of a publication, barrier, or receipt commitment record failed.
	PublicationRecord(PublicationRecordError),
	/// Publication did not report a confirmed exclusive rename and matching post-state.
	Publication {
		/// The adapter's exact outcome or error.
		source: P,
		/// A failure to synchronize the uncertain observation, if one occurred.
		recording: Option<DurableJournalError>,
	},
	/// An already-published copy's receipt could not be constructed.
	Receipt(ReceiptError),
	/// An already-published copy's synchronized receipt commitment failed journal readback.
	ReceiptJournalReadback(DurableJournalError),
	/// An already-published copy's receipt namespace or directory barrier failed.
	ReceiptNamespace(S),
	/// An already-published copy's receipt could not be written or synchronized.
	ReceiptIo(io::Error),
}

impl<R: fmt::Display, S: fmt::Display, P: fmt::Display> fmt::Display for CopyError<R, S, P> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Conflict => formatter.write_str("target was already occupied"),
			Self::StalePlan => {
				formatter.write_str("held roots or source observation changed since planning")
			}
			Self::InspectTarget(error) => {
				write!(formatter, "could not inspect the target ({error})")
			}
			Self::Source(error) => write!(formatter, "could not open the source ({error})"),
			Self::SourcePolicy(error) => write!(formatter, "source preflight failed ({error})"),
			Self::Plan(error) => write!(formatter, "local copy plan failed ({error})"),
			Self::Preparation(error) => {
				write!(formatter, "entry preparation evidence failed ({error})")
			}
			Self::Bootstrap(error) => write!(formatter, "could not prepare the job ({error})"),
			Self::CreateStage(error) => write!(
				formatter,
				"could not prepare the private stage directory ({error})"
			),
			Self::CreateCheckpoints(error) => write!(
				formatter,
				"could not prepare the private checkpoint directory ({error})"
			),
			Self::Stage(error) => write!(formatter, "private stage failed ({error})"),
			Self::Verification(error) => {
				write!(formatter, "stage verification evidence failed ({error})")
			}
			Self::Timestamp(error) => {
				write!(formatter, "could not encode required metadata ({error})")
			}
			Self::Journal { kind, source } => {
				write!(formatter, "could not synchronize {kind:?} ({source})")
			}
			Self::PublicationModel(error) => {
				write!(formatter, "publication state transition failed ({error})")
			}
			Self::PublicationRecord(error) => write!(
				formatter,
				"publication evidence requires reconciliation ({error})"
			),
			Self::Publication { source, recording } => {
				write!(formatter, "exclusive publication failed ({source})")?;
				if let Some(error) = recording {
					write!(
						formatter,
						", and its observation could not be recorded ({error})"
					)?;
				}
				Ok(())
			}
			Self::Receipt(error) => write!(
				formatter,
				"could not construct the published copy's receipt ({error})"
			),
			Self::ReceiptJournalReadback(error) => write!(
				formatter,
				"could not confirm the published copy's receipt commitment ({error})"
			),
			Self::ReceiptNamespace(error) => write!(
				formatter,
				"could not synchronize the receipt namespace ({error})"
			),
			Self::ReceiptIo(error) => write!(
				formatter,
				"could not synchronize the receipt artifact ({error})"
			),
		}
	}
}

impl<R: Error + 'static, S: Error + 'static, P: Error + 'static> Error for CopyError<R, S, P> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Conflict | Self::StalePlan => None,
			Self::InspectTarget(error)
			| Self::CreateStage(error)
			| Self::CreateCheckpoints(error)
			| Self::ReceiptNamespace(error) => Some(error),
			Self::Source(error) => Some(error),
			Self::SourcePolicy(error) | Self::PublicationModel(error) => Some(error),
			Self::Plan(error) => Some(error),
			Self::Preparation(error) => Some(error),
			Self::Bootstrap(error) => Some(error),
			Self::Stage(error) => Some(error),
			Self::Verification(error) => Some(error),
			Self::Timestamp(error) => Some(error),
			Self::Journal { source, .. } | Self::ReceiptJournalReadback(source) => Some(source),
			Self::PublicationRecord(error) => Some(error),
			Self::Publication { source, .. } => Some(source),
			Self::Receipt(error) => Some(error),
			Self::ReceiptIo(error) => Some(error),
		}
	}
}
