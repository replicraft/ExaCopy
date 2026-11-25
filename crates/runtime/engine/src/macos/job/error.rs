use std::{error::Error, fmt};

use exacopy_journal::{DarwinPreparedError, DurableJournalError, OwnerError};
use exacopy_model::InvalidJobId;
use exacopy_platform::macos::ManagedReadError;
use exacopy_platform::macos::staging::jobs::{JobError, JobName};
use exacopy_transfer::macos::job::JobPreparationStep;

/// A failed managed APFS job bootstrap and its reconciliation boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum JobBootstrapError {
	/// An input or live observation was rejected before any private creation.
	Admission(JobAdmissionError),
	/// Exclusive job creation failed or left an entry whose outcome is uncertain.
	Create(JobError),
	/// The job directory was created and remains in place for reconciliation.
	Retained {
		/// The affected private job name.
		job: JobName,
		/// The phase and cause of the failed preparation.
		source: JobPreparationError,
	},
}

impl fmt::Display for JobBootstrapError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Admission(error) => {
				write!(formatter, "managed APFS plan admission failed ({error})")
			}
			Self::Create(error) => write!(formatter, "private job creation failed ({error})"),
			Self::Retained { source, .. } => {
				write!(formatter, "private job requires reconciliation ({source})")
			}
		}
	}
}

impl Error for JobBootstrapError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(match self {
			Self::Admission(error) => error,
			Self::Create(error) => error,
			Self::Retained { source, .. } => source,
		})
	}
}

impl From<JobAdmissionError> for JobBootstrapError {
	fn from(error: JobAdmissionError) -> Self {
		Self::Admission(error)
	}
}

/// An input or live observation that prevented bootstrap admission.
#[derive(Debug)]
#[non_exhaustive]
pub enum JobAdmissionError {
	/// The independently trusted profile ID disagrees with the plan.
	ProfileMismatch,
	/// The selected UUID could not be converted to a private job name.
	InvalidJobName(InvalidJobId),
	/// The independently supplied token or signing key was refused.
	Owner(OwnerError),
	/// A live native observation could not be represented in the job format.
	Identity(OwnerError),
	/// The source grant, component, native observations, or metadata disagree with the plan.
	SourceMismatch,
	/// The destination grant or held root disagrees with the plan.
	DestinationMismatch,
	/// Live source identity or strict metadata revalidation failed.
	Source(ManagedReadError),
	/// Private-container authority or target absence could not be established.
	Destination(JobError),
}

impl fmt::Display for JobAdmissionError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ProfileMismatch => formatter.write_str("trusted profile disagrees with the plan"),
			Self::InvalidJobName(error) => {
				write!(formatter, "invalid private job identity ({error})")
			}
			Self::Owner(error) => write!(formatter, "invalid trusted owner input ({error})"),
			Self::Identity(error) => write!(formatter, "unsupported APFS identity ({error})"),
			Self::SourceMismatch => formatter.write_str("held source disagrees with the plan"),
			Self::DestinationMismatch => {
				formatter.write_str("held destination disagrees with the plan")
			}
			Self::Source(error) => write!(formatter, "managed source check failed ({error})"),
			Self::Destination(error) => {
				write!(formatter, "managed destination check failed ({error})")
			}
		}
	}
}

impl Error for JobAdmissionError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::InvalidJobName(error) => Some(error),
			Self::Owner(error) | Self::Identity(error) => Some(error),
			Self::Source(error) => Some(error),
			Self::Destination(error) => Some(error),
			_ => None,
		}
	}
}

/// Preparing the retained job failed after exclusive directory creation.
#[derive(Debug)]
#[non_exhaustive]
pub enum JobPreparationError {
	/// Building or signing the owner record failed.
	Owner(OwnerError),
	/// The job and live destination observations could not be bound to the signed owner.
	Binding(DarwinPreparedError),
	/// Creating or synchronizing a private artifact failed.
	Artifact {
		/// The artifact being prepared.
		step: JobPreparationStep,
		/// The cause, including uncertainty from any attempted creation.
		source: JobError,
	},
	/// The first segment or its initial frame could not be admitted or synchronized.
	Journal(DurableJournalError),
}

impl fmt::Display for JobPreparationError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Owner(error) => write!(formatter, "owner signing failed ({error})"),
			Self::Binding(error) => write!(formatter, "job preparation binding failed ({error})"),
			Self::Artifact { step, source } => {
				write!(formatter, "private {step:?} preparation failed ({source})")
			}
			Self::Journal(error) => write!(formatter, "initial job journal failed ({error})"),
		}
	}
}

impl Error for JobPreparationError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(match self {
			Self::Owner(error) => error,
			Self::Binding(error) => error,
			Self::Artifact { source, .. } => source,
			Self::Journal(error) => error,
		})
	}
}

impl From<OwnerError> for JobPreparationError {
	fn from(error: OwnerError) -> Self {
		Self::Owner(error)
	}
}
