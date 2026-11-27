use std::fmt;

use super::{FileIdentity, SyncGenesisOperation, SyncProfileStoreError};

/// Last known namespace state of one bounded genesis publication request.
#[derive(Debug)]
#[non_exhaustive]
pub enum SyncGenesisPublishError {
	/// No rename was submitted. Preserve any staging and intent entries.
	PreSubmission {
		/// Independently selected publication operation.
		operation: SyncGenesisOperation,
		/// Original held stage, if established during this attempt.
		stage: Option<FileIdentity>,
		/// Check or native effect that stopped the attempt.
		cause: SyncProfileStoreError,
	},
	/// The kernel no-replace rename reported that the exact target was occupied.
	KernelExists {
		/// Independently selected publication operation.
		operation: SyncGenesisOperation,
		/// Original held stage, retained beside the incumbent.
		stage: FileIdentity,
	},
	/// A rename was submitted and its outcome requires reconciliation.
	SubmittedUnknown {
		/// Independently selected publication operation.
		operation: SyncGenesisOperation,
		/// Original held stage.
		stage: FileIdentity,
		/// Native failure at submission.
		cause: SyncProfileStoreError,
	},
	/// The kernel reported rename success, but a final check or barrier refused.
	KernelSuccessLaterUncertain {
		/// Independently selected publication operation.
		operation: SyncGenesisOperation,
		/// Original held stage expected under the final name.
		stage: FileIdentity,
		/// Final check or native effect that prevented acknowledgment.
		cause: SyncProfileStoreError,
	},
}

impl fmt::Display for SyncGenesisPublishError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::PreSubmission { cause, .. } => {
				write!(
					formatter,
					"sync genesis publication stopped before submission: {cause}"
				)
			}
			Self::KernelExists { .. } => {
				formatter.write_str("sync genesis output slot is occupied")
			}
			Self::SubmittedUnknown { cause, .. } => {
				write!(formatter, "sync genesis rename outcome is unknown: {cause}")
			}
			Self::KernelSuccessLaterUncertain { cause, .. } => {
				write!(
					formatter,
					"sync genesis final acknowledgment is unconfirmed: {cause}"
				)
			}
		}
	}
}

impl std::error::Error for SyncGenesisPublishError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::PreSubmission { cause, .. }
			| Self::SubmittedUnknown { cause, .. }
			| Self::KernelSuccessLaterUncertain { cause, .. } => Some(cause),
			Self::KernelExists { .. } => None,
		}
	}
}
