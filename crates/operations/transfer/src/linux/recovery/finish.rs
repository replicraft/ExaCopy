use exacopy_endpoint::UnixComponent;

use super::super::CopyReceipt;
use super::{InspectionError, RecoveryInspection, RecoveryProfile, RecoveryStep};
use super::{LeaseReadError, RecoveryLease};

mod capabilities;
mod error;
mod held;
mod protocol;

pub use capabilities::{FinishReceiptDirectory, ReceiptLease};

pub use error::FinishFailure;
use protocol::FinishError;

/// Completes an already-published copy under the supplied exclusive lease.
///
/// # Errors
/// Fails on unsupported history, changed observations, or incomplete durable effects.
pub fn finish_with_lease<L: RecoveryLease>(
	lease: &L,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, FinishFailure<LeaseReadError<L>, L::EffectError>> {
	protocol::finish(&held::HeldRecovery(lease), name, profile, scratch)
		.map_err(FinishFailure::from)
}

pub(super) fn sync_leased_receipt<L: RecoveryLease>(
	lease: &L,
	receipt: &CopyReceipt<'_>,
) -> Result<(), FinishFailure<LeaseReadError<L>, L::EffectError>> {
	protocol::sync_receipt(&held::HeldRecovery(lease), receipt, None).map_err(FinishFailure::from)
}

pub(super) fn completion<R, S>(step: RecoveryStep) -> impl FnOnce(S) -> FinishFailure<R, S> {
	move |source| FinishFailure::Completion(step.platform()(source))
}

impl<R, S> From<FinishError<InspectionError<R, S>, S>> for FinishFailure<R, S> {
	fn from(error: FinishError<InspectionError<R, S>, S>) -> Self {
		match error {
			FinishError::Inspection(error) => Self::Inspection(error),
			FinishError::Completion(error) => Self::Completion(error),
			FinishError::Effect { step, source } => completion(step)(source),
			FinishError::IncompleteEvidence => Self::IncompleteEvidence,
			FinishError::EpochExhausted => Self::EpochExhausted,
			FinishError::Resume(error) => Self::Resume(error),
			FinishError::Decision(error) => Self::Decision(error),
			FinishError::Publication(error) => Self::Publication(error),
			FinishError::Journal { kind, source } => Self::Journal { kind, source },
			FinishError::Receipt(error) => Self::Receipt(error),
			FinishError::WriteReceipt(error) => Self::WriteReceipt(error),
		}
	}
}
