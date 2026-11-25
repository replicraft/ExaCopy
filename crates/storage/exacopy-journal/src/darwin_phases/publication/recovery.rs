//! Bounded evidence for reconciling an already-published managed APFS target.

mod decision;
mod started;

pub use decision::{
	DarwinPublishedRecoveryEvidence, DarwinRecoveryDecision, DarwinRecoveryDecisionFrames,
};
pub use started::{DarwinRecoveryHistory, DarwinRecoveryStarted};

use crate::DarwinPhaseError;
use crate::frame::{ChainHead, Frame};

fn require_successor(prior: ChainHead, frame: &Frame) -> Result<(), DarwinPhaseError> {
	if prior.sequence().checked_add(1) != Some(frame.head().sequence())
		|| prior.digest() != frame.previous_digest()
	{
		return Err(DarwinPhaseError::InvalidFrameOrder);
	}
	Ok(())
}
