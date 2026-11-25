use exacopy_journal::frame::Frame;
use exacopy_journal::{
	DarwinOwnerRecord, DarwinPhaseError, DarwinRecoveryDecision, DarwinRecoveryDecisionFrames,
	DarwinRecoveryHistory, DarwinRecoveryStarted,
};

use super::DarwinReplayError;

pub(super) fn validate(
	owner: &DarwinOwnerRecord,
	original: &[Frame],
	recovery: &[Frame],
) -> Result<(), DarwinReplayError> {
	if recovery.is_empty() {
		return Ok(());
	}
	let [
		job,
		entry,
		seal,
		verification,
		metadata,
		intent,
		publication @ ..,
	] = original
	else {
		return Err(DarwinPhaseError::InvalidFrameOrder.into());
	};
	let (preceding, observed_before_durability) = match publication {
		[] => (intent, None),
		[observed] => (observed, None),
		[observed, durability] => (durability, Some(observed)),
		_ => return Err(DarwinPhaseError::InvalidFrameOrder.into()),
	};
	let history = DarwinRecoveryHistory {
		owner,
		job,
		entry,
		seal,
		verification,
		metadata,
		intent,
		observed_before_durability,
		preceding,
	};
	match recovery {
		[started] => DarwinRecoveryStarted::from_frame(started)?.validate_evidence(history)?,
		[started, decision] => DarwinRecoveryDecision::from_frame(decision)?
			.validate_evidence(DarwinRecoveryDecisionFrames { started, history })?,
		_ => return Err(DarwinPhaseError::InvalidFrameOrder.into()),
	}
	Ok(())
}
