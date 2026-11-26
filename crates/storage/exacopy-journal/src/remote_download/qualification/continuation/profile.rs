use super::{
	RemoteContinuationCoverageProfile as Coverage, RemoteContinuationOperationProfile as Operation,
};

#[derive(Clone, Copy)]
pub(super) enum Profile {
	Original,
	Witness,
}

impl Profile {
	pub(super) const fn selection(self) -> (Operation, Coverage) {
		match self {
			Self::Original => (
				Operation::VerifiedRetainedAppendV1,
				Coverage::RetainedAppendProcessCrashV1,
			),
			Self::Witness => (
				Operation::VerifiedRetainedAppendWithWitnessV1,
				Coverage::RetainedAppendWithWitnessProcessCrashV1,
			),
		}
	}

	pub(super) const fn wire(self) -> (u8, u8, u32) {
		match self {
			Self::Original => (1, 1, 0x0fff),
			Self::Witness => (2, 2, 0x00ff_ffff),
		}
	}
}
