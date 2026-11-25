//! Single-attempt private stage preparation for an admitted copy plan.

mod engine;
pub mod publish;

pub use engine::{
	EntryAttempt, EntryOpenFailure, EntryRequest, ObservedStage, PreparationFailure, PreparedStage,
	PrivateStage, RequestError, StageAdmissionFailure, StageRequest, open, prepare,
};
