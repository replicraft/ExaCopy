//! Pure decisions for preserve-mode ExaCopy transactions.
#![forbid(unsafe_code)]

mod identity;
mod range;
mod transaction;

#[cfg(kani)]
#[path = "../verification/kani/mod.rs"]
mod kani_checks;

pub use identity::{CopyBinding, EntryId, InvalidJobId, JobId, RunEpoch, StageId};
pub use range::checked_range_end;
pub use transaction::{
	CopyEffect, CopyEvent, CopyPhase, CopySession, PublishNoClobber, ReadSource, TransitionError,
};
