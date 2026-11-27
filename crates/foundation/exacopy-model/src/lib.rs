//! Pure decisions for ExaCopy transactions.
#![forbid(unsafe_code)]

mod binding;
pub mod protected_replace;
mod range;
pub mod retained_prefix;
mod sync;
pub mod sync_genesis;
pub mod sync_successor;
mod transaction;
pub mod witnessed_publication;

#[cfg(kani)]
#[path = "../verification/kani/mod.rs"]
mod kani_checks;

pub use binding::CopyBinding;
pub use exacopy_core::{EntryId, InvalidJobId, JobId, RunEpoch, StageId};
pub use range::checked_range_end;
pub use sync::{
	RegularFileEvidence, SyncBaseline, SyncBlock, SyncConflict, SyncCopyTarget,
	SyncInventoryCompleteness, SyncObservation, SyncPathDecision, SyncSide, classify_two_way_path,
};
pub use transaction::{
	CopyEffect, CopyEvent, CopyPhase, CopySession, PublishNoClobber, ReadSource, TransitionError,
};
