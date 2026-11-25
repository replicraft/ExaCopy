//! Coordinates verification, journaled publication, and receipt commitment.

mod capabilities;
mod engine;

pub use capabilities::{
	FailedEffect, PreparedCopy, PublicationFailure, PublicationJournal, PublishedEvidence,
	ReceiptStore, VerifiedCopy, VerifiedStreams,
};
pub use engine::{CoordinatorError, CopyFailure, PreparedEvidence, PublicationProgress, execute};
