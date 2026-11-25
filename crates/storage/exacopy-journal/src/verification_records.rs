//! Local v1 journal observations for range data and sealed stages.

mod codec;
mod error;
mod metadata;
mod ranges;
mod streams;

pub use error::VerificationRecordError;
pub use metadata::{BasicMetadata, MetadataOmission, MetadataRecorded};
pub use ranges::{
	MAX_CHECKPOINT_RANGE_BYTES, MAX_RANGE_CHECKPOINTS, MAX_RANGE_PAGE_BYTES, RangeCheckpoint,
	RangePage, RangePageRef, SourceMeasurementId,
};
pub use streams::{StageSealed, StreamDigest, StreamEvidence, StreamLength, VerificationRecorded};
