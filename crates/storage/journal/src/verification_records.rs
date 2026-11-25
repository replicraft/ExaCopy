//! Local v1 journal observations after the stage writer has closed.

mod codec;
mod error;
mod metadata;
mod streams;

pub use error::VerificationRecordError;
pub use metadata::{BasicMetadata, MetadataOmission, MetadataRecorded};
pub use streams::{StageSealed, StreamDigest, StreamEvidence, StreamLength, VerificationRecorded};
