//! Exclusive publication for a metadata-ready stage in the managed APFS profile.
//!
//! The adapter requires the metadata transition before the model's capability can be used.
//!
//! ```compile_fail
//! use exacopy_model::PublishNoClobber;
//! use exacopy_platform::macos::staging::ClosedStage;
//!
//! fn publish_without_metadata(stage: ClosedStage<'_>, token: PublishNoClobber) {
//!     let _ = stage.publish_no_clobber(token);
//! }
//! ```

mod attempt;
mod error;
mod evidence;
#[allow(unsafe_code, reason = "Darwin descriptor-relative exclusive rename")]
mod native;
#[cfg(test)]
mod tests;

pub use error::{
	DirectoryBarrierFailures, PublishError, PublishRejection, PublishedObservationError,
};
pub use evidence::PublishedFile;
pub(super) use native::rename_exclusively;
