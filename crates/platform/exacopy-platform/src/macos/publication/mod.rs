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
#[cfg(test)]
mod native;
#[cfg(test)]
mod tests;

pub use error::{
	CheckedPublishError, DirectoryBarrierFailures, PublishError, PublishRejection,
	PublishedObservationError,
};
pub use evidence::{PublicationGateRequest, PublishedFile};
