//! Private synchronous staging on a positively admitted, managed local APFS volume.

mod capabilities;
#[allow(
	unsafe_code,
	reason = "single checked close of the owned Darwin write descriptor"
)]
mod close;
mod directory;
mod entropy;
mod error;
mod file;
mod identity;
mod metadata;
mod reader;
mod selected_stream;

#[cfg(test)]
mod tests;

pub use directory::jobs;
pub use directory::{ManagedStageGrant, ManagedStageRoot, StageDirectory};
pub use error::StageError;
pub(super) use file::StageLocation;
pub use file::{ClosedStage, MAX_STAGE_IO_BYTES, ManagedStageName, WriteStage};
pub use identity::{StageBindingContext, StageIdentity};
pub use metadata::MetadataReadyStage;
pub use reader::StageReader;
pub use selected_stream::{SelectedStreamObservation, SelectedStreamReader};
