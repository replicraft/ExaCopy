//! Private synchronous staging on a positively admitted, managed local APFS volume.

#[allow(
	unsafe_code,
	reason = "single checked close of the owned Darwin write descriptor"
)]
mod close;
mod directory;
#[allow(unsafe_code, reason = "fixed-size Darwin native entropy request")]
mod entropy;
mod error;
mod file;
mod identity;
mod reader;

#[cfg(test)]
mod tests;

pub use directory::{ManagedStageGrant, ManagedStageRoot, StageDirectory};
pub use error::StageError;
pub use file::{ClosedStage, WriteStage};
pub use identity::{StageBindingContext, StageIdentity};
pub use reader::StageReader;
