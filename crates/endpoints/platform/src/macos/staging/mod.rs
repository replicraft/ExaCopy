//! Private synchronous staging on a positively admitted, managed local APFS volume.

#[allow(
	unsafe_code,
	reason = "single checked close of the owned Darwin write descriptor"
)]
mod close;
mod directory;
mod error;
mod file;
mod reader;

#[cfg(test)]
mod tests;

pub use directory::{ManagedStageGrant, ManagedStageRoot, StageDirectory};
pub use error::StageError;
pub use file::{ClosedStage, WriteStage};
pub use reader::StageReader;
