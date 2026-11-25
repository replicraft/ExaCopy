//! Private staging capabilities rooted in one held destination directory.

mod directory;
mod error;
mod file;
mod publish;

pub use directory::{DestinationRoot, StageDirectory};
pub use error::{DirectoryBarriersError, PublishError, StageError};
pub use file::{ClosedStage, WriteStage};
