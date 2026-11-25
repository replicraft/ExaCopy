//! Private staging capabilities rooted in one held destination directory.

mod directory;
mod error;
mod file;
mod publish;

pub use directory::{DestinationRoot, StageDirectory};
pub use error::{DirectoryBarriersError, PublishError, StageError};
pub use file::{ClosedStage, WriteStage};

pub(super) use directory::{
	check_private_child, component, create_private_directory, sync_directory,
};
pub(super) use file::create_private_file;
