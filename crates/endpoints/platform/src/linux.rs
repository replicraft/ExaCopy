//! Linux handle-relative source, staging, and exclusive publication primitives.

mod handle;
mod source;
mod stage;

pub use handle::FileIdentity;
pub use source::{ReadError, ReadRoot, SourceFile};
pub use stage::{
	ClosedStage, DestinationRoot, DirectoryBarriersError, PublishError, StageDirectory, StageError,
	WriteStage,
};
