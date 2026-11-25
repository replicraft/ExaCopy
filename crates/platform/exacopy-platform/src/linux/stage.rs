//! Private staging capabilities rooted in one held destination directory.

mod directory;
mod error;
mod file;
mod publish;
pub(super) mod selected_stream;

pub use directory::{DestinationRoot, StageDirectory};
pub use error::{DirectoryBarriersError, PublishError, StageError};
pub use file::{ClosedStage, WriteStage};
pub use selected_stream::{
	SelectedStreamGateRequest, SelectedStreamLocation, SelectedStreamMetadataReady,
	SelectedStreamNames, SelectedStreamObservation, SelectedStreamPublication,
	SelectedStreamPublicationAuthority, SelectedStreamPublishError,
};

pub(super) use directory::{
	CHILD_RESOLVE, check_private_child, component, create_private_directory, sync_directory,
};
pub(super) use file::{
	FILE_MODE, check_named_file, check_no_visible_attributes, create_private_file,
};
pub(super) use publish::PublicationNames;
