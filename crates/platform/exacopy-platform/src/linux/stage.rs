//! Private staging capabilities rooted in one held destination directory.

mod directory;
mod error;
mod file;
mod publish;
pub(super) mod selected_stream;

pub use directory::{DestinationRoot, StageDirectory};
pub use error::{DirectoryBarriersError, PublishError, StageError};
pub use file::{CheckedStageError, ClosedStage, NativePublishedStage, WriteStage};
pub use selected_stream::{
	SelectedStreamGateRequest, SelectedStreamLocation, SelectedStreamMetadataReady,
	SelectedStreamNames, SelectedStreamObservation, SelectedStreamPublication,
	SelectedStreamPublicationAuthority, SelectedStreamPublishError,
};

pub(super) use directory::{
	CHILD_RESOLVE, DirectoryCreateFailure, check_private_child, component,
	create_private_directory, create_private_directory_admitted, create_private_directory_observed,
	sync_directory, sync_directory_admitted,
};
pub(super) use file::effect::write_admitted;
pub(super) use file::{
	FILE_MODE, check_named_file, check_no_visible_attributes, create_private_file,
	create_private_file_admitted,
};
pub(super) use publish::PublicationNames;
