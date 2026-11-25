//! Private Linux journal evidence for a single live, read-only SFTP capture.

mod bootstrap;
mod error;
mod owner;
mod records;
pub mod replay;
mod scope;
mod wire;

pub use bootstrap::{
	MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES, RemoteBootstrapTrust, RemoteStageDirectoryPrepared,
};
pub use error::RemoteDownloadError;
pub use owner::{MAX_REMOTE_DOWNLOAD_OWNER_BYTES, RemoteDownloadOwner, RemoteDownloadOwnerRecord};
pub use records::{
	MAX_REMOTE_CHECKPOINT_BYTES, MAX_REMOTE_CHECKPOINTS, MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES,
	RemoteDownloadBody, RemoteDownloadContext, RemoteDownloadRecord, RemoteEpochs,
	RemoteSourceObservation, RemoteUncertainBoundary,
};
pub use scope::{
	MAX_REMOTE_PATH_BYTES, RemoteDownloadDestination, RemoteDownloadDurability,
	RemoteDownloadRoute, RemoteDownloadScope, RemoteDownloadSource, RemoteScopeDigest,
};
