//! Private Linux journal evidence for a single live, read-only SFTP capture.

mod bootstrap;
pub mod checkpoints;
mod error;
pub mod finalization;
pub mod finalization_policy;
pub mod finalization_replay;
mod owner;
pub mod qualification;
mod records;
pub mod replay;
pub mod retirement;
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
	DirectPeerRefusal, MAX_REMOTE_PATH_BYTES, RemoteDownloadDestination, RemoteDownloadDurability,
	RemoteDownloadRoute, RemoteDownloadScope, RemoteDownloadSource, RemoteScopeDigest,
};
