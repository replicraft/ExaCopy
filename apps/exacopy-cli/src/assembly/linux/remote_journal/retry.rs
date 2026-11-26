use exacopy_journal::frame::ChainHead;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::{
	RemoteDownloadContext, RemoteEpochs, RemoteSourceObservation,
};
use exacopy_platform::linux::{FileIdentity, RecoveryFile, RecoveryStageAnchor};

/// Current-run observations. The read-only pins confer no write lease.
pub(in crate::assembly::linux) struct RetryCaptureStamp {
	pub(super) context: RemoteDownloadContext,
	pub(super) owner: RecoveryFile,
	pub(super) segment: RecoveryFile,
	pub(super) boundary: RemoteReplayBoundary,
	pub(super) allocation: ChainHead,
	pub(super) prepared: ChainHead,
	pub(super) epochs: RemoteEpochs,
	pub(super) source: RemoteSourceObservation,
	pub(super) name: Box<[u8]>,
	pub(super) directory: FileIdentity,
	pub(super) file: FileIdentity,
	pub(super) extent: u64,
	pub(super) grant: [u8; 32],
	pub(super) qualification: [u8; 32],
	pub(super) anchor: RecoveryStageAnchor,
}
