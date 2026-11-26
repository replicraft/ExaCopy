use std::ffi::OsString;
use std::path::PathBuf;

use super::Format;

pub(crate) struct RemoteCommand {
	pub(crate) request: RemoteRequest,
	pub(crate) options: RemoteOptions,
}

pub(crate) enum RemoteRequest {
	Get { source: OsString, target: PathBuf },
	Resume { job: PathBuf },
}

pub(crate) struct RemoteOptions {
	pub(crate) profile: PathBuf,
	pub(crate) ssh_profile: PathBuf,
	pub(crate) destination_qualification: PathBuf,
	pub(crate) qualification_trust: PathBuf,
	pub(crate) metadata: RemoteMetadata,
	pub(crate) format: Format,
}

pub(crate) enum RemoteMetadata {
	SftpDataOnlyV1,
}
