use std::ffi::OsString;
use std::path::PathBuf;

use super::Format;

pub(crate) struct RemoteCommand {
	pub(crate) request: RemoteRequest,
	pub(crate) options: RemoteOptions,
}

pub(crate) enum RemoteRequest {
	Get {
		source: OsString,
		target: PathBuf,
	},
	Resume {
		job: PathBuf,
		#[cfg(feature = "experimental-verified-prefix-resume")]
		strategy: RemoteResumeStrategy,
	},
}

#[cfg(feature = "experimental-verified-prefix-resume")]
pub(crate) enum RemoteResumeStrategy {
	Fresh,
	VerifiedPrefixWithWitness {
		qualification: PathBuf,
		trust: PathBuf,
	},
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
