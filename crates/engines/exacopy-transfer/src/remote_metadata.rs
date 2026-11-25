//! Transfer admission for ordinary SFTP download metadata policies.

use std::{error::Error, fmt};

use exacopy_journal::remote_download::finalization_policy::{SftpDataOnlyV1, SftpOmission};

/// User-selected metadata policy for an ordinary SFTP download.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RemoteMetadataSelection {
	/// The default Linux required-data policy.
	#[default]
	LinuxRequiredData,
	/// Explicitly select only the SFTP unnamed stream and the local safety policy.
	SftpDataOnlyV1,
}

/// Selected metadata policy for one agentless SFTP transfer.
///
/// This only establishes the policy selection. The caller still obtains scope
/// authorization, and the native adapter verifies its local observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovedSftpMetadata(());

impl ApprovedSftpMetadata {
	/// Returns the fixed policy selector.
	#[must_use]
	pub const fn name(self) -> &'static str {
		SftpDataOnlyV1::NAME
	}

	/// Returns the exact digest to bind into the authorized scope.
	#[must_use]
	pub fn digest(self) -> [u8; 32] {
		SftpDataOnlyV1::digest()
	}

	/// Returns the omission codes for the selected-stream receipt.
	#[must_use]
	pub const fn omissions(self) -> &'static [SftpOmission] {
		SftpDataOnlyV1::omissions()
	}

	/// Checks the previously signed metadata-policy digest before writable reopen.
	///
	/// # Errors
	/// Refuses an unknown or differently selected recorded policy.
	pub fn verify_recorded(self, recorded: [u8; 32]) -> Result<(), RemoteMetadataRefusal> {
		if recorded == self.digest() {
			Ok(())
		} else {
			Err(RemoteMetadataRefusal::PolicyMismatch)
		}
	}
}

/// Failure to admit a metadata policy before a job or stage allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteMetadataRefusal {
	/// Ordinary SFTP does not supply the required Linux metadata evidence.
	LinuxRequiredDataUnavailable,
	/// The selected policy differs from the one bound by the recorded scope.
	PolicyMismatch,
}

impl fmt::Display for RemoteMetadataRefusal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::LinuxRequiredDataUnavailable => "ordinary SFTP cannot supply Linux required data",
			Self::PolicyMismatch => {
				"the selected SFTP metadata policy differs from the signed scope"
			}
		})
	}
}

impl Error for RemoteMetadataRefusal {}

/// Checks the explicit metadata selection for ordinary SFTP before allocation.
///
/// # Errors
/// Refuses the default Linux required-data policy for ordinary SFTP.
pub fn admit_sftp_metadata(
	selection: RemoteMetadataSelection,
) -> Result<ApprovedSftpMetadata, RemoteMetadataRefusal> {
	match selection {
		RemoteMetadataSelection::LinuxRequiredData => {
			Err(RemoteMetadataRefusal::LinuxRequiredDataUnavailable)
		}
		RemoteMetadataSelection::SftpDataOnlyV1 => Ok(ApprovedSftpMetadata(())),
	}
}

#[cfg(test)]
mod tests {
	use super::{RemoteMetadataRefusal, RemoteMetadataSelection, admit_sftp_metadata};

	#[test]
	fn only_explicit_data_only_selection_admits_scope_binding() {
		assert_eq!(
			admit_sftp_metadata(RemoteMetadataSelection::default()),
			Err(RemoteMetadataRefusal::LinuxRequiredDataUnavailable)
		);
		let approved =
			admit_sftp_metadata(RemoteMetadataSelection::SftpDataOnlyV1).expect("explicit policy");
		assert_eq!(approved.name(), "sftp-data-only-v1");
		assert_eq!(
			approved.omissions()[0].name(),
			"additional_content_streams_unenumerated"
		);
		assert_eq!(
			approved.digest(),
			[
				0x6e, 0x36, 0x76, 0xa4, 0x24, 0x1c, 0xbf, 0x37, 0x9f, 0x4c, 0xdc, 0xa6, 0xf4, 0x6d,
				0x14, 0xf1, 0x8e, 0xbf, 0xd5, 0x43, 0x2c, 0xda, 0xb7, 0xd6, 0x99, 0x1c, 0x74, 0xa2,
				0x22, 0x41, 0x8d, 0x6e,
			]
		);
		assert_eq!(approved.verify_recorded(approved.digest()), Ok(()));
		assert_eq!(
			approved.verify_recorded([99; 32]),
			Err(RemoteMetadataRefusal::PolicyMismatch)
		);
	}
}
