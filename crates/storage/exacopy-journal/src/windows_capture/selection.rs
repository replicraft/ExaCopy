use exacopy_endpoint::MAX_FILE_LENGTH;

use crate::windows_bootstrap::{WindowsBootstrapEvidence, WindowsBootstrapFileIdentity};

use super::WindowsCaptureError;

/// Independent archival selection, including the previously authenticated V1 bootstrap.
/// The selector must originate outside the candidate sibling's bytes.
#[derive(Clone, Copy, Debug)]
pub struct WindowsCaptureSelection<'a> {
	/// The independently selected and inspected original bootstrap.
	pub bootstrap: &'a WindowsBootstrapEvidence,
	/// The independently provisioned capture sibling on the original volume.
	pub sibling: WindowsBootstrapFileIdentity,
	/// The independently selected source scope commitment.
	pub source_scope: [u8; 32],
	/// The independently selected, nonzero invocation commitment.
	pub invocation: [u8; 32],
	/// The actual selected connection generation.
	pub generation: u64,
	/// The actual selected source epoch.
	pub epoch: u64,
	/// The independently authorized maximum observed source extent.
	pub extent_ceiling: u64,
	/// Exact externally validated native target code units.
	pub target: &'a [u16],
}

/// The three additional observed identities under the original bootstrap volume.
/// Holding these values confers neither native custody nor authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsCaptureRoles {
	/// The observed capture sibling.
	pub sibling: WindowsBootstrapFileIdentity,
	/// The observed protected stage directory.
	pub stage_directory: WindowsBootstrapFileIdentity,
	/// The observed protected stage payload.
	pub stage_payload: WindowsBootstrapFileIdentity,
}

pub(super) fn check_selection(
	selection: &WindowsCaptureSelection<'_>,
	observed: WindowsCaptureRoles,
	extent: u64,
) -> Result<(), WindowsCaptureError> {
	if selection.invocation == [0; 32]
		|| selection.generation == 0
		|| selection.epoch == 0
		|| selection.extent_ceiling > MAX_FILE_LENGTH
		|| extent > selection.extent_ceiling
		|| !(1..=255).contains(&selection.target.len())
	{
		return Err(WindowsCaptureError::Selection);
	}
	let bootstrap = selection.bootstrap.owner().roles;
	let root = bootstrap.root();
	let originals = [
		root,
		bootstrap.job_directory(),
		bootstrap.owner_file(),
		bootstrap.journal_directory(),
		bootstrap.first_segment(),
	];
	let additions = [
		observed.sibling,
		observed.stage_directory,
		observed.stage_payload,
	];
	if observed.sibling != selection.sibling {
		return Err(WindowsCaptureError::Roles);
	}
	for (index, role) in additions.iter().enumerate() {
		if role.volume_guid() != root.volume_guid()
			|| role.volume_serial() != root.volume_serial()
			|| originals.contains(role)
			|| additions[..index].contains(role)
		{
			return Err(WindowsCaptureError::Roles);
		}
	}
	Ok(())
}
