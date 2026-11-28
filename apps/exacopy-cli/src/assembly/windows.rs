//! Read-only inspection of a selected fixed-NTFS bootstrap.

use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use exacopy_journal::OwnerDigest;
use exacopy_journal::windows_bootstrap::{
	FIRST_SEGMENT_BYTES, FIRST_SEGMENT_NAME, JOURNAL_DIRECTORY_NAME, OWNER_BYTES, OWNER_FILE_NAME,
	WindowsBootstrapFileIdentity, WindowsBootstrapInspectionError, WindowsBootstrapPrefix,
	WindowsBootstrapRoles, WindowsBootstrapSelection, inspect, job_directory_name,
};
use exacopy_platform::ProtectedSnapshotError;
use exacopy_platform::windows::{
	WindowsBootstrapLayout, WindowsBootstrapRecords, WindowsBootstrapRootSelection,
	WindowsComponent, WindowsStageIdentity,
};

/// Historical owner and first-frame evidence from one completed held observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsBootstrapObservation {
	owner_digest: OwnerDigest,
	boundary: WindowsBootstrapPrefix,
}

impl WindowsBootstrapObservation {
	/// Returns the digest of the authenticated owner envelope.
	#[must_use]
	pub const fn owner_digest(&self) -> OwnerDigest {
		self.owner_digest
	}

	/// Returns the verified first-frame boundary.
	#[must_use]
	pub const fn boundary(&self) -> WindowsBootstrapPrefix {
		self.boundary
	}
}

/// Reason a selected bootstrap could not be observed.
#[derive(Debug)]
pub enum WindowsBootstrapRefusal {
	/// The supplied key is weak or has a noncanonical encoding.
	UntrustedKey,
	/// A selected name or an observed identity could not represent the exact layout.
	InvalidLayout,
	/// The native holder could not open, read or finally recheck the selected roles.
	Custody(ProtectedSnapshotError),
	/// The selected owner or exact first frame failed authentication or framing.
	History(WindowsBootstrapInspectionError),
}

/// Checks one selected retained bootstrap using the exact held native record scope.
///
/// Supply the root path, full native root identity, job, profile and public key
/// from independent trusted provisioning or selection. The caller trusts the
/// kernel, storage and namespace administrators, LocalSystem and equivalent
/// principals, and cooperating current-user processes. Provisioning must exclude
/// retained untrusted mutation capabilities throughout the ancestry and roles.
/// Keep names, data, streams, owners and ACLs stable for the entire observation.
/// This opens the original owner and first segment for read-only observation and
/// may affect access times. The result contains historical values only.
///
/// # Errors
/// Refuses invalid selection, custody, authentication, first-segment format
/// or terminal EOF and custody recheck failures.
pub fn inspect_bootstrap(
	root: &Path,
	selection: &WindowsBootstrapSelection<'_>,
) -> Result<WindowsBootstrapObservation, WindowsBootstrapRefusal> {
	use WindowsBootstrapRefusal as Error;

	let key = selection.key;
	if key.is_weak() || key.to_edwards().compress().to_bytes() != key.to_bytes() {
		return Err(Error::UntrustedKey);
	}
	// Keep one overflow unit so the native counted-path parser can reject
	// oversized paths without accepting a truncated prefix.
	let root_units: Vec<_> = root.as_os_str().encode_wide().take(32_768).collect();
	let job_name = job_directory_name(selection.job);
	let layout = WindowsBootstrapLayout {
		job: component(&job_name)?,
		owner: component(&OWNER_FILE_NAME)?,
		journal: component(&JOURNAL_DIRECTORY_NAME)?,
		first_segment: component(&FIRST_SEGMENT_NAME)?,
		owner_bytes: OWNER_BYTES,
		first_segment_bytes: FIRST_SEGMENT_BYTES,
	};
	let root = WindowsBootstrapRootSelection {
		volume_guid: *selection.root.volume_guid(),
		volume_serial: selection.root.volume_serial(),
		file_id: *selection.root.file_id(),
	};
	let mut records =
		WindowsBootstrapRecords::open(&root_units, root, layout).map_err(Error::Custody)?;
	let held = records.roles();
	let roles = WindowsBootstrapRoles::new(
		identity(held.root)?,
		identity(held.job_directory)?,
		identity(held.owner_file)?,
		identity(held.journal_directory)?,
		identity(held.first_segment)?,
	)
	.map_err(|_| Error::InvalidLayout)?;
	let owner = records.read_owner().map_err(Error::Custody)?;
	let mut segment = records.first_segment();
	let historical = inspect(&owner, &mut segment, selection, roles).map_err(Error::History)?;
	segment.finish().map_err(Error::Custody)?;
	Ok(WindowsBootstrapObservation {
		owner_digest: historical.owner_digest(),
		boundary: historical.boundary(),
	})
}

fn component(name: &[u16]) -> Result<WindowsComponent<'_>, WindowsBootstrapRefusal> {
	WindowsComponent::new(name).map_err(|_| WindowsBootstrapRefusal::InvalidLayout)
}

fn identity(
	held: WindowsStageIdentity,
) -> Result<WindowsBootstrapFileIdentity, WindowsBootstrapRefusal> {
	WindowsBootstrapFileIdentity::new(held.volume_guid(), held.volume_serial(), held.file_id())
		.map_err(|_| WindowsBootstrapRefusal::InvalidLayout)
}
