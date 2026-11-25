use std::io;
use std::os::fd::BorrowedFd;

use apfs_mounted::volume::{self, Capability, VolumeCapabilities};

pub(super) fn supports_managed_root(directory: BorrowedFd<'_>) -> io::Result<bool> {
	check_reported(directory, |capabilities| {
		managed_capabilities(
			capabilities.permissions,
			capabilities.acls,
			capabilities.advisory_locking,
		)
	})
}

pub(super) fn supports_exclusive_rename(directory: BorrowedFd<'_>) -> io::Result<bool> {
	check_reported(directory, |capabilities| {
		rename_is_supported(capabilities.exclusive_rename)
	})
}

fn check_reported(
	directory: BorrowedFd<'_>,
	supported: impl FnOnce(VolumeCapabilities) -> bool,
) -> io::Result<bool> {
	match volume::observe(directory) {
		Ok(volume) => Ok(supported(volume.capabilities)),
		// The native profile refuses a malformed response as insufficient evidence.
		Err(error)
			if error.kind() == io::ErrorKind::InvalidData && error.raw_os_error().is_none() =>
		{
			Ok(false)
		}
		Err(error) => Err(error),
	}
}

fn rename_is_supported(exclusive_rename: Capability) -> bool {
	exclusive_rename == Capability::Supported
}

fn managed_capabilities(
	permissions: Capability,
	acls: Capability,
	advisory_locking: Capability,
) -> bool {
	[permissions, acls, advisory_locking]
		.into_iter()
		.all(|capability| capability == Capability::Supported)
}

#[test]
fn requires_reported_permission_acl_and_lock_support() {
	use Capability::{Supported, Unknown, Unsupported};

	assert!(managed_capabilities(Supported, Supported, Supported));
	for refused in [Unknown, Unsupported] {
		assert!(!managed_capabilities(refused, Supported, Supported));
		assert!(!managed_capabilities(Supported, refused, Supported));
		assert!(!managed_capabilities(Supported, Supported, refused));
	}
}

#[test]
fn exclusive_rename_requires_a_positive_capability_observation() {
	assert!(rename_is_supported(Capability::Supported));
	assert!(!rename_is_supported(Capability::Unknown));
	assert!(!rename_is_supported(Capability::Unsupported));
}
