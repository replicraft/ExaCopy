use std::fmt;
use std::path::Path;

#[cfg(any(
	target_os = "linux",
	all(test, any(target_os = "macos", target_os = "windows"))
))]
mod path;

#[cfg(target_os = "linux")]
pub(crate) use path::checked_components;

/// Maximum length of a protected trust snapshot, in bytes.
pub const MAX_PROTECTED_SNAPSHOT_BYTES: usize = 1024 * 1024;

/// Why acquisition of the selected protected trust snapshot was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProtectedSnapshotError {
	/// The selected platform, mount or process context is outside the supported profile.
	Unsupported,
	/// The path is not an explicit, bounded absolute path in the supported profile.
	InvalidPath,
	/// A directory or file lacks the required type, ownership or permissions.
	Unprotected,
	/// A parent lease or incompatible Windows share mode blocked stable acquisition.
	Busy,
	/// The selected file exceeds the snapshot's byte limit.
	TooLarge,
	/// The selected name, directory chain, observed metadata or bytes changed.
	Changed,
	/// A required lookup, I/O operation or protection observation failed.
	Unavailable,
}

impl fmt::Display for ProtectedSnapshotError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Unsupported => "protected trust snapshot profile is unsupported",
			Self::InvalidPath => "invalid protected trust snapshot path",
			Self::Unprotected => "protected trust snapshot permissions or file type were refused",
			Self::Busy => "protected trust snapshot directory is locked by a writer",
			Self::TooLarge => "protected trust snapshot exceeds the byte limit",
			Self::Changed => "protected trust snapshot changed during acquisition",
			Self::Unavailable => "protected trust snapshot is unavailable",
		})
	}
}

impl std::error::Error for ProtectedSnapshotError {}

/// Read the explicitly selected protected trust file within an admitted platform profile.
///
/// The Linux profile assumes a nonprivileged process with matching real and
/// effective user IDs, unchanged filesystem credentials, a trusted kernel
/// and mount administrator, and a genuine procfs mounted at `/proc`.
/// The entire path must be on the whole ext4 or XFS root mount. Every
/// ancestor must be controlled by root or the effective UID and deny writes
/// to the POSIX ACL group class and other users. The file's immediate parent
/// must belong to the effective UID with exact mode 0700. The file must be a
/// regular file with that same owner, exact mode 0600 and one hard link.
/// Cooperating writers must hold an exclusive flock on their independently
/// opened private parent when mutating the selected file or its name. The
/// namespace and file must have been provisioned without giving untrusted
/// writers retained writable handles. The reader holds a shared lock, compares
/// two complete positioned reads and rechecks metadata and names. These live
/// observations rely on the cooperation of the owner and privileged actors.
/// Ordinary reads may update access time. Success may contain zero bytes.
///
/// Windows requires the opt-in native read feature. It accepts literal absolute
/// drive paths on fixed local NTFS under a stable non-elevated, non-impersonated
/// user token with no enabled backup, restore, take-ownership or manage-volume
/// privilege. Every opened component is held without write or delete sharing.
/// Upper directories must have trusted owners and refuse untrusted access that
/// can rewrite existing entries. The current user must own the immediate parent
/// and one-link regular file, with protected DACLs excluding untrusted grants.
/// A metadata-only open precedes the data open. The reader compares two complete
/// reads and checks identity, names, protection evidence, token, and actual EOF.
/// The held and freshly named file observations must show only the unnamed data
/// stream at the admitted extent.
/// The caller must trust the kernel, volume/device namespace, LocalSystem, local
/// administrators, principals delegated equivalent storage or ACL-bypass
/// privileges, and processes acting as the current user. Provisioning must
/// exclude untrusted retained content capabilities for the private objects and
/// untrusted retained security or namespace mutation capabilities throughout
/// the admitted path.
///
/// # Errors
/// Refuses any unsupported or unstable namespace, unusable lease, invalid or
/// unprotected path, bound violation or I/O failure. Unadmitted platforms return
/// Unsupported before inspecting the path. Errors omit the path
/// and the file contents.
pub fn read_protected_snapshot(path: &Path) -> Result<Vec<u8>, ProtectedSnapshotError> {
	#[cfg(target_os = "linux")]
	return crate::linux::protected_snapshot::read(path);

	#[cfg(all(target_os = "windows", feature = "experimental-windows-read"))]
	return crate::windows::protected_snapshot::read(path);

	#[cfg(not(any(
		target_os = "linux",
		all(target_os = "windows", feature = "experimental-windows-read")
	)))]
	{
		let _ = path;
		Err(ProtectedSnapshotError::Unsupported)
	}
}

#[cfg(all(
	test,
	not(any(
		target_os = "linux",
		all(target_os = "windows", feature = "experimental-windows-read")
	))
))]
#[test]
fn an_unsupported_platform_refuses_even_before_path_validation() {
	assert_eq!(
		read_protected_snapshot(Path::new("relative")),
		Err(ProtectedSnapshotError::Unsupported)
	);
}

/// Read a protected snapshot with a caller-selected smaller byte limit.
///
/// The caller owns both buffers and their lifecycle. Both may contain
/// partial snapshot bytes on failure. Consumers of secrets should wipe
/// them on every exit. The platform never allocates a second data buffer.
///
/// The path, lease, identity and double-read checks are the same as in
/// [`read_protected_snapshot`].
///
/// # Errors
/// Refuses an empty read-back buffer, an unsupported platform or any
/// failed protection, size, identity or stability check.
pub fn read_protected_snapshot_into(
	path: &Path,
	bytes: &mut [u8],
	readback: &mut [u8],
) -> Result<usize, ProtectedSnapshotError> {
	#[cfg(target_os = "linux")]
	return crate::linux::protected_snapshot::read_into(path, bytes, readback);

	#[cfg(all(target_os = "windows", feature = "experimental-windows-read"))]
	return crate::windows::protected_snapshot::read_into(path, bytes, readback);

	#[cfg(not(any(
		target_os = "linux",
		all(target_os = "windows", feature = "experimental-windows-read")
	)))]
	{
		let _ = (path, bytes, readback);
		Err(ProtectedSnapshotError::Unsupported)
	}
}

#[cfg(test)]
#[test]
fn caller_buffer_snapshot_refuses_an_invalid_path_without_touching_buffers() {
	let mut bytes = [0x31; 8];
	let mut readback = [0x32; 4];
	let result = read_protected_snapshot_into(Path::new("relative"), &mut bytes, &mut readback);
	#[cfg(any(
		target_os = "linux",
		all(target_os = "windows", feature = "experimental-windows-read")
	))]
	assert_eq!(result, Err(ProtectedSnapshotError::InvalidPath));
	#[cfg(not(any(
		target_os = "linux",
		all(target_os = "windows", feature = "experimental-windows-read")
	)))]
	assert_eq!(result, Err(ProtectedSnapshotError::Unsupported));
	assert_eq!(bytes, [0x31; 8]);
	assert_eq!(readback, [0x32; 4]);
}
