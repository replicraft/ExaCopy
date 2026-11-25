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
	/// The private parent is already locked by a cooperating writer.
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

/// Read the explicitly selected protected trust file within the supported Linux profile.
///
/// The profile assumes a nonprivileged process with matching real and
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
/// # Errors
/// Refuses any unsupported or unstable namespace, unusable lease, invalid or
/// unprotected path, bound violation or I/O failure. macOS, Windows and other
/// targets return Unsupported before inspecting the path. Errors omit the path
/// and the file contents.
pub fn read_protected_snapshot(path: &Path) -> Result<Vec<u8>, ProtectedSnapshotError> {
	#[cfg(target_os = "linux")]
	return crate::linux::protected_snapshot::read(path);

	#[cfg(not(target_os = "linux"))]
	{
		let _ = path;
		Err(ProtectedSnapshotError::Unsupported)
	}
}

#[cfg(all(test, not(target_os = "linux")))]
#[test]
fn an_unsupported_platform_refuses_even_before_path_validation() {
	assert_eq!(
		read_protected_snapshot(Path::new("relative")),
		Err(ProtectedSnapshotError::Unsupported)
	);
}
