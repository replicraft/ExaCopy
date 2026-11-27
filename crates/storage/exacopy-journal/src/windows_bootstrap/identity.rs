use super::WindowsBootstrapIdentityError;

/// Lossless identity value for an observed Windows file or directory.
///
/// The format stores canonical GUID text, the unsigned volume serial and the
/// native file ID byte order. The value does not establish live continuity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsBootstrapFileIdentity {
	guid: [u8; 36],
	serial: u64,
	file_id: [u8; 16],
}

impl WindowsBootstrapFileIdentity {
	/// Wraps a lowercase hyphenated ASCII GUID and the full native serial and ID.
	///
	/// # Errors
	/// Refuses a noncanonical GUID or an all-zero file ID.
	pub fn new(
		guid: [u8; 36],
		serial: u64,
		file_id: [u8; 16],
	) -> Result<Self, WindowsBootstrapIdentityError> {
		for (index, &byte) in guid.iter().enumerate() {
			let valid = if matches!(index, 8 | 13 | 18 | 23) {
				byte == b'-'
			} else {
				matches!(byte, b'0'..=b'9' | b'a'..=b'f')
			};
			if !valid {
				return Err(WindowsBootstrapIdentityError::InvalidVolumeGuid);
			}
		}
		if file_id == [0; 16] {
			return Err(WindowsBootstrapIdentityError::ZeroFileId);
		}
		Ok(Self {
			guid,
			serial,
			file_id,
		})
	}

	/// Returns the canonical volume GUID text.
	#[must_use]
	pub const fn volume_guid(&self) -> &[u8; 36] {
		&self.guid
	}

	/// Returns all 64 bits of the observed volume serial.
	#[must_use]
	pub const fn volume_serial(self) -> u64 {
		self.serial
	}

	/// Returns all 16 observed file ID bytes without reordering.
	#[must_use]
	pub const fn file_id(&self) -> &[u8; 16] {
		&self.file_id
	}
}

/// The five role identities in a Windows fixed-NTFS bootstrap.
///
/// These observations must identify distinct objects on the same volume. Their
/// names, containment and live custody remain responsibilities of the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsBootstrapRoles {
	root: WindowsBootstrapFileIdentity,
	job_directory: WindowsBootstrapFileIdentity,
	owner_file: WindowsBootstrapFileIdentity,
	journal_directory: WindowsBootstrapFileIdentity,
	first_segment: WindowsBootstrapFileIdentity,
}

impl WindowsBootstrapRoles {
	/// Checks the common volume and pairwise distinct file IDs.
	///
	/// # Errors
	/// Refuses mixed volumes or repeated file IDs.
	pub fn new(
		root: WindowsBootstrapFileIdentity,
		job_directory: WindowsBootstrapFileIdentity,
		owner_file: WindowsBootstrapFileIdentity,
		journal_directory: WindowsBootstrapFileIdentity,
		first_segment: WindowsBootstrapFileIdentity,
	) -> Result<Self, WindowsBootstrapIdentityError> {
		let roles = Self {
			root,
			job_directory,
			owner_file,
			journal_directory,
			first_segment,
		};
		let identities = roles.identities();
		for (index, identity) in identities.iter().enumerate() {
			if identity.guid != root.guid || identity.serial != root.serial {
				return Err(WindowsBootstrapIdentityError::DifferentVolume);
			}
			if identities[..index]
				.iter()
				.any(|previous| previous.file_id == identity.file_id)
			{
				return Err(WindowsBootstrapIdentityError::DuplicateFileId);
			}
		}
		Ok(roles)
	}

	/// Returns the independently selected container root's role identity.
	#[must_use]
	pub const fn root(self) -> WindowsBootstrapFileIdentity {
		self.root
	}

	/// Returns the job directory's role identity.
	#[must_use]
	pub const fn job_directory(self) -> WindowsBootstrapFileIdentity {
		self.job_directory
	}

	/// Returns the owner file's role identity.
	#[must_use]
	pub const fn owner_file(self) -> WindowsBootstrapFileIdentity {
		self.owner_file
	}

	/// Returns the journal directory's role identity.
	#[must_use]
	pub const fn journal_directory(self) -> WindowsBootstrapFileIdentity {
		self.journal_directory
	}

	/// Returns the first segment's role identity.
	#[must_use]
	pub const fn first_segment(self) -> WindowsBootstrapFileIdentity {
		self.first_segment
	}

	pub(super) const fn identities(self) -> [WindowsBootstrapFileIdentity; 5] {
		[
			self.root,
			self.job_directory,
			self.owner_file,
			self.journal_directory,
			self.first_segment,
		]
	}
}
