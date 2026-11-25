const SFTP_VERSION: u32 = 3;

/// Known extensions reported by an SFTP server.
///
/// The adapter parses the exact extension names and supported versions. A
/// reported extension is a protocol advertisement only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SftpAdvertisement {
	/// The server advertises `fsync@openssh.com`.
	pub file_sync: bool,
	/// The server advertises `posix-rename@openssh.com`.
	pub posix_rename: bool,
	/// The server advertises `hardlink@openssh.com`.
	pub hardlink: bool,
}

/// The server negotiated a protocol outside this profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SftpVersionError {
	/// Version number supplied by the server.
	pub version: u32,
}

impl std::fmt::Display for SftpVersionError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(formatter, "unsupported SFTP version {}", self.version)
	}
}

impl std::error::Error for SftpVersionError {}

/// Why the generic SFTP profile withholds a requested write capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SftpRefusal {
	/// No qualified atomic publication that preserves an incumbent.
	ExclusivePublicationUnqualified,
	/// No qualified barrier for destination namespace changes.
	NamespaceDurabilityUnqualified,
	/// No qualified capture and retention of the exact displaced object.
	ProtectedReplacementUnqualified,
}

impl std::fmt::Display for SftpRefusal {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str(match self {
			Self::ExclusivePublicationUnqualified => "SFTP exclusive publication is unqualified",
			Self::NamespaceDurabilityUnqualified => "SFTP namespace durability is unqualified",
			Self::ProtectedReplacementUnqualified => "SFTP protected replacement is unqualified",
		})
	}
}

impl std::error::Error for SftpRefusal {}

/// Protocol support assessment for the generic SFTP v3 source profile.
///
/// Admission only establishes protocol compatibility for a read-only source
/// adapter. Roots, metadata and observed source stability need separate checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SftpCapabilities {
	advertised: SftpAdvertisement,
}

impl SftpCapabilities {
	/// Assesses the negotiated protocol for the initial source profile.
	///
	/// # Errors
	/// Rejects versions other than SFTP v3.
	pub fn for_source(
		version: u32,
		advertised: SftpAdvertisement,
	) -> Result<Self, SftpVersionError> {
		if version != SFTP_VERSION {
			return Err(SftpVersionError { version });
		}
		Ok(Self { advertised })
	}

	/// Returns the server's advertisement for diagnostics or future qualification.
	#[must_use]
	pub const fn advertisement(self) -> SftpAdvertisement {
		self.advertised
	}

	/// Refuses publication using generic SFTP rename or a hardlink advertisement.
	///
	/// A future server-specific profile would need independent qualification.
	///
	/// # Errors
	/// This profile has no exclusive publication capability.
	pub const fn require_exclusive_publication(self) -> Result<(), SftpRefusal> {
		Err(SftpRefusal::ExclusivePublicationUnqualified)
	}

	/// Refuses to infer namespace durability from a file-sync advertisement.
	///
	/// # Errors
	/// This profile has no namespace durability capability.
	pub const fn require_namespace_durability(self) -> Result<(), SftpRefusal> {
		Err(SftpRefusal::NamespaceDurabilityUnqualified)
	}

	/// Refuses to substitute generic SFTP primitives for protected replacement.
	///
	/// # Errors
	/// This profile has no protected replacement capability.
	pub const fn require_protected_replacement(self) -> Result<(), SftpRefusal> {
		Err(SftpRefusal::ProtectedReplacementUnqualified)
	}
}
