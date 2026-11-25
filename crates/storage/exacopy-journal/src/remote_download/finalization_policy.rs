//! Canonical policy selected for an agentless SFTP unnamed-stream download.

/// An omission in the fixed agentless SFTP data-only contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SftpOmission {
	/// Additional content streams and resource-fork data were not enumerated.
	AdditionalContentStreamsUnenumerated = 1,
	/// The source permission and special bits were not preserved.
	SourceUnixMode = 2,
	/// The source owner and group were not preserved.
	SourceOwnership = 3,
	/// Source timestamps and native precision were not preserved.
	SourceTimestamps = 4,
	/// Source ACLs and security descriptors were not preserved.
	SourceAcl = 5,
	/// Source extended attributes and security labels were not preserved.
	SourceXattrsAndSecurityLabels = 6,
	/// Source filesystem flags and attributes were not preserved.
	SourceFileFlags = 7,
	/// Source hard-link relationships were not preserved.
	SourceLinkTopology = 8,
	/// Source sparse allocation was not preserved.
	SourceSparseLayout = 9,
	/// Source compression and encryption representation were not preserved.
	SourceStorageRepresentation = 10,
}

impl SftpOmission {
	/// Returns the stable machine-readable name.
	#[must_use]
	pub const fn name(self) -> &'static str {
		match self {
			Self::AdditionalContentStreamsUnenumerated => "additional_content_streams_unenumerated",
			Self::SourceUnixMode => "source_unix_mode",
			Self::SourceOwnership => "source_ownership",
			Self::SourceTimestamps => "source_timestamps",
			Self::SourceAcl => "source_acl",
			Self::SourceXattrsAndSecurityLabels => "source_xattrs_and_security_labels",
			Self::SourceFileFlags => "source_file_flags",
			Self::SourceLinkTopology => "source_link_topology",
			Self::SourceSparseLayout => "source_sparse_layout",
			Self::SourceStorageRepresentation => "source_storage_representation",
		}
	}

	/// Returns the canonical omission code used in receipts.
	#[must_use]
	pub const fn code(self) -> u8 {
		self as u8
	}
}

const OMISSIONS: [SftpOmission; 10] = [
	SftpOmission::AdditionalContentStreamsUnenumerated,
	SftpOmission::SourceUnixMode,
	SftpOmission::SourceOwnership,
	SftpOmission::SourceTimestamps,
	SftpOmission::SourceAcl,
	SftpOmission::SourceXattrsAndSecurityLabels,
	SftpOmission::SourceFileFlags,
	SftpOmission::SourceLinkTopology,
	SftpOmission::SourceSparseLayout,
	SftpOmission::SourceStorageRepresentation,
];

const DOMAIN: &[u8] = b"ExaCopy/remote-download-metadata-policy/v1\0";
const VERSION: u8 = 1;
const UNNAMED_STREAM_ONLY: u8 = 0;
const EFFECTIVE_LOCAL_OWNER_AND_ADMITTED_GROUP: u8 = 1;
const EMPTY_VISIBLE_ATTRIBUTES_AND_ACL: u8 = 1;
const PREFIX_BYTES: usize = 6;
const DESCRIPTOR_BYTES: usize = PREFIX_BYTES + OMISSIONS.len();

/// Fixed private-download metadata profile. This marker supplies no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SftpDataOnlyV1;

impl SftpDataOnlyV1 {
	/// Explicit command and receipt selector for this policy.
	pub const NAME: &'static str = "sftp-data-only-v1";
	/// Exact ordinary permission bits required on the held local stage.
	pub const LOCAL_MODE: u16 = 0o600;

	/// Returns the fixed omission list in canonical numeric code order.
	#[must_use]
	pub const fn omissions() -> &'static [SftpOmission] {
		&OMISSIONS
	}

	/// Returns the versioned descriptor bound into the signed scope.
	///
	/// The layout is version, stream selection, big-endian mode, local ownership
	/// rule, local attribute rule, then ascending omission codes.
	#[must_use]
	pub const fn descriptor() -> [u8; DESCRIPTOR_BYTES] {
		let [hi, lo] = Self::LOCAL_MODE.to_be_bytes();
		let mut result = [0; DESCRIPTOR_BYTES];
		result[0] = VERSION;
		result[1] = UNNAMED_STREAM_ONLY;
		result[2] = hi;
		result[3] = lo;
		result[4] = EFFECTIVE_LOCAL_OWNER_AND_ADMITTED_GROUP;
		result[5] = EMPTY_VISIBLE_ATTRIBUTES_AND_ACL;
		let mut index = 0;
		while index < OMISSIONS.len() {
			result[PREFIX_BYTES + index] = OMISSIONS[index].code();
			index += 1;
		}
		result
	}

	/// Returns the exact profile digest expected in the signed remote scope.
	#[must_use]
	pub fn digest() -> [u8; 32] {
		*blake3::Hasher::new()
			.update(DOMAIN)
			.update(&Self::descriptor())
			.finalize()
			.as_bytes()
	}
}
