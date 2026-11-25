use std::fmt;

/// The owner evidence could not be encoded or interpreted under the selected local profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OwnerError {
	/// The envelope or a field exceeds its byte limit or has the wrong fixed size.
	Length,
	/// A field has an invalid encoding, type, count, or map key.
	InvalidCbor,
	/// Complete CBOR did not use the unique deterministic encoding.
	NonCanonical,
	/// Additional bytes follow the expected object.
	TrailingBytes,
	/// This reader cannot interpret the version or the required features.
	UnsupportedVersion,
	/// The envelope has a different signature domain code.
	WrongDomain,
	/// The declared profile is different from the selected profile.
	UntrustedProfile,
	/// The declaration does not match the expected externally trusted profile key.
	UntrustedKey,
	/// Ed25519 strict verification failed, or the key has low order.
	InvalidSignature,
	/// The declared job ID is not an RFC UUIDv7.
	InvalidJob,
	/// The profile ID is nil.
	InvalidProfile,
	/// The owner token is zero or duplicates a durable identity.
	InvalidToken,
	/// The subsecond timestamp exceeds 999,999,999 nanoseconds.
	InvalidTimestamp,
	/// An identity uses an unsupported platform or generation.
	UnsupportedIdentity,
	/// The state-root device differs from the destination volume observation.
	VolumeMismatch,
	/// The one-file reader only supports preserve policy.
	UnsupportedPolicy,
	/// The state-directory allowlist has an unsupported name, count, or order.
	InvalidDirectories,
	/// The Darwin state-root volume differs from the destination observation.
	DarwinVolumeMismatch,
	/// The managed APFS state-root UID is outside the admitted non-root range.
	InvalidOwnerUid,
}

impl fmt::Display for OwnerError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::Length => "owner record exceeds a limit or has an incorrect field length",
			Self::InvalidCbor => "owner record has an invalid CBOR shape",
			Self::NonCanonical => "owner record is not deterministic CBOR",
			Self::TrailingBytes => "owner object has trailing bytes",
			Self::UnsupportedVersion => "owner record version or required features are unsupported",
			Self::WrongDomain => "owner record has the wrong signature domain",
			Self::UntrustedProfile => "owner record does not match the selected profile",
			Self::UntrustedKey => "owner record does not match the trusted profile key",
			Self::InvalidSignature => "owner record signature is invalid",
			Self::InvalidJob => "owner job ID is not an RFC UUIDv7",
			Self::InvalidProfile => "owner profile ID is nil",
			Self::InvalidToken => "owner token is invalid",
			Self::InvalidTimestamp => "owner timestamp has out-of-range nanoseconds",
			Self::UnsupportedIdentity => "owner record identity is unsupported",
			Self::VolumeMismatch => "owner state-root device differs from the destination device",
			Self::DarwinVolumeMismatch => {
				"owner state-root volume differs from the destination volume"
			}
			Self::InvalidOwnerUid => "owner state-root UID is outside the admitted Darwin range",
			Self::UnsupportedPolicy => "owner policy is unsupported",
			Self::InvalidDirectories => "owner state-directory allowlist is invalid",
		};
		formatter.write_str(message)
	}
}

impl std::error::Error for OwnerError {}
