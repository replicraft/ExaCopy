use crate::OwnerError;

/// BLAKE3 digest in the public Plan v1 domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovedPublicPlanDigest([u8; 32]);

impl ApprovedPublicPlanDigest {
	/// Wraps the digest of the canonical public Plan after approval.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns the recorded digest bytes.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// Ordinary BLAKE3 digest of the approved logical data stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovedStreamDigest([u8; 32]);

impl ApprovedStreamDigest {
	/// Wraps the approved stream digest reported in the public entry.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns the recorded digest bytes.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// Digest identifying the approved versioned metadata policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyMetadataPolicyDigest([u8; 32]);

impl ApplyMetadataPolicyDigest {
	/// Wraps the admitted metadata policy digest from the public entry.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns the recorded digest bytes.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// The nonnil public Plan entry UUID in standard network byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicPlanEntryId([u8; 16]);

impl PublicPlanEntryId {
	/// Wraps a nonnil UUID from the validated public Plan entry.
	///
	/// # Errors
	/// Returns an invalid entry error for the nil UUID.
	pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, OwnerError> {
		if bytes == [0; 16] {
			return Err(OwnerError::InvalidApplyEntry);
		}
		Ok(Self(bytes))
	}

	/// Returns the identifier in network byte order.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 16] {
		&self.0
	}
}
