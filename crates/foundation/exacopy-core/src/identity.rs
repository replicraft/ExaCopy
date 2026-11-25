use core::fmt;

use uuid::{Uuid, Variant, Version};

/// The externally visible UUIDv7 identity of a job.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct JobId(Uuid);

impl JobId {
	/// Validates the supplied RFC UUID bytes as a version-seven job identifier.
	///
	/// # Errors
	///
	/// Returns [`InvalidJobId`] if the identifier does not use the RFC variant and version seven.
	pub fn try_from_bytes(bytes: [u8; 16]) -> Result<Self, InvalidJobId> {
		let id = Uuid::from_bytes(bytes);
		if id.get_variant() != Variant::RFC4122 || id.get_version() != Some(Version::SortRand) {
			return Err(InvalidJobId);
		}
		Ok(Self(id))
	}
}

/// A job identifier with an unsupported UUID variant or version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidJobId;

impl fmt::Display for InvalidJobId {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("job identifier must be an RFC UUIDv7")
	}
}

impl core::error::Error for InvalidJobId {}

/// An entry identifier scoped to its job.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EntryId(u64);

impl EntryId {
	/// Binds an entry number to the entry identifier type.
	#[must_use]
	pub const fn new(number: u64) -> Self {
		Self(number)
	}
}

/// The coordinator's generation for a run of a job.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RunEpoch(u64);

impl RunEpoch {
	/// Binds a coordinator-assigned generation number to the epoch type.
	#[must_use]
	pub const fn new(generation: u64) -> Self {
		Self(generation)
	}
}

/// An opaque application-generated token for one private stage.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct StageId([u8; 16]);

impl StageId {
	/// Wraps a token supplied by the stage owner. This does not generate a token.
	#[must_use]
	pub const fn from_bytes(token: [u8; 16]) -> Self {
		Self(token)
	}
}

impl fmt::Debug for StageId {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("StageId(<redacted>)")
	}
}
