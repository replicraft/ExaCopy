use std::fmt;

use crate::{JournalJobId, LinuxFileIdentity, PlanDigest};

use super::OwnerError;

const NANOSECONDS_PER_SECOND: u32 = 1_000_000_000;

/// An independent randomly generated owner token. Debug output omits its bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OwnerToken([u8; 16]);

impl OwnerToken {
	/// Wraps the nonzero bytes of an independently generated 128-bit owner token.
	/// The caller supplies cryptographically secure randomness for new records.
	///
	/// # Errors
	/// Returns [`OwnerError::InvalidToken`] for all-zero bytes.
	pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, OwnerError> {
		if bytes == [0; 16] {
			return Err(OwnerError::InvalidToken);
		}
		Ok(Self(bytes))
	}

	/// Returns the token bytes for an explicit protected evidence comparison.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 16] {
		&self.0
	}
}

impl fmt::Debug for OwnerToken {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("OwnerToken(<redacted>)")
	}
}

/// The local profile's nonnil UUID in standard network byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerProfileId([u8; 16]);

impl OwnerProfileId {
	/// Wraps the profile identifier from the calling profile's configuration.
	///
	/// # Errors
	/// Returns [`OwnerError::InvalidProfile`] for the nil UUID.
	pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, OwnerError> {
		if bytes == [0; 16] {
			return Err(OwnerError::InvalidProfile);
		}
		Ok(Self(bytes))
	}

	/// Returns the UUID in network byte order.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 16] {
		&self.0
	}
}

/// A UTC creation timestamp stored as signed Unix seconds and subsecond nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerTimestamp {
	seconds: i64,
	nanoseconds: u32,
}

impl OwnerTimestamp {
	/// Constructs a UTC creation timestamp from its two on-disk components.
	///
	/// # Errors
	/// Returns [`OwnerError::InvalidTimestamp`] if nanoseconds are at least one second.
	pub fn new(seconds: i64, nanoseconds: u32) -> Result<Self, OwnerError> {
		if nanoseconds >= NANOSECONDS_PER_SECOND {
			return Err(OwnerError::InvalidTimestamp);
		}
		Ok(Self {
			seconds,
			nanoseconds,
		})
	}

	/// Returns the signed Unix seconds.
	#[must_use]
	pub const fn seconds(self) -> i64 {
		self.seconds
	}

	/// Returns the nanoseconds after the whole seconds.
	#[must_use]
	pub const fn nanoseconds(self) -> u32 {
		self.nanoseconds
	}
}

/// A local v1 directory name relative to a job's state directory.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum OwnerStateDirectory {
	/// Immutable checkpoint objects.
	Checkpoints,
	/// Authoritative journal segments.
	Journal,
	/// Signed transfer receipts.
	Receipts,
	/// Exclusively created staged files.
	Stage,
	/// Retained version objects.
	Versions,
}

impl OwnerStateDirectory {
	const CHECKPOINTS_NAME: &str = "checkpoints";
	const JOURNAL_NAME: &str = "journal";
	const RECEIPTS_NAME: &str = "receipts";
	const STAGE_NAME: &str = "stage";
	const VERSIONS_NAME: &str = "versions";
	pub(super) const COUNT: usize = 5;

	/// Returns the exact v1 stored component.
	#[must_use]
	pub const fn name(self) -> &'static str {
		match self {
			Self::Checkpoints => Self::CHECKPOINTS_NAME,
			Self::Journal => Self::JOURNAL_NAME,
			Self::Receipts => Self::RECEIPTS_NAME,
			Self::Stage => Self::STAGE_NAME,
			Self::Versions => Self::VERSIONS_NAME,
		}
	}

	pub(super) fn from_name(name: &str) -> Result<Self, OwnerError> {
		match name {
			Self::CHECKPOINTS_NAME => Ok(Self::Checkpoints),
			Self::JOURNAL_NAME => Ok(Self::Journal),
			Self::RECEIPTS_NAME => Ok(Self::Receipts),
			Self::STAGE_NAME => Ok(Self::Stage),
			Self::VERSIONS_NAME => Ok(Self::Versions),
			_ => Err(OwnerError::InvalidDirectories),
		}
	}
}

/// The claims signed by the local v1 preserve-only owner codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerManifest {
	/// The independent per-job owner token.
	pub token: OwnerToken,
	/// The durable UUIDv7 job being described.
	pub job: JournalJobId,
	/// The profile that submitted the job.
	pub profile: OwnerProfileId,
	/// The wall clock at creation.
	pub created: OwnerTimestamp,
	/// The Linux destination volume's observed device number.
	pub destination_device: u64,
	/// The native identity of the owner-private state root.
	pub state_root: LinuxFileIdentity,
	/// The canonical plan digest recorded by the originator.
	pub plan_digest: PlanDigest,
	/// The allowed relative state directories in increasing name order.
	pub directories: Vec<OwnerStateDirectory>,
}

impl OwnerManifest {
	pub(super) fn validate(&self) -> Result<(), OwnerError> {
		if self.token.as_bytes() == self.job.as_bytes()
			|| self.token.as_bytes() == self.profile.as_bytes()
		{
			return Err(OwnerError::InvalidToken);
		}
		if self.state_root.device() != self.destination_device {
			return Err(OwnerError::VolumeMismatch);
		}
		if !(1..=OwnerStateDirectory::COUNT).contains(&self.directories.len())
			|| !self.directories.is_sorted_by(|a, b| a < b)
		{
			return Err(OwnerError::InvalidDirectories);
		}
		Ok(())
	}
}
