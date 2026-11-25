use exacopy_model::JobId;

use super::IntentError;

/// The RFC UUIDv7 job identity stored in a journal record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct JournalJobId([u8; 16]);

impl JournalJobId {
	/// Validates the RFC variant and version of the network-order UUID bytes.
	///
	/// # Errors
	/// Returns an invalid job error if the bytes do not describe an RFC UUIDv7.
	pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, IntentError> {
		JobId::try_from_bytes(bytes).map_err(IntentError::InvalidJob)?;
		Ok(Self(bytes))
	}

	/// Returns the UUID in network byte order.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 16] {
		&self.0
	}
}

/// The journal's entry UUID. The wire contract leaves its version unspecified.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct JournalEntryId([u8; 16]);

impl JournalEntryId {
	/// Wraps the UUID in standard network byte order.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 16]) -> Self {
		Self(bytes)
	}

	/// Returns the UUID in network byte order.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 16] {
		&self.0
	}
}

/// The coordinator-assigned run generation stored in a journal record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct JournalEpoch(u64);

impl JournalEpoch {
	/// Wraps the run generation bound to the job.
	#[must_use]
	pub const fn new(generation: u64) -> Self {
		Self(generation)
	}

	/// Returns the run generation.
	#[must_use]
	pub const fn get(self) -> u64 {
		self.0
	}
}

/// The BLAKE3 digest of the canonical plan under the plan domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PlanDigest([u8; 32]);

impl PlanDigest {
	/// Wraps the digest bytes produced by the plan owner.
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

/// The BLAKE3 digest recorded for the sealed file's independent read-back.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VerificationDigest([u8; 32]);

impl VerificationDigest {
	/// Wraps the digest bytes produced by the verifier.
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

/// A Linux device and inode observation from the local adapter.
///
/// The local v1 encoding uses platform code 1 with eight little-endian bytes for
/// each of the device and inode fields, and a null generation. An observation
/// with no generation cannot prove an inode was never reused after its handles closed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LinuxFileIdentity {
	device: u64,
	inode: u64,
}

impl LinuxFileIdentity {
	/// Captures the Linux adapter's observed device and inode numbers.
	#[must_use]
	pub const fn new(device: u64, inode: u64) -> Self {
		Self { device, inode }
	}

	/// Returns the observed device number.
	#[must_use]
	pub const fn device(self) -> u64 {
		self.device
	}

	/// Returns the observed inode number.
	#[must_use]
	pub const fn inode(self) -> u64 {
		self.inode
	}
}
