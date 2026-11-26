//! Bounded workflow page for the paired generation-one Linux baseline observation.

use core::fmt;
use core::num::NonZeroU64;

use exacopy_core::UnixComponent;

use crate::portable::MAX_LOGICAL_LENGTH;

mod wire;

const PAGE_DOMAIN: &[u8] = b"ExaCopy/workflow-page/v1\0";
const METADATA_DOMAIN: &[u8] = b"ExaCopy/sync-baseline/linux-owner-mode/v1\0";

/// Workflow page kind code for the paired baseline leaf.
pub const PAIRED_BASELINE_KIND: u16 = 0x0100;
/// Maximum accepted encoded length of the paired baseline leaf.
pub const MAX_PAIRED_BASELINE_BYTES: usize = 2048;

/// Exact commitment selected by the independently authenticated parent reader.
///
/// The value carries an expected reference. The caller establishes authenticity
/// and completeness of the enclosing workflow record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafCommitment {
	/// Expected digest in the workflow-page domain.
	pub digest: [u8; 32],
	/// Expected workflow page kind.
	pub kind: u16,
	/// Exact number of encoded bytes.
	pub byte_len: u32,
	/// Exact descendant row count.
	pub item_count: u64,
}

/// Expected native pair and policy projection selected outside the leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedSelection<'name> {
	/// Expected ordered root identities.
	pub roots: [[u8; 32]; 2],
	/// Expected exact validated raw basename.
	pub name: UnixComponent<'name>,
	/// Expected owner, selected roots and native session scope.
	pub scope_digest: [u8; 32],
	/// Expected stream, comparison, required metadata and omission policy.
	pub policy_digest: [u8; 32],
	/// Expected scan instance.
	pub scan: NonZeroU64,
}

/// Required metadata projection of Linux owner-and-mode v1.
///
/// The projection compares ordinary permission bits, numeric UID and GID under
/// the selected Linux owner namespace. The caller retains the separate native
/// admission, other-metadata omissions and timestamp stability evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxOwnerMode {
	/// Ordinary permission bits. Special mode bits are refused.
	pub mode: u16,
	/// Observed numeric owner.
	pub uid: u32,
	/// Observed numeric owning group.
	pub gid: u32,
}

impl LinuxOwnerMode {
	/// Computes the digest of the required Linux owner-and-mode metadata.
	///
	/// # Errors
	/// Refuses a mode outside the ordinary permission-bit range.
	pub fn digest(self) -> Result<[u8; 32], LeafError> {
		if self.mode > 0o777 {
			return Err(LeafError::InvalidEvidence);
		}
		let mut bytes = [0; 14];
		let encoded = wire::encode_metadata(self, &mut bytes)?;
		let mut hasher = blake3::Hasher::new();
		hasher.update(METADATA_DOMAIN).update(encoded);
		Ok(*hasher.finalize().as_bytes())
	}
}

/// Opaque admitted root and native file identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
	/// Root identity under the selected native identity scheme.
	pub root: [u8; 32],
	/// File identity under the same native identity scheme.
	pub file: [u8; 32],
}

/// Completed read or final recheck evidence within the selected scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
	/// Rooted native identity.
	pub identity: Identity,
	/// Monotonic completion position in the scan.
	pub position: NonZeroU64,
	/// Equality-relevant native timestamp, extent and metadata stability projection.
	pub stability: [u8; 32],
}

/// Independently read and finally rechecked evidence for one side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SideEvidence {
	/// Live observation associated with the completed read.
	pub measured: Observation,
	/// Live observation at the final pair recheck.
	pub rechecked: Observation,
	/// Measured byte length of the unnamed data stream.
	pub length: u64,
	/// Ordinary BLAKE3 digest of the unnamed data stream.
	pub stream_digest: [u8; 32],
	/// Actual required Linux metadata projection.
	pub metadata: LinuxOwnerMode,
	/// Recorded digest of that projection.
	pub metadata_digest: [u8; 32],
}

/// Read-only paired baseline observation verified against its expected leaf commitment.
///
/// Filesystem identity, scope freshness, root signature and history selection
/// require their own caller validation. This leaf carries no live capability.
#[derive(Debug, PartialEq, Eq)]
pub struct PairedBaselineLeaf<'name> {
	selection: ExpectedSelection<'name>,
	sides: [SideEvidence; 2],
}

impl<'name> PairedBaselineLeaf<'name> {
	/// Admits one canonical page against the selected commitment and scope.
	///
	/// # Errors
	/// Refuses wrong references, noncanonical or unsupported encoding,
	/// changed scope, and incomplete, stale, reused or mismatched evidence.
	pub fn verify(
		input: &'name [u8],
		commitment: LeafCommitment,
		expected: ExpectedSelection<'_>,
	) -> Result<Self, LeafError> {
		if input.is_empty() || input.len() > MAX_PAIRED_BASELINE_BYTES {
			return Err(LeafError::Size);
		}
		if commitment.kind != PAIRED_BASELINE_KIND {
			return Err(LeafError::WrongKind);
		}
		if u32::try_from(input.len()).ok() != Some(commitment.byte_len)
			|| commitment.item_count != 1
			|| page_digest(input)? != commitment.digest
		{
			return Err(LeafError::Commitment);
		}
		let verified = wire::decode(input)?;
		if verified.selection != expected {
			return Err(LeafError::SelectionMismatch);
		}
		verify_sides(verified.sides)?;
		wire::verify_canonical(input, &verified)?;
		Ok(verified)
	}

	/// Returns the exact checked pair, name, scope, policy and scan.
	#[must_use]
	pub const fn selection(&self) -> ExpectedSelection<'name> {
		self.selection
	}

	/// Returns the checked observations in exact left, right order.
	#[must_use]
	pub const fn sides(&self) -> &[SideEvidence; 2] {
		&self.sides
	}
}

fn verify_sides([left, right]: [SideEvidence; 2]) -> Result<(), LeafError> {
	if left.measured.identity.root == right.measured.identity.root
		|| left.measured.identity.file == right.measured.identity.file
		|| left.measured.position == right.measured.position
		|| left.length > MAX_LOGICAL_LENGTH
		|| left.length != right.length
		|| left.stream_digest != right.stream_digest
		|| left.metadata != right.metadata
	{
		return Err(LeafError::InvalidEvidence);
	}
	let last_read = left.measured.position.max(right.measured.position);
	for side in [left, right] {
		if side.rechecked.identity != side.measured.identity
			|| side.rechecked.stability != side.measured.stability
			|| side.rechecked.position <= last_read
			|| side.metadata.digest()? != side.metadata_digest
		{
			return Err(LeafError::InvalidEvidence);
		}
	}
	Ok(())
}

fn page_digest(input: &[u8]) -> Result<[u8; 32], LeafError> {
	let length = u64::try_from(input.len()).map_err(|_| LeafError::Size)?;
	let mut hasher = blake3::Hasher::new();
	hasher
		.update(PAGE_DOMAIN)
		.update(&PAIRED_BASELINE_KIND.to_le_bytes())
		.update(&length.to_le_bytes())
		.update(input);
	Ok(*hasher.finalize().as_bytes())
}

/// Refusal while checking a workflow paired baseline leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeafError {
	/// Input did not fit the fixed byte budget.
	Size,
	/// The parent reference or encoded body has another kind.
	WrongKind,
	/// The exact byte length, item count or digest did not match the reference.
	Commitment,
	/// Invalid field, extent or unsupported page shape.
	Encoding,
	/// Field encoding was valid to parse but was outside the canonical encoding.
	NonCanonical,
	/// Pair, raw subject, scope, policy or scan differs from the selection.
	SelectionMismatch,
	/// The evidence is unsupported, mismatched, reused or stale.
	InvalidEvidence,
}

impl fmt::Display for LeafError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::Size => "paired baseline page exceeds its byte bounds",
			Self::WrongKind => "paired baseline page kind mismatch",
			Self::Commitment => "paired baseline page commitment mismatch",
			Self::Encoding => "invalid paired baseline encoding",
			Self::NonCanonical => "noncanonical paired baseline page",
			Self::SelectionMismatch => "paired baseline selection mismatch",
			Self::InvalidEvidence => "invalid matched paired baseline evidence",
		};
		formatter.write_str(message)
	}
}

impl core::error::Error for LeafError {}
