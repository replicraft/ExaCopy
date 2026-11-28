//! Canonical local occupancy data for one independently selected managed activation.
//!
//! This unsigned record expresses exact expected bindings. Matching its bytes
//! cannot establish native identity, acknowledged durability, an active grant,
//! or a right to append to a ledger. Those checks belong to the live coordinator.

use core::fmt;

use exacopy_model::JobId;

use crate::frame::{ChainHead, FRAME_OVERHEAD_BYTES};
use crate::{
	ApprovedPublicPlanDigest, JournalEntryId, JournalEpoch, JournalJobId, MAX_FIRST_SEGMENT_BYTES,
	OwnerProfileId, PublicPlanEntryId,
};

const MAGIC: &[u8; 8] = b"EXMACT01";
const VERSION_MAJOR: u8 = 1;
const VERSION_MINOR: u8 = 0;
const VERSION: [u8; 2] = [VERSION_MAJOR, VERSION_MINOR];
const REQUIRED_FEATURES: u16 = 0;
const DIGEST_DOMAIN: &str = "ExaCopy Linux managed activation claim record v1";
const PAYLOAD_BYTES: usize = 492;
const CHECKSUM_BYTES: usize = 4;

/// Exact extent of the fixed private activation claim including its checksum.
pub const MANAGED_ACTIVATION_CLAIM_BYTES: usize = PAYLOAD_BYTES + CHECKSUM_BYTES;

const MAGIC_AT: usize = 0;
const VERSION_AT: usize = 8;
const FEATURES_AT: usize = 10;
const ACTIVATION_AT: usize = 12;
const HOST_SELECTION_AT: usize = 44;
const PROFILE_AT: usize = 76;
const PAIR_AT: usize = 92;
const GENERATION_AT: usize = 108;
const PREDECESSOR_AT: usize = 116;
const REVIEW_PARENT_AT: usize = 148;
const EXECUTION_PARENT_AT: usize = 180;
const ACTION_AT: usize = 212;
const GRANT_AT: usize = 228;
const PUBLIC_PLAN_AT: usize = 260;
const PUBLIC_ENTRY_AT: usize = 292;
const PRIVATE_PLAN_AT: usize = 308;
const CHILD_JOB_AT: usize = 340;
const CHILD_ENTRY_AT: usize = 356;
const CHILD_EPOCH_AT: usize = 372;
const SLOT_AT: usize = 380;
const SEGMENT_AT: usize = 412;
const SEQUENCE_AT: usize = 444;
const HEAD_AT: usize = 452;
const EXTENT_AT: usize = 484;

/// Independently selected public and private child attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedActivationChild {
	/// Digest in the approved public Plan domain.
	pub public_plan: ApprovedPublicPlanDigest,
	/// Exact selected public Plan entry.
	pub public_entry: PublicPlanEntryId,
	/// Digest in the ordinary private copy Plan domain.
	pub private_plan: [u8; 32],
	/// Selected ordinary child job UUIDv7.
	pub job: JournalJobId,
	/// Exact full private journal entry, also used as the logical stage token.
	pub entry: JournalEntryId,
	/// Selected ordinary child attempt epoch.
	pub epoch: JournalEpoch,
}

/// Independently selected, originally prepared segment boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedActivationPrepared {
	/// Exact preceding frame sequence and digest.
	pub head: ChainHead,
	/// Selected exclusive extent of the prepared segment in bytes.
	pub extent: u64,
}

/// Expected contents of an owner-private managed activation claim.
///
/// Supply these fields from independent trusted selections. The type carries no
/// live approval. In particular, slot and segment commitments must describe the
/// original held native objects admitted by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedActivationClaim {
	/// Exact independently issued activation commitment.
	pub activation: [u8; 32],
	/// Exact independently authenticated host selection commitment.
	pub host_selection: [u8; 32],
	/// Owner profile selected independently of the claim.
	pub profile: OwnerProfileId,
	/// RFC UUIDv7 of the managed pair.
	pub pair: [u8; 16],
	/// Independently selected current predecessor generation.
	pub predecessor_generation: u64,
	/// Exact current predecessor Workflow Root digest.
	pub predecessor_root: [u8; 32],
	/// Digest of the signed review-only parent.
	pub review_parent: [u8; 32],
	/// Digest of the separately selected granted executable parent.
	pub execution_parent: [u8; 32],
	/// Exact sole action identifier in the granted parent.
	pub action: [u8; 16],
	/// Digest of the explicitly approved, scoped grant reference.
	pub grant: [u8; 32],
	/// Exact ordinary child and private attempt.
	pub child: ManagedActivationChild,
	/// Role-scoped projection of the original held action slot.
	pub slot: [u8; 32],
	/// Role-scoped projection of the original held prepared segment.
	pub segment: [u8; 32],
	/// Binding of the original prepared journal frame and extent.
	pub prepared: ManagedActivationPrepared,
}

impl ManagedActivationClaim {
	fn validate(&self) -> Result<(), ManagedActivationClaimError> {
		if JobId::try_from_bytes(self.pair).is_err()
			|| self.predecessor_generation == 0
			|| self.action == [0; 16]
			|| self.child.entry.as_bytes() == &[0; 16]
			|| self.child.epoch.get() == 0
			|| self.review_parent == self.execution_parent
			|| self.slot == self.segment
			|| [
				self.activation,
				self.host_selection,
				self.predecessor_root,
				self.review_parent,
				self.execution_parent,
				self.grant,
				*self.child.public_plan.as_bytes(),
				self.child.private_plan,
				self.slot,
				self.segment,
			]
			.contains(&[0; 32])
			|| !(1..=u64::MAX - 2).contains(&self.prepared.head.sequence())
			|| !(FRAME_OVERHEAD_BYTES as u64..=MAX_FIRST_SEGMENT_BYTES)
				.contains(&self.prepared.extent)
		{
			return Err(ManagedActivationClaimError::Field);
		}
		Ok(())
	}
}

/// Commitment to the complete matched claim bytes including their checksum.
///
/// This digest describes bytes only. It attests no durable spend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedActivationClaimDigest([u8; 32]);

impl ManagedActivationClaimDigest {
	/// Borrows the exact domain-separated digest bytes.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// Refusal to encode or match the exact private claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedActivationClaimError {
	/// Slice extent differs from the single fixed record size.
	Length,
	/// Identifier does not select this record family.
	Magic,
	/// Encoded version is unsupported.
	UnsupportedVersion,
	/// Encoded required-feature word differs from the fixed zero word.
	UnsupportedFeatures,
	/// The recorded CRC32C does not cover these exact payload bytes.
	Checksum,
	/// An identifier, binding or boundary is structurally invalid.
	Field,
	/// The structurally valid record differs from the full independent selection.
	SelectionMismatch,
}

impl fmt::Display for ManagedActivationClaimError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Length => "wrong managed activation claim extent",
			Self::Magic => "wrong managed activation claim magic",
			Self::UnsupportedVersion => "unsupported managed activation claim version",
			Self::UnsupportedFeatures => "unsupported managed activation claim features",
			Self::Checksum => "managed activation claim checksum differs",
			Self::Field => "invalid managed activation claim field",
			Self::SelectionMismatch => "managed activation claim differs from selection",
		})
	}
}

impl core::error::Error for ManagedActivationClaimError {}

/// Encodes the canonical private record for this independent selection.
///
/// Creating bytes does not reserve or spend the slot.
/// # Errors
/// Refuses invalid identifiers, role bindings or prepared boundary.
pub fn encode_managed_activation_claim(
	expected: &ManagedActivationClaim,
) -> Result<[u8; MANAGED_ACTIVATION_CLAIM_BYTES], ManagedActivationClaimError> {
	expected.validate()?;
	let mut record = [0; MANAGED_ACTIVATION_CLAIM_BYTES];
	let (payload, checksum) = record.split_at_mut(PAYLOAD_BYTES);
	put(payload, MAGIC_AT, MAGIC);
	put(payload, VERSION_AT, &VERSION);
	put(payload, FEATURES_AT, &REQUIRED_FEATURES.to_le_bytes());
	put(payload, ACTIVATION_AT, &expected.activation);
	put(payload, HOST_SELECTION_AT, &expected.host_selection);
	put(payload, PROFILE_AT, expected.profile.as_bytes());
	put(payload, PAIR_AT, &expected.pair);
	put(
		payload,
		GENERATION_AT,
		&expected.predecessor_generation.to_le_bytes(),
	);
	put(payload, PREDECESSOR_AT, &expected.predecessor_root);
	put(payload, REVIEW_PARENT_AT, &expected.review_parent);
	put(payload, EXECUTION_PARENT_AT, &expected.execution_parent);
	put(payload, ACTION_AT, &expected.action);
	put(payload, GRANT_AT, &expected.grant);
	put(
		payload,
		PUBLIC_PLAN_AT,
		expected.child.public_plan.as_bytes(),
	);
	put(
		payload,
		PUBLIC_ENTRY_AT,
		expected.child.public_entry.as_bytes(),
	);
	put(payload, PRIVATE_PLAN_AT, &expected.child.private_plan);
	put(payload, CHILD_JOB_AT, expected.child.job.as_bytes());
	put(payload, CHILD_ENTRY_AT, expected.child.entry.as_bytes());
	put(
		payload,
		CHILD_EPOCH_AT,
		&expected.child.epoch.get().to_le_bytes(),
	);
	put(payload, SLOT_AT, &expected.slot);
	put(payload, SEGMENT_AT, &expected.segment);
	put(
		payload,
		SEQUENCE_AT,
		&expected.prepared.head.sequence().to_le_bytes(),
	);
	put(payload, HEAD_AT, &expected.prepared.head.digest());
	put(payload, EXTENT_AT, &expected.prepared.extent.to_le_bytes());
	checksum.copy_from_slice(&crc32c::crc32c(payload).to_le_bytes());
	Ok(record)
}

/// Checks one exact slice against the complete independent selection.
///
/// The caller separately establishes original named custody, physical EOF and
/// successful barriers. Occupancy and matching bytes cannot restore a live grant.
/// # Errors
/// Refuses wrong extent or family, unsupported options, CRC mismatch, invalid
/// fields in either record or selection, or any difference from the selection.
pub fn match_managed_activation_claim(
	bytes: &[u8],
	expected: &ManagedActivationClaim,
) -> Result<ManagedActivationClaimDigest, ManagedActivationClaimError> {
	use ManagedActivationClaimError as Error;

	let record: &[u8; MANAGED_ACTIVATION_CLAIM_BYTES] =
		bytes.try_into().map_err(|_| Error::Length)?;
	let (payload, checksum) = record.split_at(PAYLOAD_BYTES);
	if field::<8>(payload, MAGIC_AT) != *MAGIC {
		return Err(Error::Magic);
	}
	if field::<2>(payload, VERSION_AT) != VERSION {
		return Err(Error::UnsupportedVersion);
	}
	if u16::from_le_bytes(field(payload, FEATURES_AT)) != REQUIRED_FEATURES {
		return Err(Error::UnsupportedFeatures);
	}
	if checksum != crc32c::crc32c(payload).to_le_bytes() {
		return Err(Error::Checksum);
	}
	let recorded = decode_fields(payload)?;
	recorded.validate()?;
	expected.validate()?;
	if &recorded != expected {
		return Err(Error::SelectionMismatch);
	}
	Ok(ManagedActivationClaimDigest(blake3::derive_key(
		DIGEST_DOMAIN,
		record,
	)))
}

fn decode_fields(payload: &[u8]) -> Result<ManagedActivationClaim, ManagedActivationClaimError> {
	use ManagedActivationClaimError as Error;

	Ok(ManagedActivationClaim {
		activation: field(payload, ACTIVATION_AT),
		host_selection: field(payload, HOST_SELECTION_AT),
		profile: OwnerProfileId::from_bytes(field(payload, PROFILE_AT))
			.map_err(|_| Error::Field)?,
		pair: field(payload, PAIR_AT),
		predecessor_generation: u64::from_le_bytes(field(payload, GENERATION_AT)),
		predecessor_root: field(payload, PREDECESSOR_AT),
		review_parent: field(payload, REVIEW_PARENT_AT),
		execution_parent: field(payload, EXECUTION_PARENT_AT),
		action: field(payload, ACTION_AT),
		grant: field(payload, GRANT_AT),
		child: ManagedActivationChild {
			public_plan: ApprovedPublicPlanDigest::from_bytes(field(payload, PUBLIC_PLAN_AT)),
			public_entry: PublicPlanEntryId::from_bytes(field(payload, PUBLIC_ENTRY_AT))
				.map_err(|_| Error::Field)?,
			private_plan: field(payload, PRIVATE_PLAN_AT),
			job: JournalJobId::from_bytes(field(payload, CHILD_JOB_AT))
				.map_err(|_| Error::Field)?,
			entry: JournalEntryId::from_bytes(field(payload, CHILD_ENTRY_AT)),
			epoch: JournalEpoch::new(u64::from_le_bytes(field(payload, CHILD_EPOCH_AT))),
		},
		slot: field(payload, SLOT_AT),
		segment: field(payload, SEGMENT_AT),
		prepared: ManagedActivationPrepared {
			head: ChainHead::after(
				u64::from_le_bytes(field(payload, SEQUENCE_AT)),
				field(payload, HEAD_AT),
			)
			.ok_or(Error::Field)?,
			extent: u64::from_le_bytes(field(payload, EXTENT_AT)),
		},
	})
}

fn field<const N: usize>(payload: &[u8], offset: usize) -> [u8; N] {
	payload[offset..offset + N]
		.try_into()
		.expect("fixed claim field")
}

fn put<const N: usize>(payload: &mut [u8], offset: usize, value: &[u8; N]) {
	payload[offset..offset + N].copy_from_slice(value);
}
