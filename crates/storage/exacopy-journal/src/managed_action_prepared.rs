//! Canonical journal origin for one independently selected managed action slot.
//!
//! The caller obtains the expected allocation and frame boundary independently
//! and establishes physical EOF, original native custody, and provisioning
//! durability separately. A match confers no activation, writer, or right to
//! create a child. The ordinary frame reader continues to refuse this kind.

use core::fmt;

use exacopy_model::JobId;

use crate::frame::{FRAME_OVERHEAD_BYTES, FrameKind, FrameReadError, FrameReader, LENGTH_OFFSET};
use crate::managed_activation_claim::{ManagedActivationChild, ManagedActivationPrepared};
use crate::{
	ApprovedPublicPlanDigest, JournalEntryId, JournalEpoch, JournalJobId, OwnerProfileId,
	PublicPlanEntryId,
};

const VERSION_MAJOR: u8 = 1;
const VERSION_MINOR: u8 = 0;
const VERSION: [u8; 2] = [VERSION_MAJOR, VERSION_MINOR];
const REQUIRED_FEATURES: u16 = 0;

/// Exact payload length of the managed action origin.
pub const MANAGED_ACTION_PREPARED_PAYLOAD_BYTES: usize = 340;
/// Exact segment extent when only the managed action origin is present.
pub const MANAGED_ACTION_PREPARED_FRAME_BYTES: usize =
	FRAME_OVERHEAD_BYTES + MANAGED_ACTION_PREPARED_PAYLOAD_BYTES;

const VERSION_AT: usize = 0;
const FEATURES_AT: usize = 2;
const ENROLLMENT_AT: usize = 4;
const ALLOCATION_AT: usize = 20;
const PROFILE_AT: usize = 36;
const PAIR_AT: usize = 52;
const GENERATION_AT: usize = 68;
const PREDECESSOR_AT: usize = 76;
const REVIEW_PARENT_AT: usize = 108;
const ACTION_AT: usize = 140;
const PUBLIC_PLAN_AT: usize = 156;
const PUBLIC_ENTRY_AT: usize = 188;
const PRIVATE_PLAN_AT: usize = 204;
const CHILD_JOB_AT: usize = 236;
const CHILD_ENTRY_AT: usize = 252;
const CHILD_EPOCH_AT: usize = 268;
const SLOT_AT: usize = 276;
const SEGMENT_AT: usize = 308;

type Payload = [u8; MANAGED_ACTION_PREPARED_PAYLOAD_BYTES];

/// Expected allocation facts for one independently selected origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedActionPrepared {
	/// Independently assigned issuer enrollment allocation ID.
	pub enrollment: [u8; 16],
	/// Independently assigned one-use action slot allocation ID.
	pub allocation: [u8; 16],
	/// Selected managed and local child owner profile.
	pub profile: OwnerProfileId,
	/// Independently selected managed pair UUIDv7.
	pub pair: [u8; 16],
	/// Independently selected current predecessor generation, fixed at one.
	pub predecessor_generation: u64,
	/// Kind-6 predecessor root reference digest covering its signing input.
	pub predecessor_root: [u8; 32],
	/// Verified kind-5 review-only parent digest covering its signing input.
	pub review_parent: [u8; 32],
	/// Exact action ID from the verified review parent.
	pub reviewed_action: [u8; 16],
	/// Exact ordinary public and private child attempt selection.
	pub child: ManagedActivationChild,
	/// Stable role-scoped projection of the selected original slot directory.
	pub slot: [u8; 32],
	/// Stable role-scoped projection of the selected original segment file.
	pub segment: [u8; 32],
}

impl ManagedActionPrepared {
	fn validate(&self) -> Result<(), ManagedActionPreparedError> {
		if self.enrollment == self.allocation
			|| [
				self.enrollment,
				self.allocation,
				self.reviewed_action,
				*self.child.entry.as_bytes(),
			]
			.contains(&[0; 16])
			|| JobId::try_from_bytes(self.pair).is_err()
			|| self.predecessor_generation != 1
			|| self.child.epoch.get() == 0
			|| self.slot == self.segment
			|| [
				self.predecessor_root,
				self.review_parent,
				*self.child.public_plan.as_bytes(),
				self.child.private_plan,
				self.slot,
				self.segment,
			]
			.contains(&[0; 32])
		{
			return Err(ManagedActionPreparedError::Field);
		}
		Ok(())
	}
}

/// Refusal to encode or match the exact managed action origin.
#[derive(Debug)]
pub enum ManagedActionPreparedError {
	/// The supplied segment slice differs from the exact origin extent.
	Length,
	/// The envelope declares a payload length other than the fixed origin length.
	PayloadLength,
	/// The common frame reader rejected the envelope or genesis chain.
	Frame(FrameReadError),
	/// The envelope declares a different registered record kind.
	Kind,
	/// The origin payload version is unsupported.
	UnsupportedVersion,
	/// The origin payload declares unsupported required features.
	UnsupportedFeatures,
	/// A recorded or independently selected field fails the origin's structural rules.
	Field,
	/// Canonical recorded fields differ from the exact independent selection.
	SelectionMismatch,
	/// The frame head or extent differs from the independently selected boundary.
	BoundaryMismatch,
}

impl fmt::Display for ManagedActionPreparedError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Frame(error) => {
				return write!(formatter, "managed action origin frame refused: {error}");
			}
			Self::Length => "wrong managed action origin extent",
			Self::PayloadLength => "wrong managed action origin payload length",
			Self::Kind => "wrong managed action origin frame kind",
			Self::UnsupportedVersion => "unsupported managed action origin version",
			Self::UnsupportedFeatures => "unsupported managed action origin features",
			Self::Field => "invalid managed action origin field",
			Self::SelectionMismatch => "managed action origin differs from selection",
			Self::BoundaryMismatch => "managed action origin boundary differs from selection",
		})
	}
}

impl core::error::Error for ManagedActionPreparedError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::Frame(error) => Some(error),
			_ => None,
		}
	}
}

/// Encodes the canonical unsigned origin payload for a separate provisioner.
///
/// Creating bytes does not provision, reserve or spend the slot.
///
/// # Errors
/// Refuses invalid identifiers, predecessor generation, or role bindings.
pub fn encode_managed_action_prepared(
	expected: &ManagedActionPrepared,
) -> Result<[u8; MANAGED_ACTION_PREPARED_PAYLOAD_BYTES], ManagedActionPreparedError> {
	expected.validate()?;
	let mut payload = [0; MANAGED_ACTION_PREPARED_PAYLOAD_BYTES];
	put(&mut payload, VERSION_AT, &VERSION);
	put(&mut payload, FEATURES_AT, &REQUIRED_FEATURES.to_le_bytes());
	put(&mut payload, ENROLLMENT_AT, &expected.enrollment);
	put(&mut payload, ALLOCATION_AT, &expected.allocation);
	put(&mut payload, PROFILE_AT, expected.profile.as_bytes());
	put(&mut payload, PAIR_AT, &expected.pair);
	put(
		&mut payload,
		GENERATION_AT,
		&expected.predecessor_generation.to_le_bytes(),
	);
	put(&mut payload, PREDECESSOR_AT, &expected.predecessor_root);
	put(&mut payload, REVIEW_PARENT_AT, &expected.review_parent);
	put(&mut payload, ACTION_AT, &expected.reviewed_action);
	put(
		&mut payload,
		PUBLIC_PLAN_AT,
		expected.child.public_plan.as_bytes(),
	);
	put(
		&mut payload,
		PUBLIC_ENTRY_AT,
		expected.child.public_entry.as_bytes(),
	);
	put(&mut payload, PRIVATE_PLAN_AT, &expected.child.private_plan);
	put(&mut payload, CHILD_JOB_AT, expected.child.job.as_bytes());
	put(
		&mut payload,
		CHILD_ENTRY_AT,
		expected.child.entry.as_bytes(),
	);
	put(
		&mut payload,
		CHILD_EPOCH_AT,
		&expected.child.epoch.get().to_le_bytes(),
	);
	put(&mut payload, SLOT_AT, &expected.slot);
	put(&mut payload, SEGMENT_AT, &expected.segment);
	Ok(payload)
}

/// Checks one complete origin slice against independent fields and a frame boundary.
///
/// The boundary on success describes bytes only. This check does not read a
/// file, verify physical EOF, authenticate enrollment, or prove any barrier.
///
/// # Errors
/// Refuses a wrong extent, envelope, genesis chain, unsupported payload, invalid
/// fields, or a difference from any selected field or boundary.
pub fn match_managed_action_prepared(
	bytes: &[u8],
	expected: &ManagedActionPrepared,
	boundary: ManagedActivationPrepared,
) -> Result<ManagedActivationPrepared, ManagedActionPreparedError> {
	use ManagedActionPreparedError as Error;

	let record: &[u8; MANAGED_ACTION_PREPARED_FRAME_BYTES] =
		bytes.try_into().map_err(|_| Error::Length)?;
	let payload_length = u32::from_le_bytes(field(record, LENGTH_OFFSET));
	if payload_length != MANAGED_ACTION_PREPARED_PAYLOAD_BYTES as u32 {
		return Err(Error::PayloadLength);
	}
	let mut reader = FrameReader::for_managed_origin(record.as_slice());
	let mut wrong_kind = false;
	let read = reader.next_frame_with_payload_limit(|kind| {
		wrong_kind = kind != FrameKind::ManagedActionPrepared;
		if wrong_kind {
			0
		} else {
			MANAGED_ACTION_PREPARED_PAYLOAD_BYTES
		}
	});
	if wrong_kind {
		// The exact nonzero length was checked before parsing. A zero cap forbids a body read.
		return Err(Error::Kind);
	}
	let frame = read.map_err(Error::Frame)?.ok_or(Error::Length)?;
	let payload: &Payload = frame
		.payload()
		.try_into()
		.map_err(|_| Error::PayloadLength)?;
	let recorded = decode(payload)?;
	expected.validate()?;
	if &recorded != expected {
		return Err(Error::SelectionMismatch);
	}
	let verified = ManagedActivationPrepared {
		head: frame.head(),
		extent: reader.offset(),
	};
	if verified != boundary {
		return Err(Error::BoundaryMismatch);
	}
	Ok(verified)
}

fn decode(payload: &Payload) -> Result<ManagedActionPrepared, ManagedActionPreparedError> {
	use ManagedActionPreparedError as Error;

	if field::<2>(payload, VERSION_AT) != VERSION {
		return Err(Error::UnsupportedVersion);
	}
	if u16::from_le_bytes(field(payload, FEATURES_AT)) != REQUIRED_FEATURES {
		return Err(Error::UnsupportedFeatures);
	}
	let recorded = ManagedActionPrepared {
		enrollment: field(payload, ENROLLMENT_AT),
		allocation: field(payload, ALLOCATION_AT),
		profile: OwnerProfileId::from_bytes(field(payload, PROFILE_AT))
			.map_err(|_| Error::Field)?,
		pair: field(payload, PAIR_AT),
		predecessor_generation: u64::from_le_bytes(field(payload, GENERATION_AT)),
		predecessor_root: field(payload, PREDECESSOR_AT),
		review_parent: field(payload, REVIEW_PARENT_AT),
		reviewed_action: field(payload, ACTION_AT),
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
	};
	recorded.validate()?;
	Ok(recorded)
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
	bytes[offset..offset + N]
		.try_into()
		.expect("fixed managed action origin field")
}

fn put<const N: usize>(payload: &mut Payload, offset: usize, value: &[u8; N]) {
	payload[offset..offset + N].copy_from_slice(value);
}
