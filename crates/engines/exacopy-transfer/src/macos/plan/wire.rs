//! Private copy plan v2.0 for the managed APFS preserve profile.
//!
//! The definite CBOR array contains, in order, the semantic version and its
//! required features, fixed policy, attempt, source and destination. UUIDs
//! and raw components are byte strings. The native identity maps follow the
//! signed Darwin owner format. Integers use preferred CBOR serialization.

use exacopy_endpoint::{MAX_UNIX_COMPONENT_BYTES, UnixComponent};
use exacopy_journal::{
	JournalEntryId, JournalEpoch, JournalJobId, ObservedTimestamp, OwnerProfileId, PlanDigest,
	RootCapabilityId,
};
use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use super::{
	DarwinCopyPlan, DarwinCopyPlanError, DestinationPlanBinding, PlanAttempt, SourceMetadata,
	SourcePlanBinding,
};

mod identity;

pub(in crate::macos) use self::identity::{MAX_IDENTITY_BYTES, read_identity, write_identity};

const PLAN_DOMAIN: &[u8] = b"ExaCopy/darwin-managed-apfs-copy-plan/v2\0";
const VERSION: [u8; 3] = [2, 0, 1];

const COPY: u8 = 0;
const CREATE_NEW: u8 = 0;
const BLAKE3_READBACK: u8 = 0;
const DARWIN_STRICT_BASIC_METADATA: u8 = 1;
const DARWIN_RENAME_EXCL: u8 = 1;
const POLICY: [u8; 5] = [
	COPY,
	CREATE_NEW,
	BLAKE3_READBACK,
	DARWIN_STRICT_BASIC_METADATA,
	DARWIN_RENAME_EXCL,
];

const PLAN_FIELDS: u64 = 5;
const ATTEMPT_FIELDS: u64 = 4;
const SOURCE_FIELDS: u64 = 6;
const METADATA_FIELDS: u64 = 6;
const DESTINATION_FIELDS: u64 = 3;
const TIMESTAMP_FIELDS: u64 = 2;

const MAX_UINT64_BYTES: usize = 9;
const MAX_UINT32_BYTES: usize = 5;
const MAX_UINT16_BYTES: usize = 3;
const MAX_TIMESTAMP_BYTES: usize = 1 + MAX_UINT64_BYTES + MAX_UINT32_BYTES;
const UUID_BYTES: usize = 1 + 16;
const NAME_BYTES: usize = 2 + MAX_UNIX_COMPONENT_BYTES;
const ATTEMPT_BYTES: usize = 1 + 3 * UUID_BYTES + MAX_UINT64_BYTES;
const METADATA_BYTES: usize = 1 + MAX_UINT16_BYTES + 2 * MAX_UINT32_BYTES + 3 * MAX_TIMESTAMP_BYTES;
const SOURCE_BYTES: usize =
	1 + UUID_BYTES + 2 * MAX_IDENTITY_BYTES + MAX_UINT64_BYTES + METADATA_BYTES + NAME_BYTES;
const DESTINATION_BYTES: usize = 1 + UUID_BYTES + MAX_IDENTITY_BYTES + NAME_BYTES;

/// Maximum serialized bytes of a managed APFS copy plan.
pub const MAX_DARWIN_COPY_PLAN_BYTES: usize =
	1 + (1 + VERSION.len()) + (1 + POLICY.len()) + ATTEMPT_BYTES + SOURCE_BYTES + DESTINATION_BYTES;

type PlanCursor = Cursor<[u8; MAX_DARWIN_COPY_PLAN_BYTES]>;
type EncodeError = encode::Error<EndOfArray>;

impl<'name> DarwinCopyPlan<'name> {
	/// Encodes the exact deterministic CBOR body.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let encoded = self.encode_bounded();
		encoded.get_ref()[..encoded.position()].to_vec()
	}

	/// Returns the BLAKE3 digest of the canonical body in the Darwin plan domain.
	#[must_use]
	pub fn digest(&self) -> PlanDigest {
		let encoded = self.encode_bounded();
		let hash = blake3::Hasher::new()
			.update(PLAN_DOMAIN)
			.update(&encoded.get_ref()[..encoded.position()])
			.finalize();
		PlanDigest::from_bytes(*hash.as_bytes())
	}

	/// Decodes one complete bounded plan against an independently selected profile.
	/// Returned name components borrow the validated bytes.
	///
	/// # Errors
	/// Refuses malformed, unsupported, noncanonical or out-of-bounds values,
	/// including plans bound to a different local profile.
	pub fn decode(
		payload: &'name [u8],
		expected_profile: OwnerProfileId,
	) -> Result<Self, DarwinCopyPlanError> {
		if payload.len() > MAX_DARWIN_COPY_PLAN_BYTES {
			return Err(DarwinCopyPlanError::PayloadTooLarge);
		}

		let mut decoder = Decoder::new(payload);
		expect_array(&mut decoder, PLAN_FIELDS)?;
		if decoder.array()? != Some(VERSION.len() as u64)
			|| read_code_values(&mut decoder)? != VERSION
		{
			return Err(DarwinCopyPlanError::UnsupportedVersion);
		}
		if read_codes::<5>(&mut decoder)? != POLICY {
			return Err(DarwinCopyPlanError::UnsupportedPolicy);
		}

		let attempt = read_attempt(&mut decoder)?;
		if attempt.profile != expected_profile {
			return Err(DarwinCopyPlanError::ProfileMismatch);
		}
		let source = read_source(&mut decoder)?;
		let destination = read_destination(&mut decoder)?;
		let plan = Self::new(attempt, source, destination)?;
		let canonical = plan.encode_bounded();
		if canonical.get_ref()[..canonical.position()] != *payload {
			return Err(DarwinCopyPlanError::NonCanonical);
		}
		Ok(plan)
	}

	fn encode_bounded(&self) -> PlanCursor {
		let mut encoder = Encoder::new(Cursor::new([0; MAX_DARWIN_COPY_PLAN_BYTES]));
		self.write_body(&mut encoder)
			.expect("a validated APFS copy plan fits its fixed-size wire buffer");
		encoder.into_writer()
	}

	fn write_body(&self, encoder: &mut Encoder<PlanCursor>) -> Result<(), EncodeError> {
		encoder.array(PLAN_FIELDS)?;
		write_codes(encoder, VERSION)?;
		write_codes(encoder, POLICY)?;

		encoder
			.array(ATTEMPT_FIELDS)?
			.bytes(self.attempt.job.as_bytes())?
			.u64(self.attempt.epoch.get())?
			.bytes(self.attempt.entry.as_bytes())?
			.bytes(self.attempt.profile.as_bytes())?;

		encoder
			.array(SOURCE_FIELDS)?
			.bytes(self.source.root_id.as_bytes())?;
		write_identity(encoder, self.source.root_identity)?;
		write_identity(encoder, self.source.file_identity)?;
		encoder.u64(self.source.length)?;
		write_metadata(encoder, self.source.metadata)?;
		encoder.bytes(self.source.component.as_bytes())?;

		encoder
			.array(DESTINATION_FIELDS)?
			.bytes(self.destination.root_id.as_bytes())?;
		write_identity(encoder, self.destination.root_identity)?;
		encoder.bytes(self.destination.component.as_bytes())?;
		Ok(())
	}
}

fn write_codes<const N: usize>(
	encoder: &mut Encoder<PlanCursor>,
	values: [u8; N],
) -> Result<(), EncodeError> {
	encoder.array(N as u64)?;
	for value in values {
		encoder.u8(value)?;
	}
	Ok(())
}

fn read_codes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], DarwinCopyPlanError> {
	expect_array(decoder, N as u64)?;
	read_code_values(decoder)
}

fn read_code_values<const N: usize>(
	decoder: &mut Decoder<'_>,
) -> Result<[u8; N], DarwinCopyPlanError> {
	let mut values = [0; N];
	for value in &mut values {
		*value = decoder.u8()?;
	}
	Ok(values)
}

fn read_attempt(decoder: &mut Decoder<'_>) -> Result<PlanAttempt, DarwinCopyPlanError> {
	expect_array(decoder, ATTEMPT_FIELDS)?;
	let job = fixed_bytes(decoder, DarwinCopyPlanError::InvalidJobId)?;
	let job = JournalJobId::from_bytes(job).map_err(|_| DarwinCopyPlanError::InvalidJobId)?;
	let epoch = JournalEpoch::new(decoder.u64()?);
	let entry =
		JournalEntryId::from_bytes(fixed_bytes(decoder, DarwinCopyPlanError::InvalidEntryId)?);
	let profile = fixed_bytes(decoder, DarwinCopyPlanError::InvalidProfileId)?;
	let profile =
		OwnerProfileId::from_bytes(profile).map_err(|_| DarwinCopyPlanError::InvalidProfileId)?;
	Ok(PlanAttempt {
		job,
		epoch,
		entry,
		profile,
	})
}

fn read_source<'name>(
	decoder: &mut Decoder<'name>,
) -> Result<SourcePlanBinding<'name>, DarwinCopyPlanError> {
	expect_array(decoder, SOURCE_FIELDS)?;
	Ok(SourcePlanBinding {
		root_id: read_root_id(decoder)?,
		root_identity: read_identity(decoder)?,
		file_identity: read_identity(decoder)?,
		length: decoder.u64()?,
		metadata: read_metadata(decoder)?,
		component: read_component(decoder)?,
	})
}

fn read_destination<'name>(
	decoder: &mut Decoder<'name>,
) -> Result<DestinationPlanBinding<'name>, DarwinCopyPlanError> {
	expect_array(decoder, DESTINATION_FIELDS)?;
	Ok(DestinationPlanBinding {
		root_id: read_root_id(decoder)?,
		root_identity: read_identity(decoder)?,
		component: read_component(decoder)?,
	})
}

fn write_metadata(
	encoder: &mut Encoder<PlanCursor>,
	metadata: SourceMetadata,
) -> Result<(), EncodeError> {
	encoder
		.array(METADATA_FIELDS)?
		.u16(metadata.mode())?
		.u32(metadata.uid().get())?
		.u32(metadata.gid())?;
	for timestamp in [
		metadata.accessed_at(),
		metadata.modified_at(),
		metadata.changed_at(),
	] {
		encoder
			.array(TIMESTAMP_FIELDS)?
			.i64(timestamp.seconds())?
			.u32(timestamp.nanoseconds())?;
	}
	Ok(())
}

fn read_metadata(decoder: &mut Decoder<'_>) -> Result<SourceMetadata, DarwinCopyPlanError> {
	expect_array(decoder, METADATA_FIELDS)?;
	SourceMetadata::new(
		decoder.u16()?,
		decoder.u32()?,
		decoder.u32()?,
		read_timestamp(decoder)?,
		read_timestamp(decoder)?,
		read_timestamp(decoder)?,
	)
}

fn read_timestamp(decoder: &mut Decoder<'_>) -> Result<ObservedTimestamp, DarwinCopyPlanError> {
	expect_array(decoder, TIMESTAMP_FIELDS)?;
	ObservedTimestamp::new(decoder.i64()?, decoder.u32()?)
		.map_err(|_| DarwinCopyPlanError::InvalidTimestamp)
}

fn expect_array(decoder: &mut Decoder<'_>, len: u64) -> Result<(), DarwinCopyPlanError> {
	match decoder.array()? {
		Some(actual) if actual == len => Ok(()),
		_ => Err(DarwinCopyPlanError::InvalidShape),
	}
}

fn fixed_bytes<const N: usize>(
	decoder: &mut Decoder<'_>,
	error: DarwinCopyPlanError,
) -> Result<[u8; N], DarwinCopyPlanError> {
	decoder.bytes()?.try_into().map_err(|_| error)
}

fn read_root_id(decoder: &mut Decoder<'_>) -> Result<RootCapabilityId, DarwinCopyPlanError> {
	let root = fixed_bytes(decoder, DarwinCopyPlanError::InvalidRootId)?;
	RootCapabilityId::from_bytes(root).map_err(|_| DarwinCopyPlanError::InvalidRootId)
}

fn read_component<'name>(
	decoder: &mut Decoder<'name>,
) -> Result<UnixComponent<'name>, DarwinCopyPlanError> {
	UnixComponent::new(decoder.bytes()?).map_err(DarwinCopyPlanError::InvalidComponent)
}
