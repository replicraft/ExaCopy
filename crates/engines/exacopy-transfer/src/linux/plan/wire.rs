//! Private local copy plan v1. The CBOR body is a definite five-element array.
//!
//! Its fields, in order, are version, policy, attempt, source, and destination.
//! Nested arrays contain the attempt's job UUID, epoch, entry UUID, job and
//! stage names, then the source's root UUID, root identity, file identity,
//! length, modification and change times, and name, then the destination's
//! root UUID, root identity, and target name. Names and UUIDs are byte strings.
//! Identities are pairs of device and inode integers. Times are pairs of signed
//! Unix seconds and unsigned nanoseconds. All values use preferred serialization.

use exacopy_endpoint::{MAX_UNIX_COMPONENT_BYTES, UnixComponent};
use exacopy_journal::{
	DestinationRootBinding, JournalEntryId, JournalEpoch, JournalJobId, LinuxFileIdentity,
	ObservedTimestamp, PlanDigest, RootCapabilityId,
};
use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use super::{
	DestinationPlanBinding, LocalCopyPlan, LocalCopyPlanError, PlanAttempt, SourcePlanBinding,
};

// A private local projection with its own digest namespace. The public Plan v1
// domain refers to a different body with entry-page references.
const PLAN_DOMAIN: &[u8] = b"ExaCopy/local-copy-plan/v1\0";
const VERSION: [u8; 2] = [1, 0];

const COPY: u8 = 0;
const CREATE_NEW: u8 = 0;
const BLAKE3_READBACK: u8 = 0;
const LINUX_BASELINE_METADATA: u8 = 0;
const EXCLUSIVE_NO_REPLACE: u8 = 0;
const POLICY: [u8; 5] = [
	COPY,
	CREATE_NEW,
	BLAKE3_READBACK,
	LINUX_BASELINE_METADATA,
	EXCLUSIVE_NO_REPLACE,
];

const PLAN_FIELDS: u64 = 5;
const ATTEMPT_FIELDS: u64 = 5;
const SOURCE_FIELDS: u64 = 7;
const DESTINATION_FIELDS: u64 = 3;
const IDENTITY_FIELDS: u64 = 2;
const TIMESTAMP_FIELDS: u64 = 2;

// Each array header is one byte. UUID byte strings use one header byte. Each
// maximum-width u64 uses nine bytes. A 255-byte name uses two header bytes.
const MAX_UINT_BYTES: usize = 9;
const UUID_BYTES: usize = 17;
const NATIVE_IDENTITY_BYTES: usize = 1 + 2 * MAX_UINT_BYTES;
// Signed seconds can use nine bytes, and normalized fractional seconds use up to five.
const TIMESTAMP_BYTES: usize = 1 + MAX_UINT_BYTES + 5;
const NAME_BYTES: usize = 2 + MAX_UNIX_COMPONENT_BYTES;
const ATTEMPT_BYTES: usize = 1 + 2 * UUID_BYTES + MAX_UINT_BYTES + 2 * NAME_BYTES;
const SOURCE_BYTES: usize =
	1 + UUID_BYTES + 2 * NATIVE_IDENTITY_BYTES + MAX_UINT_BYTES + 2 * TIMESTAMP_BYTES + NAME_BYTES;
const DESTINATION_BYTES: usize = 1 + UUID_BYTES + NATIVE_IDENTITY_BYTES + NAME_BYTES;

/// Maximum encoded bytes for the private local Linux copy plan v1.
pub const MAX_LOCAL_COPY_PLAN_BYTES: usize =
	1 + (1 + VERSION.len()) + (1 + POLICY.len()) + ATTEMPT_BYTES + SOURCE_BYTES + DESTINATION_BYTES;

type PlanCursor = Cursor<[u8; MAX_LOCAL_COPY_PLAN_BYTES]>;
type EncodeError = encode::Error<EndOfArray>;

impl<'name> LocalCopyPlan<'name> {
	/// Encodes the exact bounded deterministic CBOR body.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let encoded = self.encode_bounded();
		encoded.get_ref()[..encoded.position()].to_vec()
	}

	/// Returns the BLAKE3 digest of the canonical body under the local v1 plan domain.
	#[must_use]
	pub fn digest(&self) -> PlanDigest {
		let encoded = self.encode_bounded();
		let hash = blake3::Hasher::new()
			.update(PLAN_DOMAIN)
			.update(&encoded.get_ref()[..encoded.position()])
			.finalize();
		PlanDigest::from_bytes(*hash.as_bytes())
	}

	/// Decodes the exact bounded local plan and borrows its validated raw components.
	///
	/// # Errors
	/// Rejects malformed, unsupported, noncanonical, or out-of-bounds encodings.
	pub fn decode(payload: &'name [u8]) -> Result<Self, LocalCopyPlanError> {
		if payload.len() > MAX_LOCAL_COPY_PLAN_BYTES {
			return Err(LocalCopyPlanError::PayloadTooLarge);
		}

		let mut decoder = Decoder::new(payload);
		expect_array(&mut decoder, PLAN_FIELDS)?;
		if read_codes::<2>(&mut decoder)? != VERSION {
			return Err(LocalCopyPlanError::UnsupportedVersion);
		}
		if read_codes::<5>(&mut decoder)? != POLICY {
			return Err(LocalCopyPlanError::UnsupportedPolicy);
		}

		let attempt = read_attempt(&mut decoder)?;
		let source = read_source(&mut decoder)?;
		let destination = read_destination(&mut decoder)?;
		let plan = Self::new(attempt, source, destination)?;
		let canonical = plan.encode_bounded();
		if canonical.get_ref()[..canonical.position()] != *payload {
			return Err(LocalCopyPlanError::NonCanonical);
		}
		Ok(plan)
	}

	fn encode_bounded(&self) -> PlanCursor {
		let mut encoder = Encoder::new(Cursor::new([0; MAX_LOCAL_COPY_PLAN_BYTES]));
		self.write_body(&mut encoder)
			.expect("a validated local copy plan fits its fixed-size wire buffer");
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
			.bytes(self.attempt.job_name.as_bytes())?
			.bytes(self.attempt.stage_name.as_bytes())?;

		encoder
			.array(SOURCE_FIELDS)?
			.bytes(self.source.root_id.as_bytes())?;
		write_identity(encoder, self.source.root_identity)?;
		write_identity(encoder, self.source.file_identity)?;
		encoder.u64(self.source.length)?;
		write_timestamp(encoder, self.source.modified_at)?;
		write_timestamp(encoder, self.source.changed_at)?;
		encoder.bytes(self.source.component.as_bytes())?;

		encoder
			.array(DESTINATION_FIELDS)?
			.bytes(self.destination.root.id.as_bytes())?;
		write_identity(encoder, self.destination.root.identity)?;
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

fn read_codes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], LocalCopyPlanError> {
	expect_array(decoder, N as u64)?;
	let mut values = [0; N];
	for value in &mut values {
		*value = decoder.u8()?;
	}
	Ok(values)
}

fn read_attempt<'name>(
	decoder: &mut Decoder<'name>,
) -> Result<PlanAttempt<'name>, LocalCopyPlanError> {
	expect_array(decoder, ATTEMPT_FIELDS)?;
	let job = decoder
		.bytes()?
		.try_into()
		.map_err(|_| LocalCopyPlanError::InvalidJobId)?;
	let job = JournalJobId::from_bytes(job).map_err(|_| LocalCopyPlanError::InvalidJobId)?;
	let epoch = JournalEpoch::new(decoder.u64()?);
	let entry = decoder
		.bytes()?
		.try_into()
		.map_err(|_| LocalCopyPlanError::InvalidEntryId)?;
	let job_name = read_component(decoder)?;
	let stage_name = read_component(decoder)?;
	Ok(PlanAttempt {
		job,
		epoch,
		entry: JournalEntryId::from_bytes(entry),
		job_name,
		stage_name,
	})
}

fn read_source<'name>(
	decoder: &mut Decoder<'name>,
) -> Result<SourcePlanBinding<'name>, LocalCopyPlanError> {
	expect_array(decoder, SOURCE_FIELDS)?;
	Ok(SourcePlanBinding {
		root_id: read_root_id(decoder)?,
		root_identity: read_identity(decoder)?,
		file_identity: read_identity(decoder)?,
		length: decoder.u64()?,
		modified_at: read_timestamp(decoder)?,
		changed_at: read_timestamp(decoder)?,
		component: read_component(decoder)?,
	})
}

fn read_destination<'name>(
	decoder: &mut Decoder<'name>,
) -> Result<DestinationPlanBinding<'name>, LocalCopyPlanError> {
	expect_array(decoder, DESTINATION_FIELDS)?;
	let root = DestinationRootBinding {
		id: read_root_id(decoder)?,
		identity: read_identity(decoder)?,
	};
	let component = read_component(decoder)?;
	Ok(DestinationPlanBinding { root, component })
}

fn expect_array(decoder: &mut Decoder<'_>, len: u64) -> Result<(), LocalCopyPlanError> {
	match decoder.array()? {
		Some(actual) if actual == len => Ok(()),
		_ => Err(LocalCopyPlanError::InvalidShape),
	}
}

fn read_root_id(decoder: &mut Decoder<'_>) -> Result<RootCapabilityId, LocalCopyPlanError> {
	let root = decoder
		.bytes()?
		.try_into()
		.map_err(|_| LocalCopyPlanError::InvalidRootId)?;
	RootCapabilityId::from_bytes(root).map_err(|_| LocalCopyPlanError::InvalidRootId)
}

fn write_identity(
	encoder: &mut Encoder<PlanCursor>,
	value: LinuxFileIdentity,
) -> Result<(), EncodeError> {
	encoder
		.array(IDENTITY_FIELDS)?
		.u64(value.device())?
		.u64(value.inode())?;
	Ok(())
}

fn read_identity(decoder: &mut Decoder<'_>) -> Result<LinuxFileIdentity, LocalCopyPlanError> {
	expect_array(decoder, IDENTITY_FIELDS)?;
	Ok(LinuxFileIdentity::new(decoder.u64()?, decoder.u64()?))
}

fn write_timestamp(
	encoder: &mut Encoder<PlanCursor>,
	value: ObservedTimestamp,
) -> Result<(), EncodeError> {
	encoder
		.array(TIMESTAMP_FIELDS)?
		.i64(value.seconds())?
		.u32(value.nanoseconds())?;
	Ok(())
}

fn read_timestamp(decoder: &mut Decoder<'_>) -> Result<ObservedTimestamp, LocalCopyPlanError> {
	expect_array(decoder, TIMESTAMP_FIELDS)?;
	ObservedTimestamp::new(decoder.i64()?, decoder.u32()?)
		.map_err(|_| LocalCopyPlanError::InvalidSourceTimestamp)
}

fn read_component<'name>(
	decoder: &mut Decoder<'name>,
) -> Result<UnixComponent<'name>, LocalCopyPlanError> {
	UnixComponent::new(decoder.bytes()?).map_err(LocalCopyPlanError::InvalidComponent)
}
