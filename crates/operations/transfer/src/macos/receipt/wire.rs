//! The private v1 APFS receipt body is a fixed-order definite CBOR array.
//!
//! Its fields are version, fixed profile and achieved durability, attempt,
//! source identity, destination, published stream, required metadata, former
//! stage directory, and exact kind-9 reference. The native identity maps
//! share the APFS plan's representation. Integers use preferred serialization.

use std::num::NonZeroU32;

use exacopy_endpoint::{MAX_UNIX_COMPONENT_BYTES, UnixComponent};
use exacopy_journal::frame::ChainHead;
use exacopy_journal::{
	DarwinFileIdentity, DarwinReceiptDigest, DarwinRequiredMetadata, DarwinStreamEvidence,
	JournalContext, JournalEntryId, JournalEpoch, JournalJobId, OwnerTimestamp, PlanDigest,
	RootCapabilityId, StreamDigest, StreamLength,
};
use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use super::{DarwinCopyReceipt, DarwinCopyReceiptError, DarwinCopyReceiptEvidence};
use crate::macos::plan::{
	DestinationPlanBinding, MAX_IDENTITY_BYTES, read_identity, write_identity,
};

const DIGEST_DOMAIN: &[u8] = b"ExaCopy/darwin-copy-receipt/v1\0";
const VERSION: [u8; 3] = [1, 0, 0];
const MANAGED_APFS_BUFFERED_PROFILE: u8 = 2;
const DURABILITY_UNCONFIRMED: u8 = 0;

const RECEIPT_FIELDS: u64 = 9;
const PROFILE_FIELDS: u64 = 2;
const ATTEMPT_FIELDS: u64 = 4;
const DESTINATION_FIELDS: u64 = 3;
const STREAM_FIELDS: u64 = 3;
const METADATA_FIELDS: u64 = 5;
const TIMESTAMP_FIELDS: u64 = 2;
const REFERENCE_FIELDS: u64 = 2;

const MAX_UINT64_BYTES: usize = 9;
const MAX_UINT32_BYTES: usize = 5;
const MODE_BYTES: usize = 3;
const UUID_BYTES: usize = 1 + 16;
const DIGEST_BYTES: usize = 2 + 32;
const MAX_NAME_BYTES: usize = 2 + MAX_UNIX_COMPONENT_BYTES;
const MAX_TIMESTAMP_BYTES: usize = 1 + MAX_UINT64_BYTES + MAX_UINT32_BYTES;
const MAX_ATTEMPT_BYTES: usize = 1 + 2 * UUID_BYTES + MAX_UINT64_BYTES + DIGEST_BYTES;
const MAX_DESTINATION_BYTES: usize = 1 + UUID_BYTES + MAX_IDENTITY_BYTES + MAX_NAME_BYTES;
const MAX_STREAM_BYTES: usize = 1 + MAX_IDENTITY_BYTES + MAX_UINT64_BYTES + DIGEST_BYTES;
const MAX_METADATA_BYTES: usize = 1 + MODE_BYTES + 2 * MAX_UINT32_BYTES + 2 * MAX_TIMESTAMP_BYTES;
const MAX_REFERENCE_BYTES: usize = 1 + MAX_UINT64_BYTES + DIGEST_BYTES;

/// Maximum serialized bytes of the private v1 managed APFS copy receipt.
pub const MAX_DARWIN_COPY_RECEIPT_BYTES: usize = 1
	+ (1 + VERSION.len())
	+ (1 + 2)
	+ MAX_ATTEMPT_BYTES
	+ MAX_IDENTITY_BYTES
	+ MAX_DESTINATION_BYTES
	+ MAX_STREAM_BYTES
	+ MAX_METADATA_BYTES
	+ MAX_IDENTITY_BYTES
	+ MAX_REFERENCE_BYTES;

type ReceiptCursor = Cursor<[u8; MAX_DARWIN_COPY_RECEIPT_BYTES]>;
type ReceiptEncoder = Encoder<ReceiptCursor>;
type EncodeError = encode::Error<EndOfArray>;

impl<'name> DarwinCopyReceipt<'name> {
	/// Encodes the exact canonical bytes of the private receipt artifact.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let encoded = self.encode_bounded();
		encoded.get_ref()[..encoded.position()].to_vec()
	}

	/// Returns the digest of the exact artifact in the private Darwin receipt domain.
	#[must_use]
	pub fn digest(&self) -> DarwinReceiptDigest {
		let encoded = self.encode_bounded();
		let hash = blake3::Hasher::new()
			.update(DIGEST_DOMAIN)
			.update(&encoded.get_ref()[..encoded.position()])
			.finalize();
		DarwinReceiptDigest::from_bytes(*hash.as_bytes())
	}

	/// Decodes a complete canonical artifact, borrowing its raw destination name.
	///
	/// # Errors
	/// Rejects malformed or noncanonical input, other profiles, and conflicting observations.
	pub fn decode(payload: &'name [u8]) -> Result<Self, DarwinCopyReceiptError> {
		if payload.len() > MAX_DARWIN_COPY_RECEIPT_BYTES {
			return Err(DarwinCopyReceiptError::TooLarge);
		}
		let mut decoder = Decoder::new(payload);
		let receipt = Self::read(&mut decoder)?;
		let canonical = receipt.encode_bounded();
		if canonical.get_ref()[..canonical.position()] != *payload {
			return Err(DarwinCopyReceiptError::NonCanonical);
		}
		Ok(receipt)
	}

	fn encode_bounded(&self) -> ReceiptCursor {
		let mut encoder = Encoder::new(Cursor::new([0; MAX_DARWIN_COPY_RECEIPT_BYTES]));
		self.write(&mut encoder)
			.expect("validated APFS receipt fields fit the bounded encoding buffer");
		encoder.into_writer()
	}

	fn write(&self, encoder: &mut ReceiptEncoder) -> Result<(), EncodeError> {
		let evidence = self.evidence;
		encoder.array(RECEIPT_FIELDS)?.array(VERSION.len() as u64)?;
		for value in VERSION {
			encoder.u8(value)?;
		}
		encoder
			.array(PROFILE_FIELDS)?
			.u8(MANAGED_APFS_BUFFERED_PROFILE)?
			.u8(DURABILITY_UNCONFIRMED)?
			.array(ATTEMPT_FIELDS)?
			.bytes(evidence.context.job.as_bytes())?
			.u64(evidence.context.epoch.get())?
			.bytes(evidence.entry.as_bytes())?
			.bytes(evidence.context.plan_digest.as_bytes())?;
		write_identity(encoder, evidence.source)?;
		encoder
			.array(DESTINATION_FIELDS)?
			.bytes(evidence.destination.root_id.as_bytes())?;
		write_identity(encoder, evidence.destination.root_identity)?;
		encoder
			.bytes(evidence.destination.component.as_bytes())?
			.array(STREAM_FIELDS)?;
		write_identity(encoder, evidence.stream.identity)?;
		encoder
			.u64(evidence.stream.length.get())?
			.bytes(evidence.stream.digest.as_bytes())?;
		write_metadata(encoder, evidence.metadata)?;
		write_identity(encoder, evidence.stage_directory)?;
		encoder
			.array(REFERENCE_FIELDS)?
			.u64(self.durability_frame.sequence())?
			.bytes(&self.durability_frame.digest())?;
		Ok(())
	}

	fn read(decoder: &mut Decoder<'name>) -> Result<Self, DarwinCopyReceiptError> {
		expect_array(decoder, RECEIPT_FIELDS)?;
		if decoder.array()? != Some(VERSION.len() as u64) {
			return Err(DarwinCopyReceiptError::UnsupportedVersion);
		}
		for value in VERSION {
			if decoder.u8()? != value {
				return Err(DarwinCopyReceiptError::UnsupportedVersion);
			}
		}
		if decoder.array()? != Some(PROFILE_FIELDS)
			|| decoder.u8()? != MANAGED_APFS_BUFFERED_PROFILE
			|| decoder.u8()? != DURABILITY_UNCONFIRMED
		{
			return Err(DarwinCopyReceiptError::UnsupportedProfile);
		}
		expect_array(decoder, ATTEMPT_FIELDS)?;
		let job = JournalJobId::from_bytes(fixed_bytes(decoder)?)
			.map_err(|_| DarwinCopyReceiptError::InvalidBinding)?;
		let epoch = JournalEpoch::new(decoder.u64()?);
		let entry = JournalEntryId::from_bytes(fixed_bytes(decoder)?);
		let plan_digest = PlanDigest::from_bytes(fixed_bytes(decoder)?);
		let source = read_native_identity(decoder)?;
		let destination = read_destination(decoder)?;
		expect_array(decoder, STREAM_FIELDS)?;
		let stream = DarwinStreamEvidence {
			identity: read_native_identity(decoder)?,
			length: StreamLength::new(decoder.u64()?)
				.map_err(|_| DarwinCopyReceiptError::InvalidLength)?,
			digest: StreamDigest::from_bytes(fixed_bytes(decoder)?),
		};
		let metadata = read_metadata(decoder)?;
		let stage_directory = read_native_identity(decoder)?;
		expect_array(decoder, REFERENCE_FIELDS)?;
		let durability_frame = ChainHead::after(decoder.u64()?, fixed_bytes(decoder)?)
			.ok_or(DarwinCopyReceiptError::InvalidDurabilityFrame)?;
		Self::from_evidence(
			DarwinCopyReceiptEvidence {
				context: JournalContext {
					job,
					epoch,
					plan_digest,
				},
				entry,
				source,
				destination,
				stream,
				metadata,
				stage_directory,
			},
			durability_frame,
		)
	}
}

fn read_destination<'name>(
	decoder: &mut Decoder<'name>,
) -> Result<DestinationPlanBinding<'name>, DarwinCopyReceiptError> {
	expect_array(decoder, DESTINATION_FIELDS)?;
	Ok(DestinationPlanBinding {
		root_id: RootCapabilityId::from_bytes(fixed_bytes(decoder)?)
			.map_err(|_| DarwinCopyReceiptError::InvalidBinding)?,
		root_identity: read_native_identity(decoder)?,
		component: UnixComponent::new(decoder.bytes()?)
			.map_err(DarwinCopyReceiptError::InvalidTarget)?,
	})
}

fn read_native_identity(
	decoder: &mut Decoder<'_>,
) -> Result<DarwinFileIdentity, DarwinCopyReceiptError> {
	read_identity(decoder).map_err(|_| DarwinCopyReceiptError::IdentityMismatch)
}

fn write_metadata(
	encoder: &mut ReceiptEncoder,
	metadata: DarwinRequiredMetadata,
) -> Result<(), EncodeError> {
	let permissions = metadata.permissions();
	encoder
		.array(METADATA_FIELDS)?
		.u32(permissions.mode())?
		.u32(permissions.owner().get())?
		.u32(permissions.group())?;
	for timestamp in [metadata.accessed_at, metadata.modified_at] {
		encoder
			.array(TIMESTAMP_FIELDS)?
			.i64(timestamp.seconds())?
			.u32(timestamp.nanoseconds())?;
	}
	Ok(())
}

fn read_metadata(
	decoder: &mut Decoder<'_>,
) -> Result<DarwinRequiredMetadata, DarwinCopyReceiptError> {
	expect_array(decoder, METADATA_FIELDS)?;
	let mode = decoder.u32()?;
	let owner = NonZeroU32::new(decoder.u32()?).ok_or(DarwinCopyReceiptError::InvalidMetadata)?;
	let group = decoder.u32()?;
	DarwinRequiredMetadata::new(
		mode,
		owner,
		group,
		read_timestamp(decoder)?,
		read_timestamp(decoder)?,
	)
	.map_err(|_| DarwinCopyReceiptError::InvalidMetadata)
}

fn read_timestamp(decoder: &mut Decoder<'_>) -> Result<OwnerTimestamp, DarwinCopyReceiptError> {
	expect_array(decoder, TIMESTAMP_FIELDS)?;
	OwnerTimestamp::new(decoder.i64()?, decoder.u32()?)
		.map_err(|_| DarwinCopyReceiptError::InvalidMetadata)
}

fn expect_array(decoder: &mut Decoder<'_>, length: u64) -> Result<(), DarwinCopyReceiptError> {
	if decoder.array()? == Some(length) {
		Ok(())
	} else {
		Err(DarwinCopyReceiptError::InvalidCbor)
	}
}

fn fixed_bytes<const N: usize>(
	decoder: &mut Decoder<'_>,
) -> Result<[u8; N], DarwinCopyReceiptError> {
	decoder
		.bytes()?
		.try_into()
		.map_err(|_| DarwinCopyReceiptError::InvalidCbor)
}
