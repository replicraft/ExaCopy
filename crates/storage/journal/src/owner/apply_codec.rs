use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use crate::{JournalEntryId, JournalEpoch, RootCapabilityId, StreamLength};

use super::apply::{
	ApplyMetadataPolicyDigest, ApplyRequestedDurability, ApprovedPublicPlanDigest,
	ApprovedStreamDigest, PublicApplyBinding, PublicApplyOwnerManifest, PublicPlanEntryId,
};
use super::codec::{self, BodyBytes, MAX_BODY_BYTES, encoded_bytes, finish, fixed_bytes, key, map};
use super::{OwnerError, OwnerTimestamp};

const FORMAT_MAJOR: u64 = 1;
const FORMAT_MINOR: u64 = 0;
const REQUIRED_FEATURES: u64 = 1;
const PROCESS_CRASH: u64 = 0;
const BINDING_FIELDS: u64 = 11;

pub(super) fn encode_body(
	manifest: &PublicApplyOwnerManifest,
	public_key: &[u8; 32],
) -> Result<BodyBytes, OwnerError> {
	let owner = codec::encode_body(&manifest.owner, public_key)?;
	let binding = &manifest.binding;
	let mut encoder = Encoder::new(BodyBytes::new([0; MAX_BODY_BYTES]));
	encoder
		.map(3)?
		.u8(0)?
		.map(3)?
		.u8(0)?
		.u64(FORMAT_MAJOR)?
		.u8(1)?
		.u64(FORMAT_MINOR)?
		.u8(2)?
		.u64(REQUIRED_FEATURES)?
		.u8(1)?
		.bytes(encoded_bytes(&owner))?
		.u8(2)?
		.map(BINDING_FIELDS)?
		.u8(0)?
		.bytes(binding.public_plan.as_bytes())?
		.u8(1)?
		.bytes(binding.public_entry.as_bytes())?
		.u8(2)?
		.bytes(binding.private_entry.as_bytes())?
		.u8(3)?
		.u64(binding.epoch.get())?
		.u8(4)?
		.bytes(binding.source_root.as_bytes())?
		.u8(5)?
		.bytes(binding.destination_root.as_bytes())?
		.u8(6)?
		.u64(binding.stream_length.get())?
		.u8(7)?
		.bytes(binding.stream_digest.as_bytes())?
		.u8(8)?
		.bytes(binding.metadata_policy.as_bytes())?
		.u8(9)?;
	if let Some(expiry) = binding.expires_at {
		encoder
			.array(2)?
			.i64(expiry.seconds())?
			.u32(expiry.nanoseconds())?;
	} else {
		encoder.null()?;
	}
	let durability = match binding.requested_durability {
		ApplyRequestedDurability::ProcessCrash => PROCESS_CRASH,
	};
	encoder.u8(10)?.u64(durability)?;
	Ok(encoder.into_writer())
}

pub(super) fn decode_body(
	bytes: &[u8],
	public_key: &[u8; 32],
) -> Result<PublicApplyOwnerManifest, OwnerError> {
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 3)?;
	key(&mut decoder, 0)?;
	decode_version(&mut decoder)?;
	key(&mut decoder, 1)?;
	let owner = codec::decode_body(decoder.bytes()?, public_key)?;
	key(&mut decoder, 2)?;
	let binding = decode_binding(&mut decoder)?;
	finish(decoder)?;
	let manifest = PublicApplyOwnerManifest { owner, binding };
	manifest.validate()?;
	if encoded_bytes(&encode_body(&manifest, public_key)?) != bytes {
		return Err(OwnerError::NonCanonical);
	}
	Ok(manifest)
}

fn decode_version(decoder: &mut Decoder<'_>) -> Result<(), OwnerError> {
	map(decoder, 3)?;
	key(decoder, 0)?;
	let major = decoder.u64()?;
	key(decoder, 1)?;
	let minor = decoder.u64()?;
	key(decoder, 2)?;
	let features = decoder.u64()?;
	if (major, minor, features) != (FORMAT_MAJOR, FORMAT_MINOR, REQUIRED_FEATURES) {
		return Err(OwnerError::UnsupportedVersion);
	}
	Ok(())
}

fn decode_binding(decoder: &mut Decoder<'_>) -> Result<PublicApplyBinding, OwnerError> {
	map(decoder, BINDING_FIELDS)?;
	key(decoder, 0)?;
	let public_plan = ApprovedPublicPlanDigest::from_bytes(fixed_bytes(decoder)?);
	key(decoder, 1)?;
	let public_entry = PublicPlanEntryId::from_bytes(fixed_bytes(decoder)?)?;
	key(decoder, 2)?;
	let private_entry = JournalEntryId::from_bytes(fixed_bytes(decoder)?);
	key(decoder, 3)?;
	let epoch = JournalEpoch::new(decoder.u64()?);
	key(decoder, 4)?;
	let source_root = decode_root(decoder)?;
	key(decoder, 5)?;
	let destination_root = decode_root(decoder)?;
	key(decoder, 6)?;
	let stream_length =
		StreamLength::new(decoder.u64()?).map_err(|_| OwnerError::InvalidApplyLength)?;
	key(decoder, 7)?;
	let stream_digest = ApprovedStreamDigest::from_bytes(fixed_bytes(decoder)?);
	key(decoder, 8)?;
	let metadata_policy = ApplyMetadataPolicyDigest::from_bytes(fixed_bytes(decoder)?);
	key(decoder, 9)?;
	let expires_at = decode_expiry(decoder)?;
	key(decoder, 10)?;
	let requested_durability = match decoder.u64()? {
		PROCESS_CRASH => ApplyRequestedDurability::ProcessCrash,
		_ => return Err(OwnerError::UnsupportedApplyDurability),
	};
	Ok(PublicApplyBinding {
		public_plan,
		public_entry,
		private_entry,
		epoch,
		source_root,
		destination_root,
		stream_length,
		stream_digest,
		metadata_policy,
		expires_at,
		requested_durability,
	})
}

fn decode_root(decoder: &mut Decoder<'_>) -> Result<RootCapabilityId, OwnerError> {
	RootCapabilityId::from_bytes(fixed_bytes(decoder)?).map_err(|_| OwnerError::InvalidApplyRoot)
}

fn decode_expiry(decoder: &mut Decoder<'_>) -> Result<Option<OwnerTimestamp>, OwnerError> {
	if decoder.datatype()? == Type::Null {
		decoder.null()?;
		return Ok(None);
	}
	if decoder.array()? != Some(2) {
		return Err(OwnerError::InvalidCbor);
	}
	let seconds = decoder.i64()?;
	let nanos = u32::try_from(decoder.u64()?).map_err(|_| OwnerError::InvalidTimestamp)?;
	Ok(Some(OwnerTimestamp::new(seconds, nanos)?))
}
