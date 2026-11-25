use std::num::{NonZeroU32, NonZeroU64};

use minicbor::data::Type;
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

use crate::{JournalJobId, PlanDigest};

use super::codec::{
	BodyBytes, MAX_BODY_BYTES, decode_timestamp, encoded_bytes, finish, fixed_bytes, key, map,
};
use super::{
	DarwinFileIdentity, DarwinOwnerManifest, DarwinVolumeIdentity, OwnerError, OwnerProfileId,
	OwnerStateDirectory, OwnerTimestamp, OwnerToken,
};

const FORMAT_MAJOR: u64 = 2;
const FORMAT_MINOR: u64 = 0;
const MANAGED_APFS_REQUIRED: u64 = 1;
const DARWIN_PLATFORM: u64 = 2;
const PRESERVE_POLICY: u64 = 0;

const DIRECTORY_COUNT: u64 = 3;
const DIRECTORIES: [OwnerStateDirectory; DIRECTORY_COUNT as usize] = [
	OwnerStateDirectory::Journal,
	OwnerStateDirectory::Receipts,
	OwnerStateDirectory::Stage,
];

pub(super) fn encode_body(
	manifest: &DarwinOwnerManifest,
	public_key: &[u8; 32],
) -> Result<BodyBytes, OwnerError> {
	let mut encoder = Encoder::new(Cursor::new([0; MAX_BODY_BYTES]));
	encoder
		.map(12)?
		.u64(0)?
		.map(3)?
		.u64(0)?
		.u64(FORMAT_MAJOR)?
		.u64(1)?
		.u64(FORMAT_MINOR)?
		.u64(2)?
		.u64(MANAGED_APFS_REQUIRED)?
		.u64(1)?
		.bytes(manifest.token.as_bytes())?
		.u64(2)?
		.bytes(manifest.job.as_bytes())?
		.u64(3)?
		.bytes(manifest.profile.as_bytes())?
		.u64(4)?
		.bytes(public_key)?
		.u64(5)?;
	encode_timestamp(&mut encoder, manifest.created)?;
	encoder.u64(6)?;
	encode_volume(&mut encoder, manifest.destination_volume)?;
	encoder.u64(7)?;
	encode_inode(&mut encoder, manifest.state_root)?;
	encoder
		.u64(8)?
		.bytes(manifest.plan_digest.as_bytes())?
		.u64(9)?
		.u64(PRESERVE_POLICY)?
		.u64(10)?
		.array(DIRECTORY_COUNT)?;
	for directory in DIRECTORIES {
		encoder.str(directory.name())?;
	}
	encoder.u64(11)?.u32(manifest.state_root_uid.get())?;
	Ok(encoder.into_writer())
}

pub(super) fn decode_body(
	bytes: &[u8],
	expected_key: &[u8; 32],
) -> Result<DarwinOwnerManifest, OwnerError> {
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 12)?;
	key(&mut decoder, 0)?;
	decode_version(&mut decoder)?;
	key(&mut decoder, 1)?;
	let token = OwnerToken::from_bytes(fixed_bytes(&mut decoder)?)?;
	key(&mut decoder, 2)?;
	let job =
		JournalJobId::from_bytes(fixed_bytes(&mut decoder)?).map_err(|_| OwnerError::InvalidJob)?;
	key(&mut decoder, 3)?;
	let profile = OwnerProfileId::from_bytes(fixed_bytes(&mut decoder)?)?;
	key(&mut decoder, 4)?;
	if fixed_bytes::<32>(&mut decoder)? != *expected_key {
		return Err(OwnerError::UntrustedKey);
	}
	key(&mut decoder, 5)?;
	let created = decode_timestamp(&mut decoder)?;
	key(&mut decoder, 6)?;
	let destination_volume = decode_volume(&mut decoder)?;
	key(&mut decoder, 7)?;
	let state_root = decode_inode(&mut decoder)?;
	key(&mut decoder, 8)?;
	let plan_digest = PlanDigest::from_bytes(fixed_bytes(&mut decoder)?);
	key(&mut decoder, 9)?;
	if decoder.u64()? != PRESERVE_POLICY {
		return Err(OwnerError::UnsupportedPolicy);
	}
	key(&mut decoder, 10)?;
	decode_directories(&mut decoder)?;
	key(&mut decoder, 11)?;
	let state_root_uid = NonZeroU32::new(decoder.u32()?).ok_or(OwnerError::InvalidOwnerUid)?;
	finish(decoder)?;
	let manifest = DarwinOwnerManifest {
		token,
		job,
		profile,
		created,
		destination_volume,
		state_root,
		state_root_uid,
		plan_digest,
	};
	manifest.validate()?;
	if encoded_bytes(&encode_body(&manifest, expected_key)?) != bytes {
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
	let required = decoder.u64()?;
	if (major, minor, required) != (FORMAT_MAJOR, FORMAT_MINOR, MANAGED_APFS_REQUIRED) {
		return Err(OwnerError::UnsupportedVersion);
	}
	Ok(())
}

fn encode_timestamp(
	encoder: &mut Encoder<BodyBytes>,
	timestamp: OwnerTimestamp,
) -> Result<(), OwnerError> {
	encoder
		.map(2)?
		.u64(0)?
		.i64(timestamp.seconds())?
		.u64(1)?
		.u32(timestamp.nanoseconds())?;
	Ok(())
}

// Device uses four little-endian signed bytes. The FSID is an ordered pair of
// CBOR uint32 words so the wire order stays independent of machine endianness.
fn encode_volume(
	encoder: &mut Encoder<BodyBytes>,
	volume: DarwinVolumeIdentity,
) -> Result<(), OwnerError> {
	let [first, second] = volume.physical_fsid();
	encoder
		.map(3)?
		.u64(0)?
		.u64(DARWIN_PLATFORM)?
		.u64(1)?
		.bytes(&volume.device().to_le_bytes())?
		.u64(2)?
		.array(2)?
		.u32(first)?
		.u32(second)?;
	Ok(())
}

fn decode_volume(decoder: &mut Decoder<'_>) -> Result<DarwinVolumeIdentity, OwnerError> {
	map(decoder, 3)?;
	key(decoder, 0)?;
	if decoder.u64()? != DARWIN_PLATFORM {
		return Err(OwnerError::UnsupportedIdentity);
	}
	key(decoder, 1)?;
	let device = i32::from_le_bytes(fixed_bytes(decoder)?);
	key(decoder, 2)?;
	if decoder.array()? != Some(2) {
		return Err(OwnerError::UnsupportedIdentity);
	}
	DarwinVolumeIdentity::new(device, [decoder.u32()?, decoder.u32()?])
}

fn encode_inode(
	encoder: &mut Encoder<BodyBytes>,
	identity: DarwinFileIdentity,
) -> Result<(), OwnerError> {
	encoder.map(4)?.u64(0)?;
	encode_volume(encoder, identity.volume())?;
	encoder
		.u64(1)?
		.bytes(&identity.inode().get().to_le_bytes())?
		.u64(2)?;
	match identity.generation() {
		Some(generation) => encoder.u32(generation.get())?,
		None => encoder.null()?,
	};
	encoder.u64(3)?;
	encode_timestamp(encoder, identity.birth())
}

fn decode_inode(decoder: &mut Decoder<'_>) -> Result<DarwinFileIdentity, OwnerError> {
	map(decoder, 4)?;
	key(decoder, 0)?;
	let volume = decode_volume(decoder)?;
	key(decoder, 1)?;
	let inode = NonZeroU64::new(u64::from_le_bytes(fixed_bytes(decoder)?))
		.ok_or(OwnerError::UnsupportedIdentity)?;
	key(decoder, 2)?;
	let generation = if decoder.datatype()? == Type::Null {
		decoder.null()?;
		None
	} else {
		let value = decoder.u32().map_err(|_| OwnerError::UnsupportedIdentity)?;
		Some(NonZeroU32::new(value).ok_or(OwnerError::UnsupportedIdentity)?)
	};
	key(decoder, 3)?;
	let birth = decode_timestamp(decoder)?;
	Ok(DarwinFileIdentity::new(volume, inode, generation, birth))
}

fn decode_directories(decoder: &mut Decoder<'_>) -> Result<(), OwnerError> {
	if decoder.array()? != Some(DIRECTORY_COUNT) {
		return Err(OwnerError::InvalidDirectories);
	}
	for directory in DIRECTORIES {
		if decoder.str()? != directory.name() {
			return Err(OwnerError::InvalidDirectories);
		}
	}
	Ok(())
}
