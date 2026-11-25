use std::num::{NonZeroU32, NonZeroU64};

use exacopy_journal::{DarwinFileIdentity, DarwinVolumeIdentity, OwnerTimestamp};
use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use super::{
	DarwinCopyPlanError, EncodeError, MAX_TIMESTAMP_BYTES, MAX_UINT32_BYTES, PlanCursor,
	fixed_bytes,
};

const DARWIN_PLATFORM: u64 = 2;
const INODE_FIELDS: u64 = 4;
const VOLUME_FIELDS: u64 = 3;
const BIRTH_FIELDS: u64 = 2;
const FSID_WORDS: u64 = 2;

// Birth uses a two-key map with the same header width as a timestamp array.
const MAX_BIRTH_BYTES: usize = 2 + MAX_TIMESTAMP_BYTES;
const MAX_VOLUME_BYTES: usize = 1 + 3 + 1 + (1 + 4) + (1 + 2 * MAX_UINT32_BYTES);
pub(super) const MAX_IDENTITY_BYTES: usize =
	1 + 4 + MAX_VOLUME_BYTES + (1 + 8) + MAX_UINT32_BYTES + MAX_BIRTH_BYTES;

pub(super) fn write_identity(
	encoder: &mut Encoder<PlanCursor>,
	identity: DarwinFileIdentity,
) -> Result<(), EncodeError> {
	let volume = identity.volume();
	let [first, second] = volume.physical_fsid();
	encoder
		.map(INODE_FIELDS)?
		.u8(0)?
		.map(VOLUME_FIELDS)?
		.u8(0)?
		.u64(DARWIN_PLATFORM)?
		.u8(1)?
		.bytes(&volume.device().to_le_bytes())?
		.u8(2)?
		.array(FSID_WORDS)?
		.u32(first)?
		.u32(second)?
		.u8(1)?
		.bytes(&identity.inode().get().to_le_bytes())?
		.u8(2)?;
	match identity.generation() {
		Some(generation) => encoder.u32(generation.get())?,
		None => encoder.null()?,
	};
	let birth = identity.birth();
	encoder
		.u8(3)?
		.map(BIRTH_FIELDS)?
		.u8(0)?
		.i64(birth.seconds())?
		.u8(1)?
		.u32(birth.nanoseconds())?;
	Ok(())
}

pub(super) fn read_identity(
	decoder: &mut Decoder<'_>,
) -> Result<DarwinFileIdentity, DarwinCopyPlanError> {
	expect_map(decoder, INODE_FIELDS)?;
	expect_key(decoder, 0)?;
	let volume = read_volume(decoder)?;
	expect_key(decoder, 1)?;
	let inode = fixed_bytes(decoder, DarwinCopyPlanError::InvalidIdentity)?;
	let inode =
		NonZeroU64::new(u64::from_le_bytes(inode)).ok_or(DarwinCopyPlanError::InvalidIdentity)?;
	expect_key(decoder, 2)?;
	let generation = if decoder.datatype()? == Type::Null {
		decoder.null()?;
		None
	} else {
		Some(NonZeroU32::new(decoder.u32()?).ok_or(DarwinCopyPlanError::InvalidIdentity)?)
	};
	expect_key(decoder, 3)?;
	expect_map(decoder, BIRTH_FIELDS)?;
	expect_key(decoder, 0)?;
	let seconds = decoder.i64()?;
	expect_key(decoder, 1)?;
	let birth = OwnerTimestamp::new(seconds, decoder.u32()?)
		.map_err(|_| DarwinCopyPlanError::InvalidTimestamp)?;
	Ok(DarwinFileIdentity::new(volume, inode, generation, birth))
}

fn read_volume(decoder: &mut Decoder<'_>) -> Result<DarwinVolumeIdentity, DarwinCopyPlanError> {
	expect_map(decoder, VOLUME_FIELDS)?;
	expect_key(decoder, 0)?;
	if decoder.u64()? != DARWIN_PLATFORM {
		return Err(DarwinCopyPlanError::InvalidIdentity);
	}
	expect_key(decoder, 1)?;
	let device = i32::from_le_bytes(fixed_bytes(decoder, DarwinCopyPlanError::InvalidIdentity)?);
	expect_key(decoder, 2)?;
	if decoder.array()? != Some(FSID_WORDS) {
		return Err(DarwinCopyPlanError::InvalidShape);
	}
	DarwinVolumeIdentity::new(device, [decoder.u32()?, decoder.u32()?])
		.map_err(|_| DarwinCopyPlanError::InvalidIdentity)
}

fn expect_map(decoder: &mut Decoder<'_>, len: u64) -> Result<(), DarwinCopyPlanError> {
	match decoder.map()? {
		Some(actual) if actual == len => Ok(()),
		_ => Err(DarwinCopyPlanError::InvalidShape),
	}
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), DarwinCopyPlanError> {
	if decoder.u8()? != expected {
		return Err(DarwinCopyPlanError::InvalidShape);
	}
	Ok(())
}
