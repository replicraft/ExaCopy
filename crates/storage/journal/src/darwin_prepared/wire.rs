use core::num::{NonZeroU32, NonZeroU64};

use minicbor::data::Type;
use minicbor::encode::{self, Write};
use minicbor::{Decoder, Encoder};

use crate::prepared::wire::{expect_key, expect_map, read_fixed};
use crate::{
	DarwinFileIdentity, DarwinVolumeIdentity, JournalContext, JournalEntryId, JournalEpoch,
	JournalJobId, OwnerTimestamp, PlanDigest, PreparedError,
};

const VERSION_MAJOR: u64 = 2;
const VERSION_MINOR: u64 = 0;
const MANAGED_APFS_REQUIRED: u64 = 1;
const DARWIN_PLATFORM: u64 = 2;

pub(crate) fn write_header<W: Write>(
	encoder: &mut Encoder<W>,
	context: JournalContext,
	entry: Option<JournalEntryId>,
) -> Result<(), encode::Error<W::Error>> {
	write_prefix(
		encoder,
		context.job,
		context.epoch,
		if entry.is_some() { 7 } else { 6 },
	)?;
	if let Some(entry) = entry {
		encoder.u8(3)?.bytes(entry.as_bytes())?;
	}
	write_suffix(encoder, context.plan_digest)
}

fn write_prefix<W: Write>(
	encoder: &mut Encoder<W>,
	job: JournalJobId,
	epoch: JournalEpoch,
	fields: u64,
) -> Result<(), encode::Error<W::Error>> {
	encoder.map(fields)?.u8(0)?;
	write_version(encoder)?;
	encoder
		.u8(1)?
		.bytes(job.as_bytes())?
		.u8(2)?
		.u64(epoch.get())?;
	Ok(())
}

fn write_suffix<W: Write>(
	encoder: &mut Encoder<W>,
	plan_digest: PlanDigest,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.u8(5)?
		.bytes(plan_digest.as_bytes())?
		.u8(6)?
		.u64(MANAGED_APFS_REQUIRED)?
		.u8(10)?;
	Ok(())
}

pub(crate) fn write_version<W: Write>(
	encoder: &mut Encoder<W>,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.map(3)?
		.u8(0)?
		.u64(VERSION_MAJOR)?
		.u8(1)?
		.u64(VERSION_MINOR)?
		.u8(2)?
		.u64(MANAGED_APFS_REQUIRED)?;
	Ok(())
}

pub(crate) fn read_job_header(decoder: &mut Decoder<'_>) -> Result<JournalContext, PreparedError> {
	let (job, epoch) = read_prefix(decoder, 6)?;
	read_suffix(decoder, job, epoch)
}

pub(crate) fn read_entry_header(
	decoder: &mut Decoder<'_>,
) -> Result<(JournalContext, JournalEntryId), PreparedError> {
	let (job, epoch) = read_prefix(decoder, 7)?;
	expect_key(decoder, 3)?;
	let entry = JournalEntryId::from_bytes(read_fixed(decoder)?);
	Ok((read_suffix(decoder, job, epoch)?, entry))
}

fn read_prefix(
	decoder: &mut Decoder<'_>,
	fields: u64,
) -> Result<(JournalJobId, JournalEpoch), PreparedError> {
	expect_map(decoder, fields)?;
	expect_key(decoder, 0)?;
	read_version(decoder)?;
	expect_key(decoder, 1)?;
	let job = JournalJobId::from_bytes(read_fixed(decoder)?).map_err(PreparedError::InvalidJob)?;
	expect_key(decoder, 2)?;
	Ok((job, JournalEpoch::new(decoder.u64()?)))
}

fn read_suffix(
	decoder: &mut Decoder<'_>,
	job: JournalJobId,
	epoch: JournalEpoch,
) -> Result<JournalContext, PreparedError> {
	expect_key(decoder, 5)?;
	let plan_digest = PlanDigest::from_bytes(read_fixed(decoder)?);
	expect_key(decoder, 6)?;
	read_features(decoder)?;
	expect_key(decoder, 10)?;
	Ok(JournalContext {
		job,
		epoch,
		plan_digest,
	})
}

pub(crate) fn read_version(decoder: &mut Decoder<'_>) -> Result<(), PreparedError> {
	expect_map(decoder, 3)?;
	expect_key(decoder, 0)?;
	let major = decoder.u64()?;
	expect_key(decoder, 1)?;
	let minor = decoder.u64()?;
	if (major, minor) != (VERSION_MAJOR, VERSION_MINOR) {
		return Err(PreparedError::UnsupportedVersion);
	}
	expect_key(decoder, 2)?;
	read_features(decoder)
}

fn read_features(decoder: &mut Decoder<'_>) -> Result<(), PreparedError> {
	if decoder.u64()? != MANAGED_APFS_REQUIRED {
		return Err(PreparedError::UnsupportedFeatures);
	}
	Ok(())
}

// This is the same native identity shape as the signed Darwin owner body.
pub(crate) fn write_identity<W: Write>(
	encoder: &mut Encoder<W>,
	identity: DarwinFileIdentity,
) -> Result<(), encode::Error<W::Error>> {
	let volume = identity.volume();
	let [first, second] = volume.physical_fsid();
	encoder
		.map(4)?
		.u8(0)?
		.map(3)?
		.u8(0)?
		.u64(DARWIN_PLATFORM)?
		.u8(1)?
		.bytes(&volume.device().to_le_bytes())?
		.u8(2)?
		.array(2)?
		.u32(first)?
		.u32(second)?
		.u8(1)?
		.bytes(&identity.inode().get().to_le_bytes())?
		.u8(2)?;
	match identity.generation() {
		Some(generation) => encoder.u32(generation.get())?,
		None => encoder.null()?,
	};
	encoder.u8(3)?;
	write_timestamp(encoder, identity.birth())
}

pub(crate) fn read_identity(
	decoder: &mut Decoder<'_>,
) -> Result<DarwinFileIdentity, PreparedError> {
	expect_map(decoder, 4)?;
	expect_key(decoder, 0)?;
	let volume = read_volume(decoder)?;
	expect_key(decoder, 1)?;
	let inode = NonZeroU64::new(u64::from_le_bytes(read_fixed(decoder)?))
		.ok_or(PreparedError::UnsupportedIdentity)?;
	expect_key(decoder, 2)?;
	let generation = if decoder.datatype()? == Type::Null {
		decoder.null()?;
		None
	} else {
		let generation =
			NonZeroU32::new(decoder.u32()?).ok_or(PreparedError::UnsupportedIdentity)?;
		Some(generation)
	};
	expect_key(decoder, 3)?;
	let birth = read_timestamp(decoder)?;
	Ok(DarwinFileIdentity::new(volume, inode, generation, birth))
}

fn read_volume(decoder: &mut Decoder<'_>) -> Result<DarwinVolumeIdentity, PreparedError> {
	expect_map(decoder, 3)?;
	expect_key(decoder, 0)?;
	if decoder.u64()? != DARWIN_PLATFORM {
		return Err(PreparedError::UnsupportedIdentity);
	}
	expect_key(decoder, 1)?;
	let device = i32::from_le_bytes(read_fixed(decoder)?);
	expect_key(decoder, 2)?;
	if decoder.array()? != Some(2) {
		return Err(PreparedError::UnsupportedIdentity);
	}
	DarwinVolumeIdentity::new(device, [decoder.u32()?, decoder.u32()?])
		.map_err(|_| PreparedError::UnsupportedIdentity)
}

pub(crate) fn write_timestamp<W: Write>(
	encoder: &mut Encoder<W>,
	timestamp: OwnerTimestamp,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.map(2)?
		.u8(0)?
		.i64(timestamp.seconds())?
		.u8(1)?
		.u32(timestamp.nanoseconds())?;
	Ok(())
}

pub(crate) fn read_timestamp(decoder: &mut Decoder<'_>) -> Result<OwnerTimestamp, PreparedError> {
	expect_map(decoder, 2)?;
	expect_key(decoder, 0)?;
	let seconds = decoder.i64()?;
	expect_key(decoder, 1)?;
	let nanoseconds = decoder.u32()?;
	OwnerTimestamp::new(seconds, nanoseconds).map_err(|_| PreparedError::InvalidTimestamp)
}

pub(super) fn write_root<W: Write>(
	encoder: &mut Encoder<W>,
	root: super::DarwinRootBinding,
) -> Result<(), encode::Error<W::Error>> {
	encoder.map(2)?.u8(0)?.bytes(root.id.as_bytes())?.u8(1)?;
	write_identity(encoder, root.identity)
}

pub(super) fn read_root(
	decoder: &mut Decoder<'_>,
) -> Result<super::DarwinRootBinding, PreparedError> {
	expect_map(decoder, 2)?;
	expect_key(decoder, 0)?;
	let id = crate::RootCapabilityId::from_bytes(read_fixed(decoder)?)?;
	expect_key(decoder, 1)?;
	let identity = read_identity(decoder)?;
	Ok(super::DarwinRootBinding { id, identity })
}
