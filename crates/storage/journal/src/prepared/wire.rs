use minicbor::encode::{self, Write};
use minicbor::{Decoder, Encoder};

use super::PreparedError;
use crate::{
	JournalEntryId, JournalEpoch, JournalJobId, LinuxFileIdentity, PlanDigest, PublishIntentContext,
};

const VERSION_MAJOR: u16 = 1;
const VERSION_MINOR: u16 = 0;
const REQUIRED_FEATURES: u64 = 0;
const PLATFORM_LINUX: u64 = 1;

/// The shared journal job, run, and plan context for preparation and observation records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalContext {
	/// The job's RFC UUIDv7.
	pub job: JournalJobId,
	/// The run generation during the observation.
	pub epoch: JournalEpoch,
	/// The digest of the canonical plan.
	pub plan_digest: PlanDigest,
}

pub(crate) fn write_header<W: Write>(
	encoder: &mut Encoder<W>,
	context: &JournalContext,
	entry: Option<JournalEntryId>,
) -> Result<(), encode::Error<W::Error>> {
	write_header_prefix(
		encoder,
		context.job,
		context.epoch,
		if entry.is_some() { 7 } else { 6 },
	)?;
	if let Some(entry) = entry {
		encoder.u8(3)?.bytes(entry.as_bytes())?;
	}
	write_header_suffix(encoder, context.plan_digest)
}

pub(crate) fn write_effect_header<W: Write>(
	encoder: &mut Encoder<W>,
	context: &PublishIntentContext,
) -> Result<(), encode::Error<W::Error>> {
	write_header_prefix(encoder, context.job, context.epoch, 8)?;
	encoder
		.u8(3)?
		.bytes(context.entry.as_bytes())?
		.u8(4)?
		.u64(context.effect_sequence)?;
	write_header_suffix(encoder, context.plan_digest)
}

fn write_header_prefix<W: Write>(
	encoder: &mut Encoder<W>,
	job: JournalJobId,
	epoch: JournalEpoch,
	fields: u64,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.map(fields)?
		.u8(0)?
		.map(3)?
		.u8(0)?
		.u16(VERSION_MAJOR)?
		.u8(1)?
		.u16(VERSION_MINOR)?
		.u8(2)?
		.u64(REQUIRED_FEATURES)?
		.u8(1)?
		.bytes(job.as_bytes())?
		.u8(2)?
		.u64(epoch.get())?;
	Ok(())
}

fn write_header_suffix<W: Write>(
	encoder: &mut Encoder<W>,
	plan_digest: PlanDigest,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.u8(5)?
		.bytes(plan_digest.as_bytes())?
		.u8(6)?
		.u64(REQUIRED_FEATURES)?
		.u8(10)?;
	Ok(())
}

pub(super) fn read_job_header(decoder: &mut Decoder<'_>) -> Result<JournalContext, PreparedError> {
	let (job, epoch) = read_header_prefix(decoder, 6)?;
	read_header_suffix(decoder, job, epoch)
}

pub(crate) fn read_entry_header(
	decoder: &mut Decoder<'_>,
) -> Result<(JournalContext, JournalEntryId), PreparedError> {
	let (job, epoch) = read_header_prefix(decoder, 7)?;
	expect_key(decoder, 3)?;
	let entry = JournalEntryId::from_bytes(read_fixed(decoder)?);
	Ok((read_header_suffix(decoder, job, epoch)?, entry))
}

pub(crate) fn read_effect_header(
	decoder: &mut Decoder<'_>,
) -> Result<PublishIntentContext, PreparedError> {
	let (job, epoch) = read_header_prefix(decoder, 8)?;
	expect_key(decoder, 3)?;
	let entry = JournalEntryId::from_bytes(read_fixed(decoder)?);
	expect_key(decoder, 4)?;
	let effect_sequence = decoder.u64()?;
	let context = read_header_suffix(decoder, job, epoch)?;
	Ok(PublishIntentContext {
		job,
		epoch,
		entry,
		effect_sequence,
		plan_digest: context.plan_digest,
	})
}

fn read_header_prefix(
	decoder: &mut Decoder<'_>,
	fields: u64,
) -> Result<(JournalJobId, JournalEpoch), PreparedError> {
	expect_map(decoder, fields)?;
	expect_key(decoder, 0)?;
	expect_map(decoder, 3)?;
	expect_key(decoder, 0)?;
	let major = decoder.u16()?;
	expect_key(decoder, 1)?;
	let minor = decoder.u16()?;
	if major != VERSION_MAJOR || minor != VERSION_MINOR {
		return Err(PreparedError::UnsupportedVersion);
	}
	expect_key(decoder, 2)?;
	read_feature_bits(decoder)?;
	expect_key(decoder, 1)?;
	let job = JournalJobId::from_bytes(read_fixed(decoder)?).map_err(PreparedError::InvalidJob)?;
	expect_key(decoder, 2)?;
	let epoch = JournalEpoch::new(decoder.u64()?);
	Ok((job, epoch))
}

fn read_header_suffix(
	decoder: &mut Decoder<'_>,
	job: JournalJobId,
	epoch: JournalEpoch,
) -> Result<JournalContext, PreparedError> {
	expect_key(decoder, 5)?;
	let plan_digest = PlanDigest::from_bytes(read_fixed(decoder)?);
	expect_key(decoder, 6)?;
	read_feature_bits(decoder)?;
	expect_key(decoder, 10)?;
	Ok(JournalContext {
		job,
		epoch,
		plan_digest,
	})
}

fn read_feature_bits(decoder: &mut Decoder<'_>) -> Result<(), PreparedError> {
	if decoder.u64()? != REQUIRED_FEATURES {
		return Err(PreparedError::UnsupportedFeatures);
	}
	Ok(())
}

pub(crate) fn write_identity<W: Write>(
	encoder: &mut Encoder<W>,
	identity: LinuxFileIdentity,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.map(4)?
		.u8(0)?
		.u64(PLATFORM_LINUX)?
		.u8(1)?
		.bytes(&identity.device().to_le_bytes())?
		.u8(2)?
		.bytes(&identity.inode().to_le_bytes())?
		.u8(3)?
		.null()?;
	Ok(())
}

pub(crate) fn read_identity(decoder: &mut Decoder<'_>) -> Result<LinuxFileIdentity, PreparedError> {
	expect_map(decoder, 4)?;
	expect_key(decoder, 0)?;
	if decoder.u64()? != PLATFORM_LINUX {
		return Err(PreparedError::UnsupportedIdentity);
	}
	expect_key(decoder, 1)?;
	let device = u64::from_le_bytes(read_fixed(decoder)?);
	expect_key(decoder, 2)?;
	let inode = u64::from_le_bytes(read_fixed(decoder)?);
	expect_key(decoder, 3)?;
	decoder.null().map_err(|error| {
		if error.is_type_mismatch() {
			PreparedError::UnsupportedIdentity
		} else {
			error.into()
		}
	})?;
	Ok(LinuxFileIdentity::new(device, inode))
}

pub(crate) fn expect_map(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), PreparedError> {
	if decoder.map()? != Some(fields) {
		return Err(PreparedError::InvalidCbor);
	}
	Ok(())
}

pub(crate) fn expect_key(decoder: &mut Decoder<'_>, key: u64) -> Result<(), PreparedError> {
	if decoder.u64()? != key {
		return Err(PreparedError::InvalidCbor);
	}
	Ok(())
}

pub(super) fn expect_array(decoder: &mut Decoder<'_>, length: u64) -> Result<(), PreparedError> {
	if decoder.array()? != Some(length) {
		return Err(PreparedError::InvalidCbor);
	}
	Ok(())
}

pub(crate) fn read_fixed<const N: usize>(
	decoder: &mut Decoder<'_>,
) -> Result<[u8; N], PreparedError> {
	decoder
		.bytes()?
		.try_into()
		.map_err(|_| PreparedError::InvalidCbor)
}
