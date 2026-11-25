use core::num::NonZeroU32;

use exacopy_endpoint::UnixComponent;
use minicbor::encode::{self, Write};
use minicbor::{Decoder, Encoder};

use super::super::wire::{
	read_identity, read_root, read_timestamp, write_identity, write_root, write_timestamp,
};
use super::super::{
	DarwinPreparedError, DarwinRootBinding, DarwinSourceMetadata, DarwinSourceTimes,
	DarwinSourceView, DarwinStageId, DarwinStageObservation,
};
use super::{DarwinEntryPreparation, DarwinEntryPrepared};
use crate::prepared::wire::{expect_key, expect_map, read_fixed};
use crate::{
	DarwinFileIdentity, JournalContext, JournalEntryId, OwnerDigest, PreparedError,
	TargetObservation,
};

const RAW_UNIX_BYTES: u64 = 1;
const LIVE_OBSERVED: u64 = 0;
const ABSENT_OBSERVED: u64 = 0;

pub(super) fn write_body<W: Write>(
	encoder: &mut Encoder<W>,
	record: &DarwinEntryPrepared<'_>,
) -> Result<(), encode::Error<W::Error>> {
	let preparation = record.preparation;
	encoder.map(4)?.u8(0)?;
	write_source(encoder, preparation.source)?;
	encoder.u8(1)?;
	write_stage(encoder, preparation.stage)?;
	encoder.u8(2)?.map(2)?.u8(0)?;
	write_root(encoder, record.destination_root)?;
	encoder.u8(1)?;
	write_component(encoder, preparation.target_component)?;
	encoder
		.u8(3)?
		.map(3)?
		.u8(0)?
		.bytes(record.owner_digest.as_bytes())?
		.u8(1)?;
	write_metadata(encoder, preparation.source.metadata())?;
	let observation = match preparation.target_observation {
		TargetObservation::AbsentObserved => ABSENT_OBSERVED,
	};
	encoder.u8(2)?.u64(observation)?;
	Ok(())
}

pub(super) fn read_body<'a>(
	decoder: &mut Decoder<'a>,
	context: JournalContext,
	entry: JournalEntryId,
) -> Result<DarwinEntryPrepared<'a>, DarwinPreparedError> {
	expect_map(decoder, 4)?;
	expect_key(decoder, 0)?;
	let source = read_source(decoder)?;
	expect_key(decoder, 1)?;
	let stage = read_stage(decoder)?;
	expect_key(decoder, 2)?;
	expect_map(decoder, 2)?;
	expect_key(decoder, 0)?;
	let destination_root = read_root(decoder)?;
	expect_key(decoder, 1)?;
	let target_component = read_component(decoder)?;
	expect_key(decoder, 3)?;
	expect_map(decoder, 3)?;
	expect_key(decoder, 0)?;
	let owner_digest = OwnerDigest::from_bytes(read_fixed(decoder)?);
	expect_key(decoder, 1)?;
	let metadata = read_metadata(decoder)?;
	expect_key(decoder, 2)?;
	if decoder.u64()? != ABSENT_OBSERVED {
		return Err(PreparedError::UnsupportedTargetObservation.into());
	}
	let source = DarwinSourceView::new(
		source.root,
		source.component,
		source.identity,
		source.length,
		source.times,
		metadata,
	)?;
	let preparation = DarwinEntryPreparation {
		source,
		stage,
		target_component,
		target_observation: TargetObservation::AbsentObserved,
	};
	Ok(DarwinEntryPrepared {
		context,
		entry,
		owner_digest,
		destination_root,
		preparation,
	})
}

fn write_source<W: Write>(
	encoder: &mut Encoder<W>,
	source: DarwinSourceView<'_>,
) -> Result<(), encode::Error<W::Error>> {
	encoder.map(8)?.u8(0)?.u64(LIVE_OBSERVED)?.u8(1)?;
	write_identity(encoder, source.identity())?;
	encoder.u8(2)?.u64(source.length())?.u8(3)?;
	let times = source.times();
	write_timestamp(encoder, times.accessed_at)?;
	encoder.u8(4)?;
	write_timestamp(encoder, times.modified_at)?;
	encoder.u8(5)?;
	write_timestamp(encoder, times.changed_at)?;
	encoder.u8(6)?;
	write_root(encoder, source.root())?;
	encoder.u8(7)?;
	write_component(encoder, source.component())
}

// The remaining source metadata follows stage and target in the wire body.
struct SourceFields<'a> {
	root: DarwinRootBinding,
	component: UnixComponent<'a>,
	identity: DarwinFileIdentity,
	length: u64,
	times: DarwinSourceTimes,
}

fn read_source<'a>(decoder: &mut Decoder<'a>) -> Result<SourceFields<'a>, DarwinPreparedError> {
	expect_map(decoder, 8)?;
	expect_key(decoder, 0)?;
	if decoder.u64()? != LIVE_OBSERVED {
		return Err(PreparedError::UnsupportedSourceView.into());
	}
	expect_key(decoder, 1)?;
	let identity = read_identity(decoder)?;
	expect_key(decoder, 2)?;
	let length = decoder.u64()?;
	expect_key(decoder, 3)?;
	let accessed_at = read_timestamp(decoder)?;
	expect_key(decoder, 4)?;
	let modified_at = read_timestamp(decoder)?;
	expect_key(decoder, 5)?;
	let changed_at = read_timestamp(decoder)?;
	expect_key(decoder, 6)?;
	let root = read_root(decoder)?;
	expect_key(decoder, 7)?;
	let component = read_component(decoder)?;
	let times = DarwinSourceTimes {
		accessed_at,
		modified_at,
		changed_at,
	};
	Ok(SourceFields {
		root,
		component,
		identity,
		length,
		times,
	})
}

fn write_stage<W: Write>(
	encoder: &mut Encoder<W>,
	stage: DarwinStageObservation<'_>,
) -> Result<(), encode::Error<W::Error>> {
	encoder.map(4)?.u8(0)?.bytes(stage.id.as_bytes())?.u8(1)?;
	write_identity(encoder, stage.directory)?;
	encoder.u8(2)?;
	write_identity(encoder, stage.identity)?;
	encoder.u8(3)?;
	write_component(encoder, stage.component)
}

fn read_stage<'a>(
	decoder: &mut Decoder<'a>,
) -> Result<DarwinStageObservation<'a>, DarwinPreparedError> {
	expect_map(decoder, 4)?;
	expect_key(decoder, 0)?;
	let id = DarwinStageId::from_bytes(read_fixed(decoder)?);
	expect_key(decoder, 1)?;
	let directory = read_identity(decoder)?;
	expect_key(decoder, 2)?;
	let identity = read_identity(decoder)?;
	expect_key(decoder, 3)?;
	let component = read_component(decoder)?;
	Ok(DarwinStageObservation {
		id,
		directory,
		identity,
		component,
	})
}

fn write_component<W: Write>(
	encoder: &mut Encoder<W>,
	component: UnixComponent<'_>,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.map(2)?
		.u8(0)?
		.u64(RAW_UNIX_BYTES)?
		.u8(1)?
		.bytes(component.as_bytes())?;
	Ok(())
}

fn read_component<'a>(decoder: &mut Decoder<'a>) -> Result<UnixComponent<'a>, DarwinPreparedError> {
	expect_map(decoder, 2)?;
	expect_key(decoder, 0)?;
	if decoder.u64()? != RAW_UNIX_BYTES {
		return Err(PreparedError::UnsupportedTargetEncoding.into());
	}
	expect_key(decoder, 1)?;
	UnixComponent::new(decoder.bytes()?).map_err(DarwinPreparedError::InvalidComponent)
}

fn write_metadata<W: Write>(
	encoder: &mut Encoder<W>,
	metadata: DarwinSourceMetadata,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.map(3)?
		.u8(0)?
		.u32(metadata.mode())?
		.u8(1)?
		.u32(metadata.owner().get())?
		.u8(2)?
		.u32(metadata.group())?;
	Ok(())
}

fn read_metadata(decoder: &mut Decoder<'_>) -> Result<DarwinSourceMetadata, PreparedError> {
	expect_map(decoder, 3)?;
	expect_key(decoder, 0)?;
	let mode = decoder.u32()?;
	expect_key(decoder, 1)?;
	let owner = NonZeroU32::new(decoder.u32()?).ok_or(PreparedError::UnsupportedSourceMetadata)?;
	expect_key(decoder, 2)?;
	let group = decoder.u32()?;
	DarwinSourceMetadata::new(mode, owner, group)
}
