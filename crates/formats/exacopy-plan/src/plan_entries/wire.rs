//! Numeric field allocation from the public document-page registry.

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use uuid::Uuid;

use crate::cbor::{BodyBytes, EncodeError, canonical_bytes};
use crate::document::{
	DocumentError, DocumentPageKind, expect_key, expect_map, expect_versioned_map, fixed_bytes,
};
use crate::plan_identity::{read_identity, write_identity};
use crate::portable::{BLAKE3_CODE, REGULAR_CODE, UNIX_BYTES_CODE};

use super::{PlanEntry, PlanPath};

const VERSION: [u8; 2] = [1, 0];
const LEAF_LEVEL: u8 = 0;
const CREATE_NEW_CODE: u8 = 0;
const SINGLE_ITEM: u64 = 1;

pub(super) fn encode(entry: PlanEntry<'_>) -> Vec<u8> {
	canonical_bytes(|encoder| {
		encoder
			.map(6)?
			.u8(0)?
			.array(2)?
			.u8(VERSION[0])?
			.u8(VERSION[1])?
			.u8(1)?
			.u16(DocumentPageKind::PlanEntries as u16)?
			.u8(2)?
			.u8(LEAF_LEVEL)?
			.u8(3)?
			.array(SINGLE_ITEM)?;
		write_entry(encoder, entry)?;
		encoder.u8(4)?.array(0)?.u8(5)?.u64(SINGLE_ITEM)?;
		Ok(())
	})
}

fn write_entry(encoder: &mut Encoder<BodyBytes>, entry: PlanEntry<'_>) -> Result<(), EncodeError> {
	encoder
		.map(12)?
		.u8(0)?
		.bytes(entry.entry_id.as_bytes())?
		.u8(1)?;
	write_path(encoder, entry.source)?;
	encoder.u8(2)?;
	write_path(encoder, entry.destination)?;
	encoder
		.u8(3)?
		.u8(REGULAR_CODE)?
		.u8(4)?
		.bytes(entry.source_view_id.as_bytes())?
		.u8(5)?;
	write_identity(encoder, entry.source_identity)?;
	encoder
		.u8(6)?
		.null()?
		.u8(7)?
		.array(SINGLE_ITEM)?
		.map(4)?
		.u8(0)?
		.bytes(b"")?
		.u8(1)?
		.u64(entry.stream_length)?
		.u8(2)?
		.u8(BLAKE3_CODE)?
		.u8(3)?
		.bytes(&entry.stream_digest)?
		.u8(8)?
		.bytes(&entry.metadata_policy_digest)?
		.u8(9)?
		.u8(CREATE_NEW_CODE)?
		.u8(10)?
		.null()?
		.u8(11)?
		.u64(entry.estimated_working_bytes)?;
	Ok(())
}

fn write_path(encoder: &mut Encoder<BodyBytes>, path: PlanPath<'_>) -> Result<(), EncodeError> {
	encoder
		.map(2)?
		.u8(0)?
		.bytes(path.root_id.as_bytes())?
		.u8(1)?
		.array(SINGLE_ITEM)?
		.map(2)?
		.u8(0)?
		.u8(UNIX_BYTES_CODE)?
		.u8(1)?
		.bytes(path.basename)?;
	Ok(())
}

pub(super) fn decode(input: &[u8]) -> Result<PlanEntry<'_>, DocumentError> {
	let mut decoder = Decoder::new(input);
	expect_versioned_map(&mut decoder, 6, VERSION)?;
	expect_key(&mut decoder, 1)?;
	if decoder.u16()? != DocumentPageKind::PlanEntries as u16 {
		return Err(DocumentError::WrongKind);
	}
	expect_key(&mut decoder, 2)?;
	expect_code(&mut decoder, LEAF_LEVEL)?;
	expect_key(&mut decoder, 3)?;
	expect_array(&mut decoder, SINGLE_ITEM)?;
	let entry = read_entry(&mut decoder)?;
	expect_key(&mut decoder, 4)?;
	expect_array(&mut decoder, 0)?;
	expect_key(&mut decoder, 5)?;
	if decoder.u64()? != SINGLE_ITEM {
		return Err(DocumentError::CountMismatch);
	}
	Ok(entry)
}

fn read_entry<'page>(decoder: &mut Decoder<'page>) -> Result<PlanEntry<'page>, DocumentError> {
	expect_map(decoder, 12)?;
	expect_key(decoder, 0)?;
	let entry_id = Uuid::from_bytes(fixed_bytes(decoder)?);
	expect_key(decoder, 1)?;
	let source = read_path(decoder)?;
	expect_key(decoder, 2)?;
	let destination = read_path(decoder)?;
	expect_key(decoder, 3)?;
	expect_code(decoder, REGULAR_CODE)?;
	expect_key(decoder, 4)?;
	let source_view_id = Uuid::from_bytes(fixed_bytes(decoder)?);
	expect_key(decoder, 5)?;
	let source_identity = read_identity(decoder)?;
	expect_key(decoder, 6)?;
	expect_null(decoder)?;
	expect_key(decoder, 7)?;
	let (stream_length, stream_digest) = read_stream(decoder)?;
	expect_key(decoder, 8)?;
	let metadata_policy_digest = fixed_bytes(decoder)?;
	expect_key(decoder, 9)?;
	expect_code(decoder, CREATE_NEW_CODE)?;
	expect_key(decoder, 10)?;
	expect_null(decoder)?;
	expect_key(decoder, 11)?;
	let estimated_working_bytes = decoder.u64()?;
	Ok(PlanEntry {
		entry_id,
		source,
		destination,
		source_view_id,
		source_identity,
		stream_length,
		stream_digest,
		metadata_policy_digest,
		estimated_working_bytes,
	})
}

fn read_path<'page>(decoder: &mut Decoder<'page>) -> Result<PlanPath<'page>, DocumentError> {
	expect_map(decoder, 2)?;
	expect_key(decoder, 0)?;
	let root_id = Uuid::from_bytes(fixed_bytes(decoder)?);
	expect_key(decoder, 1)?;
	expect_array(decoder, SINGLE_ITEM)?;
	expect_map(decoder, 2)?;
	expect_key(decoder, 0)?;
	expect_code(decoder, UNIX_BYTES_CODE)?;
	expect_key(decoder, 1)?;
	let basename = decoder.bytes()?;
	Ok(PlanPath { root_id, basename })
}

fn read_stream(decoder: &mut Decoder<'_>) -> Result<(u64, [u8; 32]), DocumentError> {
	expect_array(decoder, SINGLE_ITEM)?;
	expect_map(decoder, 4)?;
	expect_key(decoder, 0)?;
	if !decoder.bytes()?.is_empty() {
		return Err(DocumentError::Unsupported);
	}
	expect_key(decoder, 1)?;
	let length = decoder.u64()?;
	expect_key(decoder, 2)?;
	expect_code(decoder, BLAKE3_CODE)?;
	expect_key(decoder, 3)?;
	Ok((length, fixed_bytes(decoder)?))
}

fn expect_array(decoder: &mut Decoder<'_>, length: u64) -> Result<(), DocumentError> {
	if decoder.array()? == Some(length) {
		Ok(())
	} else {
		Err(DocumentError::Unsupported)
	}
}

fn expect_code(decoder: &mut Decoder<'_>, code: u8) -> Result<(), DocumentError> {
	if decoder.u8()? == code {
		Ok(())
	} else {
		Err(DocumentError::Unsupported)
	}
}

fn expect_null(decoder: &mut Decoder<'_>) -> Result<(), DocumentError> {
	if decoder.datatype()? != Type::Null {
		return Err(DocumentError::Unsupported);
	}
	decoder.null()?;
	Ok(())
}
