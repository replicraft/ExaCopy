//! Exact CBOR layout for the workflow leaf and Linux owner-and-mode metadata.

use core::num::NonZeroU64;

use exacopy_core::UnixComponent;
use minicbor::encode::write::{Cursor, EndOfSlice};
use minicbor::{Decoder, Encoder};

use crate::portable::UNIX_BYTES_CODE;

use super::{
	ExpectedSelection, Identity, LeafError, LinuxOwnerMode, MAX_PAIRED_BASELINE_BYTES, Observation,
	PAIRED_BASELINE_KIND, PairedBaselineLeaf, SideEvidence,
};

const VERSION: [u8; 2] = [1, 0];
const LEAF_LEVEL: u8 = 0;
const MATCHED: u8 = 0;
const PRESENT: u8 = 2;
const LIVE_OBSERVED: u8 = 0;

type WireEncoder<'buf> = Encoder<Cursor<&'buf mut [u8]>>;
type EncodeError = minicbor::encode::Error<EndOfSlice>;

impl From<minicbor::decode::Error> for LeafError {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::Encoding
	}
}

pub(super) fn decode(input: &[u8]) -> Result<PairedBaselineLeaf<'_>, LeafError> {
	let mut decoder = Decoder::new(input);
	map(&mut decoder, 6)?;
	key(&mut decoder, 0)?;
	array(&mut decoder, 2)?;
	code(&mut decoder, VERSION[0])?;
	code(&mut decoder, VERSION[1])?;
	key(&mut decoder, 1)?;
	if decoder.u16()? != PAIRED_BASELINE_KIND {
		return Err(LeafError::WrongKind);
	}
	key(&mut decoder, 2)?;
	code(&mut decoder, LEAF_LEVEL)?;
	key(&mut decoder, 3)?;
	array(&mut decoder, 1)?;
	let leaf = decode_row(&mut decoder)?;
	key(&mut decoder, 4)?;
	array(&mut decoder, 0)?;
	key(&mut decoder, 5)?;
	code(&mut decoder, 1)?;
	if decoder.position() != input.len() {
		return Err(LeafError::NonCanonical);
	}
	Ok(leaf)
}

fn decode_row<'a>(decoder: &mut Decoder<'a>) -> Result<PairedBaselineLeaf<'a>, LeafError> {
	map(decoder, 6)?;
	key(decoder, 0)?;
	array(decoder, 1)?;
	map(decoder, 2)?;
	key(decoder, 0)?;
	code(decoder, UNIX_BYTES_CODE)?;
	key(decoder, 1)?;
	let name = UnixComponent::new(decoder.bytes()?).map_err(|_| LeafError::Encoding)?;
	key(decoder, 1)?;
	let left = decode_side(decoder)?;
	key(decoder, 2)?;
	let right = decode_side(decoder)?;
	key(decoder, 3)?;
	code(decoder, MATCHED)?;
	key(decoder, 4)?;
	decoder.null()?;
	key(decoder, 5)?;
	map(decoder, 3)?;
	key(decoder, 0)?;
	let scope_digest = digest(decoder)?;
	key(decoder, 1)?;
	let policy_digest = digest(decoder)?;
	key(decoder, 2)?;
	let scan = nonzero(decoder)?;
	Ok(PairedBaselineLeaf {
		selection: ExpectedSelection {
			roots: [left.measured.identity.root, right.measured.identity.root],
			name,
			scope_digest,
			policy_digest,
			scan,
		},
		sides: [left, right],
	})
}

fn decode_side(decoder: &mut Decoder<'_>) -> Result<SideEvidence, LeafError> {
	map(decoder, 8)?;
	key(decoder, 0)?;
	code(decoder, PRESENT)?;
	key(decoder, 1)?;
	let measured_identity = identity(decoder)?;
	key(decoder, 2)?;
	let length = decoder.u64()?;
	key(decoder, 3)?;
	let metadata_digest = digest(decoder)?;
	key(decoder, 4)?;
	let stream_digest = digest(decoder)?;
	key(decoder, 5)?;
	map(decoder, 6)?;
	key(decoder, 0)?;
	let measured = Observation {
		identity: measured_identity,
		position: nonzero(decoder)?,
		stability: {
			key(decoder, 1)?;
			digest(decoder)?
		},
	};
	key(decoder, 2)?;
	let position = nonzero(decoder)?;
	key(decoder, 3)?;
	let identity = identity(decoder)?;
	key(decoder, 4)?;
	let stability = digest(decoder)?;
	key(decoder, 5)?;
	code(decoder, LIVE_OBSERVED)?;
	key(decoder, 6)?;
	array(decoder, 0)?;
	key(decoder, 7)?;
	array(decoder, 3)?;
	let metadata = LinuxOwnerMode {
		mode: decoder.u16()?,
		uid: decoder.u32()?,
		gid: decoder.u32()?,
	};
	Ok(SideEvidence {
		measured,
		rechecked: Observation {
			identity,
			position,
			stability,
		},
		length,
		stream_digest,
		metadata,
		metadata_digest,
	})
}

fn identity(decoder: &mut Decoder<'_>) -> Result<Identity, LeafError> {
	array(decoder, 2)?;
	Ok(Identity {
		root: digest(decoder)?,
		file: digest(decoder)?,
	})
}

fn nonzero(decoder: &mut Decoder<'_>) -> Result<NonZeroU64, LeafError> {
	NonZeroU64::new(decoder.u64()?).ok_or(LeafError::InvalidEvidence)
}

fn digest(decoder: &mut Decoder<'_>) -> Result<[u8; 32], LeafError> {
	decoder.bytes()?.try_into().map_err(|_| LeafError::Encoding)
}

fn map(decoder: &mut Decoder<'_>, count: u64) -> Result<(), LeafError> {
	expect(decoder.map()? == Some(count))
}

fn array(decoder: &mut Decoder<'_>, count: u64) -> Result<(), LeafError> {
	expect(decoder.array()? == Some(count))
}

fn key(decoder: &mut Decoder<'_>, value: u8) -> Result<(), LeafError> {
	code(decoder, value)
}

fn code(decoder: &mut Decoder<'_>, value: u8) -> Result<(), LeafError> {
	expect(decoder.u8()? == value)
}

fn expect(matches: bool) -> Result<(), LeafError> {
	if matches {
		Ok(())
	} else {
		Err(LeafError::Encoding)
	}
}

pub(super) fn verify_canonical(
	input: &[u8],
	leaf: &PairedBaselineLeaf<'_>,
) -> Result<(), LeafError> {
	let mut canonical = [0; MAX_PAIRED_BASELINE_BYTES];
	if encode(leaf, &mut canonical)? == input {
		Ok(())
	} else {
		Err(LeafError::NonCanonical)
	}
}

pub(super) fn encode<'output>(
	leaf: &PairedBaselineLeaf<'_>,
	output: &'output mut [u8; MAX_PAIRED_BASELINE_BYTES],
) -> Result<&'output [u8], LeafError> {
	let mut encoder = Encoder::new(Cursor::new(output.as_mut_slice()));
	encode_leaf(&mut encoder, leaf).map_err(|_| LeafError::Size)?;
	let length = encoder.into_writer().position();
	output.get(..length).ok_or(LeafError::Size)
}

fn encode_leaf(
	encoder: &mut WireEncoder<'_>,
	leaf: &PairedBaselineLeaf<'_>,
) -> Result<(), EncodeError> {
	encoder
		.map(6)?
		.u8(0)?
		.array(2)?
		.u8(VERSION[0])?
		.u8(VERSION[1])?
		.u8(1)?
		.u16(PAIRED_BASELINE_KIND)?
		.u8(2)?
		.u8(LEAF_LEVEL)?
		.u8(3)?
		.array(1)?
		.map(6)?
		.u8(0)?
		.array(1)?
		.map(2)?
		.u8(0)?
		.u8(UNIX_BYTES_CODE)?
		.u8(1)?
		.bytes(leaf.selection.name.as_bytes())?
		.u8(1)?;
	encode_side(encoder, leaf.sides[0])?;
	encoder.u8(2)?;
	encode_side(encoder, leaf.sides[1])?;
	encoder
		.u8(3)?
		.u8(MATCHED)?
		.u8(4)?
		.null()?
		.u8(5)?
		.map(3)?
		.u8(0)?
		.bytes(&leaf.selection.scope_digest)?
		.u8(1)?
		.bytes(&leaf.selection.policy_digest)?
		.u8(2)?
		.u64(leaf.selection.scan.get())?
		.u8(4)?
		.array(0)?
		.u8(5)?
		.u8(1)?;
	Ok(())
}

fn encode_side(encoder: &mut WireEncoder<'_>, side: SideEvidence) -> Result<(), EncodeError> {
	encoder.map(8)?.u8(0)?.u8(PRESENT)?.u8(1)?;
	encode_identity(encoder, side.measured.identity)?;
	encoder
		.u8(2)?
		.u64(side.length)?
		.u8(3)?
		.bytes(&side.metadata_digest)?
		.u8(4)?
		.bytes(&side.stream_digest)?
		.u8(5)?
		.map(6)?
		.u8(0)?
		.u64(side.measured.position.get())?
		.u8(1)?
		.bytes(&side.measured.stability)?
		.u8(2)?
		.u64(side.rechecked.position.get())?
		.u8(3)?;
	encode_identity(encoder, side.rechecked.identity)?;
	encoder
		.u8(4)?
		.bytes(&side.rechecked.stability)?
		.u8(5)?
		.u8(LIVE_OBSERVED)?
		.u8(6)?
		.array(0)?
		.u8(7)?;
	write_metadata(encoder, side.metadata)
}

fn encode_identity(encoder: &mut WireEncoder<'_>, identity: Identity) -> Result<(), EncodeError> {
	encoder
		.array(2)?
		.bytes(&identity.root)?
		.bytes(&identity.file)?;
	Ok(())
}

pub(super) fn encode_metadata(
	metadata: LinuxOwnerMode,
	buffer: &mut [u8],
) -> Result<&[u8], LeafError> {
	let mut encoder = Encoder::new(Cursor::new(&mut *buffer));
	write_metadata(&mut encoder, metadata).map_err(|_| LeafError::Encoding)?;
	let length = encoder.into_writer().position();
	buffer.get(..length).ok_or(LeafError::Encoding)
}

fn write_metadata(encoder: &mut WireEncoder<'_>, meta: LinuxOwnerMode) -> Result<(), EncodeError> {
	encoder
		.array(3)?
		.u16(meta.mode)?
		.u32(meta.uid)?
		.u32(meta.gid)?;
	Ok(())
}
