use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use super::RecoveryRecordError;
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{read_entry_header, read_fixed, write_header};
use crate::{JournalContext, JournalEntryId};

// The largest payload is kind 20, with a 93-byte header at maximum integer
// widths, three 44-byte frame references, three 25-byte Linux identities,
// a 46-byte stream measurement, and fewer than 20 additional keys and tags.
const MAX_RECOVERY_PAYLOAD_BYTES: usize = 384;

type Writer = Cursor<[u8; MAX_RECOVERY_PAYLOAD_BYTES]>;
pub(super) type PayloadEncoder = Encoder<Writer>;
pub(super) type WriteError = encode::Error<EndOfArray>;

pub(super) fn encode_record(
	context: &JournalContext,
	entry: JournalEntryId,
	body: impl FnOnce(&mut PayloadEncoder) -> Result<(), WriteError>,
) -> Vec<u8> {
	let mut encoder = Encoder::new(Cursor::new([0; MAX_RECOVERY_PAYLOAD_BYTES]));
	write_header(&mut encoder, context, Some(entry))
		.and_then(|()| body(&mut encoder))
		.expect("the validated recovery payload fits its fixed-size buffer");
	let writer = encoder.into_writer();
	writer.get_ref()[..writer.position()].to_vec()
}

pub(super) fn decode_record<T>(
	payload: &[u8],
	read_body: impl FnOnce(
		&mut Decoder<'_>,
		JournalContext,
		JournalEntryId,
	) -> Result<T, RecoveryRecordError>,
	encode: fn(&T) -> Vec<u8>,
) -> Result<T, RecoveryRecordError> {
	if payload.len() > MAX_RECOVERY_PAYLOAD_BYTES {
		return Err(RecoveryRecordError::PayloadTooLong);
	}
	let mut decoder = Decoder::new(payload);
	let (context, entry) = read_entry_header(&mut decoder)?;
	let record = read_body(&mut decoder, context, entry)?;
	if decoder.position() != payload.len() {
		return Err(RecoveryRecordError::TrailingBytes);
	}
	if encode(&record) != payload {
		return Err(RecoveryRecordError::NonCanonical);
	}
	Ok(record)
}

pub(super) fn decode_frame<T>(
	frame: &Frame,
	expected: FrameKind,
	decode: fn(&[u8]) -> Result<T, RecoveryRecordError>,
	predecessor: impl FnOnce(&T) -> ChainHead,
) -> Result<T, RecoveryRecordError> {
	let actual = frame.kind();
	if actual != expected {
		return Err(RecoveryRecordError::WrongRecordKind { expected, actual });
	}
	let record = decode(frame.payload())?;
	let prior = predecessor(&record);
	if prior.sequence().checked_add(1) != Some(frame.head().sequence())
		|| prior.digest() != frame.previous_digest()
	{
		return Err(RecoveryRecordError::InvalidFrameOrder);
	}
	Ok(record)
}

pub(super) fn require_reference(reference: ChainHead) -> Result<(), RecoveryRecordError> {
	if reference == ChainHead::start() {
		return Err(RecoveryRecordError::InvalidReference);
	}
	Ok(())
}

pub(super) fn require_before(
	earlier: ChainHead,
	later: ChainHead,
) -> Result<(), RecoveryRecordError> {
	if earlier.sequence() >= later.sequence() {
		return Err(RecoveryRecordError::InvalidFrameOrder);
	}
	Ok(())
}

pub(super) fn write_reference(
	encoder: &mut PayloadEncoder,
	reference: ChainHead,
) -> Result<(), WriteError> {
	encoder
		.array(2)?
		.u64(reference.sequence())?
		.bytes(&reference.digest())?;
	Ok(())
}

pub(super) fn read_reference(decoder: &mut Decoder<'_>) -> Result<ChainHead, RecoveryRecordError> {
	if decoder.array()? != Some(2) {
		return Err(RecoveryRecordError::InvalidCbor);
	}
	let sequence = decoder.u64()?;
	let digest = read_fixed(decoder)?;
	ChainHead::after(sequence, digest).ok_or(RecoveryRecordError::InvalidReference)
}
