use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use super::PublicationRecordError;
use crate::PublishIntentContext;
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{read_effect_header, read_fixed, write_effect_header};

// At maximum integer widths, the kind-9 header is 103 bytes and the body
// is 149 bytes, including two 44-byte frame references and two 25-byte identities.
const MAX_PAYLOAD_BYTES: usize = 256;

pub(super) type Writer = Cursor<[u8; MAX_PAYLOAD_BYTES]>;
pub(super) type PayloadEncoder = Encoder<Writer>;
pub(super) type WriteError = encode::Error<EndOfArray>;

pub(super) fn encode_record(
	context: &PublishIntentContext,
	body: impl FnOnce(&mut PayloadEncoder) -> Result<(), WriteError>,
) -> Writer {
	let mut encoder = Encoder::new(Cursor::new([0; MAX_PAYLOAD_BYTES]));
	write_effect_header(&mut encoder, context)
		.and_then(|()| body(&mut encoder))
		.expect("local publication observation fits its fixed-size buffer");
	encoder.into_writer()
}

pub(super) fn encoded_bytes(writer: &Writer) -> &[u8] {
	&writer.get_ref()[..writer.position()]
}

pub(super) fn decode_record<T>(
	payload: &[u8],
	read_body: impl FnOnce(&mut Decoder<'_>, PublishIntentContext) -> Result<T, PublicationRecordError>,
	encode: impl FnOnce(&T) -> Writer,
) -> Result<T, PublicationRecordError> {
	if payload.len() > MAX_PAYLOAD_BYTES {
		return Err(PublicationRecordError::PayloadTooLong);
	}
	let mut decoder = Decoder::new(payload);
	let context = read_effect_header(&mut decoder)?;
	let record = read_body(&mut decoder, context)?;
	if decoder.position() != payload.len() {
		return Err(PublicationRecordError::TrailingBytes);
	}
	if encoded_bytes(&encode(&record)) != payload {
		return Err(PublicationRecordError::NonCanonical);
	}
	Ok(record)
}

pub(super) fn decode_frame<T>(
	frame: &Frame,
	expected: FrameKind,
	decode: fn(&[u8]) -> Result<T, PublicationRecordError>,
	dependency: impl FnOnce(&T) -> ChainHead,
) -> Result<T, PublicationRecordError> {
	let actual = frame.kind();
	if actual != expected {
		return Err(PublicationRecordError::WrongRecordKind { expected, actual });
	}
	let record = decode(frame.payload())?;
	require_before(dependency(&record), frame.head())?;
	Ok(record)
}

pub(super) fn require_reference(reference: ChainHead) -> Result<(), PublicationRecordError> {
	if reference == ChainHead::start() {
		return Err(PublicationRecordError::InvalidReference);
	}
	Ok(())
}

pub(super) fn require_before(
	earlier: ChainHead,
	later: ChainHead,
) -> Result<(), PublicationRecordError> {
	if earlier.sequence() >= later.sequence() {
		return Err(PublicationRecordError::InvalidFrameOrder);
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

pub(super) fn read_reference(
	decoder: &mut Decoder<'_>,
) -> Result<ChainHead, PublicationRecordError> {
	if decoder.array()? != Some(2) {
		return Err(PublicationRecordError::InvalidCbor);
	}
	let sequence = decoder.u64()?;
	let digest = read_fixed(decoder)?;
	ChainHead::after(sequence, digest).ok_or(PublicationRecordError::InvalidReference)
}
