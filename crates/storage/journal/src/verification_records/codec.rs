use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use super::VerificationRecordError;
use crate::frame::{Frame, FrameKind};
use crate::prepared::wire::{read_entry_header, write_header};
use crate::{JournalContext, JournalEntryId};

// The largest body contains two native identities and two stream measurements.
// The common entry header and that body need at most 242 bytes.
const MAX_PAYLOAD_BYTES: usize = 256;
type PayloadWriter = Cursor<[u8; MAX_PAYLOAD_BYTES]>;
pub(super) type PayloadEncoder = Encoder<PayloadWriter>;
pub(super) type PayloadWriteError = encode::Error<EndOfArray>;

pub(super) fn encode_record(
	context: &JournalContext,
	entry: JournalEntryId,
	body: impl FnOnce(&mut PayloadEncoder) -> Result<(), PayloadWriteError>,
) -> Vec<u8> {
	let mut encoder = Encoder::new(Cursor::new([0; MAX_PAYLOAD_BYTES]));
	write_header(&mut encoder, context, Some(entry))
		.and_then(|()| body(&mut encoder))
		.expect("local verification observation fits its bounded buffer");
	let writer = encoder.into_writer();
	writer.get_ref()[..writer.position()].to_vec()
}

pub(super) fn decode_record<T>(
	payload: &[u8],
	body: impl FnOnce(
		&mut Decoder<'_>,
		JournalContext,
		JournalEntryId,
	) -> Result<T, VerificationRecordError>,
	encode: fn(&T) -> Vec<u8>,
) -> Result<T, VerificationRecordError> {
	if payload.len() > MAX_PAYLOAD_BYTES {
		return Err(VerificationRecordError::PayloadTooLong);
	}
	let mut decoder = Decoder::new(payload);
	let (context, entry) = read_entry_header(&mut decoder)?;
	let record = body(&mut decoder, context, entry)?;
	if decoder.position() != payload.len() {
		return Err(VerificationRecordError::TrailingBytes);
	}
	if encode(&record) != payload {
		return Err(VerificationRecordError::NonCanonical);
	}
	Ok(record)
}

pub(super) fn decode_frame<T>(
	frame: &Frame,
	expected: FrameKind,
	decode: fn(&[u8]) -> Result<T, VerificationRecordError>,
) -> Result<T, VerificationRecordError> {
	let actual = frame.kind();
	if actual != expected {
		return Err(VerificationRecordError::WrongRecordKind { expected, actual });
	}
	decode(frame.payload())
}

pub(super) fn expect_array(
	decoder: &mut Decoder<'_>,
	length: u64,
) -> Result<(), VerificationRecordError> {
	if decoder.array()? != Some(length) {
		return Err(VerificationRecordError::InvalidCbor);
	}
	Ok(())
}

pub(super) fn expect_evidence(
	decoder: &mut Decoder<'_>,
	code: u64,
) -> Result<(), VerificationRecordError> {
	if decoder.u64()? != code {
		return Err(VerificationRecordError::UnsupportedEvidence);
	}
	Ok(())
}
