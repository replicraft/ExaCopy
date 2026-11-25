use exacopy_endpoint::MAX_UNIX_COMPONENT_BYTES;
use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use super::DarwinPhaseError;
use crate::frame::{Frame, FrameKind};

// Kind 7 is the largest record: a 103-byte header, three identities of up to
// 57 bytes, the 54-byte owner/token binding, three digests, and a component.
const MAX_PAYLOAD_BYTES: usize = 448 + MAX_UNIX_COMPONENT_BYTES;
type PayloadWriter = Cursor<[u8; MAX_PAYLOAD_BYTES]>;
pub(super) type PayloadEncoder = Encoder<PayloadWriter>;
pub(super) type PayloadWriteError = encode::Error<EndOfArray>;

pub(super) fn encode_record(
	write: impl FnOnce(&mut PayloadEncoder) -> Result<(), PayloadWriteError>,
) -> Vec<u8> {
	let mut encoder = Encoder::new(Cursor::new([0; MAX_PAYLOAD_BYTES]));
	write(&mut encoder).expect("managed APFS phase evidence fits its bounded buffer");
	let writer = encoder.into_writer();
	writer.get_ref()[..writer.position()].to_vec()
}

pub(super) fn decode_record<'a, T>(
	payload: &'a [u8],
	read: impl FnOnce(&mut Decoder<'a>) -> Result<T, DarwinPhaseError>,
	encode: fn(&T) -> Vec<u8>,
) -> Result<T, DarwinPhaseError> {
	if payload.len() > MAX_PAYLOAD_BYTES {
		return Err(DarwinPhaseError::PayloadTooLong);
	}
	let mut decoder = Decoder::new(payload);
	let record = read(&mut decoder)?;
	if decoder.position() != payload.len() {
		return Err(DarwinPhaseError::TrailingBytes);
	}
	if encode(&record) != payload {
		return Err(DarwinPhaseError::NonCanonical);
	}
	Ok(record)
}

pub(super) fn frame_payload(frame: &Frame, expected: FrameKind) -> Result<&[u8], DarwinPhaseError> {
	let actual = frame.kind();
	if actual != expected {
		return Err(DarwinPhaseError::WrongKind { expected, actual });
	}
	Ok(frame.payload())
}

pub(super) fn expect_code(
	decoder: &mut Decoder<'_>,
	expected: u64,
) -> Result<(), DarwinPhaseError> {
	if decoder.u64()? != expected {
		return Err(DarwinPhaseError::UnsupportedEvidence);
	}
	Ok(())
}

pub(super) const DARWIN_FULL_FILE_BARRIER: u64 = 1;
