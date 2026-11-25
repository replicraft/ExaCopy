use minicbor::decode::{Decoder as CborDecoder, Error as DecodeError};

use super::IntentError;

pub(super) struct Decoder<'a>(CborDecoder<'a>);

impl<'a> Decoder<'a> {
	pub(super) fn new(input: &'a [u8]) -> Self {
		Self(CborDecoder::new(input))
	}

	pub(super) fn uint(&mut self) -> Result<u64, IntentError> {
		self.0.u64().map_err(decode_error)
	}

	pub(super) fn map(&mut self, fields: u64) -> Result<(), IntentError> {
		match self.0.map().map_err(decode_error)? {
			Some(actual) if actual == fields => Ok(()),
			Some(_) => Err(IntentError::UnexpectedMap),
			None => Err(IntentError::InvalidCbor),
		}
	}

	pub(super) fn key(&mut self, expected: u64) -> Result<(), IntentError> {
		let actual = self.uint()?;
		if actual != expected {
			return Err(IntentError::UnexpectedKey { expected, actual });
		}
		Ok(())
	}

	pub(super) fn bytes(&mut self, max: usize) -> Result<&'a [u8], IntentError> {
		let bytes = self.0.bytes().map_err(decode_error)?;
		if bytes.len() > max {
			return Err(IntentError::Length);
		}
		Ok(bytes)
	}

	pub(super) fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], IntentError> {
		self.bytes(N)?.try_into().map_err(|_| IntentError::Length)
	}

	pub(super) fn null(&mut self) -> Result<(), IntentError> {
		self.0.null().map_err(|error| {
			if error.is_type_mismatch() {
				IntentError::UnsupportedGeneration
			} else {
				decode_error(error)
			}
		})
	}

	pub(super) fn finish(self) -> Result<(), IntentError> {
		if self.0.position() == self.0.input().len() {
			Ok(())
		} else {
			Err(IntentError::TrailingBytes)
		}
	}
}

fn decode_error(error: DecodeError) -> IntentError {
	if error.is_end_of_input() {
		IntentError::Truncated
	} else {
		IntentError::InvalidCbor
	}
}
