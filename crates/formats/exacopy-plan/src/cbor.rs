use core::convert::Infallible;

use minicbor::Encoder;
use minicbor::encode::{Error, Write};

pub(crate) type EncodeError = Error<Infallible>;

pub(crate) fn canonical_bytes(
	write: impl FnOnce(&mut Encoder<BodyBytes>) -> Result<(), EncodeError>,
) -> Vec<u8> {
	let mut encoder = Encoder::new(BodyBytes(Vec::new()));
	match write(&mut encoder) {
		Ok(()) => encoder.into_writer().0,
		Err(error) => match error.into_write() {
			Some(never) => match never {},
			None => unreachable!("fixed body encoding uses only infallible CBOR primitives"),
		},
	}
}

pub(crate) struct BodyBytes(Vec<u8>);

impl Write for BodyBytes {
	type Error = Infallible;

	fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
		self.0.extend_from_slice(bytes);
		Ok(())
	}
}
