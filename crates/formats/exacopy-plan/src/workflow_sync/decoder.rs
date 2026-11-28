use core::num::NonZeroU64;

use exacopy_core::UnixComponent;
use minicbor::Decoder;

use super::WorkflowError as Error;
use crate::UnixTimestamp;

pub(super) struct Canonical<'bytes>(Decoder<'bytes>);

impl<'bytes> Canonical<'bytes> {
	pub(super) fn new(bytes: &'bytes [u8], maximum: usize) -> Result<Self, Error> {
		if bytes.is_empty() || bytes.len() > maximum {
			return Err(Error::Size);
		}
		Ok(Self(Decoder::new(bytes)))
	}

	pub(super) fn finish(self) -> Result<(), Error> {
		if self.0.position() != self.0.input().len() {
			return Err(Error::NonCanonical);
		}
		Ok(())
	}

	fn width(&self, start: usize, argument: u64, content: usize) -> Result<(), Error> {
		let head = match argument {
			0..=23 => 1,
			24..=255 => 2,
			256..=65_535 => 3,
			65_536..=4_294_967_295 => 5,
			_ => 9,
		};
		if self.0.position() - start != head + content {
			return Err(Error::NonCanonical);
		}
		Ok(())
	}

	pub(super) fn map(&mut self, count: u64) -> Result<(), Error> {
		let start = self.0.position();
		if self.0.map()? != Some(count) {
			return Err(Error::Shape);
		}
		self.width(start, count, 0)
	}

	pub(super) fn array(&mut self, count: u64) -> Result<(), Error> {
		let start = self.0.position();
		if self.0.array()? != Some(count) {
			return Err(Error::Shape);
		}
		self.width(start, count, 0)
	}

	pub(super) fn number(&mut self) -> Result<u64, Error> {
		let start = self.0.position();
		let value = self.0.u64()?;
		self.width(start, value, 0)?;
		Ok(value)
	}

	pub(super) fn key(&mut self, required: u64) -> Result<(), Error> {
		if self.number()? != required {
			return Err(Error::Shape);
		}
		Ok(())
	}

	pub(super) fn positive(&mut self) -> Result<NonZeroU64, Error> {
		NonZeroU64::new(self.number()?).ok_or(Error::Shape)
	}

	pub(super) fn null(&mut self) -> Result<(), Error> {
		Ok(self.0.null()?)
	}

	pub(super) fn expect_true(&mut self) -> Result<(), Error> {
		if !self.0.bool()? {
			return Err(Error::Shape);
		}
		Ok(())
	}

	pub(super) fn bytes(&mut self) -> Result<&'bytes [u8], Error> {
		let start = self.0.position();
		let bytes = self.0.bytes()?;
		self.width(start, bytes.len() as u64, bytes.len())?;
		Ok(bytes)
	}

	pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
		self.bytes()?.try_into().map_err(|_| Error::Shape)
	}

	pub(super) fn uuid(&mut self) -> Result<[u8; 16], Error> {
		let bytes = self.fixed()?;
		if bytes == [0; 16] {
			return Err(Error::Shape);
		}
		Ok(bytes)
	}

	pub(super) fn time(&mut self) -> Result<UnixTimestamp, Error> {
		self.array(2)?;
		let start = self.0.position();
		let seconds = self.0.i64()?;
		let argument = if seconds < 0 {
			seconds.unsigned_abs() - 1
		} else {
			seconds.unsigned_abs()
		};
		self.width(start, argument, 0)?;
		let nanoseconds = u32::try_from(self.number()?).map_err(|_| Error::Shape)?;
		UnixTimestamp::new(seconds, nanoseconds).map_err(|_| Error::Shape)
	}

	pub(super) fn text(&mut self, expected: &str) -> Result<(), Error> {
		let start = self.0.position();
		let text = self.0.str()?;
		if text != expected {
			return Err(Error::Shape);
		}
		self.width(start, text.len() as u64, text.len())
	}

	pub(super) fn name(&mut self) -> Result<UnixComponent<'bytes>, Error> {
		self.map(2)?;
		self.key(0)?;
		self.key(1)?;
		self.key(1)?;
		UnixComponent::new(self.bytes()?).map_err(|_| Error::Shape)
	}
}

impl From<minicbor::decode::Error> for Error {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::Shape
	}
}
