use std::cell::Cell;
use std::io::{self, Read};

use exacopy_endpoint::MAX_INTERRUPTED_RETRIES;

pub(super) struct BudgetRead<'budget, R> {
	pub(super) input: R,
	pub(super) consumed: &'budget Cell<u64>,
	pub(super) limit: u64,
}

impl<R: Read> Read for BudgetRead<'_, R> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		let remaining = self
			.limit
			.checked_sub(self.consumed.get())
			.ok_or_else(|| io::Error::other("remote journal byte budget exceeded"))?;
		let limit = usize::try_from(remaining)
			.unwrap_or(buffer.len())
			.min(buffer.len());
		if limit == 0 {
			return Ok(0);
		}
		let mut interruptions = 0;
		loop {
			match self.input.read(&mut buffer[..limit]) {
				Ok(count) if count <= limit => {
					let count_u64 = u64::try_from(count).map_err(io::Error::other)?;
					let consumed =
						self.consumed.get().checked_add(count_u64).ok_or_else(|| {
							io::Error::other("remote journal byte offset overflow")
						})?;
					self.consumed.set(consumed);
					return Ok(count);
				}
				Ok(_) => {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"remote journal reader returned an oversized count",
					));
				}
				Err(cause) if cause.kind() == io::ErrorKind::Interrupted => {
					if interruptions >= MAX_INTERRUPTED_RETRIES {
						return Err(io::Error::other(cause));
					}
					interruptions += 1;
				}
				Err(cause) => return Err(cause),
			}
		}
	}
}
