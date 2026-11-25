use russh_sftp::protocol::{Packet, SftpHandle, StatusCode};

use super::{MAX_READ_CHUNK_BYTES, MAX_STREAM_BYTES, read, unexpected};
use crate::error::Error;
use crate::wire::Wire;

pub(super) const MAX_READ_REQUESTS: u64 = 4096;

/// An admitted half-open read range. Sequential empty-file reads may have an empty range.
pub(super) struct ReadRange {
	start: u64,
	end: u64,
	cursor: u64,
	requests_left: u64,
}

impl ReadRange {
	pub(super) fn new(offset: u64, length: u64, file_length: u64) -> Result<Self, Error> {
		let end = offset.checked_add(length).ok_or(Error::Limit)?;
		if length > MAX_STREAM_BYTES || end > file_length {
			return Err(Error::Limit);
		}
		Ok(Self {
			start: offset,
			end,
			cursor: offset,
			requests_left: MAX_READ_REQUESTS,
		})
	}

	pub(super) const fn start(&self) -> u64 {
		self.start
	}

	pub(super) const fn length(&self) -> u64 {
		self.end - self.start
	}

	pub(super) fn require_complete(&self) -> Result<(), Error> {
		if self.cursor != self.end {
			return Err(Error::IncompleteRead {
				expected: self.length(),
				read: self.cursor - self.start,
			});
		}
		Ok(())
	}

	pub(super) async fn read_into(
		&mut self,
		wire: &mut Wire,
		file: &SftpHandle,
		output: &mut [u8],
	) -> Result<usize, Error> {
		if !(1..=MAX_READ_CHUNK_BYTES).contains(&output.len()) {
			return Err(Error::Limit);
		}
		let remaining = self.end.checked_sub(self.cursor).ok_or(Error::Protocol)?;
		if remaining == 0 {
			return Ok(0);
		}
		self.requests_left = self.requests_left.checked_sub(1).ok_or(Error::Limit)?;
		let requested =
			u32::try_from(remaining.min(output.len() as u64)).map_err(|_| Error::Limit)?;
		match read(wire, file, self.cursor, requested).await? {
			Packet::Data(data)
				if !data.data.is_empty() && data.data.len() <= requested as usize =>
			{
				let count = data.data.len();
				self.cursor = self.cursor.checked_add(count as u64).ok_or(Error::Limit)?;
				output[..count].copy_from_slice(&data.data);
				Ok(count)
			}
			Packet::Status(status) if status.status_code == StatusCode::Eof => Err(Error::Changed),
			response => Err(unexpected(response)),
		}
	}
}
