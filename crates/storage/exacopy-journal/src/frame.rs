//! Version 1 journal envelope I/O with explicit segment chaining.

mod errors;
mod kind;

#[cfg(test)]
mod tests;

use std::fmt;
use std::io::{self, Read, Write};

pub use errors::{FrameProblem, FrameReadError, FrameWriteError};
pub use kind::FrameKind;

const MAGIC: &[u8; 8] = b"EXAJNL01";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"ExaCopy/journal-record/v1\0";
const VERSION_OFFSET: usize = 8;
const KIND_OFFSET: usize = 10;
const LENGTH_OFFSET: usize = 12;
const SEQUENCE_OFFSET: usize = 16;
const PREVIOUS_DIGEST_OFFSET: usize = 24;
const HEADER_BYTES: usize = 56;
const CRC_BYTES: usize = 4;
const DIGEST_BYTES: usize = 32;
const ZERO_DIGEST: [u8; DIGEST_BYTES] = [0; DIGEST_BYTES];

/// Largest payload permitted in a version 1 journal frame.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Envelope bytes in addition to the encoded payload.
pub const FRAME_OVERHEAD_BYTES: usize = HEADER_BYTES + CRC_BYTES + DIGEST_BYTES;

/// The sequence and digest at a verified frame boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainHead {
	sequence: u64,
	digest: [u8; DIGEST_BYTES],
}

impl ChainHead {
	/// Returns the initial anchor for the first segment of a job.
	#[must_use]
	pub const fn start() -> Self {
		Self {
			sequence: 0,
			digest: ZERO_DIGEST,
		}
	}

	/// Constructs a reference to an already verified frame.
	///
	/// The caller supplies evidence of the preceding record. A sequence and digest supplied by a
	/// segment filename or by unverified input do not establish continuity. Returns `None` for a
	/// zero sequence or digest.
	#[must_use]
	pub fn after(sequence: u64, digest: [u8; DIGEST_BYTES]) -> Option<Self> {
		(sequence != 0 && digest != ZERO_DIGEST).then_some(Self { sequence, digest })
	}

	/// Returns the last frame's sequence, or zero at the job's initial anchor.
	#[must_use]
	pub const fn sequence(self) -> u64 {
		self.sequence
	}

	/// Returns the last frame's digest, or all zeros at the job's initial anchor.
	#[must_use]
	pub const fn digest(self) -> [u8; DIGEST_BYTES] {
		self.digest
	}
}

/// An integrity-checked envelope carrying opaque payload bytes.
#[derive(Eq, PartialEq)]
pub struct Frame {
	kind: FrameKind,
	payload: Vec<u8>,
	head: ChainHead,
	previous_digest: [u8; DIGEST_BYTES],
}

impl Frame {
	pub(crate) fn from_verified_parts(
		kind: FrameKind,
		payload: Vec<u8>,
		head: ChainHead,
		previous_digest: [u8; DIGEST_BYTES],
	) -> Self {
		Self {
			kind,
			payload,
			head,
			previous_digest,
		}
	}

	/// Returns the envelope's record discriminator.
	#[must_use]
	pub const fn kind(&self) -> FrameKind {
		self.kind
	}

	/// Borrows the payload for independent semantic validation.
	#[must_use]
	pub fn payload(&self) -> &[u8] {
		&self.payload
	}

	/// Returns the sequence and digest at this frame's end.
	#[must_use]
	pub const fn head(&self) -> ChainHead {
		self.head
	}

	/// Returns the digest recorded for the preceding frame.
	#[must_use]
	pub const fn previous_digest(&self) -> [u8; DIGEST_BYTES] {
		self.previous_digest
	}
}

impl fmt::Debug for Frame {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("Frame")
			.field("kind", &self.kind)
			.field("sequence", &self.head.sequence)
			.field("payload_bytes", &self.payload.len())
			.finish_non_exhaustive()
	}
}

#[derive(Debug, Eq, PartialEq)]
enum ReadStatus {
	Open,
	End,
	Failed,
}

/// Scans one segment in order and stops at its first incomplete or invalid frame.
///
/// The caller determines which segment is last and preserves original bytes for reconciliation.
pub struct FrameReader<R> {
	reader: R,
	head: ChainHead,
	offset: u64,
	status: ReadStatus,
}

impl<R> fmt::Debug for FrameReader<R> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("FrameReader")
			.field("offset", &self.offset)
			.field("status", &self.status)
			.field("sequence", &self.head.sequence)
			.finish_non_exhaustive()
	}
}

impl<R: Read> FrameReader<R> {
	/// Opens a scan at the start of a segment using a previously validated anchor.
	#[must_use]
	pub const fn new(reader: R, head: ChainHead) -> Self {
		Self {
			reader,
			head,
			offset: 0,
			status: ReadStatus::Open,
		}
	}

	/// Returns the last verified boundary, including after a failed read.
	#[must_use]
	pub const fn head(&self) -> ChainHead {
		self.head
	}

	/// Returns the segment-relative byte offset immediately after the last verified frame.
	#[must_use]
	pub const fn offset(&self) -> u64 {
		self.offset
	}

	/// Reads the next bounded frame or returns `None` at a clean frame boundary.
	///
	/// # Errors
	///
	/// An incomplete tail, incompatible or damaged frame, or read error stops the scan. A later
	/// call returns `FrameReadError::Stopped` without consuming additional bytes.
	pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameReadError> {
		self.next_frame_with_payload_limit(|_| MAX_PAYLOAD_BYTES)
	}

	pub(crate) fn next_frame_with_payload_limit(
		&mut self,
		limit: impl FnOnce(FrameKind) -> usize,
	) -> Result<Option<Frame>, FrameReadError> {
		match self.status {
			ReadStatus::End => return Ok(None),
			ReadStatus::Failed => return Err(FrameReadError::Stopped),
			ReadStatus::Open => {}
		}
		let result = self.read_frame(limit);
		self.status = match &result {
			Ok(Some(_)) => ReadStatus::Open,
			Ok(None) => ReadStatus::End,
			Err(_) => ReadStatus::Failed,
		};
		result
	}

	fn read_frame(
		&mut self,
		limit: impl FnOnce(FrameKind) -> usize,
	) -> Result<Option<Frame>, FrameReadError> {
		let mut header = [0_u8; HEADER_BYTES];
		let read = self.fill(&mut header)?;
		if read == 0 {
			return Ok(None);
		}
		self.check_magic(&header[..read])?;
		if read < KIND_OFFSET {
			return Err(self.torn(read));
		}

		let version = u16::from_le_bytes(bytes_at(&header, VERSION_OFFSET));
		if version != VERSION {
			return Err(self.corrupt(FrameProblem::UnsupportedVersion(version)));
		}
		if read < LENGTH_OFFSET {
			return Err(self.torn(read));
		}
		let code = u16::from_le_bytes(bytes_at(&header, KIND_OFFSET));
		let kind = FrameKind::from_code(code)
			.ok_or_else(|| self.corrupt(FrameProblem::UnsupportedKind(code)))?;
		if read < SEQUENCE_OFFSET {
			return Err(self.torn(read));
		}
		let length = u32::from_le_bytes(bytes_at(&header, LENGTH_OFFSET));
		let maximum = MAX_PAYLOAD_BYTES.min(limit(kind));
		let length = usize::try_from(length)
			.ok()
			.filter(|&length| length <= maximum)
			.ok_or_else(|| self.corrupt(FrameProblem::PayloadTooLarge(length)))?;

		if read < PREVIOUS_DIGEST_OFFSET {
			return Err(self.torn(read));
		}
		let sequence = u64::from_le_bytes(bytes_at(&header, SEQUENCE_OFFSET));
		if (self.head.sequence == 0 && sequence != 1) || sequence <= self.head.sequence {
			return Err(self.corrupt(FrameProblem::Sequence(sequence)));
		}
		let previous_digest = self.head.digest;
		if header[PREVIOUS_DIGEST_OFFSET..read] != previous_digest[..read - PREVIOUS_DIGEST_OFFSET]
		{
			return Err(self.corrupt(FrameProblem::PreviousDigest));
		}
		if read < HEADER_BYTES {
			return Err(self.torn(read));
		}

		let mut payload = vec![0; length];
		let read = self.fill(&mut payload)?;
		if read < length {
			return Err(self.torn(HEADER_BYTES + read));
		}

		let crc = checksum(&header, &payload);
		let mut stored_crc = [0; CRC_BYTES];
		let read = self.fill(&mut stored_crc)?;
		if stored_crc[..read] != crc[..read] {
			return Err(self.corrupt(FrameProblem::Checksum));
		}
		if read < CRC_BYTES {
			return Err(self.torn(HEADER_BYTES + length + read));
		}

		let digest = record_digest(&header, &payload, &crc);
		let mut stored_digest = [0; DIGEST_BYTES];
		let read = self.fill(&mut stored_digest)?;
		if stored_digest[..read] != digest[..read] || digest == ZERO_DIGEST {
			return Err(self.corrupt(FrameProblem::Digest));
		}
		if read < DIGEST_BYTES {
			return Err(self.torn(HEADER_BYTES + length + CRC_BYTES + read));
		}

		let frame_bytes = u64::try_from(FRAME_OVERHEAD_BYTES + length)
			.map_err(|_| self.corrupt(FrameProblem::OffsetOverflow))?;
		self.offset = self
			.offset
			.checked_add(frame_bytes)
			.ok_or_else(|| self.corrupt(FrameProblem::OffsetOverflow))?;
		self.head = ChainHead { sequence, digest };
		Ok(Some(Frame::from_verified_parts(
			kind,
			payload,
			self.head,
			previous_digest,
		)))
	}

	fn check_magic(&self, prefix: &[u8]) -> Result<(), FrameReadError> {
		let available = prefix.len().min(MAGIC.len());
		if prefix[..available] != MAGIC[..available] {
			return Err(self.corrupt(FrameProblem::Magic));
		}
		Ok(())
	}

	fn fill(&mut self, bytes: &mut [u8]) -> Result<usize, FrameReadError> {
		let mut read = 0;
		while read < bytes.len() {
			match self.reader.read(&mut bytes[read..]) {
				Ok(0) => break,
				Ok(count) => read += count,
				Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
				Err(source) => {
					return Err(FrameReadError::Io {
						offset: self.offset,
						source,
					});
				}
			}
		}
		Ok(read)
	}

	const fn torn(&self, bytes_read: usize) -> FrameReadError {
		FrameReadError::TornTail {
			offset: self.offset,
			bytes_read,
		}
	}

	const fn corrupt(&self, problem: FrameProblem) -> FrameReadError {
		FrameReadError::Corrupt {
			offset: self.offset,
			problem,
		}
	}
}

/// Appends complete version 1 envelopes from a supplied frame boundary.
pub struct FrameWriter<W> {
	writer: W,
	head: ChainHead,
	stopped: bool,
}

impl<W> fmt::Debug for FrameWriter<W> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("FrameWriter")
			.field("sequence", &self.head.sequence)
			.field("stopped", &self.stopped)
			.finish_non_exhaustive()
	}
}

impl<W: Write> FrameWriter<W> {
	/// Starts writing at the current position of an append stream with the given verified head.
	///
	/// The caller owns exclusive access, positions the underlying stream at the verified boundary,
	/// and establishes publication barriers separately.
	#[must_use]
	pub const fn new(writer: W, head: ChainHead) -> Self {
		Self {
			writer,
			head,
			stopped: false,
		}
	}

	/// Returns the last complete append's chain head, regardless of barrier status.
	#[must_use]
	pub const fn head(&self) -> ChainHead {
		self.head
	}

	/// Returns the underlying writer for caller-managed barriers or reconciliation.
	pub fn into_inner(self) -> W {
		self.writer
	}

	pub(crate) fn sink_mut(&mut self) -> &mut W {
		&mut self.writer
	}

	/// Writes one complete frame and returns its new chain head.
	///
	/// # Errors
	///
	/// Oversized payloads, exhausted sequences and the reserved digest are refused before I/O.
	/// A write error leaves an uncertain physical suffix and stops this writer. A successful
	/// append only establishes that the stream accepted the bytes.
	pub fn append(
		&mut self,
		kind: FrameKind,
		payload: &[u8],
	) -> Result<ChainHead, FrameWriteError> {
		self.append_admitted(kind, payload, || Ok(()))
			.map(|(head, ())| head)
			.map_err(|failure| match failure {
				AppendStartError::Frame(error) => error,
				AppendStartError::Admission(error) => FrameWriteError::Io(error),
			})
	}

	pub(crate) fn append_admitted<G>(
		&mut self,
		kind: FrameKind,
		payload: &[u8],
		enter: impl FnOnce() -> std::io::Result<G>,
	) -> Result<(ChainHead, G), AppendStartError> {
		if self.stopped {
			return Err(FrameWriteError::Stopped.into());
		}
		let length = u32::try_from(payload.len())
			.ok()
			.filter(|_| payload.len() <= MAX_PAYLOAD_BYTES)
			.ok_or(FrameWriteError::PayloadTooLarge(payload.len()))?;
		let sequence = self
			.head
			.sequence
			.checked_add(1)
			.ok_or(FrameWriteError::SequenceExhausted)?;
		let mut header = [0; HEADER_BYTES];
		header[..VERSION_OFFSET].copy_from_slice(MAGIC);
		header[VERSION_OFFSET..KIND_OFFSET].copy_from_slice(&VERSION.to_le_bytes());
		header[KIND_OFFSET..LENGTH_OFFSET].copy_from_slice(&kind.code().to_le_bytes());
		header[LENGTH_OFFSET..SEQUENCE_OFFSET].copy_from_slice(&length.to_le_bytes());
		header[SEQUENCE_OFFSET..PREVIOUS_DIGEST_OFFSET].copy_from_slice(&sequence.to_le_bytes());
		header[PREVIOUS_DIGEST_OFFSET..].copy_from_slice(&self.head.digest);

		let crc = checksum(&header, payload);
		let digest = record_digest(&header, payload, &crc);
		if digest == ZERO_DIGEST {
			return Err(FrameWriteError::ReservedDigest.into());
		}

		let guard = enter().map_err(AppendStartError::Admission)?;
		for part in [&header[..], payload, &crc, &digest] {
			if let Err(error) = self.writer.write_all(part) {
				self.stopped = true;
				return Err(FrameWriteError::Io(error).into());
			}
		}
		self.head = ChainHead { sequence, digest };
		Ok((self.head, guard))
	}
}

pub(crate) enum AppendStartError {
	Admission(std::io::Error),
	Frame(FrameWriteError),
}

impl From<FrameWriteError> for AppendStartError {
	fn from(error: FrameWriteError) -> Self {
		Self::Frame(error)
	}
}

fn bytes_at<const N: usize>(header: &[u8; HEADER_BYTES], offset: usize) -> [u8; N] {
	let mut bytes = [0; N];
	bytes.copy_from_slice(&header[offset..][..N]);
	bytes
}

fn checksum(header: &[u8; HEADER_BYTES], payload: &[u8]) -> [u8; CRC_BYTES] {
	crc32c::crc32c_append(crc32c::crc32c(header), payload).to_le_bytes()
}

fn record_digest(
	header: &[u8; HEADER_BYTES],
	payload: &[u8],
	crc: &[u8; CRC_BYTES],
) -> [u8; DIGEST_BYTES] {
	*blake3::Hasher::new()
		.update(DOMAIN)
		.update(header)
		.update(payload)
		.update(crc)
		.finalize()
		.as_bytes()
}
