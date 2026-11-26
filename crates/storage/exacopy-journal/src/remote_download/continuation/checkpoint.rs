//! Canonical range declarations for a capture prepared by kind 40.

use std::num::NonZeroU64;

use exacopy_endpoint::MAX_FILE_LENGTH;
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

use crate::frame::{ChainHead, Frame, FrameKind};
use crate::owner::codec::encoded_bytes;
use crate::remote_download::wire::{
	array, fixed, key, map, read_head, read_version, write_head, write_version,
};
use crate::{JournalEntryId, JournalJobId, OwnerDigest, StreamDigest};

use super::{Error, RemoteDownloadContext, RemoteEpochs};
use crate::remote_download::{
	MAX_REMOTE_CHECKPOINT_BYTES, MAX_REMOTE_CHECKPOINTS, MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES,
};

const VERSION: [u64; 3] = [1, 0, 15];

/// Maximum payload admitted by the continued checkpoint codec.
pub const MAX_REMOTE_CONTINUED_CHECKPOINT_BYTES: usize = MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES;

/// Recorded progress over a positive range following the adopted prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteContinuedRange {
	/// One-based ordinal within the new pass.
	pub ordinal: u16,
	/// Inclusive range start, at or beyond the positive adopted end.
	pub offset: u64,
	/// Covered byte count.
	pub length: u64,
	/// Ordinary BLAKE3 digest for exactly this range.
	pub digest: StreamDigest,
}

/// A versioned continuation checkpoint declaration.
///
/// This codec checks canonical bytes and frame links. Replay must resolve the
/// referenced continuation, exact active epochs, contiguous range and source
/// bound. A declaration cannot establish native durability or permit effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteContinuedCheckpoint {
	context: RemoteDownloadContext,
	predecessor: ChainHead,
	continuation: ChainHead,
	epochs: RemoteEpochs,
	range: RemoteContinuedRange,
}

impl RemoteContinuedCheckpoint {
	/// Builds one bounded continued checkpoint.
	///
	/// # Errors
	/// Rejects invalid context identifiers, frame links and range geometry.
	pub fn new(
		context: RemoteDownloadContext,
		predecessor: ChainHead,
		continuation: ChainHead,
		epochs: RemoteEpochs,
		range: RemoteContinuedRange,
	) -> Result<Self, Error> {
		if context.owner.as_bytes() == &[0; 32]
			|| context.entry.as_bytes() == &[0; 16]
			|| !(1..=MAX_REMOTE_CHECKPOINTS).contains(&range.ordinal)
			|| !(1..=MAX_REMOTE_CHECKPOINT_BYTES).contains(&range.length)
			|| range.offset == 0
			|| range
				.offset
				.checked_add(range.length)
				.is_none_or(|end| end > MAX_FILE_LENGTH)
		{
			return Err(Error::Binding);
		}
		let previous_checkpoints = u64::from(range.ordinal - 1);
		if continuation == ChainHead::start()
			|| predecessor.sequence().checked_add(1).is_none()
			|| continuation.sequence().checked_add(previous_checkpoints)
				!= Some(predecessor.sequence())
			|| (range.ordinal == 1 && continuation != predecessor)
		{
			return Err(Error::FrameBinding);
		}
		Ok(Self {
			context,
			predecessor,
			continuation,
			epochs,
			range,
		})
	}

	/// Returns the recorded owner, job and entry.
	#[must_use]
	pub const fn context(self) -> RemoteDownloadContext {
		self.context
	}

	/// Returns the recorded immediate predecessor.
	#[must_use]
	pub const fn predecessor(self) -> ChainHead {
		self.predecessor
	}

	/// Returns the exact declared active kind-40 head.
	#[must_use]
	pub const fn continuation(self) -> ChainHead {
		self.continuation
	}

	/// Returns the declared new run and source epochs.
	#[must_use]
	pub const fn epochs(self) -> RemoteEpochs {
		self.epochs
	}

	/// Returns the recorded range coordinates and digest.
	#[must_use]
	pub const fn range(self) -> RemoteContinuedRange {
		self.range
	}

	/// Encodes the exact [1, 0, 15] canonical checkpoint.
	///
	/// # Errors
	/// Refuses a payload outside the bounded encoding.
	pub fn encode(self) -> Result<Vec<u8>, Error> {
		let mut out = Encoder::new(Cursor::new([0; MAX_REMOTE_CONTINUED_CHECKPOINT_BYTES]));
		out.map(5)?.u8(0)?;
		write_version(&mut out, VERSION)?;
		out.u8(1)?
			.array(3)?
			.bytes(self.context.owner.as_bytes())?
			.bytes(self.context.job.as_bytes())?
			.bytes(self.context.entry.as_bytes())?
			.u8(2)?;
		write_head(&mut out, self.predecessor)?;
		out.u8(3)?
			.u16(FrameKind::RangeCheckpoint.code())?
			.u8(4)?
			.array(6)?;
		write_head(&mut out, self.continuation)?;
		out.array(2)?
			.u64(self.epochs.run.get())?
			.u64(self.epochs.source.get())?
			.u16(self.range.ordinal)?
			.u64(self.range.offset)?
			.u64(self.range.length)?
			.bytes(self.range.digest.as_bytes())?;
		Ok(encoded_bytes(&out.into_writer()).to_vec())
	}

	/// Decodes a complete canonical continued checkpoint payload.
	///
	/// # Errors
	/// Refuses unsupported versions, shapes, geometry or noncanonical encoding.
	pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
		if bytes.len() > MAX_REMOTE_CONTINUED_CHECKPOINT_BYTES {
			return Err(Error::Length);
		}
		let mut decoder = Decoder::new(bytes);
		map(&mut decoder, 5)?;
		key(&mut decoder, 0)?;
		read_version(&mut decoder, VERSION)?;
		key(&mut decoder, 1)?;
		array(&mut decoder, 3)?;
		let context = RemoteDownloadContext {
			owner: OwnerDigest::from_bytes(fixed(&mut decoder)?),
			job: JournalJobId::from_bytes(fixed(&mut decoder)?).map_err(|_| Error::Binding)?,
			entry: JournalEntryId::from_bytes(fixed(&mut decoder)?),
		};
		key(&mut decoder, 2)?;
		let predecessor = read_head(&mut decoder)?;
		key(&mut decoder, 3)?;
		if decoder.u16()? != FrameKind::RangeCheckpoint.code() {
			return Err(Error::Shape);
		}
		key(&mut decoder, 4)?;
		array(&mut decoder, 6)?;
		let continuation = read_head(&mut decoder)?;
		array(&mut decoder, 2)?;
		let epochs = RemoteEpochs {
			run: NonZeroU64::new(decoder.u64()?).ok_or(Error::Binding)?,
			source: NonZeroU64::new(decoder.u64()?).ok_or(Error::Binding)?,
		};
		let range = RemoteContinuedRange {
			ordinal: decoder.u16()?,
			offset: decoder.u64()?,
			length: decoder.u64()?,
			digest: StreamDigest::from_bytes(fixed(&mut decoder)?),
		};
		let checkpoint = Self::new(context, predecessor, continuation, epochs, range)?;
		if checkpoint.encode()? != bytes {
			return Err(Error::NonCanonical);
		}
		Ok(checkpoint)
	}

	/// Decodes and checks the outer kind, predecessor digest and consecutive sequence.
	///
	/// # Errors
	/// Refuses unsupported payloads or an inconsistent enclosing frame.
	pub fn from_frame(frame: &Frame) -> Result<Self, Error> {
		if frame.kind() != FrameKind::RangeCheckpoint {
			return Err(Error::FrameBinding);
		}
		let checkpoint = Self::decode(frame.payload())?;
		if checkpoint.predecessor.sequence().checked_add(1) != Some(frame.head().sequence())
			|| checkpoint.predecessor.digest() != frame.previous_digest()
		{
			return Err(Error::FrameBinding);
		}
		Ok(checkpoint)
	}
}
