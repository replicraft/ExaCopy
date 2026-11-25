use std::num::NonZeroU64;

use exacopy_endpoint::UnixComponent;
use minicbor::data::Type;
use minicbor::encode::Error as CborEncodeError;
use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder};

use crate::frame::FrameKind;
use crate::owner::codec::encoded_bytes;
use crate::{JournalEntryId, JournalJobId, OwnerDigest, StreamDigest, StreamLength};

use super::{
	Error, MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES, RemoteDownloadBody as Body, RemoteDownloadContext,
	RemoteDownloadRecord, RemoteEpochs, RemoteScopeDigest, RemoteSourceObservation,
	RemoteUncertainBoundary,
};
use crate::remote_download::wire::{
	array, fixed, key, map, read_head, read_identity, read_version, write_head, write_identity,
	write_version,
};

const VERSION: [u64; 3] = [1, 0, 1];
const CREATION_UNCERTAIN: u8 = 0;
const STAGE_BARRIER_UNCERTAIN: u8 = 1;
const CHECKPOINT_UNCERTAIN: u8 = 2;
const TERMINAL_SOURCE_UNCERTAIN: u8 = 3;

type Buffer = Cursor<[u8; MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES]>;
type WriteError = CborEncodeError<EndOfArray>;

pub(super) fn encode(record: &RemoteDownloadRecord<'_>) -> Result<Vec<u8>, Error> {
	Ok(encoded_bytes(&encode_into(record)?).to_vec())
}

pub(super) fn decode(bytes: &[u8]) -> Result<RemoteDownloadRecord<'_>, Error> {
	if bytes.len() > MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES {
		return Err(Error::Length);
	}
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 5)?;
	key(&mut decoder, 0)?;
	read_version(&mut decoder, VERSION)?;
	key(&mut decoder, 1)?;
	array(&mut decoder, 3)?;
	let owner = OwnerDigest::from_bytes(fixed(&mut decoder)?);
	let job = JournalJobId::from_bytes(fixed(&mut decoder)?).map_err(|_| Error::Binding)?;
	let entry = JournalEntryId::from_bytes(fixed(&mut decoder)?);
	key(&mut decoder, 2)?;
	let predecessor = if decoder.datatype()? == Type::Null {
		decoder.null()?;
		None
	} else {
		Some(read_head(&mut decoder)?)
	};
	key(&mut decoder, 3)?;
	let kind = decoder.u16()?;
	key(&mut decoder, 4)?;
	let body = read_body(&mut decoder, kind)?;
	let record = RemoteDownloadRecord::new(
		RemoteDownloadContext { owner, job, entry },
		predecessor,
		body,
	)?;
	if encoded_bytes(&encode_into(&record)?) != bytes {
		return Err(Error::NonCanonical);
	}
	Ok(record)
}

fn encode_into(record: &RemoteDownloadRecord<'_>) -> Result<Buffer, Error> {
	let context = record.context();
	let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES]));
	out.map(5)?.u8(0)?;
	write_version(&mut out, VERSION)?;
	out.u8(1)?
		.array(3)?
		.bytes(context.owner.as_bytes())?
		.bytes(context.job.as_bytes())?
		.bytes(context.entry.as_bytes())?
		.u8(2)?;
	match record.predecessor() {
		None => {
			out.null()?;
		}
		Some(head) => write_head(&mut out, head)?,
	}
	let body = record.body();
	out.u8(3)?.u16(body.kind().code())?.u8(4)?;
	write_body(&mut out, body)?;
	Ok(out.into_writer())
}

fn write_body(out: &mut Encoder<Buffer>, body: Body<'_>) -> Result<(), WriteError> {
	match body {
		Body::JobPrepared { scope } => {
			out.array(1)?.bytes(scope.as_bytes())?;
		}
		Body::StageAllocated {
			previous,
			next,
			name,
			nonce,
			source,
		} => {
			out.array(5)?;
			match previous {
				Some(epochs) => write_epochs(out, epochs)?,
				None => {
					out.null()?;
				}
			}
			write_epochs(out, next)?;
			out.bytes(name.as_bytes())?
				.bytes(&nonce)?
				.array(3)?
				.u64(source.length().get())?
				.u32(source.mode())?
				.u32(source.modified_seconds())?;
		}
		Body::EntryPrepared {
			allocation,
			epochs,
			nonce,
			stage_directory,
			stage,
		} => {
			out.array(5)?;
			write_head(out, allocation)?;
			write_epochs(out, epochs)?;
			out.bytes(&nonce)?;
			write_identity(out, stage_directory)?;
			write_identity(out, stage)?;
		}
		Body::RangeCheckpoint {
			prepared,
			epochs,
			ordinal,
			offset,
			length,
			digest,
		} => {
			out.array(6)?;
			write_head(out, prepared)?;
			write_epochs(out, epochs)?;
			out.u16(ordinal)?
				.u64(offset)?
				.u64(length)?
				.bytes(digest.as_bytes())?;
		}
		Body::FailureRecorded {
			attempt,
			epochs,
			boundary,
		} => {
			out.array(3)?;
			write_head(out, attempt)?;
			write_epochs(out, epochs)?;
			out.u8(match boundary {
				RemoteUncertainBoundary::Creation => CREATION_UNCERTAIN,
				RemoteUncertainBoundary::StageBarrier => STAGE_BARRIER_UNCERTAIN,
				RemoteUncertainBoundary::CheckpointAppend => CHECKPOINT_UNCERTAIN,
				RemoteUncertainBoundary::TerminalSource => TERMINAL_SOURCE_UNCERTAIN,
			})?;
		}
	}
	Ok(())
}

fn read_body<'a>(decoder: &mut Decoder<'a>, kind: u16) -> Result<Body<'a>, Error> {
	match kind {
		code if code == FrameKind::JobPrepared.code() => {
			array(decoder, 1)?;
			Ok(Body::JobPrepared {
				scope: RemoteScopeDigest::from_bytes(fixed(decoder)?),
			})
		}
		code if code == FrameKind::RemoteStageAllocated.code() => {
			array(decoder, 5)?;
			let previous = if decoder.datatype()? == Type::Null {
				decoder.null()?;
				None
			} else {
				Some(read_epochs(decoder)?)
			};
			let next = read_epochs(decoder)?;
			let name = UnixComponent::new(decoder.bytes()?).map_err(|_| Error::Scope)?;
			let nonce = fixed(decoder)?;
			array(decoder, 3)?;
			let length = StreamLength::new(decoder.u64()?).map_err(|_| Error::Binding)?;
			let source = RemoteSourceObservation::new(length, decoder.u32()?, decoder.u32()?)?;
			Ok(Body::StageAllocated {
				previous,
				next,
				name,
				nonce,
				source,
			})
		}
		code if code == FrameKind::EntryPrepared.code() => {
			array(decoder, 5)?;
			Ok(Body::EntryPrepared {
				allocation: read_head(decoder)?,
				epochs: read_epochs(decoder)?,
				nonce: fixed(decoder)?,
				stage_directory: read_identity(decoder)?,
				stage: read_identity(decoder)?,
			})
		}
		code if code == FrameKind::RangeCheckpoint.code() => {
			array(decoder, 6)?;
			Ok(Body::RangeCheckpoint {
				prepared: read_head(decoder)?,
				epochs: read_epochs(decoder)?,
				ordinal: decoder.u16()?,
				offset: decoder.u64()?,
				length: decoder.u64()?,
				digest: StreamDigest::from_bytes(fixed(decoder)?),
			})
		}
		code if code == FrameKind::FailureRecorded.code() => {
			array(decoder, 3)?;
			let attempt = read_head(decoder)?;
			let epochs = read_epochs(decoder)?;
			let boundary = match decoder.u8()? {
				CREATION_UNCERTAIN => RemoteUncertainBoundary::Creation,
				STAGE_BARRIER_UNCERTAIN => RemoteUncertainBoundary::StageBarrier,
				CHECKPOINT_UNCERTAIN => RemoteUncertainBoundary::CheckpointAppend,
				TERMINAL_SOURCE_UNCERTAIN => RemoteUncertainBoundary::TerminalSource,
				_ => return Err(Error::Binding),
			};
			Ok(Body::FailureRecorded {
				attempt,
				epochs,
				boundary,
			})
		}
		_ => Err(Error::Shape),
	}
}

fn write_epochs(out: &mut Encoder<Buffer>, epochs: RemoteEpochs) -> Result<(), WriteError> {
	out.array(2)?
		.u64(epochs.run.get())?
		.u64(epochs.source.get())?;
	Ok(())
}

fn read_epochs(decoder: &mut Decoder<'_>) -> Result<RemoteEpochs, Error> {
	array(decoder, 2)?;
	Ok(RemoteEpochs {
		run: NonZeroU64::new(decoder.u64()?).ok_or(Error::Binding)?,
		source: NonZeroU64::new(decoder.u64()?).ok_or(Error::Binding)?,
	})
}
