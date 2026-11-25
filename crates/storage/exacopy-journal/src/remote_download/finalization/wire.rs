use std::num::NonZeroU64;

use exacopy_endpoint::UnixComponent;
use minicbor::encode::{
	self, Write,
	write::{Cursor, EndOfArray},
};
use minicbor::{Decoder, Encoder};

use crate::frame::FrameKind;
use crate::owner::codec::encoded_bytes;
use crate::{
	JournalEntryId, JournalJobId, NamespaceObservation, OwnerDigest, RootCapabilityId,
	StreamDigest, StreamLength,
};

use super::super::finalization_policy::SftpDataOnlyV1;
use super::super::wire::{
	array, fixed, key, map, read_head, read_identity, read_version, write_head, write_identity,
	write_version,
};
use super::{
	Error, MAX_REMOTE_FINALIZATION_BYTES, RemoteDownloadContext, RemoteEpochs,
	RemoteFinalizationBinding, RemoteFinalizationBody as Body, RemoteFinalizationRecord,
	RemoteLocalMetadata, RemotePublicationObservation as Observation, RemotePublishTarget,
	RemoteReceiptDigest,
};

pub(super) const VERSION: [u64; 3] = [1, 0, 3];
const FULL_FILE_BARRIER: u8 = 1;
const WRITER_CLOSED: u8 = 1;
const BLAKE3_256: u8 = 1;
const SFTP_LIVE_OBSERVED: u8 = 1;
const INDEPENDENT_BUFFERED_READBACK: u8 = 1;
const EXACT_EOF_AND_SOURCE_CLOSED: u8 = 1;
const EMPTY_VISIBLE_ATTRIBUTES: u8 = 1;
const LINUX_RENAME_NOREPLACE: u8 = 1;
const CREATE_NEW: u8 = 1;
const SINGLE_EFFECT: u8 = 1;
const REQUIRE_PROCESS_CRASH: u8 = 1;
const COMPLETED_DIRECTORY_BARRIERS: u8 = 1;
const RECEIPT_ARTIFACT_BARRIERS: u8 = 1;

type Buffer = Cursor<[u8; MAX_REMOTE_FINALIZATION_BYTES]>;

pub(super) fn encode(record: &RemoteFinalizationRecord<'_>) -> Result<Vec<u8>, Error> {
	Ok(encoded_bytes(&encode_into(record)?).to_vec())
}

pub(super) fn decode(bytes: &[u8]) -> Result<RemoteFinalizationRecord<'_>, Error> {
	if bytes.len() > MAX_REMOTE_FINALIZATION_BYTES {
		return Err(Error::Length);
	}
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 5)?;
	key(&mut decoder, 0)?;
	read_version(&mut decoder, VERSION)?;
	key(&mut decoder, 1)?;
	let binding = read_binding(&mut decoder)?;
	key(&mut decoder, 2)?;
	let predecessor = read_head(&mut decoder)?;
	key(&mut decoder, 3)?;
	let kind = decoder.u16()?;
	key(&mut decoder, 4)?;
	let body = read_body(&mut decoder, kind)?;
	let record = RemoteFinalizationRecord::new(binding, predecessor, body)?;
	if encoded_bytes(&encode_into(&record)?) != bytes {
		return Err(Error::NonCanonical);
	}
	Ok(record)
}

fn encode_into(record: &RemoteFinalizationRecord<'_>) -> Result<Buffer, Error> {
	let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_FINALIZATION_BYTES]));
	out.map(5)?.u8(0)?;
	write_version(&mut out, VERSION)?;
	out.u8(1)?;
	write_binding(&mut out, record.binding())?;
	out.u8(2)?;
	write_head(&mut out, record.predecessor())?;
	out.u8(3)?.u16(record.body().kind().code())?.u8(4)?;
	write_body(&mut out, record.body())?;
	Ok(out.into_writer())
}

fn write_binding<W: Write>(
	out: &mut Encoder<W>,
	binding: RemoteFinalizationBinding,
) -> Result<(), encode::Error<W::Error>> {
	let context = binding.context;
	out.array(7)?
		.bytes(context.owner.as_bytes())?
		.bytes(context.job.as_bytes())?
		.bytes(context.entry.as_bytes())?;
	write_head(out, binding.prepared)?;
	out.u64(binding.epochs.run.get())?
		.u64(binding.epochs.source.get())?;
	write_identity(out, binding.stage)?;
	Ok(())
}

fn read_binding(decoder: &mut Decoder<'_>) -> Result<RemoteFinalizationBinding, Error> {
	array(decoder, 7)?;
	let owner = OwnerDigest::from_bytes(fixed(decoder)?);
	let job = JournalJobId::from_bytes(fixed(decoder)?).map_err(|_| Error::Binding)?;
	let entry = JournalEntryId::from_bytes(fixed(decoder)?);
	let prepared = read_head(decoder)?;
	let run = NonZeroU64::new(decoder.u64()?).ok_or(Error::Binding)?;
	let source = NonZeroU64::new(decoder.u64()?).ok_or(Error::Binding)?;
	Ok(RemoteFinalizationBinding {
		context: RemoteDownloadContext { owner, job, entry },
		prepared,
		epochs: RemoteEpochs { run, source },
		stage: read_identity(decoder)?,
	})
}

fn write_body(out: &mut Encoder<Buffer>, body: Body<'_>) -> Result<(), encode::Error<EndOfArray>> {
	match body {
		Body::StageSealed { directory, length } => {
			out.array(4)?;
			write_identity(out, directory)?;
			out.u64(length.get())?
				.u8(WRITER_CLOSED)?
				.u8(FULL_FILE_BARRIER)?;
		}
		Body::VerificationRecorded {
			length,
			source,
			stage,
		} => {
			out.array(7)?
				.u64(length.get())?
				.bytes(source.as_bytes())?
				.bytes(stage.as_bytes())?
				.u8(BLAKE3_256)?
				.u8(SFTP_LIVE_OBSERVED)?
				.u8(INDEPENDENT_BUFFERED_READBACK)?
				.u8(EXACT_EOF_AND_SOURCE_CLOSED)?;
		}
		Body::MetadataRecorded(metadata) => {
			out.array(7)?
				.bytes(&SftpDataOnlyV1::digest())?
				.u16(SftpDataOnlyV1::LOCAL_MODE)?
				.u32(metadata.uid)?
				.u32(metadata.gid)?
				.u8(EMPTY_VISIBLE_ATTRIBUTES)?
				.u8(FULL_FILE_BARRIER)?;
			write_omissions(out)?;
		}
		Body::PublishIntent {
			seal,
			verification,
			directory,
			target,
			qualification,
		} => {
			out.array(8)?;
			write_head(out, seal)?;
			write_head(out, verification)?;
			write_identity(out, directory)?;
			write_target(out, target)?;
			out.bytes(&qualification)?
				.u8(LINUX_RENAME_NOREPLACE)?
				.u8(CREATE_NEW)?
				.u8(SINGLE_EFFECT)?;
		}
		Body::PublishObserved(observation) => write_outcome(out, observation)?,
		Body::DurabilityRecorded {
			metadata,
			directory,
			parent,
			qualification,
		} => {
			out.array(7)?;
			write_head(out, metadata)?;
			write_identity(out, directory)?;
			write_identity(out, parent)?;
			out.bytes(&qualification)?
				.u8(REQUIRE_PROCESS_CRASH)?
				.u8(FULL_FILE_BARRIER)?
				.u8(COMPLETED_DIRECTORY_BARRIERS)?;
		}
		Body::ReceiptCommitted { digest } => {
			out.array(2)?
				.bytes(digest.as_bytes())?
				.u8(RECEIPT_ARTIFACT_BARRIERS)?;
		}
	}
	Ok(())
}

fn read_body<'name>(decoder: &mut Decoder<'name>, kind: u16) -> Result<Body<'name>, Error> {
	Ok(match kind {
		code if code == FrameKind::StageSealed.code() => {
			array(decoder, 4)?;
			let directory = read_identity(decoder)?;
			let length = read_length(decoder)?;
			key(decoder, WRITER_CLOSED)?;
			key(decoder, FULL_FILE_BARRIER)?;
			Body::StageSealed { directory, length }
		}
		code if code == FrameKind::VerificationRecorded.code() => {
			array(decoder, 7)?;
			let length = read_length(decoder)?;
			let source = StreamDigest::from_bytes(fixed(decoder)?);
			let stage = StreamDigest::from_bytes(fixed(decoder)?);
			key(decoder, BLAKE3_256)?;
			key(decoder, SFTP_LIVE_OBSERVED)?;
			key(decoder, INDEPENDENT_BUFFERED_READBACK)?;
			key(decoder, EXACT_EOF_AND_SOURCE_CLOSED)?;
			Body::VerificationRecorded {
				length,
				source,
				stage,
			}
		}
		code if code == FrameKind::MetadataRecorded.code() => {
			array(decoder, 7)?;
			if fixed::<32>(decoder)? != SftpDataOnlyV1::digest()
				|| decoder.u16()? != SftpDataOnlyV1::LOCAL_MODE
			{
				return Err(Error::Binding);
			}
			let metadata = RemoteLocalMetadata {
				uid: decoder.u32()?,
				gid: decoder.u32()?,
			};
			key(decoder, EMPTY_VISIBLE_ATTRIBUTES)?;
			key(decoder, FULL_FILE_BARRIER)?;
			read_omissions(decoder)?;
			Body::MetadataRecorded(metadata)
		}
		code if code == FrameKind::PublishIntent.code() => {
			array(decoder, 8)?;
			let seal = read_head(decoder)?;
			let verification = read_head(decoder)?;
			let directory = read_identity(decoder)?;
			let target = read_target(decoder)?;
			let qualification = fixed(decoder)?;
			key(decoder, LINUX_RENAME_NOREPLACE)?;
			key(decoder, CREATE_NEW)?;
			key(decoder, SINGLE_EFFECT)?;
			Body::PublishIntent {
				seal,
				verification,
				directory,
				target,
				qualification,
			}
		}
		code if code == FrameKind::PublishObserved.code() => {
			Body::PublishObserved(read_outcome(decoder)?)
		}
		code if code == FrameKind::DurabilityRecorded.code() => {
			array(decoder, 7)?;
			let metadata = read_head(decoder)?;
			let directory = read_identity(decoder)?;
			let parent = read_identity(decoder)?;
			let qualification = fixed(decoder)?;
			key(decoder, REQUIRE_PROCESS_CRASH)?;
			key(decoder, FULL_FILE_BARRIER)?;
			key(decoder, COMPLETED_DIRECTORY_BARRIERS)?;
			Body::DurabilityRecorded {
				metadata,
				directory,
				parent,
				qualification,
			}
		}
		code if code == FrameKind::ReceiptCommitted.code() => {
			array(decoder, 2)?;
			let digest = RemoteReceiptDigest::from_bytes(fixed(decoder)?);
			key(decoder, RECEIPT_ARTIFACT_BARRIERS)?;
			Body::ReceiptCommitted { digest }
		}
		_ => return Err(Error::Shape),
	})
}

fn read_length(decoder: &mut Decoder<'_>) -> Result<StreamLength, Error> {
	StreamLength::new(decoder.u64()?).map_err(|_| Error::Length)
}

fn write_target<W: Write>(
	out: &mut Encoder<W>,
	target: RemotePublishTarget<'_>,
) -> Result<(), encode::Error<W::Error>> {
	out.array(3)?.bytes(target.root.as_bytes())?;
	write_identity(out, target.parent)?;
	out.bytes(target.component.as_bytes())?;
	Ok(())
}

fn read_target<'name>(decoder: &mut Decoder<'name>) -> Result<RemotePublishTarget<'name>, Error> {
	array(decoder, 3)?;
	let root = RootCapabilityId::from_bytes(fixed(decoder)?).map_err(|_| Error::Binding)?;
	let parent = read_identity(decoder)?;
	let component = UnixComponent::new(decoder.bytes()?).map_err(|_| Error::Scope)?;
	Ok(RemotePublishTarget {
		root,
		parent,
		component,
	})
}

pub(super) fn write_omissions<W: Write>(
	out: &mut Encoder<W>,
) -> Result<(), encode::Error<W::Error>> {
	let omissions = SftpDataOnlyV1::omissions();
	out.array(u64::try_from(omissions.len()).expect("fixed omission count fits"))?;
	for omission in omissions {
		out.u8(omission.code())?;
	}
	Ok(())
}

pub(super) fn read_omissions(decoder: &mut Decoder<'_>) -> Result<(), Error> {
	let omissions = SftpDataOnlyV1::omissions();
	array(
		decoder,
		u64::try_from(omissions.len()).map_err(|_| Error::Length)?,
	)?;
	for omission in omissions {
		key(decoder, omission.code())?;
	}
	Ok(())
}

fn write_outcome<W: Write>(
	out: &mut Encoder<W>,
	observation: Observation,
) -> Result<(), encode::Error<W::Error>> {
	match observation {
		Observation::Published(target) => {
			out.array(2)?.u8(1)?;
			write_identity(out, target)?;
		}
		Observation::Conflict => {
			out.array(1)?.u8(2)?;
		}
		Observation::Uncertain { target, stage } => {
			out.array(3)?.u8(3)?;
			write_observed_name(out, target)?;
			write_observed_name(out, stage)?;
		}
	}
	Ok(())
}

fn read_outcome(decoder: &mut Decoder<'_>) -> Result<Observation, Error> {
	match (decoder.array()?, decoder.u8()?) {
		(Some(2), 1) => Ok(Observation::Published(read_identity(decoder)?)),
		(Some(1), 2) => Ok(Observation::Conflict),
		(Some(3), 3) => Ok(Observation::Uncertain {
			target: read_observed_name(decoder)?,
			stage: read_observed_name(decoder)?,
		}),
		_ => Err(Error::Shape),
	}
}

fn write_observed_name<W: Write>(
	out: &mut Encoder<W>,
	observation: NamespaceObservation,
) -> Result<(), encode::Error<W::Error>> {
	match observation {
		NamespaceObservation::Unobserved => {
			out.array(1)?.u8(0)?;
		}
		NamespaceObservation::Absent => {
			out.array(1)?.u8(1)?;
		}
		NamespaceObservation::Present(identity) => {
			out.array(2)?.u8(2)?;
			write_identity(out, identity)?;
		}
	}
	Ok(())
}

fn read_observed_name(decoder: &mut Decoder<'_>) -> Result<NamespaceObservation, Error> {
	match (decoder.array()?, decoder.u8()?) {
		(Some(1), 0) => Ok(NamespaceObservation::Unobserved),
		(Some(1), 1) => Ok(NamespaceObservation::Absent),
		(Some(2), 2) => Ok(NamespaceObservation::Present(read_identity(decoder)?)),
		_ => Err(Error::Shape),
	}
}
