use std::num::NonZeroU64;

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

use crate::frame::FrameKind;
use crate::owner::codec::encoded_bytes;
use crate::remote_download::wire::{
	array, fixed, key, map, read_head, read_identity, read_version, write_head, write_identity,
	write_version,
};
use crate::{JournalEntryId, JournalJobId, OwnerDigest};

use super::{
	CoverageBasis, Error, MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES, PriorPreparation,
	RemoteContinuationClaims, RemoteContinuationCoverage, RemoteContinuationPrior,
	RemoteDownloadContext, RemoteEpochs, RemoteReplayBoundary, RemoteScopeDigest,
	RemoteSourceObservation, StreamDigest, StreamLength, UnixComponent,
};

const VERSION: [u64; 3] = [1, 0, 15];
const SIGNATURE_DOMAIN: &[u8] = b"ExaCopy/linux-remote-capture-continuation/v1\0";
const CONTINUATION_KIND: u16 = FrameKind::RemoteCaptureContinued.code();
const ORIGINAL_PREPARATION_KIND: u16 = FrameKind::EntryPrepared.code();
const CHECKPOINT_KIND: u16 = FrameKind::RangeCheckpoint.code();
const OBSERVED_PREFIX_STRATEGY: u8 = 1;
const RETAINED_PREFIX_BARRIER: u8 = 1;
const TARGET_ABSENT: u8 = 1;

type Buffer = Cursor<[u8; MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES]>;

pub(super) fn signature_input(body: &[u8]) -> Result<Vec<u8>, Error> {
	let length = u32::try_from(body.len()).map_err(|_| Error::Length)?;
	Ok([
		SIGNATURE_DOMAIN,
		&CONTINUATION_KIND.to_le_bytes(),
		&length.to_le_bytes(),
		body,
	]
	.concat())
}

pub(super) fn encode_envelope(body: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>, Error> {
	let mut out = encoder();
	out.map(2)?.u8(0)?.bytes(body)?.u8(1)?.bytes(signature)?;
	Ok(encoded_bytes(&out.into_writer()).to_vec())
}

pub(super) fn decode_envelope(bytes: &[u8]) -> Result<(&[u8], [u8; 64]), Error> {
	if bytes.len() > MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES {
		return Err(Error::Length);
	}
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 2)?;
	key(&mut decoder, 0)?;
	let body = decoder.bytes()?;
	key(&mut decoder, 1)?;
	let signature = fixed(&mut decoder)?;
	if encode_envelope(body, &signature)? != bytes {
		return Err(Error::NonCanonical);
	}
	Ok((body, signature))
}

pub(super) fn encode_body(claims: &RemoteContinuationClaims<'_>) -> Result<Vec<u8>, Error> {
	let mut out = encoder();
	out.map(9)?.u8(0)?;
	write_version(&mut out, VERSION)?;
	out.u8(1)?
		.array(4)?
		.bytes(claims.context.owner.as_bytes())?
		.bytes(claims.context.job.as_bytes())?
		.bytes(claims.context.entry.as_bytes())?
		.bytes(claims.scope.as_bytes())?
		.u8(2)?
		.array(2)?;
	write_head(&mut out, claims.previous.head)?;
	out.u64(claims.previous.offset)?.u8(3)?.array(8)?;
	write_prior(&mut out, claims.prior)?;
	out.u8(4)?.array(2)?;
	write_identity(&mut out, claims.directory)?;
	write_identity(&mut out, claims.stage)?;
	out.u8(5)?.array(4)?;
	write_coverage(&mut out, claims.coverage)?;
	out.u8(6)?
		.array(5)?
		.u64(claims.epochs.run.get())?
		.u64(claims.epochs.source.get())?
		.u64(claims.source.length().get())?
		.u32(claims.source.mode())?
		.u32(claims.source.modified_seconds())?
		.u8(7)?
		.array(3)?
		.u64(claims.adopted_end.get())?
		.bytes(claims.prefix_digest.as_bytes())?
		.u8(RETAINED_PREFIX_BARRIER)?
		.u8(8)?
		.array(4)?
		.u8(OBSERVED_PREFIX_STRATEGY)?
		.bytes(&claims.grant_digest)?
		.bytes(&claims.qualification_digest)?
		.u8(TARGET_ABSENT)?;
	Ok(encoded_bytes(&out.into_writer()).to_vec())
}

pub(super) fn decode_body(bytes: &[u8]) -> Result<RemoteContinuationClaims<'_>, Error> {
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 9)?;
	key(&mut decoder, 0)?;
	read_version(&mut decoder, VERSION)?;
	key(&mut decoder, 1)?;
	array(&mut decoder, 4)?;
	let context = RemoteDownloadContext {
		owner: OwnerDigest::from_bytes(fixed(&mut decoder)?),
		job: JournalJobId::from_bytes(fixed(&mut decoder)?).map_err(|_| Error::Binding)?,
		entry: JournalEntryId::from_bytes(fixed(&mut decoder)?),
	};
	let scope = RemoteScopeDigest::from_bytes(fixed(&mut decoder)?);
	key(&mut decoder, 2)?;
	array(&mut decoder, 2)?;
	let previous = RemoteReplayBoundary {
		head: read_head(&mut decoder)?,
		offset: decoder.u64()?,
	};
	key(&mut decoder, 3)?;
	let prior = read_prior(&mut decoder)?;
	key(&mut decoder, 4)?;
	array(&mut decoder, 2)?;
	let directory = read_identity(&mut decoder)?;
	let stage = read_identity(&mut decoder)?;
	key(&mut decoder, 5)?;
	let coverage = read_coverage(&mut decoder)?;
	key(&mut decoder, 6)?;
	array(&mut decoder, 5)?;
	let epochs = read_epochs(&mut decoder)?;
	let source_length = read_length(&mut decoder)?;
	let source = RemoteSourceObservation::new(source_length, decoder.u32()?, decoder.u32()?)?;
	key(&mut decoder, 7)?;
	array(&mut decoder, 3)?;
	let adopted_end = read_length(&mut decoder)?;
	let prefix_digest = StreamDigest::from_bytes(fixed(&mut decoder)?);
	key(&mut decoder, RETAINED_PREFIX_BARRIER)?;
	key(&mut decoder, 8)?;
	array(&mut decoder, 4)?;
	key(&mut decoder, OBSERVED_PREFIX_STRATEGY)?;
	let grant_digest = fixed(&mut decoder)?;
	let qualification_digest = fixed(&mut decoder)?;
	key(&mut decoder, TARGET_ABSENT)?;
	let claims = RemoteContinuationClaims {
		context,
		scope,
		previous,
		prior,
		directory,
		stage,
		coverage,
		epochs,
		source,
		adopted_end,
		prefix_digest,
		grant_digest,
		qualification_digest,
	};
	if encode_body(&claims)? != bytes {
		return Err(Error::NonCanonical);
	}
	Ok(claims)
}

fn encoder() -> Encoder<Buffer> {
	Encoder::new(Cursor::new([0; MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES]))
}

fn read_prior<'name>(
	decoder: &mut Decoder<'name>,
) -> Result<RemoteContinuationPrior<'name>, Error> {
	array(decoder, 8)?;
	let bootstrap = read_head(decoder)?;
	let allocation = read_head(decoder)?;
	let prepared = read_head(decoder)?;
	array(decoder, 2)?;
	let kind = decoder.u16()?;
	let head = read_head(decoder)?;
	let active = match kind {
		ORIGINAL_PREPARATION_KIND => PriorPreparation::Original(head),
		CONTINUATION_KIND => PriorPreparation::Continued(head),
		_ => return Err(Error::Shape),
	};
	Ok(RemoteContinuationPrior {
		bootstrap,
		allocation,
		prepared,
		active,
		epochs: read_epochs(decoder)?,
		name: UnixComponent::new(decoder.bytes()?).map_err(|_| Error::Binding)?,
		nonce: fixed(decoder)?,
	})
}

fn write_prior(out: &mut Encoder<Buffer>, prior: RemoteContinuationPrior<'_>) -> Result<(), Error> {
	write_head(out, prior.bootstrap)?;
	write_head(out, prior.allocation)?;
	write_head(out, prior.prepared)?;
	let kind = match prior.active {
		PriorPreparation::Original(_) => ORIGINAL_PREPARATION_KIND,
		PriorPreparation::Continued(_) => CONTINUATION_KIND,
	};
	out.array(2)?.u16(kind)?;
	write_head(out, prior.active.head())?;
	out.u64(prior.epochs.run.get())?
		.u64(prior.epochs.source.get())?
		.bytes(prior.name.as_bytes())?
		.bytes(&prior.nonce)?;
	Ok(())
}

fn read_coverage(decoder: &mut Decoder<'_>) -> Result<RemoteContinuationCoverage, Error> {
	array(decoder, 4)?;
	let kind = decoder.u16()?;
	let head = read_head(decoder)?;
	let ordinal = decoder.u16()?;
	let basis = match (kind, ordinal) {
		(CHECKPOINT_KIND, 1..) => CoverageBasis::Checkpoint { head, ordinal },
		(CONTINUATION_KIND, 0) => CoverageBasis::ContinuedPrefix(head),
		_ => return Err(Error::Shape),
	};
	Ok(RemoteContinuationCoverage {
		basis,
		end: read_length(decoder)?,
	})
}

fn write_coverage(
	out: &mut Encoder<Buffer>,
	coverage: RemoteContinuationCoverage,
) -> Result<(), Error> {
	let (kind, head, ordinal) = match coverage.basis {
		CoverageBasis::Checkpoint { head, ordinal } => (CHECKPOINT_KIND, head, ordinal),
		CoverageBasis::ContinuedPrefix(head) => (CONTINUATION_KIND, head, 0),
	};
	out.u16(kind)?;
	write_head(out, head)?;
	out.u16(ordinal)?.u64(coverage.end.get())?;
	Ok(())
}

fn read_epochs(decoder: &mut Decoder<'_>) -> Result<RemoteEpochs, Error> {
	Ok(RemoteEpochs {
		run: NonZeroU64::new(decoder.u64()?).ok_or(Error::Binding)?,
		source: NonZeroU64::new(decoder.u64()?).ok_or(Error::Binding)?,
	})
}

fn read_length(decoder: &mut Decoder<'_>) -> Result<StreamLength, Error> {
	StreamLength::new(decoder.u64()?).map_err(|_| Error::Binding)
}
