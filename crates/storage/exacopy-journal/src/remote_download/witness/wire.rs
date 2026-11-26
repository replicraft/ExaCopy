use std::num::NonZeroU64;

use minicbor::encode::{Write, write::Cursor};
use minicbor::{Decoder, Encoder};

use crate::frame::{ChainHead, FrameKind};
use crate::owner::codec::encoded_bytes;
use crate::remote_download::wire::{fixed, key, map, write_head, write_identity, write_version};
use crate::remote_download::{RemoteDownloadContext, RemoteScopeDigest};

use super::{
	Error, MAX_REMOTE_WITNESS_INTENT_BYTES, RemoteWitnessBinding, RemoteWitnessCoverage,
	RemoteWitnessIntent, WITNESS_INTENT_DOMAIN,
};

const VERSION: [u64; 3] = [1, 0, 15];
const APPROVAL_VERSION: [u64; 3] = [1, 0, 1];
pub(super) const SELECTOR: u8 = 2;
pub(super) const CONFIRMED: u8 = 1;
const MAX_APPROVAL_BYTES: usize = 159;
const MAX_WITNESS_CLAIMS_BYTES: usize = 533;
const APPROVAL_DOMAIN: &[u8] = b"ExaCopy/linux-remote-witness-retention-approval/v1\0";

type FixedEncoder<const N: usize> = Encoder<Cursor<[u8; N]>>;

pub(super) fn encoder<const N: usize>() -> FixedEncoder<N> {
	Encoder::new(Cursor::new([0; N]))
}

pub(super) fn finish<const N: usize>(encoder: FixedEncoder<N>) -> Vec<u8> {
	encoded_bytes(&encoder.into_writer()).to_vec()
}

pub(super) fn approval_digest(
	context: RemoteDownloadContext,
	scope: RemoteScopeDigest,
	grant: [u8; 32],
	deadline: NonZeroU64,
) -> Result<[u8; 32], Error> {
	if context.owner.as_bytes() == &[0; 32]
		|| context.entry.as_bytes() == &[0; 16]
		|| scope.as_bytes() == &[0; 32]
		|| grant == [0; 32]
	{
		return Err(Error::Binding);
	}
	let mut out = encoder::<MAX_APPROVAL_BYTES>();
	out.map(8)?.u8(0)?;
	write_version(&mut out, APPROVAL_VERSION)?;
	out.u8(1)?
		.bytes(context.owner.as_bytes())?
		.u8(2)?
		.bytes(context.job.as_bytes())?
		.u8(3)?
		.bytes(context.entry.as_bytes())?
		.u8(4)?
		.bytes(scope.as_bytes())?
		.u8(5)?
		.bytes(&grant)?
		.u8(6)?
		.u8(SELECTOR)?
		.u8(7)?
		.u64(deadline.get())?;
	let encoded = out.into_writer();
	let mut hash = blake3::Hasher::new();
	hash.update(APPROVAL_DOMAIN);
	hash.update(encoded_bytes(&encoded));
	Ok(*hash.finalize().as_bytes())
}

pub(super) fn common<W: Write>(
	out: &mut Encoder<W>,
	binding: RemoteWitnessBinding,
	previous: ChainHead,
	kind: FrameKind,
) -> Result<(), minicbor::encode::Error<W::Error>> {
	out.map(6)?.u8(0)?;
	write_version(out, VERSION)?;
	out.u8(1)?
		.array(11)?
		.bytes(binding.context.owner.as_bytes())?
		.bytes(binding.context.job.as_bytes())?
		.bytes(binding.context.entry.as_bytes())?
		.bytes(binding.scope.as_bytes())?;
	write_head(out, binding.allocation)?;
	write_head(out, binding.prepared)?;
	write_head(out, binding.continuation)?;
	out.u64(binding.epochs.run.get())?
		.u64(binding.epochs.source.get())?;
	write_identity(out, binding.stage)?;
	match binding.coverage {
		RemoteWitnessCoverage::ContinuedPrefix { head, end } => {
			out.array(3)?.u8(0)?;
			write_head(out, head)?;
			out.u64(end.get())?;
		}
		RemoteWitnessCoverage::Checkpoint { head, ordinal, end } => {
			out.array(4)?.u8(1)?;
			write_head(out, head)?;
			out.u16(ordinal)?.u64(end.get())?;
		}
	}

	out.u8(2)?;
	write_head(out, previous)?;
	out.u8(3)?.u16(kind.code())?.u8(4)?.u8(SELECTOR)?.u8(5)?;
	Ok(())
}

pub(super) fn witness_claims(
	record: RemoteWitnessIntent,
	previous: ChainHead,
) -> Result<Vec<u8>, Error> {
	let mut out = encoder::<MAX_WITNESS_CLAIMS_BYTES>();
	common(
		&mut out,
		record.binding,
		previous,
		FrameKind::RemoteWitnessIntent,
	)?;
	out.array(8)?;
	write_identity(&mut out, record.stage_directory)?;
	write_identity(&mut out, record.job_directory)?;
	let mut name = [0; 40];
	let (prefix, suffix) = name.split_at_mut(b"witness.".len());
	prefix.copy_from_slice(b"witness.");
	hex(suffix, &record.nonce);
	out.bytes(&name)?
		.bytes(&record.consent.approval_digest)?
		.u64(record.consent.deadline.get())?
		.u8(CONFIRMED)?
		.u8(CONFIRMED)?
		.u8(CONFIRMED)?;
	Ok(finish(out))
}

pub(super) fn signature_input(claims: &[u8]) -> Result<Vec<u8>, Error> {
	if claims.len() > MAX_WITNESS_CLAIMS_BYTES {
		return Err(Error::Length);
	}
	let len = u32::try_from(claims.len()).map_err(|_| Error::Length)?;
	let mut input = Vec::with_capacity(WITNESS_INTENT_DOMAIN.len() + 6 + claims.len());
	input.extend_from_slice(WITNESS_INTENT_DOMAIN);
	input.extend_from_slice(&FrameKind::RemoteWitnessIntent.code().to_le_bytes());
	input.extend_from_slice(&len.to_le_bytes());
	input.extend_from_slice(claims);
	Ok(input)
}

pub(super) fn witness_envelope(claims: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>, Error> {
	let mut out = encoder::<MAX_REMOTE_WITNESS_INTENT_BYTES>();
	out.map(2)?.u8(0)?.bytes(claims)?.u8(1)?.bytes(signature)?;
	Ok(finish(out))
}

pub(super) fn read_witness_envelope(bytes: &[u8]) -> Result<(&[u8], [u8; 64]), Error> {
	if bytes.len() > MAX_REMOTE_WITNESS_INTENT_BYTES {
		return Err(Error::Length);
	}
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 2)?;
	key(&mut decoder, 0)?;
	let claims = decoder.bytes()?;
	if claims.len() > MAX_WITNESS_CLAIMS_BYTES {
		return Err(Error::Length);
	}
	key(&mut decoder, 1)?;
	let signature = fixed(&mut decoder)?;
	if decoder.position() != bytes.len() || witness_envelope(claims, &signature)? != bytes {
		return Err(Error::NonCanonical);
	}
	Ok((claims, signature))
}

pub(super) fn hex(output: &mut [u8], bytes: &[u8]) {
	const ALPHABET: &[u8; 16] = b"0123456789abcdef";
	for (pair, &byte) in output.as_chunks_mut::<2>().0.iter_mut().zip(bytes) {
		pair[0] = ALPHABET[usize::from(byte >> 4)];
		pair[1] = ALPHABET[usize::from(byte & 15)];
	}
}
