use std::num::NonZeroU64;

use exacopy_endpoint::UnixComponent;
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

use crate::owner::codec::encoded_bytes;
use crate::{JournalEntryId, JournalJobId, OwnerDigest, RootCapabilityId};

use super::super::finalization::RemotePublishTarget;
use super::super::wire::{
	array, fixed, key, map, read_head, read_identity, read_version, write_head, write_identity,
	write_version,
};
use super::super::{RemoteDownloadContext, RemoteEpochs, RemoteScopeDigest};
use super::{
	Error, MAX_REMOTE_RETIREMENT_BYTES, RecordedRetirementObservation, RemoteCaptureRetired,
	RetirementBinding,
};

const VERSION: [u64; 3] = [1, 0, 7];
const TARGET_ABSENT: u8 = 1;
const PRESERVE_OLD_STAGE: u8 = 1;

type Buffer = Cursor<[u8; MAX_REMOTE_RETIREMENT_BYTES]>;

pub(super) fn encode(record: RemoteCaptureRetired<'_>) -> Result<Vec<u8>, Error> {
	Ok(encoded_bytes(&encode_into(record)?).to_vec())
}

fn encode_into(record: RemoteCaptureRetired<'_>) -> Result<Buffer, Error> {
	let binding = record.binding();
	let observed = record.observation();
	let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_RETIREMENT_BYTES]));
	out.map(8)?.u8(0)?;
	write_version(&mut out, VERSION)?;
	out.u8(1)?
		.array(4)?
		.bytes(binding.context.owner.as_bytes())?
		.bytes(binding.context.job.as_bytes())?
		.bytes(binding.context.entry.as_bytes())?
		.bytes(binding.scope.as_bytes())?
		.u8(2)?;
	write_head(&mut out, binding.predecessor)?;
	out.u8(3)?.array(6)?;
	for head in [
		binding.bootstrap,
		binding.allocation,
		binding.prepared,
		binding.seal,
	] {
		write_head(&mut out, head)?;
	}
	out.u64(binding.epochs.run.get())?
		.u64(binding.epochs.source.get())?
		.u8(4)?
		.array(2)?;
	write_identity(&mut out, observed.directory)?;
	write_identity(&mut out, observed.stage)?;
	out.u8(5)?
		.array(3)?
		.bytes(observed.target.root.as_bytes())?;
	write_identity(&mut out, observed.target.parent)?;
	out.bytes(observed.target.component.as_bytes())?
		.u8(6)?
		.bytes(&observed.qualification_digest)?
		.u8(7)?
		.array(3)?
		.bytes(&observed.grant_digest)?
		.u8(TARGET_ABSENT)?
		.u8(PRESERVE_OLD_STAGE)?;
	Ok(out.into_writer())
}

pub(super) fn decode(bytes: &[u8]) -> Result<RemoteCaptureRetired<'_>, Error> {
	if bytes.len() > MAX_REMOTE_RETIREMENT_BYTES {
		return Err(Error::Length);
	}
	let mut input = Decoder::new(bytes);
	map(&mut input, 8)?;
	key(&mut input, 0)?;
	read_version(&mut input, VERSION)?;
	key(&mut input, 1)?;
	array(&mut input, 4)?;
	let context = RemoteDownloadContext {
		owner: OwnerDigest::from_bytes(fixed(&mut input)?),
		job: JournalJobId::from_bytes(fixed(&mut input)?).map_err(|_| Error::Binding)?,
		entry: JournalEntryId::from_bytes(fixed(&mut input)?),
	};
	let scope = RemoteScopeDigest::from_bytes(fixed(&mut input)?);
	key(&mut input, 2)?;
	let predecessor = read_head(&mut input)?;
	key(&mut input, 3)?;
	array(&mut input, 6)?;
	let binding = RetirementBinding {
		context,
		scope,
		predecessor,
		bootstrap: read_head(&mut input)?,
		allocation: read_head(&mut input)?,
		prepared: read_head(&mut input)?,
		seal: read_head(&mut input)?,
		epochs: RemoteEpochs {
			run: NonZeroU64::new(input.u64()?).ok_or(Error::Binding)?,
			source: NonZeroU64::new(input.u64()?).ok_or(Error::Binding)?,
		},
	};
	key(&mut input, 4)?;
	array(&mut input, 2)?;
	let directory = read_identity(&mut input)?;
	let stage = read_identity(&mut input)?;
	key(&mut input, 5)?;
	array(&mut input, 3)?;
	let target = RemotePublishTarget {
		root: RootCapabilityId::from_bytes(fixed(&mut input)?).map_err(|_| Error::Binding)?,
		parent: read_identity(&mut input)?,
		component: UnixComponent::new(input.bytes()?).map_err(|_| Error::Scope)?,
	};
	key(&mut input, 6)?;
	let qualification_digest = fixed(&mut input)?;
	key(&mut input, 7)?;
	array(&mut input, 3)?;
	let grant_digest = fixed(&mut input)?;
	key(&mut input, TARGET_ABSENT)?;
	key(&mut input, PRESERVE_OLD_STAGE)?;
	let record = RemoteCaptureRetired::new(
		binding,
		RecordedRetirementObservation {
			directory,
			stage,
			target,
			qualification_digest,
			grant_digest,
		},
	)?;
	if encoded_bytes(&encode_into(record)?) != bytes {
		return Err(Error::NonCanonical);
	}
	Ok(record)
}
