use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_remote_qualification::{
	RemoteDestinationFacts, RemoteDestinationIds, RemoteKernelArchitecture,
};
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

use crate::LinuxFileIdentity;
use crate::owner::codec::encoded_bytes;

use super::super::wire::{array, fixed, key, map, read_identity, write_identity};
use super::{
	MAX_REMOTE_QUALIFICATION_BYTES, RemoteQualificationError as Error,
	RemoteQualificationRouteClass, RemoteQualificationScope,
};

const VERSION: u8 = 1;
const QUALIFICATION_ATTESTOR_ROLE: u8 = 1;
const SIGNATURE_DOMAIN: &[u8] = b"ExaCopy/linux-remote-destination-qualification/v1\0";
const DIRECT_PINNED_TCP_V1: u8 = 1;
const EMBEDDED_WIREGUARD_TCP_V1: u8 = 2;
const X86_64: u8 = 1;
const AARCH64: u8 = 2;

type Buffer = Cursor<[u8; MAX_REMOTE_QUALIFICATION_BYTES]>;

pub(super) struct Envelope<'record> {
	pub(super) body: &'record [u8],
	pub(super) key: [u8; 32],
	pub(super) signature: [u8; 64],
}

pub(super) struct Claims {
	pub(super) attestor: [u8; 16],
	pub(super) scope: RemoteQualificationScope,
	pub(super) facts: RemoteDestinationFacts,
}

pub(super) fn read_envelope(record: &[u8]) -> Result<Envelope<'_>, Error> {
	let mut input = Decoder::new(record);
	map(&mut input, 5)?;
	key(&mut input, 0)?;
	if input.u64()? != u64::from(VERSION) {
		return Err(Error::Version);
	}
	key(&mut input, 1)?;
	if input.u64()? != u64::from(QUALIFICATION_ATTESTOR_ROLE) {
		return Err(Error::Role);
	}
	key(&mut input, 2)?;
	let body = input.bytes()?;
	key(&mut input, 3)?;
	let public_key = fixed(&mut input)?;
	key(&mut input, 4)?;
	let signature = fixed(&mut input)?;
	let envelope = Envelope {
		body,
		key: public_key,
		signature,
	};
	if encoded_bytes(&encode_envelope(&envelope)?) != record {
		return Err(Error::NonCanonical);
	}
	Ok(envelope)
}

fn encode_envelope(record: &Envelope<'_>) -> Result<Buffer, Error> {
	let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_QUALIFICATION_BYTES]));
	out.map(5)?
		.u8(0)?
		.u8(VERSION)?
		.u8(1)?
		.u8(QUALIFICATION_ATTESTOR_ROLE)?
		.u8(2)?
		.bytes(record.body)?
		.u8(3)?
		.bytes(&record.key)?
		.u8(4)?
		.bytes(&record.signature)?;
	Ok(out.into_writer())
}

pub(super) fn signature_input(record: &Envelope<'_>) -> Result<Vec<u8>, Error> {
	let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_QUALIFICATION_BYTES]));
	out.array(4)?
		.u8(VERSION)?
		.u8(QUALIFICATION_ATTESTOR_ROLE)?
		.bytes(record.body)?
		.bytes(&record.key)?;
	Ok([SIGNATURE_DOMAIN, encoded_bytes(&out.into_writer())].concat())
}

pub(super) fn read_claims(body: &[u8]) -> Result<Claims, Error> {
	let mut input = Decoder::new(body);
	map(&mut input, 6)?;
	key(&mut input, 0)?;
	let attestor = fixed(&mut input)?;
	key(&mut input, 1)?;
	let build = fixed(&mut input)?;
	key(&mut input, 2)?;
	let route = match input.u8()? {
		DIRECT_PINNED_TCP_V1 => RemoteQualificationRouteClass::DirectPinnedTcpV1,
		EMBEDDED_WIREGUARD_TCP_V1 => RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1,
		_ => return Err(Error::Scope),
	};
	key(&mut input, 3)?;
	let campaign_scope = fixed(&mut input)?;
	key(&mut input, 4)?;
	let campaign_evidence = fixed(&mut input)?;
	key(&mut input, 5)?;
	let facts = read_facts(&mut input)?;
	let claims = Claims {
		attestor,
		scope: RemoteQualificationScope {
			build,
			route,
			campaign_scope,
			campaign_evidence,
		},
		facts,
	};
	if encoded_bytes(&encode_claims(&claims)?) != body {
		return Err(Error::NonCanonical);
	}
	Ok(claims)
}

fn encode_claims(claims: &Claims) -> Result<Buffer, Error> {
	let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_QUALIFICATION_BYTES]));
	let route = match claims.scope.route {
		RemoteQualificationRouteClass::DirectPinnedTcpV1 => DIRECT_PINNED_TCP_V1,
		RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1 => EMBEDDED_WIREGUARD_TCP_V1,
	};
	out.map(6)?
		.u8(0)?
		.bytes(&claims.attestor)?
		.u8(1)?
		.bytes(&claims.scope.build)?
		.u8(2)?
		.u8(route)?
		.u8(3)?
		.bytes(&claims.scope.campaign_scope)?
		.u8(4)?
		.bytes(&claims.scope.campaign_evidence)?
		.u8(5)?;
	write_facts(&mut out, &claims.facts)?;
	Ok(out.into_writer())
}

pub(super) fn read_facts(input: &mut Decoder<'_>) -> Result<RemoteDestinationFacts, Error> {
	array(input, 11)?;
	let root = read_identity(input)?;
	let ids = RemoteDestinationIds {
		root: JobFileIdentity {
			device: root.device(),
			inode: root.inode(),
		},
		effective_uid: input.u32()?,
		effective_gid: input.u32()?,
		boot_id: fixed(input)?,
		mount_namespace: input.u64()?,
		mount_id: input.u64()?,
		unique_mount: input.u64()?,
	};
	let architecture = match input.u8()? {
		X86_64 => RemoteKernelArchitecture::X86_64,
		AARCH64 => RemoteKernelArchitecture::Aarch64,
		_ => return Err(Error::DestinationFacts),
	};
	RemoteDestinationFacts::new(
		ids,
		architecture,
		input.bytes()?,
		input.bytes()?,
		input.bytes()?,
	)
	.ok_or(Error::DestinationFacts)
}

pub(super) fn write_facts(
	out: &mut Encoder<Buffer>,
	facts: &RemoteDestinationFacts,
) -> Result<(), Error> {
	let architecture = match facts.architecture() {
		RemoteKernelArchitecture::X86_64 => X86_64,
		RemoteKernelArchitecture::Aarch64 => AARCH64,
		_ => return Err(Error::DestinationFacts),
	};
	let ids = facts.ids();
	out.array(11)?;
	write_identity(out, LinuxFileIdentity::new(ids.root.device, ids.root.inode))?;
	out.u32(ids.effective_uid)?
		.u32(ids.effective_gid)?
		.bytes(&ids.boot_id)?
		.u64(ids.mount_namespace)?
		.u64(ids.mount_id)?
		.u64(ids.unique_mount)?
		.u8(architecture)?
		.bytes(facts.kernel_release())?
		.bytes(facts.kernel_build())?
		.bytes(facts.mount_record())?;
	Ok(())
}
