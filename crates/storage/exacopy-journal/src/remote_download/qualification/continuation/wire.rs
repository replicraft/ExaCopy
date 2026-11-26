use exacopy_endpoint::linux_remote_qualification::RemoteDestinationFacts;
use minicbor::encode::write::{Cursor, Write as _};
use minicbor::{Decoder, Encoder};

use crate::owner::codec::encoded_bytes;
use crate::remote_download::wire::{fixed, key, map};

use super::super::wire::{read_facts, write_facts};
use super::super::{MAX_REMOTE_QUALIFICATION_BYTES, RemoteQualificationError as Evidence};
use super::super::{RemoteQualificationRouteClass, RemoteQualificationScope};
use super::{
	Profile, RemoteContinuationQualificationError as Error, RemoteContinuationQualificationScope,
};

const VERSION: u8 = 2;
const QUALIFICATION_ATTESTOR_ROLE: u8 = 1;
const SIGNATURE_DOMAIN: &[u8] = b"ExaCopy/linux-remote-destination-qualification/v2\0";
const DIRECT_PINNED_TCP_V1: u8 = 1;
const EMBEDDED_WIREGUARD_TCP_V1: u8 = 2;

type Buffer = Cursor<[u8; MAX_REMOTE_QUALIFICATION_BYTES]>;

pub(super) struct Envelope<'record> {
	pub(super) body: &'record [u8],
	pub(super) key: [u8; 32],
	pub(super) signature: [u8; 64],
}

pub(super) struct Claims {
	pub(super) attestor: [u8; 16],
	pub(super) scope: RemoteContinuationQualificationScope,
	pub(super) facts: RemoteDestinationFacts,
}

pub(super) fn read_envelope(record: &[u8]) -> Result<Envelope<'_>, Evidence> {
	let mut input = Decoder::new(record);
	map(&mut input, 5)?;
	key(&mut input, 0)?;
	if input.u64()? != u64::from(VERSION) {
		return Err(Evidence::Version);
	}
	key(&mut input, 1)?;
	if input.u64()? != u64::from(QUALIFICATION_ATTESTOR_ROLE) {
		return Err(Evidence::Role);
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
		return Err(Evidence::NonCanonical);
	}
	Ok(envelope)
}

fn encode_envelope(record: &Envelope<'_>) -> Result<Buffer, Evidence> {
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

pub(super) fn with_signature_input<T>(
	record: &Envelope<'_>,
	verify: impl FnOnce(&[u8]) -> T,
) -> Result<T, Evidence> {
	let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_QUALIFICATION_BYTES]));
	out.writer_mut()
		.write_all(SIGNATURE_DOMAIN)
		.map_err(|_| Evidence::Length)?;
	out.array(4)?
		.u8(VERSION)?
		.u8(QUALIFICATION_ATTESTOR_ROLE)?
		.bytes(record.body)?
		.bytes(&record.key)?;
	Ok(verify(encoded_bytes(&out.into_writer())))
}

pub(super) fn read_claims(body: &[u8], profile: Profile) -> Result<Claims, Error> {
	let mut input = Decoder::new(body);
	map(&mut input, 9).map_err(Evidence::from)?;
	key(&mut input, 0).map_err(Evidence::from)?;
	let attestor = fixed(&mut input).map_err(Evidence::from)?;
	key(&mut input, 1).map_err(Evidence::from)?;
	let build = fixed(&mut input).map_err(Evidence::from)?;
	key(&mut input, 2).map_err(Evidence::from)?;
	let route = match input.u8().map_err(Evidence::from)? {
		DIRECT_PINNED_TCP_V1 => RemoteQualificationRouteClass::DirectPinnedTcpV1,
		EMBEDDED_WIREGUARD_TCP_V1 => RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1,
		_ => return Err(Evidence::Scope.into()),
	};
	key(&mut input, 3).map_err(Evidence::from)?;
	let campaign_scope = fixed(&mut input).map_err(Evidence::from)?;
	key(&mut input, 4).map_err(Evidence::from)?;
	let campaign_evidence = fixed(&mut input).map_err(Evidence::from)?;
	key(&mut input, 5).map_err(Evidence::from)?;
	let facts = read_facts(&mut input)?;
	let (operation_code, coverage_code, expected_mask) = profile.wire();
	key(&mut input, 6).map_err(Evidence::from)?;
	if input.u8().map_err(Evidence::from)? != operation_code {
		return Err(Error::Operation);
	}
	key(&mut input, 7).map_err(Evidence::from)?;
	if input.u8().map_err(Evidence::from)? != coverage_code {
		return Err(Error::Coverage);
	}
	key(&mut input, 8).map_err(Evidence::from)?;
	let mask = match profile {
		Profile::Original => u32::from(input.u16().map_err(Evidence::from)?),
		Profile::Witness => input.u32().map_err(Evidence::from)?,
	};
	if mask != expected_mask {
		return Err(Error::Coverage);
	}
	let (operation, coverage) = profile.selection();
	let claims = Claims {
		attestor,
		scope: RemoteContinuationQualificationScope {
			common: RemoteQualificationScope {
				build,
				route,
				campaign_scope,
				campaign_evidence,
			},
			operation,
			coverage,
		},
		facts,
	};
	if encoded_bytes(&encode_claims(&claims, profile)?) != body {
		return Err(Evidence::NonCanonical.into());
	}
	Ok(claims)
}

fn encode_claims(claims: &Claims, profile: Profile) -> Result<Buffer, Evidence> {
	let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_QUALIFICATION_BYTES]));
	let common = claims.scope.common;
	let route = match common.route {
		RemoteQualificationRouteClass::DirectPinnedTcpV1 => DIRECT_PINNED_TCP_V1,
		RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1 => EMBEDDED_WIREGUARD_TCP_V1,
	};
	let (operation, coverage, mask) = profile.wire();
	out.map(9)?
		.u8(0)?
		.bytes(&claims.attestor)?
		.u8(1)?
		.bytes(&common.build)?
		.u8(2)?
		.u8(route)?
		.u8(3)?
		.bytes(&common.campaign_scope)?
		.u8(4)?
		.bytes(&common.campaign_evidence)?
		.u8(5)?;
	write_facts(&mut out, &claims.facts)?;
	out.u8(6)?
		.u8(operation)?
		.u8(7)?
		.u8(coverage)?
		.u8(8)?
		.u32(mask)?;
	Ok(out.into_writer())
}
