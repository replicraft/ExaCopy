use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

use crate::owner::codec::{OwnerDomain, encoded_bytes, finish, fixed_bytes, key, map};
use crate::{JournalJobId, OwnerDigest, OwnerError, OwnerProfileId, OwnerToken};

use super::{
	PREPARED_BYTES, WindowsBootstrapFileIdentity, WindowsBootstrapOwner,
	WindowsBootstrapOwnerError, WindowsBootstrapRoles,
};

pub(super) const DOMAIN: OwnerDomain = OwnerDomain::WindowsFixedNtfsBootstrap;
pub(super) const OWNER_BODY_BYTES: usize = 234;

const VERSION_MAJOR: u64 = 1;
const VERSION_MINOR: u64 = 0;
const ROLE_BINDING_REQUIRED: u64 = 1;
const FIXED_LAYOUT: u64 = 1;
const ROLE_TUPLE_LENGTH: u64 = 7;

pub(super) fn encode_owner(
	owner: &WindowsBootstrapOwner,
	public_key: &[u8; 32],
) -> Result<Cursor<[u8; OWNER_BODY_BYTES]>, OwnerError> {
	let mut encoder = Encoder::new(Cursor::new([0; OWNER_BODY_BYTES]));
	encode_version(&mut encoder)?;
	encoder
		.u64(1)?
		.bytes(owner.profile.as_bytes())?
		.u64(2)?
		.bytes(owner.job.as_bytes())?
		.u64(3)?
		.bytes(owner.token.as_bytes())?
		.u64(4)?
		.bytes(public_key)?;
	encode_layout(&mut encoder, owner.roles)?;
	Ok(encoder.into_writer())
}

pub(super) fn decode_owner(
	bytes: &[u8],
	public_key: &[u8; 32],
) -> Result<WindowsBootstrapOwner, WindowsBootstrapOwnerError> {
	if bytes.len() != OWNER_BODY_BYTES {
		return Err(OwnerError::Length.into());
	}
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 7)?;
	decode_version(&mut decoder)?;
	key(&mut decoder, 1)?;
	let profile = OwnerProfileId::from_bytes(fixed_bytes(&mut decoder)?)?;
	key(&mut decoder, 2)?;
	let job =
		JournalJobId::from_bytes(fixed_bytes(&mut decoder)?).map_err(|_| OwnerError::InvalidJob)?;
	key(&mut decoder, 3)?;
	let token = OwnerToken::from_bytes(fixed_bytes(&mut decoder)?)?;
	key(&mut decoder, 4)?;
	if fixed_bytes::<32>(&mut decoder)? != *public_key {
		return Err(OwnerError::UntrustedKey.into());
	}
	key(&mut decoder, 5)?;
	if decoder.u64().map_err(OwnerError::from)? != FIXED_LAYOUT {
		return Err(WindowsBootstrapOwnerError::Layout);
	}
	key(&mut decoder, 6)?;
	let roles = decode_roles(&mut decoder)?;
	finish(decoder)?;
	let owner = WindowsBootstrapOwner {
		profile,
		job,
		token,
		roles,
	};
	owner.validate()?;
	if encoded_bytes(&encode_owner(&owner, public_key)?) != bytes {
		return Err(OwnerError::NonCanonical.into());
	}
	Ok(owner)
}

pub(super) fn encode_prepared(
	owner: &WindowsBootstrapOwner,
	digest: OwnerDigest,
) -> Result<[u8; PREPARED_BYTES], OwnerError> {
	let mut encoder = Encoder::new(Cursor::new([0; PREPARED_BYTES]));
	encode_version(&mut encoder)?;
	encoder
		.u64(1)?
		.u64(DOMAIN.code())?
		.u64(2)?
		.bytes(owner.job.as_bytes())?
		.u64(3)?
		.bytes(owner.token.as_bytes())?
		.u64(4)?
		.bytes(digest.as_bytes())?;
	encode_layout(&mut encoder, owner.roles)?;
	encoded_bytes(&encoder.into_writer())
		.try_into()
		.map_err(|_| OwnerError::Length)
}

fn encode_version<const N: usize>(
	encoder: &mut Encoder<Cursor<[u8; N]>>,
) -> Result<(), OwnerError> {
	encoder
		.map(7)?
		.u64(0)?
		.map(3)?
		.u64(0)?
		.u64(VERSION_MAJOR)?
		.u64(1)?
		.u64(VERSION_MINOR)?
		.u64(2)?
		.u64(ROLE_BINDING_REQUIRED)?;
	Ok(())
}

fn decode_version(decoder: &mut Decoder<'_>) -> Result<(), OwnerError> {
	key(decoder, 0)?;
	map(decoder, 3)?;
	key(decoder, 0)?;
	let major = decoder.u64()?;
	key(decoder, 1)?;
	let minor = decoder.u64()?;
	key(decoder, 2)?;
	let required = decoder.u64()?;
	if (major, minor, required) != (VERSION_MAJOR, VERSION_MINOR, ROLE_BINDING_REQUIRED) {
		return Err(OwnerError::UnsupportedVersion);
	}
	Ok(())
}

fn encode_layout<const N: usize>(
	encoder: &mut Encoder<Cursor<[u8; N]>>,
	roles: WindowsBootstrapRoles,
) -> Result<(), OwnerError> {
	let root = roles.root();
	encoder
		.u64(5)?
		.u64(FIXED_LAYOUT)?
		.u64(6)?
		.array(ROLE_TUPLE_LENGTH)?
		.bytes(root.volume_guid())?
		.bytes(&root.volume_serial().to_le_bytes())?;
	for identity in roles.identities() {
		encoder.bytes(identity.file_id())?;
	}
	Ok(())
}

fn decode_roles(
	decoder: &mut Decoder<'_>,
) -> Result<WindowsBootstrapRoles, WindowsBootstrapOwnerError> {
	if decoder.array().map_err(OwnerError::from)? != Some(ROLE_TUPLE_LENGTH) {
		return Err(OwnerError::InvalidCbor.into());
	}
	let guid = fixed_bytes(decoder)?;
	let serial = u64::from_le_bytes(fixed_bytes(decoder)?);
	let mut next = || -> Result<_, WindowsBootstrapOwnerError> {
		Ok(WindowsBootstrapFileIdentity::new(
			guid,
			serial,
			fixed_bytes(decoder)?,
		)?)
	};
	Ok(WindowsBootstrapRoles::new(
		next()?,
		next()?,
		next()?,
		next()?,
		next()?,
	)?)
}
