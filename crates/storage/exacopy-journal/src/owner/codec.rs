use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use crate::{JournalJobId, LinuxFileIdentity, PlanDigest};

use super::{
	OwnerError, OwnerManifest, OwnerProfileId, OwnerStateDirectory, OwnerTimestamp, OwnerToken,
};

const FORMAT_MAJOR: u64 = 1;
const FORMAT_MINOR: u64 = 0;
const REQUIRED_FEATURES: u64 = 0;
const LINUX_PLATFORM: u64 = 1;
const PRESERVE_POLICY: u64 = 0;
// The closed local profile has fixed fields and at most five known component names.
pub(super) const MAX_BODY_BYTES: usize = 512;
const MAX_ENVELOPE_BYTES: usize = MAX_BODY_BYTES + 112;

pub(super) type BodyBytes = Cursor<[u8; MAX_BODY_BYTES]>;
type EnvelopeBytes = Cursor<[u8; MAX_ENVELOPE_BYTES]>;

#[derive(Clone, Copy)]
pub(crate) enum OwnerDomain {
	LinuxV1,
	DarwinManagedApfs,
	LinuxPublicApply,
	LinuxRemoteDownload,
	WindowsFixedNtfsBootstrap,
}

impl OwnerDomain {
	const fn wire(self) -> (u64, &'static [u8]) {
		match self {
			Self::LinuxV1 => (1, b"ExaCopy/owner/v1\0"),
			Self::DarwinManagedApfs => (2, b"ExaCopy/owner/darwin-managed-apfs/v1\0"),
			Self::LinuxPublicApply => (3, b"ExaCopy/owner/linux-public-apply/v1\0"),
			Self::LinuxRemoteDownload => (4, b"ExaCopy/owner/linux-remote-download/v1\0"),
			Self::WindowsFixedNtfsBootstrap => {
				(5, b"ExaCopy/owner/windows-fixed-ntfs-bootstrap/v1\0")
			}
		}
	}

	pub(crate) const fn code(self) -> u64 {
		self.wire().0
	}

	pub(crate) fn signature_input(self, body: &[u8]) -> Vec<u8> {
		let (_, prefix) = self.wire();
		[prefix, body].concat()
	}
}

pub(crate) struct Envelope<'a> {
	pub(crate) body: &'a [u8],
	pub(crate) public_key: [u8; 32],
	pub(crate) signature: [u8; 64],
}

pub(super) fn encode_envelope(
	envelope: &Envelope<'_>,
	domain: OwnerDomain,
) -> Result<EnvelopeBytes, OwnerError> {
	encode_envelope_bounded(envelope, domain)
}

pub(crate) fn encode_envelope_bounded<const N: usize>(
	envelope: &Envelope<'_>,
	domain: OwnerDomain,
) -> Result<Cursor<[u8; N]>, OwnerError> {
	let (code, _) = domain.wire();
	let mut encoder = Encoder::new(Cursor::new([0; N]));
	encoder
		.map(4)?
		.u64(0)?
		.bytes(envelope.body)?
		.u64(1)?
		.bytes(&envelope.public_key)?
		.u64(2)?
		.bytes(&envelope.signature)?
		.u64(3)?
		.u64(code)?;
	Ok(encoder.into_writer())
}

pub(super) fn decode_envelope(
	bytes: &[u8],
	domain: OwnerDomain,
) -> Result<Envelope<'_>, OwnerError> {
	decode_envelope_bounded::<MAX_BODY_BYTES, MAX_ENVELOPE_BYTES>(bytes, domain)
}

pub(crate) fn decode_envelope_bounded<const BODY: usize, const ENVELOPE: usize>(
	bytes: &[u8],
	domain: OwnerDomain,
) -> Result<Envelope<'_>, OwnerError> {
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 4)?;
	key(&mut decoder, 0)?;
	let body = decoder.bytes()?;
	if body.len() > BODY {
		return Err(OwnerError::Length);
	}
	key(&mut decoder, 1)?;
	let public_key = fixed_bytes(&mut decoder)?;
	key(&mut decoder, 2)?;
	let signature = fixed_bytes(&mut decoder)?;
	key(&mut decoder, 3)?;
	let (code, _) = domain.wire();
	if decoder.u64()? != code {
		return Err(OwnerError::WrongDomain);
	}
	finish(decoder)?;

	let envelope = Envelope {
		body,
		public_key,
		signature,
	};
	if encoded_bytes(&encode_envelope_bounded::<ENVELOPE>(&envelope, domain)?) != bytes {
		return Err(OwnerError::NonCanonical);
	}
	Ok(envelope)
}

pub(super) fn encode_body(
	manifest: &OwnerManifest,
	public_key: &[u8; 32],
) -> Result<BodyBytes, OwnerError> {
	let mut encoder = Encoder::new(Cursor::new([0; MAX_BODY_BYTES]));
	encoder
		.map(11)?
		.u64(0)?
		.map(3)?
		.u64(0)?
		.u64(FORMAT_MAJOR)?
		.u64(1)?
		.u64(FORMAT_MINOR)?
		.u64(2)?
		.u64(REQUIRED_FEATURES)?
		.u64(1)?
		.bytes(manifest.token.as_bytes())?
		.u64(2)?
		.bytes(manifest.job.as_bytes())?
		.u64(3)?
		.bytes(manifest.profile.as_bytes())?
		.u64(4)?
		.bytes(public_key)?
		.u64(5)?
		.map(2)?
		.u64(0)?
		.i64(manifest.created.seconds())?
		.u64(1)?
		.u32(manifest.created.nanoseconds())?
		.u64(6)?
		.map(2)?
		.u64(0)?
		.u64(LINUX_PLATFORM)?
		.u64(1)?
		.bytes(&manifest.destination_device.to_le_bytes())?
		.u64(7)?
		.map(4)?
		.u64(0)?
		.u64(LINUX_PLATFORM)?
		.u64(1)?
		.bytes(&manifest.state_root.device().to_le_bytes())?
		.u64(2)?
		.bytes(&manifest.state_root.inode().to_le_bytes())?
		.u64(3)?
		.null()?
		.u64(8)?
		.bytes(manifest.plan_digest.as_bytes())?
		.u64(9)?
		.u64(PRESERVE_POLICY)?;
	let count =
		u64::try_from(manifest.directories.len()).map_err(|_| OwnerError::InvalidDirectories)?;
	encoder.u64(10)?.array(count)?;
	for directory in &manifest.directories {
		encoder.str(directory.name())?;
	}
	Ok(encoder.into_writer())
}

pub(super) fn decode_body(
	bytes: &[u8],
	expected_key: &[u8; 32],
) -> Result<OwnerManifest, OwnerError> {
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 11)?;
	key(&mut decoder, 0)?;
	decode_version(&mut decoder)?;
	key(&mut decoder, 1)?;
	let token = OwnerToken::from_bytes(fixed_bytes(&mut decoder)?)?;
	key(&mut decoder, 2)?;
	let job =
		JournalJobId::from_bytes(fixed_bytes(&mut decoder)?).map_err(|_| OwnerError::InvalidJob)?;
	key(&mut decoder, 3)?;
	let profile = OwnerProfileId::from_bytes(fixed_bytes(&mut decoder)?)?;
	key(&mut decoder, 4)?;
	if fixed_bytes::<32>(&mut decoder)? != *expected_key {
		return Err(OwnerError::UntrustedKey);
	}
	key(&mut decoder, 5)?;
	let created = decode_timestamp(&mut decoder)?;
	key(&mut decoder, 6)?;
	map(&mut decoder, 2)?;
	decode_platform(&mut decoder)?;
	key(&mut decoder, 1)?;
	let destination_device = u64::from_le_bytes(fixed_bytes(&mut decoder)?);
	key(&mut decoder, 7)?;
	let state_root = decode_root_identity(&mut decoder)?;
	key(&mut decoder, 8)?;
	let plan_digest = PlanDigest::from_bytes(fixed_bytes(&mut decoder)?);
	key(&mut decoder, 9)?;
	if decoder.u64()? != PRESERVE_POLICY {
		return Err(OwnerError::UnsupportedPolicy);
	}
	key(&mut decoder, 10)?;
	let directories = decode_directories(&mut decoder)?;
	finish(decoder)?;

	let manifest = OwnerManifest {
		token,
		job,
		profile,
		created,
		destination_device,
		state_root,
		plan_digest,
		directories,
	};
	manifest.validate()?;
	if encoded_bytes(&encode_body(&manifest, expected_key)?) != bytes {
		return Err(OwnerError::NonCanonical);
	}
	Ok(manifest)
}

fn decode_version(decoder: &mut Decoder<'_>) -> Result<(), OwnerError> {
	map(decoder, 3)?;
	key(decoder, 0)?;
	let major = decoder.u64()?;
	key(decoder, 1)?;
	let minor = decoder.u64()?;
	key(decoder, 2)?;
	let required = decoder.u64()?;
	if (major, minor, required) != (FORMAT_MAJOR, FORMAT_MINOR, REQUIRED_FEATURES) {
		return Err(OwnerError::UnsupportedVersion);
	}
	Ok(())
}

pub(super) fn decode_timestamp(decoder: &mut Decoder<'_>) -> Result<OwnerTimestamp, OwnerError> {
	map(decoder, 2)?;
	key(decoder, 0)?;
	let seconds = decoder.i64()?;
	key(decoder, 1)?;
	let nanoseconds = u32::try_from(decoder.u64()?).map_err(|_| OwnerError::InvalidTimestamp)?;
	OwnerTimestamp::new(seconds, nanoseconds)
}

fn decode_platform(decoder: &mut Decoder<'_>) -> Result<(), OwnerError> {
	key(decoder, 0)?;
	if decoder.u64()? != LINUX_PLATFORM {
		return Err(OwnerError::UnsupportedIdentity);
	}
	Ok(())
}

fn decode_root_identity(decoder: &mut Decoder<'_>) -> Result<LinuxFileIdentity, OwnerError> {
	map(decoder, 4)?;
	decode_platform(decoder)?;
	key(decoder, 1)?;
	let device = u64::from_le_bytes(fixed_bytes(decoder)?);
	key(decoder, 2)?;
	let inode = u64::from_le_bytes(fixed_bytes(decoder)?);
	key(decoder, 3)?;
	decoder
		.null()
		.map_err(|_| OwnerError::UnsupportedIdentity)?;
	Ok(LinuxFileIdentity::new(device, inode))
}

fn decode_directories(decoder: &mut Decoder<'_>) -> Result<Vec<OwnerStateDirectory>, OwnerError> {
	let count = decoder.array()?.ok_or(OwnerError::InvalidDirectories)?;
	let count = usize::try_from(count).map_err(|_| OwnerError::InvalidDirectories)?;
	if !(1..=OwnerStateDirectory::COUNT).contains(&count) {
		return Err(OwnerError::InvalidDirectories);
	}
	let mut names = Vec::with_capacity(count);
	for _ in 0..count {
		names.push(OwnerStateDirectory::from_name(decoder.str()?)?);
	}
	Ok(names)
}

pub(crate) fn encoded_bytes<const N: usize>(encoded: &Cursor<[u8; N]>) -> &[u8] {
	&encoded.get_ref()[..encoded.position()]
}

pub(crate) fn map(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), OwnerError> {
	if decoder.map()? != Some(fields) {
		return Err(OwnerError::InvalidCbor);
	}
	Ok(())
}

pub(crate) fn key(decoder: &mut Decoder<'_>, field: u64) -> Result<(), OwnerError> {
	if decoder.u64()? != field {
		return Err(OwnerError::InvalidCbor);
	}
	Ok(())
}

pub(crate) fn fixed_bytes<const N: usize>(
	decoder: &mut Decoder<'_>,
) -> Result<[u8; N], OwnerError> {
	decoder.bytes()?.try_into().map_err(|_| OwnerError::Length)
}

pub(crate) fn finish(decoder: Decoder<'_>) -> Result<(), OwnerError> {
	if decoder.position() != decoder.input().len() {
		return Err(OwnerError::TrailingBytes);
	}
	Ok(())
}

impl From<minicbor::decode::Error> for OwnerError {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::InvalidCbor
	}
}

impl From<encode::Error<EndOfArray>> for OwnerError {
	fn from(_: encode::Error<EndOfArray>) -> Self {
		Self::Length
	}
}
