use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

use crate::owner::codec::{
	Envelope, OwnerDomain, decode_envelope_bounded, encode_envelope_bounded, encoded_bytes,
};
use crate::{
	JournalJobId, LinuxFileIdentity, OwnerDigest, OwnerError, OwnerProfileId, OwnerTimestamp,
	OwnerToken,
};

use super::scope::{MAX_BODY_BYTES, RemoteDownloadScope};
use super::wire::{
	array, fixed, key, map, read_identity, read_version, write_identity, write_version,
};
use super::{RemoteDownloadError as Error, RemoteDownloadRoute};

const DOMAIN: OwnerDomain = OwnerDomain::LinuxRemoteDownload;
const VERSION: [u64; 3] = [1, 0, 1];
const RESOLVED_DIRECT_VERSION: [u64; 3] = [1, 1, 3];

#[derive(Clone, Copy)]
enum OwnerFormat {
	V1,
	ResolvedDirect,
}

impl OwnerFormat {
	const fn version(self) -> [u64; 3] {
		match self {
			Self::V1 => VERSION,
			Self::ResolvedDirect => RESOLVED_DIRECT_VERSION,
		}
	}

	fn require_route(self, route: RemoteDownloadRoute) -> Result<(), Error> {
		match (self, route) {
			(
				Self::V1,
				RemoteDownloadRoute::Direct | RemoteDownloadRoute::EmbeddedWireGuard { .. },
			)
			| (Self::ResolvedDirect, RemoteDownloadRoute::ResolvedDirect { .. }) => Ok(()),
			_ => Err(Error::Scope),
		}
	}
}

/// Bound for the complete authenticated Linux remote-download owner envelope.
pub const MAX_REMOTE_DOWNLOAD_OWNER_BYTES: usize = 6272;

type Body = Cursor<[u8; MAX_BODY_BYTES]>;

/// Local immutable owner declaration for one live remote download.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RemoteDownloadOwner {
	/// Fresh independent random job token.
	pub token: OwnerToken,
	/// Durable UUIDv7 job identifier.
	pub job: JournalJobId,
	/// Independently selected local profile.
	pub profile: OwnerProfileId,
	/// Local UTC creation timestamp.
	pub created: OwnerTimestamp,
	/// Actual held local job-directory identity.
	pub job_directory: LinuxFileIdentity,
	/// Immutable scoped source, target and policy.
	pub scope: RemoteDownloadScope,
}

impl RemoteDownloadOwner {
	/// Assembles one local declaration for signing.
	/// # Errors
	/// Refuses conflicting identifiers and a job outside the destination device.
	pub fn new(
		token: OwnerToken,
		job: JournalJobId,
		profile: OwnerProfileId,
		created: OwnerTimestamp,
		job_directory: LinuxFileIdentity,
		scope: RemoteDownloadScope,
	) -> Result<Self, Error> {
		let manifest = Self {
			token,
			job,
			profile,
			created,
			job_directory,
			scope,
		};
		manifest.validate()?;
		Ok(manifest)
	}

	fn validate(&self) -> Result<(), Error> {
		let destination = self.scope.destination.parent();
		if self.job_directory == destination
			|| self.job_directory.device() != destination.device()
			|| self.token.as_bytes() == self.job.as_bytes()
			|| self.token.as_bytes() == self.profile.as_bytes()
			|| self.token.as_bytes() == self.scope.entry.as_bytes()
		{
			return Err(Error::Binding);
		}
		self.scope.validate()
	}
}

/// Exact signed owner declaration admitted for a remote capture profile.
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteDownloadOwnerRecord {
	manifest: RemoteDownloadOwner,
	bytes: Box<[u8]>,
}

impl RemoteDownloadOwnerRecord {
	/// Signs the complete canonical declaration with the selected local profile key.
	/// # Errors
	/// Refuses invalid scope, weak signing keys, and unsupported encoding.
	pub fn sign(manifest: RemoteDownloadOwner, signer: &SigningKey) -> Result<Self, Error> {
		Self::sign_in(manifest, signer, OwnerFormat::V1)
	}

	/// Signs the explicitly selected required resolved-direct profile.
	/// # Errors
	/// Refuses a different route profile, invalid scope or unusable signer.
	pub fn sign_resolved_direct(
		manifest: RemoteDownloadOwner,
		signer: &SigningKey,
	) -> Result<Self, Error> {
		Self::sign_in(manifest, signer, OwnerFormat::ResolvedDirect)
	}

	fn sign_in(
		manifest: RemoteDownloadOwner,
		signer: &SigningKey,
		format: OwnerFormat,
	) -> Result<Self, Error> {
		manifest.validate()?;
		format.require_route(manifest.scope.source.route())?;
		let key = signer.verifying_key();
		if key.is_weak() {
			return Err(OwnerError::InvalidSignature.into());
		}
		let public_key = key.to_bytes();
		let encoded = encode_body(&manifest, &public_key, format)?;
		let body = encoded_bytes(&encoded);
		let signature = signer
			.try_sign(&DOMAIN.signature_input(body))
			.map_err(|_| OwnerError::InvalidSignature)?;
		let envelope = Envelope {
			body,
			public_key,
			signature: signature.to_bytes(),
		};
		let encoded =
			encode_envelope_bounded::<MAX_REMOTE_DOWNLOAD_OWNER_BYTES>(&envelope, DOMAIN)?;
		Ok(Self {
			manifest,
			bytes: encoded_bytes(&encoded).into(),
		})
	}

	/// Authenticates a bounded canonical envelope against independent profile trust.
	/// # Errors
	/// Refuses foreign profile, domain or key, weak/invalid signatures and malformed bytes.
	pub fn decode(
		bytes: &[u8],
		profile: OwnerProfileId,
		key: &VerifyingKey,
	) -> Result<Self, Error> {
		Self::decode_in(bytes, profile, key, OwnerFormat::V1)
	}

	/// Authenticates the explicitly selected required resolved-direct profile.
	/// # Errors
	/// Refuses a different owner format or route profile, invalid key, signature or bytes.
	pub fn decode_resolved_direct(
		bytes: &[u8],
		profile: OwnerProfileId,
		key: &VerifyingKey,
	) -> Result<Self, Error> {
		Self::decode_in(bytes, profile, key, OwnerFormat::ResolvedDirect)
	}

	fn decode_in(
		bytes: &[u8],
		profile: OwnerProfileId,
		key: &VerifyingKey,
		format: OwnerFormat,
	) -> Result<Self, Error> {
		if bytes.len() > MAX_REMOTE_DOWNLOAD_OWNER_BYTES {
			return Err(Error::Length);
		}
		let envelope = decode_envelope_bounded::<MAX_BODY_BYTES, MAX_REMOTE_DOWNLOAD_OWNER_BYTES>(
			bytes, DOMAIN,
		)?;
		let public_key = key.to_bytes();
		if envelope.public_key != public_key {
			return Err(OwnerError::UntrustedKey.into());
		}
		if key.is_weak() {
			return Err(OwnerError::InvalidSignature.into());
		}
		key.verify_strict(
			&DOMAIN.signature_input(envelope.body),
			&Signature::from_bytes(&envelope.signature),
		)
		.map_err(|_| OwnerError::InvalidSignature)?;
		let manifest = decode_body(envelope.body, &public_key, format)?;
		if manifest.profile != profile {
			return Err(OwnerError::UntrustedProfile.into());
		}
		Ok(Self {
			manifest,
			bytes: bytes.into(),
		})
	}

	/// Returns the signed immutable declaration.
	#[must_use]
	pub const fn manifest(&self) -> &RemoteDownloadOwner {
		&self.manifest
	}

	/// Returns the bounded exact signed bytes.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// Measures the exact signed envelope for the initial journal binding.
	#[must_use]
	pub fn digest(&self) -> OwnerDigest {
		OwnerDigest::from_bytes(*blake3::hash(&self.bytes).as_bytes())
	}
}

impl fmt::Debug for RemoteDownloadOwnerRecord {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("RemoteDownloadOwnerRecord")
			.field("manifest", &self.manifest)
			.finish_non_exhaustive()
	}
}

fn encode_body(
	manifest: &RemoteDownloadOwner,
	public_key: &[u8; 32],
	format: OwnerFormat,
) -> Result<Body, Error> {
	let mut out = Encoder::new(Body::new([0; MAX_BODY_BYTES]));
	out.map(8)?.u8(0)?;
	write_version(&mut out, format.version())?;
	out.u8(1)?
		.bytes(manifest.token.as_bytes())?
		.u8(2)?
		.bytes(manifest.job.as_bytes())?
		.u8(3)?
		.bytes(manifest.profile.as_bytes())?
		.u8(4)?
		.bytes(public_key)?
		.u8(5)?
		.array(2)?
		.i64(manifest.created.seconds())?
		.u32(manifest.created.nanoseconds())?
		.u8(6)?;
	write_identity(&mut out, manifest.job_directory)?;
	out.u8(7)?;
	manifest.scope.write(&mut out)?;
	Ok(out.into_writer())
}

fn decode_body(
	bytes: &[u8],
	public_key: &[u8; 32],
	format: OwnerFormat,
) -> Result<RemoteDownloadOwner, Error> {
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 8)?;
	key(&mut decoder, 0)?;
	read_version(&mut decoder, format.version())?;
	key(&mut decoder, 1)?;
	let token = OwnerToken::from_bytes(fixed(&mut decoder)?)?;
	key(&mut decoder, 2)?;
	let job = JournalJobId::from_bytes(fixed(&mut decoder)?).map_err(|_| Error::Binding)?;
	key(&mut decoder, 3)?;
	let profile = OwnerProfileId::from_bytes(fixed(&mut decoder)?)?;
	key(&mut decoder, 4)?;
	if fixed::<32>(&mut decoder)? != *public_key {
		return Err(OwnerError::UntrustedKey.into());
	}
	key(&mut decoder, 5)?;
	array(&mut decoder, 2)?;
	let created = OwnerTimestamp::new(decoder.i64()?, decoder.u32()?)?;
	key(&mut decoder, 6)?;
	let job_directory = read_identity(&mut decoder)?;
	key(&mut decoder, 7)?;
	let scope = RemoteDownloadScope::read(&mut decoder)?;
	format.require_route(scope.source.route())?;
	let manifest = RemoteDownloadOwner::new(token, job, profile, created, job_directory, scope)?;
	if encoded_bytes(&encode_body(&manifest, public_key, format)?) != bytes {
		return Err(Error::NonCanonical);
	}
	Ok(manifest)
}
