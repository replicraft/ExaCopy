use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

use crate::frame::{ChainHead, Frame, FrameKind};
use crate::owner::codec::{OwnerDomain, encoded_bytes};
use crate::{
	JournalEntryId, JournalJobId, LinuxFileIdentity, OwnerDigest, OwnerError, OwnerProfileId,
};

use super::wire::{fixed, key, map, read_head, read_identity, write_head, write_identity};
use super::{
	RemoteDownloadBody, RemoteDownloadContext, RemoteDownloadError as Error,
	RemoteDownloadOwnerRecord, RemoteDownloadRecord,
};

const SIGNATURE_DOMAIN: &[u8] = b"ExaCopy/linux-remote-bootstrap/v1\0";
const VERSION: u8 = 1;
const LINUX_REMOTE_OWNER_DOMAIN: u64 = OwnerDomain::LinuxRemoteDownload.code();
const STAGE_DIRECTORY_ROLE: u8 = 0;
const JOB_PREPARED_SEQUENCE: u64 = 1;

/// Maximum encoded signed stage-directory bootstrap payload in the required profile.
pub const MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES: usize = 512;

type Buffer = Cursor<[u8; MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES]>;

/// The independently selected trust anchor and matching authenticated private owner.
///
/// This permits authentication of claims in the required bootstrap dialect.
/// It conveys no authority to use a currently named filesystem object.
#[derive(Debug)]
pub struct RemoteBootstrapTrust<'owner> {
	owner: &'owner RemoteDownloadOwnerRecord,
	key: &'owner VerifyingKey,
}

/// Authenticated historical evidence about the fixed `stage/` directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteStageDirectoryPrepared {
	head: ChainHead,
	directory: LinuxFileIdentity,
}

impl RemoteStageDirectoryPrepared {
	/// Returns the verified StageDirectoryPrepared frame boundary.
	#[must_use]
	pub const fn head(self) -> ChainHead {
		self.head
	}

	/// Returns the stored identity for comparison with a currently held directory.
	#[must_use]
	pub const fn directory(self) -> LinuxFileIdentity {
		self.directory
	}
}

impl<'owner> RemoteBootstrapTrust<'owner> {
	/// Binds the selected local profile and key to the exact signed remote owner.
	///
	/// # Errors
	/// Refuses any mismatch with the owner envelope, including weak keys.
	pub fn new(
		owner: &'owner RemoteDownloadOwnerRecord,
		expected_profile: OwnerProfileId,
		key: &'owner VerifyingKey,
	) -> Result<Self, Error> {
		RemoteDownloadOwnerRecord::decode(owner.as_bytes(), expected_profile, key)?;
		Ok(Self { owner, key })
	}

	/// Binds independently selected owner trust in the required resolved-direct profile.
	/// # Errors
	/// Refuses a different owner format, mismatched profile or untrusted key.
	pub fn new_resolved_direct(
		owner: &'owner RemoteDownloadOwnerRecord,
		expected_profile: OwnerProfileId,
		key: &'owner VerifyingKey,
	) -> Result<Self, Error> {
		RemoteDownloadOwnerRecord::decode_resolved_direct(owner.as_bytes(), expected_profile, key)?;
		Ok(Self { owner, key })
	}

	/// Binds independently selected owner trust in the required absolute-path profile.
	/// # Errors
	/// Refuses another owner format, mismatched profile or untrusted key.
	pub fn new_absolute_path(
		owner: &'owner RemoteDownloadOwnerRecord,
		expected_profile: OwnerProfileId,
		key: &'owner VerifyingKey,
	) -> Result<Self, Error> {
		RemoteDownloadOwnerRecord::decode_absolute_path(owner.as_bytes(), expected_profile, key)?;
		Ok(Self { owner, key })
	}

	/// Signs the checked stage directory observation for the actual first job frame.
	///
	/// The caller supplies the directory identity after its own native checks and
	/// barriers. The returned payload requires durable append and revalidation.
	///
	/// # Errors
	/// Refuses foreign identity, wrong signer or a frame outside the selected job.
	pub fn sign(
		&self,
		job_prepared: &Frame,
		directory: LinuxFileIdentity,
		signer: &SigningKey,
	) -> Result<Vec<u8>, Error> {
		if signer.verifying_key() != *self.key {
			return Err(OwnerError::UntrustedKey.into());
		}
		let head = self.job_prepared_head(job_prepared)?;
		self.validate_directory(directory)?;
		let body = encode_body(self.claims(head, directory))?;
		let body = encoded_bytes(&body);
		let signature = signer
			.try_sign(&signature_input(body)?)
			.map_err(|_| OwnerError::InvalidSignature)?;
		let payload = encode_envelope(body, &signature.to_bytes())?;
		Ok(encoded_bytes(&payload).to_vec())
	}

	/// Authenticates the bootstrap frame against the actual preceding first job frame.
	///
	/// # Errors
	/// Refuses mismatched context and predecessor, malformed fields and invalid signatures.
	pub fn from_frame(
		&self,
		frame: &Frame,
		job_prepared: &Frame,
	) -> Result<RemoteStageDirectoryPrepared, Error> {
		self.admit_after_job(frame, self.job_prepared_head(job_prepared)?)
	}

	pub(super) const fn owner(&self) -> &'owner RemoteDownloadOwnerRecord {
		self.owner
	}

	pub(super) fn admit_after_job(
		&self,
		frame: &Frame,
		job: ChainHead,
	) -> Result<RemoteStageDirectoryPrepared, Error> {
		if frame.kind() != FrameKind::StageDirectoryPrepared
			|| job.sequence() != JOB_PREPARED_SEQUENCE
			|| frame.head().sequence() != JOB_PREPARED_SEQUENCE + 1
			|| frame.previous_digest() != job.digest()
		{
			return Err(Error::FrameBinding);
		}
		let (body, signature) = decode_envelope(frame.payload())?;
		self.key
			.verify_strict(&signature_input(body)?, &Signature::from_bytes(&signature))
			.map_err(|_| OwnerError::InvalidSignature)?;
		let claims = decode_body(body)?;
		if claims.predecessor != job {
			return Err(Error::FrameBinding);
		}
		if claims != self.claims(job, claims.directory) {
			return Err(Error::Binding);
		}
		self.validate_directory(claims.directory)?;
		Ok(RemoteStageDirectoryPrepared {
			head: frame.head(),
			directory: claims.directory,
		})
	}

	fn job_prepared_head(&self, frame: &Frame) -> Result<ChainHead, Error> {
		let record = RemoteDownloadRecord::from_frame(frame)?;
		if record.context() != RemoteDownloadContext::for_owner(self.owner)
			|| record.body()
				!= (RemoteDownloadBody::JobPrepared {
					scope: self.owner.manifest().scope.digest()?,
				}) {
			return Err(Error::Binding);
		}
		Ok(frame.head())
	}

	fn claims(&self, predecessor: ChainHead, directory: LinuxFileIdentity) -> BootstrapClaims {
		BootstrapClaims {
			context: RemoteDownloadContext::for_owner(self.owner),
			profile: self.owner.manifest().profile,
			predecessor,
			directory,
		}
	}

	fn validate_directory(&self, directory: LinuxFileIdentity) -> Result<(), Error> {
		let owner = self.owner.manifest();
		let destination = owner.scope.destination.parent();
		if directory.device() != destination.device()
			|| [owner.job_directory, destination].contains(&directory)
		{
			return Err(Error::Binding);
		}
		Ok(())
	}
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct BootstrapClaims {
	context: RemoteDownloadContext,
	profile: OwnerProfileId,
	predecessor: ChainHead,
	directory: LinuxFileIdentity,
}

fn encode_envelope(body: &[u8], signature: &[u8; 64]) -> Result<Buffer, Error> {
	let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES]));
	out.map(4)?
		.u8(0)?
		.u8(VERSION)?
		.u8(1)?
		.u64(LINUX_REMOTE_OWNER_DOMAIN)?
		.u8(2)?
		.bytes(body)?
		.u8(3)?
		.bytes(signature)?;
	Ok(out.into_writer())
}

fn decode_envelope(bytes: &[u8]) -> Result<(&[u8], [u8; 64]), Error> {
	if bytes.len() > MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES {
		return Err(Error::Length);
	}
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 4)?;
	key(&mut decoder, 0)?;
	if decoder.u64()? != u64::from(VERSION) {
		return Err(Error::UnsupportedVersion);
	}
	key(&mut decoder, 1)?;
	if decoder.u64()? != LINUX_REMOTE_OWNER_DOMAIN {
		return Err(OwnerError::WrongDomain.into());
	}
	key(&mut decoder, 2)?;
	let body = decoder.bytes()?;
	key(&mut decoder, 3)?;
	let signature = fixed(&mut decoder)?;
	if encoded_bytes(&encode_envelope(body, &signature)?) != bytes {
		return Err(Error::NonCanonical);
	}
	Ok((body, signature))
}

fn signature_input(body: &[u8]) -> Result<Vec<u8>, Error> {
	let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES]));
	out.array(3)?
		.u8(VERSION)?
		.u64(LINUX_REMOTE_OWNER_DOMAIN)?
		.bytes(body)?;
	Ok([SIGNATURE_DOMAIN, encoded_bytes(&out.into_writer())].concat())
}

fn encode_body(claims: BootstrapClaims) -> Result<Buffer, Error> {
	let mut out = Encoder::new(Buffer::new([0; MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES]));
	out.map(7)?
		.u8(0)?
		.bytes(claims.context.owner.as_bytes())?
		.u8(1)?
		.bytes(claims.context.job.as_bytes())?
		.u8(2)?
		.bytes(claims.context.entry.as_bytes())?
		.u8(3)?
		.bytes(claims.profile.as_bytes())?
		.u8(4)?;
	write_head(&mut out, claims.predecessor)?;
	out.u8(5)?;
	write_identity(&mut out, claims.directory)?;
	out.u8(6)?.u8(STAGE_DIRECTORY_ROLE)?;
	Ok(out.into_writer())
}

fn decode_body(bytes: &[u8]) -> Result<BootstrapClaims, Error> {
	let mut decoder = Decoder::new(bytes);
	map(&mut decoder, 7)?;
	key(&mut decoder, 0)?;
	let owner = OwnerDigest::from_bytes(fixed(&mut decoder)?);
	key(&mut decoder, 1)?;
	let job = JournalJobId::from_bytes(fixed(&mut decoder)?).map_err(|_| Error::Binding)?;
	key(&mut decoder, 2)?;
	let entry = JournalEntryId::from_bytes(fixed(&mut decoder)?);
	key(&mut decoder, 3)?;
	let profile = OwnerProfileId::from_bytes(fixed(&mut decoder)?)?;
	key(&mut decoder, 4)?;
	let predecessor = read_head(&mut decoder)?;
	key(&mut decoder, 5)?;
	let directory = read_identity(&mut decoder)?;
	key(&mut decoder, 6)?;
	if decoder.u64()? != u64::from(STAGE_DIRECTORY_ROLE) {
		return Err(Error::Binding);
	}
	let claims = BootstrapClaims {
		context: RemoteDownloadContext { owner, job, entry },
		profile,
		predecessor,
		directory,
	};
	if encoded_bytes(&encode_body(claims)?) != bytes {
		return Err(Error::NonCanonical);
	}
	Ok(claims)
}
