use std::fmt;
use std::io;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_journal::{LinuxFileIdentity, OwnerProfileId, RootCapabilityId};
use exacopy_platform::linux::{FileIdentity, HeldOwnerSeed, OwnerSeedError, initialize_owner_seed};
use rustix::io::Errno;
use uuid::Builder;
use zeroize::Zeroizing;

use crate::linux_path::split;

const SEED_BYTES: usize = ed25519_dalek::SECRET_KEY_LENGTH;

pub(crate) struct LocalProfile {
	id: OwnerProfileId,
	signer: SigningKey,
	seed: HeldOwnerSeed,
}

impl LocalProfile {
	pub(crate) fn open(path: &Path) -> Result<Self, ProfileError> {
		let (parent, name) = split(path).map_err(|_| ProfileError::InvalidPath)?;
		let mut seed = Zeroizing::new([0; SEED_BYTES]);
		let mut eof_probe = Zeroizing::new([0; 1]);
		let held = HeldOwnerSeed::open(parent, name, &mut seed, &mut eof_probe)?;

		let signer = SigningKey::from_bytes(&seed);
		let id = OwnerProfileId::from_bytes(identifier(
			"ExaCopy local CLI profile ID v1",
			signer.verifying_key().as_bytes(),
		))
		.map_err(|_| ProfileError::Identifier)?;
		Ok(Self {
			id,
			signer,
			seed: held,
		})
	}

	pub(crate) const fn id(&self) -> OwnerProfileId {
		self.id
	}

	pub(crate) const fn signer(&self) -> &SigningKey {
		&self.signer
	}

	pub(crate) fn verification_key(&self) -> VerifyingKey {
		self.signer.verifying_key()
	}

	pub(crate) fn root_id(&self, identity: FileIdentity) -> Result<RootCapabilityId, ProfileError> {
		let mut context = [0; 48];
		context[..32].copy_from_slice(self.verification_key().as_bytes());
		context[32..40].copy_from_slice(&identity.device().to_le_bytes());
		context[40..].copy_from_slice(&identity.inode().to_le_bytes());
		RootCapabilityId::from_bytes(identifier("ExaCopy local CLI root ID v1", &context))
			.map_err(|_| ProfileError::Identifier)
	}

	pub(crate) fn is_seed(&self, identity: LinuxFileIdentity) -> bool {
		let held = self.seed.identity();
		LinuxFileIdentity::new(held.device(), held.inode()) == identity
	}
}

pub(crate) fn init(path: &Path) -> Result<(), ProfileError> {
	let (parent, name) = split(path).map_err(|_| ProfileError::InvalidPath)?;
	let mut seed = Zeroizing::new([0; SEED_BYTES]);
	initialize_owner_seed(parent, name, &mut seed).map_err(ProfileError::from)
}

fn identifier(domain: &str, material: &[u8]) -> [u8; 16] {
	let mut bytes = [0; 16];
	blake3::Hasher::new_derive_key(domain)
		.update(material)
		.finalize_xof()
		.fill(&mut bytes);
	Builder::from_custom_bytes(bytes).into_uuid().into_bytes()
}

pub(crate) fn kernel_random(output: &mut [u8]) -> Result<(), ProfileError> {
	exacopy_platform::linux::kernel_random(output).map_err(ProfileError::from)
}

#[derive(Debug)]
pub(crate) enum ProfileError {
	InvalidPath,
	Identifier,
	Native(OwnerSeedError),
}

impl ProfileError {
	pub(crate) fn init_exit_code(&self) -> u8 {
		match self {
			Self::InvalidPath => 2,
			Self::Native(OwnerSeedError::Io(error))
				if error.raw_os_error() == Some(Errno::EXIST.raw_os_error()) =>
			{
				3
			}
			Self::Native(
				OwnerSeedError::UnsafeParent
				| OwnerSeedError::UnsafeDirectory
				| OwnerSeedError::UnsafeSeed
				| OwnerSeedError::IdentityChanged,
			) => 8,
			_ => 4,
		}
	}

	pub(crate) const fn io_error(&self) -> Option<&io::Error> {
		match self {
			Self::Native(OwnerSeedError::Io(error)) => Some(error),
			_ => None,
		}
	}
}

impl From<OwnerSeedError> for ProfileError {
	fn from(error: OwnerSeedError) -> Self {
		Self::Native(error)
	}
}

impl fmt::Display for ProfileError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidPath => formatter.write_str("expected a named profile directory"),
			Self::Identifier => formatter.write_str("could not bind the profile or root identity"),
			Self::Native(error) => error.fmt(formatter),
		}
	}
}
