use russh::keys::ssh_key::Kdf;
use russh::keys::{Algorithm, HashAlg, PrivateKey};

use super::{Ed25519Key, MAX_PASSWORD_BYTES};
use crate::Error;

/// Maximum encoded size of a selected single-key OpenSSH Ed25519 file.
pub const MAX_OPENSSH_ED25519_BYTES: usize = 16 * 1024;
const MAX_BCRYPT_ROUNDS: u32 = 64;
const MAX_BCRYPT_SALT_BYTES: usize = 64;

impl Ed25519Key {
	/// Load one OpenSSH Ed25519 key with an explicitly selected public fingerprint.
	///
	/// The encoded bytes and optional passphrase remain caller-owned. The
	/// fingerprint is SHA-256 of the SSH public-key wire representation.
	/// A clear key requires no passphrase. An encrypted key requires a
	/// nonempty bounded passphrase and a bounded bcrypt KDF.
	///
	/// # Errors
	/// Refuses a different algorithm, fingerprint, incompatible passphrase,
	/// excessive work factors, or an invalid key. Errors omit input bytes.
	pub fn from_openssh(
		encoded: &[u8],
		passphrase: Option<&[u8]>,
		expected_sha256: [u8; 32],
	) -> Result<Self, Error> {
		if encoded.is_empty() || encoded.len() > MAX_OPENSSH_ED25519_BYTES {
			return Err(Error::KeyProfile);
		}
		let key = PrivateKey::from_openssh(encoded).map_err(|_| Error::KeyProfile)?;
		check_public_key(&key, expected_sha256)?;
		let key = match (key.is_encrypted(), passphrase, key.kdf()) {
			(false, None, Kdf::None) => key,
			(true, Some(passphrase), Kdf::Bcrypt { salt, rounds })
				if (1..=MAX_BCRYPT_ROUNDS).contains(rounds)
					&& (1..=MAX_BCRYPT_SALT_BYTES).contains(&salt.len())
					&& (1..=MAX_PASSWORD_BYTES).contains(&passphrase.len()) =>
			{
				key.decrypt(passphrase).map_err(|_| Error::KeyProfile)?
			}
			_ => return Err(Error::KeyProfile),
		};
		check_public_key(&key, expected_sha256)?;
		Ok(Self(key))
	}
}

fn check_public_key(key: &PrivateKey, expected_sha256: [u8; 32]) -> Result<(), Error> {
	if key.algorithm() != Algorithm::Ed25519
		|| key.fingerprint(HashAlg::Sha256).sha256() != Some(expected_sha256)
	{
		return Err(Error::KeyProfile);
	}
	Ok(())
}

#[cfg(test)]
mod tests;
