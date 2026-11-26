use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::{EcdsaCurve, LineEnding};

use super::*;

const PASSPHRASE: &[u8] = b" synthetic whitespace ";

#[test]
fn clear_and_bcrypt_openssh_keys_require_the_selected_fingerprint_and_passphrase() {
	let keypair = Ed25519Keypair::from_seed(&[9; 32]);
	let key = PrivateKey::new(KeypairData::Ed25519(keypair), "").unwrap();
	let pin = key.fingerprint(HashAlg::Sha256).sha256().unwrap();
	let encoded = key.to_openssh(LineEnding::LF).unwrap();
	assert!(Ed25519Key::from_openssh(encoded.as_bytes(), None, pin).is_ok());
	assert!(matches!(
		Ed25519Key::from_openssh(encoded.as_bytes(), None, [7; 32]),
		Err(Error::KeyProfile)
	));
	assert!(matches!(
		Ed25519Key::from_openssh(encoded.as_bytes(), Some(PASSPHRASE), pin),
		Err(Error::KeyProfile)
	));

	let encrypted = key
		.encrypt(&mut russh::keys::key::safe_rng(), PASSPHRASE)
		.unwrap();
	let encoded = encrypted.to_openssh(LineEnding::LF).unwrap();
	for (passphrase, expected) in [
		(None, false),
		(Some(PASSPHRASE), true),
		(Some(PASSPHRASE.trim_ascii()), false),
	] {
		assert_eq!(
			Ed25519Key::from_openssh(encoded.as_bytes(), passphrase, pin).is_ok(),
			expected
		);
	}
}

#[test]
fn different_algorithm_and_oversized_encoding_are_refused() {
	let key = PrivateKey::random(
		&mut russh::keys::key::safe_rng(),
		Algorithm::Ecdsa {
			curve: EcdsaCurve::NistP256,
		},
	)
	.unwrap();
	let pin = key.fingerprint(HashAlg::Sha256).sha256().unwrap();
	let encoded = key.to_openssh(LineEnding::LF).unwrap();
	assert!(matches!(
		Ed25519Key::from_openssh(encoded.as_bytes(), None, pin),
		Err(Error::KeyProfile)
	));
	let oversized = vec![0; MAX_OPENSSH_ED25519_BYTES + 1];
	assert!(matches!(
		Ed25519Key::from_openssh(&oversized, None, pin),
		Err(Error::KeyProfile)
	));
}

#[test]
fn excess_kdf_cost_is_refused_with_an_otherwise_valid_key() {
	use russh::keys::ssh_key::Cipher;

	let keypair = Ed25519Keypair::from_seed(&[10; 32]);
	let key = PrivateKey::new(KeypairData::Ed25519(keypair), "").unwrap();
	let pin = key.fingerprint(HashAlg::Sha256).sha256().unwrap();
	let over_budget = key
		.encrypt_with(
			Cipher::Aes256Ctr,
			Kdf::Bcrypt {
				salt: vec![0x31; 16],
				rounds: MAX_BCRYPT_ROUNDS + 1,
			},
			17,
			PASSPHRASE,
		)
		.unwrap();
	let encoded = over_budget.to_openssh(LineEnding::LF).unwrap();
	assert!(matches!(
		Ed25519Key::from_openssh(encoded.as_bytes(), Some(PASSPHRASE), pin),
		Err(Error::KeyProfile)
	));
}
