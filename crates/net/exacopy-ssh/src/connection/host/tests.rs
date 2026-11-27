use std::num::NonZeroU16;

use russh::keys::PrivateKey;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};

use super::*;
use exacopy_endpoint::ssh_sftp::HostKeyRefusal;

fn key(seed: u8) -> PublicKey {
	PrivateKey::new(
		KeypairData::Ed25519(Ed25519Keypair::from_seed(&[seed; 32])),
		"",
	)
	.unwrap()
	.public_key()
	.clone()
}

#[tokio::test]
async fn rekey_callback_rejects_a_different_host_key_before_approving_exchange() {
	let authority =
		SshAuthority::new("sftp.example", NonZeroU16::new(22).unwrap(), "download").unwrap();
	let original = key(17);
	let pin =
		HostKeyFingerprint::from_sha256(original.fingerprint(HashAlg::Sha256).sha256().unwrap());
	let record = format!("{} {}", authority.host(), original.to_openssh().unwrap());
	let trust = KnownHostTrust::from_snapshot(&authority, Ok(record.as_bytes())).unwrap();
	let mut handler = HostCheck {
		authority,
		pin,
		trust,
		verified: None,
		exchange: HostExchange::Established,
	};
	assert!(matches!(
		handler.check_server_key_on_rekey(&key(18).into()).await,
		Err(Error::HostKey(HostKeyRefusal::Changed))
	));
	assert!(matches!(handler.exchange, HostExchange::Established));
	assert!(
		handler
			.check_server_key_on_rekey(&original.clone().into())
			.await
			.unwrap()
	);
	assert!(matches!(handler.exchange, HostExchange::RekeyApproved));
	assert!(matches!(
		handler.check_server_key_on_rekey(&original.into()).await,
		Err(Error::KeyExchange)
	));
}

#[tokio::test]
async fn rekey_callback_refuses_a_trusted_key_that_does_not_match_the_session_pin() {
	const ORIGINAL_KEY_SEED: u8 = 17;
	const ROTATED_KEY_SEED: u8 = 18;

	let authority =
		SshAuthority::new("sftp.example", NonZeroU16::new(22).unwrap(), "download").unwrap();
	let original = key(ORIGINAL_KEY_SEED);
	let rotated = key(ROTATED_KEY_SEED);
	let pin =
		HostKeyFingerprint::from_sha256(original.fingerprint(HashAlg::Sha256).sha256().unwrap());
	let rotated_fingerprint =
		HostKeyFingerprint::from_sha256(rotated.fingerprint(HashAlg::Sha256).sha256().unwrap());
	let snapshot = format!(
		"{host} {}\n{host} {}",
		original.to_openssh().unwrap(),
		rotated.to_openssh().unwrap(),
		host = authority.host(),
	);
	let trust = KnownHostTrust::from_snapshot(&authority, Ok(snapshot.as_bytes())).unwrap();
	assert_eq!(
		trust.status(&authority, rotated_fingerprint),
		KnownHostStatus::Trusted,
		"the fixture must reach the independent pin check"
	);

	let mut handler = HostCheck {
		authority,
		pin,
		trust,
		verified: None,
		exchange: HostExchange::Established,
	};
	assert!(
		matches!(
			handler.check_server_key_on_rekey(&rotated.into()).await,
			Err(Error::HostKey(HostKeyRefusal::PinMismatch))
		),
		"the established session must enforce its original pin during rekey"
	);
	assert!(
		matches!(handler.exchange, HostExchange::Established),
		"the refused rekey must leave the exchange without fresh approval"
	);
}
