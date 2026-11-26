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
