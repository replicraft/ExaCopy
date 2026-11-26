use std::sync::atomic::Ordering;
use std::time::Duration;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::ssh_sftp::{
	CredentialRefusal, CredentialSource, HostKeyRefusal, InteractionPolicy,
};
use exacopy_ssh::{Ed25519Key, Error, connect_with_ed25519};
use russh::keys::Algorithm;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::server;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::peer::{NAME, authority, fixture_trust, peer, peer_with_rekey};

const SYNTHETIC_SEED: [u8; 32] = [32; 32];

pub(super) fn verify_credentials(user: &str, key: server::VerifiedPublicKey<'_>) -> server::Auth {
	let expected = Ed25519Keypair::from_seed(&SYNTHETIC_SEED).public;
	if user == "transfer"
		&& key.algorithm == &Algorithm::Ed25519
		&& key.public_key.key_data().ed25519() == Some(&expected)
	{
		server::Auth::Accept
	} else {
		server::Auth::reject()
	}
}

fn fixture_credential() -> Result<Ed25519Key, Error> {
	Ed25519Key::from_seed(Zeroizing::new(SYNTHETIC_SEED))
}

#[tokio::test]
async fn supplied_key_authenticates_once_with_a_verified_authority() {
	let (stream, pin, calls) = peer(true, false);
	let target = authority("transfer");
	let mut sftp = connect_with_ed25519(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|request| {
			assert_eq!(request.source(), CredentialSource::SuppliedKey);
			assert_eq!(request.authority(), &target);
			assert_eq!(request.fingerprint(), pin);
			assert_eq!(request.interaction(), InteractionPolicy::Forbidden);
			assert_eq!(calls.key_auth.load(Ordering::Relaxed), 0);
			fixture_credential()
		},
	)
	.await
	.unwrap();

	let authenticated = sftp.authenticated_peer();
	assert_eq!(authenticated.authority(), &target);
	assert_eq!(authenticated.fingerprint(), pin);
	assert_eq!(sftp.list(&[]).await.unwrap(), vec![NAME.to_vec()]);
	assert_eq!(calls.key_auth.load(Ordering::Relaxed), 1);
	assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
	assert_eq!(calls.subsystem.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn rejected_key_ends_the_attempt_without_password_or_subsystem_fallback() {
	let (stream, pin, calls) = peer(true, false);
	let target = authority("transfer");
	let result = connect_with_ed25519(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| Ed25519Key::from_seed(Zeroizing::new([33; 32])),
	)
	.await;

	assert!(matches!(result, Err(Error::KeyAuthentication)));
	assert_eq!(calls.key_auth.load(Ordering::Relaxed), 1);
	assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
	assert_eq!(calls.subsystem.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn untrusted_host_or_mismatched_authority_does_not_receive_a_key_offer() {
	let target = authority("transfer");
	let other = authority("another");
	let (stream, pin, calls) = peer(true, false);
	let result = connect_with_ed25519(
		stream,
		&target,
		pin,
		fixture_trust(&target, "@revoked "),
		&target,
		|_| panic!("revoked peer reached key broker"),
	)
	.await;
	assert!(matches!(
		result,
		Err(Error::HostKey(HostKeyRefusal::Revoked))
	));
	assert_eq!(calls.key_auth.load(Ordering::Relaxed), 0);

	let (stream, pin, calls) = peer(true, false);
	let result = connect_with_ed25519(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&other,
		|_| panic!("wrong authority reached key broker"),
	)
	.await;
	assert!(matches!(
		result,
		Err(Error::Credential(CredentialRefusal::AuthorityMismatch))
	));
	assert_eq!(calls.key_auth.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn successful_authentication_does_not_authorize_a_second_key_exchange() {
	let (terminated, disconnected) = oneshot::channel();
	let (stream, pin, calls, _handle) =
		peer_with_rekey(true, false, Duration::from_secs(1), Some(terminated));
	let target = authority("transfer");
	let mut session = connect_with_ed25519(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| fixture_credential(),
	)
	.await
	.unwrap();

	assert_eq!(session.list(&[]).await.unwrap(), vec![NAME.to_vec()]);
	tokio::time::timeout(Duration::from_secs(5), disconnected)
		.await
		.expect("rekey refusal should terminate the peer session")
		.unwrap();

	let path = [UnixComponent::new(NAME).unwrap()];
	assert!(matches!(session.stat(&path).await, Err(Error::Rekey)));
	assert!(matches!(session.stat(&path).await, Err(Error::Closed)));
	assert_eq!(calls.key_auth.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn async_protected_key_broker_requires_current_grant_before_actual_offer() {
	use exacopy_ssh::connect_with_ed25519_async;
	use russh::keys::ssh_key::LineEnding;
	use russh::keys::ssh_key::private::KeypairData;
	use russh::keys::{HashAlg, PrivateKey};

	for permitted in [false, true] {
		let (stream, pin, calls) = peer(true, false);
		let target = authority("transfer");
		let broker_calls = std::cell::Cell::new(0);
		let mut result = connect_with_ed25519_async(
			stream,
			&target,
			pin,
			fixture_trust(&target, ""),
			&target,
			async |request| {
				assert_eq!(request.authority(), &target);
				assert_eq!(request.fingerprint(), pin);
				assert_eq!(request.source(), CredentialSource::SuppliedKey);
				broker_calls.set(broker_calls.get() + 1);
				tokio::task::spawn_blocking(|| {
					let keypair = Ed25519Keypair::from_seed(&SYNTHETIC_SEED);
					let key = PrivateKey::new(KeypairData::Ed25519(keypair), "").unwrap();
					let encoded = key.to_openssh(LineEnding::LF).unwrap();
					let key_pin = key.fingerprint(HashAlg::Sha256).sha256().unwrap();
					Ed25519Key::from_openssh(encoded.as_bytes(), None, key_pin)
				})
				.await
				.unwrap()
			},
			|| {
				assert_eq!(broker_calls.get(), 1);
				assert_eq!(calls.key_auth.load(Ordering::Relaxed), 0);
				permitted.then_some(()).ok_or(Error::KeyProfile)
			},
		)
		.await;
		if permitted {
			let Ok(sftp) = &mut result else {
				panic!("the selected synthetic key authenticates the account");
			};
			assert_eq!(sftp.authenticated_peer().authority(), &target);
			assert_eq!(sftp.list(&[]).await.unwrap(), vec![NAME.to_vec()]);
		} else {
			assert!(matches!(result, Err(Error::KeyProfile)));
		}
		assert_eq!(
			calls.key_auth.load(Ordering::Relaxed),
			usize::from(permitted)
		);
		assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
	}
}
