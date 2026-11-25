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
