//! SSH/SFTP integration over bounded in-memory streams and synthetic credentials.
#![cfg(feature = "experimental-ssh")]

use std::sync::atomic::Ordering;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::ssh_sftp::{
	CredentialRefusal, CredentialSource, HostKeyFingerprint, HostKeyRefusal, InteractionPolicy,
};
use exacopy_ssh::{Error, KnownHostTrust, Password, connect};

#[path = "in_process/keepalive.rs"]
mod keepalive;
#[path = "in_process/key_auth.rs"]
mod key_auth;
#[path = "in_process/peer.rs"]
mod peer;
#[path = "in_process/positioned.rs"]
mod positioned;
#[path = "in_process/streaming.rs"]
mod streaming;
#[path = "in_process/version.rs"]
mod version;

use peer::{CONTENT, NAME, SECRET, authority, fixture_key, fixture_trust, peer, peer_with_handle};

#[tokio::test]
async fn requested_disconnect_observes_the_exact_transport_write_shutdown() {
	let (stream, pin, calls) = peer(true, false);
	let target = authority("transfer");
	let mut session = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await
	.unwrap();
	let path = [UnixComponent::new(NAME).unwrap()];
	let mut bytes = [0; CONTENT.len()];
	session.read_file(&path, &mut bytes).await.unwrap();
	assert_eq!(&bytes, CONTENT);
	assert_eq!(calls.close.load(Ordering::Relaxed), 1);
	session
		.disconnect_before(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
		.await
		.unwrap();
}

#[tokio::test]
async fn expired_disconnect_request_cannot_confirm_shutdown() {
	let (stream, pin, _calls) = peer(true, false);
	let target = authority("transfer");
	let session = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await
	.unwrap();
	assert!(matches!(
		session.disconnect_before(tokio::time::Instant::now()).await,
		Err(Error::Timeout)
	));
}

#[tokio::test]
async fn raw_listing_and_short_reads_use_a_pinned_authenticated_connection() {
	let (stream, pin, calls) = peer(true, false);
	let target = authority("transfer");
	let mut session = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|request| {
			assert_eq!(request.authority(), &target);
			assert_eq!(request.fingerprint(), pin);
			assert_eq!(request.source(), CredentialSource::SuppliedPassword);
			assert_eq!(request.interaction(), InteractionPolicy::Forbidden);
			assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
			Password::new(SECRET.to_owned())
		},
	)
	.await
	.unwrap();

	let authenticated = session.authenticated_peer();
	assert_eq!(authenticated.authority(), &target);
	assert_eq!(authenticated.fingerprint(), pin);
	assert_eq!(session.list(&[]).await.unwrap(), vec![NAME.to_vec()]);
	let path = [UnixComponent::new(NAME).unwrap()];
	let before = session.stat(&path).await.unwrap();
	assert_eq!(before.length, CONTENT.len() as u64);
	assert_eq!(before.mode, 0o100600);
	assert_eq!(before.modified, 22);
	let mut bytes = [0; CONTENT.len()];
	assert_eq!(session.read_file(&path, &mut bytes).await.unwrap(), before);
	assert_eq!(&bytes, CONTENT);
	assert_eq!(calls.auth.load(Ordering::Relaxed), 1);
	assert_eq!(calls.subsystem.load(Ordering::Relaxed), 1);
	assert_eq!(calls.read.load(Ordering::Relaxed), 4);
	assert_eq!(calls.close.load(Ordering::Relaxed), 2);
	assert_eq!(calls.unsupported.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_mismatched_pin_or_revocation_never_requests_or_sends_a_credential() {
	let target = authority("transfer");
	for (revoked, expected) in [
		(false, HostKeyRefusal::PinMismatch),
		(true, HostKeyRefusal::Revoked),
	] {
		let (stream, pin, calls) = peer(true, false);
		let selected = if revoked {
			pin
		} else {
			HostKeyFingerprint::from_sha256([0; 32])
		};
		let marker = if revoked { "@revoked " } else { "" };
		let result = connect(
			stream,
			&target,
			selected,
			fixture_trust(&target, marker),
			&target,
			|_| panic!("broker called before trust"),
		);
		assert!(matches!(result.await, Err(Error::HostKey(refusal)) if refusal == expected));
		assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
		assert_eq!(calls.subsystem.load(Ordering::Relaxed), 0);
	}
}

#[tokio::test]
async fn a_hashed_revocation_blocks_a_matching_pin_before_credentials() {
	// OpenSSH 9.7p1 ssh-keygen -H output for [sftp.example]:22 and
	// [unrelated.example]:22, respectively. The second label is opaque
	// and still denies the identical offered key in a dedicated store.
	let target = authority("transfer");
	for host in [
		"|1|2cIMKsRMeh/zQvVDh4zUxqCLaCM=|O3vD620kwtsYVvIcqYDajCL+kF8=",
		"|1|JTlkQlMnT3yxcQv+AMyBywfWpBM=|EWeOMzItF31gFl0QJdB7Cqz2J94=",
	] {
		let (stream, pin, calls) = peer(true, false);
		let key = fixture_key().public_key().to_openssh().unwrap();
		let record = format!("@revoked {host} {key}");
		let trust = KnownHostTrust::from_snapshot(&target, Ok(record.as_bytes())).unwrap();
		let result = connect(stream, &target, pin, trust, &target, |_| {
			panic!("broker called before trust")
		});
		assert!(matches!(
			result.await,
			Err(Error::HostKey(HostKeyRefusal::Revoked))
		));
		assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
		assert_eq!(calls.subsystem.load(Ordering::Relaxed), 0);
	}
}

#[tokio::test]
async fn a_credential_for_another_account_cannot_be_acquired_or_sent() {
	let (stream, pin, calls) = peer(true, false);
	let target = authority("transfer");
	let other = authority("unrelated");
	let result = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&other,
		|_| panic!("broker called for an unrelated account"),
	)
	.await;
	assert!(matches!(
		result,
		Err(Error::Credential(CredentialRefusal::AuthorityMismatch))
	));
	assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_rejected_password_cannot_create_an_authenticated_session() {
	let (stream, pin, calls) = peer(true, false);
	let target = authority("transfer");
	let result = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| Password::new("wrong test password".to_owned()),
	)
	.await;
	assert!(matches!(result, Err(Error::Authentication)));
	assert_eq!(calls.auth.load(Ordering::Relaxed), 1);
	assert_eq!(calls.subsystem.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_refused_sftp_subsystem_never_falls_back_to_a_shell() {
	let (stream, pin, calls) = peer(false, false);
	let target = authority("transfer");
	let result = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await;

	assert!(matches!(result, Err(Error::Subsystem)));
	assert_eq!(calls.auth.load(Ordering::Relaxed), 1);
	assert_eq!(calls.subsystem.load(Ordering::Relaxed), 1);
	assert_eq!(calls.unsupported.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn early_eof_refuses_incomplete_reads_and_fences_the_session() {
	let (stream, pin, _) = peer(true, true);
	let target = authority("transfer");
	let mut session = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await
	.unwrap();
	let path = [UnixComponent::new(NAME).unwrap()];
	let mut bytes = [0; CONTENT.len()];
	assert!(matches!(
		session.read_file(&path, &mut bytes).await,
		Err(Error::Changed)
	));
	assert!(matches!(session.stat(&path).await, Err(Error::Closed)));
}

#[tokio::test]
async fn a_peer_initiated_channel_is_refused_and_the_connection_is_fenced() {
	let (stream, pin, _, handle) = peer_with_handle(true, false);
	let target = authority("transfer");
	let mut session = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await
	.unwrap();
	let handle = handle.await.unwrap();
	assert!(handle.channel_open_session().await.is_err());
	let path = [UnixComponent::new(NAME).unwrap()];
	assert!(matches!(
		session.stat(&path).await,
		Err(Error::UnsolicitedChannel)
	));
	assert!(matches!(session.stat(&path).await, Err(Error::Closed)));
}

#[tokio::test]
async fn a_store_for_another_authority_refuses_before_the_broker() {
	let (stream, pin, calls) = peer(true, false);
	let target = authority("transfer");
	let other = authority("other");
	let result = connect(
		stream,
		&target,
		pin,
		fixture_trust(&other, ""),
		&target,
		|_| panic!("broker called for trust scoped elsewhere"),
	)
	.await;
	assert!(matches!(
		result,
		Err(Error::HostKey(HostKeyRefusal::TrustUnavailable))
	));
	assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
}
