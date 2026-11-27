use std::cell::Cell;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_endpoint::ssh_sftp::HostKeyRefusal;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{HashAlg, PrivateKey};
use russh::server;
use serde_json::json;
use tokio::io::DuplexStream;
use tokio::task::JoinHandle;

use super::{KnownHostTrust, SshError, SshProfile, authenticate};
use crate::remote_frontdoor::ssh_profile_fixture;

struct RejectCredentials;

impl server::Handler for RejectCredentials {
	type Error = russh::Error;
}

fn peer(
	accept_host: bool,
	use_key: bool,
) -> (SshProfile, KnownHostTrust, DuplexStream, JoinHandle<()>) {
	let host = PrivateKey::new(
		KeypairData::Ed25519(Ed25519Keypair::from_seed(&[31; 32])),
		"",
	)
	.unwrap();
	let host_key = host.public_key().to_openssh().unwrap();
	let profile = ssh_profile_fixture(|input| {
		if accept_host {
			let mut pin = String::new();
			for byte in host.fingerprint(HashAlg::Sha256).sha256().unwrap() {
				write!(pin, "{byte:02x}").unwrap();
			}
			input["host_key_sha256"] = json!(pin);
		}
		if use_key {
			input["credential"] = json!({
				"kind": "openssh-ed25519",
				"private_key_file": "/synthetic/private/key",
				"public_key_sha256": "b2".repeat(32),
			});
		}
	});
	let authority = &profile.authority;
	let snapshot = format!("[{}]:{} {host_key}", authority.host(), authority.port());
	let trust = KnownHostTrust::from_snapshot(authority, Ok(snapshot.as_bytes())).unwrap();
	let config = Arc::new(server::Config {
		keys: vec![host],
		..server::Config::default()
	});
	let (stream, peer_stream) = tokio::io::duplex(64 * 1024);
	let server = tokio::spawn(async move {
		if let Ok(session) = server::run_stream(config, peer_stream, RejectCredentials).await {
			let _ = session.await;
		}
	});
	(profile, trust, stream, server)
}

#[tokio::test]
async fn host_and_route_admission_precede_credential_offer_liveness() {
	for use_key in [false, true] {
		for accept_host in [false, true] {
			let (profile, trust, stream, server) = peer(accept_host, use_key);
			let route_checks = Cell::new(0);
			let result = authenticate(
				stream,
				&profile,
				trust,
				|| panic!("offer liveness requires both host admission and a current route"),
				|| {
					route_checks.set(route_checks.get() + 1);
					false
				},
			)
			.await;
			server.abort();
			let _ = server.await;
			assert_eq!(route_checks.get(), usize::from(accept_host));
			assert!(matches!(
				(accept_host, use_key, result),
				(
					false,
					_,
					Err(SshError::HostKey(HostKeyRefusal::PinMismatch))
				) | (true, false, Err(SshError::Password))
					| (true, true, Err(SshError::KeyProfile))
			));
		}
	}
}

#[tokio::test]
async fn protected_key_worker_rechecks_the_same_offer_before_reading() {
	let (profile, trust, stream, server) = peer(true, true);
	let checks = Arc::new(AtomicUsize::new(0));
	let offer_checks = Arc::clone(&checks);
	let connection_thread = std::thread::current().id();
	let result = authenticate(
		stream,
		&profile,
		trust,
		move || match offer_checks.fetch_add(1, Ordering::Relaxed) {
			0 => {
				assert_eq!(std::thread::current().id(), connection_thread);
				true
			}
			1 => {
				assert_ne!(std::thread::current().id(), connection_thread);
				false
			}
			_ => panic!("a retired key offer cannot be used"),
		},
		|| true,
	)
	.await;
	server.abort();
	let _ = server.await;
	assert!(matches!(result, Err(SshError::KeyProfile)));
	assert_eq!(checks.load(Ordering::Relaxed), 2);
}
