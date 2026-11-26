use std::cell::Cell;
use std::fmt::Write as _;

use exacopy_endpoint::ssh_sftp::{
	CredentialSource, HostKeyFingerprint, InteractionPolicy, KnownHostStatus, verify_host,
};
use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{HashAlg, PrivateKey};
use serde_json::json;

use super::*;
use crate::remote_frontdoor::SshProfile;

const PASS: &[u8] = b" synthetic passphrase with spaces ";

fn fixture_profile(public_key_sha256: [u8; 32], passphrase_env: Option<&str>) -> serde_json::Value {
	let mut hex = String::new();
	for byte in public_key_sha256 {
		write!(hex, "{byte:02x}").unwrap();
	}
	let mut profile = super::super::super::tests::profile();
	profile["credential"] = json!({
		"kind": "openssh-ed25519",
		"private_key_file": "/synthetic/private/key",
		"public_key_sha256": hex
	});
	if let Some(name) = passphrase_env {
		profile["credential"]["passphrase_env"] = json!(name);
	}
	profile
}

fn fixture() -> PrivateKey {
	let keypair = Ed25519Keypair::from_seed(&[23; 32]);
	PrivateKey::new(KeypairData::Ed25519(keypair), "").unwrap()
}

fn approve(profile: &SshProfile) -> ProtectedEd25519 {
	let verified = verify_host(
		&profile.authority,
		profile.pin,
		KnownHostStatus::Trusted,
		Some(profile.pin),
	)
	.unwrap();
	let request = verified
		.request_credential(
			&profile.authority,
			CredentialSource::SuppliedKey,
			InteractionPolicy::Forbidden,
		)
		.unwrap();
	profile.approve_ed25519(request).unwrap()
}

#[test]
fn selects_key_with_strict_broker_fields_and_verified_credential() {
	let mut selected = fixture_profile([2; 32], Some("EXACOPY_TEST_KEY_ONLY"));
	let profile = SshProfile::decode(&selected.to_string().into_bytes()).unwrap();
	assert_eq!(profile.credential_source(), CredentialSource::SuppliedKey);
	for (fingerprint, source, interaction) in [
		(
			HostKeyFingerprint::from_sha256([3; 32]),
			CredentialSource::SuppliedKey,
			InteractionPolicy::Forbidden,
		),
		(
			profile.pin,
			CredentialSource::SuppliedPassword,
			InteractionPolicy::Forbidden,
		),
		(
			profile.pin,
			CredentialSource::SuppliedKey,
			InteractionPolicy::Allowed,
		),
	] {
		let verified = verify_host(
			&profile.authority,
			fingerprint,
			KnownHostStatus::Trusted,
			None,
		)
		.unwrap();
		let request = verified
			.request_credential(&profile.authority, source, interaction)
			.unwrap();
		assert!(matches!(
			profile.approve_ed25519(request),
			Err(SshError::KeyProfile)
		));
	}
	selected["credential"]["passphrase"] = json!("not a permitted field");
	assert!(SshProfile::decode(&selected.to_string().into_bytes()).is_err());
	let mut selected = fixture_profile([2; 32], Some("invalid referral"));
	assert!(SshProfile::decode(&selected.to_string().into_bytes()).is_err());
	selected["credential"]["passphrase_env"] = json!("EXACOPY_TEST_KEY_ONLY");
	selected["credential"]["private_key_file"] = json!("relative/key");
	assert!(SshProfile::decode(&selected.to_string().into_bytes()).is_err());
}

#[test]
fn acquire_checks_grant_before_read_passphrase_and_offer() {
	let key = fixture();
	let digest = key.fingerprint(HashAlg::Sha256).sha256().unwrap();
	let encoded = key
		.encrypt(&mut russh::keys::key::safe_rng(), PASS)
		.unwrap()
		.to_openssh(LineEnding::LF)
		.unwrap();
	let input = fixture_profile(digest, Some("EXACOPY_TEST_KEY_ONLY"));
	let profile = SshProfile::decode(&input.to_string().into_bytes()).unwrap();

	for (grants, expected_reads, expected_lookups) in [(0, 0, 0), (1, 1, 0), (2, 1, 1), (3, 1, 1)] {
		let checked = Cell::new(0);
		let reads = Cell::new(0);
		let lookups = Cell::new(0);
		let result = approve(&profile).acquire_from(
			|| {
				let previous = checked.get();
				checked.set(previous + 1);
				previous < grants
			},
			|path, output, readback| {
				assert_eq!(path, Path::new("/synthetic/private/key"));
				assert_eq!(output.len(), MAX_OPENSSH_ED25519_BYTES);
				assert_eq!(readback.len(), READBACK_BYTES);
				reads.set(reads.get() + 1);
				output[..encoded.len()].copy_from_slice(encoded.as_bytes());
				Ok(encoded.len())
			},
			|name| {
				assert_eq!(name, "EXACOPY_TEST_KEY_ONLY");
				lookups.set(lookups.get() + 1);
				Some(OsString::from(std::str::from_utf8(PASS).unwrap()))
			},
		);
		assert_eq!(result.is_ok(), grants == 3);
		assert_eq!(reads.get(), expected_reads);
		assert_eq!(lookups.get(), expected_lookups);
	}
}

#[test]
fn protected_read_refusal_stops_before_passphrase_lookup() {
	let profile = fixture_profile([2; 32], Some("EXACOPY_TEST_NO_ENV_READ"));
	let profile = SshProfile::decode(&profile.to_string().into_bytes()).unwrap();
	assert!(matches!(
		approve(&profile).acquire_from(
			|| true,
			|_, output, readback| {
				output[0] = 7;
				readback[0] = 7;
				Err(ProtectedSnapshotError::Unprotected)
			},
			|_| panic!("protected read was refused"),
		),
		Err(SshError::KeyProfile)
	));
	let key = ProtectedEd25519 {
		private_key_file: PathBuf::from("relative-selection-refused-before-io"),
		public_key_sha256: PublicDigest([2; 32]),
		passphrase_env: None,
	};
	assert!(matches!(key.acquire(|| true), Err(SshError::KeyProfile)));
}
