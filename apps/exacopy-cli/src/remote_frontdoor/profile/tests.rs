use exacopy_endpoint::ssh_sftp::{KnownHostStatus, verify_host};
use exacopy_ssh::KnownHostsError;

use super::*;
use crate::remote_frontdoor::tests::profile;

fn selected_profile() -> SshProfile {
	SshProfile::decode(&serde_json::to_vec(&profile()).unwrap()).unwrap()
}

#[test]
fn reacquires_the_exact_selected_trust_snapshot_on_each_attempt() {
	let profile = selected_profile();
	let mut snapshots = [
		Ok(b"# empty dedicated store\n".to_vec()),
		Ok(b"malformed".to_vec()),
		Err(ProtectedSnapshotError::Changed),
	]
	.into_iter();
	let mut read = |path: &Path| {
		assert_eq!(path, Path::new("/synthetic/private/known_hosts"));
		snapshots.next().unwrap()
	};

	let first = profile.read_trust_from(&mut read).unwrap();
	assert_eq!(
		first.status(&profile.authority, profile.pin),
		KnownHostStatus::Unknown
	);
	let other = SshAuthority::new(
		profile.authority.host(),
		profile.authority.port(),
		"another-reader",
	)
	.unwrap();
	assert_eq!(
		first.status(&other, profile.pin),
		KnownHostStatus::Unavailable
	);
	assert!(matches!(
		profile.read_trust_from(&mut read),
		Err(FrontdoorError::Trust(KnownHostsError::Malformed {
			line: 1
		}))
	));
	assert!(matches!(
		profile.read_trust_from(&mut read),
		Err(FrontdoorError::Protected(ProtectedSnapshotError::Changed))
	));
}

#[test]
fn password_request_refusal_precedes_the_grant_and_secret_lookup() {
	let profile = selected_profile();
	let wrong_pin = HostKeyFingerprint::from_sha256([2; 32]);
	let host = verify_host(
		&profile.authority,
		wrong_pin,
		KnownHostStatus::Trusted,
		None,
	)
	.unwrap();
	let request = host
		.request_credential(
			&profile.authority,
			CredentialSource::SuppliedPassword,
			InteractionPolicy::Forbidden,
		)
		.unwrap();

	assert!(matches!(
		profile.password_from(
			request,
			|| panic!("an unmatched host reached the grant check"),
			|_| panic!("an unmatched host reached the broker"),
		),
		Err(SshError::Password)
	));
}
