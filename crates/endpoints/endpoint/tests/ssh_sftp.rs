//! Contract tests for SSH host trust, credential admission, and SFTP protocol support.

use std::num::NonZeroU16;

use exacopy_endpoint::ssh_sftp::{
	AuthorityError, CredentialRefusal, CredentialSource, HostKeyFingerprint, HostKeyRefusal,
	InteractionPolicy, KnownHostStatus, SftpAdvertisement, SftpCapabilities, SftpRefusal,
	SftpVersionError, SshAuthority, verify_host,
};

const KEY: HostKeyFingerprint = HostKeyFingerprint::from_sha256([1; 32]);
const OTHER_KEY: HostKeyFingerprint = HostKeyFingerprint::from_sha256([2; 32]);

fn authority(host: &str, port: u16, account: &str) -> SshAuthority {
	SshAuthority::new(host, NonZeroU16::new(port).unwrap(), account).unwrap()
}

#[test]
fn only_equivalent_resolved_authorities_share_identity() {
	let original = authority("Backup.Example", 2222, "transfer");
	assert_eq!(original, authority("backup.example", 2222, "transfer"));
	assert_ne!(original, authority("backup.example.", 2222, "transfer"));
	assert_ne!(original, authority("backup.example", 22, "transfer"));
	assert_ne!(original, authority("backup.example", 2222, "Transfer"));
	assert_ne!(original, authority("jump.example", 2222, "transfer"));
	assert_eq!(original.host(), "backup.example");
	assert_eq!(original.port().get(), 2222);
	assert_eq!(original.account(), "transfer");
	assert_eq!(format!("{original:?}"), "SshAuthority(<redacted>)");

	assert_eq!(
		authority("2001:0DB8:0:0:0:0:0:1", 22, "transfer"),
		authority("2001:db8::1", 22, "transfer"),
	);
	assert_eq!(authority("192.0.2.1", 22, "transfer").host(), "192.0.2.1");
	assert_eq!(
		authority("backup.example.", 22, "transfer").host(),
		"backup.example."
	);
}

#[test]
fn host_and_account_fields_are_structured_and_bounded() {
	let port = NonZeroU16::new(22).unwrap();
	for host in [
		"",
		".",
		"example..org",
		"example.org..",
		"-example.org",
		"example-.org",
		"user@example.org",
		"user:password@example.org",
		"example.org:22",
		"https://example.org",
		"example.org/root",
		"example.org\\root",
		"[2001:db8::1]",
		"2001:db8::1%interface",
		"example.org\n",
		"éxample.org",
		&"a".repeat(64),
	] {
		assert_eq!(
			SshAuthority::new(host, port, "transfer"),
			Err(AuthorityError::Host)
		);
	}
	for account in ["", "\x00", "transfer\n", "test\u{009b}", &"a".repeat(257)] {
		assert_eq!(
			SshAuthority::new("backup.example", port, account),
			Err(AuthorityError::Account),
		);
	}
	let max_host = [
		"a".repeat(63),
		"b".repeat(63),
		"c".repeat(63),
		"d".repeat(61),
	]
	.join(".");
	let max_account = "x".repeat(256);
	assert!(SshAuthority::new(&max_host, port, &max_account).is_ok());
	assert!(SshAuthority::new(&format!("{max_host}."), port, &max_account).is_ok());
	assert_eq!(
		SshAuthority::new(&format!("{max_host}x"), port, "transfer"),
		Err(AuthorityError::Host),
	);
}

#[test]
fn trust_policy_refuses_downgrades_even_with_an_explicit_pin() {
	use HostKeyRefusal as Refused;
	use KnownHostStatus as Status;

	let authority = authority("backup.example", 22, "transfer");
	for (status, pin, expected) in [
		(Status::Trusted, None, Ok(())),
		(Status::Trusted, Some(KEY), Ok(())),
		(Status::Trusted, Some(OTHER_KEY), Err(Refused::PinMismatch)),
		(Status::Unknown, None, Err(Refused::Unknown)),
		(Status::Unknown, Some(KEY), Ok(())),
		(Status::Unknown, Some(OTHER_KEY), Err(Refused::PinMismatch)),
		(Status::Changed, None, Err(Refused::Changed)),
		(Status::Changed, Some(KEY), Err(Refused::Changed)),
		(Status::Changed, Some(OTHER_KEY), Err(Refused::Changed)),
		(Status::Revoked, None, Err(Refused::Revoked)),
		(Status::Revoked, Some(KEY), Err(Refused::Revoked)),
		(Status::Revoked, Some(OTHER_KEY), Err(Refused::Revoked)),
		(Status::Unavailable, None, Err(Refused::TrustUnavailable)),
		(
			Status::Unavailable,
			Some(KEY),
			Err(Refused::TrustUnavailable),
		),
		(
			Status::Unavailable,
			Some(OTHER_KEY),
			Err(Refused::TrustUnavailable),
		),
	] {
		assert_eq!(
			verify_host(&authority, KEY, status, pin).map(|_| ()),
			expected
		);
	}
}

#[test]
fn credential_scope_binds_host_port_account_and_verified_key() {
	let target = authority("backup.example", 22, "transfer");
	let verified = verify_host(&target, KEY, KnownHostStatus::Unknown, Some(KEY)).unwrap();

	for other in [
		authority("jump.example", 22, "transfer"),
		authority("backup.example", 2222, "transfer"),
		authority("backup.example", 22, "administrator"),
	] {
		assert_eq!(
			verified
				.request_credential(
					&other,
					CredentialSource::SuppliedPassword,
					InteractionPolicy::Forbidden
				)
				.unwrap_err(),
			CredentialRefusal::AuthorityMismatch,
		);
	}
	let equivalent = authority("BACKUP.Example", 22, "transfer");
	let request = verified
		.request_credential(
			&equivalent,
			CredentialSource::SuppliedPassword,
			InteractionPolicy::Forbidden,
		)
		.unwrap();
	assert_eq!(request.authority(), &target);
	assert_eq!(request.fingerprint(), KEY);
	assert_eq!(request.source(), CredentialSource::SuppliedPassword);
	assert_eq!(request.interaction(), InteractionPolicy::Forbidden);
}

#[test]
fn unattended_prompt_fails_without_falling_back_to_another_mechanism() {
	let target = authority("backup.example", 22, "transfer");
	let verified = verify_host(&target, KEY, KnownHostStatus::Trusted, None).unwrap();
	assert_eq!(
		verified
			.request_credential(
				&target,
				CredentialSource::PasswordPrompt,
				InteractionPolicy::Forbidden
			)
			.unwrap_err(),
		CredentialRefusal::InteractionForbidden,
	);
	for (source, interaction) in [
		(CredentialSource::PasswordPrompt, InteractionPolicy::Allowed),
		(
			CredentialSource::SuppliedPassword,
			InteractionPolicy::Allowed,
		),
		(
			CredentialSource::SuppliedPassword,
			InteractionPolicy::Forbidden,
		),
		(CredentialSource::AgentKey, InteractionPolicy::Allowed),
		(CredentialSource::AgentKey, InteractionPolicy::Forbidden),
	] {
		let selected = verified
			.request_credential(&target, source, interaction)
			.unwrap();
		assert_eq!(selected.source(), source);
		assert_eq!(selected.interaction(), interaction);
	}
}

#[test]
fn sftp_v3_advertisements_are_preserved_but_grant_no_mutation_or_durability() {
	for file_sync in [false, true] {
		for posix_rename in [false, true] {
			for hardlink in [false, true] {
				let advertised = SftpAdvertisement {
					file_sync,
					posix_rename,
					hardlink,
				};
				let support = SftpCapabilities::for_source(3, advertised).unwrap();
				assert_eq!(support.advertisement(), advertised);
				assert_eq!(
					support.require_exclusive_publication(),
					Err(SftpRefusal::ExclusivePublicationUnqualified),
				);
				assert_eq!(
					support.require_namespace_durability(),
					Err(SftpRefusal::NamespaceDurabilityUnqualified),
				);
				assert_eq!(
					support.require_protected_replacement(),
					Err(SftpRefusal::ProtectedReplacementUnqualified),
				);
			}
		}
	}
}

#[test]
fn other_protocol_versions_refuse_without_fallback() {
	for version in [0, 1, 2, 4, 5, 6, u32::MAX] {
		assert_eq!(
			SftpCapabilities::for_source(version, SftpAdvertisement::default()),
			Err(SftpVersionError { version }),
		);
	}
}
