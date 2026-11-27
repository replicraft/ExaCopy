use std::ffi::{OsStr, OsString};
use std::num::NonZeroU16;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use exacopy_endpoint::remote_source::SftpPathRoot;
use exacopy_endpoint::ssh_sftp::{
	CredentialSource, HostKeyFingerprint, InteractionPolicy, KnownHostStatus, verify_host,
};
use exacopy_journal::remote_download::RemoteDownloadRoute;
use serde_json::json;

use super::{
	AddressOrder, ApprovedRoute, FrontdoorError, GetRequest, RemoteOperand, RemotePath, SshProfile,
	WireGuardRoute,
};

pub(super) fn profile() -> serde_json::Value {
	json!({
		"schema": "exacopy-ssh-profile-v1",
		"host": "ARCHIVE.example.",
		"port": 2222,
		"account": "reader",
		"host_key_sha256": "a5".repeat(32),
		"known_hosts": "/synthetic/private/known_hosts",
		"credential": {"kind": "password-env", "name": "EXACOPY_FIXTURE_ONLY"},
		"route": {"kind": "direct", "endpoint": "192.0.2.10:2222"},
		"maximum_extent": 65536,
		"grant_seconds": 30,
	})
}

fn decode(value: serde_json::Value) -> Result<SshProfile, FrontdoorError> {
	SshProfile::decode(&serde_json::to_vec(&value).unwrap())
}

pub(crate) fn ssh_profile_fixture(configure: impl FnOnce(&mut serde_json::Value)) -> SshProfile {
	let mut input = profile();
	configure(&mut input);
	decode(input).expect("decode the synthetic SSH profile")
}

fn request(
	source: &OsStr,
	destination: PathBuf,
	route: Option<&str>,
) -> Result<GetRequest, FrontdoorError> {
	GetRequest::new(
		source,
		destination,
		"owner".into(),
		"/synthetic/private/profile".into(),
		route,
	)
}

#[test]
fn retains_raw_local_and_remote_names_and_canonical_host() {
	let input = OsStr::from_bytes(b"reader@Archive.EXAMPLE.:pub/\xff:tail");
	let target = PathBuf::from(OsStr::from_bytes(b"./a:b/\xfe"));
	let command = request(input, target.clone(), Some("sftp-data-only-v1")).unwrap();
	assert_eq!(command.destination, target);
	assert_eq!(command.owner_profile, PathBuf::from("owner"));
	assert_eq!(
		command.ssh_profile,
		PathBuf::from("/synthetic/private/profile")
	);
	assert_eq!(command.metadata.name(), "sftp-data-only-v1");
	assert!(matches!(
		command.source.path(),
		RemotePath::AccountRelative(b"pub/\xff:tail")
	));
	let profile = decode(profile()).unwrap();
	assert_eq!(profile.authority.host(), "archive.example.");
	assert_eq!(profile.authority.port().get(), 2222);
	assert_eq!(profile.pin_digest, [0xa5; 32]);
	assert_eq!(profile.maximum_extent, 65536);
	assert_eq!(profile.grant_duration, Duration::from_secs(30));
	assert_eq!(
		profile.route,
		ApprovedRoute::Direct("192.0.2.10:2222".parse().unwrap())
	);
	profile.require_source(&command.source).unwrap();
	let endpoint = "192.0.2.10:2222".parse().unwrap();
	let signed = command
		.signed_source(&profile, RemoteDownloadRoute::ResolvedDirect { endpoint })
		.unwrap();
	assert_eq!(signed.path_root(), SftpPathRoot::AccountRelative);
	assert_eq!(signed.path(), b"pub/\xff:tail");
	let mismatch = RemoteOperand::parse(OsStr::new("Reader@archive.example.:name")).unwrap();
	assert!(matches!(
		profile.require_source(&mismatch),
		Err(FrontdoorError::Authority)
	));
}

#[test]
fn invalid_metadata_and_local_path_refuse_before_protected_or_destination_io() {
	let input = OsStr::new("reader@archive.example.:data");
	assert!(matches!(
		request(OsStr::new("also invalid"), "subdir/".into(), None),
		Err(FrontdoorError::MetadataRequired)
	));
	assert!(matches!(
		request(input, "target".into(), Some("required")),
		Err(FrontdoorError::MetadataSelector)
	));
	assert!(matches!(
		request(input, "subdir/".into(), Some("sftp-data-only-v1")),
		Err(FrontdoorError::Destination)
	));
}

#[test]
fn absolute_operands_keep_the_exact_signed_path_on_both_approved_routes() {
	let direct = request(
		OsStr::from_bytes(b"reader@archive.example.:/var/data/\xff:tail"),
		"target".into(),
		Some("sftp-data-only-v1"),
	)
	.unwrap();
	let direct_profile = decode(profile()).unwrap();
	let endpoint = "192.0.2.10:2222".parse().unwrap();
	let direct_route = RemoteDownloadRoute::ResolvedDirect { endpoint };
	let signed = direct.signed_source(&direct_profile, direct_route).unwrap();
	assert_eq!(signed.path_root(), SftpPathRoot::Absolute);
	assert_eq!(signed.path(), b"/var/data/\xff:tail");
	assert!(matches!(
		direct.signed_source(&direct_profile, RemoteDownloadRoute::Direct),
		Err(FrontdoorError::Route)
	));

	let embedded = request(
		OsStr::from_bytes(b"reader@[2001:db8::10]:/var/data/\xff:tail"),
		"target".into(),
		Some("sftp-data-only-v1"),
	)
	.unwrap();
	let profile = decode(embedded_profile()).unwrap();
	let ApprovedRoute::EmbeddedWireGuard(approved) = &profile.route else {
		panic!("selected embedded route");
	};
	let route = RemoteDownloadRoute::EmbeddedWireGuard {
		peer: approved.peer_public_key,
		revision: approved.revision,
		inner: approved.remote_inner,
	};
	let signed = embedded.signed_source(&profile, route).unwrap();
	assert_eq!(signed.path_root(), SftpPathRoot::Absolute);
	assert_eq!(signed.path(), b"/var/data/\xff:tail");
	assert_eq!(signed.route(), route);
	assert!(matches!(
		embedded.signed_source(&profile, direct_route),
		Err(FrontdoorError::Route)
	));
}

#[test]
fn rejects_ambiguous_and_noncanonical_remote_operands() {
	let valid = RemoteOperand::parse(OsStr::new("reader@[2001:db8::1]:report:Q1")).unwrap();
	assert_eq!(
		valid.authority(NonZeroU16::MIN).unwrap().host(),
		"2001:db8::1"
	);
	assert!(matches!(
		valid.path(),
		RemotePath::AccountRelative(b"report:Q1")
	));
	let host_name = RemoteOperand::parse(OsStr::new("reader@archive.example:report:Q1")).unwrap();
	assert!(matches!(
		host_name.path(),
		RemotePath::AccountRelative(b"report:Q1")
	));
	for bad in [
		"reader@2001:db8::1:report",
		"reader@fe80::1%3:report",
		"reader@[2001:db8::1%3]:report",
		"reader@[archive.example]:report",
		"reader:password@archive.example:path",
		"reader/alt@archive.example:path",
		"reader@archive.example:",
		"reader@archive.example:path/",
		"reader@archive.example:pub//file",
		"reader@archive.example:./file",
		"reader@archive.example:pub/../file",
		"reader@archive.example://file",
		"ssh://reader@archive.example/file",
	] {
		assert!(RemoteOperand::parse(OsStr::new(bad)).is_err(), "{bad}");
	}
	assert!(RemoteOperand::parse(OsStr::from_bytes(b"reader@archive.example:pub/a\0b")).is_err());
}

#[test]
fn protected_schema_refuses_unknown_duplicate_or_out_of_scope_values() {
	let good = serde_json::to_string(&profile()).unwrap();
	let duplicate = good.replacen("\"port\":2222", "\"port\":2222,\"port\":2222", 1);
	assert!(SshProfile::decode(duplicate.as_bytes()).is_err());
	assert!(matches!(
		SshProfile::decode(&[b' '; 16 * 1024 + 1]),
		Err(FrontdoorError::ProfileSize)
	));
	for (selector, tampered) in [
		("schema", json!("exacopy-ssh-profile-v2")),
		("port", json!(0)),
		("known_hosts", json!("relative/hosts")),
		("known_hosts", json!("/synthetic/../hosts")),
		("host_key_sha256", json!("A5".repeat(32))),
		("host_key_sha256", json!("00".repeat(32))),
		("credential", json!({"kind":"password-env","name":"a=b"})),
		(
			"credential",
			json!({"kind":"password-env","name":"VAR","secret":"fixture"}),
		),
		("credential", json!({"kind":"agent"})),
		("route", json!({"kind":"direct","endpoint":"192.0.2.10:22"})),
		(
			"route",
			json!({"kind":"direct","endpoint":"[::ffff:192.0.2.10]:2222"}),
		),
		(
			"route",
			json!({"kind":"direct","endpoint":"[fe80::1]:2222"}),
		),
		(
			"route",
			json!({"kind":"resolve-authority","order":"random"}),
		),
		(
			"route",
			json!({"kind":"resolve-authority","order":"ipv4-first","fallback":true}),
		),
		("maximum_extent", json!(exacopy_ssh::MAX_STREAM_BYTES + 1)),
		("grant_seconds", json!(3601)),
		("extra", json!(true)),
	] {
		let mut candidate = profile();
		candidate[selector] = tampered;
		assert!(decode(candidate).is_err(), "{selector}");
	}
}

#[test]
fn route_selector_retains_resolution_policy_and_fixes_literal_target() {
	let mut candidate = profile();
	candidate["route"] = json!({"kind":"resolve-authority","order":"ipv6-first"});
	assert_eq!(
		decode(candidate.clone()).unwrap().route,
		ApprovedRoute::ResolveAuthority(AddressOrder::Ipv6First)
	);
	candidate["host"] = json!("192.0.2.10");
	assert!(decode(candidate.clone()).is_err());
	candidate["route"] = json!({"kind":"direct","endpoint":"192.0.2.11:2222"});
	assert!(decode(candidate).is_err());
}

fn embedded_profile() -> serde_json::Value {
	let mut candidate = profile();
	candidate["host"] = json!("2001:db8::10");
	candidate["route"] = json!({
		"kind":"embedded-wireguard",
		"outer_mtu":1500,
		"outer":"198.51.100.10:51820",
		"local_inner":"2001:db8::11",
		"remote_inner":"[2001:db8::10]:2222",
		"local_public_key":"15".repeat(32),
		"peer_public_key":"24".repeat(32),
		"private_key_file":"/synthetic/private/key"
	});
	candidate
}

#[test]
fn embedded_revision_binds_public_fields_without_reading_key_file() {
	let mut candidate = embedded_profile();
	let profile = decode(candidate.clone()).unwrap();
	let ApprovedRoute::EmbeddedWireGuard(first) = profile.route else {
		panic!("selected route")
	};
	let _: &WireGuardRoute = &first;
	assert_eq!(first.remote_inner, "[2001:db8::10]:2222".parse().unwrap());
	assert_eq!(
		first.private_key_file,
		PathBuf::from("/synthetic/private/key")
	);
	candidate["route"]["outer"] = json!("198.51.100.11:51820");
	let ApprovedRoute::EmbeddedWireGuard(second) = decode(candidate.clone()).unwrap().route else {
		panic!("selected route")
	};
	assert_ne!(first.revision, second.revision);
	candidate["route"]["local_inner"] = json!("192.0.2.19");
	assert!(decode(candidate).is_err());
}

#[test]
fn named_embedded_authority_requires_explicit_inner_and_revision_bound_mtu() {
	let mut candidate = embedded_profile();
	candidate["host"] = json!("storage.example.test");
	let ApprovedRoute::EmbeddedWireGuard(original) = decode(candidate.clone()).unwrap().route
	else {
		panic!("expected an embedded route");
	};
	assert_eq!(
		original.remote_inner,
		"[2001:db8::10]:2222".parse().unwrap()
	);
	candidate["route"]["outer_mtu"] = json!(1400);
	let ApprovedRoute::EmbeddedWireGuard(reduced) = decode(candidate.clone()).unwrap().route else {
		panic!("expected an embedded route");
	};
	assert_ne!(original.revision, reduced.revision);
	candidate["route"]["remote_inner"] = json!("[2001:db8::12]:2222");
	let ApprovedRoute::EmbeddedWireGuard(other) = decode(candidate.clone()).unwrap().route else {
		panic!("expected an embedded route");
	};
	assert_ne!(reduced.revision, other.revision);
	candidate["host"] = json!("2001:db8::10");
	assert!(decode(candidate.clone()).is_err());
	candidate["host"] = json!("storage.example.test");
	candidate["route"]["remote_inner"] = json!("[2001:db8::12]:22");
	assert!(decode(candidate).is_err());
	for mtu in [json!(0), json!(1501), serde_json::Value::Null] {
		let mut invalid = embedded_profile();
		invalid["route"]["outer_mtu"] = mtu;
		assert!(decode(invalid).is_err());
	}
	let mut incomplete = embedded_profile();
	incomplete["route"]
		.as_object_mut()
		.unwrap()
		.remove("remote_inner");
	assert!(decode(incomplete).is_err());
}

#[test]
fn broker_reads_exact_reference_only_for_verified_host_and_current_grant() {
	let profile = decode(profile()).unwrap();
	for (fingerprint, source, interaction, grant, permitted) in [
		(
			profile.pin,
			CredentialSource::SuppliedPassword,
			InteractionPolicy::Forbidden,
			true,
			true,
		),
		(
			profile.pin,
			CredentialSource::SuppliedPassword,
			InteractionPolicy::Forbidden,
			false,
			false,
		),
		(
			profile.pin,
			CredentialSource::SuppliedKey,
			InteractionPolicy::Forbidden,
			true,
			false,
		),
		(
			profile.pin,
			CredentialSource::SuppliedPassword,
			InteractionPolicy::Allowed,
			true,
			false,
		),
		(
			HostKeyFingerprint::from_sha256([2; 32]),
			CredentialSource::SuppliedPassword,
			InteractionPolicy::Forbidden,
			true,
			false,
		),
	] {
		let host = verify_host(
			&profile.authority,
			fingerprint,
			KnownHostStatus::Trusted,
			None,
		)
		.unwrap();
		let request = host
			.request_credential(&profile.authority, source, interaction)
			.unwrap();
		let result = profile.password_from(
			request,
			|| grant,
			|name| {
				assert!(permitted);
				assert_eq!(name, "EXACOPY_FIXTURE_ONLY");
				Some(OsString::from(" synthetic password with whitespace "))
			},
		);
		assert_eq!(result.is_ok(), permitted);
	}
	let other = exacopy_endpoint::ssh_sftp::SshAuthority::new(
		profile.authority.host(),
		profile.authority.port(),
		"another-reader",
	)
	.unwrap();
	let verified = verify_host(&other, profile.pin, KnownHostStatus::Trusted, None).unwrap();
	let wrong = verified
		.request_credential(
			&other,
			CredentialSource::SuppliedPassword,
			InteractionPolicy::Forbidden,
		)
		.unwrap();
	assert!(
		profile
			.password_from(wrong, || true, |_| panic!("outside authority"))
			.is_err()
	);
	let request = || {
		verify_host(
			&profile.authority,
			profile.pin,
			KnownHostStatus::Trusted,
			None,
		)
		.unwrap()
	};
	let host = request();
	let credential = host
		.request_credential(
			&profile.authority,
			CredentialSource::SuppliedPassword,
			InteractionPolicy::Forbidden,
		)
		.unwrap();
	assert!(
		profile
			.password_from(
				credential,
				|| true,
				|_| Some(OsString::from_vec(vec![0xff]))
			)
			.is_err()
	);
	// Compile the real callback without reading the environment.
	let _broker = |request| profile.password(request, || false);
}

#[test]
fn protected_io_refuses_relative_path_and_redacts_inputs() {
	let _load = GetRequest::load_profile;
	let _read = SshProfile::read_trust;
	assert!(matches!(
		SshProfile::load(Path::new("private-do-not-echo")),
		Err(FrontdoorError::Protected(_))
	));
	let profile = decode(profile()).unwrap();
	#[cfg(not(target_os = "linux"))]
	assert!(matches!(
		profile.read_trust(),
		Err(FrontdoorError::Protected(_))
	));
	let command = request(
		OsStr::new("reader@archive.example.:secret-name"),
		"target".into(),
		Some("sftp-data-only-v1"),
	)
	.unwrap();
	#[cfg(not(target_os = "linux"))]
	assert!(matches!(
		command.load_profile(),
		Err(FrontdoorError::Protected(_))
	));
	assert!(!format!("{profile:?} {command:?}").contains("EXACOPY_FIXTURE_ONLY"));
	assert!(!format!("{command:?}").contains("secret-name"));
}
