use std::net::SocketAddrV6;

use exacopy_journal::remote_download::replay::{
	RemoteReplayState, replay_remote_download, replay_remote_download_with_bootstrap,
};
use exacopy_journal::remote_download::{DirectPeerRefusal, RemoteBootstrapTrust};

use super::{
	Body, ChainHead, Error, FrameKind, FrameWriter, LinuxFileIdentity, NonZeroU16,
	RemoteDownloadContext, RemoteDownloadOwnerRecord, RemoteDownloadRecord, RemoteDownloadRoute,
	RemoteDownloadSource, RemoteScopeDigest, SocketAddr, SshAuthority, frame, hex, manifest,
	profile, signer,
};

const PORT: NonZeroU16 = NonZeroU16::new(2222).expect("nonzero fixture SSH port");
const SELECTED: &str = "192.0.2.7:2222";
const CHANGED: &str = "192.0.2.8:2222";
const SOURCE_DOMAIN: &[u8] = b"ExaCopy/linux-remote-scope/resolved-direct/v1\0";
const V1_DOMAIN: &[u8] = b"ExaCopy/linux-remote-scope/v1\0";

fn vector(label: &str) -> Vec<u8> {
	let title = format!("[{label}]");
	let data = include_str!("resolved-direct.hex")
		.split("\n\n")
		.find_map(|item| item.strip_prefix(&title))
		.expect("known independent resolved direct fixture");
	hex(data)
}

fn socket(raw: &str) -> SocketAddr {
	raw.parse().unwrap()
}

fn source(host: &str, route: RemoteDownloadRoute) -> Result<RemoteDownloadSource, Error> {
	RemoteDownloadSource::new(
		SshAuthority::new(host, PORT, "Reader").unwrap(),
		[0x51; 32],
		route,
		b"inbox/raw-\xff",
	)
}

fn scope_digest(domain: &[u8]) -> RemoteScopeDigest {
	let mut digest = blake3::Hasher::new();
	digest.update(domain).update(&vector("scope"));
	RemoteScopeDigest::from_bytes(*digest.finalize().as_bytes())
}

#[test]
fn resolved_direct_owner_binds_hostname_pin_and_literal_socket_to_new_profile() {
	let signer = signer();
	let key = signer.verifying_key();
	let route = RemoteDownloadRoute::ResolvedDirect {
		endpoint: socket(SELECTED),
	};
	let source = source("Transfer.Example.", route).unwrap();
	let manifest = manifest(source);
	let signed =
		RemoteDownloadOwnerRecord::sign_resolved_direct(manifest.clone(), &signer).unwrap();
	let expected = vector("owner");
	assert_eq!(signed.as_bytes(), expected);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode_resolved_direct(&expected, profile(), &key),
		Ok(signed),
	);
	assert_eq!(
		manifest.scope.source.authority().host(),
		"transfer.example."
	);
	assert_eq!(manifest.scope.source.authority().port(), PORT);
	assert_eq!(manifest.scope.source.host_key_sha256(), &[0x51; 32]);
	assert_eq!(manifest.scope.source.route(), route);
	assert_eq!(
		manifest.scope.digest().unwrap(),
		scope_digest(SOURCE_DOMAIN)
	);
	assert_ne!(manifest.scope.digest().unwrap(), scope_digest(V1_DOMAIN));
	assert_eq!(
		RemoteDownloadOwnerRecord::sign(manifest, &signer),
		Err(Error::Scope)
	);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(&expected, profile(), &key),
		Err(Error::UnsupportedVersion),
	);
}

#[test]
fn resolved_direct_owner_refuses_mixed_profile_and_invalid_socket_even_when_signed() {
	let signer = signer();
	let key = signer.verifying_key();
	for label in ["legacy-header", "missing-required-bit"] {
		assert_eq!(
			RemoteDownloadOwnerRecord::decode_resolved_direct(&vector(label), profile(), &key),
			Err(Error::UnsupportedVersion),
			"{label}",
		);
	}
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(&vector("legacy-header"), profile(), &key),
		Err(Error::Scope),
	);
	for label in [
		"legacy-route",
		"wrong-port",
		"invalid-length",
		"multicast",
		"mapped",
		"link-local",
		"literal-mismatch",
	] {
		assert_eq!(
			RemoteDownloadOwnerRecord::decode_resolved_direct(&vector(label), profile(), &key),
			Err(Error::Scope),
			"{label}",
		);
	}
	let historical =
		RemoteDownloadOwnerRecord::decode(&hex(super::OWNER), profile(), &key).unwrap();
	assert_eq!(
		RemoteDownloadOwnerRecord::decode_resolved_direct(historical.as_bytes(), profile(), &key),
		Err(Error::UnsupportedVersion),
	);
	assert_eq!(
		RemoteDownloadOwnerRecord::sign_resolved_direct(historical.manifest().clone(), &signer),
		Err(Error::Scope),
	);
	let old_direct = vector("legacy-direct");
	let old_record = RemoteDownloadOwnerRecord::decode(&old_direct, profile(), &key).unwrap();
	assert_eq!(
		old_record.manifest().scope.source.route(),
		RemoteDownloadRoute::Direct
	);
	assert_eq!(
		RemoteDownloadOwnerRecord::sign(old_record.manifest().clone(), &signer)
			.unwrap()
			.as_bytes(),
		old_direct,
	);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode_resolved_direct(&old_direct, profile(), &key),
		Err(Error::UnsupportedVersion),
	);
	for (scope, flow) in [(12, 0), (0, 4)] {
		let ip = "2001:db8::7".parse().unwrap();
		let endpoint = SocketAddrV6::new(ip, PORT.get(), flow, scope).into();
		assert!(matches!(
			source(
				"transfer.example.",
				RemoteDownloadRoute::ResolvedDirect { endpoint }
			),
			Err(Error::Scope),
		));
	}
}

#[test]
fn resolved_direct_retry_refuses_different_authentic_peers_and_ports() {
	let key = signer().verifying_key();
	let existing =
		RemoteDownloadOwnerRecord::decode_resolved_direct(&vector("owner"), profile(), &key)
			.unwrap();
	let alternate =
		RemoteDownloadOwnerRecord::decode_resolved_direct(&vector("other-peer"), profile(), &key)
			.unwrap();
	let v6 = RemoteDownloadOwnerRecord::decode_resolved_direct(&vector("ipv6"), profile(), &key)
		.unwrap();
	let source = &existing.manifest().scope.source;
	let other = &alternate.manifest().scope.source;
	assert_eq!(source.authority().host(), other.authority().host());
	assert_eq!(source.host_key_sha256(), other.host_key_sha256());
	assert_ne!(
		existing.manifest().scope.digest().unwrap(),
		alternate.manifest().scope.digest().unwrap()
	);
	assert_eq!(
		source.recheck_resolved_direct_peer(socket(SELECTED)),
		Ok(())
	);
	assert_eq!(
		source.recheck_resolved_direct_peer(socket(CHANGED)),
		Err(DirectPeerRefusal::Changed),
	);
	assert_eq!(
		source.recheck_resolved_direct_peer(socket("192.0.2.7:2223")),
		Err(DirectPeerRefusal::Changed),
	);
	assert_eq!(
		v6.manifest()
			.scope
			.source
			.recheck_resolved_direct_peer(socket("[2001:db8::7]:2222")),
		Ok(()),
	);
	let historical =
		RemoteDownloadOwnerRecord::decode(&hex(super::OWNER), profile(), &key).unwrap();
	assert_eq!(
		historical
			.manifest()
			.scope
			.source
			.recheck_resolved_direct_peer(socket(SELECTED)),
		Err(DirectPeerRefusal::WrongRoute),
	);
}

#[test]
fn resolved_direct_bootstrap_requires_selected_profile_and_exact_scope() {
	let signer = signer();
	let key = signer.verifying_key();
	let owner =
		RemoteDownloadOwnerRecord::decode_resolved_direct(&vector("owner"), profile(), &key)
			.unwrap();
	assert!(matches!(
		RemoteBootstrapTrust::new(&owner, profile(), &key),
		Err(Error::UnsupportedVersion),
	));
	let trust = RemoteBootstrapTrust::new_resolved_direct(&owner, profile(), &key).unwrap();
	let context = RemoteDownloadContext {
		owner: owner.digest(),
		job: owner.manifest().job,
		entry: owner.manifest().scope.entry,
	};
	let job_payload = |scope| {
		RemoteDownloadRecord::new(context, None, Body::JobPrepared { scope })
			.unwrap()
			.encode()
			.unwrap()
	};
	let wrong = frame(
		ChainHead::start(),
		FrameKind::JobPrepared,
		&job_payload(scope_digest(V1_DOMAIN)),
	);
	let stage = LinuxFileIdentity::new(7, 12);
	assert_eq!(trust.sign(&wrong, stage, &signer), Err(Error::Binding));

	let job_payload = job_payload(owner.manifest().scope.digest().unwrap());
	let job = frame(ChainHead::start(), FrameKind::JobPrepared, &job_payload);
	let bootstrap = trust.sign(&job, stage, &signer).unwrap();
	let mut transcript = Vec::new();
	let mut writer = FrameWriter::new(&mut transcript, ChainHead::start());
	assert_eq!(
		writer.append(FrameKind::JobPrepared, &job_payload).unwrap(),
		job.head()
	);
	writer
		.append(FrameKind::StageDirectoryPrepared, &bootstrap)
		.unwrap();
	let result = replay_remote_download_with_bootstrap(transcript.as_slice(), &trust).unwrap();
	assert!(matches!(
		replay_remote_download(transcript.as_slice(), &owner),
		Err(Error::UnsupportedVersion),
	));
	assert!(matches!(
		result.state(),
		RemoteReplayState::StageDirectoryPrepared
	));
	assert_eq!(
		result.stage_directory_prepared().unwrap().directory(),
		stage
	);
}
