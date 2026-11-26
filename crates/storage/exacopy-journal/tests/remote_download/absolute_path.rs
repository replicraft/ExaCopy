use exacopy_endpoint::remote_source::SftpPathRoot;
use exacopy_journal::remote_download::replay::{
	RemoteReplayState, replay_remote_download, replay_remote_download_with_bootstrap,
};
use exacopy_journal::remote_download::{MAX_REMOTE_PATH_BYTES, RemoteBootstrapTrust};

use super::{
	Body, ChainHead, Error, FrameKind, FrameWriter, LinuxFileIdentity, NonZeroU16,
	RemoteDownloadContext, RemoteDownloadOwnerRecord, RemoteDownloadRecord, RemoteDownloadRoute,
	RemoteDownloadSource, RemoteScopeDigest, SshAuthority, frame, hex, manifest, profile, signer,
	wireguard,
};

const NAME: &[u8] = b"/inbox/raw-\xff";
const DOMAIN: &[u8] = b"ExaCopy/linux-remote-scope/absolute-path/v1\0";
const HOST: &str = "Transfer.Example.";

fn vector(label: &str) -> Vec<u8> {
	let selected = format!("[{label}]");
	let data = include_str!("absolute-path.hex")
		.split("\n\n")
		.find_map(|part| part.strip_prefix(&selected))
		.expect("independent absolute path fixture");
	hex(data)
}

fn direct() -> RemoteDownloadRoute {
	RemoteDownloadRoute::ResolvedDirect {
		endpoint: "192.0.2.7:2222".parse().unwrap(),
	}
}

fn authority() -> SshAuthority {
	SshAuthority::new(HOST, NonZeroU16::new(2222).unwrap(), "Reader").unwrap()
}

#[test]
fn absolute_owner_keeps_exact_path_and_requires_bound_direct_or_wireguard() {
	let signer = signer();
	let key = signer.verifying_key();
	for (label, scope_fixture, route) in [
		("direct", "direct-scope", direct()),
		("embedded", "embedded-scope", wireguard("10.15.17.19:2222")),
	] {
		let source =
			RemoteDownloadSource::new_absolute(authority(), [0x51; 32], route, NAME).unwrap();
		let manifest = manifest(source);
		let owner =
			RemoteDownloadOwnerRecord::sign_absolute_path(manifest.clone(), &signer).unwrap();
		assert_eq!(owner.as_bytes(), vector(label));
		assert_eq!(
			RemoteDownloadOwnerRecord::decode_absolute_path(owner.as_bytes(), profile(), &key),
			Ok(owner.clone()),
		);
		assert_eq!(manifest.scope.source.path(), NAME);
		assert_eq!(manifest.scope.source.path_root(), SftpPathRoot::Absolute);
		let mut hash = blake3::Hasher::new();
		hash.update(DOMAIN).update(&vector(scope_fixture));
		assert_eq!(
			manifest.scope.digest().unwrap(),
			RemoteScopeDigest::from_bytes(*hash.finalize().as_bytes()),
		);

		assert_eq!(
			RemoteDownloadOwnerRecord::decode(owner.as_bytes(), profile(), &key),
			Err(Error::UnsupportedVersion),
		);
		assert_eq!(
			RemoteDownloadOwnerRecord::decode_resolved_direct(owner.as_bytes(), profile(), &key),
			Err(Error::UnsupportedVersion),
		);
		assert_eq!(
			RemoteDownloadOwnerRecord::sign(manifest.clone(), &signer),
			Err(Error::Scope)
		);
		assert_eq!(
			RemoteDownloadOwnerRecord::sign_resolved_direct(manifest, &signer),
			Err(Error::Scope)
		);
		assert!(matches!(
			replay_remote_download([].as_slice(), &owner),
			Err(Error::UnsupportedVersion),
		));
		assert!(matches!(
			RemoteBootstrapTrust::new(&owner, profile(), &key),
			Err(Error::UnsupportedVersion)
		));
		assert!(RemoteBootstrapTrust::new_absolute_path(&owner, profile(), &key).is_ok());
	}
}

#[test]
fn absolute_owner_refuses_other_roots_and_malformed_signed_names() {
	let key = signer().verifying_key();
	for label in [
		"legacy-header",
		"resolved-relative-header",
		"missing-required-bit",
	] {
		assert_eq!(
			RemoteDownloadOwnerRecord::decode_absolute_path(&vector(label), profile(), &key),
			Err(Error::UnsupportedVersion),
			"{label}",
		);
	}
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(&vector("legacy-header"), profile(), &key),
		Err(Error::Scope),
	);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode_resolved_direct(
			&vector("resolved-relative-header"),
			profile(),
			&key
		),
		Err(Error::Scope),
	);
	for label in [
		"relative",
		"unbound",
		"root-only",
		"double-slash",
		"trailing",
		"parent",
		"dot",
	] {
		assert_eq!(
			RemoteDownloadOwnerRecord::decode_absolute_path(&vector(label), profile(), &key),
			Err(Error::Scope),
			"{label}",
		);
	}
	assert!(matches!(
		RemoteDownloadSource::new(authority(), [0x51; 32], direct(), NAME),
		Err(Error::Scope),
	));
	let mut maximum = Vec::new();
	for _ in 0..16 {
		maximum.push(b'/');
		maximum.extend([b'a'; 255]);
	}
	assert_eq!(maximum.len(), MAX_REMOTE_PATH_BYTES);
	RemoteDownloadSource::new_absolute(authority(), [0x51; 32], direct(), &maximum).unwrap();
	maximum.extend(b"/a");
	assert!(matches!(
		RemoteDownloadSource::new_absolute(authority(), [0x51; 32], direct(), &maximum),
		Err(Error::Length),
	));
}

#[test]
fn strict_bootstrap_binds_absolute_name_for_embedded_route() {
	let signer = signer();
	let key = signer.verifying_key();
	let owner =
		RemoteDownloadOwnerRecord::decode_absolute_path(&vector("embedded"), profile(), &key)
			.unwrap();
	let trust = RemoteBootstrapTrust::new_absolute_path(&owner, profile(), &key).unwrap();
	let context = RemoteDownloadContext {
		owner: owner.digest(),
		job: owner.manifest().job,
		entry: owner.manifest().scope.entry,
	};
	let scope = owner.manifest().scope.digest().unwrap();
	let payload = RemoteDownloadRecord::new(context, None, Body::JobPrepared { scope })
		.unwrap()
		.encode()
		.unwrap();
	let job = frame(ChainHead::start(), FrameKind::JobPrepared, &payload);
	let stage = LinuxFileIdentity::new(7, 12);
	let bootstrap = trust.sign(&job, stage, &signer).unwrap();
	let mut bytes = Vec::new();
	let mut writer = FrameWriter::new(&mut bytes, ChainHead::start());
	assert_eq!(
		writer.append(FrameKind::JobPrepared, &payload).unwrap(),
		job.head()
	);
	writer
		.append(FrameKind::StageDirectoryPrepared, &bootstrap)
		.unwrap();
	let observed = replay_remote_download_with_bootstrap(bytes.as_slice(), &trust).unwrap();
	assert!(matches!(
		observed.state(),
		RemoteReplayState::StageDirectoryPrepared
	));
	assert_eq!(
		observed.stage_directory_prepared().unwrap().directory(),
		stage
	);
}
