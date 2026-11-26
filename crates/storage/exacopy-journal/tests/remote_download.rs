//! Independent projection, authority and exact framing controls for private remote journals.

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU64};

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::ssh_sftp::SshAuthority;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::remote_download::{
	MAX_REMOTE_DOWNLOAD_OWNER_BYTES, MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES, RemoteDownloadBody as Body,
	RemoteDownloadContext, RemoteDownloadDestination, RemoteDownloadDurability,
	RemoteDownloadError as Error, RemoteDownloadOwner, RemoteDownloadOwnerRecord,
	RemoteDownloadRecord, RemoteDownloadRoute, RemoteDownloadScope, RemoteDownloadSource,
	RemoteEpochs, RemoteScopeDigest, RemoteSourceObservation, RemoteUncertainBoundary,
};
use exacopy_journal::{
	DarwinJobPrepared, DarwinOwnerRecord, DestinationRootBinding, JobPrepared, JournalContext,
	JournalEntryId, JournalEpoch, JournalJobId, LinuxFileIdentity, OwnerDigest, OwnerError,
	OwnerManifest, OwnerProfileId, OwnerRecord, OwnerStateDirectory, OwnerTimestamp, OwnerToken,
	PlanDigest, PublicApplyOwnerRecord, RootCapabilityId, StreamDigest, StreamLength,
};
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

#[path = "remote_download/absolute_path.rs"]
mod absolute_path;
#[path = "remote_download/properties.rs"]
mod properties;
#[path = "remote_download/resolved_direct.rs"]
mod resolved_direct;

const JOB: [u8; 16] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x7c, 0xde, 0x8f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
];
const ENTRY: [u8; 16] = [0x33; 16];
const DOMAIN: &[u8] = b"ExaCopy/owner/linux-remote-download/v1\0";
const OWNER: &str = include_str!("remote_download/owner.hex");
const SCOPE: &str = include_str!("remote_download/scope.hex");
const PREDECESSOR: (u64, u8) = (3, 0xa3);
const NONCE: [u8; 16] = [0x61; 16];
const MODE: u32 = 0o100644;
const EXTENT: u64 = 65_536;

fn hex(text: &str) -> Vec<u8> {
	let ascii = text.split_ascii_whitespace().collect::<String>();
	let (pairs, remainder) = ascii.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty(), "fixture must contain complete octets");
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn signer() -> SigningKey {
	SigningKey::from_bytes(&[0x52; 32])
}

fn profile() -> OwnerProfileId {
	OwnerProfileId::from_bytes([0x22; 16]).unwrap()
}

fn token() -> OwnerToken {
	OwnerToken::from_bytes([0x11; 16]).unwrap()
}

fn root() -> RootCapabilityId {
	let mut bytes = [0x54; 16];
	bytes[8] = 0x94;
	RootCapabilityId::from_bytes(bytes).unwrap()
}

fn context() -> RemoteDownloadContext {
	RemoteDownloadContext {
		owner: OwnerDigest::from_bytes([0x44; 32]),
		job: JournalJobId::from_bytes(JOB).unwrap(),
		entry: JournalEntryId::from_bytes(ENTRY),
	}
}

fn authority(host: &str, account: &str) -> SshAuthority {
	SshAuthority::new(host, NonZeroU16::new(22).unwrap(), account).unwrap()
}

fn source(route: RemoteDownloadRoute) -> RemoteDownloadSource {
	RemoteDownloadSource::new(
		authority("Transfer.Example.", "Reader"),
		[0x51; 32],
		route,
		b"inbox/raw-\xff",
	)
	.unwrap()
}

fn wireguard(inner: &str) -> RemoteDownloadRoute {
	RemoteDownloadRoute::EmbeddedWireGuard {
		peer: [0x52; 32],
		revision: [0x53; 32],
		inner: inner.parse::<SocketAddr>().unwrap(),
	}
}

fn manifest(source: RemoteDownloadSource) -> RemoteDownloadOwner {
	RemoteDownloadOwner::new(
		token(),
		context().job,
		profile(),
		OwnerTimestamp::new(-1, 999_999_999).unwrap(),
		LinuxFileIdentity::new(7, 11),
		RemoteDownloadScope::new(
			context().entry,
			source,
			RemoteDownloadDestination::new(
				root(),
				LinuxFileIdentity::new(7, 9),
				UnixComponent::new(b"target-\xff").unwrap(),
			),
			StreamLength::new(10_u64.pow(9)).unwrap(),
			[0x56; 32],
			RemoteDownloadDurability::ProcessCrash,
		)
		.unwrap(),
	)
	.unwrap()
}

fn epochs(run: u64, source: u64) -> RemoteEpochs {
	RemoteEpochs {
		run: NonZeroU64::new(run).unwrap(),
		source: NonZeroU64::new(source).unwrap(),
	}
}

fn head(sequence: u64, marker: u8) -> ChainHead {
	ChainHead::after(sequence, [marker; 32]).unwrap()
}

fn vectors() -> [(RemoteDownloadRecord<'static>, &'static str); 5] {
	let prepared = head(PREDECESSOR.0, PREDECESSOR.1);
	let stages = epochs(2, 10);
	[
		(
			None,
			Body::JobPrepared {
				scope: RemoteScopeDigest::from_bytes([0x55; 32]),
			},
			include_str!("remote_download/job.hex"),
		),
		(
			Some(head(1, 0xa1)),
			Body::StageAllocated {
				previous: Some(epochs(1, 9)),
				next: stages,
				name: UnixComponent::new(b"attempt-\xff").unwrap(),
				nonce: NONCE,
				source: RemoteSourceObservation::new(StreamLength::new(EXTENT).unwrap(), MODE, 22)
					.unwrap(),
			},
			include_str!("remote_download/allocation.hex"),
		),
		(
			Some(head(2, 0xa2)),
			Body::EntryPrepared {
				allocation: head(2, 0xa2),
				epochs: stages,
				nonce: NONCE,
				stage_directory: LinuxFileIdentity::new(7, 12),
				stage: LinuxFileIdentity::new(7, 13),
			},
			include_str!("remote_download/prepared.hex"),
		),
		(
			Some(prepared),
			Body::RangeCheckpoint {
				prepared,
				epochs: stages,
				ordinal: 1,
				offset: 0,
				length: EXTENT,
				digest: StreamDigest::from_bytes([0x62; 32]),
			},
			include_str!("remote_download/checkpoint.hex"),
		),
		(
			Some(head(4, 0xa4)),
			Body::FailureRecorded {
				attempt: prepared,
				epochs: stages,
				boundary: RemoteUncertainBoundary::CheckpointAppend,
			},
			include_str!("remote_download/failure.hex"),
		),
	]
	.map(|(preceding, body, bytes)| {
		(
			RemoteDownloadRecord::new(context(), preceding, body).unwrap(),
			bytes,
		)
	})
}

fn frame(anchor: ChainHead, kind: FrameKind, bytes: &[u8]) -> Frame {
	let mut writer = FrameWriter::new(Vec::new(), anchor);
	writer.append(kind, bytes).unwrap();
	let bytes = writer.into_inner();
	FrameReader::new(bytes.as_slice(), anchor)
		.next_frame()
		.unwrap()
		.unwrap()
}

#[test]
fn independent_owner_and_frame_vectors_round_trip_in_the_remote_profile() {
	let signed =
		RemoteDownloadOwnerRecord::sign(manifest(source(wireguard("10.15.17.19:22"))), &signer())
			.unwrap();
	let golden = hex(OWNER);
	assert_eq!(signed.as_bytes(), golden);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(&golden, profile(), &signer().verifying_key()),
		Ok(signed.clone())
	);
	assert_eq!(signed.digest().as_bytes(), blake3::hash(&golden).as_bytes());
	let mut projection = b"ExaCopy/linux-remote-scope/v1\0".to_vec();
	projection.extend_from_slice(&hex(SCOPE));
	assert_eq!(
		signed.manifest().scope.digest().unwrap().as_bytes(),
		blake3::hash(&projection).as_bytes()
	);
	assert_eq!(signed.manifest().scope.source.path(), b"inbox/raw-\xff");
	assert_eq!(signed.manifest().scope.destination.target(), b"target-\xff");
	for (expected, hex_bytes) in vectors() {
		let bytes = hex(hex_bytes);
		assert_eq!(
			expected.encode().unwrap(),
			bytes,
			"{:?}",
			expected.body().kind()
		);
		assert_eq!(RemoteDownloadRecord::decode(&bytes), Ok(expected));
		let anchor = expected.predecessor().unwrap_or_else(ChainHead::start);
		let frame = frame(anchor, expected.body().kind(), &bytes);
		assert_eq!(RemoteDownloadRecord::from_frame(&frame), Ok(expected));
	}
}

#[test]
fn owner_requires_external_key_profile_and_distinct_signature_domain() {
	let bytes = hex(OWNER);
	let key = signer().verifying_key();
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(
			&bytes,
			profile(),
			&SigningKey::from_bytes(&[0x66; 32]).verifying_key()
		),
		Err(Error::Owner(OwnerError::UntrustedKey)),
	);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(
			&bytes,
			OwnerProfileId::from_bytes([0x77; 16]).unwrap(),
			&key
		),
		Err(Error::Owner(OwnerError::UntrustedProfile)),
	);
	let body = envelope_body(&bytes);
	let wrong_signature = signed_envelope(body, b"ExaCopy/owner/v1\0", 4);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(&wrong_signature, profile(), &key),
		Err(Error::Owner(OwnerError::InvalidSignature))
	);
	let wrong_domain = signed_envelope(body, DOMAIN, 1);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(&wrong_domain, profile(), &key),
		Err(Error::Owner(OwnerError::WrongDomain))
	);
	let mut changed = body.to_vec();
	let index = changed
		.windows(b"Reader".len())
		.position(|window| window == b"Reader")
		.unwrap();
	changed[index] = b'r';
	let original_signature = signer().sign(&[DOMAIN, body].concat()).to_bytes();
	let tampered = envelope(&changed, &key.to_bytes(), &original_signature, 4);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(&tampered, profile(), &key),
		Err(Error::Owner(OwnerError::InvalidSignature))
	);
}

#[test]
fn zero_and_identity_keys_cannot_authenticate_an_owner() {
	let bytes = hex(OWNER);
	let body = envelope_body(&bytes);
	let mut identity = [0; 32];
	identity[0] = 1;
	for public in [[0; 32], identity] {
		let key = VerifyingKey::from_bytes(&public).expect("synthetic weak point encoding");
		assert!(key.is_weak());
		let record = envelope(body, &public, &[0; 64], 4);
		assert_eq!(
			RemoteDownloadOwnerRecord::decode(&record, profile(), &key),
			Err(Error::Owner(OwnerError::InvalidSignature))
		);
	}
}

#[test]
fn remote_and_legacy_profiles_refuse_one_another() {
	let bytes = hex(OWNER);
	let key = signer().verifying_key();
	assert_eq!(
		OwnerRecord::decode(&bytes, profile(), &key),
		Err(OwnerError::WrongDomain)
	);
	assert_eq!(
		DarwinOwnerRecord::decode(&bytes, profile(), &key),
		Err(OwnerError::WrongDomain)
	);
	assert_eq!(
		PublicApplyOwnerRecord::decode(&bytes, profile(), &key),
		Err(OwnerError::WrongDomain)
	);

	let legacy = OwnerRecord::sign(
		OwnerManifest {
			token: token(),
			job: context().job,
			profile: profile(),
			created: OwnerTimestamp::new(0, 0).unwrap(),
			destination_device: 7,
			state_root: LinuxFileIdentity::new(7, 11),
			plan_digest: PlanDigest::from_bytes([0x14; 32]),
			directories: vec![OwnerStateDirectory::Journal, OwnerStateDirectory::Stage],
		},
		&signer(),
	)
	.unwrap();
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(legacy.as_bytes(), profile(), &key),
		Err(Error::Owner(OwnerError::WrongDomain))
	);
	let legacy_job = JobPrepared {
		context: JournalContext {
			job: context().job,
			epoch: JournalEpoch::new(1),
			plan_digest: legacy.manifest().plan_digest,
		},
		owner_digest: legacy.digest(),
		destination_root: DestinationRootBinding {
			id: root(),
			identity: LinuxFileIdentity::new(7, 9),
		},
	};
	assert!(RemoteDownloadRecord::decode(&legacy_job.encode()).is_err());
	let remote_job = hex(include_str!("remote_download/job.hex"));
	assert!(JobPrepared::decode(&remote_job).is_err());
	assert!(DarwinJobPrepared::decode(&remote_job).is_err());
}

#[test]
fn exact_owner_and_frame_parser_bounds_and_canonical_forms() {
	let bytes = hex(OWNER);
	let key = signer().verifying_key();
	for end in 0..bytes.len() {
		assert!(
			RemoteDownloadOwnerRecord::decode(&bytes[..end], profile(), &key).is_err(),
			"truncation at {end}"
		);
	}
	let body = envelope_body(&bytes);
	let mut changed = body.to_vec();
	changed[5] = 0;
	let unsupported = signed_envelope(&changed, DOMAIN, 4);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(&unsupported, profile(), &key),
		Err(Error::UnsupportedVersion)
	);
	let mut changed = body.to_vec();
	changed.splice(3..4, [0x18, 1]);
	let noncanonical = signed_envelope(&changed, DOMAIN, 4);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(&noncanonical, profile(), &key),
		Err(Error::NonCanonical)
	);
	assert_eq!(
		RemoteDownloadOwnerRecord::decode(
			&[0; MAX_REMOTE_DOWNLOAD_OWNER_BYTES + 1],
			profile(),
			&key
		),
		Err(Error::Length),
	);

	for (_, text) in vectors() {
		let mut bytes = hex(text);
		for end in 0..bytes.len() {
			assert!(
				RemoteDownloadRecord::decode(&bytes[..end]).is_err(),
				"truncation at {end}"
			);
		}
		bytes.push(0);
		assert_eq!(
			RemoteDownloadRecord::decode(&bytes),
			Err(Error::NonCanonical)
		);
		bytes.pop();
		bytes.splice(3..4, [0x18, 1]);
		assert_eq!(
			RemoteDownloadRecord::decode(&bytes),
			Err(Error::NonCanonical)
		);
	}
	let mut payload = hex(include_str!("remote_download/job.hex"));
	payload[5] = 2;
	assert_eq!(
		RemoteDownloadRecord::decode(&payload),
		Err(Error::UnsupportedVersion)
	);
	assert_eq!(
		RemoteDownloadRecord::decode(&[0; MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES + 1]),
		Err(Error::Length)
	);
}

#[test]
fn exact_predecessor_sequence_digest_and_kind_are_required() {
	let bytes = hex(include_str!("remote_download/prepared.hex"));
	let correct = head(2, 0xa2);
	for (anchor, kind) in [
		(head(2, 0xfe), FrameKind::EntryPrepared),
		(head(7, 0xa2), FrameKind::EntryPrepared),
		(correct, FrameKind::RangeCheckpoint),
	] {
		assert_eq!(
			RemoteDownloadRecord::from_frame(&frame(anchor, kind, &bytes)),
			Err(Error::FrameBinding)
		);
	}
	let job = hex(include_str!("remote_download/job.hex"));
	assert_eq!(
		RemoteDownloadRecord::from_frame(&frame(head(1, 0xa1), FrameKind::JobPrepared, &job)),
		Err(Error::FrameBinding)
	);
}

fn envelope_body(bytes: &[u8]) -> &[u8] {
	let mut decoder = Decoder::new(bytes);
	assert_eq!(decoder.map().unwrap(), Some(4));
	assert_eq!(decoder.u8().unwrap(), 0);
	decoder.bytes().unwrap()
}

fn signed_envelope(body: &[u8], prefix: &[u8], domain: u8) -> Vec<u8> {
	let key = signer();
	let signature = key.sign(&[prefix, body].concat()).to_bytes();
	envelope(body, &key.verifying_key().to_bytes(), &signature, domain)
}

fn envelope(body: &[u8], key: &[u8; 32], signature: &[u8; 64], domain: u8) -> Vec<u8> {
	let mut out = Encoder::new(Cursor::new([0; MAX_REMOTE_DOWNLOAD_OWNER_BYTES]));
	out.map(4)
		.unwrap()
		.u8(0)
		.unwrap()
		.bytes(body)
		.unwrap()
		.u8(1)
		.unwrap()
		.bytes(key)
		.unwrap()
		.u8(2)
		.unwrap()
		.bytes(signature)
		.unwrap()
		.u8(3)
		.unwrap()
		.u8(domain)
		.unwrap();
	let out = out.into_writer();
	out.get_ref()[..out.position()].to_vec()
}
