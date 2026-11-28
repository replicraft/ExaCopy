//! Trust, exact fact matching and deterministic qualification shape.

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_remote_qualification::{
	MAX_REMOTE_KERNEL_FIELD_BYTES, MAX_REMOTE_MOUNT_RECORD_BYTES, RemoteDestinationFacts,
	RemoteDestinationIds, RemoteKernelArchitecture,
};
use exacopy_journal::remote_download::qualification::{
	MAX_REMOTE_QUALIFICATION_BYTES, RemoteQualificationError as Error,
	RemoteQualificationRouteClass as Route, RemoteQualificationScope, RemoteQualificationTrust,
	verify_remote_destination_qualification,
};

const ATTESTOR: [u8; 16] = [0x31; 16];
const RELEASE: &[u8] = b"6.8.0-fixture";
const BUILD: &[u8] = b"#1 fixture SMP";
const MOUNT: &[u8] = b"36 25 8:1 / /fixture rw,nosuid - ext4 /dev/fixture rw";
const IDS: RemoteDestinationIds = RemoteDestinationIds {
	root: JobFileIdentity {
		device: 0x801,
		inode: 11,
	},
	effective_uid: 1001,
	effective_gid: 1002,
	boot_id: [0x15; 16],
	mount_namespace: 4_026_533_000,
	mount_id: 36,
	unique_mount: 59_426,
};

struct Keys {
	attestor: VerifyingKey,
	owner: VerifyingKey,
}

impl Keys {
	fn fixture() -> Self {
		Self {
			attestor: SigningKey::from_bytes(&[0x62; 32]).verifying_key(),
			owner: SigningKey::from_bytes(&[0x52; 32]).verifying_key(),
		}
	}

	fn select(&self, route: Route) -> RemoteQualificationTrust<'_> {
		RemoteQualificationTrust {
			attestor: ATTESTOR,
			attestor_key: &self.attestor,
			owner_key: &self.owner,
			scope: RemoteQualificationScope {
				build: [0x61; 32],
				route,
				campaign_scope: [0x63; 32],
				campaign_evidence: [0x64; 32],
			},
		}
	}
}

fn facts() -> RemoteDestinationFacts {
	RemoteDestinationFacts::new(IDS, RemoteKernelArchitecture::X86_64, RELEASE, BUILD, MOUNT)
		.unwrap()
}

fn vector(label: &str) -> Vec<u8> {
	let value = include_str!("remote_download/qualification.hex")
		.lines()
		.find_map(|line| {
			let (candidate, value) = line.split_once(' ')?;
			(candidate == label).then_some(value)
		})
		.expect("named independent synthetic vector");
	let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty(), "vector must contain complete octets");
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

#[test]
fn independent_signed_records_project_matching_current_destination_facts() {
	let keys = Keys::fixture();
	let observed = facts();
	for (label, route) in [
		("direct", Route::DirectPinnedTcpV1),
		("embedded", Route::EmbeddedWireGuardTcpV1),
	] {
		let signed = vector(label);
		let verified =
			verify_remote_destination_qualification(&signed, &keys.select(route), &observed)
				.unwrap();
		assert_eq!(verified.facts(), &observed);
		let oracle = blake3::hash(
			&[
				b"ExaCopy/linux-remote-destination-qualification-record/v1\0".as_slice(),
				signed.as_slice(),
			]
			.concat(),
		);
		assert_eq!(verified.digest(), *oracle.as_bytes());
		assert_ne!(verified.digest(), *blake3::hash(&signed).as_bytes());
	}
}

#[test]
fn selected_attestor_is_independent_of_the_ordinary_owner() {
	let keys = Keys::fixture();
	let observed = facts();
	let selected = keys.select(Route::DirectPinnedTcpV1);
	for (label, expected) in [
		("version", Error::Version),
		("role", Error::Role),
		("owner-domain", Error::Signature),
		("owner-key", Error::Attestor),
		("attestor-id", Error::Attestor),
		("signature", Error::Signature),
	] {
		assert_eq!(
			verify_remote_destination_qualification(&vector(label), &selected, &observed),
			Err(expected),
			"{label}"
		);
	}
	let mut trust = keys.select(Route::DirectPinnedTcpV1);
	trust.attestor_key = &keys.owner;
	assert_eq!(
		verify_remote_destination_qualification(&vector("owner-key"), &trust, &observed),
		Err(Error::Trust)
	);

	let mut trust = keys.select(Route::DirectPinnedTcpV1);
	trust.attestor = [0; 16];
	assert_eq!(
		verify_remote_destination_qualification(&vector("direct"), &trust, &observed),
		Err(Error::Trust)
	);

	let mut small_order = [0; 32];
	small_order[0] = 1;
	let weak = VerifyingKey::from_bytes(&small_order).unwrap();
	assert!(weak.is_weak());
	for (attestor_key, owner_key) in [(&weak, &keys.owner), (&keys.attestor, &weak)] {
		let trust = RemoteQualificationTrust {
			attestor_key,
			owner_key,
			..keys.select(Route::DirectPinnedTcpV1)
		};
		assert_eq!(
			verify_remote_destination_qualification(&vector("direct"), &trust, &observed),
			Err(Error::Trust)
		);
	}
}

#[test]
fn campaign_evidence_build_and_profile_class_cannot_be_substituted() {
	let keys = Keys::fixture();
	let observed = facts();
	let direct = keys.select(Route::DirectPinnedTcpV1);
	for label in [
		"build",
		"embedded",
		"unknown-route-class",
		"campaign-scope",
		"campaign-evidence",
	] {
		assert_eq!(
			verify_remote_destination_qualification(&vector(label), &direct, &observed),
			Err(Error::Scope),
			"{label}"
		);
	}
	let embedded = keys.select(Route::EmbeddedWireGuardTcpV1);
	assert_eq!(
		verify_remote_destination_qualification(&vector("direct"), &embedded, &observed),
		Err(Error::Scope)
	);
	for scope in [
		RemoteQualificationScope {
			build: [0; 32],
			..direct.scope
		},
		RemoteQualificationScope {
			campaign_scope: [0; 32],
			..direct.scope
		},
		RemoteQualificationScope {
			campaign_evidence: [0; 32],
			..direct.scope
		},
	] {
		let trust = RemoteQualificationTrust {
			scope,
			..keys.select(Route::DirectPinnedTcpV1)
		};
		assert_eq!(
			verify_remote_destination_qualification(&vector("direct"), &trust, &observed),
			Err(Error::Scope)
		);
	}
}

#[test]
fn independently_signed_native_fact_substitutions_do_not_project() {
	let keys = Keys::fixture();
	let selected = keys.select(Route::DirectPinnedTcpV1);
	let observed = facts();
	for label in [
		"device",
		"inode",
		"uid",
		"gid",
		"boot",
		"namespace",
		"mount-id",
		"unique-mount",
		"arch",
		"kernel-release",
		"kernel-build",
		"mountinfo",
		"overlong-kernel",
		"overlong-mountinfo",
		"mountinfo-newline",
		"nil-boot",
		"unknown-arch",
	] {
		assert_eq!(
			verify_remote_destination_qualification(&vector(label), &selected, &observed),
			Err(Error::DestinationFacts),
			"{label}"
		);
	}
	let replacement = RemoteDestinationFacts::new(
		RemoteDestinationIds {
			unique_mount: 59_427,
			..IDS
		},
		RemoteKernelArchitecture::X86_64,
		RELEASE,
		BUILD,
		MOUNT,
	)
	.unwrap();
	assert_eq!(
		verify_remote_destination_qualification(&vector("direct"), &selected, &replacement),
		Err(Error::DestinationFacts)
	);
}

#[test]
fn noncanonical_qualification_claims_refuse_even_with_an_invalid_signature() {
	let keys = Keys::fixture();
	let selected = keys.select(Route::DirectPinnedTcpV1);
	let observed = facts();
	let mut record = vector("noncanonical-claims");
	*record.last_mut().unwrap() ^= 1; // The final envelope field is the signature.
	assert_eq!(
		verify_remote_destination_qualification(&record, &selected, &observed),
		Err(Error::NonCanonical)
	);
}

#[test]
fn canonical_bounded_record_refuses_every_prefix_and_unexpected_field() {
	let keys = Keys::fixture();
	let selected = keys.select(Route::DirectPinnedTcpV1);
	let observed = facts();
	let valid = vector("direct");
	for cut in 0..valid.len() {
		assert!(
			verify_remote_destination_qualification(&valid[..cut], &selected, &observed).is_err(),
			"accepted truncated record at {cut}"
		);
	}
	for (label, expected) in [
		("noncanonical-claims", Error::NonCanonical),
		("noncanonical-envelope", Error::NonCanonical),
		("suffix", Error::NonCanonical),
		("extra-field", Error::Shape),
	] {
		assert_eq!(
			verify_remote_destination_qualification(&vector(label), &selected, &observed),
			Err(expected),
			"{label}"
		);
	}
	assert_eq!(
		verify_remote_destination_qualification(
			&[0; MAX_REMOTE_QUALIFICATION_BYTES + 1],
			&selected,
			&observed,
		),
		Err(Error::Length)
	);
}

#[test]
fn largest_supported_field_lengths_fit_the_bounded_record() {
	let keys = Keys::fixture();
	let observed = RemoteDestinationFacts::new(
		IDS,
		RemoteKernelArchitecture::Aarch64,
		&[b'r'; MAX_REMOTE_KERNEL_FIELD_BYTES],
		&[b'b'; MAX_REMOTE_KERNEL_FIELD_BYTES],
		&[b'm'; MAX_REMOTE_MOUNT_RECORD_BYTES],
	)
	.unwrap();
	let signed = vector("at-field-caps");
	assert!(signed.len() <= MAX_REMOTE_QUALIFICATION_BYTES);
	let verified = verify_remote_destination_qualification(
		&signed,
		&keys.select(Route::EmbeddedWireGuardTcpV1),
		&observed,
	)
	.unwrap();
	assert_eq!(verified.facts(), &observed);
}
