//! V2 strategy attestation, version separation, and live-vs-historical admission.

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_remote_qualification::{
	MAX_REMOTE_KERNEL_FIELD_BYTES, MAX_REMOTE_MOUNT_RECORD_BYTES, RemoteDestinationFacts,
	RemoteDestinationIds, RemoteKernelArchitecture,
};
use exacopy_journal::remote_download::qualification::continuation::{
	RemoteContinuationCoverageProfile, RemoteContinuationOperationProfile,
	RemoteContinuationQualificationError as Error, RemoteContinuationQualificationScope,
	RemoteContinuationQualificationTrust, verify_remote_continuation_qualification as verify_v2,
};
use exacopy_journal::remote_download::qualification::{
	MAX_REMOTE_QUALIFICATION_BYTES, RemoteQualificationError as Evidence,
	RemoteQualificationRouteClass as Route, RemoteQualificationScope, RemoteQualificationTrust,
	verify_remote_destination_qualification as verify_v1,
};

const ATTESTOR: [u8; 16] = [0x31; 16];
const BUILD: [u8; 32] = [0x61; 32];
const V2_DOMAIN: &[u8] = b"ExaCopy/linux-remote-destination-qualification-record/v2\0";
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

struct FixtureKeys {
	attestor: VerifyingKey,
	owner: VerifyingKey,
}

impl FixtureKeys {
	fn new() -> Self {
		Self {
			attestor: SigningKey::from_bytes(&[0x62; 32]).verifying_key(),
			owner: SigningKey::from_bytes(&[0x52; 32]).verifying_key(),
		}
	}

	fn select(&self, route: Route) -> RemoteContinuationQualificationTrust<'_> {
		RemoteContinuationQualificationTrust {
			attestor: ATTESTOR,
			attestor_key: &self.attestor,
			owner_key: &self.owner,
			scope: RemoteContinuationQualificationScope {
				common: RemoteQualificationScope {
					build: BUILD,
					route,
					campaign_scope: [0x63; 32],
					campaign_evidence: [0x64; 32],
				},
				operation: RemoteContinuationOperationProfile::VerifiedRetainedAppendV1,
				coverage: RemoteContinuationCoverageProfile::RetainedAppendProcessCrashV1,
			},
		}
	}
}

fn facts(ids: RemoteDestinationIds) -> RemoteDestinationFacts {
	RemoteDestinationFacts::new(
		ids,
		RemoteKernelArchitecture::X86_64,
		b"6.8.0-fixture",
		b"#1 fixture SMP",
		b"36 25 8:1 / /fixture rw,nosuid - ext4 /dev/fixture rw",
	)
	.unwrap()
}

fn vector(label: &str) -> Vec<u8> {
	let encoded = include_str!("remote_download/continuation_qualification.hex")
		.lines()
		.find_map(|line| {
			let (name, data) = line.split_once(' ')?;
			(name == label).then_some(data)
		})
		.expect("named independent vector");
	let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

#[test]
fn independent_v2_vectors_require_selected_route_and_do_not_cross_v1() {
	let keys = FixtureKeys::new();
	let observed = facts(IDS);
	for (label, route) in [
		("direct", Route::DirectPinnedTcpV1),
		("embedded", Route::EmbeddedWireGuardTcpV1),
	] {
		let bytes = vector(label);
		let selected = keys.select(route);
		let verified = verify_v2(&bytes, &selected).unwrap();
		assert_eq!(verified.scope(), selected.scope);
		assert_eq!(verified.facts(), &observed);
		assert!(verified.matches_owner(&keys.owner));
		assert!(!verified.matches_owner(&keys.attestor));
		assert_eq!(verified.attestor_key(), &keys.attestor);
		let current = verified.match_current(BUILD, &observed).unwrap();
		assert_eq!(current.facts(), &observed);
		assert_eq!(current.verified().digest(), verified.digest());
		let digest = blake3::hash(&[V2_DOMAIN, bytes.as_slice()].concat());
		assert_eq!(verified.digest().as_bytes(), digest.as_bytes());
		assert_ne!(
			verified.digest().as_bytes(),
			blake3::hash(&bytes).as_bytes()
		);

		let v1_trust = RemoteQualificationTrust {
			attestor: selected.attestor,
			attestor_key: selected.attestor_key,
			owner_key: selected.owner_key,
			scope: selected.scope.common,
		};
		assert_eq!(
			verify_v1(&bytes, &v1_trust, &observed),
			Err(Evidence::Version)
		);
		if route == Route::DirectPinnedTcpV1 {
			let old = vector("legacy-v1");
			let legacy = verify_v1(&old, &v1_trust, &observed).unwrap();
			assert_ne!(&legacy.digest(), verified.digest().as_bytes());
			assert_eq!(
				verify_v2(&old, &selected).unwrap_err(),
				Error::Evidence(Evidence::Version)
			);
		}
	}
	assert_eq!(
		verify_v2(&vector("embedded"), &keys.select(Route::DirectPinnedTcpV1)).unwrap_err(),
		Error::Evidence(Evidence::Scope),
	);
}

#[test]
fn rejects_untrusted_or_noncanonical_wire_and_every_missing_case() {
	let keys = FixtureKeys::new();
	let selected = keys.select(Route::DirectPinnedTcpV1);
	for (label, expected) in [
		("unknown-version", Evidence::Version),
		("wrong-role", Evidence::Role),
		("v1-signature-domain", Evidence::Signature),
		("owner-key", Evidence::Attestor),
		("attestor-id", Evidence::Attestor),
		("build", Evidence::Scope),
		("unknown-route", Evidence::Scope),
		("campaign-scope", Evidence::Scope),
		("campaign-evidence", Evidence::Scope),
		("oversized-mountinfo", Evidence::DestinationFacts),
		("noncanonical-body", Evidence::NonCanonical),
		("noncanonical-envelope", Evidence::NonCanonical),
		("unknown-field", Evidence::Shape),
		("suffix", Evidence::NonCanonical),
		("changed-signature", Evidence::Signature),
	] {
		assert_eq!(
			verify_v2(&vector(label), &selected).unwrap_err(),
			Error::Evidence(expected),
			"{label}"
		);
	}
	assert_eq!(
		verify_v2(&vector("unknown-operation"), &selected).unwrap_err(),
		Error::Operation
	);
	for label in ["unknown-coverage", "extra-coverage"] {
		assert_eq!(
			verify_v2(&vector(label), &selected).unwrap_err(),
			Error::Coverage
		);
	}
	for bit in 0..12 {
		let bytes = vector(&format!("missing-coverage-{bit}"));
		assert_eq!(verify_v2(&bytes, &selected).unwrap_err(), Error::Coverage);
	}
}

#[test]
fn bounds_and_expected_trust_refuse_before_decoding_claims() {
	let keys = FixtureKeys::new();
	let mut selected = keys.select(Route::DirectPinnedTcpV1);
	selected.owner_key = &keys.attestor;
	let too_long = [0; MAX_REMOTE_QUALIFICATION_BYTES + 1];
	assert_eq!(
		verify_v2(&too_long, &selected).unwrap_err(),
		Error::Evidence(Evidence::Length)
	);
	assert_eq!(
		verify_v2(b"invalid", &selected).unwrap_err(),
		Error::Evidence(Evidence::Trust)
	);

	let mut selected = keys.select(Route::DirectPinnedTcpV1);
	selected.scope.common.campaign_evidence = [0; 32];
	assert_eq!(
		verify_v2(b"invalid", &selected).unwrap_err(),
		Error::Evidence(Evidence::Scope)
	);
	let mut weak = [0; 32];
	weak[0] = 1;
	let weak = VerifyingKey::from_bytes(&weak).unwrap();
	let mut selected = keys.select(Route::DirectPinnedTcpV1);
	selected.attestor_key = &weak;
	assert_eq!(
		verify_v2(b"invalid", &selected).unwrap_err(),
		Error::Evidence(Evidence::Trust)
	);

	let record = vector("direct");
	let trusted = keys.select(Route::DirectPinnedTcpV1);
	for len in 0..record.len() {
		assert!(
			verify_v2(&record[..len], &trusted).is_err(),
			"truncated at {len}"
		);
	}

	let caps = verify_v2(
		&vector("at-field-caps"),
		&keys.select(Route::EmbeddedWireGuardTcpV1),
	)
	.unwrap();
	assert_eq!(
		caps.facts().kernel_release().len(),
		MAX_REMOTE_KERNEL_FIELD_BYTES
	);
	assert_eq!(
		caps.facts().kernel_build().len(),
		MAX_REMOTE_KERNEL_FIELD_BYTES
	);
	assert_eq!(
		caps.facts().mount_record().len(),
		MAX_REMOTE_MOUNT_RECORD_BYTES
	);
}

#[test]
fn verified_history_cannot_substitute_for_current_build_or_native_facts() {
	let keys = FixtureKeys::new();
	let selected = keys.select(Route::DirectPinnedTcpV1);
	let observed = facts(IDS);
	let verified = verify_v2(&vector("direct"), &selected).unwrap();
	assert_eq!(
		verified.match_current([0x77; 32], &observed).unwrap_err(),
		Error::RunningBuild
	);
	for changed in [
		RemoteDestinationIds {
			root: JobFileIdentity {
				device: 0x802,
				inode: 11,
			},
			..IDS
		},
		RemoteDestinationIds {
			root: JobFileIdentity {
				device: 0x801,
				inode: 12,
			},
			..IDS
		},
		RemoteDestinationIds {
			effective_uid: 1003,
			..IDS
		},
		RemoteDestinationIds {
			effective_gid: 1003,
			..IDS
		},
		RemoteDestinationIds {
			boot_id: [0x16; 16],
			..IDS
		},
		RemoteDestinationIds {
			mount_namespace: 42,
			..IDS
		},
		RemoteDestinationIds {
			mount_id: 43,
			..IDS
		},
		RemoteDestinationIds {
			unique_mount: 44,
			..IDS
		},
	] {
		assert_eq!(
			verified.match_current(BUILD, &facts(changed)).unwrap_err(),
			Error::LiveDestination
		);
	}
	let other = verify_v2(&vector("changed-signed-root"), &selected).unwrap();
	assert_ne!(other.digest(), verified.digest());
	assert_eq!(
		other.match_current(BUILD, &observed).unwrap_err(),
		Error::LiveDestination
	);

	let mount_changed = RemoteDestinationFacts::new(
		IDS,
		RemoteKernelArchitecture::X86_64,
		observed.kernel_release(),
		observed.kernel_build(),
		b"36 25 8:1 / /fixture rw,nodev - ext4 /dev/fixture rw",
	)
	.unwrap();
	assert_eq!(
		verified.match_current(BUILD, &mount_changed).unwrap_err(),
		Error::LiveDestination
	);
}

#[test]
fn noncanonical_strong_key_encodings_refuse_both_trust_roles_before_decode() {
	// The Edwards y-coordinate 3 and y = p + 3 decompress to the same
	// non-small-order point but have different input encodings.
	let mut canonical = [0; 32];
	canonical[0] = 3;
	let mut alternate = [0xff; 32];
	alternate[0] = 0xf0;
	alternate[31] = 0x7f;
	let canonical = VerifyingKey::from_bytes(&canonical).unwrap();
	let alternate = VerifyingKey::from_bytes(&alternate).unwrap();
	assert!(!canonical.is_weak() && !alternate.is_weak());
	assert_ne!(canonical, alternate);
	assert_eq!(canonical.to_edwards(), alternate.to_edwards());
	assert_eq!(
		alternate.to_edwards().compress().to_bytes(),
		canonical.to_bytes()
	);

	let keys = FixtureKeys::new();
	for (attestor, owner) in [(&alternate, &keys.owner), (&keys.attestor, &alternate)] {
		let mut selected = keys.select(Route::DirectPinnedTcpV1);
		selected.attestor_key = attestor;
		selected.owner_key = owner;
		assert_eq!(
			verify_v2(b"invalid", &selected).unwrap_err(),
			Error::Evidence(Evidence::Trust),
		);
	}
}
