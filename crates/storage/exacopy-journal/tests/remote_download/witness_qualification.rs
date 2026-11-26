use super::*;
use exacopy_journal::remote_download::qualification::continuation::{
	VerifiedRemoteWitnessQualification, verify_remote_witness_qualification as verify_witness,
};

fn witnessed_vector(label: &str) -> Vec<u8> {
	let encoded = include_str!("witness_qualification.hex")
		.lines()
		.find_map(|line| {
			let (name, data) = line.split_once(' ')?;
			(name == label).then_some(data)
		})
		.expect("named independent witness vector");
	let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn witnessed(keys: &FixtureKeys, route: Route) -> RemoteContinuationQualificationTrust<'_> {
	let mut trust = keys.select(route);
	trust.scope.operation = RemoteContinuationOperationProfile::VerifiedRetainedAppendWithWitnessV1;
	trust.scope.coverage =
		RemoteContinuationCoverageProfile::RetainedAppendWithWitnessProcessCrashV1;
	trust
}

#[test]
fn independently_signed_witness_vectors_require_exact_profile_and_route() {
	let keys = FixtureKeys::new();
	let direct = witnessed_vector("direct");
	let original = vector("direct");
	let original_trust = keys.select(Route::DirectPinnedTcpV1);
	let witness_trust = witnessed(&keys, Route::DirectPinnedTcpV1);
	let historical: VerifiedRemoteWitnessQualification =
		verify_witness(&direct, &witness_trust).unwrap();
	assert_eq!(historical.scope(), witness_trust.scope);
	assert_eq!(historical.facts(), &facts(IDS));
	assert_eq!(historical.attestor_key(), &keys.attestor);
	assert!(historical.matches_owner(&keys.owner));
	assert!(!historical.matches_owner(&keys.attestor));
	assert_eq!(
		historical.digest().as_bytes(),
		blake3::Hasher::new()
			.update(V2_DOMAIN)
			.update(&direct)
			.finalize()
			.as_bytes(),
	);
	let legacy = verify_v2(&original, &original_trust).unwrap();
	assert_ne!(historical.digest(), legacy.digest());
	assert_eq!(
		verify_v2(&direct, &original_trust).unwrap_err(),
		Error::Operation
	);
	assert_eq!(
		verify_v2(&direct, &witness_trust).unwrap_err(),
		Error::Operation
	);
	assert_eq!(
		verify_witness(&original, &witness_trust).unwrap_err(),
		Error::Operation
	);
	assert_eq!(
		verify_witness(&direct, &original_trust).unwrap_err(),
		Error::Operation
	);

	let embedded = witnessed_vector("embedded");
	let embedded_trust = witnessed(&keys, Route::EmbeddedWireGuardTcpV1);
	assert_eq!(
		verify_witness(&embedded, &embedded_trust).unwrap().scope(),
		embedded_trust.scope
	);
	assert_eq!(
		verify_witness(&embedded, &witness_trust).unwrap_err(),
		Error::Evidence(Evidence::Scope),
	);
	let legacy_v1 = witnessed_vector("legacy-v1");
	assert_eq!(
		verify_witness(&legacy_v1, &witness_trust).unwrap_err(),
		Error::Evidence(Evidence::Version),
	);
	assert_eq!(
		verify_v1(
			&direct,
			&RemoteQualificationTrust {
				attestor: ATTESTOR,
				attestor_key: &keys.attestor,
				owner_key: &keys.owner,
				scope: witness_trust.scope.common,
			},
			&facts(IDS),
		)
		.unwrap_err(),
		Evidence::Version,
	);
}

#[test]
fn witnessed_selection_rejects_alternate_role_scope_shape_and_every_missing_case() {
	let keys = FixtureKeys::new();
	let trust = witnessed(&keys, Route::DirectPinnedTcpV1);
	for (label, failure) in [
		("wrong-role", Error::Evidence(Evidence::Role)),
		("wrong-domain", Error::Evidence(Evidence::Signature)),
		("owner-key", Error::Evidence(Evidence::Attestor)),
		("wrong-attestor", Error::Evidence(Evidence::Attestor)),
		("different-build", Error::Evidence(Evidence::Scope)),
		("different-campaign", Error::Evidence(Evidence::Scope)),
		("different-evidence", Error::Evidence(Evidence::Scope)),
		("mixed-operation", Error::Operation),
		("mixed-coverage", Error::Coverage),
		("unknown-operation", Error::Operation),
		("unknown-coverage", Error::Coverage),
		("extra-bit", Error::Coverage),
		("overflow", Error::Evidence(Evidence::Shape)),
		("overlong-mask", Error::Evidence(Evidence::NonCanonical)),
		("trailing-body", Error::Evidence(Evidence::NonCanonical)),
	] {
		assert_eq!(
			verify_witness(&witnessed_vector(label), &trust).unwrap_err(),
			failure,
			"{label}"
		);
	}
	for bit in 0..24 {
		let label = format!("missing-{bit}");
		assert_eq!(
			verify_witness(&witnessed_vector(&label), &trust).unwrap_err(),
			Error::Coverage,
			"{label}",
		);
	}
}

#[test]
fn witnessed_bounds_and_trust_are_checked_before_claim_decode() {
	let keys = FixtureKeys::new();
	let mut trust = witnessed(&keys, Route::DirectPinnedTcpV1);
	trust.owner_key = &keys.attestor;
	let oversized = [0; MAX_REMOTE_QUALIFICATION_BYTES + 1];
	assert_eq!(
		verify_witness(&oversized, &trust).unwrap_err(),
		Error::Evidence(Evidence::Length),
	);
	assert_eq!(
		verify_witness(b"invalid", &trust).unwrap_err(),
		Error::Evidence(Evidence::Trust)
	);

	let mut alternate = [0xff; 32];
	alternate[0] = 0xf0;
	alternate[31] = 0x7f;
	let alternate = VerifyingKey::from_bytes(&alternate).unwrap();
	assert!(!alternate.is_weak());
	assert_ne!(
		alternate.to_edwards().compress().to_bytes(),
		alternate.to_bytes()
	);
	let mut weak = [0; 32];
	weak[0] = 1;
	let weak = VerifyingKey::from_bytes(&weak).unwrap();
	assert!(weak.is_weak());
	for invalid in [&alternate, &weak] {
		for (attestor, owner) in [(invalid, &keys.owner), (&keys.attestor, invalid)] {
			let mut trust = witnessed(&keys, Route::DirectPinnedTcpV1);
			trust.attestor_key = attestor;
			trust.owner_key = owner;
			assert_eq!(
				verify_witness(b"invalid", &trust).unwrap_err(),
				Error::Evidence(Evidence::Trust),
			);
		}
	}
	let mut trust = witnessed(&keys, Route::DirectPinnedTcpV1);
	trust.scope.coverage = RemoteContinuationCoverageProfile::RetainedAppendProcessCrashV1;
	assert_eq!(
		verify_witness(b"invalid", &trust).unwrap_err(),
		Error::Coverage
	);

	let direct = witnessed_vector("direct");
	let trust = witnessed(&keys, Route::DirectPinnedTcpV1);
	for end in 0..direct.len() {
		assert!(verify_witness(&direct[..end], &trust).is_err(), "cut {end}");
	}
	let at_field_caps = witnessed_vector("at-field-caps");
	assert_eq!(at_field_caps.len(), 2_898);
	let historical = verify_witness(
		&at_field_caps,
		&witnessed(&keys, Route::EmbeddedWireGuardTcpV1),
	)
	.unwrap();
	assert_eq!(
		historical.facts().kernel_release().len(),
		MAX_REMOTE_KERNEL_FIELD_BYTES
	);
	assert_eq!(
		historical.facts().kernel_build().len(),
		MAX_REMOTE_KERNEL_FIELD_BYTES
	);
	assert_eq!(
		historical.facts().mount_record().len(),
		MAX_REMOTE_MOUNT_RECORD_BYTES
	);
	assert_eq!(historical.facts().ids().unique_mount, u64::MAX);
}

#[test]
fn witnessed_historical_claims_require_separate_current_build_and_facts() {
	let keys = FixtureKeys::new();
	let trust = witnessed(&keys, Route::DirectPinnedTcpV1);
	let historical = verify_witness(&witnessed_vector("direct"), &trust).unwrap();
	let observed = facts(IDS);
	let current = historical.match_current(BUILD, &observed).unwrap();
	assert_eq!(current.verified().digest(), historical.digest());
	assert!(std::ptr::eq(current.facts(), &observed));
	assert_eq!(
		historical.match_current([0xff; 32], &observed).unwrap_err(),
		Error::RunningBuild
	);
	let changed = facts(RemoteDestinationIds {
		mount_namespace: 1,
		..IDS
	});
	assert_eq!(
		historical.match_current(BUILD, &changed).unwrap_err(),
		Error::LiveDestination
	);
}
