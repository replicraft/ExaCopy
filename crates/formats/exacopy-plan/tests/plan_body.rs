//! Independent digest vectors, complete projection, and bounded plan admission.

use exacopy_plan::{
	DocumentPageKind, DocumentRef, PlanBody, PlanBodyFields, PlanConflict, PlanConsistency,
	PlanDurability, PlanEntriesPage, PlanError, PlanExtensions, PlanFidelity, PlanIdentityPlatform,
	PlanOperation, PlanPolicy, PlanPreservation, PlanPublication, PlanResourceLimits,
	PlanSourceIdentity, PlanSourceRetirement, PlanSourceView, PlanStorage, PlanVerification,
	PlanViewConsistency, UnixTimestamp,
};
use uuid::Uuid;

const COMPLETE: &[u8] =
	include_bytes!("../verification/plan_body/vectors/complete-protected.body.cbor");
const COMPLETE_DIGEST: [u8; 32] =
	*include_bytes!("../verification/plan_body/vectors/complete-protected.digest");
const COMPLEX_EXTENSIONS: &[u8] =
	include_bytes!("../verification/plan_body/vectors/complete-protected.extensions.cbor");
const INCOMPLETE: &[u8] =
	include_bytes!("../verification/plan_body/vectors/incomplete-empty.body.cbor");
const INCOMPLETE_DIGEST: [u8; 32] =
	*include_bytes!("../verification/plan_body/vectors/incomplete-empty.digest");

fn evaluate(input: &[u8]) -> Result<PlanBody<'_>, PlanError> {
	let mut bytes = b"ExaCopy/plan/v1\0".to_vec();
	bytes.extend_from_slice(input);
	PlanBody::from_canonical_cbor(*blake3::hash(&bytes).as_bytes(), input)
}

fn full_fields() -> PlanBodyFields<'static> {
	PlanBody::from_canonical_cbor(COMPLETE_DIGEST, COMPLETE)
		.unwrap()
		.fields()
		.clone()
}

fn fixture_uuid(s: &str) -> Uuid {
	Uuid::parse_str(s).unwrap()
}

fn time(seconds: i64, nanos: u32) -> UnixTimestamp {
	UnixTimestamp::new(seconds, nanos).unwrap()
}

#[test]
fn canonical_policy_and_resource_intent_are_bound_to_the_expected_digest() {
	let decoded = PlanBody::from_canonical_cbor(COMPLETE_DIGEST, COMPLETE).unwrap();
	assert_eq!(decoded.canonical_cbor(), COMPLETE);
	assert_eq!(decoded.digest(), COMPLETE_DIGEST);

	let mut changed_policy = decoded.fields().clone();
	changed_policy.policy.fidelity = PlanFidelity::NativeStrict;
	let mut changed_budget = decoded.fields().clone();
	changed_budget.resource_limits = PlanResourceLimits::new(u64::MAX - 1, 64).unwrap();
	let mut changed_reference = decoded.fields().clone();
	changed_reference.entry_pages.swap(0, 1);
	for changed in [changed_policy, changed_budget, changed_reference] {
		let changed = PlanBody::new(changed).unwrap();
		assert_ne!(changed.digest(), COMPLETE_DIGEST);
		assert_eq!(
			PlanBody::from_canonical_cbor(COMPLETE_DIGEST, changed.canonical_cbor()),
			Err(PlanError::Integrity)
		);
	}
}

#[test]
fn independently_constructed_complete_fields_match_the_portable_vector() {
	let source = fixture_uuid("ffeeddcc-bbaa-4988-8776-554433221100");
	let measurement = fixture_uuid("00112233-4455-4677-8899-aabbccddeeff");
	let first = include_bytes!("../verification/plan_entries/vectors/empty-file.ref.cbor");
	let second = include_bytes!("../verification/plan_body/vectors/coherent-second.ref.cbor");

	let fields = PlanBodyFields {
		plan_id: fixture_uuid("019a0000-0000-7000-8000-000000000002"),
		operation: PlanOperation::Move,
		created_at: time(i64::MIN, 999_999_999),
		expires_at: Some(time(i64::MAX, 0)),
		source_roots: vec![source],
		destination_root: fixture_uuid("18291f52-8015-48ff-af49-546767ec49cd"),
		entry_pages: [first, second]
			.iter()
			.map(|raw| DocumentRef::from_canonical_cbor(raw.as_slice()).unwrap())
			.collect(),
		policy: PlanPolicy {
			preservation: PlanPreservation::ProtectedMove,
			conflict: PlanConflict::ProtectedReplace,
			verification: PlanVerification::Sha256Readback,
			storage: PlanStorage::SharedCow,
			publication: PlanPublication::NewTree,
			consistency: PlanConsistency::ApplicationConsistent,
			minimum_durability: PlanDurability::QualifiedPowerLoss,
			fidelity: PlanFidelity::Portable,
			source_retirement: PlanSourceRetirement::Quarantine,
		},
		resource_limits: PlanResourceLimits::new(u64::MAX, 64).unwrap(),
		approval_required: true,
		source_views: vec![
			PlanSourceView {
				view_id: fixture_uuid("e57d5e90-ad55-446e-a983-4cc60a94290a"),
				root_id: source,
				consistency: PlanViewConsistency::ApplicationConsistent,
				provider: "observation-é-e\u{301}",
				measurement_id: measurement,
				source_identity: Some(PlanSourceIdentity {
					platform: PlanIdentityPlatform::Macos,
					volume_id: b"v\0",
					object_id: b"\xffobj",
					generation: Some(b"g"),
				}),
				observed_at: time(-1, 42),
				snapshot_token_digest: Some(core::array::from_fn(|i| u8::try_from(i).unwrap())),
				stable_until: Some(time(1, 0)),
			},
			PlanSourceView {
				view_id: fixture_uuid("e57d5e90-ad55-446e-a983-4cc60a94290b"),
				root_id: source,
				consistency: PlanViewConsistency::LiveObserved,
				provider: "live-observation",
				measurement_id: measurement,
				source_identity: None,
				observed_at: time(0, 0),
				snapshot_token_digest: None,
				stable_until: None,
			},
		],
		required_grants: vec!["read-content", "create-new", "prése\u{301}rve"],
		estimated_working_bytes: 3,
		conflict_count: 0,
		entry_count: 2,
		complete: true,
		extensions: PlanExtensions::from_canonical_cbor(COMPLEX_EXTENSIONS).unwrap(),
	};
	let constructed = PlanBody::new(fields).unwrap();
	assert_eq!(constructed.canonical_cbor(), COMPLETE);
	assert_eq!(constructed.digest(), COMPLETE_DIGEST);
	assert_eq!(
		PlanBody::from_canonical_cbor(COMPLETE_DIGEST, COMPLETE),
		Ok(constructed)
	);
}

#[test]
fn incomplete_body_stays_incomplete_with_nullable_and_empty_fields() {
	let parsed = PlanBody::from_canonical_cbor(INCOMPLETE_DIGEST, INCOMPLETE).unwrap();
	let fields = parsed.fields();
	assert_eq!(fields.operation, PlanOperation::Repair);
	assert_eq!(fields.created_at, time(0, 0));
	assert!(fields.expires_at.is_none());
	assert!(fields.source_roots.is_empty());
	assert!(fields.source_views.is_empty());
	assert!(fields.required_grants.is_empty());
	assert!(fields.entry_pages.is_empty());
	assert_eq!(
		fields.extensions.as_canonical_cbor(),
		PlanExtensions::empty().as_canonical_cbor()
	);
	assert!(!fields.complete && !fields.approval_required);
	assert_eq!(fields.entry_count, 0);
	assert_eq!(
		PlanBody::new(fields.clone()).unwrap().canonical_cbor(),
		INCOMPLETE
	);
}

#[test]
fn freshly_addressed_truncation_unpreferred_cbor_and_unknown_required_fields_fail() {
	for canonical in [COMPLETE, INCOMPLETE] {
		for length in 0..canonical.len() {
			assert!(
				evaluate(&canonical[..length]).is_err(),
				"prefix length {length}"
			);
		}
		let mut overlong = vec![0xb8, 18];
		overlong.extend_from_slice(&canonical[1..]);
		assert_eq!(evaluate(&overlong), Err(PlanError::NonCanonical));

		let mut trailing = canonical.to_vec();
		trailing.push(0);
		assert_eq!(evaluate(&trailing), Err(PlanError::NonCanonical));

		let mut duplicate_key = canonical.to_vec();
		// Replace key 1 (the first key after the version) with a second key 0.
		assert_eq!(&duplicate_key[..7], [0xb2, 0, 0x82, 1, 0, 1, 0x50]);
		duplicate_key[5] = 0;
		assert_eq!(evaluate(&duplicate_key), Err(PlanError::Malformed));

		let mut wrong_key = canonical.to_vec();
		wrong_key[5] = 17;
		assert_eq!(evaluate(&wrong_key), Err(PlanError::Malformed));

		let mut future = canonical.to_vec();
		future[3] = 2;
		assert_eq!(evaluate(&future), Err(PlanError::Version));
	}
}

#[test]
fn version_dispatch_precedes_v1_map_cardinality() {
	let future = b"\xa2\x00\x82\x02\x00\x11\xf6";
	assert_eq!(evaluate(future), Err(PlanError::Version));
	assert_eq!(
		PlanBody::from_canonical_cbor(COMPLETE_DIGEST, future),
		Err(PlanError::Integrity)
	);
	for malformed in [
		&b"\xa2\x00\x82\x01\x00\x11\xf6"[..],
		&b"\xa0\x00\x82\x02\x00"[..],
		&b"\xa1\x01\x82\x02\x00"[..],
		&b"\xa1\x00\x81\x02"[..],
		&b"\xa1\x00\x82\x02"[..],
	] {
		assert_eq!(
			evaluate(malformed),
			Err(PlanError::Malformed),
			"{malformed:?}"
		);
	}
}

#[test]
fn declared_reference_counts_use_checked_arithmetic_and_require_plan_kind() {
	let fields = full_fields();
	let mut count_mismatch = fields.clone();
	count_mismatch.entry_count = 1;
	assert_eq!(PlanBody::new(count_mismatch), Err(PlanError::CountMismatch));

	let page = fields.entry_pages[0];
	let make_ref = |kind, count| {
		DocumentRef::new(page.page_id(), kind, u64::from(page.encoded_bytes()), count).unwrap()
	};

	let mut wrong_kind = fields.clone();
	wrong_kind.entry_pages[0] = make_ref(DocumentPageKind::ManifestEntries, 1);
	assert_eq!(PlanBody::new(wrong_kind), Err(PlanError::PageReference));

	let mut overflow = fields;
	overflow.entry_pages[0] = make_ref(DocumentPageKind::PlanEntries, u64::MAX);
	overflow.entry_count = 0;
	assert_eq!(PlanBody::new(overflow), Err(PlanError::Bounds));
}

#[test]
fn time_resource_and_uuidv7_constructors_enforce_exact_domains() {
	assert_eq!(UnixTimestamp::new(0, 1_000_000_000), Err(PlanError::Bounds));
	assert_eq!(time(-1, 999_999_999).seconds(), -1);
	assert_eq!(time(-1, 999_999_999).nanoseconds(), 999_999_999);
	for count in [0, 65] {
		assert_eq!(PlanResourceLimits::new(0, count), Err(PlanError::Bounds));
	}
	let resource = PlanResourceLimits::new(u64::MAX, 64).unwrap();
	assert_eq!(resource.buffer_budget_bytes(), u64::MAX);
	assert_eq!(resource.io_inflight_max(), 64);

	let fields = full_fields();
	for invalid in [
		Uuid::nil(),
		fixture_uuid("019a0000-0000-4000-8000-000000000002"),
		fixture_uuid("019a0000-0000-7000-0000-000000000002"),
	] {
		let mut changed = fields.clone();
		changed.plan_id = invalid;
		assert_eq!(PlanBody::new(changed), Err(PlanError::Identifier));
	}

	let mut rejects_follow = COMPLETE.to_vec();
	let symlink_field = [8, 1, 9, 0xf4, 9, 0xa2];
	let start = rejects_follow
		.windows(symlink_field.len())
		.position(|w| w == symlink_field)
		.unwrap();
	rejects_follow[start + 3] = 0xf5;
	assert_eq!(evaluate(&rejects_follow), Err(PlanError::Unsupported));
}

#[test]
fn collection_and_scalar_limits_preserve_the_inclusive_boundary() {
	let mut fields = full_fields();
	let max_label = "🦀".repeat(128);
	let over_label = "🦀".repeat(129);
	fields.source_views[0].provider = &max_label;
	fields.required_grants = vec![&max_label; 128];
	let accepted = PlanBody::new(fields.clone()).unwrap();
	assert!(evaluate(accepted.canonical_cbor()).is_ok());

	fields.required_grants.push("");
	assert_eq!(PlanBody::new(fields.clone()), Err(PlanError::Bounds));
	fields.required_grants.pop();
	fields.required_grants[0] = &over_label;
	assert_eq!(PlanBody::new(fields.clone()), Err(PlanError::Bounds));
	fields.required_grants[0] = &max_label;
	fields.source_views[0].provider = &over_label;
	assert_eq!(PlanBody::new(fields), Err(PlanError::Bounds));

	let mut many_pages = full_fields();
	many_pages.entry_pages = (0_u32..4096)
		.map(|id| {
			let mut digest = [0; 32];
			digest[..4].copy_from_slice(&id.to_le_bytes());
			DocumentRef::new(digest, DocumentPageKind::PlanEntries, 4096, 1).unwrap()
		})
		.collect();
	many_pages.entry_count = 4096;
	let accepted = PlanBody::new(many_pages.clone()).unwrap();
	assert!(evaluate(accepted.canonical_cbor()).is_ok());
	many_pages.entry_pages.push(many_pages.entry_pages[0]);
	many_pages.entry_count += 1;
	assert_eq!(PlanBody::new(many_pages), Err(PlanError::Bounds));
}

#[test]
fn source_view_identifiers_and_opaque_atoms_and_collection_bounds_fail_closed() {
	let original = full_fields();
	let mut fields = original.clone();
	fields.destination_root = Uuid::nil();
	assert_eq!(PlanBody::new(fields), Err(PlanError::Identifier));
	let mut fields = original.clone();
	fields.source_roots[0] = Uuid::nil();
	assert_eq!(PlanBody::new(fields), Err(PlanError::Identifier));

	let source_view = original.source_views[0];
	for invalid in [
		PlanSourceView {
			view_id: Uuid::nil(),
			..source_view
		},
		PlanSourceView {
			root_id: Uuid::nil(),
			..source_view
		},
		PlanSourceView {
			measurement_id: Uuid::nil(),
			..source_view
		},
	] {
		let mut fields = original.clone();
		fields.source_views[0] = invalid;
		assert_eq!(PlanBody::new(fields), Err(PlanError::Identifier));
	}
	for volume_id in [b"".as_slice(), &[0; 257]] {
		let mut fields = original.clone();
		fields.source_views[0]
			.source_identity
			.as_mut()
			.unwrap()
			.volume_id = volume_id;
		assert_eq!(PlanBody::new(fields), Err(PlanError::Bounds));
	}

	let mut roots_and_views = original.clone();
	roots_and_views.source_roots = (1..=128).map(Uuid::from_u128).collect();
	roots_and_views.source_views = (1..=128)
		.map(|id| PlanSourceView {
			view_id: Uuid::from_u128(id),
			..source_view
		})
		.collect();
	let admitted = PlanBody::new(roots_and_views.clone()).unwrap();
	assert_eq!(evaluate(admitted.canonical_cbor()).unwrap(), admitted);
	roots_and_views.source_roots.push(Uuid::from_u128(129));
	assert_eq!(
		PlanBody::new(roots_and_views.clone()),
		Err(PlanError::Bounds)
	);
	roots_and_views.source_roots.pop();
	roots_and_views.source_views.push(source_view);
	assert_eq!(PlanBody::new(roots_and_views), Err(PlanError::Bounds));

	let mut claimed_roots = COMPLETE.to_vec();
	let marker = [5, 0x81, 0x50];
	let offset = claimed_roots
		.windows(marker.len())
		.position(|w| w == marker)
		.unwrap();
	claimed_roots.splice(offset + 1..offset + 2, [0x98, 129]);
	assert_eq!(evaluate(&claimed_roots), Err(PlanError::Bounds));
}

fn assert_private_error(error: PlanError) {
	for rendered in [error.to_string(), format!("{error:?}")] {
		assert!(!rendered.is_empty() && rendered.len() <= 256);
		assert!(rendered.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
		assert!(!rendered.contains("secret-plan-fragment"));
	}
}

#[test]
fn admission_diagnostics_keep_source_evidence_and_grants_private() {
	let hidden = "/secret-plan-fragment/\u{1b}[31m";
	let mut fields = full_fields();
	fields.source_views[0].provider = hidden;
	fields.required_grants = vec![hidden];
	fields.source_views[0]
		.source_identity
		.as_mut()
		.unwrap()
		.object_id = hidden.as_bytes();
	let valid = PlanBody::new(fields.clone()).unwrap();
	let rendered = format!("{valid:?}");
	assert!(!rendered.contains("secret-plan-fragment"));
	assert!(!rendered.contains(&format!("{:?}", hidden.as_bytes())));
	assert!(rendered.bytes().all(|b| b.is_ascii_graphic() || b == b' '));

	let long = hidden.repeat(10);
	let mut long_grant = fields.clone();
	long_grant.required_grants = vec![&long];
	let page = fields.entry_pages[0];
	let mut wrong_kind = fields.clone();
	wrong_kind.entry_pages[0] = DocumentRef::new(
		page.page_id(),
		DocumentPageKind::ManifestEntries,
		u64::from(page.encoded_bytes()),
		1,
	)
	.unwrap();
	let mut count_mismatch = fields.clone();
	count_mismatch.entry_count -= 1;
	fields.plan_id = Uuid::nil();
	for (input, expected) in [
		(long_grant, PlanError::Bounds),
		(wrong_kind, PlanError::PageReference),
		(count_mismatch, PlanError::CountMismatch),
		(fields, PlanError::Identifier),
	] {
		let error = PlanBody::new(input).expect_err("invalid plan fields");
		assert_eq!(error, expected);
		assert_private_error(error);
	}

	let mut trailing = valid.canonical_cbor().to_vec();
	trailing.extend_from_slice(hidden.as_bytes());
	let malformed = hidden.as_bytes();
	let mut future = valid.canonical_cbor().to_vec();
	future[3] = 2;
	for (result, expected) in [
		(evaluate(&trailing), PlanError::NonCanonical),
		(evaluate(malformed), PlanError::Malformed),
		(evaluate(&future), PlanError::Version),
		(
			PlanBody::from_canonical_cbor(COMPLETE_DIGEST, valid.canonical_cbor()),
			PlanError::Integrity,
		),
	] {
		let error = result.expect_err("invalid plan bytes");
		assert_eq!(error, expected);
		assert_private_error(error);
	}
	let oversized = hidden.repeat((1024 * 1024 / hidden.len()) + 1);
	let error = evaluate(oversized.as_bytes()).expect_err("oversized private payload");
	assert_eq!(error, PlanError::Size);
	assert_private_error(error);
}

#[test]
fn complete_fixture_bundle_has_distinct_entries_and_coherent_source_views() {
	let body = PlanBody::from_canonical_cbor(COMPLETE_DIGEST, COMPLETE).unwrap();
	let fields = body.fields();
	let pages: [&[u8]; 2] = [
		include_bytes!("../verification/plan_entries/vectors/empty-file.page.cbor"),
		include_bytes!("../verification/plan_body/vectors/coherent-second.page.cbor"),
	];
	assert_eq!(fields.entry_pages.len(), pages.len());
	let entries = pages
		.into_iter()
		.zip(fields.entry_pages.iter().copied())
		.map(|(page, reference)| {
			PlanEntriesPage::from_canonical_cbor(reference, page)
				.unwrap()
				.entry()
		})
		.collect::<Vec<_>>();
	let [first, second] = entries.as_slice() else {
		panic!("the complete fixture declares exactly two real entries");
	};
	assert_ne!(first.entry_id, second.entry_id);
	assert!(first.source != second.source && first.destination != second.destination);
	assert_ne!(first.source_view_id, second.source_view_id);
	assert_eq!([first.stream_length, second.stream_length], [0, 3]);
	for entry in &entries {
		assert!(fields.source_roots.contains(&entry.source.root_id));
		assert_eq!(entry.destination.root_id, fields.destination_root);
		let view = fields
			.source_views
			.iter()
			.find(|view| view.view_id == entry.source_view_id)
			.unwrap();
		assert_eq!(view.root_id, entry.source.root_id);
	}
	assert_eq!(fields.entry_count, entries.len() as u64);
	assert_eq!(fields.conflict_count, 0);
	assert_eq!(
		fields.estimated_working_bytes,
		entries
			.iter()
			.map(|entry| entry.estimated_working_bytes)
			.sum::<u64>()
	);
}
