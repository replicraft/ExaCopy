use exacopy_plan::{
	DocumentPageKind, DocumentRef, PlanBodyFields, PlanConflict, PlanDurability,
	PlanResourceLimits, PlanSourceIdentity, PlanSourceView,
};

use super::*;

const METADATA_POLICY: [u8; 32] = [0x21; 32];
const VOLUME_ID: [u8; 8] = 17_u64.to_le_bytes();
const OBJECT_ID: [u8; 8] = 29_u64.to_le_bytes();
const DIFFERENT_OBJECT_ID: [u8; 8] = 71_u64.to_le_bytes();

fn time(seconds: i64) -> UnixTimestamp {
	UnixTimestamp::new(seconds, 0).unwrap()
}

fn source_identity() -> PlanSourceIdentity<'static> {
	PlanSourceIdentity {
		platform: PlanIdentityPlatform::Linux,
		volume_id: &VOLUME_ID,
		object_id: &OBJECT_ID,
		generation: None,
	}
}

fn entry() -> PlanEntry<'static> {
	PlanEntry {
		entry_id: "d88c7830-6bc7-4375-8c41-e9c7eb219d8f".parse().unwrap(),
		source: PlanPath {
			root_id: "4261f49f-e6f4-41cf-82fd-504ed1386973".parse().unwrap(),
			basename: b"\xff-file",
		},
		destination: PlanPath {
			root_id: "6848d85f-4ca4-4ffc-ad90-c62514f32562".parse().unwrap(),
			basename: b"new-file",
		},
		source_view_id: "b5b0ab31-b544-46f1-9ef8-cf3ae0f73d80".parse().unwrap(),
		source_identity: Some(source_identity()),
		stream_length: 11,
		stream_digest: [0x31; 32],
		metadata_policy_digest: METADATA_POLICY,
		estimated_working_bytes: 11,
	}
}

fn fields(entry: PlanEntry<'static>, reference: DocumentRef) -> PlanBodyFields<'static> {
	PlanBodyFields {
		plan_id: "019a0000-0000-7000-8000-000000000001".parse().unwrap(),
		operation: PlanOperation::Copy,
		created_at: time(10),
		expires_at: Some(time(20)),
		source_roots: vec![entry.source.root_id],
		destination_root: entry.destination.root_id,
		entry_pages: vec![reference],
		policy: COPY_POLICY,
		resource_limits: PlanResourceLimits::new(4096, 1).unwrap(),
		approval_required: true,
		source_views: vec![PlanSourceView {
			view_id: entry.source_view_id,
			root_id: entry.source.root_id,
			consistency: PlanViewConsistency::LiveObserved,
			provider: "live-observation",
			measurement_id: "f43ea907-1de0-4dba-8d36-839c0bbd01e1".parse().unwrap(),
			source_identity: Some(source_identity()),
			observed_at: time(9),
			snapshot_token_digest: None,
			stable_until: None,
		}],
		required_grants: vec![READ_CONTENT, CREATE_NEW],
		estimated_working_bytes: 11,
		conflict_count: 0,
		entry_count: 1,
		complete: true,
		extensions: PlanExtensions::empty(),
	}
}

struct Bundle {
	body: PlanBody<'static>,
	page: Vec<u8>,
}

impl Bundle {
	fn new(
		selected: PlanEntry<'static>,
		change: impl FnOnce(&mut PlanBodyFields<'static>),
	) -> Self {
		let page = PlanEntriesPage::new(selected).unwrap();
		let mut fields = fields(selected, page.document_ref());
		change(&mut fields);
		Self {
			body: PlanBody::new(fields).unwrap(),
			page: page.canonical_cbor(),
		}
	}

	fn expected(&self) -> ExpectedCopyPlan<'static> {
		let selected = entry();
		ExpectedCopyPlan {
			digest: self.body.digest(),
			source: selected.source,
			destination: selected.destination,
			metadata_policy_digest: METADATA_POLICY,
			now: time(15),
		}
	}

	fn admit(
		&self,
		expected: ExpectedCopyPlan<'_>,
	) -> Result<AdmittedCopyPlan<'_>, PlanAdmissionError> {
		admit_single_file_plan(self.body.canonical_cbor(), &self.page, expected)
	}
}

#[test]
fn admits_exact_bound_body_and_entry_with_approval_remaining() {
	let bundle = Bundle::new(entry(), |fields| fields.required_grants.reverse());
	let admitted = bundle.admit(bundle.expected()).unwrap();
	assert_eq!(
		admitted.body().canonical_cbor(),
		bundle.body.canonical_cbor()
	);
	assert_eq!(admitted.body().digest(), bundle.body.digest());
	assert!(admitted.body().fields().approval_required);
	assert_eq!(admitted.entry().source.basename, b"\xff-file");
	assert_eq!(admitted.entry().stream_digest, [0x31; 32]);
	assert_eq!(
		admitted.entry().source_identity.unwrap().object_id,
		29_u64.to_le_bytes()
	);
}

#[test]
fn body_digest_and_addressed_leaf_are_independently_required() {
	let bundle = Bundle::new(entry(), |_| {});
	let mut wrong_digest = bundle.expected();
	wrong_digest.digest[0] ^= 1;
	assert_eq!(
		bundle.admit(wrong_digest).unwrap_err(),
		PlanAdmissionError::Body(PlanError::Integrity)
	);

	let mut alternate_entry = entry();
	alternate_entry.stream_digest[0] ^= 1;
	let different = Bundle::new(alternate_entry, |_| {});
	assert_eq!(
		admit_single_file_plan(
			bundle.body.canonical_cbor(),
			&different.page,
			bundle.expected()
		)
		.unwrap_err(),
		PlanAdmissionError::Page(DocumentError::DigestMismatch),
	);
	assert_eq!(
		admit_single_file_plan(bundle.body.canonical_cbor(), b"", bundle.expected()).unwrap_err(),
		PlanAdmissionError::Page(DocumentError::LengthMismatch),
	);
}

#[test]
fn rejects_revoked_profile_incomplete_and_conflicting_requests() {
	type Change = (fn(&mut PlanBodyFields<'static>), PlanAdmissionError);
	let changes: [Change; 8] = [
		(|f| f.complete = false, PlanAdmissionError::Incomplete),
		(|f| f.conflict_count = 1, PlanAdmissionError::Conflict),
		(
			|f| f.approval_required = false,
			PlanAdmissionError::UnsupportedProfile,
		),
		(
			|f| f.operation = PlanOperation::Move,
			PlanAdmissionError::UnsupportedProfile,
		),
		(
			|f| f.policy.conflict = PlanConflict::ProtectedReplace,
			PlanAdmissionError::UnsupportedProfile,
		),
		(
			|f| f.policy.minimum_durability = PlanDurability::QualifiedPowerLoss,
			PlanAdmissionError::UnsupportedProfile,
		),
		(
			|f| f.required_grants.push("retire-source"),
			PlanAdmissionError::UnsupportedProfile,
		),
		(
			|f| f.extensions = PlanExtensions::from_canonical_cbor(b"\xa1\x63a.b\xf6").unwrap(),
			PlanAdmissionError::UnsupportedProfile,
		),
	];
	for (change, error) in changes {
		let bundle = Bundle::new(entry(), change);
		assert_eq!(bundle.admit(bundle.expected()).unwrap_err(), error);
	}
}

#[test]
fn rejects_absent_and_multiple_references_and_additional_roots() {
	for change in [
		(|f: &mut PlanBodyFields<'static>| {
			f.entry_pages.clear();
			f.entry_count = 0;
		}) as fn(&mut PlanBodyFields<'static>),
		|f| {
			f.entry_pages.push(f.entry_pages[0]);
			f.entry_count = 2;
		},
		|f| {
			let original = f.entry_pages[0];
			f.entry_pages[0] = DocumentRef::new(
				original.page_id(),
				DocumentPageKind::PlanEntries,
				original.encoded_bytes().into(),
				2,
			)
			.unwrap();
			f.entry_count = 2;
		},
		|f| f.source_roots.push(f.destination_root),
		|f| f.source_views.clear(),
	] {
		let bundle = Bundle::new(entry(), change);
		assert_eq!(
			bundle.admit(bundle.expected()).unwrap_err(),
			PlanAdmissionError::UnsupportedProfile
		);
	}
}

#[test]
fn expiration_and_future_observations_do_not_pass_admission() {
	let bundle = Bundle::new(entry(), |_| {});
	let mut expected = bundle.expected();
	expected.now = time(20);
	assert_eq!(
		bundle.admit(expected).unwrap_err(),
		PlanAdmissionError::Expired
	);
	expected.now = time(9);
	assert_eq!(
		bundle.admit(expected).unwrap_err(),
		PlanAdmissionError::FutureObservation
	);

	let bad_view = Bundle::new(entry(), |fields| {
		fields.source_views[0].observed_at = time(11)
	});
	assert_eq!(
		bad_view.admit(bad_view.expected()).unwrap_err(),
		PlanAdmissionError::FutureObservation
	);
}

#[test]
fn body_and_leaf_cannot_redirect_the_caller_selected_roots_or_components() {
	let foreign_root = Bundle::new(entry(), |f| f.source_roots[0] = f.destination_root);
	assert_eq!(
		foreign_root.admit(foreign_root.expected()).unwrap_err(),
		PlanAdmissionError::SelectionMismatch,
	);
	let selected = entry();
	for redirected in [
		PlanEntry {
			source: PlanPath {
				basename: b"different",
				..selected.source
			},
			..selected
		},
		PlanEntry {
			destination: PlanPath {
				root_id: selected.source.root_id,
				..selected.destination
			},
			..selected
		},
	] {
		let bundle = Bundle::new(redirected, |f| {
			f.source_roots[0] = selected.source.root_id;
			f.destination_root = selected.destination.root_id;
		});
		assert_eq!(
			bundle.admit(bundle.expected()).unwrap_err(),
			PlanAdmissionError::SelectionMismatch
		);
	}
}

#[test]
fn rejects_unrelated_or_fabricated_source_views_and_conflicting_observations() {
	type Change = (fn(&mut PlanSourceView<'static>), PlanAdmissionError);
	let changes: [Change; 5] = [
		(
			|view| view.root_id = entry().destination.root_id,
			PlanAdmissionError::ViewMismatch,
		),
		(
			|view| view.view_id = view.measurement_id,
			PlanAdmissionError::ViewMismatch,
		),
		(
			|view| view.snapshot_token_digest = Some([9; 32]),
			PlanAdmissionError::ViewMismatch,
		),
		(
			|view| view.source_identity = None,
			PlanAdmissionError::SourceIdentityMismatch,
		),
		(
			|view| view.source_identity.as_mut().unwrap().object_id = &DIFFERENT_OBJECT_ID,
			PlanAdmissionError::SourceIdentityMismatch,
		),
	];
	for (change, error) in changes {
		let bundle = Bundle::new(entry(), |fields| change(&mut fields.source_views[0]));
		assert_eq!(bundle.admit(bundle.expected()).unwrap_err(), error);
	}
	for inconsistent in [
		PlanSourceIdentity {
			platform: PlanIdentityPlatform::Remote,
			..source_identity()
		},
		PlanSourceIdentity {
			volume_id: b"short",
			..source_identity()
		},
		PlanSourceIdentity {
			object_id: b"short",
			..source_identity()
		},
		PlanSourceIdentity {
			generation: Some(b"unassigned"),
			..source_identity()
		},
	] {
		let bundle = Bundle::new(
			PlanEntry {
				source_identity: Some(inconsistent),
				..entry()
			},
			|f| f.source_views[0].source_identity = Some(inconsistent),
		);
		assert_eq!(
			bundle.admit(bundle.expected()).unwrap_err(),
			PlanAdmissionError::SourceIdentityMismatch
		);
	}
}

#[test]
fn metadata_selection_is_independent_of_the_bundle() {
	let bundle = Bundle::new(entry(), |_| {});
	let mut expected = bundle.expected();
	expected.metadata_policy_digest[0] ^= 1;
	assert_eq!(
		bundle.admit(expected).unwrap_err(),
		PlanAdmissionError::MetadataPolicyMismatch
	);
}

#[test]
fn same_root_alias_admits_distinct_names_and_refuses_same_path_selection() {
	let mut selected = entry();
	selected.destination.root_id = selected.source.root_id;
	let bundle = Bundle::new(selected, |_| {});
	let mut expected = bundle.expected();
	expected.destination = selected.destination;
	let admitted = bundle.admit(expected).unwrap();
	assert_eq!(
		admitted.entry().source.root_id,
		admitted.entry().destination.root_id
	);
	assert_ne!(
		admitted.entry().source.basename,
		admitted.entry().destination.basename
	);

	expected.destination = expected.source;
	assert_eq!(
		bundle.admit(expected).unwrap_err(),
		PlanAdmissionError::SelectionMismatch
	);
}

#[test]
fn readdressed_leaf_cannot_select_the_same_path_for_both_roles() {
	let mut selected = entry();
	selected.destination.root_id = selected.source.root_id;
	selected.destination.basename = b"target";
	assert_eq!(
		selected.source.basename.len(),
		selected.destination.basename.len()
	);
	let mut page = PlanEntriesPage::new(selected).unwrap().canonical_cbor();
	let target = page
		.windows(selected.destination.basename.len())
		.position(|bytes| bytes == selected.destination.basename)
		.expect("the synthetic target name occurs in the fixture");
	page[target..target + selected.destination.basename.len()]
		.copy_from_slice(selected.source.basename);
	let body = PlanBody::new(fields(selected, readdress_page(&page))).unwrap();
	let expected = ExpectedCopyPlan {
		digest: body.digest(),
		source: selected.source,
		destination: selected.source,
		metadata_policy_digest: METADATA_POLICY,
		now: time(15),
	};
	assert_eq!(
		admit_single_file_plan(body.canonical_cbor(), &page, expected).unwrap_err(),
		PlanAdmissionError::Page(DocumentError::InvalidEntry)
	);
}

#[test]
fn malformed_bytes_refuse_even_with_fresh_body_and_page_digests() {
	let bundle = Bundle::new(entry(), |_| {});
	let mut malformed_body = bundle.body.canonical_cbor().to_vec();
	assert_eq!(malformed_body[0], 0xb2, "canonical 18-field map");
	malformed_body[0] = 0xb1;
	let mut expected = bundle.expected();
	expected.digest = *blake3::Hasher::new()
		.update(b"ExaCopy/plan/v1\0")
		.update(&malformed_body)
		.finalize()
		.as_bytes();
	assert_eq!(
		admit_single_file_plan(&malformed_body, &bundle.page, expected).unwrap_err(),
		PlanAdmissionError::Body(PlanError::Malformed),
	);

	let mut malformed_page = bundle.page;
	assert_eq!(malformed_page[0], 0xa6, "canonical six-field page");
	malformed_page[0] = 0xa5;
	let body = PlanBody::new(fields(entry(), readdress_page(&malformed_page))).unwrap();
	expected.digest = body.digest();
	assert_eq!(
		admit_single_file_plan(body.canonical_cbor(), &malformed_page, expected).unwrap_err(),
		PlanAdmissionError::Page(DocumentError::Malformed),
	);
}

fn readdress_page(page: &[u8]) -> DocumentRef {
	let length = u64::try_from(page.len()).unwrap();
	let digest = *blake3::Hasher::new()
		.update(b"ExaCopy/document-page/v1\0\x01\x00")
		.update(&length.to_le_bytes())
		.update(page)
		.finalize()
		.as_bytes();
	DocumentRef::new(digest, DocumentPageKind::PlanEntries, length, 1).unwrap()
}
