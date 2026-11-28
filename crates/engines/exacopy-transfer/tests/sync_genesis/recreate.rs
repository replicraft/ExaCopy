use ed25519_dalek::{Signer as _, SigningKey};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_model::{RegularFileEvidence, SyncConflict, SyncSide};
use exacopy_plan::workflow_sync::recreate::{
	RecreateAction, RecreateObservation, RecreateParent, RecreateReason, RecreateSide,
	action_reference, encode_action, encode_parent, encode_parent_envelope, observation_digests,
	parent_signing_input,
};
use exacopy_plan::workflow_sync::{WorkflowKind, WorkflowRef, decode_envelope, decode_root};
use exacopy_plan::{
	PlanBody, PlanBodyFields, PlanConflict, PlanConsistency, PlanDurability, PlanEntriesPage,
	PlanEntry, PlanExtensions, PlanFidelity, PlanIdentityPlatform, PlanOperation, PlanPath,
	PlanPolicy, PlanPreservation, PlanPublication, PlanResourceLimits, PlanSourceIdentity,
	PlanSourceRetirement, PlanSourceView, PlanStorage, PlanVerification, PlanViewConsistency,
	UnixTimestamp,
};
use exacopy_transfer::copy_planning::linux_baseline_metadata_policy_digest;
use exacopy_transfer::sync_genesis::recreate::{
	ExpectedRecreateExport, RecreateExportError, RecreateSourceEvidence, verify_recreate_export,
};
use uuid::Uuid;

use super::{ExpectedSyncGenesis, first, object};

const FROM: SyncSide = SyncSide::Left;
const CONFLICT: SyncConflict = SyncConflict::DeletionAgainstUnchanged {
	absent: SyncSide::Right,
};
const POLICY_PIN: [u8; 32] = [0xb0; 32];

fn record_id(byte: u8) -> [u8; 16] {
	let mut id = [byte; 16];
	id[6] = 0x70;
	id[8] = 0x80;
	id
}

fn time(seconds: i64) -> UnixTimestamp {
	UnixTimestamp::new(seconds, 17).unwrap()
}

fn child(
	selection: &ExpectedSyncGenesis<'_>,
	aliases: [Uuid; 2],
	source: &RecreateSourceEvidence,
) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
	let device = source.child.device.to_le_bytes();
	let inode = source.child.inode.to_le_bytes();
	let native = PlanSourceIdentity {
		platform: PlanIdentityPlatform::Linux,
		volume_id: &device,
		object_id: &inode,
		generation: None,
	};
	let paths = aliases.map(|root_id| PlanPath {
		root_id,
		basename: selection.subject.as_bytes(),
	});
	let leaf = PlanEntriesPage::new(PlanEntry {
		entry_id: Uuid::from_bytes([3; 16]),
		source: paths[0],
		destination: paths[1],
		source_view_id: Uuid::from_bytes([4; 16]),
		source_identity: Some(native),
		stream_length: source.stream.byte_len,
		stream_digest: source.stream.content_digest,
		metadata_policy_digest: linux_baseline_metadata_policy_digest(),
		estimated_working_bytes: source.stream.byte_len,
	})
	.unwrap();
	let child = PlanBody::new(PlanBodyFields {
		plan_id: Uuid::from_bytes(record_id(5)),
		operation: PlanOperation::Copy,
		created_at: time(100),
		expires_at: Some(time(120)),
		source_roots: vec![aliases[0]],
		destination_root: aliases[1],
		entry_pages: vec![leaf.document_ref()],
		policy: PlanPolicy {
			preservation: PlanPreservation::Preserve,
			conflict: PlanConflict::Error,
			verification: PlanVerification::Blake3Readback,
			storage: PlanStorage::Independent,
			publication: PlanPublication::PerFile,
			consistency: PlanConsistency::LiveObserved,
			minimum_durability: PlanDurability::ProcessCrash,
			fidelity: PlanFidelity::RequiredData,
			source_retirement: PlanSourceRetirement::None,
		},
		resource_limits: PlanResourceLimits::new(65_536, 1).unwrap(),
		approval_required: true,
		source_views: vec![PlanSourceView {
			view_id: Uuid::from_bytes([4; 16]),
			root_id: aliases[0],
			consistency: PlanViewConsistency::LiveObserved,
			provider: "linux-local",
			measurement_id: Uuid::from_bytes([6; 16]),
			source_identity: Some(native),
			observed_at: time(100),
			snapshot_token_digest: None,
			stable_until: None,
		}],
		required_grants: vec!["read-content", "create-new"],
		estimated_working_bytes: source.stream.byte_len,
		conflict_count: 0,
		entry_count: 1,
		complete: true,
		extensions: PlanExtensions::empty(),
	})
	.unwrap();
	let digest = child.digest();
	let bytes = child.canonical_cbor().to_vec();
	(bytes, leaf.canonical_cbor(), digest)
}

fn sign(parent: &RecreateParent, signer: &SigningKey) -> Vec<u8> {
	let body = encode_parent(parent).unwrap();
	let signature = signer
		.sign(&parent_signing_input(&body).unwrap())
		.to_bytes();
	encode_parent_envelope(&body, signer.verifying_key().to_bytes(), signature).unwrap()
}

#[test]
fn signed_recreate_requires_the_exact_independent_selection_and_bundle() {
	let fixture = first();
	let signer = SigningKey::from_bytes(&[0x51; 32]);
	let owner = signer.verifying_key();
	let expected = fixture.expected(&owner);
	let old_root = decode_root(decode_envelope(&fixture.root).unwrap().body).unwrap();
	let predecessor = WorkflowRef {
		kind: WorkflowKind::Root,
		digest: expected.root_digest,
		byte_len: u16::try_from(fixture.root.len()).unwrap(),
	};
	let aliases = [1, 2].map(Uuid::from_u128);
	let source = RecreateSourceEvidence {
		native: object(8, 1, 80),
		child: JobFileIdentity {
			device: 0x801,
			inode: 80,
		},
		stream: RegularFileEvidence {
			byte_len: 3,
			content_digest: *blake3::hash(b"abc").as_bytes(),
			required_metadata_digest: exacopy_manifest::sync_baseline::LinuxOwnerMode {
				mode: 0o754,
				uid: u32::MAX,
				gid: 1024,
			}
			.digest()
			.unwrap(),
		},
	};
	let (body, page, child_digest) = child(&expected, aliases, &source);
	let child_plan = PlanBody::from_canonical_cbor(child_digest, &body).unwrap();
	let mut selected = ExpectedRecreateExport {
		history: &expected,
		predecessor: [
			predecessor,
			old_root.endpoints[0],
			old_root.endpoints[1],
			old_root.leaf,
		],
		policy_digest: POLICY_PIN,
		pair_id: record_id(0x84),
		parent_id: record_id(0x85),
		action_id: record_id(0x86),
		child_digest,
		created_at: time(100),
		expires_at: time(120),
		now: time(101),
		root_aliases: aliases,
		from: FROM,
		reviewed: CONFLICT,
		source,
	};
	let mut action = RecreateAction {
		id: selected.action_id,
		side: RecreateSide::Left,
		name: expected.subject,
		source: source.native,
		stream_length: source.stream.byte_len,
		stream_digest: source.stream.content_digest,
		metadata_digest: source.stream.required_metadata_digest,
		child_digest,
		child_page: child_plan.fields().entry_pages[0],
		reason: RecreateReason::DeletionAgainstUnchanged,
	};
	let action_bytes = encode_action(&action).unwrap();
	let action_page = action_reference(&action_bytes).unwrap();
	let mut observation = RecreateObservation {
		pair_id: selected.pair_id,
		predecessor_pair: old_root.pair,
		endpoints: old_root.endpoints,
		predecessor,
		scope: old_root.scope,
		policy_pin: POLICY_PIN,
		action_page,
	};
	let mut parent = RecreateParent {
		id: selected.parent_id,
		profile: expected.profile,
		pair_id: selected.pair_id,
		endpoints: old_root.endpoints,
		predecessor,
		filter: old_root.filter,
		policy: old_root.policy,
		coverage: observation_digests(&observation).unwrap(),
		action_page,
		created_at: time(100),
		expires_at: time(120),
	};
	let parent_bytes = sign(&parent, &signer);
	let [left, right, leaf] = fixture.members.each_ref().map(Vec::as_slice);
	let members = [
		parent_bytes.as_slice(),
		action_bytes.as_slice(),
		body.as_slice(),
		page.as_slice(),
		fixture.root.as_slice(),
		left,
		right,
		leaf,
	];
	let verified = verify_recreate_export(members, &selected).unwrap();
	assert_eq!(
		verified.predecessor_pair_digest(),
		super::digest(fixture.projection.pair)
	);
	assert_ne!(verified.parent_digest(), expected.root_digest);

	selected.now = time(120);
	assert!(matches!(
		verify_recreate_export(members, &selected),
		Err(RecreateExportError::Time)
	));
	selected.now = time(101);
	selected.pair_id = record_id(0x91);
	assert!(matches!(
		verify_recreate_export(members, &selected),
		Err(RecreateExportError::Binding)
	));
	selected.pair_id = parent.pair_id;

	selected.policy_digest[0] ^= 1;
	assert!(matches!(
		verify_recreate_export(members, &selected),
		Err(RecreateExportError::Binding)
	));
	selected.policy_digest = POLICY_PIN;

	let mut damaged_page = page.clone();
	damaged_page[0] ^= 1;
	let mut unbound_child = members;
	unbound_child[3] = &damaged_page;
	assert!(matches!(
		verify_recreate_export(unbound_child, &selected),
		Err(RecreateExportError::Child(_))
	));
	let too_large = [0; 2049];
	let mut overbound = members;
	overbound[2] = &too_large;
	assert!(matches!(
		verify_recreate_export(overbound, &selected),
		Err(RecreateExportError::Size)
	));
	let extent = [0; 2048];
	let mut over_aggregate = [&extent[..]; 8];
	over_aggregate[2] = &too_large;
	assert!(matches!(
		verify_recreate_export(over_aggregate, &selected),
		Err(RecreateExportError::Size)
	));

	let wrong_key = sign(&parent, &SigningKey::from_bytes(&[0x67; 32]));
	let mut altered = members;
	altered[0] = &wrong_key;
	assert!(matches!(
		verify_recreate_export(altered, &selected),
		Err(RecreateExportError::Signature)
	));
	let mut swapped = members;
	swapped.swap(5, 6);
	assert!(matches!(
		verify_recreate_export(swapped, &selected),
		Err(RecreateExportError::History(_))
	));

	// Rebind the complete signed parent to each independently selected replacement
	// child. Ordinary Plan admission accepts each variant.
	for (case, mut fields) in (0..7).map(|case| (case, child_plan.fields().clone())) {
		let mut replacement_page = page.clone();
		match case {
			0 => fields.required_grants.swap(0, 1),
			1 => fields.source_views[0].provider = "other-provider",
			2 => fields.resource_limits = PlanResourceLimits::new(0, 1).unwrap(),
			3 => fields.resource_limits = PlanResourceLimits::new(65_536, 2).unwrap(),
			4 => fields.resource_limits = PlanResourceLimits::new(u64::MAX, 1).unwrap(),
			5 => fields.estimated_working_bytes += 1,
			_ => {
				let mut entry = PlanEntriesPage::from_canonical_cbor(fields.entry_pages[0], &page)
					.unwrap()
					.entry();
				entry.estimated_working_bytes += 1;
				let replacement = PlanEntriesPage::new(entry).unwrap();
				fields.entry_pages[0] = replacement.document_ref();
				replacement_page = replacement.canonical_cbor();
			}
		}
		let replacement = PlanBody::new(fields).unwrap();
		let mut replacement_selection = selected;
		replacement_selection.child_digest = replacement.digest();
		let replacement_action = encode_action(&RecreateAction {
			child_digest: replacement.digest(),
			child_page: replacement.fields().entry_pages[0],
			..action
		})
		.unwrap();
		let action_page = action_reference(&replacement_action).unwrap();
		let replacement_parent = sign(
			&RecreateParent {
				action_page,
				coverage: observation_digests(&RecreateObservation {
					action_page,
					..observation
				})
				.unwrap(),
				..parent
			},
			&signer,
		);
		let mut rebound_child = members;
		rebound_child[..4].copy_from_slice(&[
			&replacement_parent,
			&replacement_action,
			replacement.canonical_cbor(),
			&replacement_page,
		]);
		assert!(
			matches!(
				verify_recreate_export(rebound_child, &replacement_selection),
				Err(RecreateExportError::Binding)
			),
			"replacement child case {case} was not refused by exact profile binding"
		);
	}

	action.reason = RecreateReason::EditAgainstDeletion;
	let dishonest = encode_action(&action).unwrap();
	let replacement_ref = action_reference(&dishonest).unwrap();
	parent.action_page = replacement_ref;
	observation.action_page = replacement_ref;
	parent.coverage = observation_digests(&observation).unwrap();
	let resigned = sign(&parent, &signer);
	let mut rebound = members;
	rebound[0] = &resigned;
	rebound[1] = &dishonest;
	assert!(matches!(
		verify_recreate_export(rebound, &selected),
		Err(RecreateExportError::Binding)
	));
}
