use std::convert::Infallible;

use ed25519_dalek::SigningKey;
use exacopy_content::{ContentDigest, measure_at};
use exacopy_endpoint::UnixComponent;
use exacopy_journal::{
	ApplyMetadataPolicyDigest, ApprovedPublicPlanDigest, ApprovedStreamDigest,
	DestinationRootBinding, JournalEntryId, JournalEpoch, JournalJobId, ObservedTimestamp,
	OwnerProfileId, OwnerToken, PublicPlanEntryId, RootCapabilityId, StreamLength,
};
use exacopy_plan::{
	PlanBody, PlanBodyFields, PlanEntriesPage, PlanEntry, PlanExtensions, PlanOperation, PlanPath,
	PlanResourceLimits, PlanSourceView, PlanViewConsistency, UnixTimestamp,
};

use crate::copy_planning::{COPY_POLICY, CREATE_NEW, READ_CONTENT};
use crate::linux::{DestinationPlanBinding, PlanAttempt, SourcePlanBinding};
use crate::public_plan::{ExpectedCopyPlan, admit_single_file_plan};

use super::*;

const EXPECTED: &[u8] = b"approved copy";
const DIFFERENT: &[u8] = b"changed copy!";
const VOLUME: [u8; 8] = 7_u64.to_le_bytes();
const INODE: [u8; 8] = 9_u64.to_le_bytes();
const SCRATCH_BUDGET: usize = 64;

fn measured(bytes: &[u8]) -> ContentDigest {
	measure_at(bytes.len() as u64, &mut [0; 5], |offset, chunk| {
		let start = usize::try_from(offset).unwrap();
		chunk.copy_from_slice(&bytes[start..start + chunk.len()]);
		Ok::<_, Infallible>(())
	})
	.unwrap()
}

fn selected_binding() -> PublicApplyBinding {
	PublicApplyBinding {
		public_plan: ApprovedPublicPlanDigest::from_bytes([1; 32]),
		public_entry: PublicPlanEntryId::from_bytes([2; 16]).unwrap(),
		private_entry: JournalEntryId::from_bytes([3; 16]),
		epoch: JournalEpoch::new(1),
		source_root: root(),
		destination_root: root(),
		stream_length: StreamLength::new(EXPECTED.len() as u64).unwrap(),
		stream_digest: ApprovedStreamDigest::from_bytes(*blake3::hash(EXPECTED).as_bytes()),
		metadata_policy: ApplyMetadataPolicyDigest::from_bytes(
			linux_baseline_metadata_policy_digest(),
		),
		expires_at: Some(OwnerTimestamp::new(50, 8).unwrap()),
		requested_durability: ApplyRequestedDurability::ProcessCrash,
	}
}

#[test]
fn stream_evidence_requires_both_actual_measurements_and_lengths() {
	let approved = selected_binding();
	let good = measured(EXPECTED);
	let different = measured(DIFFERENT);
	assert_eq!(EXPECTED.len(), DIFFERENT.len());
	let length = EXPECTED.len() as u64;

	let correct = ObservedStreams {
		source_length: length,
		source_digest: good,
		stage_length: length,
		stage_digest: good,
	};
	assert!(matches_approved_stream(approved, correct));

	for rejected in [
		ObservedStreams {
			source_digest: different,
			stage_digest: different,
			..correct
		},
		ObservedStreams {
			source_digest: different,
			..correct
		},
		ObservedStreams {
			stage_digest: different,
			..correct
		},
		ObservedStreams {
			source_length: length - 1,
			..correct
		},
		ObservedStreams {
			stage_length: length - 1,
			..correct
		},
	] {
		assert!(!matches_approved_stream(approved, rejected));
	}
}

#[test]
fn public_owner_claims_must_match_the_admitted_bundle_and_exact_private_attempt() {
	let binding = selected_binding();
	let private_plan = local_plan(binding);
	let (body, page, expected) = bundle(binding);
	let admitted = admit_single_file_plan(body.canonical_cbor(), &page, expected).unwrap();
	let binding = PublicApplyBinding {
		public_plan: ApprovedPublicPlanDigest::from_bytes(body.digest()),
		..binding
	};
	let signer = SigningKey::from_bytes(&[6; 32]);
	let profile = CopyProfile {
		id: OwnerProfileId::from_bytes([7; 16]).unwrap(),
		signer: &signer,
		created: OwnerTimestamp::new(50, 7).unwrap(),
		owner_token: OwnerToken::from_bytes([8; 16]).unwrap(),
	};
	let request = PublicApplyStageRequest {
		binding,
		approved: &admitted,
		private_plan: &private_plan,
		profile,
	};
	assert!(matches_admitted_binding(&request, SCRATCH_BUDGET));
	assert!(!matches_admitted_binding(&request, SCRATCH_BUDGET + 1));
	for wrong in [
		PublicApplyBinding {
			public_plan: ApprovedPublicPlanDigest::from_bytes([9; 32]),
			..binding
		},
		PublicApplyBinding {
			public_entry: PublicPlanEntryId::from_bytes([9; 16]).unwrap(),
			..binding
		},
		PublicApplyBinding {
			private_entry: JournalEntryId::from_bytes([9; 16]),
			..binding
		},
		PublicApplyBinding {
			epoch: JournalEpoch::new(2),
			..binding
		},
		PublicApplyBinding {
			stream_length: StreamLength::new(0).unwrap(),
			..binding
		},
		PublicApplyBinding {
			stream_digest: ApprovedStreamDigest::from_bytes([9; 32]),
			..binding
		},
		PublicApplyBinding {
			metadata_policy: ApplyMetadataPolicyDigest::from_bytes([9; 32]),
			..binding
		},
		PublicApplyBinding {
			expires_at: None,
			..binding
		},
	] {
		assert!(!matches_admitted_binding(
			&PublicApplyStageRequest {
				binding: wrong,
				..request
			},
			SCRATCH_BUDGET
		));
	}
	let expired = CopyProfile {
		created: binding.expires_at.unwrap(),
		..profile
	};
	assert!(!matches_admitted_binding(
		&PublicApplyStageRequest {
			profile: expired,
			..request
		},
		SCRATCH_BUDGET
	));
	let renamed = LocalCopyPlan::new(
		private_plan.attempt(),
		private_plan.source(),
		DestinationPlanBinding {
			component: component(b"another"),
			..private_plan.destination()
		},
	)
	.unwrap();
	assert!(!matches_admitted_binding(
		&PublicApplyStageRequest {
			private_plan: &renamed,
			..request
		},
		SCRATCH_BUDGET
	));
}

fn root() -> RootCapabilityId {
	RootCapabilityId::from_bytes(*uuid::uuid!("caf71a5c-13a8-4ae7-bab0-1a1f287393ae").as_bytes())
		.unwrap()
}

fn component(bytes: &'static [u8]) -> UnixComponent<'static> {
	UnixComponent::new(bytes).unwrap()
}

fn local_plan(binding: PublicApplyBinding) -> LocalCopyPlan<'static> {
	let source_root = LinuxFileIdentity::new(7, 10);
	LocalCopyPlan::new(
		PlanAttempt {
			job: JournalJobId::from_bytes(
				*uuid::uuid!("019a0000-0000-7000-8000-000000000003").as_bytes(),
			)
			.unwrap(),
			epoch: binding.epoch,
			entry: binding.private_entry,
			job_name: component(b"job"),
			stage_name: component(b"stage-object"),
		},
		SourcePlanBinding {
			root_id: root(),
			root_identity: source_root,
			file_identity: LinuxFileIdentity::new(
				u64::from_le_bytes(VOLUME),
				u64::from_le_bytes(INODE),
			),
			length: binding.stream_length.get(),
			modified_at: ObservedTimestamp::new(30, 0).unwrap(),
			changed_at: ObservedTimestamp::new(30, 0).unwrap(),
			component: component(b"\xff-source"),
		},
		DestinationPlanBinding {
			root: DestinationRootBinding {
				id: root(),
				identity: source_root,
			},
			component: component(b"new-target"),
		},
	)
	.unwrap()
}

fn bundle(binding: PublicApplyBinding) -> (PlanBody<'static>, Vec<u8>, ExpectedCopyPlan<'static>) {
	let root_id = uuid::Uuid::from_bytes(*root().as_bytes());
	let source = PlanPath {
		root_id,
		basename: b"\xff-source",
	};
	let destination = PlanPath {
		root_id,
		basename: b"new-target",
	};
	let view_id = uuid::uuid!("b5b0ab31-b544-46f1-9ef8-cf3ae0f73d80");
	let identity = PlanSourceIdentity {
		platform: PlanIdentityPlatform::Linux,
		volume_id: &VOLUME,
		object_id: &INODE,
		generation: None,
	};
	let length = binding.stream_length.get();
	let metadata = *binding.metadata_policy.as_bytes();
	let page = PlanEntriesPage::new(PlanEntry {
		entry_id: uuid::Uuid::from_bytes(*binding.public_entry.as_bytes()),
		source,
		destination,
		source_view_id: view_id,
		source_identity: Some(identity),
		stream_length: length,
		stream_digest: *binding.stream_digest.as_bytes(),
		metadata_policy_digest: metadata,
		estimated_working_bytes: length,
	})
	.unwrap();
	let body = PlanBody::new(PlanBodyFields {
		plan_id: uuid::uuid!("019a0000-0000-7000-8000-000000000001"),
		operation: PlanOperation::Copy,
		created_at: UnixTimestamp::new(31, 0).unwrap(),
		expires_at: Some(UnixTimestamp::new(50, 8).unwrap()),
		source_roots: vec![root_id],
		destination_root: root_id,
		entry_pages: vec![page.document_ref()],
		policy: COPY_POLICY,
		resource_limits: PlanResourceLimits::new(SCRATCH_BUDGET as u64, 1).unwrap(),
		approval_required: true,
		source_views: vec![PlanSourceView {
			view_id,
			root_id,
			consistency: PlanViewConsistency::LiveObserved,
			provider: "live-observation",
			measurement_id: uuid::uuid!("f43ea907-1de0-4dba-8d36-839c0bbd01e1"),
			source_identity: Some(identity),
			observed_at: UnixTimestamp::new(30, 0).unwrap(),
			snapshot_token_digest: None,
			stable_until: None,
		}],
		required_grants: vec![READ_CONTENT, CREATE_NEW],
		estimated_working_bytes: length,
		conflict_count: 0,
		entry_count: 1,
		complete: true,
		extensions: PlanExtensions::empty(),
	})
	.unwrap();
	let expected = ExpectedCopyPlan {
		digest: body.digest(),
		source,
		destination,
		metadata_policy_digest: metadata,
		now: UnixTimestamp::new(49, 1).unwrap(),
	};
	(body, page.canonical_cbor(), expected)
}
