//! Approval SDK controls over a retained acknowledgement and real private Plan.

use std::fs::File;

use ed25519_dalek::SigningKey;
use exacopy_cli::assembly::linux::managed_sync::ManualRecreatePlanIds;
use exacopy_cli::assembly::linux::managed_sync::activation::{
	ApprovalEnrollment, ApprovalError, ApprovalInput, ApprovalOperation, ApprovalProfile,
	ApprovalReview, ApprovalSelection, encode_host_selection, prepare_recreate_approval,
};
use exacopy_cli::assembly::linux::{CopyRoots, LocalApplyQualificationEnrollment, plan_new_file};
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::ChainHead;
use exacopy_journal::{
	ApplyQualificationDigest, JournalEntryId, JournalEpoch, JournalJobId, OwnerProfileId,
	PlanDigest, RootCapabilityId,
};
use exacopy_model::{SyncConflict, SyncSide};
use exacopy_plan::workflow_sync::decode_envelope;
use exacopy_plan::workflow_sync::recreate::{RecreateAction, RecreateParent, parent_signing_input};
use exacopy_plan::{PlanBody, PlanEntry};
use exacopy_platform::linux::{DestinationRoot, ReadRoot};
use exacopy_transfer::linux::PlanAttempt;

use super::{Sandbox, TestResult};

#[path = "approval_slot.rs"]
mod slot;

pub(super) fn exercise(
	profile: ApprovalProfile<'_>,
	(sandbox, profile_dir, [left, right]): (&mut Sandbox, &File, [&File; 2]),
	owner_profile: [u8; 16],
	members: [&[u8]; 8],
	parent: &RecreateParent,
	action: &RecreateAction<'_>,
	(child, entry): (&PlanBody<'_>, PlanEntry<'_>),
) -> TestResult {
	let owner = ed25519_dalek::VerifyingKey::from_bytes(&profile.owner_key)?;
	let approver = SigningKey::from_bytes(&[0x23; 32]);
	let approver_key = approver.verifying_key();
	let attestor = SigningKey::from_bytes(&[0x24; 32]);
	let attestor_key = attestor.verifying_key();
	let absent_attestation = profile
		.path
		.with_file_name("unissued-approval-fixture-attestation");
	let qualification = LocalApplyQualificationEnrollment {
		record_path: &absent_attestation,
		record_digest: ApplyQualificationDigest::from_bytes([0x25; 32]),
		attestor_id: [0x26; 16],
		attestor_key: &attestor_key,
	};
	let source = ReadRoot::from_directory(right.try_clone()?)?;
	let destination = DestinationRoot::from_directory(left.try_clone()?)?;
	let roots = CopyRoots {
		source: &source,
		destination: &destination,
		source_id: RootCapabilityId::from_bytes(*entry.source.root_id.as_bytes())?,
		destination_id: RootCapabilityId::from_bytes(*entry.destination.root_id.as_bytes())?,
	};
	let subject = UnixComponent::new(action.name.as_bytes())?;
	let attempt = PlanAttempt {
		job: JournalJobId::from_bytes(
			*uuid::uuid!("019a0000-0000-7000-8000-000000000061").as_bytes(),
		)?,
		epoch: JournalEpoch::new(7),
		entry: JournalEntryId::from_bytes([0x33; 16]),
		job_name: UnixComponent::new(b"approval-fixture-uncreated-job")?,
		stage_name: UnixComponent::new(b"candidate")?,
	};
	let private = plan_new_file(roots, attempt, subject, subject)?;
	let fields = child.fields();
	let source_view = &fields.source_views[0];
	let reviewed = ApprovalReview {
		pair: parent.pair_id,
		parent: parent.id,
		parent_digest: *blake3::hash(&parent_signing_input(decode_envelope(members[0])?.body)?)
			.as_bytes(),
		action: action.id,
		from: SyncSide::Right,
		conflict: SyncConflict::EditAgainstDeletion {
			edited: SyncSide::Right,
		},
		ids: ManualRecreatePlanIds {
			plan: fields.plan_id,
			entry: entry.entry_id,
			source_view: source_view.view_id,
			measurement: source_view.measurement_id,
			observed_at: parent.created_at,
		},
		child_digest: child.digest(),
		expires_at: parent.expires_at,
	};
	// Current-selector and attestation commitments are synthetic. The native
	// prepared origin is real and independently bound by this fixture.
	let slot = slot::SelectedSlot::new(sandbox, profile_dir)?;
	let mut enrollment = ApprovalEnrollment {
		origin_ids: [[0x41; 16], [0x42; 16]],
		current_selection: [0x43; 32],
		predecessor: parent.predecessor.digest,
		role_projections: slot.roles,
		prepared: ChainHead::start(),
		prepared_extent: 432,
		attempt,
		private_plan: private.digest(),
		ordinary_owner: (OwnerProfileId::from_bytes(owner_profile)?, &owner),
		approver: &approver_key,
		qualification: &qualification,
		window: [parent.created_at, parent.expires_at],
		activation: [0x47; 16],
	};
	enrollment.prepared = slot.establish_origin(&reviewed, &enrollment)?;
	let mut scratch = vec![0; usize::try_from(fields.resource_limits.buffer_budget_bytes())?];
	let now = || Some(parent.created_at);
	let mut selection = ApprovalSelection {
		profile,
		review: &reviewed,
		enrollment: &enrollment,
	};
	let (host, host_digest) = encode_host_selection(&selection)?;
	let input = |digest| ApprovalInput {
		host: &host,
		host_digest: digest,
		review: members,
	};
	let preview = prepare_recreate_approval(
		&selection,
		input(host_digest),
		ApprovalOperation::Preview,
		roots,
		&mut scratch,
		now,
	)?;
	assert!(preview.activation.is_none());
	let signed = prepare_recreate_approval(
		&selection,
		input(host_digest),
		ApprovalOperation::Sign {
			confirmed_body: preview.body_digest,
			signer: &approver,
		},
		roots,
		&mut scratch,
		now,
	)?;
	let (activation, activation_digest) = signed.activation.ok_or("expected approval envelope")?;
	assert_eq!(
		(
			host.len(),
			signed.grant.len(),
			signed.parent.len(),
			activation.len()
		),
		(838, 293, 268, 260)
	);
	assert_eq!(
		host_digest,
		blake3::derive_key("ExaCopy Linux managed approval host selection v1", &host),
	);
	let mut independently_retained = blake3::derive_key(
		"ExaCopy Linux managed activation signed envelope v1",
		&activation,
	);
	assert_eq!(activation_digest, independently_retained);
	let verify = |digest| ApprovalOperation::Verify {
		grant: &signed.grant,
		parent: &signed.parent,
		activation: &activation,
		activation_digest: digest,
	};
	let checked = prepare_recreate_approval(
		&selection,
		input(host_digest),
		verify(independently_retained),
		roots,
		&mut scratch,
		now,
	)?;
	assert_eq!(
		checked.activation,
		Some((activation.clone(), independently_retained))
	);
	independently_retained[0] ^= 1;
	assert!(matches!(
		prepare_recreate_approval(
			&selection,
			input(host_digest),
			verify(independently_retained),
			roots,
			&mut scratch,
			now,
		),
		Err(ApprovalError::Artifact)
	));
	let mut wrong_host = host_digest;
	wrong_host[0] ^= 1;
	assert!(matches!(
		prepare_recreate_approval(
			&selection,
			input(wrong_host),
			ApprovalOperation::Preview,
			roots,
			&mut scratch,
			now,
		),
		Err(ApprovalError::Artifact)
	));
	assert!(matches!(
		prepare_recreate_approval(
			&selection,
			input(host_digest),
			ApprovalOperation::Sign {
				confirmed_body: preview.body_digest,
				signer: &attestor,
			},
			roots,
			&mut scratch,
			now,
		),
		Err(ApprovalError::Signature)
	));
	let retained_ack = selection.profile.acknowledgement;
	let mut damaged = retained_ack.to_vec();
	damaged[0] ^= 1;
	selection.profile.acknowledgement = &damaged;
	assert!(matches!(
		prepare_recreate_approval(
			&selection,
			input(host_digest),
			ApprovalOperation::Preview,
			roots,
			&mut scratch,
			now,
		),
		Err(ApprovalError::Scope(_))
	));
	let mut wrong_plan = *enrollment.private_plan.as_bytes();
	wrong_plan[0] ^= 1;
	let wrong_enrollment = ApprovalEnrollment {
		private_plan: PlanDigest::from_bytes(wrong_plan),
		..enrollment
	};
	// Reconstruct the independently retained host with a different selected
	// Plan. Its matching bytes cannot substitute for the physical plan check.
	let wrong = ApprovalSelection {
		profile: ApprovalProfile {
			acknowledgement: retained_ack,
			..selection.profile
		},
		review: &reviewed,
		enrollment: &wrong_enrollment,
	};
	let (wrong_host, wrong_digest) = encode_host_selection(&wrong)?;
	assert!(matches!(
		prepare_recreate_approval(
			&wrong,
			ApprovalInput {
				host: &wrong_host,
				host_digest: wrong_digest,
				review: members
			},
			ApprovalOperation::Preview,
			roots,
			&mut scratch,
			now,
		),
		Err(ApprovalError::Selection)
	));
	// Run the attended mode fault last because the private Plan pins the original ctime.
	selection.profile.acknowledgement = retained_ack;
	slot.exercise(
		sandbox,
		&selection,
		input,
		(
			&signed.grant,
			&signed.parent,
			&activation,
			activation_digest,
		),
		roots,
		&mut scratch,
	)?;
	slot::edges::exercise_clock_mutations(
		sandbox,
		slot::edges::ClockMutationFixture {
			profile_dir,
			live: [left, right],
			selection: &selection,
			review: members,
			approver: &approver,
			roots,
		},
		&mut scratch,
	)?;
	Ok(())
}
