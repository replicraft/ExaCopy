//! Bounded approval preparation for one selected managed recreate.

use std::fmt;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_journal::{OwnerProfileId, PlanDigest};
use exacopy_model::{SyncConflict, SyncSide};
use exacopy_plan::{PlanBody, UnixTimestamp};
use exacopy_transfer::linux::sync_preview::HeldSyncPreview as _;
use exacopy_transfer::linux::{LocalCopyPlan, PlanAttempt};
use exacopy_transfer::sync_genesis::recreate::{
	ExpectedRecreateExport, RecreateSourceEvidence, verify_recreate_export,
};
use exacopy_transfer::sync_genesis::{AuthenticatedSyncGenesis, ExpectedSyncGenesis};

use super::super::{CopyRoots, LocalApplyQualificationEnrollment, plan_new_file};
use crate::sync_preview::managed_policy::{ManagedPolicyPin, decode};

use super::acknowledgement::with_acknowledgement;
use super::manual_recreate::{RecreateReview, prepare_current};
use super::scope::{component, native_object};
use super::{
	ManagedHistoryPreview, ManagedSyncPreviewError, ManualRecreateError, ManualRecreatePlanIds,
	verify_owner_identity, with_held_history_view,
};

mod prepared;
mod wire;

pub use prepared::{PreparedApprovalInput, PreparedRecreate, with_scoped_prepared_recreate};

/// Independently selected immutable review and child coordinates.
pub struct ApprovalReview {
	/// Managed pair identifier, independent of the P-063 pair digest.
	pub pair: [u8; 16],
	/// Review parent identifier.
	pub parent: [u8; 16],
	/// Exact reviewed parent body commitment.
	pub parent_digest: [u8; 32],
	/// Sole reviewed action identifier.
	pub action: [u8; 16],
	/// Explicit survivor side.
	pub from: SyncSide,
	/// Independently reviewed current conflict.
	pub conflict: SyncConflict,
	/// Independently selected public child IDs and review creation time.
	pub ids: ManualRecreatePlanIds,
	/// Independently selected public child body commitment.
	pub child_digest: [u8; 32],
	/// Original exclusive review and ordinary Plan expiry.
	pub expires_at: UnixTimestamp,
}

/// Independent action enrollment commitments. These are not native guards.
pub struct ApprovalEnrollment<'a> {
	/// Nonzero enrollment and prepared allocation identifiers, respectively.
	pub origin_ids: [[u8; 16]; 2],
	/// Current selector commitment chosen by the host.
	pub current_selection: [u8; 32],
	/// Expected generation-one Workflow Root commitment.
	pub predecessor: [u8; 32],
	/// Selected native slot and segment commitments in order.
	pub role_projections: [[u8; 32]; 2],
	/// Selected exact prepared head.
	pub prepared: exacopy_journal::frame::ChainHead,
	/// Selected exact prepared physical extent.
	pub prepared_extent: u64,
	/// Exact private ordinary attempt, including raw job and stage names.
	pub attempt: PlanAttempt<'a>,
	/// Exact private ordinary Plan commitment.
	pub private_plan: PlanDigest,
	/// Independently selected ordinary signer profile and verification key.
	pub ordinary_owner: (OwnerProfileId, &'a VerifyingKey),
	/// Independently selected activation approver.
	pub approver: &'a VerifyingKey,
	/// Independently selected ordinary attestation key and record.
	pub qualification: &'a LocalApplyQualificationEnrollment<'a>,
	/// Selected start and exclusive expiry.
	pub window: [UnixTimestamp; 2],
	/// Nonzero selected activation identifier.
	pub activation: [u8; 16],
}

/// Explicit foreground selection of one retained Init acknowledgement.
pub struct ApprovalProfile<'a> {
	/// Independently selected existing profile path.
	pub path: &'a Path,
	/// Independently configured owner key.
	pub owner_key: [u8; 32],
	/// Exact selected profile record identifier.
	pub selection: [u8; 16],
	/// Previously retained signed Init acknowledgement.
	pub acknowledgement: &'a [u8],
}

/// Trusted selections, held apart from candidate bytes.
pub struct ApprovalSelection<'a> {
	/// Original acknowledged managed selection.
	pub profile: ApprovalProfile<'a>,
	/// Read-only review selected by the operator.
	pub review: &'a ApprovalReview,
	/// Independent enrollment for this action.
	pub enrollment: &'a ApprovalEnrollment<'a>,
}

/// Protected host record and independently selected review closure.
pub struct ApprovalInput<'a> {
	/// Exact bounded host artifact.
	pub host: &'a [u8],
	/// Independently retained host digest.
	pub host_digest: [u8; 32],
	/// Review envelope, action, child body and page, root, left, right and leaf.
	pub review: [&'a [u8]; 8],
}

/// Requested operation on the independently checked approval body.
pub enum ApprovalOperation<'a> {
	/// Produce an unsigned proposal for independent confirmation.
	Preview,
	/// Sign after confirmation of that exact proposal.
	Sign {
		/// Independently confirmed unsigned approval commitment.
		confirmed_body: [u8; 32],
		/// Separately selected approver signer.
		signer: &'a SigningKey,
	},
	/// Check an externally pinned signed approval and its exact attachments.
	Verify {
		/// Exact scoped grant.
		grant: &'a [u8],
		/// Exact executable parent.
		parent: &'a [u8],
		/// Exact signed activation.
		activation: &'a [u8],
		/// Independently retained complete signed activation digest.
		activation_digest: [u8; 32],
	},
}

/// Bounded output for independent retention, with no execution authority.
pub struct ApprovalArtifacts {
	/// Scoped grant bytes.
	pub grant: Vec<u8>,
	/// Executable parent bytes.
	pub parent: Vec<u8>,
	/// Unsigned activation body commitment for explicit approval.
	pub body_digest: [u8; 32],
	/// Exact envelope and its digest after signing or verification.
	pub activation: Option<(Vec<u8>, [u8; 32])>,
}

/// Why the approval preparation was refused.
#[derive(Debug)]
pub enum ApprovalError {
	/// The selected prepared slot could not be checked.
	Prepared(exacopy_platform::linux::PreparedManagedActionError),
	/// The actual origin frame did not match independent expectations.
	Origin(exacopy_journal::managed_action_prepared::ManagedActionPreparedError),
	/// The protected policy or original managed scope refused.
	Scope(ManagedSyncPreviewError),
	/// Current held review planning refused.
	Review(ManualRecreateError),
	/// Ordinary read-only planning refused.
	Plan(Box<super::super::LocalCopyError>),
	/// Independently selected facts or the native observation differ.
	Selection,
	/// Bounded artifact syntax or exact expected bytes differ.
	Artifact,
	/// Approver signature or selected key differs.
	Signature,
	/// Clock unavailable, regressed or outside the selected window.
	Time,
}

impl From<ManagedSyncPreviewError> for ApprovalError {
	fn from(error: ManagedSyncPreviewError) -> Self {
		match error {
			ManagedSyncPreviewError::PreparedCustody(cause) => Self::Prepared(cause),
			error => Self::Scope(error),
		}
	}
}

impl From<exacopy_platform::linux::PreparedManagedActionError> for ApprovalError {
	fn from(error: exacopy_platform::linux::PreparedManagedActionError) -> Self {
		Self::Prepared(error)
	}
}

impl fmt::Display for ApprovalError {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Prepared(cause) => fmt::Display::fmt(cause, out),
			Self::Origin(cause) => fmt::Display::fmt(cause, out),
			Self::Scope(cause) => fmt::Display::fmt(cause, out),
			Self::Review(cause) => fmt::Display::fmt(cause, out),
			Self::Plan(cause) => fmt::Display::fmt(cause, out),
			Self::Selection => out.write_str("managed approval selection differs"),
			Self::Artifact => out.write_str("managed approval artifact differs"),
			Self::Signature => out.write_str("managed approval signature refused"),
			Self::Time => out.write_str("managed approval clock or window refused"),
		}
	}
}

impl std::error::Error for ApprovalError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Prepared(cause) => Some(cause),
			Self::Origin(cause) => Some(cause),
			Self::Scope(cause) => Some(cause),
			Self::Review(cause) => Some(cause),
			Self::Plan(cause) => Some(cause.as_ref()),
			_ => None,
		}
	}
}

/// Prepares canonical host bytes and their digest from trusted inputs.
///
/// # Errors
/// Refuses inconsistent independent selections or key roles.
pub fn encode_host_selection(
	selection: &ApprovalSelection<'_>,
) -> Result<(Vec<u8>, [u8; 32]), ApprovalError> {
	let profile = &selection.profile;
	let (encoded, _) = with_acknowledgement(
		profile.path,
		profile.owner_key,
		profile.selection,
		profile.acknowledgement,
		|store, pin| {
			let key = verify_owner_identity(&pin.identity)?;
			let record = store
				.read(profile.selection)
				.map_err(ManagedSyncPreviewError::Store)?;
			decode(record.bytes(), pin).map_err(ManagedSyncPreviewError::Policy)?;
			let encoded = wire::host(selection, pin, store.identity(), &key)?;
			record.recheck().map_err(ManagedSyncPreviewError::Store)?;
			Ok::<_, ApprovalError>(encoded)
		},
	)?;
	Ok(encoded)
}

/// Prepares or verifies approval artifacts using the original held review.
///
/// The caller supplies protected artifact ingress. This SDK path creates no
/// claim, native grant or child and establishes no current-head or slot authority.
///
/// # Errors
/// Refuses a changed native or review scope, inconsistent role, missing external
/// digest pin, unapproved artifact or invalid time.
pub fn prepare_recreate_approval(
	selection: &ApprovalSelection<'_>,
	input: ApprovalInput<'_>,
	operation: ApprovalOperation<'_>,
	roots: CopyRoots<'_>,
	scratch: &mut [u8],
	now: impl Fn() -> Option<UnixTimestamp>,
) -> Result<ApprovalArtifacts, ApprovalError> {
	use ApprovalError as Error;

	let profile = &selection.profile;
	let (artifacts, _) = with_acknowledgement(
		profile.path,
		profile.owner_key,
		profile.selection,
		profile.acknowledgement,
		|store, pin| {
			let key = verify_owner_identity(&pin.identity)?;
			let record = store
				.read(profile.selection)
				.map_err(ManagedSyncPreviewError::Store)?;
			let (host, digest) = wire::host(selection, pin, store.identity(), &key)?;
			if input.host != host.as_slice() || input.host_digest != digest || digest == [0; 32] {
				return Err(Error::Artifact);
			}
			with_held_history_view(pin, &record, &key, false, |baseline, current, key, _| {
				BoundApproval {
					selection,
					input,
					operation,
					roots,
					scratch,
					now: &now,
				}
				.verify(pin, baseline, current, key)
				.map(|verified| verified.artifacts)
			})
		},
	)?;
	Ok(artifacts)
}

struct BoundApproval<'call, 'selection, 'input, 'operation, 'root, Clock> {
	selection: &'call ApprovalSelection<'selection>,
	input: ApprovalInput<'input>,
	operation: ApprovalOperation<'operation>,
	roots: CopyRoots<'root>,
	scratch: &'call mut [u8],
	now: &'call Clock,
}

struct VerifiedApproval {
	artifacts: ApprovalArtifacts,
	accepted_at: UnixTimestamp,
}

impl<Clock: Fn() -> Option<UnixTimestamp>> BoundApproval<'_, '_, '_, '_, '_, Clock> {
	fn verify(
		self,
		pin: &ManagedPolicyPin,
		baseline: &AuthenticatedSyncGenesis<'_, '_>,
		current: &ManagedHistoryPreview<'_, '_, '_>,
		key: &VerifyingKey,
	) -> Result<VerifiedApproval, ApprovalError> {
		use ApprovalError as Error;

		let Self {
			selection,
			input,
			operation,
			roots,
			scratch,
			now,
		} = self;
		let (review, enrollment) = (selection.review, selection.enrollment);
		let checked_at = check_time(enrollment, now)?;
		let candidate = prepare_current(
			baseline,
			current,
			key,
			pin.digest,
			RecreateReview {
				from: review.from,
				conflict: review.conflict,
				ids: review.ids,
				expires_at: Some(review.expires_at),
			},
			scratch,
		)
		.map_err(Error::Review)?;
		let subject = component(&current.policy.subject)?;
		let history = &current.policy.history;
		let old = baseline.root();
		let expected = ExpectedSyncGenesis {
			root_digest: enrollment.predecessor,
			profile: current.identity.owner_profile,
			revision: history.revision,
			owner: key,
			subject,
			endpoints: *baseline.endpoints(),
			scan: history.scan,
		};
		let verified = verify_recreate_export(
			input.review,
			&ExpectedRecreateExport {
				history: &expected,
				predecessor: [
					history.root.reference,
					old.endpoints[0],
					old.endpoints[1],
					old.leaf,
				],
				policy_digest: pin.digest,
				pair_id: review.pair,
				parent_id: review.parent,
				action_id: review.action,
				child_digest: review.child_digest,
				created_at: review.ids.observed_at,
				expires_at: review.expires_at,
				now: checked_at,
				root_aliases: candidate.roots.map(|root| root.child_alias),
				from: review.from,
				reviewed: review.conflict,
				source: RecreateSourceEvidence {
					native: native_object(candidate.source_identity)?,
					child: candidate.source_identity.into(),
					stream: candidate.source,
				},
			},
		)
		.map_err(|_| Error::Artifact)?;
		if verified.parent_digest() != review.parent_digest
			|| candidate.child.canonical_body() != input.review[2]
			|| candidate.child.canonical_page() != input.review[3]
		{
			return Err(Error::Selection);
		}
		let [source, target] = match review.from {
			SyncSide::Left => candidate.roots,
			SyncSide::Right => [candidate.roots[1], candidate.roots[0]],
		};
		if roots.source.identity() != source.observed_identity
			|| roots.destination.identity() != target.observed_identity
			|| roots.source_id.as_bytes() != source.child_alias.as_bytes()
			|| roots.destination_id.as_bytes() != target.child_alias.as_bytes()
		{
			return Err(Error::Selection);
		}
		let private = plan_new_file(roots, enrollment.attempt, subject, subject)
			.map_err(|cause| Error::Plan(Box::new(cause)))?;
		match_private(&private, enrollment, &candidate)?;
		current.recheck_selection()?;
		let before_approval = check_time_after(enrollment, now, checked_at)?;
		let approved_child = PlanBody::from_canonical_cbor(review.child_digest, input.review[2])
			.map_err(|_| Error::Artifact)?;
		let budget = approved_child
			.fields()
			.resource_limits
			.buffer_budget_bytes();
		let result = wire::approve(
			selection,
			input.host_digest,
			verified.predecessor_pair_digest(),
			&candidate,
			budget,
			operation,
		)?;
		current.recheck_selection()?;
		let accepted_at = check_time_after(enrollment, now, before_approval)?;
		Ok(VerifiedApproval {
			artifacts: result,
			accepted_at,
		})
	}
}

fn match_private(
	private: &LocalCopyPlan<'_>,
	enrollment: &ApprovalEnrollment<'_>,
	candidate: &super::ManualRecreateCandidate,
) -> Result<(), ApprovalError> {
	let observed = private.source();
	if private.digest() != enrollment.private_plan
		|| observed.file_identity.device() != candidate.source_identity.device()
		|| observed.file_identity.inode() != candidate.source_identity.inode()
		|| observed.length != candidate.source.byte_len
	{
		return Err(ApprovalError::Selection);
	}
	Ok(())
}

fn check_time(
	enrollment: &ApprovalEnrollment<'_>,
	now: &impl Fn() -> Option<UnixTimestamp>,
) -> Result<UnixTimestamp, ApprovalError> {
	let current = now().ok_or(ApprovalError::Time)?;
	let [from, until] = enrollment.window;
	if current < from || current >= until {
		return Err(ApprovalError::Time);
	}
	Ok(current)
}

fn check_time_after(
	enrollment: &ApprovalEnrollment<'_>,
	now: &impl Fn() -> Option<UnixTimestamp>,
	previous: UnixTimestamp,
) -> Result<UnixTimestamp, ApprovalError> {
	let current = check_time(enrollment, now)?;
	if current < previous {
		return Err(ApprovalError::Time);
	}
	Ok(current)
}
