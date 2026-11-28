//! Selected no-effect action preparation under the original native holders.

use exacopy_journal::managed_action_prepared::{
	MANAGED_ACTION_PREPARED_FRAME_BYTES, ManagedActionPrepared, match_managed_action_prepared,
};
use exacopy_journal::managed_activation_claim::{
	ManagedActivationChild, ManagedActivationPrepared,
};
use exacopy_journal::{ApprovedPublicPlanDigest, PublicPlanEntryId};
use exacopy_plan::UnixTimestamp;
use exacopy_platform::linux::PreparedActionSlotSelection;
use exacopy_transfer::linux::sync_preview::HeldSyncPreview as _;

use super::super::super::CopyRoots;
use super::super::acknowledgement::with_acknowledgement;
use super::super::history::{HistoryCustody, with_bound_history};
use super::super::scope::{expected_native, expected_object, raw_path};
use super::super::{ManagedSyncPreviewError, verify_owner_identity};
use super::{
	ApprovalArtifacts, ApprovalError, ApprovalInput, ApprovalOperation, ApprovalSelection,
	BoundApproval, check_time_after, decode, wire,
};

/// Exact independently pinned review, action slot and signed approval artifacts.
pub struct PreparedApprovalInput<'a> {
	/// Exact H and review members under the independently retained host digest.
	pub approval: ApprovalInput<'a>,
	/// Original native slot and original fixed segment selection.
	pub slot: PreparedActionSlotSelection<'a>,
	/// Exact scoped grant bytes.
	pub grant: &'a [u8],
	/// Exact executable parent bytes.
	pub parent: &'a [u8],
	/// Exact signed activation envelope.
	pub activation: &'a [u8],
	/// Independent signed activation envelope digest.
	pub activation_digest: [u8; 32],
}

/// Read-only preparation lent while the original profile, pair and slot are held.
///
/// This observation conveys no current-selector proof, writer, durable spending
/// acknowledgement or child permission.
pub struct PreparedRecreate<'held> {
	approval: &'held ApprovalArtifacts,
	origin: ManagedActivationPrepared,
}

impl PreparedRecreate<'_> {
	/// Detached approval artifacts checked under this original scope.
	#[must_use]
	pub const fn approval(&self) -> &ApprovalArtifacts {
		self.approval
	}

	/// Exact selected origin boundary observed through physical EOF.
	#[must_use]
	pub const fn origin(&self) -> ManagedActivationPrepared {
		self.origin
	}
}

/// Checks one independently selected original action for foreground observation.
///
/// Keeps the profile shared lock, common-parent exclusive preparation and slot
/// exclusion throughout the callback. Neither this function nor the observation
/// acquires a writer or establishes an active issuer, live grant or current selector.
///
/// # Errors
/// Refuses mismatched approval, canonical origin or held native scope, and changed
/// custody during or after observation.
pub fn with_scoped_prepared_recreate<R>(
	selection: &ApprovalSelection<'_>,
	input: PreparedApprovalInput<'_>,
	roots: CopyRoots<'_>,
	scratch: &mut [u8],
	now: impl Fn() -> Option<UnixTimestamp>,
	observe: impl for<'held> FnOnce(PreparedRecreate<'held>) -> Result<R, ApprovalError>,
) -> Result<R, ApprovalError> {
	use ApprovalError as Error;

	let profile = &selection.profile;
	let (result, _) = with_acknowledgement(
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
			if input.approval.host != host.as_slice()
				|| input.approval.host_digest != digest
				|| digest == [0; 32]
			{
				return Err(Error::Artifact);
			}
			let policy = decode(record.bytes(), pin).map_err(ManagedSyncPreviewError::Policy)?;
			let scope = expected_native(&policy)?;
			record.with_prepared_action_scope(
				scope,
				raw_path(&policy.history.path),
				expected_object(policy.history.directory),
				input.slot,
				|view| {
					let bytes = view.native_facts()?.role_projection_bytes();
					let roles = wire::role_projections(bytes.slot(), bytes.segment());
					if roles != selection.enrollment.role_projections {
						return Err(Error::Selection);
					}
					let expected = origin_selection(selection, roles)?;
					let mut exact = [0; MANAGED_ACTION_PREPARED_FRAME_BYTES];
					view.read_prepared(&mut exact)?;
					let enrollment = selection.enrollment;
					let origin = match_managed_action_prepared(
						&exact,
						&expected,
						ManagedActivationPrepared {
							head: enrollment.prepared,
							extent: enrollment.prepared_extent,
						},
					)
					.map_err(Error::Origin)?;
					let recheck = || {
						view.recheck()
							.map_err(ManagedSyncPreviewError::PreparedCustody)
					};
					with_bound_history(
						HistoryCustody {
							policy: &policy,
							identity: &pin.identity,
							key: &key,
							read_root: view.history().read_root(),
							recheck_custody: &recheck,
						},
						|| view.recheck_roots().map_err(Error::Prepared),
						|| view.observe().map_err(Error::Prepared),
						false,
						&mut Some(|baseline, current, key, _| {
							let verified = BoundApproval {
								selection,
								input: input.approval,
								operation: ApprovalOperation::Verify {
									grant: input.grant,
									parent: input.parent,
									activation: input.activation,
									activation_digest: input.activation_digest,
								},
								roots,
								scratch,
								now: &now,
							}
							.verify(pin, baseline, current, key)?;
							let checked_at =
								check_time_after(enrollment, &now, verified.accepted_at)?;
							current.recheck_selection()?;
							let mut again = [0; MANAGED_ACTION_PREPARED_FRAME_BYTES];
							view.read_prepared(&mut again)?;
							if again != exact {
								return Err(Error::Selection);
							}
							let result = observe(PreparedRecreate {
								approval: &verified.artifacts,
								origin,
							})?;
							check_time_after(enrollment, &now, checked_at)?;
							current.recheck_selection()?;
							view.read_prepared(&mut again)?;
							if again != exact {
								return Err(Error::Selection);
							}
							Ok(result)
						}),
					)
				},
			)
		},
	)?;
	Ok(result)
}

fn origin_selection(
	selection: &ApprovalSelection<'_>,
	[slot, segment]: [[u8; 32]; 2],
) -> Result<ManagedActionPrepared, ApprovalError> {
	let (review, enrollment) = (selection.review, selection.enrollment);
	let [enrollment_id, allocation] = enrollment.origin_ids;
	let attempt = enrollment.attempt;
	Ok(ManagedActionPrepared {
		enrollment: enrollment_id,
		allocation,
		profile: enrollment.ordinary_owner.0,
		pair: review.pair,
		predecessor_generation: 1,
		predecessor_root: enrollment.predecessor,
		review_parent: review.parent_digest,
		reviewed_action: review.action,
		child: ManagedActivationChild {
			public_plan: ApprovedPublicPlanDigest::from_bytes(review.child_digest),
			public_entry: PublicPlanEntryId::from_bytes(*review.ids.entry.as_bytes())
				.map_err(|_| ApprovalError::Selection)?,
			private_plan: *enrollment.private_plan.as_bytes(),
			job: attempt.job,
			entry: attempt.entry,
			epoch: attempt.epoch,
		},
		slot,
		segment,
	})
}
