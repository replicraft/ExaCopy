use std::fmt;

use ed25519_dalek::VerifyingKey;
use exacopy_endpoint::linux_copy::{CopyDestinationView, TargetObservation};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_staging::{ExtendedAttributes, StagingSource};
use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_model::{
	RegularFileEvidence, SyncConflict, SyncObservation, SyncPathDecision, SyncSide,
};
use exacopy_plan::{PlanEntriesPage, PlanIdentityPlatform, UnixTimestamp};
use exacopy_platform::linux::{
	FileIdentity, NamedReadView, ReadError, SourceObservation, SyncPreviewEntry, SyncProfileStore,
};
use exacopy_transfer::copy_planning::{
	CreateNewRequest, PlanSelection, PlannedCopy, PlanningError,
	linux_baseline_metadata_policy_digest, plan_create_new_with_expiry,
};
use exacopy_transfer::linux::sync_preview::{
	FirstSyncPreview, HeldSyncPreview as _, MAX_PREVIEW_FILE_BYTES, preview_with_history,
};
use uuid::Uuid;

use crate::profile::root_id_for_key;

use crate::sync_preview::managed_policy::ManagedPolicyPin;

use super::{
	ManagedHistoryPreview, ManagedSyncPreviewError, ManagedSyncSelection, selected_store,
	with_history_view,
};

/// Independently chosen ordinary child Plan identifiers and manual conflict selection.
#[derive(Clone, Copy, Debug)]
pub struct ManualRecreatePlanIds {
	/// RFC UUIDv7 for the unsigned child Plan.
	pub plan: Uuid,
	/// Non-nil single entry identifier.
	pub entry: Uuid,
	/// Non-nil selected live source view identifier.
	pub source_view: Uuid,
	/// Non-nil content measurement identifier.
	pub measurement: Uuid,
	/// Caller-sampled observation time for this planning operation.
	pub observed_at: UnixTimestamp,
}

/// Association between the configured sync locator and the normal copy Plan alias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManualRecreateRoot {
	/// The managed scope's independently selected capability locator.
	pub managed_locator: [u8; 16],
	/// Device and inode observed under the retained managed lease.
	pub observed_identity: FileIdentity,
	/// Ordinary local Plan alias derived for that identity and the selected owner key.
	pub child_alias: Uuid,
}

/// Read-only proposal for one manual recreate under an authenticated common-present baseline.
///
/// The child Plan requires separate approval. All native values describe the completed
/// observation only.
#[derive(Debug)]
pub struct ManualRecreateCandidate {
	/// Exact acknowledged policy governing the observation.
	pub policy_digest: [u8; 32],
	/// Selected authenticated immutable baseline commitment.
	pub predecessor_digest: [u8; 32],
	/// Ordered root associations, left followed by right.
	pub roots: [ManualRecreateRoot; 2],
	/// Exact managed raw basename.
	pub subject: Vec<u8>,
	/// Explicitly selected surviving side.
	pub from: SyncSide,
	/// The current history-aware conflict that the caller elected to review.
	pub conflict: SyncConflict,
	/// Observed identity of the measured survivor.
	pub source_identity: FileIdentity,
	/// Freshly measured stream and required metadata of that survivor.
	pub source: RegularFileEvidence,
	/// Exact canonical unsigned create-new Plan and single entry page for review.
	pub child: PlannedCopy,
}

/// Reason a read-only manual recreate Plan could not be prepared.
#[derive(Debug)]
#[non_exhaustive]
pub enum ManualRecreateError {
	/// The acknowledged policy, baseline or held observations could not be established.
	Scope(ManagedSyncPreviewError),
	/// The reviewed direction or conflict differs from the fresh one-sided observation.
	ReviewChanged,
	/// The source would exceed the absent peer's complete future read ceiling.
	PeerFileLimit,
	/// The existing ordinary create-new planner refused the candidate.
	Plan(Box<PlanningError<ReadError, ManagedSyncPreviewError>>),
	/// The canonical child entry did not reproduce the measured scope and stream.
	PlanEvidence,
}

impl From<ManagedSyncPreviewError> for ManualRecreateError {
	fn from(error: ManagedSyncPreviewError) -> Self {
		Self::Scope(error)
	}
}

impl fmt::Display for ManualRecreateError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Scope(error) => error.fmt(formatter),
			Self::ReviewChanged => {
				formatter.write_str("the reviewed manual recreate conflict changed")
			}
			Self::PeerFileLimit => {
				formatter.write_str("recreate exceeds the absent root's read ceiling")
			}
			Self::Plan(error) => error.fmt(formatter),
			Self::PlanEvidence => {
				formatter.write_str("child Plan differs from the measured recreate scope")
			}
		}
	}
}

impl std::error::Error for ManualRecreateError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Scope(error) => Some(error),
			Self::Plan(error) => Some(error.as_ref()),
			_ => None,
		}
	}
}

/// Prepares an unsigned create-new child Plan for an explicitly reviewed deletion conflict.
///
/// The same read lease and original named survivor remain held through measurement and
/// Plan preparation. The absent side is rechecked without creating a job or stage.
///
/// # Errors
/// Refuses mismatched history, lease, root or subject, a different conflict or direction,
/// inadequate read ceilings, copy-policy refusal or changed Plan evidence.
pub fn prepare_manual_recreate(
	selection: &ManagedSyncSelection,
	from: SyncSide,
	reviewed: SyncConflict,
	ids: ManualRecreatePlanIds,
	scratch: &mut [u8],
) -> Result<ManualRecreateCandidate, ManualRecreateError> {
	let store = selected_store(selection)?;
	prepare_held(&store, &selection.pin, from, reviewed, ids, None, scratch)
}

pub(super) fn prepare_held(
	store: &SyncProfileStore,
	pin: &ManagedPolicyPin,
	from: SyncSide,
	reviewed: SyncConflict,
	ids: ManualRecreatePlanIds,
	expires_at: Option<UnixTimestamp>,
	scratch: &mut [u8],
) -> Result<ManualRecreateCandidate, ManualRecreateError> {
	with_history_view(store, pin, |baseline, current, key| {
		let preview = preview_with_history(baseline, current, scratch)
			.map_err(|error| ManagedSyncPreviewError::Preview(Box::new(error)))?;
		let (source, target, source_evidence) = held_choice(&preview, from, reviewed)?;
		let ends = &current.policy.endpoints;
		check_peer_limit(source_evidence, ends[target].max_bytes)?;
		let native = current
			.pair
			.recheck_history_subjects()
			.map_err(ManagedSyncPreviewError::Managed)?;
		let [left, right] = native.roots.map(|root| root.root);
		let roots = [
			root_binding(key, ends[0].root, left)?,
			root_binding(key, ends[1].root, right)?,
		];
		let [source_view, target_view] = [
			current.pair.entries()[source],
			current.pair.entries()[target],
		];
		let (SyncPreviewEntry::Present(view), SyncPreviewEntry::Absent) =
			(source_view, target_view)
		else {
			return Err(ManualRecreateError::ReviewChanged);
		};
		let subject = native.subject;
		let destination = AbsentTarget {
			view: current,
			identity: roots[target].observed_identity,
			subject,
			side: target,
		};
		let source_identity = view.identity();
		let request = CreateNewRequest {
			plan_id: ids.plan,
			entry_id: ids.entry,
			source_view_id: ids.source_view,
			measurement_id: ids.measurement,
			source: PlanSelection {
				root_id: roots[source].child_alias,
				component: subject,
			},
			destination: PlanSelection {
				root_id: roots[target].child_alias,
				component: subject,
			},
			observed_at: ids.observed_at,
		};
		let child = plan_create_new_with_expiry(
			request,
			expires_at,
			|name| {
				if name == subject {
					Ok(BorrowedSource(view))
				} else {
					Err(ReadError::IdentityChanged)
				}
			},
			|identity| identity == source_identity,
			&destination,
			scratch,
		)
		.map_err(|error| ManualRecreateError::Plan(Box::new(error)))?;
		check_child(&child, &request, source_identity, source_evidence)?;
		current.recheck_selection()?;
		Ok(ManualRecreateCandidate {
			policy_digest: pin.digest,
			predecessor_digest: baseline.digest(),
			roots,
			subject: subject.as_bytes().to_vec(),
			from,
			conflict: reviewed,
			source_identity,
			source: source_evidence,
			child,
		})
	})
}

fn held_choice(
	preview: &FirstSyncPreview,
	from: SyncSide,
	reviewed: SyncConflict,
) -> Result<(usize, usize, RegularFileEvidence), ManualRecreateError> {
	let (source, target, to) = match from {
		SyncSide::Left => (0, 1, SyncSide::Right),
		SyncSide::Right => (1, 0, SyncSide::Left),
	};
	let direction_matches = match reviewed {
		SyncConflict::DeletionAgainstUnchanged { absent } => absent == to,
		SyncConflict::EditAgainstDeletion { edited } => edited == from,
		_ => false,
	};
	if !direction_matches || preview.decision != SyncPathDecision::Conflict(reviewed) {
		return Err(ManualRecreateError::ReviewChanged);
	}
	match (preview.observations[source], preview.observations[target]) {
		(SyncObservation::Present(evidence), SyncObservation::AbsentObserved) => {
			Ok((source, target, evidence))
		}
		_ => Err(ManualRecreateError::ReviewChanged),
	}
}

fn check_peer_limit(
	source: RegularFileEvidence,
	peer_limit: u64,
) -> Result<(), ManualRecreateError> {
	if source.byte_len > peer_limit.min(MAX_PREVIEW_FILE_BYTES) {
		return Err(ManualRecreateError::PeerFileLimit);
	}
	Ok(())
}

fn root_binding(
	key: &VerifyingKey,
	managed_locator: [u8; 16],
	observed_identity: FileIdentity,
) -> Result<ManualRecreateRoot, ManagedSyncPreviewError> {
	let id =
		root_id_for_key(key, observed_identity).map_err(|_| ManagedSyncPreviewError::Selection)?;
	Ok(ManualRecreateRoot {
		managed_locator,
		observed_identity,
		child_alias: Uuid::from_bytes(*id.as_bytes()),
	})
}

fn check_child(
	child: &PlannedCopy,
	request: &CreateNewRequest<'_>,
	source: FileIdentity,
	evidence: RegularFileEvidence,
) -> Result<(), ManualRecreateError> {
	let entry = PlanEntriesPage::from_canonical_cbor(child.page_ref(), child.canonical_page())
		.map_err(|_| ManualRecreateError::PlanEvidence)?
		.entry();
	let matches_source = entry.source_identity.is_some_and(|identity| {
		identity.platform == PlanIdentityPlatform::Linux
			&& identity.volume_id == source.device().to_le_bytes()
			&& identity.object_id == source.inode().to_le_bytes()
			&& identity.generation.is_none()
	});
	if !matches_source
		|| entry.source.root_id != request.source.root_id
		|| entry.source.basename != request.source.component.as_bytes()
		|| entry.destination.root_id != request.destination.root_id
		|| entry.destination.basename != request.destination.component.as_bytes()
		|| entry.stream_length != evidence.byte_len
		|| entry.stream_digest != evidence.content_digest
		|| entry.metadata_policy_digest != linux_baseline_metadata_policy_digest()
	{
		return Err(ManualRecreateError::PlanEvidence);
	}
	Ok(())
}

struct AbsentTarget<'call, 'view, 'selection> {
	view: &'call ManagedHistoryPreview<'call, 'view, 'selection>,
	identity: FileIdentity,
	subject: UnixComponent<'selection>,
	side: usize,
}

impl CopyDestinationView for AbsentTarget<'_, '_, '_> {
	type Error = ManagedSyncPreviewError;

	fn identity(&self) -> JobFileIdentity {
		self.identity.into()
	}

	fn observe_target(&self, target: UnixComponent<'_>) -> Result<TargetObservation, Self::Error> {
		if self.subject != target || self.view.recheck_selection()?.subject != target {
			return Err(ManagedSyncPreviewError::Selection);
		}
		match self.view.pair.entries()[self.side] {
			SyncPreviewEntry::Absent => Ok(TargetObservation::Absent),
			_ => Ok(TargetObservation::Occupied),
		}
	}
}

struct BorrowedSource<'call, 'view>(&'call NamedReadView<'view>);

impl ReadView for BorrowedSource<'_, '_> {
	type Error = ReadError;

	fn length(&self) -> u64 {
		self.0.length()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.0.recheck_observation()
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		self.0.read_exact_at(offset, buffer)
	}
}

impl StagingSource for BorrowedSource<'_, '_> {
	type Identity = FileIdentity;
	type Metadata = SourceObservation;

	fn identity(&self) -> Self::Identity {
		self.0.identity()
	}

	fn metadata(&self) -> Self::Metadata {
		self.0.metadata()
	}

	fn extended_attributes(&self) -> Result<ExtendedAttributes, Self::Error> {
		self.0.extended_attributes()
	}

	fn recheck_metadata(&self) -> Result<(), Self::Error> {
		self.0.recheck_metadata()
	}
}

#[cfg(test)]
mod tests;
