//! Read-only verification of the signed managed recreate review bundle.

use core::{fmt, num::NonZeroU16};
use std::io::Cursor;

use ed25519_dalek::Signature;
use exacopy_content::MAX_SCRATCH_BYTES;
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_model::{
	RegularFileEvidence, SyncBaseline, SyncConflict, SyncInventoryCompleteness, SyncObservation,
	SyncPathDecision, SyncSide, classify_two_way_path,
};
use exacopy_plan::workflow_sync::recreate::{
	RecreateAction, RecreateObservation, RecreateParent, RecreateReason, RecreateSide,
	action_reference, decode_action, decode_parent, observation_digests, parent_signing_input,
};
use exacopy_plan::workflow_sync::{
	MAX_MEMBER_BYTES, NativeObject, WorkflowError, WorkflowKind, WorkflowRef, decode_envelope,
};
use exacopy_plan::{PlanPath, UnixTimestamp};
use uuid::Uuid;

use crate::copy_planning::{CREATE_NEW, READ_CONTENT, linux_baseline_metadata_policy_digest};
use crate::linux::sync_preview::MAX_PREVIEW_FILE_BYTES;
use crate::public_plan::{ExpectedCopyPlan, PlanAdmissionError, admit_single_file_plan};

use super::{
	AuthenticatedSyncGenesis, ExpectedSyncGenesis, SelectedSyncGenesisMember, SyncGenesisError,
	inspect_selected_sync_genesis, is_canonical_strong,
};

/// Two trusted projections of one independently measured live survivor.
///
/// Derive both identities from the same held native file measurement. Neither
/// value may be taken from the untrusted package or from a distinct lookup.
/// The verifier compares each representation in its respective format.
#[derive(Clone, Copy, Debug)]
pub struct RecreateSourceEvidence {
	/// Native device components and inode used by workflow history.
	pub native: NativeObject,
	/// Raw Linux device and inode used by the ordinary child Plan.
	pub child: JobFileIdentity,
	/// Actual complete stream and required owner/mode measurement.
	pub stream: RegularFileEvidence,
}

/// Independent held-scope expectations for the serialized recreate proposal.
///
/// Supply the selected policy, identifiers, measured source and observed absence
/// before inspecting the bundle. The adapter maps both source identities from the
/// same native observation and derives both ordinary aliases from the held roots.
#[derive(Clone, Copy)]
pub struct ExpectedRecreateExport<'pin, 'name> {
	/// Independently admitted P063 trust, subject and live ordered endpoint facts.
	pub history: &'pin ExpectedSyncGenesis<'name>,
	/// Root, left endpoint, right endpoint and leaf references from the selected policy.
	pub predecessor: [WorkflowRef; 4],
	/// Digest of the independently selected canonical managed policy.
	pub policy_digest: [u8; 32],
	/// Independently selected stable workflow pair UUIDv7.
	pub pair_id: [u8; 16],
	/// Parent UUIDv7 allocated for this proposal.
	pub parent_id: [u8; 16],
	/// Separate action UUID for this proposal.
	pub action_id: [u8; 16],
	/// Exact digest of the independently prepared child Plan.
	pub child_digest: [u8; 32],
	/// Original shared creation sample of parent and child.
	pub created_at: UnixTimestamp,
	/// Exact planned exclusive deadline of parent and child.
	pub expires_at: UnixTimestamp,
	/// Independent wall-clock sample at serialized verification.
	pub now: UnixTimestamp,
	/// Independently derived ordinary root aliases, left then right.
	pub root_aliases: [Uuid; 2],
	/// Explicitly reviewed source side. The opposite name was independently observed absent.
	pub from: SyncSide,
	/// Exact independently reviewed conflict for this direction.
	pub reviewed: SyncConflict,
	/// Survivor observation from the held planning scope.
	pub source: RecreateSourceEvidence,
}

/// Checked commitments for a review proposal, carrying no effect or active-head authority.
#[derive(Debug)]
pub struct VerifiedRecreateExport {
	parent_digest: [u8; 32],
	predecessor_pair_digest: [u8; 32],
}

impl VerifiedRecreateExport {
	/// Returns the authenticated parent body commitment.
	#[must_use]
	pub const fn parent_digest(&self) -> [u8; 32] {
		self.parent_digest
	}

	/// Returns the selected predecessor's original 32-byte P063 pair digest.
	#[must_use]
	pub const fn predecessor_pair_digest(&self) -> [u8; 32] {
		self.predecessor_pair_digest
	}
}

/// A refused signed recreate export.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecreateExportError {
	/// A canonical member or the complete bundle exceeds its bound.
	Size,
	/// The workflow syntax or canonical page was refused.
	Wire(WorkflowError),
	/// The owner key or parent signature was refused.
	Signature,
	/// The original signed P063 closure could not be authenticated.
	History(SyncGenesisError),
	/// The authorized scope, measured conflict, or exact artifact binding differed.
	Binding,
	/// The proposed observation is misdated or the exclusive deadline has passed.
	Time,
	/// The ordinary child body or page was refused by its existing verifier.
	Child(PlanAdmissionError),
}

impl fmt::Display for RecreateExportError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Size => "recreate bundle exceeds its canonical member bounds",
			Self::Wire(_) => "invalid recreate workflow syntax",
			Self::Signature => "recreate workflow owner or signature refused",
			Self::History(_) => "recreate predecessor history refused",
			Self::Binding => "recreate bundle differs from the independent selection",
			Self::Time => "recreate bundle is misdated or expired",
			Self::Child(_) => "ordinary child Plan refused",
		})
	}
}

impl std::error::Error for RecreateExportError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Wire(error) => Some(error),
			Self::History(error) => Some(error),
			Self::Child(error) => Some(error),
			_ => None,
		}
	}
}

const MAX_BUNDLE_BYTES: usize = 8 * MAX_MEMBER_BYTES;

/// Checks the exact parent, action page, child body and page, and four predecessor members.
///
/// Pass them in that order, with predecessor members ordered root, left, right, leaf.
/// The supplied evidence derives separately from the held policy and measured roots.
/// This function authenticates historical bytes and checks consistency against those
/// observations. It does not reread the filesystem or admit an executable action.
///
/// # Errors
/// Rejects unbounded or malformed input, untrusted signing or history, contradictory
/// plan, action or observations, unsupported ordinary policy, and misdated or expired input.
pub fn verify_recreate_export(
	members: [&[u8]; 8],
	selected: &ExpectedRecreateExport<'_, '_>,
) -> Result<VerifiedRecreateExport, RecreateExportError> {
	use RecreateExportError as Error;

	let total = members
		.iter()
		.try_fold(0_usize, |sum, member| sum.checked_add(member.len()));
	if total.is_none_or(|total| total > MAX_BUNDLE_BYTES)
		|| members
			.iter()
			.any(|member| !(1..=MAX_MEMBER_BYTES).contains(&member.len()))
	{
		return Err(Error::Size);
	}
	let [
		parent_bytes,
		action_bytes,
		child_body,
		child_page,
		root,
		left,
		right,
		leaf,
	] = members;
	let envelope = decode_envelope(parent_bytes).map_err(Error::Wire)?;
	let owner = selected.history.owner;
	if !is_canonical_strong(owner) || envelope.public_key != owner.to_bytes() {
		return Err(Error::Signature);
	}
	let signed = parent_signing_input(envelope.body).map_err(Error::Wire)?;
	owner
		.verify_strict(&signed, &Signature::from_bytes(&envelope.signature))
		.map_err(|_| Error::Signature)?;
	let parent = decode_parent(envelope.body).map_err(Error::Wire)?;
	check_parent(&parent, selected)?;
	let [root_ref, left_ref, right_ref, leaf_ref] = selected.predecessor;
	let root_length = NonZeroU16::new(root_ref.byte_len).ok_or(Error::Binding)?;
	let mut root_buffer = [0; MAX_MEMBER_BYTES];
	let history = inspect_selected_sync_genesis(
		Cursor::new(root),
		root_length,
		&mut root_buffer,
		selected.history,
		[(left_ref, left), (right_ref, right), (leaf_ref, leaf)]
			.map(|(reference, locator)| SelectedSyncGenesisMember { reference, locator }),
		|bytes| Ok(Cursor::new(bytes)),
	)
	.map_err(Error::History)?;

	let action = decode_action(action_bytes).map_err(Error::Wire)?;
	let reference = action_reference(action_bytes).map_err(Error::Wire)?;
	let historical = history.root();
	let coverage = observation_digests(&RecreateObservation {
		pair_id: selected.pair_id,
		predecessor_pair: historical.pair,
		endpoints: [left_ref, right_ref],
		predecessor: root_ref,
		scope: historical.scope,
		policy_pin: selected.policy_digest,
		action_page: reference,
	})
	.map_err(Error::Wire)?;
	if historical.endpoints != [left_ref, right_ref]
		|| historical.leaf != leaf_ref
		|| parent.filter != historical.filter
		|| parent.policy != historical.policy
		|| parent.action_page != reference
		|| parent.coverage != coverage
	{
		return Err(Error::Binding);
	}
	let (source, target) = check_action(&action, selected, &history)?;
	check_child(child_body, child_page, &action, selected, source, target)?;
	Ok(VerifiedRecreateExport {
		parent_digest: *blake3::hash(&signed).as_bytes(),
		predecessor_pair_digest: historical.pair,
	})
}

fn check_parent(
	parent: &RecreateParent,
	selected: &ExpectedRecreateExport<'_, '_>,
) -> Result<(), RecreateExportError> {
	use RecreateExportError as Error;

	let [root, left, right, leaf] = selected.predecessor;
	if root.kind != WorkflowKind::Root
		|| root.digest != selected.history.root_digest
		|| left.kind != WorkflowKind::Endpoint
		|| right.kind != WorkflowKind::Endpoint
		|| leaf.kind != WorkflowKind::Leaf
		|| parent.predecessor != root
		|| parent.endpoints != [left, right]
		|| parent.profile != selected.history.profile
		|| parent.id != selected.parent_id
		|| parent.pair_id != selected.pair_id
		|| selected.root_aliases.iter().any(Uuid::is_nil)
		|| selected.root_aliases[0] == selected.root_aliases[1]
	{
		return Err(Error::Binding);
	}
	if parent.created_at != selected.created_at
		|| parent.expires_at != selected.expires_at
		|| selected.now < parent.created_at
		|| selected.now >= parent.expires_at
	{
		return Err(Error::Time);
	}
	Ok(())
}

fn check_action(
	action: &RecreateAction<'_>,
	selected: &ExpectedRecreateExport<'_, '_>,
	history: &AuthenticatedSyncGenesis<'_, '_>,
) -> Result<(usize, usize), RecreateExportError> {
	use RecreateExportError::Binding;
	use SyncObservation::{AbsentObserved, Present};

	let source = selected.source;
	let (side, from, to, observations) = match selected.from {
		SyncSide::Left => (
			RecreateSide::Left,
			0,
			1,
			[Present(source.stream), AbsentObserved],
		),
		SyncSide::Right => (
			RecreateSide::Right,
			1,
			0,
			[AbsentObserved, Present(source.stream)],
		),
	};
	let previous = history.sides()[0];
	let baseline = SyncBaseline::CommonPresent(RegularFileEvidence {
		byte_len: previous.length,
		content_digest: previous.stream_digest,
		required_metadata_digest: previous.metadata_digest,
	});
	let actual = classify_two_way_path(
		SyncInventoryCompleteness::Complete,
		baseline,
		observations[0],
		observations[1],
	);
	let reason = match actual {
		SyncPathDecision::Conflict(conflict) if conflict == selected.reviewed => match conflict {
			SyncConflict::DeletionAgainstUnchanged { .. } => {
				RecreateReason::DeletionAgainstUnchanged
			}
			SyncConflict::EditAgainstDeletion { .. } => RecreateReason::EditAgainstDeletion,
			_ => return Err(Binding),
		},
		_ => return Err(Binding),
	};
	let limit = selected
		.history
		.endpoints
		.iter()
		.fold(MAX_PREVIEW_FILE_BYTES, |limit, endpoint| {
			limit.min(endpoint.max_bytes)
		});
	if action.id != selected.action_id
		|| action.id == selected.parent_id
		|| action.side != side
		|| action.reason != reason
		|| action.name != selected.history.subject
		|| action.source != source.native
		|| action.stream_length != source.stream.byte_len
		|| action.stream_length > limit
		|| action.stream_digest != source.stream.content_digest
		|| action.metadata_digest != source.stream.required_metadata_digest
		|| action.child_digest != selected.child_digest
		|| source.child.inode != source.native.inode.get()
	{
		return Err(Binding);
	}
	Ok((from, to))
}

fn check_child(
	body: &[u8],
	page: &[u8],
	action: &RecreateAction<'_>,
	selected: &ExpectedRecreateExport<'_, '_>,
	from: usize,
	to: usize,
) -> Result<(), RecreateExportError> {
	use RecreateExportError as Error;

	let path = |side: usize| PlanPath {
		root_id: selected.root_aliases[side],
		basename: selected.history.subject.as_bytes(),
	};
	let admitted = admit_single_file_plan(
		body,
		page,
		ExpectedCopyPlan {
			digest: selected.child_digest,
			source: path(from),
			destination: path(to),
			metadata_policy_digest: linux_baseline_metadata_policy_digest(),
			now: selected.now,
		},
	)
	.map_err(Error::Child)?;
	let fields = admitted.body().fields();
	let child_id = fields.plan_id.into_bytes();
	let entry = admitted.entry();
	let identity = entry.source_identity.ok_or(Error::Binding)?;
	let source = selected.source.child;
	if fields.created_at != selected.created_at
		|| fields.expires_at != Some(selected.expires_at)
		|| fields.source_views[0].observed_at != selected.created_at
		|| fields.source_views[0].provider != "linux-local"
		|| fields.required_grants != [READ_CONTENT, CREATE_NEW]
		|| fields.resource_limits.io_inflight_max() != 1
		|| !usize::try_from(fields.resource_limits.buffer_budget_bytes())
			.is_ok_and(|bytes| (1..=MAX_SCRATCH_BYTES).contains(&bytes))
		|| fields.estimated_working_bytes != action.stream_length
		|| entry.estimated_working_bytes != action.stream_length
		|| fields.entry_pages != [action.child_page]
		|| child_id == selected.parent_id
		|| child_id == selected.action_id
		|| identity.volume_id != source.device.to_le_bytes()
		|| identity.object_id != source.inode.to_le_bytes()
		|| entry.stream_length != action.stream_length
		|| entry.stream_digest != action.stream_digest
	{
		return Err(Error::Binding);
	}
	Ok(())
}
