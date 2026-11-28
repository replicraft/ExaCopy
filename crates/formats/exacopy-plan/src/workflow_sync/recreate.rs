//! Canonical review-only SyncPlan and action page for one managed recreate.

use exacopy_core::UnixComponent;

use super::{
	MAX_MEMBER_BYTES, NativeObject, WorkflowError, WorkflowKind, WorkflowRef, signing_input,
};
use crate::{DocumentPageKind, DocumentRef, UnixTimestamp};

mod decoder;
mod writer;

pub use decoder::{decode_action, decode_parent};
pub use writer::{encode_action, encode_parent, encode_parent_envelope, observation_digests};

const VERSION: [u64; 2] = [1, 0];
const PARENT_KIND: u16 = 5;
const ACTION_PAGE_VERSION: [u64; 2] = [1, 0];
const ACTION_PAGE_KIND: u16 = 0x0101;
const REQUIRED_FEATURES: u64 = 69;
const MAX_STREAM_BYTES: u64 = 64 * 1024 * 1024;
const ACTION_DOMAIN: &[u8] = b"ExaCopy/workflow-page/v1\0";
const OBSERVATION_DOMAIN: &[u8] = b"ExaCopy/sync-recreate-observation/v1\0";

/// Exact digest and extent of a singleton review-only recreate action page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecreateActionRef {
	/// Digest in the workflow-page domain for kind 0x0101.
	pub digest: [u8; 32],
	/// Exact canonical page extent.
	pub byte_len: u16,
}

/// Canonical review-only kind-5 syntax before signer or closure verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecreateParent {
	/// Parent Plan UUIDv7.
	pub id: [u8; 16],
	/// Declared owner profile.
	pub profile: [u8; 16],
	/// Independently selected pair UUIDv7.
	pub pair_id: [u8; 16],
	/// Left and right authenticated predecessor endpoint references, in order.
	pub endpoints: [WorkflowRef; 2],
	/// Exact P-063 genesis root reference.
	pub predecessor: WorkflowRef,
	/// Historical subject filter commitment.
	pub filter: [u8; 32],
	/// Historical comparison and metadata policy commitment.
	pub policy: [u8; 32],
	/// Left and right one-subject observation commitments, in order.
	pub coverage: [[u8; 32]; 2],
	/// Exact action page reference.
	pub action_page: RecreateActionRef,
	/// Authored creation time.
	pub created_at: UnixTimestamp,
	/// Exclusive expiry that must also be checked against the ordinary child.
	pub expires_at: UnixTimestamp,
}

/// Ordered source side in the selected managed pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecreateSide {
	/// Copy from the left root to the absent right subject.
	Left = 0,
	/// Copy from the right root to the absent left subject.
	Right = 1,
}

/// Managed deletion conflict explicitly selected for this proposed recreate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecreateReason {
	/// One side was deleted while the retained side is unchanged.
	DeletionAgainstUnchanged = 0,
	/// One side was deleted while the retained side was edited.
	EditAgainstDeletion = 1,
}

/// The sole create-new action, without a delegated grant or effect authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecreateAction<'name> {
	/// Nonzero action UUID.
	pub id: [u8; 16],
	/// Side containing the independently measured survivor.
	pub side: RecreateSide,
	/// Exact raw basename selected on both roots.
	pub name: UnixComponent<'name>,
	/// Observed Linux source scoped by the selected source endpoint.
	pub source: NativeObject,
	/// Measured extent in bytes.
	pub stream_length: u64,
	/// Ordinary BLAKE3 digest of the survivor's data stream.
	pub stream_digest: [u8; 32],
	/// Measured required owner and mode digest.
	pub metadata_digest: [u8; 32],
	/// Exact ordinary child Plan body commitment.
	pub child_digest: [u8; 32],
	/// Exact ordinary child Plan entry page reference.
	pub child_page: DocumentRef,
	/// Explicitly selected conflict that motivated the proposed action.
	pub reason: RecreateReason,
}

/// Inputs to the two side-specific completeness commitments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecreateObservation {
	/// Independently selected pair UUIDv7.
	pub pair_id: [u8; 16],
	/// Authenticated P-063 pair digest.
	pub predecessor_pair: [u8; 32],
	/// Exact left and right endpoint references, in order.
	pub endpoints: [WorkflowRef; 2],
	/// Exact P-063 root reference.
	pub predecessor: WorkflowRef,
	/// Authenticated P-063 observation scope.
	pub scope: [u8; 32],
	/// Independently approved canonical managed policy digest.
	pub policy_pin: [u8; 32],
	/// Action page committing the observed facts at export.
	pub action_page: RecreateActionRef,
}

/// Builds the kind-5 signature input and digest preimage from exact canonical bytes.
///
/// # Errors
/// Refuses out-of-bounds, unsupported or noncanonical parent bytes.
pub fn parent_signing_input(body: &[u8]) -> Result<Vec<u8>, WorkflowError> {
	decode_parent(body)?;
	Ok(signing_input(PARENT_KIND, body))
}

/// Computes an exact kind-0x0101 reference after checking the canonical page syntax.
///
/// # Errors
/// Refuses out-of-bounds, unsupported or noncanonical action bytes.
pub fn action_reference(bytes: &[u8]) -> Result<RecreateActionRef, WorkflowError> {
	decode_action(bytes)?;
	let byte_len = u16::try_from(bytes.len()).map_err(|_| WorkflowError::Size)?;
	let digest = *blake3::Hasher::new()
		.update(ACTION_DOMAIN)
		.update(&ACTION_PAGE_KIND.to_le_bytes())
		.update(&u64::from(byte_len).to_le_bytes())
		.update(bytes)
		.finalize()
		.as_bytes();
	Ok(RecreateActionRef { digest, byte_len })
}

fn validate_references(
	endpoints: [WorkflowRef; 2],
	predecessor: WorkflowRef,
	action_page: RecreateActionRef,
) -> Result<(), WorkflowError> {
	for reference in endpoints {
		super::writer::validate_reference(reference, WorkflowKind::Endpoint)?;
	}
	super::writer::validate_reference(predecessor, WorkflowKind::Root)?;
	if !(1..=MAX_MEMBER_BYTES as u16).contains(&action_page.byte_len) {
		return Err(WorkflowError::Size);
	}
	Ok(())
}

fn validate_times_and_pair(
	pair_id: [u8; 16],
	created_at: UnixTimestamp,
	expires_at: UnixTimestamp,
	coverage: [[u8; 32]; 2],
) -> Result<(), WorkflowError> {
	if !super::wire::is_record_id(pair_id) || expires_at <= created_at || coverage[0] == coverage[1]
	{
		return Err(WorkflowError::Shape);
	}
	Ok(())
}

fn validate_action(action: &RecreateAction<'_>) -> Result<u16, WorkflowError> {
	if action.id == [0; 16]
		|| action.child_page.kind() != DocumentPageKind::PlanEntries
		|| action.child_page.item_count() != 1
	{
		return Err(WorkflowError::Shape);
	}
	if action.stream_length > MAX_STREAM_BYTES
		|| action.child_page.encoded_bytes() > MAX_MEMBER_BYTES as u32
	{
		return Err(WorkflowError::Size);
	}
	u16::try_from(action.child_page.encoded_bytes()).map_err(|_| WorkflowError::Size)
}
