//! Assemble one authenticated P063 closure in memory for a separately admitted writer.

use core::{fmt, num::NonZeroU64};
use std::io;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use exacopy_endpoint::UnixComponent;
use exacopy_manifest::sync_baseline::{
	ExpectedSelection, MAX_PAIRED_BASELINE_BYTES, SideEvidence, encode_matched_leaf,
};
use exacopy_plan::workflow_sync::{
	EncodedWorkflowBody, EncodedWorkflowRecord, EndpointBody, EndpointFacts, MAX_MEMBER_BYTES,
	RootBody, WorkflowKind, WorkflowRef, WorkflowTimestamp, encode_endpoint_body, encode_root_body,
	project_pair, scope_digest,
};

use super::{
	ExpectedSyncGenesis, SyncGenesisError as Error, SyncGenesisResolver, is_canonical_strong,
	verify_sync_genesis,
};

/// Independently selected claims for the measured generation-one pair.
#[derive(Clone, Copy, Debug)]
pub struct SyncGenesisSelection<'selection> {
	/// Selected owner profile UUID.
	pub profile: [u8; 16],
	/// Selected owner profile revision.
	pub revision: NonZeroU64,
	/// Independently selected ordinary owner public key.
	pub owner: &'selection VerifyingKey,
	/// Exact selected subject basename.
	pub subject: UnixComponent<'selection>,
	/// Admitted named root expectations in left/right order.
	pub endpoints: [EndpointFacts<'selection>; 2],
	/// Selected scan label for the measured pair.
	pub scan: NonZeroU64,
}

/// Caller-supplied record identity and signed creation metadata.
#[derive(Clone, Copy, Debug)]
pub struct SyncGenesisRecords {
	/// Fresh immutable UUIDv7 for the root record.
	pub root: [u8; 16],
	/// Fresh immutable UUIDv7s for the left and right endpoint records.
	pub endpoints: [[u8; 16]; 2],
	/// Signed creation metadata shared by the three records.
	pub created_at: WorkflowTimestamp,
}

/// A verified, bounded closure prepared in memory for a separate output operation.
pub struct AssembledSyncGenesis {
	root: EncodedWorkflowRecord,
	endpoints: [EncodedWorkflowRecord; 2],
	leaf: LeafArtifact,
}

impl AssembledSyncGenesis {
	/// Exact signed root envelope.
	#[must_use]
	pub fn root_bytes(&self) -> &[u8] {
		self.root.as_bytes()
	}

	/// Root record digest to retain with the independent selection.
	#[must_use]
	pub fn root_digest(&self) -> [u8; 32] {
		self.root.reference().digest
	}

	/// Exact child bytes and commitments in left endpoint, right endpoint, leaf order.
	#[must_use]
	pub fn members(&self) -> [(&[u8], WorkflowRef); 3] {
		let [left, right] = &self.endpoints;
		[
			(left.as_bytes(), left.reference()),
			(right.as_bytes(), right.reference()),
			(&self.leaf.bytes, self.leaf.reference),
		]
	}
}

impl fmt::Debug for AssembledSyncGenesis {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("AssembledSyncGenesis")
			.field("root", &self.root.reference())
			.field("members", &self.members().map(|(_, reference)| reference))
			.finish()
	}
}

struct LeafArtifact {
	reference: WorkflowRef,
	bytes: Box<[u8]>,
}

/// Assembles and verifies a P063 closure from an independently measured pair.
/// The caller supplies genuine live evidence and separately admits any output.
/// # Errors
/// Refuses mismatching selection, signer, evidence, record syntax or closure.
pub fn assemble_sync_genesis(
	selection: SyncGenesisSelection<'_>,
	records: SyncGenesisRecords,
	sides: [SideEvidence; 2],
	signer: &SigningKey,
) -> Result<AssembledSyncGenesis, Error> {
	if !is_canonical_strong(selection.owner)
		|| signer.verifying_key().to_bytes() != selection.owner.to_bytes()
	{
		return Err(Error::Signature);
	}
	let [left_id, right_id] = records.endpoints;
	if left_id == right_id || records.endpoints.contains(&records.root) {
		return Err(Error::Closure);
	}
	let pair = project_pair(
		selection.profile,
		selection.revision,
		selection.subject,
		selection.endpoints,
	)
	.map_err(|_| Error::Selection)?;
	let [left, right] = selection.endpoints;
	let left = endpoint(selection, left_id, left, records.created_at, signer)?;
	let right = endpoint(selection, right_id, right, records.created_at, signer)?;
	let endpoints = [left.reference(), right.reference()];
	let scope = scope_digest(
		pair,
		selection.owner.to_bytes(),
		endpoints.map(|reference| reference.digest),
		selection.endpoints.map(|endpoint| endpoint.location),
	);
	let leaf = leaf(
		ExpectedSelection {
			roots: pair.roots,
			name: selection.subject,
			scope_digest: scope,
			policy_digest: pair.policy,
			scan: selection.scan,
		},
		sides,
	)?;
	let root_body = RootBody {
		id: records.root,
		profile: selection.profile,
		pair: pair.pair,
		endpoints,
		filter: pair.filter,
		policy: pair.policy,
		scope,
		scan: selection.scan,
		name: selection.subject,
		leaf: leaf.reference,
	};
	let body = encode_root_body(&root_body, records.created_at).map_err(Error::Wire)?;
	let root = signed_record(body, signer)?;
	let assembled = AssembledSyncGenesis {
		root,
		endpoints: [left, right],
		leaf,
	};

	let expected = ExpectedSyncGenesis {
		root_digest: assembled.root_digest(),
		profile: selection.profile,
		revision: selection.revision,
		owner: selection.owner,
		subject: selection.subject,
		endpoints: selection.endpoints,
		scan: Some(selection.scan),
	};
	let mut resolver = ExactMembers(assembled.members());
	let verified = verify_sync_genesis(assembled.root_bytes(), &expected, &mut resolver)?;
	if verified.sides() != &sides {
		return Err(Error::Closure);
	}
	Ok(assembled)
}

fn endpoint(
	selection: SyncGenesisSelection<'_>,
	id: [u8; 16],
	facts: EndpointFacts<'_>,
	created_at: WorkflowTimestamp,
	signer: &SigningKey,
) -> Result<EncodedWorkflowRecord, Error> {
	let body = EndpointBody {
		id,
		profile: selection.profile,
		revision: selection.revision,
		facts,
	};
	let encoded = encode_endpoint_body(&body, created_at).map_err(Error::Wire)?;
	signed_record(encoded, signer)
}

fn leaf(selection: ExpectedSelection<'_>, sides: [SideEvidence; 2]) -> Result<LeafArtifact, Error> {
	let mut buffer = [0; MAX_PAIRED_BASELINE_BYTES];
	let (bytes, commitment) =
		encode_matched_leaf(selection, sides, &mut buffer).map_err(Error::Leaf)?;
	if bytes.is_empty() || bytes.len() > MAX_MEMBER_BYTES {
		return Err(Error::Closure);
	}
	let byte_len = u16::try_from(bytes.len()).map_err(|_| Error::Closure)?;
	let reference = WorkflowRef {
		digest: commitment.digest,
		kind: WorkflowKind::Leaf,
		byte_len,
	};
	Ok(LeafArtifact {
		reference,
		bytes: bytes.into(),
	})
}

fn signed_record(
	body: EncodedWorkflowBody,
	signer: &SigningKey,
) -> Result<EncodedWorkflowRecord, Error> {
	let signature: Signature = signer
		.try_sign(&body.signing_input())
		.map_err(|_| Error::Signature)?;
	body.attach_signature(signer.verifying_key().to_bytes(), signature.to_bytes())
		.map_err(Error::Wire)
}

struct ExactMembers<'bytes>([(&'bytes [u8], WorkflowRef); 3]);

impl SyncGenesisResolver for ExactMembers<'_> {
	type Member<'resolver>
		= &'resolver [u8]
	where
		Self: 'resolver;

	fn open(&mut self, reference: WorkflowRef) -> io::Result<Self::Member<'_>> {
		self.0
			.into_iter()
			.find_map(|(bytes, actual)| (actual == reference).then_some(bytes))
			.ok_or_else(|| io::ErrorKind::NotFound.into())
	}
}

#[cfg(test)]
mod tests;
