//! Read-only admission of explicitly selected authenticated synchronization history.

use core::{fmt, num::NonZeroU64};
use std::io::{self, Read};

use ed25519_dalek::{Signature, VerifyingKey};
use exacopy_endpoint::{MAX_INTERRUPTED_RETRIES, UnixComponent};
use exacopy_manifest::sync_baseline::{
	ExpectedSelection, LeafCommitment, LeafError, PairedBaselineLeaf, SideEvidence,
};
use exacopy_plan::workflow_sync::{
	EndpointFacts, MAX_CLOSURE_BYTES, MAX_MEMBER_BYTES, RootBody, WorkflowError, WorkflowKind,
	WorkflowRef, decode_endpoint, decode_envelope, decode_root, project_pair, scope_digest,
};

mod manual;

pub use manual::{SelectedSyncGenesisMember, inspect_selected_sync_genesis};

/// Independent historical selection. Values must come from owner-approved state.
#[derive(Clone, Copy)]
pub struct ExpectedSyncGenesis<'selection> {
	/// Exact selected root digest.
	pub root_digest: [u8; 32],
	/// Independently selected owner profile UUID.
	pub profile: [u8; 16],
	/// Expected owner profile revision.
	pub revision: NonZeroU64,
	/// Pinned ordinary owner public key.
	pub owner: &'selection VerifyingKey,
	/// Exact selected subject basename.
	pub subject: UnixComponent<'selection>,
	/// Independent named root expectations in left/right order.
	pub endpoints: [EndpointFacts<'selection>; 2],
	/// Independently selected historical scan, when known.
	pub scan: Option<NonZeroU64>,
}

/// Resolves one bounded member by its authenticated digest, kind and encoded length.
pub trait SyncGenesisResolver {
	/// Reader for precisely one immutable object.
	type Member<'resolver>: Read
	where
		Self: 'resolver;

	/// Opens a read-only view of the selected object.
	/// # Errors
	/// Reports unavailable or refused storage without falling back to an alternate object.
	fn open(&mut self, reference: WorkflowRef) -> io::Result<Self::Member<'_>>;
}

/// One fully inspected historical closure, with no live root or mutation capability.
pub struct AuthenticatedSyncGenesis<'root, 'selection> {
	digest: [u8; 32],
	root: RootBody<'root>,
	revision: NonZeroU64,
	endpoints: [EndpointFacts<'selection>; 2],
	sides: [SideEvidence; 2],
}

impl<'root, 'selection> AuthenticatedSyncGenesis<'root, 'selection> {
	/// Exact selected root digest.
	#[must_use]
	pub const fn digest(&self) -> [u8; 32] {
		self.digest
	}

	/// Authenticated historical selection, scope, scan and commitments.
	#[must_use]
	pub const fn root(&self) -> &RootBody<'root> {
		&self.root
	}

	/// Exact owner profile revision agreed by the authenticated endpoints.
	#[must_use]
	pub const fn profile_revision(&self) -> NonZeroU64 {
		self.revision
	}

	/// Historical endpoint selection, including exact rooted path and limits.
	#[must_use]
	pub const fn endpoints(&self) -> &[EndpointFacts<'selection>; 2] {
		&self.endpoints
	}

	/// Authenticated historical measurements. They are not current classifier inputs.
	#[must_use]
	pub const fn sides(&self) -> &[SideEvidence; 2] {
		&self.sides
	}
}

/// Refusal of an incomplete, unauthenticated or unselected closure.
#[derive(Debug)]
#[non_exhaustive]
pub enum SyncGenesisError {
	/// Malformed or noncanonical workflow syntax.
	Wire(WorkflowError),
	/// Refused independent selection or mismatching root/endpoint claims.
	Selection,
	/// Untrusted key or invalid signature.
	Signature,
	/// A commitment, unique identity, length, or aggregate bound failed.
	Closure,
	/// Member could not be opened or read.
	Read(io::Error),
	/// The manifest leaf failed its independent commitment or evidence checks.
	Leaf(LeafError),
}

impl fmt::Display for SyncGenesisError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::Wire(_) => "invalid synchronization workflow syntax",
			Self::Selection => "synchronization history differs from the independent selection",
			Self::Signature => "synchronization history signer or signature refused",
			Self::Closure => "synchronization history closure does not match its commitments",
			Self::Read(_) => "synchronization history member could not be read",
			Self::Leaf(_) => "paired synchronization evidence refused",
		})
	}
}

impl std::error::Error for SyncGenesisError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Wire(error) => Some(error),
			Self::Read(error) => Some(error),
			Self::Leaf(error) => Some(error),
			_ => None,
		}
	}
}

/// Verifies one complete historical generation-one closure.
/// Root verification and all root-local selection checks precede resolver access.
/// The result requires separate live readmission before use in a sync preview.
/// # Errors
/// Refuses mismatched selection, signatures, bounds, missing members and invalid leaf evidence.
pub fn verify_sync_genesis<'root, 'selection>(
	root_bytes: &'root [u8],
	expected: &ExpectedSyncGenesis<'selection>,
	resolver: &mut impl SyncGenesisResolver,
) -> Result<AuthenticatedSyncGenesis<'root, 'selection>, SyncGenesisError> {
	verify_sync_genesis_with_inventory(root_bytes, expected, resolver, |_, _| Ok(()))
}

fn verify_sync_genesis_with_inventory<'root, 'selection, Resolver: SyncGenesisResolver>(
	root_bytes: &'root [u8],
	expected: &ExpectedSyncGenesis<'selection>,
	resolver: &mut Resolver,
	check_inventory: impl FnOnce(&Resolver, [WorkflowRef; 3]) -> Result<(), SyncGenesisError>,
) -> Result<AuthenticatedSyncGenesis<'root, 'selection>, SyncGenesisError> {
	use SyncGenesisError as Error;

	let root = decode_root(authenticate(
		root_bytes,
		expected.owner,
		WorkflowKind::Root,
		expected.root_digest,
	)?)
	.map_err(Error::Wire)?;
	let pair = project_pair(
		expected.profile,
		expected.revision,
		expected.subject,
		expected.endpoints,
	)
	.map_err(|_| Error::Selection)?;
	let scope = scope_digest(
		pair,
		expected.owner.to_bytes(),
		root.endpoints.map(|member| member.digest),
		expected.endpoints.map(|data| data.location),
	);
	if root.profile != expected.profile
		|| root.name != expected.subject
		|| root.pair != pair.pair
		|| root.filter != pair.filter
		|| root.policy != pair.policy
		|| root.scope != scope
		|| expected.scan.is_some_and(|scan| scan != root.scan)
	{
		return Err(Error::Selection);
	}
	let [left, right] = root.endpoints;
	let refs = [left, right, root.leaf];
	let total = refs.iter().try_fold(root_bytes.len(), |sum, member| {
		sum.checked_add(usize::from(member.byte_len))
			.ok_or(Error::Closure)
	})?;
	if total > MAX_CLOSURE_BYTES
		|| refs
			.iter()
			.any(|member| member.digest == expected.root_digest)
		|| left.digest == right.digest
		|| left.digest == root.leaf.digest
		|| right.digest == root.leaf.digest
	{
		return Err(Error::Closure);
	}

	check_inventory(resolver, refs)?;

	let mut buffer = [0; MAX_MEMBER_BYTES];
	let mut ids = [root.id; 2];
	for ((reference, facts), last_id) in root
		.endpoints
		.into_iter()
		.zip(expected.endpoints)
		.zip(&mut ids)
	{
		let bytes = read_member(resolver, reference, &mut buffer)?;
		let endpoint = decode_endpoint(authenticate(
			bytes,
			expected.owner,
			reference.kind,
			reference.digest,
		)?)
		.map_err(Error::Wire)?;
		if endpoint.profile != expected.profile
			|| endpoint.revision != expected.revision
			|| endpoint.facts != facts
		{
			return Err(Error::Selection);
		}
		*last_id = endpoint.id;
	}
	if ids[0] == ids[1] || ids.contains(&root.id) {
		return Err(Error::Closure);
	}

	let leaf = PairedBaselineLeaf::verify(
		read_member(resolver, root.leaf, &mut buffer)?,
		LeafCommitment {
			digest: root.leaf.digest,
			kind: root.leaf.kind as u16,
			byte_len: u32::from(root.leaf.byte_len),
			item_count: 1,
		},
		ExpectedSelection {
			roots: pair.roots,
			name: expected.subject,
			scope_digest: scope,
			policy_digest: pair.policy,
			scan: root.scan,
		},
	)
	.map_err(Error::Leaf)?;
	let sides = *leaf.sides();
	let empty_digest = *blake3::hash(&[]).as_bytes();
	for (side, endpoint) in sides.into_iter().zip(expected.endpoints) {
		let id = side.measured.identity.file;
		if pair.roots.contains(&id)
			|| id == pair.parent
			|| side.length > endpoint.max_bytes
			|| (side.length == 0 && side.stream_digest != empty_digest)
		{
			return Err(Error::Closure);
		}
	}
	Ok(AuthenticatedSyncGenesis {
		digest: expected.root_digest,
		root,
		revision: expected.revision,
		endpoints: expected.endpoints,
		sides,
	})
}

fn authenticate<'bytes>(
	bytes: &'bytes [u8],
	owner: &VerifyingKey,
	kind: WorkflowKind,
	digest: [u8; 32],
) -> Result<&'bytes [u8], SyncGenesisError> {
	use SyncGenesisError as Error;
	let envelope = decode_envelope(bytes).map_err(Error::Wire)?;
	if !is_canonical_strong(owner) || owner.to_bytes() != envelope.public_key {
		return Err(Error::Signature);
	}
	let input = envelope.signing_input(kind);
	if *blake3::hash(&input).as_bytes() != digest {
		return Err(Error::Closure);
	}
	owner
		.verify_strict(&input, &Signature::from_bytes(&envelope.signature))
		.map_err(|_| Error::Signature)?;
	Ok(envelope.body)
}

fn read_member<'buffer>(
	resolver: &mut impl SyncGenesisResolver,
	reference: WorkflowRef,
	buffer: &'buffer mut [u8; MAX_MEMBER_BYTES],
) -> Result<&'buffer [u8], SyncGenesisError> {
	use SyncGenesisError as Error;
	let bytes = buffer
		.get_mut(..usize::from(reference.byte_len))
		.ok_or(Error::Closure)?;
	let reader = resolver.open(reference).map_err(Error::Read)?;
	read_exact_artifact(reader, bytes)
}

fn read_exact_artifact(mut reader: impl Read, bytes: &mut [u8]) -> Result<&[u8], SyncGenesisError> {
	use SyncGenesisError as Error;

	exacopy_endpoint::read_exact_at(0, bytes, |_, chunk| reader.read(chunk))
		.map_err(io::Error::other)
		.map_err(Error::Read)?;
	let mut probe = [0];
	for _ in 0..=MAX_INTERRUPTED_RETRIES {
		match reader.read(&mut probe) {
			Ok(0) => return Ok(bytes),
			Ok(_) => return Err(Error::Closure),
			Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
			Err(error) => return Err(Error::Read(error)),
		}
	}
	Err(Error::Read(io::ErrorKind::Interrupted.into()))
}

fn is_canonical_strong(key: &VerifyingKey) -> bool {
	!key.is_weak() && key.to_edwards().compress().to_bytes() == key.to_bytes()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn refuses_noncanonical_strong_owner_key_encoding() {
		let mut equivalent_keys = (2..19).filter_map(|y| {
			// Encode y + (2^255 - 19) with x sign zero. These are noncanonical y values.
			let mut bytes = [0xff; 32];
			bytes[0] = 0xed + y;
			bytes[31] = 0x7f;
			VerifyingKey::from_bytes(&bytes)
				.ok()
				.filter(|key| !key.is_weak())
		});
		let key = equivalent_keys.next().expect("synthetic strong key");
		assert!(!is_canonical_strong(&key));
		assert!(is_canonical_strong(
			&VerifyingKey::from_bytes(&key.to_edwards().compress().to_bytes()).unwrap()
		));
	}
}
