use core::num::NonZeroU16;
use std::io::{self, Read};

use exacopy_plan::workflow_sync::{MAX_MEMBER_BYTES, WorkflowError, WorkflowRef};

use super::{
	AuthenticatedSyncGenesis, ExpectedSyncGenesis, SyncGenesisError, SyncGenesisResolver,
	read_exact_artifact, verify_sync_genesis_with_inventory,
};

/// One manually selected read-only resource for a historical child commitment.
///
/// A locator selects a resource independently of the signed artifact. It is
/// interpreted only by the supplied reader opener. It carries no historical
/// trust, live root authority, or mutation grant.
pub struct SelectedSyncGenesisMember<Locator> {
	/// Full reference of the selected endpoint envelope or paired leaf.
	pub reference: WorkflowRef,
	/// Caller-supplied resource locator, consumed on first use.
	pub locator: Locator,
}

/// Authenticates exactly one manually selected generation-one history closure.
///
/// The caller pins owner, profile revision, canonical root digest, subject,
/// and ordered endpoint expectations from an independent trusted selection.
/// The root is read from its start through its exact declared extent and EOF.
/// Root-local authentication and selection checks precede any child opener
/// call. All three selected references must match the authenticated inventory
/// before any child is opened. Each commitment then consumes one locator,
/// regardless of inventory order. The opener returns a read-only view from byte zero.
///
/// Success verifies historical completeness for this one subject under the
/// recorded scope. It supplies no fresh inventory or authority to select a
/// current baseline, readmit roots, create a seed, or apply a sync operation.
///
/// # Errors
/// Refuses oversized or inexact root input, unauthenticated or mismatched root
/// claims, missing or mismatched child resources, and invalid paired evidence.
pub fn inspect_selected_sync_genesis<'root, 'selection, Locator, Reader>(
	root: impl Read,
	root_length: NonZeroU16,
	root_buffer: &'root mut [u8; MAX_MEMBER_BYTES],
	expected: &ExpectedSyncGenesis<'selection>,
	members: [SelectedSyncGenesisMember<Locator>; 3],
	open_member: impl FnMut(Locator) -> io::Result<Reader>,
) -> Result<AuthenticatedSyncGenesis<'root, 'selection>, SyncGenesisError>
where
	Reader: Read,
{
	inspect_selected(
		root,
		root_length,
		root_buffer,
		expected,
		members,
		open_member,
		|_, _| {},
	)
}

/// Exact canonical members retained by one successful authenticated selection.
pub struct RetainedSyncGenesisMembers([Vec<u8>; 4]);

impl RetainedSyncGenesisMembers {
	/// Returns the root, left endpoint, right endpoint and leaf in signed order.
	#[must_use]
	pub fn members(&self) -> [&[u8]; 4] {
		self.0.each_ref().map(Vec::as_slice)
	}
}

/// Authenticates an exact selected genesis closure and retains the original member bytes.
///
/// As in [`inspect_selected_sync_genesis`], root admission and the independent named
/// inventory precede child opens. Each retained member is copied from the same
/// verified buffer, with no second read or path resolution.
///
/// # Errors
/// Refuses incomplete or mismatched resources, malformed bytes and untrusted history.
pub fn inspect_selected_sync_genesis_retained<'root, 'selection, Locator, Reader>(
	root: impl Read,
	root_length: NonZeroU16,
	root_buffer: &'root mut [u8; MAX_MEMBER_BYTES],
	expected: &ExpectedSyncGenesis<'selection>,
	members: [SelectedSyncGenesisMember<Locator>; 3],
	open_member: impl FnMut(Locator) -> io::Result<Reader>,
) -> Result<
	(
		AuthenticatedSyncGenesis<'root, 'selection>,
		RetainedSyncGenesisMembers,
	),
	SyncGenesisError,
>
where
	Reader: Read,
{
	let mut retained = [const { Vec::new() }; 4];
	let authenticated = inspect_selected(
		root,
		root_length,
		root_buffer,
		expected,
		members,
		open_member,
		|index, bytes| retained[index].extend_from_slice(bytes),
	)?;
	Ok((authenticated, RetainedSyncGenesisMembers(retained)))
}

fn inspect_selected<'root, 'selection, Locator, Reader>(
	root: impl Read,
	root_length: NonZeroU16,
	root_buffer: &'root mut [u8; MAX_MEMBER_BYTES],
	expected: &ExpectedSyncGenesis<'selection>,
	members: [SelectedSyncGenesisMember<Locator>; 3],
	open_member: impl FnMut(Locator) -> io::Result<Reader>,
	retain: impl FnMut(usize, &[u8]),
) -> Result<AuthenticatedSyncGenesis<'root, 'selection>, SyncGenesisError>
where
	Reader: Read,
{
	let bytes = root_buffer
		.get_mut(..usize::from(root_length.get()))
		.ok_or(SyncGenesisError::Wire(WorkflowError::Size))?;
	let root = read_exact_artifact(root, bytes)?;
	let mut resolver = SelectedMembers {
		members: members.map(Some),
		open_member,
	};
	verify_sync_genesis_with_inventory(
		root,
		expected,
		&mut resolver,
		SelectedMembers::check,
		retain,
	)
}

struct SelectedMembers<Locator, Open> {
	members: [Option<SelectedSyncGenesisMember<Locator>>; 3],
	open_member: Open,
}

impl<Locator, Open> SelectedMembers<Locator, Open> {
	fn check(&self, authenticated: [WorkflowRef; 3]) -> Result<(), SyncGenesisError> {
		// The authenticated references are distinct and both inventories have
		// exactly three slots, so covering each one establishes exact membership.
		if authenticated.iter().all(|reference| {
			self.members
				.iter()
				.flatten()
				.any(|member| &member.reference == reference)
		}) {
			Ok(())
		} else {
			Err(SyncGenesisError::Closure)
		}
	}
}

impl<Locator, Open, Reader> SyncGenesisResolver for SelectedMembers<Locator, Open>
where
	Open: FnMut(Locator) -> io::Result<Reader>,
	Reader: Read,
{
	type Member<'resolver>
		= Reader
	where
		Self: 'resolver;

	fn open(&mut self, reference: WorkflowRef) -> io::Result<Self::Member<'_>> {
		let available = self.members.iter_mut().find(|member| {
			member
				.as_ref()
				.is_some_and(|member| member.reference == reference)
		});
		let member = available
			.and_then(Option::take)
			.ok_or(io::ErrorKind::NotFound)?;
		(self.open_member)(member.locator)
	}
}
