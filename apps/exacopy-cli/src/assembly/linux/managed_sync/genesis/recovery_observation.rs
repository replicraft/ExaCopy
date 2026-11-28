//! Read-only observation of one independently selected managed genesis attempt.

use std::io::{self, Cursor};
use std::path::Path;

use exacopy_plan::workflow_sync::{MAX_MEMBER_BYTES, NativeObject, WorkflowKind, WorkflowRef};
use exacopy_platform::linux::{
	SyncGenesisIntent, SyncGenesisNativeIdentity, SyncGenesisOperation, SyncGenesisOutput,
	SyncGenesisRecoveryExpectation, SyncGenesisRecoveryObservation, SyncGenesisRecoverySession,
	SyncProfileStoreError,
};
use exacopy_transfer::sync_genesis::{
	ExpectedSyncGenesis, SelectedSyncGenesisMember, inspect_selected_sync_genesis,
};

use crate::profile::profile_id_for_key;

#[cfg(test)]
mod tests;

/// Independently retained exact evidence for one original managed genesis attempt.
///
/// Every value comes from a separately trusted selection. A retained intent
/// read from the observed slots cannot supply these independent pins.
#[derive(Clone, Copy)]
pub struct ManagedGenesisRecoveryBasis<'selection> {
	/// Exact expected approval and four canonical and raw member commitments.
	pub intent: &'selection SyncGenesisIntent,
	/// Independently retained original stage identity.
	pub stage: SyncGenesisNativeIdentity,
	/// Exact independently chosen owner, native historical scope and history digest.
	pub history: &'selection ExpectedSyncGenesis<'selection>,
}

/// Observes the selected operation's current private namespace without opening a seed.
///
/// Missing independent pins permit bounded occupancy only. The current producer
/// does not export an independent pre-effect basis on failure. Recovery with only
/// that error cannot claim an exact closure or infer an acknowledgement. Positive
/// closure evidence requires the independent original stage identity and remaining
/// pins. This SDK matches the raw member digests and authenticates the selected
/// P-063 closure while the platform holds
/// the observed resources. Device and inode equality describes the current match to
/// the retained pin and does not establish continuity across an unheld interval.
///
/// # Errors
/// Refuses unavailable protected custody, invalid independent selection, or changed
/// slot observations. A stable but unresolved state is returned as advisory evidence.
pub fn observe_managed_genesis_recovery(
	output_parent: &Path,
	output_identity: SyncGenesisNativeIdentity,
	operation: SyncGenesisOperation,
	basis: Option<ManagedGenesisRecoveryBasis<'_>>,
) -> Result<SyncGenesisRecoveryObservation, SyncProfileStoreError> {
	let expected = basis.map(check_basis).transpose()?;
	let output = SyncGenesisOutput::open(output_parent, output_identity)?;
	output.observe_recovery(operation, expected, |members| {
		let basis =
			basis.ok_or_else(|| io::Error::other("missing independent genesis evidence"))?;
		verify_history(members, basis)
	})
}

fn check_basis<'selection>(
	basis: ManagedGenesisRecoveryBasis<'selection>,
) -> Result<SyncGenesisRecoveryExpectation<'selection>, SyncProfileStoreError> {
	let expected = basis.history;
	let owner = expected.owner;
	if owner.is_weak() || owner.to_edwards().compress().to_bytes() != owner.to_bytes() {
		return Err(SyncProfileStoreError::InvalidSelection);
	}
	let profile = profile_id_for_key(owner).map_err(|_| SyncProfileStoreError::InvalidSelection)?;
	let [left, right] = expected.endpoints.map(|endpoint| endpoint.location);
	if profile.as_bytes() != &expected.profile
		|| expected.scan.is_none()
		|| basis.intent.members[0].canonical_digest != expected.root_digest
		|| left
			!= (exacopy_plan::workflow_sync::LinuxLocation {
				root: left.root,
				..right
			}) {
		return Err(SyncProfileStoreError::InvalidSelection);
	}
	Ok(SyncGenesisRecoveryExpectation {
		intent: basis.intent,
		stage: basis.stage,
		session: SyncGenesisRecoverySession {
			boot: left.boot,
			mount_namespace: native_identity(left.mount_namespace),
			user_namespace: native_identity(left.user_namespace),
			unique_mount: left.mount,
		},
	})
}

fn native_identity(object: NativeObject) -> SyncGenesisNativeIdentity {
	SyncGenesisNativeIdentity::from_device_numbers(object.major, object.minor, object.inode)
}

fn verify_history(
	[root, left, right, leaf]: [&[u8]; 4],
	basis: ManagedGenesisRecoveryBasis<'_>,
) -> io::Result<()> {
	for (bytes, binding) in [root, left, right, leaf]
		.into_iter()
		.zip(basis.intent.members)
	{
		if *blake3::hash(bytes).as_bytes() != binding.raw_digest {
			return Err(io::Error::other("retained genesis member digest differs"));
		}
	}
	let [root_binding, left_binding, right_binding, leaf_binding] = basis.intent.members;
	let [left_reference, right_reference, leaf_reference] = [
		(WorkflowKind::Endpoint, left_binding),
		(WorkflowKind::Endpoint, right_binding),
		(WorkflowKind::Leaf, leaf_binding),
	]
	.map(|(kind, binding)| WorkflowRef {
		kind,
		digest: binding.canonical_digest,
		byte_len: binding.byte_len.get(),
	});
	let mut root_buffer = [0; MAX_MEMBER_BYTES];
	let checked = inspect_selected_sync_genesis(
		Cursor::new(root),
		root_binding.byte_len,
		&mut root_buffer,
		basis.history,
		[
			SelectedSyncGenesisMember {
				reference: left_reference,
				locator: left,
			},
			SelectedSyncGenesisMember {
				reference: right_reference,
				locator: right,
			},
			SelectedSyncGenesisMember {
				reference: leaf_reference,
				locator: leaf,
			},
		],
		|bytes| Ok(Cursor::new(bytes)),
	)
	.map_err(io::Error::other)?;
	let root = checked.root();
	if root.endpoints != [left_reference, right_reference] || root.leaf != leaf_reference {
		return Err(io::Error::other(
			"managed genesis recovery members are out of order",
		));
	}
	Ok(())
}
