use std::io;
use std::num::NonZeroU16;

use ed25519_dalek::VerifyingKey;
use exacopy_plan::workflow_sync::{EndpointFacts, MAX_MEMBER_BYTES};
use exacopy_platform::linux::{ReadRoot, SyncHistoryDirectory};
use exacopy_transfer::sync_genesis::{
	AuthenticatedSyncGenesis, ExpectedSyncGenesis, SelectedSyncGenesisMember,
	inspect_selected_sync_genesis,
};

use crate::sync_preview::managed_policy::{ManagedPolicy, ManagedPolicyIdentity};

use super::ManagedSyncPreviewError;
use super::scope::component;

pub(super) fn authenticate<'root, 'selected>(
	read_root: &'selected ReadRoot,
	policy: &'selected ManagedPolicy,
	identity: &ManagedPolicyIdentity,
	key: &'selected VerifyingKey,
	endpoints: [EndpointFacts<'selected>; 2],
	root_bytes: &'root mut [u8; MAX_MEMBER_BYTES],
) -> Result<AuthenticatedSyncGenesis<'root, 'selected>, ManagedSyncPreviewError> {
	let history = &policy.history;
	let member_limit =
		u16::try_from(MAX_MEMBER_BYTES).map_err(|_| ManagedSyncPreviewError::Selection)?;
	let directory = SyncHistoryDirectory::new(read_root, member_limit);
	let root_length = NonZeroU16::new(history.root.reference.byte_len)
		.ok_or(ManagedSyncPreviewError::Selection)?;
	let subject = component(&policy.subject)?;
	let root = directory
		.open_member(component(&history.root.name)?)
		.map_err(ManagedSyncPreviewError::ReadHistory)?;
	// The signed root establishes endpoint order. This inventory only binds
	// each exact authenticated commitment to its independently selected raw name.
	let [first, second, third] = &history.children;
	let member =
		|selected: &'selected crate::sync_preview::managed_policy::ManagedHistoryMember| {
			Ok::<_, ManagedSyncPreviewError>(SelectedSyncGenesisMember {
				reference: selected.reference,
				locator: component(&selected.name)?,
			})
		};
	let expected = ExpectedSyncGenesis {
		root_digest: history.root.reference.digest,
		profile: identity.owner_profile,
		revision: history.revision,
		owner: key,
		subject,
		endpoints,
		scan: history.scan,
	};
	inspect_selected_sync_genesis(
		root,
		root_length,
		root_bytes,
		&expected,
		[member(first)?, member(second)?, member(third)?],
		|locator| -> io::Result<_> { directory.open_member(locator) },
	)
	.map_err(ManagedSyncPreviewError::History)
}
