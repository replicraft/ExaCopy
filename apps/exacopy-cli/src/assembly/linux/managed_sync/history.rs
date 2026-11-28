use std::io;
use std::num::NonZeroU16;

use ed25519_dalek::VerifyingKey;
use exacopy_plan::workflow_sync::{EndpointFacts, MAX_MEMBER_BYTES};
use exacopy_platform::linux::{
	ManagedSyncPreviewPair, ReadRoot, SyncHistoryDirectory, SyncHistoryLocation, SyncPreviewRoots,
	SyncProfileStoreRecord,
};
use exacopy_transfer::sync_genesis::{
	AuthenticatedSyncGenesis, ExpectedSyncGenesis, RetainedSyncGenesisMembers,
	SelectedSyncGenesisMember, inspect_selected_sync_genesis,
	inspect_selected_sync_genesis_retained,
};

use crate::sync_preview::managed_policy::{
	ManagedPolicy, ManagedPolicyIdentity, ManagedPolicyPin, decode,
};

use super::scope::{component, expected_native, fresh_endpoints, native_object, raw_path};
use super::{ManagedHistoryPreview, ManagedSyncPreviewError};

pub(super) fn authenticate<'root, 'selected>(
	read_root: &'selected ReadRoot,
	policy: &'selected ManagedPolicy,
	identity: &ManagedPolicyIdentity,
	key: &'selected VerifyingKey,
	endpoints: [EndpointFacts<'selected>; 2],
	root_bytes: &'root mut [u8; MAX_MEMBER_BYTES],
	retain: bool,
) -> Result<
	(
		AuthenticatedSyncGenesis<'root, 'selected>,
		Option<RetainedSyncGenesisMembers>,
	),
	ManagedSyncPreviewError,
> {
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
	let members = [member(first)?, member(second)?, member(third)?];
	let open = |locator| -> io::Result<_> { directory.open_member(locator) };
	if retain {
		inspect_selected_sync_genesis_retained(
			root,
			root_length,
			root_bytes,
			&expected,
			members,
			open,
		)
		.map(|(baseline, retained)| (baseline, Some(retained)))
	} else {
		inspect_selected_sync_genesis(root, root_length, root_bytes, &expected, members, open)
			.map(|baseline| (baseline, None))
	}
	.map_err(ManagedSyncPreviewError::History)
}

pub(super) fn with_held_history_view<T, E>(
	pin: &ManagedPolicyPin,
	record: &SyncProfileStoreRecord<'_>,
	key: &VerifyingKey,
	retain_history: bool,
	observe: impl FnOnce(
		&AuthenticatedSyncGenesis<'_, '_>,
		&ManagedHistoryPreview<'_, '_, '_>,
		&VerifyingKey,
		Option<RetainedSyncGenesisMembers>,
	) -> Result<T, E>,
) -> Result<T, E>
where
	E: From<ManagedSyncPreviewError>,
{
	type Failure = ManagedSyncPreviewError;

	let mut observe = Some(observe);
	let policy = decode(record.bytes(), pin).map_err(Failure::Policy)?;
	let scope = expected_native(&policy)?;
	let roots = SyncPreviewRoots::open(scope.parent_path, scope.roots.map(|root| root.name))
		.map_err(Failure::Native)?;
	let lease = roots
		.acquire_managed_history_lease(scope)
		.map_err(Failure::Managed)?;
	let history = record
		.open_history(raw_path(&policy.history.path))
		.map_err(Failure::Store)?;
	if native_object(history.read_root().identity())? != policy.history.directory {
		return Err(Failure::Selection.into());
	}
	let recheck_custody = || {
		record
			.recheck_history_scope(&history, &roots)
			.map_err(Failure::Store)
	};
	with_bound_history(
		HistoryCustody {
			policy: &policy,
			identity: &pin.identity,
			key,
			read_root: history.read_root(),
			recheck_custody: &recheck_custody,
		},
		|| {
			lease
				.recheck_roots()
				.map_err(|cause| Failure::Managed(cause).into())
		},
		|| {
			lease
				.observe()
				.map_err(|cause| Failure::Managed(cause).into())
		},
		retain_history,
		&mut observe,
	)
}

pub(super) struct HistoryCustody<'view, 'selection> {
	pub(super) policy: &'selection ManagedPolicy,
	pub(super) identity: &'view ManagedPolicyIdentity,
	pub(super) key: &'view VerifyingKey,
	pub(super) read_root: &'view ReadRoot,
	pub(super) recheck_custody: &'view dyn Fn() -> Result<(), ManagedSyncPreviewError>,
}

pub(super) fn with_bound_history<'view, 'selection, T, E>(
	custody: HistoryCustody<'view, 'selection>,
	recheck_roots: impl FnOnce() -> Result<[SyncHistoryLocation<'selection>; 2], E>,
	observe_pair: impl FnOnce() -> Result<ManagedSyncPreviewPair<'view, 'selection>, E>,
	retain_history: bool,
	observe: &mut Option<
		impl FnOnce(
			&AuthenticatedSyncGenesis<'_, '_>,
			&ManagedHistoryPreview<'_, '_, '_>,
			&VerifyingKey,
			Option<RetainedSyncGenesisMembers>,
		) -> Result<T, E>,
	>,
) -> Result<T, E>
where
	E: From<ManagedSyncPreviewError>,
{
	let HistoryCustody {
		policy,
		identity,
		key,
		read_root,
		recheck_custody,
	} = custody;
	recheck_custody()?;
	let mut root_bytes = [0; MAX_MEMBER_BYTES];
	let actual = recheck_roots()?;
	let endpoints = fresh_endpoints(policy, actual)?;
	let (baseline, retained) = authenticate(
		read_root,
		policy,
		identity,
		key,
		endpoints,
		&mut root_bytes,
		retain_history,
	)?;
	let pair = observe_pair()?;
	let current = ManagedHistoryPreview {
		pair: &pair,
		policy,
		identity,
		recheck_custody,
	};
	// Both callers supply one observer. Take it only after all preceding checks,
	// so on early refusal its captures remain owned by the outer scope.
	let observe = observe.take().expect("one managed history observer");
	let observed = observe(&baseline, &current, key, retained)?;
	recheck_custody()?;
	Ok(observed)
}
