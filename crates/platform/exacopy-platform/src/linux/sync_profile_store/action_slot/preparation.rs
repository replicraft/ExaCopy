use std::io;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::Path;

use exacopy_endpoint::UnixComponent;
use rustix::{fs, process};

use crate::linux::sync_preview::unique_mount_id;
use crate::linux::{
	FileIdentity, ManagedSyncExpectedObject, ManagedSyncNativeScope, ManagedSyncPreviewPair,
	SyncHistoryLocation, SyncPreviewRoots, SyncProfileHistory, SyncProfileStoreError,
	SyncProfileStoreRecord,
};

use super::{
	Error, HeldActionSlot, PreparedActionSlotSelection, PreparedManagedActionError, mount_id,
};

/// Scoped read-only preparation of one selected managed action.
pub struct PreparedManagedActionView<'held, 'selection> {
	slot: &'held HeldActionSlot<'held, 'held, 'held, 'selection>,
}

impl SyncProfileStoreRecord<'_> {
	/// Lends one original profile, exclusive live pair and read-only prepared slot.
	///
	/// Expected facts come from an independent verified selection. The callback may
	/// parse the prepared record and measure the current subject under the held leases.
	/// The borrowed view and leases cannot escape and confer no right to mutate.
	/// # Errors
	/// Refuses changed policy, native role, bytes or exclusive custody, and preserves
	/// the callback's own refusal. Successful callbacks are followed by a final recheck.
	pub fn with_prepared_action_scope<'selection, R, E>(
		&self,
		scope: ManagedSyncNativeScope<'selection>,
		history_path: &Path,
		expected_history: ManagedSyncExpectedObject,
		selection: PreparedActionSlotSelection<'_>,
		use_scope: impl for<'held> FnOnce(PreparedManagedActionView<'held, 'selection>) -> Result<R, E>,
	) -> Result<R, E>
	where
		E: From<PreparedManagedActionError>,
	{
		self.recheck().map_err(Error::Policy)?;
		let roots = SyncPreviewRoots::open(scope.parent_path, scope.roots.map(|root| root.name))
			.map_err(Error::Roots)?;
		let pair = roots
			.acquire_managed_preparation_lease(scope)
			.map_err(Error::Pair)?;
		let history = self.open_history(history_path).map_err(Error::Policy)?;
		if !expected_history.matches(history.read_root().identity()) {
			return Err(Error::Scope(SyncProfileStoreError::Changed).into());
		}
		let slot = self.open_selected_action_slot(&history, &pair, selection)?;
		let result = use_scope(PreparedManagedActionView { slot: &slot })?;
		slot.recheck()?;
		Ok(result)
	}
}

impl<'selection> PreparedManagedActionView<'_, 'selection> {
	/// Borrows the independently selected protected history directory.
	#[must_use]
	pub const fn history(&self) -> &SyncProfileHistory {
		self.slot.history
	}

	/// Reaffirms all original names, native roles and read-only segment custody.
	/// # Errors
	/// Refuses any lost policy, pair, role, directory or segment observation.
	pub fn recheck(&self) -> Result<(), PreparedManagedActionError> {
		self.slot.recheck()
	}

	/// Returns current ordered root facts on the same retained exclusive lease.
	/// # Errors
	/// Refuses changed pair or slot custody.
	pub fn recheck_roots(
		&self,
	) -> Result<[SyncHistoryLocation<'selection>; 2], PreparedManagedActionError> {
		self.recheck()?;
		self.slot.pair.recheck_roots().map_err(Error::Pair)
	}

	/// Borrows the subject observations from the original exclusive pair.
	/// # Errors
	/// Refuses changed native scope or unsupported subject observations.
	pub fn observe(
		&self,
	) -> Result<ManagedSyncPreviewPair<'_, 'selection>, PreparedManagedActionError> {
		self.recheck()?;
		let observed = self.slot.pair.observe().map_err(Error::Pair)?;
		self.recheck()?;
		Ok(observed)
	}

	/// Reads the exact selected prepared extent from the original segment through physical EOF.
	/// # Errors
	/// Refuses wrong output extent or changed native custody and I/O failures. Discard
	/// any output if the read fails. The caller independently validates the record.
	pub fn read_prepared(&self, output: &mut [u8]) -> Result<(), PreparedManagedActionError> {
		self.slot.read_prepared(output)
	}

	/// Observes the role identities, native namespaces and current actor under the same held scope.
	/// # Errors
	/// Refuses changed native observations on the original profile or either slot role.
	pub fn native_facts(&self) -> Result<PreparedActionRoleFacts<'_>, PreparedManagedActionError> {
		let [root, _] = self.recheck_roots()?;
		let profile = &self.slot.record.lease;
		let system = |cause| Error::Scope(SyncProfileStoreError::System(cause));
		let changed = || Error::Scope(SyncProfileStoreError::Changed);
		let stat = fs::fstat(profile).map_err(|cause| system(cause.into()))?;
		let identity = FileIdentity::from_stat(&stat);
		let ordinary_mount =
			NonZeroU64::new(mount_id(profile).map_err(system)?).ok_or_else(changed)?;
		let unique_mount =
			unique_mount_id(profile).map_err(|cause| system(io::Error::other(cause)))?;
		if identity != self.slot.record.store.identity()
			|| ordinary_mount != self.slot.selection.ordinary_mount
			|| unique_mount != self.slot.selection.unique_mount
		{
			return Err(changed());
		}
		let uid = NonZeroU32::new(process::geteuid().as_raw()).ok_or_else(changed)?;
		let gid = NonZeroU32::new(process::getegid().as_raw()).ok_or_else(changed)?;
		let facts = PreparedActionRoleFacts {
			name: self.slot.selection.name,
			profile: identity,
			slot: self.slot.stamp.identity,
			segment: self.slot.segment.stamp.identity,
			mount_namespace: root.mount_namespace,
			user_namespace: root.user_namespace,
			boot: root.boot,
			ordinary_mount,
			unique_mount,
			uid,
			gid,
		};
		self.recheck()?;
		Ok(facts)
	}
}

/// Checked role facts under the original protected action preparation scope.
pub struct PreparedActionRoleFacts<'name> {
	name: UnixComponent<'name>,
	profile: FileIdentity,
	slot: FileIdentity,
	segment: FileIdentity,
	mount_namespace: FileIdentity,
	user_namespace: FileIdentity,
	boot: [u8; 16],
	ordinary_mount: NonZeroU64,
	unique_mount: NonZeroU64,
	uid: NonZeroU32,
	gid: NonZeroU32,
}

impl<'name> PreparedActionRoleFacts<'name> {
	/// Exact checked raw slot name.
	#[must_use]
	pub const fn name(&self) -> UnixComponent<'name> {
		self.name
	}

	/// Actual original held profile directory identity.
	#[must_use]
	pub const fn profile(&self) -> FileIdentity {
		self.profile
	}

	/// Actual original held action slot identity.
	#[must_use]
	pub const fn slot(&self) -> FileIdentity {
		self.slot
	}

	/// Actual original held first segment identity.
	#[must_use]
	pub const fn segment(&self) -> FileIdentity {
		self.segment
	}

	/// Current held mount namespace identity.
	#[must_use]
	pub const fn mount_namespace(&self) -> FileIdentity {
		self.mount_namespace
	}

	/// Current held user namespace identity.
	#[must_use]
	pub const fn user_namespace(&self) -> FileIdentity {
		self.user_namespace
	}

	/// Current kernel boot identity.
	#[must_use]
	pub const fn boot(&self) -> [u8; 16] {
		self.boot
	}

	/// Ordinary mount identity of the original profile, slot and segment.
	#[must_use]
	pub const fn ordinary_mount(&self) -> NonZeroU64 {
		self.ordinary_mount
	}

	/// Unique mount identity of the original profile, slot and segment.
	#[must_use]
	pub const fn unique_mount(&self) -> NonZeroU64 {
		self.unique_mount
	}

	/// Observed unprivileged effective user ID.
	#[must_use]
	pub const fn uid(&self) -> NonZeroU32 {
		self.uid
	}

	/// Observed unprivileged effective group ID.
	#[must_use]
	pub const fn gid(&self) -> NonZeroU32 {
		self.gid
	}
}
