use rustix::fs::FlockOperation;

use super::{
	ManagedRootCustody, ManagedSyncError, ManagedSyncNativeScope, ManagedSyncPreviewPair,
	SyncHistoryLocation, SyncPreviewRoots, lock_parent,
};

/// Read-only preparation under one original, nonblocking exclusive common-parent lease.
///
/// The provisioner must exclude untrusted retained handles and aliases. Cooperating
/// participants use this same parent lock for all covered changes.
#[must_use]
pub(in crate::linux) struct ManagedSyncPreparationLease<'held, 'selection> {
	custody: ManagedRootCustody<'held, 'selection>,
}

impl<'selection> SyncPreviewRoots<'selection> {
	/// Locks the existing held common parent before observing live scope or subjects.
	///
	/// An independently authenticated selection must establish the scope first.
	/// # Errors
	/// Refuses an incompatible lock or any mismatch in the held native scope.
	pub(in crate::linux) fn acquire_managed_preparation_lease(
		&self,
		scope: ManagedSyncNativeScope<'selection>,
	) -> Result<ManagedSyncPreparationLease<'_, 'selection>, ManagedSyncError> {
		self.check_selected_scope(scope)?;
		let locked_parent = self.open_lock_parent()?;
		lock_parent(&locked_parent, FlockOperation::NonBlockingLockExclusive)?;
		let admitted = self.observe_managed_scope(scope)?;
		let custody = ManagedRootCustody::new(self, scope, locked_parent, admitted);
		custody.recheck_roots()?;
		Ok(ManagedSyncPreparationLease { custody })
	}
}

impl<'selection> ManagedSyncPreparationLease<'_, 'selection> {
	/// Borrows the original held roots for physical role separation checks.
	pub(in crate::linux) fn held_roots(&self) -> &SyncPreviewRoots<'selection> {
		self.custody.roots
	}

	/// Rechecks the original pre-effect scope, retaining the same exclusive lease.
	/// # Errors
	/// Refuses any changed directory stamp, actor, mount or exact name.
	pub(in crate::linux) fn recheck_roots(
		&self,
	) -> Result<[SyncHistoryLocation<'selection>; 2], ManagedSyncError> {
		self.custody.recheck_roots()
	}

	/// Borrows the exact subject observations under the original pre-effect scope.
	/// # Errors
	/// Refuses changed roots, unsafe lookups or ambiguous subject ownership.
	pub(in crate::linux) fn observe(
		&self,
	) -> Result<ManagedSyncPreviewPair<'_, 'selection>, ManagedSyncError> {
		self.custody.observe()
	}
}
