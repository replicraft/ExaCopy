use exacopy_endpoint::linux_staging::StagingSource as _;
use exacopy_plan::workflow_sync::WorkflowTimestamp;
use exacopy_platform::linux::{
	ManagedSyncPreviewPair, NamedReadView, SourceObservation, SyncPreviewEntry,
};
use exacopy_transfer::linux::sync_genesis_measurement::{
	GenesisFileFacts, GenesisInput, HeldGenesisPair,
};
use exacopy_transfer::linux::sync_preview::LiveSyncSelection;

use super::super::ManagedSyncPreviewError;
use super::super::scope::{fresh_endpoint, native_object};

/// Keeps the actual managed lease's exact two original held views as the
/// single source of genesis observations through every later effect.
pub(super) struct LiveGenesisPair<'call, 'view, 'selection> {
	pub(super) pair: &'call ManagedSyncPreviewPair<'view, 'selection>,
	pub(super) expected: LiveSyncSelection<'selection>,
}

impl<'view> HeldGenesisPair for LiveGenesisPair<'_, 'view, '_> {
	type View = NamedReadView<'view>;
	type Error = ManagedSyncPreviewError;

	fn observations(&self) -> [GenesisInput<'_, Self::View>; 2] {
		self.pair.entries().map(|entry| match entry {
			SyncPreviewEntry::Present(view) => {
				if let Ok(facts) = collect(view.metadata()) {
					GenesisInput::Present { view, facts }
				} else {
					GenesisInput::Unsupported
				}
			}
			SyncPreviewEntry::Absent => GenesisInput::Absent,
			SyncPreviewEntry::Unsupported => GenesisInput::Unsupported,
		})
	}

	fn recheck_selection(&self) -> Result<LiveSyncSelection<'_>, Self::Error> {
		let (subject, [left_actual, right_actual]) = self
			.pair
			.recheck_history_location()
			.map_err(ManagedSyncPreviewError::Managed)?;
		let [left, right] = self.expected.endpoints;
		Ok(LiveSyncSelection {
			subject,
			endpoints: [
				fresh_endpoint(left, left_actual)?,
				fresh_endpoint(right, right_actual)?,
			],
			..self.expected
		})
	}
}

fn collect(observed: SourceObservation) -> Result<GenesisFileFacts, ManagedSyncPreviewError> {
	let modified = observed.modified_at();
	let changed = observed.changed_at();
	Ok(GenesisFileFacts {
		object: native_object(observed.identity())?,
		native_mode: observed.native_mode(),
		length: observed.len(),
		uid: observed.owner(),
		gid: observed.group(),
		links: observed.link_count(),
		modified: WorkflowTimestamp::new(modified.seconds(), modified.nanoseconds())
			.map_err(|_| ManagedSyncPreviewError::Selection)?,
		changed: WorkflowTimestamp::new(changed.seconds(), changed.nanoseconds())
			.map_err(|_| ManagedSyncPreviewError::Selection)?,
	})
}
