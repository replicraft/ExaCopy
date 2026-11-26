use exacopy_endpoint::UnixComponent;
use exacopy_journal::LinuxFileIdentity;
use exacopy_journal::remote_download::replay::RemoteReplayAttempt;
use exacopy_platform::linux::{
	RecoveryInventory, RecoveryJob, RecoveryStageAnchor, RecoveryWriteLease,
};

use super::{Error, component, record_identity};

/// Old staged bytes retained for a fresh allocation. No content is promoted.
pub(in crate::assembly::linux::remote_journal) struct PreservedCapture {
	name: Box<[u8]>,
	anchor: Option<RecoveryStageAnchor>,
}

impl PreservedCapture {
	pub(super) fn admit(
		lease: &RecoveryWriteLease<'_>,
		attempt: &RemoteReplayAttempt,
		inventory: RecoveryInventory<'_>,
	) -> Result<Self, Error> {
		let anchor = if let Some(file) = inventory.stage() {
			if !(attempt.covered_extent()..=attempt.source().length().get()).contains(&file.len()) {
				return Err(Error::UnknownStage);
			}
			file.check_logical_eof()?;
			file.recheck_observation()?;
			Some(lease.pin_stopped_stage(inventory)?)
		} else {
			inventory.recheck()?;
			None
		};
		Ok(Self {
			name: attempt.name().into(),
			anchor,
		})
	}

	pub(in crate::assembly::linux::remote_journal) fn check_all(
		prior: &[Self],
		job: &RecoveryJob<'_>,
		target: UnixComponent<'_>,
		directory: LinuxFileIdentity,
	) -> Result<(), Error> {
		for stage in prior {
			let inventory = job.inventory(component(&stage.name)?, target)?;
			if inventory.target().is_some() {
				return Err(Error::Conflict);
			}
			if inventory.stage_directory_identity().map(record_identity) != Some(directory) {
				return Err(Error::UnknownStage);
			}
			match &stage.anchor {
				Some(anchor) => anchor.recheck(&inventory)?,
				None if inventory.stage().is_none() => inventory.recheck()?,
				None => return Err(Error::UnknownStage),
			}
		}
		Ok(())
	}
}
