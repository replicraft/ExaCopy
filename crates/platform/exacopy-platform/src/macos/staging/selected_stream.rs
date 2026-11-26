use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_model::CopyBinding;
use rustix::fs::{self, FileType};
use rustix::process::geteuid;

use super::super::{FILE_MODE, ManagedObjectIdentity, with_materialization_disabled};
use super::{ClosedStage, StageError, StageReader};

/// Native location and local metadata of one privately staged unnamed stream.
///
/// The caller records the selected source profile and its omissions separately.
/// These fields describe the live local stage and carry no publication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SelectedStreamObservation<'stage> {
	/// Transaction binding fixed when the stage was created.
	pub binding: CopyBinding,
	/// Independently reopened stage inode.
	pub stage: ManagedObjectIdentity,
	/// Leased staging directory.
	pub stage_directory: ManagedObjectIdentity,
	/// Leased destination directory.
	pub destination: ManagedObjectIdentity,
	/// Raw private name allocated for this stage.
	pub stage_name: UnixComponent<'stage>,
	/// Raw final name bound to this stage.
	pub target_name: UnixComponent<'stage>,
	/// Exact logical length in bytes.
	pub length: u64,
	/// Actual local owner-private permission mode (0600).
	pub mode: u32,
	/// Actual effective local owner.
	pub owner: u32,
	/// Actual group inherited from the admitted staging directory.
	pub group: u32,
}

/// Independent bounded read-back of a complete private unnamed stream.
#[derive(Debug)]
pub struct SelectedStreamReader<'stage> {
	stage: &'stage ClosedStage<'stage>,
	reader: StageReader<'stage>,
	initial: SelectedStreamObservation<'stage>,
}

impl ClosedStage<'_> {
	/// Open the closed writer's private file for independent unnamed-stream read-back.
	///
	/// Confirms the declared length and observes local 0600 permissions, effective
	/// ownership, inherited group, and absence of additional local metadata before
	/// granting data access. The caller reads and compares the complete stream.
	///
	/// # Errors
	/// Refuses changed or unsafe observations and independently reported I/O failures.
	pub fn open_selected_stream_read_back(
		&self,
		expected_length: u64,
	) -> Result<SelectedStreamReader<'_>, StageError> {
		if self.length() != expected_length {
			return Err(StageError::MetadataMismatch);
		}
		let reader = self.open_read_back()?;
		let initial = observe(self, &reader)?;
		Ok(SelectedStreamReader {
			stage: self,
			reader,
			initial,
		})
	}
}

impl SelectedStreamReader<'_> {
	/// Checks held identity, the staging name and directories, EOF and local metadata.
	///
	/// Call after comparing the full independent read-back against the selected
	/// source. Success identifies the observed file and its local metadata.
	///
	/// # Errors
	/// Refuses changed or unavailable observations or an unsuccessful EOF probe.
	pub fn revalidate(&self) -> Result<SelectedStreamObservation<'_>, StageError> {
		self.reader.revalidate()?;
		let current = observe(self.stage, &self.reader)?;
		if current != self.initial {
			return Err(StageError::StageChanged);
		}
		Ok(current)
	}
}

impl ReadView for SelectedStreamReader<'_> {
	type Error = StageError;

	fn length(&self) -> u64 {
		self.initial.length
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.revalidate().map(|_| ())
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		self.reader.read_exact_at(offset, buffer)
	}
}

fn observe<'stage>(
	stage: &'stage ClosedStage<'stage>,
	reader: &StageReader<'stage>,
) -> Result<SelectedStreamObservation<'stage>, StageError> {
	with_materialization_disabled(|| {
		let (stage_directory, destination) = stage.location.observe_directories()?;
		let group = fs::fstat(stage.location.directory())?.st_gid;
		let local = reader.observe_selected_metadata_with_policy()?;
		if local.file_type != FileType::RegularFile
			|| local.mode != FILE_MODE
			|| local.link_count != 1
			|| local.bsd_flags != 0
			|| local.length != stage.length()
			|| local.uid != geteuid().as_raw()
			|| local.gid != group
		{
			return Err(StageError::StageChanged);
		}
		let identity = stage.location.observe_identity(stage.closed.identity())?;
		if stage.location.observe_directories()? != (stage_directory, destination)
			|| fs::fstat(stage.location.directory())?.st_gid != group
		{
			return Err(StageError::DirectoryChanged);
		}
		Ok(SelectedStreamObservation {
			binding: stage.binding(),
			stage: identity,
			stage_directory,
			destination,
			stage_name: stage.location.component(),
			target_name: stage.target(),
			length: local.length,
			mode: local.mode.bits().into(),
			owner: local.uid,
			group,
		})
	})
}

#[cfg(test)]
mod tests;
