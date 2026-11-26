//! Owned metadata readiness for the selected unnamed stream of a private stage.

use std::fs::File;

use exacopy_model::CopyBinding;
use rustix::fs;
use rustix::process::{getegid, geteuid};

use super::{ClosedStage, StageError, check_no_visible_attributes};
use crate::linux::handle::{FileIdentity, mount_id};
use crate::linux::recovery::RetainedStage;
use crate::linux::source::{SourceObservation, check_logical_eof};

mod publication;

pub use publication::{
	SelectedStreamGateRequest, SelectedStreamLocation, SelectedStreamNames,
	SelectedStreamPublication, SelectedStreamPublicationAuthority, SelectedStreamPublishError,
};

#[cfg(test)]
mod tests;

const PERMISSION_BITS: u32 = 0o7777;
const PRIVATE_MODE: u32 = 0o600;

/// Local observations confirmed around the selected-stream file barrier.
///
/// The mode and credentials describe the staged local inode. Visibility of
/// attributes is limited to the process performing the check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedStreamObservation {
	binding: CopyBinding,
	destination: FileIdentity,
	stage_directory: FileIdentity,
	file: SourceObservation,
}

impl SelectedStreamObservation {
	/// Returns the copy binding fixed at stage creation or recovery admission.
	#[must_use]
	pub const fn binding(self) -> CopyBinding {
		self.binding
	}

	/// Returns the held destination directory identity.
	#[must_use]
	pub const fn destination(self) -> FileIdentity {
		self.destination
	}

	/// Returns the held private stage-directory identity.
	#[must_use]
	pub const fn stage_directory(self) -> FileIdentity {
		self.stage_directory
	}

	/// Returns the held regular-file identity.
	#[must_use]
	pub fn stage(self) -> FileIdentity {
		self.file.identity()
	}

	/// Returns the selected stream length at the file barrier.
	#[must_use]
	pub fn length(self) -> u64 {
		self.file.len()
	}

	/// Returns the checked local mode, including special bits.
	#[must_use]
	pub fn mode(self) -> u32 {
		self.file.mode()
	}

	/// Returns the checked local owner ID.
	#[must_use]
	pub fn owner(self) -> u32 {
		self.file.owner()
	}

	/// Returns the checked local group ID.
	#[must_use]
	pub fn group(self) -> u32 {
		self.file.group()
	}
}

/// Selected-stream metadata evidence held with the original read-only stage.
///
/// The coordinator keeps its independent full-stream verification, current
/// destination eligibility and durable intent alongside this capability.
#[derive(Debug)]
#[must_use]
pub struct SelectedStreamMetadataReady<'stage> {
	stage: StageHandle<'stage>,
	observation: SelectedStreamObservation,
}

impl SelectedStreamMetadataReady<'_> {
	/// Returns the exact local observations established by the file barrier.
	#[must_use]
	pub const fn observed(&self) -> SelectedStreamObservation {
		self.observation
	}

	/// Rechecks readiness on the original held stage and its private name.
	///
	/// # Errors
	/// Refuses changed identity, namespace, credentials, content stamps or visible
	/// attributes, and reports failed inspections.
	pub fn recheck(&self) -> Result<(), StageError> {
		let view = self.stage.view()?;
		self.recheck_view(&view)
	}

	fn recheck_view(&self, view: &SelectedStreamView<'_>) -> Result<(), StageError> {
		let current = view.observe(self.observation.length())?;
		self.observation
			.file
			.recheck(current)
			.map_err(StageError::ReadBack)
	}
}

impl<'stage> ClosedStage<'stage> {
	/// Checks local selected-stream metadata after independent capture read-back.
	///
	/// Consumes the original closed stage and synchronizes the checked local
	/// inode. The caller supplies the extent obtained from full capture
	/// verification and retains the stream evidence separately.
	///
	/// # Errors
	/// Refuses changed or unsupported metadata and reports failed observations
	/// or barriers. The private stage remains for reconciliation.
	pub fn prepare_selected_stream_metadata(
		self,
		expected_length: u64,
	) -> Result<SelectedStreamMetadataReady<'stage>, StageError> {
		self.prepare_selected_stream_metadata_admitted(expected_length, || Ok(()))
	}

	/// Checks selected metadata and enters the caller's authority before the file barrier.
	///
	/// # Errors
	/// Refuses stale metadata, failed admission or a failed file barrier.
	pub fn prepare_selected_stream_metadata_admitted<G>(
		self,
		expected_length: u64,
		enter: impl FnOnce() -> std::io::Result<G>,
	) -> Result<SelectedStreamMetadataReady<'stage>, StageError> {
		prepare_with(StageHandle::Closed(self), expected_length, |file| {
			let _guard = enter().map_err(StageError::Admission)?;
			sync_metadata(file)
		})
	}
}

impl<'stage> RetainedStage<'stage> {
	/// Checks selected-stream metadata on the privately retained stage.
	///
	/// The caller freshly verifies the bytes on the retained inventory under
	/// its recovery lease and supplies the exact independently measured extent.
	///
	/// # Errors
	/// Refuses changed or unsupported metadata and reports failed inspections or
	/// barriers. The private stage remains for reconciliation.
	pub fn prepare_selected_stream_metadata(
		self,
		expected_length: u64,
	) -> Result<SelectedStreamMetadataReady<'stage>, StageError> {
		prepare_with(StageHandle::Retained(self), expected_length, sync_metadata)
	}
}

#[derive(Debug)]
enum StageHandle<'stage> {
	Closed(ClosedStage<'stage>),
	Retained(RetainedStage<'stage>),
}

impl StageHandle<'_> {
	fn view(&self) -> Result<SelectedStreamView<'_>, StageError> {
		match self {
			Self::Closed(stage) => stage.selected_stream_view(),
			Self::Retained(stage) => stage.selected_stream_view(),
		}
	}
}

pub(in crate::linux) struct SelectedStreamView<'stage> {
	pub file: &'stage File,
	pub expected: SourceObservation,
	pub destination: FileIdentity,
	pub stage_directory: FileIdentity,
	pub binding: CopyBinding,
	pub mount: u64,
}

impl SelectedStreamView<'_> {
	fn observe(&self, expected_length: u64) -> Result<SourceObservation, StageError> {
		let current = self.observe_held(expected_length)?;
		self.expected
			.recheck(current)
			.map_err(StageError::ReadBack)?;
		Ok(current)
	}

	fn observe_held(&self, expected_length: u64) -> Result<SourceObservation, StageError> {
		let before = self.check_held(expected_length)?;
		check_no_visible_attributes(self.file)?;
		check_logical_eof(self.file, expected_length).map_err(StageError::ReadBack)?;
		let after = self.check_held(expected_length)?;
		before.recheck(after).map_err(StageError::ReadBack)?;
		Ok(after)
	}

	fn check_held(&self, expected_length: u64) -> Result<SourceObservation, StageError> {
		let stat = fs::fstat(self.file)?;
		let current = SourceObservation::capture(&stat).map_err(StageError::ReadBack)?;
		check_metadata(&stat, current)?;
		if current.len() != expected_length {
			return Err(StageError::MetadataMismatch);
		}
		if mount_id(self.file)? != self.mount {
			return Err(StageError::IdentityChanged);
		}
		Ok(current)
	}
}

fn check_metadata(stat: &fs::Stat, current: SourceObservation) -> Result<(), StageError> {
	if stat.st_mode & PERMISSION_BITS != PRIVATE_MODE
		|| current.link_count() != 1
		|| current.owner() != geteuid().as_raw()
		|| current.group() != getegid().as_raw()
	{
		return Err(StageError::UnsafeFile);
	}
	Ok(())
}

fn sync_metadata(file: &File) -> Result<(), StageError> {
	fs::fsync(file).map_err(|source| StageError::BarrierFailed(source.into()))
}

#[cfg(test)]
fn prepare<'stage>(
	stage: StageHandle<'stage>,
	expected_length: u64,
	sync: impl FnOnce(&File) -> rustix::io::Result<()>,
) -> Result<SelectedStreamMetadataReady<'stage>, StageError> {
	prepare_with(stage, expected_length, |file| {
		sync(file).map_err(|source| StageError::BarrierFailed(source.into()))
	})
}

fn prepare_with<'stage>(
	stage: StageHandle<'stage>,
	expected_length: u64,
	sync: impl FnOnce(&File) -> Result<(), StageError>,
) -> Result<SelectedStreamMetadataReady<'stage>, StageError> {
	let view = stage.view()?;
	let before = view.observe(expected_length)?;
	sync(view.file)?;
	let view = stage.view()?;
	let file = view.observe(expected_length)?;
	before.recheck(file).map_err(StageError::ReadBack)?;
	Ok(SelectedStreamMetadataReady {
		observation: SelectedStreamObservation {
			binding: view.binding,
			destination: view.destination,
			stage_directory: view.stage_directory,
			file,
		},
		stage,
	})
}
