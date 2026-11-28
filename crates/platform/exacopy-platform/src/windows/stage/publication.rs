use std::fs::File;
use std::io;
use std::os::windows::fs::FileExt as _;
use std::os::windows::io::AsHandle as _;

use exacopy_endpoint::ClosedStage;
use exacopy_model::{CopyBinding, PublishNoClobber};
use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
use windows_sys::Win32::Foundation::{OBJ_DONT_REPARSE, STATUS_OBJECT_NAME_NOT_FOUND};
use windows_sys::Win32::Storage::FileSystem::{
	DELETE, FILE_SHARE_DELETE, FILE_SHARE_READ, READ_CONTROL,
};

use super::handles::{close_writer, stamp};
use super::{FILE_OPENED_INFORMATION, READ_ACCESS, WindowsStageReadBack, WindowsStageWriter};
use crate::windows::native::{Kind, ObjectId, Refusal, RelativeFileOpen, observe, observe_entry};
use crate::windows::{WindowsComponent, WindowsStageError};

mod destination;
mod error;
#[allow(
	unsafe_code,
	reason = "bounded native NTFS stream and security metadata queries"
)]
mod metadata;
#[allow(
	unsafe_code,
	reason = "verified Windows object query and single handle-relative no-replace rename"
)]
pub(in crate::windows) mod native;
mod reopen;

pub use destination::{
	WindowsPublicationDestination, WindowsPublicationRoot, WindowsUnconfirmedPublicationDirectory,
};
pub use error::WindowsPublicationError;
pub use metadata::WindowsPublicationMetadata;
pub use reopen::{WindowsPublicationTargetObservation, inspect_windows_publication_target};

const OBSERVATION_ACCESS: u32 = READ_ACCESS | READ_CONTROL;
const OBSERVATION_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_DELETE;

/// Exact logical and physical bindings for a single authorized placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsPublicationBinding<'name> {
	/// Job, entry, epoch and logical stage selected before intent.
	pub model: CopyBinding,
	/// Exact source parent ID, including volume GUID and serial.
	pub stage_parent: ObjectId,
	/// Exact file ID of the fresh completed stage.
	pub stage: ObjectId,
	/// Exact destination parent ID, including volume GUID and serial.
	pub destination_parent: ObjectId,
	/// Stored private filename component and expected spelling.
	pub stage_name: WindowsComponent<'name>,
	/// Planned public filename component and expected spelling.
	pub target_name: WindowsComponent<'name>,
}

impl<'stage> WindowsStageWriter<'stage> {
	/// Flushes and closes this fresh stage for the exact intended placement.
	///
	/// Through the attempt, the caller proves exclusive custody of the fresh
	/// stage and authorized parents. It excludes previously opened or newly
	/// accessible file/namespace mutation handles, including WRITE_ATTRIBUTES,
	/// WRITE_DAC, WRITE_OWNER, ADS creation and parent delete-child rights.
	/// These constraints cover the renamed stage until final observation.
	/// This publication-only reader shares delete access for the pinned
	/// handoff and denies data writing to the selected unnamed stream.
	///
	/// # Errors
	/// Refuses mismatched parent scopes, a changed stage or an unconfirmed close.
	pub fn finish_for_publication(
		self,
		model: CopyBinding,
		destination: WindowsPublicationDestination<'stage>,
		target_name: WindowsComponent<'stage>,
	) -> Result<WindowsClosedPublicationStage<'stage>, WindowsPublicationError> {
		let source = self.location.parent;
		let stage_parent = source.identity;
		if stage_parent == destination.identity()
			|| stage_parent.volume != destination.identity().volume
			|| stage_parent.volume_serial != destination.identity().volume_serial
		{
			return Err(WindowsPublicationError::ParentScope);
		}
		source.check()?;
		destination.check()?;
		let stage_parent_security = metadata::descriptor(source.handle)?;
		let binding = WindowsPublicationBinding {
			model,
			stage_parent,
			stage: self.location.identity,
			destination_parent: destination.identity(),
			stage_name: self.location.name,
			target_name,
		};
		let read_back = self.finish_with_observation(
			File::sync_all,
			close_writer,
			OBSERVATION_ACCESS,
			OBSERVATION_SHARE,
		)?;
		Ok(WindowsClosedPublicationStage {
			read_back,
			binding,
			destination,
			stage_parent_security,
		})
	}
}

/// Fresh closed stage associated with exactly one intended target.
pub struct WindowsClosedPublicationStage<'stage> {
	read_back: WindowsStageReadBack<'stage>,
	binding: WindowsPublicationBinding<'stage>,
	destination: WindowsPublicationDestination<'stage>,
	stage_parent_security: Vec<u8>,
}

impl<'stage> WindowsClosedPublicationStage<'stage> {
	fn check_parents(&self) -> Result<(), WindowsPublicationError> {
		let parent = self.read_back.observation.location.parent;
		parent.check()?;
		if metadata::descriptor(parent.handle)? != self.stage_parent_security {
			return Err(WindowsPublicationError::ParentChanged);
		}
		self.destination.check()
	}

	/// Returns the complete placement binding for independent intent recording.
	#[must_use]
	pub const fn binding(&self) -> WindowsPublicationBinding<'stage> {
		self.binding
	}

	/// Captures required metadata from the exact closed stage for comparison.
	///
	/// This is a stage observation. The coordinator owns the metadata policy
	/// and must separately establish what the source and stage must preserve.
	///
	/// # Errors
	/// Rejects extra data streams, unsupported metadata or changed observations.
	pub fn observe_metadata(&self) -> Result<WindowsPublicationMetadata, WindowsPublicationError> {
		let observed = &self.read_back.observation;
		self.check_parents()?;
		observed.check_eof()?;
		let result = WindowsPublicationMetadata::observe(
			observed.file.as_handle(),
			observed.observed,
			observed.length,
		)?;
		observed.check_eof()?;
		self.check_parents()?;
		Ok(result)
	}

	/// Consumes the closed stage after the caller independently verifies full read-back.
	///
	/// The caller must supply the exact required metadata authenticated for
	/// this placement before recording intent. Only the complete declared
	/// unnamed-stream profile can be sealed.
	///
	/// # Errors
	/// Refuses unsupported metadata or any discrepancy from required values.
	pub fn seal(
		self,
		required: &WindowsPublicationMetadata,
	) -> Result<WindowsSealedPublicationStage<'stage>, WindowsPublicationError> {
		let metadata = self.observe_metadata()?;
		if !metadata.matches_required(required) {
			return Err(WindowsPublicationError::MetadataChanged);
		}
		Ok(WindowsSealedPublicationStage {
			closed: self,
			metadata,
		})
	}
}

impl<'stage> ClosedStage for WindowsClosedPublicationStage<'stage> {
	type Error = WindowsStageError;
	type Reader<'view>
		= <WindowsStageReadBack<'stage> as ClosedStage>::Reader<'view>
	where
		Self: 'view;

	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		self.read_back.open_read_back()
	}
}

/// A fresh closed stage sealed against the exact required metadata profile.
pub struct WindowsSealedPublicationStage<'stage> {
	closed: WindowsClosedPublicationStage<'stage>,
	metadata: WindowsPublicationMetadata,
}

impl<'stage> WindowsSealedPublicationStage<'stage> {
	/// Returns the exact placement that must be in the caller's durable intent.
	#[must_use]
	pub const fn binding(&self) -> WindowsPublicationBinding<'stage> {
		self.closed.binding
	}

	/// Consumes the stage and matching model permission, submitting at most one rename.
	///
	/// The coordinator authenticates intent and binds its exact contents to the
	/// model permission. The result keeps the evidence handles alive and only
	/// reports observed namespace state. Reconciliation consumes uncertainty.
	#[must_use]
	pub fn attempt_no_clobber(self, permit: PublishNoClobber) -> WindowsPublicationAttempt<'stage> {
		self.attempt_with_observation(permit, WindowsPublicationAttempt::observe_result)
	}

	fn attempt_with_observation(
		self,
		permit: PublishNoClobber,
		observe_result: impl FnOnce(
			&mut WindowsPublicationAttempt<'stage>,
		) -> Result<(), WindowsPublicationError>,
	) -> WindowsPublicationAttempt<'stage> {
		let mut attempt = WindowsPublicationAttempt {
			stage: self,
			rename_pin: None,
			target_pin: None,
			outcome: WindowsPublicationOutcome::Rejected(WindowsPublicationError::BindingMismatch),
		};
		if permit.binding() != attempt.stage.closed.binding.model {
			return attempt;
		}
		let rename_pin = match attempt.stage.open_rename_pin() {
			Ok(pin) => pin,
			Err(error) => {
				attempt.outcome = WindowsPublicationOutcome::Rejected(error);
				return attempt;
			}
		};
		if let Err(error) = attempt.stage.validate_rename_pin(&rename_pin) {
			attempt.rename_pin = Some(rename_pin);
			attempt.outcome = WindowsPublicationOutcome::Rejected(error);
			return attempt;
		}
		let binding = attempt.stage.closed.binding;
		let outcome = native::rename_no_replace(
			rename_pin.as_handle(),
			attempt.stage.closed.destination.handle(),
			binding.target_name,
		);
		attempt.rename_pin = Some(rename_pin);
		attempt.outcome = match outcome {
			Err(outcome) => outcome,
			Ok(()) => match observe_result(&mut attempt) {
				Ok(()) => WindowsPublicationOutcome::ObservedRename,
				Err(error) => WindowsPublicationOutcome::RenamedUnconfirmed(error),
			},
		};
		attempt
	}

	fn open_rename_pin(&self) -> Result<File, WindowsPublicationError> {
		let observed = &self.closed.read_back.observation;
		self.closed.check_parents()?;
		observed.check_eof()?;
		observed
			.location
			.open_observation(OBSERVATION_ACCESS | DELETE, FILE_SHARE_READ)
			.map_err(WindowsPublicationError::from)
	}

	fn validate_rename_pin(&self, file: &File) -> Result<(), WindowsPublicationError> {
		let observed = &self.closed.read_back.observation;
		let initial = observed.location.check(file.as_handle(), observed.length)?;
		if initial != observed.observed {
			return Err(WindowsPublicationError::Stage(WindowsStageError::Changed));
		}
		let metadata =
			WindowsPublicationMetadata::observe(file.as_handle(), initial, observed.length)?;
		if !metadata.matches_required(&self.metadata) {
			return Err(WindowsPublicationError::MetadataChanged);
		}
		observed.check_eof()?;
		if observed.location.check(file.as_handle(), observed.length)? != initial {
			return Err(WindowsPublicationError::Stage(WindowsStageError::Changed));
		}
		self.closed.check_parents()
	}
}

/// Result of one bound native placement attempt, with its evidence pins.
pub struct WindowsPublicationAttempt<'stage> {
	stage: WindowsSealedPublicationStage<'stage>,
	rename_pin: Option<File>,
	target_pin: Option<File>,
	outcome: WindowsPublicationOutcome,
}

impl<'stage> WindowsPublicationAttempt<'stage> {
	/// Returns the logical and physical identities to reconcile.
	#[must_use]
	pub const fn binding(&self) -> WindowsPublicationBinding<'stage> {
		self.stage.binding()
	}

	/// Returns the typed result, including native failure causes.
	#[must_use]
	pub const fn outcome(&self) -> &WindowsPublicationOutcome {
		&self.outcome
	}

	fn observe_result(&mut self) -> Result<(), WindowsPublicationError> {
		let closed = &self.stage.closed;
		let observed = &closed.read_back.observation;
		let destination = &closed.destination;
		closed.check_parents()?;
		self.check_former_name()?;

		let target = crate::windows::native::open_relative_file(
			destination.handle(),
			closed.binding.target_name,
			relative_observation(),
		)
		.map(File::from)
		.map_err(WindowsPublicationError::native)?;
		let target = self.target_pin.insert(target);
		let rename_handle = self
			.rename_pin
			.as_ref()
			.ok_or(WindowsPublicationError::TargetChanged)?;
		let target_id = observe_entry(
			target.as_handle(),
			Kind::RegularFile,
			Some(closed.binding.target_name),
		)
		.map_err(WindowsPublicationError::native)?;
		let held_id = observe(rename_handle.as_handle(), Kind::RegularFile)
			.map_err(WindowsPublicationError::native)?;
		if target_id != closed.binding.stage || held_id != target_id {
			return Err(WindowsPublicationError::TargetChanged);
		}
		let post = stamp(target.as_handle(), observed.length)?;
		let held = stamp(rename_handle.as_handle(), observed.length)?;
		if post != held {
			return Err(WindowsPublicationError::TargetChanged);
		}
		let metadata =
			WindowsPublicationMetadata::observe(target.as_handle(), post, observed.length)?;
		let mut extra = [0];
		let read = target
			.seek_read(&mut extra, observed.length)
			.map_err(WindowsPublicationError::MetadataQuery)?;
		if read != 0 || !metadata.matches_required(&self.stage.metadata) {
			return Err(WindowsPublicationError::MetadataChanged);
		}
		if stamp(rename_handle.as_handle(), observed.length)? != post
			|| stamp(target.as_handle(), observed.length)? != post
		{
			return Err(WindowsPublicationError::TargetChanged);
		}
		self.check_former_name()?;
		closed.check_parents()
	}

	fn check_former_name(&self) -> Result<(), WindowsPublicationError> {
		let location = &self.stage.closed.read_back.observation.location;
		match location.parent.open(location.name, relative_observation()) {
			Err(Refusal::OpenFailed(STATUS_OBJECT_NAME_NOT_FOUND)) => Ok(()),
			Ok(_) => Err(WindowsPublicationError::FormerNameOccupied),
			Err(cause) => Err(WindowsPublicationError::native(cause)),
		}
	}
}

fn relative_observation() -> RelativeFileOpen {
	RelativeFileOpen {
		access: OBSERVATION_ACCESS,
		share: OBSERVATION_SHARE,
		disposition: FILE_OPEN,
		attributes: OBJ_DONT_REPARSE,
		expected_result: Some(FILE_OPENED_INFORMATION),
	}
}

/// Namespace outcome of an experimental placement, with durability unconfirmed.
#[derive(Debug)]
#[non_exhaustive]
pub enum WindowsPublicationOutcome {
	/// No native rename was submitted.
	Rejected(WindowsPublicationError),
	/// The native primitive explicitly refused support.
	Unsupported(io::Error),
	/// The kernel refused to replace an occupied target.
	Conflict(io::Error),
	/// A call occurred without sufficient evidence of the effect.
	Uncertain(io::Error),
	/// The kernel reported rename success and the held observations agreed.
	ObservedRename,
	/// The kernel reported rename success but the following observations failed.
	RenamedUnconfirmed(WindowsPublicationError),
}

#[cfg(test)]
mod tests;
