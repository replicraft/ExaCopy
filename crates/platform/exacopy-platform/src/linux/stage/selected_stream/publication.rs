use std::error::Error;
use std::fmt;
use std::fs::File;
use std::num::NonZeroU64;
use std::os::unix::ffi::OsStrExt as _;

use exacopy_endpoint::UnixComponent;
use exacopy_model::{CopyBinding, PublishNoClobber};
use rustix::fs;

use super::{
	ClosedStage, FileIdentity, RetainedStage, SelectedStreamMetadataReady, SelectedStreamView,
	SourceObservation, StageError, StageHandle, mount_id,
};
use crate::linux::handle::file_identity;
use crate::linux::stage::{PublicationNames, PublishError};
use crate::linux::{RemoteDestinationEligibility, RemoteDestinationEligibilityError};

#[cfg(test)]
mod tests;

/// Actual private and public names held by the native stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SelectedStreamNames<'stage> {
	/// The exact allocated private name.
	pub stage: UnixComponent<'stage>,
	/// The exact destination name bound to the stage.
	pub target: UnixComponent<'stage>,
}

/// A held stage location checked before selected-stream finalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SelectedStreamLocation<'stage> {
	/// The model binding held by this stage.
	pub binding: CopyBinding,
	/// The actual private stage inode.
	pub stage: FileIdentity,
	/// The actual private stage directory.
	pub directory: FileIdentity,
	/// The actual destination directory.
	pub destination: FileIdentity,
	/// The names held for the no-replace operation.
	pub names: SelectedStreamNames<'stage>,
}

/// Independently authorized, synchronized intent selected by the coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedStreamPublicationAuthority {
	/// Digest of the authenticated job owner.
	pub owner: [u8; 32],
	/// Digest of the exact signed remote scope.
	pub scope: [u8; 32],
	/// Digest of the exact active publication grant.
	pub grant: [u8; 32],
	/// Digest of the exact admitted native qualification.
	pub qualification: [u8; 32],
	/// Digest of the acknowledged publication-intent frame.
	pub intent_digest: [u8; 32],
	/// Sequence of the acknowledged publication-intent frame.
	pub intent_sequence: NonZeroU64,
}

/// Exact context the application must validate under its grant serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SelectedStreamGateRequest<'stage> {
	/// Selected intent and expected current approval.
	pub authority: SelectedStreamPublicationAuthority,
	/// Exact native names, directories and model binding.
	pub location: SelectedStreamLocation<'stage>,
}

/// Successful publication after file and directory barriers and native rechecks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct SelectedStreamPublication {
	target: FileIdentity,
	stage_directory: FileIdentity,
	destination: FileIdentity,
}

impl SelectedStreamPublication {
	/// Returns the observed target inode after both directory barriers.
	#[must_use]
	pub const fn target(self) -> FileIdentity {
		self.target
	}

	/// Returns the synchronized private directory with the old name absent.
	#[must_use]
	pub const fn stage_directory(self) -> FileIdentity {
		self.stage_directory
	}

	/// Returns the synchronized held destination directory.
	#[must_use]
	pub const fn destination(self) -> FileIdentity {
		self.destination
	}
}

/// Refusal or uncertain result of a selected-stream publication attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum SelectedStreamPublishError<E> {
	/// The entitlement selected for the held root differs from the synced intent.
	QualificationMismatch,
	/// The selected native destination can no longer be confirmed.
	Eligibility(RemoteDestinationEligibilityError),
	/// The final application gate refused current grant authority.
	Gate(E),
	/// Native readiness, no-replace rename, barrier or observation failure.
	Native(PublishError),
}

impl<E: fmt::Display> fmt::Display for SelectedStreamPublishError<E> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::QualificationMismatch => {
				f.write_str("qualification differs from publication intent")
			}
			Self::Eligibility(error) => write!(f, "destination qualification refused: {error}"),
			Self::Gate(error) => write!(f, "current publication grant refused: {error}"),
			Self::Native(error) => error.fmt(f),
		}
	}
}

impl<E: Error + 'static> Error for SelectedStreamPublishError<E> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::QualificationMismatch => None,
			Self::Eligibility(error) => Some(error),
			Self::Gate(error) => Some(error),
			Self::Native(error) => Some(error),
		}
	}
}

impl ClosedStage<'_> {
	/// Checks the original held stage location and returns its exact names.
	///
	/// # Errors
	/// Refuses changed or unsupported native stage observations.
	pub fn inspect_selected_stream_location(
		&self,
	) -> Result<SelectedStreamLocation<'_>, StageError> {
		let view = self.selected_stream_view()?;
		location(&view, &self.selected_stream_names())
	}
}

impl RetainedStage<'_> {
	/// Checks the retained stage location under its leased original inventory.
	///
	/// # Errors
	/// Refuses changed or unsupported native stage observations.
	pub fn inspect_selected_stream_location(
		&self,
	) -> Result<SelectedStreamLocation<'_>, StageError> {
		let view = self.selected_stream_view()?;
		location(&view, &self.selected_stream_names())
	}
}

impl SelectedStreamMetadataReady<'_> {
	/// Returns the bounded actual names held by the metadata-ready stage.
	///
	/// # Errors
	/// Refuses a component outside the native selected-stream profile.
	pub fn names(&self) -> Result<SelectedStreamNames<'_>, StageError> {
		checked_names(&self.stage.names())
	}

	/// Consumes this exact stage, model permit and current publication gate.
	///
	/// After checking the real destination qualification and completing the
	/// held file barrier and all readiness checks, this invokes the required
	/// application gate. The gate confirms the request against an independently
	/// acknowledged intent and rechecks the active grant and expiry under its
	/// revocation serialization. It must return its held serialization guard.
	/// Only the native no-replace rename runs before that guard is released.
	///
	/// # Errors
	/// Refusals or an incumbent preserve both names. An uncertain rename or
	/// failure after rename preserves the resulting state for reconciliation.
	pub fn publish_no_clobber<G, E>(
		self,
		eligibility: &RemoteDestinationEligibility<'_>,
		authority: SelectedStreamPublicationAuthority,
		permit: PublishNoClobber,
		enter_gate: impl FnOnce(SelectedStreamGateRequest<'_>) -> Result<G, E>,
	) -> Result<SelectedStreamPublication, SelectedStreamPublishError<E>> {
		self.publish_no_clobber_admitted(eligibility, authority, permit, || Ok(()), enter_gate)
	}

	/// Separately admits the pre-rename file barrier and the checked no-replace rename.
	///
	/// # Errors
	/// Refuses a failed admission, stale observations or a failed native operation.
	/// Once started, the rename's bounded observation and directory barriers still run.
	pub fn publish_no_clobber_admitted<G, H, E>(
		self,
		eligibility: &RemoteDestinationEligibility<'_>,
		authority: SelectedStreamPublicationAuthority,
		permit: PublishNoClobber,
		enter_barrier: impl FnOnce() -> Result<H, E>,
		enter_gate: impl FnOnce(SelectedStreamGateRequest<'_>) -> Result<G, E>,
	) -> Result<SelectedStreamPublication, SelectedStreamPublishError<E>> {
		self.publish_with_effects(
			eligibility,
			authority,
			permit,
			enter_gate,
			|file| {
				let _guard = enter_barrier().map_err(SelectedStreamPublishError::Gate)?;
				fs::fsync(file)
					.map_err(|source| before_rename(StageError::BarrierFailed(source.into())))
			},
			|directory| fs::fsync(directory),
		)
	}

	#[cfg(test)]
	fn publish_with_barriers<G, E>(
		self,
		eligibility: &RemoteDestinationEligibility<'_>,
		authority: SelectedStreamPublicationAuthority,
		permit: PublishNoClobber,
		enter_gate: impl FnOnce(SelectedStreamGateRequest<'_>) -> Result<G, E>,
		sync_file: impl FnOnce(&File) -> rustix::io::Result<()>,
		sync_directories: impl FnMut(&File) -> rustix::io::Result<()>,
	) -> Result<SelectedStreamPublication, SelectedStreamPublishError<E>> {
		self.publish_with_effects(
			eligibility,
			authority,
			permit,
			enter_gate,
			|file| {
				sync_file(file)
					.map_err(|source| before_rename(StageError::BarrierFailed(source.into())))
			},
			sync_directories,
		)
	}

	fn publish_with_effects<G, E>(
		self,
		eligibility: &RemoteDestinationEligibility<'_>,
		authority: SelectedStreamPublicationAuthority,
		permit: PublishNoClobber,
		enter_gate: impl FnOnce(SelectedStreamGateRequest<'_>) -> Result<G, E>,
		sync_file: impl FnOnce(&File) -> Result<(), SelectedStreamPublishError<E>>,
		sync_directories: impl FnMut(&File) -> rustix::io::Result<()>,
	) -> Result<SelectedStreamPublication, SelectedStreamPublishError<E>> {
		use SelectedStreamPublishError as Failure;
		let initial = self.observation;
		if initial.binding() != permit.binding() {
			return Err(Failure::Native(PublishError::BindingMismatch));
		}
		if authority.qualification != eligibility.qualification_digest() {
			return Err(Failure::QualificationMismatch);
		}
		let names = self.stage.names();
		eligibility
			.recheck_for(names.destination)
			.map_err(Failure::Eligibility)?;
		let before = self.stage.view().map_err(before_rename)?;
		self.recheck_view(&before).map_err(before_rename)?;
		sync_file(before.file)?;

		eligibility
			.recheck_for(names.destination)
			.map_err(Failure::Eligibility)?;
		let held = self.stage.view().map_err(before_rename)?;
		self.recheck_view(&held).map_err(before_rename)?;
		let request = SelectedStreamGateRequest {
			authority,
			location: location(&held, &names).map_err(before_rename)?,
		};
		let guard = enter_gate(request).map_err(Failure::Gate)?;
		let renamed = names.rename();
		drop(guard);
		renamed.map_err(Failure::Native)?;

		let first = self.observe_publication(&held, &names);
		names
			.sync_directories(sync_directories)
			.map_err(Failure::Native)?;
		let first = first.map_err(after_rename)?;
		let final_state = self
			.observe_publication(&held, &names)
			.map_err(after_rename)?;
		first
			.recheck(final_state)
			.map_err(|error| after_rename(StageError::ReadBack(error)))?;
		Ok(SelectedStreamPublication {
			target: final_state.identity(),
			stage_directory: initial.stage_directory(),
			destination: initial.destination(),
		})
	}

	fn observe_publication(
		&self,
		held: &SelectedStreamView<'_>,
		names: &PublicationNames<'_>,
	) -> Result<SourceObservation, StageError> {
		self.stage.check_directory()?;
		let original = self.observation;
		let named = names.observe_target(original.stage())?;
		let named = SourceObservation::capture(&named).map_err(StageError::ReadBack)?;
		let current = held.observe_held(original.length())?;
		named.recheck(current).map_err(StageError::ReadBack)?;
		// Rename itself can change ctime. All other selected facts must still
		// agree with the verified private file. The caller compares the two
		// post-rename observations including their new ctime.
		if current.identity() != original.stage()
			|| current.modified_at() != original.file.modified_at()
			|| current.mode() != original.mode()
			|| current.owner() != original.owner()
			|| current.group() != original.group()
			|| file_identity(names.stage)? != original.stage_directory()
			|| file_identity(&names.destination.directory)? != original.destination()
			|| mount_id(names.stage)? != held.mount
			|| mount_id(&names.destination.directory)? != held.mount
		{
			return Err(StageError::IdentityChanged);
		}
		self.stage.check_directory()?;
		Ok(current)
	}
}

impl StageHandle<'_> {
	fn names(&self) -> PublicationNames<'_> {
		match self {
			Self::Closed(stage) => stage.selected_stream_names(),
			Self::Retained(stage) => stage.selected_stream_names(),
		}
	}

	fn check_directory(&self) -> Result<(), StageError> {
		match self {
			Self::Closed(stage) => stage.check_selected_stream_directory(),
			Self::Retained(stage) => stage.check_selected_stream_directory(),
		}
	}
}

fn checked_names<'stage>(
	names: &PublicationNames<'stage>,
) -> Result<SelectedStreamNames<'stage>, StageError> {
	Ok(SelectedStreamNames {
		stage: UnixComponent::new(names.stage_name.as_bytes())
			.map_err(|_| StageError::IdentityChanged)?,
		target: UnixComponent::new(names.target_name.as_bytes())
			.map_err(|_| StageError::IdentityChanged)?,
	})
}

fn location<'stage>(
	view: &SelectedStreamView<'_>,
	names: &PublicationNames<'stage>,
) -> Result<SelectedStreamLocation<'stage>, StageError> {
	let actual = view.check_held(view.expected.len())?;
	view.expected
		.recheck(actual)
		.map_err(StageError::ReadBack)?;
	Ok(SelectedStreamLocation {
		binding: view.binding,
		stage: actual.identity(),
		directory: view.stage_directory,
		destination: view.destination,
		names: checked_names(names)?,
	})
}

fn before_rename<E>(error: StageError) -> SelectedStreamPublishError<E> {
	SelectedStreamPublishError::Native(PublishError::StageChanged(error))
}

fn after_rename<E>(error: StageError) -> SelectedStreamPublishError<E> {
	SelectedStreamPublishError::Native(PublishError::ObservationFailed(error))
}
