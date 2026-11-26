#[cfg(test)]
use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;

use apfs_mounted::EntryName;
use apfs_mounted::publication::{
	RenameAttempt, RenameEvidence, RenamedEntry, attempt_exclusive_rename, sync_directories,
};
use exacopy_model::PublishNoClobber;
use rustix::fs::{self, AtFlags};

use super::super::file::same_observation;
use super::super::staging::MetadataReadyStage;
use super::super::{
	ManagedObjectIdentity, ManagedReadError, PhysicalFsid, volume, with_materialization_disabled,
};
use super::evidence::PublicationObservation;
use super::{
	DirectoryBarrierFailures, PublishError, PublishRejection, PublishedFile,
	PublishedObservationError,
};

impl MetadataReadyStage<'_> {
	/// Consumes a metadata-ready stage and the matching model authorization for one rename.
	///
	/// The stage owns its binding and both directory leases. The coordinator must
	/// independently verify read-back and synchronize an authoritative intent for
	/// this stage and target before asking the model for its authorization. Success
	/// reports an exclusive rename, both directory barriers and matching observations.
	///
	/// # Errors
	///
	/// Rejection before the call leaves the namespace untouched. A conflict
	/// retains the incumbent and stage. An uncertain call or incomplete
	/// post-rename evidence requires reconciliation. A returned error never
	/// authorizes cleanup or blind retry.
	pub fn publish_no_clobber(
		self,
		authorization: PublishNoClobber,
	) -> Result<PublishedFile, PublishError> {
		self.publish_with(authorization, |location| {
			let barriers = sync_directories(location.directory(), location.destination());
			DirectoryBarrierFailures::from_results(
				barriers.source.map_err(|error| error.error),
				barriers.destination.map_err(|error| error.error),
			)
		})
	}

	#[cfg(test)]
	pub(super) fn publish_with_barriers(
		self,
		authorization: PublishNoClobber,
		mut sync: impl FnMut(&File) -> io::Result<()>,
	) -> Result<PublishedFile, PublishError> {
		self.publish_with(authorization, |location| {
			let stage = sync(location.stage_file());
			let destination = sync(location.destination_file());
			DirectoryBarrierFailures::from_results(stage, destination)
		})
	}

	fn publish_with(
		self,
		authorization: PublishNoClobber,
		sync: impl FnOnce(&super::super::staging::StageLocation<'_>) -> Option<DirectoryBarrierFailures>,
	) -> Result<PublishedFile, PublishError> {
		if authorization.binding() != self.binding() {
			return Err(PublishError::Rejected {
				reason: PublishRejection::BindingMismatch,
				policy_error: None,
			});
		}
		let mut attempt = None;
		let policy = with_materialization_disabled(|| {
			attempt = Some(self.attempt_rename(sync));
			Ok::<(), ManagedReadError>(())
		});
		finish_attempt(attempt, policy)
	}

	fn attempt_rename(
		&self,
		sync: impl FnOnce(&super::super::staging::StageLocation<'_>) -> Option<DirectoryBarrierFailures>,
	) -> Result<RenameOutcome, PublishRejection> {
		let target = EntryName::new(self.target().as_bytes()).map_err(PublishRejection::Name)?;
		let stage_dir = self.location.directory();
		let destination_dir = self.location.destination();
		if !volume::supports_exclusive_rename(stage_dir.as_fd())
			.map_err(PublishRejection::Volume)?
			|| !volume::supports_exclusive_rename(destination_dir.as_fd())
				.map_err(PublishRejection::Volume)?
		{
			return Err(PublishRejection::ExclusiveRenameUnavailable);
		}
		// The coordinator has synchronized intent and the leases protect our
		// source binding. The kernel makes the final occupancy decision.
		self.check_current_with_policy()
			.map_err(PublishRejection::Stage)?;
		match attempt_exclusive_rename(
			stage_dir,
			self.location.mounted_name(),
			destination_dir,
			&target,
			self.event_handle(),
			self.mounted_identity(),
		) {
			RenameAttempt::NotAttempted(rejection) => Err(PublishRejection::Mounted(rejection)),
			RenameAttempt::Conflict => Ok(RenameOutcome::Conflict),
			RenameAttempt::Uncertain(error) => Ok(RenameOutcome::Uncertain(error)),
			RenameAttempt::Renamed(renamed) => {
				let barriers = sync(&self.location);
				Ok(RenameOutcome::Renamed {
					barriers,
					observation: self.observe_publication(&renamed),
				})
			}
			_ => Ok(RenameOutcome::Uncertain(io::Error::other(
				"unknown mounted rename result",
			))),
		}
	}

	fn observe_publication(
		&self,
		renamed: &RenamedEntry<'_>,
	) -> Result<PublicationObservation, PublishedObservationError> {
		let target_identity = match renamed.observe() {
			RenameEvidence::Confirmed { target } => ManagedObjectIdentity::from_mounted(&target),
			evidence => return Err(PublishedObservationError::MountedNames(Box::new(evidence))),
		};
		let (stage_directory, destination_directory) = self
			.location
			.observe_directories()
			.map_err(|error| PublishedObservationError::Directories(Box::new(error)))?;
		let destination = self.location.destination().as_fd();
		let target = self.target();
		let held = self
			.check_published_descriptor()
			.map_err(|error| PublishedObservationError::Stage(Box::new(error)))?;
		let named = fs::statat(destination, target.as_bytes(), AtFlags::SYMLINK_NOFOLLOW)?;
		let Some(destination_fsid) = PhysicalFsid::held(destination)? else {
			return Err(PublishedObservationError::NamesChanged);
		};
		if !same_observation(&named, &held)
			|| named.st_atime != held.st_atime
			|| named.st_atime_nsec != held.st_atime_nsec
			|| PhysicalFsid::named(destination, target)? != Some(destination_fsid)
		{
			return Err(PublishedObservationError::NamesChanged);
		}
		let target = ManagedObjectIdentity::from_stat(&named, destination_fsid)
			.ok_or(PublishedObservationError::NamesChanged)?;
		if target != target_identity {
			return Err(PublishedObservationError::NamesChanged);
		}
		Ok(PublicationObservation {
			target,
			stage_directory,
			destination_directory,
		})
	}
}

#[derive(Debug)]
pub(super) enum RenameOutcome {
	Conflict,
	Uncertain(io::Error),
	Renamed {
		barriers: Option<DirectoryBarrierFailures>,
		observation: Result<PublicationObservation, PublishedObservationError>,
	},
}

pub(super) fn finish_attempt(
	attempt: Option<Result<RenameOutcome, PublishRejection>>,
	policy: Result<(), ManagedReadError>,
) -> Result<PublishedFile, PublishError> {
	let policy_error = policy.err();
	match attempt {
		None => Err(PublishError::Rejected {
			reason: PublishRejection::Policy,
			policy_error,
		}),
		Some(Err(reason)) => Err(PublishError::Rejected {
			reason,
			policy_error,
		}),
		Some(Ok(RenameOutcome::Conflict)) => Err(PublishError::Conflict { policy_error }),
		Some(Ok(RenameOutcome::Uncertain(error))) => Err(PublishError::Uncertain {
			error,
			policy_error,
		}),
		Some(Ok(RenameOutcome::Renamed {
			barriers: None,
			observation: Ok(observation),
		})) if policy_error.is_none() => Ok(PublishedFile::new(observation)),
		Some(Ok(RenameOutcome::Renamed {
			barriers,
			observation,
		})) => {
			let (observed_target, observation) = match observation {
				Ok(names) => (Some(names.target), None),
				Err(error) => (None, Some(error)),
			};
			Err(PublishError::Renamed {
				barriers,
				observation,
				observed_target,
				policy_error,
			})
		}
	}
}
