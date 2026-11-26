use std::convert::Infallible;
#[cfg(test)]
use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;

use apfs_mounted::EntryName;
use apfs_mounted::publication::{
	EntrySpelling, RenameAttempt, RenamedEntry, attempt_exclusive_rename,
	attempt_exclusive_rename_checked, sync_directories,
};
use exacopy_model::PublishNoClobber;

use super::super::staging::MetadataReadyStage;
use super::super::{
	ManagedObjectIdentity, ManagedReadError, volume, with_materialization_disabled,
};
use super::evidence::PublicationObservation;
use super::{
	CheckedPublishError, DirectoryBarrierFailures, PublicationGateRequest, PublishError,
	PublishRejection, PublishedFile, PublishedObservationError,
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
		local_result(self.publish_with(
			authorization,
			RenameGate::<LocalGate>::Local,
			sync_publication_directories,
		))
	}

	/// Consumes this stage and permit with a final caller-owned publication gate.
	///
	/// After all filesystem admission and companion identity probes, the caller
	/// must acquire and return its held revocation guard and check the current
	/// deadline and exact prevalidated context while that guard is held. This
	/// callback must perform no file or journal I/O and must not await.
	/// The guard remains held through the one no-clobber syscall and is released
	/// before any directory barrier. The caller owns the actual authorization,
	/// authoritative intent and protection supplied by its guard.
	///
	/// # Errors
	/// Preserves a typed caller refusal with any policy-restoration failure,
	/// or the native preflight, conflict, uncertain or post-rename outcome.
	pub fn publish_no_clobber_checked<G, E>(
		self,
		authorization: PublishNoClobber,
		enter_gate: impl FnOnce(PublicationGateRequest<'_>) -> Result<G, E>,
	) -> Result<PublishedFile, CheckedPublishError<E>> {
		self.publish_with(
			authorization,
			RenameGate::Checked(enter_gate),
			sync_publication_directories,
		)
	}

	#[cfg(test)]
	pub(super) fn publish_with_barriers(
		self,
		authorization: PublishNoClobber,
		mut sync: impl FnMut(&File) -> io::Result<()>,
	) -> Result<PublishedFile, PublishError> {
		local_result(
			self.publish_with(authorization, RenameGate::<LocalGate>::Local, |location| {
				let stage = sync(location.stage_file());
				let destination = sync(location.destination_file());
				DirectoryBarrierFailures::from_results(stage, destination)
			}),
		)
	}

	fn publish_with<G, E>(
		self,
		authorization: PublishNoClobber,
		gate: RenameGate<impl FnOnce(PublicationGateRequest<'_>) -> Result<G, E>>,
		sync: impl FnOnce(&super::super::staging::StageLocation<'_>) -> Option<DirectoryBarrierFailures>,
	) -> Result<PublishedFile, CheckedPublishError<E>> {
		if authorization.binding() != self.binding() {
			return Err(CheckedPublishError::Native(PublishError::Rejected {
				reason: PublishRejection::BindingMismatch,
				policy_error: None,
			}));
		}
		let mut attempt = None;
		let policy = with_materialization_disabled(|| {
			attempt = Some(self.attempt_rename(gate, sync));
			Ok::<(), ManagedReadError>(())
		});
		finish_checked_attempt(attempt, policy)
	}

	fn attempt_rename<G, E>(
		&self,
		gate: RenameGate<impl FnOnce(PublicationGateRequest<'_>) -> Result<G, E>>,
		sync: impl FnOnce(&super::super::staging::StageLocation<'_>) -> Option<DirectoryBarrierFailures>,
	) -> Result<RenameOutcome, AttemptRejection<E>> {
		let target = EntryName::new(self.target().as_bytes()).map_err(PublishRejection::Name)?;
		let stage_dir = self.location.directory();
		let destination_dir = self.location.destination();
		if !volume::supports_exclusive_rename(stage_dir.as_fd())
			.map_err(PublishRejection::Volume)?
			|| !volume::supports_exclusive_rename(destination_dir.as_fd())
				.map_err(PublishRejection::Volume)?
		{
			return Err(PublishRejection::ExclusiveRenameUnavailable.into());
		}
		// The coordinator has synchronized intent and the leases protect our
		// source binding. The kernel makes the final occupancy decision.
		self.check_current_with_policy()
			.map_err(PublishRejection::Stage)?;
		let attempt = match gate {
			RenameGate::Local => attempt_exclusive_rename(
				stage_dir,
				self.location.mounted_name(),
				destination_dir,
				&target,
				self.event_handle(),
				self.mounted_identity(),
			),
			RenameGate::Checked(enter_gate) => {
				let (expected_stage_directory, expected_destination_directory) = self
					.location
					.observe_directories()
					.map_err(PublishRejection::Stage)?;
				let request = PublicationGateRequest {
					binding: self.binding(),
					expected_stage: ManagedObjectIdentity::from_mounted(self.mounted_identity()),
					expected_stage_directory,
					expected_destination_directory,
					expected_stage_name: self.location.mounted_name().as_bytes(),
					expected_target_name: self.target().as_bytes(),
				};
				attempt_exclusive_rename_checked(
					stage_dir,
					self.location.mounted_name(),
					destination_dir,
					&target,
					self.event_handle(),
					self.mounted_identity(),
					|| enter_gate(request),
				)
				.map_err(AttemptRejection::Authorization)?
			}
		};
		match attempt {
			RenameAttempt::NotAttempted(rejection) => {
				Err(PublishRejection::Mounted(rejection).into())
			}
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
		let directories_before = self
			.location
			.observe_directories()
			.map_err(|error| PublishedObservationError::Directories(Box::new(error)))?;
		// Keep strict ACL, fork and xattr queries on the original sealed read-only
		// descriptor, with both names checked around the held metadata observation.
		let (snapshot, held) = renamed
			.with_observation(EntrySpelling::Lookup, |_, _| {
				Ok(self.check_published_metadata())
			})
			.map_err(|error| PublishedObservationError::MountedSnapshot(Box::new(error)))?;
		let held = held.map_err(|error| PublishedObservationError::Stage(Box::new(error)))?;
		let (stage_directory, destination_directory) = self
			.location
			.observe_directories()
			.map_err(|error| PublishedObservationError::Directories(Box::new(error)))?;
		if directories_before != (stage_directory, destination_directory)
			|| snapshot.metadata != held
		{
			return Err(PublishedObservationError::NamesChanged);
		}
		Ok(PublicationObservation {
			target: ManagedObjectIdentity::from_mounted(&snapshot.identity),
			stage_directory,
			destination_directory,
		})
	}
}

fn sync_publication_directories(
	location: &super::super::staging::StageLocation<'_>,
) -> Option<DirectoryBarrierFailures> {
	let barriers = sync_directories(location.directory(), location.destination());
	DirectoryBarrierFailures::from_results(
		barriers.source.map_err(|error| error.error),
		barriers.destination.map_err(|error| error.error),
	)
}

type LocalGate = fn(PublicationGateRequest<'_>) -> Result<(), Infallible>;

enum RenameGate<F> {
	Local,
	Checked(F),
}

pub(super) enum AttemptRejection<E> {
	Native(PublishRejection),
	Authorization(E),
}

impl<E> From<PublishRejection> for AttemptRejection<E> {
	fn from(error: PublishRejection) -> Self {
		Self::Native(error)
	}
}

fn local_result(
	result: Result<PublishedFile, CheckedPublishError<Infallible>>,
) -> Result<PublishedFile, PublishError> {
	result.map_err(|error| match error {
		CheckedPublishError::Native(error) => error,
		CheckedPublishError::Authorization { cause, .. } => match cause {},
	})
}

pub(super) fn finish_checked_attempt<E>(
	attempt: Option<Result<RenameOutcome, AttemptRejection<E>>>,
	policy: Result<(), ManagedReadError>,
) -> Result<PublishedFile, CheckedPublishError<E>> {
	let attempt = match attempt {
		Some(Err(AttemptRejection::Authorization(cause))) => {
			return Err(CheckedPublishError::Authorization {
				cause,
				policy_error: policy.err(),
			});
		}
		Some(Err(AttemptRejection::Native(error))) => Some(Err(error)),
		Some(Ok(outcome)) => Some(Ok(outcome)),
		None => None,
	};
	finish_attempt(attempt, policy).map_err(CheckedPublishError::Native)
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
