use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;

use exacopy_model::PublishNoClobber;
use rustix::fs::{self, AtFlags};
use rustix::io::Errno;

use super::super::file::same_observation;
use super::super::staging::MetadataReadyStage;
use super::super::{ManagedReadError, PhysicalFsid, volume, with_materialization_disabled};
use super::{
	DirectoryBarrierFailures, PublishError, PublishRejection, PublishedObservationError, native,
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
	pub fn publish_no_clobber(self, authorization: PublishNoClobber) -> Result<(), PublishError> {
		self.publish_with_barriers(authorization, |directory| {
			fs::fsync(directory).map_err(Into::into)
		})
	}

	pub(super) fn publish_with_barriers(
		self,
		authorization: PublishNoClobber,
		mut sync: impl FnMut(&File) -> io::Result<()>,
	) -> Result<(), PublishError> {
		if authorization.binding() != self.binding() {
			return Err(PublishError::Rejected {
				reason: PublishRejection::BindingMismatch,
				policy_error: None,
			});
		}
		let mut attempt = None;
		let policy = with_materialization_disabled(|| {
			attempt = Some(self.attempt_rename(&mut sync));
			Ok::<(), ManagedReadError>(())
		});
		finish_attempt(attempt, policy)
	}

	fn attempt_rename(
		&self,
		sync: &mut impl FnMut(&File) -> io::Result<()>,
	) -> Result<RenameOutcome, PublishRejection> {
		let stage =
			CString::new(self.location.stage_name().as_bytes()).map_err(PublishRejection::Name)?;
		let target = CString::new(self.target().as_bytes()).map_err(PublishRejection::Name)?;
		let stage_dir = self.location.directory().as_fd();
		let destination_dir = self.location.destination().as_fd();
		if !volume::supports_exclusive_rename(stage_dir).map_err(PublishRejection::Volume)?
			|| !volume::supports_exclusive_rename(destination_dir)
				.map_err(PublishRejection::Volume)?
		{
			return Err(PublishRejection::ExclusiveRenameUnavailable);
		}
		// Leases protect the stage name from cooperating writers between
		// the final check and rename. Only the syscall checks target absence.
		self.check_current_with_policy()
			.map_err(PublishRejection::Stage)?;
		match native::rename_exclusively(stage_dir, &stage, destination_dir, &target) {
			Ok(()) => {
				let stage_barrier = sync(self.location.directory());
				let destination_barrier = sync(self.location.destination());
				Ok(RenameOutcome::Renamed {
					barriers: DirectoryBarrierFailures::from_results(
						stage_barrier,
						destination_barrier,
					),
					observation: self.observe_publication().err(),
				})
			}
			Err(error) if error.raw_os_error() == Some(libc::EEXIST) => Ok(RenameOutcome::Conflict),
			Err(error) => Ok(RenameOutcome::Uncertain(error)),
		}
	}

	fn observe_publication(&self) -> Result<(), PublishedObservationError> {
		self.location
			.check_directories()
			.map_err(|error| PublishedObservationError::Directories(Box::new(error)))?;
		match fs::statat(
			self.location.directory(),
			self.location.stage_name().as_bytes(),
			AtFlags::SYMLINK_NOFOLLOW,
		) {
			Err(Errno::NOENT) => {}
			Ok(_) => return Err(PublishedObservationError::NamesChanged),
			Err(error) => return Err(PublishedObservationError::System(error.into())),
		}
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
		Ok(())
	}
}

#[derive(Debug)]
pub(super) enum RenameOutcome {
	Conflict,
	Uncertain(io::Error),
	Renamed {
		barriers: Option<DirectoryBarrierFailures>,
		observation: Option<PublishedObservationError>,
	},
}

pub(super) fn finish_attempt(
	attempt: Option<Result<RenameOutcome, PublishRejection>>,
	policy: Result<(), ManagedReadError>,
) -> Result<(), PublishError> {
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
			observation: None,
		})) if policy_error.is_none() => Ok(()),
		Some(Ok(RenameOutcome::Renamed {
			barriers,
			observation,
		})) => Err(PublishError::Renamed {
			barriers,
			observation,
			policy_error,
		}),
	}
}
