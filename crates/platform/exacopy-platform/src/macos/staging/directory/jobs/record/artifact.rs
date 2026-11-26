use std::fs::File;
use std::io;

use apfs_mounted::metadata::{MAX_EXTENDED_SECURITY_BYTES, MetadataView};
use apfs_mounted::writer::{
	ArtifactCheckPhase, ArtifactError, ArtifactPhase, InitialFlags, LifecycleEffect, WriterError,
	write_private_artifact_checked,
};
use apfs_mounted::{EntryName, IdentityError};
use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, FileType};

use super::super::super::super::super::{FILE_MODE, acl, with_materialization_disabled};
use super::super::StageError;
use super::{Creation, DirectoryLease, JobError, JobStep, ManagedObjectIdentity, record_length};

pub(super) fn write_record(
	lease: &DirectoryLease,
	name: UnixComponent<'_>,
	bytes: &[u8],
	creation: Creation,
	check_parent: impl Fn() -> Result<(), JobError>,
) -> Result<ManagedObjectIdentity, JobError> {
	write_record_with_namespace_barrier(lease, name, bytes, creation, check_parent, |file| {
		fs::fsync(file)
	})
}

pub(in super::super) fn write_record_with_namespace_barrier(
	lease: &DirectoryLease,
	name: UnixComponent<'_>,
	bytes: &[u8],
	mut creation: Creation,
	check_parent: impl Fn() -> Result<(), JobError>,
	namespace_barrier: impl FnOnce(&File) -> rustix::io::Result<()>,
) -> Result<ManagedObjectIdentity, JobError> {
	let length = record_length(bytes)?;
	let native_name = EntryName::new(name.as_bytes()).map_err(StageError::Name)?;
	// Refuse a changed job before invoking the native creation helper. Recheck
	// its held ancestry at the helper's actual exclusive-open boundary.
	with_materialization_disabled(&check_parent)?;
	let artifact = write_private_artifact_checked(
		&lease.directory,
		&native_name,
		bytes,
		InitialFlags::RequireZero,
		|| check_parent().map_err(|error| WriterError::CreationRefused(Box::new(error))),
		|phase, view| {
			check_parent()
				.and_then(|()| check_metadata(lease.owner, length, phase, &view))
				.map_err(|error| WriterError::MetadataRefused(Box::new(error)))
		},
	)
	.map_err(|error| artifact_failure(&creation, error))?;
	let identity = ManagedObjectIdentity::from_mounted(artifact.identity());

	// The verified artifact already exists even if establishing the scope for
	// the namespace barrier fails. The event-only anchor remains held through
	// the original final named-identity check.
	creation.step = Some(JobStep::Revalidate);
	creation.run(|creation| {
		creation.step = Some(JobStep::NamespaceBarrier);
		namespace_barrier(&lease.file)?;
		creation.step = Some(JobStep::Revalidate);
		check_parent()?;
		let named = lease.named_stat(name)?;
		if ManagedObjectIdentity::from_stat(&named, lease.identity.physical_fsid) != Some(identity)
		{
			return Err(JobError::IdentityChanged);
		}
		artifact
			.identity()
			.revalidate_held(artifact.event_handle())
			.map_err(|error| job_failure(WriterError::Identity(error)))?;
		Ok(identity)
	})
}

fn check_metadata(
	owner: u32,
	length: u64,
	phase: ArtifactCheckPhase,
	view: &MetadataView<'_>,
) -> Result<(), JobError> {
	let metadata = view
		.stat()
		.map_err(WriterError::from)
		.map_err(job_failure)?;
	let expected_length = if phase == ArtifactCheckPhase::AfterCreate {
		0
	} else {
		length
	};
	if metadata.file_type != FileType::RegularFile
		|| metadata.uid != owner
		|| metadata.link_count != 1
		|| metadata.mode != FILE_MODE
		|| metadata.object_flags().raw() != 0
		|| metadata.length != expected_length
		|| !acl::stage_security(view.extended_security(MAX_EXTENDED_SECURITY_BYTES))?
	{
		return Err(JobError::IdentityChanged);
	}
	Ok(())
}

fn artifact_failure(creation: &Creation, error: ArtifactError) -> JobError {
	let step = artifact_step(error.phase, &error.error);
	match (step, error.error) {
		(None, WriterError::Occupied) => JobError::Occupied {
			job: creation.job,
			artifact: creation.artifact,
		},
		(None, error) => job_failure(error),
		(Some(step), error) => JobError::Uncertain {
			job: creation.job,
			artifact: creation.artifact,
			step,
			source: Box::new(job_failure(error)),
		},
	}
}

fn artifact_step(phase: ArtifactPhase, error: &WriterError) -> Option<JobStep> {
	match phase {
		ArtifactPhase::Create => creation_step(error),
		ArtifactPhase::Write => Some(JobStep::Write),
		ArtifactPhase::FlushAndClose => Some(flush_step(error)),
		ArtifactPhase::Reopen | ArtifactPhase::ReadBack => Some(JobStep::Verify),
		_ => Some(JobStep::Revalidate),
	}
}

fn creation_step(error: &WriterError) -> Option<JobStep> {
	match error {
		WriterError::Occupied
		| WriterError::InvalidRange
		| WriterError::Identity(_)
		| WriterError::CreationRefused(_)
		| WriterError::Configure { .. } => None,
		WriterError::CreatedButUnverified(_) => Some(JobStep::Bind),
		WriterError::Restore { outcome, .. } => match outcome {
			Ok(LifecycleEffect::Created) => Some(JobStep::Bind),
			Err(cause) => creation_step(cause),
			Ok(_) => Some(JobStep::Create),
		},
		_ => Some(JobStep::Create),
	}
}

fn flush_step(error: &WriterError) -> JobStep {
	match error {
		WriterError::Barrier(_) | WriterError::BarrierPassedButUnverified(_) => {
			JobStep::FileBarrier
		}
		WriterError::Close(_) => JobStep::Close,
		WriterError::ClosedButUnverified(_) => JobStep::Verify,
		WriterError::Restore { outcome, .. } => match outcome {
			Ok(LifecycleEffect::Closed) => JobStep::Verify,
			Err(cause) => flush_step(cause),
			Ok(_) => JobStep::Write,
		},
		_ => JobStep::Write,
	}
}

fn job_failure(error: WriterError) -> JobError {
	match error {
		WriterError::CreationRefused(cause) | WriterError::MetadataRefused(cause) => {
			match cause.downcast::<JobError>() {
				Ok(cause) => *cause,
				Err(cause) => JobError::System(io::Error::other(cause)),
			}
		}
		WriterError::CreatedButUnverified(cause) => job_failure(*cause),
		WriterError::CreateUncertain(error) | WriterError::Io(error) => error.into(),
		WriterError::Barrier(error) => error.error.into(),
		WriterError::Changed
		| WriterError::NotPrivate
		| WriterError::Identity(IdentityError::Changed) => JobError::IdentityChanged,
		error => StageError::from(error).into(),
	}
}

#[cfg(test)]
mod tests;
