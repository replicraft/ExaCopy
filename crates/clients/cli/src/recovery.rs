use std::path::Path;

use exacopy_content::MAX_SCRATCH_BYTES;
use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::{DestinationRoot, PublishError, ReadError, ReadRoot, StageError};
use exacopy_transfer::linux::{
	RecoveryFinishError, RecoveryInspectError, RecoveryProfile, RecoveryRetryError, RecoverySource,
	finish_recovery, inspect_recovery, resume_recovery, retry_recovery,
};

use crate::args::{RecoveryAction, RecoveryCommand, SourceRecoveryAction};
use crate::copy_report::ErrorKind;
use crate::linux_path::{open_destination, open_directory, split};
use crate::profile::LocalProfile;
use crate::recovery_report::RecoveryOutcome;

pub(crate) fn execute(request: &RecoveryCommand) -> RecoveryOutcome {
	let (parent, job) = match split(&request.job) {
		Ok(selection) => selection,
		Err(error) => return RecoveryOutcome::failure(ErrorKind::InvalidRequest, error),
	};
	let profile = match LocalProfile::open(&request.profile) {
		Ok(profile) => profile,
		Err(error) => return RecoveryOutcome::failure(ErrorKind::ProfileAuthorization, error),
	};
	let destination = match open_destination(Path::new(parent)) {
		Ok(root) => root,
		Err(error) => return RecoveryOutcome::failure(ErrorKind::Io, error),
	};
	let mut scratch = Vec::new();
	if let Err(error) = scratch.try_reserve_exact(MAX_SCRATCH_BYTES) {
		return RecoveryOutcome::failure(ErrorKind::Io, error);
	}
	scratch.resize(MAX_SCRATCH_BYTES, 0);
	let binding = RecoveryProfile {
		id: profile.id(),
		verifying_key: &profile.verification_key(),
	};
	match &request.action {
		RecoveryAction::Inspect => match inspect_recovery(&destination, job, binding, &mut scratch)
		{
			Ok(evidence) => RecoveryOutcome::inspected(evidence),
			Err(error) => RecoveryOutcome::failure(kind(&error), error),
		},
		RecoveryAction::Finish => match finish_recovery(&destination, job, binding, &mut scratch) {
			Ok(evidence) => RecoveryOutcome::inspected(evidence),
			Err(RecoveryFinishError::Inspection(error)) => {
				RecoveryOutcome::failure(kind(&error), error)
			}
			Err(error) => RecoveryOutcome::failure(ErrorKind::RecoveryRequired, error),
		},
		RecoveryAction::FromSource {
			action,
			source_root,
		} => recover_from_source(
			*action,
			&destination,
			job,
			binding,
			&profile,
			source_root,
			&mut scratch,
		),
	}
}

fn recover_from_source(
	action: SourceRecoveryAction,
	destination: &DestinationRoot,
	job: UnixComponent<'_>,
	binding: RecoveryProfile<'_>,
	profile: &LocalProfile,
	source_root: &Path,
	scratch: &mut [u8],
) -> RecoveryOutcome {
	let root = match open_directory(source_root.as_os_str())
		.map_err(ReadError::from)
		.and_then(ReadRoot::from_directory)
	{
		Ok(root) => root,
		Err(error) => {
			return RecoveryOutcome::failure(
				ErrorKind::Io,
				format_args!("could not open the supplied source root ({error})"),
			);
		}
	};
	let id = match profile.root_id(root.identity()) {
		Ok(id) => id,
		Err(error) => return RecoveryOutcome::failure(ErrorKind::Io, error),
	};
	let source = RecoverySource { root: &root, id };
	let result = match action {
		SourceRecoveryAction::Retry => retry_recovery(destination, job, binding, source, scratch),
		SourceRecoveryAction::Resume => resume_recovery(destination, job, binding, source, scratch),
	};
	match result {
		Ok(evidence) => RecoveryOutcome::inspected(evidence),
		Err(error) => RecoveryOutcome::failure(source_recovery_kind(&error), error),
	}
}

fn source_recovery_kind(error: &RecoveryRetryError) -> ErrorKind {
	match error {
		RecoveryRetryError::Recovery(RecoveryFinishError::Inspection(error)) => kind(error),
		RecoveryRetryError::SourceMismatch
		| RecoveryRetryError::OpenSource(ReadError::NotRegularFile | ReadError::IdentityChanged) => {
			ErrorKind::SourceMismatch
		}
		RecoveryRetryError::OpenSource(ReadError::System(error))
			if error.kind() == std::io::ErrorKind::NotFound =>
		{
			ErrorKind::SourceMismatch
		}
		RecoveryRetryError::OpenSource(_) | RecoveryRetryError::MeasureSource(_) => ErrorKind::Io,
		RecoveryRetryError::Publish(PublishError::Conflict) => ErrorKind::Conflict,
		_ => ErrorKind::RecoveryRequired,
	}
}

fn kind(error: &RecoveryInspectError) -> ErrorKind {
	match error {
		RecoveryInspectError::Owner(_) | RecoveryInspectError::OwnerBinding => {
			ErrorKind::ProfileAuthorization
		}
		RecoveryInspectError::Platform {
			source: StageError::JobBusy,
			..
		}
		| RecoveryInspectError::RecordChanged(_) => ErrorKind::RecoveryRequired,
		RecoveryInspectError::Platform { .. }
		| RecoveryInspectError::Read { .. }
		| RecoveryInspectError::ReadBack(_) => ErrorKind::Io,
		RecoveryInspectError::Input(_) => ErrorKind::InvalidRequest,
		_ => ErrorKind::Integrity,
	}
}
