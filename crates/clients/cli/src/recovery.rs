use std::path::Path;

use exacopy_content::MAX_SCRATCH_BYTES;
use exacopy_platform::linux::StageError;
use exacopy_transfer::linux::{RecoveryInspectError, RecoveryProfile, inspect_recovery};

use crate::args::RecoveryCommand;
use crate::copy_report::ErrorKind;
use crate::linux_path::{open_destination, split};
use crate::profile::LocalProfile;
use crate::recovery_report::RecoveryOutcome;

pub(crate) fn inspect(request: &RecoveryCommand) -> RecoveryOutcome {
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
	let profile = RecoveryProfile {
		id: profile.id(),
		verifying_key: &profile.verification_key(),
	};
	match inspect_recovery(&destination, job, profile, &mut scratch) {
		Ok(evidence) => RecoveryOutcome::inspected(evidence),
		Err(error) => RecoveryOutcome::failure(kind(&error), error),
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
