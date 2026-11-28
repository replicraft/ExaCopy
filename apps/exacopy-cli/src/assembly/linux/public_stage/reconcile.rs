use exacopy_journal::{ApplyCrashProfile, LinuxFileIdentity};
use exacopy_platform::linux::{
	DestinationRoot, ProcessCrashEligibility, ProcessCrashEnvironment, ReadRoot,
};
use exacopy_transfer::linux::{
	InspectionError, PublicApplyReconcileSelection, PublicApplyReconciliation, RecoveryStep,
	reconcile_public_apply_with_lease,
};

use super::super::RecoveryInspectError;

/// Reads one separately selected checked local public-apply history under a shared lease.
/// The held destination and the archived Plan, owner key, qualification and
/// raw names have independent provenance. Expired approvals remain historical.
/// When the optional actual held source root and current native environment
/// do not establish the archived scope, stage and target are metadata-only.
/// # Errors
/// Refuses changed held custody, untrusted or unsupported history and unavailable
/// evidence. This entry performs no retry, publication or recovery writes.
pub fn reconcile_public_apply(
	destination: &DestinationRoot,
	source: Option<&ReadRoot>,
	selection: PublicApplyReconcileSelection<'_, '_, '_>,
	scratch: &mut [u8],
) -> Result<PublicApplyReconciliation, RecoveryInspectError> {
	if selection.approved.body().fields().expires_at.is_none() {
		return Err(InspectionError::PlanBinding);
	}
	let current = destination.identity();
	if LinuxFileIdentity::new(current.device(), current.inode()) != selection.destination.identity {
		return Err(InspectionError::OwnerBinding);
	}
	let job = destination
		.open_recovery_job(selection.job_name)
		.map_err(|source| InspectionError::Platform {
			step: RecoveryStep::Job,
			source,
		})?;
	let lease = job
		.try_read_lease()
		.map_err(|source| InspectionError::Platform {
			step: RecoveryStep::Lease,
			source,
		})?;
	let eligible = match selection.qualification.profile {
		ApplyCrashProfile::Arm64UbuntuExt4FixtureV1 => source.and_then(|source| {
			let selected = selection.qualification.environment;
			ProcessCrashEligibility::admit(
				ProcessCrashEnvironment {
					boot_id: selected.boot_id,
					mount_namespace: selected.mount_namespace,
					unique_mount: selected.unique_mount,
					device: selected.device,
				},
				source,
				destination,
			)
			.ok()
		}),
	};
	let view = lease.public_apply_view(eligible.as_ref());
	reconcile_public_apply_with_lease(&view, selection, scratch)
}
