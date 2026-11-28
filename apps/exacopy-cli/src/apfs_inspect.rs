use std::io::Write;
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use exacopy_platform::macos::staging::ManagedStageGrant;
use exacopy_platform::macos::staging::jobs::with_provisioned_recovery_job;

use crate::args::InspectApfsCommand;
use crate::assembly::macos::inspection::{
	DarwinInspectionAuthority, DarwinInspectionError, DarwinJobInspection, inspect_job,
};
use crate::unix_path::split;

mod report;

use self::report::{Failure, Report};

pub(crate) fn run(
	command: &InspectApfsCommand,
	stdout: &mut impl Write,
	stderr: &mut impl Write,
) -> u8 {
	let report = match observe(command) {
		Ok(observed) => Report::observed(observed),
		Err(failure) => Report::refused(failure),
	};
	if report.write(command.format, stdout, stderr).is_err() {
		let _ = writeln!(
			stderr,
			"exacopy: could not write the APFS inspection result"
		);
		return 4;
	}
	report.exit_code()
}

fn observe(command: &InspectApfsCommand) -> Result<DarwinJobInspection, Failure> {
	let key = VerifyingKey::from_bytes(&command.owner_key).map_err(|_| Failure::Selection)?;
	if key.is_weak() || key.to_edwards().compress().to_bytes() != command.owner_key {
		return Err(Failure::Selection);
	}
	let (destination, container) =
		split(&command.stage_container).map_err(|_| Failure::Selection)?;
	let authority = DarwinInspectionAuthority {
		profile: command.owner_profile,
		key: &key,
		destination_root: command.destination_root,
	};
	with_provisioned_recovery_job(
		Path::new(destination),
		container,
		command.job,
		ManagedStageGrant::trusted_owner_authorizes_provisioned_root(),
		|job| inspect_job(job, authority),
	)
	.map_err(|_| Failure::Custody)?
	.map_err(|error| match error {
		DarwinInspectionError::PlanBinding => Failure::Binding,
		DarwinInspectionError::Platform(_) | DarwinInspectionError::Identity(_) => Failure::Custody,
		_ => Failure::History,
	})
}
