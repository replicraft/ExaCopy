use std::path::Path;

use cargo_metadata::Package;

use super::{CaseKind, Fixture, Profile};
use crate::finding::Findings;

const OWNER: &str = "exacopy-platform";
const STATMOUNT: &str = "verification/sync_history_ext4_statmount/fixture.toml";
const WITNESSED: &str = "verification/witnessed_components_ext4/fixture.toml";
const WITNESSED_RUNNER: &str = "verification/witnessed_components_ext4/run.py";
const WITNESSED_CONTROLS: &str = "verification/witnessed_components_ext4/test_runner.py";
const WITNESSED_ID: &str = "linux-witnessed-components-ext4";
const WITNESSED_WORKFLOW: &str =
	".github/workflows/linux-witnessed-components-ext4-qualification.yml";

const WITNESSED_CASES: [(&str, &str); 6] = [
	(
		"prefix::tests::witness",
		"actual_descriptor_link_keeps_both_names_and_held_exclusion",
	),
	(
		"prefix::tests::witness",
		"occupied_slot_or_refused_later_barrier_never_removes_evidence",
	),
	(
		"prefix::tests::witness",
		"witnessed_native_rename_observes_success_conflict_and_nonregular_incumbent",
	),
	(
		"witness_reservation::tests",
		"native_allocation_preserves_the_named_segment_and_anonymous_eof",
	),
	(
		"witness_reservation::tests",
		"only_a_submitted_journal_allocation_latches_the_lease_even_on_syscall_error",
	),
	(
		"witness_reservation::continuation::tests",
		"original_reserved_descriptor_writes_and_rereads_only_the_exact_successor",
	),
];

pub(super) fn check(
	package: &Package,
	manifest: &Path,
	path: &Path,
	fixture: &Fixture,
	findings: &mut Findings,
) -> bool {
	let owner = package.name.as_str();
	let statmount = matches!(fixture.profile, Profile::UnprivilegedWholeExt4SyncStatmount);
	if statmount != (manifest == Path::new(STATMOUNT))
		|| (statmount
			&& !(owner == OWNER
				&& matches!(fixture.cases.as_slice(), [case]
					if case.test_target.as_deref() == Some("linux_sync_history_ext4_statmount")
					&& case.source == Path::new("tests/linux_sync_history_ext4_statmount.rs")
					&& case.selector == "held_ext4_history_mount_admits_unmapped_attributes")))
	{
		findings.add(
			path,
			"statmount fixture requires its exact platform owner, manifest and one case",
		);
		return false;
	}
	if !witnessed(owner, manifest, fixture) {
		findings.add(
			path,
			"witnessed component fixture requires its exact platform owner, manifest and six unit cases",
		);
		return false;
	}
	true
}

fn witnessed(owner: &str, manifest: &Path, fixture: &Fixture) -> bool {
	let registered = manifest == Path::new(WITNESSED);
	if !matches!(
		fixture.profile,
		Profile::UnprivilegedWholeExt4WitnessedComponents
	) {
		return !registered;
	}
	registered
		&& owner == OWNER
		&& fixture.id == WITNESSED_ID
		&& fixture.runner == Path::new(WITNESSED_RUNNER)
		&& fixture.controls == Path::new(WITNESSED_CONTROLS)
		&& fixture.workflow == Path::new(WITNESSED_WORKFLOW)
		&& fixture.cases.len() == WITNESSED_CASES.len()
		&& fixture
			.cases
			.iter()
			.zip(WITNESSED_CASES)
			.all(|(case, (module, test))| {
				let selector = format!("linux::recovery::writer::{module}::{test}");
				matches!(case.kind, CaseKind::RustUnit)
					&& case.owner.is_none()
					&& case.test_target.is_none()
					&& case.required_feature.is_none()
					&& case.ignored
					&& case.selector == selector
			})
}

#[cfg(test)]
mod tests;
