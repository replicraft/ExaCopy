use std::path::Path;

use cargo_metadata::Package;

use super::{CaseKind, Fixture, Profile, RESULT, managed_sync::FEATURE};
use crate::finding::Findings;

const OWNER: &str = "exacopy-cli";
const ID: &str = "linux-managed-sync-genesis-production";
const MANIFEST: &str = "verification/managed_sync_genesis_production/fixture.toml";
const RUNNER: &str = "verification/managed_sync_genesis_production/run.py";
const CONTROLS: &str = "verification/managed_sync_genesis_production/test_runner.py";
const WORKFLOW: &str = ".github/workflows/linux-managed-sync-genesis-production-qualification.yml";
const TARGET: &str = "linux_managed_sync_genesis_production";
const SOURCE: &str = "tests/linux_managed_sync_genesis_production.rs";
const SELECTOR: &str = "production_managed_genesis_publishes_and_previews_exact_p063_history";

pub(super) fn check(
	package: &Package,
	manifest: &Path,
	path: &Path,
	fixture: &Fixture,
	findings: &mut Findings,
) -> bool {
	let valid = matches_fixture(package.name.as_str(), manifest, fixture);
	if !valid {
		findings.add(
			path,
			"managed-sync genesis fixture requires its exact application owner, custody paths and one feature-bound ignored integration case",
		);
	}
	valid
}

fn matches_fixture(owner: &str, manifest: &Path, fixture: &Fixture) -> bool {
	let registered = manifest == Path::new(MANIFEST);
	if !matches!(
		fixture.profile,
		Profile::UnprivilegedWholeExt4ManagedSyncGenesisProduction
	) {
		return !registered;
	}
	registered
		&& manifest.as_os_str() == MANIFEST
		&& owner == OWNER
		&& fixture.id == ID
		&& fixture.runner.as_os_str() == RUNNER
		&& fixture.controls.as_os_str() == CONTROLS
		&& fixture.workflow.as_os_str() == WORKFLOW
		&& fixture.result.as_os_str() == RESULT
		&& matches!(fixture.cases.as_slice(), [case]
			if matches!(case.kind, CaseKind::RustIntegration)
				&& case.owner.is_none()
				&& case.test_target.as_deref() == Some(TARGET)
				&& case.source.as_os_str() == SOURCE
				&& case.selector == SELECTOR
				&& case.required_feature.as_deref() == Some(FEATURE)
				&& case.ignored)
}

#[cfg(test)]
mod tests;
