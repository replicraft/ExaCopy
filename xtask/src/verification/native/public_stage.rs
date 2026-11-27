use std::path::Path;

use cargo_metadata::Package;

use super::{Case, CaseKind, Fixture, Profile};
use crate::finding::Findings;

const OWNER: &str = "exacopy-cli";
const ID: &str = "linux-public-stage-ext4";
const MANIFEST: &str = "verification/public_stage_ext4/fixture.toml";
const RUNNER: &str = "verification/public_stage_ext4/run.py";
const CONTROLS: &str = "verification/public_stage_ext4/test_runner.py";
const WORKFLOW: &str = ".github/workflows/linux-public-stage-ext4-qualification.yml";
const SOURCE: &str = "src/assembly/linux/public_stage/tests.rs";
const SELECTOR: &str = concat!(
	"assembly::linux::public_stage::tests::",
	"approved_stage_reopens_with_exact_owner_and_preserves_uncertain_evidence",
);

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
			"public-stage fixture requires its exact application owner, manifest and one ignored unit case",
		);
	}
	valid
}

fn matches_fixture(owner: &str, manifest: &Path, fixture: &Fixture) -> bool {
	let registered = manifest == Path::new(MANIFEST);
	if !matches!(fixture.profile, Profile::UnprivilegedWholeExt4PublicStage) {
		return !registered;
	}
	registered
		&& manifest.as_os_str() == MANIFEST
		&& owner == OWNER
		&& fixture.id == ID
		&& fixture.runner.as_os_str() == RUNNER
		&& fixture.controls.as_os_str() == CONTROLS
		&& fixture.workflow.as_os_str() == WORKFLOW
		&& matches!(fixture.cases.as_slice(), [case] if matches_case(owner, fixture.profile, case))
}

pub(super) fn matches_case(owner: &str, profile: Profile, case: &Case) -> bool {
	owner == OWNER
		&& matches!(profile, Profile::UnprivilegedWholeExt4PublicStage)
		&& matches!(case.kind, CaseKind::RustUnit)
		&& case.owner.is_none()
		&& case.test_target.is_none()
		&& case.source.as_os_str() == SOURCE
		&& case.selector == SELECTOR
		&& case.required_feature.is_none()
		&& case.ignored
}

#[cfg(test)]
mod tests;
